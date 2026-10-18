package mtls

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bpalermo/cracha/broker/internal/mtls/mtlstest"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

const (
	brokerID = "spiffe://example.org/ns/cracha-system/sa/cracha-broker"
	agentID  = "spiffe://example.org/ns/cracha-system/sa/cracha-agent"
	otherID  = "spiffe://example.org/ns/payments/sa/ledger"
)

// server serves handler over the broker's TLS configuration on loopback and
// returns its URL. The handler is wrapped in Require, as the broker's is.
func server(t *testing.T, ca *mtlstest.CA, log *slog.Logger, handler http.Handler) string {
	t.Helper()
	agent := spiffeid.RequireFromString(agentID)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:           Require(agent, log, handler),
		TLSConfig:         ServerConfig(ca.SVID(t, brokerID), ca.Bundle(), agent),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return "https://" + ln.Addr().String()
}

func client(cfg *tls.Config) *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
}

// peerHandler answers with the client's SPIFFE ID, and counts how often it
// ran.
type peerHandler struct{ calls atomic.Int32 }

func (h *peerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.calls.Add(1)
	id, _ := PeerID(r)
	_, _ = io.WriteString(w, id.String())
}

func TestAgentAccepted(t *testing.T) {
	ca := mtlstest.NewCA(t, "example.org")
	var logs bytes.Buffer
	handler := &peerHandler{}
	url := server(t, ca, slog.New(slog.NewTextHandler(&logs, nil)), handler)

	broker := spiffeid.RequireFromString(brokerID)
	c := client(tlsconfig.MTLSClientConfig(ca.SVID(t, agentID), ca.Bundle(), tlsconfig.AuthorizeID(broker)))
	resp, err := c.Get(url + "/v1/credentials")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != agentID {
		t.Fatalf("got %d %q, want 200 with the agent's ID", resp.StatusCode, body)
	}
	if handler.calls.Load() != 1 {
		t.Errorf("handler ran %d times", handler.calls.Load())
	}
	if logs.Len() != 0 {
		t.Errorf("the agent's request was logged as a refusal: %s", logs.String())
	}
	// The server's certificate was the broker's SVID: the client verified it
	// by SPIFFE ID, with no DNS name involved.
	if state := resp.TLS; state == nil || state.Version < tls.VersionTLS12 {
		t.Errorf("connection state %+v", state)
	}
}

func TestRefusedAtHandshake(t *testing.T) {
	ca := mtlstest.NewCA(t, "example.org")
	foreign := mtlstest.NewCA(t, "other.org")
	anyBroker := tlsconfig.AuthorizeAny()
	tests := map[string]*tls.Config{
		// Another workload of the same trust domain, with a valid SVID.
		"other id":       tlsconfig.MTLSClientConfig(ca.SVID(t, otherID), ca.Bundle(), anyBroker),
		"no client cert": tlsconfig.TLSClientConfig(ca.Bundle(), anyBroker),
		"agent id, other authority": tlsconfig.MTLSClientConfig(
			foreign.SVID(t, "spiffe://other.org/ns/cracha-system/sa/cracha-agent"), ca.Bundle(), anyBroker),
	}
	for name, cfg := range tests {
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			handler := &peerHandler{}
			url := server(t, ca, slog.New(slog.NewTextHandler(&logs, nil)), handler)
			resp, err := client(cfg).Get(url + "/v1/credentials")
			if err == nil {
				resp.Body.Close()
				t.Fatalf("served %d", resp.StatusCode)
			}
			if handler.calls.Load() != 0 {
				t.Error("the handler ran")
			}
			if logs.Len() != 0 {
				t.Errorf("the handshake failure reached Require: %s", logs.String())
			}
		})
	}
}

func TestRequire(t *testing.T) {
	ca := mtlstest.NewCA(t, "example.org")
	agent := spiffeid.RequireFromString(agentID)
	withPeer := func(svid *x509svid.SVID) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/v1/credentials", nil)
		r.TLS = &tls.ConnectionState{PeerCertificates: svid.Certificates}
		return r
	}
	tests := map[string]struct {
		req    *http.Request
		status int
	}{
		"agent":          {withPeer(ca.SVID(t, agentID)), http.StatusOK},
		"other identity": {withPeer(ca.SVID(t, otherID)), http.StatusForbidden},
		"no tls":         {httptest.NewRequest(http.MethodGet, "/v1/credentials", nil), http.StatusForbidden},
		"tls, no peer": {func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.TLS = &tls.ConnectionState{}
			return r
		}(), http.StatusForbidden},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			handler := &peerHandler{}
			rec := httptest.NewRecorder()
			Require(agent, slog.New(slog.NewTextHandler(&logs, nil)), handler).ServeHTTP(rec, tt.req)
			if rec.Code != tt.status {
				t.Fatalf("status %d, want %d", rec.Code, tt.status)
			}
			if tt.status == http.StatusOK {
				if handler.calls.Load() != 1 || rec.Body.String() != agentID {
					t.Errorf("calls %d, body %q", handler.calls.Load(), rec.Body.String())
				}
				return
			}
			if handler.calls.Load() != 0 {
				t.Error("the handler ran")
			}
			var body struct{ Reason string }
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Reason != ReasonUnauthorizedClient {
				t.Errorf("body %q", rec.Body.String())
			}
			if !strings.Contains(logs.String(), "client is not the agent") || !strings.Contains(logs.String(), "agent="+agentID) {
				t.Errorf("log %q", logs.String())
			}
		})
	}
}

func TestDefaultAgentID(t *testing.T) {
	ca := mtlstest.NewCA(t, "example.org")
	id, err := DefaultAgentID(ca.SVID(t, brokerID), "cracha-system")
	if err != nil {
		t.Fatal(err)
	}
	if id.String() != agentID {
		t.Errorf("got %s, want %s", id, agentID)
	}
	if _, err := DefaultAgentID(ca.SVID(t, brokerID), ""); err == nil {
		t.Error("an empty namespace made an ID")
	}
	if _, err := DefaultAgentID(ca.SVID(t, brokerID), "a/b"); err == nil {
		t.Error("a namespace with a slash made an ID")
	}
	if _, err := DefaultAgentID(failingSource{}, "cracha-system"); err == nil {
		t.Error("a source without an SVID made an ID")
	}
}

// failingSource is an X.509-SVID source that has no SVID.
type failingSource struct{}

func (failingSource) GetX509SVID() (*x509svid.SVID, error) { return nil, errors.New("not yet") }

func TestSVIDReadiness(t *testing.T) {
	var r SVIDReadiness
	if err := r.Ready(); err == nil || !strings.Contains(err.Error(), "waiting") {
		t.Fatalf("ready before a source was set: %v", err)
	}
	r.Set(failingSource{})
	if err := r.Ready(); err == nil || !strings.Contains(err.Error(), "not yet") {
		t.Fatalf("ready with a source that has no SVID: %v", err)
	}
	ca := mtlstest.NewCA(t, "example.org")
	r.Set(ca.SVID(t, brokerID))
	if err := r.Ready(); err != nil {
		t.Fatal(err)
	}
}

// The configuration rotates with the source: a new SVID in the source is
// what the next handshake presents.
func TestServerConfigFollowsSource(t *testing.T) {
	ca := mtlstest.NewCA(t, "example.org")
	src := &rotatingSource{svid: ca.SVID(t, brokerID)}
	agent := spiffeid.RequireFromString(agentID)
	cfg := ServerConfig(src, ca.Bundle(), agent)
	first, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	src.svid = ca.SVID(t, brokerID)
	second, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.Certificate[0], second.Certificate[0]) {
		t.Error("the configuration kept the first certificate")
	}
	if cfg.MinVersion != tls.VersionTLS12 || cfg.ClientAuth != tls.RequireAnyClientCert {
		t.Errorf("min version %d, client auth %v", cfg.MinVersion, cfg.ClientAuth)
	}
}

type rotatingSource struct{ svid *x509svid.SVID }

func (s *rotatingSource) GetX509SVID() (*x509svid.SVID, error) { return s.svid, nil }
