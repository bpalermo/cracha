package broker

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"

	"github.com/bpalermo/cracha/agent/internal/spiffetest"
)

const (
	brokerPath = "/ns/cracha-system/sa/cracha-broker"
	agentPath  = "/ns/cracha-system/sa/cracha-agent"
)

// fakeBroker is a SPIFFE mTLS server presenting the SVID at path and
// accepting any client of the trust domain; it echoes the token and the
// path it was called with.
func fakeBroker(t *testing.T, ca *spiffetest.CA, path string) (*httptest.Server, *spiffeid.ID) {
	t.Helper()
	server := ca.NewSource(t, path)
	var clientID spiffeid.ID
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := spiffeid.FromString(r.TLS.PeerCertificates[0].URIs[0].String())
		if err != nil {
			t.Error(err)
		}
		clientID = id
		w.Header().Set("Cracha-Shape", "shape-x")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, r.URL.Path+" "+r.Header.Get("Authorization"))
	}))
	// Not StartTLS: httptest would put its own certificate first, and a
	// client without SNI (an IP address) would be served that one.
	srv.Listener = tls.NewListener(srv.Listener, tlsconfig.MTLSServerConfig(server, server, tlsconfig.AuthorizeMemberOf(ca.TrustDomain)))
	srv.Start()
	srv.URL = "https://" + srv.Listener.Addr().String()
	t.Cleanup(srv.Close)
	return srv, &clientID
}

func TestGetOverSPIFFEMTLS(t *testing.T) {
	ca := spiffetest.NewCA(t, "cracha.test")
	for name, want := range map[string]string{
		"full ID": "spiffe://cracha.test" + brokerPath,
		"path":    brokerPath,
	} {
		t.Run(name, func(t *testing.T) {
			srv, clientID := fakeBroker(t, ca, brokerPath)
			c, err := New(Config{URL: srv.URL + "/", SPIFFEID: want}, ca.NewSource(t, agentPath))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := c.Get(context.Background(), "/v1/credentials", "tok.en")
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK || string(body) != "/v1/credentials tok.en" {
				t.Fatalf("got %d %q", resp.StatusCode, body)
			}
			if resp.Header.Get("Cracha-Shape") != "shape-x" {
				t.Error("the broker's headers did not come through")
			}
			if clientID.String() != "spiffe://cracha.test"+agentPath {
				t.Errorf("the broker saw client %q, want the agent's SVID", clientID)
			}
		})
	}
}

func TestGetRefusesAnotherIdentity(t *testing.T) {
	ca := spiffetest.NewCA(t, "cracha.test")
	srv, _ := fakeBroker(t, ca, "/ns/apps/sa/impostor")
	for name, want := range map[string]string{
		"full ID": "spiffe://cracha.test" + brokerPath,
		"path":    brokerPath,
	} {
		t.Run(name, func(t *testing.T) {
			c, err := New(Config{URL: srv.URL, SPIFFEID: want}, ca.NewSource(t, agentPath))
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.Get(context.Background(), "/v1/credentials", "tok.en")
			if err == nil || !strings.Contains(err.Error(), "impostor") {
				t.Fatalf("Get = %v, want a refusal naming the presented ID", err)
			}
		})
	}
}

func TestGetWithoutIdentityYet(t *testing.T) {
	ca := spiffetest.NewCA(t, "cracha.test")
	srv, _ := fakeBroker(t, ca, brokerPath)
	c, err := New(Config{URL: srv.URL, SPIFFEID: brokerPath}, &spiffetest.Source{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(context.Background(), "/v1/credentials", "tok.en"); err == nil {
		t.Fatal("Get succeeded without an SVID")
	}
}

func TestNewRefusesBadConfig(t *testing.T) {
	ca := spiffetest.NewCA(t, "cracha.test")
	src := ca.NewSource(t, agentPath)
	for name, cfg := range map[string]Config{
		"no URL":         {SPIFFEID: brokerPath},
		"http URL":       {URL: "http://broker:8443", SPIFFEID: brokerPath},
		"query":          {URL: "https://broker:8443/?x=1", SPIFFEID: brokerPath},
		"no SPIFFE ID":   {URL: "https://broker:8443"},
		"bad SPIFFE ID":  {URL: "https://broker:8443", SPIFFEID: "spiffe://"},
		"bad path":       {URL: "https://broker:8443", SPIFFEID: "/ns//x"},
		"not an ID/path": {URL: "https://broker:8443", SPIFFEID: "cracha-broker"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(cfg, src); err == nil {
				t.Fatalf("New(%+v) succeeded", cfg)
			}
		})
	}
	if _, err := New(Config{URL: "https://broker:8443", SPIFFEID: brokerPath}, nil); err == nil {
		t.Fatal("New without a source succeeded")
	}
	c, err := New(Config{URL: "https://broker:8443/base/", SPIFFEID: brokerPath}, src)
	if err != nil {
		t.Fatal(err)
	}
	if c.URL() != "https://broker:8443/base" {
		t.Errorf("URL = %q", c.URL())
	}
}
