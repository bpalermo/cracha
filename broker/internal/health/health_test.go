package health

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bpalermo/cracha/broker/internal/mtls"
	"github.com/bpalermo/cracha/broker/internal/mtls/mtlstest"
)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func do(h http.Handler, method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

// readiness is a Readiness check with a settable answer.
type readiness struct{ err error }

func (r *readiness) Ready() error { return r.err }

func TestServesOnlyTheProbes(t *testing.T) {
	h := New(discard())
	if rec := do(h, http.MethodGet, "/healthz"); rec.Code != http.StatusOK || rec.Body.String() != "ok\n" {
		t.Errorf("healthz: %d %q", rec.Code, rec.Body.String())
	}
	if rec := do(h, http.MethodGet, "/readyz"); rec.Code != http.StatusOK || rec.Body.String() != "ok\n" {
		t.Errorf("readyz with no checks: %d %q", rec.Code, rec.Body.String())
	}
	for _, path := range []string{"/", "/v1/credentials", "/v1/grants", "/healthz/", "/metrics"} {
		if rec := do(h, http.MethodGet, path); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s: %d, want 404", path, rec.Code)
		}
	}
	for _, method := range []string{http.MethodHead, http.MethodPost, http.MethodPut, http.MethodDelete} {
		for _, path := range []string{"/healthz", "/readyz"} {
			if rec := do(h, method, path); rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s: %d, want 405", method, path, rec.Code)
			}
		}
	}
}

func TestReadyz(t *testing.T) {
	h := New(discard())
	bundle := &readiness{err: errors.New("no grant bundle loaded yet")}
	h.AddReadiness(bundle)
	h.AddReadiness(&readiness{})
	rec := do(h, http.MethodGet, "/readyz")
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "no grant bundle loaded yet") {
		t.Errorf("readyz while not ready: %d %q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("readiness answer is cacheable")
	}
	// Liveness is unaffected.
	if rec := do(h, http.MethodGet, "/healthz"); rec.Code != http.StatusOK {
		t.Errorf("healthz while not ready: %d", rec.Code)
	}
	bundle.err = nil
	if rec := do(h, http.MethodGet, "/readyz"); rec.Code != http.StatusOK {
		t.Errorf("readyz once ready: %d %q", rec.Code, rec.Body.String())
	}
}

// Readiness waits for the broker's X.509-SVID, as main wires it: the check
// is registered before the Workload API answers, and passes once it has.
func TestReadyzWaitsForSVID(t *testing.T) {
	h := New(discard())
	var svid mtls.SVIDReadiness
	h.AddReadiness(&svid)
	if rec := do(h, http.MethodGet, "/readyz"); rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "X.509-SVID") {
		t.Errorf("readyz before the SVID: %d %q", rec.Code, rec.Body.String())
	}
	svid.Set(mtlstest.NewCA(t, "example.org").SVID(t, "spiffe://example.org/ns/cracha-system/sa/cracha-broker"))
	if rec := do(h, http.MethodGet, "/readyz"); rec.Code != http.StatusOK {
		t.Errorf("readyz with the SVID: %d %q", rec.Code, rec.Body.String())
	}
}

// The probes answer over plain HTTP: the kubelet presents no SVID.
func TestPlaintextListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: New(discard()), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	c := &http.Client{Timeout: 5 * time.Second}
	for path, want := range map[string]int{"/healthz": http.StatusOK, "/readyz": http.StatusOK, "/v1/credentials": http.StatusNotFound} {
		resp, err := c.Get("http://" + ln.Addr().String() + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("GET %s: %d, want %d", path, resp.StatusCode, want)
		}
	}
}
