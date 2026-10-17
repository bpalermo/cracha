package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

func rawObject(s string) runtime.RawExtension {
	return runtime.RawExtension{Raw: []byte(s)}
}

// echoAdmitter allows everything and remembers the last request.
type echoAdmitter struct{ last *admissionv1.AdmissionRequest }

func (a *echoAdmitter) Admit(_ context.Context, req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	a.last = req
	return &admissionv1.AdmissionResponse{Allowed: true, Warnings: []string{"seen " + req.Name}}
}

// selfSigned writes a fresh self-signed certificate for 127.0.0.1 with the
// given serial to dir, and returns its paths and the certificate.
func selfSigned(t *testing.T, dir string, serial int64) (certFile, keyFile string, cert *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "cracha-webhook"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile = filepath.Join(dir, "tls.crt")
	keyFile = filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile, cert
}

func newServer(t *testing.T, cfg Config, admitter Admitter) *Server {
	t.Helper()
	if cfg.CertFile == "" {
		cfg.CertFile, cfg.KeyFile, _ = selfSigned(t, t.TempDir(), 1)
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:0"
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s, err := New(cfg, admitter)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func review(t *testing.T, uid, name string) []byte {
	t.Helper()
	body, err := json.Marshal(admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request: &admissionv1.AdmissionRequest{
			UID:       types.UID(uid),
			Kind:      metav1.GroupVersionKind{Version: "v1", Kind: "Pod"},
			Operation: admissionv1.Create,
			Namespace: "apps",
			Name:      name,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func post(h http.Handler, contentType string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/mutate", bytes.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestMutate(t *testing.T) {
	admitter := &echoAdmitter{}
	h := newServer(t, Config{}, admitter).Handler()

	rec := post(h, "application/json; charset=utf-8", review(t, "uid-1", "web-1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type %q", ct)
	}
	var out admissionv1.AdmissionReview
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decoding the response %s: %v", rec.Body, err)
	}
	if out.APIVersion != "admission.k8s.io/v1" || out.Kind != "AdmissionReview" {
		t.Errorf("response is %s %s", out.APIVersion, out.Kind)
	}
	if out.Response == nil || out.Response.UID != "uid-1" || !out.Response.Allowed {
		t.Errorf("response %+v", out.Response)
	}
	if admitter.last == nil || admitter.last.Name != "web-1" {
		t.Errorf("the admitter saw %+v", admitter.last)
	}
	if len(out.Response.Warnings) != 1 || out.Response.Warnings[0] != "seen web-1" {
		t.Errorf("warnings %q", out.Response.Warnings)
	}
}

func TestMutateRefusals(t *testing.T) {
	h := newServer(t, Config{MaxRequestBytes: 512}, &echoAdmitter{}).Handler()
	valid := review(t, "uid-1", "web-1")

	tests := []struct {
		name        string
		method      string
		contentType string
		body        []byte
		code        int
	}{
		{"GET", http.MethodGet, "application/json", valid, http.StatusMethodNotAllowed},
		{"PUT", http.MethodPut, "application/json", valid, http.StatusMethodNotAllowed},
		{"no content type", http.MethodPost, "", valid, http.StatusUnsupportedMediaType},
		{"yaml", http.MethodPost, "application/yaml", valid, http.StatusUnsupportedMediaType},
		{"too large", http.MethodPost, "application/json", bytes.Repeat([]byte(" "), 513), http.StatusRequestEntityTooLarge},
		{"not JSON", http.MethodPost, "application/json", []byte("{"), http.StatusBadRequest},
		{"not a review", http.MethodPost, "application/json", []byte(`{"apiVersion":"v1","kind":"Pod"}`), http.StatusBadRequest},
		{
			"v1beta1 review", http.MethodPost, "application/json",
			bytes.Replace(valid, []byte("admission.k8s.io/v1"), []byte("admission.k8s.io/v1beta1"), 1), http.StatusBadRequest,
		},
		{"no request", http.MethodPost, "application/json", []byte(`{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview"}`), http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/mutate", bytes.NewReader(tc.body))
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.code {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.code, rec.Body)
			}
		})
	}
}

func TestHealthAndReadiness(t *testing.T) {
	ready := errors.New("apiserver unreachable")
	h := newServer(t, Config{Ready: func(context.Context) error { return ready }}, &echoAdmitter{}).Handler()

	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}
	if rec := get("/healthz"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "ok") {
		t.Errorf("/healthz: %d %s", rec.Code, rec.Body)
	}
	if rec := get("/readyz"); rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "apiserver unreachable") {
		t.Errorf("/readyz while not ready: %d %s", rec.Code, rec.Body)
	}
	ready = nil
	if rec := get("/readyz"); rec.Code != http.StatusOK {
		t.Errorf("/readyz while ready: %d %s", rec.Code, rec.Body)
	}
	if rec := get("/nope"); rec.Code != http.StatusNotFound {
		t.Errorf("/nope: %d", rec.Code)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/healthz", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /healthz: %d", rec.Code)
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, _ := selfSigned(t, dir, 1)
	for _, tc := range []struct {
		name     string
		cfg      Config
		admitter Admitter
	}{
		{"no admitter", Config{Listen: ":0", CertFile: certFile, KeyFile: keyFile}, nil},
		{"no listen", Config{CertFile: certFile, KeyFile: keyFile}, &echoAdmitter{}},
		{"no key", Config{Listen: ":0", CertFile: certFile}, &echoAdmitter{}},
		{"missing files", Config{Listen: ":0", CertFile: filepath.Join(dir, "nope.crt"), KeyFile: keyFile}, &echoAdmitter{}},
		{"not a certificate", Config{Listen: ":0", CertFile: keyFile, KeyFile: keyFile}, &echoAdmitter{}},
	} {
		if _, err := New(tc.cfg, tc.admitter); err == nil {
			t.Errorf("%s: New succeeded", tc.name)
		}
	}
}

// TestServeTLS serves for real: TLS is on, the certificate is reloaded when
// the files change, and cancelling the context shuts the server down.
func TestServeTLS(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, first := selfSigned(t, dir, 1)
	s := newServer(t, Config{CertFile: certFile, KeyFile: keyFile, ShutdownTimeout: 5 * time.Second}, &echoAdmitter{})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- s.Serve(ctx, ln) }()
	url := "https://" + ln.Addr().String()

	client := func(trust *x509.Certificate) *http.Client {
		pool := x509.NewCertPool()
		pool.AddCert(trust)
		return &http.Client{
			Timeout:   5 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		}
	}

	resp, err := client(first).Post(url+"/mutate", "application/json", bytes.NewReader(review(t, "uid-1", "web-1")))
	if err != nil {
		t.Fatalf("POST over TLS: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}

	// Plain HTTP is refused.
	if resp, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://" + ln.Addr().String() + "/healthz"); err == nil {
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Error("plain HTTP was served")
		}
	}

	// Renew: the new certificate is served to the next handshake. The mtime
	// is pushed forward so a same-second rewrite is still seen as a change.
	_, _, second := selfSigned(t, dir, 2)
	future := time.Now().Add(time.Hour)
	for _, f := range []string{certFile, keyFile} {
		if err := os.Chtimes(f, future, future); err != nil {
			t.Fatal(err)
		}
	}
	resp, err = client(second).Get(url + "/healthz")
	if err != nil {
		t.Fatalf("GET after renewal: %v", err)
	}
	resp.Body.Close()
	if _, err := client(first).Get(url + "/healthz"); err == nil {
		t.Error("the old certificate is still served")
	}

	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return after the context was cancelled")
	}
}

func TestPodName(t *testing.T) {
	for _, tc := range []struct {
		req  admissionv1.AdmissionRequest
		want string
	}{
		{admissionv1.AdmissionRequest{Name: "web-1"}, "web-1"},
		{admissionv1.AdmissionRequest{Object: rawObject(`{"metadata":{"name":"web-2"}}`)}, "web-2"},
		{admissionv1.AdmissionRequest{Object: rawObject(`{"metadata":{"generateName":"web-"}}`)}, "web-*"},
		{admissionv1.AdmissionRequest{Object: rawObject(`{`)}, ""},
	} {
		if got := podName(&tc.req); got != tc.want {
			t.Errorf("podName = %q, want %q", got, tc.want)
		}
	}
}
