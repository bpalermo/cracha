// Package server is the webhook's HTTPS front: it decodes AdmissionReview
// requests on /mutate, hands them to an Admitter and encodes the answer,
// and serves /healthz and /readyz.
//
// The apiserver speaks admission.k8s.io/v1 to it; that is the only version
// accepted, so the webhook configuration must list admissionReviewVersions
// [v1]. Any non-200 answer (too large, not JSON, not a review) is a webhook
// failure to the apiserver, resolved by the configuration's failurePolicy.
//
// TLS is mandatory. The certificate and key are read when the server starts
// and again whenever either file changes on disk, so a renewed certificate
// (cert-manager or otherwise) is picked up without a restart.
package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
)

// Admitter answers one admission request. It is never asked a nil request.
type Admitter interface {
	Admit(ctx context.Context, req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse
}

// Config is the server's settings.
type Config struct {
	// Listen is the TCP address, such as ":8443".
	Listen string
	// CertFile and KeyFile hold the PEM certificate chain and private key.
	CertFile string
	KeyFile  string
	// MaxRequestBytes bounds the size of a request body. Zero means
	// DefaultMaxRequestBytes.
	MaxRequestBytes int64
	// Ready, when set, is consulted by /readyz: an error makes the server
	// report not ready with the error's text.
	Ready func(ctx context.Context) error
	// ShutdownTimeout bounds the drain on shutdown. Zero means
	// DefaultShutdownTimeout.
	ShutdownTimeout time.Duration
	// Logger receives one record per admission. Nil means slog.Default().
	Logger *slog.Logger
}

// Defaults for the zero values of Config.
const (
	// DefaultMaxRequestBytes is comfortably above the apiserver's own limit
	// on a pod, which an AdmissionReview carries once (twice on UPDATE).
	DefaultMaxRequestBytes = 8 << 20
	DefaultShutdownTimeout = 10 * time.Second
)

const admissionReviewAPIVersion = "admission.k8s.io/v1"

// Server serves the webhook.
type Server struct {
	cfg      Config
	admitter Admitter
	log      *slog.Logger
	certs    *certReloader
	handler  http.Handler
}

// New validates the configuration, loads the certificate once so that a bad
// one fails at start, and returns the server.
func New(cfg Config, admitter Admitter) (*Server, error) {
	if admitter == nil {
		return nil, errors.New("admitter must be set")
	}
	if cfg.Listen == "" {
		return nil, errors.New("listen address must be set")
	}
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return nil, errors.New("TLS certificate and key must be set")
	}
	if cfg.MaxRequestBytes <= 0 {
		cfg.MaxRequestBytes = DefaultMaxRequestBytes
	}
	if cfg.ShutdownTimeout <= 0 {
		cfg.ShutdownTimeout = DefaultShutdownTimeout
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	certs, err := newCertReloader(cfg.CertFile, cfg.KeyFile, cfg.Logger)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, admitter: admitter, log: cfg.Logger, certs: certs}
	mux := http.NewServeMux()
	mux.HandleFunc("/mutate", s.handleMutate)
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)
	s.handler = mux
	return s, nil
}

// Handler is the server's routes, for tests.
func (s *Server) Handler() http.Handler { return s.handler }

// Run listens on the configured address and serves until ctx is done.
func (s *Server) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.cfg.Listen, err)
	}
	return s.Serve(ctx, ln)
}

// Serve serves TLS on ln until ctx is done, then drains for at most
// ShutdownTimeout. It returns nil after a clean shutdown.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Addr:    s.cfg.Listen,
		Handler: s.handler,
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: s.certs.getCertificate,
		},
		// The apiserver gives a webhook at most 30s; these bound a slow or
		// stalled client without getting in the way of that.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}

	s.log.Info("serving", "listen", ln.Addr().String())

	served := make(chan error, 1)
	go func() { served <- srv.ServeTLS(ln, "", "") }()

	select {
	case err := <-served:
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}

	s.log.Info("shutting down", "timeout", s.cfg.ShutdownTimeout)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	<-served
	return nil
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w, "GET, HEAD")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, "ok")
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w, "GET, HEAD")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if s.cfg.Ready != nil {
		if err := s.cfg.Ready(r.Context()); err != nil {
			s.log.Warn("not ready", "error", err)
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, "not ready: %v\n", err)
			return
		}
	}
	fmt.Fprintln(w, "ok")
}

func (s *Server) handleMutate(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	if mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mediaType != "application/json" {
		http.Error(w, "content type must be application/json", http.StatusUnsupportedMediaType)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.cfg.MaxRequestBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, fmt.Sprintf("request body larger than %d bytes", s.cfg.MaxRequestBytes), http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "reading the request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	var review admissionv1.AdmissionReview
	if err := json.Unmarshal(body, &review); err != nil {
		http.Error(w, "decoding the AdmissionReview: "+err.Error(), http.StatusBadRequest)
		return
	}
	if review.APIVersion != admissionReviewAPIVersion || review.Kind != "AdmissionReview" {
		http.Error(w, fmt.Sprintf("want an %s AdmissionReview, got %s %s", admissionReviewAPIVersion, review.APIVersion, review.Kind), http.StatusBadRequest)
		return
	}
	if review.Request == nil {
		http.Error(w, "the AdmissionReview carries no request", http.StatusBadRequest)
		return
	}

	req := review.Request
	resp := s.admitter.Admit(r.Context(), req)
	resp.UID = req.UID

	out, err := json.Marshal(admissionv1.AdmissionReview{TypeMeta: review.TypeMeta, Response: resp})
	if err != nil {
		s.log.Error("encoding the response", "uid", req.UID, "error", err)
		http.Error(w, "encoding the response: "+err.Error(), http.StatusInternalServerError)
		return
	}

	attrs := []any{
		"uid", req.UID,
		"namespace", req.Namespace,
		"name", podName(req),
		"operation", req.Operation,
		"allowed", resp.Allowed,
		"patched", len(resp.Patch) > 0,
		"duration", time.Since(start),
	}
	if !resp.Allowed && resp.Result != nil {
		attrs = append(attrs, "reason", resp.Result.Message)
	}
	s.log.Info("admission", attrs...)

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(out); err != nil {
		s.log.Warn("writing the response", "uid", req.UID, "error", err)
	}
}

// podName is the name the pod will have, or its generateName prefix when the
// name is assigned on create.
func podName(req *admissionv1.AdmissionRequest) string {
	if req.Name != "" {
		return req.Name
	}
	var meta struct {
		Metadata struct {
			Name         string `json:"name"`
			GenerateName string `json:"generateName"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(req.Object.Raw, &meta); err != nil {
		return ""
	}
	if meta.Metadata.Name != "" {
		return meta.Metadata.Name
	}
	return meta.Metadata.GenerateName + "*"
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

// certReloader serves the certificate from CertFile and KeyFile, reading
// them again when either changes on disk. A failed reload keeps the last
// good certificate and is logged, so a half-written renewal cannot take the
// webhook down.
type certReloader struct {
	certFile, keyFile string
	log               *slog.Logger

	mu      sync.Mutex
	cert    *tls.Certificate
	certMod time.Time
	keyMod  time.Time
}

func newCertReloader(certFile, keyFile string, log *slog.Logger) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile, log: log}
	certMod, keyMod, err := r.modTimes()
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading the TLS certificate: %w", err)
	}
	r.cert, r.certMod, r.keyMod = &cert, certMod, keyMod
	return r, nil
}

func (r *certReloader) modTimes() (certMod, keyMod time.Time, err error) {
	certInfo, err := os.Stat(r.certFile)
	if err != nil {
		return certMod, keyMod, fmt.Errorf("TLS certificate: %w", err)
	}
	keyInfo, err := os.Stat(r.keyFile)
	if err != nil {
		return certMod, keyMod, fmt.Errorf("TLS key: %w", err)
	}
	return certInfo.ModTime(), keyInfo.ModTime(), nil
}

func (r *certReloader) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	certMod, keyMod, err := r.modTimes()
	if err != nil {
		r.log.Warn("checking the TLS files, keeping the loaded certificate", "error", err)
		return r.cert, nil
	}
	if certMod.Equal(r.certMod) && keyMod.Equal(r.keyMod) {
		return r.cert, nil
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		r.log.Warn("reloading the TLS certificate, keeping the loaded one", "error", err)
		// Not recorded as seen: the next handshake tries again, which is
		// what a renewal that is still being written needs.
		return r.cert, nil
	}
	r.log.Info("TLS certificate reloaded", "cert", r.certFile)
	r.cert, r.certMod, r.keyMod = &cert, certMod, keyMod
	return r.cert, nil
}
