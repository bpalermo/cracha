// Package server is the webhook's HTTPS front: it decodes AdmissionReview
// requests on /mutate, hands them to an Admitter and encodes the answer,
// and serves /healthz and /readyz.
//
// The apiserver speaks admission.k8s.io/v1 to it; that is the only version
// accepted, so the webhook configuration must list admissionReviewVersions
// [v1]. Any non-200 answer (too large, not JSON, not a review) is a webhook
// failure to the apiserver, resolved by the configuration's failurePolicy.
//
// TLS is mandatory and comes in as a *tls.Config: the binary builds it from
// its X.509-SVID source (go-spiffe's tlsconfig.TLSServerConfig, design
// 7.5), which serves the current SVID to every handshake and so follows the
// Workload API's rotation. The server only insists on TLS 1.2 or later.
//
// Told to stop, the server drains before it shuts down (Serve): readiness
// goes false at once, the requests of the next Drain are still answered,
// each with Connection: close, and only then is the listener closed.
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
	"sync/atomic"
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
	// TLS is the serving configuration. It is cloned, and its MinVersion
	// raised to TLS 1.2 when lower.
	TLS *tls.Config
	// MaxRequestBytes bounds the size of a request body. Zero means
	// DefaultMaxRequestBytes.
	MaxRequestBytes int64
	// Ready, when set, is consulted by /readyz: an error makes the server
	// report not ready with the error's text. While the server drains,
	// /readyz reports not ready without consulting it.
	Ready func(ctx context.Context) error
	// Drain is how long the server keeps serving after its context is done,
	// reporting not ready and asking every client to close its connection
	// after the response, before it shuts down: the time the endpoints
	// controller and kube-proxy take to stop sending it new connections once
	// the pod is not ready, so that no apiserver is left with a connection
	// to a webhook that is gone. Zero means no drain.
	Drain time.Duration
	// ShutdownTimeout bounds how long shutdown waits for the requests in
	// flight after the drain. Zero means DefaultShutdownTimeout.
	ShutdownTimeout time.Duration
	// IdleTimeout is how long a keep-alive connection may sit idle before
	// the server closes it. It is kept under Drain, so that every idle
	// connection the apiserver holds to a draining webhook is closed by the
	// webhook, gracefully, before it stops. Zero means DefaultIdleTimeout.
	IdleTimeout time.Duration
	// Logger receives one record per admission. Nil means slog.Default().
	Logger *slog.Logger
}

// Defaults for the zero values of Config.
const (
	// DefaultMaxRequestBytes is comfortably above the apiserver's own limit
	// on a pod, which an AdmissionReview carries once (twice on UPDATE).
	DefaultMaxRequestBytes = 8 << 20
	DefaultShutdownTimeout = 10 * time.Second
	// DefaultIdleTimeout is under the binary's default drain of 5s: an
	// apiserver's idle connection is closed, and reopened to another
	// webhook, before the draining one stops. HTTP/2 connections get a
	// GOAWAY first.
	DefaultIdleTimeout = 3 * time.Second
)

const admissionReviewAPIVersion = "admission.k8s.io/v1"

// Server serves the webhook.
type Server struct {
	cfg      Config
	admitter Admitter
	log      *slog.Logger
	tls      *tls.Config
	handler  http.Handler
	// draining is set when the context Serve was given ends, and never
	// cleared: /readyz then answers 503 and every response asks the
	// client to close the connection.
	draining atomic.Bool
}

// New validates the configuration and returns the server.
func New(cfg Config, admitter Admitter) (*Server, error) {
	if admitter == nil {
		return nil, errors.New("admitter must be set")
	}
	if cfg.Listen == "" {
		return nil, errors.New("listen address must be set")
	}
	if cfg.TLS == nil {
		return nil, errors.New("TLS configuration must be set")
	}
	if cfg.MaxRequestBytes <= 0 {
		cfg.MaxRequestBytes = DefaultMaxRequestBytes
	}
	if cfg.ShutdownTimeout <= 0 {
		cfg.ShutdownTimeout = DefaultShutdownTimeout
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = DefaultIdleTimeout
	}
	if cfg.Drain < 0 {
		cfg.Drain = 0
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	tlsConfig := cfg.TLS.Clone()
	if tlsConfig.MinVersion < tls.VersionTLS12 {
		tlsConfig.MinVersion = tls.VersionTLS12
	}
	s := &Server{cfg: cfg, admitter: admitter, log: cfg.Logger, tls: tlsConfig}
	mux := http.NewServeMux()
	mux.HandleFunc("/mutate", s.handleMutate)
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)
	s.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// While draining, every response asks the client to open its next
		// connection elsewhere: a plain close on HTTP/1.1, a GOAWAY on
		// HTTP/2 (which is what the apiserver speaks).
		if s.draining.Load() {
			w.Header().Set("Connection", "close")
		}
		mux.ServeHTTP(w, r)
	})
	return s, nil
}

// Draining reports whether the server has been told to stop: it is
// reporting not ready and closing the connections of the requests it still
// answers.
func (s *Server) Draining() bool { return s.draining.Load() }

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

// Serve serves TLS on ln until ctx is done. It then drains: readiness goes
// false at once, requests are answered as before for Drain, each with
// Connection: close, and only then is the listener closed and the
// requests still in flight waited for, up to ShutdownTimeout. It returns
// nil after a clean shutdown.
//
// The order matters to a rollout (design 7.5): the pod is told to stop and
// taken out of the Service's endpoints at the same time, and an apiserver
// that has not seen the removal yet keeps sending to the pod. A webhook
// that stopped at once would leave such an apiserver holding a connection
// to nothing, which hangs until the apiserver's own timeout fails the pod
// closed. The drain keeps answering while the removal propagates, and
// closes every connection of its own accord before it goes.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	// The requests' context ends when the server has stopped, not when ctx
	// does: an admission in flight at that moment, and the ones of the
	// drain, are still looked up and answered.
	requests, stopRequests := context.WithCancel(context.WithoutCancel(ctx))
	defer stopRequests()
	srv := &http.Server{
		Addr:      s.cfg.Listen,
		Handler:   s.handler,
		TLSConfig: s.tls,
		// The apiserver gives a webhook at most 30s; these bound a slow or
		// stalled client without getting in the way of that.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       s.cfg.IdleTimeout,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
		BaseContext:       func(net.Listener) context.Context { return requests },
	}

	s.log.Info("serving", "listen", ln.Addr().String())

	served := make(chan error, 1)
	go func() { served <- srv.ServeTLS(ln, "", "") }()

	select {
	case err := <-served:
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}

	s.draining.Store(true)
	s.log.Info("draining: not ready, still serving", "drain", s.cfg.Drain)
	select {
	case err := <-served:
		return fmt.Errorf("serve: %w", err)
	case <-time.After(s.cfg.Drain):
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
	if s.draining.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintln(w, "not ready: draining")
		return
	}
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
