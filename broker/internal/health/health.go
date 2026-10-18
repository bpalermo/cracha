// Package health serves the broker's probes on a plaintext listener of its
// own (--health-listen), apart from the mTLS API: the kubelet cannot
// present an SVID. It serves exactly two paths and nothing else:
//
//	GET /healthz   liveness: the process serves
//	GET /readyz    readiness: every registered check passes (the broker's
//	               X.509-SVID has arrived, the grant bundle has verified)
package health

import (
	"log/slog"
	"net/http"
	"sync"
)

// Readiness is a dependency /readyz consults: an error means the broker
// must not take traffic yet, and says why.
type Readiness interface {
	Ready() error
}

// Handler serves the probes.
type Handler struct {
	log *slog.Logger
	mux *http.ServeMux

	mu    sync.RWMutex
	ready []Readiness
}

// New returns the probe handler. Methods other than GET on the two paths
// get 405; any other path gets 404.
func New(log *slog.Logger) *Handler {
	if log == nil {
		log = slog.Default()
	}
	h := &Handler{log: log, mux: http.NewServeMux()}
	h.mux.HandleFunc("/healthz", getOnly(func(w http.ResponseWriter, _ *http.Request) {
		writeText(w, http.StatusOK, "ok\n")
	}))
	h.mux.HandleFunc("/readyz", getOnly(h.readyz))
	return h
}

// AddReadiness registers a check /readyz consults. Until every registered
// check passes the handler reports not ready; with none registered it is
// ready as soon as it serves.
func (h *Handler) AddReadiness(r Readiness) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ready = append(h.ready, r)
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) readyz(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	checks := h.ready
	h.mu.RUnlock()
	for _, c := range checks {
		if err := c.Ready(); err != nil {
			h.log.LogAttrs(r.Context(), slog.LevelWarn, "not ready", slog.String("error", err.Error()))
			writeText(w, http.StatusServiceUnavailable, "not ready: "+err.Error()+"\n")
			return
		}
	}
	writeText(w, http.StatusOK, "ok\n")
}

// getOnly answers 405 to every method but GET. (A ServeMux "GET" pattern
// would also admit HEAD.)
func getOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeText(w, http.StatusMethodNotAllowed, "method not allowed\n")
			return
		}
		next(w, r)
	}
}

func writeText(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}
