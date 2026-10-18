package enrol

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/bpalermo/cracha/agent/enrolapi"
	"github.com/bpalermo/cracha/agent/internal/cri"
	"github.com/bpalermo/cracha/agent/internal/listener"
	"github.com/bpalermo/cracha/agent/internal/serve"
	"github.com/bpalermo/cracha/agent/internal/tokenreview"
)

// Defaults of ServerConfig.
const (
	DefaultRate  = rate.Limit(1) // enrolments per second, per pod
	DefaultBurst = 5
	// The endpoint-wide bound, applied before the token is reviewed: the
	// per-pod limit is keyed on what the TokenReview says, so without this
	// a flood of garbage bearers would cost one TokenReview each. A node
	// enrols pods at kubelet's pace, far below it.
	DefaultGlobalRate  = rate.Limit(50)
	DefaultGlobalBurst = 100
	// limiterTTL is how long an idle pod's limiter is kept.
	limiterTTL = 5 * time.Minute
)

// ServerConfig tunes the init-mode endpoint.
type ServerConfig struct {
	// Port is the loopback listener's port, acknowledged to the init
	// container so it can confirm the bind.
	Port int
	// Rate and Burst bound enrolments per pod UID; the defaults when zero.
	Rate  rate.Limit
	Burst int
	// GlobalRate and GlobalBurst bound requests to the endpoint as a whole,
	// before any token is reviewed; the defaults when zero.
	GlobalRate  rate.Limit
	GlobalBurst int
	// Logger; the default logger when nil.
	Logger *slog.Logger
}

// Server is the init-mode enrolment endpoint of design 7.2, an http.Handler
// for POST /v1/enrol on the node's address. It accepts nothing without a
// bound token the TokenReview verifies for the agent's audience, answers
// only enrol, and is rate-limited per pod UID.
type Server struct {
	reviewer tokenreview.Reviewer
	enroller *Enroller
	resolver cri.Resolver
	cfg      ServerConfig

	global *rate.Limiter

	mu       sync.Mutex
	limiters map[string]*limiter
	now      func() time.Time
}

type limiter struct {
	*rate.Limiter
	seen time.Time
}

// NewServer returns the endpoint.
func NewServer(reviewer tokenreview.Reviewer, enroller *Enroller, resolver cri.Resolver, cfg ServerConfig) *Server {
	if cfg.Rate <= 0 {
		cfg.Rate = DefaultRate
	}
	if cfg.Burst <= 0 {
		cfg.Burst = DefaultBurst
	}
	if cfg.GlobalRate <= 0 {
		cfg.GlobalRate = DefaultGlobalRate
	}
	if cfg.GlobalBurst <= 0 {
		cfg.GlobalBurst = DefaultGlobalBurst
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Server{
		reviewer: reviewer, enroller: enroller, resolver: resolver, cfg: cfg,
		global:   rate.NewLimiter(cfg.GlobalRate, cfg.GlobalBurst),
		limiters: map[string]*limiter{}, now: time.Now,
	}
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != enrolapi.Path {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	token, ok := bearer(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="cracha-agent"`)
		http.Error(w, "a bearer token is required", http.StatusUnauthorized)
		return
	}
	if !s.global.AllowN(s.now(), 1) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "too many enrolments", http.StatusTooManyRequests)
		return
	}
	status, ref, err := s.enrol(r.Context(), token)
	log := s.cfg.Logger.With("pod", ref.String(), "status", status)
	if err != nil {
		log.Warn("enrolment refused", "error", err)
		http.Error(w, err.Error(), status)
		return
	}
	log.Info("enrolled")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(enrolapi.Response{Port: s.cfg.Port})
}

// enrol is the decision: the status to answer, the pod the token named (as
// far as it was learnt) and the refusal, if any.
func (s *Server) enrol(ctx context.Context, token string) (int, listener.Pod, error) {
	res, err := s.reviewer.Review(ctx, token, enrolapi.Audience)
	if err != nil {
		return http.StatusUnauthorized, listener.Pod{}, err
	}
	ref := listener.Pod{Namespace: res.Namespace(), Name: res.PodName, UID: res.PodUID}
	if ref.Namespace == "" || ref.Name == "" || ref.UID == "" {
		return http.StatusUnauthorized, ref, errors.New("the token is not bound to a pod")
	}
	if !s.allow(ref.UID) {
		return http.StatusTooManyRequests, ref, errors.New("too many enrolments for this pod")
	}
	if _, err := s.enroller.Lookup(ctx, ref); err != nil {
		if Refused(err) {
			return http.StatusForbidden, ref, err
		}
		return http.StatusServiceUnavailable, ref, err
	}
	netns, err := s.resolver.NetnsPath(ctx, ref.UID)
	switch {
	case errors.Is(err, cri.ErrNoSandbox), errors.Is(err, cri.ErrHostNetwork):
		// Not on this node, or nothing to bind in: refused, not retried.
		return http.StatusForbidden, ref, err
	case err != nil:
		return http.StatusServiceUnavailable, ref, err
	}
	if err := s.enroller.registry.Bind(ref, netns); err != nil {
		return http.StatusServiceUnavailable, ref, err
	}
	return http.StatusOK, ref, nil
}

// bearer takes the token out of the Authorization header.
func bearer(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
		return "", false
	}
	return strings.TrimSpace(token), true
}

// allow applies the per-pod rate limit, dropping idle limiters as it goes.
func (s *Server) allow(uid string) bool {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, l := range s.limiters {
		if now.Sub(l.seen) > limiterTTL {
			delete(s.limiters, k)
		}
	}
	l, ok := s.limiters[uid]
	if !ok {
		l = &limiter{Limiter: rate.NewLimiter(s.cfg.Rate, s.cfg.Burst)}
		s.limiters[uid] = l
	}
	l.seen = now
	return l.AllowN(now, 1)
}

// Serve runs the endpoint on addr (the node's address and agent.enrolPort,
// in the host network) until ctx is done.
func Serve(ctx context.Context, addr string, handler http.Handler, log *slog.Logger) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	return serve.Run(ctx, srv, srv.ListenAndServe, "enrolment endpoint "+addr, log)
}
