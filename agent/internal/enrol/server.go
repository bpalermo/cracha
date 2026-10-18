package enrol

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
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
	// The bounds applied before the token is reviewed, since the per-pod
	// limit is keyed on what the review says and a flood of garbage bearers
	// would otherwise cost one TokenReview each: per source address, so one
	// pod's flood holds back that pod alone, and for the endpoint as a
	// whole. A node enrols pods at kubelet's pace, far below either.
	DefaultSourceRate  = rate.Limit(5)
	DefaultSourceBurst = 20
	DefaultGlobalRate  = rate.Limit(50)
	DefaultGlobalBurst = 100
	// limiterTTL is how long an idle key's limiter is kept.
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
	// SourceRate and SourceBurst bound requests per source address, and
	// GlobalRate and GlobalBurst the endpoint as a whole, before any token
	// is reviewed; the defaults when zero.
	SourceRate  rate.Limit
	SourceBurst int
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

	global   *rate.Limiter
	bySource *keyedLimiter
	byPod    *keyedLimiter
	now      func() time.Time
}

// NewServer returns the endpoint.
func NewServer(reviewer tokenreview.Reviewer, enroller *Enroller, resolver cri.Resolver, cfg ServerConfig) *Server {
	if cfg.Rate <= 0 {
		cfg.Rate = DefaultRate
	}
	if cfg.Burst <= 0 {
		cfg.Burst = DefaultBurst
	}
	if cfg.SourceRate <= 0 {
		cfg.SourceRate = DefaultSourceRate
	}
	if cfg.SourceBurst <= 0 {
		cfg.SourceBurst = DefaultSourceBurst
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
		bySource: newKeyedLimiter(cfg.SourceRate, cfg.SourceBurst),
		byPod:    newKeyedLimiter(cfg.Rate, cfg.Burst),
		now:      time.Now,
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
	now := s.now()
	if !s.bySource.allow(sourceOf(r), now) || !s.global.AllowN(now, 1) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "too many enrolments", http.StatusTooManyRequests)
		return
	}
	status, ref, err := s.enrol(r.Context(), token)
	log := s.cfg.Logger.With("pod", ref.String(), "status", status, "source", sourceOf(r))
	if err != nil {
		// The detail stays in the log: the caller is not authenticated.
		log.Warn("enrolment refused", "error", err)
		http.Error(w, answers[status], status)
		return
	}
	log.Info("enrolled")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(enrolapi.Response{Port: s.cfg.Port})
}

// answers is what the caller is told per status; the reason is logged.
var answers = map[int]string{
	http.StatusUnauthorized:        "the token was refused",
	http.StatusForbidden:           "the pod is not enrolled on this node",
	http.StatusTooManyRequests:     "too many enrolments for this pod",
	http.StatusServiceUnavailable:  "enrolment is not possible right now; retry",
	http.StatusInternalServerError: "enrolment failed",
}

// sourceOf is the caller's address, without the port.
func sourceOf(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// enrol is the decision: the status to answer, the pod the token named (as
// far as it was learnt) and the refusal, if any.
func (s *Server) enrol(ctx context.Context, token string) (int, listener.Pod, error) {
	res, err := s.reviewer.Review(ctx, token, enrolapi.Audience)
	if errors.Is(err, tokenreview.ErrUnavailable) {
		// Not a verdict on the token: the caller retries.
		return http.StatusServiceUnavailable, listener.Pod{}, err
	}
	if err != nil {
		return http.StatusUnauthorized, listener.Pod{}, err
	}
	ref := listener.Pod{Namespace: res.Namespace(), Name: res.PodName, UID: res.PodUID}
	if ref.Namespace == "" || ref.Name == "" || ref.UID == "" {
		return http.StatusUnauthorized, ref, errors.New("the token is not bound to a pod")
	}
	if !s.byPod.allow(ref.UID, s.now()) {
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

// keyedLimiter is one rate limiter per key, idle ones dropped as it goes.
type keyedLimiter struct {
	rate  rate.Limit
	burst int
	mu    sync.Mutex
	by    map[string]*limiter
}

type limiter struct {
	*rate.Limiter
	seen time.Time
}

func newKeyedLimiter(r rate.Limit, burst int) *keyedLimiter {
	return &keyedLimiter{rate: r, burst: burst, by: map[string]*limiter{}}
}

// allow applies the key's limit at now.
func (k *keyedLimiter) allow(key string, now time.Time) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	for key, l := range k.by {
		if now.Sub(l.seen) > limiterTTL {
			delete(k.by, key)
		}
	}
	l, ok := k.by[key]
	if !ok {
		l = &limiter{Limiter: rate.NewLimiter(k.rate, k.burst)}
		k.by[key] = l
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
