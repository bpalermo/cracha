// Package credentials serves the loopback endpoint (docs/design.md,
// sections 7.1 and 7.3): the AWS SDK's GET /v1/credentials (and the
// inspection GET /v1/grants) from inside an enrolled pod, answered with what
// the broker issued for that pod's identity.
//
// The pod is the one of the listener the request arrived on, never anything
// the request says. Its JWT-SVID is fetched from the issuer on demand, kept
// in memory until within a minute of its expiry and dropped with the pod; the
// broker's answer is relayed unchanged (status, body, Cracha-* headers) and
// never cached. An answer the agent had to make itself is a 503 with
// Cracha-Reason.
package credentials

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/bpalermo/cracha/agent/internal/issuer"
	"github.com/bpalermo/cracha/agent/internal/listener"
)

// The paths relayed to the broker (design 6.5). Anything else is 404.
const (
	CredentialsPath = "/v1/credentials"
	GrantsPath      = "/v1/grants"
)

// HeaderReason carries why the agent answered a 503 itself.
const HeaderReason = "Cracha-Reason"

// The reasons.
const (
	// ReasonIssuerNotReady: the issuer does not know the pod yet (its entry
	// has not reached the node's issuer agent) within the fetch deadline.
	ReasonIssuerNotReady = "issuer_not_ready"
	// ReasonIssuerUnavailable: the issuer did not answer within the fetch
	// deadline (its agent is restarting, or the agent's own identity has
	// not been issued yet).
	ReasonIssuerUnavailable = "issuer_unavailable"
	// ReasonIssuerRefused: the issuer refused the pod for good (the access
	// policy, or a pod it cannot resolve as asked). Retrying does not help
	// until the issuer's configuration changes.
	ReasonIssuerRefused = "issuer_refused"
	// ReasonBrokerUnavailable: the broker was unreachable or did not answer
	// in time.
	ReasonBrokerUnavailable = "broker_unavailable"
	// ReasonPodBusy: the pod has more requests in flight than its bound.
	ReasonPodBusy = "pod_busy"
)

// Defaults of Config.
const (
	DefaultAudience    = "cracha-broker"
	DefaultPerPodLimit = 8
	// refreshBefore is how close to its expiry a cached token is replaced.
	refreshBefore = time.Minute
	// maxBody bounds a relayed body; the broker's are a few hundred bytes.
	maxBody = 1 << 20
)

// Relay calls the broker: GET path with the pod's token as the bearer.
type Relay interface {
	Get(ctx context.Context, path, token string) (*http.Response, error)
}

// Config tunes the handler.
type Config struct {
	// Audience of the JWT-SVIDs fetched for pods; DefaultAudience when
	// empty.
	Audience string
	// PerPodLimit bounds a pod's requests in flight; DefaultPerPodLimit when
	// zero.
	PerPodLimit int
	// Logger; the default logger when nil.
	Logger *slog.Logger
	// Now is the clock, for tests.
	Now func() time.Time
}

// Handler is the loopback endpoint's http.Handler.
type Handler struct {
	issuer issuer.Issuer
	broker Relay
	cfg    Config

	mu     sync.Mutex
	tokens map[string]*cached       // by pod UID
	slots  map[string]chan struct{} // by pod UID
}

// cached is a pod's JWT-SVID.
type cached struct {
	token  string
	id     string
	expiry time.Time
}

// New returns a Handler fetching tokens from iss (already wrapped with the
// retry policy of the fetch deadline) and relaying to broker.
func New(iss issuer.Issuer, broker Relay, cfg Config) *Handler {
	if cfg.Audience == "" {
		cfg.Audience = DefaultAudience
	}
	if cfg.PerPodLimit <= 0 {
		cfg.PerPodLimit = DefaultPerPodLimit
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Handler{issuer: iss, broker: broker, cfg: cfg, tokens: map[string]*cached{}, slots: map[string]chan struct{}{}}
}

// Forget drops what the handler holds for the pod: its token and its slots.
// The listener registry calls it when the pod's listener closes.
func (h *Handler) Forget(pod listener.Pod) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.tokens, pod.UID)
	delete(h.slots, pod.UID)
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	pod, ok := listener.PodFromContext(r.Context())
	if !ok {
		// Only a connection from a bound listener reaches this handler; a
		// request without a pod is a wiring error, not a client's.
		h.cfg.Logger.Error("a request arrived on no pod's listener", "path", r.URL.Path)
		http.Error(w, "no pod for this connection", http.StatusInternalServerError)
		return
	}
	if r.Method != http.MethodGet || (r.URL.Path != CredentialsPath && r.URL.Path != GrantsPath) {
		http.NotFound(w, r)
		return
	}
	release, ok := h.acquire(pod.UID)
	if !ok {
		w.Header().Set(HeaderReason, ReasonPodBusy)
		w.Header().Set("Retry-After", "1")
		http.Error(w, "too many requests in flight for this pod", http.StatusTooManyRequests)
		return
	}
	defer release()

	start := h.cfg.Now()
	log := h.cfg.Logger.With("pod", pod.String(), "path", r.URL.Path)
	status, cache, err := h.serve(w, r, pod, log)
	log.Info("request", "status", status, "cache", cache, "latency", h.cfg.Now().Sub(start).String(), "error", err)
}

// serve answers one request and returns what to log: the status sent, the
// broker's Cracha-Cache and the error, if the agent answered itself.
func (h *Handler) serve(w http.ResponseWriter, r *http.Request, pod listener.Pod, log *slog.Logger) (int, string, error) {
	tok, err := h.token(r.Context(), pod)
	if err != nil {
		reason := reasonOf(err)
		fail(w, reason)
		return http.StatusServiceUnavailable, "", fmt.Errorf("%s: %w", reason, err)
	}
	log = log.With("spiffe_id", tok.id)
	resp, err := h.broker.Get(r.Context(), r.URL.Path, tok.token)
	if err != nil {
		fail(w, ReasonBrokerUnavailable)
		return http.StatusServiceUnavailable, "", fmt.Errorf("%s: %w", ReasonBrokerUnavailable, err)
	}
	defer resp.Body.Close()
	relay(w, resp)
	if _, err := io.Copy(w, io.LimitReader(resp.Body, maxBody)); err != nil {
		log.Warn("relaying the broker's body", "error", err)
	}
	return resp.StatusCode, resp.Header.Get("Cracha-Cache"), nil
}

// relay writes the broker's status and headers: every Cracha-* header, and
// the content type and length of the body that follows.
func relay(w http.ResponseWriter, resp *http.Response) {
	for name, values := range resp.Header {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), "Cracha-") ||
			name == "Content-Type" || name == "Content-Length" || name == "Cache-Control" {
			w.Header()[name] = values
		}
	}
	w.WriteHeader(resp.StatusCode)
}

// fail answers a 503 the agent made itself.
func fail(w http.ResponseWriter, reason string) {
	w.Header().Set(HeaderReason, reason)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	fmt.Fprintf(w, "{\"reason\":%q}\n", reason)
}

// reasonOf maps a fetch failure to the Cracha-Reason of the 503.
func reasonOf(err error) string {
	switch issuer.Classify(err) {
	case issuer.NotFoundYet:
		return ReasonIssuerNotReady
	case issuer.Unavailable:
		return ReasonIssuerUnavailable
	default:
		return ReasonIssuerRefused
	}
}

// token returns the pod's JWT-SVID: the cached one while it is more than
// refreshBefore from expiry, else a fresh one from the issuer.
func (h *Handler) token(ctx context.Context, pod listener.Pod) (*cached, error) {
	now := h.cfg.Now()
	h.mu.Lock()
	tok, ok := h.tokens[pod.UID]
	h.mu.Unlock()
	if ok && tok.expiry.After(now.Add(refreshBefore)) {
		return tok, nil
	}
	ref := issuer.PodRef{Namespace: pod.Namespace, Name: pod.Name, UID: pod.UID}
	raw, expiry, err := h.issuer.FetchJWTSVID(ctx, ref, h.cfg.Audience)
	if err != nil {
		return nil, err
	}
	id, err := subjectOf(raw)
	if err != nil {
		return nil, issuer.NewError(issuer.Permanent, err)
	}
	tok = &cached{token: raw, id: id, expiry: expiry}
	h.mu.Lock()
	h.tokens[pod.UID] = tok
	h.mu.Unlock()
	return tok, nil
}

// subjectOf is the token's SPIFFE ID, for the log: the token is not verified
// here (the broker does that), only read, so the subject is taken from the
// claims without any validation.
func subjectOf(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("the issuer returned an unreadable JWT-SVID: not a compact JWS")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("the issuer returned an unreadable JWT-SVID: %w", err)
	}
	var claims struct {
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("the issuer returned an unreadable JWT-SVID: %w", err)
	}
	id, err := spiffeid.FromString(claims.Subject)
	if err != nil {
		return "", fmt.Errorf("the issuer returned a JWT-SVID whose subject is not a SPIFFE ID: %w", err)
	}
	return id.String(), nil
}

// acquire takes one of the pod's slots, or reports that none is free.
func (h *Handler) acquire(uid string) (func(), bool) {
	h.mu.Lock()
	slots, ok := h.slots[uid]
	if !ok {
		slots = make(chan struct{}, h.cfg.PerPodLimit)
		h.slots[uid] = slots
	}
	h.mu.Unlock()
	select {
	case slots <- struct{}{}:
		return func() { <-slots }, true
	default:
		return nil, false
	}
}
