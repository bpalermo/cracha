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
//
// Prewarm runs, when a pod's listener is bound, the path its first request
// would take: the JWT-SVID fetch, with a longer budget for the issuer to
// learn of the new pod, and one broker call whose answer is discarded. It
// warms the token cache here and the broker's credential cache (design 6.7),
// so the app's first request is a broker cache hit; it holds no credentials.
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
	"golang.org/x/sync/singleflight"

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
	// joinSlack is how much longer than the fetch deadline a request waits
	// for a fetch already in flight for its pod (a prewarm's, whose budget
	// is longer) before answering 503 itself: the slack lets a fetch the
	// request started give its own answer at its deadline.
	joinSlack = 500 * time.Millisecond
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
	// FetchDeadline is the request's budget for the pod's token (the retry
	// deadline the issuer is wrapped with, agent.fetchDeadline): a request
	// that joins a fetch already in flight waits that long for it, and no
	// longer. issuer.DefaultDeadline when zero.
	FetchDeadline time.Duration
	// PrewarmIssuer is the issuer a prewarm fetches with: the same one,
	// wrapped with the prewarm's longer retry budget. Nil disables prewarm
	// (agent.prewarm false).
	PrewarmIssuer issuer.Issuer
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

	// base is the parent of every prewarm, cancelled by Close.
	base   context.Context
	cancel context.CancelFunc

	mu       sync.Mutex
	tokens   map[string]*cached            // by pod UID
	slots    map[string]chan struct{}      // by pod UID
	prewarms map[string]context.CancelFunc // by pod UID
	// fetches coalesces concurrent fetches for one pod into one call, a
	// prewarm's and the requests' alike.
	fetches singleflight.Group
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
	if cfg.FetchDeadline <= 0 {
		cfg.FetchDeadline = issuer.DefaultDeadline
	}
	base, cancel := context.WithCancel(context.Background())
	return &Handler{
		issuer: iss, broker: broker, cfg: cfg, base: base, cancel: cancel,
		tokens: map[string]*cached{}, slots: map[string]chan struct{}{}, prewarms: map[string]context.CancelFunc{},
	}
}

// Forget drops what the handler holds for the pod: its token and its slots,
// and stops its prewarm. The listener registry calls it when the pod's
// listener closes.
func (h *Handler) Forget(pod listener.Pod) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if cancel, ok := h.prewarms[pod.UID]; ok {
		cancel()
		delete(h.prewarms, pod.UID)
	}
	delete(h.tokens, pod.UID)
	delete(h.slots, pod.UID)
}

// Close stops every prewarm in flight.
func (h *Handler) Close() { h.cancel() }

// Prewarm starts, in the background, what the pod's first request would do:
// fetch its JWT-SVID (retrying, within the prewarm's budget, a pod the
// issuer does not know yet) into the token cache, and call the broker's
// credentials path once, discarding the answer, so that the broker's cache
// holds the pod's session when the app asks. The listener registry calls it
// when it binds a pod's listener; it returns at once. A failure is logged
// and nothing else: the app's own request takes the path as if no prewarm
// had run. A request arriving meanwhile joins the prewarm's fetch rather
// than starting another.
func (h *Handler) Prewarm(pod listener.Pod) { h.startPrewarm(pod) }

// startPrewarm is Prewarm, returning a channel closed when the prewarm is
// done (for tests); nil when prewarm is off.
func (h *Handler) startPrewarm(pod listener.Pod) <-chan struct{} {
	if h.cfg.PrewarmIssuer == nil {
		return nil
	}
	h.mu.Lock()
	if cancel, ok := h.prewarms[pod.UID]; ok {
		cancel()
	}
	ctx, cancel := context.WithCancel(h.base)
	h.prewarms[pod.UID] = cancel
	h.mu.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer cancel()
		h.prewarm(ctx, pod)
	}()
	return done
}

// prewarm is one pod's prewarm, logged as one line like a request.
func (h *Handler) prewarm(ctx context.Context, pod listener.Pod) {
	start := h.cfg.Now()
	out := h.warm(ctx, pod)
	latency := h.cfg.Now().Sub(start).String()
	if out.err != nil {
		h.cfg.Logger.Warn("prewarm failed; the pod's first request will take the whole path", "pod", pod.String(),
			"spiffe_id", out.spiffeID, "latency", latency, "error", out.err)
		return
	}
	h.cfg.Logger.Info("prewarm", "pod", pod.String(), "spiffe_id", out.spiffeID, "status", out.status,
		"cache", out.cache, "latency", latency)
}

// warm fetches the pod's token and asks the broker once. The body is read
// to the end, so the connection is reused, and dropped: the agent never
// holds credentials (design 7.3).
func (h *Handler) warm(ctx context.Context, pod listener.Pod) outcome {
	v, err, _ := h.fetches.Do(pod.UID, func() (any, error) { return h.fetch(ctx, h.cfg.PrewarmIssuer, pod) })
	if err != nil {
		return outcome{err: fmt.Errorf("%s: %w", reasonOf(err), err)}
	}
	tok := v.(*cached)
	out := outcome{spiffeID: tok.id}
	resp, err := h.broker.Get(ctx, CredentialsPath, tok.token)
	if err != nil {
		out.err = fmt.Errorf("%s: %w", ReasonBrokerUnavailable, err)
		return out
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
	out.status, out.cache = resp.StatusCode, resp.Header.Get("Cracha-Cache")
	if resp.StatusCode != http.StatusOK {
		out.err = fmt.Errorf("the broker answered %d (%s)", resp.StatusCode, resp.Header.Get(HeaderReason))
	}
	return out
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
	out := h.serve(w, r, pod)
	h.cfg.Logger.Info("request", "pod", pod.String(), "path", r.URL.Path, "spiffe_id", out.spiffeID,
		"status", out.status, "cache", out.cache, "latency", h.cfg.Now().Sub(start).String(), "error", out.err)
}

// outcome is what one request's log line says: the status sent, the token's
// SPIFFE ID once known, the broker's Cracha-Cache and the error, if the
// agent answered itself.
type outcome struct {
	status   int
	spiffeID string
	cache    string
	err      error
}

// serve answers one request.
func (h *Handler) serve(w http.ResponseWriter, r *http.Request, pod listener.Pod) outcome {
	tok, err := h.token(r.Context(), pod)
	if err != nil {
		reason := reasonOf(err)
		fail(w, reason)
		return outcome{status: http.StatusServiceUnavailable, err: fmt.Errorf("%s: %w", reason, err)}
	}
	out := outcome{spiffeID: tok.id}
	resp, err := h.broker.Get(r.Context(), r.URL.Path, tok.token)
	if err != nil {
		fail(w, ReasonBrokerUnavailable)
		out.status, out.err = http.StatusServiceUnavailable, fmt.Errorf("%s: %w", ReasonBrokerUnavailable, err)
		return out
	}
	defer resp.Body.Close()
	relay(w, resp)
	if _, err := io.Copy(w, io.LimitReader(resp.Body, maxBody)); err != nil {
		h.cfg.Logger.Warn("relaying the broker's body", "pod", pod.String(), "error", err)
	}
	out.status, out.cache = resp.StatusCode, resp.Header.Get("Cracha-Cache")
	return out
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
//
// One fetch per pod at a time: the requests a pod fires together share it,
// and so does a request arriving during the pod's prewarm. The fetch is
// detached from the request that started it, so that one client going away
// does not fail the others (the issuer's retry deadline still bounds it),
// and a request waits for it no longer than the fetch deadline (and a
// slack): past that, a prewarm still waiting for the issuer to learn of the
// pod is the 503 issuer_not_ready the request's own fetch would have been.
func (h *Handler) token(ctx context.Context, pod listener.Pod) (*cached, error) {
	now := h.cfg.Now()
	h.mu.Lock()
	tok, ok := h.tokens[pod.UID]
	h.mu.Unlock()
	if ok && tok.expiry.After(now.Add(refreshBefore)) {
		return tok, nil
	}
	ch := h.fetches.DoChan(pod.UID, func() (any, error) {
		return h.fetch(context.WithoutCancel(ctx), h.issuer, pod)
	})
	wait, cancel := context.WithTimeout(ctx, h.cfg.FetchDeadline+joinSlack)
	defer cancel()
	select {
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		return res.Val.(*cached), nil
	case <-wait.Done():
		return nil, issuer.NewError(issuer.NotFoundYet,
			fmt.Errorf("the pod's JWT-SVID was still being fetched after %s", h.cfg.FetchDeadline))
	}
}

// fetch asks iss and caches the answer, unless ctx was cancelled first: a
// prewarm stopped by Forget leaves nothing behind for a pod that is gone.
func (h *Handler) fetch(ctx context.Context, iss issuer.Issuer, pod listener.Pod) (*cached, error) {
	ref := issuer.PodRef{Namespace: pod.Namespace, Name: pod.Name, UID: pod.UID}
	raw, expiry, err := iss.FetchJWTSVID(ctx, ref, h.cfg.Audience)
	if err != nil {
		return nil, err
	}
	id, err := subjectOf(raw)
	if err != nil {
		return nil, issuer.NewError(issuer.Permanent, err)
	}
	tok := &cached{token: raw, id: id, expiry: expiry}
	h.mu.Lock()
	defer h.mu.Unlock()
	if ctx.Err() != nil {
		return nil, issuer.NewError(issuer.Unavailable, fmt.Errorf("the fetch was stopped: %w", ctx.Err()))
	}
	h.tokens[pod.UID] = tok
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
