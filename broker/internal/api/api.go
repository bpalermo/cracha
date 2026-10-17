// Package api serves the broker API of docs/design.md, section 6.5:
//
//	GET /v1/credentials   Authorization: <JWT-SVID>  → container-credentials JSON
//	GET /v1/grants        same authorization         → shape, grants, composed policy
//	GET /healthz          liveness: the process serves
//	GET /readyz           readiness: every registered check passes (the
//	                      grant bundle has loaded, say)
//
// The identity in the token selects everything. Nothing else in the request
// is trusted: no proxy-asserted identity header is read, and nothing
// workload-supplied reaches the store or STS.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bpalermo/cracha/broker/internal/grants"
	"github.com/bpalermo/cracha/broker/internal/issuer"
	"github.com/bpalermo/cracha/common/idenc"
)

// Authenticator verifies a JWT-SVID and returns the workload identity.
type Authenticator interface {
	Verify(ctx context.Context, token string) (idenc.Identity, error)
}

// Response headers.
const (
	HeaderShape            = "Cracha-Shape"
	HeaderGrants           = "Cracha-Grants"
	HeaderBundleVersion    = "Cracha-Bundle-Version"
	HeaderConsistencyToken = "Cracha-Consistency-Token"
)

// Reasons beyond the five of section 6.5, for 401 and 503.
const (
	ReasonUnauthenticated = "unauthenticated"
	ReasonUnavailable     = "unavailable"
)

// Readiness is a dependency /readyz consults: an error means the broker
// must not take traffic yet, and says why.
type Readiness interface {
	Ready() error
}

// Handler serves the API.
type Handler struct {
	auth   Authenticator
	issuer issuer.Issuer
	log    *slog.Logger
	mux    *http.ServeMux

	mu    sync.RWMutex
	ready []Readiness
}

// New returns the API handler. Methods other than GET on the API paths get
// 405; unknown paths get 404.
func New(auth Authenticator, iss issuer.Issuer, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.Default()
	}
	h := &Handler{auth: auth, issuer: iss, log: log, mux: http.NewServeMux()}
	h.mux.HandleFunc("/v1/credentials", getOnly(h.credentials))
	h.mux.HandleFunc("/v1/grants", getOnly(h.grants))
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
// would also admit HEAD, and HEAD must not reach STS.)
func getOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeReason(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		next(w, r)
	}
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

// credentialsResponse is the container-credentials format every AWS SDK
// reads from AWS_CONTAINER_CREDENTIALS_FULL_URI.
type credentialsResponse struct {
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
	Expiration      string `json:"Expiration"`
}

func (h *Handler) credentials(w http.ResponseWriter, r *http.Request) {
	id, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	iss, err := h.issuer.Issue(r.Context(), id)
	if err != nil {
		h.deny(w, err)
		return
	}
	setDecisionHeaders(w, iss.Resolution)
	writeJSON(w, http.StatusOK, credentialsResponse{
		AccessKeyID:     iss.Credentials.AccessKeyID,
		SecretAccessKey: iss.Credentials.SecretAccessKey,
		Token:           iss.Credentials.SessionToken,
		Expiration:      iss.Credentials.Expiration.UTC().Format(time.RFC3339),
	})
}

// grantsResponse is what /v1/grants shows the caller about itself.
type grantsResponse struct {
	SPIFFEID          string            `json:"spiffeId"`
	SourceIdentity    string            `json:"sourceIdentity"`
	Subject           string            `json:"subject"`
	Cluster           string            `json:"cluster"`
	Shape             string            `json:"shape"`
	BaseRole          string            `json:"baseRole"`
	Account           string            `json:"account"`
	Grants            []string          `json:"grants"`
	SessionPolicy     json.RawMessage   `json:"sessionPolicy"`
	ManagedPolicyARNs []string          `json:"managedPolicyArns"`
	SessionTags       map[string]string `json:"sessionTags"`
	DurationSeconds   int32             `json:"durationSeconds"`
	BundleVersion     string            `json:"bundleVersion"`
	ConsistencyToken  string            `json:"consistencyToken"`
}

func (h *Handler) grants(w http.ResponseWriter, r *http.Request) {
	id, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	res, err := h.issuer.Resolve(r.Context(), id)
	if err != nil {
		h.deny(w, err)
		return
	}
	policy := json.RawMessage("null")
	if res.Composed.Policy != "" {
		policy = json.RawMessage(res.Composed.Policy)
	}
	setDecisionHeaders(w, res)
	writeJSON(w, http.StatusOK, grantsResponse{
		SPIFFEID:          res.Identity.String(),
		SourceIdentity:    res.SourceIdentity,
		Subject:           res.Subject.ID,
		Cluster:           res.Subject.Cluster,
		Shape:             res.Composed.Shape,
		BaseRole:          res.Composed.BaseRole,
		Account:           res.Composed.Account,
		Grants:            orEmpty(res.Composed.Grants),
		SessionPolicy:     policy,
		ManagedPolicyARNs: orEmpty(res.Composed.ManagedPolicyARNs),
		SessionTags:       res.SessionTags,
		DurationSeconds:   res.Composed.DurationSeconds,
		BundleVersion:     res.BundleVersion,
		ConsistencyToken:  string(res.Decision.Token),
	})
}

// authenticate takes the JWT-SVID from the Authorization header, as the
// SDK sends the token file's contents, with an optional "Bearer " prefix.
// On failure it has written the 401.
func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request) (idenc.Identity, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || strings.TrimSpace(values[0]) == "" {
		writeReason(w, http.StatusUnauthorized, ReasonUnauthenticated)
		return idenc.Identity{}, false
	}
	token := strings.TrimSpace(values[0])
	if len(token) > 7 && strings.EqualFold(token[:7], "bearer ") {
		token = strings.TrimSpace(token[7:])
	}
	id, err := h.auth.Verify(r.Context(), token)
	if err != nil {
		h.log.LogAttrs(r.Context(), slog.LevelWarn, "unauthenticated",
			slog.String("remote", r.RemoteAddr), slog.String("path", r.URL.Path), slog.String("error", err.Error()))
		writeReason(w, http.StatusUnauthorized, ReasonUnauthenticated)
		return idenc.Identity{}, false
	}
	return id, true
}

func (h *Handler) deny(w http.ResponseWriter, err error) {
	var deny *grants.DenyError
	if errors.As(err, &deny) {
		writeReason(w, http.StatusForbidden, string(deny.Reason))
		return
	}
	// Not the caller's doing (store, bundle or STS): still a deny, but one
	// the SDK should retry. The issuer logged the cause.
	writeReason(w, http.StatusServiceUnavailable, ReasonUnavailable)
}

func setDecisionHeaders(w http.ResponseWriter, res issuer.Resolution) {
	h := w.Header()
	h.Set(HeaderShape, res.Composed.Shape)
	h.Set(HeaderGrants, strings.Join(res.Composed.Grants, ", "))
	h.Set(HeaderBundleVersion, res.BundleVersion)
	h.Set(HeaderConsistencyToken, string(res.Decision.Token))
}

func writeText(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func writeReason(w http.ResponseWriter, status int, reason string) {
	writeJSON(w, status, map[string]string{"reason": reason})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
