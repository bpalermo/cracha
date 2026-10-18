// Package api serves the broker API of docs/design.md, section 6.5:
//
//	GET /v1/credentials   Authorization: <JWT-SVID>  → container-credentials JSON
//	GET /v1/grants        same authorization         → shape, grants, composed policy
//
// The identity in the token selects everything. Nothing else in the request
// is trusted: no proxy-asserted identity header is read, and nothing
// workload-supplied reaches the store or STS. The transport is the SPIFFE
// mTLS of broker/internal/mtls, which admits only the node agent; every
// request is logged with the client SVID the TLS layer verified beside the
// token's subject. The probes are served elsewhere (broker/internal/health).
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/bpalermo/cracha/broker/internal/grants"
	"github.com/bpalermo/cracha/broker/internal/issuer"
	"github.com/bpalermo/cracha/broker/internal/mtls"
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
	// HeaderCache says how the credential cache served the credentials:
	// hit, miss or refresh (section 6.7). Absent when the cache is off.
	HeaderCache = "Cracha-Cache"
)

// Reasons beyond the five of section 6.5, for 401 and 503.
const (
	ReasonUnauthenticated = "unauthenticated"
	ReasonUnavailable     = "unavailable"
)

// Handler serves the API.
type Handler struct {
	auth   Authenticator
	issuer issuer.Issuer
	log    *slog.Logger
	mux    *http.ServeMux
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
	return h
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

// ServeHTTP implements http.Handler. Every request is logged once answered,
// with the client SVID the TLS layer verified (design 6.5) beside the
// subject of the token it carried, when one verified.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	entry := &logEntry{}
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	h.mux.ServeHTTP(rec, r.WithContext(context.WithValue(r.Context(), logEntryKey{}, entry)))
	h.log.LogAttrs(r.Context(), slog.LevelInfo, "request",
		slog.String("method", r.Method), slog.String("path", r.URL.Path), slog.Int("status", rec.status),
		slog.String("client", clientID(r)), slog.String("subject", entry.subject),
		slog.Duration("duration", time.Since(start)))
}

// logEntry is what the handlers add to the request's log line: the
// subject of the token, once it verified.
type logEntry struct{ subject string }

type logEntryKey struct{}

// statusRecorder remembers the status a handler wrote, for the log.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(status int) {
	s.status = status
	s.ResponseWriter.WriteHeader(status)
}

// clientID is the SPIFFE ID of the client certificate the TLS layer
// verified, or "" when the request carried none.
func clientID(r *http.Request) string {
	id, ok := mtls.PeerID(r)
	if !ok {
		return ""
	}
	return id.String()
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
	if iss.Cache != "" {
		w.Header().Set(HeaderCache, string(iss.Cache))
	}
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
			slog.String("remote", r.RemoteAddr), slog.String("client", clientID(r)),
			slog.String("path", r.URL.Path), slog.String("error", err.Error()))
		writeReason(w, http.StatusUnauthorized, ReasonUnauthenticated)
		return idenc.Identity{}, false
	}
	if entry, ok := r.Context().Value(logEntryKey{}).(*logEntry); ok {
		entry.subject = id.String()
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
