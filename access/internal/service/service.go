// Package service is cracha-access's write path (docs/design.md, section
// 6.9): the one writer of the authorization relationships of a SpiceDB
// install. Every write is authorized in SpiceDB (the caller's workload
// holds manage on the target), bounded in time as configured, checked by
// package check against the current signed bundle and the relationships
// held now, put up for approval when the target is sensitive, and logged
// whatever the outcome.
package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/bpalermo/cracha/access/internal/api"
	"github.com/bpalermo/cracha/access/internal/audit"
	"github.com/bpalermo/cracha/access/internal/check"
	"github.com/bpalermo/cracha/access/internal/store"
	"github.com/bpalermo/cracha/common/grant"
	"github.com/bpalermo/cracha/common/idenc"
)

// Reason codes of a refusal that is not the safeguards' (check's codes
// are the broker's).
const (
	ReasonInvalid            = "invalid"
	ReasonUnauthorizedClient = "unauthorized_client"
	ReasonNotAuthorized      = "not_authorized"
	ReasonSelfApproval       = "self_approval"
	ReasonExpiryRequired     = "expiry_required"
	ReasonExpiryOverCap      = "expiry_over_cap"
	ReasonExpiryPast         = "expiry_past"
	ReasonNotFound           = "not_found"
	ReasonExpired            = "expired"
	ReasonUnavailable        = "unavailable"
)

// Defaults of Config.
const (
	DefaultBreakGlassMax = 4 * time.Hour
	DefaultPendingTTL    = 72 * time.Hour
)

// Config is the service's policy.
type Config struct {
	// Labels are the trust domains' short labels, which a caller's
	// workload encoding starts with (design 4.3).
	Labels idenc.Labels
	// BreakGlassMax caps a break-glass write's expiresAt from now.
	BreakGlassMax time.Duration
	// MaxExpiry, per target kind, makes expiresAt required on a write of
	// that kind and caps it from now; a kind not in it takes writes with
	// or without one.
	MaxExpiry map[string]time.Duration
	// PendingTTL is how long a pending request waits for an approval.
	PendingTTL time.Duration
	// Checker runs the safeguards.
	Checker check.Checker
}

// Bundles is the current signed bundle: the poller of common/publication.
type Bundles interface {
	// Bundle is the bundle in service, nil before one has verified.
	Bundle() *grant.Bundle
}

// Service implements api.Server.
type Service struct {
	cfg     Config
	store   *store.Store
	bundles Bundles
	audit   *audit.Log
	now     func() time.Time

	// mu serializes the writes, so the relationships a write is checked
	// against are the ones it is applied to: cracha-access runs one
	// replica and is SpiceDB's only writer.
	mu sync.Mutex
}

// New makes the service.
func New(cfg Config, st *store.Store, bundles Bundles, log *audit.Log) *Service {
	if cfg.BreakGlassMax <= 0 {
		cfg.BreakGlassMax = DefaultBreakGlassMax
	}
	if cfg.PendingTTL <= 0 {
		cfg.PendingTTL = DefaultPendingTTL
	}
	return &Service{cfg: cfg, store: st, bundles: bundles, audit: log, now: time.Now}
}

// SetClock replaces the clock, for tests.
func (s *Service) SetClock(now func() time.Time) { s.now = now }

var _ api.Server = (*Service)(nil)

// caller is who made the request: the SPIFFE ID the transport verified
// and the workload it is in the store.
type caller struct {
	id       string
	workload string
}

func (s *Service) caller(ctx context.Context) (caller, error) {
	id, ok := api.CallerFrom(ctx)
	if !ok {
		return caller{}, api.Refuse(codes.Unauthenticated, ReasonUnauthorizedClient, "no SPIFFE ID on the connection")
	}
	ident, err := idenc.FromID(id)
	if err != nil {
		return caller{}, api.Refuse(codes.PermissionDenied, ReasonUnauthorizedClient, "%s: %v", id, err)
	}
	enc, err := idenc.Authz(ident, s.cfg.Labels)
	if err != nil {
		return caller{}, api.Refuse(codes.PermissionDenied, ReasonUnauthorizedClient, "%s: %v", id, err)
	}
	return caller{id: id.String(), workload: enc}, nil
}

// authorize refuses unless the caller holds the permission on the tuple's
// target.
func (s *Service) authorize(ctx context.Context, c caller, permission string, t store.Tuple) error {
	id, err := t.TargetID()
	if err != nil {
		return api.Refuse(codes.InvalidArgument, ReasonInvalid, "%v", err)
	}
	ok, err := s.store.Holds(ctx, permission, t.Kind, id, c.workload)
	if err != nil {
		return err
	}
	if !ok {
		return api.Refuse(codes.PermissionDenied, ReasonNotAuthorized, "%s (workload %s) does not hold %s on %s:%s", c.id, c.workload, permission, t.Kind, t.Name)
	}
	return nil
}

// checkExpiry applies the expiry rules: a break-glass write, and a write
// of a kind with a configured maximum, needs expiresAt within its cap; any
// expiresAt must be in the future.
func (s *Service) checkExpiry(t store.Tuple, breakGlass bool, now time.Time) error {
	limit, capped := s.cfg.MaxExpiry[t.Kind]
	if breakGlass && (!capped || s.cfg.BreakGlassMax < limit) {
		limit, capped = s.cfg.BreakGlassMax, true
	}
	if t.ExpiresAt == "" {
		if capped {
			return api.Refuse(codes.InvalidArgument, ReasonExpiryRequired, "a %s needs expiresAt, at most %s from now", writeKind(t, breakGlass), limit)
		}
		return nil
	}
	exp, err := time.Parse(time.RFC3339, t.ExpiresAt)
	if err != nil {
		return api.Refuse(codes.InvalidArgument, ReasonInvalid, "expiresAt: %v", err)
	}
	if !exp.After(now) {
		return api.Refuse(codes.InvalidArgument, ReasonExpiryPast, "expiresAt %s is not in the future", t.ExpiresAt)
	}
	if capped && exp.After(now.Add(limit)) {
		return api.Refuse(codes.InvalidArgument, ReasonExpiryOverCap, "expiresAt %s is over %s from now, the cap of a %s", t.ExpiresAt, limit, writeKind(t, breakGlass))
	}
	return nil
}

func writeKind(t store.Tuple, breakGlass bool) string {
	if breakGlass {
		return "break-glass write"
	}
	return "write of a " + t.Kind
}

// bundle is the bundle in service, or a refusal: nothing is checked, so
// nothing is written, before one has verified.
func (s *Service) bundle() (*grant.Bundle, error) {
	b := s.bundles.Bundle()
	if b == nil {
		return nil, api.Refuse(codes.Unavailable, ReasonUnavailable, "no grant bundle has verified yet")
	}
	return b, nil
}

// status turns an error into what the caller gets: a refusal as it is, a
// safeguard's refusal as FailedPrecondition with its code, anything else
// (SpiceDB, Access Analyzer unreachable) as unavailable.
func status(err error) error {
	var r *api.Refusal
	if errors.As(err, &r) {
		return r
	}
	var cr *check.Refusal
	if errors.As(err, &cr) {
		return api.Refuse(codes.FailedPrecondition, cr.Reason, "%s", cr.Detail)
	}
	return api.Refuse(codes.Unavailable, ReasonUnavailable, "%v", err)
}

// refused logs a refusal and returns what the caller gets.
func (s *Service) refused(ctx context.Context, ev audit.Event, err error) error {
	out := status(err)
	var r *api.Refusal
	errors.As(out, &r)
	ev.Event, ev.Code, ev.Detail = audit.EventRefusal, r.Reason, r.Detail
	s.audit.Write(ctx, ev)
	return out
}

// metadata is a write's transaction metadata, which SpiceDB's Watch
// reports with its changes: who and why.
func metadata(ev audit.Event) map[string]any {
	md := map[string]any{"writer": Writer, "operation": ev.Operation, "caller": ev.Caller}
	for k, v := range map[string]string{"requester": ev.Requester, "reason": ev.Reason, "request_id": ev.RequestID} {
		if v != "" {
			md[k] = v
		}
	}
	return md
}

func requireReason(reason string) error {
	if reason == "" {
		return api.Refuse(codes.InvalidArgument, ReasonInvalid, "a reason is required")
	}
	return nil
}

// relString is a tuple's relationship as the audit log shows it.
func relString(t store.Tuple) string {
	r, err := t.Relationship()
	if err != nil {
		return fmt.Sprintf("%s:%s#%s@%s", t.Kind, t.Name, t.Relation, t.Holder())
	}
	return r.String()
}
