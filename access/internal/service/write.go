package service

import (
	"context"
	"slices"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/bpalermo/cracha/access/internal/api"
	"github.com/bpalermo/cracha/access/internal/audit"
	"github.com/bpalermo/cracha/access/internal/check"
	"github.com/bpalermo/cracha/access/internal/store"
	"github.com/bpalermo/cracha/common/spicedb"
)

// tupleOf is a request's tuple, validated by the grant tree's rules, its
// expiresAt in UTC and its clusters sorted.
func tupleOf(subject, service string, res api.Resource, relation, expiresAt string, clusters []string) (store.Tuple, error) {
	t := store.Tuple{Kind: res.Kind, Name: res.Name, Relation: relation, Subject: subject, Service: service, Clusters: slices.Sorted(slices.Values(clusters))}
	if expiresAt != "" {
		exp, err := time.Parse(time.RFC3339, expiresAt)
		if err != nil {
			return t, api.Refuse(codes.InvalidArgument, ReasonInvalid, "expiresAt: %v", err)
		}
		t.ExpiresAt = exp.UTC().Format(time.RFC3339)
	}
	if len(t.Clusters) == 0 {
		t.Clusters = nil
	}
	if err := t.Validate(); err != nil {
		return t, api.Refuse(codes.InvalidArgument, ReasonInvalid, "%v", err)
	}
	return t, nil
}

// Grant implements api.Server.
func (s *Service) Grant(ctx context.Context, req *api.GrantRequest) (*api.WriteResponse, error) {
	ev := audit.Event{Operation: "grant", Requester: req.Requester, Reason: req.Reason, BreakGlass: req.BreakGlass}
	c, err := s.caller(ctx)
	if err != nil {
		return nil, s.refused(ctx, ev, err)
	}
	ev.Caller = c.id
	t, err := tupleOf(req.Subject, req.Service, req.Resource, req.Relation, req.ExpiresAt, req.Clusters)
	ev.Relationship = relString(t)
	if err != nil {
		return nil, s.refused(ctx, ev, err)
	}
	resp, err := s.grant(ctx, c, t, req.BreakGlass, &ev)
	if err != nil {
		return nil, s.refused(ctx, ev, err)
	}
	return resp, nil
}

// grant authorizes, bounds and checks a write, then puts it up for
// approval or applies it.
func (s *Service) grant(ctx context.Context, c caller, t store.Tuple, breakGlass bool, ev *audit.Event) (*api.WriteResponse, error) {
	if err := requireReason(ev.Reason); err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, c, spicedb.PermissionManage, t); err != nil {
		return nil, err
	}
	now := s.now()
	if err := s.checkExpiry(t, breakGlass, now); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	pre, err := s.precheck(ctx, t, ev)
	if err != nil {
		return nil, err
	}
	sensitive, err := s.sensitive(ctx, t)
	if err != nil {
		return nil, err
	}
	if sensitive && !breakGlass {
		return s.putPending(ctx, c, t, now, ev)
	}
	return s.apply(ctx, t, pre, nil, ev, breakGlass)
}

// checked is a write the safeguards passed: what it replaces and changes.
type checked struct {
	before []string
	result *check.Result
}

// precheck runs the safeguards on adding t, against the bundle and the
// relationships held now.
func (s *Service) precheck(ctx context.Context, t store.Tuple, ev *audit.Event) (checked, error) {
	b, err := s.bundle()
	if err != nil {
		return checked{}, err
	}
	ev.BundleVersion = b.Version
	rels, err := s.store.Snapshot(ctx)
	if err != nil {
		return checked{}, err
	}
	res, err := s.cfg.Checker.Evaluate(ctx, b, rels, check.Change{Add: &t}, s.now())
	if err != nil {
		return checked{}, err
	}
	ev.PolicyDelta = res.Deltas
	return checked{before: held(rels, t), result: res}, nil
}

// held is the relationship rels hold for t's key, as the audit log shows
// it, or nothing.
func held(rels []store.Relationship, t store.Tuple) []string {
	key := t.Key()
	for _, r := range rels {
		if r.Key() == key {
			return []string{r.String()}
		}
	}
	return nil
}

func (s *Service) sensitive(ctx context.Context, t store.Tuple) (bool, error) {
	id, err := t.TargetID()
	if err != nil {
		return false, err
	}
	return s.store.Sensitive(ctx, t.Kind, id)
}

// apply writes t, with extra updates in the same transaction (an approved
// request's deletion), and logs the write.
func (s *Service) apply(ctx context.Context, t store.Tuple, pre checked, extra []store.Update, ev *audit.Event, breakGlass bool) (*api.WriteResponse, error) {
	r, err := t.Relationship()
	if err != nil {
		return nil, err
	}
	token, err := s.store.Write(ctx, append([]store.Update{{Relationship: r}}, extra...), metadata(*ev))
	if err != nil {
		return nil, err
	}
	e := *ev
	e.Event, e.Before, e.After, e.Token = audit.EventWrite, pre.before, []string{r.String()}, token
	if breakGlass {
		s.audit.Warn(ctx, e)
	} else {
		s.audit.Write(ctx, e)
	}
	return &api.WriteResponse{Status: api.StatusApplied, RequestID: ev.RequestID, Relationship: r.String(), Token: token, BundleVersion: ev.BundleVersion, PolicyDelta: ev.PolicyDelta}, nil
}

// putPending records a write on a sensitive target as a pending request.
func (s *Service) putPending(ctx context.Context, c caller, t store.Tuple, now time.Time, ev *audit.Event) (*api.WriteResponse, error) {
	id, err := store.NewPendingID()
	if err != nil {
		return nil, err
	}
	ev.RequestID = id
	p := store.Pending{
		ID: id, Caller: c.id, Requester: ev.Requester, Reason: ev.Reason, Tuple: t,
		CreatedAt: now.UTC().Format(time.RFC3339), ExpiresAt: now.Add(s.cfg.PendingTTL).UTC().Format(time.RFC3339),
	}
	token, err := s.store.PutPending(ctx, p, metadata(*ev))
	if err != nil {
		return nil, err
	}
	e := *ev
	e.Event, e.Token = audit.EventRequest, token
	s.audit.Write(ctx, e)
	return &api.WriteResponse{Status: api.StatusPending, RequestID: id, Relationship: ev.Relationship, Token: token, BundleVersion: ev.BundleVersion, PolicyDelta: ev.PolicyDelta}, nil
}

// Revoke implements api.Server. A revocation narrows, so the safeguards
// never refuse it and a sensitive target needs no approval for it; it
// still needs manage on the target.
func (s *Service) Revoke(ctx context.Context, req *api.RevokeRequest) (*api.WriteResponse, error) {
	ev := audit.Event{Operation: "revoke", Requester: req.Requester, Reason: req.Reason}
	c, err := s.caller(ctx)
	if err != nil {
		return nil, s.refused(ctx, ev, err)
	}
	ev.Caller = c.id
	t, err := tupleOf(req.Subject, req.Service, req.Resource, req.Relation, "", nil)
	ev.Relationship = relString(t)
	if err == nil {
		err = requireReason(req.Reason)
	}
	if err == nil {
		err = s.authorize(ctx, c, spicedb.PermissionManage, t)
	}
	if err != nil {
		return nil, s.refused(ctx, ev, err)
	}
	resp, err := s.revoke(ctx, t, &ev)
	if err != nil {
		return nil, s.refused(ctx, ev, err)
	}
	return resp, nil
}

func (s *Service) revoke(ctx context.Context, t store.Tuple, ev *audit.Event) (*api.WriteResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rels, err := s.store.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	before := held(rels, t)
	if len(before) == 0 {
		return nil, api.Refuse(codes.NotFound, ReasonNotFound, "%s is not held", ev.Relationship)
	}
	if b := s.bundles.Bundle(); b != nil {
		ev.BundleVersion = b.Version
		if res, err := s.cfg.Checker.Evaluate(ctx, b, rels, check.Change{Remove: &t}, s.now()); err == nil {
			ev.PolicyDelta = res.Deltas
		}
	}
	r, _ := t.Relationship()
	token, err := s.store.Write(ctx, []store.Update{{Delete: true, Relationship: r}}, metadata(*ev))
	if err != nil {
		return nil, err
	}
	e := *ev
	e.Event, e.Before, e.Token = audit.EventWrite, before, token
	s.audit.Write(ctx, e)
	return &api.WriteResponse{Status: api.StatusRevoked, Relationship: before[0], Token: token, BundleVersion: ev.BundleVersion, PolicyDelta: ev.PolicyDelta}, nil
}
