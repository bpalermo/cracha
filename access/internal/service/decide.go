package service

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/bpalermo/cracha/access/internal/api"
	"github.com/bpalermo/cracha/access/internal/audit"
	"github.com/bpalermo/cracha/access/internal/store"
	"github.com/bpalermo/cracha/common/spicedb"
)

// Approve implements api.Server: a caller who holds approve on the
// target, and is not the identity that asked, applies a pending request,
// after the safeguards pass again against the bundle and relationships of
// now. The write and the request's removal are one transaction.
func (s *Service) Approve(ctx context.Context, req *api.DecideRequest) (*api.WriteResponse, error) {
	ev := audit.Event{Operation: "approve", Requester: req.Requester, Reason: req.Reason, RequestID: req.ID}
	resp, err := s.approve(ctx, req, &ev)
	if err != nil {
		return nil, s.refused(ctx, ev, err)
	}
	return resp, nil
}

func (s *Service) approve(ctx context.Context, req *api.DecideRequest, ev *audit.Event) (*api.WriteResponse, error) {
	c, p, err := s.decision(ctx, req, ev)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, c, spicedb.PermissionApprove, p.Tuple); err != nil {
		return nil, err
	}
	if c.id == p.Caller || (req.Requester != "" && req.Requester == p.Requester) {
		return nil, api.Refuse(codes.PermissionDenied, ReasonSelfApproval, "request %s was made by %s (requester %q); another approver must decide it", p.ID, p.Caller, p.Requester)
	}
	if err := s.checkExpiry(p.Tuple, false, s.now()); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	pre, err := s.precheck(ctx, p.Tuple, ev)
	if err != nil {
		return nil, err
	}
	pr, err := store.PendingRelationship(p)
	if err != nil {
		return nil, err
	}
	e := *ev
	e.Event = audit.EventApproval
	s.audit.Write(ctx, e)
	return s.apply(ctx, p.Tuple, pre, []store.Update{{Delete: true, Relationship: pr}}, ev, false)
}

// decision reads the caller and the pending request a decision is about:
// a reason is required, an unknown request is not_found, and an expired
// one is dropped and refused.
func (s *Service) decision(ctx context.Context, req *api.DecideRequest, ev *audit.Event) (caller, store.Pending, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return caller{}, store.Pending{}, err
	}
	ev.Caller = c.id
	if err := requireReason(req.Reason); err != nil {
		return caller{}, store.Pending{}, err
	}
	p, err := s.pending(ctx, req.ID)
	if err != nil {
		return caller{}, store.Pending{}, err
	}
	ev.RequestedBy, ev.Relationship = p.Caller, relString(p.Tuple)
	if p.Expired(s.now()) {
		s.drop(ctx, p)
		return caller{}, store.Pending{}, api.Refuse(codes.FailedPrecondition, ReasonExpired, "request %s expired at %s", p.ID, p.ExpiresAt)
	}
	return c, p, nil
}

func (s *Service) pending(ctx context.Context, id string) (store.Pending, error) {
	if id == "" {
		return store.Pending{}, api.Refuse(codes.InvalidArgument, ReasonInvalid, "a request ID is required")
	}
	ps, err := s.store.ListPending(ctx, id)
	if err != nil {
		return store.Pending{}, err
	}
	if len(ps) == 0 {
		return store.Pending{}, api.Refuse(codes.NotFound, ReasonNotFound, "no pending request %s", id)
	}
	return ps[0], nil
}

// Reject implements api.Server: a caller who holds approve on the target,
// or the identity that asked (withdrawing it), drops a pending request.
func (s *Service) Reject(ctx context.Context, req *api.DecideRequest) (*api.WriteResponse, error) {
	ev := audit.Event{Operation: "reject", Requester: req.Requester, Reason: req.Reason, RequestID: req.ID}
	resp, err := s.reject(ctx, req, &ev)
	if err != nil {
		return nil, s.refused(ctx, ev, err)
	}
	return resp, nil
}

func (s *Service) reject(ctx context.Context, req *api.DecideRequest, ev *audit.Event) (*api.WriteResponse, error) {
	c, p, err := s.decision(ctx, req, ev)
	if err != nil {
		return nil, err
	}
	if c.id != p.Caller {
		if err := s.authorize(ctx, c, spicedb.PermissionApprove, p.Tuple); err != nil {
			return nil, err
		}
	}
	pr, err := store.PendingRelationship(p)
	if err != nil {
		return nil, err
	}
	token, err := s.store.Write(ctx, []store.Update{{Delete: true, Relationship: pr}}, metadata(*ev))
	if err != nil {
		return nil, err
	}
	e := *ev
	e.Event, e.Token = audit.EventRejection, token
	s.audit.Write(ctx, e)
	return &api.WriteResponse{Status: api.StatusRejected, RequestID: p.ID, Relationship: ev.Relationship, Token: token}, nil
}

// drop removes an expired request and logs it.
func (s *Service) drop(ctx context.Context, p store.Pending) {
	ev := audit.Event{Event: audit.EventExpired, RequestID: p.ID, RequestedBy: p.Caller, Requester: p.Requester, Reason: p.Reason, Relationship: relString(p.Tuple)}
	pr, err := store.PendingRelationship(p)
	if err == nil {
		ev.Token, err = s.store.Write(ctx, []store.Update{{Delete: true, Relationship: pr}}, map[string]any{"writer": Writer, "operation": "expire", "request_id": p.ID})
	}
	if err != nil {
		ev.Detail = "not dropped: " + err.Error()
	}
	s.audit.Write(ctx, ev)
}

// Pending implements api.Server: the requests waiting, all or one
// target's, oldest first; expired ones are dropped instead.
func (s *Service) Pending(ctx context.Context, req *api.PendingRequest) (*api.PendingResponse, error) {
	if _, err := s.caller(ctx); err != nil {
		return nil, status(err)
	}
	ps, err := s.store.ListPending(ctx, "")
	if err != nil {
		return nil, status(err)
	}
	out := &api.PendingResponse{Requests: []api.Pending{}}
	now := s.now()
	for _, p := range ps {
		if p.Expired(now) {
			s.drop(ctx, p)
			continue
		}
		if req.Resource != nil && (p.Tuple.Kind != req.Resource.Kind || p.Tuple.Name != req.Resource.Name) {
			continue
		}
		out.Requests = append(out.Requests, api.Pending{
			ID: p.ID, Caller: p.Caller, Requester: p.Requester, Reason: p.Reason,
			Request: relationshipOf(p.Tuple), CreatedAt: p.CreatedAt, ExpiresAt: p.ExpiresAt,
		})
	}
	return out, nil
}

// Expire drops every expired pending request: what RunExpiry does on each
// tick.
func (s *Service) Expire(ctx context.Context) error {
	ps, err := s.store.ListPending(ctx, "")
	if err != nil {
		return err
	}
	now := s.now()
	for _, p := range ps {
		if p.Expired(now) {
			s.drop(ctx, p)
		}
	}
	return nil
}

// RunExpiry drops expired requests every interval until ctx ends.
func (s *Service) RunExpiry(ctx context.Context, interval time.Duration, log *slog.Logger) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := s.Expire(ctx); err != nil {
			log.Warn("dropping expired pending requests", "error", err)
		}
	}
}
