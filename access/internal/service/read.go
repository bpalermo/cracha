package service

import (
	"context"
	"sort"

	"google.golang.org/grpc/codes"

	"github.com/bpalermo/cracha/access/internal/api"
	"github.com/bpalermo/cracha/access/internal/check"
	"github.com/bpalermo/cracha/access/internal/store"
	"github.com/bpalermo/cracha/common/grant"
)

// relationshipOf is a tuple as the API shows it.
func relationshipOf(t store.Tuple) api.Relationship {
	return api.Relationship{
		Subject: t.Subject, Service: t.Service, Resource: api.Resource{Kind: t.Kind, Name: t.Name},
		Relation: t.Relation, ExpiresAt: t.ExpiresAt, Clusters: t.Clusters,
	}
}

// List implements api.Server. Any caller of the trust domain may read.
func (s *Service) List(ctx context.Context, req *api.ListRequest) (*api.ListResponse, error) {
	if _, err := s.caller(ctx); err != nil {
		return nil, status(err)
	}
	match, err := listFilter(req)
	if err != nil {
		return nil, err
	}
	rels, err := s.store.Snapshot(ctx)
	if err != nil {
		return nil, status(err)
	}
	service := ""
	if req.Subject != "" {
		service = check.NewTree(&grant.Bundle{}, rels).ServiceOf(req.Subject)
	}
	out := &api.ListResponse{Relationships: []api.Relationship{}}
	for _, r := range rels {
		if t, ok := store.TupleOf(r); ok && match(t, service) {
			out.Relationships = append(out.Relationships, relationshipOf(t))
		}
	}
	sort.SliceStable(out.Relationships, func(i, j int) bool {
		a, b := out.Relationships[i], out.Relationships[j]
		return a.Resource.Kind+":"+a.Resource.Name < b.Resource.Kind+":"+b.Resource.Name
	})
	return out, nil
}

// listFilter selects the tuples a list request asks for: a workload's own
// and its service's, a service's, or a target's.
func listFilter(req *api.ListRequest) (func(store.Tuple, string) bool, error) {
	n := 0
	for _, set := range []bool{req.Subject != "", req.Service != "", req.Resource != nil} {
		if set {
			n++
		}
	}
	if n != 1 {
		return nil, api.Refuse(codes.InvalidArgument, ReasonInvalid, "give exactly one of subject, service and resource")
	}
	switch {
	case req.Subject != "":
		return func(t store.Tuple, service string) bool {
			return t.Subject == req.Subject || (service != "" && t.Service == service)
		}, nil
	case req.Service != "":
		return func(t store.Tuple, _ string) bool {
			return t.Service == req.Service || (t.IsMembership() && t.Name == req.Service)
		}, nil
	}
	return func(t store.Tuple, _ string) bool { return t.Kind == req.Resource.Kind && t.Name == req.Resource.Name }, nil
}

// Explain implements api.Server: what the workload would be composed of
// now, by the grant tree's composition lint over the current bundle and
// relationships. Any caller of the trust domain may read.
func (s *Service) Explain(ctx context.Context, req *api.ExplainRequest) (*api.ExplainResponse, error) {
	if _, err := s.caller(ctx); err != nil {
		return nil, status(err)
	}
	t := store.Tuple{Kind: grant.ResourceS3Bucket, Name: "explain", Relation: grant.RelationReader, Subject: req.Subject}
	if err := t.Validate(); err != nil {
		return nil, api.Refuse(codes.InvalidArgument, ReasonInvalid, "subject: %v", err)
	}
	b, err := s.bundle()
	if err != nil {
		return nil, err
	}
	rels, err := s.store.Snapshot(ctx)
	if err != nil {
		return nil, status(err)
	}
	tree := check.NewTree(b, rels)
	out := &api.ExplainResponse{Subject: req.Subject, Service: tree.ServiceOf(req.Subject), BundleVersion: b.Version, Compositions: []api.Composition{}}
	for _, c := range tree.Compositions(req.Subject, s.now()) {
		if req.Cluster == "" || c.Cluster == req.Cluster || c.Cluster == "" {
			out.Compositions = append(out.Compositions, compositionOf(c))
		}
	}
	return out, nil
}

func compositionOf(c grant.Composition) api.Composition {
	return api.Composition{
		Cluster: c.Cluster, Grants: c.Grants, Dropped: c.Dropped, Resources: c.Resources, BaseRoles: c.BaseRoles,
		Policy: c.Policy, PolicyChars: c.PolicyChars, ManagedPolicyArns: c.ManagedPolicyArns, SessionTags: c.SessionTags, Problems: c.Problems,
	}
}
