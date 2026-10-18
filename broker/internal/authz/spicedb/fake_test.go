package spicedb

import (
	"context"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/structpb"
)

// rel is one relationship of the fake, written as zed prints it:
// grant:g#assignee_workload@workload:w, optionally with a caveat and its
// context (expires_at, allowed).
type rel struct {
	resourceType, resourceID, relation, subjectType, subjectID string
	caveat                                                     string
	expiresAt                                                  string
	allowed                                                    []string
}

// parseRel parses "type:id#relation@type:id".
func parseRel(s string) rel {
	res, sub, _ := strings.Cut(s, "@")
	resource, relation, _ := strings.Cut(res, "#")
	rt, rid, _ := strings.Cut(resource, ":")
	st, sid, _ := strings.Cut(sub, ":")
	return rel{resourceType: rt, resourceID: rid, relation: relation, subjectType: st, subjectID: sid}
}

// fakeSpiceDB is an in-memory SpiceDB answering the calls the adapter makes
// over the schema of design 6.4, caveats included: enough to check every
// mapping and to compare answers with the static backend.
type fakeSpiceDB struct {
	// The generated interface's other methods are not implemented; a call
	// to one panics on the nil interface, which is a test failure.
	v1.PermissionsServiceClient

	mu    sync.Mutex
	rels  []rel
	token string
	// err fails every call when set.
	err error
	// Recorded from the last call that carried them.
	lastContext     map[string]string
	lastConsistency *v1.Consistency

	// Watch: the responses delivered, then the stream ends with watchEnd
	// (io.EOF when nil), or blocks until the context ends when watchBlock.
	watchErr       error
	watchResponses []*v1.WatchResponse
	watchEnd       error
	watchBlock     bool
	lastWatch      *v1.WatchRequest
}

func newFake(token string, rels ...rel) *fakeSpiceDB {
	return &fakeSpiceDB{rels: rels, token: token}
}

func (f *fakeSpiceDB) write(rels ...rel) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rels = append(f.rels, rels...)
}

func (f *fakeSpiceDB) zedtoken() *v1.ZedToken {
	return &v1.ZedToken{Token: f.token}
}

func (f *fakeSpiceDB) record(consistency *v1.Consistency, ctx *structpb.Struct) {
	f.lastConsistency = consistency
	if ctx != nil {
		f.lastContext = map[string]string{}
		for k, v := range ctx.GetFields() {
			f.lastContext[k] = v.GetStringValue()
		}
	}
}

// outcome of one caveated relationship against the query context, ordered
// so that max is the union of two paths: a path that holds outright wins
// over one that is conditional, which wins over none.
type outcome int

const (
	denied outcome = iota
	conditional
	allowed
)

// evaluate is the caveat evaluation of the schema's three caveats; a
// missing context value or an unknown caveat is conditional, as in SpiceDB.
func (r rel) evaluate(ctx *structpb.Struct) outcome {
	now, hasNow := ctx.GetFields()[contextNow]
	cluster, hasCluster := ctx.GetFields()[contextCluster]
	window := func() outcome {
		if !hasNow {
			return conditional
		}
		t, err := time.Parse(time.RFC3339, now.GetStringValue())
		exp, err2 := time.Parse(time.RFC3339, r.expiresAt)
		if err != nil || err2 != nil || !t.Before(exp) {
			return denied
		}
		return allowed
	}
	clusters := func() outcome {
		if !hasCluster {
			return conditional
		}
		if slices.Contains(r.allowed, cluster.GetStringValue()) {
			return allowed
		}
		return denied
	}
	switch r.caveat {
	case "":
		return allowed
	case "within_window":
		return window()
	case "in_clusters":
		return clusters()
	case "bounded":
		w, c := window(), clusters()
		switch {
		case w == conditional || c == conditional:
			return conditional
		case w == allowed && c == allowed:
			return allowed
		}
		return denied
	}
	return conditional
}

// assume evaluates grant#assume for a workload: assignee_service->member +
// assignee_workload.
func (f *fakeSpiceDB) assume(grant, workload string, ctx *structpb.Struct) outcome {
	result := denied
	for _, r := range f.rels {
		if r.resourceType != typeGrant || r.resourceID != grant {
			continue
		}
		switch {
		case r.relation == relationAssigneeWorkload && r.subjectID == workload:
		case r.relation == relationAssigneeService && f.member(r.subjectID, workload):
		default:
			continue
		}
		result = max(result, r.evaluate(ctx))
	}
	return result
}

func (f *fakeSpiceDB) member(service, workload string) bool {
	for _, r := range f.rels {
		if r.resourceType == typeService && r.resourceID == service && r.relation == relationMember && r.subjectID == workload {
			return true
		}
	}
	return false
}

func (f *fakeSpiceDB) CheckPermission(_ context.Context, in *v1.CheckPermissionRequest, _ ...grpc.CallOption) (*v1.CheckPermissionResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record(in.GetConsistency(), in.GetContext())
	if f.err != nil {
		return nil, f.err
	}
	resp := &v1.CheckPermissionResponse{CheckedAt: f.zedtoken()}
	switch f.assume(in.GetResource().GetObjectId(), in.GetSubject().GetObject().GetObjectId(), in.GetContext()) {
	case allowed:
		resp.Permissionship = v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION
	case conditional:
		resp.Permissionship = v1.CheckPermissionResponse_PERMISSIONSHIP_CONDITIONAL_PERMISSION
	default:
		resp.Permissionship = v1.CheckPermissionResponse_PERMISSIONSHIP_NO_PERMISSION
	}
	return resp, nil
}

func (f *fakeSpiceDB) LookupResources(ctx context.Context, in *v1.LookupResourcesRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[v1.LookupResourcesResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record(in.GetConsistency(), in.GetContext())
	if f.err != nil {
		return nil, f.err
	}
	var out []*v1.LookupResourcesResponse
	// Every assignment is a result of its own, as SpiceDB's lookup may
	// return a resource more than once.
	for _, r := range f.rels {
		if r.resourceType != typeGrant || (r.relation != relationAssigneeWorkload && r.relation != relationAssigneeService) {
			continue
		}
		resp := &v1.LookupResourcesResponse{LookedUpAt: f.zedtoken(), ResourceObjectId: r.resourceID}
		switch f.assume(r.resourceID, in.GetSubject().GetObject().GetObjectId(), in.GetContext()) {
		case allowed:
			resp.Permissionship = v1.LookupPermissionship_LOOKUP_PERMISSIONSHIP_HAS_PERMISSION
		case conditional:
			resp.Permissionship = v1.LookupPermissionship_LOOKUP_PERMISSIONSHIP_CONDITIONAL_PERMISSION
		default:
			continue
		}
		out = append(out, resp)
	}
	return &fakeStream[v1.LookupResourcesResponse]{ctx: ctx, items: out, end: io.EOF}, nil
}

func (f *fakeSpiceDB) ReadRelationships(ctx context.Context, in *v1.ReadRelationshipsRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[v1.ReadRelationshipsResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record(in.GetConsistency(), nil)
	if f.err != nil {
		return nil, f.err
	}
	filter := in.GetRelationshipFilter()
	var out []*v1.ReadRelationshipsResponse
	for _, r := range f.rels {
		if !r.matches(filter) {
			continue
		}
		out = append(out, &v1.ReadRelationshipsResponse{ReadAt: f.zedtoken(), Relationship: &v1.Relationship{
			Resource: &v1.ObjectReference{ObjectType: r.resourceType, ObjectId: r.resourceID},
			Relation: r.relation,
			Subject:  &v1.SubjectReference{Object: &v1.ObjectReference{ObjectType: r.subjectType, ObjectId: r.subjectID}},
		}})
	}
	return &fakeStream[v1.ReadRelationshipsResponse]{ctx: ctx, items: out, end: io.EOF}, nil
}

func (r rel) matches(f *v1.RelationshipFilter) bool {
	if r.resourceType != f.GetResourceType() {
		return false
	}
	if id := f.GetOptionalResourceId(); id != "" && id != r.resourceID {
		return false
	}
	if rel := f.GetOptionalRelation(); rel != "" && rel != r.relation {
		return false
	}
	sub := f.GetOptionalSubjectFilter()
	if sub == nil {
		return true
	}
	if sub.GetSubjectType() != r.subjectType {
		return false
	}
	return sub.GetOptionalSubjectId() == "" || sub.GetOptionalSubjectId() == r.subjectID
}

func (f *fakeSpiceDB) Watch(ctx context.Context, in *v1.WatchRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[v1.WatchResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastWatch = in
	if f.watchErr != nil {
		return nil, f.watchErr
	}
	end := f.watchEnd
	if end == nil {
		end = io.EOF
	}
	return &fakeStream[v1.WatchResponse]{ctx: ctx, items: f.watchResponses, end: end, block: f.watchBlock}, nil
}

// fakeStream is a server stream delivering items, then end; with block it
// waits for the context instead of ending.
type fakeStream[T any] struct {
	ctx   context.Context
	items []*T
	end   error
	block bool
	next  int
}

func (s *fakeStream[T]) Recv() (*T, error) {
	if s.next < len(s.items) {
		item := s.items[s.next]
		s.next++
		return item, nil
	}
	if s.block {
		<-s.ctx.Done()
		return nil, s.ctx.Err()
	}
	return nil, s.end
}

func (s *fakeStream[T]) Header() (metadata.MD, error) { return nil, nil }
func (s *fakeStream[T]) Trailer() metadata.MD         { return nil }
func (s *fakeStream[T]) CloseSend() error             { return nil }
func (s *fakeStream[T]) Context() context.Context     { return s.ctx }
func (s *fakeStream[T]) SendMsg(any) error            { return nil }
func (s *fakeStream[T]) RecvMsg(any) error            { return nil }

// update is a WatchResponse with one relationship update and a token.
func update(token string, r rel) *v1.WatchResponse {
	return &v1.WatchResponse{
		ChangesThrough: &v1.ZedToken{Token: token},
		Updates: []*v1.RelationshipUpdate{{
			Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &v1.Relationship{
				Resource: &v1.ObjectReference{ObjectType: r.resourceType, ObjectId: r.resourceID},
				Relation: r.relation,
				Subject:  &v1.SubjectReference{Object: &v1.ObjectReference{ObjectType: r.subjectType, ObjectId: r.subjectID}},
			},
		}},
	}
}
