// Package storetest is an in-memory stand-in for the SpiceDB calls
// cracha-access makes, for tests: it holds relationships by identity
// (caveat context whole), filters reads as SpiceDB does on resource type
// and ID, relation and subject, applies writes, answers CheckPermission
// from permissions a test grants, and replays every write's changes to
// Watch. It evaluates no schema.
package storetest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

// Client implements store.Client.
type Client struct {
	mu       sync.Mutex
	rels     map[string]*v1.Relationship
	allowed  map[string]bool
	revision int
	changes  []*v1.WatchResponse

	// Writes are the write requests received, in order.
	Writes []*v1.WriteRelationshipsRequest
	// Checks are the permission checks asked, as "type:id#permission@workload:id".
	Checks []string
	// ReadErr and WriteErr, when set, fail every read or write.
	ReadErr  error
	WriteErr error
}

// New makes a client holding the relationships.
func New(rels ...*v1.Relationship) *Client {
	c := &Client{rels: map[string]*v1.Relationship{}, allowed: map[string]bool{}}
	for _, r := range rels {
		c.rels[Key(r)] = proto.Clone(r).(*v1.Relationship)
	}
	return c
}

// Key is a relationship's identity without its caveat.
func Key(r *v1.Relationship) string {
	k := fmt.Sprintf("%s:%s#%s@%s:%s", r.GetResource().GetObjectType(), r.GetResource().GetObjectId(), r.GetRelation(),
		r.GetSubject().GetObject().GetObjectType(), r.GetSubject().GetObject().GetObjectId())
	if rel := r.GetSubject().GetOptionalRelation(); rel != "" {
		k += "#" + rel
	}
	return k
}

// Allow makes CheckPermission answer yes for the workload's permission on
// the object.
func (c *Client) Allow(permission, objectType, objectID, workload string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.allowed[checkKey(objectType, objectID, permission, workload)] = true
}

func checkKey(objectType, objectID, permission, workload string) string {
	return objectType + ":" + objectID + "#" + permission + "@workload:" + workload
}

// Keys returns the identities of the relationships held, sorted.
func (c *Client) Keys() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	keys := make([]string, 0, len(c.rels))
	for k := range c.rels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Get returns the relationship of that identity, or nil.
func (c *Client) Get(key string) *v1.Relationship {
	c.mu.Lock()
	defer c.mu.Unlock()
	if r, ok := c.rels[key]; ok {
		return proto.Clone(r).(*v1.Relationship)
	}
	return nil
}

func (c *Client) token() string { return fmt.Sprintf("rev-%d", c.revision) }

// ReadRelationships implements store.Client.
func (c *Client) ReadRelationships(_ context.Context, in *v1.ReadRelationshipsRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[v1.ReadRelationshipsResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ReadErr != nil {
		return nil, c.ReadErr
	}
	keys := make([]string, 0, len(c.rels))
	for k := range c.rels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	s := &stream[v1.ReadRelationshipsResponse]{}
	for _, k := range keys {
		if r := c.rels[k]; matches(in.GetRelationshipFilter(), r) {
			s.items = append(s.items, &v1.ReadRelationshipsResponse{ReadAt: &v1.ZedToken{Token: c.token()}, Relationship: proto.Clone(r).(*v1.Relationship)})
		}
	}
	return s, nil
}

func matches(f *v1.RelationshipFilter, r *v1.Relationship) bool {
	switch {
	case f.GetResourceType() != "" && f.GetResourceType() != r.GetResource().GetObjectType():
		return false
	case f.GetOptionalResourceId() != "" && f.GetOptionalResourceId() != r.GetResource().GetObjectId():
		return false
	case f.GetOptionalRelation() != "" && f.GetOptionalRelation() != r.GetRelation():
		return false
	}
	sf := f.GetOptionalSubjectFilter()
	if sf == nil {
		return true
	}
	return sf.GetSubjectType() == r.GetSubject().GetObject().GetObjectType() &&
		(sf.GetOptionalSubjectId() == "" || sf.GetOptionalSubjectId() == r.GetSubject().GetObject().GetObjectId())
}

// WriteRelationships implements store.Client: TOUCH and CREATE set, DELETE
// removes, a CREATE of an existing relationship fails, and the whole
// request applies or nothing does.
func (c *Client) WriteRelationships(_ context.Context, in *v1.WriteRelationshipsRequest, _ ...grpc.CallOption) (*v1.WriteRelationshipsResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Writes = append(c.Writes, proto.Clone(in).(*v1.WriteRelationshipsRequest))
	if c.WriteErr != nil {
		return nil, c.WriteErr
	}
	for _, u := range in.GetUpdates() {
		if _, exists := c.rels[Key(u.GetRelationship())]; exists && u.GetOperation() == v1.RelationshipUpdate_OPERATION_CREATE {
			return nil, fmt.Errorf("storetest: %s already exists", Key(u.GetRelationship()))
		}
	}
	for _, u := range in.GetUpdates() {
		k := Key(u.GetRelationship())
		if u.GetOperation() == v1.RelationshipUpdate_OPERATION_DELETE {
			delete(c.rels, k)
			continue
		}
		c.rels[k] = proto.Clone(u.GetRelationship()).(*v1.Relationship)
	}
	c.revision++
	c.changes = append(c.changes, &v1.WatchResponse{Updates: in.GetUpdates(), ChangesThrough: &v1.ZedToken{Token: c.token()}, OptionalTransactionMetadata: in.GetOptionalTransactionMetadata()})
	return &v1.WriteRelationshipsResponse{WrittenAt: &v1.ZedToken{Token: c.token()}}, nil
}

// CheckPermission implements store.Client from the permissions Allow gave.
func (c *Client) CheckPermission(_ context.Context, in *v1.CheckPermissionRequest, _ ...grpc.CallOption) (*v1.CheckPermissionResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ReadErr != nil {
		return nil, c.ReadErr
	}
	k := checkKey(in.GetResource().GetObjectType(), in.GetResource().GetObjectId(), in.GetPermission(), in.GetSubject().GetObject().GetObjectId())
	c.Checks = append(c.Checks, k)
	p := v1.CheckPermissionResponse_PERMISSIONSHIP_NO_PERMISSION
	if c.allowed[k] {
		p = v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION
	}
	return &v1.CheckPermissionResponse{Permissionship: p, CheckedAt: &v1.ZedToken{Token: c.token()}}, nil
}

// ErrWatchEnd ends every Watch stream once it has replayed the changes.
var ErrWatchEnd = errors.New("storetest: end of recorded changes")

// Watch implements store.Client: it replays the changes of every write
// after the start cursor, filtered by object type, then ends with
// ErrWatchEnd.
func (c *Client) Watch(_ context.Context, in *v1.WatchRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[v1.WatchResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	start := 0
	if t := in.GetOptionalStartCursor().GetToken(); t != "" {
		if _, err := fmt.Sscanf(t, "rev-%d", &start); err != nil {
			return nil, err
		}
	}
	s := &stream[v1.WatchResponse]{end: ErrWatchEnd}
	for _, ch := range c.changes[min(start, len(c.changes)):] {
		s.items = append(s.items, filterTypes(ch, in.GetOptionalObjectTypes()))
	}
	return s, nil
}

func filterTypes(ch *v1.WatchResponse, types []string) *v1.WatchResponse {
	out := &v1.WatchResponse{ChangesThrough: ch.GetChangesThrough(), OptionalTransactionMetadata: ch.GetOptionalTransactionMetadata()}
	for _, u := range ch.GetUpdates() {
		for _, t := range types {
			if u.GetRelationship().GetResource().GetObjectType() == t {
				out.Updates = append(out.Updates, u)
				break
			}
		}
	}
	return out
}

// stream replays recorded responses, then ends with end (io.EOF when nil).
type stream[T any] struct {
	grpc.ClientStream
	items []*T
	next  int
	end   error
}

func (s *stream[T]) Recv() (*T, error) {
	if s.next >= len(s.items) {
		if s.end != nil {
			return nil, s.end
		}
		return nil, io.EOF
	}
	item := s.items[s.next]
	s.next++
	return item, nil
}
