// Package fakespicedb is an in-memory stand-in for the two SpiceDB gRPC
// services the reconciler calls, for tests: it holds relationships by
// their identity, answers ReadRelationships from them, applies
// WriteRelationships to them, records every call and can be made to fail.
// The methods the reconciler never calls are not implemented and panic.
package fakespicedb

import (
	"context"
	"fmt"
	"io"
	"sort"
	"sync"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

// Client implements v1.PermissionsServiceClient and v1.SchemaServiceClient.
type Client struct {
	v1.PermissionsServiceClient
	v1.SchemaServiceClient

	mu sync.Mutex
	// rels holds the relationships by identity (resource, relation,
	// subject).
	rels map[string]*v1.Relationship
	// revision counts the writes; the zedtoken is "rev-<revision>".
	revision int

	// Schema is the last schema written.
	Schema string
	// Reads and Writes are the requests received, in order.
	Reads  []*v1.ReadRelationshipsRequest
	Writes []*v1.WriteRelationshipsRequest
	// SchemaWrites counts WriteSchema calls.
	SchemaWrites int
	// ReadErr, when set, fails every ReadRelationships.
	ReadErr error
	// FailWrite, when positive, fails the FailWrite-th WriteRelationships
	// (counting from 1) without applying it.
	FailWrite int
}

// New makes a client holding the given relationships.
func New(rels ...*v1.Relationship) *Client {
	c := &Client{rels: map[string]*v1.Relationship{}}
	for _, r := range rels {
		c.rels[key(r)] = proto.Clone(r).(*v1.Relationship)
	}
	return c
}

// key is the relationship's identity, without its caveat.
func key(r *v1.Relationship) string {
	return fmt.Sprintf("%s:%s#%s@%s:%s", r.GetResource().GetObjectType(), r.GetResource().GetObjectId(), r.GetRelation(),
		r.GetSubject().GetObject().GetObjectType(), r.GetSubject().GetObject().GetObjectId())
}

// Relationships returns what the client holds, sorted by identity.
func (c *Client) Relationships() []*v1.Relationship {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sorted()
}

// sorted is Relationships with the lock held.
func (c *Client) sorted() []*v1.Relationship {
	keys := make([]string, 0, len(c.rels))
	for k := range c.rels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]*v1.Relationship, 0, len(keys))
	for _, k := range keys {
		out = append(out, proto.Clone(c.rels[k]).(*v1.Relationship))
	}
	return out
}

// Token is the zedtoken of the current revision.
func (c *Client) Token() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.token()
}

func (c *Client) token() string { return fmt.Sprintf("rev-%d", c.revision) }

// WriteSchema implements v1.SchemaServiceClient.
func (c *Client) WriteSchema(_ context.Context, in *v1.WriteSchemaRequest, _ ...grpc.CallOption) (*v1.WriteSchemaResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Schema = in.GetSchema()
	c.SchemaWrites++
	c.revision++
	return &v1.WriteSchemaResponse{WrittenAt: &v1.ZedToken{Token: c.token()}}, nil
}

// ReadRelationships implements v1.PermissionsServiceClient: it filters on
// the resource type, the relation and the subject type when given, and
// streams the matches sorted by identity.
func (c *Client) ReadRelationships(_ context.Context, in *v1.ReadRelationshipsRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[v1.ReadRelationshipsResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Reads = append(c.Reads, in)
	if c.ReadErr != nil {
		return nil, c.ReadErr
	}
	s := &stream{}
	for _, r := range c.sorted() {
		if matches(in.GetRelationshipFilter(), r) {
			s.items = append(s.items, &v1.ReadRelationshipsResponse{ReadAt: &v1.ZedToken{Token: c.token()}, Relationship: r})
		}
	}
	return s, nil
}

func matches(f *v1.RelationshipFilter, r *v1.Relationship) bool {
	if f.GetResourceType() != "" && f.GetResourceType() != r.GetResource().GetObjectType() {
		return false
	}
	if f.GetOptionalRelation() != "" && f.GetOptionalRelation() != r.GetRelation() {
		return false
	}
	if sf := f.GetOptionalSubjectFilter(); sf != nil && sf.GetSubjectType() != r.GetSubject().GetObject().GetObjectType() {
		return false
	}
	return true
}

// WriteRelationships implements v1.PermissionsServiceClient: TOUCH and
// CREATE set, DELETE removes; a CREATE of an existing relationship fails.
func (c *Client) WriteRelationships(_ context.Context, in *v1.WriteRelationshipsRequest, _ ...grpc.CallOption) (*v1.WriteRelationshipsResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Writes = append(c.Writes, in)
	if c.FailWrite == len(c.Writes) {
		return nil, fmt.Errorf("fakespicedb: write %d fails", c.FailWrite)
	}
	for _, u := range in.GetUpdates() {
		k := key(u.GetRelationship())
		switch u.GetOperation() {
		case v1.RelationshipUpdate_OPERATION_CREATE:
			if _, exists := c.rels[k]; exists {
				return nil, fmt.Errorf("fakespicedb: %s already exists", k)
			}
			c.rels[k] = proto.Clone(u.GetRelationship()).(*v1.Relationship)
		case v1.RelationshipUpdate_OPERATION_TOUCH:
			c.rels[k] = proto.Clone(u.GetRelationship()).(*v1.Relationship)
		case v1.RelationshipUpdate_OPERATION_DELETE:
			delete(c.rels, k)
		default:
			return nil, fmt.Errorf("fakespicedb: unknown operation %v", u.GetOperation())
		}
	}
	c.revision++
	return &v1.WriteRelationshipsResponse{WrittenAt: &v1.ZedToken{Token: c.token()}}, nil
}

// stream replays recorded responses.
type stream struct {
	grpc.ClientStream
	items []*v1.ReadRelationshipsResponse
	next  int
}

func (s *stream) Recv() (*v1.ReadRelationshipsResponse, error) {
	if s.next >= len(s.items) {
		return nil, io.EOF
	}
	item := s.items[s.next]
	s.next++
	return item, nil
}
