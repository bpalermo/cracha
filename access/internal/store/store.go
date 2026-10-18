// Package store is cracha-access's adapter over SpiceDB (docs/design.md,
// sections 6.4 and 6.9): it reads the relationships every safeguard is
// checked against, asks whether a caller holds manage or approve on a
// target and whether the target is sensitive, writes the relationships a
// write request decided on, keeps pending requests as relationships of
// their own, and follows SpiceDB's Watch for the audit log. SpiceDB's
// types stay in this package: the rest of cracha-access sees Tuples,
// Relationships and Pending requests.
package store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/bpalermo/cracha/common/spicedb"
)

// Client is the part of the SpiceDB API the store calls: the authzed
// client, through the gateway, in production, and a fake in tests.
type Client interface {
	ReadRelationships(ctx context.Context, in *v1.ReadRelationshipsRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[v1.ReadRelationshipsResponse], error)
	WriteRelationships(ctx context.Context, in *v1.WriteRelationshipsRequest, opts ...grpc.CallOption) (*v1.WriteRelationshipsResponse, error)
	CheckPermission(ctx context.Context, in *v1.CheckPermissionRequest, opts ...grpc.CallOption) (*v1.CheckPermissionResponse, error)
	Watch(ctx context.Context, in *v1.WatchRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[v1.WatchResponse], error)
}

// Store is the adapter.
type Store struct {
	client  Client
	timeout time.Duration
}

// DefaultTimeout bounds one call to SpiceDB.
const DefaultTimeout = 10 * time.Second

// New makes a store over a client; a zero timeout is DefaultTimeout.
func New(client Client, timeout time.Duration) *Store {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Store{client: client, timeout: timeout}
}

// SnapshotTypes are the object types whose relationships decide what a
// workload holds: its grants, its service, its suspension and its
// resources. A snapshot reads all of them.
var SnapshotTypes = append([]string{spicedb.TypeGrant, spicedb.TypeService, spicedb.TypeWorkload}, spicedb.ResourceTypes...)

// Snapshot reads every relationship of SnapshotTypes, fully consistent,
// so that a check sees every write before it.
func (s *Store) Snapshot(ctx context.Context) ([]Relationship, error) {
	var out []Relationship
	for _, t := range SnapshotTypes {
		rels, err := s.read(ctx, &v1.RelationshipFilter{ResourceType: t})
		if err != nil {
			return nil, err
		}
		out = append(out, rels...)
	}
	return out, nil
}

// read is the relationships a filter matches, fully consistent.
func (s *Store) read(ctx context.Context, f *v1.RelationshipFilter) ([]Relationship, error) {
	raw, err := s.readRaw(ctx, f)
	if err != nil {
		return nil, err
	}
	out := make([]Relationship, 0, len(raw))
	for _, r := range raw {
		out = append(out, FromProto(r))
	}
	return out, nil
}

// eofIsDone is nil for the end of a stream and the error otherwise.
func eofIsDone(err error, what string) error {
	if errors.Is(err, io.EOF) {
		return nil
	}
	return fmt.Errorf("spicedb: read %s: %w", what, err)
}

// Holds reports whether the workload holds the permission (manage or
// approve) on the target, fully consistent. Only a definite answer is a
// yes: a conditional one is a no.
func (s *Store) Holds(ctx context.Context, permission, targetType, targetID, workload string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	resp, err := s.client.CheckPermission(ctx, &v1.CheckPermissionRequest{
		Consistency: &v1.Consistency{Requirement: &v1.Consistency_FullyConsistent{FullyConsistent: true}},
		Resource:    &v1.ObjectReference{ObjectType: targetType, ObjectId: targetID},
		Permission:  permission,
		Subject:     &v1.SubjectReference{Object: &v1.ObjectReference{ObjectType: spicedb.TypeWorkload, ObjectId: workload}},
	})
	if err != nil {
		return false, fmt.Errorf("spicedb: check %s:%s#%s: %w", targetType, targetID, permission, err)
	}
	return resp.GetPermissionship() == v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION, nil
}

// Sensitive reports whether the target is flagged sensitive: any
// relationship of its sensitive relation.
func (s *Store) Sensitive(ctx context.Context, targetType, targetID string) (bool, error) {
	rels, err := s.read(ctx, &v1.RelationshipFilter{ResourceType: targetType, OptionalResourceId: targetID, OptionalRelation: RelationSensitive})
	if err != nil {
		return false, err
	}
	return len(rels) > 0, nil
}

// Update is one change of a write: a touch, or a delete when Delete is set.
type Update struct {
	Delete       bool
	Relationship Relationship
}

// Write applies the updates in one transaction, with the metadata (the
// caller, the requester, the request) as its transaction metadata, which
// SpiceDB's Watch reports with the changes. It returns the zedtoken the
// write is visible at.
func (s *Store) Write(ctx context.Context, updates []Update, metadata map[string]any) (string, error) {
	req := &v1.WriteRelationshipsRequest{}
	for _, u := range updates {
		op, rel := v1.RelationshipUpdate_OPERATION_TOUCH, u.Relationship
		if u.Delete {
			op, rel = v1.RelationshipUpdate_OPERATION_DELETE, rel.object()
		}
		p, err := rel.Proto()
		if err != nil {
			return "", err
		}
		req.Updates = append(req.Updates, &v1.RelationshipUpdate{Operation: op, Relationship: p})
	}
	if len(metadata) > 0 {
		md, err := structpb.NewStruct(metadata)
		if err != nil {
			return "", fmt.Errorf("transaction metadata: %w", err)
		}
		req.OptionalTransactionMetadata = md
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	resp, err := s.client.WriteRelationships(ctx, req)
	if err != nil {
		return "", fmt.Errorf("spicedb: write: %w", err)
	}
	return resp.GetWrittenAt().GetToken(), nil
}
