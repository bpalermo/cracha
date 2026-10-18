package store

import (
	"context"
	"fmt"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
)

// Change is one relationship change SpiceDB's Watch reported.
type Change struct {
	// Operation is touch, create or delete.
	Operation    string
	Relationship Relationship
	// Token is the revision the change is part of.
	Token string
	// Metadata is the writing transaction's metadata: cracha-access sets
	// the caller and the request on every write it makes, so a change
	// without it was written by something else.
	Metadata map[string]any
}

// WatchTypes are the object types the audit watch follows: every type
// cracha-access writes, and those it reads its checks from.
var WatchTypes = append(append([]string{}, SnapshotTypes...), DefinitionPendingRequest)

// Watch follows SpiceDB's change feed for the types from the revision
// start (empty: from now), handing every change to fn, until ctx ends. A
// broken stream is reopened after backoff from the last revision seen, so
// nothing is missed while SpiceDB keeps that revision. It returns ctx's
// error.
func (s *Store) Watch(ctx context.Context, types []string, start string, backoff time.Duration, fn func(Change)) error {
	cursor := start
	for {
		next, err := s.watchOnce(ctx, types, cursor, fn)
		if next != "" {
			cursor = next
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		fn(Change{Operation: "watch_error", Token: cursor, Metadata: map[string]any{"error": fmt.Sprint(err)}})
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
	}
}

// watchOnce reads one Watch stream until it breaks, returning the last
// revision it reached.
func (s *Store) watchOnce(ctx context.Context, types []string, cursor string, fn func(Change)) (string, error) {
	req := &v1.WatchRequest{OptionalObjectTypes: types}
	if cursor != "" {
		req.OptionalStartCursor = &v1.ZedToken{Token: cursor}
	}
	stream, err := s.client.Watch(ctx, req)
	if err != nil {
		return "", err
	}
	last := ""
	for {
		resp, err := stream.Recv()
		if err != nil {
			return last, err
		}
		token := resp.GetChangesThrough().GetToken()
		md := resp.GetOptionalTransactionMetadata().AsMap()
		for _, u := range resp.GetUpdates() {
			fn(Change{Operation: operation(u.GetOperation()), Relationship: FromProto(u.GetRelationship()), Token: token, Metadata: md})
		}
		if token != "" {
			last = token
		}
	}
}

func operation(op v1.RelationshipUpdate_Operation) string {
	switch op {
	case v1.RelationshipUpdate_OPERATION_CREATE:
		return "create"
	case v1.RelationshipUpdate_OPERATION_TOUCH:
		return "touch"
	case v1.RelationshipUpdate_OPERATION_DELETE:
		return "delete"
	}
	return op.String()
}
