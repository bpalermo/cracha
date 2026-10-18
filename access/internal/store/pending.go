package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

// Pending is a write waiting for an approval (design 6.9). It lives in
// SpiceDB itself, as one relationship
// pending_request:<id>#target@<target type>:<target id> whose
// pending_payload caveat carries the request as JSON: the target is
// queryable as a relationship, nothing outside SpiceDB holds state, and
// the gateway that lets only cracha-access write keeps anything else from
// adding one. The caveat is never evaluated: no permission reads the
// relation.
type Pending struct {
	ID string `json:"id"`
	// Caller is the SPIFFE ID that asked; Requester the person or job it
	// named, for the log.
	Caller    string `json:"caller"`
	Requester string `json:"requester,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Tuple     Tuple  `json:"tuple"`
	// CreatedAt and ExpiresAt (RFC 3339, UTC) bound the request itself: a
	// request not approved by ExpiresAt is dropped.
	CreatedAt string `json:"createdAt"`
	ExpiresAt string `json:"expiresAt"`
}

// Expired reports whether the request has expired at now.
func (p Pending) Expired(now time.Time) bool {
	t, err := time.Parse(time.RFC3339, p.ExpiresAt)
	return err != nil || !now.Before(t)
}

// NewPendingID is a random request ID: 32 hex digits.
func NewPendingID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// PendingRelationship is the request's relationship without its caveat:
// what deleting it names.
func PendingRelationship(p Pending) (Relationship, error) {
	id, err := p.Tuple.TargetID()
	if err != nil {
		return Relationship{}, err
	}
	return Relationship{ResourceType: DefinitionPendingRequest, ResourceID: p.ID, Relation: RelationTarget, SubjectType: p.Tuple.Kind, SubjectID: id}, nil
}

// PutPending stores a new pending request; an ID already in use fails.
func (s *Store) PutPending(ctx context.Context, p Pending, metadata map[string]any) (string, error) {
	rel, err := PendingRelationship(p)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	proto, err := rel.Proto()
	if err != nil {
		return "", err
	}
	cctx, err := structpb.NewStruct(map[string]any{CaveatContextRequest: string(payload)})
	if err != nil {
		return "", err
	}
	proto.OptionalCaveat = &v1.ContextualizedCaveat{CaveatName: CaveatPendingPayload, Context: cctx}
	req := &v1.WriteRelationshipsRequest{Updates: []*v1.RelationshipUpdate{{Operation: v1.RelationshipUpdate_OPERATION_CREATE, Relationship: proto}}}
	if req.OptionalTransactionMetadata, err = structpb.NewStruct(metadata); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	resp, err := s.client.WriteRelationships(ctx, req)
	if err != nil {
		return "", fmt.Errorf("spicedb: write pending request: %w", err)
	}
	return resp.GetWrittenAt().GetToken(), nil
}

// ListPending returns the pending requests, by creation time, or the one
// of that ID when id is set. A relationship whose payload does not decode
// is returned as a Pending with only its ID, so it can be seen and
// dropped.
func (s *Store) ListPending(ctx context.Context, id string) ([]Pending, error) {
	stream, err := s.readRaw(ctx, &v1.RelationshipFilter{ResourceType: DefinitionPendingRequest, OptionalResourceId: id, OptionalRelation: RelationTarget})
	if err != nil {
		return nil, err
	}
	out := make([]Pending, 0, len(stream))
	for _, rel := range stream {
		out = append(out, decodePending(rel))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt != out[j].CreatedAt {
			return out[i].CreatedAt < out[j].CreatedAt
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// decodePending reads a pending request's payload; the relationship's own
// ID wins over whatever the payload says.
func decodePending(rel *v1.Relationship) Pending {
	id := rel.GetResource().GetObjectId()
	v, ok := rel.GetOptionalCaveat().GetContext().GetFields()[CaveatContextRequest]
	var p Pending
	if !ok || json.Unmarshal([]byte(v.GetStringValue()), &p) != nil {
		return Pending{ID: id}
	}
	p.ID = id
	return p
}

// readRaw is read for the relationships themselves, caveat context whole.
func (s *Store) readRaw(ctx context.Context, f *v1.RelationshipFilter) ([]*v1.Relationship, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	stream, err := s.client.ReadRelationships(ctx, &v1.ReadRelationshipsRequest{
		Consistency:        &v1.Consistency{Requirement: &v1.Consistency_FullyConsistent{FullyConsistent: true}},
		RelationshipFilter: f,
	})
	if err != nil {
		return nil, fmt.Errorf("spicedb: read %s: %w", f.GetResourceType(), err)
	}
	var out []*v1.Relationship
	for {
		resp, err := stream.Recv()
		if err != nil {
			return out, eofIsDone(err, f.GetResourceType())
		}
		out = append(out, resp.GetRelationship())
	}
}
