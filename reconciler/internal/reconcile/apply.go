package reconcile

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"

	"github.com/bpalermo/cracha/common/spicedb"
)

// MaxBatch is the most updates one WriteRelationships carries, SpiceDB's
// default limit.
const MaxBatch = 1000

// ErrDiverged is returned by Apply when, after every batch was written,
// SpiceDB read back at least as fresh as the last write still differs from
// the desired set: something else writes the owned types.
var ErrDiverged = errors.New("SpiceDB differs from the source after the write")

// OwnedTypes are the resource types whose every relationship the
// reconciler owns: what it reads to diff, and what it deletes when the
// tree no longer calls for it.
var OwnedTypes = append([]string{spicedb.TypeGrant, spicedb.TypeService, spicedb.TypeWorkload}, spicedb.ResourceTypes...)

// Reconciler writes to one SpiceDB.
type Reconciler struct {
	Permissions v1.PermissionsServiceClient
	Schema      v1.SchemaServiceClient
	Log         *slog.Logger
	// BatchSize is the most updates per write; 0 means MaxBatch.
	BatchSize int
}

// WriteSchema writes the embedded schema. SpiceDB accepts a schema it
// already holds, so this is idempotent.
func (r *Reconciler) WriteSchema(ctx context.Context) error {
	if _, err := r.Schema.WriteSchema(ctx, &v1.WriteSchemaRequest{Schema: spicedb.Schema}); err != nil {
		return fmt.Errorf("write schema: %w", err)
	}
	return nil
}

// ReadOwned reads every relationship of the owned resource types at the
// given consistency (nil for fully consistent).
func (r *Reconciler) ReadOwned(ctx context.Context, consistency *v1.Consistency) ([]Relationship, error) {
	if consistency == nil {
		consistency = &v1.Consistency{Requirement: &v1.Consistency_FullyConsistent{FullyConsistent: true}}
	}
	var out []Relationship
	for _, resourceType := range OwnedTypes {
		rels, err := r.readType(ctx, resourceType, consistency)
		if err != nil {
			return nil, fmt.Errorf("read %s relationships: %w", resourceType, err)
		}
		out = append(out, rels...)
	}
	sortByKey(out)
	return out, nil
}

func (r *Reconciler) readType(ctx context.Context, resourceType string, consistency *v1.Consistency) ([]Relationship, error) {
	stream, err := r.Permissions.ReadRelationships(ctx, &v1.ReadRelationshipsRequest{
		Consistency:        consistency,
		RelationshipFilter: &v1.RelationshipFilter{ResourceType: resourceType},
	})
	if err != nil {
		return nil, err
	}
	var out []Relationship
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		out = append(out, FromProto(resp.GetRelationship()))
	}
}

// Result is what an Apply did.
type Result struct {
	Diff Diff
	// Written is how many updates were written, in Batches writes; both
	// are 0 for a dry run or a no-op.
	Written int
	Batches int
	// Token is the zedtoken of the last write, or empty.
	Token string
}

// Apply makes SpiceDB hold exactly the desired relationships of the owned
// types: it reads what SpiceDB holds, diffs, logs the diff, writes it in
// batches of at most BatchSize updates (touches for what is missing or
// differs, deletes for what is not desired) and reads back at least as
// fresh as the last write to confirm. With dryRun it stops after logging
// the diff. A write that fails after others succeeded is reported with
// what was written; nothing is retried.
func (r *Reconciler) Apply(ctx context.Context, desired []Relationship, dryRun bool) (*Result, error) {
	current, err := r.ReadOwned(ctx, nil)
	if err != nil {
		return nil, err
	}
	res := &Result{Diff: ComputeDiff(current, desired)}
	r.logDiff(res.Diff, len(current), len(desired))
	if dryRun || res.Diff.Empty() {
		return res, nil
	}
	if err := r.write(ctx, res); err != nil {
		return res, err
	}
	after, err := r.ReadOwned(ctx, &v1.Consistency{Requirement: &v1.Consistency_AtLeastAsFresh{AtLeastAsFresh: &v1.ZedToken{Token: res.Token}}})
	if err != nil {
		return res, fmt.Errorf("confirming the write: %w", err)
	}
	if left := ComputeDiff(after, desired); !left.Empty() {
		return res, fmt.Errorf("%w: by %d relationships, such as %s", ErrDiverged, left.Len(), firstOf(left))
	}
	return res, nil
}

// log is the logger, or the default one.
func (r *Reconciler) log() *slog.Logger {
	if r.Log == nil {
		return slog.Default()
	}
	return r.Log
}

// write sends the diff in batches, recording progress in res.
func (r *Reconciler) write(ctx context.Context, res *Result) error {
	updates, err := res.Diff.Updates()
	if err != nil {
		return err
	}
	size := r.BatchSize
	if size <= 0 {
		size = MaxBatch
	}
	for start := 0; start < len(updates); start += size {
		batch := updates[start:min(start+size, len(updates))]
		resp, err := r.Permissions.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{Updates: batch})
		if err != nil {
			return fmt.Errorf("write batch %d (%d updates) failed after %d of %d updates were written in %d batches: %w", res.Batches+1, len(batch), res.Written, len(updates), res.Batches, err)
		}
		res.Written += len(batch)
		res.Batches++
		res.Token = resp.GetWrittenAt().GetToken()
		r.log().Info("wrote batch", "batch", res.Batches, "updates", len(batch), "written", res.Written, "of", len(updates))
	}
	return nil
}

// logDiff logs every change at info, and the counts.
func (r *Reconciler) logDiff(d Diff, current, desired int) {
	log := r.log()
	for _, rel := range d.Touch {
		log.Info("touch", "relationship", rel.String())
	}
	for _, rel := range d.Delete {
		log.Info("delete", "relationship", rel.String())
	}
	log.Info("diff", "current", current, "desired", desired, "touch", len(d.Touch), "delete", len(d.Delete))
}

// firstOf names the first relationship of a diff, for an error.
func firstOf(d Diff) string {
	var parts []string
	if len(d.Touch) > 0 {
		parts = append(parts, "missing "+d.Touch[0].String())
	}
	if len(d.Delete) > 0 {
		parts = append(parts, "extra "+d.Delete[0].String())
	}
	return strings.Join(parts, " and ")
}
