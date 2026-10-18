package reconcile

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"

	"github.com/bpalermo/cracha/common/spicedb"
	"github.com/bpalermo/cracha/reconciler/internal/fakespicedb"
)

func rel(resourceType, resourceID, relation, subjectType, subjectID string) Relationship {
	return plain(resourceType, resourceID, relation, subjectType, subjectID)
}

func caveated(r Relationship, caveat, expiresAt string, allowed ...string) Relationship {
	r.Caveat, r.ExpiresAt, r.Allowed = caveat, expiresAt, allowed
	return r
}

func mustProto(t *testing.T, rels ...Relationship) []*v1.Relationship {
	t.Helper()
	out := make([]*v1.Relationship, 0, len(rels))
	for _, r := range rels {
		p, err := r.Proto()
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
	return out
}

func held(c *fakespicedb.Client) []Relationship {
	var out []Relationship
	for _, r := range c.Relationships() {
		out = append(out, FromProto(r))
	}
	sortByKey(out)
	return out
}

var (
	owner   = rel(spicedb.TypeService, "svc", spicedb.RelationOwner, spicedb.TypeTeam, "payments")
	member  = rel(spicedb.TypeService, "svc", spicedb.RelationMember, spicedb.TypeWorkload, "prod/p/w1")
	account = rel(spicedb.TypeGrant, "g", spicedb.RelationAccount, spicedb.TypeAWSAccount, "111122223333")
	direct  = rel(spicedb.TypeGrant, "g", spicedb.RelationAssigneeWorkload, spicedb.TypeWorkload, "prod/p/w2")
	stale   = rel(spicedb.TypeGrant, "old", spicedb.RelationAssigneeService, spicedb.TypeService, "svc")
	susp    = rel(spicedb.TypeWorkload, "prod/p/w3", spicedb.RelationSuspended, spicedb.TypeTeam, spicedb.TeamNone)
)

func TestComputeDiff(t *testing.T) {
	bounded := caveated(direct, spicedb.CaveatWithinWindow, "2030-01-01T00:00:00Z")
	current := []Relationship{owner, bounded, stale}
	desired := []Relationship{owner, member, caveated(direct, spicedb.CaveatInClusters, "", "east")}
	d := ComputeDiff(current, desired)
	if got, want := lines(d.Touch), lines([]Relationship{desired[2], member}); got != want {
		t.Errorf("touch =\n%swant:\n%s", got, want)
	}
	if got, want := lines(d.Delete), lines([]Relationship{stale}); got != want {
		t.Errorf("delete =\n%swant:\n%s", got, want)
	}
	if d.Len() != 3 || d.Empty() {
		t.Errorf("diff = %+v", d)
	}
	if noop := ComputeDiff(desired, desired); !noop.Empty() {
		t.Errorf("diff of a set with itself = %+v", noop)
	}
	updates, err := d.Updates()
	if err != nil {
		t.Fatal(err)
	}
	var ops []string
	for _, u := range updates {
		ops = append(ops, u.GetOperation().String()+" "+FromProto(u.GetRelationship()).String())
	}
	want := []string{
		"OPERATION_TOUCH " + desired[2].String(),
		"OPERATION_TOUCH " + member.String(),
		"OPERATION_DELETE " + stale.Key(),
	}
	if strings.Join(ops, "\n") != strings.Join(want, "\n") {
		t.Errorf("updates =\n%s\nwant:\n%s", strings.Join(ops, "\n"), strings.Join(want, "\n"))
	}
}

func newReconciler(c *fakespicedb.Client, batch int) *Reconciler {
	return &Reconciler{Permissions: c, Schema: c, Log: slog.New(slog.DiscardHandler), BatchSize: batch}
}

func TestApply(t *testing.T) {
	ctx := context.Background()
	c := fakespicedb.New(mustProto(t, owner, caveated(direct, spicedb.CaveatWithinWindow, "2030-01-01T00:00:00Z"), stale)...)
	desired := []Relationship{owner, member, account, caveated(direct, spicedb.CaveatBounded, "2030-01-01T00:00:00Z", "east"), susp}
	r := newReconciler(c, 2)
	res, err := r.Apply(ctx, desired, false)
	if err != nil {
		t.Fatal(err)
	}
	// Four touches and one delete, two per batch: three writes.
	if res.Written != 5 || res.Batches != 3 || res.Token != c.Token() || len(c.Writes) != 3 || len(c.Writes[2].GetUpdates()) != 1 {
		t.Errorf("result = %+v, writes = %d", res, len(c.Writes))
	}
	sortByKey(desired)
	if got, want := lines(held(c)), lines(desired); got != want {
		t.Errorf("SpiceDB holds\n%swant:\n%s", got, want)
	}
	// One read per owned type before and one after, the latter at least
	// as fresh as the write.
	n := len(OwnedTypes)
	if len(c.Reads) != 2*n {
		t.Fatalf("reads = %d, want %d", len(c.Reads), 2*n)
	}
	var types []string
	for _, read := range c.Reads {
		types = append(types, read.GetRelationshipFilter().GetResourceType())
	}
	if want := "grant,service,workload,s3_bucket,dynamodb_table"; strings.Join(types, ",") != want+","+want {
		t.Errorf("read types = %v", types)
	}
	if !c.Reads[0].GetConsistency().GetFullyConsistent() || c.Reads[2*n-1].GetConsistency().GetAtLeastAsFresh().GetToken() != res.Token {
		t.Errorf("consistency: first %v, last %v", c.Reads[0].GetConsistency(), c.Reads[2*n-1].GetConsistency())
	}

	// A second apply is a no-op: no write, no confirmation read.
	res, err = r.Apply(ctx, desired, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Diff.Empty() || res.Written != 0 || res.Batches != 0 || res.Token != "" || len(c.Writes) != 3 || len(c.Reads) != 3*n {
		t.Errorf("second apply: result = %+v, writes = %d, reads = %d", res, len(c.Writes), len(c.Reads))
	}
}

func TestApplyDryRun(t *testing.T) {
	c := fakespicedb.New(mustProto(t, stale)...)
	res, err := newReconciler(c, 0).Apply(context.Background(), []Relationship{owner}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Diff.Touch) != 1 || len(res.Diff.Delete) != 1 || res.Written != 0 || len(c.Writes) != 0 || len(c.Reads) != len(OwnedTypes) {
		t.Errorf("dry run: result = %+v, writes = %d, reads = %d", res, len(c.Writes), len(c.Reads))
	}
	if got := held(c); len(got) != 1 || !got[0].Equal(stale) {
		t.Errorf("dry run changed SpiceDB: %v", got)
	}
}

func TestApplyWriteFails(t *testing.T) {
	c := fakespicedb.New()
	c.FailWrite = 2
	desired := []Relationship{owner, member, account}
	res, err := newReconciler(c, 2).Apply(context.Background(), desired, false)
	if err == nil || !strings.Contains(err.Error(), "write batch 2 (1 updates) failed after 2 of 3 updates were written in 1 batches") {
		t.Fatalf("error = %v", err)
	}
	if res == nil || res.Written != 2 || res.Batches != 1 || len(held(c)) != 2 {
		t.Errorf("result = %+v, held = %v", res, held(c))
	}
}

func TestApplyDiverged(t *testing.T) {
	c := fakespicedb.New()
	c.Intruder = mustProto(t, stale)[0]
	res, err := newReconciler(c, 0).Apply(context.Background(), []Relationship{owner}, false)
	if !errors.Is(err, ErrDiverged) || !strings.Contains(err.Error(), "by 1 relationships, such as extra "+stale.Key()) {
		t.Fatalf("error = %v", err)
	}
	if res == nil || res.Written != 1 {
		t.Errorf("result = %+v", res)
	}
}

func TestApplyReadFails(t *testing.T) {
	c := fakespicedb.New()
	c.ReadErr = errors.New("unavailable")
	if _, err := newReconciler(c, 0).Apply(context.Background(), []Relationship{owner}, false); err == nil || !strings.Contains(err.Error(), "read grant relationships: unavailable") {
		t.Errorf("error = %v", err)
	}
	if len(c.Writes) != 0 {
		t.Error("a failed read was followed by a write")
	}
}

func TestWriteSchema(t *testing.T) {
	c := fakespicedb.New()
	r := newReconciler(c, 0)
	for i := 0; i < 2; i++ {
		if err := r.WriteSchema(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if c.SchemaWrites != 2 || c.Schema != spicedb.Schema {
		t.Errorf("schema writes = %d, schema matches = %v", c.SchemaWrites, c.Schema == spicedb.Schema)
	}
}

func TestFromProtoOddContext(t *testing.T) {
	p := mustProto(t, caveated(direct, spicedb.CaveatBounded, "2030-01-01T00:00:00Z", "east"))[0]
	fields := p.GetOptionalCaveat().GetContext().GetFields()
	fields[spicedb.ContextExpiresAt], fields[spicedb.ContextAllowed] = fields[spicedb.ContextAllowed], fields[spicedb.ContextExpiresAt]
	got := FromProto(p)
	if !strings.HasPrefix(got.ExpiresAt, "?") || len(got.Allowed) != 1 || !strings.HasPrefix(got.Allowed[0], "?") {
		t.Errorf("FromProto = %+v, want the odd values marked", got)
	}
	if got.Equal(caveated(direct, spicedb.CaveatBounded, "2030-01-01T00:00:00Z", "east")) {
		t.Error("an odd context compares equal to the desired one")
	}
}
