package spicedb

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/bpalermo/cracha/broker/internal/authz"
	"github.com/bpalermo/cracha/broker/internal/authz/static"
)

// The static backend's test assignments, and the same assignments as the
// relationships the reconciler would write for them. Both backends must
// answer the same for every subject (design 6.3: all adapters give the same
// answers to the same questions).
const staticFile = `
services:
  - name: payments-api
    team: payments
    members: [prod/payments/ledger, prod/payments/worker]
    grants:
      - name: payments-ledger-rw
      - name: prod-only
        clusters: [prod-a, prod-b]
workloads:
  - subject: prod/payments/ledger
    grants:
      - name: break-glass
        expiresAt: "2026-06-01T00:00:00Z"
      - name: payments-ledger-rw
  - subject: prod/payments/suspended
    suspended: true
    grants:
      - name: payments-ledger-rw
  - subject: prod/payments/lonely
    grants:
      - name: cluster-and-time
        clusters: [prod-a]
        expiresAt: "2026-06-01T00:00:00Z"
access:
  - subject: prod/payments/ledger
    resource: { kind: s3_bucket, name: data-raw }
    relation: reader
  - service: payments-api
    resource: { kind: s3_bucket, name: data.curated }
    relation: writer
    clusters: [prod-a]
  - subject: prod/payments/worker
    resource: { kind: s3_bucket, name: data-old }
    relation: reader
    expiresAt: "2026-06-01T00:00:00Z"
  - service: payments-api
    resource: { kind: s3_bucket, name: data-both }
    relation: reader
    clusters: [prod-b]
    expiresAt: "2026-06-01T00:00:00Z"
  - subject: prod/payments/suspended
    resource: { kind: s3_bucket, name: data-raw }
    relation: writer
  - subject: prod/payments/lonely
    resource: { kind: dynamodb_table, name: Ledger_Index.v2 }
    relation: writer
`

func relationships() []rel {
	prodOnly := parseRel("grant:prod-only#assignee_service@service:payments-api")
	prodOnly.caveat, prodOnly.allowed = "in_clusters", []string{"prod-a", "prod-b"}
	breakGlass := parseRel("grant:break-glass#assignee_workload@workload:prod/payments/ledger")
	breakGlass.caveat, breakGlass.expiresAt = "within_window", "2026-06-01T00:00:00Z"
	both := parseRel("grant:cluster-and-time#assignee_workload@workload:prod/payments/lonely")
	both.caveat, both.expiresAt, both.allowed = "bounded", "2026-06-01T00:00:00Z", []string{"prod-a"}
	curated := parseRel("s3_bucket:data_2ecurated#writer@service:payments-api#member")
	curated.caveat, curated.allowed = "in_clusters", []string{"prod-a"}
	old := parseRel("s3_bucket:data-old#reader@workload:prod/payments/worker")
	old.caveat, old.expiresAt = "within_window", "2026-06-01T00:00:00Z"
	bothBucket := parseRel("s3_bucket:data-both#reader@service:payments-api#member")
	bothBucket.caveat, bothBucket.expiresAt, bothBucket.allowed = "bounded", "2026-06-01T00:00:00Z", []string{"prod-b"}
	return []rel{
		parseRel("s3_bucket:data-raw#reader@workload:prod/payments/ledger"),
		curated,
		old,
		bothBucket,
		parseRel("s3_bucket:data-raw#writer@workload:prod/payments/suspended"),
		parseRel("dynamodb_table:Ledger_5fIndex_2ev2#writer@workload:prod/payments/lonely"),
		parseRel("service:payments-api#owner@team:payments"),
		parseRel("service:payments-api#member@workload:prod/payments/ledger"),
		parseRel("service:payments-api#member@workload:prod/payments/worker"),
		parseRel("grant:payments-ledger-rw#assignee_service@service:payments-api"),
		prodOnly,
		breakGlass,
		parseRel("grant:payments-ledger-rw#assignee_workload@workload:prod/payments/ledger"),
		parseRel("workload:prod/payments/suspended#suspended@team:payments"),
		parseRel("grant:payments-ledger-rw#assignee_workload@workload:prod/payments/suspended"),
		both,
	}
}

func TestParityWithStatic(t *testing.T) {
	before := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	after := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	subjects := []authz.Subject{
		{ID: "prod/payments/ledger", Cluster: "prod-a"},
		{ID: "prod/payments/ledger", Cluster: "dev"},
		{ID: "prod/payments/worker", Cluster: "prod-b"},
		{ID: "prod/payments/lonely", Cluster: "prod-a"},
		{ID: "prod/payments/lonely", Cluster: "prod-b"},
		{ID: "prod/payments/suspended", Cluster: "prod-a"},
		{ID: "prod/nobody/nobody", Cluster: "prod-a"},
	}
	grants := []string{"payments-ledger-rw", "prod-only", "break-glass", "cluster-and-time", "nope"}
	for _, now := range []time.Time{before, after} {
		clock := func() time.Time { return now }
		ref, err := static.Parse([]byte(staticFile), static.WithClock(clock))
		if err != nil {
			t.Fatal(err)
		}
		s := New(newFake(token, relationships()...), nil, WithClock(clock))
		for _, sub := range subjects {
			compareListGrants(t, ref, s, sub, now)
			for _, g := range grants {
				compareCheck(t, ref, s, sub, g, now)
			}
			for _, kind := range []string{"s3_bucket", "dynamodb_table"} {
				for _, perm := range []string{"read", "write"} {
					compareLookup(t, ref, s, sub, kind, perm, now)
				}
			}
		}
	}
}

// TestParityLookupCoversEveryPath checks that the comparison above is not
// vacuous: each kind of path gives some subject a resource at some time.
func TestParityLookupCoversEveryPath(t *testing.T) {
	before := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return before }
	s := New(newFake(token, relationships()...), nil, WithClock(clock))
	for _, tt := range []struct {
		sub        authz.Subject
		kind, perm string
		want       []string
	}{
		{authz.Subject{ID: "prod/payments/ledger", Cluster: "prod-a"}, "s3_bucket", "read", []string{"data-raw", "data.curated"}},
		{authz.Subject{ID: "prod/payments/ledger", Cluster: "prod-b"}, "s3_bucket", "read", []string{"data-both", "data-raw"}},
		{authz.Subject{ID: "prod/payments/ledger", Cluster: "prod-a"}, "s3_bucket", "write", []string{"data.curated"}},
		{authz.Subject{ID: "prod/payments/worker", Cluster: "dev"}, "s3_bucket", "read", []string{"data-old"}},
		{authz.Subject{ID: "prod/payments/lonely", Cluster: "dev"}, "dynamodb_table", "read", []string{"Ledger_Index.v2"}},
	} {
		got, err := s.LookupResources(context.Background(), tt.sub, tt.kind, tt.perm, authz.Consistency{})
		if err != nil || !reflect.DeepEqual(got.Names, tt.want) {
			t.Errorf("%s in %s, %s#%s = %v, %v, want %v", tt.sub.ID, tt.sub.Cluster, tt.kind, tt.perm, got.Names, err, tt.want)
		}
	}
}

func compareLookup(t *testing.T, ref *static.Store, s *Store, sub authz.Subject, kind, perm string, now time.Time) {
	t.Helper()
	want, wantErr := ref.LookupResources(context.Background(), sub, kind, perm, authz.Consistency{})
	got, gotErr := s.LookupResources(context.Background(), sub, kind, perm, authz.Consistency{})
	if errors.Is(wantErr, authz.ErrSubjectSuspended) != errors.Is(gotErr, authz.ErrSubjectSuspended) || (wantErr == nil) != (gotErr == nil) {
		t.Errorf("%s in %s at %s, %s#%s: static %v, spicedb %v", sub.ID, sub.Cluster, now.Format(time.RFC3339), kind, perm, wantErr, gotErr)
		return
	}
	if !reflect.DeepEqual(got.Names, want.Names) {
		t.Errorf("%s in %s at %s, %s#%s: spicedb %v, static %v", sub.ID, sub.Cluster, now.Format(time.RFC3339), kind, perm, got.Names, want.Names)
	}
}

func compareListGrants(t *testing.T, ref *static.Store, s *Store, sub authz.Subject, now time.Time) {
	t.Helper()
	want, wantErr := ref.ListGrants(context.Background(), sub, authz.Consistency{})
	got, gotErr := s.ListGrants(context.Background(), sub, authz.Consistency{})
	if errors.Is(wantErr, authz.ErrSubjectSuspended) != errors.Is(gotErr, authz.ErrSubjectSuspended) || (wantErr == nil) != (gotErr == nil) {
		t.Errorf("%s at %s: static %v, spicedb %v", sub.ID, now.Format(time.RFC3339), wantErr, gotErr)
		return
	}
	if !reflect.DeepEqual(got.Grants, want.Grants) {
		t.Errorf("%s in %s at %s: grants spicedb %v, static %v", sub.ID, sub.Cluster, now.Format(time.RFC3339), got.Grants, want.Grants)
	}
	if !reflect.DeepEqual(got.Tags, want.Tags) {
		t.Errorf("%s: tags spicedb %v, static %v", sub.ID, got.Tags, want.Tags)
	}
}

func compareCheck(t *testing.T, ref *static.Store, s *Store, sub authz.Subject, grant string, now time.Time) {
	t.Helper()
	want, wantErr := ref.Check(context.Background(), sub, grant, authz.Consistency{})
	got, gotErr := s.Check(context.Background(), sub, grant, authz.Consistency{})
	if (wantErr == nil) != (gotErr == nil) || got.Allowed != want.Allowed {
		t.Errorf("%s in %s at %s, grant %s: spicedb (%v, %v), static (%v, %v)", sub.ID, sub.Cluster, now.Format(time.RFC3339), grant, got.Allowed, gotErr, want.Allowed, wantErr)
	}
}
