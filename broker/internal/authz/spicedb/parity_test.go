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
`

func relationships() []rel {
	prodOnly := parseRel("grant:prod-only#assignee_service@service:payments-api")
	prodOnly.caveat, prodOnly.allowed = "in_clusters", []string{"prod-a", "prod-b"}
	breakGlass := parseRel("grant:break-glass#assignee_workload@workload:prod/payments/ledger")
	breakGlass.caveat, breakGlass.expiresAt = "within_window", "2026-06-01T00:00:00Z"
	both := parseRel("grant:cluster-and-time#assignee_workload@workload:prod/payments/lonely")
	both.caveat, both.expiresAt, both.allowed = "bounded", "2026-06-01T00:00:00Z", []string{"prod-a"}
	return []rel{
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
		}
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
