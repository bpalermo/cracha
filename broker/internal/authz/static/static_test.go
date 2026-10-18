package static

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bpalermo/cracha/broker/internal/authz"
	"github.com/bpalermo/cracha/common/grant"
	"gopkg.in/yaml.v3"
)

const file = `
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

func load(t *testing.T, now time.Time) *Store {
	t.Helper()
	s, err := Parse([]byte(file), WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestListGrants(t *testing.T) {
	before := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	after := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		now     time.Time
		subject authz.Subject
		grants  []string
		tags    map[string]string
	}{
		{
			"service and direct, in cluster", before,
			authz.Subject{ID: "prod/payments/ledger", Cluster: "prod-a"},
			[]string{"break-glass", "payments-ledger-rw", "prod-only"},
			map[string]string{"service": "payments-api", "team": "payments"},
		},
		{
			"other cluster drops the bounded grant", before,
			authz.Subject{ID: "prod/payments/ledger", Cluster: "dev"},
			[]string{"break-glass", "payments-ledger-rw"},
			map[string]string{"service": "payments-api", "team": "payments"},
		},
		{
			"expiry drops the time-bounded grant", after,
			authz.Subject{ID: "prod/payments/ledger", Cluster: "prod-a"},
			[]string{"payments-ledger-rw", "prod-only"},
			map[string]string{"service": "payments-api", "team": "payments"},
		},
		{
			"member without direct grants", before,
			authz.Subject{ID: "prod/payments/worker", Cluster: "prod-b"},
			[]string{"payments-ledger-rw", "prod-only"},
			map[string]string{"service": "payments-api", "team": "payments"},
		},
		{
			"both conditions hold", before,
			authz.Subject{ID: "prod/payments/lonely", Cluster: "prod-a"},
			[]string{"cluster-and-time"},
			map[string]string{},
		},
		{
			"both conditions, wrong cluster", before,
			authz.Subject{ID: "prod/payments/lonely", Cluster: "prod-b"},
			nil,
			map[string]string{},
		},
		{
			"both conditions, expired", after,
			authz.Subject{ID: "prod/payments/lonely", Cluster: "prod-a"},
			nil,
			map[string]string{},
		},
		{
			"unknown subject holds nothing", before,
			authz.Subject{ID: "prod/nobody/nobody", Cluster: "prod-a"},
			nil,
			map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := load(t, tt.now)
			d, err := s.ListGrants(context.Background(), tt.subject, authz.Consistency{})
			if err != nil {
				t.Fatal(err)
			}
			checkDecision(t, s, d, tt.grants, tt.tags)
		})
	}
}

// checkDecision checks a decision's grants and tags, that it carries the
// store's token, and that it explains itself.
func checkDecision(t *testing.T, s *Store, d authz.Decision, grants []string, tags map[string]string) {
	t.Helper()
	if !reflect.DeepEqual(d.Grants, grants) {
		t.Errorf("grants %v, want %v", d.Grants, grants)
	}
	if !reflect.DeepEqual(d.Tags, tags) {
		t.Errorf("tags %v, want %v", d.Tags, tags)
	}
	if d.Token != s.Token() || d.Token == "" {
		t.Errorf("token %q, store %q", d.Token, s.Token())
	}
	if len(d.Trace) == 0 {
		t.Error("no trace")
	}
}

func TestExpiryIsExclusive(t *testing.T) {
	at := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	s := load(t, at)
	r, err := s.Check(context.Background(), authz.Subject{ID: "prod/payments/ledger", Cluster: "prod-a"}, "break-glass", authz.Consistency{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Allowed {
		t.Fatal("allowed at the expiry instant")
	}
	s = load(t, at.Add(-time.Second))
	r, err = s.Check(context.Background(), authz.Subject{ID: "prod/payments/ledger", Cluster: "prod-a"}, "break-glass", authz.Consistency{})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Allowed {
		t.Fatal("denied a second before expiry")
	}
}

func TestSuspended(t *testing.T) {
	s := load(t, time.Now())
	_, err := s.ListGrants(context.Background(), authz.Subject{ID: "prod/payments/suspended", Cluster: "prod-a"}, authz.Consistency{})
	if !errors.Is(err, authz.ErrSubjectSuspended) {
		t.Fatalf("got %v", err)
	}
	_, err = s.Check(context.Background(), authz.Subject{ID: "prod/payments/suspended", Cluster: "prod-a"}, "payments-ledger-rw", authz.Consistency{})
	if !errors.Is(err, authz.ErrSubjectSuspended) {
		t.Fatalf("got %v", err)
	}
}

func TestCheck(t *testing.T) {
	s := load(t, time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC))
	sub := authz.Subject{ID: "prod/payments/ledger", Cluster: "dev"}
	for grant, want := range map[string]bool{"payments-ledger-rw": true, "prod-only": false, "nope": false} {
		r, err := s.Check(context.Background(), sub, grant, authz.Consistency{})
		if err != nil {
			t.Fatal(err)
		}
		if r.Allowed != want {
			t.Errorf("Check(%q) = %v, want %v", grant, r.Allowed, want)
		}
	}
}

func TestConsistency(t *testing.T) {
	s := load(t, time.Now())
	sub := authz.Subject{ID: "prod/payments/ledger", Cluster: "prod-a"}
	if _, err := s.ListGrants(context.Background(), sub, authz.Consistency{AtLeastAsFresh: s.Token()}); err != nil {
		t.Fatalf("own token refused: %v", err)
	}
	if _, err := s.ListGrants(context.Background(), sub, authz.Consistency{AtLeastAsFresh: "someone-elses"}); err == nil {
		t.Fatal("foreign token accepted")
	}
	other, err := Parse([]byte(file + "\n# changed\n"))
	if err != nil {
		t.Fatal(err)
	}
	if other.Token() == s.Token() {
		t.Fatal("token does not follow the file contents")
	}
}

func TestCancelledContext(t *testing.T) {
	s := load(t, time.Now())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.ListGrants(ctx, authz.Subject{ID: "prod/payments/ledger"}, authz.Consistency{}); err == nil {
		t.Fatal("answered on a cancelled context")
	}
}

func TestParseRejects(t *testing.T) {
	tests := map[string]string{
		"unknown field":      "services:\n  - name: a\n    colour: blue\n",
		"two services":       "services:\n  - name: a\n    members: [x]\n  - name: b\n    members: [x]\n",
		"service no name":    "services:\n  - team: t\n",
		"workload twice":     "workloads:\n  - subject: x\n  - subject: x\n",
		"workload no subj":   "workloads:\n  - grants: [{name: g}]\n",
		"grant no name":      "workloads:\n  - subject: x\n    grants: [{clusters: [a]}]\n",
		"bad expiresAt":      "workloads:\n  - subject: x\n    grants: [{name: g, expiresAt: tomorrow}]\n",
		"not a mapping":      "- a\n- b\n",
		"empty member":       "services:\n  - name: a\n    members: ['']\n",
		"service grant name": "services:\n  - name: a\n    grants: [{expiresAt: '2026-01-01T00:00:00Z'}]\n",
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(in)); err == nil {
				t.Fatalf("accepted:\n%s", in)
			}
		})
	}
}

func TestJSONFile(t *testing.T) {
	s, err := Parse([]byte(`{"workloads":[{"subject":"x/y/z","grants":[{"name":"g"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.ListGrants(context.Background(), authz.Subject{ID: "x/y/z"}, authz.Consistency{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(d.Grants, ",") != "g" {
		t.Fatalf("grants %v", d.Grants)
	}
}

func TestLoadMissing(t *testing.T) {
	if _, err := Load(t.TempDir() + "/missing.yaml"); err == nil {
		t.Fatal("loaded a missing file")
	}
}

// A store with no assignments yet denies everything: an error, not an
// empty answer.
func TestEmptyStoreDenies(t *testing.T) {
	s := NewEmpty()
	ctx := context.Background()
	if _, err := s.ListGrants(ctx, authz.Subject{ID: "prod/payments/ledger"}, authz.Consistency{}); err == nil {
		t.Error("ListGrants on an empty store answered")
	}
	if _, err := s.Check(ctx, authz.Subject{ID: "prod/payments/ledger"}, "payments-ledger-rw", authz.Consistency{}); err == nil {
		t.Error("Check on an empty store answered")
	}
	if s.Token() != "" {
		t.Errorf("Token = %q", s.Token())
	}
}

func TestSwap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := NewEmpty()
	changes, err := s.Watch(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	subject := authz.Subject{ID: "prod/payments/ledger"}
	first, err := Build(File{Services: []Service{{Name: "svc", Team: "t", Members: []string{subject.ID}, Grants: []Assignment{{Name: "g1"}}}}}, "t1")
	if err != nil {
		t.Fatal(err)
	}
	s.Swap(first)
	if c := receive(t, changes); c.Token != "t1" || c.Subject.ID != "" || c.Grant != "" {
		t.Errorf("change after the first swap = %+v, want every subject at t1", c)
	}
	d, err := s.ListGrants(ctx, subject, authz.Consistency{})
	if err != nil || !reflect.DeepEqual(d.Grants, []string{"g1"}) || d.Token != "t1" {
		t.Errorf("ListGrants after the first swap = %+v, %v", d, err)
	}

	second, err := Build(File{Workloads: []Workload{{Subject: subject.ID, Grants: []Assignment{{Name: "g2"}}}}}, "t2")
	if err != nil {
		t.Fatal(err)
	}
	s.Swap(second)
	if c := receive(t, changes); c.Token != "t2" {
		t.Errorf("change after the second swap = %+v", c)
	}
	d, err = s.ListGrants(ctx, subject, authz.Consistency{})
	if err != nil || !reflect.DeepEqual(d.Grants, []string{"g2"}) || d.Token != "t2" || d.Tags["service"] != "" {
		t.Errorf("ListGrants after the second swap = %+v, %v", d, err)
	}
	if _, err := s.ListGrants(ctx, subject, authz.Consistency{AtLeastAsFresh: "t1"}); err == nil {
		t.Error("answered at least as fresh as a token swapped out")
	}

	// The same snapshot again is no change.
	s.Swap(second)
	select {
	case c := <-changes:
		t.Errorf("a change for a swap to the same token: %+v", c)
	case <-time.After(50 * time.Millisecond):
	}

	// A watcher that comes back behind is told at once.
	late, err := s.Watch(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if c := receive(t, late); c.Token != "t2" {
		t.Errorf("change for a watcher behind = %+v", c)
	}

	cancel()
	for range changes {
	}
}

func receive(t *testing.T, ch <-chan authz.Change) authz.Change {
	t.Helper()
	select {
	case c, ok := <-ch:
		if !ok {
			t.Fatal("watch closed")
		}
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("no change")
	}
	return authz.Change{}
}

// The published document is the file it stands for, field for field: the
// store built from it answers as the store parsed from the file does.
func TestFromAssignments(t *testing.T) {
	published := &grant.Assignments{
		Version: "v1", GeneratedAt: "2026-01-01T00:00:00Z",
		Services: []grant.AssignedService{{
			Name: "payments-api", Team: "payments", Members: []string{"prod/payments/ledger", "prod/payments/worker"},
			Grants: []grant.BoundedGrant{{Name: "payments-ledger-rw"}, {Name: "prod-only", Clusters: []string{"prod-a", "prod-b"}}},
		}},
		Workloads: []grant.AssignedWorkload{
			{Subject: "prod/payments/ledger", Grants: []grant.BoundedGrant{{Name: "break-glass", ExpiresAt: "2026-06-01T00:00:00Z"}, {Name: "payments-ledger-rw"}}},
			{Subject: "prod/payments/suspended", Suspended: true, Grants: []grant.BoundedGrant{{Name: "payments-ledger-rw"}}},
			{Subject: "prod/payments/lonely", Grants: []grant.BoundedGrant{{Name: "cluster-and-time", Clusters: []string{"prod-a"}, ExpiresAt: "2026-06-01T00:00:00Z"}}},
		},
	}
	var parsed File
	if err := yaml.Unmarshal([]byte(file), &parsed); err != nil {
		t.Fatal(err)
	}
	if got := FromAssignments(published); !reflect.DeepEqual(got, parsed) {
		t.Errorf("FromAssignments =\n%+v\nwant the file's\n%+v", got, parsed)
	}
}
