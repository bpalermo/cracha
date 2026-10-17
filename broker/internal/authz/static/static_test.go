package static

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bpalermo/cracha/broker/internal/authz"
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
			if !reflect.DeepEqual(d.Grants, tt.grants) {
				t.Errorf("grants %v, want %v", d.Grants, tt.grants)
			}
			if !reflect.DeepEqual(d.Tags, tt.tags) {
				t.Errorf("tags %v, want %v", d.Tags, tt.tags)
			}
			if d.Token != s.Token() || d.Token == "" {
				t.Errorf("token %q, store %q", d.Token, s.Token())
			}
			if len(d.Trace) == 0 {
				t.Error("no trace")
			}
		})
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
