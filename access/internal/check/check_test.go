package check

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bpalermo/cracha/access/internal/check/checktest"
	"github.com/bpalermo/cracha/access/internal/store"
	"github.com/bpalermo/cracha/common/grant"
	"github.com/bpalermo/cracha/common/spicedb"
)

var now = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

func assignee(g, subject string) store.Relationship {
	return store.Relationship{ResourceType: spicedb.TypeGrant, ResourceID: g, Relation: spicedb.RelationAssigneeWorkload, SubjectType: spicedb.TypeWorkload, SubjectID: subject}
}

func serviceGrant(g, service string) store.Relationship {
	return store.Relationship{ResourceType: spicedb.TypeGrant, ResourceID: g, Relation: spicedb.RelationAssigneeService, SubjectType: spicedb.TypeService, SubjectID: service}
}

func member(service, subject string) store.Relationship {
	return store.Relationship{ResourceType: spicedb.TypeService, ResourceID: service, Relation: spicedb.RelationMember, SubjectType: spicedb.TypeWorkload, SubjectID: subject}
}

func bucket(name, relation, subject string) store.Relationship {
	r, err := store.Tuple{Kind: grant.ResourceS3Bucket, Name: name, Relation: relation, Subject: subject}.Relationship()
	if err != nil {
		panic(err)
	}
	return r
}

func refusal(t *testing.T, err error) *Refusal {
	t.Helper()
	var r *Refusal
	if !errors.As(err, &r) {
		t.Fatalf("err = %v, want a refusal", err)
	}
	return r
}

func TestEvaluate(t *testing.T) {
	b := checktest.Bundle(t, "v1")
	const w = "prod/payments/ledger"
	base := []store.Relationship{assignee("data-read", w), bucket("data-a", grant.RelationReader, w)}
	tests := []struct {
		name   string
		rels   []store.Relationship
		add    store.Tuple
		reason string
	}{
		{"in the envelope", base, store.Tuple{Kind: grant.ResourceS3Bucket, Name: "data-b", Relation: grant.RelationReader, Subject: w}, ""},
		{"outside the envelope", base, store.Tuple{Kind: grant.ResourceS3Bucket, Name: "secrets", Relation: grant.RelationReader, Subject: w}, ReasonResourceOutsideEnvelope},
		{"no grant renders it", base, store.Tuple{Kind: grant.ResourceDynamoDBTable, Name: "orders-1", Relation: grant.RelationReader, Subject: w}, ReasonNoGrant},
		{"writer needs a write grant to reach", base, store.Tuple{Kind: grant.ResourceS3Bucket, Name: "data-c", Relation: grant.RelationWriter, Subject: w}, ""},
		{"a second shape", append(base, member("payments", w)), store.Tuple{Kind: store.KindService, Name: "other", Relation: spicedb.RelationMember, Subject: w}, ""},
		{"service grant of another shape", append(base, serviceGrant("other-shape", "other")), store.Tuple{Kind: store.KindService, Name: "other", Relation: spicedb.RelationMember, Subject: w}, ReasonAmbiguous},
		{
			"service access in the envelope",
			[]store.Relationship{serviceGrant("data-read", "payments"), member("payments", w)},
			store.Tuple{Kind: grant.ResourceS3Bucket, Name: "data-x", Relation: grant.RelationReader, Service: "payments"},
			"",
		},
		{
			"service access outside the envelope, no member yet",
			[]store.Relationship{serviceGrant("data-read", "payments")},
			store.Tuple{Kind: grant.ResourceS3Bucket, Name: "elsewhere", Relation: grant.RelationReader, Service: "payments"},
			ReasonResourceOutsideEnvelope,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			add := tt.add
			res, err := Checker{}.Evaluate(context.Background(), b, tt.rels, Change{Add: &add}, now)
			if tt.reason == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				if len(res.Deltas) == 0 && add.Subject != "" {
					t.Errorf("no policy delta")
				}
				return
			}
			if r := refusal(t, err); r.Reason != tt.reason {
				t.Errorf("reason = %s (%s), want %s", r.Reason, r.Detail, tt.reason)
			}
		})
	}
}

// One bucket more than the lookup grant's compiled maximum is refused
// with the broker's policy_too_large.
func TestEvaluateSizeBudget(t *testing.T) {
	b := checktest.Bundle(t, "v1")
	const w = "prod/payments/ledger"
	rels := []store.Relationship{assignee("data-read", w)}
	n := checktest.MaxResources(t, b, "data-read")
	for i := range n {
		rels = append(rels, bucket(fmt.Sprintf("data-%03d", i), grant.RelationReader, w))
	}
	add := store.Tuple{Kind: grant.ResourceS3Bucket, Name: "data-last", Relation: grant.RelationReader, Subject: w}
	_, err := Checker{}.Evaluate(context.Background(), b, rels, Change{Add: &add}, now)
	if r := refusal(t, err); r.Reason != ReasonPolicyTooLarge {
		t.Errorf("reason = %s (%s), want policy_too_large", r.Reason, r.Detail)
	}
	// Removing one never is.
	remove := store.Tuple{Kind: grant.ResourceS3Bucket, Name: "data-000", Relation: grant.RelationReader, Subject: w}
	res, err := Checker{}.Evaluate(context.Background(), b, rels, Change{Remove: &remove}, now)
	if err != nil || len(res.Deltas) != 1 || len(res.Deltas[0].ResourcesAfter["data-read"]) != n-1 {
		t.Errorf("remove = %+v, %v", res, err)
	}
}

// A problem the composition already had does not refuse a write that
// does not add one.
func TestEvaluateKeepsExistingProblems(t *testing.T) {
	b := checktest.Bundle(t, "v1")
	const w = "prod/payments/ledger"
	rels := []store.Relationship{assignee("data-read", w), assignee("other-shape", w), bucket("data-a", grant.RelationReader, w)}
	add := store.Tuple{Kind: grant.ResourceS3Bucket, Name: "data-b", Relation: grant.RelationReader, Subject: w}
	if _, err := (Checker{}).Evaluate(context.Background(), b, rels, Change{Add: &add}, now); err != nil {
		t.Errorf("refused for a problem it did not make: %v", err)
	}
}

type fakeAnalyzer struct {
	findings []grant.PolicyFinding
	pass     bool
	calls    []string
}

func (f *fakeAnalyzer) ValidatePolicy(_ context.Context, policy string) ([]grant.PolicyFinding, error) {
	f.calls = append(f.calls, "validate")
	return f.findings, nil
}

func (f *fakeAnalyzer) CheckNoNewAccess(_ context.Context, _, reference string) (*grant.AccessCheck, error) {
	f.calls = append(f.calls, "check:"+reference)
	return &grant.AccessCheck{Passed: f.pass, Reasons: []string{"wider"}}, nil
}

func TestEvaluateAccessAnalyzer(t *testing.T) {
	b := checktest.Bundle(t, "v1")
	const w = "prod/payments/ledger"
	rels := []store.Relationship{assignee("data-read", w)}
	add := store.Tuple{Kind: grant.ResourceS3Bucket, Name: "data-a", Relation: grant.RelationReader, Subject: w}
	for _, tt := range []struct {
		name   string
		a      *fakeAnalyzer
		reason string
	}{
		{"pass", &fakeAnalyzer{pass: true}, ""},
		{"blocking finding", &fakeAnalyzer{pass: true, findings: []grant.PolicyFinding{{Type: "ERROR", Code: "X"}}}, ReasonInvalidPolicy},
		{"warning only", &fakeAnalyzer{pass: true, findings: []grant.PolicyFinding{{Type: "WARNING", Code: "X"}}}, ""},
		{"new access", &fakeAnalyzer{pass: false}, ReasonEnvelopeViolation},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Checker{Analyzer: tt.a}.Evaluate(context.Background(), b, rels, Change{Add: &add}, now)
			if tt.reason == "" {
				if err != nil {
					t.Fatal(err)
				}
				if len(tt.a.calls) != 2 || !strings.Contains(tt.a.calls[1], "arn:aws:s3:::data-*") {
					t.Errorf("calls = %v", tt.a.calls)
				}
				return
			}
			if r := refusal(t, err); r.Reason != tt.reason {
				t.Errorf("reason = %s, want %s", r.Reason, tt.reason)
			}
		})
	}
}

// classify is held to the phrases common/grant's lint uses.
func TestClassify(t *testing.T) {
	for problem, want := range map[string]string{
		"grants span 2 base roles (a, b); a workload has exactly one shape":                                      ReasonAmbiguous,
		`session tag "team" is "a" in grant x and "b" in grant y`:                                                ReasonAmbiguous,
		"composed session policy is 3000 characters minified, STS allows at most 2048":                           ReasonPolicyTooLarge,
		"grant g: 20 s3_bucket resources, over its compiled maximum of 17 (the broker refuses policy_too_large)": ReasonPolicyTooLarge,
		"11 managed policy ARNs in total, STS allows at most 10":                                                 ReasonPolicyTooLarge,
		`grant "x" not found`: ReasonNoGrant,
		"grant g: rendered for its resources: x (the broker refuses resource_outside_envelope)":            ReasonResourceOutsideEnvelope,
		"composed session policy against the union envelope: statement 0":                                  ReasonEnvelopeViolation,
		"grants span 2 accounts (1, 2); one credential is one account (the broker refuses accounts_mixed)": ReasonAccountsMixed,
		"something else": ReasonInvalidComposition,
	} {
		if got := classify(problem); got != want {
			t.Errorf("classify(%q) = %s, want %s", problem, got, want)
		}
	}
}

func TestTreeReadsRelationships(t *testing.T) {
	b := checktest.Bundle(t, "v1")
	rels := []store.Relationship{
		member("payments", "prod/payments/api"),
		{ResourceType: spicedb.TypeService, ResourceID: "payments", Relation: spicedb.RelationTeam, SubjectType: spicedb.TypeTeam, SubjectID: "pay"},
		serviceGrant("data-read", "payments"),
		bucket("data-a", grant.RelationReader, "prod/payments/api"),
	}
	tree := NewTree(b, rels)
	if tree.ServiceOf("prod/payments/api") != "payments" || !tree.HasService("payments") || tree.Version() != "v1" {
		t.Fatalf("tree: service %q", tree.ServiceOf("prod/payments/api"))
	}
	cs := tree.Compositions("prod/payments/api", now)
	if len(cs) != 1 || !strings.Contains(cs[0].Policy, "arn:aws:s3:::data-a/*") {
		t.Errorf("compositions = %+v", cs)
	}
}

// With an account's implicit grant, a workload related to a bucket gets it
// without any assignment: a bucket in its envelope passes, one outside is
// refused, for a workload and for a service's members alike.
func TestEvaluateImplicitGrant(t *testing.T) {
	b := checktest.AccountBundle(t, "v1")
	const w = "prod/payments/ledger"
	for _, tt := range []struct {
		name   string
		rels   []store.Relationship
		add    store.Tuple
		reason string
	}{
		{"first bucket", nil, store.Tuple{Kind: grant.ResourceS3Bucket, Name: "data-a", Relation: grant.RelationReader, Subject: w}, ""},
		{"outside the account's envelope", nil, store.Tuple{Kind: grant.ResourceS3Bucket, Name: "secrets", Relation: grant.RelationReader, Subject: w}, ReasonResourceOutsideEnvelope},
		{"no write in the access table", nil, store.Tuple{Kind: grant.ResourceS3Bucket, Name: "data-a", Relation: grant.RelationWriter, Subject: w}, ""},
		{"service, no member yet", nil, store.Tuple{Kind: grant.ResourceS3Bucket, Name: "data-a", Relation: grant.RelationReader, Service: "payments"}, ""},
		{
			"service outside the envelope",
			[]store.Relationship{member("payments", w)},
			store.Tuple{Kind: grant.ResourceS3Bucket, Name: "secrets", Relation: grant.RelationReader, Service: "payments"},
			ReasonResourceOutsideEnvelope,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			add := tt.add
			res, err := Checker{}.Evaluate(context.Background(), b, tt.rels, Change{Add: &add}, now)
			if tt.reason == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				if add.Subject != "" && (len(res.Deltas) != 1 || !strings.Contains(res.Deltas[0].PolicyAfter, "arn:aws:s3:::data-a/*")) {
					t.Errorf("deltas = %+v", res.Deltas)
				}
				return
			}
			if r := refusal(t, err); r.Reason != tt.reason {
				t.Errorf("reason = %s (%s), want %s", r.Reason, r.Detail, tt.reason)
			}
		})
	}
}
