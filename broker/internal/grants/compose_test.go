package grants

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const (
	dynamoRole = "arn:aws:iam::111122223333:role/broker/shape-dynamo-rw"
	s3Role     = "arn:aws:iam::111122223333:role/broker/shape-s3-reader"
)

func ledgerRW() ResolvedGrant {
	return ResolvedGrant{
		Name:     "payments-ledger-rw",
		Account:  "111122223333",
		BaseRole: dynamoRole,
		SessionPolicy: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["dynamodb:GetItem","dynamodb:PutItem"],
			"Resource":["arn:aws:dynamodb:us-east-1:111122223333:table/payments-ledger","arn:aws:dynamodb:us-east-1:111122223333:table/payments-ledger/index/*"]}]}`,
		SessionTags:     map[string]string{"team": "payments"},
		DurationSeconds: 3600,
		Envelope:        []string{"arn:aws:dynamodb:*:111122223333:table/payments-*"},
	}
}

func outboxR() ResolvedGrant {
	return ResolvedGrant{
		Name:              "payments-outbox-r",
		Account:           "111122223333",
		BaseRole:          dynamoRole,
		SessionPolicy:     `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"dynamodb:Query","Resource":"arn:aws:dynamodb:us-east-1:111122223333:table/payments-outbox"}}`,
		ManagedPolicyARNs: []string{"arn:aws:iam::111122223333:policy/outbox-extra"},
		SessionTags:       map[string]string{"team": "payments"},
		DurationSeconds:   1800,
		Envelope:          []string{"arn:aws:dynamodb:*:111122223333:table/payments-*"},
	}
}

func denyReason(t *testing.T, err error) Reason {
	t.Helper()
	var d *DenyError
	if !errors.As(err, &d) {
		t.Fatalf("error %v is not a DenyError", err)
	}
	return d.Reason
}

func TestComposeUnion(t *testing.T) {
	src := NewStatic("v1", ledgerRW(), outboxR())
	c, err := Compose(src, []string{"payments-outbox-r", "payments-ledger-rw", "payments-outbox-r", ""}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.BaseRole != dynamoRole || c.Shape != "shape-dynamo-rw" || c.Account != "111122223333" {
		t.Errorf("shape %+v", c)
	}
	if !reflect.DeepEqual(c.Grants, []string{"payments-ledger-rw", "payments-outbox-r"}) {
		t.Errorf("grants %v", c.Grants)
	}
	if c.DurationSeconds != 1800 {
		t.Errorf("duration %d, want the minimum 1800", c.DurationSeconds)
	}
	if !reflect.DeepEqual(c.SessionTags, map[string]string{"team": "payments"}) {
		t.Errorf("tags %v", c.SessionTags)
	}
	if !reflect.DeepEqual(c.ManagedPolicyARNs, []string{"arn:aws:iam::111122223333:policy/outbox-extra"}) {
		t.Errorf("managed %v", c.ManagedPolicyARNs)
	}
	var doc struct {
		Version   string
		Statement []map[string]any
	}
	if err := json.Unmarshal([]byte(c.Policy), &doc); err != nil {
		t.Fatalf("policy %q: %v", c.Policy, err)
	}
	if doc.Version != PolicyVersion || len(doc.Statement) != 2 {
		t.Errorf("policy %s", c.Policy)
	}
	if doc.Statement[1]["Action"] != "dynamodb:Query" {
		t.Errorf("statement order or content: %s", c.Policy)
	}
	if strings.ContainsAny(c.Policy, "\n\t") {
		t.Errorf("policy is not compact: %q", c.Policy)
	}
	// Deterministic regardless of input order.
	again, err := Compose(src, []string{"payments-ledger-rw", "payments-outbox-r"}, nil)
	if err != nil || !reflect.DeepEqual(again, c) {
		t.Errorf("order-dependent: %+v vs %+v (%v)", again, c, err)
	}
}

func TestComposeNoInlinePolicy(t *testing.T) {
	g := ledgerRW()
	g.SessionPolicy = ""
	g.ManagedPolicyARNs = []string{"arn:aws:iam::111122223333:policy/ledger"}
	g.DurationSeconds = 0
	c, err := Compose(NewStatic("v1", g), []string{g.Name}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Policy != "" {
		t.Errorf("policy %q, want none", c.Policy)
	}
	if c.DurationSeconds != DefaultDurationSeconds {
		t.Errorf("duration %d", c.DurationSeconds)
	}
}

func TestComposeDenies(t *testing.T) {
	tooBigPolicy := func() ResolvedGrant {
		g := ledgerRW()
		g.SessionPolicy = fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"dynamodb:GetItem","Resource":"arn:aws:dynamodb:us-east-1:111122223333:table/payments-%s"}]}`, strings.Repeat("x", 2100))
		return g
	}
	manyManaged := func() ResolvedGrant {
		g := outboxR()
		for i := 0; i < 11; i++ {
			g.ManagedPolicyARNs = append(g.ManagedPolicyARNs, fmt.Sprintf("arn:aws:iam::111122223333:policy/p%d", i))
		}
		return g
	}
	otherShape := func() ResolvedGrant {
		g := outboxR()
		g.BaseRole = s3Role
		return g
	}
	otherAccount := func() ResolvedGrant {
		g := outboxR()
		g.Account = "444455556666"
		return g
	}
	outside := func() ResolvedGrant {
		g := ledgerRW()
		g.SessionPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"dynamodb:GetItem","Resource":["arn:aws:dynamodb:us-east-1:111122223333:table/payments-ledger","arn:aws:dynamodb:us-east-1:111122223333:table/billing-ledger"]}]}`
		return g
	}
	star := func() ResolvedGrant {
		g := ledgerRW()
		g.SessionPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"dynamodb:GetItem","Resource":"*"}]}`
		return g
	}
	noResource := func() ResolvedGrant {
		g := ledgerRW()
		g.SessionPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"dynamodb:GetItem"}]}`
		return g
	}
	notResource := func() ResolvedGrant {
		g := ledgerRW()
		g.SessionPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"dynamodb:GetItem","NotResource":"arn:aws:dynamodb:us-east-1:111122223333:table/x","Resource":"arn:aws:dynamodb:us-east-1:111122223333:table/payments-x"}]}`
		return g
	}
	emptyEnvelope := func() ResolvedGrant {
		g := ledgerRW()
		g.Envelope = nil
		return g
	}
	otherGrantsEnvelope := func() ResolvedGrant {
		// The envelope of another grant in the set must not cover this one.
		g := outboxR()
		g.Envelope = []string{"arn:aws:dynamodb:*:111122223333:table/other-*"}
		return g
	}
	teamConflict := func() ResolvedGrant {
		g := outboxR()
		g.SessionTags = map[string]string{"team": "billing"}
		return g
	}

	tests := []struct {
		name   string
		grants []ResolvedGrant
		names  []string
		reason Reason
	}{
		{"no grants", []ResolvedGrant{ledgerRW()}, nil, ReasonNoGrant},
		{"only empty names", []ResolvedGrant{ledgerRW()}, []string{""}, ReasonNoGrant},
		{"unknown grant", []ResolvedGrant{ledgerRW()}, []string{"payments-ledger-rw", "nope"}, ReasonNoGrant},
		{"two shapes", []ResolvedGrant{ledgerRW(), otherShape()}, []string{"payments-ledger-rw", "payments-outbox-r"}, ReasonAmbiguous},
		{"two accounts", []ResolvedGrant{ledgerRW(), otherAccount()}, []string{"payments-ledger-rw", "payments-outbox-r"}, ReasonAmbiguous},
		{"tag conflict", []ResolvedGrant{ledgerRW(), teamConflict()}, []string{"payments-ledger-rw", "payments-outbox-r"}, ReasonAmbiguous},
		{"inline too large", []ResolvedGrant{tooBigPolicy()}, []string{"payments-ledger-rw"}, ReasonPolicyTooLarge},
		{"too many managed", []ResolvedGrant{manyManaged()}, []string{"payments-outbox-r"}, ReasonPolicyTooLarge},
		{"resource outside envelope", []ResolvedGrant{outside()}, []string{"payments-ledger-rw"}, ReasonEnvelopeViolation},
		{"star resource", []ResolvedGrant{star()}, []string{"payments-ledger-rw"}, ReasonEnvelopeViolation},
		{"no resource", []ResolvedGrant{noResource()}, []string{"payments-ledger-rw"}, ReasonEnvelopeViolation},
		{"not resource", []ResolvedGrant{notResource()}, []string{"payments-ledger-rw"}, ReasonEnvelopeViolation},
		{"empty envelope", []ResolvedGrant{emptyEnvelope()}, []string{"payments-ledger-rw"}, ReasonEnvelopeViolation},
		{"envelope is per grant", []ResolvedGrant{ledgerRW(), otherGrantsEnvelope()}, []string{"payments-ledger-rw", "payments-outbox-r"}, ReasonEnvelopeViolation},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Compose(NewStatic("v1", tt.grants...), tt.names, nil)
			if err == nil {
				t.Fatal("composed")
			}
			if got := denyReason(t, err); got != tt.reason {
				t.Fatalf("reason %q, want %q (%v)", got, tt.reason, err)
			}
		})
	}
}

func TestComposeErrors(t *testing.T) {
	malformed := ledgerRW()
	malformed.SessionPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":`
	badVersion := ledgerRW()
	badVersion.SessionPolicy = `{"Version":"2008-10-17","Statement":[{"Effect":"Allow","Action":"x","Resource":"arn:aws:dynamodb:us-east-1:111122223333:table/payments-ledger"}]}`
	badTagKey := ledgerRW()
	badTagKey.SessionTags = map[string]string{"cluster": "x"}
	shortDuration := ledgerRW()
	shortDuration.DurationSeconds = 60
	noRole := ledgerRW()
	noRole.BaseRole = ""
	for name, g := range map[string]ResolvedGrant{"malformed": malformed, "bad version": badVersion, "bad tag key": badTagKey, "short duration": shortDuration, "no role": noRole} {
		t.Run(name, func(t *testing.T) {
			_, err := Compose(NewStatic("v1", g), []string{g.Name}, nil)
			if err == nil {
				t.Fatal("composed")
			}
			var d *DenyError
			if errors.As(err, &d) {
				t.Fatalf("got a deny reason %q for an unusable grant: %v", d.Reason, err)
			}
		})
	}
}

func TestStatementsOf(t *testing.T) {
	policy := func(statement string) string {
		return `{"Version":"2012-10-17","Statement":` + statement + `}`
	}
	tests := []struct {
		name   string
		policy string
		reason Reason // "" when the policy is unusable rather than denied
	}{
		{"no statement", `{"Version":"2012-10-17"}`, ""},
		{"statement not an object", policy(`[1]`), ""},
		{"statement list malformed", policy(`[{"Effect":"Allow"},`), ""},
		{"resource neither string nor list", policy(`[{"Effect":"Allow","Resource":5}]`), ""},
		{"empty resource list", policy(`[{"Effect":"Allow","Resource":[]}]`), ReasonEnvelopeViolation},
		{"second statement outside envelope", policy(`[{"Effect":"Allow","Resource":"arn:aws:dynamodb:us-east-1:111122223333:table/payments-a"},{"Effect":"Allow","Resource":"arn:aws:dynamodb:us-east-1:111122223333:table/billing"}]`), ReasonEnvelopeViolation},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := ledgerRW()
			g.SessionPolicy = tt.policy
			_, err := statementsOf(g)
			if err == nil {
				t.Fatal("accepted")
			}
			var d *DenyError
			if got := errors.As(err, &d); got != (tt.reason != "") {
				t.Fatalf("deny %v, want %v: %v", got, tt.reason != "", err)
			}
			if d != nil && d.Reason != tt.reason {
				t.Fatalf("reason %q, want %q", d.Reason, tt.reason)
			}
		})
	}
	// A single statement, not in a list, and a policy without a Version.
	g := ledgerRW()
	g.SessionPolicy = `{"Statement":{"Effect":"Allow","Action":"dynamodb:GetItem", "Resource": "arn:aws:dynamodb:us-east-1:111122223333:table/payments-a"}}`
	stmts, err := statementsOf(g)
	if err != nil || len(stmts) != 1 {
		t.Fatalf("statements %s: %v", stmts, err)
	}
	if string(stmts[0]) != `{"Effect":"Allow","Action":"dynamodb:GetItem","Resource":"arn:aws:dynamodb:us-east-1:111122223333:table/payments-a"}` {
		t.Errorf("not compact: %s", stmts[0])
	}
}

func TestComposeDurationCap(t *testing.T) {
	g := ledgerRW()
	g.DurationSeconds = 7200
	c, err := Compose(NewStatic("v1", g), []string{g.Name}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.DurationSeconds != MaxDurationSeconds {
		t.Fatalf("duration %d", c.DurationSeconds)
	}
}

func TestMatchARN(t *testing.T) {
	tests := []struct {
		pattern, arn string
		want         bool
	}{
		{"arn:aws:dynamodb:*:111122223333:table/payments-*", "arn:aws:dynamodb:us-east-1:111122223333:table/payments-ledger", true},
		{"arn:aws:dynamodb:*:111122223333:table/payments-*", "arn:aws:dynamodb:us-east-1:111122223333:table/payments-ledger/index/x", true},
		{"arn:aws:dynamodb:*:111122223333:table/payments-*", "arn:aws:dynamodb:us-east-1:111122223333:table/billing", false},
		{"arn:aws:dynamodb:*:111122223333:table/payments-*", "arn:aws:dynamodb:us-east-1:444455556666:table/payments-ledger", false},
		{"arn:aws:s3:::bucket-?", "arn:aws:s3:::bucket-1", true},
		{"arn:aws:s3:::bucket-?", "arn:aws:s3:::bucket-12", false},
		{"*", "anything", true},
		{"", "", true},
		{"", "x", false},
		{"a*b*c", "aXXbYYc", true},
		{"a*b*c", "aXXbYY", false},
		{"ARN:x", "arn:x", false},
	}
	for _, tt := range tests {
		if got := MatchARN(tt.pattern, tt.arn); got != tt.want {
			t.Errorf("MatchARN(%q, %q) = %v, want %v", tt.pattern, tt.arn, got, tt.want)
		}
	}
}

func TestShapeName(t *testing.T) {
	if got := ShapeName(dynamoRole); got != "shape-dynamo-rw" {
		t.Errorf("got %q", got)
	}
	if got := ShapeName("shape"); got != "shape" {
		t.Errorf("got %q", got)
	}
}

func TestStaticReplace(t *testing.T) {
	s := NewStatic("v1", ledgerRW())
	s.Replace("v2", outboxR())
	if s.Version() != "v2" {
		t.Errorf("version %q", s.Version())
	}
	if _, ok := s.Lookup("payments-ledger-rw"); ok {
		t.Error("old grant survived Replace")
	}
	if !reflect.DeepEqual(s.Names(), []string{"payments-outbox-r"}) {
		t.Errorf("names %v", s.Names())
	}
}
