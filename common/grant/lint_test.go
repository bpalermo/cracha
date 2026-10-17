package grant

import (
	"strings"
	"testing"
	"time"
)

func TestLintSize(t *testing.T) {
	small := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}`
	big := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":[` +
		strings.Repeat(`"arn:aws:s3:::bucket/prefix/key-number-0000000000/*",`, 50) + `"arn:aws:s3:::b/*"]}]}`
	manyTags := map[string]string{}
	for i := 0; i < 45; i++ {
		manyTags[string(rune('a'+i%26))+string(rune('a'+i/26))] = "v"
	}
	fatTags := map[string]string{}
	for i := 0; i < 6; i++ {
		fatTags[string(rune('a'+i))] = strings.Repeat("v", 256)
	}
	tests := []struct {
		name   string
		policy string
		tags   map[string]string
		want   string
	}{
		{"fits", small, map[string]string{"team": "payments"}, ""},
		{"no policy", "", nil, ""},
		{"pretty policy is measured minified", "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": []\n}", nil, ""},
		{"policy too large", big, nil, "STS allows at most 2048"},
		{"broken policy", "{", nil, "not valid JSON"},
		{"too many tags", small, manyTags, "at most 44 allowed"},
		{"tags too fat", small, fatTags, "at most 1280 allowed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := LintSize("g", tt.policy, tt.tags)
			if tt.want == "" {
				if !r.Problems.OK() {
					t.Errorf("problems = %v, want none", r.Problems)
				}
				return
			}
			if r.Problems.OK() || !strings.Contains(strings.Join(r.Problems, "\n"), tt.want) {
				t.Errorf("problems = %v, want one containing %q", r.Problems, tt.want)
			}
		})
	}
	r := LintSize("g", "{ \"Version\": \"2012-10-17\" }", map[string]string{"team": "payments"})
	if r.PolicyChars != len(`{"Version":"2012-10-17"}`) || r.TagCount != 1 || r.TagChars != 12 {
		t.Errorf("report = %+v", r)
	}
}

func TestLintEnvelope(t *testing.T) {
	envelope := []string{"arn:aws:dynamodb:*:111122223333:table/payments-*"}
	tests := []struct {
		name     string
		policy   string
		envelope []string
		want     string
	}{
		{"inside", `{"Statement":[{"Effect":"Allow","Action":"dynamodb:Query","Resource":["arn:aws:dynamodb:*:111122223333:table/payments-a","arn:aws:dynamodb:us-east-1:111122223333:table/payments-b/index/*"]}]}`, envelope, ""},
		{"single statement object", `{"Statement":{"Effect":"Allow","Action":"dynamodb:Query","Resource":"arn:aws:dynamodb:*:111122223333:table/payments-a"}}`, envelope, ""},
		{"deny is not checked", `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`, envelope, ""},
		{"star with star envelope", `{"Statement":[{"Effect":"Allow","Action":"sts:GetCallerIdentity","Resource":"*"}]}`, []string{"*"}, ""},
		{"outside", `{"Statement":[{"Effect":"Allow","Action":"dynamodb:Query","Resource":"arn:aws:dynamodb:*:111122223333:table/other"}]}`, envelope, `"arn:aws:dynamodb:*:111122223333:table/other" matches no envelope pattern`},
		{"star", `{"Statement":[{"Effect":"Allow","Action":"dynamodb:Query","Resource":"*"}]}`, envelope, `Resource "*" is outside the envelope`},
		{"star with arn star envelope", `{"Statement":[{"Effect":"Allow","Action":"dynamodb:Query","Resource":"*"}]}`, []string{"arn:*"}, `Resource "*" is outside the envelope`},
		{"not resource", `{"Statement":[{"Effect":"Allow","Action":"dynamodb:Query","NotResource":"arn:aws:dynamodb:*:111122223333:table/x"}]}`, envelope, "NotResource cannot be checked"},
		{"no resource", `{"Statement":[{"Effect":"Allow","Action":"dynamodb:Query"}]}`, envelope, "needs a Resource"},
		{"bad resource type", `{"Statement":[{"Effect":"Allow","Action":"dynamodb:Query","Resource":[1]}]}`, envelope, "not a string"},
		{"no statement", `{"Version":"2012-10-17"}`, envelope, "no Statement"},
		{"not json", `nope`, envelope, "not a JSON object"},
		{"statement not object", `{"Statement":["x"]}`, envelope, "statement 0 is not an object"},
		{"second of two outside", `{"Statement":[{"Effect":"Allow","Action":"a","Resource":"arn:aws:dynamodb:*:111122223333:table/payments-a"},{"Effect":"Allow","Action":"b","Resource":"arn:aws:s3:::x"}]}`, envelope, `statement 1: Resource "arn:aws:s3:::x"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := LintEnvelope("g", tt.policy, tt.envelope)
			if tt.want == "" {
				if !r.Problems.OK() {
					t.Errorf("problems = %v, want none", r.Problems)
				}
				return
			}
			if r.Problems.OK() || !strings.Contains(strings.Join(r.Problems, "\n"), tt.want) {
				t.Errorf("problems = %v, want one containing %q", r.Problems, tt.want)
			}
		})
	}
	r := LintEnvelope("g", `{"Statement":[{"Effect":"Allow","Action":"a","Resource":["arn:aws:dynamodb:*:111122223333:table/payments-a","arn:aws:s3:::x"]}]}`, envelope)
	if len(r.Resources) != 2 || r.Resources[0].Matched != envelope[0] || r.Resources[1].Matched != "" {
		t.Errorf("resources = %+v", r.Resources)
	}
}

func TestComposePolicies(t *testing.T) {
	got, err := ComposePolicies(
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"a","Resource":"r1"}}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"b","Resource":"r2"},{"Effect":"Deny","Action":"c","Resource":"*"}]}`,
	)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"Statement":[{"Action":"a","Effect":"Allow","Resource":"r1"},{"Action":"b","Effect":"Allow","Resource":"r2"},{"Action":"c","Effect":"Deny","Resource":"*"}],"Version":"2012-10-17"}`
	if got != want {
		t.Errorf("ComposePolicies =\n%s\nwant\n%s", got, want)
	}
	if _, err := ComposePolicies(`{}`); err == nil || !strings.Contains(err.Error(), "policy 0") {
		t.Errorf("error = %v", err)
	}
}

func renderAll(t *testing.T, src *Source) map[string]string {
	t.Helper()
	rendered := map[string]string{}
	for _, g := range src.Grants {
		if sp := g.Spec.SessionPolicy; sp != nil {
			policy, err := src.Templates[sp.Template].Render(g.Spec.Account, sp.Params)
			if err != nil {
				t.Fatalf("render %s: %v", g.Name(), err)
			}
			rendered[g.Name()] = policy
		}
	}
	return rendered
}

var lintNow = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

func TestLintCompositionGood(t *testing.T) {
	src := loadGood(t)
	r := LintComposition(src, renderAll(t, src), lintNow)
	if !r.Problems.OK() {
		t.Fatalf("problems = %v", r.Problems)
	}
	if strings.Join(r.Expired, ",") != "legacy-expired" {
		t.Errorf("expired = %v, want legacy-expired", r.Expired)
	}
	if len(r.Compositions) != 2 {
		t.Fatalf("compositions = %+v, want 2", r.Compositions)
	}
	billing, payments := r.Compositions[0], r.Compositions[1]
	if billing.Subject != "prod/billing/reports" || billing.Cluster != "" || billing.Policy != "" ||
		len(billing.ManagedPolicyArns) != 2 || len(billing.BaseRoles) != 1 {
		t.Errorf("billing = %+v", billing)
	}
	// The payments subject has an unbounded assignment and one bound to a
	// cluster: one union, for that cluster, takes in both.
	if payments.Subject != "prod/payments/ledger" || payments.Cluster != "prod-us-east-1" ||
		strings.Join(payments.Assignments, ",") != "payments-ledger,payments-ledger-temp" ||
		strings.Join(payments.Grants, ",") != "payments-ledger-rw,payments-outbox-r" ||
		len(payments.BaseRoles) != 1 || payments.PolicyChars == 0 || payments.PolicyChars != len(payments.Policy) ||
		payments.SessionTags["team"] != "payments" || payments.SessionTags["service"] != "outbox" {
		t.Errorf("payments = %+v", payments)
	}
}

func TestLintCompositionProblems(t *testing.T) {
	tests := []struct {
		dir  string
		want string
	}{
		{"two-shapes", "grants span 2 base roles"},
		{"tag-conflict", `session tag "team" is "billing" in grant payments-ledger-other and "payments" in grant payments-ledger-rw`},
	}
	for _, tt := range tests {
		t.Run(tt.dir, func(t *testing.T) {
			src, err := Load("testdata/lint/" + tt.dir)
			if err != nil {
				t.Fatal(err)
			}
			r := LintComposition(src, renderAll(t, src), lintNow)
			if r.Problems.OK() || !strings.Contains(strings.Join(r.Problems, "\n"), tt.want) {
				t.Errorf("problems = %v, want one containing %q", r.Problems, tt.want)
			}
			if !strings.HasPrefix(r.Problems[0], "subject prod/payments/ledger: ") {
				t.Errorf("problem not prefixed with the subject: %q", r.Problems[0])
			}
		})
	}
}

func TestLintCompositionSynthetic(t *testing.T) {
	grant := func(name, role string, managed ...string) *Grant {
		return &Grant{
			Kind: KindGrant, Metadata: Metadata{Name: name},
			Spec: GrantSpec{
				Account: "111122223333", BaseRole: role, ManagedPolicyArns: managed,
				Envelope: []string{"arn:aws:s3:::" + name + "/*"},
			},
		}
	}
	assign := func(name, subject string, clusters []string, grants ...string) *Assignment {
		return &Assignment{
			Kind: KindAssignment, Metadata: Metadata{Name: name},
			Spec: AssignmentSpec{Subject: subject, Grants: grants, Clusters: clusters},
		}
	}
	role := "arn:aws:iam::111122223333:role/shape"
	var manyA, manyB []string
	for i := 0; i < 6; i++ {
		manyA = append(manyA, "arn:aws:iam::aws:policy/a"+string(rune('0'+i)))
		manyB = append(manyB, "arn:aws:iam::aws:policy/b"+string(rune('0'+i)))
	}
	src := &Source{
		Grants: []*Grant{grant("a", role, manyA...), grant("b", role, manyB...), grant("c", role), grant("d", role)},
		Assignments: []*Assignment{
			assign("x-east", "x", []string{"east"}, "a"),
			assign("x-west", "x", []string{"west"}, "b"),
			assign("x-all", "x", nil, "c"),
			assign("y", "y", nil, "d", "ghost"),
			{Kind: KindAssignment, Metadata: Metadata{Name: "z"}, Spec: AssignmentSpec{Subject: "z", Grants: []string{"d"}, ExpiresAt: "bad"}},
		},
	}
	rendered := map[string]string{
		"c": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::c/*"}]}`,
		"d": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::elsewhere/*"}]}`,
	}
	r := LintComposition(src, rendered, lintNow)
	// x is checked once per named cluster, each taking in the unbounded c.
	var scopes []string
	for _, c := range r.Compositions {
		scopes = append(scopes, c.Subject+"@"+c.Cluster+"="+strings.Join(c.Grants, "+"))
	}
	if got, want := strings.Join(scopes, " "), "x@east=a+c x@west=b+c y@=d+ghost"; got != want {
		t.Errorf("compositions = %s, want %s", got, want)
	}
	all := strings.Join(r.Problems, "\n")
	for _, want := range []string{
		"assignment z: expiresAt",
		`subject y: grant "ghost" not found`,
		`subject y: composed session policy against the union envelope: statement 0: Resource "arn:aws:s3:::elsewhere/*" matches no envelope pattern`,
	} {
		if !strings.Contains(all, want) {
			t.Errorf("problems = %v, want one containing %q", r.Problems, want)
		}
	}
	for _, c := range r.Compositions {
		if c.Subject == "x" && !c.Problems.OK() {
			t.Errorf("x@%s = %v, want no problems (6 managed policies each)", c.Cluster, c.Problems)
		}
	}
	// Eleven managed policies in one cluster union is too many.
	src.Assignments[0].Spec.Grants = []string{"a", "b"}
	r = LintComposition(src, rendered, lintNow)
	if !strings.Contains(strings.Join(r.Problems, "\n"), "subject x in cluster east: 12 managed policy ARNs in total") {
		t.Errorf("problems = %v, want the managed policy total", r.Problems)
	}
}
