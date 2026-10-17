package grant

import (
	"strings"
	"testing"
)

func baseGrant() *Grant {
	return &Grant{
		Kind:     KindGrant,
		Metadata: Metadata{Name: "payments-ledger-rw"},
		Spec: GrantSpec{
			Account:  "111122223333",
			BaseRole: "arn:aws:iam::111122223333:role/broker/shape-dynamo-rw",
			SessionPolicy: &SessionPolicy{
				Template: "dynamo-table-rw",
				Params:   map[string]Param{"tables": ListParam("payments-ledger")},
			},
			SessionTags: map[string]string{"team": "payments"},
			Duration:    3600,
			Envelope:    []string{"arn:aws:dynamodb:*:111122223333:table/payments-*"},
		},
	}
}

func TestValidateGrant(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(g *Grant)
		want   string // substring of the error; empty means valid
	}{
		{"valid", func(*Grant) {}, ""},
		{"no duration", func(g *Grant) { g.Spec.Duration = 0 }, ""},
		{"managed only", func(g *Grant) {
			g.Spec.SessionPolicy = nil
			g.Spec.Envelope = nil
			g.Spec.ManagedPolicyArns = []string{"arn:aws:iam::aws:policy/ReadOnlyAccess"}
		}, ""},
		{"wildcard envelope", func(g *Grant) { g.Spec.Envelope = []string{"*"} }, ""},
		{"gov partition", func(g *Grant) { g.Spec.BaseRole = "arn:aws-us-gov:iam::111122223333:role/x" }, ""},
		{"wrong kind", func(g *Grant) { g.Kind = "Assignment" }, "kind must be Grant"},
		{"uppercase name", func(g *Grant) { g.Metadata.Name = "Payments" }, "grant name"},
		{"name too long", func(g *Grant) { g.Metadata.Name = strings.Repeat("a", 64) }, "longer than 63"},
		{"name ends with dash", func(g *Grant) { g.Metadata.Name = "payments-" }, "grant name"},
		{"short account", func(g *Grant) { g.Spec.Account = "1234" }, "must be 12 digits"},
		{"role not an arn", func(g *Grant) { g.Spec.BaseRole = "shape-dynamo-rw" }, "must be an IAM role ARN"},
		{"role is a user", func(g *Grant) { g.Spec.BaseRole = "arn:aws:iam::111122223333:user/x" }, "must be an IAM role ARN"},
		{"role in other account", func(g *Grant) { g.Spec.BaseRole = "arn:aws:iam::999999999999:role/x" }, "does not match the grant's account"},
		{"role name too long", func(g *Grant) { g.Spec.BaseRole = "arn:aws:iam::111122223333:role/" + strings.Repeat("r", 65) }, "role name longer than 64"},
		{"no policy at all", func(g *Grant) { g.Spec.SessionPolicy = nil }, "needs a sessionPolicy or managedPolicyArns"},
		{"bad template name", func(g *Grant) { g.Spec.SessionPolicy.Template = "Dynamo RW" }, "sessionPolicy.template"},
		{"bad param name", func(g *Grant) { g.Spec.SessionPolicy.Params["bad name"] = StringParam("x") }, "parameter name"},
		{"no envelope", func(g *Grant) { g.Spec.Envelope = nil }, "envelope is required"},
		{"envelope not arn", func(g *Grant) { g.Spec.Envelope = []string{"payments-*"} }, "is not an ARN pattern"},
		{"envelope with space", func(g *Grant) { g.Spec.Envelope = []string{"arn:aws:s3:::bucket/a b"} }, "is not an ARN pattern"},
		{"envelope duplicate", func(g *Grant) { g.Spec.Envelope = append(g.Spec.Envelope, g.Spec.Envelope[0]) }, "listed twice"},
		{"too many managed", func(g *Grant) {
			for i := 0; i < 11; i++ {
				g.Spec.ManagedPolicyArns = append(g.Spec.ManagedPolicyArns, "arn:aws:iam::111122223333:policy/p"+string(rune('a'+i)))
			}
		}, "STS allows at most 10"},
		{"managed not a policy", func(g *Grant) { g.Spec.ManagedPolicyArns = []string{"arn:aws:iam::111122223333:role/x"} }, "is not an IAM managed policy ARN"},
		{"managed other account", func(g *Grant) { g.Spec.ManagedPolicyArns = []string{"arn:aws:iam::999999999999:policy/x"} }, "not the grant's account"},
		{"managed duplicate", func(g *Grant) {
			g.Spec.ManagedPolicyArns = []string{"arn:aws:iam::aws:policy/x", "arn:aws:iam::aws:policy/x"}
		}, "listed twice"},
		{"duration too short", func(g *Grant) { g.Spec.Duration = 899 }, "must be between 900 and 3600"},
		{"duration too long", func(g *Grant) { g.Spec.Duration = 3601 }, "must be between 900 and 3600"},
		{"tag key reserved aws", func(g *Grant) { g.Spec.SessionTags["AWS:x"] = "1" }, "aws: prefix is reserved"},
		{"tag key broker", func(g *Grant) { g.Spec.SessionTags["spiffe-ns"] = "x" }, "set by the broker"},
		{"tag key charset", func(g *Grant) { g.Spec.SessionTags["te$m"] = "x" }, "outside the tag charset"},
		{"tag value charset", func(g *Grant) { g.Spec.SessionTags["team"] = "pay;ments" }, "outside the tag charset"},
		{"tag key long", func(g *Grant) { g.Spec.SessionTags[strings.Repeat("k", 129)] = "x" }, "longer than 128"},
		{"tag value long", func(g *Grant) { g.Spec.SessionTags["team"] = strings.Repeat("v", 257) }, "longer than 256"},
		{"tag count", func(g *Grant) {
			for i := 0; i < 45; i++ {
				g.Spec.SessionTags["k"+string(rune('a'+i%26))+string(rune('a'+i/26))] = "v"
			}
		}, "at most 44 allowed"},
		{"tag budget", func(g *Grant) {
			for i := 0; i < 6; i++ {
				g.Spec.SessionTags["k"+string(rune('a'+i))] = strings.Repeat("v", 256)
			}
		}, "at most 1280 allowed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := baseGrant()
			tt.mutate(g)
			err := ValidateGrant(g)
			if tt.want == "" {
				if err != nil {
					t.Errorf("ValidateGrant: %v, want valid", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidateGrant succeeded, want error containing %q", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestValidateGrantReportsEverything(t *testing.T) {
	g := baseGrant()
	g.Spec.Account = "1"
	g.Spec.Duration = 1
	err := ValidateGrant(g)
	if err == nil {
		t.Fatal("want an error")
	}
	for _, want := range []string{"must be 12 digits", "does not match the grant's account", "must be between"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to contain %q", err, want)
		}
	}
}

func TestValidateAssignment(t *testing.T) {
	base := func() *Assignment {
		return &Assignment{
			Kind:     KindAssignment,
			Metadata: Metadata{Name: "payments"},
			Spec: AssignmentSpec{
				Subject:   "prod/payments/ledger",
				Grants:    []string{"payments-ledger-rw"},
				ExpiresAt: "2030-01-01T00:00:00Z",
				Clusters:  []string{"prod-us-east-1"},
			},
		}
	}
	tests := []struct {
		name   string
		mutate func(a *Assignment)
		want   string
	}{
		{"valid", func(*Assignment) {}, ""},
		{"no expiry no clusters", func(a *Assignment) { a.Spec.ExpiresAt = ""; a.Spec.Clusters = nil }, ""},
		{"escaped subject", func(a *Assignment) { a.Spec.Subject = "prod/pay=2Ements/ledger|x_y-z+" }, ""},
		{"wrong kind", func(a *Assignment) { a.Kind = KindGrant }, "kind must be Assignment"},
		{"bad name", func(a *Assignment) { a.Metadata.Name = "Pay" }, "assignment name"},
		{"subject with dot", func(a *Assignment) { a.Spec.Subject = "prod.payments.ledger" }, "authorization subject encoding"},
		{"subject with colon", func(a *Assignment) { a.Spec.Subject = "spiffe://td/ns/sa" }, "authorization subject encoding"},
		{"subject empty", func(a *Assignment) { a.Spec.Subject = "" }, "authorization subject encoding"},
		{"subject long", func(a *Assignment) { a.Spec.Subject = strings.Repeat("a", 1025) }, "authorization subject encoding"},
		{"no grants", func(a *Assignment) { a.Spec.Grants = nil }, "at least one grant"},
		{"grant twice", func(a *Assignment) { a.Spec.Grants = []string{"g", "g"} }, "listed twice"},
		{"bad grant name", func(a *Assignment) { a.Spec.Grants = []string{"G"} }, "grant name"},
		{"bad expiry", func(a *Assignment) { a.Spec.ExpiresAt = "tomorrow" }, "expiresAt"},
		{"empty cluster", func(a *Assignment) { a.Spec.Clusters = []string{""} }, "empty name"},
		{"cluster twice", func(a *Assignment) { a.Spec.Clusters = []string{"c", "c"} }, "listed twice"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := base()
			tt.mutate(a)
			err := ValidateAssignment(a)
			if tt.want == "" {
				if err != nil {
					t.Errorf("ValidateAssignment: %v, want valid", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

// A document that does not validate on its own is reported by ValidateSource
// with its name and path, and its references are not checked.
func TestValidateSourceInvalidDocuments(t *testing.T) {
	g := baseGrant()
	g.Path = "grants/bad.yaml"
	g.Spec.Account = "1"
	a := &Assignment{
		Kind: KindAssignment, Metadata: Metadata{Name: "bad"}, Path: "assignments/bad.yaml",
		Spec: AssignmentSpec{Subject: "prod/x/y", Grants: []string{"ghost"}, Clusters: []string{""}},
	}
	err := ValidateSource(&Source{Grants: []*Grant{g}, Assignments: []*Assignment{a}, Templates: map[string]*Template{}})
	if err == nil {
		t.Fatal("ValidateSource succeeded, want an error")
	}
	for _, want := range []string{
		"grant payments-ledger-rw (grants/bad.yaml): ",
		"must be 12 digits",
		"assignment bad (assignments/bad.yaml): ",
		"clusters: empty name",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to contain %q", err, want)
		}
	}
	for _, unwanted := range []string{`template "dynamo-table-rw" not found`, `grant "ghost" not found`} {
		if strings.Contains(err.Error(), unwanted) {
			t.Errorf("error = %v, references of an invalid document should not be checked (%q)", err, unwanted)
		}
	}
}
