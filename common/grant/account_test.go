package grant

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const accountsDir = "testdata/accounts"

const (
	appsRole     = "arn:aws:iam::111122223333:role/cracha/apps"
	implicitRead = "account:apps:s3_bucket:read"
	implicitW    = "account:apps:s3_bucket:write"
	implicitDDB  = "account:apps:dynamodb_table:read"
)

func accountsTree(t *testing.T, extra map[string]string) *Source {
	t.Helper()
	src, err := Load(treeCopy(t, accountsDir, extra))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return src
}

func TestCompileAccountsGolden(t *testing.T) {
	src := accountsTree(t, nil)
	c, report, err := Compile(context.Background(), src, CompileOptions{Version: "abc123", GeneratedAt: generatedAt, Lint: LintOptions{Now: lintNow}})
	if err != nil {
		t.Fatalf("Compile: %v (problems: %v)", err, report.Problems)
	}
	bundle, err := Marshal(c.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "accounts-bundle.json", bundle)
	assignments, err := MarshalAssignments(c.Assignments)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "accounts-assignments.json", assignments)
	if _, err := ParseBundle(bundle); err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	if strings.Contains(string(assignments), `"account"`) {
		t.Error("the assignments carry a resource's account; the store relates by name alone")
	}
}

func TestCompiledGrantsApplyTheAccount(t *testing.T) {
	src := accountsTree(t, nil)
	if err := ValidateSource(src); err != nil {
		t.Fatal(err)
	}
	byName := map[string]*Grant{}
	var names []string
	for _, g := range src.CompiledGrants() {
		byName[g.Name()] = g
		names = append(names, g.Name())
	}
	if want := []string{implicitDDB, implicitRead, implicitW, "legacy-batch", "payments-ledger"}; !slices.Equal(names, want) {
		t.Fatalf("compiled grants = %v, want %v", names, want)
	}
	ledger := byName["payments-ledger"]
	if ledger.Spec.BaseRole != appsRole || !slices.Equal(ledger.Spec.Envelope, src.Accounts[0].Spec.Envelope) || ledger.Implicit() {
		t.Errorf("payments-ledger = %+v, want the account role and envelope", ledger.Spec)
	}
	if src.Grant("payments-ledger").Spec.BaseRole != "" {
		t.Error("compiling changed the loaded grant")
	}
	legacy := byName["legacy-batch"]
	if legacy.Spec.BaseRole != "arn:aws:iam::111122223333:role/broker/shape-legacy" || !slices.Equal(legacy.Spec.Envelope, []string{"arn:aws:s3:::legacy-*"}) {
		t.Errorf("legacy-batch = %+v, want its own role and envelope", legacy.Spec)
	}
	w := byName[implicitW]
	if !w.Implicit() || w.Spec.BaseRole != appsRole || w.Spec.Duration != 1800 {
		t.Errorf("%s = %+v", implicitW, w.Spec)
	}
	if name, l := lookupParam(w.Spec.SessionPolicy); name != "buckets" || l.Kind != ResourceS3Bucket || l.Permission != PermissionWrite {
		t.Errorf("%s looks up %s = %+v", implicitW, name, l)
	}
	if name, _ := lookupParam(byName[implicitRead].Spec.SessionPolicy); name != "bucket" {
		t.Errorf("%s fills %q, want the template's only parameter", implicitRead, name)
	}
}

func TestLintImplicitGrants(t *testing.T) {
	r := lintLookup(t, accountsTree(t, nil))
	if !r.OK() {
		t.Fatalf("problems: %v", r.Problems)
	}
	for subject, want := range map[string][]string{
		"prod/payments/api":    {implicitRead, "payments-ledger"},
		"prod/payments/worker": {implicitDDB, implicitRead, "payments-ledger"},
		"prod/data/etl":        {implicitRead, implicitW},
		"prod/legacy/batch":    {"legacy-batch"},
	} {
		c := compositionOf(t, r, subject, "")
		if !slices.Equal(c.Grants, want) {
			t.Errorf("%s: grants %v, want %v", subject, c.Grants, want)
		}
	}
	etl := compositionOf(t, r, "prod/data/etl", "")
	if want := map[string][]string{implicitRead: {"data-curated"}, implicitW: {"data-curated"}}; !reflect.DeepEqual(etl.Resources, want) {
		t.Errorf("etl resources = %v, want %v", etl.Resources, want)
	}
	if !slices.Equal(etl.BaseRoles, []string{appsRole}) || !strings.Contains(etl.Policy, "arn:aws:s3:::data-curated/incoming/*") {
		t.Errorf("etl: base roles %v, policy %s", etl.BaseRoles, etl.Policy)
	}
}

func TestLintImplicitGrantMixes(t *testing.T) {
	second := `kind: Account
metadata:
  name: data
spec:
  id: "444455556666"
  role: arn:aws:iam::444455556666:role/cracha/apps
  envelope: [arn:aws:s3:::data-*]
  access:
    - { kind: s3_bucket, permission: read, template: s3-object-read }
`
	for name, tc := range map[string]struct {
		extra map[string]string
		want  string
	}{
		"a dedicated shape beside the account role": {
			map[string]string{"access/legacy-data.yaml": access("legacy-data", "subject: prod/legacy/batch", "data-legacy", "")},
			"subject prod/legacy/batch: grants span 2 base roles",
		},
		"relations in two accounts": {
			map[string]string{
				"accounts/data.yaml":            second,
				"access/payments-exports.yaml":  access("payments-exports", "service: payments", "data-payments-exports", "111122223333"),
				"access/etl-curated.yaml":       access("etl-curated", "subject: prod/data/etl", "data-curated", "111122223333"),
				"access/worker-audit.yaml":      "",
				"access/etl-other-account.yaml": access("etl-other", "subject: prod/data/etl", "data-elsewhere", "444455556666"),
			},
			"subject prod/data/etl: grants span 2 accounts (111122223333, 444455556666); one credential is one account",
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := lintLookup(t, accountsTree(t, tc.extra))
			if !containsProblem(r.Problems, tc.want) {
				t.Errorf("problems %v, want one containing %q", r.Problems, tc.want)
			}
		})
	}
}

// access is an Access document of a bucket reader; account, when set, is
// the bucket's.
func access(name, holder, bucket, account string) string {
	resource := "{ kind: s3_bucket, name: " + bucket + " }"
	if account != "" {
		resource = "{ kind: s3_bucket, name: " + bucket + `, account: "` + account + `" }`
	}
	return "kind: Access\nmetadata:\n  name: " + name + "\nspec:\n  " + holder + "\n  resource: " + resource + "\n  relation: reader\n"
}

func containsProblem(problems Problems, want string) bool {
	for _, p := range problems {
		if strings.Contains(p, want) {
			return true
		}
	}
	return false
}

func TestValidateAccounts(t *testing.T) {
	account := func(spec string) string {
		return "kind: Account\nmetadata:\n  name: apps\nspec:\n" + spec
	}
	base := `  id: "111122223333"
  role: arn:aws:iam::111122223333:role/cracha/apps
  envelope: [arn:aws:s3:::data-*, "arn:aws:dynamodb:*:111122223333:table/*"]
`
	for name, tc := range map[string]struct {
		extra map[string]string
		want  string
	}{
		"a grant without baseRole and no Account": {
			map[string]string{"accounts/apps.yaml": "", "access/payments-exports.yaml": "", "access/etl-curated.yaml": "", "access/worker-audit.yaml": ""},
			"baseRole: required, since no Account document of account 111122223333",
		},
		"a grant without envelope and an account without one": {
			map[string]string{"accounts/apps.yaml": account(`  id: "111122223333"
  role: arn:aws:iam::111122223333:role/cracha/apps
`)},
			"envelope is required when a sessionPolicy is set, on the grant or on its Account document",
		},
		"access without envelope": {
			map[string]string{"accounts/apps.yaml": account(`  id: "111122223333"
  role: arn:aws:iam::111122223333:role/cracha/apps
  access: [{ kind: s3_bucket, permission: read, template: s3-object-read }]
`)},
			"envelope is required with access",
		},
		"a role in another account": {
			map[string]string{"accounts/apps.yaml": account(`  id: "111122223333"
  role: arn:aws:iam::444455556666:role/cracha/apps
`)},
			`role "arn:aws:iam::444455556666:role/cracha/apps": account 444455556666 does not match the account 111122223333`,
		},
		"an entry listed twice": {
			map[string]string{"accounts/apps.yaml": account(base + `  access:
    - { kind: s3_bucket, permission: read, template: s3-object-read }
    - { kind: s3_bucket, permission: read, template: s3-object-read }
`)},
			"access: s3_bucket#read listed twice",
		},
		"an unknown kind": {
			map[string]string{"accounts/apps.yaml": account(base + "  access: [{ kind: sqs_queue, permission: read, template: s3-object-read }]\n")},
			`lookup kind "sqs_queue"`,
		},
		"a lookup in params": {
			map[string]string{"accounts/apps.yaml": account(base + "  access: [{ kind: s3_bucket, permission: read, template: s3-bucket-write, param: buckets, params: { prefix: { lookup: { kind: s3_bucket, permission: read } } } }]\n")},
			"params: prefix: a lookup",
		},
		"a missing template": {
			map[string]string{"accounts/apps.yaml": account(base + "  access: [{ kind: s3_bucket, permission: read, template: nope }]\n")},
			`template "nope" not found`,
		},
		"an undeclared param": {
			map[string]string{"accounts/apps.yaml": account(base + "  access: [{ kind: s3_bucket, permission: read, template: s3-object-read, param: buckets }]\n")},
			`param "buckets" is not declared by template s3-object-read`,
		},
		"no param to fill": {
			map[string]string{"accounts/apps.yaml": account(base + "  access: [{ kind: s3_bucket, permission: read, template: s3-object-read, params: { bucket: x } }]\n")},
			"template s3-object-read leaves 0 parameters without a value",
		},
		"a bad duration": {
			map[string]string{"accounts/apps.yaml": account(base + "  access: [{ kind: s3_bucket, permission: read, template: s3-object-read, duration: 60 }]\n")},
			"access s3_bucket#read: duration 60",
		},
		"two documents of one account": {
			map[string]string{"accounts/again.yaml": strings.Replace(account(base), "name: apps", "name: again", 1)},
			"account 111122223333 already has Account document again",
		},
		"a resource in an unknown account": {
			map[string]string{"access/etl-curated.yaml": access("etl-curated", "subject: prod/data/etl", "data-curated", "444455556666")},
			`resource.account "444455556666": no Account document has that id`,
		},
		"two accounts and a resource that names none": {
			map[string]string{"accounts/data.yaml": `kind: Account
metadata:
  name: data
spec:
  id: "444455556666"
  role: arn:aws:iam::444455556666:role/cracha/apps
`},
			"access payments-exports (access/payments-exports.yaml): resource.account is required: the tree has 2 Account documents",
		},
		"a resource in two accounts": {
			map[string]string{
				"accounts/data.yaml": `kind: Account
metadata:
  name: data
spec:
  id: "444455556666"
  role: arn:aws:iam::444455556666:role/cracha/apps
`,
				"access/payments-exports.yaml": access("payments-exports", "service: payments", "data-payments-exports", "111122223333"),
				"access/worker-audit.yaml":     "",
				"access/etl-curated.yaml":      access("etl-curated", "subject: prod/data/etl", "data-payments-exports", "444455556666"),
			},
			"s3_bucket:data-payments-exports is in account",
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := ValidateSource(accountsTree(t, tc.extra))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("ValidateSource = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

func TestImplicitGrantName(t *testing.T) {
	name := ImplicitGrantName("apps", ResourceS3Bucket, PermissionRead)
	if name != "account:apps:s3_bucket:read" {
		t.Errorf("name = %q", name)
	}
	if validateName("grant name", name) == nil {
		t.Error("an implicit grant's name is a name a Grant document may have")
	}
}

func TestCompileTwoAccountsPlacesResources(t *testing.T) {
	src := accountsTree(t, map[string]string{
		"accounts/data.yaml": `kind: Account
metadata:
  name: data
spec:
  id: "444455556666"
  role: arn:aws:iam::444455556666:role/cracha/apps
  envelope: [arn:aws:s3:::lake-*]
  access:
    - { kind: s3_bucket, permission: read, template: s3-object-read }
`,
		"access/payments-exports.yaml": access("payments-exports", "service: payments", "data-payments-exports", "111122223333"),
		"access/worker-audit.yaml":     "",
		"access/etl-curated.yaml":      access("etl-curated", "subject: prod/data/etl", "lake-curated", "444455556666"),
	})
	c, report, err := Compile(context.Background(), src, CompileOptions{Version: "v1", GeneratedAt: generatedAt, Lint: LintOptions{Now: lintNow}})
	if err != nil {
		t.Fatalf("Compile: %v (problems: %v)", err, report.Problems)
	}
	want := []BundleAccount{
		{Name: "apps", ID: "111122223333", Role: appsRole, Envelope: src.Accounts[0].Spec.Envelope, Resources: []Resource{{Kind: ResourceS3Bucket, Name: "data-payments-exports"}}},
		{Name: "data", ID: "444455556666", Role: "arn:aws:iam::444455556666:role/cracha/apps", Envelope: []string{"arn:aws:s3:::lake-*"}, Resources: []Resource{{Kind: ResourceS3Bucket, Name: "lake-curated"}}},
	}
	if !reflect.DeepEqual(c.Bundle.Accounts, want) {
		t.Errorf("accounts = %+v, want %+v", c.Bundle.Accounts, want)
	}
	if got := compositionOf(t, report, "prod/data/etl", "").Grants; !slices.Equal(got, []string{"account:data:s3_bucket:read"}) {
		t.Errorf("etl grants = %v, want the data account's implicit read", got)
	}
}
