package grant

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const lookupDir = "testdata/lookup"

// lookupTree copies the lookup tree into a temporary directory, writes the
// extra files over it (path relative to the root, empty content removes
// the file) and loads it.
func lookupTree(t *testing.T, extra map[string]string) *Source {
	t.Helper()
	dir := t.TempDir()
	err := filepath.WalkDir(lookupDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(lookupDir, path)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dir, rel), 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dir, rel), data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	for rel, content := range extra {
		path := filepath.Join(dir, rel)
		if content == "" {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	src, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return src
}

func lintLookup(t *testing.T, src *Source) *Report {
	t.Helper()
	report, err := Lint(context.Background(), src, LintOptions{Now: lintNow})
	if err != nil {
		t.Fatalf("Lint: %v", err)
	}
	return report
}

func TestLoadLookupTree(t *testing.T) {
	src, err := Load(lookupDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSource(src); err != nil {
		t.Fatalf("ValidateSource: %v", err)
	}
	if len(src.Accesses) != 6 {
		t.Fatalf("accesses = %d, want 6", len(src.Accesses))
	}
	a := src.Accesses[0]
	want := AccessSpec{Service: "analytics", Resource: Resource{Kind: ResourceS3Bucket, Name: "data-raw"}, Relation: RelationReader}
	if a.Name() != "analytics-raw" || !reflect.DeepEqual(a.Spec, want) || a.Path != filepath.Join("access", "analytics-raw.yaml") {
		t.Errorf("first access = %+v (%s)", a.Spec, a.Path)
	}
	p := src.Grant("data-read").Spec.SessionPolicy.Params["bucket"]
	if p.Lookup == nil || *p.Lookup != (Lookup{Kind: ResourceS3Bucket, Permission: PermissionRead}) {
		t.Errorf("data-read's bucket = %+v, want the lookup", p)
	}
}

func TestCompileLookupGolden(t *testing.T) {
	src, err := Load(lookupDir)
	if err != nil {
		t.Fatal(err)
	}
	c, report, err := Compile(context.Background(), src, CompileOptions{Version: "lookup1", GeneratedAt: generatedAt, Lint: LintOptions{Now: lintNow}})
	if err != nil {
		t.Fatalf("Compile: %v (%v)", err, report.Problems)
	}
	bundle, err := Marshal(c.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "lookup-bundle.json", bundle)
	assignments, err := MarshalAssignments(c.Assignments)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "lookup-assignments.json", assignments)

	// Both parse back, strictly, as what was compiled.
	b, err := ParseBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := Marshal(b); err != nil || string(again) != string(bundle) {
		t.Errorf("bundle round trip differs (%v):\n%s", err, again)
	}
	a, err := ParseAssignments(assignments)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a.Access, c.Assignments.Access) {
		t.Errorf("access round trip: %+v, want %+v", a.Access, c.Assignments.Access)
	}
}

func TestLookupMaxResources(t *testing.T) {
	src := lookupTree(t, nil)
	report := lintLookup(t, src)
	if !report.OK() {
		t.Fatalf("problems: %v", report.Problems)
	}
	for _, r := range report.Grants {
		g := src.Grant(r.Grant)
		if r.Lookup == nil {
			if r.Grant != "data-static" {
				t.Errorf("grant %s: no lookup", r.Grant)
			}
			continue
		}
		if r.Rendered != "" {
			t.Errorf("grant %s: rendered %q, want nothing: a lookup grant is rendered at issuance", r.Grant, r.Rendered)
		}
		max := r.Lookup.MaxResources
		fits, err := renderProbes(r.Lookup, g.Spec.Account, max)
		if err != nil || len(fits) > MaxPolicyChars {
			t.Errorf("grant %s: %d probes render %d characters (%v), want at most %d", r.Grant, max, len(fits), err, MaxPolicyChars)
		}
		over, err := renderProbes(r.Lookup, g.Spec.Account, max+1)
		if err != nil || len(over) <= MaxPolicyChars {
			t.Errorf("grant %s: %d probes render %d characters (%v), want over %d", r.Grant, max+1, len(over), err, MaxPolicyChars)
		}
		if max < 10 {
			t.Errorf("grant %s: maximum %d is implausibly small", r.Grant, max)
		}
	}
}

func TestRenderLookupRule(t *testing.T) {
	src := lookupTree(t, nil)
	read := src.Templates["s3-object-read"]
	// A string parameter: one rendering per resource, sorted, repeats
	// dropped, statements put together.
	got, err := read.RenderLookup("111122223333", nil, "bucket", []string{"data-b", "data-a", "data-b"})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"Statement":[{"Action":["s3:GetObject"],"Effect":"Allow","Resource":"arn:aws:s3:::data-a/*"},{"Action":["s3:GetObject"],"Effect":"Allow","Resource":"arn:aws:s3:::data-b/*"}],"Version":"2012-10-17"}`
	if got != want {
		t.Errorf("string rule:\n got %s\nwant %s", got, want)
	}
	// A list parameter: the resources are the list, rendered once.
	write := src.Templates["s3-bucket-write"]
	got, err = write.RenderLookup("111122223333", map[string]Param{"prefix": StringParam("in/"), "buckets": LookupParam(ResourceS3Bucket, PermissionWrite)}, "buckets", []string{"data-b", "data-a"})
	if err != nil {
		t.Fatal(err)
	}
	want = `{"Statement":[{"Action":["s3:PutObject","s3:GetObject"],"Effect":"Allow","Resource":["arn:aws:s3:::data-a/in/*","arn:aws:s3:::data-b/in/*"],"Sid":"Write"},{"Action":["s3:ListBucket"],"Effect":"Allow","Resource":["arn:aws:s3:::data-a","arn:aws:s3:::data-b"],"Sid":"List"}],"Version":"2012-10-17"}`
	if got != want {
		t.Errorf("list rule:\n got %s\nwant %s", got, want)
	}
	if _, err := read.RenderLookup("111122223333", nil, "bucket", nil); err == nil || !strings.Contains(err.Error(), "no resources") {
		t.Errorf("no resources: %v", err)
	}
	// A lookup parameter is never rendered by Render.
	if _, err := read.Render("111122223333", map[string]Param{"bucket": LookupParam(ResourceS3Bucket, PermissionRead)}); err == nil || !strings.Contains(err.Error(), "is a lookup") {
		t.Errorf("Render of a lookup: %v", err)
	}
}

func compositionOf(t *testing.T, r *Report, subject, cluster string) Composition {
	t.Helper()
	for _, c := range r.Composition.Compositions {
		if c.Subject == subject && c.Cluster == cluster {
			return c
		}
	}
	t.Fatalf("no composition for %s in %q: %+v", subject, cluster, r.Composition.Compositions)
	return Composition{}
}

func TestLintCompositionLookups(t *testing.T) {
	r := lintLookup(t, lookupTree(t, nil))
	if !r.OK() {
		t.Fatalf("problems: %v", r.Problems)
	}
	etl := compositionOf(t, r, "prod/data/etl", "prod-a")
	wantRes := map[string][]string{"data-read": {"data-raw", "data.curated"}, "data-write": {"data.curated"}}
	if !reflect.DeepEqual(etl.Resources, wantRes) || len(etl.Dropped) != 0 {
		t.Errorf("etl in prod-a: resources %v dropped %v, want %v", etl.Resources, etl.Dropped, wantRes)
	}
	if !strings.Contains(etl.Policy, "arn:aws:s3:::data.curated/incoming/*") || !strings.Contains(etl.Policy, "arn:aws:s3:::data-raw/*") {
		t.Errorf("etl's composed policy %s", etl.Policy)
	}
	compositionOf(t, r, "prod/data/etl", "prod-b")
	report := compositionOf(t, r, "prod/data/report", "")
	if want := map[string][]string{"data-read": {"data-archive", "data-raw"}}; !reflect.DeepEqual(report.Resources, want) {
		t.Errorf("report: resources %v, want %v", report.Resources, want)
	}
	expired := strings.Join(r.Composition.Expired, ",")
	if !strings.Contains(expired, "access report-expired") {
		t.Errorf("expired = %v, want the expired access", r.Composition.Expired)
	}
}

func TestLintCompositionLookupProblems(t *testing.T) {
	tests := []struct {
		name  string
		extra map[string]string
		want  string
	}{
		{"related bucket outside the envelope", map[string]string{"access/x.yaml": `kind: Access
metadata: { name: x }
spec:
  subject: prod/data/report
  resource: { kind: s3_bucket, name: other-bucket }
  relation: reader
`}, `grant data-read: rendered for its resources: statement 2: Resource "arn:aws:s3:::other-bucket/*" matches no envelope pattern (the broker refuses resource_outside_envelope)`},
		{"repeated sid", map[string]string{"templates/s3-object-read.json": `{"params":{"bucket":{"type":"string"}},"policy":{"Version":"2012-10-17","Statement":[{"Sid":"Read","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::${bucket}/*"}]}}`}, `statement Sid "Read" repeats`},
		{"one resource does not fit", map[string]string{"templates/s3-object-read.json": `{"params":{"bucket":{"type":"string"}},"policy":{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::${bucket}/*","Condition":{"StringLike":{"s3:prefix":"` + strings.Repeat("x", 2000) + `"}}}]}}`}, "makes a policy of"},
		{"template resource outside the envelope", map[string]string{"templates/s3-object-read.json": `{"params":{"bucket":{"type":"string"}},"policy":{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":["arn:aws:s3:::${bucket}/*","arn:aws:s3:::elsewhere/*"]}]}}`}, `Resource "arn:aws:s3:::elsewhere/*" matches no envelope pattern`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := lintLookup(t, lookupTree(t, tt.extra))
			if !strings.Contains(strings.Join(r.Problems, "\n"), tt.want) {
				t.Errorf("problems = %v, want one containing %q", r.Problems, tt.want)
			}
		})
	}
}

func TestLintCompositionTooManyResources(t *testing.T) {
	extra := map[string]string{}
	for i := 0; i < 40; i++ {
		name := "data-" + strings.Repeat("x", 50) + string(rune('a'+i%26)) + string(rune('a'+i/26))
		extra["access/many-"+string(rune('a'+i%26))+string(rune('a'+i/26))+".yaml"] = `kind: Access
metadata: { name: many-` + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ` }
spec:
  subject: prod/data/report
  resource: { kind: s3_bucket, name: ` + name + ` }
  relation: reader
`
	}
	r := lintLookup(t, lookupTree(t, extra))
	if !strings.Contains(strings.Join(r.Problems, "\n"), "over its compiled maximum") {
		t.Errorf("problems = %v, want the compiled maximum exceeded", r.Problems)
	}
}

func TestLintCompositionDropsLookupWithoutResources(t *testing.T) {
	// The report workload loses its access: data-read is left out of its
	// composition, data-static stays.
	r := lintLookup(t, lookupTree(t, map[string]string{
		"access/analytics-raw.yaml":  "",
		"access/report-archive.yaml": "",
	}))
	if !r.OK() {
		t.Fatalf("problems: %v", r.Problems)
	}
	c := compositionOf(t, r, "prod/data/report", "")
	if !reflect.DeepEqual(c.Dropped, []string{"data-read"}) || !reflect.DeepEqual(c.Grants, []string{"data-static"}) {
		t.Errorf("report: grants %v dropped %v, want data-static and data-read dropped", c.Grants, c.Dropped)
	}
}

func TestValidateLookupAndAccess(t *testing.T) {
	grant := func(params string) string {
		return `kind: Grant
metadata: { name: data-read }
spec:
  account: "111122223333"
  baseRole: arn:aws:iam::111122223333:role/broker/shape-data
  sessionPolicy:
    template: s3-bucket-write
    params: ` + params + `
  envelope: [arn:aws:s3:::data-*]
`
	}
	access := func(spec string) map[string]string {
		return map[string]string{"access/bad.yaml": "kind: Access\nmetadata: { name: bad }\nspec:\n" + spec}
	}
	tests := []struct {
		name  string
		extra map[string]string
		want  string
	}{
		{"unknown kind", map[string]string{"grants/data-read.yaml": grant(`{ buckets: { lookup: { kind: sqs_queue, permission: read } } }`)}, `lookup kind "sqs_queue"`},
		{"unknown permission", map[string]string{"grants/data-read.yaml": grant(`{ buckets: { lookup: { kind: s3_bucket, permission: admin } } }`)}, `lookup permission "admin"`},
		{"two lookups", map[string]string{"grants/data-read.yaml": grant(`{ buckets: { lookup: { kind: s3_bucket, permission: read } }, prefix: { lookup: { kind: s3_bucket, permission: read } } }`)}, "2 lookup parameters"},
		{"undeclared lookup", map[string]string{"grants/data-read.yaml": grant(`{ tables: { lookup: { kind: s3_bucket, permission: read } } }`)}, `lookup parameter "tables" is not declared`},
		{"no holder", access("  resource: { kind: s3_bucket, name: data-x }\n  relation: reader\n"), "one of subject or service is required"},
		{"two holders", access("  subject: prod/data/etl\n  service: analytics\n  resource: { kind: s3_bucket, name: data-x }\n  relation: reader\n"), "exclusive"},
		{"unknown service", access("  service: nope\n  resource: { kind: s3_bucket, name: data-x }\n  relation: reader\n"), `service "nope" not found`},
		{"bad bucket", access("  subject: prod/data/etl\n  resource: { kind: s3_bucket, name: Data_X }\n  relation: reader\n"), `bucket name "Data_X"`},
		{"unknown resource kind", access("  subject: prod/data/etl\n  resource: { kind: sqs_queue, name: q }\n  relation: reader\n"), `resource.kind "sqs_queue"`},
		{"bad relation", access("  subject: prod/data/etl\n  resource: { kind: s3_bucket, name: data-x }\n  relation: owner\n"), `relation "owner"`},
		{"bad expiry", access("  subject: prod/data/etl\n  resource: { kind: s3_bucket, name: data-x }\n  relation: reader\n  expiresAt: tomorrow\n"), "expiresAt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSource(lookupTree(t, tt.extra))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("ValidateSource = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestLoadAccessRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte("kind: Access\nmetadata: { name: a }\nspec:\n  subject: a/b/c\n  resources: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), `unknown field "resources"`) {
		t.Errorf("Load = %v, want the unknown field", err)
	}
}

func TestLookupParamJSON(t *testing.T) {
	var p Param
	if err := json.Unmarshal([]byte(`{"lookup":{"kind":"s3_bucket","permission":"read"}}`), &p); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(p)
	if err != nil || string(out) != `{"lookup":{"kind":"s3_bucket","permission":"read"}}` {
		t.Errorf("round trip = %s, %v", out, err)
	}
	for _, bad := range []string{`{"lookup":{"kind":"s3_bucket","permission":"read","extra":1}}`, `{"other":1}`, `{}`} {
		if err := json.Unmarshal([]byte(bad), &p); err == nil {
			t.Errorf("%s decoded", bad)
		}
	}
	if _, err := ParseTemplate([]byte(`{"params":{"b":{"type":"string","default":{"lookup":{"kind":"s3_bucket","permission":"read"}}}},"policy":{}}`)); err == nil {
		t.Error("a template whose default is a lookup parsed")
	}
}

func TestResolveAccessRefusesInexpressibleUnion(t *testing.T) {
	src := lookupTree(t, map[string]string{"access/etl-curated-b.yaml": `kind: Access
metadata: { name: etl-curated-b }
spec:
  subject: prod/data/etl
  resource: { kind: s3_bucket, name: data.curated }
  relation: writer
  expiresAt: "2030-01-01T00:00:00Z"
`})
	if _, err := ResolveAccess(src); err == nil || !strings.Contains(err.Error(), "access to s3_bucket:data.curated") {
		t.Errorf("ResolveAccess = %v, want the union refused", err)
	}
}

func TestBucketNames(t *testing.T) {
	good := []string{"abc", "a.b.c", "my-bucket-1", "1bucket", strings.Repeat("a", 63), "data.curated"}
	bad := []string{"ab", strings.Repeat("a", 64), "Abc", "a_b", "-abc", "abc-", "a..b", "192.168.5.4", "xn--abc", "sthree-x", "amzn-s3-demo-x", "abc-s3alias", "abc--ol-s3", "abc.mrap", "abc--x-s3", "abc--table-s3", ".abc"}
	for _, n := range good {
		if err := validateBucketName(n); err != nil {
			t.Errorf("%q: %v", n, err)
		}
	}
	for _, n := range bad {
		if err := validateBucketName(n); err == nil {
			t.Errorf("%q: valid, want an error", n)
		}
	}
	k, _ := LookupResourceKind(ResourceS3Bucket)
	for _, p := range probeNames(k, 3) {
		if err := k.Validate(p); err != nil || len(p) != k.MaxNameLen {
			t.Errorf("probe %q: %v", p, err)
		}
	}
	k, _ = LookupResourceKind(ResourceDynamoDBTable)
	for _, p := range probeNames(k, 3) {
		if err := k.Validate(p); err != nil || len(p) != k.MaxNameLen {
			t.Errorf("probe %q: %v", p, err)
		}
	}
}
