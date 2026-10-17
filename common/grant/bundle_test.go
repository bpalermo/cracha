package grant

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var generatedAt = time.Date(2026, 10, 17, 12, 34, 56, 0, time.UTC)

func compileGood(t *testing.T, version string) (*Bundle, []byte) {
	t.Helper()
	src := loadGood(t)
	b, report, err := Compile(context.Background(), src, CompileOptions{
		Version:     version,
		GeneratedAt: generatedAt,
		Lint:        LintOptions{Now: lintNow},
	})
	if err != nil {
		t.Fatalf("Compile: %v (problems: %v)", err, report.Problems)
	}
	data, err := Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return b, data
}

func TestCompileGolden(t *testing.T) {
	_, got := compileGood(t, "abc123")
	golden := filepath.Join("testdata", "golden", "bundle.json")
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if !bytes.Equal(got, want) {
		if dir := os.Getenv("TEST_UNDECLARED_OUTPUTS_DIR"); dir != "" {
			_ = os.WriteFile(filepath.Join(dir, "bundle.json"), got, 0o644)
		}
		t.Errorf("compiled bundle differs from %s; got:\n%s", golden, got)
	}
}

func TestCompileDeterministic(t *testing.T) {
	b1, d1 := compileGood(t, "")
	b2, d2 := compileGood(t, "")
	if !bytes.Equal(d1, d2) {
		t.Error("two compilations of the same sources differ")
	}
	if len(b1.Version) != 64 || b1.Version != b2.Version {
		t.Errorf("content version = %q", b1.Version)
	}
	if b1.GeneratedAt != "2026-10-17T12:34:56Z" {
		t.Errorf("generatedAt = %q", b1.GeneratedAt)
	}
	// The version is of the grants alone: a different generatedAt keeps it.
	src := loadGood(t)
	b3, _, err := Compile(context.Background(), src, CompileOptions{GeneratedAt: generatedAt.Add(time.Hour), Lint: LintOptions{Now: lintNow}})
	if err != nil {
		t.Fatal(err)
	}
	if b3.Version != b1.Version {
		t.Errorf("version changed with generatedAt: %s vs %s", b3.Version, b1.Version)
	}
	// And changes with the grants.
	src.Grants[0].Spec.Duration = 900
	b4, _, err := Compile(context.Background(), src, CompileOptions{GeneratedAt: generatedAt, Lint: LintOptions{Now: lintNow}})
	if err != nil {
		t.Fatal(err)
	}
	if b4.Version == b1.Version {
		t.Error("version did not change with a grant")
	}
}

func TestCompileShape(t *testing.T) {
	b, data := compileGood(t, "v1")
	if len(b.Grants) != 3 || b.Grants[0].Name != "billing-reports" || b.Grants[2].Name != "payments-outbox-r" {
		t.Errorf("grants = %+v", b.Grants)
	}
	billing := b.Grants[0]
	if billing.SessionPolicy != "" || billing.Duration != 1800 || len(billing.ManagedPolicyArns) != 2 || billing.SessionTags == nil || billing.Envelope == nil {
		t.Errorf("billing-reports = %+v", billing)
	}
	ledger := b.Grants[1]
	if ledger.Duration != 3600 || !strings.HasPrefix(ledger.SessionPolicy, `{"Statement":[`) || ledger.SessionTags["team"] != "payments" {
		t.Errorf("payments-ledger-rw = %+v", ledger)
	}
	for _, want := range []string{`"version": "v1"`, `"generatedAt": "2026-10-17T12:34:56Z"`, `"managedPolicyArns": []`, `"sessionTags": {}`, `"envelope": []`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("bundle lacks %s:\n%s", want, data)
		}
	}
	if !bytes.HasSuffix(data, []byte("}\n")) {
		t.Error("bundle does not end with a newline")
	}
	parsed, err := ParseBundle(data)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Version != "v1" || len(parsed.Grants) != 3 || parsed.Grants[1].SessionPolicy != ledger.SessionPolicy {
		t.Errorf("ParseBundle = %+v", parsed)
	}
}

func TestCompileRefusesProblems(t *testing.T) {
	src, err := Load("testdata/lint/outside-envelope")
	if err != nil {
		t.Fatal(err)
	}
	b, report, err := Compile(context.Background(), src, CompileOptions{})
	if err == nil || b != nil || report == nil || report.OK() {
		t.Errorf("Compile = %v, %v, %v; want a report with problems and no bundle", b, report, err)
	}
	if _, _, err := Compile(context.Background(), loadGood(t), CompileOptions{Version: "v/1"}); err == nil || !strings.Contains(err.Error(), "version") {
		t.Errorf("error = %v, want a version error", err)
	}
	src, _ = Load("testdata/bad/missing-template")
	if _, _, err := Compile(context.Background(), src, CompileOptions{}); err == nil {
		t.Error("Compile of an invalid source succeeded")
	}
}

func TestParseBundleRejects(t *testing.T) {
	tests := []struct {
		name, doc, want string
	}{
		{"unknown field", `{"version":"v","generatedAt":"t","grants":[],"extra":1}`, `unknown field "extra"`},
		{"bad version", `{"version":"../x","generatedAt":"t","grants":[]}`, "version"},
		{"trailing", `{"version":"v","generatedAt":"t","grants":[]} {}`, "trailing data"},
		{"not json", `nope`, "bundle:"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseBundle([]byte(tt.doc)); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}
