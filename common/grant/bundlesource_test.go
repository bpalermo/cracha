package grant

import (
	"context"
	"testing"
	"time"
)

// The composition lint over a compiled bundle sees what it sees over the
// tree the bundle was compiled from: the implicit grants included.
func TestBundleSourceComposesAsTheTree(t *testing.T) {
	src, err := Load(accountsDir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	c, _, err := Compile(context.Background(), src, CompileOptions{Version: "v1", Lint: LintOptions{Now: now}})
	if err != nil {
		t.Fatal(err)
	}
	b := c.Bundle
	bs, rendered, lookups := BundleSource(b)
	bs.Services, bs.Assignments = src.Services, src.Assignments
	for _, a := range src.Accesses {
		copied := *a
		copied.Spec.Resource.Account = BundleResourceAccount(b, a.Spec.Resource)
		bs.Accesses = append(bs.Accesses, &copied)
	}
	got := LintComposition(bs, rendered, lookups, now)
	if len(got.Compositions) == 0 {
		t.Fatal("no composition")
	}
	implicit := 0
	for _, g := range bs.Grants {
		if g.Implicit() {
			implicit++
		}
	}
	if implicit == 0 {
		t.Fatal("no implicit grant carried over")
	}
	wantReport := compileReport(t, src, now)
	if len(got.Compositions) != len(wantReport.Compositions) {
		t.Fatalf("%d compositions over the bundle, %d over the tree", len(got.Compositions), len(wantReport.Compositions))
	}
	for i, c := range got.Compositions {
		w := wantReport.Compositions[i]
		if c.Subject != w.Subject || c.Cluster != w.Cluster || c.Policy != w.Policy || len(c.Problems) != len(w.Problems) {
			t.Errorf("composition %d over the bundle = %+v\nover the tree = %+v", i, c, w)
		}
	}
}

// compileReport is the composition report the pipeline makes over the tree.
func compileReport(t *testing.T, src *Source, now time.Time) *CompositionReport {
	t.Helper()
	report, err := Lint(context.Background(), src, LintOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return report.Composition
}
