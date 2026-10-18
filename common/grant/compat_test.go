package grant

import (
	"context"
	"testing"
)

// TestContentVersionUnchanged pins the content version of the trees that
// predate Account documents (the good and the lookup tree): a tree that
// uses neither an Account nor a grant without baseRole compiles to the
// version, and so the bytes, it did before them, which a broker that
// predates them keeps reading. The pins are what main compiled before
// Account documents existed; the golden files pin the bytes.
func TestContentVersionUnchanged(t *testing.T) {
	for dir, want := range map[string]string{
		goodDir:   "1ee75107d62aa565e5d9c718e917f56045e4d4287379c92194a6c265cc18e35d",
		lookupDir: "d9eaf14fb3ea38dd5758000494a99c8042559939397ff47fd263196de2755d23",
	} {
		src, err := Load(dir)
		if err != nil {
			t.Fatal(err)
		}
		c, report, err := Compile(context.Background(), src, CompileOptions{GeneratedAt: generatedAt, Lint: LintOptions{Now: lintNow}})
		if err != nil {
			t.Fatalf("%s: %v (%v)", dir, err, report.Problems)
		}
		if c.Bundle.Version != want {
			t.Errorf("%s: version %s, want %s", dir, c.Bundle.Version, want)
		}
	}
}
