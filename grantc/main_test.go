package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bpalermo/cracha/common/grant"
)

// noAWS fails every AWS client, so a command that reaches for AWS without
// being asked to is caught.
var noAWS = awsClients{
	analyzer: func(context.Context, string) (grant.PolicyAnalyzer, error) { return nil, errors.New("no aws in tests") },
	kms:      func(context.Context, string) (grant.KMSAPI, error) { return nil, errors.New("no aws in tests") },
	s3:       func(context.Context, string) (grant.S3API, error) { return nil, errors.New("no aws in tests") },
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// sourceTree writes a small grant source tree; envelope decides whether
// the rendered policy fits it.
func sourceTree(t *testing.T, envelope string) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "templates", "s3-prefix-r.json"), `{
	  "params": {"prefixes": {"type": "list"}},
	  "policy": {"Version": "2012-10-17", "Statement": [
	    {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::data-${account}/${prefixes}/*"]}
	  ]}
	}`)
	writeFile(t, filepath.Join(dir, "grants", "reports-r.yaml"), `kind: Grant
metadata:
  name: reports-r
spec:
  account: "111122223333"
  baseRole: arn:aws:iam::111122223333:role/shape-s3-r
  sessionPolicy:
    template: s3-prefix-r
    params: { prefixes: [reports] }
  sessionTags: { team: billing }
  envelope: ["`+envelope+`"]
`)
	writeFile(t, filepath.Join(dir, "assignments", "reports.yaml"), `kind: Assignment
metadata:
  name: reports
spec:
  subject: prod/billing/reports
  grants: [reports-r]
`)
	return dir
}

func runCLI(t *testing.T, clients awsClients, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = run(args, &out, &errOut, clients)
	return code, out.String(), errOut.String()
}

func TestVersionAndUsage(t *testing.T) {
	code, out, _ := runCLI(t, noAWS, "--version")
	if code != 0 || !strings.HasPrefix(out, "cracha-grantc ") {
		t.Errorf("--version: %d, %q", code, out)
	}
	code, _, errOut := runCLI(t, noAWS)
	if code != 2 || !strings.Contains(errOut, "usage:") {
		t.Errorf("no args: %d, %q", code, errOut)
	}
	code, _, errOut = runCLI(t, noAWS, "frobnicate")
	if code != 2 || !strings.Contains(errOut, `unknown command "frobnicate"`) {
		t.Errorf("unknown command: %d, %q", code, errOut)
	}
	code, _, _ = runCLI(t, noAWS, "lint", "-h")
	if code != 0 {
		t.Errorf("lint -h: %d", code)
	}
	code, _, errOut = runCLI(t, noAWS, "lint")
	if code != 2 || !strings.Contains(errOut, "exactly one source directory") {
		t.Errorf("lint without dir: %d, %q", code, errOut)
	}
}

func TestLintCommand(t *testing.T) {
	good := sourceTree(t, "arn:aws:s3:::data-111122223333/reports/*")
	code, out, _ := runCLI(t, noAWS, "lint", good)
	if code != 0 {
		t.Fatalf("lint: %d\n%s", code, out)
	}
	for _, want := range []string{"grant reports-r: ok", "subject prod/billing/reports: ok", "skipped: ValidatePolicy", "ok: no problems"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}

	bad := sourceTree(t, "arn:aws:s3:::other/*")
	code, out, errOut := runCLI(t, noAWS, "lint", bad)
	if code != 1 || !strings.Contains(out, "matches no envelope pattern") || !strings.Contains(errOut, "problems found: 2") {
		t.Errorf("lint bad: %d\n%s\n%s", code, out, errOut)
	}

	code, _, errOut = runCLI(t, noAWS, "lint", filepath.Join(good, "nope"))
	if code != 2 || errOut == "" {
		t.Errorf("lint missing dir: %d, %q", code, errOut)
	}

	// With -access-analyzer the analyzer runs and nothing is skipped.
	fa := &fakeAnalyzer{}
	clients := noAWS
	clients.analyzer = func(_ context.Context, region string) (grant.PolicyAnalyzer, error) {
		fa.region = region
		return fa, nil
	}
	code, out, _ = runCLI(t, clients, "lint", "-access-analyzer", "-region", "eu-west-1", good)
	if code != 0 || strings.Contains(out, "skipped") || fa.calls != 1 || fa.region != "eu-west-1" {
		t.Errorf("lint with analyzer: %d, calls %d, region %q\n%s", code, fa.calls, fa.region, out)
	}
	code, _, errOut = runCLI(t, noAWS, "lint", "-access-analyzer", good)
	if code != 2 || !strings.Contains(errOut, "no aws in tests") {
		t.Errorf("lint with analyzer and no AWS: %d, %q", code, errOut)
	}
}

type fakeAnalyzer struct {
	calls  int
	region string
}

func (f *fakeAnalyzer) ValidatePolicy(context.Context, string) ([]grant.PolicyFinding, error) {
	f.calls++
	return []grant.PolicyFinding{{Type: "SUGGESTION", Code: "EMPTY_SID_VALUE", Detail: "add a Sid"}}, nil
}

func (f *fakeAnalyzer) CheckNoNewAccess(context.Context, string, string) (*grant.AccessCheck, error) {
	return &grant.AccessCheck{Passed: true}, nil
}

func TestCompileSignVerifyPublish(t *testing.T) {
	src := sourceTree(t, "arn:aws:s3:::data-111122223333/*")
	work := t.TempDir()
	bundle := filepath.Join(work, "bundle.json")

	code, out, errOut := runCLI(t, noAWS, "compile", "-o", bundle, "-version", "deadbeef", "-generated-at", "2026-10-17T12:00:00Z", src)
	if code != 0 || !strings.Contains(out, "compiled "+bundle+": version deadbeef, 1 grants") {
		t.Fatalf("compile: %d\n%s%s", code, out, errOut)
	}
	data, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"version": "deadbeef"`, `"generatedAt": "2026-10-17T12:00:00Z"`, `"name": "reports-r"`, `arn:aws:s3:::data-111122223333/reports/*`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("bundle lacks %s:\n%s", want, data)
		}
	}

	code, _, errOut = runCLI(t, noAWS, "compile", src)
	if code != 2 || !strings.Contains(errOut, "-o is required") {
		t.Errorf("compile without -o: %d, %q", code, errOut)
	}
	code, _, errOut = runCLI(t, noAWS, "compile", "-o", bundle, "-generated-at", "yesterday", src)
	if code != 2 || !strings.Contains(errOut, "-generated-at") {
		t.Errorf("compile with bad time: %d, %q", code, errOut)
	}
	bad := sourceTree(t, "arn:aws:s3:::other/*")
	code, out, _ = runCLI(t, noAWS, "compile", "-o", filepath.Join(work, "bad.json"), bad)
	if code != 1 || !strings.Contains(out, "problems") {
		t.Errorf("compile bad: %d\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(work, "bad.json")); err == nil {
		t.Error("a bundle was written from a failing source")
	}

	// Keys.
	key, err := grant.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	privPEM, _ := grant.EncodeECPrivateKey(key)
	pubPEM, _ := grant.EncodeECPublicKey(&key.PublicKey)
	other, _ := grant.GenerateKey()
	otherPubPEM, _ := grant.EncodeECPublicKey(&other.PublicKey)
	privPath, pubPath, otherPath := filepath.Join(work, "key.pem"), filepath.Join(work, "pub.pem"), filepath.Join(work, "other.pem")
	writeFile(t, privPath, string(privPEM))
	writeFile(t, pubPath, string(pubPEM))
	writeFile(t, otherPath, string(otherPubPEM))

	code, out, errOut = runCLI(t, noAWS, "sign", "-key", privPath, bundle)
	if code != 0 || !strings.Contains(out, "signed "+bundle+" with sha256:") {
		t.Fatalf("sign: %d\n%s%s", code, out, errOut)
	}
	if _, err := os.Stat(bundle + ".sig"); err != nil {
		t.Fatalf("signature not written: %v", err)
	}
	code, _, errOut = runCLI(t, noAWS, "sign", bundle)
	if code != 2 || !strings.Contains(errOut, "one of -key or -kms-key") {
		t.Errorf("sign without key: %d, %q", code, errOut)
	}
	code, _, errOut = runCLI(t, noAWS, "sign", "-key", privPath, "-kms-key", "arn", bundle)
	if code != 2 || !strings.Contains(errOut, "exclusive") {
		t.Errorf("sign with both: %d, %q", code, errOut)
	}
	code, _, errOut = runCLI(t, noAWS, "sign", "-key", pubPath, bundle)
	if code != 2 || !strings.Contains(errOut, "want PRIVATE KEY") {
		t.Errorf("sign with a public key: %d, %q", code, errOut)
	}

	code, out, errOut = runCLI(t, noAWS, "verify", "-pub", pubPath, bundle)
	if code != 0 || !strings.Contains(out, "verified "+bundle) {
		t.Errorf("verify: %d\n%s%s", code, out, errOut)
	}
	code, _, errOut = runCLI(t, noAWS, "verify", "-pub", otherPath, bundle)
	if code != 1 || !strings.Contains(errOut, "signature does not verify") {
		t.Errorf("verify with the wrong key: %d, %q", code, errOut)
	}
	tampered := filepath.Join(work, "tampered.json")
	writeFile(t, tampered, strings.Replace(string(data), "s3:GetObject", "s3:*", 1))
	code, _, errOut = runCLI(t, noAWS, "verify", "-pub", pubPath, "-sig", bundle+".sig", tampered)
	if code != 1 || !strings.Contains(errOut, "digest") {
		t.Errorf("verify tampered: %d, %q", code, errOut)
	}
	code, _, errOut = runCLI(t, noAWS, "verify", bundle)
	if code != 2 || !strings.Contains(errOut, "one of -pub or -kms-key") {
		t.Errorf("verify without key: %d, %q", code, errOut)
	}

	pubDir := filepath.Join(work, "published")
	code, out, errOut = runCLI(t, noAWS, "publish", "-dir", pubDir, bundle)
	if code != 0 || !strings.Contains(out, "published version deadbeef: bundles/deadbeef/bundle.json, bundles/deadbeef/bundle.json.sig, latest") {
		t.Errorf("publish: %d\n%s%s", code, out, errOut)
	}
	if _, err := os.Stat(filepath.Join(pubDir, "latest")); err != nil {
		t.Errorf("latest not written: %v", err)
	}
	code, _, errOut = runCLI(t, noAWS, "publish", bundle)
	if code != 2 || !strings.Contains(errOut, "one of -dir or -s3") {
		t.Errorf("publish without destination: %d, %q", code, errOut)
	}
	code, _, errOut = runCLI(t, noAWS, "publish", "-s3", "bucket/prefix", bundle)
	if code != 2 || !strings.Contains(errOut, "no aws in tests") {
		t.Errorf("publish to s3 without AWS: %d, %q", code, errOut)
	}
	code, _, errOut = runCLI(t, noAWS, "publish", "-s3", "/", bundle)
	if code != 2 || !strings.Contains(errOut, "needs a bucket") {
		t.Errorf("publish to no bucket: %d, %q", code, errOut)
	}
}
