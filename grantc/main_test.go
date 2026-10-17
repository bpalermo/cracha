package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
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

// compiledBundle compiles the passing source tree into work/bundle.json
// and returns the bundle's path and contents.
func compiledBundle(t *testing.T, work string) (bundle string, data []byte) {
	t.Helper()
	src := sourceTree(t, "arn:aws:s3:::data-111122223333/*")
	bundle = filepath.Join(work, "bundle.json")
	code, out, errOut := runCLI(t, noAWS, "compile", "-o", bundle, "-version", "deadbeef", "-generated-at", "2026-10-17T12:00:00Z", src)
	if code != 0 || !strings.Contains(out, "compiled "+bundle+": version deadbeef, 1 grants") {
		t.Fatalf("compile: %d\n%s%s", code, out, errOut)
	}
	data, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return bundle, data
}

// keyPair writes a private key, its public key and an unrelated public key
// into work, and returns their paths.
func keyPair(t *testing.T, work string) (priv, pub, other string) {
	t.Helper()
	key, err := grant.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	privPEM, _ := grant.EncodeECPrivateKey(key)
	pubPEM, _ := grant.EncodeECPublicKey(&key.PublicKey)
	otherKey, _ := grant.GenerateKey()
	otherPubPEM, _ := grant.EncodeECPublicKey(&otherKey.PublicKey)
	priv, pub, other = filepath.Join(work, "key.pem"), filepath.Join(work, "pub.pem"), filepath.Join(work, "other.pem")
	writeFile(t, priv, string(privPEM))
	writeFile(t, pub, string(pubPEM))
	writeFile(t, other, string(otherPubPEM))
	return priv, pub, other
}

// signedBundle compiles and signs a bundle, for verify and publish, and
// returns its path and contents with the signing key's public key and an
// unrelated one.
func signedBundle(t *testing.T, work string) (bundle string, data []byte, pub, other string) {
	t.Helper()
	bundle, data = compiledBundle(t, work)
	priv, pub, other := keyPair(t, work)
	code, out, errOut := runCLI(t, noAWS, "sign", "-key", priv, bundle)
	if code != 0 {
		t.Fatalf("sign: %d\n%s%s", code, out, errOut)
	}
	return bundle, data, pub, other
}

func TestCompileCommand(t *testing.T) {
	work := t.TempDir()
	src := sourceTree(t, "arn:aws:s3:::data-111122223333/*")
	bundle, data := compiledBundle(t, work)
	for _, want := range []string{`"version": "deadbeef"`, `"generatedAt": "2026-10-17T12:00:00Z"`, `"name": "reports-r"`, `arn:aws:s3:::data-111122223333/reports/*`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("bundle lacks %s:\n%s", want, data)
		}
	}

	code, _, errOut := runCLI(t, noAWS, "compile", src)
	if code != 2 || !strings.Contains(errOut, "-o is required") {
		t.Errorf("compile without -o: %d, %q", code, errOut)
	}
	code, _, errOut = runCLI(t, noAWS, "compile", "-o", bundle, "-generated-at", "yesterday", src)
	if code != 2 || !strings.Contains(errOut, "-generated-at") {
		t.Errorf("compile with bad time: %d, %q", code, errOut)
	}
	bad := sourceTree(t, "arn:aws:s3:::other/*")
	code, out, _ := runCLI(t, noAWS, "compile", "-o", filepath.Join(work, "bad.json"), bad)
	if code != 1 || !strings.Contains(out, "problems") {
		t.Errorf("compile bad: %d\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(work, "bad.json")); err == nil {
		t.Error("a bundle was written from a failing source")
	}
}

func TestSignCommand(t *testing.T) {
	work := t.TempDir()
	bundle, _ := compiledBundle(t, work)
	privPath, pubPath, _ := keyPair(t, work)

	code, out, errOut := runCLI(t, noAWS, "sign", "-key", privPath, bundle)
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
}

func TestVerifyCommand(t *testing.T) {
	work := t.TempDir()
	bundle, data, pubPath, otherPath := signedBundle(t, work)

	code, out, errOut := runCLI(t, noAWS, "verify", "-pub", pubPath, bundle)
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
}

func TestPublishCommand(t *testing.T) {
	work := t.TempDir()
	bundle, _, _, _ := signedBundle(t, work)

	pubDir := filepath.Join(work, "published")
	code, out, errOut := runCLI(t, noAWS, "publish", "-dir", pubDir, bundle)
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

// TestPrintReport covers the report lines a lint of the test source tree
// never produces: a validation note, a subject scoped to a cluster with
// problems, and an assignment left out as expired.
func TestPrintReport(t *testing.T) {
	limit := strconv.Itoa(grant.MaxPolicyChars)
	r := &grant.Report{
		Grants: []grant.GrantResult{
			{
				Grant: "reports-r",
				Validation: []grant.PolicyFinding{
					{Type: "SUGGESTION", Code: "EMPTY_SID_VALUE", Detail: "add a Sid"},
					{Type: "ERROR", Code: "BAD", Detail: "blocking, so a problem"},
				},
				Size:     &grant.SizeReport{PolicyChars: 120, TagCount: 1},
				Problems: grant.Problems{"ValidatePolicy: ERROR BAD: blocking, so a problem"},
			},
			{Grant: "no-policy"},
		},
		Composition: &grant.CompositionReport{
			Compositions: []grant.Composition{
				{Subject: "prod/billing/reports", Cluster: "eu-1", Grants: []string{"reports-r", "no-policy"}, PolicyChars: 130, Problems: grant.Problems{"two base roles"}},
				{Subject: "prod/billing/other", Grants: []string{"no-policy"}},
			},
			Expired: []string{"old"},
		},
		Skipped:  []string{"CheckNoNewAccess"},
		Problems: grant.Problems{"reports-r: ValidatePolicy", "prod/billing/reports in cluster eu-1: two base roles"},
	}
	var out bytes.Buffer
	printReport(&out, r)
	want := "grant reports-r: 1 problems, policy 120/" + limit + " chars, tags 1\n" +
		"  note: SUGGESTION EMPTY_SID_VALUE: add a Sid\n" +
		"  problem: ValidatePolicy: ERROR BAD: blocking, so a problem\n" +
		"grant no-policy: ok\n" +
		"subject prod/billing/reports in cluster eu-1: 1 problems, grants reports-r,no-policy, policy 130/" + limit + " chars\n" +
		"  problem: two base roles\n" +
		"subject prod/billing/other: ok, grants no-policy, policy 0/" + limit + " chars\n" +
		"assignment old: expired, left out of the composition\n" +
		"skipped: CheckNoNewAccess (run with -access-analyzer)\n" +
		"2 problems\n"
	if got := out.String(); got != want {
		t.Errorf("report:\n%s\nwant:\n%s", got, want)
	}

	var empty bytes.Buffer
	printReport(&empty, &grant.Report{})
	if got := empty.String(); got != "ok: no problems\n" {
		t.Errorf("empty report: %q", got)
	}
}

// TestKeySource covers the key-source flags sign and verify share: the KMS
// path reaches the client factory with the region, both flags at once are
// refused, and a PEM of the wrong kind is reported with its file.
func TestKeySource(t *testing.T) {
	work := t.TempDir()
	bundle := filepath.Join(work, "bundle.json")
	writeFile(t, bundle, `{"version":"v1","generatedAt":"2026-10-17T12:00:00Z","grants":[]}`)
	key, err := grant.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	privPEM, _ := grant.EncodeECPrivateKey(key)
	privPath := filepath.Join(work, "key.pem")
	writeFile(t, privPath, string(privPEM))

	var gotRegion string
	clients := noAWS
	clients.kms = func(_ context.Context, region string) (grant.KMSAPI, error) {
		gotRegion = region
		return nil, errors.New("kms unavailable")
	}
	for _, cmd := range []string{"sign", "verify"} {
		gotRegion = ""
		code, _, errOut := runCLI(t, clients, cmd, "-kms-key", "arn:aws:kms:eu-west-1:111122223333:key/k", "-region", "eu-west-1", bundle)
		if code != 2 || !strings.Contains(errOut, "kms unavailable") || gotRegion != "eu-west-1" {
			t.Errorf("%s with kms: %d, region %q, %q", cmd, code, gotRegion, errOut)
		}
	}

	code, _, errOut := runCLI(t, noAWS, "verify", "-pub", privPath, "-kms-key", "arn", bundle)
	if code != 2 || !strings.Contains(errOut, "verify: -pub and -kms-key are exclusive") {
		t.Errorf("verify with both: %d, %q", code, errOut)
	}
	code, _, errOut = runCLI(t, noAWS, "verify", "-pub", privPath, bundle)
	if code != 2 || !strings.Contains(errOut, "verify: "+privPath+": ") || !strings.Contains(errOut, "want PUBLIC KEY") {
		t.Errorf("verify with a private key: %d, %q", code, errOut)
	}
	code, _, errOut = runCLI(t, noAWS, "sign", "-key", filepath.Join(work, "missing.pem"), bundle)
	if code != 2 || !strings.Contains(errOut, "missing.pem") {
		t.Errorf("sign with a missing key file: %d, %q", code, errOut)
	}
}
