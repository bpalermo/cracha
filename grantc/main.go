// Command cracha-grantc is the grant compiler (docs/design.md, section 6.2):
// it lints a Git checkout of grants, compiles the bundle the broker consumes
// and the assignments document its static backend reads, signs them,
// verifies their signatures and publishes a signed version.
//
//	cracha-grantc lint <dir> [-access-analyzer [-region r]]
//	cracha-grantc compile <dir> -o bundle.json [-assignments assignments.json] [-version v] [-generated-at t] [-access-analyzer [-region r]]
//	cracha-grantc sign (-key priv.pem | -kms-key arn [-region r]) [-o FILE.sig] bundle.json [assignments.json]
//	cracha-grantc verify (-pub pub.pem | -kms-key arn [-region r]) [-sig FILE.sig] bundle.json [assignments.json]
//	cracha-grantc publish (-dir path | -s3 bucket[/prefix] [-region r]) [-sig bundle.json.sig] bundle.json [assignments.json]
//
// sign, verify and publish take either document, told apart by their
// content; each one's signature is <file>.sig unless -o or -sig names it,
// which only a single file allows (publish's -sig is the bundle's). -pub
// may hold several public keys, any of which verifies: the one the
// signature names. A KMS signature names the key by its public key, so the
// key's exported PEM (aws kms get-public-key) verifies it; verify -kms-key
// fetches that public key (kms:GetPublicKey) and checks locally, never
// calling kms:Verify.
//
// The exit status is 0 on success, 1 when a lint finds problems or a
// signature does not verify, and 2 on a usage or operational error.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/bpalermo/cracha/common/grant"
	"github.com/bpalermo/cracha/common/version"
)

const usage = `usage: cracha-grantc <command> [flags] [args]

commands:
  lint     <dir>           run the pipeline's lints on a grant source tree
  compile  <dir> -o FILE   lint, then compile the bundle and, beside it, the assignments
  sign     FILE...         sign a bundle or assignments with a local key or a KMS key
  verify   FILE...         verify a bundle's or assignments' signature
  publish  bundle.json [assignments.json]
                           publish a signed version to a directory or S3
  --version                print the version

Run "cracha-grantc <command> -h" for a command's flags.`

// awsClients makes the AWS clients the commands use, so tests can
// substitute fakes. region is empty when none was given on the command
// line, which leaves the SDK's own resolution.
type awsClients struct {
	analyzer func(ctx context.Context, region string) (grant.PolicyAnalyzer, error)
	kms      func(ctx context.Context, region string) (grant.KMSAPI, error)
	s3       func(ctx context.Context, region string) (grant.S3API, error)
}

// loadConfig resolves the SDK's configuration (environment, profile,
// instance or pod identity), with the region overridden when one is given.
func loadConfig(ctx context.Context, region string) (aws.Config, error) {
	var opts []func(*config.LoadOptions) error
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("aws configuration: %w", err)
	}
	return cfg, nil
}

var defaultClients = awsClients{
	analyzer: func(ctx context.Context, region string) (grant.PolicyAnalyzer, error) {
		cfg, err := loadConfig(ctx, region)
		if err != nil {
			return nil, err
		}
		return grant.NewAccessAnalyzer(accessanalyzer.NewFromConfig(cfg)), nil
	},
	kms: func(ctx context.Context, region string) (grant.KMSAPI, error) {
		cfg, err := loadConfig(ctx, region)
		if err != nil {
			return nil, err
		}
		return kms.NewFromConfig(cfg), nil
	},
	s3: func(ctx context.Context, region string) (grant.S3API, error) {
		cfg, err := loadConfig(ctx, region)
		if err != nil {
			return nil, err
		}
		return s3.NewFromConfig(cfg), nil
	},
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, defaultClients))
}

// run is main without the process: it returns the exit status.
func run(args []string, stdout, stderr io.Writer, clients awsClients) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	ctx := context.Background()
	var err error
	switch cmd := args[0]; cmd {
	case "--version", "-version":
		fmt.Fprintf(stdout, "cracha-grantc %s\n", version.Version)
		return 0
	case "-h", "--help", "help":
		fmt.Fprintln(stdout, usage)
		return 0
	case "lint":
		err = runLint(ctx, args[1:], stdout, stderr, clients)
	case "compile":
		err = runCompile(ctx, args[1:], stdout, stderr, clients)
	case "sign":
		err = runSign(ctx, args[1:], stdout, stderr, clients)
	case "verify":
		err = runVerify(ctx, args[1:], stdout, stderr, clients)
	case "publish":
		err = runPublish(ctx, args[1:], stdout, stderr, clients)
	default:
		fmt.Fprintf(stderr, "cracha-grantc: unknown command %q\n%s\n", cmd, usage)
		return 2
	}
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errProblems), errors.Is(err, errNotVerified):
		fmt.Fprintf(stderr, "cracha-grantc: %v\n", err)
		return 1
	case errors.Is(err, flag.ErrHelp):
		return 0
	default:
		fmt.Fprintf(stderr, "cracha-grantc: %v\n", err)
		return 2
	}
}

var (
	errProblems    = errors.New("problems found")
	errNotVerified = errors.New("signature does not verify")
)

func newFlags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("cracha-grantc "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// lintFlags are the pipeline flags lint and compile share.
type lintFlags struct {
	analyzer bool
	region   string
}

func (f *lintFlags) register(fs *flag.FlagSet) {
	fs.BoolVar(&f.analyzer, "access-analyzer", false, "run IAM Access Analyzer ValidatePolicy and CheckNoNewAccess (needs AWS credentials)")
	fs.StringVar(&f.region, "region", "", "AWS region for the AWS calls (default: the SDK's)")
}

func (f *lintFlags) options(ctx context.Context, clients awsClients) (grant.LintOptions, error) {
	opts := grant.LintOptions{}
	if f.analyzer {
		a, err := clients.analyzer(ctx, f.region)
		if err != nil {
			return opts, err
		}
		opts.Analyzer = a
	}
	return opts, nil
}

func runLint(ctx context.Context, args []string, stdout, stderr io.Writer, clients awsClients) error {
	fs := newFlags("lint", stderr)
	var lf lintFlags
	lf.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("lint: want exactly one source directory")
	}
	src, err := grant.Load(fs.Arg(0))
	if err != nil {
		return err
	}
	opts, err := lf.options(ctx, clients)
	if err != nil {
		return err
	}
	report, err := grant.Lint(ctx, src, opts)
	if err != nil {
		return err
	}
	printReport(stdout, report)
	if !report.OK() {
		return fmt.Errorf("%w: %d", errProblems, len(report.Problems))
	}
	return nil
}

func runCompile(ctx context.Context, args []string, stdout, stderr io.Writer, clients awsClients) error {
	fs := newFlags("compile", stderr)
	var lf lintFlags
	lf.register(fs)
	out := fs.String("o", "", "where to write the bundle (required)")
	assignOut := fs.String("assignments", "", "where to write the assignments (default: "+grant.AssignmentsFile+" beside the bundle)")
	ver := fs.String("version", "", "the version of the bundle and the assignments, such as the git commit (default: the content hash of both)")
	at := fs.String("generated-at", "", "the generatedAt stamp, RFC 3339 (default: now)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("compile: want exactly one source directory")
	}
	if *out == "" {
		return errors.New("compile: -o is required")
	}
	copts := grant.CompileOptions{Version: *ver}
	if *at != "" {
		t, err := time.Parse(time.RFC3339, *at)
		if err != nil {
			return fmt.Errorf("compile: -generated-at: %w", err)
		}
		copts.GeneratedAt = t
	}
	src, err := grant.Load(fs.Arg(0))
	if err != nil {
		return err
	}
	if copts.Lint, err = lf.options(ctx, clients); err != nil {
		return err
	}
	compiled, report, err := grant.Compile(ctx, src, copts)
	if report != nil {
		printReport(stdout, report)
	}
	if err != nil {
		if report != nil && !report.OK() {
			return fmt.Errorf("%w: %d", errProblems, len(report.Problems))
		}
		return err
	}
	if *assignOut == "" {
		*assignOut = filepath.Join(filepath.Dir(*out), grant.AssignmentsFile)
	}
	return writeCompiled(stdout, compiled, *out, *assignOut)
}

// writeCompiled writes the bundle and the assignments of one compilation.
func writeCompiled(stdout io.Writer, c *grant.Compiled, bundlePath, assignmentsPath string) error {
	if bundlePath == assignmentsPath {
		return fmt.Errorf("compile: the bundle and the assignments cannot both be written to %s", bundlePath)
	}
	data, err := grant.Marshal(c.Bundle)
	if err != nil {
		return err
	}
	assignments, err := grant.MarshalAssignments(c.Assignments)
	if err != nil {
		return err
	}
	if err := os.WriteFile(bundlePath, data, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(assignmentsPath, assignments, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "compiled %s: version %s, %d grants, %d bytes\n", bundlePath, c.Bundle.Version, len(c.Bundle.Grants), len(data))
	fmt.Fprintf(stdout, "compiled %s: version %s, %d services, %d workloads, %d bytes\n", assignmentsPath, c.Assignments.Version,
		len(c.Assignments.Services), len(c.Assignments.Workloads), len(assignments))
	return nil
}

// keyFlags are the key-source flags sign and verify share: a local PEM
// file, named by the command's own flag (-key or -pub), or a KMS key. cmd
// and local name the command and that flag in errors.
type keyFlags struct {
	cmd, local string
	file       string
	kmsKey     string
	region     string
}

func (f *keyFlags) register(fs *flag.FlagSet, fileUsage, kmsUsage string) {
	fs.StringVar(&f.file, f.local, "", fileUsage)
	fs.StringVar(&f.kmsKey, "kms-key", "", kmsUsage)
	fs.StringVar(&f.region, "region", "", "AWS region for KMS (default: the SDK's)")
}

// resolve reads the key source the flags name: the PEM file's contents for
// a local key, or the KMS client for -kms-key. Exactly one of the two is
// returned; giving both flags, or neither, is an error.
func (f *keyFlags) resolve(ctx context.Context, clients awsClients) ([]byte, grant.KMSAPI, error) {
	switch {
	case f.file != "" && f.kmsKey != "":
		return nil, nil, fmt.Errorf("%s: -%s and -kms-key are exclusive", f.cmd, f.local)
	case f.file != "":
		pemData, err := os.ReadFile(f.file)
		return pemData, nil, err
	case f.kmsKey != "":
		api, err := clients.kms(ctx, f.region)
		return nil, api, err
	default:
		return nil, nil, fmt.Errorf("%s: one of -%s or -kms-key is required", f.cmd, f.local)
	}
}

// wrap names the PEM file in an error about the key it holds.
func (f *keyFlags) wrap(err error) error {
	return fmt.Errorf("%s: %s: %w", f.cmd, f.file, err)
}

// signer makes the signer the flags name.
func (f *keyFlags) signer(ctx context.Context, clients awsClients) (grant.Signer, error) {
	pemData, api, err := f.resolve(ctx, clients)
	if err != nil {
		return nil, err
	}
	if api != nil {
		return grant.NewKMSSigner(api, f.kmsKey), nil
	}
	key, err := grant.ParseECPrivateKey(pemData)
	if err != nil {
		return nil, f.wrap(err)
	}
	signer, err := grant.NewLocalSigner(key)
	if err != nil {
		return nil, f.wrap(err)
	}
	return signer, nil
}

// verifier makes the verifier the flags name.
func (f *keyFlags) verifier(ctx context.Context, clients awsClients) (grant.Verifier, error) {
	pemData, api, err := f.resolve(ctx, clients)
	if err != nil {
		return nil, err
	}
	if api != nil {
		return grant.NewKMSVerifier(api, f.kmsKey), nil
	}
	pubs, err := grant.ParseECPublicKeys(pemData)
	if err != nil {
		return nil, f.wrap(err)
	}
	ring, err := grant.NewKeyRing(pubs...)
	if err != nil {
		return nil, f.wrap(err)
	}
	return ring, nil
}

func runSign(ctx context.Context, args []string, stdout, stderr io.Writer, clients awsClients) error {
	fs := newFlags("sign", stderr)
	kf := keyFlags{cmd: "sign", local: "key"}
	kf.register(fs, "PEM file with the ECDSA P-256 private key", "ARN of the KMS signing key (ECC_NIST_P256)")
	out := fs.String("o", "", "where to write the signature, with a single file (default: <file>.sig)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	files, err := documentArgs("sign", fs.Args(), *out, "-o")
	if err != nil {
		return err
	}
	signer, err := kf.signer(ctx, clients)
	if err != nil {
		return err
	}
	for _, path := range files {
		if err := signFile(ctx, stdout, signer, path, sigPathOf(path, *out)); err != nil {
			return err
		}
	}
	return nil
}

// documentArgs checks the files a command was given: at least one, and
// the single-file flag (flagName, set to value) only with exactly one.
func documentArgs(cmd string, files []string, value, flagName string) ([]string, error) {
	switch {
	case len(files) == 0:
		return nil, fmt.Errorf("%s: want a bundle or assignments file", cmd)
	case value != "" && len(files) > 1:
		return nil, fmt.Errorf("%s: %s names one signature; give one file with it", cmd, flagName)
	}
	return files, nil
}

// sigPathOf is the signature file of a document: the one given, or
// <file>.sig.
func sigPathOf(path, given string) string {
	if given != "" {
		return given
	}
	return path + ".sig"
}

// signFile signs one document, a bundle or assignments, into sigPath.
func signFile(ctx context.Context, stdout io.Writer, signer grant.Signer, path, sigPath string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if _, _, err := grant.ParseArtifact(data); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	sig, err := signer.Sign(ctx, data)
	if err != nil {
		return err
	}
	sigData, err := sig.Marshal()
	if err != nil {
		return err
	}
	if err := os.WriteFile(sigPath, sigData, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "signed %s with %s: %s\n", path, sig.KeyID, sigPath)
	return nil
}

func runVerify(ctx context.Context, args []string, stdout, stderr io.Writer, clients awsClients) error {
	fs := newFlags("verify", stderr)
	kf := keyFlags{cmd: "verify", local: "pub"}
	kf.register(fs, "PEM file with the ECDSA P-256 public key, or several: any of them verifies", "ARN or alias of the KMS key that signed; only its public key is fetched")
	sigPath := fs.String("sig", "", "the signature file, with a single file (default: <file>.sig)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	files, err := documentArgs("verify", fs.Args(), *sigPath, "-sig")
	if err != nil {
		return err
	}
	verifier, err := kf.verifier(ctx, clients)
	if err != nil {
		return err
	}
	for _, path := range files {
		data, sig, err := readSigned(path, sigPathOf(path, *sigPath))
		if err != nil {
			return err
		}
		if err := verifier.Verify(ctx, data, sig); err != nil {
			return fmt.Errorf("%w: %s: %v", errNotVerified, path, err)
		}
		fmt.Fprintf(stdout, "verified %s: signed by %s\n", path, sig.KeyID)
	}
	return nil
}

func runPublish(ctx context.Context, args []string, stdout, stderr io.Writer, clients awsClients) error {
	fs := newFlags("publish", stderr)
	dir := fs.String("dir", "", "publish into this directory")
	s3Dest := fs.String("s3", "", "publish into this bucket, as bucket or bucket/prefix")
	region := fs.String("region", "", "AWS region for S3 (default: the SDK's)")
	sigPath := fs.String("sig", "", "the bundle's signature file (default: <bundle>.sig)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 || fs.NArg() > 2 {
		return errors.New("publish: want a bundle file and, optionally, its assignments file")
	}
	publisher, err := newPublisher(ctx, *dir, *s3Dest, *region, clients)
	if err != nil {
		return err
	}
	pub, err := readPublication(fs.Args(), *sigPath)
	if err != nil {
		return err
	}
	res, err := publisher.Publish(ctx, *pub)
	if err != nil {
		return err
	}
	written := []string{res.Bundle, res.Signature}
	if res.Assignments != "" {
		written = append(written, res.Assignments, res.AssignmentsSignature)
	} else {
		fmt.Fprintf(stderr, "cracha-grantc: publish: version %s has no assignments; a broker reading its assignments from the publication refuses it\n", res.Version)
	}
	fmt.Fprintf(stdout, "published version %s: %s, %s\n", res.Version, strings.Join(written, ", "), res.Latest)
	return nil
}

// newPublisher makes the publisher the destination flags name.
func newPublisher(ctx context.Context, dir, s3Dest, region string, clients awsClients) (grant.Publisher, error) {
	switch {
	case dir != "" && s3Dest != "":
		return nil, errors.New("publish: -dir and -s3 are exclusive")
	case dir != "":
		return &grant.LocalPublisher{Root: dir}, nil
	case s3Dest != "":
		bucket, prefix, _ := strings.Cut(strings.TrimPrefix(s3Dest, "s3://"), "/")
		if bucket == "" {
			return nil, errors.New("publish: -s3 needs a bucket")
		}
		api, err := clients.s3(ctx, region)
		if err != nil {
			return nil, err
		}
		return grant.NewS3Publisher(api, bucket, prefix), nil
	default:
		return nil, errors.New("publish: one of -dir or -s3 is required")
	}
}

// readPublication reads the documents to publish and their signatures:
// exactly one bundle and at most one assignments document, in any order.
// bundleSig, when given, is the bundle's signature file.
func readPublication(files []string, bundleSig string) (*grant.Publication, error) {
	pub := &grant.Publication{}
	for _, path := range files {
		if err := addDocument(pub, path, bundleSig); err != nil {
			return nil, err
		}
	}
	if pub.Bundle == nil {
		return nil, errors.New("publish: no bundle among the files")
	}
	return pub, nil
}

// addDocument reads one document and its signature into the publication,
// in the place its kind says.
func addDocument(pub *grant.Publication, path, bundleSig string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	kind, _, err := grant.ParseArtifact(data)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	doc, sig, given := &pub.Bundle, &pub.BundleSignature, bundleSig
	if kind == grant.ArtifactAssignments {
		doc, sig, given = &pub.Assignments, &pub.AssignmentsSignature, ""
	}
	if *doc != nil {
		return fmt.Errorf("publish: %s is a second %s", path, kind)
	}
	if _, *sig, err = readSigned(path, sigPathOf(path, given)); err != nil {
		return err
	}
	*doc = data
	return nil
}

// readSigned reads a document and its signature envelope.
func readSigned(path, sigPath string) ([]byte, *grant.Signature, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	sigData, err := os.ReadFile(sigPath)
	if err != nil {
		return nil, nil, err
	}
	sig, err := grant.ParseSignature(sigData)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", sigPath, err)
	}
	return data, sig, nil
}

// printReport writes a lint report for humans: a line per grant, one per
// subject, the steps that did not run and the verdict.
func printReport(w io.Writer, r *grant.Report) {
	for _, g := range r.Grants {
		printGrant(w, g)
	}
	if r.Composition != nil {
		printComposition(w, r.Composition)
	}
	for _, step := range r.Skipped {
		fmt.Fprintf(w, "skipped: %s (run with -access-analyzer)\n", step)
	}
	if r.OK() {
		fmt.Fprintln(w, "ok: no problems")
	} else {
		fmt.Fprintf(w, "%d problems\n", len(r.Problems))
	}
}

// printGrant writes a grant's line, with its status and its size when the
// size step ran, then the validation findings that do not block and its
// problems.
func printGrant(w io.Writer, g grant.GrantResult) {
	var size string
	if g.Size != nil {
		size = fmt.Sprintf(", policy %d/%d chars, tags %d", g.Size.PolicyChars, grant.MaxPolicyChars, g.Size.TagCount)
	}
	fmt.Fprintf(w, "grant %s: %s%s\n", g.Grant, problemStatus(g.Problems), size)
	for _, f := range g.Validation {
		if !f.Blocking() {
			fmt.Fprintf(w, "  note: %s %s: %s\n", f.Type, f.Code, f.Detail)
		}
	}
	printProblems(w, g.Problems)
}

// printComposition writes a line per subject and cluster scope, then the
// assignments and service grants left out as expired.
func printComposition(w io.Writer, r *grant.CompositionReport) {
	for _, c := range r.Compositions {
		printSubject(w, c)
	}
	for _, source := range r.Expired {
		fmt.Fprintf(w, "%s: expired, left out of the composition\n", source)
	}
}

// printSubject writes one composition's line and its problems.
func printSubject(w io.Writer, c grant.Composition) {
	scope := c.Subject
	if c.Cluster != "" {
		scope += " in cluster " + c.Cluster
	}
	fmt.Fprintf(w, "subject %s: %s, grants %s, policy %d/%d chars\n", scope, problemStatus(c.Problems), strings.Join(c.Grants, ","), c.PolicyChars, grant.MaxPolicyChars)
	printProblems(w, c.Problems)
}

// problemStatus is "ok" or the count of problems.
func problemStatus(p grant.Problems) string {
	if p.OK() {
		return "ok"
	}
	return fmt.Sprintf("%d problems", len(p))
}

// printProblems writes each problem under its grant's or subject's line.
func printProblems(w io.Writer, problems grant.Problems) {
	for _, p := range problems {
		fmt.Fprintf(w, "  problem: %s\n", p)
	}
}
