// Command cracha-grantc is the grant compiler (docs/design.md, section 6.2):
// it lints a Git checkout of grants, compiles the bundle the broker consumes,
// signs it, verifies a signature and publishes a signed bundle.
//
//	cracha-grantc lint <dir> [-access-analyzer [-region r]]
//	cracha-grantc compile <dir> -o bundle.json [-version v] [-generated-at t] [-access-analyzer [-region r]]
//	cracha-grantc sign (-key priv.pem | -kms-key arn [-region r]) [-o bundle.json.sig] bundle.json
//	cracha-grantc verify (-pub pub.pem | -kms-key arn [-region r]) [-sig bundle.json.sig] bundle.json
//	cracha-grantc publish (-dir path | -s3 bucket[/prefix] [-region r]) [-sig bundle.json.sig] bundle.json
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
  compile  <dir> -o FILE   lint, then compile the bundle
  sign     bundle.json     sign a bundle with a local key or a KMS key
  verify   bundle.json     verify a bundle's signature
  publish  bundle.json     publish a signed bundle to a directory or S3
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
	ver := fs.String("version", "", "the bundle's version, such as the git commit (default: the content hash)")
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
	bundle, report, err := grant.Compile(ctx, src, copts)
	if report != nil {
		printReport(stdout, report)
	}
	if err != nil {
		if report != nil && !report.OK() {
			return fmt.Errorf("%w: %d", errProblems, len(report.Problems))
		}
		return err
	}
	data, err := grant.Marshal(bundle)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "compiled %s: version %s, %d grants, %d bytes\n", *out, bundle.Version, len(bundle.Grants), len(data))
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
	pub, err := grant.ParseECPublicKey(pemData)
	if err != nil {
		return nil, f.wrap(err)
	}
	verifier, err := grant.NewLocalVerifier(pub)
	if err != nil {
		return nil, f.wrap(err)
	}
	return verifier, nil
}

func runSign(ctx context.Context, args []string, stdout, stderr io.Writer, clients awsClients) error {
	fs := newFlags("sign", stderr)
	kf := keyFlags{cmd: "sign", local: "key"}
	kf.register(fs, "PEM file with the ECDSA P-256 private key", "ARN of the KMS signing key (ECC_NIST_P256)")
	out := fs.String("o", "", "where to write the signature (default: <bundle>.sig)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("sign: want exactly one bundle file")
	}
	signer, err := kf.signer(ctx, clients)
	if err != nil {
		return err
	}
	bundlePath := fs.Arg(0)
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		return err
	}
	if _, err := grant.ParseBundle(data); err != nil {
		return err
	}
	sig, err := signer.Sign(ctx, data)
	if err != nil {
		return err
	}
	sigData, err := sig.Marshal()
	if err != nil {
		return err
	}
	sigPath := *out
	if sigPath == "" {
		sigPath = bundlePath + ".sig"
	}
	if err := os.WriteFile(sigPath, sigData, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "signed %s with %s: %s\n", bundlePath, sig.KeyID, sigPath)
	return nil
}

func runVerify(ctx context.Context, args []string, stdout, stderr io.Writer, clients awsClients) error {
	fs := newFlags("verify", stderr)
	kf := keyFlags{cmd: "verify", local: "pub"}
	kf.register(fs, "PEM file with the ECDSA P-256 public key", "ARN of the KMS key that signed")
	sigPath := fs.String("sig", "", "the signature file (default: <bundle>.sig)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("verify: want exactly one bundle file")
	}
	verifier, err := kf.verifier(ctx, clients)
	if err != nil {
		return err
	}
	bundlePath := fs.Arg(0)
	data, sig, err := readSigned(bundlePath, *sigPath)
	if err != nil {
		return err
	}
	if err := verifier.Verify(ctx, data, sig); err != nil {
		return fmt.Errorf("%w: %v", errNotVerified, err)
	}
	fmt.Fprintf(stdout, "verified %s: signed by %s\n", bundlePath, sig.KeyID)
	return nil
}

func runPublish(ctx context.Context, args []string, stdout, stderr io.Writer, clients awsClients) error {
	fs := newFlags("publish", stderr)
	dir := fs.String("dir", "", "publish into this directory")
	s3Dest := fs.String("s3", "", "publish into this bucket, as bucket or bucket/prefix")
	region := fs.String("region", "", "AWS region for S3 (default: the SDK's)")
	sigPath := fs.String("sig", "", "the signature file (default: <bundle>.sig)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("publish: want exactly one bundle file")
	}
	var publisher grant.Publisher
	switch {
	case *dir != "" && *s3Dest != "":
		return errors.New("publish: -dir and -s3 are exclusive")
	case *dir != "":
		publisher = &grant.LocalPublisher{Root: *dir}
	case *s3Dest != "":
		bucket, prefix, _ := strings.Cut(strings.TrimPrefix(*s3Dest, "s3://"), "/")
		if bucket == "" {
			return errors.New("publish: -s3 needs a bucket")
		}
		api, err := clients.s3(ctx, *region)
		if err != nil {
			return err
		}
		publisher = grant.NewS3Publisher(api, bucket, prefix)
	default:
		return errors.New("publish: one of -dir or -s3 is required")
	}
	data, sig, err := readSigned(fs.Arg(0), *sigPath)
	if err != nil {
		return err
	}
	res, err := publisher.Publish(ctx, data, sig)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "published version %s: %s, %s, %s\n", res.Version, res.Bundle, res.Signature, res.Latest)
	return nil
}

// readSigned reads a bundle and its signature envelope.
func readSigned(bundlePath, sigPath string) ([]byte, *grant.Signature, error) {
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		return nil, nil, err
	}
	if sigPath == "" {
		sigPath = bundlePath + ".sig"
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
// assignments left out as expired.
func printComposition(w io.Writer, r *grant.CompositionReport) {
	for _, c := range r.Compositions {
		printSubject(w, c)
	}
	for _, name := range r.Expired {
		fmt.Fprintf(w, "assignment %s: expired, left out of the composition\n", name)
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
