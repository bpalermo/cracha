// Command cracha-reconciler is the authz-reconciler of docs/design.md,
// section 6.4: it writes the SpiceDB schema and makes SpiceDB's
// relationships match a Git checkout of grants, the same tree
// cracha-grantc compiles.
//
//	cracha-reconciler schema -endpoint host:port -token-file FILE [-ca pem] [-insecure] [-dry-run]
//	cracha-reconciler apply  -source DIR -endpoint host:port -token-file FILE [-ca pem] [-insecure] [-dry-run]
//
// apply refuses a tree the loader or the lints reject, reads every
// relationship of the resource types it owns (grant, service, workload),
// logs the difference and writes it in batches, then reads back to confirm;
// a second run is a no-op. -dry-run logs the difference and writes
// nothing. The exit status is 0 on success, 1 when the tree is rejected or
// SpiceDB still differs after the write, and 2 on a usage or operational
// error.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	authzed "github.com/authzed/authzed-go/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/bpalermo/cracha/common/grant"
	"github.com/bpalermo/cracha/common/spicedb"
	"github.com/bpalermo/cracha/common/version"
	"github.com/bpalermo/cracha/reconciler/internal/reconcile"
)

const usage = `usage: cracha-reconciler <command> [flags]

commands:
  schema   write the SpiceDB schema (idempotent); -dry-run prints it
  apply    make SpiceDB's relationships match a grant source tree
  --version  print the version

Run "cracha-reconciler <command> -h" for a command's flags.`

// clients are the SpiceDB services a command uses; close releases the
// connection.
type clients struct {
	permissions v1.PermissionsServiceClient
	schema      v1.SchemaServiceClient
	close       func() error
}

// dialer connects to SpiceDB as the flags say, so tests can substitute a
// fake.
type dialer func(ctx context.Context, f *connFlags) (*clients, error)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, dial))
}

var (
	errRejected  = errors.New("source tree rejected")
	errDiverged  = errors.New("SpiceDB differs from the source after the write")
	errDialFlags = errors.New("-endpoint and -token-file are required")
)

// run is main without the process: it returns the exit status.
func run(args []string, stdout, stderr io.Writer, dial dialer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(stderr, nil))
	var err error
	switch cmd := args[0]; cmd {
	case "--version", "-version":
		fmt.Fprintf(stdout, "cracha-reconciler %s\n", version.Version)
		return 0
	case "-h", "--help", "help":
		fmt.Fprintln(stdout, usage)
		return 0
	case "schema":
		err = runSchema(ctx, args[1:], stdout, stderr, dial)
	case "apply":
		err = runApply(ctx, args[1:], stdout, stderr, log, dial)
	default:
		fmt.Fprintf(stderr, "cracha-reconciler: unknown command %q\n%s\n", cmd, usage)
		return 2
	}
	switch {
	case err == nil:
		return 0
	case errors.Is(err, flag.ErrHelp):
		return 0
	case errors.Is(err, errRejected), errors.Is(err, errDiverged):
		fmt.Fprintf(stderr, "cracha-reconciler: %v\n", err)
		return 1
	default:
		fmt.Fprintf(stderr, "cracha-reconciler: %v\n", err)
		return 2
	}
}

func newFlags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("cracha-reconciler "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// connFlags say how to reach SpiceDB.
type connFlags struct {
	endpoint  string
	tokenFile string
	ca        string
	insecure  bool
	dryRun    bool
}

func (f *connFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.endpoint, "endpoint", "", "SpiceDB gRPC endpoint, host:port (required)")
	fs.StringVar(&f.tokenFile, "token-file", "", "file holding the preshared key (required)")
	fs.StringVar(&f.ca, "ca", "", "PEM file with the CA that signed SpiceDB's certificate (default: the system roots)")
	fs.BoolVar(&f.insecure, "insecure", false, "connect without TLS; for kind only")
	fs.BoolVar(&f.dryRun, "dry-run", false, "write nothing")
}

// check validates the connection flags before anything is read.
func (f *connFlags) check() error {
	if f.endpoint == "" || f.tokenFile == "" {
		return errDialFlags
	}
	return nil
}

// bearer sends the preshared key as a bearer token on every call.
type bearer struct {
	token     string
	plaintext bool
}

func (b bearer) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + b.token}, nil
}

// RequireTransportSecurity refuses to send the key in clear unless
// -insecure asked for exactly that.
func (b bearer) RequireTransportSecurity() bool { return !b.plaintext }

// dial connects to SpiceDB as the flags say.
func dial(_ context.Context, f *connFlags) (*clients, error) {
	token, err := os.ReadFile(f.tokenFile)
	if err != nil {
		return nil, fmt.Errorf("token file: %w", err)
	}
	key := strings.TrimSpace(string(token))
	if key == "" {
		return nil, fmt.Errorf("token file %s is empty", f.tokenFile)
	}
	creds, err := f.transport()
	if err != nil {
		return nil, err
	}
	c, err := authzed.NewClient(f.endpoint, grpc.WithTransportCredentials(creds), grpc.WithPerRPCCredentials(bearer{token: key, plaintext: f.insecure}))
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", f.endpoint, err)
	}
	return &clients{permissions: c.PermissionsServiceClient, schema: c.SchemaServiceClient, close: c.Close}, nil
}

// transport is the TLS configuration the flags describe, or plaintext.
func (f *connFlags) transport() (credentials.TransportCredentials, error) {
	if f.insecure {
		return insecure.NewCredentials(), nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if f.ca != "" {
		pemData, err := os.ReadFile(f.ca)
		if err != nil {
			return nil, fmt.Errorf("ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("ca: no certificate in %s", f.ca)
		}
		cfg.RootCAs = pool
	}
	return credentials.NewTLS(cfg), nil
}

func runSchema(ctx context.Context, args []string, stdout, stderr io.Writer, dial dialer) error {
	fs := newFlags("schema", stderr)
	var cf connFlags
	cf.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("schema: takes no arguments")
	}
	if cf.dryRun {
		_, err := io.WriteString(stdout, spicedb.Schema)
		return err
	}
	if err := cf.check(); err != nil {
		return fmt.Errorf("schema: %w", err)
	}
	c, err := dial(ctx, &cf)
	if err != nil {
		return err
	}
	defer c.close()
	r := &reconcile.Reconciler{Permissions: c.permissions, Schema: c.schema}
	if err := r.WriteSchema(ctx); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote the schema to %s\n", cf.endpoint)
	return nil
}

func runApply(ctx context.Context, args []string, stdout, stderr io.Writer, log *slog.Logger, dial dialer) error {
	fs := newFlags("apply", stderr)
	var cf connFlags
	cf.register(fs)
	source := fs.String("source", "", "the grant source tree (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("apply: takes no arguments")
	}
	if *source == "" {
		return errors.New("apply: -source is required")
	}
	if err := cf.check(); err != nil {
		return fmt.Errorf("apply: %w", err)
	}
	desired, err := loadDesired(ctx, *source, stderr)
	if err != nil {
		return err
	}
	c, err := dial(ctx, &cf)
	if err != nil {
		return err
	}
	defer c.close()
	r := &reconcile.Reconciler{Permissions: c.permissions, Schema: c.schema, Log: log}
	res, err := r.Apply(ctx, desired, cf.dryRun)
	if res != nil {
		printResult(stdout, res, cf.dryRun)
	}
	if err != nil {
		if res != nil && res.Written == res.Diff.Len() {
			return fmt.Errorf("%w: %v", errDiverged, err)
		}
		return err
	}
	return nil
}

// loadDesired loads and lints the tree, printing the lints' problems to
// stderr, and computes the relationships it calls for. A tree the loader
// or a lint rejects is errRejected.
func loadDesired(ctx context.Context, source string, stderr io.Writer) ([]reconcile.Relationship, error) {
	src, err := grant.Load(source)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errRejected, err)
	}
	report, err := grant.Lint(ctx, src, grant.LintOptions{})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errRejected, err)
	}
	if !report.OK() {
		for _, p := range report.Problems {
			fmt.Fprintf(stderr, "problem: %s\n", p)
		}
		return nil, fmt.Errorf("%w: %d problems", errRejected, len(report.Problems))
	}
	desired, err := reconcile.Desired(src)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errRejected, err)
	}
	return desired, nil
}

// printResult writes the one-line summary of an apply.
func printResult(w io.Writer, res *reconcile.Result, dryRun bool) {
	d := res.Diff
	switch {
	case d.Empty():
		fmt.Fprintln(w, "nothing to change: SpiceDB matches the source")
	case dryRun:
		fmt.Fprintf(w, "dry run: %d relationships to write and %d to delete; nothing written\n", len(d.Touch), len(d.Delete))
	default:
		fmt.Fprintf(w, "wrote %d of %d updates (%d to write, %d to delete) in %d batches, at %s\n", res.Written, d.Len(), len(d.Touch), len(d.Delete), res.Batches, res.Token)
	}
}
