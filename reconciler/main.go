// Command cracha-reconciler writes the SpiceDB schema of docs/design.md,
// section 6.4, through the SpiceDB gateway, over SPIFFE mTLS with its own
// X.509-SVID: from the Workload API, or from files (an SVID the issuer
// minted for a CI job or an operator).
//
//	cracha-reconciler schema -endpoint host:port -server-spiffe-id ID \
//	    (-workload-api unix:///path | -svid cert.pem -svid-key key.pem -bundle bundle.pem) [-dry-run]
//
// schema writes the embedded schema, which is idempotent, and reads it
// back to confirm; -dry-run prints it and connects to nothing. The gateway
// admits the reconciler's SPIFFE ID to SchemaService's WriteSchema and
// ReadSchema and to nothing else: the reconciler writes no relationship.
// With the spicedb backend, relationships live only in SpiceDB and their
// one writer is the access service (cracha-access); the former apply
// command, which wrote them from a Git tree, refuses with that message.
// The exit status is 0 on success, 1 when the schema read back lacks a
// definition or caveat written, and 2 on a usage or operational error.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/bpalermo/cracha/common/spicedb"
	"github.com/bpalermo/cracha/common/spicedb/conn"
	"github.com/bpalermo/cracha/common/version"
)

const usage = `usage: cracha-reconciler <command> [flags]

commands:
  schema   write the SpiceDB schema (idempotent); -dry-run prints it
  --version  print the version

Run "cracha-reconciler <command> -h" for a command's flags.`

// errApplyRemoved is what apply answers: the reconciler no longer writes
// relationships.
var errApplyRemoved = errors.New("apply was removed: with the spicedb backend, relationships live only in SpiceDB and are written by the access service (cracha-access), their one writer (docs/design.md, section 6.4); the reconciler writes the schema only, and the gateway refuses it every relationship write")

// errDiverged is a schema read back without the definitions written.
var errDiverged = errors.New("SpiceDB holds another schema after the write")

// declaration is a definition or caveat of a schema. SpiceDB answers
// ReadSchema with the schema it compiled, formatted its own way, so the
// read-back is compared by what it declares, not byte for byte.
var declaration = regexp.MustCompile(`(?m)^(definition|caveat) ([a-z][a-z0-9_]*)`)

// missingNames is every definition and caveat of the embedded schema that
// the schema read back does not declare.
func missingNames(read string) []string {
	held := map[string]bool{}
	for _, m := range declaration.FindAllStringSubmatch(read, -1) {
		held[m[1]+" "+m[2]] = true
	}
	var missing []string
	for _, m := range declaration.FindAllStringSubmatch(spicedb.Schema, -1) {
		if name := m[1] + " " + m[2]; !held[name] {
			missing = append(missing, name)
		}
	}
	return missing
}

// session is a connection to SpiceDB: its SchemaService and what to close.
type session struct {
	schema v1.SchemaServiceClient
	close  func() error
}

// dialer connects as the flags say, so tests can substitute a fake.
type dialer func(ctx context.Context, f *connFlags) (*session, error)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, dial))
}

// run is main without the process: it returns the exit status.
func run(args []string, stdout, stderr io.Writer, dial dialer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	var err error
	switch cmd := args[0]; cmd {
	case "--version", "-version":
		fmt.Fprintf(stdout, "cracha-reconciler %s\n", version.Version)
		return 0
	case "-h", "--help", "help":
		fmt.Fprintln(stdout, usage)
		return 0
	case "schema":
		err = runSchema(context.Background(), args[1:], stdout, stderr, dial)
	case "apply":
		err = errApplyRemoved
	default:
		fmt.Fprintf(stderr, "cracha-reconciler: unknown command %q\n%s\n", cmd, usage)
		return 2
	}
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return 0
	case errors.Is(err, errDiverged):
		fmt.Fprintf(stderr, "cracha-reconciler: %v\n", err)
		return 1
	default:
		fmt.Fprintf(stderr, "cracha-reconciler: %v\n", err)
		return 2
	}
}

// connFlags say how to reach SpiceDB's gateway and with which SVID.
type connFlags struct {
	endpoint    string
	server      string
	workloadAPI string
	svid        string
	svidKey     string
	bundle      string
	dryRun      bool
}

func (f *connFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.endpoint, "endpoint", "", "the SpiceDB gateway's gRPC address, host:port (required)")
	fs.StringVar(&f.server, "server-spiffe-id", "", "the SPIFFE ID the gateway must present (required)")
	fs.StringVar(&f.workloadAPI, "workload-api", "", "the SPIFFE Workload API address the reconciler's X.509-SVID and bundle come from, unix:///path; excludes -svid")
	fs.StringVar(&f.svid, "svid", "", "PEM file of the reconciler's X.509-SVID and its intermediates, with -svid-key and -bundle; excludes -workload-api")
	fs.StringVar(&f.svidKey, "svid-key", "", "PEM file of the SVID's private key (PKCS#8)")
	fs.StringVar(&f.bundle, "bundle", "", "PEM file of the trust domain's X.509 authorities, which verify the gateway")
	fs.BoolVar(&f.dryRun, "dry-run", false, "print the schema and connect to nothing")
}

// check validates the connection flags and parses the gateway's ID.
func (f *connFlags) check() (spiffeid.ID, error) {
	if f.endpoint == "" || f.server == "" {
		return spiffeid.ID{}, errors.New("-endpoint and -server-spiffe-id are required")
	}
	id, err := spiffeid.FromString(f.server)
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("-server-spiffe-id %q: %w", f.server, err)
	}
	files := f.svid != "" || f.svidKey != "" || f.bundle != ""
	switch {
	case f.workloadAPI != "" && files:
		return spiffeid.ID{}, errors.New("-workload-api excludes -svid, -svid-key and -bundle")
	case f.workloadAPI == "" && (f.svid == "" || f.svidKey == "" || f.bundle == ""):
		return spiffeid.ID{}, errors.New("give -workload-api, or -svid, -svid-key and -bundle")
	}
	return id, nil
}

// dial connects to the gateway with the SVID the flags name.
func dial(ctx context.Context, f *connFlags) (*session, error) {
	server, err := f.check()
	if err != nil {
		return nil, err
	}
	svids, bundles, closeSource, err := f.sources(ctx, server.TrustDomain())
	if err != nil {
		return nil, err
	}
	c, err := conn.Dial(conn.Config{Endpoint: f.endpoint, Server: server, SVIDs: svids, Bundles: bundles})
	if err != nil {
		_ = closeSource()
		return nil, err
	}
	return &session{schema: c.SchemaServiceClient, close: func() error { return errors.Join(c.Close(), closeSource()) }}, nil
}

// sources are the reconciler's SVID and bundle: the Workload API's, or the
// files', the bundle for the gateway's trust domain.
func (f *connFlags) sources(ctx context.Context, td spiffeid.TrustDomain) (x509svid.Source, x509bundle.Source, func() error, error) {
	if f.workloadAPI != "" {
		src, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(f.workloadAPI)))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("workload api %s: %w", f.workloadAPI, err)
		}
		return src, src, src.Close, nil
	}
	svid, err := x509svid.Load(f.svid, f.svidKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("svid: %w", err)
	}
	bundle, err := x509bundle.Load(td, f.bundle)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("bundle: %w", err)
	}
	return svid, bundle, func() error { return nil }, nil
}

func runSchema(ctx context.Context, args []string, stdout, stderr io.Writer, dial dialer) error {
	fs := flag.NewFlagSet("cracha-reconciler schema", flag.ContinueOnError)
	fs.SetOutput(stderr)
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
	if _, err := cf.check(); err != nil {
		return fmt.Errorf("schema: %w", err)
	}
	s, err := dial(ctx, &cf)
	if err != nil {
		return err
	}
	defer s.close()
	if _, err := s.schema.WriteSchema(ctx, &v1.WriteSchemaRequest{Schema: spicedb.Schema}); err != nil {
		return fmt.Errorf("write schema: %w", err)
	}
	read, err := s.schema.ReadSchema(ctx, &v1.ReadSchemaRequest{})
	if err != nil {
		return fmt.Errorf("read the schema back: %w", err)
	}
	if missing := missingNames(read.GetSchemaText()); len(missing) > 0 {
		return fmt.Errorf("%w: it lacks %s", errDiverged, strings.Join(missing, ", "))
	}
	fmt.Fprintf(stdout, "wrote the schema to %s\n", cf.endpoint)
	return nil
}
