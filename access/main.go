// Command cracha-access is the only writer of Crachá's authorization
// relationships on a SpiceDB install (docs/design.md, section 6.9).
//
//	cracha-access serve [flags]          the service: a gRPC API over SPIFFE mTLS
//	cracha-access watch-audit [flags]    log every relationship change on SpiceDB's Watch
//	cracha-access grant|revoke|approve|reject|list|explain|pending [flags]
//	                                     the CLI, calling the service with the caller's SVID
//	cracha-access version
//
// The service authorizes every write in SpiceDB (manage on the target),
// checks it against the current signed bundle the way CI checks a grant
// tree, puts a write on a sensitive target up for approval, and logs
// every request, decision, write and refusal as a JSON line on stdout. It
// reaches SpiceDB only through the gateway, with its own SVID. Flags have
// a CRACHA_<FLAG> environment fallback.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/bpalermo/cracha/access/internal/audit"
	"github.com/bpalermo/cracha/access/internal/service"
	"github.com/bpalermo/cracha/access/internal/store"
	"github.com/bpalermo/cracha/common/version"
)

const usage = `usage: cracha-access <command> [flags]

commands:
  serve        run the service
  watch-audit  log every relationship change SpiceDB's Watch reports
  grant        relate a workload or a service to a resource, or add a member to a service
  revoke       remove such a relationship
  approve      apply a pending request
  reject       drop a pending request
  list         a workload's, a service's or a resource's relationships
  explain      what a workload's credential is composed of now
  pending      the requests waiting for an approval
  version      print the version

run "cracha-access <command> -h" for a command's flags.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.LookupEnv, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, lookup func(string) (string, bool), stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "version", "--version", "-version":
		fmt.Fprintf(stdout, "cracha-access %s\n", version.Version)
		return 0
	case "serve":
		cfg, err := parseServe(rest, lookup, stderr)
		return exit(stderr, err, func() error { return runServe(ctx, cfg) })
	case "watch-audit":
		cfg, err := parseWatch(rest, lookup, stderr)
		return exit(stderr, err, func() error { return runWatch(ctx, cfg, stdout) })
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	if c, ok := commands[cmd]; ok {
		return runCLI(ctx, cmd, c, rest, lookup, stdout, stderr)
	}
	fmt.Fprintf(stderr, "cracha-access: unknown command %q\n%s", cmd, usage)
	return 2
}

// exit runs f once the flags parsed, and turns the outcome into an exit
// code: 2 for bad flags, 1 for a failure.
func exit(stderr io.Writer, parseErr error, f func() error) int {
	switch {
	case errors.Is(parseErr, flag.ErrHelp):
		return 0
	case parseErr != nil:
		fmt.Fprintf(stderr, "cracha-access: %v\n", parseErr)
		return 2
	}
	if err := f(); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(stderr, "cracha-access: %v\n", err)
		return 1
	}
	return 0
}

// watchConfig is watch-audit's configuration: the Workload API and
// SpiceDB, nothing else.
type watchConfig struct {
	workloadAPISocket string
	spicedb           spicedbFlags
}

func parseWatch(args []string, lookup func(string) (string, bool), stderr io.Writer) (watchConfig, error) {
	var c watchConfig
	e := env(lookup)
	fs := flag.NewFlagSet("cracha-access watch-audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&c.workloadAPISocket, "workload-api-socket", e.str("workload-api-socket", "unix:///run/spire/sockets/agent.sock"), "the SPIFFE Workload API")
	c.spicedb.bind(fs, e)
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	return c, c.spicedb.validate()
}

// runWatch logs SpiceDB's change feed until ctx ends.
func runWatch(ctx context.Context, cfg watchConfig, stdout io.Writer) error {
	src, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(cfg.workloadAPISocket)))
	if err != nil {
		return fmt.Errorf("workload api %s: %w", cfg.workloadAPISocket, err)
	}
	defer src.Close()
	client, err := dialSpiceDB(cfg.spicedb, src)
	if err != nil {
		return err
	}
	defer client.Close()
	service.WatchAudit(ctx, store.New(client, cfg.spicedb.timeout), audit.New(stdout), 5*time.Second)
	return ctx.Err()
}
