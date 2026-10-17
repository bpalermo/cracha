package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/bpalermo/cracha/common/idenc"
)

// config is the broker's configuration. Every flag has an environment
// fallback, CRACHA_<FLAG> with the flag's dashes as underscores; the flag
// wins when both are set.
type config struct {
	listen            string
	tlsCert           string
	tlsKey            string
	insecurePlaintext bool
	workloadAPISocket string
	cluster           string
	trustDomainLabels string
	assignments       string
	grantsFixture     string
	awsRegion         string
	logLevel          string
	showVersion       bool

	labels idenc.Labels
}

// errVersion is returned by parseConfig when --version was asked for.
var errVersion = errors.New("version")

// parseConfig parses the command line and the environment. lookupEnv is
// os.LookupEnv in production.
func parseConfig(args []string, lookupEnv func(string) (string, bool), stderr io.Writer) (config, error) {
	var c config
	fs := flag.NewFlagSet("cracha-broker", flag.ContinueOnError)
	fs.SetOutput(stderr)
	env := func(name, def string) string {
		if v, ok := lookupEnv("CRACHA_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))); ok {
			return v
		}
		return def
	}
	envBool := func(name string, def bool) bool {
		v := env(name, "")
		if v == "" {
			return def
		}
		b, err := strconv.ParseBool(v)
		return err == nil && b
	}
	fs.StringVar(&c.listen, "listen", env("listen", ":8443"), "address to listen on")
	fs.StringVar(&c.tlsCert, "tls-cert", env("tls-cert", ""), "path to the TLS certificate (PEM); required unless --insecure-plaintext")
	fs.StringVar(&c.tlsKey, "tls-key", env("tls-key", ""), "path to the TLS private key (PEM)")
	fs.BoolVar(&c.insecurePlaintext, "insecure-plaintext", envBool("insecure-plaintext", false), "serve plain HTTP; for tests only, JWT-SVIDs travel in the clear")
	fs.StringVar(&c.workloadAPISocket, "workload-api-socket", env("workload-api-socket", "unix:///run/spire/sockets/agent.sock"), "SPIFFE Workload API address, for the trust bundles")
	fs.StringVar(&c.cluster, "cluster", env("cluster", ""), "name of the cluster this broker serves (required)")
	fs.StringVar(&c.trustDomainLabels, "trust-domain-labels", env("trust-domain-labels", ""), "trust domain short labels, <trust-domain>=<label>,...; unmapped domains get td.<name>")
	fs.StringVar(&c.assignments, "assignments", env("assignments", ""), "path to the static authorization backend's assignments file (required)")
	fs.StringVar(&c.grantsFixture, "grants-fixture", env("grants-fixture", ""), "path to the resolved-grants fixture file (required until the compiled bundle loader lands)")
	fs.StringVar(&c.awsRegion, "aws-region", env("aws-region", ""), "AWS region for STS; the SDK's default chain when empty")
	fs.StringVar(&c.logLevel, "log-level", env("log-level", "info"), "log level: debug, info, warn or error")
	fs.BoolVar(&c.showVersion, "version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if c.showVersion {
		return c, errVersion
	}
	if fs.NArg() > 0 {
		return c, fmt.Errorf("unexpected arguments: %q", fs.Args())
	}

	var problems []string
	if c.cluster == "" {
		problems = append(problems, "--cluster is required")
	}
	if c.assignments == "" {
		problems = append(problems, "--assignments is required")
	}
	if c.grantsFixture == "" {
		problems = append(problems, "--grants-fixture is required")
	}
	switch {
	case c.insecurePlaintext && (c.tlsCert != "" || c.tlsKey != ""):
		problems = append(problems, "--insecure-plaintext excludes --tls-cert and --tls-key")
	case !c.insecurePlaintext && (c.tlsCert == "" || c.tlsKey == ""):
		problems = append(problems, "--tls-cert and --tls-key are required (TLS is mandatory; --insecure-plaintext is for tests)")
	}
	labels, err := idenc.ParseLabels(c.trustDomainLabels)
	if err != nil {
		problems = append(problems, err.Error())
	}
	c.labels = labels
	switch c.logLevel {
	case "debug", "info", "warn", "error":
	default:
		problems = append(problems, fmt.Sprintf("--log-level %q is not debug, info, warn or error", c.logLevel))
	}
	if len(problems) > 0 {
		return c, errors.New(strings.Join(problems, "; "))
	}
	return c, nil
}
