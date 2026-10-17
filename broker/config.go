package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/bpalermo/cracha/broker/internal/bundle"
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

	// The compiled grant bundle (broker/internal/bundle), the production
	// source of grants; --grants-fixture is the development one, and
	// exactly one of the two is given.
	bundleSource       string
	bundleVerifyKey    string
	bundleKMSKey       string
	bundlePollInterval string

	labels       idenc.Labels
	bundle       bundle.Location
	pollInterval time.Duration
}

// errVersion is returned by parseConfig when --version was asked for.
var errVersion = errors.New("version")

// parseConfig parses the command line and the environment. lookupEnv is
// os.LookupEnv in production.
func parseConfig(args []string, lookupEnv func(string) (string, bool), stderr io.Writer) (config, error) {
	var c config
	fs := flag.NewFlagSet("cracha-broker", flag.ContinueOnError)
	fs.SetOutput(stderr)
	c.bindFlags(fs, envDefaults(lookupEnv))
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if c.showVersion {
		return c, errVersion
	}
	if fs.NArg() > 0 {
		return c, fmt.Errorf("unexpected arguments: %q", fs.Args())
	}
	err := c.validate()
	return c, err
}

// envDefaults resolves a flag's default from the environment: CRACHA_<FLAG>
// with the flag's dashes as underscores, else the built-in default. A flag
// given on the command line still wins, since it overrides the default.
type envDefaults func(string) (string, bool)

// str is the environment's value for the flag, or def when unset.
func (env envDefaults) str(flag, def string) string {
	if v, ok := env("CRACHA_" + strings.ToUpper(strings.ReplaceAll(flag, "-", "_"))); ok {
		return v
	}
	return def
}

// boolean is the environment's value for the flag parsed as a bool, def
// when unset, and false when it is set to something that is not a bool.
func (env envDefaults) boolean(flag string, def bool) bool {
	v := env.str(flag, "")
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	return err == nil && b
}

// bindFlags declares the broker's flags on fs with their defaults from env.
func (c *config) bindFlags(fs *flag.FlagSet, env envDefaults) {
	fs.StringVar(&c.listen, "listen", env.str("listen", ":8443"), "address to listen on")
	fs.StringVar(&c.tlsCert, "tls-cert", env.str("tls-cert", ""), "path to the TLS certificate (PEM); required unless --insecure-plaintext")
	fs.StringVar(&c.tlsKey, "tls-key", env.str("tls-key", ""), "path to the TLS private key (PEM)")
	fs.BoolVar(&c.insecurePlaintext, "insecure-plaintext", env.boolean("insecure-plaintext", false), "serve plain HTTP; for tests only, JWT-SVIDs travel in the clear")
	fs.StringVar(&c.workloadAPISocket, "workload-api-socket", env.str("workload-api-socket", "unix:///run/spire/sockets/agent.sock"), "SPIFFE Workload API address, for the trust bundles")
	fs.StringVar(&c.cluster, "cluster", env.str("cluster", ""), "name of the cluster this broker serves (required)")
	fs.StringVar(&c.trustDomainLabels, "trust-domain-labels", env.str("trust-domain-labels", ""), "trust domain short labels, <trust-domain>=<label>,...; unmapped domains get td.<name>")
	fs.StringVar(&c.assignments, "assignments", env.str("assignments", ""), "path to the static authorization backend's assignments file (required)")
	fs.StringVar(&c.grantsFixture, "grants-fixture", env.str("grants-fixture", ""), "path to a resolved-grants fixture file, for development; excludes --bundle-source")
	fs.StringVar(&c.bundleSource, "bundle-source", env.str("bundle-source", ""), "where the compiled grant bundle is published: local:<dir> or s3://bucket[/prefix]; excludes --grants-fixture")
	fs.StringVar(&c.bundleVerifyKey, "bundle-verify-key", env.str("bundle-verify-key", ""), "path to the PEM public key the bundle's signature is verified with")
	fs.StringVar(&c.bundleKMSKey, "bundle-kms-key", env.str("bundle-kms-key", ""), "ARN of the KMS key the bundle's signature is verified with, instead of --bundle-verify-key")
	fs.StringVar(&c.bundlePollInterval, "bundle-poll-interval", env.str("bundle-poll-interval", bundle.DefaultPollInterval.String()), "how often to look for a new bundle version")
	fs.StringVar(&c.awsRegion, "aws-region", env.str("aws-region", ""), "AWS region for STS; the SDK's default chain when empty")
	fs.StringVar(&c.logLevel, "log-level", env.str("log-level", "info"), "log level: debug, info, warn or error")
	fs.BoolVar(&c.showVersion, "version", false, "print the version and exit")
}

// validate checks the parsed flags against each other and parses the trust
// domain labels into c.labels. Every problem found is reported, joined by
// "; ".
func (c *config) validate() error {
	var problems []string
	required := []struct{ value, flag string }{
		{c.cluster, "--cluster"},
		{c.assignments, "--assignments"},
	}
	for _, r := range required {
		if r.value == "" {
			problems = append(problems, r.flag+" is required")
		}
	}
	if p := c.tlsProblem(); p != "" {
		problems = append(problems, p)
	}
	problems = append(problems, c.grantsProblems()...)
	labels, err := idenc.ParseLabels(c.trustDomainLabels)
	if err != nil {
		problems = append(problems, err.Error())
	}
	c.labels = labels
	if !validLogLevel(c.logLevel) {
		problems = append(problems, fmt.Sprintf("--log-level %q is not debug, info, warn or error", c.logLevel))
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// tlsProblem is what is wrong with the TLS flags, or empty: plaintext
// excludes a certificate and key, and TLS requires both.
func (c *config) tlsProblem() string {
	switch {
	case c.insecurePlaintext && (c.tlsCert != "" || c.tlsKey != ""):
		return "--insecure-plaintext excludes --tls-cert and --tls-key"
	case !c.insecurePlaintext && (c.tlsCert == "" || c.tlsKey == ""):
		return "--tls-cert and --tls-key are required (TLS is mandatory; --insecure-plaintext is for tests)"
	}
	return ""
}

// grantsProblems is what is wrong with the grant source flags: exactly one
// of the fixture and the bundle source, and with the bundle source exactly
// one verification key and a positive poll interval. It parses the bundle
// source into c.bundle and the interval into c.pollInterval.
func (c *config) grantsProblems() []string {
	var problems []string
	switch {
	case c.grantsFixture == "" && c.bundleSource == "":
		problems = append(problems, "one of --bundle-source (the compiled grant bundle) or --grants-fixture (development) is required")
	case c.grantsFixture != "" && c.bundleSource != "":
		problems = append(problems, "--grants-fixture and --bundle-source are exclusive")
	}
	if c.bundleSource == "" {
		if c.bundleVerifyKey != "" || c.bundleKMSKey != "" {
			problems = append(problems, "--bundle-verify-key and --bundle-kms-key need --bundle-source")
		}
		return problems
	}
	loc, err := bundle.ParseSource(c.bundleSource)
	if err != nil {
		problems = append(problems, err.Error())
	}
	c.bundle = loc
	switch {
	case c.bundleVerifyKey != "" && c.bundleKMSKey != "":
		problems = append(problems, "--bundle-verify-key and --bundle-kms-key are exclusive")
	case c.bundleVerifyKey == "" && c.bundleKMSKey == "":
		problems = append(problems, "--bundle-source needs one of --bundle-verify-key or --bundle-kms-key")
	}
	d, err := time.ParseDuration(c.bundlePollInterval)
	if err != nil || d <= 0 {
		problems = append(problems, fmt.Sprintf("--bundle-poll-interval %q is not a positive duration", c.bundlePollInterval))
	}
	c.pollInterval = d
	return problems
}

func validLogLevel(level string) bool {
	switch level {
	case "debug", "info", "warn", "error":
		return true
	}
	return false
}
