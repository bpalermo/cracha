package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/bpalermo/cracha/broker/internal/authz/spicedb"
	"github.com/bpalermo/cracha/broker/internal/bundle"
	"github.com/bpalermo/cracha/broker/internal/cache"
	"github.com/bpalermo/cracha/broker/internal/grants"
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
	grantsFixture     string
	awsRegion         string
	logLevel          string
	showVersion       bool

	// The authorization backend (design 6.3): static, the assignments file
	// (broker/internal/authz/static), or spicedb, the reference backend
	// (broker/internal/authz/spicedb).
	authzBackend     string
	assignments      string
	spicedbEndpoint  string
	spicedbTokenFile string
	spicedbCA        string
	spicedbInsecure  bool
	spicedbTimeout   time.Duration

	// The compiled grant bundle (broker/internal/bundle), the production
	// source of grants; --grants-fixture is the development one, and
	// exactly one of the two is given.
	bundleSource       string
	bundleVerifyKey    string
	bundleKMSKey       string
	bundlePollInterval string

	// The credential cache (design 6.7); off keeps every request on the
	// direct path, for debugging.
	cache              bool
	cacheMinRemaining  time.Duration
	cacheRefreshAt     float64
	cacheMaxEntries    int
	cacheStaleCheckMax time.Duration

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

// duration is the environment's value for the flag parsed as a duration;
// def when unset or not a duration.
func (env envDefaults) duration(flag string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(env.str(flag, "")); err == nil {
		return d
	}
	return def
}

// float is the environment's value for the flag parsed as a float; def when
// unset or not a float.
func (env envDefaults) float(flag string, def float64) float64 {
	if f, err := strconv.ParseFloat(env.str(flag, ""), 64); err == nil {
		return f
	}
	return def
}

// integer is the environment's value for the flag parsed as an int; def
// when unset or not an int.
func (env envDefaults) integer(flag string, def int) int {
	if i, err := strconv.Atoi(env.str(flag, "")); err == nil {
		return i
	}
	return def
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
	fs.StringVar(&c.grantsFixture, "grants-fixture", env.str("grants-fixture", ""), "path to a resolved-grants fixture file, for development; excludes --bundle-source")
	fs.StringVar(&c.bundleSource, "bundle-source", env.str("bundle-source", ""), "where the compiled grant bundle is published: local:<dir> or s3://bucket[/prefix]; excludes --grants-fixture")
	fs.StringVar(&c.bundleVerifyKey, "bundle-verify-key", env.str("bundle-verify-key", ""), "path to the PEM public key the bundle's signature is verified with")
	fs.StringVar(&c.bundleKMSKey, "bundle-kms-key", env.str("bundle-kms-key", ""), "ARN of the KMS key the bundle's signature is verified with, instead of --bundle-verify-key")
	fs.StringVar(&c.bundlePollInterval, "bundle-poll-interval", env.str("bundle-poll-interval", bundle.DefaultPollInterval.String()), "how often to look for a new bundle version")
	fs.StringVar(&c.awsRegion, "aws-region", env.str("aws-region", ""), "AWS region for STS; the SDK's default chain when empty")
	fs.StringVar(&c.logLevel, "log-level", env.str("log-level", "info"), "log level: debug, info, warn or error")
	fs.BoolVar(&c.showVersion, "version", false, "print the version and exit")
	c.bindAuthzFlags(fs, env)
	c.bindCacheFlags(fs, env)
}

// bindAuthzFlags declares the authorization backend's flags (design 6.3).
func (c *config) bindAuthzFlags(fs *flag.FlagSet, env envDefaults) {
	fs.StringVar(&c.authzBackend, "authz-backend", env.str("authz-backend", backendStatic), "authorization backend: static (an assignments file) or spicedb")
	fs.StringVar(&c.assignments, "assignments", env.str("assignments", ""), "path to the static backend's assignments file (required with --authz-backend static)")
	fs.StringVar(&c.spicedbEndpoint, "spicedb-endpoint", env.str("spicedb-endpoint", ""), "SpiceDB gRPC address, host:port (required with --authz-backend spicedb)")
	fs.StringVar(&c.spicedbTokenFile, "spicedb-token-file", env.str("spicedb-token-file", ""), "path to the file holding SpiceDB's preshared key (required with --authz-backend spicedb)")
	fs.StringVar(&c.spicedbCA, "spicedb-ca", env.str("spicedb-ca", ""), "path to the PEM bundle SpiceDB's certificate is verified with; the system roots when empty")
	fs.BoolVar(&c.spicedbInsecure, "spicedb-insecure", env.boolean("spicedb-insecure", false), "speak plaintext gRPC to SpiceDB, the key in the clear; for kind only, excludes --spicedb-ca")
	fs.DurationVar(&c.spicedbTimeout, "spicedb-timeout", env.duration("spicedb-timeout", spicedb.DefaultTimeout), "how long one SpiceDB call may take")
}

// The authorization backends.
const (
	backendStatic  = "static"
	backendSpiceDB = "spicedb"
)

// authzProblems is what is wrong with the authorization backend flags: the
// static backend needs its assignments file and none of the SpiceDB flags;
// the SpiceDB backend needs an endpoint and a token file, no assignments
// file, at most one of a CA and insecure, and a positive timeout.
func (c *config) authzProblems() []string {
	var problems []string
	switch c.authzBackend {
	case backendStatic:
		problems = c.staticProblems()
	case backendSpiceDB:
		problems = c.spicedbProblems()
	default:
		problems = append(problems, fmt.Sprintf("--authz-backend %q is not static or spicedb", c.authzBackend))
	}
	if c.spicedbTimeout <= 0 {
		problems = append(problems, fmt.Sprintf("--spicedb-timeout %v is not positive", c.spicedbTimeout))
	}
	return problems
}

func (c *config) staticProblems() []string {
	var problems []string
	if c.assignments == "" {
		problems = append(problems, "--assignments is required with --authz-backend static")
	}
	if c.spicedbEndpoint != "" || c.spicedbTokenFile != "" || c.spicedbCA != "" || c.spicedbInsecure {
		problems = append(problems, "the --spicedb-* flags need --authz-backend spicedb")
	}
	return problems
}

func (c *config) spicedbProblems() []string {
	var problems []string
	if c.assignments != "" {
		problems = append(problems, "--assignments needs --authz-backend static")
	}
	if c.spicedbEndpoint == "" {
		problems = append(problems, "--spicedb-endpoint is required with --authz-backend spicedb")
	}
	if c.spicedbTokenFile == "" {
		problems = append(problems, "--spicedb-token-file is required with --authz-backend spicedb")
	}
	if c.spicedbInsecure && c.spicedbCA != "" {
		problems = append(problems, "--spicedb-insecure excludes --spicedb-ca")
	}
	return problems
}

// bindCacheFlags declares the credential cache's flags (design 6.7).
func (c *config) bindCacheFlags(fs *flag.FlagSet, env envDefaults) {
	fs.BoolVar(&c.cache, "cache", env.boolean("cache", true), "cache issued credentials between the authorization check and STS; off keeps every request on the direct path")
	fs.DurationVar(&c.cacheMinRemaining, "cache-min-remaining", env.duration("cache-min-remaining", cache.DefaultMinRemaining), "least lifetime cached credentials are served with")
	fs.Float64Var(&c.cacheRefreshAt, "cache-refresh-at", env.float("cache-refresh-at", cache.DefaultRefreshAt), "fraction of a session's usable lifetime (lifetime less --cache-min-remaining) after which it is refreshed in the background, in (0, 1)")
	fs.IntVar(&c.cacheMaxEntries, "cache-max-entries", env.integer("cache-max-entries", cache.DefaultMaxEntries), "most sessions cached; the least recently used is evicted beyond it")
	fs.DurationVar(&c.cacheStaleCheckMax, "cache-stale-check-max", env.duration("cache-stale-check-max", cache.DefaultStaleCheckMax), "how old a session's last successful authorization check may be for it to be served while the store is unavailable")
}

// cacheProblems is what is wrong with the cache flags.
func (c *config) cacheProblems() []string {
	var problems []string
	if c.cacheMinRemaining <= 0 || c.cacheMinRemaining >= grants.MaxDurationSeconds*time.Second {
		problems = append(problems, fmt.Sprintf("--cache-min-remaining %v is not between 0 and the session ceiling of %ds", c.cacheMinRemaining, grants.MaxDurationSeconds))
	}
	if c.cacheRefreshAt <= 0 || c.cacheRefreshAt >= 1 {
		problems = append(problems, fmt.Sprintf("--cache-refresh-at %v is not in (0, 1)", c.cacheRefreshAt))
	}
	if c.cacheMaxEntries <= 0 {
		problems = append(problems, fmt.Sprintf("--cache-max-entries %d is not positive", c.cacheMaxEntries))
	}
	if c.cacheStaleCheckMax <= 0 {
		problems = append(problems, fmt.Sprintf("--cache-stale-check-max %v is not positive", c.cacheStaleCheckMax))
	}
	return problems
}

// validate checks the parsed flags against each other and parses the trust
// domain labels into c.labels. Every problem found is reported, joined by
// "; ".
func (c *config) validate() error {
	var problems []string
	if c.cluster == "" {
		problems = append(problems, "--cluster is required")
	}
	if p := c.tlsProblem(); p != "" {
		problems = append(problems, p)
	}
	problems = append(problems, c.authzProblems()...)
	problems = append(problems, c.grantsProblems()...)
	labels, err := idenc.ParseLabels(c.trustDomainLabels)
	if err != nil {
		problems = append(problems, err.Error())
	}
	c.labels = labels
	if !validLogLevel(c.logLevel) {
		problems = append(problems, fmt.Sprintf("--log-level %q is not debug, info, warn or error", c.logLevel))
	}
	problems = append(problems, c.cacheProblems()...)
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
