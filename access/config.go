package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/bpalermo/cracha/access/internal/service"
	"github.com/bpalermo/cracha/common/grant"
	"github.com/bpalermo/cracha/common/idenc"
	"github.com/bpalermo/cracha/common/publication"
)

// env resolves a flag's default from the environment: CRACHA_<FLAG> with
// the flag's dashes as underscores. A flag given on the command line wins.
type env func(string) (string, bool)

func (e env) str(flag, def string) string {
	if v, ok := e("CRACHA_" + strings.ToUpper(strings.ReplaceAll(flag, "-", "_"))); ok {
		return v
	}
	return def
}

func (e env) boolean(flag string, def bool) bool {
	b, err := strconv.ParseBool(e.str(flag, strconv.FormatBool(def)))
	return err == nil && b
}

func (e env) duration(flag string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(e.str(flag, "")); err == nil {
		return d
	}
	return def
}

// spicedbFlags is how cracha-access reaches SpiceDB: through the gateway,
// over SPIFFE mTLS with its own SVID (design 6.9).
type spicedbFlags struct {
	endpoint string
	serverID string
	timeout  time.Duration
	id       spiffeid.ID
}

func (f *spicedbFlags) bind(fs *flag.FlagSet, e env) {
	fs.StringVar(&f.endpoint, "spicedb-endpoint", e.str("spicedb-endpoint", ""), "the SpiceDB gateway's gRPC address, host:port")
	fs.StringVar(&f.serverID, "spicedb-spiffe-id", e.str("spicedb-spiffe-id", ""), "the SpiceDB gateway's SPIFFE ID, which its certificate must carry")
	fs.DurationVar(&f.timeout, "spicedb-timeout", e.duration("spicedb-timeout", 10*time.Second), "deadline of one SpiceDB call")
}

func (f *spicedbFlags) validate() error {
	if f.endpoint == "" || f.serverID == "" {
		return errors.New("--spicedb-endpoint and --spicedb-spiffe-id are required")
	}
	id, err := spiffeid.FromString(f.serverID)
	if err != nil {
		return fmt.Errorf("--spicedb-spiffe-id: %w", err)
	}
	f.id = id
	return nil
}

// serveConfig is the server's configuration.
type serveConfig struct {
	listen            string
	healthListen      string
	workloadAPISocket string
	trustDomainLabels string
	logLevel          string
	awsRegion         string
	spicedb           spicedbFlags

	bundleSource    string
	bundleVerifyKey string
	bundleKMSKey    string
	bundlePoll      time.Duration

	accessAnalyzer bool
	breakGlassMax  time.Duration
	maxExpiry      string
	pendingTTL     time.Duration
	watchAudit     bool

	labels    idenc.Labels
	bundle    publication.Location
	maxByKind map[string]time.Duration
}

func parseServe(args []string, lookup func(string) (string, bool), stderr io.Writer) (serveConfig, error) {
	var c serveConfig
	e := env(lookup)
	fs := flag.NewFlagSet("cracha-access serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&c.listen, "listen", e.str("listen", ":8443"), "address of the gRPC API, over SPIFFE mTLS")
	fs.StringVar(&c.healthListen, "health-listen", e.str("health-listen", ":8081"), "address of the plaintext probes (/healthz, /readyz)")
	fs.StringVar(&c.workloadAPISocket, "workload-api-socket", e.str("workload-api-socket", "unix:///run/spire/sockets/agent.sock"), "the SPIFFE Workload API")
	fs.StringVar(&c.trustDomainLabels, "trust-domain-labels", e.str("trust-domain-labels", ""), "trust domain short labels, td=label,... (design 4.3); the broker's")
	fs.StringVar(&c.logLevel, "log-level", e.str("log-level", "info"), "debug, info, warn or error")
	fs.StringVar(&c.awsRegion, "aws-region", e.str("aws-region", ""), "AWS region for S3, KMS and Access Analyzer; empty uses the SDK's default chain")
	c.spicedb.bind(fs, e)
	fs.StringVar(&c.bundleSource, "bundle-source", e.str("bundle-source", ""), "the grant publication: local:<dir> or s3://bucket[/prefix], the broker's")
	fs.StringVar(&c.bundleVerifyKey, "bundle-verify-key", e.str("bundle-verify-key", ""), "comma-separated PEM files of the publication's public keys")
	fs.StringVar(&c.bundleKMSKey, "bundle-kms-key", e.str("bundle-kms-key", ""), "KMS key whose public key verifies the publication, instead of --bundle-verify-key")
	fs.DurationVar(&c.bundlePoll, "bundle-poll-interval", e.duration("bundle-poll-interval", publication.DefaultPollInterval), "how often to look for a new bundle version")
	fs.BoolVar(&c.accessAnalyzer, "access-analyzer", e.boolean("access-analyzer", false), "run IAM Access Analyzer ValidatePolicy and CheckNoNewAccess on every composed policy a write changes (AWS credentials from the platform)")
	fs.DurationVar(&c.breakGlassMax, "break-glass-max", e.duration("break-glass-max", service.DefaultBreakGlassMax), "the furthest a break-glass write's expiresAt may be")
	fs.StringVar(&c.maxExpiry, "max-expiry", e.str("max-expiry", ""), "kind=duration,...: expiresAt is required on a write of the kind and at most this far")
	fs.DurationVar(&c.pendingTTL, "pending-ttl", e.duration("pending-ttl", service.DefaultPendingTTL), "how long a pending request waits for an approval")
	fs.BoolVar(&c.watchAudit, "watch-audit", e.boolean("watch-audit", true), "log every relationship change SpiceDB's Watch reports, by whoever made it")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if fs.NArg() > 0 {
		return c, fmt.Errorf("unexpected arguments: %q", fs.Args())
	}
	return c, c.validate()
}

func (c *serveConfig) validate() error {
	var err error
	if c.labels, err = idenc.ParseLabels(c.trustDomainLabels); err != nil {
		return fmt.Errorf("--trust-domain-labels: %w", err)
	}
	if err := c.spicedb.validate(); err != nil {
		return err
	}
	if c.bundle, err = publication.ParseSource(c.bundleSource); err != nil {
		return fmt.Errorf("--bundle-source: %w", err)
	}
	if (c.bundleVerifyKey == "") == (c.bundleKMSKey == "") {
		return errors.New("exactly one of --bundle-verify-key and --bundle-kms-key is required")
	}
	if c.breakGlassMax <= 0 || c.pendingTTL <= 0 || c.bundlePoll <= 0 {
		return errors.New("--break-glass-max, --pending-ttl and --bundle-poll-interval must be positive")
	}
	c.maxByKind, err = parseMaxExpiry(c.maxExpiry)
	return err
}

// parseMaxExpiry parses kind=duration,...; a kind is a resource kind of
// common/grant or service.
func parseMaxExpiry(s string) (map[string]time.Duration, error) {
	out := map[string]time.Duration{}
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item == "" {
			continue
		}
		kind, d, ok := strings.Cut(item, "=")
		if _, known := grant.LookupResourceKind(kind); !ok || (!known && kind != "service") {
			return nil, fmt.Errorf("--max-expiry %q: want kind=duration with a kind of %s or service", item, strings.Join(grant.ResourceKindNames(), ", "))
		}
		dur, err := time.ParseDuration(d)
		if err != nil || dur <= 0 {
			return nil, fmt.Errorf("--max-expiry %q: a positive duration", item)
		}
		out[kind] = dur
	}
	return out, nil
}

func (c *serveConfig) verifyKeys() []string {
	var out []string
	for _, p := range strings.Split(c.bundleVerifyKey, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
