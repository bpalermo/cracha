package main

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func envOf(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

func TestParseConfig(t *testing.T) {
	c, err := parseConfig([]string{
		"--cluster", "prod-a", "--assignments", "a.yaml", "--grants-fixture", "g.yaml",
		"--namespace", "cracha-system", "--trust-domain-labels", "example.org=prod",
	}, envOf(nil), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.listen != ":8443" || c.healthListen != ":8081" || c.cluster != "prod-a" || c.labels.Short("example.org") != "prod" || c.logLevel != "info" {
		t.Errorf("config %+v", c)
	}
	if c.namespace != "cracha-system" || !c.agentID.IsZero() {
		t.Errorf("agent identity not left to be derived: %+v", c)
	}
	if !c.cache || c.cacheMinRemaining != 20*time.Minute || c.cacheRefreshAt != 0.7 || c.cacheMaxEntries != 10000 || c.cacheStaleCheckMax != 10*time.Minute {
		t.Errorf("cache defaults %+v", c)
	}
}

func TestParseConfigCacheFlags(t *testing.T) {
	env := envOf(map[string]string{
		"CRACHA_CACHE":                 "false",
		"CRACHA_CACHE_MIN_REMAINING":   "15m",
		"CRACHA_CACHE_REFRESH_AT":      "0.5",
		"CRACHA_CACHE_MAX_ENTRIES":     "500",
		"CRACHA_CACHE_STALE_CHECK_MAX": "5m",
	})
	base := []string{"--cluster", "c", "--assignments", "a", "--grants-fixture", "g", "--namespace", "n"}
	c, err := parseConfig(base, env, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.cache || c.cacheMinRemaining != 15*time.Minute || c.cacheRefreshAt != 0.5 || c.cacheMaxEntries != 500 || c.cacheStaleCheckMax != 5*time.Minute {
		t.Errorf("env did not set the cache flags: %+v", c)
	}
	c, err = parseConfig(append(append([]string{}, base...), "--cache", "--cache-refresh-at", "0.8", "--cache-max-entries", "7"), env, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !c.cache || c.cacheRefreshAt != 0.8 || c.cacheMaxEntries != 7 || c.cacheMinRemaining != 15*time.Minute {
		t.Errorf("flags did not win over env: %+v", c)
	}
	for name, args := range map[string][]string{
		"refresh at zero":       {"--cache-refresh-at", "0"},
		"refresh at one":        {"--cache-refresh-at", "1"},
		"min remaining zero":    {"--cache-min-remaining", "0s"},
		"min remaining an hour": {"--cache-min-remaining", "1h"},
		"no entries":            {"--cache-max-entries", "0"},
		"stale check zero":      {"--cache-stale-check-max", "0s"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseConfig(append(append([]string{}, base...), args...), envOf(nil), io.Discard); err == nil {
				t.Fatalf("accepted %q", strings.Join(args, " "))
			}
		})
	}
}

func TestEnvDefaultsTyped(t *testing.T) {
	env := envDefaults(envOf(map[string]string{
		"CRACHA_CACHE_MIN_REMAINING": "soon",
		"CRACHA_CACHE_REFRESH_AT":    "0.25",
		"CRACHA_CACHE_MAX_ENTRIES":   "lots",
	}))
	if got := env.duration("cache-min-remaining", time.Minute); got != time.Minute {
		t.Errorf("a value that is not a duration gave %v, want the default", got)
	}
	if got := env.duration("cache-stale-check-max", time.Minute); got != time.Minute {
		t.Errorf("unset duration gave %v, want the default", got)
	}
	if got := env.float("cache-refresh-at", 0.7); got != 0.25 {
		t.Errorf("float %v", got)
	}
	if got := env.integer("cache-max-entries", 3); got != 3 {
		t.Errorf("a value that is not an int gave %d, want the default", got)
	}
}

func TestParseConfigEnvFallback(t *testing.T) {
	env := envOf(map[string]string{
		"CRACHA_CLUSTER":             "prod-b",
		"CRACHA_ASSIGNMENTS":         "a.yaml",
		"CRACHA_GRANTS_FIXTURE":      "g.yaml",
		"CRACHA_NAMESPACE":           "cracha-system",
		"CRACHA_LISTEN":              ":8080",
		"CRACHA_TRUST_DOMAIN_LABELS": "example.org=prod",
		"CRACHA_LOG_LEVEL":           "debug",
	})
	c, err := parseConfig([]string{"--listen", ":9090"}, env, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.cluster != "prod-b" || c.namespace != "cracha-system" || c.logLevel != "debug" {
		t.Errorf("config %+v", c)
	}
	if c.listen != ":9090" {
		t.Errorf("flag did not win over env: %q", c.listen)
	}
}

func TestEnvDefaults(t *testing.T) {
	env := envDefaults(envOf(map[string]string{
		"CRACHA_LISTEN":          ":8080",
		"CRACHA_CACHE":           "maybe",
		"CRACHA_AGENT_SPIFFE_ID": "",
	}))
	if got := env.str("listen", ":8443"); got != ":8080" {
		t.Errorf("listen %q", got)
	}
	if got := env.str("agent-spiffe-id", "default"); got != "" {
		t.Errorf("an empty variable is a value, got %q", got)
	}
	if got := env.str("namespace", "k.pem"); got != "k.pem" {
		t.Errorf("unset variable gave %q, want the default", got)
	}
	// A bool set to something that is not a bool is false, not the default.
	if env.boolean("cache", true) {
		t.Error("non-bool value read as true")
	}
	if !env.boolean("namespace", true) {
		t.Error("unset bool did not take the default")
	}
	if !env.boolean("agent-spiffe-id", true) {
		t.Error("empty bool did not take the default")
	}
}

func TestParseConfigBundle(t *testing.T) {
	c, err := parseConfig([]string{
		"--cluster", "prod-a", "--assignments", "a.yaml", "--namespace", "n",
		"--bundle-source", "s3://grants/cracha/prod", "--bundle-kms-key", "arn:aws:kms:eu-west-1:111122223333:key/abc",
	}, envOf(nil), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.bundle.Bucket != "grants" || c.bundle.Prefix != "cracha/prod" || !c.bundle.IsS3() || c.pollInterval != 60*time.Second {
		t.Errorf("config %+v", c)
	}
	env := envOf(map[string]string{
		"CRACHA_CLUSTER":              "prod-b",
		"CRACHA_ASSIGNMENTS":          "a.yaml",
		"CRACHA_NAMESPACE":            "cracha-system",
		"CRACHA_BUNDLE_SOURCE":        "local:/etc/cracha/bundle",
		"CRACHA_BUNDLE_VERIFY_KEY":    "/etc/cracha/bundle-key/public.pem",
		"CRACHA_BUNDLE_POLL_INTERVAL": "5m",
	})
	c, err = parseConfig(nil, env, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.bundle.Dir != "/etc/cracha/bundle" || c.bundle.IsS3() || c.pollInterval != 5*time.Minute || c.bundleVerifyKey.String() != "/etc/cracha/bundle-key/public.pem" {
		t.Errorf("config %+v", c)
	}
}

// The published assignments, and the verification keys as a list: from
// repeated flags, and from the environment's comma-separated list, which a
// flag replaces.
func TestParseConfigPublishedAssignments(t *testing.T) {
	base := []string{"--cluster", "c", "--namespace", "n", "--bundle-source", "local:/b", "--assignments-source", "published"}
	c, err := parseConfig(append(base, "--bundle-verify-key", "old.pem", "--bundle-verify-key", "new.pem"), envOf(nil), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.assignmentsSource != "published" || c.assignments != "" || strings.Join(c.bundleVerifyKey.paths, " ") != "old.pem new.pem" {
		t.Errorf("config %+v", c)
	}
	env := envOf(map[string]string{"CRACHA_BUNDLE_VERIFY_KEY": "a.pem, b.pem", "CRACHA_ASSIGNMENTS_SOURCE": "published"})
	c, err = parseConfig([]string{"--cluster", "c", "--namespace", "n", "--bundle-source", "local:/b"}, env, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.assignmentsSource != "published" || strings.Join(c.bundleVerifyKey.paths, " ") != "a.pem b.pem" {
		t.Errorf("env config %+v", c)
	}
	c, err = parseConfig(append(base, "--bundle-verify-key", "flag.pem"), env, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(c.bundleVerifyKey.paths, " ") != "flag.pem" {
		t.Errorf("the flag did not replace the environment's keys: %v", c.bundleVerifyKey.paths)
	}
	if _, err := parseConfig(append(base, "--bundle-verify-key", ""), envOf(nil), io.Discard); err == nil {
		t.Error("an empty --bundle-verify-key was accepted")
	}
}

func TestParseConfigBundleRejects(t *testing.T) {
	base := []string{"--cluster", "c", "--assignments", "a", "--namespace", "n"}
	with := func(args ...string) []string { return append(append([]string{}, base...), args...) }
	tests := map[string]struct {
		args []string
		want string
	}{
		"neither fixture nor bundle": {with(), "one of --bundle-source"},
		"both fixture and bundle":    {with("--grants-fixture", "g", "--bundle-source", "local:/b", "--bundle-verify-key", "k"), "exclusive"},
		"bundle without a key":       {with("--bundle-source", "local:/b"), "one of --bundle-verify-key or --bundle-kms-key"},
		"bundle with both keys":      {with("--bundle-source", "local:/b", "--bundle-verify-key", "k", "--bundle-kms-key", "arn"), "exclusive"},
		"key without a bundle":       {with("--grants-fixture", "g", "--bundle-verify-key", "k"), "need --bundle-source"},
		"kms without a bundle":       {with("--grants-fixture", "g", "--bundle-kms-key", "arn"), "need --bundle-source"},
		"bad source":                 {with("--bundle-source", "/b", "--bundle-verify-key", "k"), "want local:<dir> or s3://bucket"},
		"empty local dir":            {with("--bundle-source", "local:", "--bundle-verify-key", "k"), "needs a directory"},
		"bad interval":               {with("--bundle-source", "local:/b", "--bundle-verify-key", "k", "--bundle-poll-interval", "soon"), "not a positive duration"},
		"zero interval":              {with("--bundle-source", "local:/b", "--bundle-verify-key", "k", "--bundle-poll-interval", "0s"), "not a positive duration"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := parseConfig(tc.args, envOf(nil), io.Discard)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%q: got %v, want an error containing %q", strings.Join(tc.args, " "), err, tc.want)
			}
		})
	}
}

func TestParseConfigAuthz(t *testing.T) {
	c, err := parseConfig([]string{
		"--cluster", "prod-a", "--grants-fixture", "g.yaml", "--namespace", "n",
		"--authz-backend", "spicedb", "--spicedb-endpoint", "spicedb:50051",
		"--spicedb-server-spiffe-id", "spiffe://prod.example.org/ns/authz/sa/spicedb", "--spicedb-timeout", "2s",
	}, envOf(nil), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.authzBackend != "spicedb" || c.spicedbEndpoint != "spicedb:50051" ||
		c.spicedbServer.String() != "spiffe://prod.example.org/ns/authz/sa/spicedb" || c.spicedbTimeout != 2*time.Second {
		t.Errorf("config %+v", c)
	}
	env := envOf(map[string]string{
		"CRACHA_CLUSTER":            "prod-b",
		"CRACHA_GRANTS_FIXTURE":     "g.yaml",
		"CRACHA_NAMESPACE":          "cracha-system",
		"CRACHA_AUTHZ_BACKEND":      "spicedb",
		"CRACHA_SPICEDB_ENDPOINT":   "spicedb.spicedb.svc:50051",
		"CRACHA_SPICEDB_SERVER_SPIFFE_ID": "/ns/authz/sa/spicedb",
	})
	c, err = parseConfig(nil, env, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.authzBackend != "spicedb" || c.spicedbEndpoint != "spicedb.spicedb.svc:50051" || c.spicedbServerID != "/ns/authz/sa/spicedb" ||
		!c.spicedbServer.IsZero() || c.spicedbTimeout != 5*time.Second {
		t.Errorf("env did not set the spicedb flags: %+v", c)
	}
	c, err = parseConfig([]string{"--cluster", "c", "--grants-fixture", "g", "--namespace", "n", "--assignments", "a"}, envOf(nil), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.authzBackend != "static" {
		t.Errorf("default backend %q", c.authzBackend)
	}
}

func TestParseConfigAuthzRejects(t *testing.T) {
	base := []string{"--cluster", "c", "--grants-fixture", "g", "--namespace", "n"}
	with := func(args ...string) []string { return append(append([]string{}, base...), args...) }
	spicedb := []string{"--authz-backend", "spicedb", "--spicedb-endpoint", "e"}
	tests := map[string]struct {
		args []string
		want string
	}{
		"unknown backend":            {with("--authz-backend", "ldap", "--assignments", "a"), "not static or spicedb"},
		"static without assignments": {with(), "--assignments is required"},
		"static with endpoint":       {with("--assignments", "a", "--spicedb-endpoint", "e"), "need --authz-backend spicedb"},
		"static with server id":      {with("--assignments", "a", "--spicedb-server-spiffe-id", "/ns/a/sa/b"), "need --authz-backend spicedb"},
		"spicedb without endpoint":   {with("--authz-backend", "spicedb"), "--spicedb-endpoint is required"},
		"spicedb without namespace":  {[]string{"--cluster", "c", "--grants-fixture", "g", "--agent-spiffe-id", "spiffe://td/a", "--authz-backend", "spicedb", "--spicedb-endpoint", "e"}, "derive the SpiceDB gateway's SPIFFE ID"},
		"bad server id":              {with(append(spicedb, "--spicedb-server-spiffe-id", "https://x/y")...), "--spicedb-server-spiffe-id"},
		"bad server path":            {with(append(spicedb, "--spicedb-server-spiffe-id", "/ns/../sa")...), "--spicedb-server-spiffe-id"},
		"server is a trust domain":   {with(append(spicedb, "--spicedb-server-spiffe-id", "spiffe://td")...), "names a trust domain"},
		"spicedb with assignments":   {with(append(spicedb, "--assignments", "a")...), "--assignments needs --authz-backend static"},
		"spicedb with published":     {with(append(spicedb, "--assignments-source", "published")...), "--assignments-source published needs --authz-backend static"},
		"unknown source":             {with("--assignments-source", "git", "--assignments", "a"), `--assignments-source "git" is not file or published`},
		"published and a file":       {with("--assignments-source", "published", "--assignments", "a"), "are exclusive"},
		"published without a bundle": {with("--assignments-source", "published"), "needs --bundle-source"},
		"zero timeout":               {with(append(spicedb, "--spicedb-timeout", "0s")...), "not positive"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := parseConfig(tc.args, envOf(nil), io.Discard)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%q: got %v, want an error containing %q", strings.Join(tc.args, " "), err, tc.want)
			}
		})
	}
}

func TestParseConfigAgentID(t *testing.T) {
	c, err := parseConfig([]string{
		"--cluster", "c", "--assignments", "a", "--grants-fixture", "g",
		"--agent-spiffe-id", "spiffe://example.org/ns/infra/sa/node-agent",
	}, envOf(nil), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.agentID.String() != "spiffe://example.org/ns/infra/sa/node-agent" {
		t.Errorf("agent ID %q", c.agentID)
	}
	// The environment gives both, as the chart does for the namespace.
	env := envOf(map[string]string{"CRACHA_NAMESPACE": "cracha-system", "CRACHA_HEALTH_LISTEN": ":9081"})
	c, err = parseConfig([]string{"--cluster", "c", "--assignments", "a", "--grants-fixture", "g"}, env, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.namespace != "cracha-system" || c.healthListen != ":9081" || !c.agentID.IsZero() {
		t.Errorf("config %+v", c)
	}
}

func TestParseConfigVersion(t *testing.T) {
	if _, err := parseConfig([]string{"--version"}, envOf(nil), io.Discard); !errors.Is(err, errVersion) {
		t.Fatalf("got %v", err)
	}
}

func TestParseConfigRejects(t *testing.T) {
	base := []string{"--cluster", "c", "--assignments", "a", "--grants-fixture", "g", "--namespace", "n"}
	tests := map[string][]string{
		"no cluster":          {"--assignments", "a", "--grants-fixture", "g", "--namespace", "n"},
		"no assignments":      {"--cluster", "c", "--grants-fixture", "g", "--namespace", "n"},
		"no namespace, no id": {"--cluster", "c", "--assignments", "a", "--grants-fixture", "g"},
		"bad agent id":        {"--cluster", "c", "--assignments", "a", "--grants-fixture", "g", "--agent-spiffe-id", "cracha-agent"},
		"agent id is a td":    {"--cluster", "c", "--assignments", "a", "--grants-fixture", "g", "--agent-spiffe-id", "spiffe://example.org"},
		"no listen":           append(append([]string{}, base...), "--listen", ""),
		"no health listen":    append(append([]string{}, base...), "--health-listen", ""),
		"shared listen":       append(append([]string{}, base...), "--listen", ":8443", "--health-listen", ":8443"),
		"bad labels":          append(append([]string{}, base...), "--trust-domain-labels", "example.org"),
		"reserved label":      append(append([]string{}, base...), "--trust-domain-labels", "example.org=h"),
		"bad log level":       append(append([]string{}, base...), "--log-level", "loud"),
		"positional argument": append(append([]string{}, base...), "extra"),
		"unknown flag":        append(append([]string{}, base...), "--nope"),
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := parseConfig(args, envOf(nil), io.Discard)
			if err == nil || errors.Is(err, errVersion) {
				t.Fatalf("accepted %q", strings.Join(args, " "))
			}
		})
	}
}
