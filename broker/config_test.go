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
		"--tls-cert", "c.pem", "--tls-key", "k.pem", "--trust-domain-labels", "example.org=prod",
	}, envOf(nil), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.listen != ":8443" || c.cluster != "prod-a" || c.labels.Short("example.org") != "prod" || c.logLevel != "info" {
		t.Errorf("config %+v", c)
	}
}

func TestParseConfigEnvFallback(t *testing.T) {
	env := envOf(map[string]string{
		"CRACHA_CLUSTER":             "prod-b",
		"CRACHA_ASSIGNMENTS":         "a.yaml",
		"CRACHA_GRANTS_FIXTURE":      "g.yaml",
		"CRACHA_INSECURE_PLAINTEXT":  "true",
		"CRACHA_LISTEN":              ":8080",
		"CRACHA_TRUST_DOMAIN_LABELS": "example.org=prod",
		"CRACHA_LOG_LEVEL":           "debug",
	})
	c, err := parseConfig([]string{"--listen", ":9090"}, env, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.cluster != "prod-b" || !c.insecurePlaintext || c.logLevel != "debug" {
		t.Errorf("config %+v", c)
	}
	if c.listen != ":9090" {
		t.Errorf("flag did not win over env: %q", c.listen)
	}
}

func TestEnvDefaults(t *testing.T) {
	env := envDefaults(envOf(map[string]string{
		"CRACHA_LISTEN":             ":8080",
		"CRACHA_INSECURE_PLAINTEXT": "maybe",
		"CRACHA_TLS_CERT":           "",
	}))
	if got := env.str("listen", ":8443"); got != ":8080" {
		t.Errorf("listen %q", got)
	}
	if got := env.str("tls-cert", "default.pem"); got != "" {
		t.Errorf("an empty variable is a value, got %q", got)
	}
	if got := env.str("tls-key", "k.pem"); got != "k.pem" {
		t.Errorf("unset variable gave %q, want the default", got)
	}
	// A bool set to something that is not a bool is false, not the default.
	if env.boolean("insecure-plaintext", true) {
		t.Error("non-bool value read as true")
	}
	if !env.boolean("tls-key", true) {
		t.Error("unset bool did not take the default")
	}
	if !env.boolean("tls-cert", true) {
		t.Error("empty bool did not take the default")
	}
}

func TestParseConfigBundle(t *testing.T) {
	c, err := parseConfig([]string{
		"--cluster", "prod-a", "--assignments", "a.yaml", "--insecure-plaintext",
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
		"CRACHA_INSECURE_PLAINTEXT":   "true",
		"CRACHA_BUNDLE_SOURCE":        "local:/etc/cracha/bundle",
		"CRACHA_BUNDLE_VERIFY_KEY":    "/etc/cracha/bundle-key/public.pem",
		"CRACHA_BUNDLE_POLL_INTERVAL": "5m",
	})
	c, err = parseConfig(nil, env, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.bundle.Dir != "/etc/cracha/bundle" || c.bundle.IsS3() || c.pollInterval != 5*time.Minute || c.bundleVerifyKey != "/etc/cracha/bundle-key/public.pem" {
		t.Errorf("config %+v", c)
	}
}

func TestParseConfigBundleRejects(t *testing.T) {
	base := []string{"--cluster", "c", "--assignments", "a", "--insecure-plaintext"}
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

func TestParseConfigVersion(t *testing.T) {
	if _, err := parseConfig([]string{"--version"}, envOf(nil), io.Discard); !errors.Is(err, errVersion) {
		t.Fatalf("got %v", err)
	}
}

func TestParseConfigRejects(t *testing.T) {
	base := []string{"--cluster", "c", "--assignments", "a", "--grants-fixture", "g", "--tls-cert", "c.pem", "--tls-key", "k.pem"}
	tests := map[string][]string{
		"no cluster":          {"--assignments", "a", "--grants-fixture", "g", "--insecure-plaintext"},
		"no assignments":      {"--cluster", "c", "--grants-fixture", "g", "--insecure-plaintext"},
		"no tls":              {"--cluster", "c", "--assignments", "a", "--grants-fixture", "g"},
		"half tls":            {"--cluster", "c", "--assignments", "a", "--grants-fixture", "g", "--tls-cert", "c.pem"},
		"plaintext with tls":  append(append([]string{}, base...), "--insecure-plaintext"),
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
