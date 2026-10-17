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
	base := []string{"--cluster", "c", "--assignments", "a", "--grants-fixture", "g", "--insecure-plaintext"}
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
