package token

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bpalermo/cracha/csi/internal/jwttest"
)

var (
	now  = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	want = Expectation{Audience: "cracha-broker", Namespace: "team-a", ServiceAccount: "web", Now: now}
)

const subject = "spiffe://example.org/ns/team-a/sa/web"

func good() jwttest.Claims {
	return jwttest.Claims{
		Subject:  subject,
		Audience: []string{"cracha-broker"},
		IssuedAt: now.Add(-10 * time.Second),
		Expiry:   now.Add(4*time.Minute + 50*time.Second),
	}
}

func TestValidateAccepts(t *testing.T) {
	c, err := Validate(jwttest.Mint(good()), want)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if c.ID.String() != subject {
		t.Errorf("ID %s, want %s", c.ID, subject)
	}
	if !c.IssuedAt.Equal(good().IssuedAt) || !c.Expiry.Equal(good().Expiry) {
		t.Errorf("times %v/%v, want %v/%v", c.IssuedAt, c.Expiry, good().IssuedAt, good().Expiry)
	}
	if got := c.Lifetime(time.Time{}); got != 5*time.Minute {
		t.Errorf("Lifetime %v, want 5m", got)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*jwttest.Claims)
		exp    Expectation
		ttl    bool // the rejection must be a TTLError
		want   string
	}{
		{name: "other audience", mutate: func(c *jwttest.Claims) { c.Audience = []string{"other"} }, exp: want, want: "audience"},
		{name: "extra audience", mutate: func(c *jwttest.Claims) { c.Audience = []string{"cracha-broker", "other"} }, exp: want, want: "audience"},
		{name: "no audience", mutate: func(c *jwttest.Claims) { c.Audience = nil }, exp: want, want: "audience"},
		{name: "other namespace", mutate: func(c *jwttest.Claims) { c.Subject = "spiffe://example.org/ns/team-b/sa/web" }, exp: want, want: "subject"},
		{name: "other service account", mutate: func(c *jwttest.Claims) { c.Subject = "spiffe://example.org/ns/team-a/sa/db" }, exp: want, want: "subject"},
		{name: "not the scheme", mutate: func(c *jwttest.Claims) { c.Subject = "spiffe://example.org/team-a/web" }, exp: want, want: "subject"},
		{name: "expired", mutate: func(c *jwttest.Claims) { c.Expiry = now.Add(-time.Second) }, exp: want, want: "expired"},
		{name: "one hour TTL", mutate: func(c *jwttest.Claims) { c.Expiry = c.IssuedAt.Add(time.Hour) }, exp: want, ttl: true},
		{name: "a second over", mutate: func(c *jwttest.Claims) { c.Expiry = c.IssuedAt.Add(5*time.Minute + time.Second) }, exp: want, ttl: true},
		{name: "no iat, long exp", mutate: func(c *jwttest.Claims) { c.IssuedAt = time.Time{}; c.Expiry = now.Add(6 * time.Minute) }, exp: want, ttl: true},
		{name: "lower max TTL", mutate: func(*jwttest.Claims) {}, exp: func() Expectation { e := want; e.MaxTTL = time.Minute; return e }(), ttl: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := good()
			tc.mutate(&c)
			_, err := Validate(jwttest.Mint(c), tc.exp)
			if err == nil {
				t.Fatal("expected a rejection")
			}
			var ttlErr *TTLError
			if isTTL := errors.As(err, &ttlErr); isTTL != tc.ttl {
				t.Fatalf("TTLError=%v, want %v: %v", isTTL, tc.ttl, err)
			}
			if tc.ttl {
				if !strings.Contains(err.Error(), "jwtSVIDTTL") {
					t.Errorf("a TTL rejection must name the fix, got: %v", err)
				}
				return
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestValidateNoIATUsesNow(t *testing.T) {
	c := good()
	c.IssuedAt = time.Time{}
	c.Expiry = now.Add(5 * time.Minute)
	claims, err := Validate(jwttest.Mint(c), want)
	if err != nil {
		t.Fatalf("a token without iat whose remaining life fits must pass: %v", err)
	}
	if !claims.IssuedAt.IsZero() {
		t.Errorf("IssuedAt %v, want zero for a token without iat", claims.IssuedAt)
	}
	if got := claims.Lifetime(now.Add(-time.Minute)); got != 6*time.Minute {
		t.Errorf("Lifetime from the given issue time %v, want 6m", got)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	for _, tok := range []string{
		"",
		"not.a.jwt",
		jwttest.MintRaw(map[string]any{"aud": []string{"cracha-broker"}, "exp": now.Add(time.Minute).Unix()}), // no sub
		jwttest.MintRaw(map[string]any{"sub": subject, "aud": []string{"cracha-broker"}}),                     // no exp
		jwttest.MintRaw(map[string]any{"sub": "not a spiffe id", "aud": []string{"cracha-broker"}, "exp": now.Add(time.Minute).Unix()}),
	} {
		if _, err := Parse(tok); err == nil {
			t.Errorf("Parse(%q) accepted", tok)
		}
	}
}

func TestWriteAtomic(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "mount")
	owner := Owner{UID: os.Getuid(), GID: os.Getgid()}

	if err := Write(dir, "first", owner); err != nil {
		t.Fatalf("Write: %v", err)
	}
	checkToken(t, dir, "first")

	if err := Write(dir, "second", owner); err != nil {
		t.Fatalf("Write over an existing token: %v", err)
	}
	checkToken(t, dir, "second")

	// Leave the owner alone: the process's own IDs result either way.
	if err := Write(dir, "third", Owner{UID: -1, GID: -1}); err != nil {
		t.Fatalf("Write without chown: %v", err)
	}
	checkToken(t, dir, "third")

	if err := Remove(dir); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("after Remove the directory still exists: %v", err)
	}
	if err := Remove(dir); err != nil {
		t.Errorf("Remove of a missing directory must succeed: %v", err)
	}
}

func checkToken(t *testing.T, dir, want string) {
	t.Helper()
	got, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatalf("reading the token: %v", err)
	}
	if string(got) != want {
		t.Errorf("token %q, want %q", got, want)
	}
	fi, err := os.Stat(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != Mode {
		t.Errorf("mode %o, want %o", fi.Mode().Perm(), Mode)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("the directory holds %d entries, want only the token", len(entries))
	}
}
