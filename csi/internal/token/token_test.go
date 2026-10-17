package token

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
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
	// A TTL rejection must name the fix (jwtSVIDTTL), which the ttl cases
	// assert through want.
	const namesFix = "jwtSVIDTTL"
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
		{name: "one hour TTL", mutate: func(c *jwttest.Claims) { c.Expiry = c.IssuedAt.Add(time.Hour) }, exp: want, ttl: true, want: namesFix},
		{name: "a second over", mutate: func(c *jwttest.Claims) { c.Expiry = c.IssuedAt.Add(5*time.Minute + time.Second) }, exp: want, ttl: true, want: namesFix},
		{name: "no iat, long exp", mutate: func(c *jwttest.Claims) { c.IssuedAt = time.Time{}; c.Expiry = now.Add(6 * time.Minute) }, exp: want, ttl: true, want: namesFix},
		{name: "lower max TTL", mutate: func(*jwttest.Claims) {}, exp: func() Expectation { e := want; e.MaxTTL = time.Minute; return e }(), ttl: true, want: namesFix},
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

// segment is a JWS segment: v as JSON, base64url without padding.
func segment(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// mint is jwttest.MintRaw with the header given, for the header checks.
func mint(header, payload map[string]any) string {
	return segment(header) + "." + segment(payload) + "." + base64.RawURLEncoding.EncodeToString([]byte("not a signature"))
}

func TestParseRejects(t *testing.T) {
	exp := now.Add(time.Minute).Unix()
	claims := map[string]any{"sub": subject, "aud": []string{"cracha-broker"}, "exp": exp}
	signed := map[string]any{"alg": "ES256", "typ": "JWT"}
	cases := []struct {
		name  string
		token string
		want  string // a substring of the rejection
	}{
		{name: "four segments", token: mint(signed, claims) + ".extra", want: "JWS compact serialization"},
		{name: "header not base64url", token: "!!!." + segment(claims) + ".sig", want: "the token's header: not base64url"},
		{name: "header not JSON", token: segment("nope") + "." + segment(claims) + ".sig", want: "the token's header: not JSON"},
		{name: "alg none", token: mint(map[string]any{"alg": "none", "typ": "JWT"}, claims), want: `algorithm "none" is not a signature`},
		{name: "alg None", token: mint(map[string]any{"alg": "None", "typ": "JWT"}, claims), want: `algorithm "None" is not a signature`},
		{name: "no alg", token: mint(map[string]any{"typ": "JWT"}, claims), want: `algorithm "" is not a signature`},
		{name: "typ neither JWT nor JOSE", token: mint(map[string]any{"alg": "ES256", "typ": "at+jwt"}, claims), want: `type "at+jwt" is neither JWT nor JOSE`},
		{name: "claims not base64url", token: segment(signed) + ".!!!.sig", want: "the token's claims: not base64url"},
		{name: "claims not JSON", token: segment(signed) + "." + segment("nope") + ".sig", want: "the token's claims: not JSON"},
		{name: "aud neither string nor array", token: jwttest.MintRaw(map[string]any{"sub": subject, "aud": 42, "exp": exp}), want: "aud claim is neither a string nor an array of strings"},
		{name: "aud array of numbers", token: jwttest.MintRaw(map[string]any{"sub": subject, "aud": []int{1}, "exp": exp}), want: "aud claim is neither a string nor an array of strings"},
		{name: "exp out of range", token: jwttest.MintRaw(map[string]any{"sub": subject, "exp": json.Number("1e999")}), want: "the token's exp claim"},
		{name: "iat out of range", token: jwttest.MintRaw(map[string]any{"sub": subject, "exp": exp, "iat": json.Number("1e999")}), want: "the token's iat claim"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.token)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestParseHeaderTypes(t *testing.T) {
	claims := map[string]any{"sub": subject, "aud": []string{"cracha-broker"}, "exp": now.Add(time.Minute).Unix()}
	for _, header := range []map[string]any{
		{"alg": "ES256", "typ": "JWT"},
		{"alg": "ES256", "typ": "JOSE"},
		{"alg": "RS256"},
	} {
		if _, err := Parse(mint(header, claims)); err != nil {
			t.Errorf("Parse with the header %v: %v", header, err)
		}
	}
}

func TestParseAudience(t *testing.T) {
	exp := now.Add(time.Minute).Unix()
	cases := []struct {
		name    string
		payload map[string]any
		want    []string
	}{
		{name: "a string", payload: map[string]any{"sub": subject, "aud": "cracha-broker", "exp": exp}, want: []string{"cracha-broker"}},
		{name: "an array", payload: map[string]any{"sub": subject, "aud": []string{"cracha-broker", "other"}, "exp": exp}, want: []string{"cracha-broker", "other"}},
		{name: "an empty array", payload: map[string]any{"sub": subject, "aud": []string{}, "exp": exp}, want: nil},
		{name: "absent", payload: map[string]any{"sub": subject, "exp": exp}, want: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Parse(jwttest.MintRaw(tc.payload))
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(c.Audience, tc.want) {
				t.Errorf("Audience %q, want %q", c.Audience, tc.want)
			}
		})
	}
}

func TestWriteAtomic(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "mount")
	owner := Owner{UID: os.Getuid(), GID: os.Getgid()}

	if err := Write(dir, "first", owner); err != nil {
		t.Fatalf("Write: %v", err)
	}
	checkToken(t, dir, "first", owner)

	if err := Write(dir, "second", owner); err != nil {
		t.Fatalf("Write over an existing token: %v", err)
	}
	checkToken(t, dir, "second", owner)

	// Leave the owner alone: the process's own IDs result either way.
	if err := Write(dir, "third", Owner{UID: -1, GID: -1}); err != nil {
		t.Fatalf("Write without chown: %v", err)
	}
	checkToken(t, dir, "third", owner)

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

// The group of the file and of its directory follow the owner given: a
// pod's fsGroup on the node. A later write with another group moves both.
func TestWriteGroup(t *testing.T) {
	gid := otherGroup(t)
	dir := filepath.Join(t.TempDir(), "mount")

	// The group alone: the uid stays the process's.
	if err := Write(dir, "first", Owner{UID: -1, GID: gid}); err != nil {
		t.Fatalf("Write with group %d: %v", gid, err)
	}
	checkToken(t, dir, "first", Owner{UID: os.Getuid(), GID: gid})

	// Back to the primary group: the directory follows.
	own := Owner{UID: os.Getuid(), GID: os.Getgid()}
	if err := Write(dir, "second", own); err != nil {
		t.Fatalf("Write back to the primary group: %v", err)
	}
	checkToken(t, dir, "second", own)
}

// otherGroup returns a group the process is a member of other than its
// primary one, which it may give a file without CAP_CHOWN. It skips the test
// when there is none it can use: a sandbox with a user namespace maps the
// supplementary groups to the overflow group, which cannot own a file.
func otherGroup(t *testing.T) int {
	t.Helper()
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatalf("Getgroups: %v", err)
	}
	probe := filepath.Join(t.TempDir(), "probe")
	if err := os.WriteFile(probe, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var refused []string
	for _, g := range groups {
		if g == os.Getgid() {
			continue
		}
		if err := os.Chown(probe, -1, g); err != nil {
			refused = append(refused, err.Error())
			continue
		}
		return g
	}
	t.Skipf("skipping the group change: no group of this process but its primary one (%d) may own a file here: %v", os.Getgid(), refused)
	return -1
}

func checkToken(t *testing.T, dir, want string, owner Owner) {
	t.Helper()
	got, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatalf("reading the token: %v", err)
	}
	if string(got) != want {
		t.Errorf("token %q, want %q", got, want)
	}
	checkOwner(t, filepath.Join(dir, FileName), Mode, owner)
	checkOwner(t, dir, DirMode, owner)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("the directory holds %d entries, want only the token", len(entries))
	}
}

// checkOwner asserts the mode and the owner of path.
func checkOwner(t *testing.T, path string, mode os.FileMode, owner Owner) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != mode {
		t.Errorf("%s: mode %o, want %o", path, fi.Mode().Perm(), mode)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("%s: no stat", path)
	}
	if int(st.Uid) != owner.UID || int(st.Gid) != owner.GID {
		t.Errorf("%s: owner %d:%d, want %d:%d", path, st.Uid, st.Gid, owner.UID, owner.GID)
	}
}
