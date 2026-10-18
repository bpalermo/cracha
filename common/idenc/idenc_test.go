package idenc

import (
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

func mustLabels(t *testing.T, m map[string]string) Labels {
	t.Helper()
	l, err := NewLabels(m)
	if err != nil {
		t.Fatalf("NewLabels(%v): %v", m, err)
	}
	return l
}

func TestParse(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want Identity
	}{
		{"plain", "spiffe://example.org/ns/payments/sa/ledger", Identity{"example.org", "payments", "ledger"}},
		{"dotted sa", "spiffe://prod.example.org/ns/kube-system/sa/my.app_v2", Identity{"prod.example.org", "kube-system", "my.app_v2"}},
		{"upper-case path", "spiffe://example.org/ns/Ns/sa/SA", Identity{"example.org", "Ns", "SA"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.in)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("Parse(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
			if got.String() != tt.in {
				t.Fatalf("round trip: %q != %q", got.String(), tt.in)
			}
			id, err := spiffeid.FromString(tt.in)
			if err != nil {
				t.Fatal(err)
			}
			if got2, err := FromID(id); err != nil || got2 != got {
				t.Fatalf("FromID = %+v, %v", got2, err)
			}
		})
	}
}

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		scheme bool // the error is ErrScheme (shape), not a SPIFFE syntax error
	}{
		{"empty", "", false},
		{"not spiffe", "https://example.org/ns/a/sa/b", false},
		{"no path", "spiffe://example.org", true},
		{"root", "spiffe://example.org/", false},
		{"missing sa", "spiffe://example.org/ns/a", true},
		{"missing sa name", "spiffe://example.org/ns/a/sa", true},
		{"extra segment", "spiffe://example.org/ns/a/sa/b/c", true},
		{"wrong markers", "spiffe://example.org/namespace/a/serviceaccount/b", true},
		{"swapped", "spiffe://example.org/sa/a/ns/b", true},
		{"empty ns", "spiffe://example.org/ns//sa/b", false},
		{"dot segment", "spiffe://example.org/ns/./sa/b", false},
		{"bad char", "spiffe://example.org/ns/a%20b/sa/b", false},
		{"colon", "spiffe://example.org/ns/a:b/sa/b", false},
		{"upper trust domain", "spiffe://Example.org/ns/a/sa/b", false},
		{"query", "spiffe://example.org/ns/a/sa/b?x=1", false},
		{"trailing slash", "spiffe://example.org/ns/a/sa/b/", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.in)
			if err == nil {
				t.Fatalf("Parse(%q) succeeded", tt.in)
			}
			if errors.Is(err, ErrScheme) != tt.scheme {
				t.Fatalf("Parse(%q) error %v: ErrScheme=%v, want %v", tt.in, err, errors.Is(err, ErrScheme), tt.scheme)
			}
		})
	}
}

func TestLabels(t *testing.T) {
	l := mustLabels(t, map[string]string{"example.org": "prod", "dev.example.org": "dev-1"})
	tests := map[string]string{
		"example.org":     "prod",
		"dev.example.org": "dev-1",
		"other.org":       "td.other.org",
		"prod":            "td.prod", // an unmapped domain named like a label does not collide
	}
	for td, want := range tests {
		if got := l.Short(td); got != want {
			t.Errorf("Short(%q) = %q, want %q", td, got, want)
		}
	}
	if got := (Labels{}).Short("example.org"); got != "td.example.org" {
		t.Errorf("zero Labels: %q", got)
	}
	if got := l.String(); got != "dev.example.org=dev-1,example.org=prod" {
		t.Errorf("String() = %q", got)
	}

	bad := []map[string]string{
		{"example.org": "h"},
		{"example.org": "Prod"},
		{"example.org": "td.x"},
		{"example.org": "-x"},
		{"example.org": "x-"},
		{"example.org": ""},
		{"example.org": strings.Repeat("a", 33)},
		{"Example.org": "prod"},
		{"example.org": "prod", "other.org": "prod"},
	}
	for _, m := range bad {
		if _, err := NewLabels(m); err == nil {
			t.Errorf("NewLabels(%v) succeeded", m)
		}
	}
}

func TestParseLabels(t *testing.T) {
	l, err := ParseLabels(" example.org=prod, other.org = dev ,")
	if err != nil {
		t.Fatal(err)
	}
	if l.Short("example.org") != "prod" || l.Short("other.org") != "dev" {
		t.Fatalf("parsed %v", l.Map())
	}
	if _, err := ParseLabels(""); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"example.org", "example.org=prod,example.org=dev", "=prod"} {
		if _, err := ParseLabels(s); err == nil {
			t.Errorf("ParseLabels(%q) succeeded", s)
		}
	}
}

var stsRE = regexp.MustCompile(`^[\w+=,.@-]{2,64}$`)

func TestSTS(t *testing.T) {
	labels := mustLabels(t, map[string]string{"example.org": "prod"})
	longSA := strings.Repeat("a", 60)
	longID := Identity{"example.org", "payments", longSA}
	sum := sha256.Sum256([]byte(longID.String()))
	wantHash := "w.h." + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:]))

	tests := []struct {
		name string
		id   Identity
		want string
	}{
		{"mapped", Identity{"example.org", "payments", "ledger"}, "w.prod.payments.ledger"},
		{"fallback", Identity{"other.org", "payments", "ledger"}, "w.td.other.org.payments.ledger"},
		{"dotted sa", Identity{"example.org", "kube-system", "my.app_v2"}, "w.prod.kube-system.my.app_v2"},
		{"exactly 64", Identity{"example.org", "ns", strings.Repeat("s", 64-len("w.prod.ns."))}, "w.prod.ns." + strings.Repeat("s", 64-len("w.prod.ns."))},
		{"65 hashes", Identity{"example.org", "ns", strings.Repeat("s", 65-len("w.prod.ns."))}, ""},
		{"long", longID, wantHash},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := STS(tt.id, labels)
			if !stsRE.MatchString(got) {
				t.Fatalf("STS = %q does not match %s", got, stsRE)
			}
			if tt.want != "" && got != tt.want {
				t.Fatalf("STS = %q, want %q", got, tt.want)
			}
			if tt.want == "" && !IsHashedSTS(got) {
				t.Fatalf("STS = %q, want hashed", got)
			}
			if again := STS(tt.id, labels); again != got {
				t.Fatalf("not deterministic: %q then %q", got, again)
			}
		})
	}

	if len(wantHash) != 56 {
		t.Fatalf("hashed form is %d characters, want 56", len(wantHash))
	}
	// The hashed form does not depend on the label map, and differs between identities.
	if STS(longID, Labels{}) != wantHash {
		t.Fatal("hashed form depends on labels")
	}
	other := Identity{"other.org", "payments", longSA}
	if STS(other, labels) == wantHash {
		t.Fatal("different identities hash alike")
	}
	if IsHashedSTS("w.prod.payments.ledger") {
		t.Fatal("plain form reported as hashed")
	}
}

var authzRE = regexp.MustCompile(`^[a-zA-Z0-9/_|\-=+]+$`)

func TestAuthz(t *testing.T) {
	labels := mustLabels(t, map[string]string{"example.org": "prod"})
	tests := []struct {
		name string
		id   Identity
		want string
	}{
		{"mapped", Identity{"example.org", "payments", "ledger"}, "prod/payments/ledger"},
		{"fallback escapes dots", Identity{"other.org", "payments", "ledger"}, "td_2eother_2eorg/payments/ledger"},
		{"dot and underscore in sa", Identity{"example.org", "kube-system", "my.app_v2"}, "prod/kube-system/my_2eapp_5fv2"},
		{"upper case kept", Identity{"example.org", "Ns", "SA"}, "prod/Ns/SA"},
		{"unexpected bytes escaped", Identity{"example.org", "a:b", "c/d|e"}, "prod/a_3ab/c_2fd_7ce"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Authz(tt.id, labels)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("Authz = %q, want %q", got, tt.want)
			}
			if !authzRE.MatchString(got) || len(got) > AuthzMaxLen {
				t.Fatalf("Authz = %q does not match %s within %d characters", got, authzRE, AuthzMaxLen)
			}
			parts := strings.Split(got, "/")
			if len(parts) != 3 {
				t.Fatalf("Authz = %q has %d components", got, len(parts))
			}
			for i, orig := range []string{labels.Short(tt.id.TrustDomain), tt.id.Namespace, tt.id.ServiceAccount} {
				back, err := UnescapeAuthzComponent(parts[i])
				if err != nil {
					t.Fatalf("unescape %q: %v", parts[i], err)
				}
				if back != orig {
					t.Fatalf("unescape %q = %q, want %q", parts[i], back, orig)
				}
			}
		})
	}

	// Injective: distinct inputs that could alias under a naive escape.
	a, _ := Authz(Identity{"example.org", "a.b", "c"}, labels)
	b, _ := Authz(Identity{"example.org", "a_2eb", "c"}, labels)
	if a == b {
		t.Fatalf("escape is not injective: %q", a)
	}

	// Too long is an error, never a truncation.
	long := Identity{"example.org", strings.Repeat("n", 600), strings.Repeat("s", 600)}
	if _, err := Authz(long, labels); err == nil {
		t.Fatal("over-long subject accepted")
	}
	for _, bad := range []string{"a_2", "a_zz", "a.b", "a_"} {
		if _, err := UnescapeAuthzComponent(bad); err == nil {
			t.Errorf("UnescapeAuthzComponent(%q) succeeded", bad)
		}
	}
}

// spicedbObjectID is SpiceDB's object ID charset, the strictest store
// considered (design 4.3); the length, at most 1024, is Resource's own
// check.
var spicedbObjectID = regexp.MustCompile(`^[a-zA-Z0-9/_|\-=+]+$`)

func TestResourceRoundTrip(t *testing.T) {
	// Every shape of a valid S3 bucket name (3 to 63 characters of
	// lower-case letters, digits, dots and hyphens, starting and ending
	// with a letter or digit), and DynamoDB table names, which add
	// upper-case letters and underscores.
	names := map[string]string{
		"abc":                          "abc",
		"a-b":                          "a-b",
		"a.b":                          "a_2eb",
		"1.2.3":                        "1_2e2_2e3",
		"my.bucket.example-com":        "my_2ebucket_2eexample-com",
		"cracha-e2e-data":              "cracha-e2e-data",
		"a--b":                         "a--b",
		"x1-y2.z3":                     "x1-y2_2ez3",
		"Payments_Ledger.v2":           "Payments_5fLedger_2ev2",
		strings.Repeat("a", 63):        strings.Repeat("a", 63),
		strings.Repeat("a.", 31) + "a": strings.Repeat("a_2e", 31) + "a",
	}
	for name, want := range names {
		id, err := Resource(name)
		if err != nil {
			t.Fatalf("Resource(%q): %v", name, err)
		}
		if id != want {
			t.Errorf("Resource(%q) = %q, want %q", name, id, want)
		}
		if !spicedbObjectID.MatchString(id) {
			t.Errorf("Resource(%q) = %q is outside the object ID charset", name, id)
		}
		back, err := ParseResource(id)
		if err != nil || back != name {
			t.Errorf("ParseResource(%q) = %q, %v, want %q", id, back, err, name)
		}
	}
}

func TestResourceEveryBucketByte(t *testing.T) {
	// Every byte a bucket name may hold, in every position.
	alphabet := "abcdefghijklmnopqrstuvwxyz0123456789.-"
	for i := 0; i < len(alphabet); i++ {
		name := "a" + string(alphabet[i]) + "z"
		id, err := Resource(name)
		if err != nil {
			t.Fatal(err)
		}
		if !spicedbObjectID.MatchString(id) {
			t.Errorf("Resource(%q) = %q is outside the object ID charset", name, id)
		}
		if back, err := ParseResource(id); err != nil || back != name {
			t.Errorf("ParseResource(%q) = %q, %v, want %q", id, back, err, name)
		}
	}
}

func TestResourceRejects(t *testing.T) {
	if _, err := Resource(""); err == nil {
		t.Error("Resource(\"\") succeeded")
	}
	if _, err := Resource(strings.Repeat(".", 400)); err == nil {
		t.Error("Resource of a name whose ID is over 1024 characters succeeded")
	}
	for _, id := range []string{"", "a_2", "a_zz", "a.b", "a_2db", "a_2Eb"} {
		if name, err := ParseResource(id); err == nil {
			t.Errorf("ParseResource(%q) = %q, want an error", id, name)
		}
	}
}
