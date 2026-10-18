// Package idenc is the single identity-encoding library of Crachá
// (docs/design.md, section 4.3). It parses a workload's SPIFFE ID against the
// scheme spiffe://<trust-domain>/ns/<namespace>/sa/<serviceaccount> and
// derives from it the two encoded forms every other component uses: the STS
// SourceIdentity/RoleSessionName and the authorization-store subject ID.
// Nothing outside this package hand-formats either (design invariant: "all
// identity encodings come from the single shared encoding library").
//
// # Trust-domain short labels
//
// Both encodings start with a short label for the trust domain. Labels are
// configured as a map from trust domain name to label (see [NewLabels]); a
// label matches ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$, is at most 32 characters
// and is never "h", which is reserved for the hashed STS form below.
//
// A trust domain without a configured label gets the deterministic fallback
// "td." followed by its name, for example "td.example.org". The fallback
// always contains a dot, and configured labels never do, so a fallback can
// never collide with a configured label; two different trust domains give
// two different fallbacks because the name is carried verbatim.
//
// # STS encoding
//
// [STS] returns "w.<label>.<namespace>.<serviceaccount>". Every character a
// SPIFFE ID may carry is in the STS charset [\w+=,.@-], so no escaping is
// needed. When the result would exceed 64 characters (or, defensively, carry
// a character outside the charset) it becomes "w.h.<digest>", where digest
// is the SHA-256 of the full SPIFFE ID string in lower-case, unpadded base32
// (RFC 4648): all 52 characters, for 56 in total, so there is no truncation
// and no prefix to choose. Both forms are deterministic and stay within the
// 2–64 limit.
//
// # Authorization subject encoding
//
// [Authz] returns "<label>/<namespace>/<serviceaccount>" restricted to the
// charset [a-zA-Z0-9/_|\-=+]. Within each component every byte outside
// [A-Za-z0-9-] is replaced by "_" followed by its two lower-case hex digits
// ("." becomes "_2e", "_" becomes "_5f", ":" becomes "_3a"). "_" is only
// ever produced by the escape itself, so the encoding is injective and the
// original can be recovered by reversing it. The result must be at most 1024
// characters; a longer one is an error rather than a truncation.
//
// # Resource encoding
//
// [Resource] returns the authorization-store object ID of a resource that a
// workload is related to by name (design 6.4, Level 3): an S3 bucket, a
// DynamoDB table. Resource names may carry characters the store's object ID
// charset lacks (a bucket name may hold "."), so the name is escaped with
// the subject encoding's component rule: every byte outside [A-Za-z0-9-]
// becomes "_" and its two lower-case hex digits ("my.bucket" is
// "my_2ebucket"). [ParseResource] reverses it. The kind of the resource is
// the object type, not part of the ID.
package idenc

import (
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Identity is a workload identity parsed from the SPIFFE ID scheme
// spiffe://<trust-domain>/ns/<namespace>/sa/<serviceaccount>.
type Identity struct {
	TrustDomain    string
	Namespace      string
	ServiceAccount string
}

// ErrScheme is wrapped by every parse error that is about the path shape.
var ErrScheme = errors.New("SPIFFE ID does not match spiffe://<trust-domain>/ns/<namespace>/sa/<serviceaccount>")

// Parse parses and validates a SPIFFE ID string against the scheme.
func Parse(s string) (Identity, error) {
	id, err := spiffeid.FromString(s)
	if err != nil {
		return Identity{}, fmt.Errorf("idenc: %w", err)
	}
	return FromID(id)
}

// FromID validates an already parsed SPIFFE ID against the scheme.
func FromID(id spiffeid.ID) (Identity, error) {
	segments := strings.Split(strings.TrimPrefix(id.Path(), "/"), "/")
	if id.Path() == "" || len(segments) != 4 || segments[0] != "ns" || segments[2] != "sa" || segments[1] == "" || segments[3] == "" {
		return Identity{}, fmt.Errorf("idenc: %w: %q", ErrScheme, id.String())
	}
	return Identity{
		TrustDomain:    id.TrustDomain().Name(),
		Namespace:      segments[1],
		ServiceAccount: segments[3],
	}, nil
}

// String returns the SPIFFE ID, spiffe://<trust-domain>/ns/<ns>/sa/<sa>.
func (i Identity) String() string {
	return "spiffe://" + i.TrustDomain + "/ns/" + i.Namespace + "/sa/" + i.ServiceAccount
}

// Labels maps trust domains to their short labels. The zero value maps
// nothing: every trust domain gets the fallback label.
type Labels struct {
	byDomain map[string]string
}

const (
	// hashedLabel is the label of the hashed STS form, w.h.<digest>.
	hashedLabel = "h"
	// fallbackPrefix starts the label of an unmapped trust domain.
	fallbackPrefix = "td."
	maxLabelLen    = 32
)

var labelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// NewLabels validates a trust domain to short label map. Keys must be valid
// trust domain names and values valid labels (see the package doc); two
// trust domains may not share a label.
func NewLabels(m map[string]string) (Labels, error) {
	byDomain := make(map[string]string, len(m))
	byLabel := make(map[string]string, len(m))
	for domain, label := range m {
		td, err := spiffeid.TrustDomainFromString(domain)
		if err != nil {
			return Labels{}, fmt.Errorf("idenc: label map: %w", err)
		}
		if !labelRE.MatchString(label) || len(label) > maxLabelLen {
			return Labels{}, fmt.Errorf("idenc: label map: label %q for %q must match %s and be at most %d characters", label, domain, labelRE, maxLabelLen)
		}
		if label == hashedLabel {
			return Labels{}, fmt.Errorf("idenc: label map: label %q is reserved", hashedLabel)
		}
		if other, dup := byLabel[label]; dup {
			return Labels{}, fmt.Errorf("idenc: label map: trust domains %q and %q share label %q", other, domain, label)
		}
		byLabel[label] = td.Name()
		byDomain[td.Name()] = label
	}
	return Labels{byDomain: byDomain}, nil
}

// ParseLabels parses the flag form "example.org=prod,other.org=dev". An empty
// string gives the zero Labels.
func ParseLabels(s string) (Labels, error) {
	m := map[string]string{}
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		domain, label, ok := strings.Cut(pair, "=")
		if !ok {
			return Labels{}, fmt.Errorf("idenc: label map: %q is not <trust-domain>=<label>", pair)
		}
		domain, label = strings.TrimSpace(domain), strings.TrimSpace(label)
		if _, dup := m[domain]; dup {
			return Labels{}, fmt.Errorf("idenc: label map: trust domain %q given twice", domain)
		}
		m[domain] = label
	}
	return NewLabels(m)
}

// Short returns the short label of a trust domain: the configured one, or
// the fallback "td.<name>".
func (l Labels) Short(trustDomain string) string {
	if label, ok := l.byDomain[trustDomain]; ok {
		return label
	}
	return fallbackPrefix + trustDomain
}

// Map returns a copy of the configured mapping, in no particular order.
func (l Labels) Map() map[string]string {
	m := make(map[string]string, len(l.byDomain))
	for k, v := range l.byDomain {
		m[k] = v
	}
	return m
}

// String renders the configured mapping in the flag form, sorted by trust
// domain, for logs.
func (l Labels) String() string {
	domains := make([]string, 0, len(l.byDomain))
	for d := range l.byDomain {
		domains = append(domains, d)
	}
	sort.Strings(domains)
	parts := make([]string, 0, len(domains))
	for _, d := range domains {
		parts = append(parts, d+"="+l.byDomain[d])
	}
	return strings.Join(parts, ",")
}

// STSMaxLen is the length limit of an STS SourceIdentity or RoleSessionName.
const STSMaxLen = 64

var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// STS returns the STS SourceIdentity / RoleSessionName encoding of an
// identity: w.<label>.<namespace>.<serviceaccount>, or w.h.<digest> when
// that would not fit (see the package doc).
func STS(id Identity, labels Labels) string {
	plain := "w." + labels.Short(id.TrustDomain) + "." + id.Namespace + "." + id.ServiceAccount
	if len(plain) <= STSMaxLen && isSTSCharset(plain) {
		return plain
	}
	sum := sha256.Sum256([]byte(id.String()))
	return "w." + hashedLabel + "." + strings.ToLower(base32NoPad.EncodeToString(sum[:]))
}

// IsHashedSTS reports whether an STS encoding is the hashed form, in which
// case only the issuance log maps it back to a SPIFFE ID.
func IsHashedSTS(encoded string) bool {
	return strings.HasPrefix(encoded, "w."+hashedLabel+".")
}

func isSTSCharset(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '_', c == '+', c == '=', c == ',', c == '.', c == '@', c == '-':
		default:
			return false
		}
	}
	return true
}

// AuthzMaxLen is the length limit of an authorization subject ID.
const AuthzMaxLen = 1024

// Authz returns the authorization-store subject encoding of an identity,
// <label>/<namespace>/<serviceaccount> with each component escaped (see the
// package doc). It fails when the result would exceed [AuthzMaxLen].
func Authz(id Identity, labels Labels) (string, error) {
	s := escape(labels.Short(id.TrustDomain)) + "/" + escape(id.Namespace) + "/" + escape(id.ServiceAccount)
	if len(s) > AuthzMaxLen {
		return "", fmt.Errorf("idenc: authz subject for %s is %d characters, over %d", id, len(s), AuthzMaxLen)
	}
	return s, nil
}

// UnescapeAuthzComponent reverses the component escaping of [Authz]. It is
// the inverse of the escape rule and exists so that tooling can recover the
// original component; the broker itself never decodes a subject.
func UnescapeAuthzComponent(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '_' {
			if !isPlainAuthzByte(c) {
				return "", fmt.Errorf("idenc: byte %q at %d is not a plain authz character", c, i)
			}
			b.WriteByte(c)
			continue
		}
		if i+2 >= len(s) {
			return "", fmt.Errorf("idenc: truncated escape at %d", i)
		}
		hi, lo := unhex(s[i+1]), unhex(s[i+2])
		if hi < 0 || lo < 0 {
			return "", fmt.Errorf("idenc: bad escape %q at %d", s[i:i+3], i)
		}
		b.WriteByte(byte(hi<<4 | lo))
		i += 2
	}
	return b.String(), nil
}

const hexDigits = "0123456789abcdef"

func escape(component string) string {
	var b strings.Builder
	b.Grow(len(component))
	for i := 0; i < len(component); i++ {
		c := component[i]
		if isPlainAuthzByte(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('_')
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&0x0f])
	}
	return b.String()
}

func isPlainAuthzByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-'
}

func unhex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	default:
		return -1
	}
}

// Resource returns the authorization-store object ID of a resource name
// (see the package doc). It fails on an empty name and when the result
// would exceed [AuthzMaxLen].
func Resource(name string) (string, error) {
	if name == "" {
		return "", errors.New("idenc: empty resource name")
	}
	s := escape(name)
	if len(s) > AuthzMaxLen {
		return "", fmt.Errorf("idenc: resource ID for %q is %d characters, over %d", name, len(s), AuthzMaxLen)
	}
	return s, nil
}

// ParseResource returns the resource name an object ID made by [Resource]
// stands for. An ID that [Resource] would not have made (an escape of a
// byte that needs none, an upper-case hex digit) is an error, so one name
// has exactly one ID.
func ParseResource(id string) (string, error) {
	if id == "" {
		return "", errors.New("idenc: empty resource ID")
	}
	name, err := UnescapeAuthzComponent(id)
	if err != nil {
		return "", err
	}
	if escape(name) != id {
		return "", fmt.Errorf("idenc: resource ID %q is not in canonical form", id)
	}
	return name, nil
}
