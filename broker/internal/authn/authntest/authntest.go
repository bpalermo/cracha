// Package authntest mints JWT-SVIDs for tests: an ECDSA P-256 key, the
// static JWT bundle that holds its public key, and tokens signed with it.
// It builds the JWS by hand so that the tests depend on nothing the broker
// does not already depend on.
package authntest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Issuer signs tokens for one trust domain.
type Issuer struct {
	TrustDomain spiffeid.TrustDomain
	KeyID       string
	Key         *ecdsa.PrivateKey
}

// NewIssuer generates a signing key for the trust domain.
func NewIssuer(t testing.TB, trustDomain string) *Issuer {
	t.Helper()
	td, err := spiffeid.TrustDomainFromString(trustDomain)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &Issuer{TrustDomain: td, KeyID: "test-key", Key: key}
}

// Bundle returns the JWT bundle that verifies this issuer's tokens.
func (i *Issuer) Bundle(t testing.TB) *jwtbundle.Bundle {
	t.Helper()
	b := jwtbundle.New(i.TrustDomain)
	if err := b.AddJWTAuthority(i.KeyID, &i.Key.PublicKey); err != nil {
		t.Fatal(err)
	}
	return b
}

// Claims are the claims of a token to mint. Zero fields are left out.
type Claims struct {
	Subject  string
	Audience []string
	Expiry   time.Time
	IssuedAt time.Time
}

// Token mints a token with the given claims and the issuer's key ID in the
// header. Audience is encoded as a JSON string when it has one element, as
// an array otherwise.
func (i *Issuer) Token(t testing.TB, c Claims) string {
	t.Helper()
	return i.TokenWithHeader(t, map[string]any{"alg": "ES256", "typ": "JWT", "kid": i.KeyID}, c)
}

// TokenWithHeader mints a token with an explicit JOSE header.
func (i *Issuer) TokenWithHeader(t testing.TB, header map[string]any, c Claims) string {
	t.Helper()
	claims := map[string]any{}
	if c.Subject != "" {
		claims["sub"] = c.Subject
	}
	switch len(c.Audience) {
	case 0:
	case 1:
		claims["aud"] = c.Audience[0]
	default:
		claims["aud"] = c.Audience
	}
	if !c.Expiry.IsZero() {
		claims["exp"] = c.Expiry.Unix()
	}
	if !c.IssuedAt.IsZero() {
		claims["iat"] = c.IssuedAt.Unix()
	}
	signingInput := b64(mustJSON(t, header)) + "." + b64(mustJSON(t, claims))
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, i.Key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	// JWS ES256 signatures are r and s, each left-padded to 32 bytes.
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + b64(sig)
}

// ValidToken mints a token for the subject, audience cracha-broker, valid
// for five minutes.
func (i *Issuer) ValidToken(t testing.TB, subject string) string {
	t.Helper()
	return i.Token(t, Claims{
		Subject:  subject,
		Audience: []string{"cracha-broker"},
		IssuedAt: time.Now(),
		Expiry:   time.Now().Add(5 * time.Minute),
	})
}

func mustJSON(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
