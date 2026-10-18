// Package jwttest mints unsigned JWT-SVIDs for tests. cracha-agent never
// verifies a signature (the broker does), so a token with a bogus signature
// exercises every path the plugin has.
package jwttest

import (
	"encoding/base64"
	"encoding/json"
	"time"
)

// Claims is what Mint puts in a token. Zero fields are left out.
type Claims struct {
	Subject  string
	Audience []string
	IssuedAt time.Time
	Expiry   time.Time
}

// Mint returns a JWS compact serialization with an ES256 header, the given
// claims and a signature that verifies against nothing.
func Mint(c Claims) string {
	payload := map[string]any{}
	if c.Subject != "" {
		payload["sub"] = c.Subject
	}
	if c.Audience != nil {
		payload["aud"] = c.Audience
	}
	if !c.IssuedAt.IsZero() {
		payload["iat"] = c.IssuedAt.Unix()
	}
	if !c.Expiry.IsZero() {
		payload["exp"] = c.Expiry.Unix()
	}
	return MintRaw(payload)
}

// MintRaw is Mint over arbitrary claims.
func MintRaw(payload map[string]any) string {
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": "test"})
	body, _ := json.Marshal(payload)
	enc := base64.RawURLEncoding
	return enc.EncodeToString(header) + "." + enc.EncodeToString(body) + "." + enc.EncodeToString([]byte("not a signature"))
}
