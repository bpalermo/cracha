package authn

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bpalermo/cracha/broker/internal/authn/authntest"
	"github.com/bpalermo/cracha/common/idenc"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
)

const subject = "spiffe://example.org/ns/payments/sa/ledger"

func TestVerify(t *testing.T) {
	issuer := authntest.NewIssuer(t, "example.org")
	v := New(issuer.Bundle(t))

	id, err := v.Verify(context.Background(), issuer.ValidToken(t, subject))
	if err != nil {
		t.Fatal(err)
	}
	if want := (idenc.Identity{TrustDomain: "example.org", Namespace: "payments", ServiceAccount: "ledger"}); id != want {
		t.Fatalf("identity %+v, want %+v", id, want)
	}
}

func TestVerifyRejects(t *testing.T) {
	issuer := authntest.NewIssuer(t, "example.org")
	other := authntest.NewIssuer(t, "other.org")
	federated := jwtbundle.NewSet(issuer.Bundle(t), other.Bundle(t))
	now := time.Now()
	valid := authntest.Claims{Subject: subject, Audience: []string{Audience}, IssuedAt: now, Expiry: now.Add(5 * time.Minute)}
	with := func(f func(*authntest.Claims)) authntest.Claims {
		c := valid
		f(&c)
		return c
	}

	tests := []struct {
		name    string
		bundles jwtbundle.Source
		token   func(t *testing.T) string
	}{
		{"empty", issuer.Bundle(t), func(*testing.T) string { return "" }},
		{"garbage", issuer.Bundle(t), func(*testing.T) string { return "not.a.jwt" }},
		{"expired", issuer.Bundle(t), func(t *testing.T) string {
			return issuer.Token(t, with(func(c *authntest.Claims) { c.Expiry = now.Add(-time.Minute) }))
		}},
		{"no exp", issuer.Bundle(t), func(t *testing.T) string {
			return issuer.Token(t, with(func(c *authntest.Claims) { c.Expiry = time.Time{} }))
		}},
		{"missing audience", issuer.Bundle(t), func(t *testing.T) string {
			return issuer.Token(t, with(func(c *authntest.Claims) { c.Audience = nil }))
		}},
		{"wrong audience", issuer.Bundle(t), func(t *testing.T) string {
			return issuer.Token(t, with(func(c *authntest.Claims) { c.Audience = []string{"sts.amazonaws.com"} }))
		}},
		{"extra audience", issuer.Bundle(t), func(t *testing.T) string {
			return issuer.Token(t, with(func(c *authntest.Claims) { c.Audience = []string{Audience, "other"} }))
		}},
		{"no subject", issuer.Bundle(t), func(t *testing.T) string {
			return issuer.Token(t, with(func(c *authntest.Claims) { c.Subject = "" }))
		}},
		{"subject off scheme", issuer.Bundle(t), func(t *testing.T) string {
			return issuer.Token(t, with(func(c *authntest.Claims) { c.Subject = "spiffe://example.org/workload/ledger" }))
		}},
		{"subject not spiffe", issuer.Bundle(t), func(t *testing.T) string {
			return issuer.Token(t, with(func(c *authntest.Claims) { c.Subject = "ledger" }))
		}},
		{"trust domain without bundle", issuer.Bundle(t), func(t *testing.T) string {
			return other.Token(t, with(func(c *authntest.Claims) { c.Subject = "spiffe://other.org/ns/a/sa/b" }))
		}},
		{"signed by another domain's key", federated, func(t *testing.T) string {
			// The subject claims example.org, the signature is other.org's.
			return other.Token(t, valid)
		}},
		{"unknown kid", issuer.Bundle(t), func(t *testing.T) string {
			return issuer.TokenWithHeader(t, map[string]any{"alg": "ES256", "typ": "JWT", "kid": "nope"}, valid)
		}},
		{"missing kid", issuer.Bundle(t), func(t *testing.T) string {
			return issuer.TokenWithHeader(t, map[string]any{"alg": "ES256", "typ": "JWT"}, valid)
		}},
		{"alg none", issuer.Bundle(t), func(t *testing.T) string {
			return issuer.TokenWithHeader(t, map[string]any{"alg": "none", "typ": "JWT", "kid": issuer.KeyID}, valid)
		}},
		{"tampered", issuer.Bundle(t), func(t *testing.T) string {
			tok := issuer.Token(t, valid)
			parts := strings.Split(tok, ".")
			parts[1] = parts[1][:len(parts[1])-2] + "AA"
			return strings.Join(parts, ".")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.bundles).Verify(context.Background(), tt.token(t))
			if err == nil {
				t.Fatal("verified")
			}
			if !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("error %v does not wrap ErrInvalidToken", err)
			}
		})
	}
}

func TestVerifyFederated(t *testing.T) {
	issuer := authntest.NewIssuer(t, "example.org")
	other := authntest.NewIssuer(t, "other.org")
	v := New(jwtbundle.NewSet(issuer.Bundle(t), other.Bundle(t)))
	id, err := v.Verify(context.Background(), other.ValidToken(t, "spiffe://other.org/ns/a/sa/b"))
	if err != nil {
		t.Fatal(err)
	}
	if id.TrustDomain != "other.org" {
		t.Fatalf("trust domain %q", id.TrustDomain)
	}
}

func TestVerifyCancelled(t *testing.T) {
	issuer := authntest.NewIssuer(t, "example.org")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New(issuer.Bundle(t)).Verify(ctx, issuer.ValidToken(t, subject)); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("got %v", err)
	}
}
