// Package authn verifies the JWT-SVID a workload presents to the broker
// (docs/design.md, section 6.5): signature against the trust bundle of the
// subject's trust domain, audience exactly "cracha-broker", expiry, and a
// subject that matches the SPIFFE ID scheme of section 4.
//
// The bundles come from a [jwtbundle.Source]. In production that is the JWT
// source over the broker's own Workload API connection (the one its X.509
// source for mTLS shares, broker/spiffe.go), which also carries federated
// bundles; tests use a static [jwtbundle.Bundle]. The broker touches
// nothing issuer-specific (section 4.1).
package authn

import (
	"context"
	"errors"
	"fmt"

	"github.com/bpalermo/cracha/common/idenc"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
)

// Audience is the only audience a JWT-SVID for the broker may carry.
const Audience = "cracha-broker"

// ErrInvalidToken wraps every verification failure, so callers can map all
// of them to one 401 without inspecting the cause.
var ErrInvalidToken = errors.New("invalid JWT-SVID")

// Verifier validates JWT-SVIDs against a bundle source.
type Verifier struct {
	bundles jwtbundle.Source
}

// New returns a Verifier over the given bundle source.
func New(bundles jwtbundle.Source) *Verifier {
	return &Verifier{bundles: bundles}
}

// Verify validates a serialized JWT-SVID and returns the workload identity
// from its subject. Every failure wraps [ErrInvalidToken]. A token whose
// audience is anything but exactly [Audience] is rejected, as is one whose
// trust domain has no bundle in the source.
func (v *Verifier) Verify(ctx context.Context, token string) (idenc.Identity, error) {
	if err := ctx.Err(); err != nil {
		return idenc.Identity{}, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	if token == "" {
		return idenc.Identity{}, fmt.Errorf("%w: empty token", ErrInvalidToken)
	}
	svid, err := jwtsvid.ParseAndValidate(token, v.bundles, []string{Audience})
	if err != nil {
		return idenc.Identity{}, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	// go-spiffe accepts a token that carries the expected audience among
	// others; the broker only takes a token minted for it alone.
	if len(svid.Audience) != 1 || svid.Audience[0] != Audience {
		return idenc.Identity{}, fmt.Errorf("%w: audience %q is not exactly [%q]", ErrInvalidToken, svid.Audience, Audience)
	}
	id, err := idenc.FromID(svid.ID)
	if err != nil {
		return idenc.Identity{}, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	return id, nil
}
