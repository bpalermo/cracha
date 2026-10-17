// Package token checks a pod's JWT-SVID before it reaches the disk and writes
// it where the AWS SDK reads it (docs/design.md, sections 7.2 and 7.3).
//
// The claims are read without verifying the signature: the issuer just minted
// the token over an authenticated channel, and verifying it is the broker's
// job. What is checked here is that the token is the one the pod may hold:
// the audience of the broker and nothing else, a subject that is the pod's
// own identity, and a lifetime within the invariant of section 11 (at most
// 5 minutes on disk). A token that fails any of these is never written.
package token

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// FileName is the token's name inside the volume: /var/run/cracha/token in
// the container, <target_path>/token on the node.
const FileName = "token"

// DefaultMaxTTL is the longest lifetime a token may have to be written: the
// invariant of section 11.
const DefaultMaxTTL = 5 * time.Minute

// Claims are the JWT-SVID claims the plugin acts on.
type Claims struct {
	// ID is the subject.
	ID spiffeid.ID
	// Audience is the aud claim.
	Audience []string
	// IssuedAt is the iat claim, zero when the token has none.
	IssuedAt time.Time
	// Expiry is the exp claim.
	Expiry time.Time
}

// Expectation is what a token must match to be written for a pod.
type Expectation struct {
	// Audience is the one audience the token must carry.
	Audience string
	// Namespace and ServiceAccount are the pod's; the subject must be
	// spiffe://<td>/ns/<Namespace>/sa/<ServiceAccount>.
	Namespace      string
	ServiceAccount string
	// MaxTTL bounds the token's lifetime, iat to exp (or now to exp when it
	// has no iat). Zero means DefaultMaxTTL.
	MaxTTL time.Duration
	// Now is the time to check against; zero means time.Now().
	Now time.Time
}

// TTLError reports a token that outlives MaxTTL. It is its own type because it
// is the one rejection whose fix is on the issuer's side, not the pod's.
type TTLError struct {
	ID       spiffeid.ID
	Lifetime time.Duration
	MaxTTL   time.Duration
}

// Error implements error, naming the fix.
func (e *TTLError) Error() string {
	return fmt.Sprintf("the JWT-SVID for %s lives %s, longer than the %s allowed on disk; the token is not written. "+
		"The fix is on the issuer: the JWT-SVID TTL of this pod's entry must be at most %s "+
		"(SPIRE: the entry's jwt_svid_ttl, ClusterSPIFFEID.spec.jwtSVIDTTL)",
		e.ID, e.Lifetime, e.MaxTTL, e.MaxTTL)
}

// Parse reads the claims of a JWT-SVID without verifying its signature. It
// fails on a malformed token, one without a subject that is a SPIFFE ID, or
// one without an expiry. Time is not checked here: Check does, against the
// caller's clock.
func Parse(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("the token is not a JWS compact serialization")
	}
	if err := checkHeader(parts[0]); err != nil {
		return nil, err
	}
	var payload rawClaims
	if err := decodeSegment(parts[1], &payload); err != nil {
		return nil, fmt.Errorf("the token's claims: %w", err)
	}
	return payload.claims()
}

// checkHeader decodes the JOSE header and checks that it announces a signed
// JWT: an algorithm that is not none and, when it names one, a type of JWT
// or JOSE.
func checkHeader(segment string) error {
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := decodeSegment(segment, &header); err != nil {
		return fmt.Errorf("the token's header: %w", err)
	}
	if header.Alg == "" || strings.EqualFold(header.Alg, "none") {
		return fmt.Errorf("the token's algorithm %q is not a signature", header.Alg)
	}
	if header.Typ != "" && header.Typ != "JWT" && header.Typ != "JOSE" {
		return fmt.Errorf("the token's type %q is neither JWT nor JOSE", header.Typ)
	}
	return nil
}

// rawClaims is the payload as decoded, before any claim is checked.
type rawClaims struct {
	Sub string          `json:"sub"`
	Aud json.RawMessage `json:"aud"`
	Exp json.Number     `json:"exp"`
	Iat json.Number     `json:"iat"`
}

// claims checks the claims Parse requires and reads the rest: the subject,
// then the times, then the audience.
func (r *rawClaims) claims() (*Claims, error) {
	if r.Sub == "" {
		return nil, errors.New("the token has no sub claim")
	}
	id, err := spiffeid.FromString(r.Sub)
	if err != nil {
		return nil, fmt.Errorf("the token's sub claim is not a SPIFFE ID: %w", err)
	}
	if r.Exp == "" {
		return nil, errors.New("the token has no exp claim")
	}
	c := &Claims{ID: id}
	if c.Expiry, err = claimTime(r.Exp); err != nil {
		return nil, fmt.Errorf("the token's exp claim: %w", err)
	}
	if r.Iat != "" {
		if c.IssuedAt, err = claimTime(r.Iat); err != nil {
			return nil, fmt.Errorf("the token's iat claim: %w", err)
		}
	}
	if c.Audience, err = audience(r.Aud); err != nil {
		return nil, err
	}
	return c, nil
}

// audience reads an aud claim, which RFC 7519 allows to be a string or an
// array of strings. A token without one has no audience.
func audience(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, errors.New("the token's aud claim is neither a string nor an array of strings")
	}
	return many, nil
}

// decodeSegment base64url-decodes a JWS segment into a JSON value.
func decodeSegment(segment string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return fmt.Errorf("not base64url: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("not JSON: %w", err)
	}
	return nil
}

// claimTime reads a NumericDate claim.
func claimTime(n json.Number) (time.Time, error) {
	secs, err := n.Float64()
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(int64(secs), 0).UTC(), nil
}

// Validate parses token and checks it against exp.
func Validate(token string, exp Expectation) (*Claims, error) {
	c, err := Parse(token)
	if err != nil {
		return nil, err
	}
	if err := c.Check(exp); err != nil {
		return nil, err
	}
	return c, nil
}

// Check checks already parsed claims against exp.
func (c *Claims) Check(exp Expectation) error {
	now := exp.Now
	if now.IsZero() {
		now = time.Now()
	}
	maxTTL := exp.MaxTTL
	if maxTTL <= 0 {
		maxTTL = DefaultMaxTTL
	}

	if len(c.Audience) != 1 || c.Audience[0] != exp.Audience {
		return fmt.Errorf("the token's audience is %q, must be exactly [%s]", c.Audience, exp.Audience)
	}
	wantPath := fmt.Sprintf("/ns/%s/sa/%s", exp.Namespace, exp.ServiceAccount)
	if c.ID.Path() != wantPath {
		return fmt.Errorf("the token's subject %s is not the pod's identity (path must be %s)", c.ID, wantPath)
	}
	if !c.Expiry.After(now) {
		return fmt.Errorf("the token expired at %s", c.Expiry.Format(time.RFC3339))
	}
	// The lifetime as the issuer set it, when it says; otherwise the most the
	// token can still live, which is a lower bound of its lifetime.
	lifetime := c.Expiry.Sub(now)
	if !c.IssuedAt.IsZero() {
		if c.Expiry.Before(c.IssuedAt) {
			return fmt.Errorf("the token expires (%s) before it was issued (%s)",
				c.Expiry.Format(time.RFC3339), c.IssuedAt.Format(time.RFC3339))
		}
		lifetime = c.Expiry.Sub(c.IssuedAt)
	}
	if lifetime > maxTTL {
		return &TTLError{ID: c.ID, Lifetime: lifetime, MaxTTL: maxTTL}
	}
	return nil
}

// Lifetime is the token's issue-to-expiry span. issued stands in for iat when
// the token has none.
func (c *Claims) Lifetime(issued time.Time) time.Duration {
	if !c.IssuedAt.IsZero() {
		issued = c.IssuedAt
	}
	return c.Expiry.Sub(issued)
}

// Owner is the owner of the written file and of its directory. A negative ID
// leaves that ID as the process created it. The driver takes the group from
// the pod's fsGroup, which kubelet passes as the volume mount group, and
// falls back to the plugin's --token-gid.
type Owner struct {
	UID int
	GID int
}

// Mode is the token file's mode: the owner and group read it, nobody else.
const Mode = 0o640

// DirMode is the volume directory's mode: the owner and group enter it. The
// directory is the volume's mount point in the container, so a pod's
// processes have to traverse it to reach the token.
const DirMode = 0o750

// Write puts token at <dir>/token atomically: a temporary file in dir, set to
// Mode and owner before it holds the token, then renamed over the name, so a
// reader sees either the previous token or the new one, never a partial file
// and never one with the wrong owner. dir is created if it does not exist,
// and gets DirMode and the same owner, so that the group can enter it.
//
// Giving the file a group the process is not a member of needs CAP_CHOWN,
// which the DaemonSet grants for exactly this.
func Write(dir, token string, owner Owner) (err error) {
	if err := prepareDir(dir, owner); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+FileName+".*")
	if err != nil {
		return fmt.Errorf("creating the temporary token file in %s: %w", dir, err)
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(Mode); err != nil {
		return fmt.Errorf("setting the mode of %s: %w", tmp, err)
	}
	if owner.wanted() {
		if err := f.Chown(owner.UID, owner.GID); err != nil {
			return fmt.Errorf("setting the owner of %s to %d:%d: %w", tmp, owner.UID, owner.GID, err)
		}
	}
	if _, err := f.WriteString(token); err != nil {
		return fmt.Errorf("writing %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("syncing %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", tmp, err)
	}
	final := filepath.Join(dir, FileName)
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("renaming %s to %s: %w", tmp, final, err)
	}
	return nil
}

// wanted reports whether owner asks for any ID to be set.
func (o Owner) wanted() bool { return o.UID >= 0 || o.GID >= 0 }

// prepareDir creates dir and gives it DirMode and owner. An existing
// directory is brought to the same state: on a republish with another group
// the directory must follow the file.
func prepareDir(dir string, owner Owner) error {
	if err := os.MkdirAll(dir, DirMode); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	if err := os.Chmod(dir, DirMode); err != nil {
		return fmt.Errorf("setting the mode of %s: %w", dir, err)
	}
	if owner.wanted() {
		if err := os.Chown(dir, owner.UID, owner.GID); err != nil {
			return fmt.Errorf("setting the owner of %s to %d:%d: %w", dir, owner.UID, owner.GID, err)
		}
	}
	return nil
}

// Remove deletes the token file and anything else in dir, then dir itself.
// A missing dir is not an error: unpublish is idempotent.
func Remove(dir string) error {
	if err := os.RemoveAll(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing %s: %w", dir, err)
	}
	return nil
}
