// Package publication is the reading side of the grant publication
// common/grant writes (docs/design.md, section 6.2): a [Fetcher] that
// follows the latest pointer of a local directory or an S3 prefix to a
// version's objects, [Verify], which checks the signature over the exact
// published bytes and parses the bundle strictly, and a [Poller] that
// keeps the last good bundle in service.
//
// The broker's grant source (broker/internal/bundle) reads the publication
// with the fetchers of this package; cracha-access, which checks every
// relationship write against the grants the broker holds (design 6.9),
// reads it with the Poller, so both see the same versions verified with
// the same keys.
package publication

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bpalermo/cracha/common/grant"
)

// DefaultPollInterval is how often a Poller looks for a new version when
// none is configured.
const DefaultPollInterval = 60 * time.Second

// Verify checks a fetched publication's bundle the way grantc verify does,
// the signature first over the exact bytes, then parses it strictly and
// requires it to be the version the pointer named.
func Verify(ctx context.Context, verifier grant.Verifier, f *Fetched) (*grant.Bundle, error) {
	sig, err := grant.ParseSignature(f.Signature)
	if err != nil {
		return nil, err
	}
	if err := verifier.Verify(ctx, f.Bundle, sig); err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	b, err := grant.ParseBundle(f.Bundle)
	if err != nil {
		return nil, err
	}
	if b.Version != f.Version {
		return nil, fmt.Errorf("bundle says version %q, the pointer %q", b.Version, f.Version)
	}
	return b, nil
}

// LoadKeyRing reads every public key of every PEM file into one key ring,
// any key of which verifies (the one a signature names), so that the
// signing key rotates without a gap.
func LoadKeyRing(paths []string) (*grant.KeyRing, error) {
	var pubs []*ecdsa.PublicKey
	for _, path := range paths {
		pemData, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("bundle verify key: %w", err)
		}
		keys, err := grant.ParseECPublicKeys(pemData)
		if err != nil {
			return nil, fmt.Errorf("bundle verify key %s: %w", path, err)
		}
		pubs = append(pubs, keys...)
	}
	ring, err := grant.NewKeyRing(pubs...)
	if err != nil {
		return nil, fmt.Errorf("bundle verify keys %s: %w", strings.Join(paths, ", "), err)
	}
	return ring, nil
}

// errNotLoaded is what Ready returns before a bundle has loaded.
var errNotLoaded = errors.New("no grant bundle loaded yet")

// Poller holds the last good bundle of a publication: it reloads on an
// interval and swaps the bundle only when a new version verified and
// parsed. Anything that fails is logged once and the bundle in service
// stays; until a first one loads, Bundle is nil and Ready says why.
type Poller struct {
	fetcher  Fetcher
	verifier grant.Verifier
	interval time.Duration
	log      *slog.Logger

	current atomic.Pointer[grant.Bundle]

	mu           sync.Mutex
	lastRejected string
	lastErr      error
}

// NewPoller makes a Poller; nothing is loaded until Reload or Run. A zero
// interval is DefaultPollInterval and a nil log slog.Default().
func NewPoller(fetcher Fetcher, verifier grant.Verifier, interval time.Duration, log *slog.Logger) *Poller {
	if interval <= 0 {
		interval = DefaultPollInterval
	}
	if log == nil {
		log = slog.Default()
	}
	return &Poller{fetcher: fetcher, verifier: verifier, interval: interval, log: log}
}

// Bundle is the bundle in service, or nil before the first load. It is
// never modified once in service.
func (p *Poller) Bundle() *grant.Bundle { return p.current.Load() }

// Ready is nil once a bundle is in service, otherwise why there is none.
func (p *Poller) Ready() error {
	if p.current.Load() != nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.lastErr != nil {
		return fmt.Errorf("%w: %w", errNotLoaded, p.lastErr)
	}
	return errNotLoaded
}

// Reload fetches and verifies the publication once and puts a new version
// in service. A rejection is logged once per publication and returned.
func (p *Poller) Reload(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	f, err := p.fetcher.Fetch(ctx, false)
	if err != nil {
		return p.reject("fetch:"+err.Error(), "", fmt.Errorf("fetch: %w", err))
	}
	b, err := Verify(ctx, p.verifier, f)
	if err != nil {
		return p.reject(f.Version+"@"+grant.Digest(f.Bundle), f.Version, err)
	}
	p.lastRejected, p.lastErr = "", nil
	old := p.current.Load()
	if old != nil && old.Version == b.Version {
		return nil
	}
	p.current.Store(b)
	oldVersion := ""
	if old != nil {
		oldVersion = old.Version
	}
	p.log.Info("grant bundle loaded", "old_version", oldVersion, "new_version", b.Version, "grants", len(b.Grants), "generated_at", b.GeneratedAt)
	return nil
}

// Run reloads every interval, with a tenth of jitter either way, until
// ctx ends. The first attempt is the caller's.
func (p *Poller) Run(ctx context.Context) {
	for {
		timer := time.NewTimer(time.Duration(float64(p.interval) * (0.9 + 0.2*rand.Float64())))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		_ = p.Reload(ctx)
	}
}

func (p *Poller) reject(key, version string, err error) error {
	p.lastErr = err
	if p.lastRejected != key {
		p.lastRejected = key
		in := ""
		if b := p.current.Load(); b != nil {
			in = b.Version
		}
		p.log.Error("grant bundle rejected; keeping the bundle in service", "version", version, "in_service", in, "error", err)
	}
	return err
}
