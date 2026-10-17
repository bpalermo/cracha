// Package bundle is the broker's production source of grants: a
// grants.Source backed by the compiled, signed bundle grantc publishes
// (docs/design.md, section 6.2, and common/grant's publication layout).
//
// A [Source] polls a [Fetcher] (a local directory or an S3 prefix), verifies
// the signature over the exact published bytes with a grant.Verifier, parses
// the bundle strictly and swaps the whole grant set atomically when the
// version changed. Anything that fails to fetch, verify or parse is rejected
// with a logged reason and the bundle in service stays: the broker never
// fails open. Until a first bundle has loaded the source holds nothing,
// Lookup finds no grant, Version is empty and Ready reports the reason, so
// the readiness probe keeps the broker out of service.
package bundle

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bpalermo/cracha/broker/internal/grants"
	"github.com/bpalermo/cracha/common/grant"
)

// DefaultPollInterval is how often a Source looks for a new version when
// none is configured.
const DefaultPollInterval = 60 * time.Second

// errNotLoaded is what Ready returns before a bundle has loaded; the
// rejection of the last attempt is joined to it.
var errNotLoaded = errors.New("no grant bundle loaded yet")

// snapshot is one loaded bundle: immutable once built, swapped as a whole.
type snapshot struct {
	version string
	grants  map[string]grants.ResolvedGrant
}

// Source is a grants.Source that serves the last good bundle.
type Source struct {
	fetcher  Fetcher
	verifier grant.Verifier
	interval time.Duration
	log      *slog.Logger

	current atomic.Pointer[snapshot]

	// mu serializes reloads, so two of them cannot race to swap, and
	// guards the rejection state below.
	mu sync.Mutex
	// lastRejected keys the last rejection (the version and digest of the
	// publication, or the fetch error), so a broken publication is logged
	// once, not on every poll.
	lastRejected string
	lastErr      error
}

// Options configure a Source.
type Options struct {
	// PollInterval is how often Run looks for a new version; zero means
	// DefaultPollInterval.
	PollInterval time.Duration
	// Log receives swaps and rejections; nil means slog.Default().
	Log *slog.Logger
}

// New makes a Source over a fetcher and the verifier its publications must
// satisfy. Nothing is loaded until Reload or Run.
func New(fetcher Fetcher, verifier grant.Verifier, opts Options) *Source {
	if opts.PollInterval <= 0 {
		opts.PollInterval = DefaultPollInterval
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	return &Source{fetcher: fetcher, verifier: verifier, interval: opts.PollInterval, log: opts.Log}
}

// Lookup implements grants.Source. Nothing is found until a bundle loads.
func (s *Source) Lookup(name string) (grants.ResolvedGrant, bool) {
	snap := s.current.Load()
	if snap == nil {
		return grants.ResolvedGrant{}, false
	}
	g, ok := snap.grants[name]
	return g, ok
}

// Version implements grants.Source: the loaded bundle's version field,
// which Cracha-Bundle-Version reports, or empty before the first load.
func (s *Source) Version() string {
	snap := s.current.Load()
	if snap == nil {
		return ""
	}
	return snap.version
}

// Ready implements the API's readiness check: nil once a bundle is in
// service, otherwise why there is none yet.
func (s *Source) Ready() error {
	if s.current.Load() != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastErr != nil {
		return fmt.Errorf("%w: %w", errNotLoaded, s.lastErr)
	}
	return errNotLoaded
}

// Run polls until ctx ends: every interval, with jitter of up to a tenth
// of it either way, it reloads. The first attempt is left to the caller
// (Reload), so startup can log it synchronously.
func (s *Source) Run(ctx context.Context) {
	for {
		timer := time.NewTimer(s.jittered())
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		_ = s.Reload(ctx)
	}
}

// jittered is the interval scaled by a uniform factor in [0.9, 1.1], so
// replicas that started together do not poll in lockstep.
func (s *Source) jittered() time.Duration {
	return time.Duration(float64(s.interval) * (0.9 + 0.2*rand.Float64()))
}

// Reload fetches, verifies and parses the current publication once and,
// when it is a new version, puts it in service. A rejected publication is
// logged (once per publication) and returned; the bundle in service, if
// any, is untouched.
func (s *Source) Reload(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	fetched, err := s.fetcher.Fetch(ctx)
	if err != nil {
		return s.reject("fetch:"+err.Error(), "", fmt.Errorf("fetch: %w", err))
	}
	key := fetched.Version + "@" + grant.Digest(fetched.Bundle)
	b, err := s.verifyAndParse(ctx, fetched)
	if err != nil {
		return s.reject(key, fetched.Version, err)
	}
	s.lastRejected, s.lastErr = "", nil
	old := s.current.Load()
	if old != nil && old.version == b.Version {
		return nil
	}
	snap, err := convert(b)
	if err != nil {
		return s.reject(key, fetched.Version, err)
	}
	s.current.Store(snap)
	oldVersion := ""
	if old != nil {
		oldVersion = old.version
	}
	s.log.Info("grant bundle loaded", "old_version", oldVersion, "new_version", snap.version,
		"grants", len(snap.grants), "generated_at", b.GeneratedAt)
	return nil
}

// verifyAndParse checks a fetched publication the way grantc verify does,
// signature first over the exact bytes, then parses it strictly and
// requires the bundle to be the version the pointer named.
func (s *Source) verifyAndParse(ctx context.Context, f *Fetched) (*grant.Bundle, error) {
	sig, err := grant.ParseSignature(f.Signature)
	if err != nil {
		return nil, err
	}
	if err := s.verifier.Verify(ctx, f.Bundle, sig); err != nil {
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

// reject records a rejection and logs it unless the same publication was
// already rejected. It returns the error for the caller.
func (s *Source) reject(key, version string, err error) error {
	s.lastErr = err
	if s.lastRejected != key {
		s.lastRejected = key
		s.log.Error("grant bundle rejected; keeping the bundle in service",
			"version", version, "in_service", s.Version(), "error", err)
	}
	return err
}

// convert turns a parsed bundle into a snapshot, field for field: the
// bundle's grant and the broker's resolved grant are the same record by
// design (common/grant's BundleGrant names the fields of ResolvedGrant).
func convert(b *grant.Bundle) (*snapshot, error) {
	snap := &snapshot{version: b.Version, grants: make(map[string]grants.ResolvedGrant, len(b.Grants))}
	for _, g := range b.Grants {
		if g.Name == "" {
			return nil, errors.New("bundle: a grant has no name")
		}
		if _, dup := snap.grants[g.Name]; dup {
			return nil, fmt.Errorf("bundle: grant %q listed twice", g.Name)
		}
		if g.Duration < 0 || g.Duration > math.MaxInt32 {
			return nil, fmt.Errorf("bundle: grant %q: duration %d is out of range", g.Name, g.Duration)
		}
		snap.grants[g.Name] = grants.ResolvedGrant{
			Name:              g.Name,
			Account:           g.Account,
			BaseRole:          g.BaseRole,
			SessionPolicy:     g.SessionPolicy,
			ManagedPolicyARNs: g.ManagedPolicyArns,
			SessionTags:       g.SessionTags,
			DurationSeconds:   int32(g.Duration),
			Envelope:          g.Envelope,
		}
	}
	return snap, nil
}
