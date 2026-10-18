// Package bundle is the broker's production source of grants: a
// grants.Source backed by the compiled, signed bundle grantc publishes
// (docs/design.md, section 6.2, and common/grant's publication layout),
// and, when the static authorization backend reads its assignments from
// the same publication, the source of those too.
//
// A [Source] polls a [Fetcher] (a local directory or an S3 prefix), verifies
// the signature over the exact published bytes with a grant.Verifier, parses
// the bundle strictly and swaps the whole grant set atomically when the
// version changed. With an [AssignmentsSink] it does the same with the
// version's assignments document, and a version is put in service only
// when both verified and parsed: the pair is swapped together, and a
// version that lacks its assignments, or whose assignments fail, is
// rejected whole. Anything that fails to fetch, verify or parse is rejected
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
	"sort"
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
	// implicit are the accounts' implicit grants, sorted by name, which
	// apply by relation and are never looked up by name.
	implicit []grants.ResolvedGrant
	// placed maps kind\x00name to the account a resource is in; only is
	// the bundle's one account, which holds every resource, when it has
	// exactly one.
	placed map[string]string
	only   string
}

// Source is a grants.Source that serves the last good bundle.
type Source struct {
	fetcher     Fetcher
	verifier    grant.Verifier
	interval    time.Duration
	log         *slog.Logger
	assignments AssignmentsSink

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

// AssignmentsSink takes the assignments of each version the source puts
// in service: the static authorization backend's store, when it reads its
// assignments from the publication.
type AssignmentsSink interface {
	// Prepare checks a version's verified, parsed assignments (data is
	// their published bytes) and returns the function that puts them in
	// service. It changes nothing in service itself: a version whose
	// bundle fails after its assignments prepared is not committed.
	Prepare(a *grant.Assignments, data []byte) (commit func(), err error)
}

// Options configure a Source.
type Options struct {
	// PollInterval is how often Run looks for a new version; zero means
	// DefaultPollInterval.
	PollInterval time.Duration
	// Log receives swaps and rejections; nil means slog.Default().
	Log *slog.Logger
	// Assignments, when set, has every version's assignments fetched,
	// verified and handed to it with the bundle; nil leaves them unread.
	Assignments AssignmentsSink
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
	return &Source{fetcher: fetcher, verifier: verifier, interval: opts.PollInterval, log: opts.Log, assignments: opts.Assignments}
}

// A bundle's accounts carry implicit grants, which Compose finds through
// this interface.
var _ grants.ImplicitSource = (*Source)(nil)

// Lookup implements grants.Source. Nothing is found until a bundle loads.
func (s *Source) Lookup(name string) (grants.ResolvedGrant, bool) {
	snap := s.current.Load()
	if snap == nil {
		return grants.ResolvedGrant{}, false
	}
	g, ok := snap.grants[name]
	return g, ok
}

// ImplicitGrants implements grants.ImplicitSource: the implicit grants of
// the loaded bundle's accounts.
func (s *Source) ImplicitGrants() []grants.ResolvedGrant {
	snap := s.current.Load()
	if snap == nil {
		return nil
	}
	return snap.implicit
}

// AccountOf implements grants.ImplicitSource: the account the bundle
// places a resource in, every resource being in a bundle's only account.
func (s *Source) AccountOf(kind, name string) (string, bool) {
	snap := s.current.Load()
	if snap == nil {
		return "", false
	}
	if id, ok := snap.placed[kind+"\x00"+name]; ok {
		return id, true
	}
	return snap.only, snap.only != ""
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
// when it is a new version, puts it in service: its bundle and, with an
// AssignmentsSink, its assignments, both or neither. A rejected
// publication is logged (once per publication) and returned; what is in
// service, if anything, is untouched.
func (s *Source) Reload(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	fetched, err := s.fetcher.Fetch(ctx, s.assignments != nil)
	if err != nil {
		return s.reject("fetch:"+err.Error(), "", fmt.Errorf("fetch: %w", err))
	}
	key := fetched.Version + "@" + grant.Digest(fetched.Bundle) + "@" + grant.Digest(fetched.Assignments)
	b, err := s.verifyAndParse(ctx, fetched)
	if err != nil {
		return s.reject(key, fetched.Version, err)
	}
	old := s.current.Load()
	if old != nil && old.version == b.Version {
		s.lastRejected, s.lastErr = "", nil
		return nil
	}
	commit, counts, err := s.prepareAssignments(ctx, fetched)
	if err != nil {
		return s.reject(key, fetched.Version, fmt.Errorf("assignments: %w", err))
	}
	snap, err := convert(b)
	if err != nil {
		return s.reject(key, fetched.Version, err)
	}
	s.lastRejected, s.lastErr = "", nil
	s.current.Store(snap)
	commit()
	oldVersion := ""
	if old != nil {
		oldVersion = old.version
	}
	attrs := []any{"old_version", oldVersion, "new_version", snap.version, "grants", len(snap.grants), "generated_at", b.GeneratedAt}
	s.log.Info("grant bundle loaded", append(attrs, counts...)...)
	return nil
}

// prepareAssignments verifies, parses and prepares the fetched version's
// assignments, when the source has a sink; it returns the commit and what
// to log about them. Without a sink the commit does nothing.
func (s *Source) prepareAssignments(ctx context.Context, f *Fetched) (func(), []any, error) {
	if s.assignments == nil {
		return func() {}, nil, nil
	}
	sig, err := grant.ParseSignature(f.AssignmentsSignature)
	if err != nil {
		return nil, nil, err
	}
	if err := s.verifier.Verify(ctx, f.Assignments, sig); err != nil {
		return nil, nil, fmt.Errorf("signature: %w", err)
	}
	a, err := grant.ParseAssignments(f.Assignments)
	if err != nil {
		return nil, nil, err
	}
	if a.Version != f.Version {
		return nil, nil, fmt.Errorf("assignments say version %q, the pointer %q", a.Version, f.Version)
	}
	commit, err := s.assignments.Prepare(a, f.Assignments)
	if err != nil {
		return nil, nil, err
	}
	return commit, []any{"services", len(a.Services), "workloads", len(a.Workloads)}, nil
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
	accounts, err := snap.placeAccounts(b.Accounts)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, g := range b.Grants {
		if g.Name == "" {
			return nil, errors.New("bundle: a grant has no name")
		}
		if seen[g.Name] {
			return nil, fmt.Errorf("bundle: grant %q listed twice", g.Name)
		}
		seen[g.Name] = true
		if g.Duration < 0 || g.Duration > math.MaxInt32 {
			return nil, fmt.Errorf("bundle: grant %q: duration %d is out of range", g.Name, g.Duration)
		}
		lookup, err := lookupOf(g)
		if err != nil {
			return nil, err
		}
		if err := checkImplicit(g, accounts); err != nil {
			return nil, err
		}
		rg := grants.ResolvedGrant{
			Name:              g.Name,
			Account:           g.Account,
			BaseRole:          g.BaseRole,
			SessionPolicy:     g.SessionPolicy,
			ManagedPolicyARNs: g.ManagedPolicyArns,
			SessionTags:       g.SessionTags,
			DurationSeconds:   int32(g.Duration),
			Envelope:          g.Envelope,
			Lookup:            lookup,
			Implicit:          g.Implicit,
		}
		if g.Implicit {
			snap.implicit = append(snap.implicit, rg)
			continue
		}
		snap.grants[g.Name] = rg
	}
	sort.Slice(snap.implicit, func(i, j int) bool { return snap.implicit[i].Name < snap.implicit[j].Name })
	return snap, nil
}

// placeAccounts records where the bundle's accounts place resources and
// returns the account ids. An account listed twice, or a resource placed
// in two, rejects the bundle.
func (snap *snapshot) placeAccounts(accounts []grant.BundleAccount) (map[string]bool, error) {
	ids := map[string]bool{}
	snap.placed = map[string]string{}
	for _, a := range accounts {
		if a.ID == "" || ids[a.ID] {
			return nil, fmt.Errorf("bundle: account %q (%q) is empty or listed twice", a.Name, a.ID)
		}
		ids[a.ID] = true
		for _, r := range a.Resources {
			key := r.Kind + "\x00" + r.Name
			if prev, dup := snap.placed[key]; dup && prev != a.ID {
				return nil, fmt.Errorf("bundle: %s is placed in accounts %s and %s", r, prev, a.ID)
			}
			snap.placed[key] = a.ID
		}
	}
	if len(accounts) == 1 {
		snap.only = accounts[0].ID
	}
	return ids, nil
}

// checkImplicit rejects an implicit grant that is not a lookup grant or is
// in no account of the bundle.
func checkImplicit(g grant.BundleGrant, accounts map[string]bool) error {
	switch {
	case !g.Implicit:
		return nil
	case g.Lookup == nil:
		return fmt.Errorf("bundle: implicit grant %q has no lookup", g.Name)
	case !accounts[g.Account]:
		return fmt.Errorf("bundle: implicit grant %q is in account %s, which the bundle does not list", g.Name, g.Account)
	}
	return nil
}

// lookupOf is a lookup grant's lookup, rendered by common/grant's own
// renderer, the compiler's: nil for any other grant. A lookup grant must
// carry no rendered policy, a known kind and permission and a positive
// maximum, or the bundle is rejected.
func lookupOf(g grant.BundleGrant) (*grants.Lookup, error) {
	l := g.Lookup
	if l == nil {
		return nil, nil
	}
	_, known := grant.LookupResourceKind(l.Kind)
	_, permission := grant.RelationsOf(l.Permission)
	switch {
	case g.SessionPolicy != "":
		return nil, fmt.Errorf("bundle: grant %q: a lookup grant carries no rendered session policy", g.Name)
	case !known || !permission:
		return nil, fmt.Errorf("bundle: grant %q: lookup %s#%s is not a known kind and permission", g.Name, l.Kind, l.Permission)
	case l.MaxResources < 1:
		return nil, fmt.Errorf("bundle: grant %q: lookup maximum %d", g.Name, l.MaxResources)
	}
	account := g.Account
	return &grants.Lookup{
		Kind: l.Kind, Permission: l.Permission, MaxResources: l.MaxResources,
		Render: func(resources []string) (string, error) { return l.Render(account, resources) },
	}, nil
}
