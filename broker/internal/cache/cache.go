// Package cache is the credential cache of docs/design.md, section 6.7: an
// [issuer.Issuer] that sits between resolution and the STS call of the
// issuer it wraps.
//
// Every request is still resolved against the authorization store and the
// bundle; what the cache saves is the STS call. The key is (shape, sorted
// grant set, bundle version, encoded workload), so a changed grant set is a
// new key and takes effect at the next fetch. A hit is served only after the
// resolution succeeded, which is the re-check of the store on every issuance;
// a denial from the store is a denial. Credentials are never served with
// less than Options.MinRemaining left, are refreshed ahead of time in the
// background once Options.RefreshAt of their usable lifetime (what is left
// before that floor) has passed, and one
// STS call serves every concurrent caller for a key (singleflight on miss
// and on refresh).
//
// When the store cannot answer, new keys are denied (never fail open); a key
// already held is served only while its last successful store check is
// younger than Options.StaleCheckMax, and logged as degraded. A store with
// [authz.Watcher] has its changes invalidate the entries they touch; without
// one the cache is in TTL-only mode, which [Cache.Mode] reports.
//
// The cache is in memory only, bounded by Options.MaxEntries with LRU
// eviction, and never persisted.
package cache

import (
	"container/list"
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bpalermo/cracha/broker/internal/authz"
	"github.com/bpalermo/cracha/broker/internal/grants"
	"github.com/bpalermo/cracha/broker/internal/issuer"
	"github.com/bpalermo/cracha/broker/internal/sts"
	"github.com/bpalermo/cracha/common/idenc"
	"golang.org/x/sync/singleflight"
)

// Inner is the issuer the cache wraps: one that resolves a workload against
// the store and the bundle, and assumes the shape role for a resolution the
// cache made, so a miss costs one store call, not two. *issuer.Direct is
// one.
type Inner interface {
	Resolve(ctx context.Context, id idenc.Identity) (issuer.Resolution, error)
	Assume(ctx context.Context, r issuer.Resolution) (issuer.Issuance, error)
}

// Mode is how the cache learns of assignment changes.
type Mode string

const (
	// ModeWatch invalidates entries from the store's Watch stream.
	ModeWatch Mode = "watch"
	// ModeTTL has no stream: entries live until they are replaced through a
	// changed key, expire or are evicted.
	ModeTTL Mode = "ttl"
)

// Defaults of the Options.
const (
	DefaultMinRemaining  = 20 * time.Minute
	DefaultRefreshAt     = 0.7
	DefaultMaxEntries    = 10000
	DefaultStaleCheckMax = 10 * time.Minute
	DefaultRefreshRetry  = 30 * time.Second
	DefaultIssueTimeout  = 30 * time.Second
)

// Options configure a Cache. The zero value takes every default.
type Options struct {
	// MinRemaining is the least lifetime credentials are served with; an
	// entry with less is replaced (section 11: never under 20 minutes).
	MinRemaining time.Duration
	// RefreshAt is the fraction of a session's usable lifetime, its
	// lifetime less MinRemaining, after which a hit starts a refresh in the
	// background, in (0, 1).
	RefreshAt float64
	// MaxEntries bounds the cache; the least recently used entry is evicted
	// beyond it.
	MaxEntries int
	// StaleCheckMax is how old an entry's last successful store check may be
	// for it to be served while the store cannot answer.
	StaleCheckMax time.Duration
	// RefreshRetry is how long after a failed refresh the next hit tries
	// again, with jitter up to half as much more.
	RefreshRetry time.Duration
	// IssueTimeout bounds the STS call made for a miss or a refresh, which
	// runs detached from the request that triggered it.
	IssueTimeout time.Duration
	// Now is the clock; time.Now when nil.
	Now func() time.Time
	// Log is the logger; slog.Default when nil.
	Log *slog.Logger
}

func (o Options) withDefaults() Options {
	if o.MinRemaining <= 0 {
		o.MinRemaining = DefaultMinRemaining
	}
	if o.RefreshAt <= 0 || o.RefreshAt >= 1 {
		o.RefreshAt = DefaultRefreshAt
	}
	if o.MaxEntries <= 0 {
		o.MaxEntries = DefaultMaxEntries
	}
	if o.StaleCheckMax <= 0 {
		o.StaleCheckMax = DefaultStaleCheckMax
	}
	if o.RefreshRetry <= 0 {
		o.RefreshRetry = DefaultRefreshRetry
	}
	if o.IssueTimeout <= 0 {
		o.IssueTimeout = DefaultIssueTimeout
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	return o
}

// Stats are the cache's counters since it started, for logs and tests.
type Stats struct {
	// Entries held right now.
	Entries int
	// Hits served cached credentials after a successful re-check.
	Hits uint64
	// Misses called STS inline.
	Misses uint64
	// Refreshes completed in the background; RefreshFailures did not and
	// left the old credentials in place.
	Refreshes       uint64
	RefreshFailures uint64
	// Degraded hits were served while the store could not answer.
	Degraded uint64
	// Denials are resolutions that failed, hits included.
	Denials uint64
	// Evictions by the LRU bound; Invalidations by the Watch stream.
	Evictions     uint64
	Invalidations uint64
}

// entry is one cached session.
type entry struct {
	key        string
	resolution issuer.Resolution
	creds      sts.Credentials
	// issuedAt is when STS answered; refreshAt is when a hit starts the
	// next refresh; lastCheck is the last successful store check for this
	// key, which is the last resolution that hit it.
	issuedAt   time.Time
	refreshAt  time.Time
	lastCheck  time.Time
	refreshing bool
	elem       *list.Element
}

// Cache is the credential cache. It implements issuer.Issuer.
type Cache struct {
	inner   Inner
	watcher authz.Watcher
	opts    Options
	flight  singleflight.Group
	// watchDown is set while the Watch stream is not delivering.
	watchDown atomic.Bool

	mu      sync.Mutex
	entries map[string]*entry
	// lru orders the entries, most recently used first.
	lru *list.List
	// byWorkload maps an encoded workload to the entry it was last served
	// from, for the degraded path, which has no key to look up.
	byWorkload map[string]*entry
	stats      Stats
}

// New returns a cache over inner. A store implementing authz.Watcher puts
// the cache in watch mode once Run consumes the stream; any other store
// leaves it in TTL-only mode.
func New(inner Inner, store authz.Store, opts Options) *Cache {
	c := &Cache{
		inner:      inner,
		opts:       opts.withDefaults(),
		entries:    map[string]*entry{},
		lru:        list.New(),
		byWorkload: map[string]*entry{},
	}
	c.watcher, _ = store.(authz.Watcher)
	return c
}

// Mode reports how the cache learns of assignment changes right now: watch
// while the store's stream is up, TTL-only otherwise.
func (c *Cache) Mode() Mode {
	if c.watcher != nil && !c.watchDown.Load() {
		return ModeWatch
	}
	return ModeTTL
}

// Stats returns the counters.
func (c *Cache) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.stats
	s.Entries = len(c.entries)
	return s
}

// Resolve implements issuer.Issuer: resolution is never cached.
func (c *Cache) Resolve(ctx context.Context, id idenc.Identity) (issuer.Resolution, error) {
	return c.inner.Resolve(ctx, id)
}

// Issue implements issuer.Issuer.
func (c *Cache) Issue(ctx context.Context, id idenc.Identity) (issuer.Issuance, error) {
	r, err := c.inner.Resolve(ctx, id)
	if err != nil {
		return c.resolveFailed(ctx, r, err)
	}
	key := keyOf(r)
	checkedAt := c.opts.Now()
	if creds, outcome, ok := c.lookup(r, key, checkedAt); ok {
		if outcome == issuer.CacheRefresh {
			go c.refresh(ctx, r, key, checkedAt)
		}
		c.opts.Log.LogAttrs(ctx, slog.LevelDebug, "served from cache",
			slog.String("source_identity", r.SourceIdentity), slog.String("shape", r.Composed.Shape),
			slog.Any("grants", r.Composed.Grants), slog.String("outcome", string(outcome)))
		return issuer.Issuance{Resolution: r, Credentials: creds, Cache: outcome}, nil
	}
	creds, err := c.assume(ctx, r, key, checkedAt)
	if err != nil {
		return issuer.Issuance{}, err
	}
	return issuer.Issuance{Resolution: r, Credentials: creds, Cache: issuer.CacheMiss}, nil
}

// keyOf is the cache key of section 6.7: shape, sorted grant set, bundle
// version, encoded workload.
func keyOf(r issuer.Resolution) string {
	names := append([]string(nil), r.Composed.Grants...)
	sort.Strings(names)
	return strings.Join([]string{r.Composed.Shape, strings.Join(names, ","), r.BundleVersion, r.SourceIdentity}, "\n")
}

// lookup finds a usable entry for the key, counts the hit or miss, and
// says whether the hit should start a refresh. The resolution that led here
// succeeded at checkedAt, which it records as the store check.
func (c *Cache) lookup(r issuer.Resolution, key string, checkedAt time.Time) (sts.Credentials, issuer.CacheOutcome, bool) {
	now := checkedAt
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if ok && e.creds.Expiration.Sub(now) < c.opts.MinRemaining {
		c.remove(e)
		ok = false
	}
	if !ok {
		c.stats.Misses++
		return sts.Credentials{}, "", false
	}
	c.stats.Hits++
	e.lastCheck = now
	c.lru.MoveToFront(e.elem)
	c.byWorkload[r.SourceIdentity] = e
	outcome := issuer.CacheHit
	if !e.refreshing && !now.Before(e.refreshAt) {
		e.refreshing = true
		outcome = issuer.CacheRefresh
	}
	return e.creds, outcome, true
}

// assume calls STS for the key, once for every concurrent caller, and stores
// the result with checkedAt, when the resolution it issues for was made, as
// the store check. The call runs detached from the request's cancellation so
// one caller going away does not fail the others.
func (c *Cache) assume(ctx context.Context, r issuer.Resolution, key string, checkedAt time.Time) (sts.Credentials, error) {
	v, err, _ := c.flight.Do(key, func() (any, error) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.opts.IssueTimeout)
		defer cancel()
		iss, err := c.inner.Assume(ctx, r)
		if err != nil {
			return nil, err
		}
		c.store(r, key, iss.Credentials, checkedAt)
		return iss.Credentials, nil
	})
	if err != nil {
		return sts.Credentials{}, err
	}
	return v.(sts.Credentials), nil
}

// store puts freshly issued credentials under the key, replacing in place
// an entry a refresh is updating, and evicts beyond the bound.
func (c *Cache) store(r issuer.Resolution, key string, creds sts.Credentials, checkedAt time.Time) {
	now := c.opts.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		e = &entry{key: key}
		e.elem = c.lru.PushFront(e)
		c.entries[key] = e
	}
	e.resolution = r
	e.creds = creds
	e.issuedAt = now
	// The fraction is of the usable lifetime, what is left before the
	// floor: with the defaults a one-hour session is refreshed 28 minutes
	// in, 12 minutes before it stops being served.
	usable := max(creds.Expiration.Sub(now)-c.opts.MinRemaining, 0)
	e.refreshAt = now.Add(time.Duration(c.opts.RefreshAt * float64(usable)))
	e.lastCheck = checkedAt
	e.refreshing = false
	c.lru.MoveToFront(e.elem)
	c.byWorkload[r.SourceIdentity] = e
	for len(c.entries) > c.opts.MaxEntries {
		c.remove(c.lru.Back().Value.(*entry))
		c.stats.Evictions++
	}
}

// remove drops an entry; the caller holds c.mu.
func (c *Cache) remove(e *entry) {
	delete(c.entries, e.key)
	c.lru.Remove(e.elem)
	if c.byWorkload[e.resolution.SourceIdentity] == e {
		delete(c.byWorkload, e.resolution.SourceIdentity)
	}
}

// refresh replaces the key's credentials in the background with the
// resolution of the hit that started it. Callers keep getting the old
// credentials until it completes; on failure they stay, and the next hit
// after RefreshRetry (with jitter) tries again.
func (c *Cache) refresh(ctx context.Context, r issuer.Resolution, key string, checkedAt time.Time) {
	ctx = context.WithoutCancel(ctx)
	_, err := c.assume(ctx, r, key, checkedAt)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		c.stats.Refreshes++
		c.opts.Log.LogAttrs(ctx, slog.LevelInfo, "refreshed cached credentials",
			slog.String("source_identity", r.SourceIdentity), slog.String("shape", r.Composed.Shape), slog.Any("grants", r.Composed.Grants))
		return
	}
	c.stats.RefreshFailures++
	c.opts.Log.LogAttrs(ctx, slog.LevelWarn, "refreshing cached credentials failed; serving the old ones",
		slog.String("source_identity", r.SourceIdentity), slog.String("shape", r.Composed.Shape), slog.String("error", err.Error()))
	if e, ok := c.entries[key]; ok {
		e.refreshing = false
		e.refreshAt = c.opts.Now().Add(c.opts.RefreshRetry + jitter(c.opts.RefreshRetry/2))
	}
}

// resolveFailed handles a resolution that did not succeed. A denial is a
// denial. A store that could not answer denies a new key and serves a held
// one within bounded staleness, unless the caller asked for a consistency
// the cache cannot vouch for.
func (c *Cache) resolveFailed(ctx context.Context, r issuer.Resolution, err error) (issuer.Issuance, error) {
	var deny *grants.DenyError
	if errors.As(err, &deny) || !errors.Is(err, issuer.ErrStore) || ctx.Err() != nil || issuer.ConsistencyFrom(ctx).AtLeastAsFresh != "" {
		return c.denied(err)
	}
	now := c.opts.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.byWorkload[r.SourceIdentity]
	if e == nil || e.resolution.BundleVersion != r.BundleVersion ||
		now.Sub(e.lastCheck) >= c.opts.StaleCheckMax || e.creds.Expiration.Sub(now) < c.opts.MinRemaining {
		c.stats.Denials++
		return issuer.Issuance{}, err
	}
	c.stats.Degraded++
	c.opts.Log.LogAttrs(ctx, slog.LevelWarn, "degraded: serving cached credentials with the authorization store unavailable",
		slog.String("spiffe_id", r.Identity.String()), slog.String("source_identity", r.SourceIdentity),
		slog.String("shape", e.resolution.Composed.Shape), slog.Any("grants", e.resolution.Composed.Grants),
		slog.Duration("since_last_check", now.Sub(e.lastCheck)), slog.String("error", err.Error()))
	return issuer.Issuance{Resolution: e.resolution, Credentials: e.creds, Cache: issuer.CacheHit}, nil
}

func (c *Cache) denied(err error) (issuer.Issuance, error) {
	c.mu.Lock()
	c.stats.Denials++
	c.mu.Unlock()
	return issuer.Issuance{}, err
}

// Run consumes the store's Watch stream until ctx ends, reconnecting with
// backoff when it fails; while it is down the cache reports TTL-only mode.
// It returns at once when the store has no Watch.
func (c *Cache) Run(ctx context.Context) {
	if c.watcher == nil {
		return
	}
	var since authz.Token
	backoff := time.Second
	for ctx.Err() == nil {
		token, err := c.watch(ctx, since)
		if token != "" {
			since = token
		}
		if ctx.Err() != nil {
			return
		}
		c.watchDown.Store(true)
		c.opts.Log.LogAttrs(ctx, slog.LevelWarn, "authorization store watch down; cache in ttl mode until it returns",
			slog.String("error", errString(err)), slog.Duration("retry_in", backoff))
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

// watch consumes one stream and returns the last token seen and why the
// stream ended.
func (c *Cache) watch(ctx context.Context, since authz.Token) (authz.Token, error) {
	ch, err := c.watcher.Watch(ctx, since)
	if err != nil {
		return "", err
	}
	if c.watchDown.Swap(false) {
		c.opts.Log.LogAttrs(ctx, slog.LevelInfo, "authorization store watch restored; cache in watch mode")
	}
	for change := range ch {
		c.Invalidate(change)
		if change.Token != "" {
			since = change.Token
		}
	}
	return since, errors.New("stream closed")
}

// Invalidate drops the entries a change touches: those of its subject (any
// subject when it names none) holding its grant (any grant when it names
// none). It logs what it dropped, so a flush from the Watch stream is
// visible in the broker's log.
func (c *Cache) Invalidate(change authz.Change) {
	c.mu.Lock()
	defer c.mu.Unlock()
	dropped := 0
	for _, e := range c.entries {
		if touches(change, e.resolution) {
			c.remove(e)
			c.stats.Invalidations++
			dropped++
		}
	}
	if dropped > 0 {
		c.opts.Log.LogAttrs(context.Background(), slog.LevelInfo, "invalidated cached credentials from the authorization store's watch",
			slog.Int("entries", dropped), slog.String("subject", change.Subject.ID), slog.String("grant", change.Grant))
	}
}

func touches(change authz.Change, r issuer.Resolution) bool {
	if change.Subject.ID != "" && change.Subject.ID != r.Subject.ID {
		return false
	}
	if change.Subject.Cluster != "" && change.Subject.Cluster != r.Subject.Cluster {
		return false
	}
	if change.Grant == "" {
		return true
	}
	for _, g := range r.Composed.Grants {
		if g == change.Grant {
			return true
		}
	}
	return false
}

// jitter is a random duration in [0, upTo), or zero when upTo is not
// positive.
func jitter(upTo time.Duration) time.Duration {
	if upTo <= 0 {
		return 0
	}
	return rand.N(upTo)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
