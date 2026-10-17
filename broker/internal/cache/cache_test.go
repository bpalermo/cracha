package cache

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bpalermo/cracha/broker/internal/authz"
	"github.com/bpalermo/cracha/broker/internal/grants"
	"github.com/bpalermo/cracha/broker/internal/issuer"
	"github.com/bpalermo/cracha/broker/internal/sts"
	"github.com/bpalermo/cracha/common/idenc"
)

const dynamoRole = "arn:aws:iam::111122223333:role/broker/shape-dynamo-rw"

var (
	ledger = idenc.Identity{TrustDomain: "example.org", Namespace: "payments", ServiceAccount: "ledger"}
	outbox = idenc.Identity{TrustDomain: "example.org", Namespace: "payments", ServiceAccount: "outbox"}
	refund = idenc.Identity{TrustDomain: "example.org", Namespace: "payments", ServiceAccount: "refund"}
)

// clock is the fake clock.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fakeStore answers the same decision for every subject, or fails.
type fakeStore struct {
	mu       sync.Mutex
	decision authz.Decision
	err      error
	lists    int
}

func (f *fakeStore) set(d authz.Decision, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.decision, f.err = d, err
}

func (f *fakeStore) ListGrants(context.Context, authz.Subject, authz.Consistency) (authz.Decision, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lists++
	return f.decision, f.err
}

func (f *fakeStore) Check(context.Context, authz.Subject, string, authz.Consistency) (authz.CheckResult, error) {
	return authz.CheckResult{}, errors.New("not used")
}

// watchStore is a fakeStore with the optional Watch.
type watchStore struct {
	fakeStore
	changes chan authz.Change
}

func (w *watchStore) Watch(context.Context, authz.Token) (<-chan authz.Change, error) {
	return w.changes, nil
}

// fakeSTS issues numbered credentials living ttl from the clock's now; it
// can be gated so calls block until the gate opens, or made to fail.
type fakeSTS struct {
	clock *clock
	ttl   time.Duration
	mu    sync.Mutex
	calls int
	err   error
	gate  chan struct{}
}

func (f *fakeSTS) AssumeRole(ctx context.Context, _ sts.Request) (sts.Credentials, error) {
	f.mu.Lock()
	f.calls++
	n, err, gate := f.calls, f.err, f.gate
	f.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return sts.Credentials{}, ctx.Err()
		}
	}
	if err != nil {
		return sts.Credentials{}, err
	}
	return sts.Credentials{AccessKeyID: fmt.Sprintf("AKIA%d", n), SecretAccessKey: "s", SessionToken: "t", Expiration: f.clock.Now().Add(f.ttl)}, nil
}

func (f *fakeSTS) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeSTS) fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

// hold gates the next calls; the returned function opens the gate.
func (f *fakeSTS) hold() func() {
	f.mu.Lock()
	defer f.mu.Unlock()
	gate := make(chan struct{})
	f.gate = gate
	return func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.gate == gate {
			f.gate = nil
		}
		close(gate)
	}
}

func grant(name string) grants.ResolvedGrant {
	return grants.ResolvedGrant{
		Name:            name,
		Account:         "111122223333",
		BaseRole:        dynamoRole,
		SessionPolicy:   `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"dynamodb:GetItem","Resource":"arn:aws:dynamodb:*:111122223333:table/` + name + `"}]}`,
		SessionTags:     map[string]string{"team": "payments"},
		DurationSeconds: 3600,
		Envelope:        []string{"arn:aws:dynamodb:*:111122223333:table/*"},
	}
}

func holding(names ...string) authz.Decision {
	return authz.Decision{Grants: names, Token: "t1", Tags: map[string]string{"service": "ledger"}}
}

// fixture is a cache over a real Direct issuer with a fake store and STS.
type fixture struct {
	clock *clock
	store *fakeStore
	sts   *fakeSTS
	cache *Cache
	logs  *bytes.Buffer
}

func newFixture(t *testing.T, store authz.Store, opts Options) *fixture {
	t.Helper()
	labels, err := idenc.NewLabels(map[string]string{"example.org": "prod"})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{clock: &clock{now: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)}, logs: &bytes.Buffer{}}
	switch s := store.(type) {
	case *fakeStore:
		f.store = s
	case *watchStore:
		f.store = &s.fakeStore
	}
	f.sts = &fakeSTS{clock: f.clock, ttl: time.Hour}
	log := slog.New(slog.NewJSONHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	direct := &issuer.Direct{
		Store:   store,
		Grants:  grants.NewStatic("bundle-7", grant("ledger"), grant("outbox")),
		STS:     f.sts,
		Labels:  labels,
		Cluster: "prod-a",
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	opts.Now = f.clock.Now
	opts.Log = log
	f.cache = New(direct, store, opts)
	return f
}

func (f *fixture) issue(t *testing.T, id idenc.Identity, want issuer.CacheOutcome, wantKey string) issuer.Issuance {
	t.Helper()
	iss, err := f.cache.Issue(context.Background(), id)
	if err != nil {
		t.Fatalf("issue %s: %v", id.ServiceAccount, err)
	}
	if iss.Cache != want || iss.Credentials.AccessKeyID != wantKey {
		t.Fatalf("issue %s: cache %q with %s, want %q with %s", id.ServiceAccount, iss.Cache, iss.Credentials.AccessKeyID, want, wantKey)
	}
	return iss
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestMissThenHit(t *testing.T) {
	f := newFixture(t, &fakeStore{decision: holding("ledger")}, Options{})
	iss := f.issue(t, ledger, issuer.CacheMiss, "AKIA1")
	if iss.Composed.Shape != "shape-dynamo-rw" || iss.SourceIdentity != "w.prod.payments.ledger" {
		t.Errorf("resolution %+v", iss.Resolution)
	}
	f.issue(t, ledger, issuer.CacheHit, "AKIA1")
	f.issue(t, ledger, issuer.CacheHit, "AKIA1")
	if f.sts.count() != 1 {
		t.Errorf("STS called %d times, want 1", f.sts.count())
	}
	if s := f.cache.Stats(); s.Hits != 2 || s.Misses != 1 || s.Entries != 1 {
		t.Errorf("stats %+v", s)
	}
	// Every issuance, hits included, resolved against the store.
	if f.store.lists != 3 {
		t.Errorf("store consulted %d times, want 3", f.store.lists)
	}
	if f.cache.Mode() != ModeTTL {
		t.Errorf("mode %q, want ttl without a Watcher", f.cache.Mode())
	}
}

func TestHitRechecksStore(t *testing.T) {
	f := newFixture(t, &fakeStore{decision: holding("ledger")}, Options{})
	f.issue(t, ledger, issuer.CacheMiss, "AKIA1")

	f.store.set(authz.Decision{Token: "t2"}, nil)
	_, err := f.cache.Issue(context.Background(), ledger)
	var deny *grants.DenyError
	if !errors.As(err, &deny) || deny.Reason != grants.ReasonNoGrant {
		t.Fatalf("store revoked the grant, got %v, want no_grant", err)
	}

	f.store.set(authz.Decision{}, authz.ErrSubjectSuspended)
	_, err = f.cache.Issue(context.Background(), ledger)
	if !errors.As(err, &deny) || deny.Reason != grants.ReasonSubjectSuspended {
		t.Fatalf("store suspended the subject, got %v, want subject_suspended", err)
	}
	if f.sts.count() != 1 {
		t.Errorf("STS called %d times, want 1", f.sts.count())
	}
	if s := f.cache.Stats(); s.Denials != 2 || s.Hits != 0 {
		t.Errorf("stats %+v", s)
	}

	// A changed grant set is a new key: the cached session is not reused.
	f.store.set(holding("ledger", "outbox"), nil)
	iss := f.issue(t, ledger, issuer.CacheMiss, "AKIA2")
	if strings.Join(iss.Composed.Grants, ",") != "ledger,outbox" {
		t.Errorf("grants %v", iss.Composed.Grants)
	}
	f.store.set(holding("ledger"), nil)
	f.issue(t, ledger, issuer.CacheHit, "AKIA1")
}

func TestMinRemainingForcesNewIssue(t *testing.T) {
	f := newFixture(t, &fakeStore{decision: holding("ledger")}, Options{MinRemaining: 20 * time.Minute, RefreshAt: 0.9})
	f.issue(t, ledger, issuer.CacheMiss, "AKIA1")
	f.clock.Advance(35 * time.Minute)
	f.issue(t, ledger, issuer.CacheHit, "AKIA1")
	f.clock.Advance(6 * time.Minute)
	// 19 minutes left: under the floor, so a new session, never the old one.
	iss := f.issue(t, ledger, issuer.CacheMiss, "AKIA2")
	if remaining := iss.Credentials.Expiration.Sub(f.clock.Now()); remaining != time.Hour {
		t.Errorf("new credentials have %v left, want 1h", remaining)
	}
	if s := f.cache.Stats(); s.Misses != 2 || s.Entries != 1 {
		t.Errorf("stats %+v", s)
	}
}

func TestRefreshAhead(t *testing.T) {
	f := newFixture(t, &fakeStore{decision: holding("ledger")}, Options{RefreshAt: 0.7})
	f.issue(t, ledger, issuer.CacheMiss, "AKIA1")
	f.clock.Advance(27 * time.Minute)
	f.issue(t, ledger, issuer.CacheHit, "AKIA1")

	release := f.sts.hold()
	f.clock.Advance(time.Minute)
	// 70% of the usable 40 minutes has passed: the hit starts a refresh and
	// serves the old credentials; so do the hits while it is in flight.
	f.issue(t, ledger, issuer.CacheRefresh, "AKIA1")
	eventually(t, "the refresh to reach STS", func() bool { return f.sts.count() == 2 })
	f.issue(t, ledger, issuer.CacheHit, "AKIA1")
	f.issue(t, ledger, issuer.CacheHit, "AKIA1")
	if f.sts.count() != 2 {
		t.Fatalf("STS called %d times, want 2: one refresh", f.sts.count())
	}
	release()
	eventually(t, "the refresh to complete", func() bool { return f.cache.Stats().Refreshes == 1 })
	f.issue(t, ledger, issuer.CacheHit, "AKIA2")
	if f.sts.count() != 2 {
		t.Errorf("STS called %d times, want 2", f.sts.count())
	}
}

func TestRefreshFailureKeepsOldCredentials(t *testing.T) {
	f := newFixture(t, &fakeStore{decision: holding("ledger")}, Options{RefreshAt: 0.7, RefreshRetry: time.Minute})
	f.issue(t, ledger, issuer.CacheMiss, "AKIA1")
	f.sts.fail(errors.New("throttled"))
	f.clock.Advance(28 * time.Minute)
	f.issue(t, ledger, issuer.CacheRefresh, "AKIA1")
	eventually(t, "the refresh to fail", func() bool { return f.cache.Stats().RefreshFailures == 1 })
	// Not retried before RefreshRetry (plus up to half as much jitter).
	f.clock.Advance(30 * time.Second)
	f.issue(t, ledger, issuer.CacheHit, "AKIA1")
	if f.sts.count() != 2 {
		t.Errorf("STS called %d times, want 2", f.sts.count())
	}
	f.sts.fail(nil)
	f.clock.Advance(2 * time.Minute)
	f.issue(t, ledger, issuer.CacheRefresh, "AKIA1")
	eventually(t, "the retried refresh", func() bool { return f.cache.Stats().Refreshes == 1 })
	f.issue(t, ledger, issuer.CacheHit, "AKIA3")
}

func TestSingleflight(t *testing.T) {
	f := newFixture(t, &fakeStore{decision: holding("ledger")}, Options{})
	release := f.sts.hold()
	const n = 25
	var wg sync.WaitGroup
	results := make([]issuer.Issuance, n)
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = f.cache.Issue(context.Background(), ledger)
		}()
	}
	eventually(t, "the first caller to reach STS", func() bool { return f.sts.count() == 1 })
	// Give the others time to pile up behind it before it answers.
	time.Sleep(20 * time.Millisecond)
	release()
	wg.Wait()
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("caller %d: %v", i, errs[i])
		}
		if results[i].Credentials.AccessKeyID != "AKIA1" {
			t.Errorf("caller %d got %s", i, results[i].Credentials.AccessKeyID)
		}
	}
	if f.sts.count() != 1 {
		t.Errorf("STS called %d times for %d concurrent callers, want 1", f.sts.count(), n)
	}
	if s := f.cache.Stats(); s.Hits+s.Misses != n || s.Misses < 1 {
		t.Errorf("stats %+v", s)
	}
}

func TestMissSurvivesCallerCancellation(t *testing.T) {
	f := newFixture(t, &fakeStore{decision: holding("ledger")}, Options{})
	release := f.sts.hold()
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() {
		_, err := f.cache.Issue(ctx, ledger)
		first <- err
	}()
	eventually(t, "the first caller to reach STS", func() bool { return f.sts.count() == 1 })
	second := make(chan issuer.Issuance, 1)
	go func() {
		iss, _ := f.cache.Issue(context.Background(), ledger)
		second <- iss
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	release()
	if err := <-first; err != nil {
		t.Errorf("the cancelled caller got %v; the STS call runs detached", err)
	}
	if iss := <-second; iss.Credentials.AccessKeyID != "AKIA1" {
		t.Errorf("second caller got %+v", iss.Credentials)
	}
}

func TestStoreUnavailable(t *testing.T) {
	f := newFixture(t, &fakeStore{decision: holding("ledger")}, Options{StaleCheckMax: 10 * time.Minute})
	down := errors.New("connection refused")

	// A miss with the store down is a denial, never an STS call.
	f.store.set(authz.Decision{}, down)
	_, err := f.cache.Issue(context.Background(), ledger)
	if !errors.Is(err, issuer.ErrStore) || !errors.Is(err, down) {
		t.Fatalf("got %v, want the store's error", err)
	}
	if f.sts.count() != 0 {
		t.Fatal("STS was called with the store down")
	}

	f.store.set(holding("ledger"), nil)
	f.issue(t, ledger, issuer.CacheMiss, "AKIA1")
	f.clock.Advance(5 * time.Minute)
	f.issue(t, ledger, issuer.CacheHit, "AKIA1")

	// A hit checked less than StaleCheckMax ago is served, as degraded.
	f.store.set(authz.Decision{}, down)
	f.clock.Advance(9 * time.Minute)
	iss := f.issue(t, ledger, issuer.CacheHit, "AKIA1")
	if iss.Composed.Shape != "shape-dynamo-rw" || iss.Decision.Token != "t1" {
		t.Errorf("degraded hit carries %+v, want the cached resolution", iss.Resolution)
	}
	if !strings.Contains(f.logs.String(), "degraded") {
		t.Errorf("degraded hit not logged: %s", f.logs.String())
	}
	// A caller asking at-least-as-fresh gets no stale answer.
	ctx := issuer.WithConsistency(context.Background(), authz.Consistency{AtLeastAsFresh: "t1"})
	if _, err := f.cache.Issue(ctx, ledger); !errors.Is(err, down) {
		t.Errorf("at-least-as-fresh with the store down got %v, want a denial", err)
	}
	// Past StaleCheckMax since the last successful check, it is refused.
	f.clock.Advance(time.Minute)
	if _, err := f.cache.Issue(context.Background(), ledger); !errors.Is(err, down) {
		t.Errorf("stale hit got %v, want a denial", err)
	}
	// Another workload, never issued, is refused.
	if _, err := f.cache.Issue(context.Background(), outbox); !errors.Is(err, down) {
		t.Errorf("new key with the store down got %v, want a denial", err)
	}
	if s := f.cache.Stats(); s.Degraded != 1 || s.Denials != 4 || s.Hits != 1 {
		t.Errorf("stats %+v", s)
	}
	if f.sts.count() != 1 {
		t.Errorf("STS called %d times, want 1", f.sts.count())
	}
}

func TestWatchInvalidates(t *testing.T) {
	store := &watchStore{fakeStore: fakeStore{decision: holding("ledger")}, changes: make(chan authz.Change)}
	f := newFixture(t, store, Options{})
	if f.cache.Mode() != ModeWatch {
		t.Fatalf("mode %q, want watch", f.cache.Mode())
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		f.cache.Run(ctx)
		close(done)
	}()

	f.issue(t, ledger, issuer.CacheMiss, "AKIA1")
	f.issue(t, outbox, issuer.CacheMiss, "AKIA2")
	res, err := f.cache.Resolve(ctx, ledger)
	if err != nil {
		t.Fatal(err)
	}

	// A change to another grant of the subject touches nothing of ours.
	store.changes <- authz.Change{Subject: res.Subject, Grant: "other", Token: "t2"}
	// One to the subject's grant drops its entry and nobody else's.
	store.changes <- authz.Change{Subject: res.Subject, Grant: "ledger", Token: "t3"}
	eventually(t, "the invalidation", func() bool { return f.cache.Stats().Invalidations == 1 })
	f.issue(t, outbox, issuer.CacheHit, "AKIA2")
	f.issue(t, ledger, issuer.CacheMiss, "AKIA3")

	// A change naming no subject touches every entry holding the grant.
	store.changes <- authz.Change{Grant: "ledger", Token: "t4"}
	eventually(t, "the broad invalidation", func() bool { return f.cache.Stats().Invalidations == 3 })
	if s := f.cache.Stats(); s.Entries != 0 {
		t.Errorf("stats %+v", s)
	}

	// The stream failing puts the cache in TTL mode until it is back.
	close(store.changes)
	eventually(t, "ttl mode", func() bool { return f.cache.Mode() == ModeTTL })
	cancel()
	<-done
}

func TestLRUBound(t *testing.T) {
	f := newFixture(t, &fakeStore{decision: holding("ledger")}, Options{MaxEntries: 2})
	f.issue(t, ledger, issuer.CacheMiss, "AKIA1")
	f.issue(t, outbox, issuer.CacheMiss, "AKIA2")
	f.issue(t, refund, issuer.CacheMiss, "AKIA3")
	if s := f.cache.Stats(); s.Entries != 2 || s.Evictions != 1 {
		t.Fatalf("stats %+v", s)
	}
	// ledger, the least recently used, went; its return evicts outbox.
	f.issue(t, ledger, issuer.CacheMiss, "AKIA4")
	f.issue(t, refund, issuer.CacheHit, "AKIA3")
	f.issue(t, outbox, issuer.CacheMiss, "AKIA5")
	if s := f.cache.Stats(); s.Entries != 2 || s.Evictions != 3 {
		t.Errorf("stats %+v", s)
	}
}

func TestKey(t *testing.T) {
	a := issuer.Resolution{SourceIdentity: "w.prod.payments.ledger", BundleVersion: "b1", Composed: grants.Composed{Shape: "s", Grants: []string{"y", "x"}}}
	b := a
	b.Composed.Grants = []string{"x", "y"}
	if keyOf(a) != keyOf(b) {
		t.Error("grant order changed the key")
	}
	for _, change := range []func(*issuer.Resolution){
		func(r *issuer.Resolution) { r.BundleVersion = "b2" },
		func(r *issuer.Resolution) { r.SourceIdentity = "w.prod.payments.outbox" },
		func(r *issuer.Resolution) { r.Composed.Shape = "t" },
		func(r *issuer.Resolution) { r.Composed.Grants = []string{"x"} },
	} {
		c := a
		change(&c)
		if keyOf(c) == keyOf(a) {
			t.Errorf("change left the key %q", keyOf(c))
		}
	}
}
