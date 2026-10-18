package credentials

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bpalermo/cracha/agent/internal/issuer"
	"github.com/bpalermo/cracha/agent/internal/jwttest"
	"github.com/bpalermo/cracha/agent/internal/listener"
)

var pod = listener.Pod{Namespace: "apps", Name: "api-1", UID: "uid-1"}

// fakeBroker is a Relay answering from a canned response and recording what
// it was asked.
type fakeBroker struct {
	mu     sync.Mutex
	status int
	header http.Header
	body   string
	err    error
	calls  []call
	block  chan struct{} // when set, Get waits on it
}

type call struct{ path, token string }

func (b *fakeBroker) Get(ctx context.Context, path, token string) (*http.Response, error) {
	b.mu.Lock()
	b.calls = append(b.calls, call{path, token})
	block := b.block
	b.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if b.err != nil {
		return nil, b.err
	}
	rec := httptest.NewRecorder()
	for k, v := range b.header {
		rec.Header()[k] = v
	}
	rec.WriteHeader(b.status)
	io.WriteString(rec, b.body)
	return rec.Result(), nil
}

func (b *fakeBroker) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.calls)
}

func token(exp time.Time) string {
	return jwttest.Mint(jwttest.Claims{Subject: "spiffe://cracha.test/ns/apps/sa/api", Audience: []string{"cracha-broker"}, Expiry: exp})
}

// do sends a GET for path on pod's connection.
func do(h http.Handler, p listener.Pod, method, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req = req.WithContext(listener.WithPod(req.Context(), p))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRelaysTheBrokersAnswer(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	iss := issuer.NewFake(issuer.Result{Token: token(exp), Expiry: exp})
	broker := &fakeBroker{
		status: http.StatusOK,
		header: http.Header{
			"Content-Type":          {"application/json"},
			"Cracha-Shape":          {"shape-s3-reader"},
			"Cracha-Grants":         {"a, b"},
			"Cracha-Cache":          {"hit"},
			"Cracha-Bundle-Version": {"v1"},
			"X-Internal":            {"secret"},
		},
		body: `{"AccessKeyId":"AKIA"}`,
	}
	h := New(iss, broker, Config{})

	rec := do(h, pod, http.MethodGet, CredentialsPath)
	if rec.Code != http.StatusOK || rec.Body.String() != `{"AccessKeyId":"AKIA"}` {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	for name, want := range map[string]string{
		"Cracha-Shape": "shape-s3-reader", "Cracha-Grants": "a, b", "Cracha-Cache": "hit",
		"Cracha-Bundle-Version": "v1", "Content-Type": "application/json", "X-Internal": "", HeaderReason: "",
	} {
		if got := rec.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	calls := iss.Calls()
	if len(calls) != 1 || calls[0].Ref != (issuer.PodRef{Namespace: "apps", Name: "api-1", UID: "uid-1"}) || calls[0].Audience != DefaultAudience {
		t.Errorf("issuer calls = %+v", calls)
	}
	if broker.calls[0] != (call{CredentialsPath, token(exp)}) {
		t.Errorf("broker call = %+v", broker.calls[0])
	}

	// /v1/grants goes the same way; the broker's status comes back as it is.
	broker.status = http.StatusForbidden
	broker.body = `{"reason":"no_grant"}`
	rec = do(h, pod, http.MethodGet, GrantsPath)
	if rec.Code != http.StatusForbidden || rec.Body.String() != `{"reason":"no_grant"}` {
		t.Fatalf("grants: got %d %q", rec.Code, rec.Body.String())
	}
	if broker.calls[1].path != GrantsPath {
		t.Errorf("broker path = %q", broker.calls[1].path)
	}
}

func TestTokenIsReusedUntilNearExpiry(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	clock := now
	exp := now.Add(10 * time.Minute)
	later := now.Add(time.Hour)
	iss := issuer.NewFake(
		issuer.Result{Token: token(exp), Expiry: exp},
		issuer.Result{Token: token(later), Expiry: later},
	)
	broker := &fakeBroker{status: http.StatusOK, body: "{}"}
	h := New(iss, broker, Config{Now: func() time.Time { return clock }})

	for range 3 {
		if rec := do(h, pod, http.MethodGet, CredentialsPath); rec.Code != http.StatusOK {
			t.Fatal(rec.Code)
		}
	}
	if n := len(iss.Calls()); n != 1 {
		t.Fatalf("the token was fetched %d times for 3 requests", n)
	}
	if broker.calls[2].token != token(exp) {
		t.Error("the cached token was not reused")
	}
	// Within a minute of expiry: fetched again.
	clock = exp.Add(-30 * time.Second)
	if rec := do(h, pod, http.MethodGet, CredentialsPath); rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	if n := len(iss.Calls()); n != 2 {
		t.Fatalf("the token was fetched %d times, want a refresh near expiry", n)
	}
	if broker.calls[3].token != token(later) {
		t.Error("the broker was not given the fresh token")
	}
	// Dropped with the pod.
	h.Forget(pod)
	do(h, pod, http.MethodGet, CredentialsPath)
	if n := len(iss.Calls()); n != 3 {
		t.Fatalf("the token survived Forget (%d fetches)", n)
	}
	// Another pod has its own.
	other := listener.Pod{Namespace: "apps", Name: "api-2", UID: "uid-2"}
	do(h, other, http.MethodGet, CredentialsPath)
	if n := len(iss.Calls()); n != 4 || iss.Calls()[3].Ref.UID != "uid-2" {
		t.Fatalf("calls = %+v", iss.Calls())
	}
}

func TestConcurrentRequestsShareOneFetch(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	iss := &blockingIssuer{inner: issuer.NewFake(issuer.Result{Token: token(exp), Expiry: exp}), release: make(chan struct{})}
	h := New(iss, &fakeBroker{status: http.StatusOK}, Config{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rec := do(h, pod, http.MethodGet, CredentialsPath); rec.Code != http.StatusOK {
				t.Errorf("status = %d", rec.Code)
			}
		}()
	}
	deadline := time.Now().Add(2 * time.Second)
	for iss.waiting.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond) // let the others reach the fetch
	close(iss.release)
	wg.Wait()
	if n := len(iss.inner.Calls()); n != 1 {
		t.Fatalf("4 concurrent requests fetched the token %d times, want once", n)
	}
}

// blockingIssuer holds every fetch until release is closed.
type blockingIssuer struct {
	inner   *issuer.Fake
	release chan struct{}
	waiting atomic.Int32
}

func (b *blockingIssuer) FetchJWTSVID(ctx context.Context, ref issuer.PodRef, audience string) (string, time.Time, error) {
	b.waiting.Add(1)
	<-b.release
	return b.inner.FetchJWTSVID(ctx, ref, audience)
}

func TestIssuerFailuresAre503WithAReason(t *testing.T) {
	for name, tc := range map[string]struct {
		err    error
		reason string
	}{
		"not found yet":     {issuer.NewError(issuer.NotFoundYet, errors.New("no entry")), ReasonIssuerNotReady},
		"unavailable":       {issuer.NewError(issuer.Unavailable, errors.New("down")), ReasonIssuerUnavailable},
		"permission denied": {issuer.NewError(issuer.PermissionDenied, errors.New("rbac")), ReasonIssuerRefused},
		"permanent":         {errors.New("what"), ReasonIssuerRefused},
	} {
		t.Run(name, func(t *testing.T) {
			broker := &fakeBroker{status: http.StatusOK}
			h := New(issuer.NewFake(issuer.Result{Err: tc.err}), broker, Config{})
			rec := do(h, pod, http.MethodGet, CredentialsPath)
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d", rec.Code)
			}
			if got := rec.Header().Get(HeaderReason); got != tc.reason {
				t.Errorf("%s = %q, want %q", HeaderReason, got, tc.reason)
			}
			if !strings.Contains(rec.Body.String(), tc.reason) {
				t.Errorf("body = %q", rec.Body.String())
			}
			if broker.count() != 0 {
				t.Error("the broker was called without a token")
			}
		})
	}
	// An unreadable token from the issuer is refused too, never relayed.
	exp := time.Now().Add(time.Hour)
	broker := &fakeBroker{status: http.StatusOK}
	h := New(issuer.NewFake(issuer.Result{Token: "garbage", Expiry: exp}), broker, Config{})
	if rec := do(h, pod, http.MethodGet, CredentialsPath); rec.Code != http.StatusServiceUnavailable || rec.Header().Get(HeaderReason) != ReasonIssuerRefused {
		t.Fatalf("garbage token: %d %q", rec.Code, rec.Header().Get(HeaderReason))
	}
	if broker.count() != 0 {
		t.Error("the broker was given an unreadable token")
	}
}

func TestBrokerUnavailableIs503(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	h := New(issuer.NewFake(issuer.Result{Token: token(exp), Expiry: exp}), &fakeBroker{err: errors.New("dial tcp: refused")}, Config{})
	rec := do(h, pod, http.MethodGet, CredentialsPath)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get(HeaderReason) != ReasonBrokerUnavailable {
		t.Fatalf("got %d %q", rec.Code, rec.Header().Get(HeaderReason))
	}
}

func TestOnlyTheTwoGetsAreServed(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	iss := issuer.NewFake(issuer.Result{Token: token(exp), Expiry: exp})
	broker := &fakeBroker{status: http.StatusOK}
	h := New(iss, broker, Config{})
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, CredentialsPath},
		{http.MethodGet, "/v1/other"},
		{http.MethodGet, "/"},
		{http.MethodGet, "/v1/credentials/"},
		{http.MethodDelete, GrantsPath},
	} {
		if rec := do(h, pod, tc.method, tc.path); rec.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404", tc.method, tc.path, rec.Code)
		}
	}
	if broker.count() != 0 || len(iss.Calls()) != 0 {
		t.Error("an unserved request reached the issuer or the broker")
	}
}

func TestARequestWithoutAPodIsAnError(t *testing.T) {
	h := New(issuer.NewFake(), &fakeBroker{}, Config{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, CredentialsPath, nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestPerPodBound(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	broker := &fakeBroker{status: http.StatusOK, block: make(chan struct{})}
	h := New(issuer.NewFake(issuer.Result{Token: token(exp), Expiry: exp}), broker, Config{PerPodLimit: 2})

	var wg sync.WaitGroup
	results := make(chan int, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- do(h, pod, http.MethodGet, CredentialsPath).Code
		}()
	}
	// Both are in flight at the broker.
	deadline := time.Now().Add(2 * time.Second)
	for broker.count() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if broker.count() != 2 {
		t.Fatalf("%d requests reached the broker, want 2", broker.count())
	}
	// A third for the same pod is refused; another pod's is not.
	if rec := do(h, pod, http.MethodGet, CredentialsPath); rec.Code != http.StatusTooManyRequests || rec.Header().Get(HeaderReason) != ReasonPodBusy {
		t.Errorf("third request: %d %q", rec.Code, rec.Header().Get(HeaderReason))
	}
	other := listener.Pod{Namespace: "apps", Name: "api-2", UID: "uid-2"}
	otherDone := make(chan int, 1)
	go func() { otherDone <- do(h, other, http.MethodGet, CredentialsPath).Code }()
	for broker.count() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if broker.count() != 3 {
		t.Errorf("the other pod's request was held back by the first pod's bound")
	}
	close(broker.block)
	wg.Wait()
	close(results)
	for code := range results {
		if code != http.StatusOK {
			t.Errorf("an in-flight request ended %d", code)
		}
	}
	if code := <-otherDone; code != http.StatusOK {
		t.Errorf("the other pod's request ended %d", code)
	}
	// The slots are free again.
	if rec := do(h, pod, http.MethodGet, CredentialsPath); rec.Code != http.StatusOK {
		t.Errorf("after release: %d", rec.Code)
	}
}

// logBuffer is a logger whose lines a test reads back.
type logBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func (l *logBuffer) logger() *slog.Logger { return slog.New(slog.NewTextHandler(l, nil)) }

func waitDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	if done == nil {
		t.Fatal("no prewarm was started")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the prewarm did not finish")
	}
}

// A prewarm takes the first request's path once: one fetch, one broker call
// for the credentials, with the pod's token. The app's request then reuses
// the token and still calls the broker: the prewarm's answer was not kept.
func TestPrewarmWarmsTheTokenAndTheBrokerButKeepsNoCredentials(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	requests := issuer.NewFake(issuer.Result{Err: errors.New("the request issuer was used")})
	prewarm := issuer.NewFake(issuer.Result{Token: token(exp), Expiry: exp})
	broker := &fakeBroker{status: http.StatusOK, header: http.Header{"Cracha-Cache": {"miss"}}, body: `{"AccessKeyId":"FIRST"}`}
	var logs logBuffer
	h := New(requests, broker, Config{PrewarmIssuer: prewarm, Logger: logs.logger()})
	defer h.Close()

	waitDone(t, h.startPrewarm(pod))
	if n := len(prewarm.Calls()); n != 1 {
		t.Fatalf("the prewarm fetched %d times, want once", n)
	}
	if broker.count() != 1 || broker.calls[0] != (call{CredentialsPath, token(exp)}) {
		t.Fatalf("broker calls = %+v, want one for the credentials", broker.calls)
	}
	if !strings.Contains(logs.String(), "msg=prewarm") || !strings.Contains(logs.String(), "cache=miss") {
		t.Errorf("the prewarm was not logged with the broker's cache outcome: %s", logs.String())
	}

	broker.mu.Lock()
	broker.header, broker.body = http.Header{"Cracha-Cache": {"hit"}}, `{"AccessKeyId":"SECOND"}`
	broker.mu.Unlock()
	rec := do(h, pod, http.MethodGet, CredentialsPath)
	if rec.Code != http.StatusOK || rec.Body.String() != `{"AccessKeyId":"SECOND"}` || rec.Header().Get("Cracha-Cache") != "hit" {
		t.Fatalf("the app's request got %d %q %q: not the broker's answer of now", rec.Code, rec.Body.String(), rec.Header().Get("Cracha-Cache"))
	}
	if broker.count() != 2 {
		t.Fatalf("the app's request did not reach the broker (%d calls): the prewarm's answer was cached", broker.count())
	}
	if len(requests.Calls()) != 0 || len(prewarm.Calls()) != 1 {
		t.Errorf("the app's request fetched again: request issuer %d, prewarm issuer %d", len(requests.Calls()), len(prewarm.Calls()))
	}
}

// An app request arriving while the prewarm's fetch is in flight joins it.
func TestARequestDuringAPrewarmJoinsItsFetch(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	requests := issuer.NewFake(issuer.Result{Err: errors.New("the request issuer was used")})
	prewarm := &blockingIssuer{inner: issuer.NewFake(issuer.Result{Token: token(exp), Expiry: exp}), release: make(chan struct{})}
	broker := &fakeBroker{status: http.StatusOK, body: "{}"}
	h := New(requests, broker, Config{PrewarmIssuer: prewarm, Logger: slog.New(slog.DiscardHandler)})
	defer h.Close()

	done := h.startPrewarm(pod)
	deadline := time.Now().Add(2 * time.Second)
	for prewarm.waiting.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	got := make(chan int, 1)
	go func() { got <- do(h, pod, http.MethodGet, CredentialsPath).Code }()
	time.Sleep(50 * time.Millisecond) // let the request reach the fetch
	close(prewarm.release)
	if code := <-got; code != http.StatusOK {
		t.Fatalf("the joined request ended %d", code)
	}
	waitDone(t, done)
	if n := len(prewarm.inner.Calls()); n != 1 || len(requests.Calls()) != 0 {
		t.Fatalf("fetches: prewarm %d, request %d; want the request to join the prewarm's one", n, len(requests.Calls()))
	}
	if broker.count() != 2 {
		t.Errorf("broker calls = %d, want the prewarm's and the request's", broker.count())
	}
}

// A request does not wait for a prewarm's longer fetch beyond its own
// deadline: it answers 503 issuer_not_ready, as its own fetch would have.
func TestARequestWaitsForAPrewarmNoLongerThanItsDeadline(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	prewarm := &blockingIssuer{inner: issuer.NewFake(issuer.Result{Token: token(exp), Expiry: exp}), release: make(chan struct{})}
	h := New(issuer.NewFake(), &fakeBroker{status: http.StatusOK}, Config{
		PrewarmIssuer: prewarm, FetchDeadline: 50 * time.Millisecond, Logger: slog.New(slog.DiscardHandler),
	})
	defer h.Close()
	done := h.startPrewarm(pod)
	deadline := time.Now().Add(2 * time.Second)
	for prewarm.waiting.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	start := time.Now()
	rec := do(h, pod, http.MethodGet, CredentialsPath)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get(HeaderReason) != ReasonIssuerNotReady {
		t.Fatalf("got %d %q, want 503 %s", rec.Code, rec.Header().Get(HeaderReason), ReasonIssuerNotReady)
	}
	if waited := time.Since(start); waited > 2*time.Second {
		t.Errorf("the request waited %s", waited)
	}
	close(prewarm.release)
	waitDone(t, done)
}

// A failed prewarm is a log line and nothing else: nothing is cached, and
// the app's request takes the whole path itself.
func TestPrewarmFailureIsSilent(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	for name, tc := range map[string]struct {
		prewarm     *issuer.Fake
		broker      *fakeBroker
		brokerCalls int // after the app's request
		fetches     int // by the request issuer
	}{
		"issuer": {
			prewarm: issuer.NewFake(issuer.Result{Err: issuer.NewError(issuer.NotFoundYet, errors.New("no entry"))}),
			broker:  &fakeBroker{status: http.StatusOK}, brokerCalls: 1, fetches: 1,
		},
		"broker unreachable": {
			prewarm: issuer.NewFake(issuer.Result{Token: token(exp), Expiry: exp}),
			broker:  &fakeBroker{err: errors.New("dial tcp: refused")}, brokerCalls: 2, fetches: 0,
		},
		"broker refuses": {
			prewarm: issuer.NewFake(issuer.Result{Token: token(exp), Expiry: exp}),
			broker:  &fakeBroker{status: http.StatusForbidden, body: `{"reason":"no_grant"}`}, brokerCalls: 2, fetches: 0,
		},
	} {
		t.Run(name, func(t *testing.T) {
			requests := issuer.NewFake(issuer.Result{Token: token(exp), Expiry: exp})
			var logs logBuffer
			h := New(requests, tc.broker, Config{PrewarmIssuer: tc.prewarm, Logger: logs.logger()})
			defer h.Close()
			waitDone(t, h.startPrewarm(pod))
			if !strings.Contains(logs.String(), "prewarm failed") {
				t.Errorf("the failure was not logged: %s", logs.String())
			}
			rec := do(h, pod, http.MethodGet, CredentialsPath)
			if rec.Code != tc.broker.status && tc.broker.err == nil {
				t.Errorf("the app's request got %d, want the broker's %d", rec.Code, tc.broker.status)
			}
			if tc.broker.count() != tc.brokerCalls || len(requests.Calls()) != tc.fetches {
				t.Errorf("after the app's request: broker %d calls (want %d), request fetches %d (want %d)",
					tc.broker.count(), tc.brokerCalls, len(requests.Calls()), tc.fetches)
			}
		})
	}
}

// Forget stops a prewarm, and a fetch that finishes afterwards leaves no
// token behind for the pod that is gone.
func TestForgetStopsAPrewarm(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	prewarm := &blockingIssuer{inner: issuer.NewFake(issuer.Result{Token: token(exp), Expiry: exp}), release: make(chan struct{})}
	requests := issuer.NewFake(issuer.Result{Token: token(exp), Expiry: exp})
	broker := &fakeBroker{status: http.StatusOK}
	h := New(requests, broker, Config{PrewarmIssuer: prewarm, Logger: slog.New(slog.DiscardHandler)})
	defer h.Close()
	done := h.startPrewarm(pod)
	deadline := time.Now().Add(2 * time.Second)
	for prewarm.waiting.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	h.Forget(pod)
	close(prewarm.release)
	waitDone(t, done)
	if broker.count() != 0 {
		t.Error("a forgotten pod's prewarm called the broker")
	}
	do(h, pod, http.MethodGet, CredentialsPath)
	if len(requests.Calls()) != 1 {
		t.Error("the forgotten pod's prewarmed token was kept")
	}
}

func TestPrewarmOff(t *testing.T) {
	iss := issuer.NewFake()
	broker := &fakeBroker{}
	h := New(iss, broker, Config{})
	defer h.Close()
	if done := h.startPrewarm(pod); done != nil {
		t.Fatal("a prewarm started without a prewarm issuer")
	}
	h.Prewarm(pod)
	if len(iss.Calls()) != 0 || broker.count() != 0 {
		t.Error("prewarm off reached the issuer or the broker")
	}
}
