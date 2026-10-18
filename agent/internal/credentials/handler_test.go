package credentials

import (
	"context"
	"errors"
	"io"
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
