package issuer

import (
	"context"
	"errors"
	"testing"
	"time"
)

var testRef = PodRef{Namespace: "ns", Name: "pod", UID: "uid"}

// newTestRetrying returns a retrying issuer whose waits are recorded instead
// of slept.
func newTestRetrying(inner Issuer, policy RetryPolicy) (*retrying, *[]time.Duration) {
	var waits []time.Duration
	r := WithRetry(inner, policy, nil).(*retrying)
	r.sleep = func(ctx context.Context, d time.Duration) error {
		waits = append(waits, d)
		return ctx.Err()
	}
	return r, &waits
}

func TestRetryNotFoundThenSuccess(t *testing.T) {
	exp := time.Now().Add(time.Minute)
	fake := NewFake(
		Result{Err: NewError(NotFoundYet, errors.New("no entry"))},
		Result{Err: NewError(Unavailable, errors.New("agent restarting"))},
		Result{Token: "tok", Expiry: exp},
	)
	r, waits := newTestRetrying(fake, RetryPolicy{Initial: 100 * time.Millisecond, Max: time.Second, Jitter: 0.1})

	token, expiry, err := r.FetchJWTSVID(context.Background(), testRef, "aud")
	if err != nil {
		t.Fatalf("FetchJWTSVID: %v", err)
	}
	if token != "tok" || !expiry.Equal(exp) {
		t.Fatalf("got (%q, %v), want (tok, %v)", token, expiry, exp)
	}
	if n := len(fake.Calls()); n != 3 {
		t.Fatalf("got %d calls, want 3", n)
	}
	if len(*waits) != 2 {
		t.Fatalf("got %d waits, want 2: %v", len(*waits), *waits)
	}
	// Second wait doubles the first, within the jitter.
	if w := (*waits)[0]; w < 90*time.Millisecond || w > 110*time.Millisecond {
		t.Errorf("first wait %v outside 100ms ±10%%", w)
	}
	if w := (*waits)[1]; w < 180*time.Millisecond || w > 220*time.Millisecond {
		t.Errorf("second wait %v outside 200ms ±10%%", w)
	}
}

func TestRetryFailsPermanentAtOnce(t *testing.T) {
	for _, kind := range []Kind{PermissionDenied, Permanent} {
		fake := NewFake(Result{Err: NewError(kind, errors.New("refused"))})
		r, waits := newTestRetrying(fake, RetryPolicy{})
		_, _, err := r.FetchJWTSVID(context.Background(), testRef, "aud")
		if Classify(err) != kind {
			t.Fatalf("%s: got %v, want kind %s", kind, err, kind)
		}
		if n := len(fake.Calls()); n != 1 {
			t.Errorf("%s: got %d calls, want 1", kind, n)
		}
		if len(*waits) != 0 {
			t.Errorf("%s: waited %v, want no wait", kind, *waits)
		}
	}
}

func TestRetryGivesUpAtDeadline(t *testing.T) {
	fake := NewFake(Result{Err: NewError(NotFoundYet, errors.New("no entry"))})
	r, _ := newTestRetrying(fake, RetryPolicy{Deadline: 50 * time.Millisecond, Initial: 10 * time.Millisecond})
	r.sleep = sleepCtx

	_, _, err := r.FetchJWTSVID(context.Background(), testRef, "aud")
	if err == nil {
		t.Fatal("expected an error after the deadline")
	}
	if Classify(err) != NotFoundYet {
		t.Errorf("the last failure must keep its kind, got %v", err)
	}
	if n := len(fake.Calls()); n < 2 {
		t.Errorf("got %d calls, want at least 2 before the deadline", n)
	}
}

func TestRetryUnclassifiedIsPermanent(t *testing.T) {
	fake := NewFake(Result{Err: errors.New("something else")})
	r, _ := newTestRetrying(fake, RetryPolicy{})
	_, _, err := r.FetchJWTSVID(context.Background(), testRef, "aud")
	if err == nil || Retryable(err) {
		t.Fatalf("an unclassified error must not be retried, got %v", err)
	}
	if n := len(fake.Calls()); n != 1 {
		t.Errorf("got %d calls, want 1", n)
	}
}
