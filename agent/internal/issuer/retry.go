package issuer

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"
)

// RetryPolicy bounds the retries of one fetch. The deadline is per fetch, not
// per attempt: it is the request's budget (design 7.3, agent.fetchDeadline),
// under the SDKs' own request timeouts, so the agent only absorbs the seconds
// a new pod's entry takes to reach the issuer's agent and then answers 503
// for the SDK to retry.
type RetryPolicy struct {
	// Deadline bounds the whole fetch, attempts and waits included. Zero means
	// DefaultDeadline.
	Deadline time.Duration
	// Initial is the first wait between attempts; each later wait doubles up to
	// Max. Zero means the defaults below.
	Initial time.Duration
	Max     time.Duration
	// Jitter is the fraction of each wait that is randomised: a wait of w
	// becomes w * (1 ± Jitter). Zero means DefaultJitter.
	Jitter float64
}

// Defaults of RetryPolicy.
const (
	DefaultDeadline = 3 * time.Second
	DefaultInitial  = 250 * time.Millisecond
	DefaultMax      = 5 * time.Second
	DefaultJitter   = 0.2
)

func (p RetryPolicy) withDefaults() RetryPolicy {
	if p.Deadline <= 0 {
		p.Deadline = DefaultDeadline
	}
	if p.Initial <= 0 {
		p.Initial = DefaultInitial
	}
	if p.Max <= 0 {
		p.Max = DefaultMax
	}
	if p.Jitter <= 0 {
		p.Jitter = DefaultJitter
	}
	return p
}

// retrying is an Issuer that retries another one's retryable failures.
type retrying struct {
	inner  Issuer
	policy RetryPolicy
	log    *slog.Logger
	// sleep is replaced in tests.
	sleep func(context.Context, time.Duration) error
}

// WithRetry returns an Issuer that retries inner's NotFoundYet and Unavailable
// failures with jittered exponential backoff until the policy's deadline, and
// returns every other failure at once. The last failure is what the caller
// sees when the deadline passes.
func WithRetry(inner Issuer, policy RetryPolicy, log *slog.Logger) Issuer {
	if log == nil {
		log = slog.Default()
	}
	return &retrying{inner: inner, policy: policy.withDefaults(), log: log, sleep: sleepCtx}
}

// FetchJWTSVID implements Issuer.
func (r *retrying) FetchJWTSVID(ctx context.Context, ref PodRef, audience string) (string, time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, r.policy.Deadline)
	defer cancel()

	wait := r.policy.Initial
	for attempt := 1; ; attempt++ {
		token, expiry, err := r.inner.FetchJWTSVID(ctx, ref, audience)
		if err == nil {
			if attempt > 1 {
				r.log.Info("JWT-SVID fetched after retries", "pod", ref.String(), "attempts", attempt)
			}
			return token, expiry, nil
		}
		if !Retryable(err) {
			return "", time.Time{}, err
		}
		if ctx.Err() != nil {
			return "", time.Time{}, fmt.Errorf("giving up after %d attempts within %s: %w", attempt, r.policy.Deadline, err)
		}
		r.log.Debug("JWT-SVID fetch failed; retrying", "pod", ref.String(), "attempt", attempt,
			"wait", wait, "error", err)
		if serr := r.sleep(ctx, jittered(wait, r.policy.Jitter)); serr != nil {
			return "", time.Time{}, fmt.Errorf("giving up after %d attempts within %s: %w", attempt, r.policy.Deadline, err)
		}
		wait = min(wait*2, r.policy.Max)
	}
}

// jittered returns d scaled by a random factor in [1-jitter, 1+jitter].
func jittered(d time.Duration, jitter float64) time.Duration {
	f := 1 + jitter*(2*rand.Float64()-1)
	return time.Duration(float64(d) * f)
}

// sleepCtx waits for d or until ctx is done, whichever comes first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
