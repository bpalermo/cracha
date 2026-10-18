package issuer

import (
	"context"
	"sync"
	"time"
)

// Result is one canned answer of a Fake.
type Result struct {
	Token  string
	Expiry time.Time
	Err    error
}

// Call records one FetchJWTSVID call a Fake received.
type Call struct {
	Ref      PodRef
	Audience string
}

// Fake is an Issuer for tests. It answers from a queue of results, repeating
// the last one once the queue runs dry, and records every call. The zero
// value refuses every call with a Permanent error.
type Fake struct {
	mu      sync.Mutex
	results []Result
	calls   []Call
}

// NewFake returns a Fake answering with results in order, then the last one.
func NewFake(results ...Result) *Fake {
	return &Fake{results: results}
}

// FetchJWTSVID implements Issuer.
func (f *Fake) FetchJWTSVID(_ context.Context, ref PodRef, audience string) (string, time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, Call{Ref: ref, Audience: audience})
	if len(f.results) == 0 {
		return "", time.Time{}, NewError(Permanent, errNoResult)
	}
	r := f.results[0]
	if len(f.results) > 1 {
		f.results = f.results[1:]
	}
	return r.Token, r.Expiry, r.Err
}

// Calls returns a copy of the calls received so far.
func (f *Fake) Calls() []Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Call(nil), f.calls...)
}

type fakeErr string

func (e fakeErr) Error() string { return string(e) }

const errNoResult fakeErr = "fake issuer has no result to give"
