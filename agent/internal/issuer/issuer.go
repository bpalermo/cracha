// Package issuer is the identity issuer adapter contract of cracha-agent
// (docs/design.md, section 4.1): the one piece of the agent that is not the
// standard Workload API, a per-pod JWT-SVID fetch on the pod's behalf.
//
// The agent names a pod by its Kubernetes object reference and an audience;
// the issuer resolves and attests the pod itself and answers only for pods its
// own agent sees on this node. Crachá never attests a workload (section 11).
// Issuer-specific types never leave their adapter: the reference SPIRE adapter
// lives in the spire subpackage and nothing outside it imports SPIRE or Broker
// API types.
package issuer

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// PodRef identifies the pod a JWT-SVID is fetched for. All three are sent:
// the issuer resolves the pod by namespace and name and must refuse the
// request when that pod does not carry this UID, which is what stops a
// recycled pod name from inheriting the previous pod's identity.
type PodRef struct {
	Namespace string
	Name      string
	UID       string
}

// String renders the reference for logs.
func (r PodRef) String() string {
	return fmt.Sprintf("%s/%s (uid %s)", r.Namespace, r.Name, r.UID)
}

// Issuer fetches a JWT-SVID for a pod.
type Issuer interface {
	// FetchJWTSVID returns the pod's JWT-SVID for the audience and the token's
	// expiry, as the issuer reports it. The token is not verified here: it was
	// just minted by the issuer over an authenticated channel, and verifying it
	// is the broker's job; the agent only reads its expiry, to know when to
	// fetch again.
	//
	// An error is classified with Classify: the caller retries NotFoundYet and
	// Unavailable, and fails the request on anything else.
	FetchJWTSVID(ctx context.Context, ref PodRef, audience string) (token string, expiry time.Time, err error)
}

// Kind classifies a fetch failure for the retry decision.
type Kind int

const (
	// Permanent: the request itself is wrong (malformed reference, audience
	// refused) or the failure is of a kind that retrying cannot fix. Never
	// retried.
	Permanent Kind = iota
	// NotFoundYet: the issuer cannot resolve the pod, or has no entry for it
	// yet. Benign for a brand new pod, whose registration entry takes seconds
	// to reach the node's agent, so it is retried within the fetch deadline.
	NotFoundYet
	// Unavailable: the issuer's agent is restarting, or the agent's own
	// identity has not been issued yet, so the authenticated channel cannot be
	// built. Retried.
	Unavailable
	// PermissionDenied: the issuer's access policy refuses the agent for this
	// pod. Retrying cannot help; the fix is the issuer's RBAC. Never retried.
	PermissionDenied
)

// String names the kind for logs.
func (k Kind) String() string {
	switch k {
	case NotFoundYet:
		return "not found yet"
	case Unavailable:
		return "unavailable"
	case PermissionDenied:
		return "permission denied"
	default:
		return "permanent"
	}
}

// Error is a classified fetch failure. Adapters wrap every failure in one so
// that the retry policy does not depend on the issuer's own error types.
type Error struct {
	Kind Kind
	Err  error
}

// Error implements error.
func (e *Error) Error() string {
	return fmt.Sprintf("issuer: %s: %v", e.Kind, e.Err)
}

// Unwrap exposes the adapter's error.
func (e *Error) Unwrap() error { return e.Err }

// NewError wraps err with a kind.
func NewError(kind Kind, err error) *Error {
	return &Error{Kind: kind, Err: err}
}

// Classify returns the kind of a fetch failure. An error no adapter classified
// is Permanent: the retry loop must never spin on something it does not
// understand.
func Classify(err error) Kind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return Permanent
}

// Retryable reports whether a fetch failure is worth retrying within the
// fetch deadline.
func Retryable(err error) bool {
	switch Classify(err) {
	case NotFoundYet, Unavailable:
		return true
	default:
		return false
	}
}
