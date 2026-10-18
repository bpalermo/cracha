// Package authz is the authorization store contract of docs/design.md,
// section 6.3: the questions the broker asks about who holds which grants,
// answered by any backend through an adapter. Backend-specific types never
// leave their adapter; this package has none.
//
// Rules carried by the contract: any error is a deny (a caller never treats a
// failed call as an allow); consistency tokens are opaque; time-bounded and
// cluster-bounded assignments are part of the model, evaluated by every
// backend.
package authz

import (
	"context"
	"errors"
)

// Subject identifies the workload asking: its authorization encoding
// (common/idenc) and the cluster the broker serves. Nothing in it comes from
// the workload itself beyond its verified identity.
type Subject struct {
	// ID is the idenc authz encoding, <td-short>/<namespace>/<serviceaccount>.
	ID string
	// Cluster is the name of the cluster this broker serves.
	Cluster string
}

// Token is an opaque consistency token minted by a store. Its content is the
// adapter's business: a SpiceDB zedtoken, a file hash, anything. The empty
// token means "none".
type Token string

// Consistency says how fresh an answer must be. The zero value asks for the
// store's lowest-latency answer; AtLeastAsFresh asks for one at least as
// fresh as a token the store minted earlier.
type Consistency struct {
	AtLeastAsFresh Token
}

// Decision is the answer to ListGrants.
type Decision struct {
	// Grants the subject holds right now, sorted, without duplicates.
	Grants []string
	// Tags are the ABAC attributes the store knows about the subject, such
	// as "service" and "team". They become session tags.
	Tags map[string]string
	// Token is the consistency token of this answer.
	Token Token
	// Trace explains the decision, one line per step, for the decision log.
	Trace []string
}

// CheckResult is the answer to Check.
type CheckResult struct {
	Allowed bool
	Token   Token
	Trace   []string
}

// ErrSubjectSuspended is returned by a store that knows the subject and has
// it suspended: it holds nothing until the suspension is lifted. The broker
// reports it as the "subject_suspended" reason.
var ErrSubjectSuspended = errors.New("authz: subject suspended")

// Store is what every backend must answer. A nil error with an empty grant
// list is a valid "holds nothing"; any non-nil error is a deny.
type Store interface {
	// ListGrants returns the grants the subject holds.
	ListGrants(ctx context.Context, subject Subject, consistency Consistency) (Decision, error)
	// Check reports whether the subject holds one grant; it is how a cached
	// session is re-validated grant by grant.
	Check(ctx context.Context, subject Subject, grant string, consistency Consistency) (CheckResult, error)
}

// Resources is the answer to LookupResources.
type Resources struct {
	// Names of the resources of the kind the subject holds the permission
	// on right now, sorted, without duplicates: resource names (an S3
	// bucket's name), never a backend's object IDs.
	Names []string
	// Token is the consistency token of this answer.
	Token Token
	// Trace explains the answer, one line per relation considered, for the
	// decision log.
	Trace []string
}

// ResourceLookup is LookupResources of 6.3, for Level 3 template filling:
// which resources of a kind (an object type of design 6.4, such as
// s3_bucket) the subject holds a permission (read or write) on, directly
// or through its service, with the same time and cluster bounds, and the
// same suspension, as its grants. Both backends implement it; a broker
// whose store does not denies every grant that needs it.
type ResourceLookup interface {
	LookupResources(ctx context.Context, subject Subject, kind, permission string, consistency Consistency) (Resources, error)
}

// Change is one assignment change seen by Watch, a change of a resource
// relation (Level 3) included.
type Change struct {
	// Subject whose grants or resources changed, if the backend knows;
	// empty means "any".
	Subject Subject
	// Grant that was assigned or removed, if the backend knows.
	Grant string
	// Token after the change.
	Token Token
}

// Watcher is the optional Watch of 6.3. The channel closes when the context
// ends or the stream fails; a broker without a Watcher degrades to TTL-only
// cache invalidation.
type Watcher interface {
	Watch(ctx context.Context, since Token) (<-chan Change, error)
}
