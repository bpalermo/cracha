// Package api is cracha-access's API (docs/design.md, section 6.9): the
// gRPC service cracha.access.v1.Access, its messages, and the client the
// CLI calls it with. The messages are Go structs carried as JSON in gRPC
// frames (content subtype "json", [Codec]), so the build needs no protoc;
// everything else is plain gRPC over SPIFFE mTLS: status codes, deadlines,
// HTTP/2. A refusal is a status error whose message starts with its
// reason code, which the trailer cracha-reason also carries.
package api

import "github.com/bpalermo/cracha/access/internal/check"

// Resource names a write's target: a resource of a kind of common/grant
// (s3_bucket, dynamodb_table), or a service (kind service) for a
// membership.
type Resource struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// GrantRequest relates a workload (Subject), or every member of a service
// (Service), to a resource by Relation (reader or writer), or makes a
// workload a member of a service (Resource kind service, Relation
// member). It is what a kind: Access document says (design 6.2), with the
// same optional bounds.
type GrantRequest struct {
	Subject  string   `json:"subject,omitempty"`
	Service  string   `json:"service,omitempty"`
	Resource Resource `json:"resource"`
	Relation string   `json:"relation"`
	// ExpiresAt (RFC 3339) and Clusters bound the relationship.
	ExpiresAt string   `json:"expiresAt,omitempty"`
	Clusters  []string `json:"clusters,omitempty"`
	// Reason is why, and Requester who asks (a person or a job): both are
	// recorded, neither is authenticated; the caller's SPIFFE ID is.
	Reason    string `json:"reason"`
	Requester string `json:"requester,omitempty"`
	// BreakGlass applies a write on a sensitive target at once, without
	// an approval: the caller must manage the target, expiresAt is
	// required within the break-glass cap, and the write is logged at WARN.
	BreakGlass bool `json:"breakGlass,omitempty"`
}

// RevokeRequest removes the relationship a GrantRequest would make; its
// bounds are not needed.
type RevokeRequest struct {
	Subject   string   `json:"subject,omitempty"`
	Service   string   `json:"service,omitempty"`
	Resource  Resource `json:"resource"`
	Relation  string   `json:"relation"`
	Reason    string   `json:"reason"`
	Requester string   `json:"requester,omitempty"`
}

// Statuses of a write.
const (
	StatusApplied  = "applied"
	StatusPending  = "pending"
	StatusRevoked  = "revoked"
	StatusRejected = "rejected"
)

// WriteResponse is the outcome of a Grant, Revoke, Approve or Reject.
type WriteResponse struct {
	Status string `json:"status"`
	// RequestID names the pending request, when the write is one.
	RequestID string `json:"requestId,omitempty"`
	// Relationship is the relationship written or removed.
	Relationship string `json:"relationship,omitempty"`
	// Token is the zedtoken the write is visible at: a caller that reads
	// right after may ask the broker for at-least-as-fresh (6.7).
	Token         string        `json:"token,omitempty"`
	BundleVersion string        `json:"bundleVersion,omitempty"`
	PolicyDelta   []check.Delta `json:"policyDelta,omitempty"`
}

// DecideRequest approves or rejects a pending request.
type DecideRequest struct {
	ID        string `json:"id"`
	Reason    string `json:"reason"`
	Requester string `json:"requester,omitempty"`
}

// ListRequest selects relationships: a workload's (Subject: its own and
// its service's), a service's (its members and its resources), or a
// resource's (who reaches it). Exactly one is set.
type ListRequest struct {
	Subject  string    `json:"subject,omitempty"`
	Service  string    `json:"service,omitempty"`
	Resource *Resource `json:"resource,omitempty"`
}

// Relationship is one relationship cracha-access writes, as it is held.
type Relationship struct {
	Subject   string   `json:"subject,omitempty"`
	Service   string   `json:"service,omitempty"`
	Resource  Resource `json:"resource"`
	Relation  string   `json:"relation"`
	ExpiresAt string   `json:"expiresAt,omitempty"`
	Clusters  []string `json:"clusters,omitempty"`
}

// ListResponse is the relationships selected, sorted.
type ListResponse struct {
	Relationships []Relationship `json:"relationships"`
}

// ExplainRequest asks what a workload holds now, in one cluster or, when
// Cluster is empty, in every cluster scope its relationships name.
type ExplainRequest struct {
	Subject string `json:"subject"`
	Cluster string `json:"cluster,omitempty"`
}

// Composition is a workload's composed credential in one cluster scope,
// as the grant tree's composition lint renders it (design 6.2, step 5).
type Composition struct {
	Cluster           string              `json:"cluster,omitempty"`
	Grants            []string            `json:"grants"`
	Dropped           []string            `json:"dropped,omitempty"`
	Resources         map[string][]string `json:"resources,omitempty"`
	BaseRoles         []string            `json:"baseRoles,omitempty"`
	Policy            string              `json:"policy,omitempty"`
	PolicyChars       int                 `json:"policyChars,omitempty"`
	ManagedPolicyArns []string            `json:"managedPolicyArns,omitempty"`
	SessionTags       map[string]string   `json:"sessionTags,omitempty"`
	// Problems are what the broker would deny the workload for.
	Problems []string `json:"problems,omitempty"`
}

// ExplainResponse is a workload's compositions.
type ExplainResponse struct {
	Subject       string        `json:"subject"`
	Service       string        `json:"service,omitempty"`
	BundleVersion string        `json:"bundleVersion"`
	Compositions  []Composition `json:"compositions"`
}

// PendingRequest lists pending requests, all of them or one target's.
type PendingRequest struct {
	Resource *Resource `json:"resource,omitempty"`
}

// Pending is one pending request.
type Pending struct {
	ID        string       `json:"id"`
	Caller    string       `json:"caller"`
	Requester string       `json:"requester,omitempty"`
	Reason    string       `json:"reason,omitempty"`
	Request   Relationship `json:"request"`
	CreatedAt string       `json:"createdAt"`
	ExpiresAt string       `json:"expiresAt"`
}

// PendingResponse is the pending requests, oldest first.
type PendingResponse struct {
	Requests []Pending `json:"requests"`
}
