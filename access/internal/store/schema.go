package store

import "github.com/bpalermo/cracha/common/spicedb"

// The names below are the schema's (common/spicedb) for what the SpiceDB
// gateway change adds to it: ownership, approvers and the sensitive flag
// on services and resources, and the pending_request definition this
// package keeps approvals in. They are spelled here, once, until that
// change is on main; then each becomes the common/spicedb constant of the
// same name.
const (
	// RelationTeam is service#team, the service's owning team (it was
	// service#owner before ownership moved to workloads).
	RelationTeam = "team"
	// RelationOwner and RelationApprover relate a workload, or a
	// service's members, to a service or a resource as its owners and
	// approvers.
	RelationOwner    = "owner"
	RelationApprover = "approver"
	// RelationSensitive flags a service or a resource whose writes need
	// an approval: a wildcard relationship (workload:*).
	RelationSensitive = "sensitive"
	// PermissionManage (owner) may write a resource's relations, or a
	// service's membership; PermissionApprove (approver + owner) may
	// approve a pending write of one.
	PermissionManage  = "manage"
	PermissionApprove = "approve"

	// DefinitionPendingRequest is a pending write: one relationship
	// pending_request:<id>#target@<target> with the CaveatPendingPayload
	// caveat, whose context CaveatContextRequest holds the request as
	// JSON.
	DefinitionPendingRequest = "pending_request"
	RelationTarget           = "target"
	CaveatPendingPayload     = "pending_payload"
	CaveatContextRequest     = "request"
)

// KindService is the target kind of a membership write: the service is
// the resource, member the relation.
const KindService = spicedb.TypeService
