// Package spicedb holds the SpiceDB schema of the reference authorization
// backend (docs/design.md, section 6.4) and the names in it, so that the
// broker's adapter, which queries it, and the reconciler, which writes to
// the access service, which writes its relationships, and the reconciler,
// which writes the schema, share one spelling of every object type,
// relation, permission, caveat and caveat context key. The schema itself is
// schema.zed, embedded verbatim; the reconciler's schema command writes it
// to SpiceDB.
//
// Object IDs: a workload's is its authorization subject encoding of design
// 4.3 (common/idenc), whose charset is a subset of SpiceDB's object ID
// charset; a grant's, a service's and a team's is its name in Git; an AWS
// account's is the 12-digit account ID; a resource's (an s3_bucket's) is
// its name escaped by common/idenc's Resource, since a bucket name may hold
// a dot.
package spicedb

import _ "embed"

// Schema is the schema, as written to SpiceDB.
//
//go:embed schema.zed
var Schema string

// Object types.
const (
	TypeTeam          = "team"
	TypeService       = "service"
	TypeWorkload      = "workload"
	TypeAWSAccount    = "aws_account"
	TypeGrant         = "grant"
	TypeS3Bucket      = "s3_bucket"
	TypeDynamoDBTable = "dynamodb_table"
	// DefinitionPendingRequest is a write request awaiting approval, one
	// relationship to its target (RelationTarget) with the request in its
	// caveat context (CaveatPendingPayload). Written and read only by
	// cracha-access; the broker never reads it.
	DefinitionPendingRequest = "pending_request"
)

// ManagedTypes are the object types the write path manages (design 6.4):
// each has the relations RelationOwner, RelationApprover and
// RelationSensitive, and the permissions PermissionManage and
// PermissionApprove. The broker never reads them.
var ManagedTypes = []string{TypeService, TypeS3Bucket, TypeDynamoDBTable}

// ResourceTypes are the object types of the resources a workload is
// related to by name (Level 3): each has the relations RelationReader and
// RelationWriter, held by a workload or a service's members with the same
// caveats as a grant's assignees, and the permissions PermissionRead
// (reader or writer) and PermissionWrite (writer). Their names are the
// resource kinds of common/grant, and their object IDs the resource names
// as common/idenc's Resource encodes them.
var ResourceTypes = []string{TypeS3Bucket, TypeDynamoDBTable}

// Relations.
const (
	// RelationTeam is service#team: the team that owns a service, its
	// team tag.
	RelationTeam = "team"
	// RelationMember is service#member: a workload of a service.
	RelationMember = "member"
	// RelationSuspended is workload#suspended: a suspended workload, whose
	// subject is the team of its service, or TeamNone when it has none.
	RelationSuspended = "suspended"
	// RelationAccount is grant#account.
	RelationAccount = "account"
	// RelationAssigneeService is grant#assignee_service: a service whose
	// members hold the grant.
	RelationAssigneeService = "assignee_service"
	// RelationAssigneeWorkload is grant#assignee_workload: a workload that
	// holds the grant directly.
	RelationAssigneeWorkload = "assignee_workload"
	// RelationWriter and RelationReader are the relations of every
	// resource type (Level 3).
	RelationWriter = "writer"
	RelationReader = "reader"
	// RelationOwner and RelationApprover are the relations of every managed
	// type (ManagedTypes): the workloads, or a service's members, who
	// manage the object's relationships and who approve a request to
	// change them.
	RelationOwner    = "owner"
	RelationApprover = "approver"
	// RelationSensitive flags a managed object as sensitive: the
	// relationship <type>:<id>#sensitive@workload:*, read with
	// ReadRelationships. Its subject is the wildcard, so the flag is a
	// property of the object, not of any workload.
	RelationSensitive = "sensitive"
	// RelationTarget is pending_request#target: the object a pending
	// request would change.
	RelationTarget = "target"
)

// Permissions.
const (
	// PermissionIsSuspended is workload#is_suspended.
	PermissionIsSuspended = "is_suspended"
	// PermissionAssume is grant#assume: whether a workload holds the grant.
	PermissionAssume = "assume"
	// PermissionWrite and PermissionRead are the permissions of every
	// resource type (Level 3).
	PermissionWrite = "write"
	PermissionRead  = "read"
	// PermissionManage is owner, and PermissionApprove approver or owner,
	// on every managed type: an owner may approve.
	PermissionManage  = "manage"
	PermissionApprove = "approve"
)

// Caveats. A relationship carries at most one caveat, so a bound on time
// alone is within_window, on clusters alone in_clusters, and on both bounded.
const (
	CaveatWithinWindow = "within_window"
	CaveatInClusters   = "in_clusters"
	CaveatBounded      = "bounded"
	// CaveatPendingPayload carries a pending request on its target
	// relationship, under CaveatContextRequest.
	CaveatPendingPayload = "pending_payload"
)

// Caveat context keys. ContextExpiresAt (an RFC 3339 timestamp) and
// ContextAllowed (a list of cluster names) are stored on the relationship;
// ContextNow (an RFC 3339 timestamp) and ContextCluster (the cluster the
// broker serves) are sent by the broker at query time.
const (
	ContextExpiresAt = "expires_at"
	ContextNow       = "now"
	ContextAllowed   = "allowed"
	ContextCluster   = "cluster"
	// CaveatContextRequest is the JSON of a pending request, stored on the
	// relationship of CaveatPendingPayload.
	CaveatContextRequest = "request"
)

// TeamNone is the team object a suspended workload without a service is
// related to: the suspended relation needs a subject, and the workload has
// no team.
const TeamNone = "none"
