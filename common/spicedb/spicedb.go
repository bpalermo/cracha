// Package spicedb holds the SpiceDB schema of the reference authorization
// backend (docs/design.md, section 6.4) and the names in it, so that the
// broker's adapter, which queries it, and the reconciler, which writes to
// it, share one spelling of every object type, relation, permission, caveat
// and caveat context key. The schema itself is schema.zed, embedded
// verbatim; the reconciler's schema command writes it to SpiceDB.
//
// Object IDs: a workload's is its authorization subject encoding of design
// 4.3 (common/idenc), whose charset is a subset of SpiceDB's object ID
// charset; a grant's, a service's and a team's is its name in Git; an AWS
// account's is the 12-digit account ID.
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
	TypeDynamoDBTable = "dynamodb_table"
)

// Relations.
const (
	// RelationOwner is service#owner: the team that owns a service.
	RelationOwner = "owner"
	// RelationMember is service#member: a workload of a service.
	RelationMember = "member"
	// RelationSuspended is workload#suspended: a suspended workload, whose
	// subject is the team of its service, or TeamNone when it has none.
	RelationSuspended = "suspended"
	// RelationAccount is grant#account and dynamodb_table#account.
	RelationAccount = "account"
	// RelationAssigneeService is grant#assignee_service: a service whose
	// members hold the grant.
	RelationAssigneeService = "assignee_service"
	// RelationAssigneeWorkload is grant#assignee_workload: a workload that
	// holds the grant directly.
	RelationAssigneeWorkload = "assignee_workload"
	// RelationWriter and RelationReader are dynamodb_table#writer and
	// dynamodb_table#reader (Level 3).
	RelationWriter = "writer"
	RelationReader = "reader"
)

// Permissions.
const (
	// PermissionIsSuspended is workload#is_suspended.
	PermissionIsSuspended = "is_suspended"
	// PermissionAssume is grant#assume: whether a workload holds the grant.
	PermissionAssume = "assume"
	// PermissionWrite and PermissionRead are dynamodb_table#write and
	// dynamodb_table#read (Level 3).
	PermissionWrite = "write"
	PermissionRead  = "read"
)

// Caveats. A relationship carries at most one caveat, so a bound on time
// alone is within_window, on clusters alone in_clusters, and on both bounded.
const (
	CaveatWithinWindow = "within_window"
	CaveatInClusters   = "in_clusters"
	CaveatBounded      = "bounded"
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
)

// TeamNone is the team object a suspended workload without a service is
// related to: the suspended relation needs a subject, and the workload has
// no team.
const TeamNone = "none"
