package e2e

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	authzed "github.com/authzed/authzed-go/v1"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/bpalermo/cracha/common/idenc"
	schema "github.com/bpalermo/cracha/common/spicedb"
	"github.com/bpalermo/cracha/common/spicedb/conn"
)

// How the suite reaches SpiceDB in spicedb mode: through the chart's
// gateway, over the port-forward run.sh keeps open, with X.509-SVIDs the
// SPIRE server minted for the suite (run.sh, spire-server x509 mint), one
// directory per identity under E2E_SPICEDB_SVIDS, each with svid.pem,
// key.pem and bundle.pem. The gateway sees them as it sees any workload's
// SVID of the trust domain: it authorizes the SPIFFE ID and the method.
const (
	spicedbSVIDsEnv = "E2E_SPICEDB_SVIDS"
	// The identities run.sh minted: the three the gateway admits, under
	// their service accounts of the release, and one it does not.
	identityBroker     = "broker"
	identityAccess     = "access"
	identityReconciler = "reconciler"
	identityIntruder   = "intruder"
)

// gatewayID is the SPIFFE ID of the chart's SpiceDB pods, which the suite
// verifies the gateway by.
var gatewayID = spiffeid.RequireFromString(fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", trustDomain, systemNamespace, conn.GatewayServiceAccount))

// minted is the SVID and bundle run.sh minted for one identity.
func minted(identity string) (*x509svid.SVID, *x509bundle.Bundle, error) {
	dir := filepath.Join(os.Getenv(spicedbSVIDsEnv), identity)
	svid, err := x509svid.Load(filepath.Join(dir, "svid.pem"), filepath.Join(dir, "key.pem"))
	if err != nil {
		return nil, nil, fmt.Errorf("the %s SVID: %w", identity, err)
	}
	bundle, err := x509bundle.Load(gatewayID.TrustDomain(), filepath.Join(dir, "bundle.pem"))
	if err != nil {
		return nil, nil, fmt.Errorf("the trust bundle: %w", err)
	}
	return svid, bundle, nil
}

// dialAs connects to the gateway with the identity's SVID.
func dialAs(identity string) (*authzed.Client, error) {
	svid, bundle, err := minted(identity)
	if err != nil {
		return nil, err
	}
	return conn.Dial(conn.Config{Endpoint: os.Getenv(spicedbEndpointEnv), Server: gatewayID, SVIDs: svid, Bundles: bundle})
}

// mustDialAs is dialAs for a test, closed when it ends.
func mustDialAs(t *testing.T, identity string) *authzed.Client {
	t.Helper()
	c, err := dialAs(identity)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func rel(resourceType, resourceID, relation, subjectType, subjectID, subjectRelation string) *v1.Relationship {
	return &v1.Relationship{
		Resource: &v1.ObjectReference{ObjectType: resourceType, ObjectId: resourceID},
		Relation: relation,
		Subject: &v1.SubjectReference{
			Object:           &v1.ObjectReference{ObjectType: subjectType, ObjectId: subjectID},
			OptionalRelation: subjectRelation,
		},
	}
}

// workloadID is the authorization subject of a test workload (design 4.3).
func workloadID(sa string) string {
	return "cracha/" + testNamespace + "/" + sa
}

// bucketID is a bucket's object ID (design 4.3).
func bucketID(name string) string {
	id, err := idenc.Resource(name)
	if err != nil {
		panic(err)
	}
	return id
}

// The suite's relationships: what e2e/grants gives the static mode in its
// published assignments, in SpiceDB, where the spicedb backend's
// relationships live (design 6.4). The account's implicit grants are the
// bundle's, never relationships.
//
// They reach SpiceDB two ways. What cracha-access writes (design 6.9) it
// writes here too, through its CLI as the owner (viaAccess): the services'
// members and the buckets' readers, checked against the bundle like any
// write. What it has no request for is fixture setup, written directly as
// the access identity, the one the gateway lets write (bootstrap): the
// grant's account, the services' teams and grants, and the first owner,
// approver and sensitive flag of every target the tests use. A target's
// first owner has no API path (an owner is made by an owner), so whoever
// runs SpiceDB seeds it this way.
var (
	clientAssignment = rel(schema.TypeGrant, "e2e-s3-reader", schema.RelationAssigneeService, schema.TypeService, "e2e-client", "")
	readerDataAccess = rel(schema.TypeS3Bucket, bucketID("cracha-e2e-data"), schema.RelationReader, schema.TypeService, "e2e-reader", schema.RelationMember)
	clientSuspension = rel(schema.TypeWorkload, workloadID(assignedSA), schema.RelationSuspended, schema.TypeTeam, "platform", "")
)

// The targets the access tests write, and who owns and approves them.
const (
	grantedBucket   = "cracha-e2e-granted"
	sensitiveBucket = "cracha-e2e-sensitive"
	glassBucket     = "cracha-e2e-glass"
)

func bootstrapRelationships() []*v1.Relationship {
	owner, approver := workloadID(identityOwner), workloadID(identityApprover)
	out := []*v1.Relationship{
		rel(schema.TypeGrant, "e2e-s3-reader", schema.RelationAccount, schema.TypeAWSAccount, "111122223333", ""),
		rel(schema.TypeService, "e2e-client", schema.RelationTeam, schema.TypeTeam, "platform", ""),
		clientAssignment,
		rel(schema.TypeService, "e2e-reader", schema.RelationTeam, schema.TypeTeam, "platform", ""),
		rel(schema.TypeGrant, "e2e-s3-reader", schema.RelationAssigneeService, schema.TypeService, "e2e-reader", ""),
		rel(schema.TypeService, "e2e-client", schema.RelationOwner, schema.TypeWorkload, owner, ""),
		rel(schema.TypeService, "e2e-reader", schema.RelationOwner, schema.TypeWorkload, owner, ""),
		rel(schema.TypeS3Bucket, bucketID(sensitiveBucket), schema.RelationApprover, schema.TypeWorkload, approver, ""),
		rel(schema.TypeS3Bucket, bucketID(sensitiveBucket), schema.RelationSensitive, schema.TypeWorkload, "*", ""),
		rel(schema.TypeS3Bucket, bucketID(glassBucket), schema.RelationSensitive, schema.TypeWorkload, "*", ""),
	}
	for _, b := range []string{"cracha-e2e-data", "cracha-e2e-other", grantedBucket, sensitiveBucket, glassBucket, outsideBucket} {
		out = append(out, rel(schema.TypeS3Bucket, bucketID(b), schema.RelationOwner, schema.TypeWorkload, owner, ""))
	}
	return out
}

// viaAccess are the suite's relationships cracha-access writes, as the
// arguments of its CLI's grant.
func viaAccess() [][]string {
	return [][]string{
		{"--subject", workloadID(assignedSA), "--resource", "service:e2e-client", "--relation", "member"},
		{"--subject", workloadID(readerSA), "--resource", "service:e2e-reader", "--relation", "member"},
		{"--service", "e2e-reader", "--resource", "s3_bucket:cracha-e2e-data", "--relation", "reader"},
		{"--subject", workloadID("bystander"), "--resource", "s3_bucket:cracha-e2e-other", "--relation", "reader"},
	}
}

// write applies the updates as the access identity, the one writer of
// relationships, and returns the revision they were written at.
func write(ctx context.Context, op v1.RelationshipUpdate_Operation, rels ...*v1.Relationship) (*v1.ZedToken, error) {
	c, err := dialAs(identityAccess)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	updates := make([]*v1.RelationshipUpdate, 0, len(rels))
	for _, r := range rels {
		updates = append(updates, &v1.RelationshipUpdate{Operation: op, Relationship: r})
	}
	resp, err := c.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{Updates: updates})
	if err != nil {
		return nil, fmt.Errorf("writing %d relationships as %s: %w", len(rels), identityAccess, err)
	}
	return resp.GetWrittenAt(), nil
}

// mustWrite is write for a test.
func mustWrite(ctx context.Context, t *testing.T, op v1.RelationshipUpdate_Operation, rels ...*v1.Relationship) {
	t.Helper()
	if _, err := write(ctx, op, rels...); err != nil {
		t.Fatal(err)
	}
}

// seedSpiceDB writes the suite's relationships in spicedb mode, the
// bootstrap directly and the rest through cracha-access, and takes away
// whatever a test of an earlier run on a kept cluster may have left (a
// suspension); nothing outside spicedb mode. SpiceDB's memory datastore
// forgets everything when its pod restarts, so every run writes them. The
// schema is already there: run.sh has the reconciler write it.
func seedSpiceDB() error {
	if os.Getenv(authzEnv) != spicedbMode {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := retry(ctx, func() error {
		_, err := write(ctx, v1.RelationshipUpdate_OPERATION_TOUCH, bootstrapRelationships()...)
		return err
	}); err != nil {
		return err
	}
	if _, err := write(ctx, v1.RelationshipUpdate_OPERATION_DELETE, clientSuspension); err != nil {
		return err
	}
	for _, args := range viaAccess() {
		args := append([]string{"grant"}, append(args, "--reason", "e2e seed", "--requester", "e2e")...)
		if err := retry(ctx, func() error {
			_, err := accessCLI(ctx, identityOwner, args...)
			return err
		}); err != nil {
			return fmt.Errorf("seeding through cracha-access: %w", err)
		}
	}
	return awaitVisible(ctx)
}

// retry calls f every two seconds until it succeeds, 30 times at most.
func retry(ctx context.Context, f func() error) error {
	var err error
	for range 30 {
		if err = f(); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w (last: %v)", ctx.Err(), err)
		case <-time.After(2 * time.Second):
		}
	}
	return err
}

// awaitVisible waits until the client's membership is visible at the
// consistency the broker asks with, minimize_latency, which SpiceDB serves
// from a revision up to its quantization interval (five seconds by default)
// old: the first tests must not see the store as it was before the write.
func awaitVisible(ctx context.Context) error {
	c, err := dialAs(identityBroker)
	if err != nil {
		return err
	}
	defer c.Close()
	for {
		resp, err := c.CheckPermission(ctx, &v1.CheckPermissionRequest{
			Consistency: &v1.Consistency{Requirement: &v1.Consistency_MinimizeLatency{MinimizeLatency: true}},
			Resource:    &v1.ObjectReference{ObjectType: schema.TypeGrant, ObjectId: clientAssignment.GetResource().GetObjectId()},
			Permission:  schema.PermissionAssume,
			Subject:     &v1.SubjectReference{Object: &v1.ObjectReference{ObjectType: schema.TypeWorkload, ObjectId: workloadID(assignedSA)}},
		})
		if err == nil && resp.GetPermissionship() == v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("the suite's relationships are not visible at minimize_latency: %v (last: %v)", ctx.Err(), err)
		case <-time.After(time.Second):
		}
	}
}
