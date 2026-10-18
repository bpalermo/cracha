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
// relationships live (design 6.4). The services' teams and members, their
// grants, and the Access documents' buckets; the account's implicit grants
// are the bundle's, never relationships.
var (
	clientAssignment = rel(schema.TypeGrant, "e2e-s3-reader", schema.RelationAssigneeService, schema.TypeService, "e2e-client", "")
	readerDataAccess = rel(schema.TypeS3Bucket, bucketID("cracha-e2e-data"), schema.RelationReader, schema.TypeService, "e2e-reader", schema.RelationMember)
	clientSuspension = rel(schema.TypeWorkload, workloadID(assignedSA), schema.RelationSuspended, schema.TypeTeam, "platform", "")
)

func suiteRelationships() []*v1.Relationship {
	return []*v1.Relationship{
		rel(schema.TypeGrant, "e2e-s3-reader", schema.RelationAccount, schema.TypeAWSAccount, "111122223333", ""),
		rel(schema.TypeService, "e2e-client", schema.RelationTeam, schema.TypeTeam, "platform", ""),
		rel(schema.TypeService, "e2e-client", schema.RelationMember, schema.TypeWorkload, workloadID(assignedSA), ""),
		clientAssignment,
		rel(schema.TypeService, "e2e-reader", schema.RelationTeam, schema.TypeTeam, "platform", ""),
		rel(schema.TypeService, "e2e-reader", schema.RelationMember, schema.TypeWorkload, workloadID(readerSA), ""),
		rel(schema.TypeGrant, "e2e-s3-reader", schema.RelationAssigneeService, schema.TypeService, "e2e-reader", ""),
		rel(schema.TypeS3Bucket, bucketID("cracha-e2e-other"), schema.RelationReader, schema.TypeWorkload, workloadID("bystander"), ""),
		readerDataAccess,
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

// seedSpiceDB writes the suite's relationships in spicedb mode, and takes
// away whatever a test of an earlier run on a kept cluster may have left
// (a suspension); nothing outside spicedb mode. SpiceDB's memory datastore
// forgets everything when its pod restarts, so every run writes them. The
// schema is already there: run.sh has the reconciler write it.
func seedSpiceDB() error {
	if os.Getenv(authzEnv) != spicedbMode {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var err error
	for range 30 {
		if _, err = write(ctx, v1.RelationshipUpdate_OPERATION_TOUCH, suiteRelationships()...); err == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		return err
	}
	_, err = write(ctx, v1.RelationshipUpdate_OPERATION_DELETE, clientSuspension)
	return err
}
