package e2e

import (
	"context"
	"crypto/tls"
	"io"
	"os"
	"testing"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	authzed "github.com/authzed/authzed-go/v1"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	grpcstatus "google.golang.org/grpc/status"

	schema "github.com/bpalermo/cracha/common/spicedb"
)

// The SpiceDB gateway of the chart (design 6.4): every client reaches
// SpiceDB over SPIFFE mTLS, and the gateway authorizes each call by the
// client's SPIFFE ID and the gRPC method, answering anything else with
// PERMISSION_DENIED before SpiceDB sees it.

// A probe of one method, as one identity; what the gateway answers.
type probe func(ctx context.Context, c *authzed.Client) error

func readRelationships(ctx context.Context, c *authzed.Client) error {
	stream, err := c.ReadRelationships(ctx, &v1.ReadRelationshipsRequest{
		Consistency:        &v1.Consistency{Requirement: &v1.Consistency_FullyConsistent{FullyConsistent: true}},
		RelationshipFilter: &v1.RelationshipFilter{ResourceType: schema.TypeService, OptionalResourceId: "e2e-client"},
	})
	if err != nil {
		return err
	}
	for {
		if _, err := stream.Recv(); err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}
	}
}

func checkPermission(ctx context.Context, c *authzed.Client) error {
	_, err := c.CheckPermission(ctx, &v1.CheckPermissionRequest{
		Consistency: &v1.Consistency{Requirement: &v1.Consistency_FullyConsistent{FullyConsistent: true}},
		Resource:    &v1.ObjectReference{ObjectType: schema.TypeWorkload, ObjectId: workloadID(assignedSA)},
		Permission:  schema.PermissionIsSuspended,
		Subject:     &v1.SubjectReference{Object: &v1.ObjectReference{ObjectType: schema.TypeTeam, ObjectId: "platform"}},
	})
	return err
}

// gatewayProbeRel is a relationship of no consequence: a managed type's
// sensitivity flag on a bucket nothing reads.
var gatewayProbeRel = rel(schema.TypeS3Bucket, bucketID("cracha-e2e-probe"), schema.RelationSensitive, schema.TypeWorkload, "*", "")

func writeRelationships(ctx context.Context, c *authzed.Client) error {
	_, err := c.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{Updates: []*v1.RelationshipUpdate{
		{Operation: v1.RelationshipUpdate_OPERATION_TOUCH, Relationship: gatewayProbeRel},
	}})
	return err
}

func deleteRelationships(ctx context.Context, c *authzed.Client) error {
	_, err := c.DeleteRelationships(ctx, &v1.DeleteRelationshipsRequest{RelationshipFilter: &v1.RelationshipFilter{
		ResourceType: schema.TypeS3Bucket, OptionalResourceId: gatewayProbeRel.GetResource().GetObjectId(), OptionalRelation: schema.RelationSensitive,
	}})
	return err
}

func readSchema(ctx context.Context, c *authzed.Client) error {
	_, err := c.ReadSchema(ctx, &v1.ReadSchemaRequest{})
	return err
}

func writeSchema(ctx context.Context, c *authzed.Client) error {
	_, err := c.WriteSchema(ctx, &v1.WriteSchemaRequest{Schema: schema.Schema})
	return err
}

// watch opens the stream and reads nothing: the gateway refuses it, or
// lets it through to SpiceDB, at the first message's headers.
func watch(ctx context.Context, c *authzed.Client) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	stream, err := c.Watch(ctx, &v1.WatchRequest{OptionalObjectTypes: []string{schema.TypeGrant}})
	if err != nil {
		return err
	}
	_, err = stream.Recv()
	if grpcstatus.Code(err) == codes.DeadlineExceeded {
		// Open and waiting for a change: allowed.
		return nil
	}
	return err
}

// answer is the code the gateway answers a probe with. UNAVAILABLE is
// never the answer looked for, but what the client sees when the suite's
// port-forward, which ends at a connection the pod side resets, is being
// started again (run.sh): the probe is retried then.
func answer(ctx context.Context, c *authzed.Client, call probe) codes.Code {
	for range 5 {
		code := grpcstatus.Code(call(ctx, c))
		if code != codes.Unavailable {
			return code
		}
		time.Sleep(time.Second)
	}
	return codes.Unavailable
}

// The method table, each identity against every method: allowed is
// answered by SpiceDB (OK), anything else PERMISSION_DENIED by the gateway.
func TestSpiceDBGatewayMethodTable(t *testing.T) {
	requireSpiceDB(t)
	probes := map[string]probe{
		"CheckPermission":     checkPermission,
		"ReadRelationships":   readRelationships,
		"Watch":               watch,
		"WriteRelationships":  writeRelationships,
		"DeleteRelationships": deleteRelationships,
		"ReadSchema":          readSchema,
		"WriteSchema":         writeSchema,
	}
	read := []string{"CheckPermission", "ReadRelationships", "Watch"}
	allowed := map[string][]string{
		identityBroker:     read,
		identityAccess:     append(append([]string{}, read...), "WriteRelationships", "DeleteRelationships"),
		identityReconciler: {"ReadSchema", "WriteSchema"},
		identityIntruder:   nil,
	}
	for identity, methods := range allowed {
		t.Run(identity, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			c := mustDialAs(t, identity)
			for name, call := range probes {
				want := codes.PermissionDenied
				for _, m := range methods {
					if m == name {
						want = codes.OK
					}
				}
				if got := answer(ctx, c, call); got != want {
					t.Errorf("%s as %s: %v, want %v", name, identity, got, want)
				}
			}
		})
	}
}

// The broker's identity reads, and its write is refused at the gateway:
// a compromised broker cannot change who holds what.
func TestSpiceDBGatewayBrokerCannotWrite(t *testing.T) {
	requireSpiceDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c := mustDialAs(t, identityBroker)
	if code := answer(ctx, c, checkPermission); code != codes.OK {
		t.Fatalf("the broker cannot read: %v", code)
	}
	write := func(ctx context.Context, c *authzed.Client) error {
		_, err := c.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{Updates: []*v1.RelationshipUpdate{
			{Operation: v1.RelationshipUpdate_OPERATION_TOUCH, Relationship: rel(schema.TypeGrant, "e2e-s3-reader", schema.RelationAssigneeWorkload, schema.TypeWorkload, workloadID(unassignedSA), "")},
		}})
		return err
	}
	if code := answer(ctx, c, write); code != codes.PermissionDenied {
		t.Fatalf("the broker's write: %v, want PERMISSION_DENIED", code)
	}
}

// A client without a certificate does not get past the handshake, and one
// that is not the gateway's trust domain's gets no further.
func TestSpiceDBGatewayRequiresClientCertificate(t *testing.T) {
	requireSpiceDB(t)
	_, bundle, err := minted(identityBroker)
	if err != nil {
		t.Fatal(err)
	}
	// The gateway verified as usual; no certificate of the client's own.
	cfg := tlsconfig.TLSClientConfig(bundle, tlsconfig.AuthorizeID(gatewayID))
	cfg.MinVersion = tls.VersionTLS12
	c, err := authzed.NewClient(os.Getenv(spicedbEndpointEnv), grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = checkPermission(ctx, c)
	if err == nil || grpcstatus.Code(err) == codes.OK {
		t.Fatal("a client without a certificate was answered")
	}
	if code := grpcstatus.Code(err); code != codes.Unavailable {
		t.Errorf("without a certificate: %v, want UNAVAILABLE (the handshake failed)", err)
	}
}
