// Package spicedb_test is the smoke test of the SpiceDB binary Crachá builds
// and publishes (//bazel/spicedb:spicedb): it reports this build's
// version, it has the flags of the SPIFFE datastore identity patch, and it serves a
// schema write, a relationship write and a permission check end to end on the
// in-memory datastore.
package spicedb_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	authzed "github.com/authzed/authzed-go/v1"
	"github.com/bazelbuild/rules_go/go/runfiles"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const presharedKey = "smoke-test-key"

const schema = `
definition user {}

definition document {
	relation viewer: user
	permission view = viewer
}
`

// runfile resolves the runfile whose rlocation path the environment variable
// env holds (set by the test's BUILD rule).
func runfile(t *testing.T, env string) string {
	t.Helper()
	rlocation := os.Getenv(env)
	if rlocation == "" {
		t.Fatalf("%s is not set; run the test with Bazel", env)
	}
	path, err := runfiles.Rlocation(rlocation)
	if err != nil {
		t.Fatalf("resolving %s: %v", rlocation, err)
	}
	return path
}

// binary is the path of the spicedb binary.
func binary(t *testing.T) string {
	t.Helper()
	return runfile(t, "SPICEDB_RLOCATIONPATH")
}

func run(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(binary(t), args...).CombinedOutput()
	if err != nil {
		t.Fatalf("spicedb %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func TestVersionIsThisBuild(t *testing.T) {
	want := os.Getenv("SPICEDB_VERSION")
	if want == "" {
		t.Fatal("SPICEDB_VERSION is not set; run the test with Bazel")
	}
	if out := run(t, "version"); !strings.Contains(out, want) {
		t.Fatalf("spicedb version = %q, want it to report %s", out, want)
	}
}

// TestVersionMatchesGoMod holds the stamped version to the release go.mod
// pins: the suffix is Crachá's, the release before it must be the module's.
func TestVersionMatchesGoMod(t *testing.T) {
	gomod, err := os.ReadFile(runfile(t, "GO_MOD_RLOCATIONPATH"))
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	release, _, _ := strings.Cut(os.Getenv("SPICEDB_VERSION"), "-cracha.")
	want := "\tgithub.com/authzed/spicedb " + release + "\n"
	if !strings.Contains(string(gomod), want) {
		t.Fatalf("go.mod does not require github.com/authzed/spicedb %s, the release SPICEDB_VERSION of //bazel/spicedb names", release)
	}
}

func TestHasTheSPIFFEFlags(t *testing.T) {
	for _, cmd := range [][]string{{"serve"}, {"migrate"}, {"datastore", "migrate"}} {
		help := run(t, append(cmd, "--help")...)
		for _, flag := range []string{
			"--datastore-spiffe",
			"--datastore-spiffe-id",
			"--datastore-spiffe-server-id",
			"--datastore-spiffe-socket",
		} {
			if !strings.Contains(help, flag+" ") {
				t.Errorf("spicedb %s --help does not list %s", strings.Join(cmd, " "), flag)
			}
		}
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// serve starts `spicedb serve` on the in-memory datastore and returns a
// client for it. Nothing leaves the host: telemetry and the release check are
// off, and so are the HTTP gateway and the metrics server.
func serve(t *testing.T) *authzed.Client {
	t.Helper()
	addr := freeAddr(t)
	cmd := exec.Command(binary(t), "serve",
		"--datastore-engine", "memory",
		"--grpc-preshared-key", presharedKey,
		"--grpc-addr", addr,
		"--http-enabled=false",
		"--metrics-enabled=false",
		"--telemetry-endpoint=",
		"--skip-release-check",
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting spicedb serve: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	client, err := authzed.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithPerRPCCredentials(bearer(presharedKey)),
	)
	if err != nil {
		t.Fatalf("dialling spicedb: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// writeSchema writes the schema, retrying while the server starts.
func writeSchema(ctx context.Context, t *testing.T, client *authzed.Client) {
	t.Helper()
	for {
		_, err := client.WriteSchema(ctx, &v1.WriteSchemaRequest{Schema: schema})
		if err == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("WriteSchema never succeeded: %v", err)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func TestServeChecksAPermission(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	client := serve(t)
	writeSchema(ctx, t, client)

	doc := &v1.ObjectReference{ObjectType: "document", ObjectId: "readme"}
	written, err := client.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{
		Updates: []*v1.RelationshipUpdate{{
			Operation: v1.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &v1.Relationship{
				Resource: doc,
				Relation: "viewer",
				Subject:  &v1.SubjectReference{Object: &v1.ObjectReference{ObjectType: "user", ObjectId: "alice"}},
			},
		}},
	})
	if err != nil {
		t.Fatalf("WriteRelationships: %v", err)
	}

	for user, want := range map[string]v1.CheckPermissionResponse_Permissionship{
		"alice": v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION,
		"bob":   v1.CheckPermissionResponse_PERMISSIONSHIP_NO_PERMISSION,
	} {
		resp, err := client.CheckPermission(ctx, &v1.CheckPermissionRequest{
			Consistency: &v1.Consistency{Requirement: &v1.Consistency_AtLeastAsFresh{AtLeastAsFresh: written.WrittenAt}},
			Resource:    doc,
			Permission:  "view",
			Subject:     &v1.SubjectReference{Object: &v1.ObjectReference{ObjectType: "user", ObjectId: user}},
		})
		if err != nil {
			t.Fatalf("CheckPermission %s: %v", user, err)
		}
		if got := resp.GetPermissionship(); got != want {
			t.Errorf("CheckPermission document:readme#view@user:%s = %v, want %v", user, got, want)
		}
	}
}

// bearer is the preshared key as gRPC per-RPC credentials over plaintext.
type bearer string

func (b bearer) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": fmt.Sprintf("Bearer %s", string(b))}, nil
}

func (bearer) RequireTransportSecurity() bool { return false }
