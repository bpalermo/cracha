package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/bpalermo/cracha/common/spicedb"
	"github.com/bpalermo/cracha/common/spiffetest"
)

const (
	gatewayID    = "spiffe://cracha.test/ns/cracha-system/sa/cracha-spicedb"
	reconcilerID = "spiffe://cracha.test/ns/cracha-system/sa/cracha-reconciler"
)

// fakeSchema is SpiceDB's SchemaService: it holds what was written, and
// answers ReadSchema with readBack when set.
type fakeSchema struct {
	v1.SchemaServiceClient
	written  []string
	readBack *string
	err      error
}

func (f *fakeSchema) WriteSchema(_ context.Context, in *v1.WriteSchemaRequest, _ ...grpc.CallOption) (*v1.WriteSchemaResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.written = append(f.written, in.GetSchema())
	return &v1.WriteSchemaResponse{}, nil
}

func (f *fakeSchema) ReadSchema(context.Context, *v1.ReadSchemaRequest, ...grpc.CallOption) (*v1.ReadSchemaResponse, error) {
	if f.readBack != nil {
		return &v1.ReadSchemaResponse{SchemaText: *f.readBack}, nil
	}
	return &v1.ReadSchemaResponse{SchemaText: f.written[len(f.written)-1]}, nil
}

// fakeDial hands the command the fake, recording the flags it was given.
func fakeDial(f *fakeSchema) (dialer, *connFlags) {
	var got connFlags
	return func(_ context.Context, cf *connFlags) (*session, error) {
		got = *cf
		return &session{schema: f, close: func() error { return nil }}, nil
	}, &got
}

// noDial fails the test when a command connects.
func noDial(t *testing.T) dialer {
	return func(context.Context, *connFlags) (*session, error) {
		t.Error("the command connected to SpiceDB")
		return nil, errors.New("no connection")
	}
}

var fileFlags = []string{"-endpoint", "gw:50051", "-server-spiffe-id", gatewayID, "-svid", "s.pem", "-svid-key", "k.pem", "-bundle", "b.pem"}

func TestRunUsage(t *testing.T) {
	tests := []struct {
		name string
		args []string
		code int
		want string // in stdout or stderr
	}{
		{"no command", nil, 2, "usage:"},
		{"unknown", []string{"nope"}, 2, `unknown command "nope"`},
		{"help", []string{"help"}, 0, "usage:"},
		{"version", []string{"--version"}, 0, "cracha-reconciler "},
		{"schema help", []string{"schema", "-h"}, 0, "-server-spiffe-id"},
		{"schema argument", []string{"schema", "x"}, 2, "takes no arguments"},
		{"schema no flags", []string{"schema"}, 2, "-endpoint and -server-spiffe-id are required"},
		{"schema bad id", []string{"schema", "-endpoint", "e", "-server-spiffe-id", "https://x"}, 2, "-server-spiffe-id"},
		{"schema no svid", []string{"schema", "-endpoint", "e", "-server-spiffe-id", gatewayID}, 2, "give -workload-api, or -svid"},
		{"schema partial files", []string{"schema", "-endpoint", "e", "-server-spiffe-id", gatewayID, "-svid", "s"}, 2, "give -workload-api, or -svid"},
		{"schema both sources", append([]string{"schema", "-workload-api", "unix:///x"}, fileFlags...), 2, "-workload-api excludes"},
		{"apply", []string{"apply", "-source", "grants"}, 2, "apply was removed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(tt.args, &stdout, &stderr, noDial(t)); code != tt.code {
				t.Errorf("exit %d, want %d; stderr: %s", code, tt.code, stderr.String())
			}
			if out := stdout.String() + stderr.String(); !strings.Contains(out, tt.want) {
				t.Errorf("output %q does not contain %q", out, tt.want)
			}
		})
	}
}

// apply names the access service, the one writer of relationships.
func TestApplyRefuses(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"apply"}, &stdout, &stderr, noDial(t)); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "cracha-access") || !strings.Contains(stderr.String(), "schema only") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestSchemaDryRunPrints(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"schema", "-dry-run"}, &stdout, &stderr, noDial(t)); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if stdout.String() != spicedb.Schema {
		t.Errorf("stdout = %q, want the schema", stdout.String())
	}
}

func TestSchemaWrites(t *testing.T) {
	f := &fakeSchema{}
	dial, flags := fakeDial(f)
	var stdout, stderr bytes.Buffer
	if code := run(append([]string{"schema"}, fileFlags...), &stdout, &stderr, dial); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if len(f.written) != 1 || f.written[0] != spicedb.Schema {
		t.Errorf("schema writes = %d", len(f.written))
	}
	if flags.endpoint != "gw:50051" || flags.server != gatewayID || flags.svid != "s.pem" || flags.svidKey != "k.pem" || flags.bundle != "b.pem" {
		t.Errorf("flags = %+v", *flags)
	}
	if !strings.Contains(stdout.String(), "wrote the schema to gw:50051") {
		t.Errorf("stdout = %q", stdout.String())
	}
}

// SpiceDB formats the schema it reads back its own way: what counts is
// that it declares every definition and caveat written.
func TestSchemaReadBack(t *testing.T) {
	formatted := strings.ReplaceAll(spicedb.Schema, "  ", "\t")
	f := &fakeSchema{readBack: &formatted}
	dial, _ := fakeDial(f)
	var stdout, stderr bytes.Buffer
	if code := run(append([]string{"schema"}, fileFlags...), &stdout, &stderr, dial); code != 0 {
		t.Fatalf("a reformatted schema: exit %d: %s", code, stderr.String())
	}
	older := "definition team {}\n\ndefinition service {}\n"
	f = &fakeSchema{readBack: &older}
	dial, _ = fakeDial(f)
	stderr.Reset()
	if code := run(append([]string{"schema"}, fileFlags...), &stdout, &stderr, dial); code != 1 {
		t.Fatalf("an older schema: exit %d, want 1: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "definition pending_request") {
		t.Errorf("stderr = %q, want the missing definitions named", stderr.String())
	}
}

func TestSchemaWriteFails(t *testing.T) {
	f := &fakeSchema{err: errors.New("PERMISSION_DENIED")}
	dial, _ := fakeDial(f)
	var stdout, stderr bytes.Buffer
	if code := run(append([]string{"schema"}, fileFlags...), &stdout, &stderr, dial); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "write schema: PERMISSION_DENIED") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

// gateway is SpiceDB's SchemaService behind SPIFFE mTLS, recording the
// client's SPIFFE ID.
type gateway struct {
	v1.UnimplementedSchemaServiceServer
	schema string
	client string
}

func (g *gateway) WriteSchema(ctx context.Context, in *v1.WriteSchemaRequest) (*v1.WriteSchemaResponse, error) {
	if p, ok := peer.FromContext(ctx); ok {
		if id, err := x509svid.IDFromCert(p.AuthInfo.(credentials.TLSInfo).State.PeerCertificates[0]); err == nil {
			g.client = id.String()
		}
	}
	g.schema = in.GetSchema()
	return &v1.WriteSchemaResponse{}, nil
}

func (g *gateway) ReadSchema(context.Context, *v1.ReadSchemaRequest) (*v1.ReadSchemaResponse, error) {
	return &v1.ReadSchemaResponse{SchemaText: g.schema}, nil
}

func writePEM(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The SVID files, as the issuer mints them, reach a gateway that verifies
// the reconciler's SPIFFE ID, and the reconciler verifies the gateway's.
func TestSchemaWithSVIDFiles(t *testing.T) {
	ca := spiffetest.NewCA(t, "cracha.test")
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g := &gateway{}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsconfig.MTLSServerConfig(ca.SVID(t, gatewayID), ca.Bundle(), tlsconfig.AuthorizeAny()))))
	v1.RegisterSchemaServiceServer(srv, g)
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	dir := t.TempDir()
	certs, key, err := ca.SVID(t, reconcilerID).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := ca.Bundle().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"schema", "-endpoint", lis.Addr().String(), "-server-spiffe-id", gatewayID,
		"-svid", writePEM(t, dir, "svid.pem", certs), "-svid-key", writePEM(t, dir, "key.pem", key), "-bundle", writePEM(t, dir, "bundle.pem", bundle)}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr, dial); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if g.schema != spicedb.Schema || g.client != reconcilerID {
		t.Errorf("the gateway got the schema %v from %q", g.schema == spicedb.Schema, g.client)
	}

	// Another gateway ID: refused at the handshake.
	args[4] = "spiffe://cracha.test/ns/cracha-system/sa/impostor"
	stderr.Reset()
	if code := run(args, &stdout, &stderr, dial); code != 2 {
		t.Fatalf("an impostor gateway: exit %d, want 2", code)
	}
	// A missing file is an error before any connection.
	args[4], args[6] = gatewayID, filepath.Join(dir, "none.pem")
	stderr.Reset()
	if code := run(args, &stdout, &stderr, dial); code != 2 || !strings.Contains(stderr.String(), "svid:") {
		t.Fatalf("a missing SVID: exit %d: %s", code, stderr.String())
	}
}
