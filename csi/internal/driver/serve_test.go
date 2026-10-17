package driver

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/bpalermo/cracha/csi/internal/issuer"
)

func TestParseEndpoint(t *testing.T) {
	for in, want := range map[string]string{
		"unix:///csi/csi.sock":  "/csi/csi.sock",
		"unix:/csi/csi.sock":    "/csi/csi.sock",
		"/csi/csi.sock":         "/csi/csi.sock",
		"unix://csi/csi.sock":   "csi/csi.sock",
		"unix:///csi//csi.sock": "/csi/csi.sock",
	} {
		got, err := ParseEndpoint(in)
		if err != nil || got != want {
			t.Errorf("ParseEndpoint(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "tcp://127.0.0.1:10000", "unix://"} {
		if got, err := ParseEndpoint(in); err == nil {
			t.Errorf("ParseEndpoint(%q) = %q, want an error", in, got)
		}
	}
}

func TestServe(t *testing.T) {
	h := newHarness(t, issuer.NewFake(), goodReviewer())
	// A short directory: Unix socket paths are limited to ~100 bytes.
	dir, err := os.MkdirTemp("", "cracha-csi")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "csi.sock")

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- Serve(ctx, ServeConfig{Socket: socket}, h.d, h.d.log) }()

	deadline := time.Now().Add(5 * time.Second)
	for probeSocket(socket) != nil {
		if time.Now().After(deadline) {
			t.Fatal("the socket never appeared")
		}
		time.Sleep(10 * time.Millisecond)
	}

	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	info, err := csi.NewIdentityClient(conn).GetPluginInfo(ctx, &csi.GetPluginInfoRequest{})
	if err != nil || info.GetName() != DriverName {
		t.Fatalf("GetPluginInfo over the socket: %v, %v", info, err)
	}
	node, err := csi.NewNodeClient(conn).NodeGetInfo(ctx, &csi.NodeGetInfoRequest{})
	if err != nil || node.GetNodeId() != "node-1" {
		t.Fatalf("NodeGetInfo over the socket: %v, %v", node, err)
	}

	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Errorf("Serve returned %v on cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after cancellation")
	}
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the socket remains after shutdown: %v", err)
	}
}

func TestListenUnixRefusesNonSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "csi.sock")
	if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listenUnix(path); err == nil {
		t.Fatal("listenUnix replaced a regular file")
	}
}
