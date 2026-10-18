package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/bpalermo/cracha/broker/internal/authz"
	"github.com/bpalermo/cracha/common/grant"
)

// The SpiceDB store the broker opens has Watch, and what main hands the
// cache is that store, not the wrapper that holds its connection: the cache
// finds Watch by type assertion (design 6.7), and a wrapper without it
// would leave the cache in TTL mode without a word.
func TestSpiceDBStoreWatches(t *testing.T) {
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Dial is lazy: no SpiceDB is needed to open the store.
	s, err := newStore(config{authzBackend: backendSpiceDB, spicedbEndpoint: "127.0.0.1:1", spicedbTokenFile: token, spicedbInsecure: true},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, ok := s.Store.(authz.Watcher); !ok {
		t.Fatalf("the spicedb store %T has no Watch", s.Store)
	}
	if _, ok := any(s).(authz.Watcher); ok {
		t.Fatal("the wrapper forwards Watch; main must still hand the cache the store itself")
	}
}

// The static store reading the published assignments is the grant source's
// sink, starts empty (denying) and watches, so its swaps flush the cache.
func TestPublishedStaticStore(t *testing.T) {
	s, err := newStore(config{authzBackend: backendStatic, assignmentsSource: assignmentsPublished, bundleSource: "local:/b"},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if s.assignments == nil {
		t.Fatal("the published static store is not the grant source's sink")
	}
	if _, ok := s.Store.(authz.Watcher); !ok {
		t.Fatalf("the static store %T has no Watch", s.Store)
	}
	if _, err := s.ListGrants(context.Background(), authz.Subject{ID: "cracha/e2e/client"}, authz.Consistency{}); err == nil {
		t.Error("the store answered before any assignments were published")
	}
	file := filepath.Join(t.TempDir(), "a.yaml")
	if err := os.WriteFile(file, []byte("services: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err = newStore(config{authzBackend: backendStatic, assignmentsSource: assignmentsFile, assignments: file}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil || s.assignments != nil {
		t.Errorf("the file store: %v, sink %v", err, s.assignments)
	}
}

// Every key of every --bundle-verify-key file verifies.
func TestLoadKeyRing(t *testing.T) {
	dir := t.TempDir()
	var keys []*ecdsa.PrivateKey
	var paths []string
	for i, n := range []int{2, 1} {
		var pemData []byte
		for range n {
			k, _ := grant.GenerateKey()
			keys = append(keys, k)
			p, _ := grant.EncodeECPublicKey(&k.PublicKey)
			pemData = append(pemData, p...)
		}
		path := filepath.Join(dir, fmt.Sprintf("keys-%d.pem", i))
		if err := os.WriteFile(path, pemData, 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	ring, err := loadKeyRing(paths)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte(`{}`)
	for i, k := range keys {
		signer, _ := grant.NewLocalSigner(k)
		sig, _ := signer.Sign(context.Background(), data)
		if err := ring.Verify(context.Background(), data, sig); err != nil {
			t.Errorf("key %d: %v", i, err)
		}
	}
	if _, err := loadKeyRing([]string{paths[0], paths[0]}); err == nil {
		t.Error("the same keys twice were accepted")
	}
	if _, err := loadKeyRing([]string{filepath.Join(dir, "missing.pem")}); err == nil {
		t.Error("a missing key file was accepted")
	}
}
