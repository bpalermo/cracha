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
	"github.com/bpalermo/cracha/common/spiffetest"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// The SpiceDB store the broker opens has Watch, and what main hands the
// cache is that store, not the wrapper that holds its connection: the cache
// finds Watch by type assertion (design 6.7), and a wrapper without it
// would leave the cache in TTL mode without a word.
func TestSpiceDBStoreWatches(t *testing.T) {
	// Dial is lazy: no SpiceDB is needed to open the store.
	s, err := newStore(config{authzBackend: backendSpiceDB, spicedbEndpoint: "127.0.0.1:1", namespace: "cracha-system"},
		testSVIDs(t), slog.New(slog.NewTextHandler(io.Discard, nil)))
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

// testSVIDs is the broker's SVID and bundle, from a test authority.
func testSVIDs(t *testing.T) svidSource {
	ca := spiffetest.NewCA(t, "cracha.test")
	return struct {
		*x509svid.SVID
		*x509bundle.Bundle
	}{ca.SVID(t, "spiffe://cracha.test/ns/cracha-system/sa/cracha-broker"), ca.Bundle()}
}

// The gateway's SPIFFE ID: the default in the broker's trust domain and
// namespace, a path completed in that trust domain, or a full ID.
func TestSpiceDBServerID(t *testing.T) {
	svids := testSVIDs(t)
	full := spiffeid.RequireFromString("spiffe://other.test/ns/x/sa/gw")
	for name, tc := range map[string]struct {
		cfg  config
		want string
	}{
		"default": {config{namespace: "cracha-system"}, "spiffe://cracha.test/ns/cracha-system/sa/cracha-spicedb"},
		"path":    {config{spicedbServerID: "/ns/authz/sa/spicedb"}, "spiffe://cracha.test/ns/authz/sa/spicedb"},
		"full":    {config{spicedbServerID: full.String(), spicedbServer: full}, full.String()},
	} {
		t.Run(name, func(t *testing.T) {
			id, err := spicedbServerID(tc.cfg, svids)
			if err != nil || id.String() != tc.want {
				t.Fatalf("got %v, %v; want %s", id, err, tc.want)
			}
		})
	}
}

// The static store reading the published assignments is the grant source's
// sink, starts empty (denying) and watches, so its swaps flush the cache.
func TestPublishedStaticStore(t *testing.T) {
	s, err := newStore(config{authzBackend: backendStatic, assignmentsSource: assignmentsPublished, bundleSource: "local:/b"},
		nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
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
	s, err = newStore(config{authzBackend: backendStatic, assignmentsSource: assignmentsFile, assignments: file}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
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
