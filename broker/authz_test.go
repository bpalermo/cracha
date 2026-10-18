package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/bpalermo/cracha/broker/internal/authz"
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
