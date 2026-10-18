package main

import (
	"fmt"
	"log/slog"

	"github.com/bpalermo/cracha/broker/internal/authz"
	"github.com/bpalermo/cracha/broker/internal/authz/spicedb"
	"github.com/bpalermo/cracha/broker/internal/authz/static"
	"github.com/bpalermo/cracha/broker/internal/bundle"
)

// authzStore is the broker's authorization store with whatever the backend
// holds open: SpiceDB's connection; nothing for the static one. What the
// issuer and the cache get is Store itself, never this wrapper: the cache
// finds Watch on the store by type assertion (cache.New), and a wrapper
// would hide it and leave the cache in TTL mode.
type authzStore struct {
	authz.Store
	close func() error
	// assignments is the static store when it reads its assignments from
	// the publication: the grant source hands it every version's
	// assignments with the bundle (grants.go). nil otherwise.
	assignments bundle.AssignmentsSink
}

// Close releases what the backend holds open.
func (s authzStore) Close() error {
	if s.close == nil {
		return nil
	}
	return s.close()
}

// newStore opens the authorization backend the configuration names (design
// 6.3): the static backend, with the assignments file read once or, empty
// until the grant source verifies a first version, the published
// assignments; or SpiceDB, dialed lazily so a SpiceDB that is down denies
// requests rather than keeping the broker from starting.
func newStore(cfg config, log *slog.Logger) (authzStore, error) {
	switch cfg.authzBackend {
	case backendStatic:
		if cfg.assignmentsSource == assignmentsPublished {
			s := static.NewEmpty()
			log.Info("authorization backend static", "assignments_source", assignmentsPublished, "bundle_source", cfg.bundleSource)
			return authzStore{Store: s, assignments: s}, nil
		}
		s, err := static.Load(cfg.assignments)
		if err != nil {
			return authzStore{}, err
		}
		log.Info("authorization backend static", "assignments_source", assignmentsFile, "path", cfg.assignments, "consistency_token", string(s.Token()))
		return authzStore{Store: s}, nil
	case backendSpiceDB:
		s, err := spicedb.Dial(spicedb.Config{
			Endpoint:  cfg.spicedbEndpoint,
			TokenFile: cfg.spicedbTokenFile,
			CAFile:    cfg.spicedbCA,
			Insecure:  cfg.spicedbInsecure,
		}, spicedb.WithTimeout(cfg.spicedbTimeout), spicedb.WithLogger(log))
		if err != nil {
			return authzStore{}, err
		}
		if cfg.spicedbInsecure {
			log.Warn("speaking plaintext gRPC to SpiceDB; the preshared key travels in the clear")
		}
		log.Info("authorization backend spicedb", "endpoint", cfg.spicedbEndpoint, "ca", cfg.spicedbCA, "timeout", cfg.spicedbTimeout)
		return authzStore{Store: s, close: s.Close}, nil
	}
	return authzStore{}, fmt.Errorf("authorization backend %q is not static or spicedb", cfg.authzBackend)
}
