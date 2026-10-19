package main

import (
	"fmt"
	"log/slog"

	"github.com/bpalermo/cracha/broker/internal/authz"
	"github.com/bpalermo/cracha/broker/internal/authz/spicedb"
	"github.com/bpalermo/cracha/broker/internal/authz/static"
	"github.com/bpalermo/cracha/broker/internal/bundle"
	"github.com/bpalermo/cracha/common/spicedb/conn"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
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
// assignments; or SpiceDB, dialed lazily through its gateway over SPIFFE
// mTLS with the broker's own SVID and bundles (svids), so a SpiceDB that is
// down denies requests rather than keeping the broker from starting.
func newStore(cfg config, svids svidSource, log *slog.Logger) (authzStore, error) {
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
		server, err := spicedbServerID(cfg, svids)
		if err != nil {
			return authzStore{}, err
		}
		s, err := spicedb.Dial(conn.Config{
			Endpoint: cfg.spicedbEndpoint,
			Server:   server,
			SVIDs:    svids,
			Bundles:  svids,
		}, spicedb.WithTimeout(cfg.spicedbTimeout), spicedb.WithLogger(log))
		if err != nil {
			return authzStore{}, err
		}
		log.Info("authorization backend spicedb", "endpoint", cfg.spicedbEndpoint, "server_spiffe_id", server.String(), "timeout", cfg.spicedbTimeout)
		return authzStore{Store: s, close: s.Close}, nil
	}
	return authzStore{}, fmt.Errorf("authorization backend %q is not static or spicedb", cfg.authzBackend)
}

// svidSource is the broker's X.509-SVID and its trust bundles: the
// Workload API's X509Source in production.
type svidSource interface {
	x509svid.Source
	x509bundle.Source
}

// spicedbServerID is the SPIFFE ID the SpiceDB gateway must present:
// --spicedb-server-spiffe-id when it is a full ID, else that path, or the
// default /ns/<namespace>/sa/cracha-spicedb, in the trust domain of the
// broker's own SVID.
func spicedbServerID(cfg config, svids x509svid.Source) (spiffeid.ID, error) {
	if !cfg.spicedbServer.IsZero() {
		return cfg.spicedbServer, nil
	}
	own, err := svids.GetX509SVID()
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("own X.509-SVID: %w", err)
	}
	if cfg.spicedbServerID == "" {
		return conn.DefaultServerID(own.ID.TrustDomain(), cfg.namespace)
	}
	id, err := spiffeid.FromPath(own.ID.TrustDomain(), cfg.spicedbServerID)
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("--spicedb-server-spiffe-id %q: %w", cfg.spicedbServerID, err)
	}
	return id, nil
}
