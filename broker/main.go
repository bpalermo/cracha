// Command cracha-broker issues AWS credentials to workloads: it verifies a
// pod's JWT-SVID, consults the authorization store, composes the session
// policy from the workload's grants and assumes a shape role on the
// workload's behalf (docs/design.md, section 6).
//
// It serves SPIFFE mTLS with its own X.509-SVID from the Workload API and
// accepts one client, the node agent (--agent-spiffe-id, section 6.5); the
// kubelet's probes are answered on a plaintext listener of their own
// (--health-listen). Grants come from the signed, polled bundle grantc
// publishes (--bundle-source, broker/internal/bundle) or, for development,
// from a resolved-grants fixture file (--grants-fixture); the
// authorization backend is the static one, its assignments from a file or
// from the same publication as the bundle (--assignments-source), or
// SpiceDB (--authz-backend, authz.go), and the credential cache (design 6.7) wraps
// the issuer unless --cache=false. Revocation comes later. Configuration
// is by flags, each with a CRACHA_* environment fallback (see config.go).
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/bpalermo/cracha/broker/internal/api"
	"github.com/bpalermo/cracha/broker/internal/authn"
	"github.com/bpalermo/cracha/broker/internal/authz"
	"github.com/bpalermo/cracha/broker/internal/cache"
	"github.com/bpalermo/cracha/broker/internal/health"
	"github.com/bpalermo/cracha/broker/internal/issuer"
	"github.com/bpalermo/cracha/broker/internal/mtls"
	"github.com/bpalermo/cracha/broker/internal/sts"
	"github.com/bpalermo/cracha/common/version"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

func main() {
	cfg, err := parseConfig(os.Args[1:], os.LookupEnv, os.Stderr)
	switch {
	case errors.Is(err, errVersion):
		fmt.Printf("cracha-broker %s\n", version.Version)
		return
	case err != nil:
		fmt.Fprintf(os.Stderr, "cracha-broker: %v\n", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "cracha-broker: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg config) error {
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.logLevel)); err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(log)
	log.Info("starting", "version", version.Version, "cluster", cfg.cluster, "listen", cfg.listen,
		"health_listen", cfg.healthListen, "trust_domain_labels", cfg.labels.String())

	// The probes first, so that liveness answers while the rest comes up;
	// readiness waits for the broker's SVID and, below, the grant bundle.
	probes := health.New(log)
	svidReady := &mtls.SVIDReadiness{}
	probes.AddReadiness(svidReady)
	servers := newServers(cfg, probes)
	servers.serve("health", servers.health.ListenAndServe)

	store, err := newStore(cfg, log)
	if err != nil {
		return err
	}
	defer store.Close()

	var awsOpts []func(*awsconfig.LoadOptions) error
	if cfg.awsRegion != "" {
		awsOpts = append(awsOpts, awsconfig.WithRegion(cfg.awsRegion))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsOpts...)
	if err != nil {
		return fmt.Errorf("aws config: %w", err)
	}

	src, err := newGrantSource(ctx, cfg, awsCfg, store.assignments, log)
	if err != nil {
		return err
	}
	if src.ready != nil {
		probes.AddReadiness(src.ready)
	}

	wl, err := connectWorkloadAPI(ctx, cfg.workloadAPISocket)
	if err != nil {
		return fmt.Errorf("workload api %s: %w", cfg.workloadAPISocket, err)
	}
	defer wl.Close()
	svidReady.Set(wl.x509)
	agent, err := agentID(cfg, wl)
	if err != nil {
		return err
	}
	own, err := wl.x509.GetX509SVID()
	if err != nil {
		return fmt.Errorf("own X.509-SVID: %w", err)
	}
	log.Info("connected to the workload api", "socket", cfg.workloadAPISocket, "spiffe_id", own.ID.String(), "agent_spiffe_id", agent.String())

	direct := &issuer.Direct{
		Store: store.Store,
		// The source itself, not its readiness wrapper, so that a bundle's
		// implicit grants (grants.ImplicitSource) reach Compose.
		Grants:  src.Source,
		STS:     sts.NewFromConfig(awsCfg),
		Labels:  cfg.labels,
		Cluster: cfg.cluster,
		Log:     log,
	}
	iss := newIssuer(ctx, cfg, direct, store.Store, log)
	servers.api.Handler = mtls.Require(agent, log, api.New(authn.New(wl.jwt), iss, log))
	servers.api.TLSConfig = mtls.ServerConfig(wl.x509, wl.x509, agent)
	servers.serve("api", func() error { return servers.api.ListenAndServeTLS("", "") })
	return servers.wait(ctx, log)
}

// agentID is the one client identity the broker accepts: --agent-spiffe-id,
// or by default the agent's service account in the broker's namespace and
// the trust domain of the broker's own SVID (design 6.5).
func agentID(cfg config, wl *workloadAPI) (spiffeid.ID, error) {
	if !cfg.agentID.IsZero() {
		return cfg.agentID, nil
	}
	id, err := mtls.DefaultAgentID(wl.x509, cfg.namespace)
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("deriving the agent's SPIFFE ID: %w", err)
	}
	return id, nil
}

// servers is the broker's two listeners: the API over SPIFFE mTLS, and the
// probes over plain HTTP. The first to fail ends the process.
type servers struct {
	api    *http.Server
	health *http.Server
	errc   chan error
}

func newServers(cfg config, probes http.Handler) *servers {
	return &servers{
		api: &http.Server{
			Addr:              cfg.listen,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       2 * time.Minute,
			MaxHeaderBytes:    64 << 10,
		},
		health: &http.Server{
			Addr:              cfg.healthListen,
			Handler:           probes,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       2 * time.Minute,
			MaxHeaderBytes:    64 << 10,
		},
		errc: make(chan error, 2),
	}
}

// serve runs one listener until it fails.
func (s *servers) serve(name string, listen func() error) {
	go func() {
		if err := listen(); !errors.Is(err, http.ErrServerClosed) {
			s.errc <- fmt.Errorf("serve %s: %w", name, err)
		}
	}()
}

// wait blocks until a listener fails or ctx ends, then shuts both down.
func (s *servers) wait(ctx context.Context, log *slog.Logger) error {
	select {
	case err := <-s.errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return errors.Join(s.api.Shutdown(shutdownCtx), s.health.Shutdown(shutdownCtx))
}

// newIssuer wraps the direct issuer in the credential cache of design 6.7,
// unless --cache=false keeps every request on the direct path.
func newIssuer(ctx context.Context, cfg config, direct *issuer.Direct, store authz.Store, log *slog.Logger) issuer.Issuer {
	if !cfg.cache {
		log.Warn("credential cache off; every request calls STS")
		return direct
	}
	c := cache.New(direct, store, cache.Options{
		MinRemaining:  cfg.cacheMinRemaining,
		RefreshAt:     cfg.cacheRefreshAt,
		MaxEntries:    cfg.cacheMaxEntries,
		StaleCheckMax: cfg.cacheStaleCheckMax,
		Log:           log,
	})
	go c.Run(ctx)
	log.Info("credential cache on", "mode", string(c.Mode()), "min_remaining", cfg.cacheMinRemaining,
		"refresh_at", cfg.cacheRefreshAt, "max_entries", cfg.cacheMaxEntries, "stale_check_max", cfg.cacheStaleCheckMax)
	return c
}
