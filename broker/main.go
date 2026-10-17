// Command cracha-broker issues AWS credentials to workloads: it verifies a
// pod's JWT-SVID, consults the authorization store, composes the session
// policy from the workload's grants and assumes a shape role on the
// workload's behalf (docs/design.md, section 6).
//
// This slice wires the static authorization backend, a resolved-grants
// fixture file and the credential cache; the compiled bundle loader and
// revocation come later. Configuration is by flags, each with a CRACHA_*
// environment fallback (see config.go).
package main

import (
	"context"
	"crypto/tls"
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
	"github.com/bpalermo/cracha/broker/internal/authz/static"
	"github.com/bpalermo/cracha/broker/internal/cache"
	"github.com/bpalermo/cracha/broker/internal/grants"
	"github.com/bpalermo/cracha/broker/internal/issuer"
	"github.com/bpalermo/cracha/broker/internal/sts"
	"github.com/bpalermo/cracha/common/version"
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
		"trust_domain_labels", cfg.labels.String(), "plaintext", cfg.insecurePlaintext)

	store, err := static.Load(cfg.assignments)
	if err != nil {
		return err
	}
	log.Info("loaded assignments", "path", cfg.assignments, "consistency_token", string(store.Token()))

	src, err := grants.LoadFixture(cfg.grantsFixture)
	if err != nil {
		return err
	}
	log.Info("loaded grants fixture", "path", cfg.grantsFixture, "bundle_version", src.Version(), "grants", src.Names())

	var awsOpts []func(*awsconfig.LoadOptions) error
	if cfg.awsRegion != "" {
		awsOpts = append(awsOpts, awsconfig.WithRegion(cfg.awsRegion))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsOpts...)
	if err != nil {
		return fmt.Errorf("aws config: %w", err)
	}

	bundles, err := authn.NewWorkloadAPISource(ctx, cfg.workloadAPISocket)
	if err != nil {
		return fmt.Errorf("workload api %s: %w", cfg.workloadAPISocket, err)
	}
	defer bundles.Close()
	log.Info("connected to the workload api", "socket", cfg.workloadAPISocket)

	direct := &issuer.Direct{
		Store:   store,
		Grants:  src,
		STS:     sts.NewFromConfig(awsCfg),
		Labels:  cfg.labels,
		Cluster: cfg.cluster,
		Log:     log,
	}
	iss := newIssuer(ctx, cfg, direct, store, log)
	srv := &http.Server{
		Addr:              cfg.listen,
		Handler:           api.New(authn.New(bundles), iss, log),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}

	errc := make(chan error, 1)
	go func() {
		if cfg.insecurePlaintext {
			log.Warn("serving plaintext HTTP; JWT-SVIDs travel in the clear")
			errc <- srv.ListenAndServe()
			return
		}
		errc <- srv.ListenAndServeTLS(cfg.tlsCert, cfg.tlsKey)
	}()

	select {
	case err := <-errc:
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
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
