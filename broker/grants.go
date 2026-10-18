package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/bpalermo/cracha/broker/internal/bundle"
	"github.com/bpalermo/cracha/broker/internal/grants"
	"github.com/bpalermo/cracha/broker/internal/health"
	"github.com/bpalermo/cracha/common/grant"
)

// grantSource is the broker's grants with, for the compiled bundle, the
// readiness check that keeps the broker out of service until one has
// loaded.
type grantSource struct {
	grants.Source
	ready health.Readiness
}

// newGrantSource opens the grant source the configuration names: the
// signed, polled bundle (production) or the resolved-grants fixture
// (development). The bundle's first load is attempted here and its result
// logged; a failure is not fatal, since the broker stays not ready until a
// bundle verifies, and polling continues in the background until ctx ends.
func newGrantSource(ctx context.Context, cfg config, awsCfg aws.Config, log *slog.Logger) (grantSource, error) {
	if cfg.bundleSource == "" {
		src, err := grants.LoadFixture(cfg.grantsFixture)
		if err != nil {
			return grantSource{}, err
		}
		log.Info("loaded grants fixture", "path", cfg.grantsFixture, "bundle_version", src.Version(), "grants", src.Names())
		return grantSource{Source: src}, nil
	}
	verifier, err := newVerifier(cfg, awsCfg)
	if err != nil {
		return grantSource{}, err
	}
	var fetcher bundle.Fetcher = &bundle.Local{Root: cfg.bundle.Dir}
	if cfg.bundle.IsS3() {
		fetcher = bundle.NewS3(s3.NewFromConfig(awsCfg), cfg.bundle.Bucket, cfg.bundle.Prefix)
	}
	src := bundle.New(fetcher, verifier, bundle.Options{PollInterval: cfg.pollInterval, Log: log})
	if err := src.Reload(ctx); err != nil {
		log.Warn("no grant bundle in service yet; not ready until one verifies", "source", cfg.bundleSource, "error", err)
	} else {
		log.Info("grant bundle in service", "source", cfg.bundleSource, "bundle_version", src.Version(), "poll_interval", cfg.pollInterval)
	}
	go src.Run(ctx)
	return grantSource{Source: src, ready: src}, nil
}

// newVerifier makes the verifier the configuration names: the PEM public
// key, or the KMS key through kms:Verify.
func newVerifier(cfg config, awsCfg aws.Config) (grant.Verifier, error) {
	if cfg.bundleKMSKey != "" {
		return grant.NewKMSVerifier(kms.NewFromConfig(awsCfg), cfg.bundleKMSKey), nil
	}
	pemData, err := os.ReadFile(cfg.bundleVerifyKey)
	if err != nil {
		return nil, fmt.Errorf("bundle verify key: %w", err)
	}
	pub, err := grant.ParseECPublicKey(pemData)
	if err != nil {
		return nil, fmt.Errorf("bundle verify key %s: %w", cfg.bundleVerifyKey, err)
	}
	verifier, err := grant.NewLocalVerifier(pub)
	if err != nil {
		return nil, fmt.Errorf("bundle verify key %s: %w", cfg.bundleVerifyKey, err)
	}
	return verifier, nil
}
