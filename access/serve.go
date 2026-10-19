package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	authzed "github.com/authzed/authzed-go/v1"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/bpalermo/cracha/access/internal/api"
	"github.com/bpalermo/cracha/access/internal/audit"
	"github.com/bpalermo/cracha/access/internal/check"
	"github.com/bpalermo/cracha/access/internal/service"
	"github.com/bpalermo/cracha/access/internal/store"
	"github.com/bpalermo/cracha/common/grant"
	"github.com/bpalermo/cracha/common/publication"
	"github.com/bpalermo/cracha/common/spicedb/conn"
	"github.com/bpalermo/cracha/common/version"
)

func newLogger(level string) (*slog.Logger, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		return nil, err
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: l})), nil
}

// dialSpiceDB opens the client to SpiceDB through the gateway
// (common/spicedb/conn): SPIFFE mTLS with cracha-access's own SVID, the
// gateway verified by its SPIFFE ID (design 6.9). The connection is lazy.
func dialSpiceDB(f spicedbFlags, src *workloadapi.X509Source) (*authzed.Client, error) {
	own, err := src.GetX509SVID()
	if err != nil {
		return nil, fmt.Errorf("own X.509-SVID: %w", err)
	}
	server, err := f.resolve(own.ID.TrustDomain())
	if err != nil {
		return nil, err
	}
	return conn.Dial(conn.Config{Endpoint: f.endpoint, Server: server, SVIDs: src, Bundles: src})
}

func runServe(ctx context.Context, cfg serveConfig) error {
	log, err := newLogger(cfg.logLevel)
	if err != nil {
		return err
	}
	slog.SetDefault(log)
	log.Info("starting", "version", version.Version, "listen", cfg.listen, "spicedb", cfg.spicedb.endpoint,
		"bundle_source", cfg.bundleSource, "access_analyzer", cfg.accessAnalyzer, "break_glass_max", cfg.breakGlassMax, "pending_ttl", cfg.pendingTTL)
	probes := &probes{}
	health := &http.Server{Addr: cfg.healthListen, Handler: probes, ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 2)
	go func() { errc <- serveHTTP(health) }()

	awsCfg, err := loadAWS(ctx, cfg.awsRegion)
	if err != nil {
		return err
	}
	poller, err := newPoller(ctx, cfg, awsCfg, log)
	if err != nil {
		return err
	}
	src, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(cfg.workloadAPISocket)))
	if err != nil {
		return fmt.Errorf("workload api %s: %w", cfg.workloadAPISocket, err)
	}
	defer src.Close()
	own, err := src.GetX509SVID()
	if err != nil {
		return fmt.Errorf("own X.509-SVID: %w", err)
	}
	probes.set(poller, src)
	client, err := dialSpiceDB(cfg.spicedb, src)
	if err != nil {
		return err
	}
	defer client.Close()

	st := store.New(client, cfg.spicedb.timeout)
	auditLog := audit.New(os.Stdout)
	svc := service.New(service.Config{
		Labels: cfg.labels, BreakGlassMax: cfg.breakGlassMax, MaxExpiry: cfg.maxByKind,
		PendingTTL: cfg.pendingTTL, Checker: check.Checker{Analyzer: analyzer(cfg, awsCfg)},
	}, st, poller, auditLog)
	go svc.RunExpiry(ctx, time.Minute, log)
	if cfg.watchAudit {
		go service.WatchAudit(ctx, st, auditLog, 5*time.Second)
	}

	server := api.NewServer(src, src, own.ID.TrustDomain(), svc)
	lis, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		return err
	}
	go func() { errc <- server.Serve(lis) }()
	log.Info("serving", "spiffe_id", own.ID.String(), "accepts", "spiffe://"+own.ID.TrustDomain().Name()+"/*")
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	server.GracefulStop()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return health.Shutdown(shutdown)
}

func serveHTTP(s *http.Server) error {
	if err := s.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve health: %w", err)
	}
	return nil
}

func loadAWS(ctx context.Context, region string) (aws.Config, error) {
	var opts []func(*awsconfig.LoadOptions) error
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("aws config: %w", err)
	}
	return cfg, nil
}

// newPoller reads the publication the broker reads, verified with the
// same keys, and keeps polling it until ctx ends.
func newPoller(ctx context.Context, cfg serveConfig, awsCfg aws.Config, log *slog.Logger) (*publication.Poller, error) {
	var verifier grant.Verifier
	if cfg.bundleKMSKey != "" {
		verifier = grant.NewKMSVerifier(kms.NewFromConfig(awsCfg), cfg.bundleKMSKey)
	} else {
		ring, err := publication.LoadKeyRing(cfg.verifyKeys())
		if err != nil {
			return nil, err
		}
		verifier = ring
	}
	var fetcher publication.Fetcher = &publication.Local{Root: cfg.bundle.Dir}
	if cfg.bundle.IsS3() {
		fetcher = publication.NewS3(s3.NewFromConfig(awsCfg), cfg.bundle.Bucket, cfg.bundle.Prefix)
	}
	p := publication.NewPoller(fetcher, verifier, cfg.bundlePoll, log)
	if err := p.Reload(ctx); err != nil {
		log.Warn("no grant bundle in service yet; every write is refused until one verifies", "error", err)
	}
	go p.Run(ctx)
	return p, nil
}

func analyzer(cfg serveConfig, awsCfg aws.Config) grant.PolicyAnalyzer {
	if !cfg.accessAnalyzer {
		return nil
	}
	return grant.NewAccessAnalyzer(accessanalyzer.NewFromConfig(awsCfg))
}

// probes answers /healthz always and /readyz once the bundle has verified
// and the SVID is there.
type probes struct {
	ready atomic.Pointer[func() error]
}

func (p *probes) set(poller *publication.Poller, src *workloadapi.X509Source) {
	ready := func() error {
		if _, err := src.GetX509SVID(); err != nil {
			return err
		}
		return poller.Ready()
	}
	p.ready.Store(&ready)
}

func (p *probes) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/healthz":
		w.WriteHeader(http.StatusOK)
	case "/readyz":
		ready := p.ready.Load()
		if ready == nil {
			http.Error(w, "starting", http.StatusServiceUnavailable)
			return
		}
		if err := (*ready)(); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		http.NotFound(w, r)
	}
}
