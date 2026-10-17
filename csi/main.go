// Command cracha-csi is the CSI node plugin that writes a pod's JWT-SVID where
// the AWS SDK reads it, before the pod's containers start, and keeps it fresh
// (docs/design.md, section 7).
//
// It serves the CSI Identity and Node services on the kubelet plugin socket
// (registration with kubelet is the node-driver-registrar sidecar's job),
// fetches each pod's JWT-SVID through the issuer adapter (SPIRE's Broker API)
// and checks the kubelet-supplied service account token with a TokenReview,
// the only thing it uses the Kubernetes API for.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/bpalermo/cracha/common/version"
	"github.com/bpalermo/cracha/csi/internal/driver"
	"github.com/bpalermo/cracha/csi/internal/issuer"
	"github.com/bpalermo/cracha/csi/internal/issuer/spire"
	"github.com/bpalermo/cracha/csi/internal/token"
	"github.com/bpalermo/cracha/csi/internal/tokenreview"
)

func main() {
	var (
		showVersion     = flag.Bool("version", false, "print the version and exit")
		endpoint        = flag.String("endpoint", driver.DefaultEndpoint, "CSI endpoint to serve (unix:///path)")
		nodeID          = flag.String("node-id", os.Getenv("NODE_NAME"), "node name reported by NodeGetInfo (default $NODE_NAME)")
		brokerSocket    = flag.String("issuer-broker-socket", "/run/spire/broker/broker.sock", "path of the issuer's SPIFFE Broker API socket")
		workloadAPI     = flag.String("workload-api", "unix:///spiffe-workload-api/spire-agent.sock", "SPIFFE Workload API address for the plugin's own identity")
		audience        = flag.String("audience", driver.DefaultAudience, "audience of the JWT-SVIDs written for pods")
		saTokenAudience = flag.String("sa-token-audience", driver.DefaultSATokenAudience, "audience of the bound service account token kubelet supplies")
		maxTokenTTL     = flag.Duration("max-token-ttl", token.DefaultMaxTTL, "longest JWT-SVID lifetime written to disk; a longer token is refused")
		publishDeadline = flag.Duration("publish-deadline", issuer.DefaultDeadline, "how long one NodePublishVolume retries a not-yet-known pod or an unavailable issuer")
		tokenUID        = flag.Int("token-uid", 0, "owner of the token file (-1 keeps the plugin's own)")
		tokenGID        = flag.Int("token-gid", 0, "group of the token file (-1 keeps the plugin's own)")
		healthz         = flag.String("healthz", ":9808", "address of the /healthz endpoint (empty disables it)")
		logLevel        = flag.String("log-level", "info", "log level: debug, info, warn or error")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("cracha-csi %s\n", version.Version)
		return
	}

	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		fmt.Fprintf(os.Stderr, "cracha-csi: --log-level: %v\n", err)
		os.Exit(2)
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(log)

	if err := run(log, config{
		endpoint:        *endpoint,
		nodeID:          *nodeID,
		brokerSocket:    *brokerSocket,
		workloadAPI:     *workloadAPI,
		audience:        *audience,
		saTokenAudience: *saTokenAudience,
		maxTokenTTL:     *maxTokenTTL,
		publishDeadline: *publishDeadline,
		owner:           token.Owner{UID: *tokenUID, GID: *tokenGID},
		healthz:         *healthz,
	}); err != nil {
		log.Error("cracha-csi exiting", "error", err)
		os.Exit(1)
	}
}

type config struct {
	endpoint        string
	nodeID          string
	brokerSocket    string
	workloadAPI     string
	audience        string
	saTokenAudience string
	maxTokenTTL     time.Duration
	publishDeadline time.Duration
	owner           token.Owner
	healthz         string
}

func run(log *slog.Logger, cfg config) error {
	if cfg.maxTokenTTL > token.DefaultMaxTTL {
		// Section 11: the only on-disk secrets are JWT-SVIDs with a TTL of at
		// most 5 minutes. The flag can tighten that, never loosen it.
		return fmt.Errorf("--max-token-ttl %s is above the %s the design allows on disk", cfg.maxTokenTTL, token.DefaultMaxTTL)
	}
	socket, err := driver.ParseEndpoint(cfg.endpoint)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	restCfg, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("the in-cluster Kubernetes configuration is needed for TokenReview: %w", err)
	}
	client, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("creating the Kubernetes client: %w", err)
	}

	spireIssuer, err := spire.New(ctx, spire.Config{BrokerSocket: cfg.brokerSocket, WorkloadAPI: cfg.workloadAPI}, log)
	if err != nil {
		return err
	}
	defer func() { _ = spireIssuer.Close() }()
	iss := issuer.WithRetry(spireIssuer, issuer.RetryPolicy{Deadline: cfg.publishDeadline}, log)

	d, err := driver.New(driver.Config{
		NodeID:          cfg.nodeID,
		Version:         version.Version,
		Audience:        cfg.audience,
		SATokenAudience: cfg.saTokenAudience,
		MaxTokenTTL:     cfg.maxTokenTTL,
		Owner:           cfg.owner,
	}, iss, tokenreview.NewKubernetes(client), log)
	if err != nil {
		return err
	}
	log.Info("starting", "version", version.Version, "node", cfg.nodeID, "endpoint", socket,
		"broker_socket", cfg.brokerSocket, "workload_api", cfg.workloadAPI, "audience", cfg.audience,
		"max_token_ttl", cfg.maxTokenTTL, "publish_deadline", cfg.publishDeadline)

	// Either server failing stops the other; a signal stops both.
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return driver.Serve(gctx, driver.ServeConfig{Socket: socket}, d, log) })
	g.Go(func() error { return driver.ServeHealthz(gctx, cfg.healthz, socket, log) })
	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
