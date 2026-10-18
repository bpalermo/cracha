// Command cracha-webhook is the mutating admission webhook that injects the
// CSI volume and the AWS SDK environment into enabled pods (docs/design.md,
// section 7.4). The decision is in internal/mutate, the HTTPS front in
// internal/server, the ServiceAccount lookups in internal/sacache and the
// per-namespace region override in internal/nsregion.
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

	"github.com/go-logr/logr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	"github.com/bpalermo/cracha/common/version"
	"github.com/bpalermo/cracha/webhook/internal/mutate"
	"github.com/bpalermo/cracha/webhook/internal/nsregion"
	"github.com/bpalermo/cracha/webhook/internal/sacache"
	"github.com/bpalermo/cracha/webhook/internal/server"
)

type options struct {
	listen          string
	tlsCert         string
	tlsKey          string
	brokerURL       string
	defaultRegion   string
	conflictingEnv  mutate.ConflictPolicy
	saCacheTTL      time.Duration
	kubeconfig      string
	maxRequestBytes int64
	logLevel        slog.Level
}

func main() {
	var (
		opts        options
		showVersion = flag.Bool("version", false, "print the version and exit")
		logLevel    = flag.String("log-level", "info", "log level: debug, info, warn or error")
	)
	flag.StringVar(&opts.listen, "listen", ":8443", "address to serve HTTPS on")
	flag.StringVar(&opts.tlsCert, "tls-cert", "", "PEM file with the serving certificate chain (required)")
	flag.StringVar(&opts.tlsKey, "tls-key", "", "PEM file with the serving key (required)")
	flag.StringVar(&opts.brokerURL, "broker-url", "", "https URL of the broker; "+mutate.CredentialsPath+" is appended if absent (required)")
	flag.StringVar(&opts.defaultRegion, "default-region", "", "AWS_REGION for pods that do not set their own (required)")
	flag.Var(&opts.conflictingEnv, "conflicting-env", "what to do with AWS credential variables a pod sets itself: reject or strip")
	flag.DurationVar(&opts.saCacheTTL, "sa-cache-ttl", 30*time.Second, "how long a ServiceAccount lookup is remembered; 0 disables the cache")
	flag.StringVar(&opts.kubeconfig, "kubeconfig", "", "kubeconfig to reach the apiserver with; the default is the in-cluster configuration")
	flag.Int64Var(&opts.maxRequestBytes, "max-request-bytes", server.DefaultMaxRequestBytes, "largest admission request accepted")
	flag.Parse()

	if *showVersion {
		fmt.Printf("cracha-webhook %s\n", version.Version)
		return
	}

	if err := opts.logLevel.UnmarshalText([]byte(*logLevel)); err != nil {
		fmt.Fprintf(os.Stderr, "cracha-webhook: --log-level: %v\n", err)
		os.Exit(2)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: opts.logLevel}))
	slog.SetDefault(logger)
	// client-go logs through klog; send that through the same handler.
	klog.SetLogger(logr.FromSlogHandler(logger.Handler()))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, opts, logger); err != nil {
		logger.Error("exiting", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, opts options, logger *slog.Logger) error {
	var missing []string
	for _, f := range []struct{ name, value string }{
		{"tls-cert", opts.tlsCert},
		{"tls-key", opts.tlsKey},
		{"broker-url", opts.brokerURL},
		{"default-region", opts.defaultRegion},
	} {
		if f.value == "" {
			missing = append(missing, "--"+f.name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("required: %v", missing)
	}

	restConfig, err := restConfig(opts.kubeconfig)
	if err != nil {
		return err
	}
	restConfig.UserAgent = "cracha-webhook/" + version.Version
	client, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("creating the Kubernetes client: %w", err)
	}

	// The per-namespace region overrides, watched for as long as the
	// webhook runs. Until the first list the hook serves the default.
	regions := nsregion.New(client)
	go regions.Run(ctx)

	mutator, err := mutate.New(mutate.Config{
		BrokerURL:      opts.brokerURL,
		DefaultRegion:  opts.defaultRegion,
		ConflictingEnv: opts.conflictingEnv,
	}, sacache.New(client, opts.saCacheTTL), mutate.WithRegions(regions))
	if err != nil {
		return err
	}

	srv, err := server.New(server.Config{
		Listen:          opts.listen,
		CertFile:        opts.tlsCert,
		KeyFile:         opts.tlsKey,
		MaxRequestBytes: opts.maxRequestBytes,
		Ready:           ready(client, regions),
		Logger:          logger,
	}, mutator)
	if err != nil {
		return err
	}

	cfg := mutator.Config()
	logger.Info("starting", "version", version.Version,
		"broker_url", cfg.BrokerURL, "default_region", cfg.DefaultRegion,
		"conflicting_env", cfg.ConflictingEnv.String(), "sa_cache_ttl", opts.saCacheTTL)
	return srv.Run(ctx)
}

// ready is the /readyz check: the apiserver answers, without which no
// ServiceAccount can be looked up and every enabled pod would be denied,
// and the namespaces have been listed, without which every pod would get
// the default region, and a webhook that may not watch namespaces would
// go unnoticed.
func ready(client kubernetes.Interface, regions *nsregion.Regions) func(context.Context) error {
	return func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if err := client.Discovery().RESTClient().Get().AbsPath("/readyz").Do(ctx).Error(); err != nil {
			return fmt.Errorf("apiserver: %w", err)
		}
		if !regions.HasSynced() {
			return errors.New("namespaces not listed yet")
		}
		return nil
	}
}

// restConfig is the in-cluster configuration, or the kubeconfig when one is
// named.
func restConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("reading kubeconfig %s: %w", kubeconfig, err)
		}
		return cfg, nil
	}
	cfg, err := rest.InClusterConfig()
	if err != nil {
		if errors.Is(err, rest.ErrNotInCluster) {
			return nil, errors.New("not running in a cluster: pass --kubeconfig")
		}
		return nil, fmt.Errorf("in-cluster configuration: %w", err)
	}
	return cfg, nil
}
