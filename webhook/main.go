// Command cracha-webhook is the mutating admission webhook that wires
// enabled pods up to the node agent (docs/design.md, section 7.5): the
// loopback credentials endpoint in every container's environment, the
// enrolment label and, in the init enrolment mode, the enrolment init
// container. It serves its X.509-SVID from the Workload API and publishes
// its trust bundle as its own webhook configuration's caBundle. The decision
// is in internal/mutate, the HTTPS front in internal/server, the caBundle in
// internal/cabundle, the ServiceAccount lookups in internal/sacache and the
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
	"slices"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	"github.com/bpalermo/cracha/common/version"
	"github.com/bpalermo/cracha/webhook/internal/cabundle"
	"github.com/bpalermo/cracha/webhook/internal/mutate"
	"github.com/bpalermo/cracha/webhook/internal/nsregion"
	"github.com/bpalermo/cracha/webhook/internal/sacache"
	"github.com/bpalermo/cracha/webhook/internal/server"
)

type options struct {
	listen            string
	workloadAPISocket string
	webhookConfigName string
	serviceDNSName    string
	mutate            mutate.Config
	saCacheTTL        time.Duration
	kubeconfig        string
	maxRequestBytes   int64
	logLevel          slog.Level
}

func main() {
	var (
		opts        options
		showVersion = flag.Bool("version", false, "print the version and exit")
		logLevel    = flag.String("log-level", "info", "log level: debug, info, warn or error")
	)
	flag.StringVar(&opts.listen, "listen", ":8443", "address to serve HTTPS on")
	flag.StringVar(&opts.workloadAPISocket, "workload-api-socket", "", "address of the SPIFFE Workload API the serving X.509-SVID and the trust bundle come from, such as unix:///spiffe-workload-api/spire-agent.sock (required)")
	flag.StringVar(&opts.webhookConfigName, "webhook-config-name", "", "the MutatingWebhookConfiguration whose caBundle is kept at the trust bundle (required)")
	flag.StringVar(&opts.serviceDNSName, "service-dns-name", "", "the DNS name the apiserver verifies the serving certificate by, <service>.<namespace>.svc; a warning is logged when the SVID does not carry it")
	flag.IntVar(&opts.mutate.AgentPort, "agent-port", 0, "port of the agent's loopback listener in every pod, for AWS_CONTAINER_CREDENTIALS_FULL_URI (required)")
	flag.Var(&opts.mutate.Enrol, "enrol", "enrolment mode: init (inject the cracha-enrol init container) or cni")
	flag.StringVar(&opts.mutate.AgentImage, "agent-image", "", "the agent image the cracha-enrol init container runs (required with --enrol=init)")
	flag.IntVar(&opts.mutate.EnrolPort, "enrol-port", 0, "port of the agent's enrolment endpoint on the node's address (required with --enrol=init)")
	flag.DurationVar(&opts.mutate.EnrolTimeout, "enrol-timeout", 60*time.Second, "how long the cracha-enrol init container retries before it fails")
	flag.StringVar(&opts.mutate.DefaultRegion, "default-region", "", "AWS_REGION for pods that do not set their own (required)")
	flag.Var(&opts.mutate.ConflictingEnv, "conflicting-env", "what to do with AWS credential variables a pod sets itself: reject or strip")
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
	if err := opts.check(); err != nil {
		return err
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

	// The serving identity. NewX509Source returns once the first SVID has
	// arrived, so nothing is served before there is a certificate to serve.
	logger.Info("waiting for the X.509-SVID", "workload_api", opts.workloadAPISocket)
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(opts.workloadAPISocket)))
	if err != nil {
		return fmt.Errorf("connecting to the Workload API: %w", err)
	}
	defer source.Close()
	if err := logSVID(source, opts.serviceDNSName, logger); err != nil {
		return err
	}

	// The per-namespace region overrides, watched for as long as the
	// webhook runs. Until the first list the hook serves the default.
	regions := nsregion.New(client)
	go regions.Run(ctx)

	// The caBundle of the webhook's own configuration, kept at the trust
	// bundle for as long as the webhook runs.
	publisher, err := cabundle.New(cabundle.Config{Name: opts.webhookConfigName, Logger: logger}, client, source)
	if err != nil {
		return err
	}
	go publisher.Run(ctx)

	mutator, err := mutate.New(opts.mutate, sacache.New(client, opts.saCacheTTL), mutate.WithRegions(regions))
	if err != nil {
		return err
	}

	srv, err := server.New(server.Config{
		Listen:          opts.listen,
		TLS:             tlsconfig.TLSServerConfig(source),
		MaxRequestBytes: opts.maxRequestBytes,
		Ready:           ready(client, regions, source, publisher),
		Logger:          logger,
	}, mutator)
	if err != nil {
		return err
	}

	cfg := mutator.Config()
	logger.Info("starting", "version", version.Version,
		"credentials_uri", cfg.CredentialsURI(), "default_region", cfg.DefaultRegion,
		"conflicting_env", cfg.ConflictingEnv.String(), "enrol", cfg.Enrol.String(),
		"agent_image", cfg.AgentImage, "enrol_port", cfg.EnrolPort, "enrol_timeout", cfg.EnrolTimeout,
		"webhook_config", opts.webhookConfigName, "sa_cache_ttl", opts.saCacheTTL)
	return srv.Run(ctx)
}

// check reports the required flags that are missing. The mutate package
// checks its own values and ranges.
func (o options) check() error {
	var missing []string
	for _, f := range []struct {
		name  string
		unset bool
	}{
		{"workload-api-socket", o.workloadAPISocket == ""},
		{"webhook-config-name", o.webhookConfigName == ""},
		{"agent-port", o.mutate.AgentPort == 0},
		{"default-region", o.mutate.DefaultRegion == ""},
		{"agent-image", o.mutate.Enrol == mutate.EnrolInit && o.mutate.AgentImage == ""},
		{"enrol-port", o.mutate.Enrol == mutate.EnrolInit && o.mutate.EnrolPort == 0},
	} {
		if f.unset {
			missing = append(missing, "--"+f.name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("required: %v", missing)
	}
	return nil
}

// logSVID records the identity being served and its DNS SANs, and warns
// when the name the apiserver verifies is not among them: the webhook would
// start, and every admission would fail the handshake.
func logSVID(source *workloadapi.X509Source, dnsName string, logger *slog.Logger) error {
	svid, err := source.GetX509SVID()
	if err != nil {
		return fmt.Errorf("reading the X.509-SVID: %w", err)
	}
	if len(svid.Certificates) == 0 {
		return errors.New("the X.509-SVID carries no certificate")
	}
	leaf := svid.Certificates[0]
	logger.Info("serving the X.509-SVID", "spiffe_id", svid.ID.String(), "dns_names", leaf.DNSNames,
		"not_after", leaf.NotAfter)
	if dnsName != "" && !slices.Contains(leaf.DNSNames, dnsName) {
		logger.Warn("the X.509-SVID does not carry the DNS name the apiserver verifies: the webhook's registration entry needs a dnsNameTemplates entry for it (design 4.2)",
			"want", dnsName, "dns_names", leaf.DNSNames)
	}
	return nil
}

// ready is the /readyz check: the apiserver answers, without which no
// ServiceAccount can be looked up and every enabled pod would be denied;
// the namespaces have been listed, without which every pod would get the
// default region, and a webhook that may not watch namespaces would go
// unnoticed; there is an SVID to serve; and the trust bundle has been
// published, without which the apiserver cannot verify the webhook.
func ready(client kubernetes.Interface, regions *nsregion.Regions, source *workloadapi.X509Source, publisher *cabundle.Publisher) func(context.Context) error {
	return func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if err := client.Discovery().RESTClient().Get().AbsPath("/readyz").Do(ctx).Error(); err != nil {
			return fmt.Errorf("apiserver: %w", err)
		}
		if !regions.HasSynced() {
			return errors.New("namespaces not listed yet")
		}
		if _, err := source.GetX509SVID(); err != nil {
			return fmt.Errorf("X.509-SVID: %w", err)
		}
		if !publisher.Published() {
			return errors.New("the CA bundle has not been published yet")
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
