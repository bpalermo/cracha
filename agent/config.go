package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"time"

	"k8s.io/client-go/kubernetes"

	"github.com/bpalermo/cracha/agent/enrolapi"
	"github.com/bpalermo/cracha/agent/internal/broker"
	cniserver "github.com/bpalermo/cracha/agent/internal/cni/server"
	"github.com/bpalermo/cracha/agent/internal/credentials"
	"github.com/bpalermo/cracha/agent/internal/cri"
	"github.com/bpalermo/cracha/agent/internal/enrol"
	"github.com/bpalermo/cracha/agent/internal/identity"
	"github.com/bpalermo/cracha/agent/internal/issuer"
	"github.com/bpalermo/cracha/agent/internal/issuer/spire"
	"github.com/bpalermo/cracha/agent/internal/listener"
	"github.com/bpalermo/cracha/agent/internal/netns"
	"github.com/bpalermo/cracha/agent/internal/recovery"
	"github.com/bpalermo/cracha/agent/internal/tokenreview"
)

// Defaults the chart's values mirror (agent.*).
const (
	DefaultPort      = 9797
	DefaultEnrolPort = 9798
	DefaultHealthz   = ":9799"
	DefaultCNISocket = "/run/cracha/cni.sock"
	DefaultCRISocket = "/run/containerd/containerd.sock"
)

// config is the agent's configuration, from its flags.
type config struct {
	node             string
	port             int
	enrol            string
	enrolListen      string
	cniSocket        string
	criSocket        string
	brokerSocket     string
	workloadAPI      string
	brokerURL        string
	brokerSPIFFEID   string
	brokerTimeout    time.Duration
	audience         string
	fetchDeadline    time.Duration
	perPodLimit      int
	recoveryInterval time.Duration
	healthz          string
}

// flags registers the agent's flags on fs.
func (c *config) flags(fs *flag.FlagSet) {
	fs.StringVar(&c.node, "node-name", envOr("NODE_NAME", ""), "this node's name, whose pods the agent serves (default $NODE_NAME)")
	fs.IntVar(&c.port, "port", DefaultPort, "port of the loopback listener bound in every enrolled pod (agent.port)")
	fs.StringVar(&c.enrol, "enrol", "init", "enrolment mode: init (the cracha-enrol init container calls the enrolment endpoint) or cni (the cracha-cni plugin calls the Unix socket)")
	fs.StringVar(&c.enrolListen, "enrol-listen", fmt.Sprintf(":%d", DefaultEnrolPort), "address of the init-mode enrolment endpoint, on the node's address (agent.enrolPort)")
	fs.StringVar(&c.cniSocket, "cni-socket", DefaultCNISocket, "path of the cni-mode Unix socket (agent.cni.socket)")
	fs.StringVar(&c.criSocket, "cri-socket", DefaultCRISocket, "path of the container runtime's CRI socket (agent.criSocket)")
	fs.StringVar(&c.brokerSocket, "issuer-broker-socket", "/run/spire/broker/broker.sock", "path of the issuer's SPIFFE Broker API socket")
	fs.StringVar(&c.workloadAPI, "workload-api", "unix:///spiffe-workload-api/spire-agent.sock", "SPIFFE Workload API address for the agent's own identity")
	fs.StringVar(&c.brokerURL, "broker-url", "", "https URL of the broker (agent.brokerUrl; required)")
	fs.StringVar(&c.brokerSPIFFEID, "broker-spiffe-id", "", "SPIFFE ID the broker must present (agent.brokerSpiffeID): a full ID, or a path such as /ns/cracha-system/sa/cracha-broker in the agent's own trust domain (required)")
	fs.DurationVar(&c.brokerTimeout, "broker-timeout", broker.DefaultTimeout, "how long one call to the broker may take")
	fs.StringVar(&c.audience, "audience", credentials.DefaultAudience, "audience of the JWT-SVIDs fetched for pods")
	fs.DurationVar(&c.fetchDeadline, "fetch-deadline", issuer.DefaultDeadline, "how long one request retries a pod the issuer does not know yet or an unavailable issuer before answering 503 (agent.fetchDeadline)")
	fs.IntVar(&c.perPodLimit, "per-pod-limit", credentials.DefaultPerPodLimit, "requests in flight allowed per pod")
	fs.DurationVar(&c.recoveryInterval, "recovery-interval", recovery.DefaultInterval, "how often the listeners that could not be bound are retried")
	fs.StringVar(&c.healthz, "healthz", DefaultHealthz, "address of the /healthz and /readyz endpoints (empty disables them)")
}

// check validates the configuration.
func (c config) check() error {
	var missing []string
	for _, f := range []struct{ name, value string }{
		{"node-name", c.node}, {"broker-url", c.brokerURL}, {"broker-spiffe-id", c.brokerSPIFFEID},
	} {
		if f.value == "" {
			missing = append(missing, "--"+f.name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("required: %v", missing)
	}
	if c.enrol != "init" && c.enrol != "cni" {
		return fmt.Errorf("--enrol must be init or cni, not %q", c.enrol)
	}
	if c.port <= 0 || c.port > 65535 {
		return fmt.Errorf("--port %d is not a port", c.port)
	}
	return nil
}

// components is what run wires.
type components struct {
	identity    *identity.Source
	spire       *spire.Issuer
	cri         *cri.Client
	broker      *broker.Client
	registry    *listener.Registry
	credentials *credentials.Handler
	enrolServer *enrol.Server
	cniServer   *cniserver.Server
	recovery    *recovery.Reconciler
}

// newComponents builds them. Nothing is dialled here.
func newComponents(_ context.Context, cfg config, client kubernetes.Interface, log *slog.Logger) (*components, error) {
	c := &components{identity: identity.New(cfg.workloadAPI, log)}
	var err error
	if c.spire, err = spire.New(spire.Config{BrokerSocket: cfg.brokerSocket}, c.identity, log); err != nil {
		return nil, err
	}
	if c.cri, err = cri.Dial(cfg.criSocket); err != nil {
		return nil, err
	}
	if c.broker, err = broker.New(broker.Config{URL: cfg.brokerURL, SPIFFEID: cfg.brokerSPIFFEID, Timeout: cfg.brokerTimeout}, c.identity); err != nil {
		return nil, err
	}
	iss := issuer.WithRetry(c.spire, issuer.RetryPolicy{Deadline: cfg.fetchDeadline}, log)
	c.credentials = credentials.New(iss, c.broker, credentials.Config{Audience: cfg.audience, PerPodLimit: cfg.perPodLimit, Logger: log})
	c.registry = listener.New(netns.Loopback{Port: cfg.port}, listener.WithLogger(log), listener.WithCloseHook(c.credentials.Forget))
	enroller := enrol.NewEnroller(client, c.registry, log)
	c.enrolServer = enrol.NewServer(tokenreview.NewKubernetes(client), enroller, c.cri, enrol.ServerConfig{Port: cfg.port, Logger: log})
	c.cniServer = cniserver.New(enroller, cfg.port, log)
	if c.recovery, err = recovery.New(client, c.cri, c.registry, recovery.Config{Node: cfg.node, Interval: cfg.recoveryInterval, Logger: log}); err != nil {
		return nil, err
	}
	return c, nil
}

// close releases what holds a connection.
func (c *components) close() {
	if c.registry != nil {
		_ = c.registry.CloseAll()
	}
	if c.spire != nil {
		_ = c.spire.Close()
	}
	if c.cri != nil {
		_ = c.cri.Close()
	}
	if c.identity != nil {
		_ = c.identity.Close()
	}
}

// enrolFlags registers the enrol subcommand's flags, each defaulting to its
// enrolapi environment variable.
func enrolFlags(fs *flag.FlagSet) (*enrol.ClientConfig, *string) {
	var cfg enrol.ClientConfig
	fs.StringVar(&cfg.HostIP, "host-ip", envOr(enrolapi.EnvHostIP, ""), "the node's address ($"+enrolapi.EnvHostIP+")")
	fs.IntVar(&cfg.EnrolPort, "enrol-port", envInt(enrolapi.EnvEnrolPort, DefaultEnrolPort), "the agent's enrolment port ($"+enrolapi.EnvEnrolPort+")")
	fs.IntVar(&cfg.Port, "port", envInt(enrolapi.EnvPort, DefaultPort), "the loopback listener's port, confirmed before exiting ($"+enrolapi.EnvPort+")")
	fs.StringVar(&cfg.TokenFile, "token-file", envOr(enrolapi.EnvTokenFile, enrolapi.DefaultTokenFile), "the projected token ($"+enrolapi.EnvTokenFile+")")
	fs.DurationVar(&cfg.Timeout, "timeout", envDuration(enrolapi.EnvTimeout, enrol.DefaultEnrolTimeout), "how long to keep trying ($"+enrolapi.EnvTimeout+")")
	logLevel := fs.String("log-level", "info", "log level: debug, info, warn or error")
	return &cfg, logLevel
}
