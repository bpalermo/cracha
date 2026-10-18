// Command cracha-agent is the node agent that answers the AWS SDK's credential
// requests from inside every enrolled pod (docs/design.md, section 7): it
// binds a loopback listener in each enrolled pod's network namespace
// (internal/listener, internal/netns), fetches the pod's JWT-SVID through
// the issuer adapter (internal/issuer) and relays the broker's answer over
// SPIFFE mTLS (internal/broker, internal/credentials). Enrolment is the init
// container's call in init mode (internal/enrol) or the CNI plugin's in cni
// mode (internal/cni/server); on start it rebinds the node's enrolled pods
// (internal/recovery).
//
// `cracha-agent enrol` is the cracha-enrol init container: it enrols the pod
// it runs in and exits 0 once the listener accepts a connection.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/sync/errgroup"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	cniserver "github.com/bpalermo/cracha/agent/internal/cni/server"
	"github.com/bpalermo/cracha/agent/internal/enrol"
	"github.com/bpalermo/cracha/agent/internal/serve"
	"github.com/bpalermo/cracha/common/version"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "enrol" {
		os.Exit(enrolMain(os.Args[2:]))
	}
	os.Exit(serveMain(os.Args[1:]))
}

// logger builds the JSON logger at level and routes client-go's logs to it.
func logger(level string) (*slog.Logger, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("--log-level: %w", err)
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
	slog.SetDefault(log)
	klog.SetLogger(logr.FromSlogHandler(log.Handler()))
	return log, nil
}

// serveMain is the agent proper.
func serveMain(args []string) int {
	fs := flag.NewFlagSet("cracha-agent", flag.ContinueOnError)
	var cfg config
	showVersion := fs.Bool("version", false, "print the version and exit")
	logLevel := fs.String("log-level", "info", "log level: debug, info, warn or error")
	cfg.flags(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Printf("cracha-agent %s\n", version.Version)
		return 0
	}
	log, err := logger(*logLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cracha-agent: %v\n", err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg, log); err != nil {
		log.Error("cracha-agent exiting", "error", err)
		return 1
	}
	return 0
}

// run wires the components and serves until ctx is done.
func run(ctx context.Context, cfg config, log *slog.Logger) error {
	if err := cfg.check(); err != nil {
		return err
	}
	restCfg, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("the in-cluster Kubernetes configuration is needed: %w", err)
	}
	restCfg.UserAgent = "cracha-agent/" + version.Version
	client, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("creating the Kubernetes client: %w", err)
	}
	c, err := newComponents(ctx, cfg, client, log)
	if err != nil {
		return err
	}
	defer c.close()
	log.Info("starting", "version", version.Version, "node", cfg.node, "port", cfg.port, "enrol", cfg.enrol,
		"broker_url", c.broker.URL(), "broker_spiffe_id", cfg.brokerSPIFFEID, "fetch_deadline", cfg.fetchDeadline,
		"broker_socket", cfg.brokerSocket, "workload_api", cfg.workloadAPI, "cri_socket", cfg.criSocket)

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { c.identity.Run(gctx); return nil })
	g.Go(func() error {
		srv := &http.Server{
			Handler: c.credentials, ConnContext: c.registry.ConnContext,
			ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second,
		}
		return serve.Run(gctx, srv, func() error { return srv.Serve(c.registry.Listener()) }, "loopback listeners", log)
	})
	switch cfg.enrol {
	case "init":
		g.Go(func() error { return enrol.Serve(gctx, cfg.enrolListen, c.enrolServer, log) })
	case "cni":
		g.Go(func() error { return cniserver.Serve(gctx, cfg.cniSocket, c.cniServer, log) })
	}
	g.Go(func() error { return c.recovery.Run(gctx) })
	g.Go(func() error { return serveHealth(gctx, cfg.healthz, c, log) })
	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// serveHealth serves /healthz (the process is up) and /readyz (its identity
// is issued and the node's pods are listed).
func serveHealth(ctx context.Context, addr string, c *components, log *slog.Logger) error {
	if addr == "" {
		<-ctx.Done()
		return nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		switch {
		case !c.identity.Ready():
			http.Error(w, "the agent's identity has not been issued yet", http.StatusServiceUnavailable)
		case !c.recovery.HasSynced():
			http.Error(w, "the node's pods are not listed yet", http.StatusServiceUnavailable)
		default:
			fmt.Fprintln(w, "ok")
		}
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	return serve.Run(ctx, srv, srv.ListenAndServe, "health endpoint "+addr, log)
}

// enrolMain is `cracha-agent enrol`, the init container.
func enrolMain(args []string) int {
	fs := flag.NewFlagSet("cracha-agent enrol", flag.ContinueOnError)
	cfg, logLevel := enrolFlags(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	log, err := logger(*logLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cracha-agent enrol: %v\n", err)
		return 2
	}
	cfg.Logger = log
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := enrol.Run(ctx, *cfg); err != nil {
		log.Error("enrolment failed", "error", err)
		return 1
	}
	return 0
}

// envInt is the integer in the environment variable, or def.
func envInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// envDuration is the duration in the environment variable, or def.
func envDuration(name string, def time.Duration) time.Duration {
	if v := os.Getenv(name); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

// envOr is the environment variable, or def.
func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}
