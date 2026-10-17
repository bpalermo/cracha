package driver

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc"
)

// DefaultEndpoint is where kubelet's node-driver-registrar sidecar expects
// the CSI socket inside the plugin's container.
const DefaultEndpoint = "unix:///csi/csi.sock"

// ParseEndpoint turns a CSI endpoint (unix:///path, unix:/path or a bare
// path) into the socket path. Only Unix sockets are served: kubelet talks to
// a node plugin over its plugin directory, never over TCP.
func ParseEndpoint(endpoint string) (string, error) {
	if endpoint == "" {
		return "", errors.New("the endpoint is required")
	}
	if strings.HasPrefix(endpoint, "/") {
		return filepath.Clean(endpoint), nil
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("endpoint %q: %w", endpoint, err)
	}
	if u.Scheme != "unix" {
		return "", fmt.Errorf("endpoint %q: only unix:// endpoints are served", endpoint)
	}
	path := u.Path
	if u.Host != "" {
		// unix://relative/path: the host is the first segment.
		path = u.Host + u.Path
	}
	if path == "" {
		return "", fmt.Errorf("endpoint %q has no path", endpoint)
	}
	return filepath.Clean(path), nil
}

// ServeConfig names the socket and the shutdown grace.
type ServeConfig struct {
	// Socket is the CSI socket path.
	Socket string
	// ShutdownGrace bounds the graceful gRPC stop; zero means 5s.
	ShutdownGrace time.Duration
}

// Serve runs the CSI server on the socket until ctx is done, then removes the
// socket. It returns nil on a clean cancellation and the server's error
// otherwise. Registration with kubelet is the node-driver-registrar sidecar's
// job, which watches this socket.
func Serve(ctx context.Context, cfg ServeConfig, d *Driver, log *slog.Logger) error {
	grace := cfg.ShutdownGrace
	if grace <= 0 {
		grace = 5 * time.Second
	}
	lis, err := listenUnix(cfg.Socket)
	if err != nil {
		return err
	}
	defer removeSocket(log, cfg.Socket)

	srv := grpc.NewServer()
	csi.RegisterIdentityServer(srv, d)
	csi.RegisterNodeServer(srv, d)

	served := make(chan error, 1)
	go func() { served <- srv.Serve(lis) }()
	log.Info("serving", "driver", DriverName, "socket", cfg.Socket, "node", d.cfg.NodeID)

	select {
	case <-ctx.Done():
		log.Info("shutting down")
		stopWithin(srv, grace)
		return nil
	case err := <-served:
		return fmt.Errorf("CSI server on %s: %w", cfg.Socket, err)
	}
}

// listenUnix listens on path after clearing a stale socket a previous instance
// left behind. It refuses to delete anything at path that is not a socket.
func listenUnix(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode().Type() != fs.ModeSocket {
			return nil, fmt.Errorf("%s exists and is not a socket (%s); refusing to remove it", path, fi.Mode().Type())
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("removing the stale socket %s: %w", path, err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	lis, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", path, err)
	}
	return lis, nil
}

func removeSocket(log *slog.Logger, path string) {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		log.Warn("could not remove the socket", "path", path, "error", err)
	}
}

func stopWithin(s *grpc.Server, grace time.Duration) {
	done := make(chan struct{})
	go func() {
		s.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(grace):
		s.Stop()
	}
}

// ServeHealthz answers GET /healthz on addr with 200 while the CSI socket
// exists and 503 otherwise, until ctx is done. An empty addr serves nothing.
func ServeHealthz(ctx context.Context, addr, socket string, log *slog.Logger) error {
	if addr == "" {
		<-ctx.Done()
		return nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		if err := probeSocket(socket); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	served := make(chan error, 1)
	go func() { served <- srv.ListenAndServe() }()
	log.Info("serving healthz", "addr", addr)

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-served:
		return fmt.Errorf("healthz server on %s: %w", addr, err)
	}
}

// probeSocket is nil iff socket exists and is a socket.
func probeSocket(socket string) error {
	fi, err := os.Stat(socket)
	if err != nil {
		return err
	}
	if fi.Mode().Type() != fs.ModeSocket {
		return fmt.Errorf("%s is not a socket", socket)
	}
	return nil
}
