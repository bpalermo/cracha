// Package serve runs the agent's HTTP servers: until the context is done,
// then a graceful shutdown; and listens on Unix sockets, clearing what a
// previous instance left behind.
package serve

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// ShutdownGrace bounds the graceful shutdown.
const ShutdownGrace = 5 * time.Second

// Run serves with serve (srv.ListenAndServe, or srv.Serve over a listener)
// until ctx is done, then shuts srv down. It returns nil on a clean stop and
// the server's error otherwise.
func Run(ctx context.Context, srv *http.Server, serve func() error, what string, log *slog.Logger) error {
	if log == nil {
		log = slog.Default()
	}
	served := make(chan error, 1)
	go func() { served <- serve() }()
	log.Info("serving", "what", what)
	select {
	case <-ctx.Done():
		log.Info("shutting down", "what", what)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), ShutdownGrace)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			_ = srv.Close()
		}
		return nil
	case err := <-served:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("%s: %w", what, err)
	}
}

// ListenUnix listens on path after clearing a stale socket a previous
// instance left behind. It refuses to delete anything at path that is not a
// socket. The directory is the agent's own (agent.cni.socket's, design
// 7.8): it is created, or kept, 0700, and the socket is 0600, so only root
// on the node (the runtime, which execs the plugin) reaches it.
func ListenUnix(path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("chmod %s: %w", dir, err)
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
	if err := os.Chmod(path, 0o600); err != nil {
		_ = lis.Close()
		return nil, fmt.Errorf("chmod %s: %w", path, err)
	}
	return lis, nil
}

// RemoveSocket removes the socket file, logging a failure.
func RemoveSocket(log *slog.Logger, path string) {
	if log == nil {
		log = slog.Default()
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		log.Warn("could not remove the socket", "path", path, "error", err)
	}
}
