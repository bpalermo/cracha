// Package netns enters a pod's network namespace to bind a listener in it
// (docs/design.md, section 7.1). The pattern is aether's withPodNetns
// (cni/internal/plugin/netns.go): setns on a locked OS thread through the
// namespace path the runtime reports, the work, then back to the host's
// namespace. A socket stays in the namespace it was created in after the
// thread leaves, so the listener is served from the host namespace like any
// other.
//
// setns into a network namespace needs CAP_SYS_ADMIN, the agent's one
// capability.
package netns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// Do runs fn on an OS thread that has entered the network namespace at path,
// and returns what fn returns. The thread is dedicated to the call: it is
// locked to a goroutine of its own, restored to the host's namespace after
// fn, and never unlocked, so the runtime destroys it once fn is done rather
// than schedule other goroutines on a thread that was ever in a pod's
// namespace (a thread cloned from it while it was there would inherit the
// namespace; a thread that failed to come back would be stuck there).
func Do(path string, fn func() error) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// No UnlockOSThread, by design: see above.
		done <- enterAndRun(path, fn)
	}()
	return <-done
}

// enterAndRun is Do's body on the locked thread.
func enterAndRun(path string, fn func() error) error {
	target, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening the network namespace %s: %w", path, err)
	}
	defer func() { _ = target.Close() }()

	origin, err := os.Open(fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid()))
	if err != nil {
		return fmt.Errorf("opening the host's network namespace: %w", err)
	}
	defer func() { _ = origin.Close() }()

	if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("entering the network namespace %s: %w", path, err)
	}
	fnErr := fn()
	if err := unix.Setns(int(origin.Fd()), unix.CLONE_NEWNET); err != nil {
		// The thread stays locked and dies with its goroutine, so nothing
		// else runs on a thread stuck in the pod's namespace.
		return errors.Join(fnErr, fmt.Errorf("returning to the host's network namespace: %w", err))
	}
	return fnErr
}

// Listen listens for TCP connections on addr inside the network namespace at
// path. The listener is usable from any namespace afterwards.
func Listen(path, addr string) (net.Listener, error) {
	var lis net.Listener
	err := Do(path, func() error {
		var cfg net.ListenConfig
		l, err := cfg.Listen(context.Background(), "tcp4", addr)
		if err != nil {
			return fmt.Errorf("listening on %s in %s: %w", addr, path, err)
		}
		lis = l
		return nil
	})
	if err != nil {
		return nil, err
	}
	return lis, nil
}

// Loopback binds the loopback listener of design 7.1, 127.0.0.1:Port, in a
// pod's network namespace. It is the listener registry's Binder.
type Loopback struct {
	Port int
}

// Bind implements listener.Binder.
func (l Loopback) Bind(netnsPath string) (net.Listener, error) {
	return Listen(netnsPath, fmt.Sprintf("127.0.0.1:%d", l.Port))
}
