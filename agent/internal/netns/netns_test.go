package netns

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// innerEnv marks the re-executed test process (see privileged).
const innerEnv = "CRACHA_NETNS_TEST_INNER"

// privileged runs the calling test in a process of its own under
// `unshare -Urn`: a new user namespace, in which the process has the
// CAP_SYS_ADMIN that creating and entering network namespaces needs, and a
// new network namespace standing in for the host's. It returns true in the
// outer process, once the inner run's verdict has been applied to t, and
// false in the inner one, which then runs the test body. Without user
// namespaces (a kernel or a sandbox that refuses them) the test is skipped.
func privileged(t *testing.T) bool {
	t.Helper()
	if os.Getenv(innerEnv) == "1" {
		return false
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("unshare", "-Urn", exe, "-test.run=^"+t.Name()+"$", "-test.v")
	cmd.Env = append(os.Environ(), innerEnv+"=1")
	out, err := cmd.CombinedOutput()
	t.Logf("inner run:\n%s", out)
	switch {
	case bytes.Contains(out, []byte("--- FAIL")):
		t.Fatalf("the test failed in its user namespace: %v", err)
	case bytes.Contains(out, []byte("--- PASS")) && err == nil:
	case bytes.Contains(out, []byte("--- SKIP")):
		t.Skip("skipped in its user namespace")
	default:
		t.Skipf("cannot run in a user namespace here: %v", err)
	}
	return true
}

// hostNetns is the network namespace of the calling thread, as /proc names it
// (net:[inode]). Every thread of the test shares the host's unless Do leaked
// one.
func hostNetns(t *testing.T) string {
	t.Helper()
	ns, err := os.Readlink("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	return ns
}

// newNetns creates a network namespace with its loopback interface up and
// returns a path to it, which stays valid until the test ends: the namespace
// lives on a thread the helper keeps alive. Creating one needs CAP_SYS_ADMIN
// in the process's user namespace, which privileged arranges; without it
// the test is skipped.
func newNetns(t *testing.T) string {
	t.Helper()
	type result struct {
		path string
		err  error
		skip bool
	}
	ready := make(chan result, 1)
	stop := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		// Never unlocked: the thread is the namespace's keeper and dies with
		// the goroutine.
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			ready <- result{err: err, skip: errors.Is(err, unix.EPERM)}
			return
		}
		if err := loopbackUp(); err != nil {
			ready <- result{err: err}
			return
		}
		ready <- result{path: fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid())}
		<-stop
	}()
	t.Cleanup(func() { close(stop) })
	r := <-ready
	if r.skip {
		t.Skipf("cannot create a network namespace here: %v", r.err)
	}
	if r.err != nil {
		t.Fatalf("creating a network namespace: %v", r.err)
	}
	return r.path
}

// loopbackUp brings lo up in the calling thread's network namespace, which
// a fresh namespace does not do by itself; 127.0.0.1 is bindable only then.
func loopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("SIOCGIFFLAGS lo: %w", err)
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("SIOCSIFFLAGS lo: %w", err)
	}
	return nil
}

func TestListenBindsInsideTheNamespaceAndServesOutside(t *testing.T) {
	if privileged(t) {
		return
	}
	path := newNetns(t)
	before := hostNetns(t)

	lis, err := Listen(path, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer lis.Close()
	addr := lis.Addr().String()

	if got := hostNetns(t); got != before {
		t.Fatalf("the test's thread is in %s after Listen, was in %s", got, before)
	}

	// Served from the host namespace: the listener answers a connection
	// made from inside the pod's.
	accepted := make(chan error, 1)
	go func() {
		c, err := lis.Accept()
		if err == nil {
			_, err = c.Write([]byte("hello"))
			c.Close()
		}
		accepted <- err
	}()
	var reply string
	err = Do(path, func() error {
		c, err := net.DialTimeout("tcp4", addr, 2*time.Second)
		if err != nil {
			return err
		}
		defer c.Close()
		buf := make([]byte, 16)
		n, err := c.Read(buf)
		reply = string(buf[:n])
		return err
	})
	if err != nil {
		t.Fatalf("dialing %s from inside the namespace: %v", addr, err)
	}
	if err := <-accepted; err != nil {
		t.Fatalf("accept: %v", err)
	}
	if reply != "hello" {
		t.Fatalf("reply = %q", reply)
	}

	// Reachable from the pod's namespace alone. Dialing the same address from
	// the host's namespace does not reach this listener: either nothing
	// listens there or something unrelated does, and in neither case is it
	// this listener's greeting.
	if c, err := net.DialTimeout("tcp4", addr, 500*time.Millisecond); err == nil {
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 16)
		n, _ := c.Read(buf)
		c.Close()
		if string(buf[:n]) == "hello" {
			t.Fatal("the listener is reachable from the host's namespace")
		}
	}
}

func TestDoRestoresTheHostNamespace(t *testing.T) {
	if privileged(t) {
		return
	}
	path := newNetns(t)
	host := hostNetns(t)
	var inside string
	err := Do(path, func() error {
		ns, err := os.Readlink("/proc/thread-self/ns/net")
		inside = ns
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if inside == host {
		t.Fatalf("fn ran in the host's namespace %s", host)
	}
	if got := hostNetns(t); got != host {
		t.Fatalf("the test's thread is in %s afterwards, was in %s", got, host)
	}
}

func TestDoReturnsFnError(t *testing.T) {
	if privileged(t) {
		return
	}
	path := newNetns(t)
	want := errors.New("boom")
	if err := Do(path, func() error { return want }); !errors.Is(err, want) {
		t.Fatalf("Do = %v, want %v", err, want)
	}
}

func TestDoRefusesAMissingNamespace(t *testing.T) {
	err := Do("/nonexistent/netns", func() error { return nil })
	if err == nil || !strings.Contains(err.Error(), "opening the network namespace") {
		t.Fatalf("Do = %v, want an open error", err)
	}
	if _, err := (Loopback{Port: 1}).Bind("/nonexistent/netns"); err == nil {
		t.Fatal("Bind of a missing namespace succeeded")
	}
}
