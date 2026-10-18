package listener

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

// loopback is a Binder that ignores the namespace path and listens on an
// ephemeral loopback port, remembering which path each listener was asked
// for.
type loopback struct {
	mu    sync.Mutex
	bound []string
	fail  error
}

func (b *loopback) Bind(netnsPath string) (net.Listener, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fail != nil {
		return nil, b.fail
	}
	b.bound = append(b.bound, netnsPath)
	return net.Listen("tcp4", "127.0.0.1:0")
}

func (b *loopback) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.bound)
}

var (
	podA = Pod{Namespace: "apps", Name: "a", UID: "uid-a"}
	podB = Pod{Namespace: "apps", Name: "b", UID: "uid-b"}
)

// serve runs an http.Server over the registry that answers every request
// with the pod of its connection.
func serve(t *testing.T, r *Registry) {
	t.Helper()
	srv := &http.Server{
		ConnContext: r.ConnContext,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			pod, ok := PodFromContext(req.Context())
			if !ok {
				http.Error(w, "no pod", http.StatusInternalServerError)
				return
			}
			fmt.Fprint(w, pod.UID)
		}),
	}
	go func() { _ = srv.Serve(r.Listener()) }()
	t.Cleanup(func() { _ = srv.Close() })
}

// get fetches / from the listener bound for uid, through its real address.
func get(t *testing.T, r *Registry, uid string) (string, error) {
	t.Helper()
	addr := addrOf(t, r, uid)
	c := http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get("http://" + addr + "/")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body), nil
}

func addrOf(t *testing.T, r *Registry, uid string) string {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.byUID[uid]
	if !ok {
		t.Fatalf("no entry for %s", uid)
	}
	return e.lis.Addr().String()
}

func TestRequestsResolveToTheListenersPod(t *testing.T) {
	b := &loopback{}
	r := New(b)
	defer r.CloseAll()
	serve(t, r)

	for _, p := range []Pod{podA, podB} {
		if err := r.Bind(p, "/run/netns/"+p.UID); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []Pod{podA, podB, podA} {
		got, err := get(t, r, p.UID)
		if err != nil {
			t.Fatal(err)
		}
		if got != p.UID {
			t.Errorf("a request on %s's listener was answered for %q", p.UID, got)
		}
	}
	entries := r.Entries()
	if len(entries) != 2 {
		t.Fatalf("Entries = %v", entries)
	}
	if e, ok := r.Lookup(podA.UID); !ok || e.NetnsPath != "/run/netns/uid-a" || e.Pod != podA {
		t.Errorf("Lookup(a) = %+v, %v", e, ok)
	}
	if _, ok := r.Lookup("nobody"); ok {
		t.Error("Lookup of an unbound pod succeeded")
	}
}

func TestBindIsIdempotentAndRebindsOnANewNamespace(t *testing.T) {
	b := &loopback{}
	var closed []Pod
	r := New(b, WithCloseHook(func(p Pod) { closed = append(closed, p) }))
	defer r.CloseAll()

	if err := r.Bind(podA, "/run/netns/one"); err != nil {
		t.Fatal(err)
	}
	first := addrOf(t, r, podA.UID)
	if err := r.Bind(podA, "/run/netns/one"); err != nil {
		t.Fatal(err)
	}
	if b.count() != 1 {
		t.Fatalf("binding the same namespace twice bound %d listeners", b.count())
	}
	if addrOf(t, r, podA.UID) != first {
		t.Fatal("the idempotent bind replaced the listener")
	}

	if err := r.Bind(podA, "/run/netns/two"); err != nil {
		t.Fatal(err)
	}
	if b.count() != 2 {
		t.Fatalf("a new namespace bound %d listeners, want 2", b.count())
	}
	if addrOf(t, r, podA.UID) == first {
		t.Fatal("the rebind kept the old listener")
	}
	if _, err := net.DialTimeout("tcp4", first, 200*time.Millisecond); err == nil {
		t.Fatal("the old listener still accepts")
	}
	if e, _ := r.Lookup(podA.UID); e.NetnsPath != "/run/netns/two" {
		t.Errorf("entry = %+v", e)
	}
	if len(closed) != 1 || closed[0] != podA {
		t.Errorf("the close hook saw %v, want the rebound pod once", closed)
	}
}

// The bind hook (the agent's prewarm) runs once per listener bound: not for
// an idempotent bind, again for a rebind into a new namespace, never for a
// failed bind.
func TestBindHookRunsOncePerBind(t *testing.T) {
	b := &loopback{}
	var bound []Pod
	r := New(b, WithBindHook(func(p Pod) { bound = append(bound, p) }))
	defer r.CloseAll()

	for range 3 {
		if err := r.Bind(podA, "/run/netns/one"); err != nil {
			t.Fatal(err)
		}
	}
	if len(bound) != 1 || bound[0] != podA {
		t.Fatalf("three binds in one namespace ran the hook for %v, want podA once", bound)
	}
	if err := r.Bind(podA, "/run/netns/two"); err != nil {
		t.Fatal(err)
	}
	if len(bound) != 2 {
		t.Fatalf("a rebind ran the hook %d times in all, want 2", len(bound))
	}
	r.Close(podA.UID)
	if err := r.Bind(podA, "/run/netns/two"); err != nil {
		t.Fatal(err)
	}
	if len(bound) != 3 {
		t.Fatalf("a bind after a close ran the hook %d times in all, want 3", len(bound))
	}

	failing := New(&loopback{fail: errors.New("EPERM")}, WithBindHook(func(p Pod) { bound = append(bound, p) }))
	defer failing.CloseAll()
	if err := failing.Bind(podA, "/run/netns/a"); err == nil {
		t.Fatal("the failing binder bound")
	}
	if len(bound) != 3 {
		t.Error("a failed bind ran the hook")
	}
}

func TestBindRefusesBadInput(t *testing.T) {
	r := New(&loopback{})
	defer r.CloseAll()
	if err := r.Bind(Pod{Namespace: "a", Name: "b"}, "/x"); err == nil {
		t.Error("a pod without UID was bound")
	}
	if err := r.Bind(podA, ""); err == nil {
		t.Error("a pod without a namespace path was bound")
	}
	if _, ok := r.Lookup(podA.UID); ok {
		t.Error("a refused bind left an entry")
	}
}

func TestBindReportsTheBindersError(t *testing.T) {
	want := errors.New("EPERM")
	r := New(&loopback{fail: want})
	defer r.CloseAll()
	err := r.Bind(podA, "/run/netns/a")
	if !errors.Is(err, want) {
		t.Fatalf("Bind = %v, want %v", err, want)
	}
	if len(r.Entries()) != 0 {
		t.Error("a failed bind left an entry")
	}
}

func TestCloseClosesTheListenerAndItsConnections(t *testing.T) {
	var closed []Pod
	r := New(&loopback{}, WithCloseHook(func(p Pod) { closed = append(closed, p) }))
	defer r.CloseAll()
	serve(t, r)
	if err := r.Bind(podA, "/run/netns/a"); err != nil {
		t.Fatal(err)
	}
	addr := addrOf(t, r, podA.UID)

	// A connection accepted before the close, idle on the server side.
	conn, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Make sure it has been accepted and handed to the server.
	time.Sleep(50 * time.Millisecond)

	if !r.Close(podA.UID) {
		t.Fatal("Close reported no entry")
	}
	if r.Close(podA.UID) {
		t.Fatal("a second Close reported an entry")
	}
	if len(closed) != 1 || closed[0] != podA {
		t.Errorf("close hook saw %v", closed)
	}
	if _, ok := r.Lookup(podA.UID); ok {
		t.Error("the entry is still there")
	}
	if _, err := net.DialTimeout("tcp4", addr, 200*time.Millisecond); err == nil {
		t.Error("the listener still accepts")
	}
	// The in-flight connection is gone: a read on it fails.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Error("the connection accepted before the close is still open")
	}
}

func TestCloseAllStopsAccept(t *testing.T) {
	r := New(&loopback{})
	if err := r.Bind(podA, "/run/netns/a"); err != nil {
		t.Fatal(err)
	}
	if err := r.Listener().Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after CloseAll = %v", err)
	}
	if err := r.Bind(podB, "/run/netns/b"); !errors.Is(err, ErrClosed) {
		t.Fatalf("Bind after CloseAll = %v", err)
	}
	if len(r.Entries()) != 0 {
		t.Error("entries survived CloseAll")
	}
}

func TestPodFromContext(t *testing.T) {
	if _, ok := PodFromContext(context.Background()); ok {
		t.Error("an empty context has a pod")
	}
	ctx := WithPod(context.Background(), podA)
	if p, ok := PodFromContext(ctx); !ok || p != podA {
		t.Errorf("PodFromContext = %v, %v", p, ok)
	}
	r := New(&loopback{})
	defer r.CloseAll()
	// A connection that is not a podConn adds nothing.
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, ok := PodFromContext(r.ConnContext(context.Background(), a)); ok {
		t.Error("a foreign connection got a pod")
	}
}
