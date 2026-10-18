package recovery

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/bpalermo/cracha/agent/enrolapi"
	"github.com/bpalermo/cracha/agent/internal/cri"
	"github.com/bpalermo/cracha/agent/internal/listener"
)

type fakeRegistry struct {
	mu     sync.Mutex
	bound  map[string]string
	fail   map[string]bool // uids whose bind fails
	binds  int
	closed []string
}

func newFakeRegistry() *fakeRegistry {
	return &fakeRegistry{bound: map[string]string{}, fail: map[string]bool{}}
}

func (r *fakeRegistry) Bind(pod listener.Pod, netnsPath string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.binds++
	if r.fail[pod.UID] {
		return errors.New("EPERM")
	}
	r.bound[pod.UID] = netnsPath
	return nil
}

func (r *fakeRegistry) Close(uid string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = append(r.closed, uid)
	_, ok := r.bound[uid]
	delete(r.bound, uid)
	return ok
}

func (r *fakeRegistry) Lookup(uid string) (listener.Entry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, ok := r.bound[uid]
	return listener.Entry{NetnsPath: n}, ok
}

func (r *fakeRegistry) Entries() []listener.Entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]listener.Entry, 0, len(r.bound))
	for uid, n := range r.bound {
		out = append(out, listener.Entry{Pod: listener.Pod{UID: uid}, NetnsPath: n})
	}
	return out
}

func (r *fakeRegistry) snapshot() (map[string]string, []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	b := map[string]string{}
	for k, v := range r.bound {
		b[k] = v
	}
	return b, append([]string(nil), r.closed...)
}

// resolver maps each UID to /run/netns/<uid>, refusing uids in down.
type resolver struct {
	mu   sync.Mutex
	down map[string]bool
}

func (r *resolver) NetnsPath(_ context.Context, uid string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.down[uid] {
		return "", cri.ErrNoSandbox
	}
	return "/run/netns/" + uid, nil
}

func pod(name, uid, node string, phase corev1.PodPhase, ip string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: name, UID: types.UID(uid),
			Labels: map[string]string{enrolapi.Label: enrolapi.LabelValue},
		},
		Spec:   corev1.PodSpec{NodeName: node},
		Status: corev1.PodStatus{Phase: phase, PodIP: ip},
	}
}

// eventually waits for cond.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestRecoveryRebindsTheNodesRunningPodsAndFollowsTheWatch(t *testing.T) {
	running := pod("a", "uid-a", "node-1", corev1.PodRunning, "10.0.0.1")
	pending := pod("b", "uid-b", "node-1", corev1.PodPending, "")
	elsewhere := pod("c", "uid-c", "node-2", corev1.PodRunning, "10.0.0.3")
	unlabelled := pod("d", "uid-d", "node-1", corev1.PodRunning, "10.0.0.4")
	unlabelled.Labels = nil
	hostNet := pod("e", "uid-e", "node-1", corev1.PodRunning, "10.0.0.5")
	hostNet.Spec.HostNetwork = true
	finished := pod("f", "uid-f", "node-1", corev1.PodSucceeded, "10.0.0.6")
	client := fake.NewClientset(running, pending, elsewhere, unlabelled, hostNet, finished)
	reg := newFakeRegistry()
	res := &resolver{down: map[string]bool{}}
	r, err := New(client, res, reg, Config{Node: "node-1", Interval: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()

	eventually(t, "the running pod's bind", func() bool { b, _ := reg.snapshot(); return b["uid-a"] == "/run/netns/uid-a" })
	eventually(t, "the first list", r.HasSynced)
	time.Sleep(100 * time.Millisecond) // a pass or two
	bound, _ := reg.snapshot()
	if len(bound) != 1 {
		t.Fatalf("bound = %v, want the running pod of this node only", bound)
	}

	// The pending pod gets its sandbox: bound on the update.
	pending.Status.PodIP = "10.0.0.2"
	if _, err := client.CoreV1().Pods("apps").UpdateStatus(ctx, pending, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the pending pod's bind", func() bool { b, _ := reg.snapshot(); return b["uid-b"] == "/run/netns/uid-b" })

	// A deleted pod's listener is closed.
	if err := client.CoreV1().Pods("apps").Delete(ctx, "a", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the deleted pod's close", func() bool { b, _ := reg.snapshot(); _, ok := b["uid-a"]; return !ok })

	// A pod that finishes is closed too.
	pending.Status.Phase = corev1.PodFailed
	if _, err := client.CoreV1().Pods("apps").UpdateStatus(ctx, pending, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the failed pod's close", func() bool { b, _ := reg.snapshot(); _, ok := b["uid-b"]; return !ok })

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryRetriesFailedBindsOnThePeriodicPass(t *testing.T) {
	p := pod("a", "uid-a", "node-1", corev1.PodRunning, "10.0.0.1")
	client := fake.NewClientset(p)
	reg := newFakeRegistry()
	res := &resolver{down: map[string]bool{"uid-a": true}}
	r, err := New(client, res, reg, Config{Node: "node-1", Interval: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = r.Run(ctx) }()
	eventually(t, "the first list", r.HasSynced)
	time.Sleep(60 * time.Millisecond)
	if b, _ := reg.snapshot(); len(b) != 0 {
		t.Fatalf("bound = %v while the sandbox was unresolvable", b)
	}
	// The sandbox appears: the next pass binds it.
	res.mu.Lock()
	res.down["uid-a"] = false
	res.mu.Unlock()
	eventually(t, "the retried bind", func() bool { b, _ := reg.snapshot(); return b["uid-a"] == "/run/netns/uid-a" })

	// A bind that the registry refuses is retried the same way.
	reg.mu.Lock()
	reg.fail["uid-a"] = true
	delete(reg.bound, "uid-a")
	before := reg.binds
	reg.mu.Unlock()
	eventually(t, "further bind attempts", func() bool { reg.mu.Lock(); defer reg.mu.Unlock(); return reg.binds > before+1 })
	reg.mu.Lock()
	reg.fail["uid-a"] = false
	reg.mu.Unlock()
	eventually(t, "the bind after the registry recovers", func() bool { b, _ := reg.snapshot(); return b["uid-a"] == "/run/netns/uid-a" })
}

func TestNewRequiresTheNode(t *testing.T) {
	if _, err := New(fake.NewClientset(), &resolver{}, newFakeRegistry(), Config{}); err == nil {
		t.Fatal("New without a node succeeded")
	}
}
