package enrol

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/bpalermo/cracha/agent/enrolapi"
	"github.com/bpalermo/cracha/agent/internal/listener"
)

// fakeRegistry records binds and closes.
type fakeRegistry struct {
	mu     sync.Mutex
	bound  map[string]string // uid -> netns
	fail   error
	closed []string
}

func newFakeRegistry() *fakeRegistry { return &fakeRegistry{bound: map[string]string{}} }

func (r *fakeRegistry) Bind(pod listener.Pod, netnsPath string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail != nil {
		return r.fail
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
	netns, ok := r.bound[uid]
	return listener.Entry{Pod: listener.Pod{UID: uid}, NetnsPath: netns}, ok
}

func (r *fakeRegistry) Entries() []listener.Entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []listener.Entry
	for uid, netns := range r.bound {
		out = append(out, listener.Entry{Pod: listener.Pod{UID: uid}, NetnsPath: netns})
	}
	return out
}

func (r *fakeRegistry) netnsOf(uid string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.bound[uid]
}

// enrolledPod is a pod carrying the label, on node "node-1".
func enrolledPod(ns, name, uid string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name, UID: types.UID(uid),
			Labels: map[string]string{enrolapi.Label: enrolapi.LabelValue},
		},
		Spec:   corev1.PodSpec{NodeName: "node-1"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0.5"},
	}
}

var ref = listener.Pod{Namespace: "apps", Name: "api", UID: "uid-1"}

func TestEnrolBindsAnEnrolledPod(t *testing.T) {
	reg := newFakeRegistry()
	e := NewEnroller(fake.NewClientset(enrolledPod("apps", "api", "uid-1")), reg, nil)
	if err := e.Enrol(context.Background(), ref, "/run/netns/a"); err != nil {
		t.Fatal(err)
	}
	if reg.netnsOf("uid-1") != "/run/netns/a" {
		t.Fatalf("bound = %v", reg.bound)
	}
	if !e.Unenrol(ref) || e.Unenrol(ref) {
		t.Error("Unenrol did not report the close once")
	}
}

func TestEnrolRefusals(t *testing.T) {
	unlabelled := enrolledPod("apps", "api", "uid-1")
	unlabelled.Labels = nil
	wrongValue := enrolledPod("apps", "api", "uid-1")
	wrongValue.Labels[enrolapi.Label] = "yes"
	hostNet := enrolledPod("apps", "api", "uid-1")
	hostNet.Spec.HostNetwork = true
	now := metav1.Now()
	gone := enrolledPod("apps", "api", "uid-1")
	gone.DeletionTimestamp = &now
	for name, tc := range map[string]struct {
		pod  *corev1.Pod
		want error
	}{
		"no label":    {unlabelled, ErrNotEnrolled},
		"wrong value": {wrongValue, ErrNotEnrolled},
		"host net":    {hostNet, ErrHostNetwork},
		"deleting":    {gone, ErrGone},
		"recycled":    {enrolledPod("apps", "api", "uid-old"), ErrNoSuchPod},
		"missing":     {enrolledPod("apps", "other", "uid-1"), ErrNoSuchPod},
	} {
		t.Run(name, func(t *testing.T) {
			reg := newFakeRegistry()
			e := NewEnroller(fake.NewClientset(tc.pod), reg, nil)
			err := e.Enrol(context.Background(), ref, "/run/netns/a")
			if !errors.Is(err, tc.want) {
				t.Fatalf("Enrol = %v, want %v", err, tc.want)
			}
			if !Refused(err) {
				t.Error("not reported as a refusal")
			}
			if len(reg.bound) != 0 {
				t.Error("a refused pod was bound")
			}
		})
	}
}

func TestEnrolReportsBindFailures(t *testing.T) {
	reg := newFakeRegistry()
	reg.fail = errors.New("EPERM")
	e := NewEnroller(fake.NewClientset(enrolledPod("apps", "api", "uid-1")), reg, nil)
	err := e.Enrol(context.Background(), ref, "/run/netns/a")
	if err == nil || Refused(err) {
		t.Fatalf("Enrol = %v, want the bind's error, not a refusal", err)
	}
}

// pipeDialer is a Dial for the client tests: it answers from accept.
func pipeDialer(accept bool) func(context.Context, string) (net.Conn, error) {
	return func(context.Context, string) (net.Conn, error) {
		if !accept {
			return nil, errors.New("connection refused")
		}
		a, b := net.Pipe()
		go b.Close()
		return a, nil
	}
}
