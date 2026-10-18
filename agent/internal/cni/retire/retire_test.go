package retire

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/bpalermo/cracha/agent/internal/cni/install"
)

const (
	namespace = "cracha-system"
	name      = "cracha-agent"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// daemonSet is the agent's DaemonSet with the mode in its pod template, or
// without the annotation when mode is "".
func daemonSet(mode string) *appsv1.DaemonSet {
	ds := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
	if mode != "" {
		ds.Spec.Template.Annotations = map[string]string{AnnotationEnrol: mode}
	}
	return ds
}

// failing is a clientset whose DaemonSet reads fail with err.
func failing(err error) kubernetes.Interface {
	client := fake.NewClientset(daemonSet(ModeCNI))
	client.PrependReactor("get", "daemonsets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, err
	})
	return client
}

func TestDecide(t *testing.T) {
	retryInterval = 5 * time.Millisecond
	deleting := daemonSet(ModeCNI)
	now := metav1.Now()
	deleting.DeletionTimestamp = &now
	deleting.Finalizers = []string{"foregroundDeletion"}
	gr := schema.GroupResource{Group: "apps", Resource: "daemonsets"}
	tests := map[string]struct {
		client kubernetes.Interface
		retire bool
		reason string
	}{
		"mode unchanged":          {fake.NewClientset(daemonSet(ModeCNI)), false, "still selects the cni mode"},
		"mode changed":            {fake.NewClientset(daemonSet("init")), true, "now selects the init mode"},
		"annotation missing":      {fake.NewClientset(daemonSet("")), false, "does not carry cracha.dev/enrol"},
		"daemonset absent":        {fake.NewClientset(), true, "is gone"},
		"daemonset being deleted": {fake.NewClientset(deleting), true, "is being deleted"},
		"forbidden":               {failing(apierrors.NewForbidden(gr, name, errors.New("no"))), false, "could not be read within the budget"},
		"unavailable":             {failing(apierrors.NewServiceUnavailable("down")), false, "could not be read within the budget"},
		"unknown error":           {failing(errors.New("connection refused")), false, "could not be read within the budget"},
		"unauthorized":            {failing(apierrors.NewUnauthorized("token invalid")), true, "no longer accepted"},
	}
	for tname, tt := range tests {
		t.Run(tname, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			d := Decide(ctx, tt.client, namespace, name, quiet)
			if d.Retire != tt.retire || !strings.Contains(d.Reason, tt.reason) {
				t.Errorf("Decide = %+v, want retire %t with reason containing %q", d, tt.retire, tt.reason)
			}
		})
	}
}

// A transient failure followed by an answer decides on the answer, not on
// the failure.
func TestDecideRetries(t *testing.T) {
	retryInterval = 5 * time.Millisecond
	client := fake.NewClientset(daemonSet("init"))
	failures := 2
	client.PrependReactor("get", "daemonsets", func(k8stesting.Action) (bool, runtime.Object, error) {
		if failures > 0 {
			failures--
			return true, nil, apierrors.NewServiceUnavailable("starting")
		}
		return false, nil, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if d := Decide(ctx, client, namespace, name, quiet); !d.Retire || failures != 0 {
		t.Errorf("Decide = %+v after %d failures left, want retire on the answer that followed", d, failures)
	}
}

// node is a node's CNI directories with the plugin installed: the binary
// and the entry in the primary conflist.
type node struct {
	cfg      install.Config
	binary   string
	conflist string
}

func newNode(t *testing.T) *node {
	t.Helper()
	root := t.TempDir()
	n := &node{
		binary:   filepath.Join(root, "bin", "cracha-cni"),
		conflist: filepath.Join(root, "net.d", "10-kindnet.conflist"),
	}
	n.cfg = install.Config{BinDir: filepath.Dir(n.binary), ConfDir: filepath.Dir(n.conflist), Socket: "/run/cracha/cni.sock", Logger: quiet}
	for _, d := range []string{n.cfg.BinDir, n.cfg.ConfDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(n.binary, []byte("plugin"), 0o755); err != nil {
		t.Fatal(err)
	}
	conflist := `{"cniVersion": "0.3.1", "name": "kindnet", "plugins": [{"type": "ptp"}, {"type": "cracha-cni", "socket": "/run/cracha/cni.sock", "timeout": "5s"}]}`
	if err := os.WriteFile(n.conflist, []byte(conflist), 0o644); err != nil {
		t.Fatal(err)
	}
	return n
}

// installed reports whether the plugin is still on the node.
func (n *node) installed(t *testing.T) bool {
	t.Helper()
	data, err := os.ReadFile(n.conflist)
	if err != nil {
		t.Fatal(err)
	}
	_, statErr := os.Stat(n.binary)
	return strings.Contains(string(data), "cracha-cni") || statErr == nil
}

// Run uninstalls on a decision to retire and touches nothing otherwise.
func TestRun(t *testing.T) {
	for tname, tt := range map[string]struct {
		mode    string
		removed bool
	}{
		"mode changed":   {"init", true},
		"mode unchanged": {ModeCNI, false},
	} {
		t.Run(tname, func(t *testing.T) {
			n := newNode(t)
			cfg := Config{Namespace: namespace, DaemonSet: name, Timeout: time.Second, Install: n.cfg, Logger: quiet}
			if err := Run(context.Background(), fake.NewClientset(daemonSet(tt.mode)), cfg); err != nil {
				t.Fatal(err)
			}
			if n.installed(t) == tt.removed {
				t.Errorf("plugin installed = %t after Run, want %t", n.installed(t), !tt.removed)
			}
		})
	}
}

// The pod template of a real DaemonSet carries the annotation among the
// chart's others; only its value matters.
func TestDecideReadsTemplateAnnotation(t *testing.T) {
	ds := daemonSet("init")
	ds.Annotations = map[string]string{AnnotationEnrol: ModeCNI} // on the object, not the template: ignored
	ds.Spec.Template.Annotations["other"] = "x"
	ds.Spec.Template.Spec.Containers = []corev1.Container{{Name: "agent"}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if d := Decide(ctx, fake.NewClientset(ds), namespace, name, quiet); !d.Retire {
		t.Errorf("Decide = %+v, want retire from the template's annotation", d)
	}
}
