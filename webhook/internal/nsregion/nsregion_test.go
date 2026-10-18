package nsregion

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	"github.com/bpalermo/cracha/webhook/internal/mutate"
)

func namespace(name string, annotations map[string]string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Annotations: annotations}}
}

func annotated(name, region string) *corev1.Namespace {
	return namespace(name, map[string]string{mutate.AnnotationRegion: region})
}

// synced returns a Regions over the namespaces, running and listed.
func synced(t *testing.T, namespaces ...*corev1.Namespace) (*Regions, *fake.Clientset) {
	t.Helper()
	objects := make([]runtime.Object, 0, len(namespaces))
	for _, ns := range namespaces {
		objects = append(objects, ns)
	}
	client := fake.NewClientset(objects...)
	r := New(client)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go r.Run(ctx)
	if !cache.WaitForCacheSync(ctx.Done(), r.HasSynced) {
		t.Fatal("the namespace informer did not sync")
	}
	return r, client
}

func TestRegionBeforeSync(t *testing.T) {
	// Not running: nothing is listed, so nothing overrides, and nothing
	// denies either.
	r := New(fake.NewClientset(annotated("apps", "sa-east-1"), annotated("bad", "nowhere")))
	for _, ns := range []string{"apps", "bad", "missing"} {
		got, err := r.Region(context.Background(), ns)
		if got != "" || err != nil {
			t.Errorf("Region(%q) before the sync = %q, %v; want no override and no error", ns, got, err)
		}
	}
	if r.HasSynced() {
		t.Error("HasSynced before Run")
	}
}

func TestRegion(t *testing.T) {
	r, _ := synced(t,
		namespace("plain", nil),
		namespace("empty", map[string]string{mutate.AnnotationRegion: ""}),
		namespace("other", map[string]string{"team": "payments"}),
		annotated("apps", "sa-east-1"),
		annotated("gov", "us-gov-west-1"),
		annotated("bad", "São Paulo"),
		annotated("partial", "us-east"),
	)
	ctx := context.Background()
	for _, tc := range []struct {
		namespace string
		want      string
	}{
		{"plain", ""},
		{"empty", ""},
		{"other", ""},
		{"missing", ""},
		{"apps", "sa-east-1"},
		{"gov", "us-gov-west-1"},
	} {
		got, err := r.Region(ctx, tc.namespace)
		if err != nil {
			t.Errorf("Region(%q): %v", tc.namespace, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Region(%q) = %q, want %q", tc.namespace, got, tc.want)
		}
	}
	for _, ns := range []string{"bad", "partial"} {
		_, err := r.Region(ctx, ns)
		var invalid *mutate.InvalidRegionError
		if !errors.As(err, &invalid) {
			t.Errorf("Region(%q) = %v, want an InvalidRegionError", ns, err)
			continue
		}
		if invalid.Namespace != ns {
			t.Errorf("Region(%q) names namespace %q", ns, invalid.Namespace)
		}
	}
}

func TestRegionFollowsChanges(t *testing.T) {
	r, client := synced(t, namespace("apps", nil), annotated("old", "eu-west-1"))
	ctx := context.Background()

	for _, change := range []struct {
		name string
		do   func() error
		ns   string
		want string
	}{
		{
			name: "annotating a namespace",
			do: func() error {
				_, err := client.CoreV1().Namespaces().Update(ctx, annotated("apps", "ap-southeast-2"), metav1.UpdateOptions{})
				return err
			},
			ns:   "apps",
			want: "ap-southeast-2",
		},
		{
			name: "removing the annotation",
			do: func() error {
				_, err := client.CoreV1().Namespaces().Update(ctx, namespace("old", nil), metav1.UpdateOptions{})
				return err
			},
			ns:   "old",
			want: "",
		},
		{
			name: "creating an annotated namespace",
			do: func() error {
				_, err := client.CoreV1().Namespaces().Create(ctx, annotated("new", "ca-central-1"), metav1.CreateOptions{})
				return err
			},
			ns:   "new",
			want: "ca-central-1",
		},
		{
			name: "deleting a namespace",
			do: func() error {
				return client.CoreV1().Namespaces().Delete(ctx, "new", metav1.DeleteOptions{})
			},
			ns:   "new",
			want: "",
		},
	} {
		if err := change.do(); err != nil {
			t.Fatalf("%s: %v", change.name, err)
		}
		deadline := time.Now().Add(10 * time.Second)
		for {
			got, err := r.Region(ctx, change.ns)
			if err != nil {
				t.Fatalf("%s: Region(%q): %v", change.name, change.ns, err)
			}
			if got == change.want {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: Region(%q) = %q, want %q", change.name, change.ns, got, change.want)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}
