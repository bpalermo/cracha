package sacache

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func sa(namespace, name string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
}

// countingClient returns a fake clientset holding the objects, and a counter
// of the ServiceAccount gets it served.
func countingClient(objects ...runtime.Object) (*fake.Clientset, *atomic.Int64) {
	client := fake.NewClientset(objects...)
	var gets atomic.Int64
	client.PrependReactor("get", "serviceaccounts", func(k8stesting.Action) (bool, runtime.Object, error) {
		gets.Add(1)
		return false, nil, nil
	})
	return client, &gets
}

func TestGetCachesWithinTTL(t *testing.T) {
	client, gets := countingClient(sa("ns", "app"))
	c := New(client, time.Minute)
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		got, err := c.Get(ctx, "ns", "app")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.Name != "app" {
			t.Fatalf("Get returned %q", got.Name)
		}
	}
	if n := gets.Load(); n != 1 {
		t.Fatalf("apiserver gets within the TTL: %d, want 1", n)
	}

	now = now.Add(time.Minute)
	if _, err := c.Get(ctx, "ns", "app"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if n := gets.Load(); n != 2 {
		t.Fatalf("apiserver gets after the TTL: %d, want 2", n)
	}
}

func TestGetDoesNotCacheMisses(t *testing.T) {
	client, gets := countingClient()
	c := New(client, time.Minute)
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		_, err := c.Get(ctx, "ns", "missing")
		if !apierrors.IsNotFound(err) {
			t.Fatalf("Get of a missing service account: %v, want not found", err)
		}
	}
	if n := gets.Load(); n != 2 {
		t.Fatalf("apiserver gets for a missing service account: %d, want 2", n)
	}

	// It appears: the next lookup sees it.
	if _, err := client.CoreV1().ServiceAccounts("ns").Create(ctx, sa("ns", "missing"), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(ctx, "ns", "missing"); err != nil {
		t.Fatalf("Get after creation: %v", err)
	}
}

func TestGetDoesNotCacheErrors(t *testing.T) {
	client, gets := countingClient(sa("ns", "app"))
	fail := true
	// Prepended in front of the counting reactor, so it counts for itself.
	client.PrependReactor("get", "serviceaccounts", func(k8stesting.Action) (bool, runtime.Object, error) {
		if fail {
			gets.Add(1)
			return true, nil, apierrors.NewServiceUnavailable("down")
		}
		return false, nil, nil
	})
	c := New(client, time.Minute)
	ctx := context.Background()

	_, err := c.Get(ctx, "ns", "app")
	var statusErr *apierrors.StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("Get while the apiserver is down: %v, want the apiserver's error", err)
	}
	fail = false
	if _, err := c.Get(ctx, "ns", "app"); err != nil {
		t.Fatalf("Get after recovery: %v", err)
	}
	if n := gets.Load(); n != 2 {
		t.Fatalf("apiserver gets: %d, want 2", n)
	}
}

func TestGetWithoutTTL(t *testing.T) {
	client, gets := countingClient(sa("ns", "app"))
	c := New(client, 0)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := c.Get(ctx, "ns", "app"); err != nil {
			t.Fatalf("Get: %v", err)
		}
	}
	if n := gets.Load(); n != 2 {
		t.Fatalf("apiserver gets with caching off: %d, want 2", n)
	}
}

func TestSweepDropsExpiredEntries(t *testing.T) {
	client, _ := countingClient(sa("ns", "a"), sa("ns", "b"))
	c := New(client, time.Minute)
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	ctx := context.Background()

	if _, err := c.Get(ctx, "ns", "a"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := c.Get(ctx, "ns", "b"); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[key{"ns", "a"}]; ok {
		t.Fatal("the expired entry survived the sweep")
	}
	if _, ok := c.entries[key{"ns", "b"}]; !ok {
		t.Fatal("the fresh entry is missing")
	}
}
