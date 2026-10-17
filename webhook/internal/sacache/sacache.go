// Package sacache looks ServiceAccounts up through client-go and remembers
// each answer for a short time.
//
// A cache was chosen over an informer because the webhook only ever needs
// the one ServiceAccount a pod names: a Get needs no cluster-wide list and
// watch permission, no memory for every ServiceAccount in the cluster, and
// no sync before the first admission. The cost is that flipping the
// "cracha.dev/enabled" annotation takes up to the TTL to be seen, and that
// a burst of pods on one ServiceAccount costs one apiserver Get per TTL.
// Only successful lookups are cached: an error or a missing ServiceAccount is
// asked again on the next pod, so a ServiceAccount created moments ago is
// seen as soon as the apiserver has it.
package sacache

import (
	"context"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Cache serves ServiceAccounts from the apiserver with a TTL.
type Cache struct {
	client kubernetes.Interface
	ttl    time.Duration
	now    func() time.Time

	mu      sync.Mutex
	entries map[key]entry
}

type key struct{ namespace, name string }

type entry struct {
	sa      *corev1.ServiceAccount
	expires time.Time
}

// New returns a Cache that remembers each ServiceAccount for ttl. A ttl of
// zero or less disables caching.
func New(client kubernetes.Interface, ttl time.Duration) *Cache {
	return &Cache{
		client:  client,
		ttl:     ttl,
		now:     time.Now,
		entries: map[key]entry{},
	}
}

// Get returns the ServiceAccount, from the cache while its entry is fresh.
// The returned object is shared and must not be modified.
func (c *Cache) Get(ctx context.Context, namespace, name string) (*corev1.ServiceAccount, error) {
	k := key{namespace, name}
	now := c.now()

	c.mu.Lock()
	e, ok := c.entries[k]
	c.mu.Unlock()
	if ok && now.Before(e.expires) {
		return e.sa, nil
	}

	sa, err := c.client.CoreV1().ServiceAccounts(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if c.ttl <= 0 {
		return sa, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// Misses are rare (one per ServiceAccount per TTL), so sweeping on each
	// bounds the map to the ServiceAccounts seen within one TTL.
	for k, e := range c.entries {
		if !now.Before(e.expires) {
			delete(c.entries, k)
		}
	}
	c.entries[k] = entry{sa: sa, expires: now.Add(c.ttl)}
	return sa, nil
}
