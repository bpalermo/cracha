// Package nsregion serves the per-namespace AWS_REGION override of
// docs/design.md, section 7.4, the Namespace annotation "cracha.dev/region",
// to the webhook's Regions hook from an informer's cache.
//
// An informer, where sacache looks up and remembers, because a region
// override is an attribute of a namespace: a cluster has few, the whole set
// fits in memory, and a watch keeps it current without a round trip per
// pod. Nothing is asked of the apiserver on the admission path. A namespace
// the cache does not hold, because the informer has not listed yet or
// because the namespace does not exist, has no override and the default
// region applies: an override is a refinement, never a reason to deny. The
// one way to deny is an annotation whose value is not an AWS region, which
// is a mistake worth refusing loudly rather than injecting into every pod
// of the namespace. An annotation with an empty value is no override.
//
// The informer needs list and watch on namespaces, cluster-wide, which the
// chart's ClusterRole grants. Until it has listed, the webhook reports not
// ready (main.go), so a webhook that cannot watch namespaces is noticed
// rather than silently ignoring the annotation.
package nsregion

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/bpalermo/cracha/webhook/internal/mutate"
)

// Regions answers the webhook's region lookups from a namespace informer.
type Regions struct {
	informer cache.SharedIndexInformer
	lister   corev1listers.NamespaceLister
}

// New returns a Regions over the client's namespaces. It serves nothing but
// the default until Run has listed them.
func New(client kubernetes.Interface) *Regions {
	namespaces := informers.NewSharedInformerFactory(client, 0).Core().V1().Namespaces()
	return &Regions{informer: namespaces.Informer(), lister: namespaces.Lister()}
}

// Run lists and watches the namespaces until ctx is done.
func (r *Regions) Run(ctx context.Context) {
	r.informer.Run(ctx.Done())
}

// HasSynced reports whether the cache has listed the namespaces once, which
// is when the overrides are served.
func (r *Regions) HasSynced() bool {
	return r.informer.HasSynced()
}

// Region implements mutate.Regions: the namespace's annotated region, or ""
// when it has none, is unknown to the cache, or the cache has not listed
// yet. An annotation that is not an AWS region is a mutate.InvalidRegionError.
func (r *Regions) Region(_ context.Context, namespace string) (string, error) {
	if !r.informer.HasSynced() {
		return "", nil
	}
	ns, err := r.lister.Get(namespace)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return "", nil
		}
		return "", err
	}
	value := ns.Annotations[mutate.AnnotationRegion]
	if value == "" {
		return "", nil
	}
	if !mutate.IsRegion(value) {
		return "", &mutate.InvalidRegionError{Namespace: namespace, Value: value}
	}
	return value, nil
}
