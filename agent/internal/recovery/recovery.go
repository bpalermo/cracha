// Package recovery rebuilds the listener registry on start and keeps it in
// step with the node's pods (docs/design.md, section 7.4): the enrolled pods
// of this node (label cracha.dev/credentials, field selector spec.nodeName)
// are listed and watched; each running pod's network namespace is resolved
// through the CRI exactly as init-mode enrolment does, and its listener is
// bound again. A listener that cannot be bound is logged and retried on
// the next periodic pass; the listener of a pod that is gone is closed. In
// init mode this watch is what closes listeners, since nothing else tells
// the agent a pod went.
package recovery

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/bpalermo/cracha/agent/enrolapi"
	"github.com/bpalermo/cracha/agent/internal/cri"
	"github.com/bpalermo/cracha/agent/internal/enrol"
	"github.com/bpalermo/cracha/agent/internal/listener"
)

// DefaultInterval is the default period of the retry pass.
const DefaultInterval = 30 * time.Second

// Registry is what the reconciler keeps in step.
type Registry interface {
	Bind(pod listener.Pod, netnsPath string) error
	Close(uid string) bool
	Lookup(uid string) (listener.Entry, bool)
	Entries() []listener.Entry
}

// Config of the reconciler.
type Config struct {
	// Node is this node's name: the pods watched are its own.
	Node string
	// Interval is the period of the retry pass; DefaultInterval when zero.
	Interval time.Duration
	// Logger; the default logger when nil.
	Logger *slog.Logger
}

// Reconciler is the pod watch and the periodic pass.
type Reconciler struct {
	client   kubernetes.Interface
	resolver cri.Resolver
	registry Registry
	cfg      Config
	informer cache.SharedIndexInformer
}

// New returns a Reconciler over the API client, the CRI resolver and the
// registry.
func New(client kubernetes.Interface, resolver cri.Resolver, registry Registry, cfg Config) (*Reconciler, error) {
	if cfg.Node == "" {
		return nil, errors.New("the node name is required")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	req, err := labels.NewRequirement(enrolapi.Label, selection.Equals, []string{enrolapi.LabelValue})
	if err != nil {
		return nil, err
	}
	selector := labels.NewSelector().Add(*req).String()
	field := fields.OneTermEqualSelector("spec.nodeName", cfg.Node).String()
	factory := informers.NewSharedInformerFactoryWithOptions(client, 0,
		informers.WithTweakListOptions(func(o *metav1.ListOptions) {
			o.LabelSelector = selector
			o.FieldSelector = field
		}))
	r := &Reconciler{
		client: client, resolver: resolver, registry: registry, cfg: cfg,
		informer: factory.Core().V1().Pods().Informer(),
	}
	_, err = r.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { r.observe(obj, false) },
		UpdateFunc: func(_, obj any) { r.observe(obj, false) },
		DeleteFunc: func(obj any) { r.gone(obj) },
	})
	if err != nil {
		return nil, err
	}
	return r, nil
}

// HasSynced reports whether the first list has completed.
func (r *Reconciler) HasSynced() bool { return r.informer.HasSynced() }

// Run watches until ctx is done: the informer, then a pass over every pod
// in its store each interval.
func (r *Reconciler) Run(ctx context.Context) error {
	go r.informer.Run(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), r.informer.HasSynced) {
		return ctx.Err()
	}
	r.cfg.Logger.Info("recovery: the node's enrolled pods are listed", "node", r.cfg.Node,
		"pods", len(r.informer.GetStore().List()), "bound", len(r.registry.Entries()))
	ticker := time.NewTicker(r.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			r.pass(ctx)
		}
	}
}

// pass tries every pod of the store, which retries the binds that failed,
// rebinds a pod whose sandbox was recreated and closes what is finished.
func (r *Reconciler) pass(ctx context.Context) {
	for _, obj := range r.informer.GetStore().List() {
		if ctx.Err() != nil {
			return
		}
		r.observe(obj, true)
	}
}

// observe brings the registry in step with one pod object. An event about
// a pod that is already bound costs no CRI call: only the periodic pass
// (rebind) resolves every pod's namespace again, which is what catches a
// sandbox recreated under the same pod.
func (r *Reconciler) observe(obj any, rebind bool) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return
	}
	ref := listener.Pod{Namespace: pod.Namespace, Name: pod.Name, UID: string(pod.UID)}
	// The API cannot filter to the node's pods in every path the informer
	// takes, so the agent does, and it checks the label itself.
	if pod.Spec.NodeName != r.cfg.Node || !enrolapi.Enrolled(pod.Labels) {
		return
	}
	if finished(pod) {
		if r.registry.Close(ref.UID) {
			r.cfg.Logger.Info("recovery: closed the listener of a finished pod", "pod", ref.String(), "phase", pod.Status.Phase)
		}
		return
	}
	if _, err := enrol.Check(pod, ref); err != nil {
		if errors.Is(err, enrol.ErrGone) {
			// Still running out its grace period: its SDK may still call.
			return
		}
		r.cfg.Logger.Debug("recovery: skipping", "pod", ref.String(), "error", err)
		return
	}
	if !sandboxed(pod) {
		// No sandbox yet: enrolment (7.2) binds it when there is one.
		return
	}
	if _, bound := r.registry.Lookup(ref.UID); bound && !rebind {
		return
	}
	if err := r.bind(ref); err != nil {
		r.cfg.Logger.Warn("recovery: cannot bind; will retry", "pod", ref.String(), "error", err)
	}
}

// bind resolves the pod's network namespace and binds its listener; the
// registry's Bind is idempotent for an unchanged namespace.
func (r *Reconciler) bind(ref listener.Pod) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	netns, err := r.resolver.NetnsPath(ctx, ref.UID)
	if err != nil {
		return fmt.Errorf("resolving the network namespace: %w", err)
	}
	return r.registry.Bind(ref, netns)
}

// gone closes the listener of a deleted pod.
func (r *Reconciler) gone(obj any) {
	if tomb, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = tomb.Obj
	}
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return
	}
	if r.registry.Close(string(pod.UID)) {
		r.cfg.Logger.Info("recovery: closed the listener of a deleted pod",
			"pod", listener.Pod{Namespace: pod.Namespace, Name: pod.Name, UID: string(pod.UID)}.String())
	}
}

// finished reports a pod whose containers will not run again.
func finished(pod *corev1.Pod) bool {
	return pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed
}

// sandboxed reports a pod whose sandbox exists: it is running, or has an
// address (the sandbox is up while its init containers run).
func sandboxed(pod *corev1.Pod) bool {
	return pod.Status.Phase == corev1.PodRunning || pod.Status.PodIP != ""
}
