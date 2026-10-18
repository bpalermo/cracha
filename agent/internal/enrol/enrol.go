// Package enrol binds a pod's loopback listener before its app containers
// start (docs/design.md, section 7.2). Enroller is what both modes share:
// the pod is looked up through the API, must carry the enrolment label and
// must not use the host's network, then its listener is bound in the
// network namespace path the mode resolved. Server is the init mode's
// endpoint (POST /v1/enrol with a bound token, TokenReview, CRI for the
// namespace path); Client is the cracha-enrol init container's side.
package enrol

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/bpalermo/cracha/agent/enrolapi"
	"github.com/bpalermo/cracha/agent/internal/listener"
)

// Refusals of an enrolment.
var (
	// ErrNotEnrolled: the pod does not carry the enrolment label.
	ErrNotEnrolled = errors.New("the pod does not carry " + enrolapi.Label + ": " + enrolapi.LabelValue)
	// ErrHostNetwork: the pod has no network namespace of its own.
	ErrHostNetwork = errors.New("the pod uses the host's network")
	// ErrNoSuchPod: there is no pod of that namespace, name and UID.
	ErrNoSuchPod = errors.New("no such pod")
	// ErrGone: the pod's deletion has been requested.
	ErrGone = errors.New("the pod is being deleted")
)

// Registry is the listener registry Enroller binds in.
type Registry interface {
	Bind(pod listener.Pod, netnsPath string) error
	Close(uid string) bool
}

// Enroller checks and binds.
type Enroller struct {
	client   kubernetes.Interface
	registry Registry
	log      *slog.Logger
}

// NewEnroller returns an Enroller over the API client and the registry.
func NewEnroller(client kubernetes.Interface, registry Registry, log *slog.Logger) *Enroller {
	if log == nil {
		log = slog.Default()
	}
	return &Enroller{client: client, registry: registry, log: log}
}

// Lookup gets the pod and checks it may be enrolled: it exists with that
// UID, carries the label and has a network namespace of its own. The pod
// object exists by the time either mode runs, so a missing pod is a
// refusal, not something to wait for.
func (e *Enroller) Lookup(ctx context.Context, ref listener.Pod) (*corev1.Pod, error) {
	pod, err := e.client.CoreV1().Pods(ref.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("%w: %s", ErrNoSuchPod, ref)
	}
	if err != nil {
		return nil, fmt.Errorf("getting pod %s: %w", ref, err)
	}
	return Check(pod, ref)
}

// Check is Lookup's decision over a pod object.
func Check(pod *corev1.Pod, ref listener.Pod) (*corev1.Pod, error) {
	if ref.UID != "" && string(pod.UID) != ref.UID {
		return nil, fmt.Errorf("%w: %s/%s is uid %s, not %s", ErrNoSuchPod, ref.Namespace, ref.Name, pod.UID, ref.UID)
	}
	if !enrolapi.Enrolled(pod.Labels) {
		return nil, fmt.Errorf("%w: %s", ErrNotEnrolled, ref)
	}
	if pod.Spec.HostNetwork {
		return nil, fmt.Errorf("%w: %s", ErrHostNetwork, ref)
	}
	if pod.DeletionTimestamp != nil {
		return nil, fmt.Errorf("%w: %s", ErrGone, ref)
	}
	return pod, nil
}

// Enrol looks the pod up and binds its listener in netnsPath.
func (e *Enroller) Enrol(ctx context.Context, ref listener.Pod, netnsPath string) error {
	if _, err := e.Lookup(ctx, ref); err != nil {
		return err
	}
	return e.registry.Bind(ref, netnsPath)
}

// Unenrol closes the pod's listener, if it had one.
func (e *Enroller) Unenrol(ref listener.Pod) bool {
	return e.registry.Close(ref.UID)
}

// Refused reports whether err is a refusal of the pod (as opposed to a
// failure to find out).
func Refused(err error) bool {
	return errors.Is(err, ErrNotEnrolled) || errors.Is(err, ErrHostNetwork) ||
		errors.Is(err, ErrNoSuchPod) || errors.Is(err, ErrGone)
}
