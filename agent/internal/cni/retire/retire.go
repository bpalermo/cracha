// Package retire is `cracha-agent cni-retire`, the preStop hook of the agent
// container in cni mode (docs/design.md, section 7.2): it decides whether
// the termination it runs in retires the cracha-cni plugin from the node
// and, when it does, runs the installer's uninstall
// (agent/internal/cni/install), which removes the plugin's entry from the
// node's primary conflist and its binary.
//
// The plugin is on the sandbox path of every pod of the node and fails
// every sandbox while nothing serves its socket. An agent that is only
// restarting, being rolled out with the mode unchanged or evicted by a
// drain comes back and serves it, so the plugin stays. It is retired when
// the agent is not coming back in cni mode: its DaemonSet is gone or being
// deleted (the chart is being uninstalled), the DaemonSet's pod template
// selects another mode (the chart's annotation AnnotationEnrol, which
// follows agent.enrol), or the pod's own identity is no longer accepted
// (401 for as long as the budget lasts: the release's ServiceAccount was
// deleted, which an uninstall does moments after the DaemonSet, and
// without which the agent could enrol nothing anyway). On anything else,
// a Forbidden, an apiserver that does not answer within the budget or a
// template that does not say its mode, it logs and leaves the plugin in
// place: retiring on doubt would break every new pod of a node whose agent
// is about to return. A pod killed without the hook (a node crash) leaves
// the plugin too; `cracha-agent cni-install --uninstall` run once on the
// node, or the chart installed again in cni mode, puts that right.
package retire

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/bpalermo/cracha/agent/internal/cni/install"
)

const (
	// AnnotationEnrol is the annotation the chart sets on the agent's pod
	// template with the enrolment mode the template selects (agent.enrol).
	AnnotationEnrol = "cracha.dev/enrol"
	// ModeCNI is the value of AnnotationEnrol that keeps the plugin.
	ModeCNI = "cni"
	// DefaultTimeout is how long the DaemonSet is retried for before the
	// plugin is left in place. The pod's terminationGracePeriodSeconds must
	// cover it, plus the uninstall and the agent's own shutdown.
	DefaultTimeout = 20 * time.Second
)

// retryInterval is the pause between attempts to read the DaemonSet.
var retryInterval = time.Second

// Config is the hook's.
type Config struct {
	// Namespace and DaemonSet name the agent's own DaemonSet.
	Namespace string
	DaemonSet string
	// Timeout is the budget for reading the DaemonSet; DefaultTimeout when
	// zero.
	Timeout time.Duration
	// Install is the installer's configuration the uninstall runs with:
	// the node's CNI bin and conf directories, as mounted.
	Install install.Config
	Logger  *slog.Logger
}

func (c Config) log() *slog.Logger {
	if c.Logger == nil {
		return slog.Default()
	}
	return c.Logger
}

// Decision is whether the termination retires the plugin, and why.
type Decision struct {
	Retire bool
	Reason string
}

// Run decides and, when the decision is to retire, uninstalls. Deciding
// not to retire is not an error.
func Run(ctx context.Context, client kubernetes.Interface, cfg Config) error {
	log := cfg.log()
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	d := Decide(ctx, client, cfg.Namespace, cfg.DaemonSet, log)
	if !d.Retire {
		log.Info("leaving the cracha-cni plugin in place", "reason", d.Reason)
		return nil
	}
	log.Info("retiring the cracha-cni plugin from the node", "reason", d.Reason)
	cfg.Install.Logger = log
	if err := install.Uninstall(cfg.Install); err != nil {
		return fmt.Errorf("retiring the plugin: %w", err)
	}
	return nil
}

// errUnauthorized is a 401 from the apiserver: the pod's token is no longer
// accepted.
var errUnauthorized = errors.New("the apiserver no longer accepts the pod's token")

// Decide reads the DaemonSet, retrying until ctx ends, and says whether
// the plugin is to be retired. It never retires on an answer it did not
// get, except a 401 that lasted the whole budget.
func Decide(ctx context.Context, client kubernetes.Interface, namespace, name string, log *slog.Logger) Decision {
	for {
		d, err := decideOnce(ctx, client, namespace, name)
		if err == nil {
			return d
		}
		log.Warn("reading the agent's DaemonSet failed; retrying", "daemonset", namespace+"/"+name, "error", err)
		select {
		case <-ctx.Done():
			if errors.Is(err, errUnauthorized) {
				return Decision{Retire: true, Reason: "the pod's identity is no longer accepted by the apiserver: the release's ServiceAccount is gone, so the agent is not coming back under it"}
			}
			return Decision{Reason: fmt.Sprintf("the DaemonSet %s/%s could not be read within the budget (%v); nothing says the agent is not coming back", namespace, name, err)}
		case <-time.After(retryInterval):
		}
	}
}

// decideOnce is one attempt. The error is nil whenever the apiserver gave
// an answer the decision can be made on.
func decideOnce(ctx context.Context, client kubernetes.Interface, namespace, name string) (Decision, error) {
	ds, err := client.AppsV1().DaemonSets(namespace).Get(ctx, name, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		return Decision{Retire: true, Reason: fmt.Sprintf("the DaemonSet %s/%s is gone: the release is being uninstalled", namespace, name)}, nil
	case apierrors.IsUnauthorized(err):
		return Decision{}, fmt.Errorf("%w: %v", errUnauthorized, err)
	case err != nil:
		return Decision{}, err
	case ds.DeletionTimestamp != nil:
		return Decision{Retire: true, Reason: fmt.Sprintf("the DaemonSet %s/%s is being deleted: the release is being uninstalled", namespace, name)}, nil
	}
	mode, ok := ds.Spec.Template.Annotations[AnnotationEnrol]
	switch {
	case !ok:
		return Decision{Reason: fmt.Sprintf("the pod template of %s/%s does not carry %s, so nothing says the mode changed", namespace, name, AnnotationEnrol)}, nil
	case mode == ModeCNI:
		return Decision{Reason: fmt.Sprintf("the pod template of %s/%s still selects the %s mode: a restart, a rollout or an eviction", namespace, name, ModeCNI)}, nil
	}
	return Decision{Retire: true, Reason: fmt.Sprintf("the pod template of %s/%s now selects the %s mode", namespace, name, mode)}, nil
}
