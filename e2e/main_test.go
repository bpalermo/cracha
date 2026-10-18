package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// The suite runs against whatever cluster the ambient kubeconfig points at,
// through client-go. It is tagged e2e and excluded from `bazel test //...`;
// e2e/run.sh creates the kind cluster, loads the images built from this
// checkout, deploys SPIRE and Crachá (e2e/spire.sh, then the chart with
// e2e/values.yaml) and runs it.

const (
	// imageTag is the tag the Bazel image_load targets give locally built
	// images; e2e/run.sh loads them into the kind node under the same names.
	imageTag = "e2e"

	// systemNamespace is where e2e/run.sh installs the chart, which deploys
	// Crachá; testNamespace is where the suite runs its workloads
	// (e2e/manifests/e2e.yaml), with the ServiceAccounts below.
	systemNamespace = "cracha-system"
	testNamespace   = "e2e"
	// assignedSA holds one grant through the Service of e2e/grants;
	// readerSA that grant and the lookup grant, whose bucket an Access
	// document gives (resources_test.go); unassignedSA holds none. All are
	// registered with SPIRE and opt in to the webhook.
	assignedSA   = "client"
	readerSA     = "reader"
	unassignedSA = "unassigned"
	trustDomain  = "cracha.test"

	// suiteLabel marks the pods the suite creates, for cleanup.
	suiteLabel = "e2e.cracha.dev/suite"

	// busybox 1.37, pinned so the suite does not depend on a moving tag.
	busybox = "docker.io/library/busybox@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e"

	pollInterval = time.Second
)

// What the webhook injects (docs/design.md, section 7.5): the loopback
// endpoint of the agent's listener on agent.port of the chart's defaults,
// the region of e2e/values.yaml, and the enrolment label the agent checks.
const (
	agentPort      = 9797
	credentialsURI = "http://127.0.0.1:9797/v1/credentials"
	region         = "us-east-1"
	enrolLabel     = "cracha.dev/credentials"
)

// The enrolment mode e2e/run.sh installed the chart in (E2E_ENROL, design
// 7.2): init, the cracha-enrol init container the webhook injects, or cni,
// the cracha-cni plugin on the node. The suite runs in both; a test that
// looks at one mode's wiring skips in the other.
const (
	enrolEnv  = "E2E_ENROL"
	enrolInit = "init"
	enrolCNI  = "cni"
)

// enrolMode is the mode the suite runs in; unset means the default, init.
func enrolMode() string {
	if mode := os.Getenv(enrolEnv); mode != "" {
		return mode
	}
	return enrolInit
}

// requireEnrol skips the test outside the given mode.
func requireEnrol(t *testing.T, mode string) {
	t.Helper()
	if got := enrolMode(); got != mode {
		t.Skipf("%s=%q: this test looks at the %s enrolment mode; run E2E_ENROL=%s e2e/run.sh", enrolEnv, got, mode, mode)
	}
}

var client *kubernetes.Clientset

// image returns the name of an image built from this checkout and loaded
// into the node.
func image(name string) string {
	return fmt.Sprintf("localhost/%s:%s", name, imageTag)
}

func TestMain(m *testing.M) {
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(), nil).ClientConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e: kubeconfig: %v\nrun e2e/run.sh, which creates a cluster\n", err)
		os.Exit(1)
	}
	client, err = kubernetes.NewForConfig(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e: %v\n", err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	if _, err := client.Discovery().ServerVersion(); err != nil {
		cancel()
		fmt.Fprintf(os.Stderr, "e2e: no reachable cluster: %v\nrun e2e/run.sh, which creates one\n", err)
		os.Exit(1)
	}
	// A kept cluster still has the last run's pods; their names are reused.
	if err := deleteSuitePods(ctx, true); err != nil {
		cancel()
		fmt.Fprintf(os.Stderr, "e2e: cleaning up the previous run: %v\n", err)
		os.Exit(1)
	}
	cancel()

	code := m.Run()

	ctx, cancel = context.WithTimeout(context.Background(), time.Minute)
	if err := deleteSuitePods(ctx, false); err != nil {
		fmt.Fprintf(os.Stderr, "e2e: cleanup: %v\n", err)
	}
	cancel()
	os.Exit(code)
}

// deleteSuitePods removes every pod the suite labels, and waits for them to
// be gone when asked.
func deleteSuitePods(ctx context.Context, wait bool) error {
	pods := client.CoreV1().Pods(testNamespace)
	selector := metav1.ListOptions{LabelSelector: suiteLabel + "=true"}
	grace := int64(0)
	if err := pods.DeleteCollection(ctx, metav1.DeleteOptions{GracePeriodSeconds: &grace}, selector); err != nil {
		return err
	}
	if !wait {
		return nil
	}
	return eventually(ctx, func() error {
		list, err := pods.List(ctx, selector)
		if err != nil {
			return err
		}
		if n := len(list.Items); n > 0 {
			return fmt.Errorf("%d pods of the previous run still terminating", n)
		}
		return nil
	})
}

// eventually retries check until it passes or the context ends, and then
// returns the last failure.
func eventually(ctx context.Context, check func() error) error {
	for {
		err := check()
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w (gave up: %v)", err, ctx.Err())
		case <-time.After(pollInterval):
		}
	}
}

// createPod creates a pod in the test namespace, labelled for cleanup, and
// returns it as the apiserver persisted it: with the webhook's patch applied.
func createPod(ctx context.Context, pod *corev1.Pod) (*corev1.Pod, error) {
	return createPodIn(ctx, testNamespace, pod)
}

// createPodIn is createPod in another namespace, one the test owns.
func createPodIn(ctx context.Context, namespace string, pod *corev1.Pod) (*corev1.Pod, error) {
	if pod.Labels == nil {
		pod.Labels = map[string]string{}
	}
	pod.Labels[suiteLabel] = "true"
	return client.CoreV1().Pods(namespace).Create(ctx, pod, metav1.CreateOptions{})
}

func mustCreatePod(ctx context.Context, t *testing.T, pod *corev1.Pod) *corev1.Pod {
	t.Helper()
	created, err := createPod(ctx, pod)
	if err != nil {
		t.Fatalf("creating pod %s: %v", pod.Name, err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			dumpDiagnostics(t, created.Name)
		}
	})
	return created
}

// waitForPodPhase polls until the pod reaches one of the wanted phases.
func waitForPodPhase(ctx context.Context, name string, want ...corev1.PodPhase) (*corev1.Pod, error) {
	var last *corev1.Pod
	err := eventually(ctx, func() error {
		pod, err := client.CoreV1().Pods(testNamespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		last = pod
		for _, w := range want {
			if pod.Status.Phase == w {
				return nil
			}
		}
		return fmt.Errorf("pod %s is %s, waiting for %v: %s", name, pod.Status.Phase, want, podState(pod))
	})
	return last, err
}

// podState summarizes why a pod is where it is, for a failure message.
func podState(pod *corev1.Pod) string {
	var parts []string
	for _, c := range pod.Status.Conditions {
		if c.Status != corev1.ConditionTrue && c.Message != "" {
			parts = append(parts, fmt.Sprintf("%s=%s (%s)", c.Type, c.Status, c.Message))
		}
	}
	for _, statuses := range [][]corev1.ContainerStatus{pod.Status.InitContainerStatuses, pod.Status.ContainerStatuses} {
		for _, s := range statuses {
			switch {
			case s.State.Waiting != nil:
				parts = append(parts, fmt.Sprintf("%s waiting: %s %s", s.Name, s.State.Waiting.Reason, s.State.Waiting.Message))
			case s.State.Terminated != nil:
				parts = append(parts, fmt.Sprintf("%s terminated: %s exit %d", s.Name, s.State.Terminated.Reason, s.State.Terminated.ExitCode))
			}
		}
	}
	return strings.Join(parts, "; ")
}

// podLogs returns a container's log so far.
func podLogs(ctx context.Context, ns, name, container string) (string, error) {
	raw, err := client.CoreV1().Pods(ns).GetLogs(name, &corev1.PodLogOptions{Container: container}).DoRaw(ctx)
	if err != nil {
		return "", fmt.Errorf("logs of %s/%s: %w", ns, name, err)
	}
	return string(raw), nil
}

// jsonLines decodes every line of a log that is a JSON object with the
// given kind, in order.
func jsonLines[T any](log, kind string) ([]T, error) {
	var out []T
	for _, line := range strings.Split(log, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var probe struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal([]byte(line), &probe); err != nil || probe.Kind != kind {
			continue
		}
		var v T
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			return nil, fmt.Errorf("decoding %q: %w", line, err)
		}
		out = append(out, v)
	}
	return out, nil
}

// dumpDiagnostics logs what a failed test needs and the cluster will not
// keep: the pod, the namespace's events and the components' logs.
func dumpDiagnostics(t *testing.T, pod string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if p, err := client.CoreV1().Pods(testNamespace).Get(ctx, pod, metav1.GetOptions{}); err == nil {
		t.Logf("pod %s: phase %s, %s", pod, p.Status.Phase, podState(p))
	}
	if events, err := client.CoreV1().Events(testNamespace).List(ctx, metav1.ListOptions{
		FieldSelector: "involvedObject.name=" + pod,
	}); err == nil {
		for _, e := range events.Items {
			t.Logf("event %s %s: %s", e.Type, e.Reason, e.Message)
		}
	}
	for _, c := range []struct{ ns, selector, container string }{
		{testNamespace, suiteLabel + "=true", ""},
		{systemNamespace, agentSelector, agentContainer},
		{systemNamespace, "app.kubernetes.io/name=cracha,app.kubernetes.io/component=broker", ""},
		{systemNamespace, "app.kubernetes.io/name=cracha,app.kubernetes.io/component=webhook", ""},
		{systemNamespace, "app.kubernetes.io/name=cracha-stsstub", ""},
		{"spire", "app=spire-agent", ""},
	} {
		pods, err := client.CoreV1().Pods(c.ns).List(ctx, metav1.ListOptions{LabelSelector: c.selector})
		if err != nil {
			t.Logf("listing %s pods: %v", c.selector, err)
			continue
		}
		for _, p := range pods.Items {
			logs, err := podLogs(ctx, c.ns, p.Name, c.container)
			if err != nil {
				t.Logf("%v", err)
				continue
			}
			t.Logf("logs of %s/%s (last 60 lines):\n%s", c.ns, p.Name, tail(logs, 60))
		}
	}
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
