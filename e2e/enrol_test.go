package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// The node agent as the chart deploys it (docs/design.md, section 7): one
// DaemonSet, whose pod's one container logs JSON; the enrolment init
// container it injects in init mode; and what it logs about a listener and
// a request (agent/internal/listener, recovery, credentials, enrol).
const (
	agentSelector  = "app.kubernetes.io/name=cracha,app.kubernetes.io/component=agent"
	agentContainer = "agent"
	agentDaemonSet = "cracha-agent"
	enrolContainer = "cracha-enrol"

	msgListenerBound  = "listener bound"
	msgListenerClosed = "listener closed"
	msgPodsListed     = "recovery: the node's enrolled pods are listed"
	msgRequest        = "request"
	msgEnrolRetrying  = "enrolment attempt failed; retrying"

	// holdLabel is the node label the agent's DaemonSet is pointed at to
	// hold the agent off the node: no node carries it.
	holdLabel = "e2e.cracha.dev/agent-held"

	// enrolBudget is how long from a pod's creation the enrolment init
	// container may take to exit in init mode (design 7.2): the container
	// is sized not to be CFS-throttled (the chart's agent.enrolResources),
	// and at 10m CPU it took close to 30 s.
	enrolBudget = 5 * time.Second
	// restartBudget is how long after the restarted agent is ready a pod's
	// fetches must be answered again (design 7.4: the restart is hitless
	// for an SDK that retries a refused connection).
	restartBudget = 30 * time.Second
	// holdFor is how long a pod created while the agent is away is watched
	// to make sure it does not start without it (design 7.2, fail closed).
	holdFor = 15 * time.Second
)

// agentLine is a line of the agent's JSON log, with the fields the tests
// here read.
type agentLine struct {
	Time     time.Time `json:"time"`
	Msg      string    `json:"msg"`
	Pod      string    `json:"pod"`
	SPIFFEID string    `json:"spiffe_id"`
	Status   int       `json:"status"`
	Path     string    `json:"path"`
	Netns    string    `json:"netns"`
	Error    string    `json:"error"`
}

// podRef is how the agent names a pod in its log (listener.Pod.String).
func podRef(pod *corev1.Pod) string {
	return fmt.Sprintf("%s/%s (uid %s)", pod.Namespace, pod.Name, pod.UID)
}

// agentPods lists the agent's pods; the kind cluster has one node, so one.
func agentPods(ctx context.Context) ([]corev1.Pod, error) {
	list, err := client.CoreV1().Pods(systemNamespace).List(ctx, metav1.ListOptions{LabelSelector: agentSelector})
	if err != nil {
		return nil, fmt.Errorf("listing the agent's pods: %w", err)
	}
	return list.Items, nil
}

// agentLogs returns every JSON line of every agent pod's log, in order.
func agentLogs(ctx context.Context) ([]agentLine, error) {
	pods, err := agentPods(ctx)
	if err != nil {
		return nil, err
	}
	var out []agentLine
	for _, p := range pods {
		logs, err := podLogs(ctx, systemNamespace, p.Name, agentContainer)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(logs, "\n") {
			var l agentLine
			if strings.HasPrefix(line, "{") && json.Unmarshal([]byte(line), &l) == nil && l.Msg != "" {
				out = append(out, l)
			}
		}
	}
	return out, nil
}

// waitForAgentLine polls the agent's log for the first line satisfying
// want, describing it as what.
func waitForAgentLine(ctx context.Context, t *testing.T, what string, want func(agentLine) bool) agentLine {
	t.Helper()
	var found agentLine
	err := eventually(ctx, func() error {
		lines, err := agentLogs(ctx)
		if err != nil {
			return err
		}
		for _, l := range lines {
			if want(l) {
				found = l
				return nil
			}
		}
		return fmt.Errorf("the agent has not logged %s yet (%d lines)", what, len(lines))
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// agentImage is the image the agent runs, from its DaemonSet: the one the
// webhook must use for the enrolment init container.
func agentImage(ctx context.Context, t *testing.T) string {
	t.Helper()
	ds, err := client.AppsV1().DaemonSets(systemNamespace).Get(ctx, agentDaemonSet, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("reading the agent's DaemonSet: %v", err)
	}
	for _, c := range ds.Spec.Template.Spec.Containers {
		if c.Name == agentContainer {
			return c.Image
		}
	}
	t.Fatalf("the agent's DaemonSet has no %q container: %+v", agentContainer, ds.Spec.Template.Spec.Containers)
	return ""
}

// patchAgent applies a strategic merge patch to the agent's DaemonSet.
func patchAgent(ctx context.Context, patch string) error {
	_, err := client.AppsV1().DaemonSets(systemNamespace).Patch(ctx, agentDaemonSet, types.StrategicMergePatchType, []byte(patch), metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("patching the agent's DaemonSet: %w", err)
	}
	return nil
}

// waitForAgentRollout waits until the DaemonSet has rolled its current
// template out and every pod of it is ready, and returns when that was
// first observed.
func waitForAgentRollout(ctx context.Context, t *testing.T) time.Time {
	t.Helper()
	err := eventually(ctx, func() error {
		ds, err := client.AppsV1().DaemonSets(systemNamespace).Get(ctx, agentDaemonSet, metav1.GetOptions{})
		if err != nil {
			return err
		}
		return rolledOut(ds)
	})
	if err != nil {
		t.Fatalf("the agent's DaemonSet did not roll out: %v", err)
	}
	return time.Now()
}

// rolledOut is nil when the DaemonSet's status says its template is on
// every node it wants and ready there (what kubectl rollout status waits
// for).
func rolledOut(ds *appsv1.DaemonSet) error {
	s := ds.Status
	switch {
	case s.ObservedGeneration < ds.Generation:
		return fmt.Errorf("generation %d not observed yet (%d)", ds.Generation, s.ObservedGeneration)
	case s.DesiredNumberScheduled == 0:
		return fmt.Errorf("no node wants the agent")
	case s.UpdatedNumberScheduled < s.DesiredNumberScheduled:
		return fmt.Errorf("%d of %d pods updated", s.UpdatedNumberScheduled, s.DesiredNumberScheduled)
	case s.NumberReady < s.DesiredNumberScheduled || s.NumberUnavailable > 0:
		return fmt.Errorf("%d of %d pods ready, %d unavailable", s.NumberReady, s.DesiredNumberScheduled, s.NumberUnavailable)
	}
	return nil
}

// holdAgent keeps the agent off the node for the rest of the test: its
// DaemonSet is pointed at a node label nothing carries, which removes its
// pod, and put back the way it was when the test ends, or earlier through
// the returned function.
func holdAgent(ctx context.Context, t *testing.T) (release func()) {
	t.Helper()
	patch := fmt.Sprintf(`{"spec":{"template":{"spec":{"nodeSelector":{%q:"true"}}}}}`, holdLabel)
	if err := patchAgent(ctx, patch); err != nil {
		t.Fatal(err)
	}
	released := false
	release = func() {
		if released {
			return
		}
		released = true
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		if err := patchAgent(ctx, `{"spec":{"template":{"spec":{"nodeSelector":null}}}}`); err != nil {
			t.Fatal(err)
		}
		waitForAgentRollout(ctx, t)
	}
	t.Cleanup(release)
	err := eventually(ctx, func() error {
		pods, err := agentPods(ctx)
		if err != nil {
			return err
		}
		if len(pods) > 0 {
			return fmt.Errorf("%d agent pods still there", len(pods))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("the agent did not leave the node: %v", err)
	}
	return release
}

// Enrolment completes before the app containers start (design 7.2,
// "Ordering"): the SDK's first request, with the provider's retries off,
// is answered, so the listener was there at first use. In init mode the
// init container also exits within enrolBudget of the pod's creation.
func TestFirstFetchNeedsNoRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	pod, rep := assignedWorkload(ctx, t)
	if rep.Error != "" {
		t.Fatalf("the SDK's first request failed: %s (exchange: %+v)", rep.Error, rep.Exchange)
	}
	if rep.Attempts != 1 {
		t.Errorf("the first credentials took %d requests, want 1", rep.Attempts)
	}
	if rep.Exchange == nil || rep.Exchange.Status != 200 {
		t.Errorf("the first request was answered %+v, want 200", rep.Exchange)
	}
	if enrolMode() == enrolInit {
		// And it was quick about it: the init container exited within the
		// budget of the pod's creation, so its resources did not throttle it.
		current, err := client.CoreV1().Pods(testNamespace).Get(ctx, pod.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		took, err := enrolDuration(current)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s exited %s after the pod was created", enrolContainer, took)
		if took > enrolBudget {
			t.Errorf("%s took %s from the pod's creation to its exit, want under %s: its resources throttle it", enrolContainer, took, enrolBudget)
		}
	}
}

// enrolDuration is how long after the pod's creation its enrolment init
// container exited, from the pod's status.
func enrolDuration(pod *corev1.Pod) (time.Duration, error) {
	for _, s := range pod.Status.InitContainerStatuses {
		if s.Name != enrolContainer {
			continue
		}
		if s.State.Terminated == nil {
			return 0, fmt.Errorf("%s has not terminated: %+v", enrolContainer, s.State)
		}
		return s.State.Terminated.FinishedAt.Sub(pod.CreationTimestamp.Time), nil
	}
	return 0, fmt.Errorf("the pod has no %s init container status: %+v", enrolContainer, pod.Status.InitContainerStatuses)
}

// grantsLine is what e2e/client prints about GET /v1/grants.
type grantsLine = fetchLine

// The inspection endpoint of design 6.5 goes through the same listener
// (design 7.1): the workload sees its own shape, grants and policy, from
// the bundle run.sh published.
func TestGrantsThroughLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	pod, _ := assignedWorkload(ctx, t)
	var line *grantsLine
	err := eventually(ctx, func() error {
		logs, err := podLogs(ctx, testNamespace, pod.Name, "client")
		if err != nil {
			return err
		}
		lines, err := jsonLines[grantsLine](logs, "grants")
		if err != nil {
			return err
		}
		if len(lines) == 0 {
			return fmt.Errorf("no grants line in the client's log yet")
		}
		line = &lines[0]
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if line.Error != "" || line.Exchange == nil {
		t.Fatalf("GET /v1/grants failed: %s", line.Error)
	}
	ex := line.Exchange
	if want := strings.TrimSuffix(credentialsURI, "/v1/credentials") + "/v1/grants"; ex.URL != want {
		t.Errorf("the client called %s, want %s", ex.URL, want)
	}
	if ex.Status != 200 {
		t.Fatalf("the listener answered %d: %s", ex.Status, ex.Body)
	}
	var body struct {
		SPIFFEID       string   `json:"spiffeId"`
		SourceIdentity string   `json:"sourceIdentity"`
		Shape          string   `json:"shape"`
		BaseRole       string   `json:"baseRole"`
		Grants         []string `json:"grants"`
		BundleVersion  string   `json:"bundleVersion"`
	}
	if err := json.Unmarshal([]byte(ex.Body), &body); err != nil {
		t.Fatalf("body is not the grants document: %v: %s", err, ex.Body)
	}
	bundleVersion, err := publishedBundleVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := struct{ spiffeID, sourceIdentity, shape, baseRole, grants, bundleVersion string }{
		fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", trustDomain, testNamespace, assignedSA),
		sourceIdentity, shapeName, baseRole, grantName, bundleVersion,
	}
	got := struct{ spiffeID, sourceIdentity, shape, baseRole, grants, bundleVersion string }{
		body.SPIFFEID, body.SourceIdentity, body.Shape, body.BaseRole, strings.Join(body.Grants, ","), body.BundleVersion,
	}
	if got != want {
		t.Errorf("grants = %+v, want %+v: %s", got, want, ex.Body)
	}
	if h := strings.Join(ex.Headers["Cracha-Shape"], ","); h != shapeName {
		t.Errorf("Cracha-Shape = %q, want %q", h, shapeName)
	}
}

// A pod the webhook did not wire has no listener: nothing answers on the
// loopback port in its network namespace (design 7.2: a pod without the
// label is enrolled by nobody).
func TestUnwiredPodHasNoListener(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	pod := sleeper("unwired", "default")
	pod.Spec.Containers[0].Command = []string{"sh", "-c", fmt.Sprintf(
		`if out="$(wget -T 2 -O - %s 2>&1)"; then echo "listener=open: $out"; else echo "listener=closed: $out"; fi`, credentialsURI)}
	created := mustCreatePod(ctx, t, pod)
	for _, c := range created.Spec.Containers {
		if len(c.Env) != 0 {
			t.Errorf("container %q got env %v, want none", c.Name, c.Env)
		}
	}
	if _, err := waitForPodPhase(ctx, created.Name, corev1.PodSucceeded, corev1.PodFailed); err != nil {
		t.Fatal(err)
	}
	logs, err := podLogs(ctx, testNamespace, created.Name, "main")
	if err != nil {
		t.Fatal(err)
	}
	logs = strings.TrimSpace(logs)
	if !strings.HasPrefix(logs, "listener=closed:") || !strings.Contains(logs, "Connection refused") {
		t.Errorf("connecting to %s from an unwired pod: %q, want a refused connection", credentialsURI, logs)
	}
}

// The listener goes with the pod (design 7.1, 7.2): once the pod is deleted
// the agent closes it and says so.
func TestDeletedPodListenerCloses(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	pod, rep := runWorkload(ctx, t, "closing", assignedSA)
	if rep.Error != "" {
		t.Fatalf("the workload got no credentials to begin with: %s", rep.Error)
	}
	ref := podRef(pod)
	waitForAgentLine(ctx, t, "the listener bound for "+ref, func(l agentLine) bool {
		return l.Msg == msgListenerBound && l.Pod == ref
	})
	grace := int64(0)
	if err := client.CoreV1().Pods(testNamespace).Delete(ctx, pod.Name, metav1.DeleteOptions{GracePeriodSeconds: &grace}); err != nil {
		t.Fatalf("deleting pod %s: %v", pod.Name, err)
	}
	closed := waitForAgentLine(ctx, t, "the listener closed for "+ref, func(l agentLine) bool {
		return l.Msg == msgListenerClosed && l.Pod == ref
	})
	t.Logf("agent: %s (netns %s)", closed.Msg, closed.Netns)
}

// deletePodWhenDone removes the pod at the end of the test and waits for
// it to be gone: a pod that keeps fetching would share the broker's cache
// entry with the later tests' pods of the same identity and take their
// misses.
func deletePodWhenDone(t *testing.T, name string) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		pods := client.CoreV1().Pods(testNamespace)
		grace := int64(0)
		if err := pods.Delete(ctx, name, metav1.DeleteOptions{GracePeriodSeconds: &grace}); err != nil {
			t.Logf("deleting pod %s: %v", name, err)
			return
		}
		err := eventually(ctx, func() error {
			if _, err := pods.Get(ctx, name, metav1.GetOptions{}); err == nil {
				return fmt.Errorf("pod %s still terminating", name)
			}
			return nil
		})
		if err != nil {
			t.Logf("waiting for pod %s to go: %v", name, err)
		}
	})
}

// An agent restart is hitless (design 7.4): a pod fetching every two
// seconds is refused while the agent is away, and answered again within
// restartBudget of the new agent being ready, after it re-bound the pod's
// listener from the API and the runtime, with no change to the pod.
func TestAgentRestartIsHitless(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	pod := runFetchingWorkload(ctx, t, "restarted")
	deletePodWhenDone(t, pod.Name)
	ref := podRef(pod)

	restartedAt := time.Now()
	patch := fmt.Sprintf(`{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":%q}}}}}`, restartedAt.UTC().Format(time.RFC3339))
	if err := patchAgent(ctx, patch); err != nil {
		t.Fatal(err)
	}
	readyAt := waitForAgentRollout(ctx, t)
	t.Logf("the agent rolled out %s after the restart", readyAt.Sub(restartedAt).Round(time.Millisecond))

	// The new agent listed the node's pods and bound this one's listener
	// again, from the API and the runtime.
	waitForAgentLine(ctx, t, "the node's pods listed after the restart", func(l agentLine) bool {
		return l.Msg == msgPodsListed && l.Time.After(restartedAt)
	})
	bound := waitForAgentLine(ctx, t, "the listener re-bound for "+ref, func(l agentLine) bool {
		return l.Msg == msgListenerBound && l.Pod == ref && l.Time.After(restartedAt)
	})
	t.Logf("agent: %s %s after the restart (netns %s)", bound.Msg, bound.Time.Sub(restartedAt).Round(time.Millisecond), bound.Netns)

	// Fetches during the restart may fail; one after the new agent is ready
	// must succeed within the budget.
	budget, cancelBudget := context.WithDeadline(ctx, readyAt.Add(restartBudget))
	defer cancelBudget()
	back := waitForFetch(budget, t, pod, readyAt, "credentials after the restart", status(200))
	t.Logf("credentials again %s after the restarted agent was ready", back.At.Sub(readyAt).Round(time.Millisecond))

	logs, err := podLogs(ctx, testNamespace, pod.Name, "client")
	if err != nil {
		t.Fatal(err)
	}
	lines, err := jsonLines[fetchLine](logs, "fetch")
	if err != nil {
		t.Fatal(err)
	}
	failed := 0
	for _, l := range lines {
		if l.At.After(restartedAt) && l.At.Before(back.At) && (l.Error != "" || l.Exchange.Status != 200) {
			failed++
		}
	}
	t.Logf("%d fetches failed between the restart and the first answer after it", failed)
	if current, err := client.CoreV1().Pods(testNamespace).Get(ctx, pod.Name, metav1.GetOptions{}); err != nil {
		t.Fatal(err)
	} else if current.UID != pod.UID || current.Status.Phase != corev1.PodRunning {
		t.Errorf("the pod is %s (uid %s), want the same pod still running", current.Status.Phase, current.UID)
	}
}

// Both modes fail closed (design 7.2): a pod created while the agent is
// away waits for it rather than starting without credentials, and starts
// once the agent is back, with its first request answered.
func TestPodCreatedWhileAgentDownWaits(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	release := holdAgent(ctx, t)

	pod := mustCreatePod(ctx, t, workloadPod("waiting", assignedSA))
	if enrolMode() == enrolInit {
		// The init container is up, calling an agent that is not there.
		err := eventually(ctx, func() error {
			logs, err := podLogs(ctx, testNamespace, pod.Name, enrolContainer)
			if err != nil {
				return err
			}
			if !strings.Contains(logs, msgEnrolRetrying) {
				return fmt.Errorf("%s has not retried yet: %q", enrolContainer, tail(logs, 3))
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// And the pod stays that way: no app container runs without the agent.
	held := time.After(holdFor)
	for waiting := true; waiting; {
		select {
		case <-held:
			waiting = false
		case <-time.After(pollInterval):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		current, err := client.CoreV1().Pods(testNamespace).Get(ctx, pod.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if current.Status.Phase != corev1.PodPending {
			t.Fatalf("the pod is %s with the agent away, want Pending: %s", current.Status.Phase, podState(current))
		}
		for _, s := range current.Status.ContainerStatuses {
			if s.State.Running != nil || s.State.Terminated != nil {
				t.Fatalf("container %q ran with the agent away: %+v", s.Name, s.State)
			}
		}
	}
	t.Logf("the pod waited %s for the agent", holdFor)

	release()
	if _, err := waitForPodPhase(ctx, pod.Name, corev1.PodRunning); err != nil {
		t.Fatal(err)
	}
	var rep *report
	err := eventually(ctx, func() error {
		logs, err := podLogs(ctx, testNamespace, pod.Name, "client")
		if err != nil {
			return err
		}
		reports, err := jsonLines[report](logs, "report")
		if err != nil {
			return err
		}
		if len(reports) == 0 {
			return fmt.Errorf("no report in the client's log yet")
		}
		rep = &reports[0]
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Error != "" || rep.Exchange == nil || rep.Exchange.Status != 200 || rep.Attempts != 1 {
		t.Errorf("after the agent came back the first request got %+v (error %q, %d attempts), want 200 in one", rep.Exchange, rep.Error, rep.Attempts)
	}
}

// Every request is logged with the pod, the token's SPIFFE ID and the
// broker's status (design 7.3), and the broker logs the agent's identity,
// the only client it admits, beside the token's subject (design 6.5). A
// pod of this test's own, since the agent's log is the current agent pod's
// and the tests above restarted it.
func TestRequestIsLoggedWithIdentities(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	pod, rep := runWorkload(ctx, t, "identified", assignedSA)
	if rep.Error != "" {
		t.Fatalf("the workload got no credentials: %s", rep.Error)
	}
	ref := podRef(pod)
	spiffeID := fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", trustDomain, testNamespace, assignedSA)
	agentID := fmt.Sprintf("spiffe://%s/ns/%s/sa/cracha-agent", trustDomain, systemNamespace)

	line := waitForAgentLine(ctx, t, "the request of "+ref, func(l agentLine) bool {
		return l.Msg == msgRequest && l.Pod == ref && l.Path == "/v1/credentials"
	})
	if line.SPIFFEID != spiffeID || line.Status != 200 {
		t.Errorf("agent logged spiffe_id %q status %d, want %q 200", line.SPIFFEID, line.Status, spiffeID)
	}

	err := eventually(ctx, func() error {
		lines, err := brokerLogs(ctx)
		if err != nil {
			return err
		}
		for _, l := range lines {
			if l.Msg == msgRequest && l.Path == "/v1/credentials" && l.Subject == spiffeID && l.Status == 200 {
				if l.Client != agentID {
					return fmt.Errorf("the broker logged client %q, want the agent's %q", l.Client, agentID)
				}
				return nil
			}
		}
		return fmt.Errorf("the broker has not logged a request for %s yet", spiffeID)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Switching the release's enrolment mode (design 7.2, retirement): the helm
// run.sh installed the chart with and the package it installed, handed
// over as E2E_HELM and E2E_CHART_PACKAGE (forwarded by .bazelrc's
// test:e2e), the release name, and the node's CNI directories as the
// chart's defaults have them, which e2e/values.yaml leaves alone.
const (
	helmEnv         = "E2E_HELM"
	chartPackageEnv = "E2E_CHART_PACKAGE"
	releaseName     = "cracha"
	cniPluginType   = "cracha-cni"
	cniBinDir       = "/opt/cni/bin"
	cniConfDir      = "/etc/cni/net.d"
)

// helmUpgrade switches the release to the given enrolment mode, keeping
// every other value run.sh installed it with, and waits for the rollout.
func helmUpgrade(ctx context.Context, t *testing.T, mode string) {
	t.Helper()
	helm, chart := os.Getenv(helmEnv), os.Getenv(chartPackageEnv)
	if helm == "" || chart == "" {
		t.Skipf("%s and %s are not set: this test switches the release's mode with helm; run it through e2e/run.sh", helmEnv, chartPackageEnv)
	}
	started := time.Now()
	cmd := exec.CommandContext(ctx, helm, "upgrade", releaseName, chart,
		"--namespace", systemNamespace, "--reuse-values", "--set", "agent.enrol="+mode,
		"--wait", "--timeout", "300s")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helm upgrade to %s mode: %v\n%s", mode, err, out)
	}
	t.Logf("the release switched to %s mode in %s", mode, time.Since(started).Round(time.Millisecond))
}

// nodeCNI reads the node's CNI configuration through a pod that mounts the
// node's two CNI directories (the suite has no shell on the node): the
// conflists of the conf directory concatenated, and whether the plugin
// binary is in the bin directory.
func nodeCNI(ctx context.Context, t *testing.T, probe string) (conflists string, binary bool) {
	t.Helper()
	pod := sleeper(probe, "default")
	pod.Spec.Containers[0].Command = []string{
		"sh", "-c",
		"cat /host/net.d/*.conflist; echo; if [ -x /host/bin/" + cniPluginType + " ]; then echo BINARY=present; else echo BINARY=absent; fi",
	}
	pod.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{
		{Name: "bin", MountPath: "/host/bin", ReadOnly: true},
		{Name: "net-d", MountPath: "/host/net.d", ReadOnly: true},
	}
	pod.Spec.Volumes = []corev1.Volume{
		{Name: "bin", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: cniBinDir}}},
		{Name: "net-d", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: cniConfDir}}},
	}
	created := createPodAfterRollout(ctx, t, pod)
	deletePodWhenDone(t, created.Name)
	if _, err := waitForPodPhase(ctx, created.Name, corev1.PodSucceeded, corev1.PodFailed); err != nil {
		t.Fatal(err)
	}
	logs, err := podLogs(ctx, testNamespace, created.Name, "main")
	if err != nil {
		t.Fatal(err)
	}
	return logs, strings.Contains(logs, "BINARY=present")
}

// createPodAfterRollout is mustCreatePod for the first pod after the
// webhook rolled out: the apiserver's first call to the webhook can then
// hang on a connection to the pod that went until its own timeout, which
// it reports as an internal error on the create, failing closed. That is
// the rollout's, not the switch's, so such a create is retried for a
// while; any other failure is final.
func createPodAfterRollout(ctx context.Context, t *testing.T, pod *corev1.Pod) *corev1.Pod {
	t.Helper()
	budget, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	var created *corev1.Pod
	err := eventually(budget, func() error {
		var err error
		created, err = createPod(ctx, pod)
		if err != nil && apierrors.IsInternalError(err) && strings.Contains(err.Error(), "failed calling webhook") {
			t.Logf("creating pod %s right after the webhook rolled out: %v; retrying", pod.Name, err)
			return err
		}
		if err != nil {
			t.Fatalf("creating pod %s: %v", pod.Name, err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("creating pod %s after the webhook rolled out: %v", pod.Name, err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			dumpDiagnostics(t, created.Name)
		}
	})
	return created
}

// pluginOnNode asserts the node's CNI configuration has, or has not, the
// plugin chained and its binary installed.
func pluginOnNode(ctx context.Context, t *testing.T, probe string, want bool) {
	t.Helper()
	conflists, binary := nodeCNI(ctx, t, probe)
	chained := strings.Contains(conflists, cniPluginType)
	if chained != want || binary != want {
		t.Fatalf("%s: the plugin is chained %t and its binary present %t, want %t both:\n%s", probe, chained, binary, want, conflists)
	}
	t.Logf("%s: the plugin is chained %t and its binary present %t", probe, chained, binary)
}

// Leaving cni mode retires the plugin (design 7.2): switched to init mode
// with helm upgrade, the release's old agent takes the entry out of the
// node's conflist and the binary off the node in its preStop hook, and a
// pod created then is wired the init way and fetches; switched back, the
// installer chains the plugin again and a cni-mode pod fetches. On a
// node that kept the plugin, every sandbox would fail with no agent on
// the socket, so the pods of each half are the proof.
func TestLeavingCNIModeRetiresPlugin(t *testing.T) {
	requireEnrol(t, enrolCNI)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	pluginOnNode(ctx, t, "cni-probe-before", true)

	// Whatever happens, the release ends in the mode the suite runs in.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
		defer cancel()
		helmUpgrade(ctx, t, enrolCNI)
		waitForAgentRollout(ctx, t)
	})

	helmUpgrade(ctx, t, enrolInit)
	waitForAgentRollout(ctx, t)
	pluginOnNode(ctx, t, "cni-probe-init", false)
	pod, rep := runWorkload(ctx, t, "switched-to-init", assignedSA)
	deletePodWhenDone(t, pod.Name)
	if rep.Error != "" || rep.Exchange == nil || rep.Exchange.Status != 200 {
		t.Errorf("in init mode after the switch the first request got %+v (error %q), want 200", rep.Exchange, rep.Error)
	}
	if len(pod.Spec.InitContainers) == 0 || pod.Spec.InitContainers[0].Name != enrolContainer {
		t.Errorf("the pod created in init mode has init containers %+v, want %s first", pod.Spec.InitContainers, enrolContainer)
	}

	helmUpgrade(ctx, t, enrolCNI)
	waitForAgentRollout(ctx, t)
	pluginOnNode(ctx, t, "cni-probe-cni", true)
	pod, rep = runWorkload(ctx, t, "switched-to-cni", assignedSA)
	deletePodWhenDone(t, pod.Name)
	if rep.Error != "" || rep.Exchange == nil || rep.Exchange.Status != 200 {
		t.Errorf("in cni mode after the switch back the first request got %+v (error %q), want 200", rep.Exchange, rep.Error)
	}
	for _, c := range pod.Spec.InitContainers {
		if c.Name == enrolContainer {
			t.Errorf("the pod created in cni mode was given %s", enrolContainer)
		}
	}
}
