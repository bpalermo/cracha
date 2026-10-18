package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// The broker as the chart deploys it, which the prewarm test restarts to
// empty its cache, and the agent's prewarm flag (agent.prewarm).
const (
	brokerDeployment = "cracha-broker"
	prewarmOff       = "--prewarm=false"
	prewarmFlag      = "--prewarm="
)

// Prewarm (design 7.2, 7.3): when the agent binds a new pod's listener it
// runs the pod's first request in the background, so the broker's cache
// holds the pod's session when the app asks and the app's first request,
// on a broker whose cache was empty, is a hit. Turned off, the same first
// request is the miss that calls STS. The broker is restarted before each
// half, so its cache holds nothing of the workload but what the pod itself
// brings (no other pod of the suite fetches meanwhile).
func TestPrewarmMakesTheFirstRequestACacheHit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	requirePrewarm(ctx, t)

	t.Run("on", func(t *testing.T) {
		restartBroker(ctx, t)
		since := time.Now()
		pod, rep := runWorkload(ctx, t, "prewarmed", assignedSA)
		deletePodWhenDone(t, pod.Name)
		ref := podRef(pod)
		warm := waitForAgentLine(ctx, t, "the prewarm of "+ref, func(l agentLine) bool {
			return (l.Msg == msgPrewarm || l.Msg == msgPrewarmFailed) && l.Pod == ref
		})
		if warm.Msg != msgPrewarm || warm.Status != 200 || warm.Cache != cacheOutcomeMiss {
			t.Errorf("the agent logged %q status %d cache %q (error %q), want a prewarm answered 200 from STS (%s)",
				warm.Msg, warm.Status, warm.Cache, warm.Error, cacheOutcomeMiss)
		}
		first := firstExchange(t, rep)
		if got := strings.Join(first.Headers[headerCache], ","); got != cacheOutcomeHit {
			t.Errorf("%s = %q on the app's first request, want %q: the prewarm did not warm the broker's cache", headerCache, got, cacheOutcomeHit)
		}
		t.Logf("prewarm: %s (%s); app's first credentials: %.1f ms (%s)", warm.Latency, warm.Cache, rep.LatencyMillis,
			strings.Join(first.Headers[headerCache], ","))
		logBrokerDurations(ctx, t, since)
	})

	t.Run("off", func(t *testing.T) {
		setPrewarm(ctx, t, false)
		restartBroker(ctx, t)
		since := time.Now()
		pod, rep := runWorkload(ctx, t, "cold", assignedSA)
		deletePodWhenDone(t, pod.Name)
		first := firstExchange(t, rep)
		if got := strings.Join(first.Headers[headerCache], ","); got != cacheOutcomeMiss {
			t.Errorf("%s = %q on the app's first request with prewarm off, want %q", headerCache, got, cacheOutcomeMiss)
		}
		lines, err := agentLogs(ctx)
		if err != nil {
			t.Fatal(err)
		}
		ref := podRef(pod)
		for _, l := range lines {
			if (l.Msg == msgPrewarm || l.Msg == msgPrewarmFailed) && l.Pod == ref {
				t.Errorf("the agent prewarmed %s with prewarm off: %+v", ref, l)
			}
		}
		t.Logf("app's first credentials without prewarm: %.1f ms (%s)", rep.LatencyMillis, strings.Join(first.Headers[headerCache], ","))
		logBrokerDurations(ctx, t, since)
	})
}

// requirePrewarm skips the test against an agent that has no prewarm (a
// published chart older than it).
func requirePrewarm(ctx context.Context, t *testing.T) {
	t.Helper()
	if !slices.ContainsFunc(agentArgs(ctx, t), func(a string) bool { return strings.HasPrefix(a, prewarmFlag) }) {
		t.Skipf("the agent's DaemonSet passes no %s: this chart predates prewarm", prewarmFlag)
	}
}

// agentArgs are the agent container's arguments in its DaemonSet.
func agentArgs(ctx context.Context, t *testing.T) []string {
	t.Helper()
	ds, err := client.AppsV1().DaemonSets(systemNamespace).Get(ctx, agentDaemonSet, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range ds.Spec.Template.Spec.Containers {
		if c.Name == agentContainer {
			return c.Args
		}
	}
	t.Fatalf("the agent's DaemonSet has no %q container", agentContainer)
	return nil
}

// setPrewarm turns the agent's prewarm off (the last flag wins) and rolls
// the agent out; the arguments are put back when the test ends.
func setPrewarm(ctx context.Context, t *testing.T, on bool) {
	t.Helper()
	if on {
		t.Fatal("setPrewarm only turns prewarm off; the cleanup turns it back on")
	}
	original := agentArgs(ctx, t)
	replace := func(ctx context.Context, args []string) error {
		patch, err := json.Marshal([]map[string]any{{
			"op": "replace", "path": "/spec/template/spec/containers/0/args", "value": args,
		}})
		if err != nil {
			return err
		}
		_, err = client.AppsV1().DaemonSets(systemNamespace).Patch(ctx, agentDaemonSet, types.JSONPatchType, patch, metav1.PatchOptions{})
		return err
	}
	if err := replace(ctx, append(slices.Clone(original), prewarmOff)); err != nil {
		t.Fatalf("turning prewarm off: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		if err := replace(ctx, original); err != nil {
			t.Fatalf("turning prewarm back on: %v", err)
		}
		waitForAgentRollout(ctx, t)
	})
	waitForAgentRollout(ctx, t)
}

// restartBroker restarts the broker, which empties its credential cache
// (design 6.7: in memory only), and waits until the one pod left is a new
// one and ready.
func restartBroker(ctx context.Context, t *testing.T) {
	t.Helper()
	pods := func() ([]corev1.Pod, error) {
		list, err := client.CoreV1().Pods(systemNamespace).List(ctx, metav1.ListOptions{LabelSelector: brokerSelector})
		if err != nil {
			return nil, err
		}
		return list.Items, nil
	}
	before, err := pods()
	if err != nil {
		t.Fatal(err)
	}
	old := map[types.UID]bool{}
	for _, p := range before {
		old[p.UID] = true
	}
	restartedAt := time.Now()
	patch := fmt.Sprintf(`{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":%q}}}}}`, restartedAt.UTC().Format(time.RFC3339Nano))
	if _, err := client.AppsV1().Deployments(systemNamespace).Patch(ctx, brokerDeployment, types.StrategicMergePatchType, []byte(patch), metav1.PatchOptions{}); err != nil {
		t.Fatalf("restarting the broker: %v", err)
	}
	err = eventually(ctx, func() error {
		current, err := pods()
		if err != nil {
			return err
		}
		if len(current) != 1 {
			return fmt.Errorf("%d broker pods, want the new one alone", len(current))
		}
		p := current[0]
		if old[p.UID] {
			return fmt.Errorf("broker pod %s is the old one", p.Name)
		}
		for _, c := range p.Status.Conditions {
			if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
				return nil
			}
		}
		return fmt.Errorf("broker pod %s is not ready: %s", p.Name, podState(&p))
	})
	if err != nil {
		t.Fatalf("the broker did not come back: %v", err)
	}
	t.Logf("the broker restarted in %s", time.Since(restartedAt).Round(time.Millisecond))
}

// firstExchange is the answer to the SDK's first request, which must have
// been a 200 in one attempt.
func firstExchange(t *testing.T, rep *report) *exchange {
	t.Helper()
	if rep.Error != "" || rep.Exchange == nil || rep.Exchange.Status != 200 || rep.Attempts != 1 {
		t.Fatalf("the first request got %+v (error %q, %d attempts), want 200 in one", rep.Exchange, rep.Error, rep.Attempts)
	}
	return rep.Exchange
}

// logBrokerDurations logs how long the broker took over each credentials
// request of the assigned workload since then: the cold path's cost and
// the hit's.
func logBrokerDurations(ctx context.Context, t *testing.T, since time.Time) {
	t.Helper()
	lines, err := brokerLogs(ctx)
	if err != nil {
		t.Logf("reading the broker's log: %v", err)
		return
	}
	spiffeID := fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", trustDomain, testNamespace, assignedSA)
	var durations []string
	for _, l := range lines {
		if l.Msg == msgRequest && l.Path == "/v1/credentials" && l.Subject == spiffeID && l.Time.After(since) {
			durations = append(durations, l.Duration.String())
		}
	}
	t.Logf("broker: credentials requests of %s since the pod was created took %v", spiffeID, durations)
}
