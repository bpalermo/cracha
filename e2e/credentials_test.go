package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// What e2e/stsstub answers and e2e/values.yaml (the chart's assignments)
// and e2e/grants (the compiled bundle) grant.
const (
	stubAccessKeyID = "ASIACRACHAE2ESTUB000"
	grantName       = "e2e-s3-reader"
	baseRole        = "arn:aws:iam::111122223333:role/broker/shape-e2e"
	shapeName       = "shape-e2e"
	// sourceIdentity is the idenc STS encoding of the client's identity:
	// w.<label>.<ns>.<sa>, with the label the broker maps cracha.test to.
	sourceIdentity = "w.cracha.e2e.client"
	// bundleConfigMap is where e2e/run.sh puts the bundle it compiled,
	// signed and published, in the chart's namespace; latestKey holds the
	// publication's latest pointer, whose version the broker must report.
	bundleConfigMap = "cracha-e2e-bundle"
	latestKey       = "latest"
)

// publishedBundleVersion reads the version of the bundle e2e/run.sh
// published, from the latest pointer in the ConfigMap the broker mounts.
func publishedBundleVersion(ctx context.Context) (string, error) {
	cm, err := client.CoreV1().ConfigMaps(systemNamespace).Get(ctx, bundleConfigMap, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("reading the published bundle: %w", err)
	}
	var latest struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal([]byte(cm.Data[latestKey]), &latest); err != nil {
		return "", fmt.Errorf("decoding the published bundle's %s pointer: %w", latestKey, err)
	}
	if latest.Version == "" {
		return "", fmt.Errorf("the published bundle's %s pointer names no version: %q", latestKey, cm.Data[latestKey])
	}
	return latest.Version, nil
}

// report is the first line e2e/client prints.
type report struct {
	Kind        string `json:"kind"`
	Credentials *struct {
		AccessKeyID     string    `json:"accessKeyId"`
		SecretAccessKey string    `json:"secretAccessKey"`
		SessionToken    string    `json:"sessionToken"`
		Source          string    `json:"source"`
		CanExpire       bool      `json:"canExpire"`
		Expires         time.Time `json:"expires"`
	} `json:"credentials"`
	Error    string    `json:"error"`
	Exchange *exchange `json:"exchange"`
	Attempts int       `json:"attempts"`
	// LatencyMillis is how long the SDK took for the first credentials.
	LatencyMillis float64 `json:"latencyMillis"`
}

// exchange is one HTTP answer of the broker as e2e/client recorded it.
type exchange struct {
	URL     string              `json:"url"`
	Status  int                 `json:"status"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
}

// reason decodes the body of a refusal (design 6.5).
func (e *exchange) reason() string {
	var body struct {
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(e.Body), &body); err != nil {
		return ""
	}
	return body.Reason
}

// stsRequest is one AssumeRole as e2e/stsstub recorded it.
type stsRequest struct {
	RoleArn           string            `json:"roleArn"`
	RoleSessionName   string            `json:"roleSessionName"`
	SourceIdentity    string            `json:"sourceIdentity"`
	Policy            string            `json:"policy"`
	PolicyArns        []string          `json:"policyArns"`
	DurationSeconds   int               `json:"durationSeconds"`
	Tags              map[string]string `json:"tags"`
	TransitiveTagKeys []string          `json:"transitiveTagKeys"`
}

// The workload's identity in its pod: a non-root user with an fsGroup of its
// own, the way a hardened pod runs. Neither matters to Crachá any more
// (nothing in the pod is read), which is the point: the enrolment the
// webhook injects in init mode runs under the restricted standard beside
// whatever the pod chose.
const (
	workloadUID     = int64(1000)
	workloadGID     = int64(1000)
	workloadFSGroup = int64(2000)
)

// workloadPod is the suite's workload (e2e/client) running as the given
// ServiceAccount. Nothing about AWS is configured, nothing is mounted and
// nothing is trusted: the environment the webhook injects is all it has
// (design 7.7).
func workloadPod(name, serviceAccount string, env ...corev1.EnvVar) *corev1.Pod {
	grace := int64(0)
	uid, gid, fsGroup := workloadUID, workloadGID, workloadFSGroup
	nonRoot := true
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: corev1.PodSpec{
			ServiceAccountName:            serviceAccount,
			RestartPolicy:                 corev1.RestartPolicyNever,
			TerminationGracePeriodSeconds: &grace,
			SecurityContext: &corev1.PodSecurityContext{
				RunAsUser: &uid, RunAsGroup: &gid, RunAsNonRoot: &nonRoot, FSGroup: &fsGroup,
			},
			Containers: []corev1.Container{{
				Name:            "client",
				Image:           image("cracha-e2e-client"),
				ImagePullPolicy: corev1.PullNever,
				Env:             env,
			}},
		},
	}
}

// runWorkload creates a workload pod, waits for it to run and for its report.
func runWorkload(ctx context.Context, t *testing.T, name, serviceAccount string, env ...corev1.EnvVar) (*corev1.Pod, *report) {
	t.Helper()
	pod := mustCreatePod(ctx, t, workloadPod(name, serviceAccount, env...))
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
			return fmt.Errorf("no report in the client's log yet: %q", tail(logs, 5))
		}
		rep = &reports[0]
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return pod, rep
}

// The assigned workload's pod is shared by the tests that look at it; it is
// started on first use and removed with the rest of the suite's pods.
var assigned struct {
	once sync.Once
	pod  *corev1.Pod
	rep  *report
	err  error
}

func assignedWorkload(ctx context.Context, t *testing.T) (*corev1.Pod, *report) {
	t.Helper()
	assigned.once.Do(func() {
		defer func() {
			if r := recover(); r != nil {
				assigned.err = fmt.Errorf("starting the assigned workload: %v", r)
			}
		}()
		assigned.pod, assigned.rep = runWorkload(ctx, t, "client", assignedSA)
		if t.Failed() {
			assigned.err = fmt.Errorf("starting the assigned workload failed; see above")
		}
	})
	if assigned.err != nil {
		t.Fatal(assigned.err)
	}
	if assigned.pod == nil {
		t.Fatal("the assigned workload did not start")
	}
	return assigned.pod, assigned.rep
}

// stubRequests reads what the STS stub recorded, through the apiserver's
// service proxy, keeping those of the given session name.
func stubRequests(ctx context.Context, session string) ([]stsRequest, error) {
	raw, err := client.CoreV1().Services(systemNamespace).ProxyGet("http", "cracha-stsstub", "8080", "/requests", nil).DoRaw(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading the STS stub's record: %w", err)
	}
	var all []stsRequest
	if err := json.Unmarshal(raw, &all); err != nil {
		return nil, fmt.Errorf("decoding the STS stub's record: %w", err)
	}
	var out []stsRequest
	for _, r := range all {
		if r.RoleSessionName == session {
			out = append(out, r)
		}
	}
	return out, nil
}

// The whole path for a workload that holds a grant: the pod is enrolled
// before its containers start, the SDK, configured by nothing but the
// injected environment, obtains credentials through the loopback listener,
// and the broker assumed the shape role the way section 6.6 says.
func TestWorkloadObtainsCredentials(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	pod, rep := assignedWorkload(ctx, t)

	t.Run("enrolled", func(t *testing.T) {
		if pod.Labels[enrolLabel] != "true" {
			t.Errorf("labels = %v, want %s=true, the enrolment mark", pod.Labels, enrolLabel)
		}
		if enrolMode() != enrolInit {
			return
		}
		// In init mode the webhook's init container held the pod until the
		// agent acknowledged and the listener accepted a connection.
		running, err := client.CoreV1().Pods(testNamespace).Get(ctx, pod.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if n := len(running.Spec.InitContainers); n == 0 || running.Spec.InitContainers[0].Name != enrolContainer {
			t.Fatalf("init containers = %+v, want %s first", running.Spec.InitContainers, enrolContainer)
		}
		for _, s := range running.Status.InitContainerStatuses {
			if s.Name == enrolContainer && (s.State.Terminated == nil || s.State.Terminated.ExitCode != 0) {
				t.Errorf("the %s init container did not succeed: %+v", enrolContainer, s.State)
			}
		}
	})

	t.Run("credentials", func(t *testing.T) {
		if rep.Error != "" {
			t.Fatalf("the SDK got no credentials: %s (exchange: %+v)", rep.Error, rep.Exchange)
		}
		if rep.Credentials == nil {
			t.Fatal("no credentials in the report")
		}
		if rep.Credentials.AccessKeyID != stubAccessKeyID {
			t.Errorf("AccessKeyId = %q, want the stub's %q", rep.Credentials.AccessKeyID, stubAccessKeyID)
		}
		if !rep.Credentials.CanExpire || time.Until(rep.Credentials.Expires) <= 0 {
			t.Errorf("credentials expire %v (canExpire %t), want in the future", rep.Credentials.Expires, rep.Credentials.CanExpire)
		}
		ex := rep.Exchange
		if ex == nil {
			t.Fatal("no HTTP exchange recorded")
		}
		if ex.URL != credentialsURI {
			t.Errorf("the SDK called %s, want %s", ex.URL, credentialsURI)
		}
		if ex.Status != 200 {
			t.Errorf("the listener answered %d: %s", ex.Status, ex.Body)
		}
		// The bundle version is the compiled bundle's: the broker served
		// the bundle run.sh published, verified, not a fixture.
		bundleVersion, err := publishedBundleVersion(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for header, want := range map[string]string{
			"Cracha-Shape":          shapeName,
			"Cracha-Grants":         grantName,
			"Cracha-Bundle-Version": bundleVersion,
		} {
			if got := strings.Join(ex.Headers[header], ","); got != want {
				t.Errorf("%s = %q, want %q", header, got, want)
			}
		}
		if ex.Headers["Cracha-Consistency-Token"] == nil {
			t.Error("no Cracha-Consistency-Token header")
		}
		var body struct {
			AccessKeyID string `json:"AccessKeyId"`
			Token       string `json:"Token"`
			Expiration  string `json:"Expiration"`
		}
		if err := json.Unmarshal([]byte(ex.Body), &body); err != nil {
			t.Fatalf("body is not the container-credentials JSON: %v: %s", err, ex.Body)
		}
		if body.AccessKeyID != stubAccessKeyID || body.Token == "" || body.Expiration == "" {
			t.Errorf("body = %s, want AccessKeyId %s with Token and Expiration", ex.Body, stubAccessKeyID)
		}
	})

	t.Run("assume role", func(t *testing.T) {
		reqs, err := stubRequests(ctx, sourceIdentity)
		if err != nil {
			t.Fatal(err)
		}
		if len(reqs) != 1 {
			t.Fatalf("the stub recorded %d AssumeRole calls for %s, want 1: %+v", len(reqs), sourceIdentity, reqs)
		}
		r := reqs[0]
		if r.RoleArn != baseRole {
			t.Errorf("RoleArn = %q, want %q", r.RoleArn, baseRole)
		}
		if r.SourceIdentity != r.RoleSessionName || !strings.HasPrefix(r.SourceIdentity, "w.") {
			t.Errorf("SourceIdentity = %q, RoleSessionName = %q, want equal and starting with w.", r.SourceIdentity, r.RoleSessionName)
		}
		wantTags := map[string]string{
			"spiffe-ns": testNamespace, "spiffe-sa": assignedSA, "cluster": "kind",
			"grant": grantName, "team": "platform", "service": "e2e-client",
		}
		var keys []string
		for k := range r.Tags {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if len(r.Tags) != len(wantTags) {
			t.Errorf("session tag keys = %v, want %d of them", keys, len(wantTags))
		}
		for k, want := range wantTags {
			if got := r.Tags[k]; got != want {
				t.Errorf("session tag %s = %q, want %q", k, got, want)
			}
		}
		if len(r.TransitiveTagKeys) != 0 {
			t.Errorf("transitive tag keys = %v, want none", r.TransitiveTagKeys)
		}
		var policy struct {
			Version   string `json:"Version"`
			Statement []struct {
				Effect   string `json:"Effect"`
				Resource string `json:"Resource"`
			} `json:"Statement"`
		}
		if err := json.Unmarshal([]byte(r.Policy), &policy); err != nil {
			t.Fatalf("session policy is not a policy document: %v: %q", err, r.Policy)
		}
		if policy.Version != "2012-10-17" || len(policy.Statement) != 1 || policy.Statement[0].Resource != "arn:aws:s3:::cracha-e2e-bucket/*" {
			t.Errorf("session policy = %s, want the grant's one statement", r.Policy)
		}
		if len(r.PolicyArns) != 0 {
			t.Errorf("PolicyArns = %v, want none", r.PolicyArns)
		}
		if r.DurationSeconds != 3600 {
			t.Errorf("DurationSeconds = %d, want 3600", r.DurationSeconds)
		}
	})
}

// A workload with an identity but no assignment is refused with the
// reason of section 6.5, and never reaches STS.
func TestUnassignedWorkloadIsRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	_, rep := runWorkload(ctx, t, "unassigned", unassignedSA)

	if rep.Error == "" || rep.Credentials != nil {
		t.Fatalf("the unassigned workload got credentials: %+v", rep.Credentials)
	}
	ex := rep.Exchange
	if ex == nil {
		t.Fatalf("no HTTP exchange recorded; the SDK said: %s", rep.Error)
	}
	if ex.Status != 403 {
		t.Errorf("broker answered %d, want 403: %s", ex.Status, ex.Body)
	}
	if ex.reason() != "no_grant" {
		t.Errorf("body = %q, want {\"reason\": \"no_grant\"}", ex.Body)
	}
	session := fmt.Sprintf("w.cracha.%s.%s", testNamespace, unassignedSA)
	reqs, err := stubRequests(ctx, session)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 0 {
		t.Errorf("the stub recorded AssumeRole calls for %s: %+v", session, reqs)
	}
}
