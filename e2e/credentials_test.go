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

// What e2e/stsstub answers and e2e/values.yaml (the chart's assignments and
// grants) grants.
const (
	stubAccessKeyID = "ASIACRACHAE2ESTUB000"
	grantName       = "e2e-s3-reader"
	baseRole        = "arn:aws:iam::111122223333:role/broker/shape-e2e"
	shapeName       = "shape-e2e"
	// sourceIdentity is the idenc STS encoding of the client's identity:
	// w.<label>.<ns>.<sa>, with the label the broker maps cracha.test to.
	sourceIdentity = "w.cracha.e2e.client"
	// jwtTTL is the JWT-SVID lifetime e2e/spire.sh registers the test
	// workloads with.
	jwtTTL = 240 * time.Second
)

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
	Error    string `json:"error"`
	Exchange *struct {
		URL     string              `json:"url"`
		Status  int                 `json:"status"`
		Headers map[string][]string `json:"headers"`
		Body    string              `json:"body"`
	} `json:"exchange"`
	Token *tokenLine `json:"token"`
}

// tokenLine is what e2e/client prints about the token file: in the report,
// and once per change afterwards.
type tokenLine struct {
	Kind    string    `json:"kind"`
	Subject string    `json:"sub"`
	Aud     []string  `json:"aud"`
	Iat     int64     `json:"iat"`
	Exp     int64     `json:"exp"`
	ReadAt  time.Time `json:"readAt"`
	Error   string    `json:"error"`
	Changed bool      `json:"changed"`
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

// workloadPod is the suite's workload (e2e/client) running as the given
// ServiceAccount. An init container checks that the token exists before any
// container starts (section 7, "Ordering"); the container trusts the
// suite's CA through SSL_CERT_FILE, which Go honours, and nothing else about
// AWS is configured: the environment the webhook injects is all it has.
//
// It runs as root because the CSI plugin writes the token 0640 root:root by
// default, and the plugin is deployed without the capability --token-gid
// would need to hand the file to another group (section 7.7).
func workloadPod(name, serviceAccount string) *corev1.Pod {
	grace := int64(0)
	root := int64(0)
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: corev1.PodSpec{
			ServiceAccountName:            serviceAccount,
			RestartPolicy:                 corev1.RestartPolicyNever,
			TerminationGracePeriodSeconds: &grace,
			InitContainers: []corev1.Container{{
				Name:    "token-present",
				Image:   busybox,
				Command: []string{"sh", "-c", "test -f " + tokenPath + " && test -s " + tokenPath},
			}},
			Containers: []corev1.Container{{
				Name:            "client",
				Image:           image("cracha-e2e-client"),
				ImagePullPolicy: corev1.PullNever,
				Env:             []corev1.EnvVar{{Name: "SSL_CERT_FILE", Value: "/etc/cracha-ca/ca.crt"}},
				SecurityContext: &corev1.SecurityContext{RunAsUser: &root, RunAsGroup: &root},
				VolumeMounts:    []corev1.VolumeMount{{Name: "ca", MountPath: "/etc/cracha-ca", ReadOnly: true}},
			}},
			Volumes: []corev1.Volume{{
				Name: "ca",
				VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: "cracha-ca"},
				}},
			}},
		},
	}
}

// runWorkload creates a workload pod, waits for it to run and for its report.
func runWorkload(ctx context.Context, t *testing.T, name, serviceAccount string) (*corev1.Pod, *report) {
	t.Helper()
	pod := mustCreatePod(ctx, t, workloadPod(name, serviceAccount))
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

// The whole path for a workload that holds a grant: the token is in place
// before its containers start, the SDK, configured by nothing but the
// injected environment, obtains credentials from the broker, and the broker
// assumed the shape role the way section 6.6 says.
func TestWorkloadObtainsCredentials(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	pod, rep := assignedWorkload(ctx, t)

	t.Run("token file", func(t *testing.T) {
		// The init container only ran if the token was there.
		for _, s := range pod.Status.InitContainerStatuses {
			if s.Name == "token-present" && (s.State.Terminated == nil || s.State.Terminated.ExitCode != 0) {
				t.Errorf("the init container that checks for the token did not succeed: %+v", s.State)
			}
		}
		tok := rep.Token
		if tok == nil || tok.Error != "" {
			t.Fatalf("the client could not read the token: %+v", tok)
		}
		wantSubject := fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", trustDomain, testNamespace, assignedSA)
		if tok.Subject != wantSubject {
			t.Errorf("token sub = %q, want %q", tok.Subject, wantSubject)
		}
		if len(tok.Aud) != 1 || tok.Aud[0] != "cracha-broker" {
			t.Errorf("token aud = %v, want [cracha-broker]", tok.Aud)
		}
		if lifetime := time.Duration(tok.Exp-tok.Iat) * time.Second; lifetime != jwtTTL {
			t.Errorf("token lifetime = %s, want %s (section 11 caps it at 5m)", lifetime, jwtTTL)
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
			t.Errorf("broker answered %d: %s", ex.Status, ex.Body)
		}
		for header, want := range map[string]string{
			"Cracha-Shape":          shapeName,
			"Cracha-Grants":         grantName,
			"Cracha-Bundle-Version": "e2e-1",
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
	var body struct {
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(ex.Body), &body); err != nil || body.Reason != "no_grant" {
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
