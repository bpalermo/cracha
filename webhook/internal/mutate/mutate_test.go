package mutate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	jsonpatch "gopkg.in/evanphx/json-patch.v4"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

const (
	agentPort    = 8780
	enrolPort    = 8781
	enrolTimeout = 30 * time.Second
	agentImage   = "registry.example.com/cracha/agent@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	region       = "eu-west-1"
)

var credentialsURI = "http://127.0.0.1:8780/v1/credentials"

// config is the configuration under test in the given mode.
func config(mode EnrolMode, policy ConflictPolicy) Config {
	return Config{
		AgentPort:      agentPort,
		DefaultRegion:  region,
		ConflictingEnv: policy,
		Enrol:          mode,
		AgentImage:     agentImage,
		EnrolPort:      enrolPort,
		EnrolTimeout:   enrolTimeout,
	}
}

// clientLookup adapts a clientset to ServiceAccounts, without a cache, so
// the tests exercise the real client path.
type clientLookup struct{ client *fake.Clientset }

func (l clientLookup) Get(ctx context.Context, namespace, name string) (*corev1.ServiceAccount, error) {
	return l.client.CoreV1().ServiceAccounts(namespace).Get(ctx, name, metav1.GetOptions{})
}

func serviceAccount(name string, enabled bool) *corev1.ServiceAccount {
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: name}}
	if enabled {
		sa.Annotations = map[string]string{AnnotationEnabled: "true"}
	}
	return sa
}

// Two service accounts exist in the "apps" namespace: "enabled" opted in,
// "plain" did not.
func fakeClient() *fake.Clientset {
	return fake.NewClientset(serviceAccount("enabled", true), serviceAccount("plain", false))
}

func pod(sa string, containers ...corev1.Container) *corev1.Pod {
	return &corev1.Pod{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", GenerateName: "web-"},
		Spec: corev1.PodSpec{
			ServiceAccountName: sa,
			Containers:         containers,
		},
	}
}

func container(name string, env ...corev1.EnvVar) corev1.Container {
	return corev1.Container{Name: name, Image: "example/" + name, Env: env}
}

func env(name, value string) corev1.EnvVar {
	return corev1.EnvVar{Name: name, Value: value}
}

func secretEnv(name string) corev1.EnvVar {
	return corev1.EnvVar{Name: name, ValueFrom: &corev1.EnvVarSource{
		SecretKeyRef: &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: "aws"},
			Key:                  name,
		},
	}}
}

func injectedEnv() []corev1.EnvVar {
	return []corev1.EnvVar{
		env(EnvCredentialsURI, credentialsURI),
		env(EnvRegion, region),
	}
}

// injected is what a container looks like after injection: its own
// environment first, then ours.
func injected(c corev1.Container) corev1.Container {
	c.Env = append(append([]corev1.EnvVar{}, c.Env...), injectedEnv()...)
	return c
}

// enrolled is a pod after injection in the given mode, from the containers
// as they should end up: the label, and in the init mode the token volume
// and the enrolment container ahead of every other init container.
func enrolled(mode EnrolMode, p *corev1.Pod) *corev1.Pod {
	out := p.DeepCopy()
	if out.Labels == nil {
		out.Labels = map[string]string{}
	}
	out.Labels[LabelCredentials] = "true"
	if mode == EnrolInit {
		out.Spec.Volumes = append(out.Spec.Volumes, enrolVolume())
		pl := planner{cfg: config(EnrolInit, Reject)}
		out.Spec.InitContainers = append([]corev1.Container{pl.enrolContainer()}, out.Spec.InitContainers...)
	}
	return out
}

func createRequest(t *testing.T, p *corev1.Pod) *admissionv1.AdmissionRequest {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return &admissionv1.AdmissionRequest{
		UID:       types.UID("req-1"),
		Kind:      metav1.GroupVersionKind{Version: "v1", Kind: "Pod"},
		Resource:  metav1.GroupVersionResource{Version: "v1", Resource: "pods"},
		Operation: admissionv1.Create,
		Namespace: p.Namespace,
		Object:    runtime.RawExtension{Raw: raw},
	}
}

// diff compares two pods structurally through their JSON form, which is
// what the apiserver sees and keeps metav1.Time's unexported fields out of
// cmp's way.
func diff(t *testing.T, want, got *corev1.Pod) string {
	t.Helper()
	var w, g map[string]any
	for _, x := range []struct {
		p   *corev1.Pod
		out *map[string]any
	}{{want, &w}, {got, &g}} {
		raw, err := json.Marshal(x.p)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, x.out); err != nil {
			t.Fatal(err)
		}
	}
	return cmp.Diff(w, g)
}

// apply returns the pod the response's patch produces from p.
func apply(t *testing.T, p *corev1.Pod, resp *admissionv1.AdmissionResponse) *corev1.Pod {
	t.Helper()
	if resp.PatchType == nil || *resp.PatchType != admissionv1.PatchTypeJSONPatch {
		t.Fatalf("patch type %v, want JSONPatch", resp.PatchType)
	}
	patch, err := jsonpatch.DecodePatch(resp.Patch)
	if err != nil {
		t.Fatalf("decoding the patch %s: %v", resp.Patch, err)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	patched, err := patch.Apply(raw)
	if err != nil {
		t.Fatalf("applying the patch %s: %v", resp.Patch, err)
	}
	var out corev1.Pod
	if err := json.Unmarshal(patched, &out); err != nil {
		t.Fatalf("decoding the patched pod: %v", err)
	}
	return &out
}

type want struct {
	// allowed with no patch
	unchanged bool
	// allowed with a patch that produces this pod
	pod *corev1.Pod
	// denied, with a message containing each of these
	denied []string
	code   int32
	// warnings expected, each as a substring
	warnings []string
}

func TestAdmit(t *testing.T) {
	plainApp := container("app", env("FOO", "bar"))
	plainInit := corev1.Container{Name: "init", Image: "example/init"}

	// The conflicting variables, one per class.
	conflicting := []corev1.EnvVar{
		env("AWS_ACCESS_KEY_ID", "AKIA"),
		env("AWS_SECRET_ACCESS_KEY", "secret"),
		env("AWS_SESSION_TOKEN", "token"),
		env("AWS_CONFIG_FILE", "/etc/aws/config"),
		env("AWS_SHARED_CREDENTIALS_FILE", "/etc/aws/credentials"),
		env("AWS_WEB_IDENTITY_TOKEN_FILE", "/var/run/secrets/eks/token"),
		env("AWS_ROLE_ARN", "arn:aws:iam::1:role/x"),
		env("AWS_ROLE_SESSION_NAME", "x"),
		env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/x"),
		env("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://169.254.170.23/v1/credentials"),
		env("AWS_CONTAINER_AUTHORIZATION_TOKEN", "x"),
		env("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "/elsewhere/token"),
	}

	withInit := func(p *corev1.Pod, init ...corev1.Container) *corev1.Pod {
		p.Spec.InitContainers = init
		return p
	}
	labelled := func(p *corev1.Pod) *corev1.Pod {
		p.Labels = map[string]string{LabelCredentials: "true"}
		return p
	}

	tests := []admitCase{
		{
			name: "unannotated service account is left alone",
			pod:  pod("plain", plainApp),
			want: want{unchanged: true},
		},
		{
			name: "init mode: env, label, token volume and the enrolment container",
			pod:  pod("enabled", plainApp),
			want: want{pod: enrolled(EnrolInit, pod("enabled", injected(plainApp)))},
		},
		{
			name: "cni mode: env and label only",
			mode: EnrolCNI,
			pod:  pod("enabled", plainApp),
			want: want{pod: enrolled(EnrolCNI, pod("enabled", injected(plainApp)))},
		},
		{
			name: "empty service account name means default",
			pod:  pod("", plainApp),
			client: func(c *fake.Clientset) {
				if err := c.Tracker().Add(serviceAccount("default", true)); err != nil {
					t.Fatal(err)
				}
			},
			want: want{pod: enrolled(EnrolInit, pod("", injected(plainApp)))},
		},
		{
			name: "init mode: the pod's init containers get the env and come after the enrolment",
			pod:  withInit(pod("enabled", plainApp), plainInit),
			want: want{pod: enrolled(EnrolInit, withInit(pod("enabled", injected(plainApp)), injected(plainInit)))},
		},
		{
			name: "cni mode: the pod's init containers get the env",
			mode: EnrolCNI,
			pod:  withInit(pod("enabled", plainApp), plainInit),
			want: want{pod: enrolled(EnrolCNI, withInit(pod("enabled", injected(plainApp)), injected(plainInit)))},
		},
		{
			name: "existing volumes, labels and annotations are kept",
			pod: func() *corev1.Pod {
				c := plainApp
				c.VolumeMounts = []corev1.VolumeMount{{Name: "data", MountPath: "/data"}}
				p := pod("enabled", c)
				p.Labels = map[string]string{"app": "web"}
				p.Annotations = map[string]string{"team": "payments"}
				p.Spec.Volumes = []corev1.Volume{{Name: "data"}}
				return p
			}(),
			want: want{pod: func() *corev1.Pod {
				c := plainApp
				c.VolumeMounts = []corev1.VolumeMount{{Name: "data", MountPath: "/data"}}
				p := pod("enabled", injected(c))
				p.Labels = map[string]string{"app": "web"}
				p.Annotations = map[string]string{"team": "payments"}
				p.Spec.Volumes = []corev1.Volume{{Name: "data"}}
				return enrolled(EnrolInit, p)
			}()},
		},
		{
			name: "a labelled pod is unchanged",
			pod:  enrolled(EnrolInit, pod("enabled", injected(plainApp))),
			want: want{unchanged: true},
		},
		{
			name: "a labelled pod is unchanged even when it carries none of the rest",
			pod:  labelled(pod("enabled", plainApp)),
			want: want{unchanged: true},
		},
		{
			name: "a labelled pod is unchanged even with conflicts",
			pod:  labelled(pod("enabled", container("app", env("AWS_ACCESS_KEY_ID", "x")))),
			want: want{unchanged: true},
		},
		{
			name: "the label with another value is not the mark",
			pod: func() *corev1.Pod {
				p := pod("enabled", plainApp)
				p.Labels = map[string]string{LabelCredentials: "false"}
				return p
			}(),
			want: want{pod: func() *corev1.Pod {
				p := enrolled(EnrolInit, pod("enabled", injected(plainApp)))
				return p
			}()},
		},
		{
			name: "env already there is completed with the rest",
			pod:  pod("enabled", container("app", env("FOO", "bar"), env(EnvCredentialsURI, credentialsURI), env(EnvRegion, region))),
			want: want{pod: enrolled(EnrolInit, pod("enabled", injected(plainApp)))},
		},
		{
			name: "the pod's own AWS_REGION wins",
			pod:  pod("enabled", container("app", env(EnvRegion, "us-east-1"))),
			want: want{pod: enrolled(EnrolInit, pod("enabled",
				container("app", env(EnvRegion, "us-east-1"), env(EnvCredentialsURI, credentialsURI))))},
		},
		{
			name:    "the region hook overrides the default",
			pod:     pod("enabled", plainApp),
			regions: regionsFunc(func(context.Context, string) (string, error) { return "sa-east-1", nil }),
			want: want{pod: func() *corev1.Pod {
				c := injected(plainApp)
				c.Env[len(c.Env)-1].Value = "sa-east-1"
				return enrolled(EnrolInit, pod("enabled", c))
			}()},
		},
		{
			name:    "the region hook declining keeps the default",
			pod:     pod("enabled", plainApp),
			regions: regionsFunc(func(context.Context, string) (string, error) { return "", nil }),
			want:    want{pod: enrolled(EnrolInit, pod("enabled", injected(plainApp)))},
		},
		{
			name:    "the region hook failing denies",
			pod:     pod("enabled", plainApp),
			regions: regionsFunc(func(context.Context, string) (string, error) { return "", errors.New("namespace lister down") }),
			want:    want{denied: []string{"namespace lister down"}, code: 503},
		},
		{
			name: "an override that is not a region denies as invalid",
			pod:  pod("enabled", plainApp),
			regions: regionsFunc(func(_ context.Context, ns string) (string, error) {
				return "", &InvalidRegionError{Namespace: ns, Value: "nowhere"}
			}),
			want: want{denied: []string{`cracha: annotation cracha.dev/region of namespace apps is "nowhere", not an AWS region`}, code: 422},
		},
		{
			name: "hostNetwork is refused",
			pod: func() *corev1.Pod {
				p := pod("enabled", plainApp)
				p.Spec.HostNetwork = true
				return p
			}(),
			want: want{denied: []string{"pod uses hostNetwork"}, code: 422},
		},
		{
			name: "hostNetwork is refused in cni mode too",
			mode: EnrolCNI,
			pod: func() *corev1.Pod {
				p := pod("enabled", plainApp)
				p.Spec.HostNetwork = true
				return p
			}(),
			want: want{denied: []string{"pod uses hostNetwork"}, code: 422},
		},
		{
			name: "a foreign cracha-enrol init container is refused",
			pod:  withInit(pod("enabled", plainApp), corev1.Container{Name: EnrolContainerName, Image: "example/impostor"}),
			want: want{denied: []string{`init container "cracha-enrol" is reserved`}, code: 422},
		},
		{
			name: "a foreign cracha-enrol init container is refused in cni mode too",
			mode: EnrolCNI,
			pod:  withInit(pod("enabled", plainApp), corev1.Container{Name: EnrolContainerName, Image: "example/impostor"}),
			want: want{denied: []string{`init container "cracha-enrol" is reserved`}, code: 422},
		},
		{
			name: "a foreign cracha-enrol volume is refused",
			pod: func() *corev1.Pod {
				p := pod("enabled", plainApp)
				p.Spec.Volumes = []corev1.Volume{{Name: EnrolVolumeName, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}
				return p
			}(),
			want: want{denied: []string{`volume "cracha-enrol" is reserved`}, code: 422},
		},
		{
			name: "every problem is reported together",
			pod: func() *corev1.Pod {
				p := pod("enabled", container("app", env("AWS_ACCESS_KEY_ID", "x")))
				p.Spec.HostNetwork = true
				return p
			}(),
			want: want{denied: []string{"pod uses hostNetwork", "sets AWS_ACCESS_KEY_ID"}, code: 422},
		},
		{
			name: "valueFrom conflicts are rejected",
			pod:  pod("enabled", container("app", secretEnv("AWS_ACCESS_KEY_ID"), secretEnv("AWS_SECRET_ACCESS_KEY"))),
			want: want{denied: []string{`container "app" sets AWS_ACCESS_KEY_ID`, `container "app" sets AWS_SECRET_ACCESS_KEY`}, code: 422},
		},
		{
			name: "conflicts in an init container are rejected",
			pod:  withInit(pod("enabled", plainApp), container("init", env("AWS_ROLE_ARN", "x"))),
			want: want{denied: []string{`container "init" sets AWS_ROLE_ARN`}, code: 422},
		},
		{
			name:   "strip removes the conflicts and records them",
			policy: Strip,
			pod: withInit(pod("enabled", container("app", env("FOO", "bar"), secretEnv("AWS_ACCESS_KEY_ID"), env("AWS_SESSION_TOKEN", "t"), env("KEEP", "me"))),
				container("init", env("AWS_ROLE_ARN", "x"))),
			want: want{
				pod: func() *corev1.Pod {
					p := withInit(pod("enabled", injected(container("app", env("FOO", "bar"), env("KEEP", "me")))), injected(container("init")))
					p = enrolled(EnrolInit, p)
					p.Annotations = map[string]string{AnnotationStrippedEnv: `[{"container":"init","name":"AWS_ROLE_ARN"},{"container":"app","name":"AWS_ACCESS_KEY_ID"},{"container":"app","name":"AWS_SESSION_TOKEN"}]`}
					return p
				}(),
				warnings: []string{`removed AWS_ROLE_ARN from container "init"`, `removed AWS_ACCESS_KEY_ID from container "app"`, `removed AWS_SESSION_TOKEN from container "app"`},
			},
		},
		{
			name:   "strip replaces our variables set to other values",
			policy: Strip,
			pod:    pod("enabled", container("app", env(EnvCredentialsURI, "https://elsewhere/v1/credentials"))),
			want: want{
				pod: func() *corev1.Pod {
					p := enrolled(EnrolInit, pod("enabled", injected(container("app"))))
					p.Annotations = map[string]string{AnnotationStrippedEnv: `[{"container":"app","name":"AWS_CONTAINER_CREDENTIALS_FULL_URI"}]`}
					return p
				}(),
				warnings: []string{"removed AWS_CONTAINER_CREDENTIALS_FULL_URI"},
			},
		},
		{
			name:   "strip keeps existing annotations",
			policy: Strip,
			pod: func() *corev1.Pod {
				p := pod("enabled", container("app", env("AWS_SESSION_TOKEN", "t")))
				p.Annotations = map[string]string{"team": "payments"}
				return p
			}(),
			want: want{
				pod: func() *corev1.Pod {
					p := enrolled(EnrolInit, pod("enabled", injected(container("app"))))
					p.Annotations = map[string]string{"team": "payments", AnnotationStrippedEnv: `[{"container":"app","name":"AWS_SESSION_TOKEN"}]`}
					return p
				}(),
				warnings: []string{"removed AWS_SESSION_TOKEN"},
			},
		},
		{
			name: "service account lookup error denies",
			pod:  pod("enabled", plainApp),
			client: func(c *fake.Clientset) {
				c.PrependReactor("get", "serviceaccounts", func(k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, apierrors.NewServiceUnavailable("etcd is down")
				})
			},
			want: want{denied: []string{"looking up service account apps/enabled", "etcd is down"}, code: 503},
		},
		{
			name: "missing service account denies",
			pod:  pod("nobody", plainApp),
			want: want{denied: []string{"service account apps/nobody not found"}, code: 422},
		},
		{
			name: "update operations are left alone",
			pod:  pod("enabled", plainApp),
			request: func(r *admissionv1.AdmissionRequest) {
				r.Operation = admissionv1.Update
			},
			want: want{unchanged: true},
		},
		{
			name: "other kinds are left alone",
			pod:  pod("enabled", plainApp),
			request: func(r *admissionv1.AdmissionRequest) {
				r.Kind = metav1.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}
			},
			want: want{unchanged: true},
		},
		{
			name: "subresources are left alone",
			pod:  pod("enabled", plainApp),
			request: func(r *admissionv1.AdmissionRequest) {
				r.SubResource = "ephemeralcontainers"
			},
			want: want{unchanged: true},
		},
		{
			name: "a pod that does not decode denies",
			pod:  pod("enabled", plainApp),
			request: func(r *admissionv1.AdmissionRequest) {
				r.Object.Raw = []byte(`{"spec": "not an object"}`)
			},
			want: want{denied: []string{"decoding the pod"}, code: 400},
		},
	}

	for _, c := range conflicting {
		tests = append(tests, admitCase{
			name: "conflict " + c.Name + " is rejected",
			pod:  pod("enabled", container("app", env("FOO", "bar"), c)),
			want: want{denied: []string{`container "app" sets ` + c.Name}, code: 422},
		})
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := tc.mutator(t)
			req := createRequest(t, tc.pod)
			if tc.request != nil {
				tc.request(req)
			}
			original := tc.pod.DeepCopy()

			resp := m.Admit(context.Background(), req)

			if resp.UID != req.UID {
				t.Errorf("response UID %q, want %q", resp.UID, req.UID)
			}
			if d := diff(t, original, tc.pod); d != "" {
				t.Errorf("Admit modified its input (-before +after):\n%s", d)
			}
			tc.want.check(t, m, tc.pod, resp)
		})
	}
}

// admitCase is one TestAdmit case.
type admitCase struct {
	name   string
	mode   EnrolMode
	policy ConflictPolicy
	pod    *corev1.Pod
	// request can turn the request into something else; client can break
	// the client.
	request func(*admissionv1.AdmissionRequest)
	client  func(*fake.Clientset)
	regions Regions
	want    want
}

// mutator builds the Mutator under test, over a fake client the case may
// have broken and with its region hook, if any.
func (tc admitCase) mutator(t *testing.T) *Mutator {
	t.Helper()
	client := fakeClient()
	if tc.client != nil {
		tc.client(client)
	}
	var opts []Option
	if tc.regions != nil {
		opts = append(opts, WithRegions(tc.regions))
	}
	m, err := New(config(tc.mode, tc.policy), clientLookup{client}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// check asserts that resp, the decision on p, is the one wanted.
func (w want) check(t *testing.T, m *Mutator, p *corev1.Pod, resp *admissionv1.AdmissionResponse) {
	t.Helper()
	switch {
	case w.denied != nil:
		w.checkDenied(t, resp)
	case w.unchanged:
		checkUnchanged(t, resp)
	default:
		w.checkPatched(t, m, p, resp)
	}
	w.checkWarnings(t, resp.Warnings)
}

func (w want) checkDenied(t *testing.T, resp *admissionv1.AdmissionResponse) {
	t.Helper()
	if resp.Allowed {
		t.Fatalf("allowed, want denied with %q; patch %s", w.denied, resp.Patch)
	}
	if resp.Result == nil {
		t.Fatal("denied without a result")
	}
	for _, want := range w.denied {
		if !strings.Contains(resp.Result.Message, want) {
			t.Errorf("denial message %q does not contain %q", resp.Result.Message, want)
		}
	}
	if resp.Result.Code != w.code {
		t.Errorf("denial code %d, want %d", resp.Result.Code, w.code)
	}
}

func checkUnchanged(t *testing.T, resp *admissionv1.AdmissionResponse) {
	t.Helper()
	if !resp.Allowed {
		t.Fatalf("denied: %v", resp.Result)
	}
	if resp.Patch != nil || resp.PatchType != nil {
		t.Fatalf("patched: %s", resp.Patch)
	}
}

// checkPatched applies the patch to p and compares the result with the pod
// wanted, then admits that result once more: nothing must be left to do.
func (w want) checkPatched(t *testing.T, m *Mutator, p *corev1.Pod, resp *admissionv1.AdmissionResponse) {
	t.Helper()
	if !resp.Allowed {
		t.Fatalf("denied: %v", resp.Result)
	}
	got := apply(t, p, resp)
	if d := diff(t, w.pod, got); d != "" {
		t.Errorf("patched pod (-want +got):\n%s\npatch: %s", d, resp.Patch)
	}
	again := m.Admit(context.Background(), createRequest(t, got))
	if !again.Allowed || again.Patch != nil {
		t.Errorf("admitting the patched pod again: allowed=%v patch=%s", again.Allowed, again.Patch)
	}
}

func (w want) checkWarnings(t *testing.T, warnings []string) {
	t.Helper()
	if len(warnings) != len(w.warnings) {
		t.Errorf("warnings %q, want %d matching %q", warnings, len(w.warnings), w.warnings)
		return
	}
	for i, want := range w.warnings {
		if !strings.Contains(warnings[i], want) {
			t.Errorf("warning %d %q does not contain %q", i, warnings[i], want)
		}
	}
}

// TestPatchShape pins the operations themselves: their order is what makes
// the patch applicable (the enrolment container is inserted at index 0
// after the init containers' env has been addressed by their indices), and
// the paths are what an operator reads in the audit log.
func TestPatchShape(t *testing.T) {
	p := pod("enabled", container("app", env("FOO", "bar")), corev1.Container{Name: "bare", Image: "example/bare"})
	p.Spec.InitContainers = []corev1.Container{{Name: "init", Image: "example/init"}}
	p.Labels = map[string]string{"app": "web"}

	for _, tc := range []struct {
		mode EnrolMode
		want []string
	}{
		{EnrolInit, []string{
			"add /spec/initContainers/0/env",
			"replace /spec/containers/0/env",
			"add /spec/containers/1/env",
			"add /spec/volumes",
			"add /spec/initContainers/0",
			"add /metadata/labels/cracha.dev~1credentials",
		}},
		{EnrolCNI, []string{
			"add /spec/initContainers/0/env",
			"replace /spec/containers/0/env",
			"add /spec/containers/1/env",
			"add /metadata/labels/cracha.dev~1credentials",
		}},
	} {
		t.Run(tc.mode.String(), func(t *testing.T) {
			pl := planner{cfg: config(tc.mode, Reject), region: region}
			pl.plan(p)
			if len(pl.problems) > 0 {
				t.Fatalf("problems: %v", pl.problems)
			}
			var got []string
			for _, op := range pl.ops {
				got = append(got, op.Op+" "+op.Path)
			}
			if d := cmp.Diff(tc.want, got); d != "" {
				t.Errorf("operations (-want +got):\n%s", d)
			}
		})
	}

	t.Run("bare pod", func(t *testing.T) {
		bare := pod("enabled", corev1.Container{Name: "app", Image: "example/app"})
		pl := planner{cfg: config(EnrolInit, Reject), region: region}
		pl.plan(bare)
		var got []string
		for _, op := range pl.ops {
			got = append(got, op.Op+" "+op.Path)
		}
		want := []string{"add /spec/containers/0/env", "add /spec/volumes", "add /spec/initContainers", "add /metadata/labels"}
		if d := cmp.Diff(want, got); d != "" {
			t.Errorf("operations (-want +got):\n%s", d)
		}
	})
}

// TestGolden admits one pod with a bit of everything (its own init
// container, env, volume, labels and annotations) in each mode and compares
// the result with testdata/<mode>.golden.json: the whole mutated pod, as
// the apiserver stores it, reviewed as a file. To refresh the files, run
// with --test_env=UPDATE_GOLDEN=1 and copy them out of the test's
// undeclared outputs.
func TestGolden(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "pod.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []EnrolMode{EnrolInit, EnrolCNI} {
		t.Run(mode.String(), func(t *testing.T) {
			var p corev1.Pod
			if err := json.Unmarshal(raw, &p); err != nil {
				t.Fatal(err)
			}
			m, err := New(config(mode, Reject), clientLookup{fakeClient()})
			if err != nil {
				t.Fatal(err)
			}
			resp := m.Admit(context.Background(), createRequest(t, &p))
			if !resp.Allowed {
				t.Fatalf("denied: %v", resp.Result)
			}
			got, err := json.MarshalIndent(apply(t, &p, resp), "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')
			name := mode.String() + ".golden.json"
			if os.Getenv("UPDATE_GOLDEN") != "" {
				out := filepath.Join(os.Getenv("TEST_UNDECLARED_OUTPUTS_DIR"), name)
				if err := os.WriteFile(out, got, 0o644); err != nil {
					t.Fatal(err)
				}
				t.Fatalf("wrote %s; copy it to testdata/ and run again", out)
			}
			want, err := os.ReadFile(filepath.Join("testdata", name))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(want, got) {
				t.Errorf("mutated pod differs from testdata/%s (-want +got):\n%s", name, cmp.Diff(string(want), string(got)))
			}
		})
	}
}

// TestEnrolContainer pins what the init container asks of the pod: nothing
// a restricted namespace refuses, and nothing but the token.
func TestEnrolContainer(t *testing.T) {
	pl := planner{cfg: config(EnrolInit, Reject)}
	c := pl.enrolContainer()
	sc := c.SecurityContext
	switch {
	case sc == nil:
		t.Fatal("no security context")
	case sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot:
		t.Error("runAsNonRoot is not true")
	case sc.RunAsUser == nil || *sc.RunAsUser == 0:
		t.Error("runAsUser is root or unset")
	case sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation:
		t.Error("allowPrivilegeEscalation is not false")
	case sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem:
		t.Error("readOnlyRootFilesystem is not true")
	case sc.Capabilities == nil || len(sc.Capabilities.Add) > 0 || len(sc.Capabilities.Drop) != 1 || sc.Capabilities.Drop[0] != "ALL":
		t.Errorf("capabilities %+v, want drop ALL and nothing added", sc.Capabilities)
	case sc.SeccompProfile == nil || sc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault:
		t.Error("seccomp profile is not RuntimeDefault")
	case sc.Privileged != nil && *sc.Privileged:
		t.Error("privileged")
	}
	if c.Image != agentImage || len(c.Args) != 1 || c.Args[0] != EnrolArg || len(c.Command) != 0 {
		t.Errorf("runs %q %q from %q, want the image's entrypoint with %q", c.Command, c.Args, c.Image, EnrolArg)
	}
	if len(c.VolumeMounts) != 1 || c.VolumeMounts[0].Name != EnrolVolumeName || c.VolumeMounts[0].MountPath != EnrolTokenDir || !c.VolumeMounts[0].ReadOnly {
		t.Errorf("mounts %+v, want the token volume read-only at %s", c.VolumeMounts, EnrolTokenDir)
	}
	got := map[string]corev1.EnvVar{}
	for _, e := range c.Env {
		got[e.Name] = e
	}
	if e := got[EnvHostIP]; e.ValueFrom == nil || e.ValueFrom.FieldRef == nil || e.ValueFrom.FieldRef.FieldPath != "status.hostIP" {
		t.Errorf("%s = %+v, want status.hostIP from the downward API", EnvHostIP, e)
	}
	for name, want := range map[string]string{EnvEnrolPort: "8781", EnvAgentPort: strconv.Itoa(pl.cfg.AgentPort), EnvEnrolTimeout: "30s", EnvEnrolTokenFile: EnrolTokenPath} {
		if got[name].Value != want {
			t.Errorf("%s = %q, want %q", name, got[name].Value, want)
		}
	}
	if c.Resources.Limits.Cpu().IsZero() || !c.Resources.Limits.Cpu().Equal(*c.Resources.Requests.Cpu()) ||
		c.Resources.Limits.Memory().IsZero() || !c.Resources.Limits.Memory().Equal(*c.Resources.Requests.Memory()) {
		t.Errorf("resources %+v, want requests equal to limits", c.Resources)
	}

	v := enrolVolume()
	tok := v.Projected.Sources[0].ServiceAccountToken
	if v.Name != EnrolVolumeName || len(v.Projected.Sources) != 1 || tok == nil {
		t.Fatalf("volume %+v, want one projected token", v)
	}
	if tok.Audience != EnrolTokenAudience || tok.ExpirationSeconds == nil || *tok.ExpirationSeconds != EnrolTokenExpirationSeconds || tok.Path != EnrolTokenFile {
		t.Errorf("token %+v, want audience %s, %d seconds, at %s", tok, EnrolTokenAudience, EnrolTokenExpirationSeconds, EnrolTokenFile)
	}
}

func TestIsPodCreate(t *testing.T) {
	podCreate := func() *admissionv1.AdmissionRequest {
		return &admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Kind:      metav1.GroupVersionKind{Version: "v1", Kind: "Pod"},
		}
	}
	cases := []struct {
		name   string
		change func(*admissionv1.AdmissionRequest)
		want   bool
	}{
		{name: "a pod create", change: func(*admissionv1.AdmissionRequest) {}, want: true},
		{name: "an update", change: func(r *admissionv1.AdmissionRequest) { r.Operation = admissionv1.Update }},
		{name: "a subresource", change: func(r *admissionv1.AdmissionRequest) { r.SubResource = "status" }},
		{name: "another group", change: func(r *admissionv1.AdmissionRequest) { r.Kind.Group = "apps" }},
		{name: "another version", change: func(r *admissionv1.AdmissionRequest) { r.Kind.Version = "v1beta1" }},
		{name: "another kind", change: func(r *admissionv1.AdmissionRequest) { r.Kind.Kind = "PodTemplate" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := podCreate()
			tc.change(req)
			if got := isPodCreate(req); got != tc.want {
				t.Errorf("isPodCreate = %v, want %v", got, tc.want)
			}
		})
	}
}

type regionsFunc func(ctx context.Context, namespace string) (string, error)

func (f regionsFunc) Region(ctx context.Context, namespace string) (string, error) {
	return f(ctx, namespace)
}

func TestCredentialsURI(t *testing.T) {
	if got := (Config{AgentPort: 80}).CredentialsURI(); got != "http://127.0.0.1:80/v1/credentials" {
		t.Errorf("CredentialsURI = %q", got)
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	sas := clientLookup{fakeClient()}
	good := config(EnrolInit, Reject)
	for name, change := range map[string]func(*Config){
		"no agent port":          func(c *Config) { c.AgentPort = 0 },
		"agent port too large":   func(c *Config) { c.AgentPort = 65536 },
		"no default region":      func(c *Config) { c.DefaultRegion = "" },
		"init without image":     func(c *Config) { c.AgentImage = "" },
		"init without port":      func(c *Config) { c.EnrolPort = 0 },
		"init without timeout":   func(c *Config) { c.EnrolTimeout = 0 },
		"init negative timeout":  func(c *Config) { c.EnrolTimeout = -time.Second },
		"cni without agent port": func(c *Config) { c.Enrol = EnrolCNI; c.AgentPort = 0 },
	} {
		cfg := good
		change(&cfg)
		if _, err := New(cfg, sas); err == nil {
			t.Errorf("%s: New accepted %+v", name, cfg)
		}
	}
	if _, err := New(good, nil); err == nil {
		t.Error("New accepted a nil service account lookup")
	}
	// The cni mode needs none of the enrolment settings.
	if _, err := New(Config{AgentPort: 1, DefaultRegion: region, Enrol: EnrolCNI}, sas); err != nil {
		t.Errorf("cni mode without the enrolment settings: %v", err)
	}
	m, err := New(good, sas)
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Config(); got != good {
		t.Errorf("Config() = %+v, want %+v", got, good)
	}
}

func TestIsRegion(t *testing.T) {
	for _, s := range []string{"us-east-1", "eu-central-2", "ap-southeast-3", "us-gov-west-1", "cn-north-1", "il-central-1", "eu-isoe-west-1"} {
		if !IsRegion(s) {
			t.Errorf("IsRegion(%q) = false", s)
		}
	}
	for _, s := range []string{"", "us-east", "us-east-", "US-EAST-1", "us east 1", "us-east-1 ", "useast1", "u-east-1", "us-east-1-lax-1a", "aws-global", "nowhere"} {
		if IsRegion(s) {
			t.Errorf("IsRegion(%q) = true", s)
		}
	}
}

func TestConflictPolicyFlag(t *testing.T) {
	var p ConflictPolicy
	if p.String() != "reject" {
		t.Errorf("zero policy is %q, want reject", p.String())
	}
	if err := p.Set("strip"); err != nil || p != Strip {
		t.Errorf("Set(strip): %v, %v", p, err)
	}
	if err := p.Set("reject"); err != nil || p != Reject {
		t.Errorf("Set(reject): %v, %v", p, err)
	}
	if err := p.Set("drop"); err == nil {
		t.Error("Set(drop) succeeded")
	}
}

func TestEnrolModeFlag(t *testing.T) {
	var m EnrolMode
	if m.String() != "init" {
		t.Errorf("zero mode is %q, want init", m.String())
	}
	if err := m.Set("cni"); err != nil || m != EnrolCNI {
		t.Errorf("Set(cni): %v, %v", m, err)
	}
	if err := m.Set("init"); err != nil || m != EnrolInit {
		t.Errorf("Set(init): %v, %v", m, err)
	}
	if err := m.Set("sidecar"); err == nil {
		t.Error("Set(sidecar) succeeded")
	}
}

func TestConflicts(t *testing.T) {
	for _, name := range []string{
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
		"AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE",
		"AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_ROLE_SESSION_NAME",
		"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
		"AWS_CONTAINER_AUTHORIZATION_TOKEN", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
	} {
		if !Conflicts(name) {
			t.Errorf("Conflicts(%q) = false", name)
		}
	}
	for _, name := range []string{"AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE", "AWS_SDK_LOAD_CONFIG", "PATH", "aws_access_key_id"} {
		if Conflicts(name) {
			t.Errorf("Conflicts(%q) = true", name)
		}
	}
}
