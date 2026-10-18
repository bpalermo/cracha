package mutate

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

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
	brokerURL = "https://broker.cracha.svc/v1/credentials"
	region    = "eu-west-1"
)

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

func boolPtr(b bool) *bool { return &b }

func injectedEnv() []corev1.EnvVar {
	return []corev1.EnvVar{
		env(EnvCredentialsURI, brokerURL),
		env(EnvTokenFile, TokenPath),
		env(EnvRegion, region),
	}
}

// injected is what a container looks like after injection: its own
// environment first, then ours, and the mount appended.
func injected(c corev1.Container) corev1.Container {
	c.Env = append(append([]corev1.EnvVar{}, c.Env...), injectedEnv()...)
	c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: VolumeName, MountPath: MountPath, ReadOnly: true})
	return c
}

// injectedPod is a pod after injection, from the containers as they should
// end up.
func injectedPod(sa string, p *corev1.Pod) *corev1.Pod {
	out := p.DeepCopy()
	out.Spec.ServiceAccountName = sa
	out.Spec.Volumes = append(out.Spec.Volumes, corev1.Volume{
		Name:         VolumeName,
		VolumeSource: corev1.VolumeSource{CSI: &corev1.CSIVolumeSource{Driver: Driver, ReadOnly: boolPtr(true)}},
	})
	if out.Annotations == nil {
		out.Annotations = map[string]string{}
	}
	out.Annotations[AnnotationInjected] = "true"
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

	alreadyInjected := injectedPod("enabled", pod("enabled", injected(plainApp)))

	tests := []admitCase{
		{
			name: "unannotated service account is left alone",
			pod:  pod("plain", plainApp),
			want: want{unchanged: true},
		},
		{
			name: "annotated service account gets volume, mount, env and annotation",
			pod:  pod("enabled", plainApp),
			want: want{pod: injectedPod("enabled", pod("enabled", injected(plainApp)))},
		},
		{
			name: "empty service account name means default",
			pod:  pod("", plainApp),
			client: func(c *fake.Clientset) {
				if err := c.Tracker().Add(serviceAccount("default", true)); err != nil {
					t.Fatal(err)
				}
			},
			want: want{pod: injectedPod("", pod("", injected(plainApp)))},
		},
		{
			name: "init containers are injected too",
			pod: func() *corev1.Pod {
				p := pod("enabled", plainApp)
				p.Spec.InitContainers = []corev1.Container{plainInit}
				return p
			}(),
			want: want{pod: func() *corev1.Pod {
				p := pod("enabled", injected(plainApp))
				p.Spec.InitContainers = []corev1.Container{injected(plainInit)}
				return injectedPod("enabled", p)
			}()},
		},
		{
			name: "existing volumes, mounts and annotations are kept",
			pod: func() *corev1.Pod {
				c := plainApp
				c.VolumeMounts = []corev1.VolumeMount{{Name: "data", MountPath: "/data"}}
				p := pod("enabled", c)
				p.Annotations = map[string]string{"team": "payments"}
				p.Spec.Volumes = []corev1.Volume{{Name: "data"}}
				return p
			}(),
			want: want{pod: func() *corev1.Pod {
				c := plainApp
				c.VolumeMounts = []corev1.VolumeMount{{Name: "data", MountPath: "/data"}}
				p := pod("enabled", injected(c))
				p.Annotations = map[string]string{"team": "payments"}
				p.Spec.Volumes = []corev1.Volume{{Name: "data"}}
				return injectedPod("enabled", p)
			}()},
		},
		{
			name: "already injected pod is unchanged",
			pod:  alreadyInjected,
			want: want{unchanged: true},
		},
		{
			name: "partially injected pod is completed",
			pod: func() *corev1.Pod {
				// The env is there, the volume and mount are not.
				c := plainApp
				c.Env = append(c.Env, injectedEnv()...)
				return pod("enabled", c)
			}(),
			want: want{pod: injectedPod("enabled", pod("enabled", injected(plainApp)))},
		},
		{
			name: "the pod's own AWS_REGION wins",
			pod:  pod("enabled", container("app", env(EnvRegion, "us-east-1"))),
			want: want{pod: func() *corev1.Pod {
				c := container("app", env(EnvRegion, "us-east-1"),
					env(EnvCredentialsURI, brokerURL), env(EnvTokenFile, TokenPath))
				c.VolumeMounts = []corev1.VolumeMount{{Name: VolumeName, MountPath: MountPath, ReadOnly: true}}
				return injectedPod("enabled", pod("enabled", c))
			}()},
		},
		{
			name:    "the region hook overrides the default",
			pod:     pod("enabled", plainApp),
			regions: regionsFunc(func(context.Context, string) (string, error) { return "sa-east-1", nil }),
			want: want{pod: func() *corev1.Pod {
				c := injected(plainApp)
				c.Env[len(c.Env)-1].Value = "sa-east-1"
				return injectedPod("enabled", pod("enabled", c))
			}()},
		},
		{
			name:    "the region hook declining keeps the default",
			pod:     pod("enabled", plainApp),
			regions: regionsFunc(func(context.Context, string) (string, error) { return "", nil }),
			want:    want{pod: injectedPod("enabled", pod("enabled", injected(plainApp)))},
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
			name: "valueFrom conflicts are rejected",
			pod:  pod("enabled", container("app", secretEnv("AWS_ACCESS_KEY_ID"), secretEnv("AWS_SECRET_ACCESS_KEY"))),
			want: want{denied: []string{`container "app" sets AWS_ACCESS_KEY_ID`, `container "app" sets AWS_SECRET_ACCESS_KEY`}, code: 422},
		},
		{
			name: "conflicts in an init container are rejected",
			pod: func() *corev1.Pod {
				p := pod("enabled", plainApp)
				p.Spec.InitContainers = []corev1.Container{container("init", env("AWS_ROLE_ARN", "x"))}
				return p
			}(),
			want: want{denied: []string{`container "init" sets AWS_ROLE_ARN`}, code: 422},
		},
		{
			name:   "strip removes the conflicts and records them",
			policy: Strip,
			pod: func() *corev1.Pod {
				p := pod("enabled", container("app", env("FOO", "bar"), secretEnv("AWS_ACCESS_KEY_ID"), env("AWS_SESSION_TOKEN", "t"), env("KEEP", "me")))
				p.Spec.InitContainers = []corev1.Container{container("init", env("AWS_ROLE_ARN", "x"))}
				return p
			}(),
			want: want{
				pod: func() *corev1.Pod {
					p := pod("enabled", injected(container("app", env("FOO", "bar"), env("KEEP", "me"))))
					p.Spec.InitContainers = []corev1.Container{injected(container("init"))}
					p = injectedPod("enabled", p)
					p.Annotations[AnnotationStrippedEnv] = `[{"container":"init","name":"AWS_ROLE_ARN"},{"container":"app","name":"AWS_ACCESS_KEY_ID"},{"container":"app","name":"AWS_SESSION_TOKEN"}]`
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
					p := injectedPod("enabled", pod("enabled", injected(container("app"))))
					p.Annotations[AnnotationStrippedEnv] = `[{"container":"app","name":"AWS_CONTAINER_CREDENTIALS_FULL_URI"}]`
					return p
				}(),
				warnings: []string{"removed AWS_CONTAINER_CREDENTIALS_FULL_URI"},
			},
		},
		{
			name: "a foreign mount at the path is rejected",
			pod: func() *corev1.Pod {
				c := plainApp
				c.VolumeMounts = []corev1.VolumeMount{{Name: "secrets", MountPath: "/var/run/cracha/"}}
				p := pod("enabled", c)
				p.Spec.Volumes = []corev1.Volume{{Name: "secrets"}}
				return p
			}(),
			want: want{denied: []string{`container "app" mounts volume "secrets" at /var/run/cracha`}, code: 422},
		},
		{
			name: "a mount inside the path is rejected",
			pod: func() *corev1.Pod {
				c := plainApp
				c.VolumeMounts = []corev1.VolumeMount{{Name: "secrets", MountPath: "/var/run/cracha/token"}}
				p := pod("enabled", c)
				p.Spec.Volumes = []corev1.Volume{{Name: "secrets"}}
				return p
			}(),
			want: want{denied: []string{`container "app" mounts volume "secrets" at /var/run/cracha/token`}, code: 422},
		},
		{
			name: "a volume named cracha that is not ours is rejected",
			pod: func() *corev1.Pod {
				p := pod("enabled", plainApp)
				p.Spec.Volumes = []corev1.Volume{{Name: VolumeName, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}
				return p
			}(),
			want: want{denied: []string{`volume "cracha" is not the csi.cracha.dev CSI volume`}, code: 422},
		},
		{
			name: "a conflict is reported even in a pod with a bad mount",
			pod: func() *corev1.Pod {
				c := container("app", env("AWS_ACCESS_KEY_ID", "x"))
				c.VolumeMounts = []corev1.VolumeMount{{Name: "secrets", MountPath: MountPath}}
				return pod("enabled", c)
			}(),
			want: want{denied: []string{`mounts volume "secrets"`, "sets AWS_ACCESS_KEY_ID"}, code: 422},
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
	m, err := New(Config{
		BrokerURL:      "https://broker.cracha.svc",
		DefaultRegion:  region,
		ConflictingEnv: tc.policy,
	}, clientLookup{client}, opts...)
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

func TestBrokerURL(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"https://broker.cracha.svc", "https://broker.cracha.svc/v1/credentials"},
		{"https://broker.cracha.svc/", "https://broker.cracha.svc/v1/credentials"},
		{"https://broker.cracha.svc:8443", "https://broker.cracha.svc:8443/v1/credentials"},
		{"https://broker.cracha.svc/v1/credentials", "https://broker.cracha.svc/v1/credentials"},
		{"https://broker.cracha.svc/v1/credentials/", "https://broker.cracha.svc/v1/credentials"},
		{"https://broker.example.com/cracha", "https://broker.example.com/cracha/v1/credentials"},
		{"http://broker.cracha.svc", ""},
		{"broker.cracha.svc", ""},
		{"https://", ""},
		{"https://broker.cracha.svc?x=1", ""},
		{"https://user@broker.cracha.svc", ""},
		{"https://broker.cracha.svc#f", ""},
		{"://bad", ""},
	}
	for _, tc := range tests {
		got, err := BrokerURL(tc.in)
		if tc.want == "" {
			if err == nil {
				t.Errorf("BrokerURL(%q) = %q, want an error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("BrokerURL(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("BrokerURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	sas := clientLookup{fakeClient()}
	if _, err := New(Config{BrokerURL: "http://broker", DefaultRegion: region}, sas); err == nil {
		t.Error("New accepted an http broker URL")
	}
	if _, err := New(Config{BrokerURL: "https://broker"}, sas); err == nil {
		t.Error("New accepted an empty default region")
	}
	if _, err := New(Config{BrokerURL: "https://broker", DefaultRegion: region}, nil); err == nil {
		t.Error("New accepted a nil service account lookup")
	}
	m, err := New(Config{BrokerURL: "https://broker", DefaultRegion: region}, sas)
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Config().BrokerURL; got != "https://broker/v1/credentials" {
		t.Errorf("Config().BrokerURL = %q", got)
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
