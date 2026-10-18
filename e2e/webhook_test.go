package e2e

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// What the webhook injects for enrolment in init mode (docs/design.md,
// section 7.2; agent/enrolapi is the contract): the init container, its
// token volume and the variables it reads, with the chart's defaults.
const (
	enrolVolume        = "cracha-enrol"
	enrolTokenDir      = "/var/run/secrets/cracha.dev/enrol"
	enrolTokenFile     = enrolTokenDir + "/token"
	enrolTokenAudience = "cracha-agent"
	enrolPort          = "9798"
	enrolTimeout       = "2m0s"
)

// sleeper is a pod that does nothing, for looking at what admission made of
// it.
func sleeper(name, serviceAccount string, env ...corev1.EnvVar) *corev1.Pod {
	grace := int64(0)
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: corev1.PodSpec{
			ServiceAccountName:            serviceAccount,
			RestartPolicy:                 corev1.RestartPolicyNever,
			TerminationGracePeriodSeconds: &grace,
			Containers: []corev1.Container{{
				Name:    "main",
				Image:   busybox,
				Command: []string{"sleep", "3600"},
				Env:     env,
			}},
		},
	}
}

func envValue(c corev1.Container, name string) (string, bool) {
	for _, e := range c.Env {
		if e.Name == name {
			return e.Value, true
		}
	}
	return "", false
}

func findVolume(pod *corev1.Pod, name string) (corev1.Volume, bool) {
	for _, v := range pod.Spec.Volumes {
		if v.Name == name {
			return v, true
		}
	}
	return corev1.Volume{}, false
}

func findMount(c corev1.Container, volume string) (corev1.VolumeMount, bool) {
	for _, m := range c.VolumeMounts {
		if m.Name == volume {
			return m, true
		}
	}
	return corev1.VolumeMount{}, false
}

// workloadContainers is every container of the pod that the pod itself
// declared: all of them but the enrolment init container.
func workloadContainers(pod *corev1.Pod) []corev1.Container {
	var out []corev1.Container
	for _, c := range append(pod.Spec.InitContainers, pod.Spec.Containers...) {
		if c.Name != enrolContainer {
			out = append(out, c)
		}
	}
	return out
}

// checkWired asserts the wiring of design 7.5 that both enrolment modes
// share: the label, and in every container the loopback endpoint and the
// region, with no token file and nothing mounted for the app.
func checkWired(t *testing.T, pod *corev1.Pod) {
	t.Helper()
	if pod.Labels[enrolLabel] != "true" {
		t.Errorf("labels = %v, want %s=true", pod.Labels, enrolLabel)
	}
	for _, c := range workloadContainers(pod) {
		for name, want := range map[string]string{
			"AWS_CONTAINER_CREDENTIALS_FULL_URI": credentialsURI,
			"AWS_REGION":                         region,
		} {
			if v, ok := envValue(c, name); !ok || v != want {
				t.Errorf("container %q: %s = %q (set %t), want %q", c.Name, name, v, ok, want)
			}
		}
		for _, e := range c.Env {
			if strings.HasPrefix(e.Name, "AWS_CONTAINER_AUTHORIZATION") {
				t.Errorf("container %q got %s=%q; the pod holds no token", c.Name, e.Name, e.Value)
			}
		}
		if _, ok := findMount(c, enrolVolume); ok {
			t.Errorf("container %q mounts the %q volume; only the enrolment init container may", c.Name, enrolVolume)
		}
	}
}

// checkEnrolInjected asserts the init mode's enrolment: the init container
// first in the list, from the agent's image, with the environment the
// agent's `enrol` reads, and its projected token mounted into it alone.
func checkEnrolInjected(ctx context.Context, t *testing.T, pod *corev1.Pod) {
	t.Helper()
	if len(pod.Spec.InitContainers) == 0 || pod.Spec.InitContainers[0].Name != enrolContainer {
		t.Fatalf("init containers = %+v, want %s first", pod.Spec.InitContainers, enrolContainer)
	}
	c := pod.Spec.InitContainers[0]
	if want := agentImage(ctx, t); c.Image != want {
		t.Errorf("%s image = %q, want the agent's, %q", enrolContainer, c.Image, want)
	}
	if len(c.Args) != 1 || c.Args[0] != "enrol" {
		t.Errorf("%s args = %v, want [enrol]", enrolContainer, c.Args)
	}
	for name, want := range map[string]string{
		"CRACHA_ENROL_PORT":       enrolPort,
		"CRACHA_AGENT_PORT":       fmt.Sprint(agentPort),
		"CRACHA_ENROL_TIMEOUT":    enrolTimeout,
		"CRACHA_ENROL_TOKEN_FILE": enrolTokenFile,
	} {
		if v, ok := envValue(c, name); !ok || v != want {
			t.Errorf("%s: %s = %q (set %t), want %q", enrolContainer, name, v, ok, want)
		}
	}
	hostIP := false
	for _, e := range c.Env {
		if e.Name == "CRACHA_HOST_IP" && e.ValueFrom != nil && e.ValueFrom.FieldRef != nil && e.ValueFrom.FieldRef.FieldPath == "status.hostIP" {
			hostIP = true
		}
	}
	if !hostIP {
		t.Errorf("%s env = %+v, want CRACHA_HOST_IP from status.hostIP", enrolContainer, c.Env)
	}
	if m, ok := findMount(c, enrolVolume); !ok || m.MountPath != enrolTokenDir || !m.ReadOnly {
		t.Errorf("%s mounts %+v, want %q read-only at %s", enrolContainer, c.VolumeMounts, enrolVolume, enrolTokenDir)
	}
	if c.SecurityContext == nil || c.SecurityContext.RunAsNonRoot == nil || !*c.SecurityContext.RunAsNonRoot {
		t.Errorf("%s security context = %+v, want non-root", enrolContainer, c.SecurityContext)
	}
	v, ok := findVolume(pod, enrolVolume)
	if !ok {
		t.Fatalf("no %q volume; volumes: %+v", enrolVolume, pod.Spec.Volumes)
	}
	if v.Projected == nil || len(v.Projected.Sources) != 1 || v.Projected.Sources[0].ServiceAccountToken == nil {
		t.Fatalf("volume %q = %+v, want one projected ServiceAccount token", enrolVolume, v.VolumeSource)
	}
	tok := v.Projected.Sources[0].ServiceAccountToken
	if tok.Audience != enrolTokenAudience || tok.ExpirationSeconds == nil || *tok.ExpirationSeconds != 600 || tok.Path != "token" {
		t.Errorf("projected token = %+v, want audience %s, 600 s, path token", tok, enrolTokenAudience)
	}
}

// checkNothingEnrolInjected asserts the cni mode's pod spec: nothing but
// the variables and the label entered it.
func checkNothingEnrolInjected(t *testing.T, pod *corev1.Pod) {
	t.Helper()
	for _, c := range pod.Spec.InitContainers {
		if c.Name == enrolContainer {
			t.Errorf("init container %q was injected in cni mode", enrolContainer)
		}
	}
	if _, ok := findVolume(pod, enrolVolume); ok {
		t.Errorf("volume %q was injected in cni mode", enrolVolume)
	}
}

// The webhook (docs/design.md, section 7.5): a pod of an enabled
// ServiceAccount gets the label, the loopback endpoint and the region in
// every container and, in init mode, the enrolment init container; a pod
// of any other ServiceAccount is left alone; a pod that brings its own AWS
// credentials, runs in the host's network or carries the enrolment
// container's name is refused.
func TestWebhookWiresEnabledPods(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	t.Run("enabled", func(t *testing.T) {
		pod := sleeper("enabled", assignedSA)
		pod.Spec.InitContainers = []corev1.Container{{
			Name:    "init",
			Image:   busybox,
			Command: []string{"true"},
		}}
		got := mustCreatePod(ctx, t, pod)
		checkWired(t, got)
		if n := len(workloadContainers(got)); n != 2 {
			t.Errorf("the pod's own containers = %d, want its init container and its container", n)
		}
		switch enrolMode() {
		case enrolInit:
			checkEnrolInjected(ctx, t, got)
		case enrolCNI:
			checkNothingEnrolInjected(t, got)
		}
	})

	t.Run("not enabled", func(t *testing.T) {
		got := mustCreatePod(ctx, t, sleeper("plain", "default"))
		if _, ok := got.Labels[enrolLabel]; ok {
			t.Errorf("labels = %v, want no %s", got.Labels, enrolLabel)
		}
		if len(got.Spec.InitContainers) != 0 {
			t.Errorf("init containers = %+v, want none", got.Spec.InitContainers)
		}
		if _, ok := findVolume(got, enrolVolume); ok {
			t.Errorf("a %q volume was injected into a pod of the default ServiceAccount", enrolVolume)
		}
		for _, c := range got.Spec.Containers {
			if len(c.Env) != 0 {
				t.Errorf("container %q got env %v", c.Name, c.Env)
			}
		}
	})

	t.Run("conflicting env is refused", func(t *testing.T) {
		_, err := createPod(ctx, sleeper("conflicting", assignedSA, corev1.EnvVar{Name: "AWS_ACCESS_KEY_ID", Value: "AKIAEXAMPLE"}))
		if err == nil {
			t.Fatal("a pod setting AWS_ACCESS_KEY_ID was admitted")
		}
		for _, want := range []string{"pods.cracha.dev", "AWS_ACCESS_KEY_ID", "conflicts"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("refusal %q does not mention %q", err, want)
			}
		}
	})

	t.Run("host network is refused", func(t *testing.T) {
		pod := sleeper("hostnet", assignedSA)
		pod.Spec.HostNetwork = true
		_, err := createPod(ctx, pod)
		if err == nil {
			t.Fatal("a pod with hostNetwork was admitted; its listener would serve the whole node (design 7.1)")
		}
		for _, want := range []string{"pods.cracha.dev", "hostNetwork"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("refusal %q does not mention %q", err, want)
			}
		}
	})

	t.Run("the enrolment container's name is reserved", func(t *testing.T) {
		pod := sleeper("reserved", assignedSA)
		pod.Spec.InitContainers = []corev1.Container{{
			Name:    enrolContainer,
			Image:   busybox,
			Command: []string{"true"},
		}}
		_, err := createPod(ctx, pod)
		if err == nil {
			t.Fatalf("a pod carrying its own %q init container was admitted", enrolContainer)
		}
		for _, want := range []string{"pods.cracha.dev", enrolContainer, "reserved"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("refusal %q does not mention %q", err, want)
			}
		}
	})
}

// The per-namespace region override (docs/design.md, section 7.5): a pod of
// a namespace annotated cracha.dev/region gets that region, a pod of the e2e
// namespace keeps the chart's webhook.defaultRegion, and an annotation that
// is not a region refuses the namespace's pods. The namespace is the test's
// own, wired like the e2e namespace (an enabled ServiceAccount of the same
// name) and deleted after. Only admission is exercised: e2e/spire.sh
// registers no identity for it, so its pods get no credentials, and the
// injection is read from the pod as the apiserver persisted it.
func TestWebhookNamespaceRegion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	const (
		regionNamespace = "e2e-region"
		override        = "sa-east-1"
	)

	// A previous run on a kept cluster may still be tearing it down.
	if err := deleteNamespace(ctx, regionNamespace, true); err != nil {
		t.Fatalf("removing the namespace of a previous run: %v", err)
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name:        regionNamespace,
		Labels:      map[string]string{suiteLabel: "true"},
		Annotations: map[string]string{"cracha.dev/region": override},
	}}
	if _, err := client.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating namespace %s: %v", regionNamespace, err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := deleteNamespace(ctx, regionNamespace, false); err != nil {
			t.Logf("deleting namespace %s: %v", regionNamespace, err)
		}
	})
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{
		Name:        assignedSA,
		Namespace:   regionNamespace,
		Annotations: map[string]string{"cracha.dev/enabled": "true"},
	}}
	if _, err := client.CoreV1().ServiceAccounts(regionNamespace).Create(ctx, sa, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating service account %s/%s: %v", regionNamespace, assignedSA, err)
	}

	// admitted creates a pod in the annotated namespace and returns what
	// the webhook made of it, or the refusal.
	admitted := func() (*corev1.Pod, error) {
		pod := sleeper("", assignedSA)
		pod.GenerateName = "region-"
		return createPodIn(ctx, regionNamespace, pod)
	}

	t.Run("annotated namespace", func(t *testing.T) {
		// The webhook serves the override from a watch on the namespaces,
		// which may not have seen one created a moment ago: a pod admitted
		// before that gets the default, so ask again with a fresh pod.
		var got *corev1.Pod
		err := eventually(ctx, func() error {
			pod, err := admitted()
			if err != nil {
				return err
			}
			got = pod
			if v, _ := envValue(pod.Spec.Containers[0], "AWS_REGION"); v != override {
				return fmt.Errorf("pod %s got AWS_REGION %q, want %q", pod.Name, v, override)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("no pod of namespace %s got the annotated region: %v", regionNamespace, err)
		}
		if got.Labels[enrolLabel] != "true" {
			t.Errorf("labels = %v, want %s=true; the override must not change the rest of the wiring", got.Labels, enrolLabel)
		}
		if v, _ := envValue(got.Spec.Containers[0], "AWS_CONTAINER_CREDENTIALS_FULL_URI"); v != credentialsURI {
			t.Errorf("AWS_CONTAINER_CREDENTIALS_FULL_URI = %q, want %q", v, credentialsURI)
		}
	})

	t.Run("e2e namespace keeps the default", func(t *testing.T) {
		got := mustCreatePod(ctx, t, sleeper("default-region", assignedSA))
		if v, ok := envValue(got.Spec.Containers[0], "AWS_REGION"); !ok || v != region {
			t.Errorf("AWS_REGION = %q (set %t), want the chart's default %q", v, ok, region)
		}
	})

	t.Run("an annotation that is not a region refuses", func(t *testing.T) {
		ns, err := client.CoreV1().Namespaces().Get(ctx, regionNamespace, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		ns.Annotations["cracha.dev/region"] = "nowhere"
		if _, err := client.CoreV1().Namespaces().Update(ctx, ns, metav1.UpdateOptions{}); err != nil {
			t.Fatalf("annotating namespace %s: %v", regionNamespace, err)
		}
		var refusal error
		err = eventually(ctx, func() error {
			pod, err := admitted()
			if err == nil {
				// Admitted before the watch saw the change.
				return fmt.Errorf("pod %s was admitted with AWS_REGION %q", pod.Name, pod.Spec.Containers[0].Env)
			}
			refusal = err
			return nil
		})
		if err != nil {
			t.Fatalf("no pod of namespace %s was refused: %v", regionNamespace, err)
		}
		if !apierrors.IsInvalid(refusal) {
			t.Errorf("refused with %v, want Invalid", refusal)
		}
		for _, want := range []string{"pods.cracha.dev", "cracha.dev/region", `"nowhere"`, "not an AWS region"} {
			if !strings.Contains(refusal.Error(), want) {
				t.Errorf("refusal %q does not mention %q", refusal, want)
			}
		}
	})
}

// deleteNamespace deletes a namespace of the suite's, if it exists, and
// waits for it to be gone when asked.
func deleteNamespace(ctx context.Context, name string, wait bool) error {
	namespaces := client.CoreV1().Namespaces()
	err := namespaces.Delete(ctx, name, metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil || !wait {
		return err
	}
	return eventually(ctx, func() error {
		_, err := namespaces.Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		return fmt.Errorf("namespace %s still terminating", name)
	})
}
