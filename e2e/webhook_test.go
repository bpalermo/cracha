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

func hasVolume(pod *corev1.Pod) (corev1.Volume, bool) {
	for _, v := range pod.Spec.Volumes {
		if v.Name == volumeName {
			return v, true
		}
	}
	return corev1.Volume{}, false
}

func hasMount(c corev1.Container) (corev1.VolumeMount, bool) {
	for _, m := range c.VolumeMounts {
		if m.Name == volumeName {
			return m, true
		}
	}
	return corev1.VolumeMount{}, false
}

// The webhook (docs/design.md, section 7.4): a pod of an enabled
// ServiceAccount gets the volume and the environment in every container, a
// pod of any other ServiceAccount is left alone, and a pod that brings its
// own AWS credentials is refused.
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

		if got.Annotations["cracha.dev/injected"] != "true" {
			t.Errorf("annotations = %v, want cracha.dev/injected=true", got.Annotations)
		}
		v, ok := hasVolume(got)
		if !ok {
			t.Fatalf("no %q volume; volumes: %+v", volumeName, got.Spec.Volumes)
		}
		if v.CSI == nil || v.CSI.Driver != driverName || v.CSI.ReadOnly == nil || !*v.CSI.ReadOnly {
			t.Errorf("volume %q = %+v, want a read-only %s CSI volume", volumeName, v.VolumeSource, driverName)
		}
		for _, c := range append(got.Spec.InitContainers, got.Spec.Containers...) {
			m, ok := hasMount(c)
			if !ok {
				t.Errorf("container %q has no %q mount", c.Name, volumeName)
			} else if m.MountPath != mountPath || !m.ReadOnly {
				t.Errorf("container %q mounts %q at %s read-only=%t, want %s read-only", c.Name, volumeName, m.MountPath, m.ReadOnly, mountPath)
			}
			for name, want := range map[string]string{
				"AWS_CONTAINER_CREDENTIALS_FULL_URI":     credentialsURI,
				"AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE": tokenPath,
				"AWS_REGION":                             region,
			} {
				if v, ok := envValue(c, name); !ok || v != want {
					t.Errorf("container %q: %s = %q (set %t), want %q", c.Name, name, v, ok, want)
				}
			}
		}
	})

	t.Run("not enabled", func(t *testing.T) {
		got := mustCreatePod(ctx, t, sleeper("plain", "default"))
		if _, ok := got.Annotations["cracha.dev/injected"]; ok {
			t.Errorf("annotations = %v, want no cracha.dev/injected", got.Annotations)
		}
		if _, ok := hasVolume(got); ok {
			t.Errorf("a %q volume was injected into a pod of the default ServiceAccount", volumeName)
		}
		for _, c := range got.Spec.Containers {
			if _, ok := hasMount(c); ok {
				t.Errorf("container %q got a %q mount", c.Name, volumeName)
			}
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
}

// The per-namespace region override (docs/design.md, section 7.4): a pod of
// a namespace annotated cracha.dev/region gets that region, a pod of the e2e
// namespace keeps the chart's webhook.defaultRegion, and an annotation that
// is not a region refuses the namespace's pods. The namespace is the test's
// own, wired like the e2e namespace (an enabled ServiceAccount of the same
// name) and deleted after. Only admission is exercised: e2e/spire.sh
// registers no identity for it, so its pods never start, and the injection
// is read from the pod as the apiserver persisted it.
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
		if got.Annotations["cracha.dev/injected"] != "true" {
			t.Errorf("annotations = %v, want cracha.dev/injected=true", got.Annotations)
		}
		if _, ok := hasVolume(got); !ok {
			t.Errorf("no %q volume; the override must not change the rest of the wiring", volumeName)
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
