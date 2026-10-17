package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
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
