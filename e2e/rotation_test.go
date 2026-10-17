package e2e

import (
	"context"
	"fmt"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Rotation (docs/design.md, section 7.3): kubelet republishes the volume
// periodically and the plugin replaces the token once less than half its
// lifetime remains, without the pod noticing. The client prints a line
// whenever the file changes; the first replacement lands between half the
// lifetime and half the lifetime plus kubelet's republish period (60-90 s)
// after the first token was issued.
func TestTokenIsRotated(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), jwtTTL+2*time.Minute)
	defer cancel()
	pod, rep := assignedWorkload(ctx, t)
	if rep.Token == nil || rep.Token.Error != "" {
		t.Fatalf("the client could not read its first token: %+v", rep.Token)
	}
	first := *rep.Token

	var next *tokenLine
	err := eventually(ctx, func() error {
		logs, err := podLogs(ctx, testNamespace, pod.Name, "client")
		if err != nil {
			return err
		}
		lines, err := jsonLines[tokenLine](logs, "token")
		if err != nil {
			return err
		}
		for i := range lines {
			if lines[i].Changed && lines[i].Iat > first.Iat {
				next = &lines[i]
				return nil
			}
			if lines[i].Error != "" {
				return fmt.Errorf("the client could not read the token: %s", lines[i].Error)
			}
		}
		return fmt.Errorf("no replacement yet; the first token was issued %s ago",
			time.Since(time.Unix(first.Iat, 0)).Round(time.Second))
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("token replaced %s after the first one was issued", time.Duration(next.Iat-first.Iat)*time.Second)

	if next.Subject != first.Subject {
		t.Errorf("the replacement's sub = %q, want %q", next.Subject, first.Subject)
	}
	if lifetime := time.Duration(next.Exp-next.Iat) * time.Second; lifetime != jwtTTL {
		t.Errorf("the replacement's lifetime = %s, want %s", lifetime, jwtTTL)
	}
	// The old token was still valid when it was replaced.
	if next.Iat >= first.Exp {
		t.Errorf("the replacement was issued at %d, after the first token expired at %d", next.Iat, first.Exp)
	}
	if elapsed := time.Duration(next.Iat-first.Iat) * time.Second; elapsed < jwtTTL/2-5*time.Second {
		t.Errorf("replaced after %s, before half the lifetime (%s)", elapsed, jwtTTL/2)
	}
	current, err := client.CoreV1().Pods(testNamespace).Get(ctx, pod.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	restarts := int32(0)
	for _, s := range current.Status.ContainerStatuses {
		restarts += s.RestartCount
	}
	if restarts != 0 {
		t.Errorf("the container restarted %d times; rotation must not need a restart", restarts)
	}
}
