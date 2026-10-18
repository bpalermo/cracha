package e2e

import (
	"context"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bazelbuild/rules_go/go/runfiles"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/bpalermo/cracha/common/grant"
)

// The static mode of the suite (E2E_AUTHZ=static, the default): the
// broker's assignments are the ones grantc compiled from e2e/grants and
// published with the bundle, in the ConfigMap the broker polls
// (broker.assignments.source published). The test here republishes the
// tree the way a grant repository's pipeline would, compiled, signed and
// published as a new version, and the running broker takes it at its next
// poll, with no restart and no change to its pod. It runs the assigned
// workload's identity through STS, so it is in a file that sorts after
// credentials_test.go, whose test counts that identity's AssumeRole calls.

const (
	// bundleKeyEnv names the private key run.sh signed the publication
	// with.
	bundleKeyEnv = "E2E_BUNDLE_KEY"
	// grantcRlocation is the grant compiler built from this checkout, in
	// the test's runfiles (data of //e2e:e2e_test).
	grantcRlocation = "_main/grantc/grantc_/cracha-grantc"
	// republishedVersion is the version a test republishes under: the
	// broker's bundle volume lays it out, optionally, under ConfigMap keys
	// prefixed with it (e2e/run.sh).
	republishedVersion = "e2e-republished"

	msgBundleLoaded = "grant bundle loaded"
	staticMode      = "static"
	nudgeAnnotation = "e2e.cracha.dev/nudge"
)

// requireStatic skips the test outside static mode.
func requireStatic(t *testing.T) {
	t.Helper()
	if mode := os.Getenv(authzEnv); mode != "" && mode != staticMode {
		t.Skipf("%s=%q: the broker's assignments are not the published ones", authzEnv, mode)
	}
	if os.Getenv(bundleKeyEnv) == "" {
		t.Fatalf("%s is not set; e2e/run.sh sets it", bundleKeyEnv)
	}
}

// grantc runs the grant compiler built from this checkout.
func grantc(ctx context.Context, t *testing.T, args ...string) {
	t.Helper()
	bin, err := runfiles.Rlocation(grantcRlocation)
	if err != nil {
		t.Fatalf("grantc is not in the runfiles: %v", err)
	}
	out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
	t.Logf("cracha-grantc %s:\n%s", strings.Join(args, " "), strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatalf("cracha-grantc %s: %v", args[0], err)
	}
}

// publication compiles a tree under republishedVersion, signs both
// documents with run.sh's key and publishes them, and returns the
// ConfigMap data that carries the new version beside the one in service:
// its documents under the slot's keys, and its latest pointer.
func publication(ctx context.Context, t *testing.T, tree string, current map[string]string) map[string]string {
	t.Helper()
	return mixedPublication(ctx, t, tree, tree, current)
}

// mixedPublication is publication with the bundle compiled from one tree
// and the assignments from another, under the same version and signed
// with the same key: assignments the lints of the bundle's tree never saw,
// as a writer other than the Git pipeline could produce them, for the
// tests of what the broker checks at issuance whatever the lints did.
func mixedPublication(ctx context.Context, t *testing.T, bundleTree, assignmentsTree string, current map[string]string) map[string]string {
	t.Helper()
	dir := t.TempDir()
	bundle, assignments := filepath.Join(dir, grant.BundleFile), filepath.Join(dir, grant.AssignmentsFile)
	grantc(ctx, t, "compile", "-o", bundle, "-version", republishedVersion, bundleTree)
	if assignmentsTree != bundleTree {
		other := t.TempDir()
		grantc(ctx, t, "compile", "-o", filepath.Join(other, grant.BundleFile), "-version", republishedVersion, assignmentsTree)
		data, err := os.ReadFile(filepath.Join(other, grant.AssignmentsFile))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(assignments, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	grantc(ctx, t, "sign", "-key", os.Getenv(bundleKeyEnv), bundle, assignments)
	published := filepath.Join(dir, "published")
	grantc(ctx, t, "publish", "-dir", published, bundle, assignments)
	data := maps.Clone(current)
	files := map[string]string{latestKey: grant.LatestFile}
	for _, name := range []string{grant.BundleFile, grant.SignatureFile, grant.AssignmentsFile, grant.AssignmentsSignatureFile} {
		files[republishedVersion+"."+name] = filepath.Join("bundles", republishedVersion, name)
	}
	for key, rel := range files {
		content, err := os.ReadFile(filepath.Join(published, rel))
		if err != nil {
			t.Fatal(err)
		}
		data[key] = string(content)
	}
	return data
}

// bundleData is the ConfigMap's data as it is now.
func bundleData(ctx context.Context, t *testing.T) map[string]string {
	t.Helper()
	cm, err := client.CoreV1().ConfigMaps(systemNamespace).Get(ctx, bundleConfigMap, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return cm.Data
}

// setBundleData replaces the ConfigMap's data, then has the kubelet
// refresh the broker pods' volumes at once: a change to a pod's
// annotations makes the kubelet sync the pod, ConfigMap volumes included,
// rather than at its next periodic sync, up to a minute and more later.
// The pods are neither restarted nor changed otherwise.
func setBundleData(ctx context.Context, t *testing.T, data map[string]string) {
	t.Helper()
	cm, err := client.CoreV1().ConfigMaps(systemNamespace).Get(ctx, bundleConfigMap, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cm.Data = data
	if _, err := client.CoreV1().ConfigMaps(systemNamespace).Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	pods, err := client.CoreV1().Pods(systemNamespace).List(ctx, metav1.ListOptions{LabelSelector: brokerSelector})
	if err != nil {
		t.Fatal(err)
	}
	patch := fmt.Sprintf(`{"metadata":{"annotations":{%q:%q}}}`, nudgeAnnotation, time.Now().Format(time.RFC3339Nano))
	for _, p := range pods.Items {
		if _, err := client.CoreV1().Pods(systemNamespace).Patch(ctx, p.Name, types.MergePatchType, []byte(patch), metav1.PatchOptions{}); err != nil {
			t.Fatal(err)
		}
	}
}

// waitForVersion waits for the broker to log that it put the version in
// service after since.
func waitForVersion(ctx context.Context, t *testing.T, since time.Time, version string) {
	t.Helper()
	err := eventually(ctx, func() error {
		lines, err := brokerLogs(ctx)
		if err != nil {
			return err
		}
		for _, l := range lines {
			if l.Msg == msgBundleLoaded && l.NewVersion == version && l.Time.After(since) {
				t.Logf("broker: %s %s (services %d, workloads %d) %s after the publication",
					l.Msg, l.NewVersion, l.Services, l.Workloads, l.Time.Sub(since).Round(time.Millisecond))
				return nil
			}
		}
		return fmt.Errorf("the broker has not loaded version %s since %s", version, since.Format(time.RFC3339))
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Revocation through the publication (design 6.2, 6.3): the client's
// service loses its grant in a copy of the tree, which is compiled, signed
// and published as a new version; the running broker loads it at its next
// poll and refuses the next fetch, its cache flushed by the static store's
// Watch. Publishing the tree as run.sh did gives the grant back.
func TestPublishedAssignmentsTakeEffect(t *testing.T) {
	requireStatic(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	original := bundleData(ctx, t)
	originalVersion, err := publishedBundleVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pod := runFetchingWorkload(ctx, t, "republished")
	waitForFetch(ctx, t, pod, time.Time{}, "a cache hit", func(e *exchange) bool {
		return e.Status == 200 && strings.Join(e.Headers[headerCache], ",") == cacheOutcomeHit
	})

	restored := false
	restore := func(ctx context.Context) {
		at := time.Now()
		setBundleData(ctx, t, original)
		waitForVersion(ctx, t, at, originalVersion)
		restored = true
	}
	t.Cleanup(func() {
		if !restored {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			restore(ctx)
		}
	})

	publishedAt := time.Now()
	setBundleData(ctx, t, publication(ctx, t, modifiedSource(t, withoutGrant), original))
	waitForVersion(ctx, t, publishedAt, republishedVersion)
	denied := waitForFetch(ctx, t, pod, publishedAt, "a refusal", status(403))
	if r := denied.Exchange.reason(); r != reasonNoGrant {
		t.Errorf("refused with %q, want %q: %s", r, reasonNoGrant, denied.Exchange.Body)
	}
	t.Logf("refused %s after the publication", denied.At.Sub(publishedAt).Round(time.Millisecond))
	lines, err := brokerLogs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	flushed := false
	for _, l := range lines {
		if l.Msg == msgInvalidated && l.Time.After(publishedAt) && l.Entries > 0 && l.Subject == "" {
			flushed = true
		}
	}
	if !flushed {
		t.Errorf("the broker did not log a Watch invalidation of every subject after the publication at %s", publishedAt.Format(time.RFC3339))
	}

	restoredAt := time.Now()
	restore(ctx)
	back := waitForFetch(ctx, t, pod, restoredAt, "credentials again", status(200))
	if got := strings.Join(back.Exchange.Headers["Cracha-Bundle-Version"], ","); got != originalVersion {
		t.Errorf("Cracha-Bundle-Version = %q after the restore, want %q", got, originalVersion)
	}
	if got := strings.Join(back.Exchange.Headers["Cracha-Grants"], ","); got != grantName {
		t.Errorf("Cracha-Grants = %q after the restore, want %q", got, grantName)
	}
}
