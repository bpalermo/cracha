package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bazelbuild/rules_go/go/runfiles"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The SpiceDB mode of the suite (E2E_AUTHZ=spicedb in e2e/run.sh): the
// broker's authorization backend is the SpiceDB run.sh deployed, with the
// relationships cracha-reconciler wrote from e2e/grants. The tests here run
// only in that mode; the rest of the suite runs in both. They change the
// relationships through the reconciler, the writer of design 6.4, against
// the port-forward run.sh keeps open, and put them back when they are
// done, so the tests after them and a reused cluster see the tree as
// run.sh wrote it.

const (
	// authzEnv names the mode run.sh ran the suite in; spicedbEndpointEnv
	// and spicedbTokenEnv are how to reach the SpiceDB it deployed from the
	// host: the port-forward's address and the file with the preshared key.
	authzEnv           = "E2E_AUTHZ"
	spicedbEndpointEnv = "E2E_SPICEDB_ENDPOINT"
	spicedbTokenEnv    = "E2E_SPICEDB_TOKEN_FILE"
	spicedbMode        = "spicedb"

	// reconcilerRlocation is the reconciler built from this checkout, in
	// the test's runfiles (data of //e2e:e2e_test).
	reconcilerRlocation = "_main/reconciler/reconciler_/cracha-reconciler"
	// grantSource is the tree run.sh compiled and reconciled, relative to
	// the package directory the test runs in.
	grantSource = "grants"
	// serviceDocument is the document of grantSource that assigns the
	// client its grant.
	serviceDocument = "services/e2e-client.yaml"

	// fetchInterval is how often a fetching workload asks the broker for
	// credentials again; revocationBudget is how long after the write a
	// refusal must show, against a session lifetime of 3600 s (e2e/grants)
	// and a cache floor of 20 minutes: a refusal inside it did not wait for
	// anything to expire.
	fetchInterval    = 2 * time.Second
	revocationBudget = 30 * time.Second

	brokerSelector = "app.kubernetes.io/name=cracha,app.kubernetes.io/component=broker"
)

// What the broker logs about the cache's mode (broker/internal/cache).
const (
	msgCacheOn       = "credential cache on"
	msgWatchDown     = "authorization store watch down; cache in ttl mode until it returns"
	msgWatchRestored = "authorization store watch restored; cache in watch mode"
	msgInvalidated   = "invalidated cached credentials from the authorization store's watch"
	cacheModeWatch   = "watch"
	cacheOutcomeHit  = "hit"
	cacheOutcomeMiss = "miss"
	reasonSuspended  = "subject_suspended"
	reasonNoGrant    = "no_grant"
	headerCache      = "Cracha-Cache"
)

// requireSpiceDB skips the test outside spicedb mode.
func requireSpiceDB(t *testing.T) {
	t.Helper()
	if mode := os.Getenv(authzEnv); mode != spicedbMode {
		t.Skipf("%s=%q: the authorization backend is not SpiceDB; run E2E_AUTHZ=spicedb e2e/run.sh", authzEnv, mode)
	}
	for _, name := range []string{spicedbEndpointEnv, spicedbTokenEnv} {
		if os.Getenv(name) == "" {
			t.Fatalf("%s is not set; e2e/run.sh sets it in spicedb mode", name)
		}
	}
}

// fetchLine is what e2e/client prints per fetch of its own.
type fetchLine struct {
	Kind     string    `json:"kind"`
	At       time.Time `json:"at"`
	Exchange *exchange `json:"exchange"`
	Error    string    `json:"error"`
}

// brokerLine is a line of the broker's JSON log, with the fields the tests
// here read.
type brokerLine struct {
	Time    time.Time `json:"time"`
	Msg     string    `json:"msg"`
	Mode    string    `json:"mode"`
	Entries int       `json:"entries"`
	Subject string    `json:"subject"`
	Grant   string    `json:"grant"`
	Client  string    `json:"client"`
	Path    string    `json:"path"`
	Status  int       `json:"status"`
	// Duration is how long the broker took over a request.
	Duration time.Duration `json:"duration"`
	// What a bundle load reports (broker/internal/bundle).
	NewVersion string `json:"new_version"`
	Services   int    `json:"services"`
	Workloads  int    `json:"workloads"`
}

// brokerLogs returns every JSON line of every broker pod's log, in order.
func brokerLogs(ctx context.Context) ([]brokerLine, error) {
	pods, err := client.CoreV1().Pods(systemNamespace).List(ctx, metav1.ListOptions{LabelSelector: brokerSelector})
	if err != nil {
		return nil, fmt.Errorf("listing the broker's pods: %w", err)
	}
	var out []brokerLine
	for _, p := range pods.Items {
		logs, err := podLogs(ctx, systemNamespace, p.Name, "")
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(logs, "\n") {
			var l brokerLine
			if strings.HasPrefix(line, "{") && json.Unmarshal([]byte(line), &l) == nil && l.Msg != "" {
				out = append(out, l)
			}
		}
	}
	return out, nil
}

// reconcile runs cracha-reconciler apply on a tree against the SpiceDB
// run.sh deployed, and fails the test when it does not converge.
func reconcile(ctx context.Context, t *testing.T, tree string) {
	t.Helper()
	bin, err := runfiles.Rlocation(reconcilerRlocation)
	if err != nil {
		t.Fatalf("the reconciler is not in the runfiles: %v", err)
	}
	cmd := exec.CommandContext(ctx, bin, "apply", "-source", tree,
		"-endpoint", os.Getenv(spicedbEndpointEnv), "-token-file", os.Getenv(spicedbTokenEnv), "-insecure")
	out, err := cmd.CombinedOutput()
	t.Logf("cracha-reconciler apply -source %s:\n%s", tree, strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatalf("reconciling %s: %v", tree, err)
	}
}

// restoreSource puts the relationships back as run.sh wrote them, whatever
// happened, on its own clock: the test's context may be spent.
func restoreSource(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		reconcile(ctx, t, grantSource)
	})
}

// modifiedSource copies the suite's grant source tree into a temporary
// directory and applies edit to it, for a reconcile that changes one thing.
// The copy is of the files' contents: in the runfiles the tree is symbolic
// links to the checkout, and os.CopyFS would reproduce the links, so an
// edit would go through to the checkout.
func modifiedSource(t *testing.T, edit func(dir string) error) string {
	t.Helper()
	dir := t.TempDir()
	src := os.DirFS(grantSource)
	err := fs.WalkDir(src, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dir, path), 0o755)
		}
		data, err := fs.ReadFile(src, path)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dir, path), data, 0o644)
	})
	if err != nil {
		t.Fatalf("copying %s: %v", grantSource, err)
	}
	if err := edit(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

// withoutGrant is the tree with the client's service holding no grant: the
// assignment removed, the membership and so the tags kept.
func withoutGrant(dir string) error {
	return os.WriteFile(filepath.Join(dir, serviceDocument), []byte(`kind: Service
metadata:
  name: e2e-client
spec:
  team: platform
  members: [cracha/e2e/client]
`), 0o644)
}

// withSuspension is the tree with the client suspended: an Assignment that
// gives nothing and takes everything away, until it is removed.
func withSuspension(dir string) error {
	if err := os.MkdirAll(filepath.Join(dir, "assignments"), 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "assignments", "suspend-client.yaml"), []byte(`kind: Assignment
metadata:
  name: suspend-client
spec:
  subject: cracha/e2e/client
  suspended: true
`), 0o644)
}

// runFetchingWorkload starts the assigned workload with fetches at
// fetchInterval, and waits for its first credentials.
func runFetchingWorkload(ctx context.Context, t *testing.T, name string) *corev1.Pod {
	t.Helper()
	pod, rep := runWorkload(ctx, t, name, assignedSA, corev1.EnvVar{Name: "E2E_FETCH_INTERVAL", Value: fetchInterval.String()})
	if rep.Error != "" || rep.Credentials == nil {
		t.Fatalf("the workload got no credentials to begin with: %s (exchange: %+v)", rep.Error, rep.Exchange)
	}
	return pod
}

// waitForFetch polls the workload's log for the first fetch after since
// whose answer satisfies want, describing it as what.
func waitForFetch(ctx context.Context, t *testing.T, pod *corev1.Pod, since time.Time, what string, want func(*exchange) bool) *fetchLine {
	t.Helper()
	var found *fetchLine
	err := eventually(ctx, func() error {
		logs, err := podLogs(ctx, testNamespace, pod.Name, "client")
		if err != nil {
			return err
		}
		lines, err := jsonLines[fetchLine](logs, "fetch")
		if err != nil {
			return err
		}
		var last *fetchLine
		for i := range lines {
			if !lines[i].At.After(since) {
				continue
			}
			last = &lines[i]
			if lines[i].Exchange != nil && want(lines[i].Exchange) {
				found = &lines[i]
				return nil
			}
		}
		if last == nil {
			return fmt.Errorf("no fetch since %s yet", since.Format(time.RFC3339))
		}
		return fmt.Errorf("waiting for %s; the last fetch answered %+v (%s)", what, last.Exchange, last.Error)
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func status(code int) func(*exchange) bool {
	return func(e *exchange) bool { return e.Status == code }
}

// The broker reports its cache in watch mode: the store has Watch and the
// stream is up (design 6.7). The startup line says which mode the cache
// started in, and the stream's failures and recoveries are logged after
// it; the last word must be watch.
func TestSpiceDBCacheWatchMode(t *testing.T) {
	requireSpiceDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	lines, err := brokerLogs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mode := ""
	for _, l := range lines {
		switch l.Msg {
		case msgCacheOn:
			mode = l.Mode
		case msgWatchDown:
			mode = "ttl (" + msgWatchDown + ")"
		case msgWatchRestored:
			mode = cacheModeWatch
		}
	}
	if mode != cacheModeWatch {
		t.Fatalf("the broker's cache mode is %q, want %q", mode, cacheModeWatch)
	}
}

// Revocation, design 6.8 step 1: the assignment is removed in Git, the
// reconciler writes the difference, and the next fetch is refused, long
// before the session or the cache's floor would have run out; the Watch
// stream flushed the entry, which a TTL-only cache would have kept and
// served again once the assignment was back.
func TestSpiceDBRevocationViaWatch(t *testing.T) {
	requireSpiceDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	pod := runFetchingWorkload(ctx, t, "revoked")
	// Warm: a fetch served from the cache.
	waitForFetch(ctx, t, pod, time.Time{}, "a cache hit", func(e *exchange) bool {
		return e.Status == 200 && strings.Join(e.Headers[headerCache], ",") == cacheOutcomeHit
	})

	revokedAt := time.Now()
	restoreSource(t)
	reconcile(ctx, t, modifiedSource(t, withoutGrant))
	denied := waitForFetch(ctx, t, pod, revokedAt, "a refusal", status(403))
	if r := denied.Exchange.reason(); r != reasonNoGrant {
		t.Errorf("refused with %q, want %q: %s", r, reasonNoGrant, denied.Exchange.Body)
	}
	if took := denied.At.Sub(revokedAt); took > revocationBudget {
		t.Errorf("the refusal took %s after the write, want within %s", took.Round(time.Second), revocationBudget)
	} else {
		t.Logf("refused %s after the write", took.Round(time.Millisecond))
	}

	// The flush came from Watch: the broker logged it, after the write.
	lines, err := brokerLogs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	flushed := false
	for _, l := range lines {
		if l.Msg == msgInvalidated && l.Time.After(revokedAt.Add(-time.Second)) && l.Entries > 0 {
			flushed = true
			t.Logf("broker: %s (entries %d, subject %q, grant %q)", l.Msg, l.Entries, l.Subject, l.Grant)
		}
	}
	if !flushed {
		t.Errorf("the broker did not log a Watch invalidation after the write at %s", revokedAt.Format(time.RFC3339))
	}

	// Back: the first credentials are issued anew. A cache that had only
	// aged the entry out would have served it as a hit.
	restoredAt := time.Now()
	reconcile(ctx, t, grantSource)
	back := waitForFetch(ctx, t, pod, restoredAt, "credentials again", status(200))
	if got := strings.Join(back.Exchange.Headers[headerCache], ","); got != cacheOutcomeMiss {
		t.Errorf("%s = %q after the assignment came back, want %q: the Watch flush did not drop the entry", headerCache, got, cacheOutcomeMiss)
	}
}

// A suspended workload holds nothing, whatever its assignments say, and is
// refused with subject_suspended (design 6.4, 6.5); lifting the suspension
// gives it its grant back.
func TestSpiceDBSuspension(t *testing.T) {
	requireSpiceDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	pod := runFetchingWorkload(ctx, t, "suspended")

	suspendedAt := time.Now()
	restoreSource(t)
	reconcile(ctx, t, modifiedSource(t, withSuspension))
	denied := waitForFetch(ctx, t, pod, suspendedAt, "a refusal", status(403))
	if r := denied.Exchange.reason(); r != reasonSuspended {
		t.Errorf("refused with %q, want %q: %s", r, reasonSuspended, denied.Exchange.Body)
	}
	if took := denied.At.Sub(suspendedAt); took > revocationBudget {
		t.Errorf("the refusal took %s after the write, want within %s", took.Round(time.Second), revocationBudget)
	}

	liftedAt := time.Now()
	reconcile(ctx, t, grantSource)
	back := waitForFetch(ctx, t, pod, liftedAt, "credentials again", status(200))
	if got := strings.Join(back.Exchange.Headers["Cracha-Grants"], ","); got != grantName {
		t.Errorf("Cracha-Grants = %q after the suspension was lifted, want %q", got, grantName)
	}
}
