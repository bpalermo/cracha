package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// Resource-level access (design 6.2 and 6.4, Level 3) through the
// account's implicit grant. The reader holds one grant, e2e-s3-reader,
// which names its bucket; nothing assigns it another. The Account document
// of e2e/grants (accounts/e2e.yaml) says what reading a bucket of the
// account means, and its Access documents relate the reader's service to
// cracha-e2e-data and a workload that runs nowhere to cracha-e2e-other,
// the other bucket of the stub's world. The broker applies the implicit
// grant account:e2e:s3_bucket:read at issuance, rendered with the buckets
// it finds, and checks each against the account's envelope
// (arn:aws:s3:::cracha-e2e-*), on the account role, which e2e-s3-reader
// names as its own. The tests run in both modes: in static mode a change
// is a new publication (published_test.go's), in spicedb mode a reconcile
// (spicedb_test.go's), and both are put back.

const (
	lookupGrantName      = "account:e2e:s3_bucket:read"
	readerSession        = "w.cracha.e2e.reader"
	readerAccessDocument = "access/e2e-reader-data.yaml"
	accountDocument      = "accounts/e2e.yaml"
	reasonOutside        = "resource_outside_envelope"

	staticBucketARN = "arn:aws:s3:::cracha-e2e-bucket/*"
	dataBucketARN   = "arn:aws:s3:::cracha-e2e-data/*"
	otherBucketARN  = "arn:aws:s3:::cracha-e2e-other/*"
	outsideBucket   = "cracha-outside"
)

// bothGrants is Cracha-Grants for the reader with the implicit grant.
var bothGrants = lookupGrantName + ", " + grantName

// policyResources is every Resource of a session policy's statements,
// sorted.
func policyResources(t *testing.T, policy string) []string {
	t.Helper()
	var doc struct {
		Statement []struct {
			Resource json.RawMessage `json:"Resource"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(policy), &doc); err != nil {
		t.Fatalf("session policy is not a policy document: %v: %q", err, policy)
	}
	var out []string
	for _, st := range doc.Statement {
		var one string
		if json.Unmarshal(st.Resource, &one) == nil {
			out = append(out, one)
			continue
		}
		var many []string
		if err := json.Unmarshal(st.Resource, &many); err != nil {
			t.Fatalf("Resource %s: %v", st.Resource, err)
		}
		out = append(out, many...)
	}
	slices.Sort(out)
	return out
}

// lastReaderPolicy is the session policy of the stub's last AssumeRole for
// the reader received after since.
func lastReaderPolicy(ctx context.Context, t *testing.T, since time.Time) string {
	t.Helper()
	return lastReaderRequest(ctx, t, since).Policy
}

// lastReaderRequest is the stub's last AssumeRole for the reader received
// after since.
func lastReaderRequest(ctx context.Context, t *testing.T, since time.Time) stsRequest {
	t.Helper()
	var last stsRequest
	err := eventually(ctx, func() error {
		reqs, err := stubRequests(ctx, readerSession)
		if err != nil {
			return err
		}
		for i := len(reqs) - 1; i >= 0; i-- {
			if reqs[i].Received.After(since) {
				last = reqs[i]
				return nil
			}
		}
		return fmt.Errorf("the stub has recorded no AssumeRole for %s since %s", readerSession, since.Format(time.RFC3339))
	})
	if err != nil {
		t.Fatal(err)
	}
	return last
}

// fetchingReader starts the reader with fetches at fetchInterval and waits
// for its first credentials.
func fetchingReader(ctx context.Context, t *testing.T, name string) *corev1.Pod {
	t.Helper()
	pod, rep := runWorkload(ctx, t, name, readerSA, corev1.EnvVar{Name: "E2E_FETCH_INTERVAL", Value: fetchInterval.String()})
	if rep.Error != "" || rep.Credentials == nil {
		t.Fatalf("the reader got no credentials to begin with: %s (exchange: %+v)", rep.Error, rep.Exchange)
	}
	return pod
}

// changeTree puts a changed grant tree in force the way the mode does:
// in static mode a publication of its bundle and assignments (the bundle
// from bundleTree, which is usually the same tree), in spicedb mode a
// reconcile of its relationships (the broker's bundle is the one run.sh
// published, so bundleTree is not used). The tree run.sh used is put back
// when the test ends, or earlier through the function returned.
func changeTree(ctx context.Context, t *testing.T, bundleTree, tree string) (restore func(context.Context)) {
	t.Helper()
	if os.Getenv(authzEnv) == spicedbMode {
		restoreSource(t)
		reconcile(ctx, t, tree)
		return func(ctx context.Context) { reconcile(ctx, t, grantSource) }
	}
	requireStatic(t)
	original := bundleData(ctx, t)
	originalVersion, err := publishedBundleVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	restored := false
	restore = func(ctx context.Context) {
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
	at := time.Now()
	setBundleData(ctx, t, mixedPublication(ctx, t, bundleTree, tree, original))
	waitForVersion(ctx, t, at, republishedVersion)
	return restore
}

// withoutReaderAccess is the tree with the reader's service related to no
// bucket.
func withoutReaderAccess(dir string) error {
	return os.Remove(filepath.Join(dir, readerAccessDocument))
}

// withOutsideAccess is the tree with the reader's service also related to
// a bucket outside the account's envelope, and the envelope widened to it
// so that the tree passes the lints: the assignments and the
// relationships of this tree are put in force, the bundle (with the
// envelope as it was) is not.
func withOutsideAccess(dir string) error {
	err := os.WriteFile(filepath.Join(dir, "access", "e2e-reader-outside.yaml"), []byte(`kind: Access
metadata:
  name: e2e-reader-outside
spec:
  service: e2e-reader
  resource: { kind: s3_bucket, name: `+outsideBucket+` }
  relation: reader
`), 0o644)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, accountDocument)
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	widened := strings.Replace(string(data), "    - arn:aws:s3:::cracha-e2e-*\n", "    - arn:aws:s3:::cracha-e2e-*\n    - arn:aws:s3:::"+outsideBucket+"/*\n", 1)
	if widened == string(data) {
		return fmt.Errorf("%s: no envelope to widen", path)
	}
	return os.WriteFile(path, []byte(widened), 0o644)
}

// The account's implicit grant applies to the reader, which holds no grant
// naming it, and is rendered with the bucket the reader's Access document
// gives and nothing else: Cracha-Grants shows its generated name, and the
// session policy STS was asked for names e2e-s3-reader's own bucket and
// cracha-e2e-data, not cracha-e2e-other, which is related to another
// workload.
func TestImplicitGrantNamesRelatedBuckets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	start := time.Now()
	_, rep := runWorkload(ctx, t, "reader", readerSA)
	if rep.Error != "" || rep.Credentials == nil || rep.Exchange == nil {
		t.Fatalf("the reader got no credentials: %s (exchange: %+v)", rep.Error, rep.Exchange)
	}
	if got := strings.Join(rep.Exchange.Headers["Cracha-Grants"], ","); got != bothGrants {
		t.Errorf("Cracha-Grants = %q, want %q", got, bothGrants)
	}
	req := lastReaderRequest(ctx, t, start)
	if req.RoleArn != baseRole {
		t.Errorf("RoleArn = %q, want the account role %q", req.RoleArn, baseRole)
	}
	if want := lookupGrantName + "+" + grantName; req.Tags["grant"] != want {
		t.Errorf("session tag grant = %q, want %q", req.Tags["grant"], want)
	}
	got := policyResources(t, req.Policy)
	if want := []string{staticBucketARN, dataBucketARN}; !slices.Equal(got, want) {
		t.Errorf("session policy resources = %v, want %v", got, want)
	}
	if slices.Contains(got, otherBucketARN) {
		t.Errorf("the reader's session policy names %s, another workload's bucket", otherBucketARN)
	}
}

// The reader's Access document removed, the implicit grant has no bucket
// and does not apply: the reader keeps its grant, and its next credentials
// are for that grant alone, issued anew (the grant set and the resource
// set are part of the cache key). Put back, the implicit grant returns.
func TestImplicitGrantFollowsAccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	pod := fetchingReader(ctx, t, "reader-access")
	changedAt := time.Now()
	restore := changeTree(ctx, t, grantSource, modifiedSource(t, withoutReaderAccess))
	alone := waitForFetch(ctx, t, pod, changedAt, "credentials without the implicit grant", func(e *exchange) bool {
		return e.Status == 200 && strings.Join(e.Headers["Cracha-Grants"], ",") == grantName
	})
	t.Logf("the implicit grant left out %s after the change", alone.At.Sub(changedAt).Round(time.Millisecond))
	if got, want := policyResources(t, lastReaderPolicy(ctx, t, changedAt)), []string{staticBucketARN}; !slices.Equal(got, want) {
		t.Errorf("session policy resources without the access = %v, want %v", got, want)
	}

	restoredAt := time.Now()
	restore(ctx)
	waitForFetch(ctx, t, pod, restoredAt, "the implicit grant again", func(e *exchange) bool {
		return e.Status == 200 && strings.Join(e.Headers["Cracha-Grants"], ",") == bothGrants
	})
	if got, want := policyResources(t, lastReaderPolicy(ctx, t, restoredAt)), []string{staticBucketARN, dataBucketARN}; !slices.Equal(got, want) {
		t.Errorf("session policy resources with the access back = %v, want %v", got, want)
	}
}

// A bucket related to the reader outside the account's envelope is
// refused at issuance with resource_outside_envelope, whatever the lints
// of the tree that related it said (design 11: every rendered resource is
// checked against the envelope before STS is called).
func TestImplicitOutsideEnvelopeIsRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	pod := fetchingReader(ctx, t, "reader-outside")
	changedAt := time.Now()
	restore := changeTree(ctx, t, grantSource, modifiedSource(t, withOutsideAccess))
	denied := waitForFetch(ctx, t, pod, changedAt, "a refusal", status(403))
	if r := denied.Exchange.reason(); r != reasonOutside {
		t.Errorf("refused with %q, want %q: %s", r, reasonOutside, denied.Exchange.Body)
	}
	reqs, err := stubRequests(ctx, readerSession)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range reqs {
		if strings.Contains(r.Policy, outsideBucket) {
			t.Errorf("STS was asked for a session naming %s: %s", outsideBucket, r.Policy)
		}
	}

	restoredAt := time.Now()
	restore(ctx)
	waitForFetch(ctx, t, pod, restoredAt, "credentials again", status(200))
}
