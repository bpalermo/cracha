package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/bazelbuild/rules_go/go/runfiles"

	schema "github.com/bpalermo/cracha/common/spicedb"
)

// The write path (design 6.9) in spicedb mode: cracha-access runs in the
// release, and the tests call it the way a CI job or a tool pod does,
// through its CLI with an X.509-SVID, here the ones the SPIRE server
// minted for them (run.sh): access-owner owns every bucket the tests
// write (bootstrapRelationships), access-approver approves the sensitive
// one, access-stranger is neither. The CLI reaches the service over the
// port-forward run.sh keeps open (E2E_ACCESS_ENDPOINT) and verifies it by
// its SPIFFE ID.
//
// The file is named to run after every other test of the package (Go runs
// them in file order): the tests here have the reader fetch credentials
// for compositions the resource tests then expect to be issued anew, and a
// session the broker cached here would be a cache hit there.
const (
	accessEndpointEnv = "E2E_ACCESS_ENDPOINT"
	// accessCLIRlocation is cracha-access built from this checkout.
	accessCLIRlocation = "_main/access/access_/cracha-access"
	accessSelector     = "app.kubernetes.io/name=cracha,app.kubernetes.io/component=access"

	identityOwner    = "access-owner"
	identityApprover = "access-approver"
	identityStranger = "access-stranger"
)

// accessID is the SPIFFE ID cracha-access serves its API with.
var accessID = fmt.Sprintf("spiffe://%s/ns/%s/sa/cracha-access", trustDomain, systemNamespace)

// cliError is a failed CLI call: its exit and what it printed.
type cliError struct {
	args   []string
	stderr string
	err    error
}

func (e *cliError) Error() string {
	return fmt.Sprintf("cracha-access %s: %v: %s", strings.Join(e.args, " "), e.err, strings.TrimSpace(e.stderr))
}

// accessCLI runs cracha-access's CLI as the identity: the command first,
// then its flags.
func accessCLI(ctx context.Context, identity string, args ...string) ([]byte, error) {
	bin, err := runfiles.Rlocation(accessCLIRlocation)
	if err != nil {
		return nil, fmt.Errorf("cracha-access is not in the runfiles: %w", err)
	}
	dir := filepath.Join(os.Getenv(spicedbSVIDsEnv), identity)
	full := append(append([]string{}, args...),
		"--server", os.Getenv(accessEndpointEnv), "--server-spiffe-id", accessID,
		"--svid", filepath.Join(dir, "svid.pem"), "--svid-key", filepath.Join(dir, "key.pem"), "--bundle", filepath.Join(dir, "bundle.pem"))
	cmd := exec.CommandContext(ctx, bin, full...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), &cliError{args: args, stderr: stderr.String(), err: err}
	}
	return stdout.Bytes(), nil
}

// writeResponse is what a write call prints.
type writeResponse struct {
	Status       string `json:"status"`
	RequestID    string `json:"requestId"`
	Relationship string `json:"relationship"`
}

// mustAccess runs a write call that must succeed and decodes it.
func mustAccess(ctx context.Context, t *testing.T, identity string, args ...string) writeResponse {
	t.Helper()
	out, err := accessCLI(ctx, identity, args...)
	if err != nil {
		t.Fatal(err)
	}
	var resp writeResponse
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("cracha-access %s printed %q: %v", args[0], out, err)
	}
	t.Logf("cracha-access %s as %s: %s %s %s", args[0], identity, resp.Status, resp.RequestID, resp.Relationship)
	return resp
}

// mustRefuse runs a call that must be refused with the reason code.
func mustRefuse(ctx context.Context, t *testing.T, reason, identity string, args ...string) {
	t.Helper()
	_, err := accessCLI(ctx, identity, args...)
	var ce *cliError
	if !errors.As(err, &ce) {
		t.Fatalf("cracha-access %s as %s was not refused: %v", args[0], identity, err)
	}
	if !strings.Contains(ce.stderr, reason+":") {
		t.Fatalf("cracha-access %s as %s refused, but not with %s: %s", args[0], identity, reason, ce.stderr)
	}
	t.Logf("refused as expected: %s", strings.TrimSpace(ce.stderr))
}

// requireAccess skips outside spicedb mode, where cracha-access does not run.
func requireAccess(t *testing.T) {
	t.Helper()
	requireSpiceDB(t)
	if os.Getenv(accessEndpointEnv) == "" {
		t.Fatalf("%s is not set; e2e/run.sh sets it in spicedb mode", accessEndpointEnv)
	}
}

// grantArgs is a grant of the bucket to the reader.
func grantArgs(bucket string, extra ...string) []string {
	return append([]string{
		"grant", "--subject", workloadID(readerSA), "--resource", "s3_bucket:" + bucket, "--relation", "reader",
		"--reason", "e2e", "--requester", "e2e-" + bucket,
	}, extra...)
}

// revokeLater revokes the reader's bucket when the test ends, if it is held.
func revokeLater(t *testing.T, bucket string) {
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, _ = accessCLI(ctx, identityOwner, "revoke", "--subject", workloadID(readerSA), "--resource", "s3_bucket:"+bucket, "--relation", "reader", "--reason", "e2e cleanup")
	})
}

// readerBucket is the reader's relationship to a bucket.
func readerBucket(bucket string) *v1.Relationship {
	return rel(schema.TypeS3Bucket, bucketID(bucket), schema.RelationReader, schema.TypeWorkload, workloadID(readerSA), "")
}

// held reports whether SpiceDB holds the relationship, read fully
// consistent as the broker, which may read.
func held(ctx context.Context, t *testing.T, r *v1.Relationship) bool {
	t.Helper()
	c := mustDialAs(t, identityBroker)
	stream, err := c.ReadRelationships(ctx, &v1.ReadRelationshipsRequest{
		Consistency: &v1.Consistency{Requirement: &v1.Consistency_FullyConsistent{FullyConsistent: true}},
		RelationshipFilter: &v1.RelationshipFilter{
			ResourceType: r.GetResource().GetObjectType(), OptionalResourceId: r.GetResource().GetObjectId(), OptionalRelation: r.GetRelation(),
			OptionalSubjectFilter: &v1.SubjectFilter{SubjectType: r.GetSubject().GetObject().GetObjectType(), OptionalSubjectId: r.GetSubject().GetObject().GetObjectId()},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = stream.Recv()
	if errors.Is(err, io.EOF) {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	return true
}

// waitForReaderPolicy waits for an AssumeRole of the reader after since
// whose session policy names the ARN, or does not when want is false.
func waitForReaderPolicy(ctx context.Context, t *testing.T, since time.Time, arn string, want bool) time.Duration {
	t.Helper()
	err := eventually(ctx, func() error {
		reqs, err := stubRequests(ctx, readerSession)
		if err != nil {
			return err
		}
		for _, r := range reqs {
			if r.Received.After(since) && strings.Contains(r.Policy, arn) == want {
				return nil
			}
		}
		return fmt.Errorf("no AssumeRole of %s since %s with %s in its policy = %t", readerSession, since.Format(time.RFC3339), arn, want)
	})
	if err != nil {
		t.Fatal(err)
	}
	return time.Since(since)
}

// An owner grants the reader a bucket through cracha-access, and the
// reader's next credentials name it within seconds; revoked, they stop.
func TestAccessGrantAndRevoke(t *testing.T) {
	requireAccess(t)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	fetchingReader(ctx, t, "reader-granted")
	arn := "arn:aws:s3:::" + grantedBucket + "/*"
	revokeLater(t, grantedBucket)

	grantedAt := time.Now()
	if resp := mustAccess(ctx, t, identityOwner, grantArgs(grantedBucket)...); resp.Status != "applied" {
		t.Fatalf("grant status %q, want applied", resp.Status)
	}
	if took := waitForReaderPolicy(ctx, t, grantedAt, arn, true); took > revocationBudget {
		t.Errorf("the grant reached the reader's credentials after %s, over %s", took, revocationBudget)
	} else {
		t.Logf("the grant reached the reader's credentials after %s", took.Round(time.Millisecond))
	}

	revokedAt := time.Now()
	if resp := mustAccess(ctx, t, identityOwner, "revoke", "--subject", workloadID(readerSA), "--resource", "s3_bucket:"+grantedBucket,
		"--relation", "reader", "--reason", "e2e"); resp.Status != "revoked" {
		t.Fatalf("revoke status %q, want revoked", resp.Status)
	}
	if took := waitForReaderPolicy(ctx, t, revokedAt, arn, false); took > revocationBudget {
		t.Errorf("the revocation reached the reader's credentials after %s, over %s", took, revocationBudget)
	}
	if held(ctx, t, readerBucket(grantedBucket)) {
		t.Error("the revoked relationship is still in SpiceDB")
	}
}

// A caller that does not own the target is refused not_authorized; an
// owner's grant of a bucket outside the account's envelope is refused
// resource_outside_envelope before anything reaches SpiceDB.
func TestAccessRefusals(t *testing.T) {
	requireAccess(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	mustRefuse(ctx, t, "not_authorized", identityStranger, grantArgs(grantedBucket)...)
	mustRefuse(ctx, t, reasonOutside, identityOwner, grantArgs(outsideBucket)...)
	if held(ctx, t, readerBucket(outsideBucket)) {
		t.Error("the refused relationship outside the envelope is in SpiceDB")
	}
	if held(ctx, t, readerBucket(grantedBucket)) {
		t.Error("the stranger's refused relationship is in SpiceDB")
	}
}

// A grant of a sensitive bucket waits for an approval: the identity that
// asked cannot approve it, another approver applies it.
func TestAccessApproval(t *testing.T) {
	requireAccess(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	revokeLater(t, sensitiveBucket)
	pending := mustAccess(ctx, t, identityOwner, grantArgs(sensitiveBucket)...)
	if pending.Status != "pending" || pending.RequestID == "" {
		t.Fatalf("grant of a sensitive bucket = %+v, want pending", pending)
	}
	if held(ctx, t, readerBucket(sensitiveBucket)) {
		t.Fatal("a pending grant is in SpiceDB")
	}
	out, err := accessCLI(ctx, identityStranger, "pending", "--resource", "s3_bucket:"+sensitiveBucket)
	if err != nil || !bytes.Contains(out, []byte(pending.RequestID)) {
		t.Errorf("pending = %s, %v; want request %s", out, err, pending.RequestID)
	}
	mustRefuse(ctx, t, "self_approval", identityOwner, "approve", "--id", pending.RequestID, "--reason", "mine")
	mustRefuse(ctx, t, "not_authorized", identityStranger, "approve", "--id", pending.RequestID, "--reason", "not mine to approve")
	if resp := mustAccess(ctx, t, identityApprover, "approve", "--id", pending.RequestID, "--reason", "e2e", "--requester", "e2e-approver"); resp.Status != "applied" {
		t.Fatalf("approval status %q, want applied", resp.Status)
	}
	if !held(ctx, t, readerBucket(sensitiveBucket)) {
		t.Error("the approved grant is not in SpiceDB")
	}
}

// Break-glass applies a write on a sensitive bucket at once, but only with
// an expiry within the cap.
func TestAccessBreakGlass(t *testing.T) {
	requireAccess(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	revokeLater(t, glassBucket)
	mustRefuse(ctx, t, "expiry_required", identityOwner, grantArgs(glassBucket, "--break-glass")...)
	mustRefuse(ctx, t, "expiry_over_cap", identityOwner, grantArgs(glassBucket, "--break-glass", "--expires-at", time.Now().Add(5*time.Hour).UTC().Format(time.RFC3339))...)
	expires := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if resp := mustAccess(ctx, t, identityOwner, grantArgs(glassBucket, "--break-glass", "--expires-at", expires)...); resp.Status != "applied" {
		t.Fatalf("break-glass status %q, want applied", resp.Status)
	}
	if !held(ctx, t, readerBucket(glassBucket)) {
		t.Error("the break-glass grant is not in SpiceDB")
	}
}

// auditLine is a line of cracha-access's audit log.
type auditLine struct {
	Level string `json:"level"`
	Msg   string `json:"msg"`
	Audit struct {
		Event        string `json:"event"`
		Caller       string `json:"caller"`
		Requester    string `json:"requester"`
		Code         string `json:"code"`
		Relationship string `json:"relationship"`
		BreakGlass   bool   `json:"breakGlass"`
		Change       string `json:"change"`
	} `json:"audit"`
}

// Every request leaves its audit line: a refusal with the caller and its
// code, a write with the requester, and the Watch's line for the change
// it made.
func TestAccessAudit(t *testing.T) {
	requireAccess(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	revokeLater(t, grantedBucket)
	mustRefuse(ctx, t, "not_authorized", identityStranger, grantArgs(grantedBucket)...)
	mustAccess(ctx, t, identityOwner, grantArgs(grantedBucket)...)
	stranger := fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", trustDomain, testNamespace, identityStranger)
	owner := fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", trustDomain, testNamespace, identityOwner)
	rel := "s3_bucket:" + bucketID(grantedBucket) + "#reader@workload:" + workloadID(readerSA)
	err := eventually(ctx, func() error {
		lines, err := accessAudit(ctx)
		if err != nil {
			return err
		}
		var refusal, write, change bool
		for _, l := range lines {
			a := l.Audit
			refusal = refusal || (a.Event == "refusal" && a.Caller == stranger && a.Code == "not_authorized")
			write = write || (a.Event == "write" && a.Caller == owner && a.Requester == "e2e-"+grantedBucket && a.Relationship == rel)
			change = change || (a.Event == "change" && a.Caller == owner && a.Relationship == rel && a.Change == "touch")
		}
		if !refusal || !write || !change {
			return fmt.Errorf("audit lines: refusal %t, write %t, watch change %t", refusal, write, change)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// accessAudit is every audit line of cracha-access's pods.
func accessAudit(ctx context.Context) ([]auditLine, error) {
	pods, err := client.CoreV1().Pods(systemNamespace).List(ctx, metav1.ListOptions{LabelSelector: accessSelector})
	if err != nil {
		return nil, err
	}
	var out []auditLine
	for _, p := range pods.Items {
		logs, err := podLogs(ctx, systemNamespace, p.Name, "")
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(logs, "\n") {
			var l auditLine
			if strings.HasPrefix(line, "{") && json.Unmarshal([]byte(line), &l) == nil && l.Msg == "audit" {
				out = append(out, l)
			}
		}
	}
	return out, nil
}
