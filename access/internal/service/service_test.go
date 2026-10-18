package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/grpc/codes"

	"github.com/bpalermo/cracha/access/internal/api"
	"github.com/bpalermo/cracha/access/internal/audit"
	"github.com/bpalermo/cracha/access/internal/check"
	"github.com/bpalermo/cracha/access/internal/check/checktest"
	"github.com/bpalermo/cracha/access/internal/store"
	"github.com/bpalermo/cracha/access/internal/store/storetest"
	"github.com/bpalermo/cracha/common/grant"
	"github.com/bpalermo/cracha/common/idenc"
	"github.com/bpalermo/cracha/common/spicedb"
)

var now = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

const (
	ledger   = "prod/payments/ledger"
	owner    = "spiffe://example.org/ns/tools/sa/owner"
	approver = "spiffe://example.org/ns/tools/sa/approver"
	stranger = "spiffe://example.org/ns/tools/sa/stranger"
)

// workloadOf is a caller's workload encoding under the test labels.
func workloadOf(id string) string {
	return "prod/tools/" + id[strings.LastIndex(id, "/")+1:]
}

type bundles struct{ b *grant.Bundle }

func (b bundles) Bundle() *grant.Bundle { return b.b }

type fixture struct {
	t     *testing.T
	fake  *storetest.Client
	svc   *Service
	audit *bytes.Buffer
}

func rel(resType, resID, relation, subType, subID, subRel string) *v1.Relationship {
	return &v1.Relationship{
		Resource: &v1.ObjectReference{ObjectType: resType, ObjectId: resID}, Relation: relation,
		Subject: &v1.SubjectReference{Object: &v1.ObjectReference{ObjectType: subType, ObjectId: subID}, OptionalRelation: subRel},
	}
}

// newFixture is a service over a store where ledger holds data-read and
// the bucket data-a, owner manages data-a, data-b, data-secure and
// secrets, approver approves data-secure, and data-secure is sensitive.
func newFixture(t *testing.T, cfg Config) *fixture {
	t.Helper()
	fake := storetest.New(
		rel(spicedb.TypeGrant, "data-read", spicedb.RelationAssigneeWorkload, spicedb.TypeWorkload, ledger, ""),
		rel(grant.ResourceS3Bucket, "data-a", spicedb.RelationReader, spicedb.TypeWorkload, ledger, ""),
		rel(grant.ResourceS3Bucket, "data-secure", store.RelationSensitive, spicedb.TypeWorkload, "*", ""),
	)
	for _, b := range []string{"data-a", "data-b", "data-secure", "secrets"} {
		fake.Allow(store.PermissionManage, grant.ResourceS3Bucket, b, workloadOf(owner))
		fake.Allow(store.PermissionApprove, grant.ResourceS3Bucket, b, workloadOf(owner))
	}
	fake.Allow(store.PermissionApprove, grant.ResourceS3Bucket, "data-secure", workloadOf(approver))
	labels, err := idenc.NewLabels(map[string]string{"example.org": "prod"})
	if err != nil {
		t.Fatal(err)
	}
	cfg.Labels = labels
	var buf bytes.Buffer
	svc := New(cfg, store.New(fake, time.Second), bundles{checktest.Bundle(t, "v1")}, audit.New(&buf))
	svc.SetClock(func() time.Time { return now })
	return &fixture{t: t, fake: fake, svc: svc, audit: &buf}
}

func as(id string) context.Context {
	return api.WithCaller(context.Background(), spiffeid.RequireFromString(id))
}

func grantOf(name string) *api.GrantRequest {
	return &api.GrantRequest{Subject: ledger, Resource: api.Resource{Kind: grant.ResourceS3Bucket, Name: name}, Relation: grant.RelationReader, Reason: "ticket-1", Requester: "alice"}
}

// events are the audit lines written so far.
func (f *fixture) events() []map[string]any {
	f.t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(f.audit.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			f.t.Fatalf("audit line %q: %v", line, err)
		}
		e, _ := m["audit"].(map[string]any)
		e["level"] = m["level"]
		out = append(out, e)
	}
	return out
}

func (f *fixture) last() map[string]any {
	f.t.Helper()
	ev := f.events()
	if len(ev) == 0 {
		f.t.Fatal("no audit line")
	}
	return ev[len(ev)-1]
}

func reasonOf(t *testing.T, err error) (codes.Code, string) {
	t.Helper()
	var r *api.Refusal
	if !errors.As(err, &r) {
		t.Fatalf("err = %v, want a refusal", err)
	}
	return r.Code, r.Reason
}

func (f *fixture) has(key string) bool {
	for _, k := range f.fake.Keys() {
		if k == key {
			return true
		}
	}
	return false
}

func TestGrantApplied(t *testing.T) {
	f := newFixture(t, Config{})
	resp, err := f.svc.Grant(as(owner), grantOf("data-b"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != api.StatusApplied || resp.Token == "" || resp.BundleVersion != "v1" || !f.has("s3_bucket:data-b#reader@workload:"+ledger) {
		t.Fatalf("resp = %+v, held %v", resp, f.fake.Keys())
	}
	if len(resp.PolicyDelta) != 1 || !strings.Contains(resp.PolicyDelta[0].PolicyAfter, "data-b") || strings.Contains(resp.PolicyDelta[0].PolicyBefore, "data-b") {
		t.Errorf("delta = %+v", resp.PolicyDelta)
	}
	ev := f.last()
	if ev["event"] != audit.EventWrite || ev["caller"] != owner || ev["requester"] != "alice" || ev["reason"] != "ticket-1" || ev["level"] != "INFO" || ev["policyDelta"] == nil {
		t.Errorf("audit = %v", ev)
	}
	md := f.fake.Writes[0].GetOptionalTransactionMetadata().AsMap()
	if md["writer"] != Writer || md["caller"] != owner || md["requester"] != "alice" {
		t.Errorf("transaction metadata = %v", md)
	}
}

func TestGrantRefusals(t *testing.T) {
	tests := []struct {
		name   string
		caller string
		req    func(*api.GrantRequest)
		cfg    Config
		code   codes.Code
		reason string
	}{
		{"not an owner", stranger, nil, Config{}, codes.PermissionDenied, ReasonNotAuthorized},
		{"outside the envelope", owner, func(r *api.GrantRequest) { r.Resource.Name = "secrets" }, Config{}, codes.FailedPrecondition, check.ReasonResourceOutsideEnvelope},
		{"no reason", owner, func(r *api.GrantRequest) { r.Reason = "" }, Config{}, codes.InvalidArgument, ReasonInvalid},
		{"invalid bucket name", owner, func(r *api.GrantRequest) { r.Resource.Name = "Bad_Bucket" }, Config{}, codes.InvalidArgument, ReasonInvalid},
		{"unknown kind", owner, func(r *api.GrantRequest) { r.Resource.Kind = "queue" }, Config{}, codes.InvalidArgument, ReasonInvalid},
		{"expiry in the past", owner, func(r *api.GrantRequest) { r.ExpiresAt = "2026-10-18T11:00:00Z" }, Config{}, codes.InvalidArgument, ReasonExpiryPast},
		{"kind needs expiry", owner, nil, Config{MaxExpiry: map[string]time.Duration{grant.ResourceS3Bucket: 24 * time.Hour}}, codes.InvalidArgument, ReasonExpiryRequired},
		{
			"kind expiry over its max", owner, func(r *api.GrantRequest) { r.ExpiresAt = "2026-10-20T12:00:00Z" },
			Config{MaxExpiry: map[string]time.Duration{grant.ResourceS3Bucket: 24 * time.Hour}},
			codes.InvalidArgument, ReasonExpiryOverCap,
		},
		{"break-glass without expiry", owner, func(r *api.GrantRequest) { r.BreakGlass = true; r.Resource.Name = "data-secure" }, Config{}, codes.InvalidArgument, ReasonExpiryRequired},
		{"break-glass over the cap", owner, func(r *api.GrantRequest) {
			r.BreakGlass, r.Resource.Name, r.ExpiresAt = true, "data-secure", "2026-10-18T16:00:01Z"
		}, Config{}, codes.InvalidArgument, ReasonExpiryOverCap},
		{"break-glass by an approver who does not manage", approver, func(r *api.GrantRequest) {
			r.BreakGlass, r.Resource.Name, r.ExpiresAt = true, "data-secure", "2026-10-18T13:00:00Z"
		}, Config{}, codes.PermissionDenied, ReasonNotAuthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, tt.cfg)
			req := grantOf("data-b")
			if tt.req != nil {
				tt.req(req)
			}
			_, err := f.svc.Grant(as(tt.caller), req)
			if code, reason := reasonOf(t, err); code != tt.code || reason != tt.reason {
				t.Fatalf("refused %s %s (%v), want %s %s", code, reason, err, tt.code, tt.reason)
			}
			if len(f.fake.Writes) != 0 {
				t.Errorf("a refused write reached SpiceDB: %v", f.fake.Writes)
			}
			ev := f.last()
			if ev["event"] != audit.EventRefusal || ev["code"] != tt.reason || ev["caller"] != tt.caller {
				t.Errorf("audit = %v", ev)
			}
		})
	}
}

func TestGrantSizeBudget(t *testing.T) {
	f := newFixture(t, Config{})
	n := checktest.MaxResources(t, checktest.Bundle(t, "v1"), "data-read")
	for i := 1; i < n; i++ {
		name := fmt.Sprintf("data-%03d", i)
		f.fake.Allow(store.PermissionManage, grant.ResourceS3Bucket, name, workloadOf(owner))
		if _, err := f.svc.Grant(as(owner), grantOf(name)); err != nil {
			t.Fatalf("bucket %d of %d: %v", i+1, n, err)
		}
	}
	writes := len(f.fake.Writes)
	_, err := f.svc.Grant(as(owner), grantOf("data-b"))
	if code, reason := reasonOf(t, err); code != codes.FailedPrecondition || reason != check.ReasonPolicyTooLarge {
		t.Fatalf("refused %s %s, want policy_too_large", code, reason)
	}
	if len(f.fake.Writes) != writes {
		t.Error("the refused write reached SpiceDB")
	}
}

func TestBreakGlass(t *testing.T) {
	f := newFixture(t, Config{})
	req := grantOf("data-secure")
	req.BreakGlass, req.ExpiresAt = true, "2026-10-18T15:00:00+01:00"
	resp, err := f.svc.Grant(as(owner), req)
	if err != nil {
		t.Fatal(err)
	}
	r := f.fake.Get("s3_bucket:data-secure#reader@workload:" + ledger)
	if resp.Status != api.StatusApplied || r.GetOptionalCaveat().GetCaveatName() != spicedb.CaveatWithinWindow ||
		r.GetOptionalCaveat().GetContext().AsMap()[spicedb.ContextExpiresAt] != "2026-10-18T14:00:00Z" {
		t.Fatalf("resp = %+v, relationship %v", resp, r)
	}
	if ev := f.last(); ev["level"] != "WARN" || ev["breakGlass"] != true || ev["event"] != audit.EventWrite {
		t.Errorf("audit = %v", ev)
	}
}

func TestSensitiveApproval(t *testing.T) {
	f := newFixture(t, Config{})
	req := grantOf("data-secure")
	resp, err := f.svc.Grant(as(owner), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != api.StatusPending || resp.RequestID == "" || f.has("s3_bucket:data-secure#reader@workload:"+ledger) {
		t.Fatalf("resp = %+v, held %v", resp, f.fake.Keys())
	}
	if ev := f.last(); ev["event"] != audit.EventRequest || ev["requestId"] != resp.RequestID {
		t.Errorf("audit = %v", ev)
	}
	pending, err := f.svc.Pending(as(stranger), &api.PendingRequest{})
	if err != nil || len(pending.Requests) != 1 || pending.Requests[0].Caller != owner || pending.Requests[0].Request.Resource.Name != "data-secure" {
		t.Fatalf("pending = %+v, %v", pending, err)
	}

	decide := &api.DecideRequest{ID: resp.RequestID, Reason: "ok"}
	// The identity that asked cannot approve its own request, though it
	// holds approve.
	if _, err := f.svc.Approve(as(owner), decide); err == nil {
		t.Fatal("self-approval applied")
	} else if _, reason := reasonOf(t, err); reason != ReasonSelfApproval {
		t.Fatalf("self-approval refused with %s", reason)
	}
	// Nor can another identity naming the same requester.
	if _, err := f.svc.Approve(as(approver), &api.DecideRequest{ID: resp.RequestID, Reason: "ok", Requester: "alice"}); err == nil {
		t.Fatal("approved by the same requester")
	} else if _, reason := reasonOf(t, err); reason != ReasonSelfApproval {
		t.Fatalf("same requester refused with %s", reason)
	}
	// Nor anyone without approve.
	if _, err := f.svc.Approve(as(stranger), decide); err == nil {
		t.Fatal("approved by a stranger")
	} else if _, reason := reasonOf(t, err); reason != ReasonNotAuthorized {
		t.Fatalf("stranger refused with %s", reason)
	}

	out, err := f.svc.Approve(as(approver), &api.DecideRequest{ID: resp.RequestID, Reason: "ok", Requester: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != api.StatusApplied || !f.has("s3_bucket:data-secure#reader@workload:"+ledger) {
		t.Fatalf("approve = %+v, held %v", out, f.fake.Keys())
	}
	for _, k := range f.fake.Keys() {
		if strings.HasPrefix(k, store.DefinitionPendingRequest+":") {
			t.Errorf("pending request left: %s", k)
		}
	}
	last := f.fake.Writes[len(f.fake.Writes)-1]
	if len(last.GetUpdates()) != 2 {
		t.Errorf("the write and the request's removal are not one transaction: %v", last.GetUpdates())
	}
	evs := f.events()
	approval, write := evs[len(evs)-2], evs[len(evs)-1]
	if approval["event"] != audit.EventApproval || approval["caller"] != approver || approval["requestedBy"] != owner ||
		write["event"] != audit.EventWrite || write["requestId"] != resp.RequestID {
		t.Errorf("audit = %v, %v", approval, write)
	}
	if _, err := f.svc.Approve(as(approver), decide); err == nil {
		t.Error("a request approved twice")
	} else if code, _ := reasonOf(t, err); code != codes.NotFound {
		t.Errorf("second approval: %v", err)
	}
}

// A pending request is checked again at approval: a write the safeguards
// would refuse now is refused then.
func TestApprovalRechecks(t *testing.T) {
	f := newFixture(t, Config{})
	resp, err := f.svc.Grant(as(owner), grantOf("data-secure"))
	if err != nil {
		t.Fatal(err)
	}
	// The grant that rendered the bucket goes away meanwhile.
	if _, err := f.svc.store.Write(context.Background(), []store.Update{{Delete: true, Relationship: store.Relationship{
		ResourceType: spicedb.TypeGrant, ResourceID: "data-read", Relation: spicedb.RelationAssigneeWorkload, SubjectType: spicedb.TypeWorkload, SubjectID: ledger,
	}}}, nil); err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.Approve(as(approver), &api.DecideRequest{ID: resp.RequestID, Reason: "ok"})
	if _, reason := reasonOf(t, err); reason != check.ReasonNoGrant {
		t.Fatalf("approval of what no grant renders: %s", reason)
	}
}

func TestRejectAndExpiry(t *testing.T) {
	f := newFixture(t, Config{PendingTTL: time.Hour})
	a, _ := f.svc.Grant(as(owner), grantOf("data-secure"))
	if _, err := f.svc.Reject(as(stranger), &api.DecideRequest{ID: a.RequestID, Reason: "no"}); err == nil {
		t.Fatal("rejected by a stranger")
	}
	out, err := f.svc.Reject(as(approver), &api.DecideRequest{ID: a.RequestID, Reason: "no"})
	if err != nil || out.Status != api.StatusRejected {
		t.Fatalf("reject = %+v, %v", out, err)
	}
	if ev := f.last(); ev["event"] != audit.EventRejection || ev["caller"] != approver {
		t.Errorf("audit = %v", ev)
	}
	// The asker may withdraw its own.
	b, _ := f.svc.Grant(as(owner), grantOf("data-secure"))
	if _, err := f.svc.Reject(as(owner), &api.DecideRequest{ID: b.RequestID, Reason: "withdrawn"}); err != nil {
		t.Errorf("withdrawal: %v", err)
	}
	// An unapproved request expires.
	c, _ := f.svc.Grant(as(owner), grantOf("data-secure"))
	f.svc.SetClock(func() time.Time { return now.Add(2 * time.Hour) })
	if _, err := f.svc.Approve(as(approver), &api.DecideRequest{ID: c.RequestID, Reason: "late"}); err == nil {
		t.Fatal("an expired request was approved")
	} else if _, reason := reasonOf(t, err); reason != ReasonExpired {
		t.Fatalf("expired request refused with %s", reason)
	}
	evs := f.events()
	if evs[len(evs)-2]["event"] != audit.EventExpired {
		t.Errorf("no expiry line: %v", evs[len(evs)-2])
	}
	d, _ := f.svc.Grant(as(owner), grantOf("data-secure"))
	f.svc.SetClock(func() time.Time { return now.Add(4 * time.Hour) })
	if err := f.svc.Expire(context.Background()); err != nil {
		t.Fatal(err)
	}
	if p, _ := f.svc.store.ListPending(context.Background(), d.RequestID); len(p) != 0 {
		t.Errorf("expired request kept: %v", p)
	}
}

func TestRevoke(t *testing.T) {
	f := newFixture(t, Config{})
	req := &api.RevokeRequest{Subject: ledger, Resource: api.Resource{Kind: grant.ResourceS3Bucket, Name: "data-a"}, Relation: grant.RelationReader, Reason: "offboard"}
	if _, err := f.svc.Revoke(as(stranger), req); err == nil {
		t.Fatal("revoked by a stranger")
	}
	resp, err := f.svc.Revoke(as(owner), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != api.StatusRevoked || f.has("s3_bucket:data-a#reader@workload:"+ledger) {
		t.Fatalf("revoke = %+v, held %v", resp, f.fake.Keys())
	}
	if len(resp.PolicyDelta) != 1 || resp.PolicyDelta[0].PolicyAfter != "" || !strings.Contains(resp.PolicyDelta[0].PolicyBefore, "data-a") {
		t.Errorf("delta = %+v", resp.PolicyDelta)
	}
	ev := f.last()
	if ev["event"] != audit.EventWrite || ev["operation"] != "revoke" || ev["before"] == nil {
		t.Errorf("audit = %v", ev)
	}
	if _, err := f.svc.Revoke(as(owner), req); err == nil {
		t.Error("revoked what is not held")
	} else if code, _ := reasonOf(t, err); code != codes.NotFound {
		t.Errorf("revoke of nothing: %v", err)
	}
}

func TestMembership(t *testing.T) {
	f := newFixture(t, Config{})
	f.fake.Allow(store.PermissionManage, spicedb.TypeService, "other", workloadOf(owner))
	// other's members hold a grant of another shape: ledger joining it
	// would make its composition ambiguous.
	if _, err := f.svc.store.Write(context.Background(), []store.Update{{Relationship: store.Relationship{
		ResourceType: spicedb.TypeGrant, ResourceID: "other-shape", Relation: spicedb.RelationAssigneeService, SubjectType: spicedb.TypeService, SubjectID: "other",
	}}}, nil); err != nil {
		t.Fatal(err)
	}
	req := &api.GrantRequest{Subject: ledger, Resource: api.Resource{Kind: spicedb.TypeService, Name: "other"}, Relation: spicedb.RelationMember, Reason: "move"}
	if _, err := f.svc.Grant(as(owner), req); err == nil {
		t.Fatal("an ambiguous membership was written")
	} else if _, reason := reasonOf(t, err); reason != check.ReasonAmbiguous {
		t.Fatalf("refused with %s", reason)
	}
	if _, err := f.svc.Grant(as(stranger), req); err == nil {
		t.Fatal("membership written by a stranger")
	}
}

func TestReads(t *testing.T) {
	f := newFixture(t, Config{})
	list, err := f.svc.List(as(stranger), &api.ListRequest{Subject: ledger})
	if err != nil || len(list.Relationships) != 1 || list.Relationships[0].Resource.Name != "data-a" {
		t.Fatalf("list = %+v, %v", list, err)
	}
	if _, err := f.svc.List(as(stranger), &api.ListRequest{}); err == nil {
		t.Error("an empty list request")
	}
	byRes, err := f.svc.List(as(stranger), &api.ListRequest{Resource: &api.Resource{Kind: grant.ResourceS3Bucket, Name: "data-a"}})
	if err != nil || len(byRes.Relationships) != 1 || byRes.Relationships[0].Subject != ledger {
		t.Fatalf("list by resource = %+v, %v", byRes, err)
	}
	ex, err := f.svc.Explain(as(stranger), &api.ExplainRequest{Subject: ledger})
	if err != nil || ex.BundleVersion != "v1" || len(ex.Compositions) != 1 || !strings.Contains(ex.Compositions[0].Policy, "arn:aws:s3:::data-a/*") {
		t.Fatalf("explain = %+v, %v", ex, err)
	}
	if _, err := f.svc.Explain(as(stranger), &api.ExplainRequest{Subject: "not a subject"}); err == nil {
		t.Error("explained an invalid subject")
	}
	if _, err := f.svc.List(context.Background(), &api.ListRequest{Subject: ledger}); err == nil {
		t.Error("a read without a caller")
	}
}

func TestNoBundleRefusesWrites(t *testing.T) {
	f := newFixture(t, Config{})
	f.svc.bundles = bundles{}
	_, err := f.svc.Grant(as(owner), grantOf("data-b"))
	if code, reason := reasonOf(t, err); code != codes.Unavailable || reason != ReasonUnavailable {
		t.Fatalf("refused %s %s", code, reason)
	}
}

func TestStoreDownFailsClosed(t *testing.T) {
	f := newFixture(t, Config{})
	f.fake.ReadErr = errors.New("spicedb down")
	_, err := f.svc.Grant(as(owner), grantOf("data-b"))
	if code, reason := reasonOf(t, err); code != codes.Unavailable || reason != ReasonUnavailable {
		t.Fatalf("refused %s %s", code, reason)
	}
	if len(f.fake.Writes) != 0 {
		t.Error("wrote with the store down")
	}
}

func TestCallerOutsideTheScheme(t *testing.T) {
	f := newFixture(t, Config{})
	_, err := f.svc.Grant(as("spiffe://example.org/job/ci"), grantOf("data-b"))
	if code, reason := reasonOf(t, err); code != codes.PermissionDenied || reason != ReasonUnauthorizedClient {
		t.Fatalf("refused %s %s", code, reason)
	}
}

func TestWatchAudit(t *testing.T) {
	f := newFixture(t, Config{})
	if _, err := f.svc.Grant(as(owner), grantOf("data-b")); err != nil {
		t.Fatal(err)
	}
	// A write around the service.
	if _, err := f.svc.store.Write(context.Background(), []store.Update{{Relationship: store.Relationship{
		ResourceType: grant.ResourceS3Bucket, ResourceID: "data-z", Relation: spicedb.RelationReader, SubjectType: spicedb.TypeWorkload, SubjectID: ledger,
	}}}, map[string]any{"writer": "zed"}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	log := audit.New(&buf)
	done := make(chan struct{})
	go func() {
		defer close(done)
		WatchAudit(ctx, f.svc.store, log, time.Millisecond)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(buf.String(), "watch_error") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	out := buf.String()
	if !strings.Contains(out, `"relationship":"s3_bucket:data-b#reader@workload:`+ledger+`"`) || !strings.Contains(out, `"caller":"`+owner+`"`) {
		t.Errorf("the service's write is not in the watch log:\n%s", out)
	}
	if !strings.Contains(out, `"level":"WARN","msg":"audit","audit":{"event":"change"`) || !strings.Contains(out, "written outside cracha-access") {
		t.Errorf("the outside write is not flagged:\n%s", out)
	}
}

// An owner makes another workload an approver; the write reaches no
// composition, and only an owner may make it.
func TestOwnership(t *testing.T) {
	f := newFixture(t, Config{})
	req := &api.GrantRequest{Subject: "prod/tools/bob", Resource: api.Resource{Kind: grant.ResourceS3Bucket, Name: "data-b"}, Relation: store.RelationApprover, Reason: "rota"}
	if _, err := f.svc.Grant(as(stranger), req); err == nil {
		t.Fatal("an approver made by a stranger")
	}
	resp, err := f.svc.Grant(as(owner), req)
	if err != nil || resp.Status != api.StatusApplied || len(resp.PolicyDelta) != 0 || !f.has("s3_bucket:data-b#approver@workload:prod/tools/bob") {
		t.Fatalf("resp = %+v, %v, held %v", resp, err, f.fake.Keys())
	}
	list, err := f.svc.List(as(stranger), &api.ListRequest{Resource: &api.Resource{Kind: grant.ResourceS3Bucket, Name: "data-b"}})
	if err != nil || len(list.Relationships) != 1 || list.Relationships[0].Relation != store.RelationApprover {
		t.Errorf("list = %+v, %v", list, err)
	}
	req.ExpiresAt = "2026-10-19T00:00:00Z"
	if _, err := f.svc.Grant(as(owner), req); err == nil {
		t.Error("a bounded approver was written")
	}
}
