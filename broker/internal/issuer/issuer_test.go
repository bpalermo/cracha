package issuer

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bpalermo/cracha/broker/internal/authz"
	"github.com/bpalermo/cracha/broker/internal/grants"
	"github.com/bpalermo/cracha/broker/internal/sts"
	"github.com/bpalermo/cracha/common/idenc"
)

const dynamoRole = "arn:aws:iam::111122223333:role/broker/shape-dynamo-rw"

var ledger = idenc.Identity{TrustDomain: "example.org", Namespace: "payments", ServiceAccount: "ledger"}

type fakeStore struct {
	subject     authz.Subject
	consistency authz.Consistency
	decision    authz.Decision
	err         error
}

func (f *fakeStore) ListGrants(_ context.Context, s authz.Subject, c authz.Consistency) (authz.Decision, error) {
	f.subject = s
	f.consistency = c
	return f.decision, f.err
}

func (f *fakeStore) Check(context.Context, authz.Subject, string, authz.Consistency) (authz.CheckResult, error) {
	return authz.CheckResult{}, errors.New("not used")
}

type fakeSTS struct {
	req   sts.Request
	creds sts.Credentials
	err   error
	calls int
}

func (f *fakeSTS) AssumeRole(_ context.Context, req sts.Request) (sts.Credentials, error) {
	f.calls++
	f.req = req
	return f.creds, f.err
}

func grant(name string) grants.ResolvedGrant {
	return grants.ResolvedGrant{
		Name:            name,
		Account:         "111122223333",
		BaseRole:        dynamoRole,
		SessionPolicy:   `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"dynamodb:GetItem","Resource":"arn:aws:dynamodb:*:111122223333:table/` + name + `"}]}`,
		SessionTags:     map[string]string{"team": "payments"},
		DurationSeconds: 3600,
		Envelope:        []string{"arn:aws:dynamodb:*:111122223333:table/*"},
	}
}

func newDirect(t *testing.T, store *fakeStore, assumer *fakeSTS, log *slog.Logger) *Direct {
	t.Helper()
	labels, err := idenc.NewLabels(map[string]string{"example.org": "prod"})
	if err != nil {
		t.Fatal(err)
	}
	return &Direct{
		Store:   store,
		Grants:  grants.NewStatic("bundle-7", grant("ledger"), grant("outbox")),
		STS:     assumer,
		Labels:  labels,
		Cluster: "prod-a",
		Log:     log,
	}
}

func TestIssue(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, nil))
	store := &fakeStore{decision: authz.Decision{
		Grants: []string{"outbox", "ledger"},
		Tags:   map[string]string{"service": "payments-api", "team": "payments-platform"},
		Token:  "tok-1",
		Trace:  []string{"member of service payments-api"},
	}}
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	assumer := &fakeSTS{creds: sts.Credentials{AccessKeyID: "AKIA", SecretAccessKey: "s", SessionToken: "t", Expiration: exp}}
	d := newDirect(t, store, assumer, log)

	iss, err := d.Issue(context.Background(), ledger)
	if err != nil {
		t.Fatal(err)
	}
	if store.subject != (authz.Subject{ID: "prod/payments/ledger", Cluster: "prod-a"}) {
		t.Errorf("subject %+v", store.subject)
	}
	if iss.Credentials.AccessKeyID != "AKIA" || !iss.Credentials.Expiration.Equal(exp) {
		t.Errorf("credentials %+v", iss.Credentials)
	}
	if iss.SourceIdentity != "w.prod.payments.ledger" || iss.BundleVersion != "bundle-7" || iss.Decision.Token != "tok-1" {
		t.Errorf("resolution %+v", iss.Resolution)
	}
	if !reflect.DeepEqual(iss.Composed.Grants, []string{"ledger", "outbox"}) || iss.Composed.Shape != "shape-dynamo-rw" {
		t.Errorf("composed %+v", iss.Composed)
	}
	wantTags := map[string]string{
		"spiffe-ns": "payments", "spiffe-sa": "ledger", "cluster": "prod-a", "grant": "ledger+outbox",
		"team": "payments-platform", "service": "payments-api",
	}
	if !reflect.DeepEqual(iss.SessionTags, wantTags) {
		t.Errorf("tags %v, want %v", iss.SessionTags, wantTags)
	}
	checkSTSRequest(t, assumer.req, wantTags)
	// The issuance log maps the encodings back to the SPIFFE ID.
	checkLogFields(t, logs.String(),
		`"msg":"issued"`, `"spiffe_id":"spiffe://example.org/ns/payments/sa/ledger"`, `"source_identity":"w.prod.payments.ledger"`,
		`"subject":"prod/payments/ledger"`, `"bundle_version":"bundle-7"`, `"consistency_token":"tok-1"`)
}

// checkSTSRequest checks the AssumeRole request for the ledger workload
// holding the ledger and outbox grants.
func checkSTSRequest(t *testing.T, req sts.Request, wantTags map[string]string) {
	t.Helper()
	if req.RoleARN != dynamoRole || req.SessionName != "w.prod.payments.ledger" || req.DurationSeconds != 3600 {
		t.Errorf("sts request %+v", req)
	}
	if !strings.Contains(req.Policy, "table/ledger") || !strings.Contains(req.Policy, "table/outbox") {
		t.Errorf("policy %s", req.Policy)
	}
	if !reflect.DeepEqual(req.Tags, wantTags) {
		t.Errorf("sts tags %v", req.Tags)
	}
}

// checkLogFields checks that every want appears in the log line.
func checkLogFields(t *testing.T, line string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(line, want) {
			t.Errorf("log lacks %s:\n%s", want, line)
		}
	}
}

func TestIssueGrantTagsWithoutStoreTags(t *testing.T) {
	store := &fakeStore{decision: authz.Decision{Grants: []string{"ledger"}}}
	assumer := &fakeSTS{creds: sts.Credentials{AccessKeyID: "a", SecretAccessKey: "s", SessionToken: "t", Expiration: time.Now()}}
	iss, err := newDirect(t, store, assumer, nil).Issue(context.Background(), ledger)
	if err != nil {
		t.Fatal(err)
	}
	if iss.SessionTags["team"] != "payments" {
		t.Errorf("grant team tag lost: %v", iss.SessionTags)
	}
	if _, ok := iss.SessionTags["service"]; ok {
		t.Errorf("empty service tag set: %v", iss.SessionTags)
	}
}

func TestResolveDoesNotCallSTS(t *testing.T) {
	store := &fakeStore{decision: authz.Decision{Grants: []string{"ledger"}}}
	assumer := &fakeSTS{}
	r, err := newDirect(t, store, assumer, nil).Resolve(context.Background(), ledger)
	if err != nil {
		t.Fatal(err)
	}
	if assumer.calls != 0 {
		t.Fatal("Resolve called STS")
	}
	if r.Composed.Shape != "shape-dynamo-rw" || r.Composed.Policy == "" {
		t.Errorf("resolution %+v", r)
	}
}

func TestDenials(t *testing.T) {
	tests := []struct {
		name   string
		store  *fakeStore
		reason grants.Reason
	}{
		{"no grants", &fakeStore{decision: authz.Decision{}}, grants.ReasonNoGrant},
		{"suspended", &fakeStore{err: authz.ErrSubjectSuspended}, grants.ReasonSubjectSuspended},
		{"unknown grant", &fakeStore{decision: authz.Decision{Grants: []string{"nope"}}}, grants.ReasonNoGrant},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assumer := &fakeSTS{}
			d := newDirect(t, tt.store, assumer, nil)
			_, err := d.Issue(context.Background(), ledger)
			var deny *grants.DenyError
			if !errors.As(err, &deny) || deny.Reason != tt.reason {
				t.Fatalf("got %v, want reason %s", err, tt.reason)
			}
			if assumer.calls != 0 {
				t.Fatal("STS called on a denial")
			}
			if _, err := d.Resolve(context.Background(), ledger); !errors.As(err, &deny) || deny.Reason != tt.reason {
				t.Fatalf("Resolve: got %v", err)
			}
		})
	}
}

func TestStoreAndSTSFailuresDeny(t *testing.T) {
	assumer := &fakeSTS{}
	d := newDirect(t, &fakeStore{err: errors.New("store down")}, assumer, nil)
	_, err := d.Issue(context.Background(), ledger)
	var deny *grants.DenyError
	if err == nil || errors.As(err, &deny) || !errors.Is(err, ErrStore) {
		t.Fatalf("store failure: got %v, want a non-reason error marked ErrStore", err)
	}
	if assumer.calls != 0 {
		t.Fatal("STS called after a store failure")
	}

	d = newDirect(t, &fakeStore{decision: authz.Decision{Grants: []string{"ledger"}}}, &fakeSTS{err: errors.New("throttled")}, nil)
	if _, err := d.Issue(context.Background(), ledger); err == nil || errors.As(err, &deny) || errors.Is(err, ErrStore) {
		t.Fatalf("sts failure: got %v, want a non-reason error that is not the store's", err)
	}
}

func TestConsistencyFromContext(t *testing.T) {
	store := &fakeStore{decision: authz.Decision{Grants: []string{"ledger"}}}
	d := newDirect(t, store, &fakeSTS{}, nil)
	if _, err := d.Resolve(context.Background(), ledger); err != nil {
		t.Fatal(err)
	}
	if store.consistency != (authz.Consistency{}) {
		t.Errorf("a plain context asked for %+v, want minimize-latency", store.consistency)
	}
	ctx := WithConsistency(context.Background(), authz.Consistency{AtLeastAsFresh: "zed-5"})
	if _, err := d.Issue(ctx, ledger); err != nil {
		t.Fatal(err)
	}
	if store.consistency.AtLeastAsFresh != "zed-5" {
		t.Errorf("the store was asked for %+v, want at least as fresh as zed-5", store.consistency)
	}
	if got := ConsistencyFrom(context.Background()); got != (authz.Consistency{}) {
		t.Errorf("ConsistencyFrom(plain) = %+v", got)
	}
}

func TestLongIdentityIsHashedEverywhere(t *testing.T) {
	long := idenc.Identity{TrustDomain: "example.org", Namespace: "payments", ServiceAccount: strings.Repeat("s", 70)}
	store := &fakeStore{decision: authz.Decision{Grants: []string{"ledger"}}}
	assumer := &fakeSTS{creds: sts.Credentials{AccessKeyID: "a", SecretAccessKey: "s", SessionToken: "t", Expiration: time.Now()}}
	iss, err := newDirect(t, store, assumer, nil).Issue(context.Background(), long)
	if err != nil {
		t.Fatal(err)
	}
	if !idenc.IsHashedSTS(assumer.req.SessionName) || assumer.req.SessionName != iss.SourceIdentity {
		t.Errorf("session name %q", assumer.req.SessionName)
	}
	if store.subject.ID != "prod/payments/"+strings.Repeat("s", 70) {
		t.Errorf("subject %q", store.subject.ID)
	}
}

// lookupStore is a fakeStore that also answers LookupResources.
type lookupStore struct {
	fakeStore
	resources authz.Resources
	err       error
	asked     []string
}

func (l *lookupStore) LookupResources(_ context.Context, s authz.Subject, kind, permission string, _ authz.Consistency) (authz.Resources, error) {
	l.asked = append(l.asked, s.ID+" "+kind+"#"+permission)
	return l.resources, l.err
}

func bucketGrant() grants.ResolvedGrant {
	g := grant("buckets")
	g.SessionPolicy = ""
	g.Envelope = []string{"arn:aws:s3:::data-*"}
	g.Lookup = &grants.Lookup{Kind: "s3_bucket", Permission: "read", MaxResources: 5, Render: func(rs []string) (string, error) {
		return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::` + strings.Join(rs, ",") + `/*"}]}`, nil
	}}
	return g
}

func TestResolveLookup(t *testing.T) {
	var logs bytes.Buffer
	store := &lookupStore{
		fakeStore: fakeStore{decision: authz.Decision{Grants: []string{"buckets", "ledger"}, Token: "tok-1"}},
		resources: authz.Resources{Names: []string{"data-a"}, Trace: []string{"s3_bucket data-a reader via workload: active"}},
	}
	d := newDirect(t, &store.fakeStore, &fakeSTS{creds: sts.Credentials{Expiration: time.Now().Add(time.Hour)}}, slog.New(slog.NewJSONHandler(&logs, nil)))
	d.Store = store
	d.Grants = grants.NewStatic("bundle-7", grant("ledger"), bucketGrant())
	iss, err := d.Issue(context.Background(), ledger)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"prod/payments/ledger s3_bucket#read"}; !reflect.DeepEqual(store.asked, want) {
		t.Errorf("asked %v, want %v", store.asked, want)
	}
	if !reflect.DeepEqual(iss.Composed.Resources, map[string][]string{"buckets": {"data-a"}}) || !strings.Contains(iss.Composed.Policy, "arn:aws:s3:::data-a/*") {
		t.Errorf("composed %+v", iss.Composed)
	}
	if !strings.Contains(strings.Join(iss.Decision.Trace, "\n"), "s3_bucket data-a reader") {
		t.Errorf("trace %v, want the store's lookup trace", iss.Decision.Trace)
	}
	if !strings.Contains(logs.String(), `"resources":{"buckets":["data-a"]}`) {
		t.Errorf("the decision log does not name the resources: %s", logs.String())
	}

	// Nothing related: the lookup grant is left out, the trace says so.
	store.resources = authz.Resources{}
	r, err := d.Resolve(context.Background(), ledger)
	if err != nil || !reflect.DeepEqual(r.Composed.Grants, []string{"ledger"}) || !strings.Contains(strings.Join(r.Decision.Trace, "\n"), "grant buckets: no resource related; left out") {
		t.Errorf("resolve without resources: %+v, %v", r.Composed, err)
	}
	if r.SessionTags[TagGrant] != "ledger" {
		t.Errorf("grant tag %q, want the composed grants only", r.SessionTags[TagGrant])
	}

	// The store failing to look up is a store failure.
	store.err = errors.New("down")
	if _, err := d.Resolve(context.Background(), ledger); !errors.Is(err, ErrStore) {
		t.Errorf("a failed lookup: %v, want ErrStore", err)
	}
	store.err = authz.ErrSubjectSuspended
	var deny *grants.DenyError
	if _, err := d.Resolve(context.Background(), ledger); !errors.As(err, &deny) || deny.Reason != grants.ReasonSubjectSuspended {
		t.Errorf("a suspension found by the lookup: %v", err)
	}
	// A store without lookups denies a lookup grant.
	d.Store = &store.fakeStore
	if _, err := d.Resolve(context.Background(), ledger); !errors.Is(err, ErrStore) {
		t.Errorf("a store without lookups: %v, want ErrStore", err)
	}
}
