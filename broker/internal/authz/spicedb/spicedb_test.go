package spicedb

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/bpalermo/cracha/broker/internal/authz"
	"github.com/bpalermo/cracha/common/spicedb/conn"
	"github.com/bpalermo/cracha/common/spiffetest"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	ledger = "prod/payments/ledger"
	worker = "prod/payments/worker"
	token  = "GhUKEzE3MDAwMDAwMDAwMDAwMDAwMDA="
)

var (
	clock   = time.Date(2026, 5, 1, 12, 30, 0, 0, time.UTC)
	subject = authz.Subject{ID: ledger, Cluster: "prod-a"}
)

// fixture is the example of the static backend's package documentation in
// relationships: the ledger is a member of payments-api, owned by payments,
// with a service grant, a cluster-bounded service grant, a time-bounded
// direct grant and a direct grant it also holds through the service.
func fixture() *fakeSpiceDB {
	windowed := parseRel("grant:break-glass#assignee_workload@workload:" + ledger)
	windowed.caveat, windowed.expiresAt = "within_window", "2026-06-01T00:00:00Z"
	bounded := parseRel("grant:prod-only#assignee_service@service:payments-api")
	bounded.caveat, bounded.allowed = "in_clusters", []string{"prod-a", "prod-b"}
	return newFake(token,
		parseRel("service:payments-api#team@team:payments"),
		parseRel("service:payments-api#member@workload:"+ledger),
		parseRel("service:payments-api#member@workload:"+worker),
		parseRel("grant:payments-ledger-rw#assignee_service@service:payments-api"),
		parseRel("grant:payments-ledger-rw#assignee_workload@workload:"+ledger),
		windowed,
		bounded,
	)
}

func newStore(f *fakeSpiceDB) *Store {
	return New(f, f, WithClock(func() time.Time { return clock }), WithTimeout(time.Second))
}

func TestListGrants(t *testing.T) {
	f := fixture()
	d, err := newStore(f).ListGrants(context.Background(), subject, authz.Consistency{})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"break-glass", "payments-ledger-rw", "prod-only"}; !reflect.DeepEqual(d.Grants, want) {
		t.Errorf("grants %v, want %v (sorted, without the duplicate)", d.Grants, want)
	}
	if want := map[string]string{"service": "payments-api", "team": "payments"}; !reflect.DeepEqual(d.Tags, want) {
		t.Errorf("tags %v, want %v", d.Tags, want)
	}
	if d.Token != token {
		t.Errorf("token %q, want the zedtoken %q", d.Token, token)
	}
	if len(d.Trace) < 4 {
		t.Errorf("trace %q explains too little", d.Trace)
	}
	if want := map[string]string{"now": "2026-05-01T12:30:00Z", "cluster": "prod-a"}; !reflect.DeepEqual(f.lastContext, want) {
		t.Errorf("caveat context %v, want %v", f.lastContext, want)
	}
	if !f.lastConsistency.GetMinimizeLatency() {
		t.Errorf("consistency %v, want minimize_latency", f.lastConsistency)
	}
}

func TestListGrantsConditions(t *testing.T) {
	tests := []struct {
		name    string
		now     time.Time
		cluster string
		grants  []string
	}{
		{"in window and cluster", clock, "prod-a", []string{"break-glass", "payments-ledger-rw", "prod-only"}},
		{"other cluster", clock, "dev", []string{"break-glass", "payments-ledger-rw"}},
		{"expired", clock.AddDate(0, 2, 0), "prod-b", []string{"payments-ledger-rw", "prod-only"}},
		{"at the expiry instant", time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), "prod-a", []string{"payments-ledger-rw", "prod-only"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New(fixture(), nil, WithClock(func() time.Time { return tt.now }))
			d, err := s.ListGrants(context.Background(), authz.Subject{ID: ledger, Cluster: tt.cluster}, authz.Consistency{})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(d.Grants, tt.grants) {
				t.Errorf("grants %v, want %v", d.Grants, tt.grants)
			}
		})
	}
}

func TestUnknownSubjectHoldsNothing(t *testing.T) {
	d, err := newStore(fixture()).ListGrants(context.Background(), authz.Subject{ID: "prod/nobody/nobody", Cluster: "prod-a"}, authz.Consistency{})
	if err != nil {
		t.Fatal(err)
	}
	if d.Grants != nil || len(d.Tags) != 0 {
		t.Errorf("decision %+v, want nothing held", d)
	}
}

func TestCheck(t *testing.T) {
	f := fixture()
	s := newStore(f)
	for grant, want := range map[string]bool{"payments-ledger-rw": true, "prod-only": true, "break-glass": true, "nope": false} {
		r, err := s.Check(context.Background(), subject, grant, authz.Consistency{})
		if err != nil {
			t.Fatal(err)
		}
		if r.Allowed != want || r.Token != token || len(r.Trace) == 0 {
			t.Errorf("Check(%q) = %+v, want allowed %v with the zedtoken and a trace", grant, r, want)
		}
	}
	r, err := s.Check(context.Background(), authz.Subject{ID: ledger, Cluster: "dev"}, "prod-only", authz.Consistency{})
	if err != nil || r.Allowed {
		t.Errorf("cluster-bounded grant in another cluster: %+v, %v", r, err)
	}
	if f.lastContext["cluster"] != "dev" {
		t.Errorf("check sent cluster %q", f.lastContext["cluster"])
	}
}

func TestConsistency(t *testing.T) {
	f := fixture()
	s := newStore(f)
	fresh := base64.StdEncoding.EncodeToString([]byte("some revision"))
	if _, err := s.ListGrants(context.Background(), subject, authz.Consistency{AtLeastAsFresh: authz.Token(fresh)}); err != nil {
		t.Fatal(err)
	}
	if got := f.lastConsistency.GetAtLeastAsFresh().GetToken(); got != fresh {
		t.Errorf("consistency %v, want at_least_as_fresh %q", f.lastConsistency, fresh)
	}
	f.lastConsistency = nil
	if _, err := s.Check(context.Background(), subject, "nope", authz.Consistency{AtLeastAsFresh: "not base64!"}); err == nil {
		t.Fatal("a token that is not a zedtoken was accepted")
	}
	if _, err := s.ListGrants(context.Background(), subject, authz.Consistency{AtLeastAsFresh: "not base64!"}); err == nil {
		t.Fatal("a token that is not a zedtoken was accepted")
	}
	if f.lastConsistency != nil {
		t.Error("a bad token reached SpiceDB")
	}
}

func TestSuspended(t *testing.T) {
	f := fixture()
	f.write(parseRel("workload:" + ledger + "#suspended@team:security"))
	s := newStore(f)
	_, err := s.ListGrants(context.Background(), subject, authz.Consistency{})
	if !errors.Is(err, authz.ErrSubjectSuspended) || !strings.Contains(err.Error(), "security") {
		t.Fatalf("ListGrants: %v", err)
	}
	_, err = s.Check(context.Background(), subject, "payments-ledger-rw", authz.Consistency{})
	if !errors.Is(err, authz.ErrSubjectSuspended) {
		t.Fatalf("Check: %v", err)
	}
}

func TestTags(t *testing.T) {
	t.Run("no service", func(t *testing.T) {
		f := fixture()
		f.write(parseRel("grant:solo#assignee_workload@workload:prod/solo/solo"))
		d, err := newStore(f).ListGrants(context.Background(), authz.Subject{ID: "prod/solo/solo", Cluster: "prod-a"}, authz.Consistency{})
		if err != nil {
			t.Fatal(err)
		}
		if len(d.Tags) != 0 || !reflect.DeepEqual(d.Grants, []string{"solo"}) {
			t.Errorf("decision %+v", d)
		}
	})
	t.Run("two services", func(t *testing.T) {
		f := fixture()
		f.write(parseRel("service:other#member@workload:" + ledger))
		d, err := newStore(f).ListGrants(context.Background(), subject, authz.Consistency{})
		if err != nil {
			t.Fatal(err)
		}
		if len(d.Tags) != 0 {
			t.Errorf("tags %v, want none for a member of two services", d.Tags)
		}
		if !strings.Contains(strings.Join(d.Trace, "\n"), "2 services") {
			t.Errorf("trace %q does not say the subject is in 2 services", d.Trace)
		}
	})
	t.Run("two teams", func(t *testing.T) {
		f := fixture()
		f.write(parseRel("service:payments-api#team@team:finance"))
		d, err := newStore(f).ListGrants(context.Background(), subject, authz.Consistency{})
		if err != nil {
			t.Fatal(err)
		}
		if want := map[string]string{"service": "payments-api"}; !reflect.DeepEqual(d.Tags, want) {
			t.Errorf("tags %v, want %v", d.Tags, want)
		}
	})
}

func TestConditionalIsAnError(t *testing.T) {
	f := newFake(token)
	odd := parseRel("grant:odd#assignee_workload@workload:" + ledger)
	odd.caveat = "unknown_to_this_broker"
	f.write(odd)
	s := newStore(f)
	if _, err := s.ListGrants(context.Background(), subject, authz.Consistency{}); err == nil || !strings.Contains(err.Error(), "CONDITIONAL") {
		t.Errorf("ListGrants with a conditional result: %v, want an error naming it", err)
	}
	if _, err := s.Check(context.Background(), subject, "odd", authz.Consistency{}); err == nil || !strings.Contains(err.Error(), "CONDITIONAL") {
		t.Errorf("Check with a conditional result: %v, want an error naming it", err)
	}
}

func TestGRPCErrorIsADeny(t *testing.T) {
	f := fixture()
	f.err = status.Error(codes.Unavailable, "spicedb is away")
	s := newStore(f)
	if _, err := s.ListGrants(context.Background(), subject, authz.Consistency{}); err == nil || status.Code(err) != codes.Unavailable {
		t.Errorf("ListGrants: %v, want the gRPC error", err)
	}
	if _, err := s.Check(context.Background(), subject, "payments-ledger-rw", authz.Consistency{}); err == nil || status.Code(err) != codes.Unavailable {
		t.Errorf("Check: %v, want the gRPC error", err)
	}
}

func TestWatchMapping(t *testing.T) {
	f := fixture()
	f.watchResponses = []*v1.WatchResponse{
		update("t1", parseRel("grant:break-glass#assignee_workload@workload:"+ledger)),
		update("t2", parseRel("grant:prod-only#assignee_service@service:payments-api")),
		update("t3", parseRel("service:payments-api#member@workload:"+worker)),
		update("t4", parseRel("service:payments-api#team@team:finance")),
		update("t5", parseRel("workload:"+ledger+"#suspended@team:security")),
		update("t6", parseRel("grant:break-glass#account@aws_account:111122223333")),
		update("t7", parseRel("s3_bucket:data_2eraw#reader@workload:"+worker)),
		update("t8", parseRel("s3_bucket:data-raw#writer@service:payments-api#member")),
		// The write path's relations: nothing the broker reads.
		update("t8a", parseRel("s3_bucket:data-raw#owner@workload:"+worker)),
		update("t8b", parseRel("service:payments-api#approver@service:payments-api#member")),
		update("t8c", parseRel("dynamodb_table:ledger#sensitive@workload:*")),
		{ChangesThrough: &v1.ZedToken{Token: "t9"}, IsCheckpoint: true},
	}
	ch, err := newStore(f).Watch(context.Background(), "t0")
	if err != nil {
		t.Fatal(err)
	}
	var got []authz.Change
	for c := range ch {
		got = append(got, c)
	}
	want := []authz.Change{
		{Subject: authz.Subject{ID: ledger}, Grant: "break-glass", Token: "t1"},
		{Token: "t2"},
		{Token: "t3"},
		{Token: "t4"},
		{Token: "t5"},
		{Subject: authz.Subject{ID: worker}, Token: "t7"},
		{Token: "t8"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("changes %+v, want %+v", got, want)
	}
	if f.lastWatch.GetOptionalStartCursor().GetToken() != "t0" {
		t.Errorf("watch started at %v, want t0", f.lastWatch.GetOptionalStartCursor())
	}
	if want := []string{"grant", "service", "workload", "s3_bucket", "dynamodb_table"}; !reflect.DeepEqual(f.lastWatch.GetOptionalObjectTypes(), want) {
		t.Errorf("watched %v, want %v", f.lastWatch.GetOptionalObjectTypes(), want)
	}
}

func TestWatchFromTheStart(t *testing.T) {
	f := fixture()
	ch, err := newStore(f).Watch(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	for range ch {
	}
	if f.lastWatch.GetOptionalStartCursor() != nil {
		t.Errorf("watch without a token started at %v", f.lastWatch.GetOptionalStartCursor())
	}
}

func TestWatchClosesWhenTheStreamFails(t *testing.T) {
	f := fixture()
	f.watchResponses = []*v1.WatchResponse{update("t1", parseRel("workload:x#suspended@team:y"))}
	f.watchEnd = status.Error(codes.Unavailable, "gone")
	ch, err := newStore(f).Watch(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for range ch {
		n++
	}
	if n != 1 {
		t.Errorf("got %d changes before the stream failed, want 1", n)
	}
}

func TestWatchClosesWhenTheContextEnds(t *testing.T) {
	f := fixture()
	f.watchBlock = true
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := newStore(f).Watch(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("a change after the context ended")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("channel still open after the context ended")
	}
}

func TestWatchRefused(t *testing.T) {
	f := fixture()
	f.watchErr = status.Error(codes.Unimplemented, "no watch here")
	if _, err := newStore(f).Watch(context.Background(), ""); err == nil || !errors.Is(err, f.watchErr) {
		t.Fatalf("got %v, want the backend's error", err)
	}
	if _, err := New(f, nil).Watch(context.Background(), ""); err == nil {
		t.Fatal("a store without a watch client watched")
	}
}

func TestDial(t *testing.T) {
	ca := spiffetest.NewCA(t, "cracha.test")
	cfg := conn.Config{
		Endpoint: "127.0.0.1:1",
		Server:   spiffeid.RequireFromString("spiffe://cracha.test/ns/cracha-system/sa/cracha-spicedb"),
		SVIDs:    ca.SVID(t, "spiffe://cracha.test/ns/cracha-system/sa/cracha-broker"),
		Bundles:  ca.Bundle(),
	}
	if s, err := Dial(conn.Config{Endpoint: cfg.Endpoint}); err == nil {
		s.Close()
		t.Fatal("a configuration without an SVID source was accepted")
	}
	// The connection is lazy, so an endpoint nobody listens on fails the
	// call, within the timeout, not Dial.
	s, err := Dial(cfg, WithTimeout(200*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Check(context.Background(), subject, "g", authz.Consistency{}); err == nil {
		t.Fatal("a call to nowhere succeeded")
	}
}

func TestLookupResources(t *testing.T) {
	f := fixture()
	f.write(parseRel("s3_bucket:data_2ecurated#reader@workload:"+ledger), parseRel("s3_bucket:data-raw#writer@workload:"+ledger))
	s := newStore(f)
	got, err := s.LookupResources(context.Background(), subject, "s3_bucket", "read", authz.Consistency{})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"data-raw", "data.curated"}; !reflect.DeepEqual(got.Names, want) || got.Token != token {
		t.Errorf("read = %+v, want %v at %s", got, want, token)
	}
	if f.lastContext["cluster"] != subject.Cluster || f.lastContext["now"] == "" {
		t.Errorf("caveat context = %v, want now and the cluster", f.lastContext)
	}
	got, err = s.LookupResources(context.Background(), subject, "s3_bucket", "write", authz.Consistency{})
	if err != nil || !reflect.DeepEqual(got.Names, []string{"data-raw"}) {
		t.Errorf("write = %+v, %v, want data-raw", got, err)
	}
	if _, err := s.LookupResources(context.Background(), subject, "grant", "assume", authz.Consistency{}); err == nil {
		t.Error("a lookup of grants as resources succeeded")
	}
	// An ID idenc did not make is an error, not a name.
	f.write(parseRel("s3_bucket:data_2Dodd#reader@workload:" + ledger))
	if _, err := s.LookupResources(context.Background(), subject, "s3_bucket", "read", authz.Consistency{}); err == nil {
		t.Error("a non-canonical resource ID was accepted")
	}
	f.err = status.Error(codes.Unavailable, "spicedb is away")
	if _, err := s.LookupResources(context.Background(), subject, "s3_bucket", "read", authz.Consistency{}); status.Code(err) != codes.Unavailable {
		t.Errorf("LookupResources: %v, want the gRPC error", err)
	}
}
