package store

import (
	"context"
	"testing"
	"time"

	"github.com/bpalermo/cracha/access/internal/store/storetest"
	"github.com/bpalermo/cracha/common/grant"
	"github.com/bpalermo/cracha/common/spicedb"
)

func TestTupleRoundTrip(t *testing.T) {
	for _, tt := range []Tuple{
		{Kind: grant.ResourceS3Bucket, Name: "data.raw", Relation: grant.RelationReader, Subject: "prod/a/b"},
		{Kind: grant.ResourceS3Bucket, Name: "data-raw", Relation: grant.RelationWriter, Service: "payments", ExpiresAt: "2026-12-31T00:00:00Z", Clusters: []string{"a", "b"}},
		{Kind: grant.ResourceDynamoDBTable, Name: "orders_1", Relation: grant.RelationReader, Subject: "prod/a/b", Clusters: []string{"a"}},
		{Kind: KindService, Name: "payments", Relation: spicedb.RelationMember, Subject: "prod/a/b"},
	} {
		if err := tt.Validate(); err != nil {
			t.Errorf("%+v: %v", tt, err)
		}
		r, err := tt.Relationship()
		if err != nil {
			t.Fatal(err)
		}
		p, err := r.Proto()
		if err != nil {
			t.Fatal(err)
		}
		got, ok := TupleOf(FromProto(p))
		if !ok || got.Key() != tt.Key() || got.ExpiresAt != tt.ExpiresAt || len(got.Clusters) != len(tt.Clusters) {
			t.Errorf("round trip of %+v = %+v, %t", tt, got, ok)
		}
	}
	if r, _ := (Tuple{Kind: grant.ResourceS3Bucket, Name: "data.raw", Relation: grant.RelationReader, Subject: "prod/a/b"}).Relationship(); r.ResourceID != "data_2eraw" {
		t.Errorf("resource ID = %q, want the idenc encoding", r.ResourceID)
	}
}

func TestTupleValidate(t *testing.T) {
	for name, tt := range map[string]Tuple{
		"both holders":      {Kind: grant.ResourceS3Bucket, Name: "data-a", Relation: grant.RelationReader, Subject: "prod/a/b", Service: "s"},
		"bad relation":      {Kind: grant.ResourceS3Bucket, Name: "data-a", Relation: "owner", Subject: "prod/a/b"},
		"member of service": {Kind: KindService, Name: "s", Relation: spicedb.RelationMember, Service: "t"},
		"bad member rel":    {Kind: KindService, Name: "s", Relation: grant.RelationReader, Subject: "prod/a/b"},
		"bad expiry":        {Kind: KindService, Name: "s", Relation: spicedb.RelationMember, Subject: "prod/a/b", ExpiresAt: "tomorrow"},
		"bad subject":       {Kind: grant.ResourceS3Bucket, Name: "data-a", Relation: grant.RelationReader, Subject: "no spaces"},
	} {
		if err := tt.Validate(); err == nil {
			t.Errorf("%s: valid", name)
		}
	}
}

func TestPendingStore(t *testing.T) {
	fake := storetest.New()
	s := New(fake, time.Second)
	ctx := context.Background()
	id, err := NewPendingID()
	if err != nil || len(id) != 32 {
		t.Fatalf("id %q, %v", id, err)
	}
	p := Pending{
		ID: id, Caller: "spiffe://example.org/ns/a/sa/b", Tuple: Tuple{Kind: grant.ResourceS3Bucket, Name: "data.a", Relation: grant.RelationReader, Subject: "prod/a/b"},
		CreatedAt: "2026-10-18T00:00:00Z", ExpiresAt: "2026-10-19T00:00:00Z",
	}
	if _, err := s.PutPending(ctx, p, map[string]any{"writer": "test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutPending(ctx, p, nil); err == nil {
		t.Error("an ID was used twice")
	}
	got, err := s.ListPending(ctx, id)
	if err != nil || len(got) != 1 || got[0].Tuple.Key() != p.Tuple.Key() || got[0].Caller != p.Caller {
		t.Fatalf("ListPending = %+v, %v", got, err)
	}
	if fake.Keys()[0] != "pending_request:"+id+"#target@s3_bucket:data_2ea" {
		t.Errorf("held %v", fake.Keys())
	}
	if !got[0].Expired(time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)) || got[0].Expired(time.Date(2026, 10, 18, 1, 0, 0, 0, time.UTC)) {
		t.Error("expiry")
	}
	if none, _ := s.ListPending(ctx, "0000"); len(none) != 0 {
		t.Errorf("found %v", none)
	}
}
