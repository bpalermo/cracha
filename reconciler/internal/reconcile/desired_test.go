package reconcile

import (
	"strings"
	"testing"

	"github.com/bpalermo/cracha/common/grant"
)

// lines renders relationships one per line, for comparisons.
func lines(rels []Relationship) string {
	var b strings.Builder
	for _, r := range rels {
		b.WriteString(r.String())
		b.WriteString("\n")
	}
	return b.String()
}

func assign(name, subject string, grants []string, expiresAt string, clusters []string) *grant.Assignment {
	return &grant.Assignment{
		Kind: grant.KindAssignment, Metadata: grant.Metadata{Name: name},
		Spec: grant.AssignmentSpec{Subject: subject, Grants: grants, ExpiresAt: expiresAt, Clusters: clusters},
	}
}

func TestDesired(t *testing.T) {
	src := &grant.Source{
		Grants: []*grant.Grant{
			{Kind: grant.KindGrant, Metadata: grant.Metadata{Name: "g1"}, Spec: grant.GrantSpec{Account: "111122223333"}},
			{Kind: grant.KindGrant, Metadata: grant.Metadata{Name: "g2"}, Spec: grant.GrantSpec{Account: "444455556666"}},
		},
		Services: []*grant.Service{
			{Kind: grant.KindService, Metadata: grant.Metadata{Name: "svc"}, Spec: grant.ServiceSpec{
				Team: "payments", Members: []string{"prod/p/w1", "prod/p/w2"},
				Grants: []grant.BoundedGrant{
					{Name: "g1"},
					{Name: "g2", ExpiresAt: "2030-01-01T02:00:00+02:00", Clusters: []string{"west", "east", "east"}},
				},
			}},
		},
		Assignments: []*grant.Assignment{
			assign("a1", "prod/p/w1", []string{"g2"}, "", nil),
			assign("a2", "prod/p/w3", []string{"g1"}, "2030-01-01T00:00:00Z", nil),
			assign("a3", "prod/p/w3", []string{"g2"}, "", []string{"east"}),
			assign("a4", "prod/p/w4", []string{"g1"}, "2030-01-01T00:00:00Z", []string{"east"}),
			{Kind: grant.KindAssignment, Metadata: grant.Metadata{Name: "a5"}, Spec: grant.AssignmentSpec{Subject: "prod/p/w1", Suspended: true}},
			{Kind: grant.KindAssignment, Metadata: grant.Metadata{Name: "a6"}, Spec: grant.AssignmentSpec{Subject: "prod/p/w5", Suspended: true, Grants: []string{"g1"}}},
		},
	}
	got, err := Desired(src)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{
		"grant:g1#account@aws_account:111122223333",
		"grant:g1#assignee_service@service:svc",
		"grant:g1#assignee_workload@workload:prod/p/w3[within_window{expires_at=2030-01-01T00:00:00Z}]",
		"grant:g1#assignee_workload@workload:prod/p/w4[bounded{expires_at=2030-01-01T00:00:00Z allowed=[east]}]",
		"grant:g1#assignee_workload@workload:prod/p/w5",
		"grant:g2#account@aws_account:444455556666",
		"grant:g2#assignee_service@service:svc[bounded{expires_at=2030-01-01T00:00:00Z allowed=[east,west]}]",
		"grant:g2#assignee_workload@workload:prod/p/w1",
		"grant:g2#assignee_workload@workload:prod/p/w3[in_clusters{allowed=[east]}]",
		"service:svc#member@workload:prod/p/w1",
		"service:svc#member@workload:prod/p/w2",
		"service:svc#owner@team:payments",
		"workload:prod/p/w1#suspended@team:payments",
		"workload:prod/p/w5#suspended@team:none",
	}, "\n") + "\n"
	if lines(got) != want {
		t.Errorf("Desired =\n%swant:\n%s", lines(got), want)
	}
	for _, r := range got {
		p, err := r.Proto()
		if err != nil {
			t.Fatalf("%s: Proto: %v", r, err)
		}
		if back := FromProto(p); !back.Equal(r) {
			t.Errorf("FromProto(Proto(%s)) = %s", r, back)
		}
	}
}

func TestDesiredMergesAssignments(t *testing.T) {
	const expiry, later = "2030-01-01T00:00:00Z", "2031-01-01T00:00:00Z"
	tests := []struct {
		name string
		a, b *grant.Assignment
		want string // the relationship, or "" for an error
	}{
		{"unbounded wins", assign("a", "s", []string{"g"}, "", nil), assign("b", "s", []string{"g"}, expiry, []string{"east"}), "grant:g#assignee_workload@workload:s"},
		{"later expiry wins", assign("a", "s", []string{"g"}, expiry, nil), assign("b", "s", []string{"g"}, later, nil), "grant:g#assignee_workload@workload:s[within_window{expires_at=" + later + "}]"},
		{"clusters unite", assign("a", "s", []string{"g"}, "", []string{"west"}), assign("b", "s", []string{"g"}, "", []string{"east"}), "grant:g#assignee_workload@workload:s[in_clusters{allowed=[east,west]}]"},
		{"same expiry clusters unite", assign("a", "s", []string{"g"}, expiry, []string{"west"}), assign("b", "s", []string{"g"}, expiry, []string{"east"}), "grant:g#assignee_workload@workload:s[bounded{expires_at=" + expiry + " allowed=[east,west]}]"},
		{"superset of clusters wins", assign("a", "s", []string{"g"}, expiry, []string{"west"}), assign("b", "s", []string{"g"}, later, []string{"east", "west"}), "grant:g#assignee_workload@workload:s[bounded{expires_at=" + later + " allowed=[east,west]}]"},
		{"identical", assign("a", "s", []string{"g"}, expiry, nil), assign("b", "s", []string{"g"}, expiry, nil), "grant:g#assignee_workload@workload:s[within_window{expires_at=" + expiry + "}]"},
		{"time against clusters", assign("a", "s", []string{"g"}, expiry, nil), assign("b", "s", []string{"g"}, "", []string{"east"}), ""},
		{"different expiries and clusters", assign("a", "s", []string{"g"}, expiry, []string{"west"}), assign("b", "s", []string{"g"}, later, []string{"east"}), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := &grant.Source{Assignments: []*grant.Assignment{tt.a, tt.b}}
			got, err := Desired(src)
			if tt.want == "" {
				if err == nil || !strings.Contains(err.Error(), "subject s, grant g: assignments a and b") {
					t.Fatalf("Desired = %v, %v; want the two assignments named in an error", got, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if lines(got) != tt.want+"\n" {
				t.Errorf("Desired =\n%swant:\n%s", lines(got), tt.want)
			}
		})
	}
}

func TestDesiredBadExpiry(t *testing.T) {
	_, err := Desired(&grant.Source{Assignments: []*grant.Assignment{assign("a", "s", []string{"g"}, "soon", nil)}})
	if err == nil || !strings.Contains(err.Error(), "assignment a: expiresAt") {
		t.Errorf("error = %v", err)
	}
	_, err = Desired(&grant.Source{Services: []*grant.Service{{Metadata: grant.Metadata{Name: "s"}, Spec: grant.ServiceSpec{Grants: []grant.BoundedGrant{{Name: "g", ExpiresAt: "soon"}}}}}})
	if err == nil || !strings.Contains(err.Error(), "service s: grant g: expiresAt") {
		t.Errorf("error = %v", err)
	}
}

func access(name, subject, service, bucket, relation, expiresAt string, clusters []string) *grant.Access {
	return &grant.Access{
		Kind: grant.KindAccess, Metadata: grant.Metadata{Name: name},
		Spec: grant.AccessSpec{
			Subject: subject, Service: service, Resource: grant.Resource{Kind: grant.ResourceS3Bucket, Name: bucket},
			Relation: relation, ExpiresAt: expiresAt, Clusters: clusters,
		},
	}
}

func TestDesiredAccess(t *testing.T) {
	src := &grant.Source{Accesses: []*grant.Access{
		access("a1", "prod/p/w1", "", "data-raw", grant.RelationReader, "", nil),
		access("a2", "", "svc", "data.curated", grant.RelationWriter, "", []string{"west"}),
		access("a3", "", "svc", "data.curated", grant.RelationWriter, "", []string{"east"}),
		access("a4", "prod/p/w2", "", "data-old", grant.RelationReader, "2030-01-01T00:00:00Z", nil),
		{Kind: grant.KindAccess, Metadata: grant.Metadata{Name: "a5"}, Spec: grant.AccessSpec{
			Subject: "prod/p/w2", Resource: grant.Resource{Kind: grant.ResourceDynamoDBTable, Name: "Ledger_Index"}, Relation: grant.RelationWriter,
			ExpiresAt: "2030-01-01T00:00:00Z", Clusters: []string{"east"},
		}},
	}}
	got, err := Desired(src)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{
		"dynamodb_table:Ledger_5fIndex#writer@workload:prod/p/w2[bounded{expires_at=2030-01-01T00:00:00Z allowed=[east]}]",
		"s3_bucket:data-old#reader@workload:prod/p/w2[within_window{expires_at=2030-01-01T00:00:00Z}]",
		"s3_bucket:data-raw#reader@workload:prod/p/w1",
		"s3_bucket:data_2ecurated#writer@service:svc#member[in_clusters{allowed=[east,west]}]",
	}, "\n") + "\n"
	if lines(got) != want {
		t.Errorf("Desired =\n%swant:\n%s", lines(got), want)
	}
	for _, r := range got {
		p, err := r.Proto()
		if err != nil {
			t.Fatalf("%s: Proto: %v", r, err)
		}
		if back := FromProto(p); !back.Equal(r) {
			t.Errorf("FromProto(Proto(%s)) = %s", r, back)
		}
	}
	// A relation to a service's members and one to the service object
	// itself are different relationships.
	member := Relationship{ResourceType: "s3_bucket", ResourceID: "b", Relation: "reader", SubjectType: "service", SubjectID: "svc", SubjectRelation: "member"}
	plainService := member
	plainService.SubjectRelation = ""
	if member.Key() == plainService.Key() {
		t.Error("the subject relation is not part of the key")
	}
}
