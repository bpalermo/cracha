package grant

import (
	"reflect"
	"strings"
	"testing"
)

func assignment(name, subject string, grants []string, expiresAt string, clusters []string) *Assignment {
	return &Assignment{
		Kind: KindAssignment, Metadata: Metadata{Name: name},
		Spec: AssignmentSpec{Subject: subject, Grants: grants, ExpiresAt: expiresAt, Clusters: clusters},
	}
}

func TestResolveAssignments(t *testing.T) {
	src := &Source{
		Services: []*Service{
			{Kind: KindService, Metadata: Metadata{Name: "zeta"}, Spec: ServiceSpec{Team: "z"}},
			{Kind: KindService, Metadata: Metadata{Name: "svc"}, Spec: ServiceSpec{
				Team: "payments", Members: []string{"prod/p/w2", "prod/p/w1"},
				Grants: []BoundedGrant{
					{Name: "g2", ExpiresAt: "2030-01-01T02:00:00+02:00", Clusters: []string{"west", "east", "east"}},
					{Name: "g1"},
				},
			}},
		},
		Assignments: []*Assignment{
			assignment("a1", "prod/p/w1", []string{"g2"}, "", nil),
			assignment("a2", "prod/p/w3", []string{"g1"}, "2030-01-01T00:00:00Z", nil),
			assignment("a3", "prod/p/w3", []string{"g1"}, "2031-01-01T00:00:00Z", nil),
			assignment("a4", "prod/p/w3", []string{"g2"}, "", []string{"east"}),
			{Kind: KindAssignment, Metadata: Metadata{Name: "a5"}, Spec: AssignmentSpec{Subject: "prod/p/w1", Suspended: true}},
		},
	}
	services, workloads, err := ResolveAssignments(src)
	if err != nil {
		t.Fatal(err)
	}
	wantServices := []AssignedService{
		{Name: "svc", Team: "payments", Members: []string{"prod/p/w1", "prod/p/w2"}, Grants: []BoundedGrant{
			{Name: "g1"},
			{Name: "g2", ExpiresAt: "2030-01-01T00:00:00Z", Clusters: []string{"east", "west"}},
		}},
		{Name: "zeta", Team: "z", Members: []string{}, Grants: []BoundedGrant{}},
	}
	if !reflect.DeepEqual(services, wantServices) {
		t.Errorf("services =\n%+v\nwant\n%+v", services, wantServices)
	}
	wantWorkloads := []AssignedWorkload{
		{Subject: "prod/p/w1", Suspended: true, Grants: []BoundedGrant{{Name: "g2"}}},
		{Subject: "prod/p/w3", Grants: []BoundedGrant{
			{Name: "g1", ExpiresAt: "2031-01-01T00:00:00Z"},
			{Name: "g2", Clusters: []string{"east"}},
		}},
	}
	if !reflect.DeepEqual(workloads, wantWorkloads) {
		t.Errorf("workloads =\n%+v\nwant\n%+v", workloads, wantWorkloads)
	}
}

func TestResolveAssignmentsRefuses(t *testing.T) {
	_, _, err := ResolveAssignments(&Source{Assignments: []*Assignment{
		assignment("a", "s", []string{"g"}, "2030-01-01T00:00:00Z", nil),
		assignment("b", "s", []string{"g"}, "", []string{"east"}),
	}})
	if err == nil || !strings.Contains(err.Error(), "subject s, grant g: assignments a and b") {
		t.Errorf("error = %v, want the two assignments named", err)
	}
	_, _, err = ResolveAssignments(&Source{Assignments: []*Assignment{assignment("a", "s", []string{"g"}, "soon", nil)}})
	if err == nil || !strings.Contains(err.Error(), "assignment a: expiresAt") {
		t.Errorf("error = %v", err)
	}
}

func TestAssignmentsRoundTrip(t *testing.T) {
	c := compileGoodAll(t, "v1")
	data, err := MarshalAssignments(c.Assignments)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseAssignments(data)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(parsed, c.Assignments) {
		t.Errorf("ParseAssignments(MarshalAssignments(a)) =\n%+v\nwant\n%+v", parsed, c.Assignments)
	}
	kind, version, err := ParseArtifact(data)
	if err != nil || kind != ArtifactAssignments || version != "v1" {
		t.Errorf("ParseArtifact(assignments) = %q, %q, %v", kind, version, err)
	}
	bundle, err := Marshal(c.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	kind, version, err = ParseArtifact(bundle)
	if err != nil || kind != ArtifactBundle || version != "v1" {
		t.Errorf("ParseArtifact(bundle) = %q, %q, %v", kind, version, err)
	}
	if _, _, err := ParseArtifact([]byte(`{"version":"v1"}`)); err == nil {
		t.Error("ParseArtifact accepted a document of neither kind")
	}
}

func TestParseAssignmentsRejects(t *testing.T) {
	tests := []struct {
		name, doc, want string
	}{
		{"unknown field", `{"version":"v","generatedAt":"t","services":[],"workloads":[],"extra":1}`, `unknown field "extra"`},
		{"bad version", `{"version":"../x","generatedAt":"t","services":[],"workloads":[]}`, "version"},
		{"trailing", `{"version":"v","generatedAt":"t","services":[],"workloads":[]} {}`, "trailing data"},
		{"not json", `nope`, "assignments:"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseAssignments([]byte(tt.doc)); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}
