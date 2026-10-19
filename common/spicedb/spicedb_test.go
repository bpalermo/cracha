package spicedb

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/bpalermo/cracha/common/idenc"
)

// objectIDRE is SpiceDB's object ID charset.
var objectIDRE = regexp.MustCompile(`^(([a-zA-Z0-9/_|\-=+]{1,})|\*)$`)

// TestSchemaNames checks that every name this package exports is spelled
// the same way in the schema, so a rename of one without the other fails
// here rather than at the first query.
func TestSchemaNames(t *testing.T) {
	if !strings.HasPrefix(Schema, "definition team {}") {
		t.Fatalf("schema does not start with the team definition:\n%s", Schema)
	}
	for _, want := range []string{
		"definition " + TypeTeam + " {",
		"definition " + TypeService + " {",
		"definition " + TypeWorkload + " {",
		"definition " + TypeAWSAccount + " {",
		"definition " + TypeGrant + " {",
		"definition " + TypeS3Bucket + " {",
		"definition " + TypeDynamoDBTable + " {",
		"relation " + RelationTeam + ": " + TypeTeam,
		"relation " + RelationMember + ": " + TypeWorkload,
		"relation " + RelationSuspended + ": " + TypeTeam,
		"relation " + RelationAccount + ": " + TypeAWSAccount,
		"relation " + RelationAssigneeService + ": " + TypeService + " | " + TypeService + " with " + CaveatWithinWindow + " | " + TypeService + " with " + CaveatInClusters + " | " + TypeService + " with " + CaveatBounded,
		"relation " + RelationAssigneeWorkload + ": " + TypeWorkload + " | " + TypeWorkload + " with " + CaveatWithinWindow + " | " + TypeWorkload + " with " + CaveatInClusters + " | " + TypeWorkload + " with " + CaveatBounded,
		"permission " + PermissionIsSuspended + " = " + RelationSuspended,
		"permission " + PermissionAssume + " = " + RelationAssigneeService + "->" + RelationMember + " + " + RelationAssigneeWorkload,
		"caveat " + CaveatWithinWindow + "(" + ContextExpiresAt + " timestamp, " + ContextNow + " timestamp)",
		"caveat " + CaveatInClusters + "(" + ContextAllowed + " list<string>, " + ContextCluster + " string)",
		"caveat " + CaveatBounded + "(" + ContextExpiresAt + " timestamp, " + ContextNow + " timestamp, " + ContextAllowed + " list<string>, " + ContextCluster + " string)",
	} {
		if !strings.Contains(Schema, want) {
			t.Errorf("schema does not contain %q", want)
		}
	}
	holders := strings.Join([]string{
		TypeWorkload, TypeWorkload + " with " + CaveatWithinWindow, TypeWorkload + " with " + CaveatInClusters, TypeWorkload + " with " + CaveatBounded,
		TypeService + "#" + RelationMember, TypeService + "#" + RelationMember + " with " + CaveatWithinWindow,
		TypeService + "#" + RelationMember + " with " + CaveatInClusters, TypeService + "#" + RelationMember + " with " + CaveatBounded,
	}, " | ")
	managed := "  relation " + RelationOwner + ": " + TypeWorkload + " | " + TypeService + "#" + RelationMember + "\n" +
		"  relation " + RelationApprover + ": " + TypeWorkload + " | " + TypeService + "#" + RelationMember + "\n" +
		"  relation " + RelationSensitive + ": " + TypeWorkload + ":*\n" +
		"  permission " + PermissionManage + " = " + RelationOwner + "\n" +
		"  permission " + PermissionApprove + " = " + RelationApprover + " + " + RelationOwner + "\n"
	service := "definition " + TypeService + " {\n" +
		"  relation " + RelationTeam + ": " + TypeTeam + "\n" +
		"  relation " + RelationMember + ": " + TypeWorkload + "\n" + managed + "}"
	if !strings.Contains(Schema, service) {
		t.Errorf("schema does not contain\n%s", service)
	}
	pending := "caveat " + CaveatPendingPayload + "(" + CaveatContextRequest + " string) {\n" +
		"  " + CaveatContextRequest + " != \"\"\n}\n\n" +
		"definition " + DefinitionPendingRequest + " {\n" +
		"  relation " + RelationTarget + ": " + TypeS3Bucket + " with " + CaveatPendingPayload + " | " +
		TypeDynamoDBTable + " with " + CaveatPendingPayload + " | " + TypeService + " with " + CaveatPendingPayload + "\n}"
	if !strings.Contains(Schema, pending) {
		t.Errorf("schema does not contain\n%s", pending)
	}
	if len(ManagedTypes) != 3 || !slices.Contains(ManagedTypes, TypeService) {
		t.Errorf("ManagedTypes = %v", ManagedTypes)
	}
	for _, typ := range ResourceTypes {
		def := "definition " + typ + " {\n" +
			"  relation " + RelationReader + ": " + holders + "\n" +
			"  relation " + RelationWriter + ": " + holders + "\n" +
			"  permission " + PermissionWrite + " = " + RelationWriter + "\n" +
			"  permission " + PermissionRead + " = " + RelationReader + " + " + RelationWriter + "\n" +
			managed +
			"}"
		if !strings.Contains(Schema, def) {
			t.Errorf("schema does not contain\n%s", def)
		}
	}
}

// TestObjectIDs checks that every encoding idenc produces, escapes
// included, is a valid SpiceDB object ID, as are the other IDs this
// package documents.
func TestObjectIDs(t *testing.T) {
	labels, err := idenc.NewLabels(map[string]string{"example.org": "prod"})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []idenc.Identity{
		{TrustDomain: "example.org", Namespace: "payments", ServiceAccount: "ledger"},
		{TrustDomain: "other.org", Namespace: "payments", ServiceAccount: "ledger"},
		{TrustDomain: "example.org", Namespace: "a.b_c", ServiceAccount: "d:e/f|g"},
		{TrustDomain: "example.org", Namespace: strings.Repeat("x", 253), ServiceAccount: strings.Repeat("y", 253)},
	} {
		subject, err := idenc.Authz(id, labels)
		if err != nil {
			t.Fatal(err)
		}
		if !objectIDRE.MatchString(subject) {
			t.Errorf("Authz(%s) = %q is not a SpiceDB object ID", id, subject)
		}
	}
	if !objectIDRE.MatchString("td_2eother_2eorg/a_3ab/c_2fd_7ce") {
		t.Error("an escaped subject is not a SpiceDB object ID")
	}
	for _, bucket := range []string{"data.curated", "a-b.c-d", "cracha-e2e-data"} {
		id, err := idenc.Resource(bucket)
		if err != nil || !objectIDRE.MatchString(id) {
			t.Errorf("Resource(%q) = %q, %v: not a SpiceDB object ID", bucket, id, err)
		}
	}
	for _, id := range []string{"payments-ledger-rw", "payments", "111122223333", TeamNone} {
		if !objectIDRE.MatchString(id) {
			t.Errorf("%q is not a SpiceDB object ID", id)
		}
	}
}
