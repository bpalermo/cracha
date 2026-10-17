// Package reconcile turns a grant source tree (common/grant) into the
// SpiceDB relationships of docs/design.md section 6.4 and makes a SpiceDB
// instance hold exactly those: it is the authz-reconciler writer of the
// design. It owns every relationship whose resource is a grant, a service or
// a workload; what it does not find in the tree it deletes.
package reconcile

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/bpalermo/cracha/common/spicedb"
)

// Relationship is one SpiceDB relationship in a form that compares by
// value: the caveat is reduced to the bounds it carries.
type Relationship struct {
	ResourceType string
	ResourceID   string
	Relation     string
	SubjectType  string
	SubjectID    string
	// Caveat is the caveat's name, or empty for none. ExpiresAt (RFC 3339,
	// UTC) and Allowed (sorted) are its context; a context value of another
	// shape than this package writes is kept as its text, so that it
	// compares unequal and is rewritten.
	Caveat    string
	ExpiresAt string
	Allowed   []string
}

// Key identifies the relationship without its caveat, the way SpiceDB does:
// writing a relationship with the same key and another caveat replaces it.
func (r Relationship) Key() string {
	return r.ResourceType + ":" + r.ResourceID + "#" + r.Relation + "@" + r.SubjectType + ":" + r.SubjectID
}

// String renders the relationship with its caveat, for logs and diffs.
func (r Relationship) String() string {
	if r.Caveat == "" {
		return r.Key()
	}
	var ctx []string
	if r.ExpiresAt != "" {
		ctx = append(ctx, spicedb.ContextExpiresAt+"="+r.ExpiresAt)
	}
	if r.Allowed != nil {
		ctx = append(ctx, spicedb.ContextAllowed+"=["+strings.Join(r.Allowed, ",")+"]")
	}
	return r.Key() + "[" + r.Caveat + "{" + strings.Join(ctx, " ") + "}]"
}

// Equal reports whether two relationships are the same, caveat included.
func (r Relationship) Equal(o Relationship) bool {
	return r.Key() == o.Key() && r.Caveat == o.Caveat && r.ExpiresAt == o.ExpiresAt && slices.Equal(r.Allowed, o.Allowed)
}

// Proto converts the relationship to its wire form.
func (r Relationship) Proto() (*v1.Relationship, error) {
	rel := &v1.Relationship{
		Resource: &v1.ObjectReference{ObjectType: r.ResourceType, ObjectId: r.ResourceID},
		Relation: r.Relation,
		Subject:  &v1.SubjectReference{Object: &v1.ObjectReference{ObjectType: r.SubjectType, ObjectId: r.SubjectID}},
	}
	if r.Caveat == "" {
		return rel, nil
	}
	context := map[string]any{}
	if r.ExpiresAt != "" {
		context[spicedb.ContextExpiresAt] = r.ExpiresAt
	}
	if r.Allowed != nil {
		allowed := make([]any, len(r.Allowed))
		for i, c := range r.Allowed {
			allowed[i] = c
		}
		context[spicedb.ContextAllowed] = allowed
	}
	s, err := structpb.NewStruct(context)
	if err != nil {
		return nil, fmt.Errorf("%s: caveat context: %w", r.Key(), err)
	}
	rel.OptionalCaveat = &v1.ContextualizedCaveat{CaveatName: r.Caveat, Context: s}
	return rel, nil
}

// FromProto converts a relationship read from SpiceDB.
func FromProto(rel *v1.Relationship) Relationship {
	r := Relationship{
		ResourceType: rel.GetResource().GetObjectType(),
		ResourceID:   rel.GetResource().GetObjectId(),
		Relation:     rel.GetRelation(),
		SubjectType:  rel.GetSubject().GetObject().GetObjectType(),
		SubjectID:    rel.GetSubject().GetObject().GetObjectId(),
	}
	caveat := rel.GetOptionalCaveat()
	if caveat == nil {
		return r
	}
	r.Caveat = caveat.GetCaveatName()
	fields := caveat.GetContext().GetFields()
	if v, ok := fields[spicedb.ContextExpiresAt]; ok {
		r.ExpiresAt = contextString(v)
	}
	if v, ok := fields[spicedb.ContextAllowed]; ok {
		r.Allowed = contextList(v)
	}
	return r
}

// contextString reads a string context value; another kind is rendered as
// text so that it never equals what this package writes.
func contextString(v *structpb.Value) string {
	if s, ok := v.GetKind().(*structpb.Value_StringValue); ok {
		return s.StringValue
	}
	return "?" + v.String()
}

// contextList reads a list of strings, sorted; another kind, or a list
// with a non-string, becomes a one-element list of its text.
func contextList(v *structpb.Value) []string {
	list, ok := v.GetKind().(*structpb.Value_ListValue)
	if !ok {
		return []string{"?" + v.String()}
	}
	out := make([]string, 0, len(list.ListValue.GetValues()))
	for _, item := range list.ListValue.GetValues() {
		s, ok := item.GetKind().(*structpb.Value_StringValue)
		if !ok {
			return []string{"?" + v.String()}
		}
		out = append(out, s.StringValue)
	}
	sort.Strings(out)
	return out
}

// sortByKey orders relationships by key, for deterministic output.
func sortByKey(rels []Relationship) {
	sort.Slice(rels, func(i, j int) bool { return rels[i].Key() < rels[j].Key() })
}
