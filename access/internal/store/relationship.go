package store

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
// value, its caveat reduced to the bounds it carries (the reconciler's
// form, design 6.4).
type Relationship struct {
	ResourceType    string
	ResourceID      string
	Relation        string
	SubjectType     string
	SubjectID       string
	SubjectRelation string
	// Caveat is the caveat's name, or empty. ExpiresAt (RFC 3339, UTC)
	// and Allowed (sorted) are the bounds in its context.
	Caveat    string
	ExpiresAt string
	Allowed   []string
}

// Key identifies the relationship without its caveat, as SpiceDB does.
func (r Relationship) Key() string {
	k := r.ResourceType + ":" + r.ResourceID + "#" + r.Relation + "@" + r.SubjectType + ":" + r.SubjectID
	if r.SubjectRelation != "" {
		k += "#" + r.SubjectRelation
	}
	return k
}

// String is the relationship with its caveat, for the audit log.
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

// setBounds sets the caveat that carries the bounds: bounded for both,
// within_window for time alone, in_clusters for clusters alone.
func (r *Relationship) setBounds(expiresAt string, clusters []string) {
	r.ExpiresAt = expiresAt
	r.Allowed = nil
	if len(clusters) > 0 {
		r.Allowed = slices.Sorted(slices.Values(clusters))
	}
	switch {
	case r.ExpiresAt != "" && r.Allowed != nil:
		r.Caveat = spicedb.CaveatBounded
	case r.ExpiresAt != "":
		r.Caveat = spicedb.CaveatWithinWindow
	case r.Allowed != nil:
		r.Caveat = spicedb.CaveatInClusters
	default:
		r.Caveat = ""
	}
}

// object is the relationship without its caveat, for a delete.
func (r Relationship) object() Relationship {
	return Relationship{
		ResourceType: r.ResourceType, ResourceID: r.ResourceID, Relation: r.Relation,
		SubjectType: r.SubjectType, SubjectID: r.SubjectID, SubjectRelation: r.SubjectRelation,
	}
}

// Proto converts the relationship to its wire form.
func (r Relationship) Proto() (*v1.Relationship, error) {
	rel := &v1.Relationship{
		Resource: &v1.ObjectReference{ObjectType: r.ResourceType, ObjectId: r.ResourceID},
		Relation: r.Relation,
		Subject:  &v1.SubjectReference{Object: &v1.ObjectReference{ObjectType: r.SubjectType, ObjectId: r.SubjectID}, OptionalRelation: r.SubjectRelation},
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

// FromProto converts a relationship read from SpiceDB. A context value of
// another shape than this package writes is kept as its text.
func FromProto(rel *v1.Relationship) Relationship {
	r := Relationship{
		ResourceType:    rel.GetResource().GetObjectType(),
		ResourceID:      rel.GetResource().GetObjectId(),
		Relation:        rel.GetRelation(),
		SubjectType:     rel.GetSubject().GetObject().GetObjectType(),
		SubjectID:       rel.GetSubject().GetObject().GetObjectId(),
		SubjectRelation: rel.GetSubject().GetOptionalRelation(),
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

func contextString(v *structpb.Value) string {
	if s, ok := v.GetKind().(*structpb.Value_StringValue); ok {
		return s.StringValue
	}
	return "?" + v.String()
}

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
