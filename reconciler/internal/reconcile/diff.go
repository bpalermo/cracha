package reconcile

import (
	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
)

// Diff is what separates SpiceDB from the desired set: the relationships
// to write (new, or present with another caveat) and the ones to delete.
// Both are sorted by key.
type Diff struct {
	Touch  []Relationship
	Delete []Relationship
}

// Empty reports whether there is nothing to change.
func (d Diff) Empty() bool { return len(d.Touch) == 0 && len(d.Delete) == 0 }

// Len is the number of updates the diff takes.
func (d Diff) Len() int { return len(d.Touch) + len(d.Delete) }

// ComputeDiff compares what SpiceDB holds with what is desired.
func ComputeDiff(current, desired []Relationship) Diff {
	have := make(map[string]Relationship, len(current))
	for _, r := range current {
		have[r.Key()] = r
	}
	want := make(map[string]bool, len(desired))
	var d Diff
	for _, r := range desired {
		want[r.Key()] = true
		if cur, ok := have[r.Key()]; !ok || !cur.Equal(r) {
			d.Touch = append(d.Touch, r)
		}
	}
	for _, r := range current {
		if !want[r.Key()] {
			d.Delete = append(d.Delete, r)
		}
	}
	sortByKey(d.Touch)
	sortByKey(d.Delete)
	return d
}

// Updates renders the diff as SpiceDB updates: the touches, then the
// deletes.
func (d Diff) Updates() ([]*v1.RelationshipUpdate, error) {
	out := make([]*v1.RelationshipUpdate, 0, d.Len())
	for _, r := range d.Touch {
		rel, err := r.Proto()
		if err != nil {
			return nil, err
		}
		out = append(out, &v1.RelationshipUpdate{Operation: v1.RelationshipUpdate_OPERATION_TOUCH, Relationship: rel})
	}
	for _, r := range d.Delete {
		// A delete names the relationship without its caveat.
		rel, err := Relationship{ResourceType: r.ResourceType, ResourceID: r.ResourceID, Relation: r.Relation, SubjectType: r.SubjectType, SubjectID: r.SubjectID, SubjectRelation: r.SubjectRelation}.Proto()
		if err != nil {
			return nil, err
		}
		out = append(out, &v1.RelationshipUpdate{Operation: v1.RelationshipUpdate_OPERATION_DELETE, Relationship: rel})
	}
	return out, nil
}
