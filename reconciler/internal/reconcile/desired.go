package reconcile

import (
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/bpalermo/cracha/common/grant"
	"github.com/bpalermo/cracha/common/spicedb"
)

// Desired computes the relationships a source tree calls for (design 6.4,
// the writer's mapping):
//
//	Grant        grant:<g>#account@aws_account:<account>
//	Service      service:<s>#owner@team:<team>
//	             service:<s>#member@workload:<member>        per member
//	             grant:<g>#assignee_service@service:<s>      per grant, caveated by its bounds
//	Assignment   grant:<g>#assignee_workload@workload:<subject>  per grant, caveated by its bounds
//	             workload:<subject>#suspended@team:<team>    when suspended; the team of
//	                                                          the subject's service, or "none"
//
// A bound in time alone is the within_window caveat, in clusters alone
// in_clusters, both bounded, neither no caveat. Two assignments that give
// one subject the same grant are one relationship, with the bounds that
// allow what either allows; when no single caveat can express that union
// (one bound in time, the other in clusters, say) the tree is refused. The
// source must have passed the loader and the lints; this does not validate
// it again. The result is sorted by key.
func Desired(src *grant.Source) ([]Relationship, error) {
	b := builder{rels: map[string]Relationship{}}
	for _, g := range src.Grants {
		b.add(plain(spicedb.TypeGrant, g.Name(), spicedb.RelationAccount, spicedb.TypeAWSAccount, g.Spec.Account))
	}
	for _, s := range src.Services {
		if err := b.addService(s); err != nil {
			return nil, err
		}
	}
	if err := b.addAssignments(src); err != nil {
		return nil, err
	}
	out := make([]Relationship, 0, len(b.rels))
	for _, r := range b.rels {
		out = append(out, r)
	}
	sortByKey(out)
	return out, nil
}

// builder accumulates the desired set by key.
type builder struct {
	rels map[string]Relationship
}

func (b *builder) add(r Relationship) { b.rels[r.Key()] = r }

func plain(resourceType, resourceID, relation, subjectType, subjectID string) Relationship {
	return Relationship{ResourceType: resourceType, ResourceID: resourceID, Relation: relation, SubjectType: subjectType, SubjectID: subjectID}
}

func (b *builder) addService(s *grant.Service) error {
	b.add(plain(spicedb.TypeService, s.Name(), spicedb.RelationOwner, spicedb.TypeTeam, s.Spec.Team))
	for _, member := range s.Spec.Members {
		b.add(plain(spicedb.TypeService, s.Name(), spicedb.RelationMember, spicedb.TypeWorkload, member))
	}
	for _, g := range s.Spec.Grants {
		bd, err := newBounds(g.ExpiresAt, g.Clusters)
		if err != nil {
			return fmt.Errorf("service %s: grant %s: %w", s.Name(), g.Name, err)
		}
		r := plain(spicedb.TypeGrant, g.Name, spicedb.RelationAssigneeService, spicedb.TypeService, s.Name())
		bd.caveat(&r)
		b.add(r)
	}
	return nil
}

// assigned is one assignment's bounds on one grant, for merging.
type assigned struct {
	assignment string
	bounds     bounds
}

// addAssignments adds the direct assignments, merging the ones that give a
// subject the same grant, and the suspensions.
func (b *builder) addAssignments(src *grant.Source) error {
	byPair := map[[2]string][]assigned{}
	var pairs [][2]string
	for _, a := range src.Assignments {
		bd, err := newBounds(a.Spec.ExpiresAt, a.Spec.Clusters)
		if err != nil {
			return fmt.Errorf("assignment %s: %w", a.Name(), err)
		}
		for _, g := range a.Spec.Grants {
			pair := [2]string{a.Spec.Subject, g}
			if _, seen := byPair[pair]; !seen {
				pairs = append(pairs, pair)
			}
			byPair[pair] = append(byPair[pair], assigned{a.Name(), bd})
		}
		if a.Spec.Suspended {
			b.add(plain(spicedb.TypeWorkload, a.Spec.Subject, spicedb.RelationSuspended, spicedb.TypeTeam, teamOf(src, a.Spec.Subject)))
		}
	}
	for _, pair := range pairs {
		merged, err := mergeAssigned(byPair[pair])
		if err != nil {
			return fmt.Errorf("subject %s, grant %s: %w", pair[0], pair[1], err)
		}
		r := plain(spicedb.TypeGrant, pair[1], spicedb.RelationAssigneeWorkload, spicedb.TypeWorkload, pair[0])
		merged.caveat(&r)
		b.add(r)
	}
	return nil
}

// teamOf is the team of the subject's service, or spicedb.TeamNone.
func teamOf(src *grant.Source, subject string) string {
	if s := src.ServiceOf(subject); s != nil {
		return s.Spec.Team
	}
	return spicedb.TeamNone
}

// mergeAssigned unions the bounds of every assignment of one grant to one
// subject, or says which two cannot be expressed as one caveat.
func mergeAssigned(as []assigned) (bounds, error) {
	acc := as[0]
	for _, a := range as[1:] {
		u, ok := acc.bounds.union(a.bounds)
		if !ok {
			return bounds{}, fmt.Errorf("assignments %s and %s bound it in ways one relationship cannot express; give it the same bounds in both, or merge them into one", acc.assignment, a.assignment)
		}
		acc = assigned{acc.assignment + "+" + a.assignment, u}
	}
	return acc.bounds, nil
}

// bounds are the time and cluster bounds of one assignment of a grant.
type bounds struct {
	// expiresAt is the zero time when unbounded in time.
	expiresAt time.Time
	// clusters is nil when unbounded in clusters; otherwise sorted, without
	// repeats.
	clusters []string
}

func newBounds(expiresAt string, clusters []string) (bounds, error) {
	var b bounds
	if expiresAt != "" {
		t, err := time.Parse(time.RFC3339, expiresAt)
		if err != nil {
			return b, fmt.Errorf("expiresAt: %w", err)
		}
		b.expiresAt = t.UTC()
	}
	if len(clusters) > 0 {
		b.clusters = slices.Compact(slices.Sorted(slices.Values(clusters)))
	}
	return b, nil
}

// caveat sets the relationship's caveat from the bounds.
func (b bounds) caveat(r *Relationship) {
	if !b.expiresAt.IsZero() {
		r.ExpiresAt = b.expiresAt.Format(time.RFC3339)
	}
	if b.clusters != nil {
		r.Allowed = slices.Clone(b.clusters)
	}
	switch {
	case r.ExpiresAt != "" && r.Allowed != nil:
		r.Caveat = spicedb.CaveatBounded
	case r.ExpiresAt != "":
		r.Caveat = spicedb.CaveatWithinWindow
	case r.Allowed != nil:
		r.Caveat = spicedb.CaveatInClusters
	}
}

// subsumes reports whether b allows at least everything o allows.
func (b bounds) subsumes(o bounds) bool {
	inTime := b.expiresAt.IsZero() || (!o.expiresAt.IsZero() && !b.expiresAt.Before(o.expiresAt))
	inClusters := b.clusters == nil || (o.clusters != nil && subset(o.clusters, b.clusters))
	return inTime && inClusters
}

// union returns the bounds that allow what either allows, when one caveat
// can express it: one subsumes the other, or they expire together and
// differ in clusters only.
func (b bounds) union(o bounds) (bounds, bool) {
	switch {
	case b.subsumes(o):
		return b, true
	case o.subsumes(b):
		return o, true
	case b.expiresAt.Equal(o.expiresAt):
		all := append(slices.Clone(b.clusters), o.clusters...)
		sort.Strings(all)
		return bounds{expiresAt: b.expiresAt, clusters: slices.Compact(all)}, true
	default:
		return bounds{}, false
	}
}

// subset reports whether every element of a is in b.
func subset(a, b []string) bool {
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}
