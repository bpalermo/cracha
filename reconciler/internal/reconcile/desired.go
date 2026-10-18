package reconcile

import (
	"slices"

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
// in_clusters, both bounded, neither no caveat. Who holds what is
// grant.ResolveAssignments, the mapping the published assignments document
// of the static backend carries too: two assignments that give one subject
// the same grant are one relationship, with the bounds that allow what
// either allows, and a tree whose union no single caveat can express (one
// bound in time, the other in clusters, say) is refused. The source must
// have passed the loader and the lints; this does not validate it again.
// The result is sorted by key.
func Desired(src *grant.Source) ([]Relationship, error) {
	b := builder{rels: map[string]Relationship{}}
	for _, g := range src.Grants {
		b.add(plain(spicedb.TypeGrant, g.Name(), spicedb.RelationAccount, spicedb.TypeAWSAccount, g.Spec.Account))
	}
	services, workloads, err := grant.ResolveAssignments(src)
	if err != nil {
		return nil, err
	}
	teams := map[string]string{}
	for _, s := range services {
		b.addService(s)
		for _, m := range s.Members {
			teams[m] = s.Team
		}
	}
	for _, w := range workloads {
		b.addWorkload(w, teams)
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

func (b *builder) addService(s grant.AssignedService) {
	b.add(plain(spicedb.TypeService, s.Name, spicedb.RelationOwner, spicedb.TypeTeam, s.Team))
	for _, member := range s.Members {
		b.add(plain(spicedb.TypeService, s.Name, spicedb.RelationMember, spicedb.TypeWorkload, member))
	}
	for _, g := range s.Grants {
		r := plain(spicedb.TypeGrant, g.Name, spicedb.RelationAssigneeService, spicedb.TypeService, s.Name)
		caveat(&r, g)
		b.add(r)
	}
}

// addWorkload adds a subject's direct assignments and its suspension,
// whose subject is the team of its service (teams), or spicedb.TeamNone.
func (b *builder) addWorkload(w grant.AssignedWorkload, teams map[string]string) {
	for _, g := range w.Grants {
		r := plain(spicedb.TypeGrant, g.Name, spicedb.RelationAssigneeWorkload, spicedb.TypeWorkload, w.Subject)
		caveat(&r, g)
		b.add(r)
	}
	if w.Suspended {
		team := teams[w.Subject]
		if team == "" {
			team = spicedb.TeamNone
		}
		b.add(plain(spicedb.TypeWorkload, w.Subject, spicedb.RelationSuspended, spicedb.TypeTeam, team))
	}
}

// caveat sets the relationship's caveat from a grant's normalized bounds.
func caveat(r *Relationship, g grant.BoundedGrant) {
	r.ExpiresAt = g.ExpiresAt
	if len(g.Clusters) > 0 {
		r.Allowed = slices.Clone(g.Clusters)
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
