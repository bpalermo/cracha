// Package check holds cracha-access's safeguards (docs/design.md, section
// 6.9): every relationship write is checked, before it reaches SpiceDB,
// the way CI checks a grant tree (6.2), against the current signed bundle
// and the relationships SpiceDB holds now.
//
// The check rebuilds the grant tree a write would leave: the bundle's
// grants, and the Services, Assignments and Access documents SpiceDB's
// relationships say, with the write applied. It then runs common/grant's
// own composition lint (LintComposition, CI's step 5) for every workload
// the write reaches, and refuses what it finds that was not already there,
// with the reason codes the broker denies with (6.5): one shape, the size
// budget, maxResources, the envelope of every lookup grant the resource is
// rendered into. Optionally the composed policy goes through Access
// Analyzer's ValidatePolicy and CheckNoNewAccess against the envelope of
// its grants (steps 2 and 3).
package check

import (
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/bpalermo/cracha/access/internal/store"
	"github.com/bpalermo/cracha/common/grant"
	"github.com/bpalermo/cracha/common/spicedb"
)

// Tree is the grant tree a bundle and a set of relationships make: what
// LintComposition reads.
type Tree struct {
	bundle   *grant.Bundle
	src      *grant.Source
	rendered map[string]string
	lookups  map[string]*grant.BundleLookup
}

// NewTree rebuilds the tree from the bundle's grants and accounts
// (grant.BundleSource, its implicit grants included) and the store's
// relationships: services from service#member, #team and the grants'
// assignee_service; one Assignment per grant#assignee_workload and per
// workload#suspended; one Access per resource relation. Relationships of
// other shapes are ignored.
func NewTree(b *grant.Bundle, rels []store.Relationship) *Tree {
	src, rendered, lookups := grant.BundleSource(b)
	t := &Tree{bundle: b, src: src, rendered: rendered, lookups: lookups}
	tb := treeBuilder{tree: t, services: map[string]*grant.Service{}}
	for _, r := range rels {
		tb.add(r)
	}
	for _, name := range sortedKeys(tb.services) {
		t.src.Services = append(t.src.Services, tb.services[name])
	}
	return t
}

type treeBuilder struct {
	tree     *Tree
	services map[string]*grant.Service
	n        int
}

func (tb *treeBuilder) service(name string) *grant.Service {
	s, ok := tb.services[name]
	if !ok {
		s = &grant.Service{Kind: grant.KindService, Metadata: grant.Metadata{Name: name}}
		tb.services[name] = s
	}
	return s
}

// name is a fresh document name, for messages.
func (tb *treeBuilder) name(kind string) string {
	tb.n++
	return fmt.Sprintf("spicedb-%s-%d", kind, tb.n)
}

func (tb *treeBuilder) add(r store.Relationship) {
	switch r.ResourceType {
	case spicedb.TypeGrant:
		tb.addAssignee(r)
	case spicedb.TypeService:
		tb.addServiceRelation(r)
	case spicedb.TypeWorkload:
		if r.Relation == spicedb.RelationSuspended {
			tb.tree.src.Assignments = append(tb.tree.src.Assignments, &grant.Assignment{
				Kind:     grant.KindAssignment,
				Metadata: grant.Metadata{Name: tb.name("suspension")}, Spec: grant.AssignmentSpec{Subject: r.ResourceID, Suspended: true},
			})
		}
	default:
		if t, ok := store.TupleOf(r); ok && t.IsAccess() {
			a := t.Access(tb.name("access"))
			a.Spec.Resource.Account = grant.BundleResourceAccount(tb.tree.bundle, a.Spec.Resource)
			tb.tree.src.Accesses = append(tb.tree.src.Accesses, a)
		}
	}
}

func (tb *treeBuilder) addAssignee(r store.Relationship) {
	switch {
	case r.Relation == spicedb.RelationAssigneeService && r.SubjectType == spicedb.TypeService:
		s := tb.service(r.SubjectID)
		s.Spec.Grants = append(s.Spec.Grants, grant.BoundedGrant{Name: r.ResourceID, ExpiresAt: r.ExpiresAt, Clusters: r.Allowed})
	case r.Relation == spicedb.RelationAssigneeWorkload && r.SubjectType == spicedb.TypeWorkload:
		tb.tree.src.Assignments = append(tb.tree.src.Assignments, &grant.Assignment{
			Kind:     grant.KindAssignment,
			Metadata: grant.Metadata{Name: tb.name("assignment")},
			Spec:     grant.AssignmentSpec{Subject: r.SubjectID, Grants: []string{r.ResourceID}, ExpiresAt: r.ExpiresAt, Clusters: r.Allowed},
		})
	}
}

// addServiceRelation reads a service's members and team: the team is
// service#team, or service#owner on a team as the schema had it before
// ownership moved to workloads.
func (tb *treeBuilder) addServiceRelation(r store.Relationship) {
	switch {
	case r.Relation == spicedb.RelationMember && r.SubjectType == spicedb.TypeWorkload:
		s := tb.service(r.ResourceID)
		s.Spec.Members = append(s.Spec.Members, r.SubjectID)
	case r.Relation == spicedb.RelationTeam && r.SubjectType == spicedb.TypeTeam:
		tb.service(r.ResourceID).Spec.Team = r.SubjectID
	}
}

// Members are the service's members, sorted.
func (t *Tree) Members(service string) []string {
	if s := t.src.Service(service); s != nil {
		return slices.Sorted(slices.Values(s.Spec.Members))
	}
	return nil
}

// ServiceOf is the service the subject is a member of, or empty.
func (t *Tree) ServiceOf(subject string) string {
	if s := t.src.ServiceOf(subject); s != nil {
		return s.Name()
	}
	return ""
}

// HasService reports whether any relationship names the service.
func (t *Tree) HasService(name string) bool { return t.src.Service(name) != nil }

// Compositions are the subject's compositions at now, one per cluster
// scope, as LintComposition makes them (the subject's problems in each),
// and the holdings left out as expired.
func (t *Tree) Compositions(subject string, now time.Time) []grant.Composition {
	var out []grant.Composition
	for _, c := range t.report(now).Compositions {
		if c.Subject == subject {
			out = append(out, c)
		}
	}
	return out
}

func (t *Tree) report(now time.Time) *grant.CompositionReport {
	return grant.LintComposition(t.src, t.rendered, t.lookups, now)
}

// Version is the bundle's version.
func (t *Tree) Version() string { return t.bundle.Version }

// grant returns a compiled grant by name.
func (t *Tree) grant(name string) *grant.Grant { return t.src.Grant(name) }

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
