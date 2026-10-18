package grant

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"
)

// Assignments is the compiled assignments document the broker's static
// authorization backend consumes when it reads its assignments from the
// publication (design 6.3): who holds which grant, computed from the
// tree's Service and Assignment documents by [ResolveAssignments]. It is
// published beside the bundle, under the same version, and signed the same
// way. Field names are part of the broker's contract.
type Assignments struct {
	Version     string             `json:"version"`
	GeneratedAt string             `json:"generatedAt"`
	Services    []AssignedService  `json:"services"`
	Workloads   []AssignedWorkload `json:"workloads"`
}

// AssignedService is one Service: its team, its members and the grants
// every member holds, each with its bounds.
type AssignedService struct {
	Name    string         `json:"name"`
	Team    string         `json:"team"`
	Members []string       `json:"members"`
	Grants  []BoundedGrant `json:"grants"`
}

// AssignedWorkload is one subject's own assignments: every Assignment
// naming it, merged per grant, and whether any of them suspends it.
type AssignedWorkload struct {
	Subject   string         `json:"subject"`
	Suspended bool           `json:"suspended"`
	Grants    []BoundedGrant `json:"grants"`
}

// ResolveAssignments is the one mapping from a source tree's Services and
// Assignments to who holds what, which the published assignments document
// carries and the reconciler writes to SpiceDB (design 6.4):
//
//   - a Service is its team, its members and its grants with their bounds;
//   - a subject's Assignments are one workload, suspended when any of them
//     suspends it, holding each grant any of them names; two Assignments
//     that give the subject the same grant are one, with the bounds that
//     allow what either allows, and when no single bound can express that
//     union (one bound in time, the other in clusters, say) the tree is
//     refused.
//
// Bounds are normalized: expiresAt in UTC, clusters sorted without
// repeats, nil when unbounded. Services are sorted by name, workloads by
// subject, members and grants by name. The source must have passed the
// loader; this does not validate it again.
func ResolveAssignments(src *Source) ([]AssignedService, []AssignedWorkload, error) {
	services := make([]AssignedService, 0, len(src.Services))
	for _, s := range src.Services {
		svc, err := resolveService(s)
		if err != nil {
			return nil, nil, err
		}
		services = append(services, svc)
	}
	sort.Slice(services, func(i, j int) bool { return services[i].Name < services[j].Name })
	workloads, err := resolveWorkloads(src.Assignments)
	if err != nil {
		return nil, nil, err
	}
	return services, workloads, nil
}

func resolveService(s *Service) (AssignedService, error) {
	svc := AssignedService{
		Name:    s.Name(),
		Team:    s.Spec.Team,
		Members: slices.Sorted(slices.Values(s.Spec.Members)),
		Grants:  make([]BoundedGrant, 0, len(s.Spec.Grants)),
	}
	if svc.Members == nil {
		svc.Members = []string{}
	}
	for _, g := range s.Spec.Grants {
		b, err := newBounds(g.ExpiresAt, g.Clusters)
		if err != nil {
			return AssignedService{}, fmt.Errorf("service %s: grant %s: %w", s.Name(), g.Name, err)
		}
		svc.Grants = append(svc.Grants, b.grant(g.Name))
	}
	sortGrants(svc.Grants)
	return svc, nil
}

// assigned is one assignment's bounds on one grant, for merging.
type assigned struct {
	assignment string
	bounds     bounds
}

// subjectAssignments accumulates one subject's assignments.
type subjectAssignments struct {
	suspended bool
	grants    map[string][]assigned
}

func resolveWorkloads(assignments []*Assignment) ([]AssignedWorkload, error) {
	bySubject := map[string]*subjectAssignments{}
	for _, a := range assignments {
		b, err := newBounds(a.Spec.ExpiresAt, a.Spec.Clusters)
		if err != nil {
			return nil, fmt.Errorf("assignment %s: %w", a.Name(), err)
		}
		sa, ok := bySubject[a.Spec.Subject]
		if !ok {
			sa = &subjectAssignments{grants: map[string][]assigned{}}
			bySubject[a.Spec.Subject] = sa
		}
		sa.suspended = sa.suspended || a.Spec.Suspended
		for _, g := range a.Spec.Grants {
			sa.grants[g] = append(sa.grants[g], assigned{a.Name(), b})
		}
	}
	workloads := make([]AssignedWorkload, 0, len(bySubject))
	for subject, sa := range bySubject {
		w := AssignedWorkload{Subject: subject, Suspended: sa.suspended, Grants: make([]BoundedGrant, 0, len(sa.grants))}
		for name, as := range sa.grants {
			merged, err := mergeAssigned(as)
			if err != nil {
				return nil, fmt.Errorf("subject %s, grant %s: %w", subject, name, err)
			}
			w.Grants = append(w.Grants, merged.grant(name))
		}
		sortGrants(w.Grants)
		workloads = append(workloads, w)
	}
	sort.Slice(workloads, func(i, j int) bool { return workloads[i].Subject < workloads[j].Subject })
	return workloads, nil
}

func sortGrants(gs []BoundedGrant) {
	sort.Slice(gs, func(i, j int) bool { return gs[i].Name < gs[j].Name })
}

// mergeAssigned unions the bounds of every assignment of one grant to one
// subject, or says which two cannot be expressed as one bound.
func mergeAssigned(as []assigned) (bounds, error) {
	acc := as[0]
	for _, a := range as[1:] {
		u, ok := acc.bounds.union(a.bounds)
		if !ok {
			return bounds{}, fmt.Errorf("assignments %s and %s bound it in ways one assignment cannot express; give it the same bounds in both, or merge them into one", acc.assignment, a.assignment)
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
	t, err := parseExpiry(expiresAt)
	if err != nil {
		return b, err
	}
	if !t.IsZero() {
		b.expiresAt = t.UTC()
	}
	if len(clusters) > 0 {
		b.clusters = slices.Compact(slices.Sorted(slices.Values(clusters)))
	}
	return b, nil
}

// grant is the bounded grant of that name.
func (b bounds) grant(name string) BoundedGrant {
	g := BoundedGrant{Name: name, Clusters: slices.Clone(b.clusters)}
	if !b.expiresAt.IsZero() {
		g.ExpiresAt = b.expiresAt.Format(time.RFC3339)
	}
	return g
}

// subsumes reports whether b allows at least everything o allows.
func (b bounds) subsumes(o bounds) bool {
	inTime := b.expiresAt.IsZero() || (!o.expiresAt.IsZero() && !b.expiresAt.Before(o.expiresAt))
	inClusters := b.clusters == nil || (o.clusters != nil && subset(o.clusters, b.clusters))
	return inTime && inClusters
}

// union returns the bounds that allow what either allows, when one bound
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

// MarshalAssignments encodes an assignments document in its canonical form,
// as Marshal does a bundle: these are the bytes that are signed and
// published.
func MarshalAssignments(a *Assignments) ([]byte, error) {
	return canonical(a)
}

// ParseAssignments decodes an assignments document. Unknown fields are an
// error.
func ParseAssignments(data []byte) (*Assignments, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var a Assignments
	if err := dec.Decode(&a); err != nil {
		return nil, fmt.Errorf("assignments: %w", err)
	}
	if dec.More() {
		return nil, errors.New("assignments: trailing data")
	}
	if !ValidVersion(a.Version) {
		return nil, fmt.Errorf("assignments: version %q: must match %s", a.Version, versionRE)
	}
	if a.Services == nil || a.Workloads == nil {
		return nil, errors.New("assignments: no services or no workloads")
	}
	return &a, nil
}

// Artifact kinds, as ParseArtifact reports them.
const (
	ArtifactBundle      = "bundle"
	ArtifactAssignments = "assignments"
)

// ParseArtifact decodes a published document of either kind, strictly, and
// reports which it is and its version: what grantc sign, verify and
// publish take.
func ParseArtifact(data []byte) (kind, version string, err error) {
	b, berr := ParseBundle(data)
	if berr == nil {
		return ArtifactBundle, b.Version, nil
	}
	a, aerr := ParseAssignments(data)
	if aerr == nil {
		return ArtifactAssignments, a.Version, nil
	}
	return "", "", fmt.Errorf("neither a bundle (%v) nor an assignments document (%v)", berr, aerr)
}
