package check

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/bpalermo/cracha/access/internal/store"
	"github.com/bpalermo/cracha/common/grant"
)

// Reason codes of a refused write. The policy codes are the broker's
// (design 6.5): a write that would make the broker deny the workload is
// refused with what the broker would deny it with.
const (
	ReasonNoGrant                 = "no_grant"
	ReasonAmbiguous               = "ambiguous"
	ReasonEnvelopeViolation       = "envelope_violation"
	ReasonPolicyTooLarge          = "policy_too_large"
	ReasonResourceOutsideEnvelope = "resource_outside_envelope"
	// ReasonInvalidPolicy is a blocking finding of Access Analyzer's
	// ValidatePolicy on the composed policy (CI's step 2).
	ReasonInvalidPolicy = "invalid_policy"
	// ReasonInvalidComposition is a composition problem of no other code.
	ReasonInvalidComposition = "invalid_composition"
)

// Refusal is a write the safeguards refuse. Detail is for the caller and
// the audit log.
type Refusal struct {
	Reason string
	Detail string
}

func (r *Refusal) Error() string { return r.Reason + ": " + r.Detail }

func refuse(reason, format string, args ...any) *Refusal {
	return &Refusal{Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// Change is a write to check: a tuple added (or its bounds changed), or
// one removed.
type Change struct {
	Add    *store.Tuple
	Remove *store.Tuple
}

// Delta is what a write changes in one workload's composition in one
// cluster scope: the policy delta of the audit log.
type Delta struct {
	Subject string `json:"subject"`
	Cluster string `json:"cluster,omitempty"`
	// GrantsBefore and GrantsAfter are the composed grants.
	GrantsBefore []string `json:"grantsBefore,omitempty"`
	GrantsAfter  []string `json:"grantsAfter,omitempty"`
	// ResourcesBefore and ResourcesAfter are what each lookup grant is
	// rendered with.
	ResourcesBefore map[string][]string `json:"resourcesBefore,omitempty"`
	ResourcesAfter  map[string][]string `json:"resourcesAfter,omitempty"`
	PolicyBefore    string              `json:"policyBefore,omitempty"`
	PolicyAfter     string              `json:"policyAfter,omitempty"`
}

// Result is a write that passed: what it changes.
type Result struct {
	// Subjects are the workloads the write reaches.
	Subjects []string
	Deltas   []Delta
}

// Checker runs the safeguards; Analyzer, when set, adds Access
// Analyzer's checks of every composed policy the write changes.
type Checker struct {
	Analyzer grant.PolicyAnalyzer
}

// Evaluate checks a change against the bundle and the relationships held
// now, and returns what it changes. An added tuple is refused with a
// *Refusal when the resource renders into no grant its holder has, when
// it falls outside a grant's envelope, when the composition of a
// workload it reaches gains a problem it did not have, or when Access
// Analyzer finds against the composed policy. A removal is never refused:
// it narrows. Any other error means the check could not run, which the
// caller must treat as a refusal too.
func (c Checker) Evaluate(ctx context.Context, b *grant.Bundle, rels []store.Relationship, ch Change, now time.Time) (*Result, error) {
	after, err := apply(rels, ch)
	if err != nil {
		return nil, err
	}
	treeBefore, treeAfter := NewTree(b, rels), NewTree(b, after)
	subjects := affected(treeBefore, treeAfter, ch)
	before := byScope(treeBefore.report(now), subjects)
	afterC := byScope(treeAfter.report(now), subjects)
	res := &Result{Subjects: subjects, Deltas: deltas(subjects, before, afterC)}
	if ch.Add == nil || ch.Remove != nil {
		return res, nil
	}
	if err := coverage(treeAfter, *ch.Add, subjects, afterC); err != nil {
		return nil, err
	}
	if err := newProblems(before, afterC); err != nil {
		return nil, err
	}
	if err := c.analyze(ctx, treeAfter, before, afterC); err != nil {
		return nil, err
	}
	return res, nil
}

// apply is the relationships with the change made.
func apply(rels []store.Relationship, ch Change) ([]store.Relationship, error) {
	out := slices.Clone(rels)
	for _, t := range []*store.Tuple{ch.Remove, ch.Add} {
		if t == nil {
			continue
		}
		r, err := t.Relationship()
		if err != nil {
			return nil, err
		}
		out = slices.DeleteFunc(out, func(o store.Relationship) bool { return o.Key() == r.Key() })
		if t == ch.Add {
			out = append(out, r)
		}
	}
	return out, nil
}

// affected are the workloads a change reaches, sorted: the tuple's
// subject, or every member of its service before or after.
func affected(before, after *Tree, ch Change) []string {
	set := map[string]bool{}
	for _, t := range []*store.Tuple{ch.Add, ch.Remove} {
		if t == nil {
			continue
		}
		if t.Subject != "" {
			set[t.Subject] = true
		}
		if t.Service != "" {
			for _, m := range append(before.Members(t.Service), after.Members(t.Service)...) {
				set[m] = true
			}
		}
	}
	return sortedKeys(set)
}

// scoped is one subject's compositions by cluster scope.
type scoped map[string]map[string]grant.Composition

func byScope(r *grant.CompositionReport, subjects []string) scoped {
	out := scoped{}
	for _, c := range r.Compositions {
		if !slices.Contains(subjects, c.Subject) {
			continue
		}
		if out[c.Subject] == nil {
			out[c.Subject] = map[string]grant.Composition{}
		}
		out[c.Subject][c.Cluster] = c
	}
	return out
}

func deltas(subjects []string, before, after scoped) []Delta {
	var out []Delta
	for _, s := range subjects {
		scopes := map[string]bool{}
		for k := range before[s] {
			scopes[k] = true
		}
		for k := range after[s] {
			scopes[k] = true
		}
		for _, cluster := range sortedKeys(scopes) {
			b, a := before[s][cluster], after[s][cluster]
			out = append(out, Delta{
				Subject: s, Cluster: cluster, GrantsBefore: b.Grants, GrantsAfter: a.Grants,
				ResourcesBefore: b.Resources, ResourcesAfter: a.Resources, PolicyBefore: b.Policy, PolicyAfter: a.Policy,
			})
		}
	}
	return out
}

// coverage is the envelope check of an added resource tuple: some grant
// its holder has must render the resource (a lookup grant of its kind
// whose permission the relation gives), and every such grant's envelope
// must hold the resource rendered alone. A membership has nothing to
// cover.
func coverage(t *Tree, add store.Tuple, subjects []string, after scoped) error {
	if add.IsMembership() {
		return nil
	}
	grants := renderingGrants(t, add, subjects, after)
	if len(grants) == 0 {
		return refuse(ReasonNoGrant, "no grant %s holds renders %s resources through %s: the relation would reach nothing, and no envelope bounds it", add.Holder(), add.Kind, add.Relation)
	}
	for _, name := range grants {
		g, l := t.grant(name), t.lookups[name]
		policy, err := l.Render(g.Spec.Account, []string{add.Name})
		if err != nil {
			return refuse(ReasonInvalidComposition, "grant %s rendered for %s: %v", name, add.Name, err)
		}
		if p := grant.LintEnvelope(name, policy, g.Spec.Envelope).Problems; len(p) > 0 {
			return refuse(ReasonResourceOutsideEnvelope, "%s %s rendered into grant %s: %s", add.Kind, add.Name, name, p[0])
		}
	}
	return nil
}

// renderingGrants are the lookup grants that would render the added
// resource: those of the reached workloads' compositions that hold it,
// and, for a service, the service's own lookup grants of its kind.
func renderingGrants(t *Tree, add store.Tuple, subjects []string, after scoped) []string {
	set := map[string]bool{}
	for _, s := range subjects {
		for _, c := range after[s] {
			holding(set, c, add.Name)
		}
	}
	for _, name := range serviceLookups(t, add) {
		set[name] = true
	}
	return sortedKeys(set)
}

// holding adds to set the lookup grants of the composition rendered with
// the resource.
func holding(set map[string]bool, c grant.Composition, resource string) {
	for g, rs := range c.Resources {
		if slices.Contains(rs, resource) {
			set[g] = true
		}
	}
}

// serviceLookups are, for a tuple of a service, the service's own lookup
// grants of the tuple's kind whose permission its relation gives.
func serviceLookups(t *Tree, add store.Tuple) []string {
	if add.Service == "" {
		return nil
	}
	svc := t.src.Service(add.Service)
	if svc == nil {
		return nil
	}
	var out []string
	for _, bg := range svc.Spec.Grants {
		if l, ok := t.lookups[bg.Name]; ok && rendersWith(l, add) {
			out = append(out, bg.Name)
		}
	}
	return out
}

// rendersWith reports whether a lookup asks for the tuple's kind with a
// permission its relation gives.
func rendersWith(l *grant.BundleLookup, t store.Tuple) bool {
	relations, _ := grant.RelationsOf(l.Permission)
	return l.Kind == t.Kind && slices.Contains(relations, t.Relation)
}

// newProblems refuses the first composition problem the write adds: one
// the same subject and scope did not have before.
func newProblems(before, after scoped) error {
	for _, s := range sortedKeys(after) {
		for _, cluster := range sortedKeys(after[s]) {
			old := before[s][cluster].Problems
			for _, p := range after[s][cluster].Problems {
				if !slices.Contains(old, p) {
					return refuse(classify(p), "%s: %s", scopeName(s, cluster), p)
				}
			}
		}
	}
	return nil
}

func scopeName(subject, cluster string) string {
	if cluster == "" {
		return "workload " + subject
	}
	return "workload " + subject + " in cluster " + cluster
}

// classify gives a composition problem of common/grant's lint the code the
// broker denies the same fault with. The lint words its problems for
// people; these are the phrases it uses for each (lint.go), held to them by
// this package's tests.
func classify(problem string) string {
	rules := []struct{ phrase, reason string }{
		{"resource_outside_envelope", ReasonResourceOutsideEnvelope},
		{"policy_too_large", ReasonPolicyTooLarge},
		{"session tag \"", ReasonAmbiguous},
		{"base roles", ReasonAmbiguous},
		{"characters", ReasonPolicyTooLarge},
		{"managed policy", ReasonPolicyTooLarge},
		{"not found", ReasonNoGrant},
		{"envelope", ReasonEnvelopeViolation},
	}
	for _, r := range rules {
		if strings.Contains(problem, r.phrase) {
			return r.reason
		}
	}
	return ReasonInvalidComposition
}

// analyze runs Access Analyzer on every composed policy the write changes:
// ValidatePolicy, then CheckNoNewAccess against the envelope of the
// composition's grants.
func (c Checker) analyze(ctx context.Context, t *Tree, before, after scoped) error {
	if c.Analyzer == nil {
		return nil
	}
	for _, s := range sortedKeys(after) {
		for _, cluster := range sortedKeys(after[s]) {
			comp := after[s][cluster]
			if comp.Policy == "" || comp.Policy == before[s][cluster].Policy {
				continue
			}
			if err := c.analyzeOne(ctx, t, comp); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c Checker) analyzeOne(ctx context.Context, t *Tree, comp grant.Composition) error {
	findings, err := c.Analyzer.ValidatePolicy(ctx, comp.Policy)
	if err != nil {
		return err
	}
	for _, f := range findings {
		if f.Blocking() {
			return refuse(ReasonInvalidPolicy, "%s: Access Analyzer %s %s: %s", scopeName(comp.Subject, comp.Cluster), f.Type, f.Code, f.Detail)
		}
	}
	var envelope []string
	for _, name := range comp.Grants {
		if g := t.grant(name); g != nil {
			envelope = append(envelope, g.Spec.Envelope...)
		}
	}
	reference, err := grant.EnvelopePolicy(envelope)
	if err != nil {
		return refuse(ReasonEnvelopeViolation, "%s: %v", scopeName(comp.Subject, comp.Cluster), err)
	}
	check, err := c.Analyzer.CheckNoNewAccess(ctx, comp.Policy, reference)
	if err != nil {
		return err
	}
	if !check.Passed {
		return refuse(ReasonEnvelopeViolation, "%s: CheckNoNewAccess against the envelope: %s", scopeName(comp.Subject, comp.Cluster), strings.Join(check.Reasons, "; "))
	}
	return nil
}
