package grant

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Problems is a list of lint findings, each a sentence for a human. An empty
// list means the lint passed.
type Problems []string

func (p *Problems) addf(format string, args ...any) {
	*p = append(*p, fmt.Sprintf(format, args...))
}

// OK reports whether there are no problems.
func (p Problems) OK() bool { return len(p) == 0 }

// SizeReport is the result of LintSize: how a grant's rendered policy and
// session tags measure against the STS budgets (design 6.2, step 4).
type SizeReport struct {
	Grant string
	// PolicyChars is the length of the minified rendered policy, against
	// MaxPolicyChars.
	PolicyChars int
	// TagCount and TagChars are the grant's own tags and the length of their
	// keys and values, against MaxSessionTags and TagBudgetChars less the
	// broker's reserve.
	TagCount int
	TagChars int
	Problems Problems
}

// LintSize checks the size budget: the minified inline policy fits
// MaxPolicyChars and the session tags fit the packed tag budget once the
// broker's own tags are reserved. policy is the rendered policy, or empty
// for a grant without one.
func LintSize(name, policy string, tags map[string]string) *SizeReport {
	r := &SizeReport{Grant: name}
	if policy != "" {
		minified, err := MinifyPolicy(policy)
		if err != nil {
			r.Problems.addf("session policy: %v", err)
		} else {
			r.PolicyChars = len(minified)
			if r.PolicyChars > MaxPolicyChars {
				r.Problems.addf("session policy is %d characters minified, STS allows at most %d", r.PolicyChars, MaxPolicyChars)
			}
		}
	}
	r.TagCount = len(tags)
	for k, v := range tags {
		r.TagChars += len(k) + len(v)
	}
	if limit := MaxSessionTags - BrokerTagCount; r.TagCount > limit {
		r.Problems.addf("%d session tags, at most %d allowed once the broker's %d are counted", r.TagCount, limit, BrokerTagCount)
	}
	if limit := TagBudgetChars - BrokerTagChars; r.TagChars > limit {
		r.Problems.addf("session tags are %d characters of keys and values, at most %d allowed once the broker's %d are counted", r.TagChars, limit, BrokerTagChars)
	}
	return r
}

// ResourceCheck is one Allow resource of a policy and the envelope pattern
// it matched, empty when none did.
type ResourceCheck struct {
	Statement int
	Resource  string
	Matched   string
}

// EnvelopeReport is the result of LintEnvelope.
type EnvelopeReport struct {
	Grant     string
	Resources []ResourceCheck
	Problems  Problems
}

// LintEnvelope checks that every Resource of every Allow statement of the
// rendered policy matches at least one pattern of the envelope (design 6.2:
// the envelope is the runtime ARN allowlist for rendered policies, and
// invariant 11.2). A Resource of "*" is allowed only by an envelope that
// contains "*". NotResource is rejected: an exclusion cannot be checked
// against an allowlist. Deny statements are not checked, since they only
// narrow.
func LintEnvelope(name, policy string, envelope []string) *EnvelopeReport {
	return lintEnvelope(name, policy, envelope, nil)
}

// lintEnvelope is LintEnvelope leaving out the resources skip reports,
// when it is set.
func lintEnvelope(name, policy string, envelope []string, skip func(string) bool) *EnvelopeReport {
	r := &EnvelopeReport{Grant: name}
	statements, err := policyStatements(policy)
	if err != nil {
		r.Problems.addf("session policy: %v", err)
		return r
	}
	for i, st := range statements {
		if effect, _ := st["Effect"].(string); effect != "Allow" {
			continue
		}
		resources, err := allowStatementResources(st)
		if err != nil {
			r.Problems.addf("statement %d: %v", i, err)
			continue
		}
		for _, res := range resources {
			if skip == nil || !skip(res) {
				r.checkResource(i, res, envelope)
			}
		}
	}
	return r
}

// allowStatementResources returns the resources of an Allow statement, or
// why they cannot be checked against the envelope.
func allowStatementResources(st map[string]any) ([]string, error) {
	if _, ok := st["NotResource"]; ok {
		return nil, errors.New("NotResource cannot be checked against the envelope")
	}
	resources, err := stringOrList(st["Resource"])
	if err != nil {
		return nil, fmt.Errorf("Resource: %w", err)
	}
	if len(resources) == 0 {
		return nil, errors.New("an Allow statement needs a Resource")
	}
	return resources, nil
}

// checkResource records one resource of a statement and the envelope
// pattern it matched, and a problem when none did.
func (r *EnvelopeReport) checkResource(statement int, res string, envelope []string) {
	check := ResourceCheck{Statement: statement, Resource: res, Matched: matchEnvelope(res, envelope)}
	r.Resources = append(r.Resources, check)
	switch {
	case check.Matched != "":
	case res == "*":
		r.Problems.addf("statement %d: Resource \"*\" is outside the envelope, which does not contain \"*\"", statement)
	default:
		r.Problems.addf("statement %d: Resource %q matches no envelope pattern", statement, res)
	}
}

// matchEnvelope returns the first envelope pattern a resource matches, or
// empty. "*" matches everything; an ARN pattern matches ARNs only.
func matchEnvelope(res string, envelope []string) string {
	for _, pattern := range envelope {
		if pattern == "*" || (strings.HasPrefix(res, "arn:") && MatchARN(pattern, res)) {
			return pattern
		}
	}
	return ""
}

// Composition is the union of one subject's grants, for one cluster scope.
type Composition struct {
	Subject string
	// Cluster is the cluster the union applies to; empty when the subject's
	// holdings name no cluster, so the union applies everywhere.
	Cluster string
	// Sources are where the grants come from, in order: an assignment's
	// name, or "service <name>" for a membership.
	Sources []string
	Grants  []string
	// Resources are, per lookup grant, the resources its Access documents
	// relate the subject to, which the composed policy was rendered with.
	Resources map[string][]string
	// Dropped are the lookup grants left out because no resource is
	// related, as the broker leaves them out. When every grant is, the
	// broker refuses the subject with no_resources; that is reported here,
	// not a problem.
	Dropped []string
	// BaseRoles are the distinct base roles of the grants; exactly one is
	// the shape (design 6.2).
	BaseRoles []string
	// Policy is the composed session policy and PolicyChars its minified
	// length.
	Policy            string
	PolicyChars       int
	ManagedPolicyArns []string
	SessionTags       map[string]string
	Problems          Problems
}

// CompositionReport is the result of LintComposition.
type CompositionReport struct {
	Compositions []Composition
	// Expired are the holdings left out because their expiresAt has
	// passed: "assignment <name>", "service <name> grant <grant>" or
	// "access <name>".
	Expired []string
	// Problems are every composition's problems, prefixed with the subject.
	Problems Problems
}

// holding is one source of grants for a subject: an Assignment, or one
// bounded grant of a service the subject is a member of.
type holding struct {
	// source is "assignment <name>" or "service <name> grant <grant>", for
	// messages; origin is the assignment's name or "service <name>", for
	// Composition.Sources.
	source, origin string
	subject        string
	grants         []string
	expiresAt      string
	clusters       []string
}

// holdings lists every source of grants in the tree, assignments first and
// then the services' grants for each member, in the tree's order. An
// assignment that names no grant (a suspension alone) is no source.
func holdings(src *Source) []holding {
	var out []holding
	for _, a := range src.Assignments {
		if len(a.Spec.Grants) == 0 {
			continue
		}
		out = append(out, holding{
			source: "assignment " + a.Name(), origin: a.Name(), subject: a.Spec.Subject,
			grants: a.Spec.Grants, expiresAt: a.Spec.ExpiresAt, clusters: a.Spec.Clusters,
		})
	}
	for _, s := range src.Services {
		for _, member := range s.Spec.Members {
			for _, g := range s.Spec.Grants {
				out = append(out, holding{
					source: "service " + s.Name() + " grant " + g.Name, origin: "service " + s.Name(), subject: member,
					grants: []string{g.Name}, expiresAt: g.ExpiresAt, clusters: g.Clusters,
				})
			}
		}
	}
	return out
}

// accessHolding is one Access document as it applies to one subject:
// directly, or through the subject's service.
type accessHolding struct {
	resource Resource
	relation string
	clusters []string
}

// accessBySubject lists, per subject, the Access documents that relate it
// to a resource, directly or through its service, leaving out and
// recording the expired ones.
func (r *CompositionReport) accessBySubject(src *Source, now time.Time) map[string][]accessHolding {
	out := map[string][]accessHolding{}
	for _, a := range src.Accesses {
		exp, err := parseExpiry(a.Spec.ExpiresAt)
		if err != nil {
			r.Problems.addf("access %s: %v", a.Name(), err)
			continue
		}
		if !exp.IsZero() && !exp.After(now) {
			r.Expired = append(r.Expired, "access "+a.Name())
			continue
		}
		h := accessHolding{resource: a.Spec.Resource, relation: a.Spec.Relation, clusters: a.Spec.Clusters}
		subjects := []string{a.Spec.Subject}
		if a.Spec.Service != "" {
			subjects = nil
			if svc := src.Service(a.Spec.Service); svc != nil {
				subjects = svc.Spec.Members
			}
		}
		for _, sub := range subjects {
			out[sub] = append(out[sub], h)
		}
	}
	return out
}

// LintComposition checks, for every subject with grants known in Git, that
// the union of its grants stays within one shape, the size budget and the
// union envelope (design 6.2, step 5): one base role, a composed policy of
// at most MaxPolicyChars, at most MaxManagedPolicyArns managed policies,
// and no session tag set to different values by two grants. A subject's
// grants come from its Assignments and from the Service it is a member of;
// a suspended subject is checked like any other, since lifting the
// suspension must not surprise.
//
// rendered maps a grant's name to its rendered policy (empty for a grant
// without one); lookups maps a lookup grant's name to what the bundle
// carries for it. A lookup grant is rendered, as the broker renders it,
// with the resources the tree's Access documents relate the subject to in
// that scope, and each of its resources must match that grant's envelope
// (the broker refuses resource_outside_envelope otherwise), within its
// compiled maximum; one with no resource is left out of the union, as the
// broker leaves it out. Holdings and access expired at now are left out
// and reported. When a subject's holdings or access name clusters, one
// union is checked per named cluster, taking in those that are not
// cluster-bound; otherwise one union covers every cluster.
func LintComposition(src *Source, rendered map[string]string, lookups map[string]*BundleLookup, now time.Time) *CompositionReport {
	r := &CompositionReport{}
	bySubject := r.liveBySubject(holdings(src), now)
	access := r.accessBySubject(src, now)
	c := composer{src: src, rendered: rendered, lookups: lookups}
	for _, subject := range sortedKeys(bySubject) {
		hs, as := bySubject[subject], access[subject]
		for _, cluster := range clusterScopes(hs, as) {
			r.add(c.compose(subject, cluster, holdingsInCluster(hs, cluster), accessInCluster(as, cluster)))
		}
	}
	return r
}

// liveBySubject groups the holdings by subject, leaving out and recording
// the expired ones and those whose expiry does not parse.
func (r *CompositionReport) liveBySubject(hs []holding, now time.Time) map[string][]holding {
	bySubject := map[string][]holding{}
	for _, h := range hs {
		exp, err := parseExpiry(h.expiresAt)
		if err != nil {
			r.Problems.addf("%s: %v", h.source, err)
			continue
		}
		if !exp.IsZero() && !exp.After(now) {
			r.Expired = append(r.Expired, h.source)
			continue
		}
		bySubject[h.subject] = append(bySubject[h.subject], h)
	}
	return bySubject
}

// clusterScopes returns the clusters a subject's unions are checked for:
// every cluster its holdings and access name, sorted, or the one unnamed
// scope when they name none.
func clusterScopes(hs []holding, as []accessHolding) []string {
	clusters := map[string]bool{}
	for _, h := range hs {
		for _, c := range h.clusters {
			clusters[c] = true
		}
	}
	for _, a := range as {
		for _, c := range a.clusters {
			clusters[c] = true
		}
	}
	if len(clusters) == 0 {
		return []string{""}
	}
	return sortedKeys(clusters)
}

// holdingsInCluster returns the holdings that apply in cluster: the ones
// bound to it and the ones bound to no cluster.
func holdingsInCluster(hs []holding, cluster string) []holding {
	var in []holding
	for _, h := range hs {
		if len(h.clusters) == 0 || slices.Contains(h.clusters, cluster) {
			in = append(in, h)
		}
	}
	return in
}

// accessInCluster returns the access that applies in cluster, as
// holdingsInCluster does.
func accessInCluster(as []accessHolding, cluster string) []accessHolding {
	var in []accessHolding
	for _, a := range as {
		if len(a.clusters) == 0 || slices.Contains(a.clusters, cluster) {
			in = append(in, a)
		}
	}
	return in
}

// add records a composition and its problems, prefixed with the subject
// and the cluster scope.
func (r *CompositionReport) add(c Composition) {
	r.Compositions = append(r.Compositions, c)
	for _, p := range c.Problems {
		if c.Cluster == "" {
			r.Problems.addf("subject %s: %s", c.Subject, p)
		} else {
			r.Problems.addf("subject %s in cluster %s: %s", c.Subject, c.Cluster, p)
		}
	}
}

// composer composes one subject's grants in one cluster scope.
type composer struct {
	src      *Source
	rendered map[string]string
	lookups  map[string]*BundleLookup
}

func (cp composer) compose(subject, cluster string, hs []holding, as []accessHolding) Composition {
	c := Composition{Subject: subject, Cluster: cluster, SessionTags: map[string]string{}}
	c.Sources, c.Grants = heldGrants(hs)
	u := newGrantUnion()
	for _, name := range c.Grants {
		g := cp.src.Grant(name)
		if g == nil {
			c.Problems.addf("grant %q not found", name)
			continue
		}
		policy, held := cp.policyOf(&c, g, as)
		if held {
			u.add(&c, g, policy)
		}
	}
	c.Grants = slices.DeleteFunc(c.Grants, func(name string) bool { return slices.Contains(c.Dropped, name) })
	c.BaseRoles = sortedKeys(u.baseRoles)
	if len(c.BaseRoles) > 1 {
		c.Problems.addf("grants span %d base roles (%s); a workload has exactly one shape", len(c.BaseRoles), strings.Join(c.BaseRoles, ", "))
	}
	c.ManagedPolicyArns = sortedKeys(u.managed)
	if len(c.ManagedPolicyArns) > MaxManagedPolicyArns {
		c.Problems.addf("%d managed policy ARNs in total, STS allows at most %d", len(c.ManagedPolicyArns), MaxManagedPolicyArns)
	}
	c.lintComposedPolicy(u.policies, u.envelope)
	size := LintSize(subject, "", c.SessionTags)
	c.Problems = append(c.Problems, size.Problems...)
	return c
}

// policyOf is a grant's policy in the subject's composition and whether
// the grant takes part: a lookup grant's is rendered with the resources
// its access relates the subject to, and with none the grant is dropped.
func (cp composer) policyOf(c *Composition, g *Grant, as []accessHolding) (string, bool) {
	l, ok := cp.lookups[g.Name()]
	if !ok {
		return cp.rendered[g.Name()], true
	}
	resources := relatedResources(as, l)
	if len(resources) == 0 {
		c.Dropped = append(c.Dropped, g.Name())
		return "", false
	}
	if c.Resources == nil {
		c.Resources = map[string][]string{}
	}
	c.Resources[g.Name()] = resources
	if len(resources) > l.MaxResources {
		c.Problems.addf("grant %s: %d %s resources, over its compiled maximum of %d (the broker refuses policy_too_large)", g.Name(), len(resources), l.Kind, l.MaxResources)
	}
	policy, err := l.Render(g.Spec.Account, resources)
	if err != nil {
		c.Problems.addf("grant %s: rendering for %s: %v", g.Name(), strings.Join(resources, ", "), err)
		return "", true
	}
	for _, p := range LintEnvelope(g.Name(), policy, g.Spec.Envelope).Problems {
		c.Problems.addf("grant %s: rendered for its resources: %s (the broker refuses resource_outside_envelope)", g.Name(), p)
	}
	return policy, true
}

// relatedResources are the names of the resources of the lookup's kind
// that the access gives its permission on, sorted.
func relatedResources(as []accessHolding, l *BundleLookup) []string {
	relations, _ := RelationsOf(l.Permission)
	var names []string
	for _, a := range as {
		if a.resource.Kind == l.Kind && slices.Contains(relations, a.relation) {
			names = append(names, a.resource.Name)
		}
	}
	return sortedUnique(names)
}

// heldGrants returns the holdings' origins, in order without repeats, and
// the distinct grants they name, sorted.
func heldGrants(hs []holding) (origins, grants []string) {
	grantNames := map[string]bool{}
	for _, h := range hs {
		if !slices.Contains(origins, h.origin) {
			origins = append(origins, h.origin)
		}
		for _, name := range h.grants {
			grantNames[name] = true
		}
	}
	return origins, sortedKeys(grantNames)
}

// grantUnion accumulates what a subject's grants put together, apart from
// the session tags, which go straight on the Composition.
type grantUnion struct {
	baseRoles map[string]bool
	managed   map[string]bool
	// tagSetBy is the grant that set each session tag, for the conflict
	// message.
	tagSetBy map[string]string
	policies []string
	envelope []string
}

func newGrantUnion() *grantUnion {
	return &grantUnion{baseRoles: map[string]bool{}, managed: map[string]bool{}, tagSetBy: map[string]string{}}
}

// add takes one grant into the union; policy is its rendered session
// policy, empty for a grant without one.
func (u *grantUnion) add(c *Composition, g *Grant, policy string) {
	u.baseRoles[g.Spec.BaseRole] = true
	for _, arn := range g.Spec.ManagedPolicyArns {
		u.managed[arn] = true
	}
	u.mergeTags(c, g)
	if policy != "" {
		u.policies = append(u.policies, policy)
	}
	u.envelope = append(u.envelope, g.Spec.Envelope...)
}

// mergeTags adds a grant's session tags to the composition; a tag another
// grant set to a different value is a problem.
func (u *grantUnion) mergeTags(c *Composition, g *Grant) {
	for _, k := range sortedKeys(g.Spec.SessionTags) {
		v := g.Spec.SessionTags[k]
		if prev, ok := c.SessionTags[k]; ok && prev != v {
			c.Problems.addf("session tag %q is %q in grant %s and %q in grant %s", k, prev, u.tagSetBy[k], v, g.Name())
			continue
		}
		c.SessionTags[k] = v
		u.tagSetBy[k] = g.Name()
	}
}

// lintComposedPolicy composes the grants' rendered policies, when there are
// any, and checks the result against the size budget and the union
// envelope.
func (c *Composition) lintComposedPolicy(policies, envelope []string) {
	if len(policies) == 0 {
		return
	}
	composed, err := ComposePolicies(policies...)
	if err != nil {
		c.Problems.addf("composing session policies: %v", err)
		return
	}
	c.Policy = composed
	c.PolicyChars = len(composed)
	if c.PolicyChars > MaxPolicyChars {
		c.Problems.addf("composed session policy is %d characters minified, STS allows at most %d", c.PolicyChars, MaxPolicyChars)
	}
	env := LintEnvelope(c.Subject, composed, envelope)
	for _, p := range env.Problems {
		c.Problems.addf("composed session policy against the union envelope: %s", p)
	}
}

// ComposePolicies merges session policies into one document the way the
// broker composes a workload's grants at issuance: the statements of every
// policy, in order, under one Version. The result is minified with sorted
// keys.
func ComposePolicies(policies ...string) (string, error) {
	var statements []any
	for i, p := range policies {
		sts, err := policyStatements(p)
		if err != nil {
			return "", fmt.Errorf("policy %d: %w", i, err)
		}
		for _, st := range sts {
			statements = append(statements, st)
		}
	}
	return MinifyJSON(map[string]any{
		"Version":   "2012-10-17",
		"Statement": statements,
	})
}

// policyStatements parses a policy document and returns its statements,
// whether Statement is one object or an array of them.
func policyStatements(policy string) ([]map[string]any, error) {
	var doc map[string]any
	if err := json.Unmarshal([]byte(policy), &doc); err != nil {
		return nil, fmt.Errorf("not a JSON object: %w", err)
	}
	raw, ok := doc["Statement"]
	if !ok {
		return nil, fmt.Errorf("no Statement")
	}
	var items []any
	switch x := raw.(type) {
	case map[string]any:
		items = []any{x}
	case []any:
		items = x
	default:
		return nil, fmt.Errorf("Statement must be an object or an array")
	}
	out := make([]map[string]any, 0, len(items))
	for i, item := range items {
		st, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("statement %d is not an object", i)
		}
		out = append(out, st)
	}
	return out, nil
}

// stringOrList reads a policy element that is a string or a list of
// strings. nil yields no strings.
func stringOrList(v any) ([]string, error) {
	switch x := v.(type) {
	case nil:
		return nil, nil
	case string:
		return []string{x}, nil
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("list element %v is not a string", item)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("must be a string or a list of strings")
	}
}
