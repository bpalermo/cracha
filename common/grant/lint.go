package grant

import (
	"encoding/json"
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
	r := &EnvelopeReport{Grant: name}
	statements, err := policyStatements(policy)
	if err != nil {
		r.Problems.addf("session policy: %v", err)
		return r
	}
	for i, st := range statements {
		effect, _ := st["Effect"].(string)
		if effect != "Allow" {
			continue
		}
		if _, ok := st["NotResource"]; ok {
			r.Problems.addf("statement %d: NotResource cannot be checked against the envelope", i)
			continue
		}
		resources, err := stringOrList(st["Resource"])
		if err != nil {
			r.Problems.addf("statement %d: Resource: %v", i, err)
			continue
		}
		if len(resources) == 0 {
			r.Problems.addf("statement %d: an Allow statement needs a Resource", i)
			continue
		}
		for _, res := range resources {
			check := ResourceCheck{Statement: i, Resource: res}
			for _, pattern := range envelope {
				if pattern == "*" || (strings.HasPrefix(res, "arn:") && MatchARN(pattern, res)) {
					check.Matched = pattern
					break
				}
			}
			r.Resources = append(r.Resources, check)
			if check.Matched != "" {
				continue
			}
			if res == "*" {
				r.Problems.addf("statement %d: Resource \"*\" is outside the envelope, which does not contain \"*\"", i)
			} else {
				r.Problems.addf("statement %d: Resource %q matches no envelope pattern", i, res)
			}
		}
	}
	return r
}

// Composition is the union of one subject's grants, for one cluster scope.
type Composition struct {
	Subject string
	// Cluster is the cluster the union applies to; empty when the subject's
	// assignments name no cluster, so the union applies everywhere.
	Cluster     string
	Assignments []string
	Grants      []string
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
	// Expired are the assignments left out because their expiresAt has
	// passed.
	Expired []string
	// Problems are every composition's problems, prefixed with the subject.
	Problems Problems
}

// LintComposition checks, for every subject with assignments known in Git,
// that the union of its grants stays within one shape, the size budget and
// the union envelope (design 6.2, step 5): one base role, a composed policy
// of at most MaxPolicyChars, at most MaxManagedPolicyArns managed policies,
// and no session tag set to different values by two grants.
//
// rendered maps a grant's name to its rendered policy (empty for a grant
// without one). Assignments expired at now are left out and reported. When
// a subject's assignments name clusters, one union is checked per named
// cluster, taking in the assignments that are not cluster-bound; otherwise
// one union covers every cluster.
func LintComposition(src *Source, rendered map[string]string, now time.Time) *CompositionReport {
	r := &CompositionReport{}
	bySubject := map[string][]*Assignment{}
	for _, a := range src.Assignments {
		exp, err := a.Spec.Expiry()
		if err != nil {
			r.Problems.addf("assignment %s: %v", a.Name(), err)
			continue
		}
		if !exp.IsZero() && !exp.After(now) {
			r.Expired = append(r.Expired, a.Name())
			continue
		}
		bySubject[a.Spec.Subject] = append(bySubject[a.Spec.Subject], a)
	}
	for _, subject := range sortedKeys(bySubject) {
		assignments := bySubject[subject]
		clusters := map[string]bool{}
		for _, a := range assignments {
			for _, c := range a.Spec.Clusters {
				clusters[c] = true
			}
		}
		scopes := sortedKeys(clusters)
		if len(scopes) == 0 {
			scopes = []string{""}
		}
		for _, cluster := range scopes {
			var in []*Assignment
			for _, a := range assignments {
				if len(a.Spec.Clusters) == 0 || slices.Contains(a.Spec.Clusters, cluster) {
					in = append(in, a)
				}
			}
			c := composeSubject(src, rendered, subject, cluster, in)
			r.Compositions = append(r.Compositions, c)
			for _, p := range c.Problems {
				if cluster == "" {
					r.Problems.addf("subject %s: %s", subject, p)
				} else {
					r.Problems.addf("subject %s in cluster %s: %s", subject, cluster, p)
				}
			}
		}
	}
	return r
}

func composeSubject(src *Source, rendered map[string]string, subject, cluster string, assignments []*Assignment) Composition {
	c := Composition{Subject: subject, Cluster: cluster, SessionTags: map[string]string{}}
	grantNames := map[string]bool{}
	for _, a := range assignments {
		c.Assignments = append(c.Assignments, a.Name())
		for _, name := range a.Spec.Grants {
			grantNames[name] = true
		}
	}
	c.Grants = sortedKeys(grantNames)

	baseRoles := map[string]bool{}
	managed := map[string]bool{}
	tagSetBy := map[string]string{}
	var policies []string
	var envelope []string
	for _, name := range c.Grants {
		g := src.Grant(name)
		if g == nil {
			c.Problems.addf("grant %q not found", name)
			continue
		}
		baseRoles[g.Spec.BaseRole] = true
		for _, arn := range g.Spec.ManagedPolicyArns {
			managed[arn] = true
		}
		for _, k := range sortedKeys(g.Spec.SessionTags) {
			v := g.Spec.SessionTags[k]
			if prev, ok := c.SessionTags[k]; ok && prev != v {
				c.Problems.addf("session tag %q is %q in grant %s and %q in grant %s", k, prev, tagSetBy[k], v, name)
				continue
			}
			c.SessionTags[k] = v
			tagSetBy[k] = name
		}
		if p := rendered[name]; p != "" {
			policies = append(policies, p)
		}
		envelope = append(envelope, g.Spec.Envelope...)
	}
	c.BaseRoles = sortedKeys(baseRoles)
	if len(c.BaseRoles) > 1 {
		c.Problems.addf("grants span %d base roles (%s); a workload has exactly one shape", len(c.BaseRoles), strings.Join(c.BaseRoles, ", "))
	}
	c.ManagedPolicyArns = sortedKeys(managed)
	if len(c.ManagedPolicyArns) > MaxManagedPolicyArns {
		c.Problems.addf("%d managed policy ARNs in total, STS allows at most %d", len(c.ManagedPolicyArns), MaxManagedPolicyArns)
	}
	if len(policies) > 0 {
		composed, err := ComposePolicies(policies...)
		if err != nil {
			c.Problems.addf("composing session policies: %v", err)
		} else {
			c.Policy = composed
			c.PolicyChars = len(composed)
			if c.PolicyChars > MaxPolicyChars {
				c.Problems.addf("composed session policy is %d characters minified, STS allows at most %d", c.PolicyChars, MaxPolicyChars)
			}
			env := LintEnvelope(subject, composed, envelope)
			for _, p := range env.Problems {
				c.Problems.addf("composed session policy against the union envelope: %s", p)
			}
		}
	}
	size := LintSize(subject, "", c.SessionTags)
	c.Problems = append(c.Problems, size.Problems...)
	return c
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
