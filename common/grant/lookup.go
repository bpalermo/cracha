package grant

import (
	"fmt"
	"strings"
)

// maxLookupResources bounds the compiled maximum of a lookup grant, so
// that sizing a template that grows by nothing per resource ends.
const maxLookupResources = 1000

// newBundleLookup is what the bundle carries for a lookup grant: the
// template, the grant's other parameters, and the most resources of the
// kind's longest name its policy holds within MaxPolicyChars. A template
// that does not fit one such resource, or does not render, is an error.
func newBundleLookup(g *Grant, t *Template) (*BundleLookup, error) {
	sp := g.Spec.SessionPolicy
	name, l := lookupParam(sp)
	params := map[string]Param{}
	for k, v := range sp.Params {
		if k != name {
			params[k] = v
		}
	}
	tparams := t.Params
	if tparams == nil {
		tparams = map[string]ParamSpec{}
	}
	bl := &BundleLookup{
		Param: name, Kind: l.Kind, Permission: l.Permission,
		Template: BundleTemplate{Name: t.Name, Params: tparams, Policy: t.Policy},
		Params:   params,
	}
	kind, _ := LookupResourceKind(l.Kind)
	one, err := renderProbes(bl, g.Spec.Account, 1)
	if err != nil {
		return nil, err
	}
	if len(one) > MaxPolicyChars {
		return nil, fmt.Errorf("one %s of the longest name (%d characters) makes a policy of %d characters, over %d", l.Kind, kind.MaxNameLen, len(one), MaxPolicyChars)
	}
	n := 1
	for n < maxLookupResources {
		p, err := renderProbes(bl, g.Spec.Account, n+1)
		if err != nil || len(p) > MaxPolicyChars {
			break
		}
		n++
	}
	bl.MaxResources = n
	return bl, nil
}

// renderProbes renders a lookup grant for n probe resources.
func renderProbes(l *BundleLookup, account string, n int) (string, error) {
	kind, ok := LookupResourceKind(l.Kind)
	if !ok {
		return "", fmt.Errorf("lookup kind %q is unknown", l.Kind)
	}
	return l.Render(account, probeNames(kind, n))
}

// mustRenderProbes is renderProbes for a lookup newBundleLookup already
// rendered for at least n.
func mustRenderProbes(l *BundleLookup, account string, n int) string {
	p, err := renderProbes(l, account, n)
	if err != nil {
		panic(fmt.Sprintf("grant: rendering a sized lookup: %v", err))
	}
	return p
}

// isProbeResource reports whether a rendered resource comes from the
// lookup's probes, which the envelope is not expected to name.
func isProbeResource(r string) bool { return strings.Contains(r, probeMarker) }

// lintSids checks that a template rendered once per resource (a string
// lookup parameter) does not repeat a statement Sid, which IAM refuses in
// one policy.
func lintSids(l *BundleLookup, account string) Problems {
	var problems Problems
	if l.Template.Params[l.Param].Type != ParamString {
		return nil
	}
	policy := mustRenderProbes(l, account, min(2, l.MaxResources))
	statements, err := policyStatements(policy)
	if err != nil {
		problems.addf("session policy: %v", err)
		return problems
	}
	seen := map[string]bool{}
	for _, st := range statements {
		sid, _ := st["Sid"].(string)
		if sid == "" {
			continue
		}
		if seen[sid] {
			problems.addf("statement Sid %q repeats when the template is rendered once per resource; reference ${%s} in it or declare the parameter a list", sid, l.Param)
			return problems
		}
		seen[sid] = true
	}
	return problems
}
