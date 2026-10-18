package grant

import (
	"context"
	"fmt"
	"time"
)

// Pipeline step names, as reported in Report.Skipped.
const (
	StepValidatePolicy   = "ValidatePolicy"
	StepCheckNoNewAccess = "CheckNoNewAccess"
)

// LintOptions configure Lint.
type LintOptions struct {
	// Analyzer runs pipeline steps 2 and 3. nil skips them; the report says
	// so.
	Analyzer PolicyAnalyzer
	// Now decides which assignments are expired. Zero means time.Now().
	Now time.Time
}

// GrantResult is the pipeline's result for one grant.
type GrantResult struct {
	Grant string
	// Rendered is the rendered session policy; empty for a grant without
	// one and for a lookup grant, whose policy is rendered at issuance.
	Rendered string
	// Lookup is set for a lookup grant: what the bundle carries for the
	// broker to render its policy, the compiled maximum of resources
	// included. Probe is its policy rendered for one resource of the
	// kind's longest name, which steps 2 and 4 check in place of Rendered.
	Lookup *BundleLookup
	Probe  string
	// Validation holds the Access Analyzer findings; AccessCheck the result
	// of the no-new-access check. Both are nil when the step was skipped.
	Validation  []PolicyFinding
	AccessCheck *AccessCheck
	Size        *SizeReport
	Envelope    *EnvelopeReport
	// Problems are this grant's problems from every step.
	Problems Problems
}

// Report is the result of Lint.
type Report struct {
	Grants      []GrantResult
	Composition *CompositionReport
	// Skipped names the steps that did not run, for want of an analyzer.
	Skipped []string
	// Problems are every problem of the report, prefixed with the grant or
	// subject.
	Problems Problems
}

// OK reports whether no step found a problem. Skipped steps do not count
// against the report, but Skipped says they did not run.
func (r *Report) OK() bool { return r.Problems.OK() }

// Lint runs the grant-compiler pipeline of design 6.2 up to compilation,
// over the grants the bundle will hold (Source.CompiledGrants: the
// accounts' implicit grants among them, and every grant with its
// account's defaults applied):
// render (1), Access Analyzer validation (2) and no-new-access check against
// the envelope (3) when an analyzer is given, the size budget (4) and, for
// the assignments known in Git, composition (5). The source must validate
// (ValidateSource) first; a source that does not is returned as the error.
func Lint(ctx context.Context, src *Source, opts LintOptions) (*Report, error) {
	if err := ValidateSource(src); err != nil {
		return nil, err
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	report := &Report{}
	if opts.Analyzer == nil {
		report.Skipped = []string{StepValidatePolicy, StepCheckNoNewAccess}
	}
	rendered := map[string]string{}
	lookups := map[string]*BundleLookup{}
	for _, g := range src.CompiledGrants() {
		res, err := lintGrant(ctx, g, src.Templates, opts.Analyzer)
		if err != nil {
			return nil, err
		}
		rendered[g.Name()] = res.Rendered
		if res.Lookup != nil {
			lookups[g.Name()] = res.Lookup
		}
		report.Grants = append(report.Grants, *res)
		for _, p := range res.Problems {
			report.Problems.addf("grant %s: %s", g.Name(), p)
		}
	}
	report.Composition = LintComposition(src, rendered, lookups, now)
	report.Problems = append(report.Problems, report.Composition.Problems...)
	return report, nil
}

// lintGrant runs steps 1 to 4 for one grant. Only an analyzer call that
// fails outright (not a finding) is returned as an error.
func lintGrant(ctx context.Context, g *Grant, templates map[string]*Template, analyzer PolicyAnalyzer) (*GrantResult, error) {
	res := &GrantResult{Grant: g.Name()}
	if _, l := lookupParam(g.Spec.SessionPolicy); l != nil {
		return res, res.lintLookupGrant(ctx, g, templates, analyzer)
	}
	res.render(g, templates)
	if res.Rendered != "" && analyzer != nil {
		if err := res.analyze(ctx, g, analyzer); err != nil {
			return nil, fmt.Errorf("grant %s: %w", g.Name(), err)
		}
	}
	res.Size = LintSize(g.Name(), res.Rendered, g.Spec.SessionTags)
	res.Problems = append(res.Problems, res.Size.Problems...)
	if res.Rendered != "" {
		res.Envelope = LintEnvelope(g.Name(), res.Rendered, g.Spec.Envelope)
		res.Problems = append(res.Problems, res.Envelope.Problems...)
	}
	return res, nil
}

// lintLookupGrant runs steps 1 to 4 for a lookup grant, whose resources
// are known only at issuance: it renders the policy for probe resources of
// the kind's longest name, computes the most that fit the size budget
// (BundleLookup.MaxResources), validates the policy for one with the
// analyzer (ValidatePolicy only: the probes are no resource the envelope
// names, so CheckNoNewAccess would fail them all; the broker checks every
// rendered resource against the envelope instead), and checks the
// resources the template writes itself, those that hold no probe, against
// the envelope.
func (res *GrantResult) lintLookupGrant(ctx context.Context, g *Grant, templates map[string]*Template, analyzer PolicyAnalyzer) error {
	sp := g.Spec.SessionPolicy
	t, ok := templates[sp.Template]
	if !ok {
		res.Problems.addf("template %q not found", sp.Template)
		return nil
	}
	l, err := newBundleLookup(g, t)
	if err != nil {
		res.Problems.addf("render: %v", err)
		return nil
	}
	res.Lookup = l
	res.Probe = mustRenderProbes(l, g.Spec.Account, 1)
	res.Problems = append(res.Problems, lintSids(l, g.Spec.Account)...)
	if analyzer != nil {
		findings, err := analyzer.ValidatePolicy(ctx, res.Probe)
		if err != nil {
			return fmt.Errorf("grant %s: %w", g.Name(), err)
		}
		res.Validation = findings
		res.Problems = append(res.Problems, blockingFindings(findings)...)
	}
	res.Size = LintSize(g.Name(), mustRenderProbes(l, g.Spec.Account, l.MaxResources), g.Spec.SessionTags)
	res.Problems = append(res.Problems, res.Size.Problems...)
	res.Envelope = lintEnvelope(g.Name(), res.Probe, g.Spec.Envelope, isProbeResource)
	res.Problems = append(res.Problems, res.Envelope.Problems...)
	return nil
}

// render is step 1: it renders the grant's session policy, when it has
// one, into Rendered; a template that is missing or does not render is a
// problem.
func (res *GrantResult) render(g *Grant, templates map[string]*Template) {
	sp := g.Spec.SessionPolicy
	if sp == nil {
		return
	}
	t, ok := templates[sp.Template]
	if !ok {
		res.Problems.addf("template %q not found", sp.Template)
		return
	}
	policy, err := t.Render(g.Spec.Account, sp.Params)
	if err != nil {
		res.Problems.addf("render: %v", err)
		return
	}
	res.Rendered = policy
}

// analyze is steps 2 and 3: it validates the rendered policy and checks it
// grants no access outside the envelope. An analyzer call that fails
// outright is returned; findings become problems.
func (res *GrantResult) analyze(ctx context.Context, g *Grant, analyzer PolicyAnalyzer) error {
	findings, err := analyzer.ValidatePolicy(ctx, res.Rendered)
	if err != nil {
		return err
	}
	res.Validation = findings
	res.Problems = append(res.Problems, blockingFindings(findings)...)
	reference, err := EnvelopePolicy(g.Spec.Envelope)
	if err != nil {
		return err
	}
	check, err := analyzer.CheckNoNewAccess(ctx, res.Rendered, reference)
	if err != nil {
		return err
	}
	res.AccessCheck = check
	res.Problems = append(res.Problems, accessCheckProblems(check)...)
	return nil
}

// blockingFindings turns the findings that fail the pipeline into
// problems; warnings and suggestions are reported only.
func blockingFindings(findings []PolicyFinding) Problems {
	var problems Problems
	for _, f := range findings {
		if f.Blocking() {
			problems.addf("%s: %s %s: %s", StepValidatePolicy, f.Type, f.Code, f.Detail)
		}
	}
	return problems
}

// accessCheckProblems turns a failed no-new-access check into problems:
// one per reason, or a single one when the check gave none.
func accessCheckProblems(check *AccessCheck) Problems {
	if check.Passed {
		return nil
	}
	var problems Problems
	for _, reason := range check.Reasons {
		problems.addf("%s: %s", StepCheckNoNewAccess, reason)
	}
	if len(check.Reasons) == 0 {
		problems.addf("%s: the policy grants access outside the envelope", StepCheckNoNewAccess)
	}
	return problems
}
