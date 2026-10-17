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
	// one.
	Rendered string
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

// Lint runs the grant-compiler pipeline of design 6.2 up to compilation:
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
	for _, g := range src.Grants {
		res, err := lintGrant(ctx, g, src.Templates, opts.Analyzer)
		if err != nil {
			return nil, err
		}
		rendered[g.Name()] = res.Rendered
		report.Grants = append(report.Grants, *res)
		for _, p := range res.Problems {
			report.Problems.addf("grant %s: %s", g.Name(), p)
		}
	}
	report.Composition = LintComposition(src, rendered, now)
	report.Problems = append(report.Problems, report.Composition.Problems...)
	return report, nil
}

// lintGrant runs steps 1 to 4 for one grant. Only an analyzer call that
// fails outright (not a finding) is returned as an error.
func lintGrant(ctx context.Context, g *Grant, templates map[string]*Template, analyzer PolicyAnalyzer) (*GrantResult, error) {
	res := &GrantResult{Grant: g.Name()}
	if sp := g.Spec.SessionPolicy; sp != nil {
		t, ok := templates[sp.Template]
		if !ok {
			res.Problems.addf("template %q not found", sp.Template)
		} else if policy, err := t.Render(g.Spec.Account, sp.Params); err != nil {
			res.Problems.addf("render: %v", err)
		} else {
			res.Rendered = policy
		}
	}
	if res.Rendered != "" && analyzer != nil {
		findings, err := analyzer.ValidatePolicy(ctx, res.Rendered)
		if err != nil {
			return nil, fmt.Errorf("grant %s: %w", g.Name(), err)
		}
		res.Validation = findings
		for _, f := range findings {
			if f.Blocking() {
				res.Problems.addf("%s: %s %s: %s", StepValidatePolicy, f.Type, f.Code, f.Detail)
			}
		}
		reference, err := EnvelopePolicy(g.Spec.Envelope)
		if err != nil {
			return nil, fmt.Errorf("grant %s: %w", g.Name(), err)
		}
		check, err := analyzer.CheckNoNewAccess(ctx, res.Rendered, reference)
		if err != nil {
			return nil, fmt.Errorf("grant %s: %w", g.Name(), err)
		}
		res.AccessCheck = check
		if !check.Passed {
			for _, reason := range check.Reasons {
				res.Problems.addf("%s: %s", StepCheckNoNewAccess, reason)
			}
			if len(check.Reasons) == 0 {
				res.Problems.addf("%s: the policy grants access outside the envelope", StepCheckNoNewAccess)
			}
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
