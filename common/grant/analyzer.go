package grant

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
)

// PolicyFinding is one finding of a policy validation (pipeline step 2).
type PolicyFinding struct {
	// Type is ERROR, SECURITY_WARNING, WARNING or SUGGESTION.
	Type string
	// Code is the finding's issue code, such as INVALID_ARN_RESOURCE.
	Code string
	// Detail is the finding's text.
	Detail string
}

// Blocking reports whether the finding fails the pipeline: errors and
// security warnings do, warnings and suggestions are reported only.
func (f PolicyFinding) Blocking() bool {
	return f.Type == "ERROR" || f.Type == "SECURITY_WARNING"
}

// AccessCheck is the result of a no-new-access check (pipeline step 3).
type AccessCheck struct {
	// Passed is true when the policy grants no access the reference does
	// not.
	Passed bool
	// Reasons explain a failure, one per offending statement.
	Reasons []string
}

// PolicyAnalyzer runs the pipeline's Access Analyzer steps: ValidatePolicy
// (step 2) and CheckNoNewAccess against the shape's envelope policy (step
// 3). AccessAnalyzer is the AWS implementation; a nil analyzer makes the
// pipeline skip both steps and say so.
type PolicyAnalyzer interface {
	// ValidatePolicy validates an identity policy document.
	ValidatePolicy(ctx context.Context, policy string) ([]PolicyFinding, error)
	// CheckNoNewAccess reports whether policy grants no access that
	// reference does not.
	CheckNoNewAccess(ctx context.Context, policy, reference string) (*AccessCheck, error)
}

// EnvelopePolicy is the shape's envelope as an identity policy: every
// action on the envelope's resources. It is the reference policy of the
// no-new-access check, so a rendered policy that reaches outside the
// envelope fails it.
func EnvelopePolicy(envelope []string) (string, error) {
	if len(envelope) == 0 {
		return "", errors.New("empty envelope")
	}
	resources := make([]any, len(envelope))
	for i, pattern := range envelope {
		resources[i] = pattern
	}
	return MinifyJSON(map[string]any{
		"Version": "2012-10-17",
		"Statement": []any{map[string]any{
			"Effect":   "Allow",
			"Action":   "*",
			"Resource": resources,
		}},
	})
}

// AccessAnalyzerAPI is the part of the Access Analyzer client the adapter
// uses, so tests can substitute a fake.
type AccessAnalyzerAPI interface {
	ValidatePolicy(ctx context.Context, in *accessanalyzer.ValidatePolicyInput, opts ...func(*accessanalyzer.Options)) (*accessanalyzer.ValidatePolicyOutput, error)
	CheckNoNewAccess(ctx context.Context, in *accessanalyzer.CheckNoNewAccessInput, opts ...func(*accessanalyzer.Options)) (*accessanalyzer.CheckNoNewAccessOutput, error)
}

// AccessAnalyzer is the PolicyAnalyzer backed by IAM Access Analyzer.
type AccessAnalyzer struct {
	api AccessAnalyzerAPI
}

// NewAccessAnalyzer wraps an Access Analyzer client.
func NewAccessAnalyzer(api AccessAnalyzerAPI) *AccessAnalyzer {
	return &AccessAnalyzer{api: api}
}

// ValidatePolicy implements PolicyAnalyzer with
// accessanalyzer:ValidatePolicy, following pagination.
func (a *AccessAnalyzer) ValidatePolicy(ctx context.Context, policy string) ([]PolicyFinding, error) {
	var findings []PolicyFinding
	var next *string
	for {
		out, err := a.api.ValidatePolicy(ctx, &accessanalyzer.ValidatePolicyInput{
			PolicyDocument: aws.String(policy),
			PolicyType:     types.PolicyTypeIdentityPolicy,
			NextToken:      next,
		})
		if err != nil {
			return nil, fmt.Errorf("accessanalyzer ValidatePolicy: %w", err)
		}
		for _, f := range out.Findings {
			findings = append(findings, PolicyFinding{
				Type:   string(f.FindingType),
				Code:   aws.ToString(f.IssueCode),
				Detail: aws.ToString(f.FindingDetails),
			})
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return findings, nil
		}
		next = out.NextToken
	}
}

// CheckNoNewAccess implements PolicyAnalyzer with
// accessanalyzer:CheckNoNewAccess, policy as the new document and
// reference as the existing one.
func (a *AccessAnalyzer) CheckNoNewAccess(ctx context.Context, policy, reference string) (*AccessCheck, error) {
	out, err := a.api.CheckNoNewAccess(ctx, &accessanalyzer.CheckNoNewAccessInput{
		NewPolicyDocument:      aws.String(policy),
		ExistingPolicyDocument: aws.String(reference),
		PolicyType:             types.AccessCheckPolicyTypeIdentityPolicy,
	})
	if err != nil {
		return nil, fmt.Errorf("accessanalyzer CheckNoNewAccess: %w", err)
	}
	check := &AccessCheck{Passed: out.Result == types.CheckNoNewAccessResultPass}
	for _, r := range out.Reasons {
		reason := aws.ToString(r.Description)
		if r.StatementIndex != nil {
			reason = fmt.Sprintf("statement %d: %s", *r.StatementIndex, reason)
		}
		check.Reasons = append(check.Reasons, reason)
	}
	if !check.Passed && len(check.Reasons) == 0 {
		check.Reasons = append(check.Reasons, aws.ToString(out.Message))
	}
	return check, nil
}
