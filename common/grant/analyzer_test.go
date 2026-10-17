package grant

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
)

// fakeAccessAnalyzerAPI stands in for the SDK client.
type fakeAccessAnalyzerAPI struct {
	pages    [][]types.ValidatePolicyFinding
	calls    []*accessanalyzer.ValidatePolicyInput
	check    *accessanalyzer.CheckNoNewAccessOutput
	checkIn  *accessanalyzer.CheckNoNewAccessInput
	validErr error
	checkErr error
}

func (f *fakeAccessAnalyzerAPI) ValidatePolicy(_ context.Context, in *accessanalyzer.ValidatePolicyInput, _ ...func(*accessanalyzer.Options)) (*accessanalyzer.ValidatePolicyOutput, error) {
	f.calls = append(f.calls, in)
	if f.validErr != nil {
		return nil, f.validErr
	}
	page := 0
	if in.NextToken != nil {
		page = int((*in.NextToken)[0] - '0')
	}
	out := &accessanalyzer.ValidatePolicyOutput{Findings: f.pages[page]}
	if page+1 < len(f.pages) {
		out.NextToken = aws.String(string(rune('0' + page + 1)))
	}
	return out, nil
}

func (f *fakeAccessAnalyzerAPI) CheckNoNewAccess(_ context.Context, in *accessanalyzer.CheckNoNewAccessInput, _ ...func(*accessanalyzer.Options)) (*accessanalyzer.CheckNoNewAccessOutput, error) {
	f.checkIn = in
	if f.checkErr != nil {
		return nil, f.checkErr
	}
	return f.check, nil
}

func TestAccessAnalyzerValidatePolicy(t *testing.T) {
	api := &fakeAccessAnalyzerAPI{pages: [][]types.ValidatePolicyFinding{
		{{FindingType: types.ValidatePolicyFindingTypeError, IssueCode: aws.String("INVALID_ARN_RESOURCE"), FindingDetails: aws.String("bad arn")}},
		{{FindingType: types.ValidatePolicyFindingTypeSuggestion, IssueCode: aws.String("EMPTY_SID_VALUE"), FindingDetails: aws.String("sid")}},
	}}
	a := NewAccessAnalyzer(api)
	findings, err := a.ValidatePolicy(context.Background(), `{"Version":"2012-10-17"}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 || !findings[0].Blocking() || findings[0].Code != "INVALID_ARN_RESOURCE" || findings[1].Blocking() || findings[1].Type != "SUGGESTION" {
		t.Errorf("findings = %+v", findings)
	}
	if len(api.calls) != 2 || api.calls[0].PolicyType != types.PolicyTypeIdentityPolicy || aws.ToString(api.calls[0].PolicyDocument) != `{"Version":"2012-10-17"}` || aws.ToString(api.calls[1].NextToken) != "1" {
		t.Errorf("calls = %+v", api.calls)
	}

	api.validErr = errors.New("throttled")
	if _, err := a.ValidatePolicy(context.Background(), "{}"); err == nil || !strings.Contains(err.Error(), "throttled") {
		t.Errorf("error = %v", err)
	}
}

func TestAccessAnalyzerCheckNoNewAccess(t *testing.T) {
	api := &fakeAccessAnalyzerAPI{check: &accessanalyzer.CheckNoNewAccessOutput{Result: types.CheckNoNewAccessResultPass}}
	a := NewAccessAnalyzer(api)
	check, err := a.CheckNoNewAccess(context.Background(), "new", "ref")
	if err != nil {
		t.Fatal(err)
	}
	if !check.Passed || len(check.Reasons) != 0 {
		t.Errorf("check = %+v", check)
	}
	if aws.ToString(api.checkIn.NewPolicyDocument) != "new" || aws.ToString(api.checkIn.ExistingPolicyDocument) != "ref" || api.checkIn.PolicyType != types.AccessCheckPolicyTypeIdentityPolicy {
		t.Errorf("input = %+v", api.checkIn)
	}

	api.check = &accessanalyzer.CheckNoNewAccessOutput{
		Result:  types.CheckNoNewAccessResultFail,
		Reasons: []types.ReasonSummary{{Description: aws.String("wider resource"), StatementIndex: aws.Int32(1)}},
	}
	check, err = a.CheckNoNewAccess(context.Background(), "new", "ref")
	if err != nil {
		t.Fatal(err)
	}
	if check.Passed || len(check.Reasons) != 1 || check.Reasons[0] != "statement 1: wider resource" {
		t.Errorf("check = %+v", check)
	}

	api.check = &accessanalyzer.CheckNoNewAccessOutput{Result: types.CheckNoNewAccessResultFail, Message: aws.String("new access")}
	check, _ = a.CheckNoNewAccess(context.Background(), "new", "ref")
	if check.Passed || len(check.Reasons) != 1 || check.Reasons[0] != "new access" {
		t.Errorf("check = %+v", check)
	}

	api.checkErr = errors.New("denied")
	if _, err := a.CheckNoNewAccess(context.Background(), "new", "ref"); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Errorf("error = %v", err)
	}
}

func TestEnvelopePolicy(t *testing.T) {
	got, err := EnvelopePolicy([]string{"arn:aws:s3:::b/*", "arn:aws:dynamodb:*:111122223333:table/payments-*"})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"Statement":[{"Action":"*","Effect":"Allow","Resource":["arn:aws:s3:::b/*","arn:aws:dynamodb:*:111122223333:table/payments-*"]}],"Version":"2012-10-17"}`
	if got != want {
		t.Errorf("EnvelopePolicy = %s, want %s", got, want)
	}
	if _, err := EnvelopePolicy(nil); err == nil {
		t.Error("EnvelopePolicy(nil) succeeded")
	}
}

// fakeAnalyzer is a PolicyAnalyzer for pipeline tests.
type fakeAnalyzer struct {
	findings  []PolicyFinding
	check     AccessCheck
	err       error
	policies  []string
	reference string
}

func (f *fakeAnalyzer) ValidatePolicy(_ context.Context, policy string) ([]PolicyFinding, error) {
	f.policies = append(f.policies, policy)
	return f.findings, f.err
}

func (f *fakeAnalyzer) CheckNoNewAccess(_ context.Context, _, reference string) (*AccessCheck, error) {
	f.reference = reference
	c := f.check
	return &c, f.err
}

func TestLintOffline(t *testing.T) {
	src := loadGood(t)
	report, err := Lint(context.Background(), src, LintOptions{Now: lintNow})
	if err != nil {
		t.Fatal(err)
	}
	if !report.OK() {
		t.Errorf("problems = %v", report.Problems)
	}
	if strings.Join(report.Skipped, ",") != "ValidatePolicy,CheckNoNewAccess" {
		t.Errorf("skipped = %v", report.Skipped)
	}
	if len(report.Grants) != 3 {
		t.Fatalf("grants = %d", len(report.Grants))
	}
	for _, g := range report.Grants {
		if g.Validation != nil || g.AccessCheck != nil || g.Size == nil {
			t.Errorf("%s: %+v", g.Grant, g)
		}
		if g.Grant == "billing-reports" {
			if g.Rendered != "" || g.Envelope != nil {
				t.Errorf("billing-reports: %+v", g)
			}
		} else if g.Rendered == "" || g.Envelope == nil {
			t.Errorf("%s: %+v", g.Grant, g)
		}
	}
	if report.Composition == nil || len(report.Composition.Compositions) != 2 {
		t.Errorf("composition = %+v", report.Composition)
	}
}

func TestLintWithAnalyzer(t *testing.T) {
	src := loadGood(t)
	fa := &fakeAnalyzer{check: AccessCheck{Passed: true}, findings: []PolicyFinding{{Type: "SUGGESTION", Code: "EMPTY_SID_VALUE"}}}
	report, err := Lint(context.Background(), src, LintOptions{Analyzer: fa, Now: lintNow})
	if err != nil {
		t.Fatal(err)
	}
	if !report.OK() || len(report.Skipped) != 0 {
		t.Errorf("problems = %v, skipped = %v", report.Problems, report.Skipped)
	}
	if len(fa.policies) != 2 {
		t.Errorf("analyzer saw %d policies, want 2 (grants with a session policy)", len(fa.policies))
	}
	if !strings.Contains(fa.reference, `"Resource":["arn:aws:dynamodb:*:111122223333:table/payments-outbox"]`) {
		t.Errorf("reference = %s, want the last grant's envelope policy", fa.reference)
	}
	if v := report.Grants[1].Validation; len(v) != 1 || v[0].Code != "EMPTY_SID_VALUE" {
		t.Errorf("validation = %+v", v)
	}

	fa = &fakeAnalyzer{
		findings: []PolicyFinding{{Type: "ERROR", Code: "INVALID_ARN", Detail: "bad"}, {Type: "WARNING", Code: "W", Detail: "meh"}},
		check:    AccessCheck{Passed: false, Reasons: []string{"statement 0: wider"}},
	}
	report, err = Lint(context.Background(), src, LintOptions{Analyzer: fa, Now: lintNow})
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(report.Problems, "\n")
	for _, want := range []string{
		"grant payments-ledger-rw: ValidatePolicy: ERROR INVALID_ARN: bad",
		"grant payments-ledger-rw: CheckNoNewAccess: statement 0: wider",
		"grant payments-outbox-r: CheckNoNewAccess: statement 0: wider",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("problems = %v, want one containing %q", report.Problems, want)
		}
	}
	if strings.Contains(all, "WARNING") {
		t.Errorf("a warning became a problem: %v", report.Problems)
	}

	fa = &fakeAnalyzer{check: AccessCheck{Passed: false}}
	report, _ = Lint(context.Background(), src, LintOptions{Analyzer: fa, Now: lintNow})
	if !strings.Contains(strings.Join(report.Problems, "\n"), "CheckNoNewAccess: the policy grants access outside the envelope") {
		t.Errorf("problems = %v", report.Problems)
	}

	fa = &fakeAnalyzer{err: errors.New("no credentials")}
	if _, err := Lint(context.Background(), src, LintOptions{Analyzer: fa}); err == nil || !strings.Contains(err.Error(), "no credentials") {
		t.Errorf("error = %v, want the analyzer's", err)
	}
}

func TestLintProblems(t *testing.T) {
	tests := []struct {
		dir  string
		want string
	}{
		{"outside-envelope", `grant payments-ledger-rw: statement 0: Resource "arn:aws:dynamodb:*:111122223333:table/payments-ledger" matches no envelope pattern`},
		{"too-large", "grant payments-ledger-rw: session policy is "},
		{"render-error", `grant payments-ledger-rw: render: template dynamo-table-rw: parameter "colour" is not declared`},
		{"two-shapes", "subject prod/payments/ledger: grants span 2 base roles"},
	}
	for _, tt := range tests {
		t.Run(tt.dir, func(t *testing.T) {
			src, err := Load("testdata/lint/" + tt.dir)
			if err != nil {
				t.Fatal(err)
			}
			report, err := Lint(context.Background(), src, LintOptions{Now: lintNow})
			if err != nil {
				t.Fatal(err)
			}
			if report.OK() || !strings.Contains(strings.Join(report.Problems, "\n"), tt.want) {
				t.Errorf("problems = %v, want one containing %q", report.Problems, tt.want)
			}
		})
	}
}

func TestLintRejectsInvalidSource(t *testing.T) {
	src, err := Load("testdata/bad/missing-template")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Lint(context.Background(), src, LintOptions{}); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %v", err)
	}
}
