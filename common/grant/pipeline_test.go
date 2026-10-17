package grant

import (
	"context"
	"strings"
	"testing"
)

// lintGrant's own branches that Lint cannot reach, because ValidateSource
// rejects the source first: a template that is not loaded, and a rendered
// policy with no envelope to check it against.
func TestLintGrantUnreachableThroughLint(t *testing.T) {
	templates := map[string]*Template{"dynamo-table-rw": mustTemplate(t, `{"params": {"tables": {"type": "list"}}, "policy": {"Statement": [{"Effect": "Allow", "Action": "dynamodb:Query", "Resource": "arn:aws:dynamodb:*:${account}:table/${tables}"}]}}`)}

	t.Run("template not found", func(t *testing.T) {
		res, err := lintGrant(context.Background(), baseGrant(), map[string]*Template{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if res.Rendered != "" || res.Envelope != nil || !strings.Contains(strings.Join(res.Problems, "\n"), `template "dynamo-table-rw" not found`) {
			t.Errorf("result = %+v", res)
		}
	})

	t.Run("no envelope for the access check", func(t *testing.T) {
		g := baseGrant()
		g.Spec.Envelope = nil
		fa := &fakeAnalyzer{check: AccessCheck{Passed: true}}
		_, err := lintGrant(context.Background(), g, templates, fa)
		if err == nil || !strings.Contains(err.Error(), "grant payments-ledger-rw: empty envelope") {
			t.Errorf("error = %v, want the envelope policy's", err)
		}
		if len(fa.policies) != 1 {
			t.Errorf("analyzer saw %d policies, want the rendered one before the envelope is built", len(fa.policies))
		}
	})

	t.Run("renders and checks", func(t *testing.T) {
		fa := &fakeAnalyzer{check: AccessCheck{Passed: true}}
		res, err := lintGrant(context.Background(), baseGrant(), templates, fa)
		if err != nil {
			t.Fatal(err)
		}
		if !res.Problems.OK() || res.Rendered == "" || res.AccessCheck == nil || res.Envelope == nil || res.Size == nil {
			t.Errorf("result = %+v", res)
		}
	})
}
