// Package checktest compiles a small grant bundle for cracha-access's
// tests, with common/grant's own compiler: a lookup grant of S3 buckets
// for reading (data-read, envelope data-*), one for writing (data-write,
// envelope data-*), a lookup grant of DynamoDB tables whose envelope
// admits only one prefix (table-read, envelope table/orders-*), and a
// static grant of another shape (other-shape).
package checktest

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/bpalermo/cracha/common/grant"
)

const account = "111122223333"

// Roles are the two shapes.
const (
	ShapeData  = "arn:aws:iam::111122223333:role/broker/shape-data"
	ShapeOther = "arn:aws:iam::111122223333:role/broker/shape-other"
)

func template(name, params, policy string) *grant.Template {
	t := &grant.Template{Name: name, Policy: json.RawMessage(policy)}
	if err := json.Unmarshal([]byte(params), &t.Params); err != nil {
		panic(err)
	}
	return t
}

func lookupGrant(name, tmpl, param, kind, permission, role string, envelope ...string) *grant.Grant {
	return &grant.Grant{Kind: grant.KindGrant, Metadata: grant.Metadata{Name: name}, Spec: grant.GrantSpec{
		Account: account, BaseRole: role, Envelope: envelope,
		SessionPolicy: &grant.SessionPolicy{Template: tmpl, Params: map[string]grant.Param{param: grant.LookupParam(kind, permission)}},
	}}
}

// Bundle compiles the bundle at version.
func Bundle(t testing.TB, version string) *grant.Bundle {
	t.Helper()
	src := &grant.Source{
		Templates: map[string]*grant.Template{
			"s3-object-read": template("s3-object-read", `{"bucket":{"type":"string"}}`,
				`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::${bucket}/*"}]}`),
			"s3-object-write": template("s3-object-write", `{"bucket":{"type":"string"}}`,
				`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject"],"Resource":"arn:aws:s3:::${bucket}/*"}]}`),
			"table-read": template("table-read", `{"table":{"type":"string"}}`,
				`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["dynamodb:GetItem"],"Resource":"arn:aws:dynamodb:*:${account}:table/${table}"}]}`),
			"other": template("other", `{}`,
				`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::other/*"}]}`),
		},
		Grants: []*grant.Grant{
			lookupGrant("data-read", "s3-object-read", "bucket", grant.ResourceS3Bucket, grant.PermissionRead, ShapeData, "arn:aws:s3:::data-*"),
			lookupGrant("data-write", "s3-object-write", "bucket", grant.ResourceS3Bucket, grant.PermissionWrite, ShapeData, "arn:aws:s3:::data-*"),
			{Kind: grant.KindGrant, Metadata: grant.Metadata{Name: "other-shape"}, Spec: grant.GrantSpec{
				Account: account, BaseRole: ShapeOther, Envelope: []string{"arn:aws:s3:::other*"},
				SessionPolicy: &grant.SessionPolicy{Template: "other"},
			}},
			lookupGrant("table-read", "table-read", "table", grant.ResourceDynamoDBTable, grant.PermissionRead, ShapeData, "arn:aws:dynamodb:*:111122223333:table/orders-*"),
		},
	}
	c, report, err := grant.Compile(context.Background(), src, grant.CompileOptions{Version: version, GeneratedAt: time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		if report != nil {
			t.Fatalf("compile: %v: %v", err, report.Problems)
		}
		t.Fatalf("compile: %v", err)
	}
	return c.Bundle
}

// AccountBundle compiles a bundle of one Account, apps, whose access table
// gives an implicit grant for reading S3 buckets (envelope data-*) to
// every workload related to one, and no Grant document.
func AccountBundle(t testing.TB, version string) *grant.Bundle {
	t.Helper()
	src := &grant.Source{
		Templates: map[string]*grant.Template{
			"s3-object-read": template("s3-object-read", `{"bucket":{"type":"string"}}`,
				`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::${bucket}/*"}]}`),
		},
		Accounts: []*grant.Account{{Kind: grant.KindAccount, Metadata: grant.Metadata{Name: "apps"}, Spec: grant.AccountSpec{
			ID: account, Role: "arn:aws:iam::111122223333:role/cracha/apps", Envelope: []string{"arn:aws:s3:::data-*"},
			Access: []grant.AccountAccess{{Kind: grant.ResourceS3Bucket, Permission: grant.PermissionRead, Template: "s3-object-read"}},
		}}},
	}
	c, report, err := grant.Compile(context.Background(), src, grant.CompileOptions{Version: version, GeneratedAt: time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		if report != nil {
			t.Fatalf("compile: %v: %v", err, report.Problems)
		}
		t.Fatalf("compile: %v", err)
	}
	return c.Bundle
}

// MaxResources is a lookup grant's compiled maximum.
func MaxResources(t testing.TB, b *grant.Bundle, name string) int {
	t.Helper()
	for _, g := range b.Grants {
		if g.Name == name && g.Lookup != nil {
			return g.Lookup.MaxResources
		}
	}
	t.Fatalf("no lookup grant %s", name)
	return 0
}
