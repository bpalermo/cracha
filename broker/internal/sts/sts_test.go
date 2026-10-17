package sts

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awssts "github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
)

type fakeAPI struct {
	in  *awssts.AssumeRoleInput
	out *awssts.AssumeRoleOutput
	err error
}

func (f *fakeAPI) AssumeRole(_ context.Context, in *awssts.AssumeRoleInput, _ ...func(*awssts.Options)) (*awssts.AssumeRoleOutput, error) {
	f.in = in
	return f.out, f.err
}

func TestAssumeRoleMapsRequest(t *testing.T) {
	exp := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	api := &fakeAPI{out: &awssts.AssumeRoleOutput{Credentials: &types.Credentials{
		AccessKeyId: aws.String("AKIA"), SecretAccessKey: aws.String("secret"), SessionToken: aws.String("token"), Expiration: &exp,
	}}}
	c := New(api)
	got, err := c.AssumeRole(context.Background(), Request{
		RoleARN:         "arn:aws:iam::111122223333:role/broker/shape-dynamo-rw",
		SessionName:     "w.prod.payments.ledger",
		Policy:          `{"Version":"2012-10-17","Statement":[]}`,
		PolicyARNs:      []string{"arn:aws:iam::111122223333:policy/b", "arn:aws:iam::111122223333:policy/a"},
		DurationSeconds: 1800,
		Tags:            map[string]string{"spiffe-sa": "ledger", "spiffe-ns": "payments", "cluster": "prod-a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != (Credentials{AccessKeyID: "AKIA", SecretAccessKey: "secret", SessionToken: "token", Expiration: exp}) {
		t.Errorf("credentials %+v", got)
	}
	in := api.in
	if aws.ToString(in.RoleArn) != "arn:aws:iam::111122223333:role/broker/shape-dynamo-rw" {
		t.Errorf("RoleArn %v", in.RoleArn)
	}
	if aws.ToString(in.RoleSessionName) != "w.prod.payments.ledger" || aws.ToString(in.SourceIdentity) != "w.prod.payments.ledger" {
		t.Errorf("RoleSessionName %v SourceIdentity %v", in.RoleSessionName, in.SourceIdentity)
	}
	if aws.ToInt32(in.DurationSeconds) != 1800 {
		t.Errorf("DurationSeconds %v", in.DurationSeconds)
	}
	if aws.ToString(in.Policy) != `{"Version":"2012-10-17","Statement":[]}` {
		t.Errorf("Policy %v", in.Policy)
	}
	if len(in.PolicyArns) != 2 || aws.ToString(in.PolicyArns[0].Arn) != "arn:aws:iam::111122223333:policy/b" {
		t.Errorf("PolicyArns %v", in.PolicyArns)
	}
	if len(in.Tags) != 3 || aws.ToString(in.Tags[0].Key) != "cluster" || aws.ToString(in.Tags[1].Key) != "spiffe-ns" || aws.ToString(in.Tags[2].Value) != "ledger" {
		t.Errorf("Tags %v", in.Tags)
	}
	if len(in.TransitiveTagKeys) != 0 {
		t.Errorf("tags must not be transitive: %v", in.TransitiveTagKeys)
	}
}

func TestAssumeRoleOmitsEmpty(t *testing.T) {
	exp := time.Now()
	api := &fakeAPI{out: &awssts.AssumeRoleOutput{Credentials: &types.Credentials{
		AccessKeyId: aws.String("a"), SecretAccessKey: aws.String("s"), SessionToken: aws.String("t"), Expiration: &exp,
	}}}
	if _, err := New(api).AssumeRole(context.Background(), Request{RoleARN: "r", SessionName: "w.x.y.z"}); err != nil {
		t.Fatal(err)
	}
	if api.in.Policy != nil || api.in.DurationSeconds != nil || len(api.in.PolicyArns) != 0 || len(api.in.Tags) != 0 {
		t.Errorf("empty fields were sent: %+v", api.in)
	}
}

func TestAssumeRoleErrors(t *testing.T) {
	boom := errors.New("boom")
	if _, err := New(&fakeAPI{err: boom}).AssumeRole(context.Background(), Request{RoleARN: "r", SessionName: "s"}); !errors.Is(err, boom) {
		t.Errorf("got %v", err)
	}
	if _, err := New(&fakeAPI{out: &awssts.AssumeRoleOutput{}}).AssumeRole(context.Background(), Request{RoleARN: "r", SessionName: "s"}); err == nil {
		t.Error("accepted a response without credentials")
	}
	if _, err := New(&fakeAPI{}).AssumeRole(context.Background(), Request{RoleARN: "r"}); err == nil {
		t.Error("accepted an empty session name")
	}
}
