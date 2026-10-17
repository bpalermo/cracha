// Package sts assumes shape roles (docs/design.md, section 6.6). The
// [Assumer] interface is what the issuance path depends on; [Client] is the
// implementation over the AWS SDK, and tests use a fake.
package sts

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awssts "github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
)

// Request is one AssumeRole call. SessionName is the idenc STS encoding and
// is used for both RoleSessionName and SourceIdentity; the caller never sets
// the two apart.
type Request struct {
	RoleARN         string
	SessionName     string
	Policy          string
	PolicyARNs      []string
	DurationSeconds int32
	// Tags are the session tags; all are non-transitive.
	Tags map[string]string
}

// Credentials is an assumed session.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

// Assumer assumes a role. Any error means no credentials.
type Assumer interface {
	AssumeRole(ctx context.Context, req Request) (Credentials, error)
}

// API is the part of the STS client the Client uses.
type API interface {
	AssumeRole(ctx context.Context, params *awssts.AssumeRoleInput, optFns ...func(*awssts.Options)) (*awssts.AssumeRoleOutput, error)
}

// Client is an Assumer over the AWS SDK.
type Client struct {
	api API
}

// New returns a Client over an STS API, normally sts.NewFromConfig(cfg).
func New(api API) *Client {
	return &Client{api: api}
}

// NewFromConfig returns a Client over the STS client of an AWS config.
func NewFromConfig(cfg aws.Config) *Client {
	return New(awssts.NewFromConfig(cfg))
}

// AssumeRole implements Assumer.
func (c *Client) AssumeRole(ctx context.Context, req Request) (Credentials, error) {
	if req.RoleARN == "" || req.SessionName == "" {
		return Credentials{}, errors.New("sts: role ARN and session name are required")
	}
	in := &awssts.AssumeRoleInput{
		RoleArn:         aws.String(req.RoleARN),
		RoleSessionName: aws.String(req.SessionName),
		SourceIdentity:  aws.String(req.SessionName),
	}
	if req.DurationSeconds > 0 {
		in.DurationSeconds = aws.Int32(req.DurationSeconds)
	}
	if req.Policy != "" {
		in.Policy = aws.String(req.Policy)
	}
	for _, arn := range req.PolicyARNs {
		in.PolicyArns = append(in.PolicyArns, types.PolicyDescriptorType{Arn: aws.String(arn)})
	}
	keys := make([]string, 0, len(req.Tags))
	for k := range req.Tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		in.Tags = append(in.Tags, types.Tag{Key: aws.String(k), Value: aws.String(req.Tags[k])})
	}
	// TransitiveTagKeys stays empty: every tag is non-transitive.

	out, err := c.api.AssumeRole(ctx, in)
	if err != nil {
		return Credentials{}, fmt.Errorf("sts: assume %s: %w", req.RoleARN, err)
	}
	cr := out.Credentials
	if cr == nil || cr.AccessKeyId == nil || cr.SecretAccessKey == nil || cr.SessionToken == nil || cr.Expiration == nil {
		return Credentials{}, errors.New("sts: incomplete credentials in AssumeRole response")
	}
	return Credentials{
		AccessKeyID:     *cr.AccessKeyId,
		SecretAccessKey: *cr.SecretAccessKey,
		SessionToken:    *cr.SessionToken,
		Expiration:      cr.Expiration.UTC(),
	}, nil
}
