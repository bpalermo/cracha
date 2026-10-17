// Package issuer is the issuance path of the broker (docs/design.md,
// section 6.5 and the sequence in 7.5): from a verified workload identity to
// the authorization store, the composed grants and the STS call. [Issuer] is
// the interface the API serves; [Direct] is the implementation that goes to
// the store and STS on every call. The cache of section 6.7 will wrap an
// Issuer in a later slice.
package issuer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/bpalermo/cracha/broker/internal/authz"
	"github.com/bpalermo/cracha/broker/internal/grants"
	"github.com/bpalermo/cracha/broker/internal/sts"
	"github.com/bpalermo/cracha/common/idenc"
)

// Resolution is everything decided about a workload before STS is called:
// what /v1/grants shows.
type Resolution struct {
	Identity       idenc.Identity
	Subject        authz.Subject
	SourceIdentity string
	Decision       authz.Decision
	Composed       grants.Composed
	BundleVersion  string
	// SessionTags are the tags the session gets: the fixed keys of
	// section 6.6 with the store's and the grants' ABAC values.
	SessionTags map[string]string
}

// Issuance is a Resolution with the credentials STS returned.
type Issuance struct {
	Resolution
	Credentials sts.Credentials
}

// Issuer decides and issues. A *grants.DenyError is a denial with a reason
// for the caller; any other error is a denial the caller is only told is
// not its own fault.
type Issuer interface {
	// Resolve runs authorization and composition without calling STS.
	Resolve(ctx context.Context, id idenc.Identity) (Resolution, error)
	// Issue resolves and assumes the shape role.
	Issue(ctx context.Context, id idenc.Identity) (Issuance, error)
}

// Direct is an Issuer that consults the store and STS on every call.
type Direct struct {
	Store   authz.Store
	Grants  grants.Source
	STS     sts.Assumer
	Labels  idenc.Labels
	Cluster string
	Log     *slog.Logger
}

// Session tag keys (section 6.6). The shape roles' trust policies accept no
// others.
const (
	TagNamespace      = "spiffe-ns"
	TagServiceAccount = "spiffe-sa"
	TagCluster        = "cluster"
	TagGrant          = "grant"
	TagTeam           = "team"
	TagService        = "service"
)

// maxTagValue is STS's limit on a session tag value.
const maxTagValue = 256

// Resolve implements Issuer.
func (d *Direct) Resolve(ctx context.Context, id idenc.Identity) (Resolution, error) {
	r, err := d.resolve(ctx, id)
	if err != nil {
		d.logDenial(id, r, err)
	}
	return r, err
}

func (d *Direct) resolve(ctx context.Context, id idenc.Identity) (Resolution, error) {
	r := Resolution{Identity: id, SourceIdentity: idenc.STS(id, d.Labels), BundleVersion: d.Grants.Version()}
	subjectID, err := idenc.Authz(id, d.Labels)
	if err != nil {
		return r, err
	}
	r.Subject = authz.Subject{ID: subjectID, Cluster: d.Cluster}

	decision, err := d.Store.ListGrants(ctx, r.Subject, authz.Consistency{})
	if err != nil {
		if errors.Is(err, authz.ErrSubjectSuspended) {
			return r, &grants.DenyError{Reason: grants.ReasonSubjectSuspended, Detail: err.Error()}
		}
		return r, fmt.Errorf("authorization store: %w", err)
	}
	r.Decision = decision

	composed, err := grants.Compose(d.Grants, decision.Grants)
	if err != nil {
		return r, err
	}
	r.Composed = composed

	tags := map[string]string{
		TagNamespace:      id.Namespace,
		TagServiceAccount: id.ServiceAccount,
		TagCluster:        d.Cluster,
		TagGrant:          strings.Join(composed.Grants, "+"),
	}
	for _, k := range []string{TagTeam, TagService} {
		// The grant's value is what Git reviewed; the store's is what the
		// catalog says about this workload, which is more specific.
		if v := composed.SessionTags[k]; v != "" {
			tags[k] = v
		}
		if v := decision.Tags[k]; v != "" {
			tags[k] = v
		}
	}
	for k, v := range tags {
		if len(v) > maxTagValue {
			return r, fmt.Errorf("session tag %s is %d characters, over %d", k, len(v), maxTagValue)
		}
	}
	r.SessionTags = tags
	return r, nil
}

// Issue implements Issuer.
func (d *Direct) Issue(ctx context.Context, id idenc.Identity) (Issuance, error) {
	r, err := d.resolve(ctx, id)
	if err != nil {
		d.logDenial(id, r, err)
		return Issuance{}, err
	}
	creds, err := d.STS.AssumeRole(ctx, sts.Request{
		RoleARN:         r.Composed.BaseRole,
		SessionName:     r.SourceIdentity,
		Policy:          r.Composed.Policy,
		PolicyARNs:      r.Composed.ManagedPolicyARNs,
		DurationSeconds: r.Composed.DurationSeconds,
		Tags:            r.SessionTags,
	})
	if err != nil {
		d.logDenial(id, r, err)
		return Issuance{}, err
	}
	// The decision log: the encoded identities map back to the SPIFFE ID
	// here and nowhere else (section 4.3).
	d.logger().LogAttrs(ctx, slog.LevelInfo, "issued",
		slog.String("spiffe_id", id.String()),
		slog.String("source_identity", r.SourceIdentity),
		slog.String("subject", r.Subject.ID),
		slog.String("cluster", r.Subject.Cluster),
		slog.String("shape", r.Composed.Shape),
		slog.String("base_role", r.Composed.BaseRole),
		slog.Any("grants", r.Composed.Grants),
		slog.String("bundle_version", r.BundleVersion),
		slog.String("consistency_token", string(r.Decision.Token)),
		slog.Int("duration_seconds", int(r.Composed.DurationSeconds)),
		slog.Time("expiration", creds.Expiration),
		slog.Any("trace", r.Decision.Trace),
	)
	return Issuance{Resolution: r, Credentials: creds}, nil
}

func (d *Direct) logDenial(id idenc.Identity, r Resolution, err error) {
	attrs := []slog.Attr{
		slog.String("spiffe_id", id.String()),
		slog.String("source_identity", r.SourceIdentity),
		slog.String("subject", r.Subject.ID),
		slog.String("cluster", d.Cluster),
		slog.String("bundle_version", r.BundleVersion),
		slog.Any("trace", r.Decision.Trace),
	}
	var deny *grants.DenyError
	if errors.As(err, &deny) {
		attrs = append(attrs, slog.String("reason", string(deny.Reason)), slog.String("detail", deny.Detail))
	} else {
		attrs = append(attrs, slog.String("error", err.Error()))
	}
	d.logger().LogAttrs(context.Background(), slog.LevelWarn, "denied", attrs...)
}

func (d *Direct) logger() *slog.Logger {
	if d.Log != nil {
		return d.Log
	}
	return slog.Default()
}
