// Package issuer is the issuance path of the broker (docs/design.md,
// section 6.5 and the sequence in 7.5): from a verified workload identity to
// the authorization store, the composed grants and the STS call. [Issuer] is
// the interface the API serves; [Direct] is the implementation that goes to
// the store and STS on every call; broker/internal/cache wraps it with the
// cache of section 6.7.
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
	// Cache says how the credential cache served the issuance, for the
	// Cracha-Cache header; empty when no cache was involved.
	Cache CacheOutcome
}

// CacheOutcome is what the cache did for one issuance (section 6.7).
type CacheOutcome string

const (
	// CacheHit served cached credentials after re-checking the store.
	CacheHit CacheOutcome = "hit"
	// CacheMiss called STS for the credentials it served.
	CacheMiss CacheOutcome = "miss"
	// CacheRefresh served cached credentials and started a refresh-ahead.
	CacheRefresh CacheOutcome = "refresh"
)

// ErrStore marks a failure of the authorization store to answer, as
// opposed to an answer that denies. A cache may serve a hit within bounded
// staleness on it (section 6.7); nothing else treats it differently from a
// deny.
var ErrStore = errors.New("authorization store")

type consistencyKey struct{}

// WithConsistency returns a context asking the store for answers at least
// as fresh as the token, for a caller such as an approver or revocation
// tool that holds one (section 6.7). The API does not set it yet.
func WithConsistency(ctx context.Context, c authz.Consistency) context.Context {
	return context.WithValue(ctx, consistencyKey{}, c)
}

// ConsistencyFrom returns the consistency a context asks for; the zero
// value, minimize-latency, when it asks for none.
func ConsistencyFrom(ctx context.Context) authz.Consistency {
	c, _ := ctx.Value(consistencyKey{}).(authz.Consistency)
	return c
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

	decision, err := d.Store.ListGrants(ctx, r.Subject, ConsistencyFrom(ctx))
	if err != nil {
		if errors.Is(err, authz.ErrSubjectSuspended) {
			return r, &grants.DenyError{Reason: grants.ReasonSubjectSuspended, Detail: err.Error()}
		}
		return r, fmt.Errorf("%w: %w", ErrStore, err)
	}
	r.Decision = decision

	composed, err := grants.Compose(d.Grants, decision.Grants, d.finder(ctx, &r))
	if err != nil {
		return r, err
	}
	r.Composed = composed
	for _, g := range composed.Dropped {
		r.Decision.Trace = append(r.Decision.Trace, "grant "+g+": no resource related; left out")
	}
	for _, res := range composed.Unplaced {
		r.Decision.Trace = append(r.Decision.Trace, "resource "+res+": in no account of the bundle; no implicit grant renders it")
	}

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

// finder is the store's LookupResources for Compose (Level 3), at the
// resolution's consistency, its traces added to the decision's. A store
// that cannot look resources up, or fails to, is a store failure: a deny,
// or a bounded-staleness hit of the cache. A suspension found here is a
// deny like the one ListGrants reports.
func (d *Direct) finder(ctx context.Context, r *Resolution) grants.Finder {
	return func(kind, permission string) ([]string, error) {
		lookup, ok := d.Store.(authz.ResourceLookup)
		if !ok {
			return nil, fmt.Errorf("%w: the store cannot look up resources (%s#%s)", ErrStore, kind, permission)
		}
		res, err := lookup.LookupResources(ctx, r.Subject, kind, permission, ConsistencyFrom(ctx))
		if err != nil {
			if errors.Is(err, authz.ErrSubjectSuspended) {
				return nil, &grants.DenyError{Reason: grants.ReasonSubjectSuspended, Detail: err.Error()}
			}
			return nil, fmt.Errorf("%w: %w", ErrStore, err)
		}
		r.Decision.Trace = append(r.Decision.Trace, res.Trace...)
		return res.Names, nil
	}
}

// Issue implements Issuer.
func (d *Direct) Issue(ctx context.Context, id idenc.Identity) (Issuance, error) {
	r, err := d.resolve(ctx, id)
	if err != nil {
		d.logDenial(id, r, err)
		return Issuance{}, err
	}
	return d.Assume(ctx, r)
}

// Assume assumes the shape role for a resolution already made, without
// going back to the store: what the cache calls on a miss, after its own
// Resolve.
func (d *Direct) Assume(ctx context.Context, r Resolution) (Issuance, error) {
	id := r.Identity
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
		slog.Any("resources", r.Composed.Resources),
		slog.Any("dropped", r.Composed.Dropped),
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
