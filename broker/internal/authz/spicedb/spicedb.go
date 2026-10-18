// Package spicedb is the "spicedb" authorization backend of docs/design.md,
// section 6.3: the adapter over the reference SpiceDB model of section 6.4.
// It asks SpiceDB the store's questions over gRPC and maps the answers to
// the contract; no SpiceDB type leaves it.
//
// Objects are workload:<authz encoding of design 4.3>, grant:<name>,
// service:<name> and team:<name>; every type, relation, permission and
// context key is spelled as common/spicedb, the schema package the
// reconciler shares, exports it. Every permission query carries the caveat
// context the schema's conditions evaluate against: now, the broker's clock
// as an RFC 3339 timestamp, and cluster, the cluster the broker serves. A
// result SpiceDB reports as conditional therefore means context is missing,
// which is a bug, and is an error: like every error here, a deny.
//
// Consistency: the zero value is minimize_latency; AtLeastAsFresh is
// at_least_as_fresh with the token as the zedtoken SpiceDB minted earlier.
// Tokens are zedtokens verbatim.
//
// LookupResources (Level 3) is SpiceDB's LookupResources on the resource's
// object type (s3_bucket) and permission (read, write), with the same
// caveat context, after the same suspension check; the object IDs it
// returns are decoded back to resource names with common/idenc.
//
// Watch maps SpiceDB's Watch stream to assignment changes: an assignment to
// a workload names its subject and grant, and a workload's relation to a
// resource its subject; everything else (an assignment to a service, a
// membership, an ownership, a suspension, a service's relation to a
// resource) invalidates every cached session. The stream is never reconnected here: the cache does that
// from the last token.
package spicedb

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"sort"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/bpalermo/cracha/broker/internal/authz"
	"github.com/bpalermo/cracha/common/idenc"
	schema "github.com/bpalermo/cracha/common/spicedb"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
)

// DefaultTimeout bounds one gRPC call when no Option sets another.
const DefaultTimeout = 5 * time.Second

// Option configures a Store.
type Option func(*Store)

// WithClock sets the clock the caveat context's now comes from. The default
// is time.Now.
func WithClock(now func() time.Time) Option {
	return func(s *Store) { s.now = now }
}

// WithTimeout bounds every call but Watch. The default is DefaultTimeout.
func WithTimeout(d time.Duration) Option {
	return func(s *Store) {
		if d > 0 {
			s.timeout = d
		}
	}
}

// WithLogger sets the logger. The default is slog.Default.
func WithLogger(log *slog.Logger) Option {
	return func(s *Store) {
		if log != nil {
			s.log = log
		}
	}
}

// Store is the SpiceDB backend. It implements authz.Store,
// authz.ResourceLookup and authz.Watcher.
type Store struct {
	perms   v1.PermissionsServiceClient
	watcher v1.WatchServiceClient
	closer  io.Closer
	now     func() time.Time
	timeout time.Duration
	log     *slog.Logger
}

// New builds a store over the generated client interfaces, which is how
// tests inject fakes; Dial builds one over a connection.
func New(perms v1.PermissionsServiceClient, watcher v1.WatchServiceClient, opts ...Option) *Store {
	s := &Store{perms: perms, watcher: watcher, now: time.Now, timeout: DefaultTimeout, log: slog.Default()}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Close closes the connection a Dial opened; a store built with New has
// none.
func (s *Store) Close() error {
	if s.closer == nil {
		return nil
	}
	return s.closer.Close()
}

// ListGrants implements authz.Store: the suspension first, then the grants
// the subject may assume, then the service and team tags.
func (s *Store) ListGrants(ctx context.Context, subject authz.Subject, c authz.Consistency) (authz.Decision, error) {
	consistency, err := consistencyOf(c)
	if err != nil {
		return authz.Decision{}, err
	}
	d := authz.Decision{Tags: map[string]string{}}
	if err := s.checkSuspended(ctx, subject, consistency, &d); err != nil {
		return authz.Decision{}, err
	}
	if err := s.lookupGrants(ctx, subject, consistency, &d); err != nil {
		return authz.Decision{}, err
	}
	if err := s.tagsOf(ctx, subject, consistency, &d); err != nil {
		return authz.Decision{}, err
	}
	return d, nil
}

// Check implements authz.Store. A suspended subject holds nothing.
func (s *Store) Check(ctx context.Context, subject authz.Subject, grant string, c authz.Consistency) (authz.CheckResult, error) {
	consistency, err := consistencyOf(c)
	if err != nil {
		return authz.CheckResult{}, err
	}
	var d authz.Decision
	if err := s.checkSuspended(ctx, subject, consistency, &d); err != nil {
		return authz.CheckResult{}, err
	}
	r := authz.CheckResult{Trace: d.Trace}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	resp, err := s.perms.CheckPermission(ctx, &v1.CheckPermissionRequest{
		Consistency: consistency,
		Resource:    &v1.ObjectReference{ObjectType: schema.TypeGrant, ObjectId: grant},
		Permission:  schema.PermissionAssume,
		Subject:     workloadSubject(subject),
		Context:     s.caveatContext(subject),
	})
	if err != nil {
		return authz.CheckResult{}, fmt.Errorf("spicedb: check grant %s for %s: %w", grant, subject.ID, err)
	}
	r.Token = tokenOf(resp.GetCheckedAt())
	switch resp.GetPermissionship() {
	case v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION:
		r.Allowed = true
		r.Trace = append(r.Trace, "grant "+grant+": assume")
	case v1.CheckPermissionResponse_PERMISSIONSHIP_NO_PERMISSION:
		r.Trace = append(r.Trace, "grant "+grant+": no permission")
	default:
		return authz.CheckResult{}, fmt.Errorf("spicedb: check grant %s for %s: permissionship %s (caveat context missing?)", grant, subject.ID, resp.GetPermissionship())
	}
	return r, nil
}

// checkSuspended reads the subject's suspended relation: any team there
// suspends it.
func (s *Store) checkSuspended(ctx context.Context, subject authz.Subject, consistency *v1.Consistency, d *authz.Decision) error {
	rels, token, err := s.readRelationships(ctx, consistency, &v1.RelationshipFilter{
		ResourceType:       schema.TypeWorkload,
		OptionalResourceId: subject.ID,
		OptionalRelation:   schema.RelationSuspended,
	})
	if err != nil {
		return fmt.Errorf("spicedb: suspension of %s: %w", subject.ID, err)
	}
	if token != "" {
		d.Token = token
	}
	if len(rels) > 0 {
		return fmt.Errorf("%w: %s by team %s", authz.ErrSubjectSuspended, subject.ID, rels[0].GetSubject().GetObject().GetObjectId())
	}
	d.Trace = append(d.Trace, "subject "+subject.ID+" is not suspended")
	return nil
}

// lookupGrants streams the grants the subject may assume into d: those
// SpiceDB reports held outright; a conditional one is an error.
func (s *Store) lookupGrants(ctx context.Context, subject authz.Subject, consistency *v1.Consistency, d *authz.Decision) error {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	stream, err := s.perms.LookupResources(ctx, &v1.LookupResourcesRequest{
		Consistency:        consistency,
		ResourceObjectType: schema.TypeGrant,
		Permission:         schema.PermissionAssume,
		Subject:            workloadSubject(subject),
		Context:            s.caveatContext(subject),
	})
	if err != nil {
		return fmt.Errorf("spicedb: lookup grants of %s: %w", subject.ID, err)
	}
	held := map[string]bool{}
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("spicedb: lookup grants of %s: %w", subject.ID, err)
		}
		if resp.GetPermissionship() != v1.LookupPermissionship_LOOKUP_PERMISSIONSHIP_HAS_PERMISSION {
			return fmt.Errorf("spicedb: lookup grants of %s: grant %s is %s (caveat context missing?)", subject.ID, resp.GetResourceObjectId(), resp.GetPermissionship())
		}
		held[resp.GetResourceObjectId()] = true
		if t := tokenOf(resp.GetLookedUpAt()); t != "" {
			d.Token = t
		}
	}
	d.Grants = sortedKeys(held)
	for _, g := range d.Grants {
		d.Trace = append(d.Trace, "grant "+g+": assume")
	}
	if len(d.Grants) == 0 {
		d.Grants = nil
		d.Trace = append(d.Trace, "subject "+subject.ID+" may assume no grant")
	}
	return nil
}

// LookupResources implements authz.ResourceLookup.
func (s *Store) LookupResources(ctx context.Context, subject authz.Subject, kind, permission string, c authz.Consistency) (authz.Resources, error) {
	if !slices.Contains(schema.ResourceTypes, kind) || (permission != schema.PermissionRead && permission != schema.PermissionWrite) {
		return authz.Resources{}, fmt.Errorf("spicedb: lookup %s#%s: not a resource type and permission of the schema", kind, permission)
	}
	consistency, err := consistencyOf(c)
	if err != nil {
		return authz.Resources{}, err
	}
	var d authz.Decision
	if err := s.checkSuspended(ctx, subject, consistency, &d); err != nil {
		return authz.Resources{}, err
	}
	r := authz.Resources{Token: d.Token}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	stream, err := s.perms.LookupResources(ctx, &v1.LookupResourcesRequest{
		Consistency:        consistency,
		ResourceObjectType: kind,
		Permission:         permission,
		Subject:            workloadSubject(subject),
		Context:            s.caveatContext(subject),
	})
	if err != nil {
		return authz.Resources{}, fmt.Errorf("spicedb: lookup %s#%s of %s: %w", kind, permission, subject.ID, err)
	}
	held, err := readResources(stream, &r)
	if err != nil {
		return authz.Resources{}, fmt.Errorf("spicedb: lookup %s#%s of %s: %w", kind, permission, subject.ID, err)
	}
	r.Names = sortedKeys(held)
	for _, name := range r.Names {
		r.Trace = append(r.Trace, kind+" "+name+": "+permission)
	}
	if len(r.Names) == 0 {
		r.Names = nil
		r.Trace = append(r.Trace, "subject "+subject.ID+" holds "+permission+" on no "+kind)
	}
	return r, nil
}

// readResources reads a lookup's stream to its end: the resource names,
// with the latest token in r.
func readResources(stream grpc.ServerStreamingClient[v1.LookupResourcesResponse], r *authz.Resources) (map[string]bool, error) {
	held := map[string]bool{}
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return held, nil
		}
		if err != nil {
			return nil, err
		}
		name, err := resourceName(resp)
		if err != nil {
			return nil, err
		}
		held[name] = true
		if t := tokenOf(resp.GetLookedUpAt()); t != "" {
			r.Token = t
		}
	}
}

// resourceName is the resource name a lookup result stands for; a
// conditional result (caveat context missing) or an ID common/idenc did
// not make is an error.
func resourceName(resp *v1.LookupResourcesResponse) (string, error) {
	if resp.GetPermissionship() != v1.LookupPermissionship_LOOKUP_PERMISSIONSHIP_HAS_PERMISSION {
		return "", fmt.Errorf("resource %s is %s (caveat context missing?)", resp.GetResourceObjectId(), resp.GetPermissionship())
	}
	return idenc.ParseResource(resp.GetResourceObjectId())
}

// tagsOf sets the service and team tags: the one service the subject is a
// member of, and that service's team (service#team). A subject in several services gets
// neither tag.
func (s *Store) tagsOf(ctx context.Context, subject authz.Subject, consistency *v1.Consistency, d *authz.Decision) error {
	rels, _, err := s.readRelationships(ctx, consistency, &v1.RelationshipFilter{
		ResourceType:     schema.TypeService,
		OptionalRelation: schema.RelationMember,
		OptionalSubjectFilter: &v1.SubjectFilter{
			SubjectType:       schema.TypeWorkload,
			OptionalSubjectId: subject.ID,
		},
	})
	if err != nil {
		return fmt.Errorf("spicedb: services of %s: %w", subject.ID, err)
	}
	services := resourceIDs(rels)
	switch len(services) {
	case 0:
		d.Trace = append(d.Trace, "subject "+subject.ID+" is a member of no service")
		return nil
	case 1:
	default:
		d.Trace = append(d.Trace, fmt.Sprintf("subject %s is a member of %d services; no service or team tag", subject.ID, len(services)))
		return nil
	}
	service := services[0]
	d.Tags["service"] = service
	d.Trace = append(d.Trace, "member of service "+service)
	owners, _, err := s.readRelationships(ctx, consistency, &v1.RelationshipFilter{
		ResourceType:       schema.TypeService,
		OptionalResourceId: service,
		OptionalRelation:   schema.RelationTeam,
	})
	if err != nil {
		return fmt.Errorf("spicedb: team of service %s: %w", service, err)
	}
	teams := subjectIDs(owners)
	if len(teams) != 1 {
		d.Trace = append(d.Trace, fmt.Sprintf("service %s has %d teams; no team tag", service, len(teams)))
		return nil
	}
	d.Tags["team"] = teams[0]
	d.Trace = append(d.Trace, "service "+service+" is owned by team "+teams[0])
	return nil
}

// readRelationships reads every relationship matching the filter, with the
// zedtoken they were read at.
func (s *Store) readRelationships(ctx context.Context, consistency *v1.Consistency, filter *v1.RelationshipFilter) ([]*v1.Relationship, authz.Token, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	stream, err := s.perms.ReadRelationships(ctx, &v1.ReadRelationshipsRequest{Consistency: consistency, RelationshipFilter: filter})
	if err != nil {
		return nil, "", err
	}
	var (
		rels  []*v1.Relationship
		token authz.Token
	)
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return rels, token, nil
		}
		if err != nil {
			return nil, "", err
		}
		rels = append(rels, resp.GetRelationship())
		if t := tokenOf(resp.GetReadAt()); t != "" {
			token = t
		}
	}
}

// Watch implements authz.Watcher.
func (s *Store) Watch(ctx context.Context, since authz.Token) (<-chan authz.Change, error) {
	if s.watcher == nil {
		return nil, errors.New("spicedb: watch: no watch client")
	}
	req := &v1.WatchRequest{OptionalObjectTypes: append([]string{schema.TypeGrant, schema.TypeService, schema.TypeWorkload}, schema.ResourceTypes...)}
	if since != "" {
		req.OptionalStartCursor = &v1.ZedToken{Token: string(since)}
	}
	stream, err := s.watcher.Watch(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("spicedb: watch: %w", err)
	}
	ch := make(chan authz.Change)
	go s.forward(ctx, stream, ch)
	return ch, nil
}

// forward delivers the stream's changes to ch until the stream ends, then
// closes ch.
func (s *Store) forward(ctx context.Context, stream v1.WatchService_WatchClient, ch chan<- authz.Change) {
	defer close(ch)
	for {
		resp, err := stream.Recv()
		if err != nil {
			if ctx.Err() == nil {
				s.log.LogAttrs(ctx, slog.LevelWarn, "spicedb watch stream ended", slog.String("error", err.Error()))
			}
			return
		}
		token := tokenOf(resp.GetChangesThrough())
		for _, u := range resp.GetUpdates() {
			change, ok := changeOf(u.GetRelationship(), token)
			if !ok {
				continue
			}
			select {
			case ch <- change:
			case <-ctx.Done():
				return
			}
		}
	}
}

// changeOf maps one relationship update to the assignment change it is,
// or reports that it touches nothing the cache holds.
func changeOf(rel *v1.Relationship, token authz.Token) (authz.Change, bool) {
	resource, relation := rel.GetResource(), rel.GetRelation()
	switch {
	case resource.GetObjectType() == schema.TypeGrant && relation == schema.RelationAssigneeWorkload:
		return authz.Change{
			Subject: authz.Subject{ID: rel.GetSubject().GetObject().GetObjectId()},
			Grant:   resource.GetObjectId(),
			Token:   token,
		}, true
	case !accessRelation(resource.GetObjectType(), relation):
		// The write path's relations (owner, approver, sensitive) and its
		// pending requests: nothing the broker reads.
		return authz.Change{}, false
	case slices.Contains(schema.ResourceTypes, resource.GetObjectType()) && rel.GetSubject().GetObject().GetObjectType() == schema.TypeWorkload:
		// A workload's relation to a resource: its sessions, whatever
		// their grants, since any lookup grant of the kind may change.
		return authz.Change{Subject: authz.Subject{ID: rel.GetSubject().GetObject().GetObjectId()}, Token: token}, true
	case slices.Contains(schema.ResourceTypes, resource.GetObjectType()),
		resource.GetObjectType() == schema.TypeGrant && relation == schema.RelationAssigneeService,
		resource.GetObjectType() == schema.TypeService && (relation == schema.RelationMember || relation == schema.RelationTeam),
		resource.GetObjectType() == schema.TypeWorkload && relation == schema.RelationSuspended:
		return authz.Change{Token: token}, true
	}
	return authz.Change{}, false
}

// accessRelation is false for a relation of a resource type the broker
// does not read: anything of a resource type (Level 3) but reader and
// writer. Every other relationship is left to changeOf.
func accessRelation(objectType, relation string) bool {
	if !slices.Contains(schema.ResourceTypes, objectType) {
		return true
	}
	return relation == schema.RelationReader || relation == schema.RelationWriter
}

// consistencyOf maps the contract's consistency to SpiceDB's. A token that
// is not a zedtoken (standard base64) is refused here rather than sent.
func consistencyOf(c authz.Consistency) (*v1.Consistency, error) {
	if c.AtLeastAsFresh == "" {
		return &v1.Consistency{Requirement: &v1.Consistency_MinimizeLatency{MinimizeLatency: true}}, nil
	}
	if _, err := base64.StdEncoding.DecodeString(string(c.AtLeastAsFresh)); err != nil {
		return nil, fmt.Errorf("spicedb: consistency token %q is not a zedtoken: %w", c.AtLeastAsFresh, err)
	}
	return &v1.Consistency{Requirement: &v1.Consistency_AtLeastAsFresh{AtLeastAsFresh: &v1.ZedToken{Token: string(c.AtLeastAsFresh)}}}, nil
}

// caveatContext is the context every permission query carries: the clock
// and the cluster, for the schema's within_window, in_clusters and bounded
// caveats.
func (s *Store) caveatContext(subject authz.Subject) *structpb.Struct {
	return &structpb.Struct{Fields: map[string]*structpb.Value{
		schema.ContextNow:     structpb.NewStringValue(s.now().UTC().Format(time.RFC3339)),
		schema.ContextCluster: structpb.NewStringValue(subject.Cluster),
	}}
}

func workloadSubject(subject authz.Subject) *v1.SubjectReference {
	return &v1.SubjectReference{Object: &v1.ObjectReference{ObjectType: schema.TypeWorkload, ObjectId: subject.ID}}
}

func tokenOf(t *v1.ZedToken) authz.Token {
	return authz.Token(t.GetToken())
}

// resourceIDs is the sorted, distinct resource ids of the relationships.
func resourceIDs(rels []*v1.Relationship) []string {
	ids := map[string]bool{}
	for _, r := range rels {
		ids[r.GetResource().GetObjectId()] = true
	}
	return sortedKeys(ids)
}

// subjectIDs is the sorted, distinct subject ids of the relationships.
func subjectIDs(rels []*v1.Relationship) []string {
	ids := map[string]bool{}
	for _, r := range rels {
		ids[r.GetSubject().GetObject().GetObjectId()] = true
	}
	return sortedKeys(ids)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
