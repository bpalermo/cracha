package store

import (
	"errors"
	"fmt"
	"slices"

	"github.com/bpalermo/cracha/common/grant"
	"github.com/bpalermo/cracha/common/idenc"
	"github.com/bpalermo/cracha/common/spicedb"
)

// Tuple is one relationship cracha-access writes, in the terms of the
// grant tree (design 6.2): a workload, or every member of a service,
// related to a resource by reader or writer (what a kind: Access document
// says); a workload made a member of a service; or a workload, or every
// member of a service, made an owner or an approver of a resource or a
// service.
type Tuple struct {
	// Kind is the target's kind: a resource kind of common/grant
	// (s3_bucket, dynamodb_table) or KindService for a membership.
	Kind string `json:"kind"`
	// Name is the resource's name, or the service's.
	Name string `json:"name"`
	// Relation is reader or writer on a resource, member on a service, or
	// owner or approver on either.
	Relation string `json:"relation"`
	// Subject is a workload's authorization subject encoding (design
	// 4.3); Service a service whose members are related. Exactly one is
	// set, and a membership has a Subject.
	Subject string `json:"subject,omitempty"`
	Service string `json:"service,omitempty"`
	// ExpiresAt (RFC 3339, UTC) and Clusters (sorted) bound it; empty
	// means unbounded.
	ExpiresAt string   `json:"expiresAt,omitempty"`
	Clusters  []string `json:"clusters,omitempty"`
}

// IsMembership reports whether the tuple makes a workload a member of a
// service.
func (t Tuple) IsMembership() bool {
	return t.Kind == KindService && t.Relation == spicedb.RelationMember
}

// IsAccess reports whether the tuple relates a holder to a resource by
// reader or writer: what a lookup grant renders.
func (t Tuple) IsAccess() bool {
	return isResourceType(t.Kind) && (t.Relation == spicedb.RelationReader || t.Relation == spicedb.RelationWriter)
}

// IsOwnership reports whether the tuple makes an owner or an approver.
func (t Tuple) IsOwnership() bool { return isOwnership(t.Relation) }

func isOwnership(relation string) bool {
	return relation == RelationOwner || relation == RelationApprover
}

// Holder is who the tuple relates: "workload <subject>" or "service
// <name>", for messages.
func (t Tuple) Holder() string {
	if t.Service != "" {
		return "service " + t.Service
	}
	return "workload " + t.Subject
}

// TargetID is the store's object ID of the target: the service's name, or
// the resource's name in the resource encoding of design 4.3.
func (t Tuple) TargetID() (string, error) {
	if t.Kind == KindService {
		return t.Name, nil
	}
	return idenc.Resource(t.Name)
}

// Relationship is the tuple as the store holds it.
func (t Tuple) Relationship() (Relationship, error) {
	id, err := t.TargetID()
	if err != nil {
		return Relationship{}, err
	}
	r := Relationship{ResourceType: t.Kind, ResourceID: id, Relation: t.Relation, SubjectType: spicedb.TypeWorkload, SubjectID: t.Subject}
	if t.Service != "" {
		r.SubjectType, r.SubjectID, r.SubjectRelation = spicedb.TypeService, t.Service, spicedb.RelationMember
	}
	r.setBounds(t.ExpiresAt, t.Clusters)
	return r, nil
}

// Key is the tuple's identity without its bounds.
func (t Tuple) Key() string {
	r, err := t.Relationship()
	if err != nil {
		return t.Kind + ":" + t.Name + "#" + t.Relation + "@" + t.Holder()
	}
	return r.Key()
}

// TupleOf reads a relationship as a tuple: a resource's reader or writer,
// or a service's member. Anything else is not one, and false.
func TupleOf(r Relationship) (Tuple, bool) {
	t := Tuple{Kind: r.ResourceType, Relation: r.Relation, ExpiresAt: r.ExpiresAt, Clusters: slices.Clone(r.Allowed)}
	if !t.IsMembership() && !t.IsAccess() && !(t.IsOwnership() && (isResourceType(t.Kind) || t.Kind == KindService)) {
		return Tuple{}, false
	}
	name, ok := targetName(r)
	if !ok {
		return Tuple{}, false
	}
	t.Name = name
	switch {
	case r.SubjectType == spicedb.TypeWorkload && r.SubjectRelation == "":
		t.Subject = r.SubjectID
	case r.SubjectType == spicedb.TypeService && r.SubjectRelation == spicedb.RelationMember && !t.IsMembership():
		t.Service = r.SubjectID
	default:
		return Tuple{}, false
	}
	return t, true
}

// targetName is the name of a relationship's resource: a service's ID, or
// a resource's name decoded.
func targetName(r Relationship) (string, bool) {
	if r.ResourceType == KindService {
		return r.ResourceID, true
	}
	name, err := idenc.ParseResource(r.ResourceID)
	return name, err == nil
}

func isResourceType(t string) bool { return slices.Contains(spicedb.ResourceTypes, t) }

// Validate checks the tuple with the grant tree's own rules (common/grant):
// a known kind and a name valid for it, a relation of the kind, a subject
// encoding or a service name, and well-formed bounds. A membership is
// checked as a Service document holding the subject would be; a resource
// relation as an Access document.
func (t Tuple) Validate() error {
	switch {
	case t.IsOwnership():
		return t.validateOwnership()
	case t.Kind == KindService:
		return t.validateMembership()
	}
	return grant.ValidateAccess(t.Access("request"))
}

// validateMembership checks a membership as a Service document holding the
// subject would be.
func (t Tuple) validateMembership() error {
	if t.Service != "" || t.Subject == "" {
		return errors.New("a membership makes a workload (subject) a member of a service")
	}
	if t.Relation != spicedb.RelationMember {
		return fmt.Errorf("relation %q on a service: want %s, %s or %s", t.Relation, spicedb.RelationMember, RelationOwner, RelationApprover)
	}
	if err := t.validateService(); err != nil {
		return err
	}
	return validateBounds(t)
}

// validateOwnership checks an owner or an approver: a target of a known
// kind and a valid name, one holder, and no bounds, which the schema's
// owner and approver relations do not carry.
func (t Tuple) validateOwnership() error {
	if t.ExpiresAt != "" || len(t.Clusters) > 0 {
		return fmt.Errorf("%s is not bounded: no expiresAt, no clusters", t.Relation)
	}
	if t.Kind == KindService {
		if (t.Subject == "") == (t.Service == "") {
			return errors.New("one of subject or service is required")
		}
		return t.validateService()
	}
	// The holder and the target, checked as an Access document's.
	a := t.Access("request")
	a.Spec.Relation = grant.RelationReader
	return grant.ValidateAccess(a)
}

// validateService checks the service's name and the subject, as a Service
// document holding it would be.
func (t Tuple) validateService() error {
	spec := grant.ServiceSpec{Team: "request"}
	if t.Subject != "" {
		spec.Members = []string{t.Subject}
	}
	if t.Service != "" {
		if err := grant.ValidateService(&grant.Service{Kind: grant.KindService, Metadata: grant.Metadata{Name: t.Service}, Spec: grant.ServiceSpec{Team: "request"}}); err != nil {
			return err
		}
	}
	return grant.ValidateService(&grant.Service{Kind: grant.KindService, Metadata: grant.Metadata{Name: t.Name}, Spec: spec})
}

// validateBounds checks a membership's bounds as an Access document's.
func validateBounds(t Tuple) error {
	a := &grant.Access{Kind: grant.KindAccess, Metadata: grant.Metadata{Name: "request"}, Spec: grant.AccessSpec{
		Subject: t.Subject, Resource: grant.Resource{Kind: grant.ResourceS3Bucket, Name: "bounds-only"},
		Relation: grant.RelationReader, ExpiresAt: t.ExpiresAt, Clusters: t.Clusters,
	}}
	return grant.ValidateAccess(a)
}

// Access is a resource tuple as the kind: Access document of the grant
// tree that says the same, under the given name.
func (t Tuple) Access(name string) *grant.Access {
	return &grant.Access{Kind: grant.KindAccess, Metadata: grant.Metadata{Name: name}, Spec: grant.AccessSpec{
		Subject: t.Subject, Service: t.Service, Resource: grant.Resource{Kind: t.Kind, Name: t.Name},
		Relation: t.Relation, ExpiresAt: t.ExpiresAt, Clusters: t.Clusters,
	}}
}
