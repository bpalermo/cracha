package grant

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Document kinds.
const (
	KindGrant      = "Grant"
	KindAssignment = "Assignment"
	KindService    = "Service"
	KindAccess     = "Access"
)

// STS limits the pipeline lints against (design 6.2 step 4 and 6.6).
const (
	// DefaultDuration is the session duration of a grant that sets none.
	DefaultDuration = 3600
	// MinDuration and MaxDuration bound a grant's duration: STS's floor and
	// the role chaining ceiling.
	MinDuration = 900
	MaxDuration = 3600
	// MaxManagedPolicyArns is STS's limit on session managed policies.
	MaxManagedPolicyArns = 10
	// MaxPolicyChars is STS's limit on the plaintext of an inline session
	// policy, applied to the minified rendered policy.
	MaxPolicyChars = 2048
	// MaxSessionTags, MaxTagKeyChars and MaxTagValueChars are STS's limits
	// on session tags.
	MaxSessionTags   = 50
	MaxTagKeyChars   = 128
	MaxTagValueChars = 256
	// TagBudgetChars is this package's conservative stand-in for STS's packed
	// size limit, which is opaque: the plaintext of all session tag keys and
	// values of one session, the broker's own included, must fit in it.
	TagBudgetChars = 2048
	// BrokerTagCount and BrokerTagChars are what the lints reserve, out of
	// MaxSessionTags and TagBudgetChars, for the tags the broker sets on
	// every session (design 6.6): spiffe-ns, spiffe-sa, cluster, grant, team
	// and service.
	BrokerTagCount = 6
	BrokerTagChars = 768
)

// BrokerTagKeys are the session tag keys only the broker sets (design 6.6).
// A grant may not set them.
var BrokerTagKeys = []string{"spiffe-ns", "spiffe-sa", "cluster", "grant"}

// Metadata names a document.
type Metadata struct {
	Name string `json:"name"`
}

// Grant is a kind: Grant document (design 6.2).
type Grant struct {
	Kind     string    `json:"kind"`
	Metadata Metadata  `json:"metadata"`
	Spec     GrantSpec `json:"spec"`
	// Path is the file the grant was loaded from, relative to the source
	// root, for messages.
	Path string `json:"-"`
}

// Name returns the grant's name.
func (g *Grant) Name() string { return g.Metadata.Name }

// GrantSpec is the body of a Grant.
type GrantSpec struct {
	// Account is the 12-digit AWS account the base role lives in.
	Account string `json:"account"`
	// BaseRole is the ARN of the shape role the broker assumes.
	BaseRole string `json:"baseRole"`
	// SessionPolicy names a template and the parameters it is rendered with.
	SessionPolicy *SessionPolicy `json:"sessionPolicy,omitempty"`
	// ManagedPolicyArns are passed to STS as session managed policies.
	ManagedPolicyArns []string `json:"managedPolicyArns,omitempty"`
	// SessionTags are set on every session issued from this grant.
	SessionTags map[string]string `json:"sessionTags,omitempty"`
	// Duration is the session duration in seconds; 0 means DefaultDuration.
	Duration int `json:"duration,omitempty"`
	// Envelope is the ARN allowlist every resource of the rendered policy
	// must match.
	Envelope []string `json:"envelope,omitempty"`
}

// EffectiveDuration is the grant's duration with the default applied.
func (s *GrantSpec) EffectiveDuration() int {
	if s.Duration == 0 {
		return DefaultDuration
	}
	return s.Duration
}

// SessionPolicy selects a template and its parameters.
type SessionPolicy struct {
	Template string           `json:"template"`
	Params   map[string]Param `json:"params,omitempty"`
}

// Param is a template parameter value: a string or a list of strings, or,
// in a grant's sessionPolicy.params only, a lookup the broker fills at
// issuance with the resources the workload is related to (Level 3).
type Param struct {
	// IsList says which of List and String holds the value.
	IsList bool
	List   []string
	String string
	// Lookup, when set, is a lookup parameter, and the other fields are
	// unset.
	Lookup *Lookup
}

// Lookup is a parameter left to the authorization store: the resources of
// a kind the workload holds a permission on (design 6.2, Level 3).
type Lookup struct {
	// Kind is the resource kind (ResourceKinds), such as s3_bucket.
	Kind string `json:"kind"`
	// Permission is read or write.
	Permission string `json:"permission"`
}

// StringParam makes a string parameter.
func StringParam(s string) Param { return Param{String: s} }

// ListParam makes a list parameter.
func ListParam(items ...string) Param { return Param{List: items, IsList: true} }

// LookupParam makes a lookup parameter.
func LookupParam(kind, permission string) Param {
	return Param{Lookup: &Lookup{Kind: kind, Permission: permission}}
}

// UnmarshalJSON accepts a JSON string, an array of strings, or an object
// {"lookup": {"kind", "permission"}} with no other field.
func (p *Param) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*p = StringParam(s)
		return nil
	}
	var list []string
	if err := json.Unmarshal(data, &list); err == nil {
		*p = ListParam(list...)
		return nil
	}
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
		return p.unmarshalLookup(data)
	}
	return fmt.Errorf("parameter must be a string, a list of strings (quote numbers and booleans) or a lookup, got %s", string(data))
}

// unmarshalLookup decodes {"lookup": {...}} strictly.
func (p *Param) unmarshalLookup(data []byte) error {
	var obj struct {
		Lookup *Lookup `json:"lookup"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&obj); err != nil {
		return fmt.Errorf("lookup parameter: %w", err)
	}
	if obj.Lookup == nil {
		return errors.New("an object parameter must be {lookup: {kind, permission}}")
	}
	*p = Param{Lookup: obj.Lookup}
	return nil
}

// MarshalJSON writes the value back as a string, an array or a lookup.
func (p Param) MarshalJSON() ([]byte, error) {
	if p.Lookup != nil {
		return json.Marshal(struct {
			Lookup *Lookup `json:"lookup"`
		}{p.Lookup})
	}
	if p.IsList {
		if p.List == nil {
			return []byte("[]"), nil
		}
		return json.Marshal(p.List)
	}
	return json.Marshal(p.String)
}

// Assignment is a kind: Assignment document: the grants a subject holds, as
// known in Git (see the package documentation).
type Assignment struct {
	Kind     string         `json:"kind"`
	Metadata Metadata       `json:"metadata"`
	Spec     AssignmentSpec `json:"spec"`
	// Path is the file the assignment was loaded from, relative to the
	// source root, for messages.
	Path string `json:"-"`
}

// Name returns the assignment's name.
func (a *Assignment) Name() string { return a.Metadata.Name }

// AssignmentSpec is the body of an Assignment.
type AssignmentSpec struct {
	// Subject is the workload's authorization subject encoding (design 4.3).
	Subject string `json:"subject"`
	// Grants are the names of the grants the subject holds.
	Grants []string `json:"grants"`
	// ExpiresAt, when set, bounds the assignment in time (RFC 3339).
	ExpiresAt string `json:"expiresAt,omitempty"`
	// Clusters, when set, bounds the assignment to these clusters.
	Clusters []string `json:"clusters,omitempty"`
	// Suspended, when set, says the subject holds nothing, through this
	// assignment or any other source, until it is cleared.
	Suspended bool `json:"suspended,omitempty"`
}

// Expiry parses ExpiresAt. It returns the zero time when unset.
func (s *AssignmentSpec) Expiry() (time.Time, error) {
	return parseExpiry(s.ExpiresAt)
}

// Service is a kind: Service document: a group of workloads that share an
// owning team and a set of grants (see the package documentation).
type Service struct {
	Kind     string      `json:"kind"`
	Metadata Metadata    `json:"metadata"`
	Spec     ServiceSpec `json:"spec"`
	// Path is the file the service was loaded from, relative to the source
	// root, for messages.
	Path string `json:"-"`
}

// Name returns the service's name.
func (s *Service) Name() string { return s.Metadata.Name }

// ServiceSpec is the body of a Service.
type ServiceSpec struct {
	// Team is the team that owns the service.
	Team string `json:"team"`
	// Members are the authorization subject encodings (design 4.3) of the
	// service's workloads. A workload is a member of at most one service.
	Members []string `json:"members,omitempty"`
	// Grants are the grants every member holds.
	Grants []BoundedGrant `json:"grants,omitempty"`
}

// BoundedGrant names a grant a service's members hold, optionally bounded
// in time and to clusters the way an Assignment is.
type BoundedGrant struct {
	Name string `json:"name"`
	// ExpiresAt, when set, bounds the grant in time (RFC 3339).
	ExpiresAt string `json:"expiresAt,omitempty"`
	// Clusters, when set, bounds the grant to these clusters.
	Clusters []string `json:"clusters,omitempty"`
}

// Expiry parses ExpiresAt. It returns the zero time when unset.
func (g *BoundedGrant) Expiry() (time.Time, error) {
	return parseExpiry(g.ExpiresAt)
}

// Access is a kind: Access document: a workload, or every member of a
// service, related to one resource by name (design 6.2, Level 3). A grant
// whose template leaves a parameter to a lookup is filled, at issuance,
// with the resources its holder is related to this way.
type Access struct {
	Kind     string     `json:"kind"`
	Metadata Metadata   `json:"metadata"`
	Spec     AccessSpec `json:"spec"`
	// Path is the file the access was loaded from, relative to the source
	// root, for messages.
	Path string `json:"-"`
}

// Name returns the access document's name.
func (a *Access) Name() string { return a.Metadata.Name }

// AccessSpec is the body of an Access. Exactly one of Subject and Service
// is set.
type AccessSpec struct {
	// Subject is a workload's authorization subject encoding (design 4.3).
	Subject string `json:"subject,omitempty"`
	// Service names a Service whose members are related.
	Service string `json:"service,omitempty"`
	// Resource is the resource related to.
	Resource Resource `json:"resource"`
	// Relation is the relation of the resource's kind: reader or writer.
	Relation string `json:"relation"`
	// ExpiresAt, when set, bounds the access in time (RFC 3339).
	ExpiresAt string `json:"expiresAt,omitempty"`
	// Clusters, when set, bounds the access to these clusters.
	Clusters []string `json:"clusters,omitempty"`
}

// Resource names one resource of a kind.
type Resource struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// String is kind:name, for messages.
func (r Resource) String() string { return r.Kind + ":" + r.Name }

// parseExpiry parses an expiresAt field; empty is the zero time.
func parseExpiry(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("expiresAt: %w", err)
	}
	return t, nil
}

// Bundle is the compiled document the broker consumes (see the package
// documentation). Field names are part of the broker's contract.
type Bundle struct {
	Version     string        `json:"version"`
	GeneratedAt string        `json:"generatedAt"`
	Grants      []BundleGrant `json:"grants"`
}

// BundleGrant is one compiled grant: the Grant with its session policy
// rendered and its defaults applied.
type BundleGrant struct {
	Name              string            `json:"name"`
	Account           string            `json:"account"`
	BaseRole          string            `json:"baseRole"`
	SessionPolicy     string            `json:"sessionPolicy"`
	ManagedPolicyArns []string          `json:"managedPolicyArns"`
	SessionTags       map[string]string `json:"sessionTags"`
	Duration          int               `json:"duration"`
	Envelope          []string          `json:"envelope"`
	// Lookup is set on a grant that leaves a template parameter to the
	// authorization store: its SessionPolicy is then empty and the broker
	// renders the policy at issuance. Absent on every other grant, so a
	// bundle without lookup grants is what it was before them.
	Lookup *BundleLookup `json:"lookup,omitempty"`
}

// BundleLookup is what the broker needs to render a lookup grant's policy
// at issuance: the template, the parameters the grant gives it, and the
// one parameter the resources fill.
type BundleLookup struct {
	// Param is the template parameter the resources fill.
	Param string `json:"param"`
	// Kind and Permission are what the broker asks the store for.
	Kind       string `json:"kind"`
	Permission string `json:"permission"`
	// MaxResources is the most resources the rendered policy can hold
	// within MaxPolicyChars whatever their names, computed at compile time
	// with names of the kind's longest length. The broker denies
	// policy_too_large beyond it.
	MaxResources int `json:"maxResources"`
	// Template is the session policy template; Params the grant's other
	// parameters.
	Template BundleTemplate   `json:"template"`
	Params   map[string]Param `json:"params"`
}

// BundleTemplate is a template as the bundle carries it.
type BundleTemplate struct {
	Name   string               `json:"name"`
	Params map[string]ParamSpec `json:"params"`
	Policy json.RawMessage      `json:"policy"`
}

// Render renders the lookup grant's policy for the resources (see
// RenderLookup). account is the grant's.
func (l *BundleLookup) Render(account string, resources []string) (string, error) {
	t := &Template{Name: l.Template.Name, Params: l.Template.Params, Policy: l.Template.Policy}
	return t.RenderLookup(account, l.Params, l.Param, resources)
}
