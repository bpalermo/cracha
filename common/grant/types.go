package grant

import (
	"encoding/json"
	"fmt"
	"time"
)

// Document kinds.
const (
	KindGrant      = "Grant"
	KindAssignment = "Assignment"
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

// Param is a template parameter value: a string or a list of strings.
type Param struct {
	// IsList says which of List and String holds the value.
	IsList bool
	List   []string
	String string
}

// StringParam makes a string parameter.
func StringParam(s string) Param { return Param{String: s} }

// ListParam makes a list parameter.
func ListParam(items ...string) Param { return Param{List: items, IsList: true} }

// UnmarshalJSON accepts a JSON string or an array of strings.
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
	return fmt.Errorf("parameter must be a string or a list of strings (quote numbers and booleans), got %s", string(data))
}

// MarshalJSON writes the value back as a string or an array.
func (p Param) MarshalJSON() ([]byte, error) {
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
}

// Expiry parses ExpiresAt. It returns the zero time when unset.
func (s *AssignmentSpec) Expiry() (time.Time, error) {
	if s.ExpiresAt == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, s.ExpiresAt)
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
}
