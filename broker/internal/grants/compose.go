package grants

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Reason is a 403 reason of docs/design.md, section 6.5.
type Reason string

// The reasons the broker denies with.
const (
	ReasonNoGrant           Reason = "no_grant"
	ReasonAmbiguous         Reason = "ambiguous"
	ReasonSubjectSuspended  Reason = "subject_suspended"
	ReasonEnvelopeViolation Reason = "envelope_violation"
	ReasonPolicyTooLarge    Reason = "policy_too_large"
)

// DenyError is a denial with one of the reasons above. Detail is for the
// log, never for the caller.
type DenyError struct {
	Reason Reason
	Detail string
}

func (e *DenyError) Error() string {
	return string(e.Reason) + ": " + e.Detail
}

// Limits of a composed credential (sections 6.2 and 6.6).
const (
	// MaxPolicyChars is the size budget of the inline session policy.
	MaxPolicyChars = 2048
	// MaxManagedPolicies is STS's limit on PolicyArns.
	MaxManagedPolicies = 10
	// MaxDurationSeconds is the role-chaining ceiling.
	MaxDurationSeconds = 3600
	// MinDurationSeconds is STS's floor.
	MinDurationSeconds = 900
	// DefaultDurationSeconds applies when no grant sets a duration.
	DefaultDurationSeconds = 3600
	// PolicyVersion is the only policy language version accepted.
	PolicyVersion = "2012-10-17"
)

// Composed is what the broker asks STS for on behalf of one workload.
type Composed struct {
	// BaseRole is the shape role ARN shared by every grant.
	BaseRole string
	// Shape is the shape's short name, for Cracha-Shape.
	Shape string
	// Account is the shape role's account.
	Account string
	// Grants are the composed grant names, sorted.
	Grants []string
	// Policy is the composed inline session policy, compact JSON, or empty
	// when no grant has inline statements.
	Policy string
	// ManagedPolicyARNs is the union of the grants' managed policies, sorted.
	ManagedPolicyARNs []string
	// SessionTags is the union of the grants' session tags.
	SessionTags map[string]string
	// DurationSeconds is the shortest duration among the grants, capped.
	DurationSeconds int32
}

// Compose resolves the named grants and composes them (sections 6.2 and
// 6.5): one shape or "ambiguous"; no grants or a grant missing from the
// source is "no_grant"; the inline statements are unioned into one policy,
// every Resource of which must match an envelope pattern of the grant that
// contributed it, else "envelope_violation"; an inline policy over
// MaxPolicyChars or more than MaxManagedPolicies managed policies is
// "policy_too_large"; the duration is the minimum across grants, capped at
// MaxDurationSeconds; session tags are merged, and a key with two values is
// "ambiguous". A denial is a *DenyError; any other error means the source's
// content is unusable, which is also a deny.
//
// The grants are folded in name order, and the first fault found is the
// one reported: for each grant, its shape and account, then its statements,
// then its session tags; after all grants, the policy size, the managed
// policy count and the duration.
func Compose(src Source, names []string) (Composed, error) {
	names = sortedUnique(names)
	if len(names) == 0 {
		return Composed{}, &DenyError{ReasonNoGrant, "no grants assigned"}
	}
	resolved, err := resolveGrants(src, names)
	if err != nil {
		return Composed{}, err
	}
	c, err := newComposition(resolved[0], names)
	if err != nil {
		return Composed{}, err
	}
	for _, g := range resolved {
		if err := c.add(g); err != nil {
			return Composed{}, err
		}
	}
	return c.finish()
}

// resolveGrants looks every name up in the source, in order; a name the
// source lacks is "no_grant".
func resolveGrants(src Source, names []string) ([]ResolvedGrant, error) {
	resolved := make([]ResolvedGrant, 0, len(names))
	for _, n := range names {
		g, ok := src.Lookup(n)
		if !ok {
			return nil, &DenyError{ReasonNoGrant, fmt.Sprintf("grant %q is not in bundle version %q", n, src.Version())}
		}
		resolved = append(resolved, g)
	}
	return resolved, nil
}

// composition accumulates the grants of one workload, in name order, into a
// Composed. The first grant fixes the shape and account every later grant
// must share.
type composition struct {
	first      ResolvedGrant
	out        Composed
	statements []json.RawMessage
	managed    map[string]bool
	tagSource  map[string]string // the grant each session tag came from
	duration   int32             // the shortest duration so far; 0 until a grant sets one
}

// newComposition starts a composition from the first grant, whose base role
// is the shape of the whole set.
func newComposition(first ResolvedGrant, names []string) (*composition, error) {
	if first.BaseRole == "" {
		return nil, fmt.Errorf("grant %q has no base role", first.Name)
	}
	return &composition{
		first: first,
		out: Composed{
			BaseRole:    first.BaseRole,
			Shape:       ShapeName(first.BaseRole),
			Account:     first.Account,
			Grants:      names,
			SessionTags: map[string]string{},
		},
		managed:   map[string]bool{},
		tagSource: map[string]string{},
	}, nil
}

// add folds one grant in: its shape and account must match the first
// grant's, its statements are appended, its managed policies and session
// tags unioned, and its duration shortens the set's.
func (c *composition) add(g ResolvedGrant) error {
	if err := c.sameShape(g); err != nil {
		return err
	}
	stmts, err := statementsOf(g)
	if err != nil {
		return err
	}
	c.statements = append(c.statements, stmts...)
	for _, arn := range g.ManagedPolicyARNs {
		c.managed[arn] = true
	}
	if err := c.mergeTags(g); err != nil {
		return err
	}
	if g.DurationSeconds > 0 && (c.duration == 0 || g.DurationSeconds < c.duration) {
		c.duration = g.DurationSeconds
	}
	return nil
}

// sameShape is "ambiguous" when g names another shape role or account than
// the first grant.
func (c *composition) sameShape(g ResolvedGrant) error {
	if g.BaseRole != c.out.BaseRole {
		return &DenyError{ReasonAmbiguous, fmt.Sprintf("grant %q has shape %s, grant %q has shape %s", c.first.Name, c.out.BaseRole, g.Name, g.BaseRole)}
	}
	if g.Account != c.out.Account {
		return &DenyError{ReasonAmbiguous, fmt.Sprintf("grant %q is in account %s, grant %q in %s", c.first.Name, c.out.Account, g.Name, g.Account)}
	}
	return nil
}

// mergeTags unions g's session tags into the set. Only team and service are
// allowed; a key an earlier grant set to another value is "ambiguous".
func (c *composition) mergeTags(g ResolvedGrant) error {
	for k, v := range g.SessionTags {
		if k != "team" && k != "service" {
			return fmt.Errorf("grant %q sets session tag %q; only team and service are allowed", g.Name, k)
		}
		if prev, ok := c.out.SessionTags[k]; ok && prev != v {
			return &DenyError{ReasonAmbiguous, fmt.Sprintf("session tag %q is %q in grant %q and %q in grant %q", k, prev, c.tagSource[k], v, g.Name)}
		}
		c.out.SessionTags[k], c.tagSource[k] = v, g.Name
	}
	return nil
}

// finish applies the limits of sections 6.2 and 6.6 and returns the result.
func (c *composition) finish() (Composed, error) {
	policy, err := policyDocument(c.statements)
	if err != nil {
		return Composed{}, err
	}
	c.out.Policy = policy
	c.out.ManagedPolicyARNs = sortedKeys(c.managed)
	if len(c.out.ManagedPolicyARNs) > MaxManagedPolicies {
		return Composed{}, &DenyError{ReasonPolicyTooLarge, fmt.Sprintf("%d managed policies, over %d", len(c.out.ManagedPolicyARNs), MaxManagedPolicies)}
	}
	duration, err := sessionDuration(c.duration)
	if err != nil {
		return Composed{}, err
	}
	c.out.DurationSeconds = duration
	return c.out, nil
}

// policyDocument renders the unioned statements as one compact policy, or
// nothing when there are none. A document over MaxPolicyChars is
// "policy_too_large".
func policyDocument(statements []json.RawMessage) (string, error) {
	if len(statements) == 0 {
		return "", nil
	}
	doc, err := json.Marshal(struct {
		Version   string            `json:"Version"`
		Statement []json.RawMessage `json:"Statement"`
	}{PolicyVersion, statements})
	if err != nil {
		return "", fmt.Errorf("compose policy: %w", err)
	}
	if len(doc) > MaxPolicyChars {
		return "", &DenyError{ReasonPolicyTooLarge, fmt.Sprintf("inline session policy is %d characters, over %d", len(doc), MaxPolicyChars)}
	}
	return string(doc), nil
}

// sessionDuration turns the shortest grant duration (0 when no grant set
// one) into the one asked of STS: the default when unset, capped at the
// role-chaining ceiling, and an error under STS's floor.
func sessionDuration(shortest int32) (int32, error) {
	switch {
	case shortest == 0:
		return DefaultDurationSeconds, nil
	case shortest < MinDurationSeconds:
		return 0, fmt.Errorf("session duration %ds is under STS's minimum of %ds", shortest, MinDurationSeconds)
	case shortest > MaxDurationSeconds:
		return MaxDurationSeconds, nil
	}
	return shortest, nil
}

// sortedKeys returns the keys of set, sorted, or nil when it is empty.
func sortedKeys(set map[string]bool) []string {
	var keys []string
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// statementsOf parses a grant's rendered session policy and checks every
// Resource against the grant's envelope. It returns the statements compact.
func statementsOf(g ResolvedGrant) ([]json.RawMessage, error) {
	if strings.TrimSpace(g.SessionPolicy) == "" {
		return nil, nil
	}
	stmts, err := policyStatements(g)
	if err != nil {
		return nil, err
	}
	out := make([]json.RawMessage, 0, len(stmts))
	for i, raw := range stmts {
		stmt, err := normalizeStatement(g, i, raw)
		if err != nil {
			return nil, err
		}
		out = append(out, stmt)
	}
	return out, nil
}

// policyStatements parses the policy document of g and returns its
// Statement as a list, whether it was written as one or as a single
// statement.
func policyStatements(g ResolvedGrant) ([]json.RawMessage, error) {
	var doc struct {
		Version   string          `json:"Version"`
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(g.SessionPolicy), &doc); err != nil {
		return nil, fmt.Errorf("grant %q: session policy: %w", g.Name, err)
	}
	if doc.Version != "" && doc.Version != PolicyVersion {
		return nil, fmt.Errorf("grant %q: session policy version %q, want %q", g.Name, doc.Version, PolicyVersion)
	}
	if len(doc.Statement) == 0 {
		return nil, fmt.Errorf("grant %q: session policy has no Statement", g.Name)
	}
	if !bytes.HasPrefix(bytes.TrimSpace(doc.Statement), []byte("[")) {
		return []json.RawMessage{doc.Statement}, nil
	}
	var stmts []json.RawMessage
	if err := json.Unmarshal(doc.Statement, &stmts); err != nil {
		return nil, fmt.Errorf("grant %q: session policy Statement: %w", g.Name, err)
	}
	return stmts, nil
}

// normalizeStatement checks statement i of g against the envelope and
// returns it compact. A statement no envelope can bound (NotResource, no or
// empty Resource, a Resource outside every pattern) is
// "envelope_violation".
func normalizeStatement(g ResolvedGrant, i int, raw json.RawMessage) (json.RawMessage, error) {
	var stmt map[string]json.RawMessage
	if err := json.Unmarshal(raw, &stmt); err != nil {
		return nil, fmt.Errorf("grant %q: statement %d: %w", g.Name, i, err)
	}
	if _, ok := stmt["NotResource"]; ok {
		return nil, &DenyError{ReasonEnvelopeViolation, fmt.Sprintf("grant %q: statement %d uses NotResource, which no envelope can bound", g.Name, i)}
	}
	resRaw, ok := stmt["Resource"]
	if !ok {
		return nil, &DenyError{ReasonEnvelopeViolation, fmt.Sprintf("grant %q: statement %d has no Resource", g.Name, i)}
	}
	resources, err := stringOrList(resRaw)
	if err != nil {
		return nil, fmt.Errorf("grant %q: statement %d: Resource: %w", g.Name, i, err)
	}
	if len(resources) == 0 {
		return nil, &DenyError{ReasonEnvelopeViolation, fmt.Sprintf("grant %q: statement %d has an empty Resource", g.Name, i)}
	}
	for _, r := range resources {
		if !inEnvelope(r, g.Envelope) {
			return nil, &DenyError{ReasonEnvelopeViolation, fmt.Sprintf("grant %q: statement %d: resource %q matches no envelope pattern %q", g.Name, i, r, g.Envelope)}
		}
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return nil, fmt.Errorf("grant %q: statement %d: %w", g.Name, i, err)
	}
	return compact.Bytes(), nil
}

func stringOrList(raw json.RawMessage) ([]string, error) {
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, fmt.Errorf("neither a string nor a list of strings")
	}
	return many, nil
}

func inEnvelope(resource string, envelope []string) bool {
	for _, pattern := range envelope {
		if MatchARN(pattern, resource) {
			return true
		}
	}
	return false
}

// MatchARN reports whether an ARN matches an IAM-style pattern, where "*"
// matches any run of characters (including ":" and "/") and "?" matches
// exactly one. Anything else matches itself, case-sensitively.
func MatchARN(pattern, arn string) bool {
	p, a := 0, 0
	starP, starA := -1, -1
	for a < len(arn) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == arn[a]):
			p++
			a++
		case p < len(pattern) && pattern[p] == '*':
			starP, starA = p, a
			p++
		case starP >= 0:
			starA++
			p, a = starP+1, starA
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

func sortedUnique(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
