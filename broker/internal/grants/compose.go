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
func Compose(src Source, names []string) (Composed, error) {
	names = sortedUnique(names)
	if len(names) == 0 {
		return Composed{}, &DenyError{ReasonNoGrant, "no grants assigned"}
	}
	resolved := make([]ResolvedGrant, 0, len(names))
	for _, n := range names {
		g, ok := src.Lookup(n)
		if !ok {
			return Composed{}, &DenyError{ReasonNoGrant, fmt.Sprintf("grant %q is not in bundle version %q", n, src.Version())}
		}
		resolved = append(resolved, g)
	}

	out := Composed{
		BaseRole:    resolved[0].BaseRole,
		Account:     resolved[0].Account,
		Grants:      names,
		SessionTags: map[string]string{},
	}
	if out.BaseRole == "" {
		return Composed{}, fmt.Errorf("grant %q has no base role", resolved[0].Name)
	}
	out.Shape = ShapeName(out.BaseRole)

	var statements []json.RawMessage
	managed := map[string]bool{}
	tagSource := map[string]string{}
	var duration int32
	for _, g := range resolved {
		if g.BaseRole != out.BaseRole {
			return Composed{}, &DenyError{ReasonAmbiguous, fmt.Sprintf("grant %q has shape %s, grant %q has shape %s", resolved[0].Name, out.BaseRole, g.Name, g.BaseRole)}
		}
		if g.Account != out.Account {
			return Composed{}, &DenyError{ReasonAmbiguous, fmt.Sprintf("grant %q is in account %s, grant %q in %s", resolved[0].Name, out.Account, g.Name, g.Account)}
		}
		stmts, err := statementsOf(g)
		if err != nil {
			return Composed{}, err
		}
		statements = append(statements, stmts...)
		for _, arn := range g.ManagedPolicyARNs {
			managed[arn] = true
		}
		for k, v := range g.SessionTags {
			if k != "team" && k != "service" {
				return Composed{}, fmt.Errorf("grant %q sets session tag %q; only team and service are allowed", g.Name, k)
			}
			if prev, ok := out.SessionTags[k]; ok && prev != v {
				return Composed{}, &DenyError{ReasonAmbiguous, fmt.Sprintf("session tag %q is %q in grant %q and %q in grant %q", k, prev, tagSource[k], v, g.Name)}
			}
			out.SessionTags[k], tagSource[k] = v, g.Name
		}
		if g.DurationSeconds > 0 && (duration == 0 || g.DurationSeconds < duration) {
			duration = g.DurationSeconds
		}
	}

	if len(statements) > 0 {
		doc, err := json.Marshal(struct {
			Version   string            `json:"Version"`
			Statement []json.RawMessage `json:"Statement"`
		}{PolicyVersion, statements})
		if err != nil {
			return Composed{}, fmt.Errorf("compose policy: %w", err)
		}
		if len(doc) > MaxPolicyChars {
			return Composed{}, &DenyError{ReasonPolicyTooLarge, fmt.Sprintf("inline session policy is %d characters, over %d", len(doc), MaxPolicyChars)}
		}
		out.Policy = string(doc)
	}

	for arn := range managed {
		out.ManagedPolicyARNs = append(out.ManagedPolicyARNs, arn)
	}
	sort.Strings(out.ManagedPolicyARNs)
	if len(out.ManagedPolicyARNs) > MaxManagedPolicies {
		return Composed{}, &DenyError{ReasonPolicyTooLarge, fmt.Sprintf("%d managed policies, over %d", len(out.ManagedPolicyARNs), MaxManagedPolicies)}
	}

	switch {
	case duration == 0:
		duration = DefaultDurationSeconds
	case duration < MinDurationSeconds:
		return Composed{}, fmt.Errorf("session duration %ds is under STS's minimum of %ds", duration, MinDurationSeconds)
	case duration > MaxDurationSeconds:
		duration = MaxDurationSeconds
	}
	out.DurationSeconds = duration
	return out, nil
}

// statementsOf parses a grant's rendered session policy and checks every
// Resource against the grant's envelope. It returns the statements compact.
func statementsOf(g ResolvedGrant) ([]json.RawMessage, error) {
	if strings.TrimSpace(g.SessionPolicy) == "" {
		return nil, nil
	}
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
	var stmts []json.RawMessage
	if bytes.HasPrefix(bytes.TrimSpace(doc.Statement), []byte("[")) {
		if err := json.Unmarshal(doc.Statement, &stmts); err != nil {
			return nil, fmt.Errorf("grant %q: session policy Statement: %w", g.Name, err)
		}
	} else {
		stmts = []json.RawMessage{doc.Statement}
	}
	out := make([]json.RawMessage, 0, len(stmts))
	for i, raw := range stmts {
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
		out = append(out, compact.Bytes())
	}
	return out, nil
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
