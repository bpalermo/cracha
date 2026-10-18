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
	// ReasonResourceOutsideEnvelope: a resource the store related the
	// workload to rendered outside a lookup grant's envelope (Level 3).
	ReasonResourceOutsideEnvelope Reason = "resource_outside_envelope"
	// ReasonNoResources: every grant the workload holds is a lookup grant
	// and the store relates it to no resource of any.
	ReasonNoResources Reason = "no_resources"
	// ReasonAccountsMixed: the workload's grants, its implicit ones
	// included, are in more than one AWS account. One credential is one
	// AssumeRole, in one account.
	ReasonAccountsMixed Reason = "accounts_mixed"
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
	// Resources are, per lookup grant composed, the resources its policy
	// was rendered with, sorted.
	Resources map[string][]string
	// Dropped are the lookup grants held but left out, for want of any
	// resource.
	Dropped []string
	// Unplaced are the resources (kind:name) the store relates the
	// workload to that no account of the bundle places, so that no
	// implicit grant renders them, sorted.
	Unplaced []string
}

// Finder answers which resources of a kind the workload holds a
// permission on: the authorization store's LookupResources, for Compose.
type Finder func(kind, permission string) ([]string, error)

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
// A lookup grant (Level 3) is rendered first, with the resources find
// returns for its kind and permission (one call per kind and permission):
// more than its compiled maximum is "policy_too_large", and a rendered
// resource outside its envelope is "resource_outside_envelope", whatever
// the other grants. A lookup grant for which the store finds no resource is
// left out of the composition, and reported in Dropped, so that the
// workload keeps the rest of its grants; when that leaves nothing, the
// denial is "no_resources". An error of find is returned as it is, for the
// caller to tell a store that cannot answer from a deny.
//
// With an ImplicitSource, the implicit grants of the bundle's accounts
// (design 6.2) are composed as well: one of a kind and permission that no
// held lookup grant is of, rendered with the resources of that kind the
// store relates the workload to in its account, and left out silently
// when there are none. A workload that holds no grant and is related to
// no such resource is "no_grant". Grants in more than one account, the
// implicit ones included, are "accounts_mixed": a credential is one
// AssumeRole, in one account.
//
// The grants are folded in name order, and the first fault found is the
// one reported: for each grant, its account and shape, then its
// statements, then its session tags; after all grants, the policy size,
// the managed policy count and the duration.
func Compose(src Source, names []string, find Finder) (Composed, error) {
	names = sortedUnique(names)
	resolved, err := resolveGrants(src, names)
	if err != nil {
		return Composed{}, err
	}
	implicit, place := implicitOf(src, resolved)
	if len(resolved)+len(implicit) == 0 {
		return Composed{}, &DenyError{ReasonNoGrant, "no grants assigned"}
	}
	f := newFiller(find, place)
	for _, g := range append(resolved, implicit...) {
		if err := f.add(g); err != nil {
			return Composed{}, err
		}
	}
	filled := f.out
	if len(filled.grants) == 0 {
		return Composed{}, nothingFilled(names, filled)
	}
	sort.Slice(filled.grants, func(i, j int) bool { return filled.grants[i].Name < filled.grants[j].Name })
	resolved, names = filled.grants, grantNames(filled.grants)
	c, err := newComposition(resolved[0], names)
	if err != nil {
		return Composed{}, err
	}
	c.out.Resources, c.out.Dropped, c.out.Unplaced = filled.resources, filled.dropped, sortedKeys(f.unplaced)
	for _, g := range resolved {
		if err := c.add(g); err != nil {
			return Composed{}, err
		}
	}
	return c.finish()
}

// nothingFilled is the denial of a workload left with no grant once the
// lookups found their resources: "no_grant" when it holds none and no
// implicit grant applies, "no_resources" when its lookup grants found
// nothing.
func nothingFilled(held []string, filled filledGrants) error {
	if len(held) == 0 {
		return &DenyError{ReasonNoGrant, "no grants assigned, and no resource related in an account's access table"}
	}
	return &DenyError{ReasonNoResources, fmt.Sprintf("lookup grants %s: no resource is related to the workload", strings.Join(filled.dropped, ", "))}
}

// implicitOf are the implicit grants of src that may apply to a workload
// holding held, those of a kind and permission no held lookup grant is
// of, and where the source places a resource; none when src has no
// accounts.
func implicitOf(src Source, held []ResolvedGrant) ([]ResolvedGrant, func(kind, name string) (string, bool)) {
	is, ok := src.(ImplicitSource)
	if !ok {
		return nil, nil
	}
	covered := map[string]bool{}
	for _, g := range held {
		if g.Lookup != nil {
			covered[g.Lookup.Kind+"#"+g.Lookup.Permission] = true
		}
	}
	var out []ResolvedGrant
	for _, g := range is.ImplicitGrants() {
		if g.Lookup != nil && !covered[g.Lookup.Kind+"#"+g.Lookup.Permission] {
			out = append(out, g)
		}
	}
	return out, is.AccountOf
}

// filledGrants are a workload's grants with their lookups rendered.
type filledGrants struct {
	grants    []ResolvedGrant
	resources map[string][]string
	dropped   []string
}

// filler renders a workload's lookup grants with the resources find gives
// each kind and permission (one call per pair), an implicit grant with
// those place puts in its account, and leaves out those it finds none for.
type filler struct {
	find     Finder
	place    func(kind, name string) (string, bool)
	found    map[string][]string
	out      filledGrants
	unplaced map[string]bool
}

func newFiller(find Finder, place func(kind, name string) (string, bool)) *filler {
	return &filler{find: find, place: place, found: map[string][]string{}, unplaced: map[string]bool{}}
}

// add takes one grant in, rendered when it is a lookup grant.
func (f *filler) add(g ResolvedGrant) error {
	if g.Lookup == nil {
		f.out.grants = append(f.out.grants, g)
		return nil
	}
	resources, err := f.resources(g)
	if err != nil {
		return err
	}
	if len(resources) == 0 {
		if !g.Implicit {
			f.out.dropped = append(f.out.dropped, g.Name)
		}
		return nil
	}
	filled, err := fillLookup(g, resources)
	if err != nil {
		return err
	}
	if f.out.resources == nil {
		f.out.resources = map[string][]string{}
	}
	f.out.resources[g.Name] = resources
	f.out.grants = append(f.out.grants, filled)
	return nil
}

// resources are a lookup grant's resources: all those of its kind and
// permission, or, for an implicit grant, those in its account. A resource
// no account places is recorded in unplaced.
func (f *filler) resources(g ResolvedGrant) ([]string, error) {
	all, err := findOnce(f.found, f.find, g)
	if err != nil || !g.Implicit {
		return all, err
	}
	var in []string
	for _, r := range all {
		account, ok := "", false
		if f.place != nil {
			account, ok = f.place(g.Lookup.Kind, r)
		}
		switch {
		case !ok:
			f.unplaced[g.Lookup.Kind+":"+r] = true
		case account == g.Account:
			in = append(in, r)
		}
	}
	return in, nil
}

// findOnce asks find for a lookup grant's resources, once per kind and
// permission: found holds the answers so far.
func findOnce(found map[string][]string, find Finder, g ResolvedGrant) ([]string, error) {
	key := g.Lookup.Kind + "#" + g.Lookup.Permission
	if resources, ok := found[key]; ok {
		return resources, nil
	}
	if find == nil {
		return nil, fmt.Errorf("grant %q needs a resource lookup and there is no store to ask", g.Name)
	}
	resources, err := find(g.Lookup.Kind, g.Lookup.Permission)
	if err != nil {
		return nil, err
	}
	resources = sortedUnique(resources)
	found[key] = resources
	return resources, nil
}

// fillLookup renders one lookup grant for its resources and checks every
// resource of the result against its envelope.
func fillLookup(g ResolvedGrant, resources []string) (ResolvedGrant, error) {
	l := g.Lookup
	if len(resources) > l.MaxResources {
		return ResolvedGrant{}, &DenyError{ReasonPolicyTooLarge, fmt.Sprintf("grant %q: %d %s resources, over its compiled maximum of %d", g.Name, len(resources), l.Kind, l.MaxResources)}
	}
	if l.Render == nil {
		return ResolvedGrant{}, fmt.Errorf("grant %q: a lookup without a renderer", g.Name)
	}
	policy, err := l.Render(resources)
	if err != nil {
		return ResolvedGrant{}, fmt.Errorf("grant %q: rendering for %s: %w", g.Name, strings.Join(resources, ", "), err)
	}
	g.SessionPolicy, g.Lookup = policy, nil
	stmts, err := policyStatements(g)
	if err != nil {
		return ResolvedGrant{}, err
	}
	for i, raw := range stmts {
		if err := lookupStatementInEnvelope(g, i, raw, resources); err != nil {
			return ResolvedGrant{}, err
		}
	}
	return g, nil
}

// lookupStatementInEnvelope is "resource_outside_envelope" when a
// Resource of statement i of a rendered lookup grant matches no pattern of
// its envelope. What no envelope can bound at all is left to
// normalizeStatement, which reports it as for any grant.
func lookupStatementInEnvelope(g ResolvedGrant, i int, raw json.RawMessage, resources []string) error {
	var stmt map[string]json.RawMessage
	if err := json.Unmarshal(raw, &stmt); err != nil {
		return fmt.Errorf("grant %q: statement %d: %w", g.Name, i, err)
	}
	resRaw, ok := stmt["Resource"]
	if !ok {
		return nil
	}
	rendered, err := stringOrList(resRaw)
	if err != nil {
		return fmt.Errorf("grant %q: statement %d: Resource: %w", g.Name, i, err)
	}
	for _, r := range rendered {
		if !inEnvelope(r, g.Envelope) {
			return &DenyError{ReasonResourceOutsideEnvelope, fmt.Sprintf("grant %q rendered for %s: statement %d: resource %q matches no envelope pattern %q", g.Name, strings.Join(resources, ", "), i, r, g.Envelope)}
		}
	}
	return nil
}

func grantNames(gs []ResolvedGrant) []string {
	out := make([]string, len(gs))
	for i, g := range gs {
		out[i] = g.Name
	}
	return out
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

// sameShape is "accounts_mixed" when g is in another account than the
// first grant, and "ambiguous" when it names another role.
func (c *composition) sameShape(g ResolvedGrant) error {
	if g.Account != c.out.Account {
		return &DenyError{ReasonAccountsMixed, fmt.Sprintf("grant %q is in account %s, grant %q in %s; one credential is one account", c.first.Name, c.out.Account, g.Name, g.Account)}
	}
	if g.BaseRole != c.out.BaseRole {
		return &DenyError{ReasonAmbiguous, fmt.Sprintf("grant %q has shape %s, grant %q has shape %s", c.first.Name, c.out.BaseRole, g.Name, g.BaseRole)}
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
	if policy == "" && len(c.out.ManagedPolicyARNs) == 0 {
		// A session with neither would have the role's whole identity
		// policy, which on an account role is every workload's (6.6).
		return Composed{}, &DenyError{ReasonEnvelopeViolation, fmt.Sprintf("grants %s carry neither a session policy nor managed policies", strings.Join(c.out.Grants, ", "))}
	}
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
