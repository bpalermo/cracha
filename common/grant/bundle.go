package grant

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"
)

// versionRE is the charset of a bundle version: it names a directory and an
// S3 key.
var versionRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// CompileOptions configure Compile.
type CompileOptions struct {
	// Version is the version of the compiled bundle and assignments,
	// typically the git commit of the sources. Empty means the content
	// hash of both (ContentVersion).
	Version string
	// GeneratedAt is stamped into both documents. Zero means time.Now().
	GeneratedAt time.Time
	// Lint options for the pipeline run before compiling.
	Lint LintOptions
}

// Compiled is what one compilation produces: the bundle (what the grants
// are) and the assignments (who holds them), under one version, published
// together as one version of the publication.
type Compiled struct {
	Bundle      *Bundle
	Assignments *Assignments
}

// Compile runs the pipeline (Lint) and, when it finds no problem, compiles
// the bundle and the assignments document. A source with problems does not
// compile: the error carries the report.
func Compile(ctx context.Context, src *Source, opts CompileOptions) (*Compiled, *Report, error) {
	report, err := Lint(ctx, src, opts.Lint)
	if err != nil {
		return nil, nil, err
	}
	if !report.OK() {
		return nil, report, fmt.Errorf("%d problems; the bundle was not compiled", len(report.Problems))
	}
	b := compileBundle(src, report)
	services, workloads, err := ResolveAssignments(src)
	if err != nil {
		return nil, report, err
	}
	access, err := ResolveAccess(src)
	if err != nil {
		return nil, report, err
	}
	a := &Assignments{Services: services, Workloads: workloads}
	if len(access) > 0 {
		a.Access = access
	}
	version := opts.Version
	if version == "" {
		if version, err = ContentVersion(b.Grants, b.Accounts, a); err != nil {
			return nil, nil, err
		}
	}
	if !ValidVersion(version) {
		return nil, nil, fmt.Errorf("version %q: must match %s", version, versionRE)
	}
	at := opts.GeneratedAt
	if at.IsZero() {
		at = time.Now()
	}
	stamp := at.UTC().Format(time.RFC3339)
	b.Version, b.GeneratedAt = version, stamp
	a.Version, a.GeneratedAt = version, stamp
	return &Compiled{Bundle: b, Assignments: a}, report, nil
}

// compileBundle compiles the grants of a source the lints passed
// (Source.CompiledGrants), with the policies they rendered, and its
// accounts.
func compileBundle(src *Source, report *Report) *Bundle {
	rendered := map[string]string{}
	lookups := map[string]*BundleLookup{}
	for _, r := range report.Grants {
		rendered[r.Grant] = r.Rendered
		lookups[r.Grant] = r.Lookup
	}
	b := &Bundle{Grants: []BundleGrant{}, Accounts: bundleAccounts(src)}
	for _, g := range src.CompiledGrants() {
		b.Grants = append(b.Grants, BundleGrant{
			Name:              g.Name(),
			Account:           g.Spec.Account,
			BaseRole:          g.Spec.BaseRole,
			SessionPolicy:     rendered[g.Name()],
			ManagedPolicyArns: nonNil(g.Spec.ManagedPolicyArns),
			SessionTags:       nonNilMap(g.Spec.SessionTags),
			Duration:          g.Spec.EffectiveDuration(),
			Envelope:          nonNil(g.Spec.Envelope),
			Lookup:            lookups[g.Name()],
			Implicit:          g.Implicit(),
		})
	}
	sort.Slice(b.Grants, func(i, j int) bool { return b.Grants[i].Name < b.Grants[j].Name })
	return b
}

// ValidVersion reports whether v is a well-formed bundle version: it names
// a directory and an S3 key, so a reader following a pointer can require it.
func ValidVersion(v string) bool { return versionRE.MatchString(v) }

// ContentVersion is the SHA-256, in hex, of the canonical JSON of the
// grants, the accounts, and who holds them (the services, workloads and
// access of the assignments; their version and generatedAt are not part of
// it): the version of a compilation whose sources carry no version of
// their own. A change to any, the assignments alone included, is a new
// version. Without accounts the hash is what it was before them.
func ContentVersion(grants []BundleGrant, accounts []BundleAccount, a *Assignments) (string, error) {
	content := struct {
		Grants    []BundleGrant      `json:"grants"`
		Accounts  []BundleAccount    `json:"accounts,omitempty"`
		Services  []AssignedService  `json:"services"`
		Workloads []AssignedWorkload `json:"workloads"`
		Access    []AssignedAccess   `json:"access,omitempty"`
	}{Grants: grants, Accounts: accounts}
	if a != nil {
		content.Services, content.Workloads, content.Access = a.Services, a.Workloads, a.Access
	}
	data, err := canonical(content)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// Marshal encodes a bundle in its canonical form: keys sorted, two space
// indentation, no HTML escaping, a trailing newline. These are the bytes
// that are signed and published.
func Marshal(b *Bundle) ([]byte, error) {
	return canonical(b)
}

// ParseBundle decodes a bundle document. Unknown fields are an error.
func ParseBundle(data []byte) (*Bundle, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var b Bundle
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	if dec.More() {
		return nil, errors.New("bundle: trailing data")
	}
	if !ValidVersion(b.Version) {
		return nil, fmt.Errorf("bundle: version %q: must match %s", b.Version, versionRE)
	}
	if b.Grants == nil {
		return nil, errors.New("bundle: no grants")
	}
	return &b, nil
}

// canonical encodes v with sorted keys and two space indentation, by way of
// a generic decode so that struct field order does not matter.
func canonical(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(generic); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nonNilMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}
