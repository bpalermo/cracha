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
	// Version is the bundle's version, typically the git commit of the
	// sources. Empty means the SHA-256 of the compiled grants.
	Version string
	// GeneratedAt is stamped into the bundle. Zero means time.Now().
	GeneratedAt time.Time
	// Lint options for the pipeline run before compiling.
	Lint LintOptions
}

// Compile runs the pipeline (Lint) and, when it finds no problem, compiles
// the bundle. A source with problems does not compile: the error carries
// the report.
func Compile(ctx context.Context, src *Source, opts CompileOptions) (*Bundle, *Report, error) {
	report, err := Lint(ctx, src, opts.Lint)
	if err != nil {
		return nil, nil, err
	}
	if !report.OK() {
		return nil, report, fmt.Errorf("%d problems; the bundle was not compiled", len(report.Problems))
	}
	rendered := map[string]string{}
	for _, r := range report.Grants {
		rendered[r.Grant] = r.Rendered
	}
	b := &Bundle{Grants: []BundleGrant{}}
	for _, g := range src.Grants {
		b.Grants = append(b.Grants, BundleGrant{
			Name:              g.Name(),
			Account:           g.Spec.Account,
			BaseRole:          g.Spec.BaseRole,
			SessionPolicy:     rendered[g.Name()],
			ManagedPolicyArns: nonNil(g.Spec.ManagedPolicyArns),
			SessionTags:       nonNilMap(g.Spec.SessionTags),
			Duration:          g.Spec.EffectiveDuration(),
			Envelope:          nonNil(g.Spec.Envelope),
		})
	}
	sort.Slice(b.Grants, func(i, j int) bool { return b.Grants[i].Name < b.Grants[j].Name })
	b.Version = opts.Version
	if b.Version == "" {
		v, err := ContentVersion(b.Grants)
		if err != nil {
			return nil, nil, err
		}
		b.Version = v
	}
	if !versionRE.MatchString(b.Version) {
		return nil, nil, fmt.Errorf("version %q: must match %s", b.Version, versionRE)
	}
	at := opts.GeneratedAt
	if at.IsZero() {
		at = time.Now()
	}
	b.GeneratedAt = at.UTC().Format(time.RFC3339)
	return b, report, nil
}

// ContentVersion is the SHA-256, in hex, of the canonical JSON of the
// grants: the version of a bundle whose sources carry no version of their
// own.
func ContentVersion(grants []BundleGrant) (string, error) {
	data, err := canonical(grants)
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
	if !versionRE.MatchString(b.Version) {
		return nil, fmt.Errorf("bundle: version %q: must match %s", b.Version, versionRE)
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
