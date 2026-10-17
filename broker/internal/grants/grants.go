// Package grants is what the broker needs from the compiled grant bundle
// (docs/design.md, sections 6.1 and 6.2), as a contract: a [Source] that
// resolves a grant by name, and [Compose], which turns the set of grants a
// workload holds into the one shape, session policy, managed policies, tags
// and duration of its credential.
//
// This package parses neither grant YAML nor the compiled bundle. The
// compiler lives in common/grant, and broker/internal/bundle is the [Source]
// over its published bundle, with polling and signature verification. The
// in-memory [Static] source serves wiring and tests, and [LoadFixture] reads
// a development fixture of already resolved grants.
package grants

import (
	"sort"
	"strings"
	"sync"
)

// ResolvedGrant is one grant after rendering: everything the broker passes
// to STS, plus the envelope the rendered policy is checked against.
type ResolvedGrant struct {
	// Name is the grant's name, as assigned in the authorization store.
	Name string
	// Account is the AWS account of the shape role.
	Account string
	// BaseRole is the ARN of the shape role. Every grant a workload holds
	// must name the same one.
	BaseRole string
	// SessionPolicy is the rendered inline session policy as a JSON
	// document, or empty when the grant adds no inline statements.
	SessionPolicy string
	// ManagedPolicyARNs are the managed session policies to attach.
	ManagedPolicyARNs []string
	// SessionTags are the grant's session tags; only "team" and "service"
	// are allowed (section 6.6 names the full set of keys).
	SessionTags map[string]string
	// DurationSeconds is the session duration; 0 means the default.
	DurationSeconds int32
	// Envelope are the ARN patterns (with * and ? wildcards) every Resource
	// of the rendered policy must match.
	Envelope []string
}

// Source resolves grants by name.
type Source interface {
	// Lookup returns the grant and whether it exists.
	Lookup(name string) (ResolvedGrant, bool)
	// Version identifies the bundle the grants came from; it is reported
	// in Cracha-Bundle-Version.
	Version() string
}

// Static is an in-memory Source.
type Static struct {
	mu      sync.RWMutex
	version string
	grants  map[string]ResolvedGrant
}

// NewStatic returns a Source holding the given grants under a version.
func NewStatic(version string, grants ...ResolvedGrant) *Static {
	s := &Static{version: version, grants: map[string]ResolvedGrant{}}
	for _, g := range grants {
		s.grants[g.Name] = g
	}
	return s
}

// Lookup implements Source.
func (s *Static) Lookup(name string) (ResolvedGrant, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	g, ok := s.grants[name]
	return g, ok
}

// Version implements Source.
func (s *Static) Version() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.version
}

// Replace swaps the whole grant set and version atomically, the way a
// bundle poller will.
func (s *Static) Replace(version string, grants ...ResolvedGrant) {
	m := make(map[string]ResolvedGrant, len(grants))
	for _, g := range grants {
		m[g.Name] = g
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.version, s.grants = version, m
}

// Names returns the grant names, sorted.
func (s *Static) Names() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := make([]string, 0, len(s.grants))
	for n := range s.grants {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ShapeName returns the shape's short name from its role ARN: the last path
// element, so arn:aws:iam::111122223333:role/broker/shape-dynamo-rw gives
// shape-dynamo-rw. An ARN without a path gives itself.
func ShapeName(roleARN string) string {
	if i := strings.LastIndex(roleARN, "/"); i >= 0 {
		return roleARN[i+1:]
	}
	return roleARN
}
