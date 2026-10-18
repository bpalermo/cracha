// Package static is the "static" authorization backend of docs/design.md,
// section 6.3: assignments held in memory, for bootstrap, air-gapped or
// tiny installs, from one of two sources. A file (Load), read once, for
// development, whose SHA-256 is the consistency token. Or the assignments
// document of the signed publication the grant bundle comes from
// (common/grant's Assignments, converted by FromAssignments), which the
// bundle poller verifies and hands to Swap with the bundle of the same
// version; the token is then the SHA-256 of the published bytes, so every
// swap is a new token, and Watch reports each swap as a change of every
// subject.
//
// The file is YAML (JSON is YAML, so a JSON file works too) with this shape:
//
//	services:
//	  - name: payments-api            # the service, also the "service" tag
//	    team: payments                # the "team" tag
//	    members:                      # workload subjects (idenc authz encoding)
//	      - prod/payments/ledger
//	    grants:                       # assigned to every member
//	      - name: payments-ledger-rw
//	        clusters: [prod-us-east-1]          # optional: only in these clusters
//	        expiresAt: "2026-12-31T00:00:00Z"   # optional: RFC 3339, exclusive
//	workloads:
//	  - subject: prod/payments/ledger
//	    suspended: false              # true: holds nothing, "subject_suspended"
//	    grants:                       # assigned to this workload alone
//	      - name: payments-outbox-r
//	        expiresAt: "2026-12-31T00:00:00Z"
//
// Both assignment forms take both conditions. A workload is a member of at
// most one service. Unknown fields are an error. Time-bounded and
// cluster-bounded assignments are evaluated here, at every call, against the
// subject's cluster and the clock.
package static

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bpalermo/cracha/broker/internal/authz"
	"github.com/bpalermo/cracha/common/grant"
	"gopkg.in/yaml.v3"
)

// File is the assignments file.
type File struct {
	Services  []Service  `yaml:"services"`
	Workloads []Workload `yaml:"workloads"`
}

// Service groups workloads that share grants and tags.
type Service struct {
	Name    string       `yaml:"name"`
	Team    string       `yaml:"team"`
	Members []string     `yaml:"members"`
	Grants  []Assignment `yaml:"grants"`
}

// Workload holds direct assignments and the suspension flag of one subject.
type Workload struct {
	Subject   string       `yaml:"subject"`
	Suspended bool         `yaml:"suspended"`
	Grants    []Assignment `yaml:"grants"`
}

// Assignment assigns one grant, optionally bounded by cluster and time.
type Assignment struct {
	Name      string   `yaml:"name"`
	Clusters  []string `yaml:"clusters"`
	ExpiresAt string   `yaml:"expiresAt"`
}

// FromAssignments is the published assignments document as the file it
// stands for: field for field, the version and generatedAt left out.
func FromAssignments(a *grant.Assignments) File {
	f := File{Services: make([]Service, 0, len(a.Services)), Workloads: make([]Workload, 0, len(a.Workloads))}
	for _, s := range a.Services {
		f.Services = append(f.Services, Service{Name: s.Name, Team: s.Team, Members: s.Members, Grants: fromBounded(s.Grants)})
	}
	for _, w := range a.Workloads {
		f.Workloads = append(f.Workloads, Workload{Subject: w.Subject, Suspended: w.Suspended, Grants: fromBounded(w.Grants)})
	}
	return f
}

func fromBounded(gs []grant.BoundedGrant) []Assignment {
	out := make([]Assignment, 0, len(gs))
	for _, g := range gs {
		out = append(out, Assignment{Name: g.Name, Clusters: g.Clusters, ExpiresAt: g.ExpiresAt})
	}
	return out
}

// Option configures a Store.
type Option func(*Store)

// WithClock sets the clock that time-bounded assignments are evaluated
// against. The default is time.Now.
func WithClock(now func() time.Time) Option {
	return func(s *Store) { s.now = now }
}

// Store is the static backend. It implements authz.Store and
// authz.Watcher.
type Store struct {
	now     func() time.Time
	current atomic.Pointer[Snapshot]

	// mu guards the watchers.
	mu       sync.Mutex
	watchers map[chan authz.Change]struct{}
}

// Snapshot is one set of assignments, built and checked ahead of the swap
// that puts it in service, and immutable after.
type Snapshot struct {
	token     authz.Token
	workloads map[string]*workload
}

type workload struct {
	suspended   bool
	service     string
	team        string
	assignments []assignment
}

type assignment struct {
	grant     string
	source    string // "service <name>" or "workload"
	clusters  []string
	expiresAt time.Time // zero: unbounded
}

// Load reads and parses an assignments file.
func Load(path string, opts ...Option) (*Store, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("static: %w", err)
	}
	s, err := Parse(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("static: %s: %w", path, err)
	}
	return s, nil
}

// Parse parses the contents of an assignments file. The consistency token
// of the store is the hex SHA-256 of data.
func Parse(data []byte, opts ...Option) (*Store, error) {
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	return New(f, TokenOf(data), opts...)
}

// TokenOf is the consistency token of a document: its hex SHA-256.
func TokenOf(data []byte) authz.Token {
	sum := sha256.Sum256(data)
	return authz.Token(hex.EncodeToString(sum[:]))
}

// New builds a store from an already parsed file and the token to report.
func New(f File, token authz.Token, opts ...Option) (*Store, error) {
	snap, err := Build(f, token)
	if err != nil {
		return nil, err
	}
	s := NewEmpty(opts...)
	s.current.Store(snap)
	return s, nil
}

// NewEmpty makes a store that holds no assignments until the first Swap:
// until then every question is answered with an error, which is a deny.
func NewEmpty(opts ...Option) *Store {
	s := &Store{now: time.Now, watchers: map[chan authz.Change]struct{}{}}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Build checks a file and makes the snapshot a Swap puts in service.
func Build(f File, token authz.Token) (*Snapshot, error) {
	snap := &Snapshot{token: token, workloads: map[string]*workload{}}
	if err := snap.addServices(f.Services); err != nil {
		return nil, err
	}
	if err := snap.addWorkloads(f.Workloads); err != nil {
		return nil, err
	}
	return snap, nil
}

// Token returns the snapshot's consistency token.
func (snap *Snapshot) Token() authz.Token { return snap.token }

// Swap puts a snapshot in service, atomically: a question is answered
// wholly from the old snapshot or wholly from the new one. Every watcher
// is told that every subject may have changed.
func (s *Store) Swap(snap *Snapshot) {
	old := s.current.Swap(snap)
	if old != nil && old.token == snap.token {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.watchers {
		notify(ch, authz.Change{Token: snap.token})
	}
}

// Prepare builds the snapshot of a published assignments document (data
// is its bytes, whose SHA-256 is the snapshot's token) and returns the
// Swap that puts it in service: the bundle source's assignments sink
// (broker/internal/bundle), which commits it together with the bundle of
// the same version.
func (s *Store) Prepare(a *grant.Assignments, data []byte) (func(), error) {
	snap, err := Build(FromAssignments(a), TokenOf(data))
	if err != nil {
		return nil, err
	}
	return func() { s.Swap(snap) }, nil
}

// notify sends a change without blocking. A watcher's buffer holds one
// change; one already waiting there says what a second would (every
// subject changed), so the second is dropped.
func notify(ch chan authz.Change, c authz.Change) {
	select {
	case ch <- c:
	default:
	}
}

// Watch implements authz.Watcher: a change naming no subject, which the
// cache takes as every subject, after each Swap, and at once when the
// store is no longer at since (a swap the caller missed). The channel
// closes when ctx ends.
func (s *Store) Watch(ctx context.Context, since authz.Token) (<-chan authz.Change, error) {
	ch := make(chan authz.Change, 1)
	s.mu.Lock()
	s.watchers[ch] = struct{}{}
	if cur := s.current.Load(); since != "" && cur != nil && cur.token != since {
		notify(ch, authz.Change{Token: cur.token})
	}
	s.mu.Unlock()
	out := make(chan authz.Change)
	go func() {
		defer close(out)
		defer func() {
			s.mu.Lock()
			delete(s.watchers, ch)
			s.mu.Unlock()
		}()
		for {
			select {
			case <-ctx.Done():
				return
			case c := <-ch:
				select {
				case out <- c:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out, nil
}

// addServices loads the services section: every member of a service takes
// its name and team as tags and its grants as assignments.
func (snap *Snapshot) addServices(services []Service) error {
	for i, svc := range services {
		if svc.Name == "" {
			return fmt.Errorf("services[%d]: name is required", i)
		}
		as, err := convert(svc.Grants, "service "+svc.Name)
		if err != nil {
			return fmt.Errorf("service %q: %w", svc.Name, err)
		}
		for _, member := range svc.Members {
			if err := snap.addMember(svc, member, as); err != nil {
				return err
			}
		}
	}
	return nil
}

// addMember enrols one member in a service. A workload is a member of at
// most one service.
func (snap *Snapshot) addMember(svc Service, member string, as []assignment) error {
	if member == "" {
		return fmt.Errorf("service %q: empty member", svc.Name)
	}
	w := snap.workload(member)
	if w.service != "" {
		return fmt.Errorf("workload %q is a member of services %q and %q; at most one is allowed", member, w.service, svc.Name)
	}
	w.service, w.team = svc.Name, svc.Team
	w.assignments = append(w.assignments, as...)
	return nil
}

// addWorkloads loads the workloads section: direct assignments and the
// suspension flag, each subject listed at most once.
func (snap *Snapshot) addWorkloads(workloads []Workload) error {
	seen := map[string]bool{}
	for i, wl := range workloads {
		if wl.Subject == "" {
			return fmt.Errorf("workloads[%d]: subject is required", i)
		}
		if seen[wl.Subject] {
			return fmt.Errorf("workload %q listed twice", wl.Subject)
		}
		seen[wl.Subject] = true
		as, err := convert(wl.Grants, "workload")
		if err != nil {
			return fmt.Errorf("workload %q: %w", wl.Subject, err)
		}
		w := snap.workload(wl.Subject)
		w.suspended = wl.Suspended
		w.assignments = append(w.assignments, as...)
	}
	return nil
}

func (snap *Snapshot) workload(subject string) *workload {
	w, ok := snap.workloads[subject]
	if !ok {
		w = &workload{}
		snap.workloads[subject] = w
	}
	return w
}

func convert(in []Assignment, source string) ([]assignment, error) {
	out := make([]assignment, 0, len(in))
	for i, a := range in {
		if a.Name == "" {
			return nil, fmt.Errorf("grants[%d]: name is required", i)
		}
		conv := assignment{grant: a.Name, source: source, clusters: append([]string(nil), a.Clusters...)}
		if a.ExpiresAt != "" {
			t, err := time.Parse(time.RFC3339, a.ExpiresAt)
			if err != nil {
				return nil, fmt.Errorf("grant %q: expiresAt: %w", a.Name, err)
			}
			conv.expiresAt = t
		}
		out = append(out, conv)
	}
	return out, nil
}

// errEmpty is the answer of a store that holds no assignments yet.
var errEmpty = errors.New("static: no assignments loaded yet")

// Token returns the store's consistency token; empty before the first
// Swap.
func (s *Store) Token() authz.Token {
	if snap := s.current.Load(); snap != nil {
		return snap.token
	}
	return ""
}

// snapshot is the snapshot in service for a question at consistency c.
func (s *Store) snapshot(c authz.Consistency) (*Snapshot, error) {
	snap := s.current.Load()
	if snap == nil {
		return nil, errEmpty
	}
	if c.AtLeastAsFresh != "" && c.AtLeastAsFresh != snap.token {
		return nil, fmt.Errorf("static: cannot answer at least as fresh as %q: this store is at %q", c.AtLeastAsFresh, snap.token)
	}
	return snap, nil
}

// ListGrants implements authz.Store.
func (s *Store) ListGrants(ctx context.Context, subject authz.Subject, c authz.Consistency) (authz.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authz.Decision{}, err
	}
	snap, err := s.snapshot(c)
	if err != nil {
		return authz.Decision{}, err
	}
	d := authz.Decision{Token: snap.token, Tags: map[string]string{}}
	w, ok := snap.workloads[subject.ID]
	if !ok {
		d.Trace = append(d.Trace, "subject "+subject.ID+" is not in the assignments")
		return d, nil
	}
	if w.suspended {
		return authz.Decision{}, fmt.Errorf("%w: %s", authz.ErrSubjectSuspended, subject.ID)
	}
	if w.service != "" {
		d.Tags["service"] = w.service
		d.Trace = append(d.Trace, "member of service "+w.service)
	}
	if w.team != "" {
		d.Tags["team"] = w.team
	}
	now := s.now()
	held := map[string]bool{}
	for _, a := range w.assignments {
		line, active := a.evaluate(subject.Cluster, now)
		d.Trace = append(d.Trace, line)
		if active {
			held[a.grant] = true
		}
	}
	for g := range held {
		d.Grants = append(d.Grants, g)
	}
	sort.Strings(d.Grants)
	return d, nil
}

// Check implements authz.Store.
func (s *Store) Check(ctx context.Context, subject authz.Subject, grant string, c authz.Consistency) (authz.CheckResult, error) {
	d, err := s.ListGrants(ctx, subject, c)
	if err != nil {
		return authz.CheckResult{}, err
	}
	r := authz.CheckResult{Token: d.Token, Trace: d.Trace}
	for _, g := range d.Grants {
		if g == grant {
			r.Allowed = true
		}
	}
	return r, nil
}

func (a assignment) evaluate(cluster string, now time.Time) (string, bool) {
	prefix := "grant " + a.grant + " via " + a.source + ": "
	if len(a.clusters) > 0 {
		in := false
		for _, c := range a.clusters {
			if c == cluster {
				in = true
			}
		}
		if !in {
			return prefix + "not for cluster " + cluster, false
		}
	}
	if !a.expiresAt.IsZero() && !now.Before(a.expiresAt) {
		return prefix + "expired at " + a.expiresAt.UTC().Format(time.RFC3339), false
	}
	return prefix + "active", true
}
