// Package static is the "static" authorization backend of docs/design.md,
// section 6.3: assignments held in memory, loaded from a file, for
// bootstrap, air-gapped or tiny installs. Signature verification of the file
// is not part of this slice; the file's SHA-256 is its consistency token.
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
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/bpalermo/cracha/broker/internal/authz"
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

// Option configures a Store.
type Option func(*Store)

// WithClock sets the clock that time-bounded assignments are evaluated
// against. The default is time.Now.
func WithClock(now func() time.Time) Option {
	return func(s *Store) { s.now = now }
}

// Store is the static backend. It implements authz.Store.
type Store struct {
	token     authz.Token
	now       func() time.Time
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
	sum := sha256.Sum256(data)
	return New(f, authz.Token(hex.EncodeToString(sum[:])), opts...)
}

// New builds a store from an already parsed file and the token to report.
func New(f File, token authz.Token, opts ...Option) (*Store, error) {
	s := &Store{token: token, now: time.Now, workloads: map[string]*workload{}}
	for _, o := range opts {
		o(s)
	}
	for i, svc := range f.Services {
		if svc.Name == "" {
			return nil, fmt.Errorf("services[%d]: name is required", i)
		}
		as, err := convert(svc.Grants, "service "+svc.Name)
		if err != nil {
			return nil, fmt.Errorf("service %q: %w", svc.Name, err)
		}
		for _, member := range svc.Members {
			if member == "" {
				return nil, fmt.Errorf("service %q: empty member", svc.Name)
			}
			w := s.workload(member)
			if w.service != "" {
				return nil, fmt.Errorf("workload %q is a member of services %q and %q; at most one is allowed", member, w.service, svc.Name)
			}
			w.service, w.team = svc.Name, svc.Team
			w.assignments = append(w.assignments, as...)
		}
	}
	seen := map[string]bool{}
	for i, wl := range f.Workloads {
		if wl.Subject == "" {
			return nil, fmt.Errorf("workloads[%d]: subject is required", i)
		}
		if seen[wl.Subject] {
			return nil, fmt.Errorf("workload %q listed twice", wl.Subject)
		}
		seen[wl.Subject] = true
		as, err := convert(wl.Grants, "workload")
		if err != nil {
			return nil, fmt.Errorf("workload %q: %w", wl.Subject, err)
		}
		w := s.workload(wl.Subject)
		w.suspended = wl.Suspended
		w.assignments = append(w.assignments, as...)
	}
	return s, nil
}

func (s *Store) workload(subject string) *workload {
	w, ok := s.workloads[subject]
	if !ok {
		w = &workload{}
		s.workloads[subject] = w
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

// Token returns the store's consistency token.
func (s *Store) Token() authz.Token {
	return s.token
}

func (s *Store) checkConsistency(c authz.Consistency) error {
	if c.AtLeastAsFresh != "" && c.AtLeastAsFresh != s.token {
		return fmt.Errorf("static: cannot answer at least as fresh as %q: this store is at %q", c.AtLeastAsFresh, s.token)
	}
	return nil
}

// ListGrants implements authz.Store.
func (s *Store) ListGrants(ctx context.Context, subject authz.Subject, c authz.Consistency) (authz.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authz.Decision{}, err
	}
	if err := s.checkConsistency(c); err != nil {
		return authz.Decision{}, err
	}
	d := authz.Decision{Token: s.token, Tags: map[string]string{}}
	w, ok := s.workloads[subject.ID]
	if !ok {
		d.Trace = append(d.Trace, "subject "+subject.ID+" is not in the assignments file")
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
