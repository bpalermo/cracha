package bundle

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/bpalermo/cracha/common/grant"
)

// testAssignments is an assignments document of one service holding the
// given grants, under the given version.
func testAssignments(t *testing.T, version string, grants ...string) []byte {
	t.Helper()
	a := &grant.Assignments{Version: version, GeneratedAt: "2026-01-01T00:00:00Z", Services: []grant.AssignedService{{
		Name: "payments-api", Team: "payments", Members: []string{"prod/payments/ledger"}, Grants: []grant.BoundedGrant{},
	}}, Workloads: []grant.AssignedWorkload{}}
	for _, g := range grants {
		a.Services[0].Grants = append(a.Services[0].Grants, grant.BoundedGrant{Name: g})
	}
	data, err := grant.MarshalAssignments(a)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// publishPair signs both documents with key (the publication's own unless
// another is given; assignmentsKey likewise for the assignments alone) and
// publishes them as one version.
func (p *publication) publishPair(t *testing.T, bundle, assignments []byte, assignmentsKey *ecdsa.PrivateKey) {
	t.Helper()
	sign := func(key *ecdsa.PrivateKey, data []byte) *grant.Signature {
		if key == nil {
			key = p.key
		}
		signer, err := grant.NewLocalSigner(key)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := signer.Sign(context.Background(), data)
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
	pub := grant.Publication{Bundle: bundle, BundleSignature: sign(nil, bundle), Assignments: assignments, AssignmentsSignature: sign(assignmentsKey, assignments)}
	if _, err := (&grant.LocalPublisher{Root: p.root}).Publish(context.Background(), pub); err != nil {
		t.Fatal(err)
	}
}

// sink records what the source prepares and commits.
type sink struct {
	prepared  []string
	committed []string
	err       error
}

func (s *sink) Prepare(a *grant.Assignments, data []byte) (func(), error) {
	if s.err != nil {
		return nil, s.err
	}
	if !bytes.Equal(data, mustAssignments(a)) {
		return nil, errors.New("data is not the document's bytes")
	}
	s.prepared = append(s.prepared, a.Version)
	return func() { s.committed = append(s.committed, a.Version) }, nil
}

func mustAssignments(a *grant.Assignments) []byte {
	data, _ := grant.MarshalAssignments(a)
	return data
}

func (p *publication) sourceWith(buf *bytes.Buffer, s AssignmentsSink) *Source {
	return New(&Local{Root: p.root}, p.verifier, Options{Log: slog.New(slog.NewTextHandler(buf, nil)), Assignments: s})
}

func TestLoadsBundleAndAssignmentsTogether(t *testing.T) {
	pub := newPublication(t)
	pub.publishPair(t, testBundle(t, "v1", "payments-ledger-rw"), testAssignments(t, "v1", "payments-ledger-rw"), nil)
	var logs bytes.Buffer
	sk := &sink{}
	src := pub.sourceWith(&logs, sk)
	if err := src.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := src.Ready(); err != nil || src.Version() != "v1" {
		t.Errorf("Ready = %v, Version = %q", err, src.Version())
	}
	if strings.Join(sk.committed, ",") != "v1" {
		t.Errorf("committed = %v", sk.committed)
	}
	if !strings.Contains(logs.String(), "workloads=0") || !strings.Contains(logs.String(), "services=1") {
		t.Errorf("load not logged with the assignments: %s", logs.String())
	}
	// The same version again commits nothing new.
	if err := src.Reload(context.Background()); err != nil || len(sk.committed) != 1 {
		t.Errorf("reload of the same version: %v, committed %v", err, sk.committed)
	}
	// A new version swaps both.
	pub.publishPair(t, testBundle(t, "v2", "payments-ledger-rw"), testAssignments(t, "v2"), nil)
	if err := src.Reload(context.Background()); err != nil || src.Version() != "v2" || strings.Join(sk.committed, ",") != "v1,v2" {
		t.Errorf("reload of v2: %v, version %q, committed %v", err, src.Version(), sk.committed)
	}
}

// A source without a sink does not read the assignments: a version
// published without them, or with broken ones, loads.
func TestAssignmentsUnreadWithoutSink(t *testing.T) {
	pub := newPublication(t)
	pub.publishPair(t, testBundle(t, "v1", "g"), testAssignments(t, "v1"), nil)
	assignmentsKey, sigKey := grant.AssignmentsKeys("v1")
	pub.overwrite(t, assignmentsKey, []byte("junk"))
	pub.overwrite(t, sigKey, []byte("junk"))
	src := pub.source(&bytes.Buffer{})
	if err := src.Reload(context.Background()); err != nil || src.Version() != "v1" {
		t.Errorf("Reload = %v, version %q", err, src.Version())
	}
}

// Whatever is wrong with a version's assignments, the version is rejected
// whole: neither its bundle nor its assignments go in service, the pair in
// service stays, and before a first pair the source is not ready.
func TestAssignmentsFailureKeepsThePair(t *testing.T) {
	stranger, err := grant.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		publish func(t *testing.T, pub *publication)
		sinkErr error
		want    string
	}{
		{"missing", func(t *testing.T, pub *publication) { pub.publish(t, testBundle(t, "v2", "g"), nil) }, nil, "publishes no readable assignments"},
		{"signed by another key", func(t *testing.T, pub *publication) {
			pub.publishPair(t, testBundle(t, "v2", "g"), testAssignments(t, "v2"), stranger)
		}, nil, "assignments: signature"},
		{"another version", func(t *testing.T, pub *publication) {
			pub.publishPair(t, testBundle(t, "v2", "g"), testAssignments(t, "v2"), nil)
			v3 := testAssignments(t, "v3")
			signer, _ := grant.NewLocalSigner(pub.key)
			sig, _ := signer.Sign(context.Background(), v3)
			sigData, _ := sig.Marshal()
			key, sigKey := grant.AssignmentsKeys("v2")
			pub.overwrite(t, key, v3)
			pub.overwrite(t, sigKey, sigData)
		}, nil, `assignments say version "v3"`},
		{"refused by the store", func(t *testing.T, pub *publication) {
			pub.publishPair(t, testBundle(t, "v2", "g"), testAssignments(t, "v2"), nil)
		}, errors.New("workload listed twice"), "workload listed twice"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Before a first pair: not ready.
			pub := newPublication(t)
			tt.publish(t, pub)
			sk := &sink{err: tt.sinkErr}
			src := pub.sourceWith(&bytes.Buffer{}, sk)
			if err := src.Reload(context.Background()); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("first Reload = %v, want %q", err, tt.want)
			}
			if err := src.Ready(); !errors.Is(err, errNotLoaded) || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Ready = %v", err)
			}
			if src.Version() != "" || len(sk.committed) != 0 {
				t.Errorf("version %q, committed %v", src.Version(), sk.committed)
			}

			// After a good pair: the pair stays.
			pub = newPublication(t)
			pub.publishPair(t, testBundle(t, "v1", "g"), testAssignments(t, "v1", "g"), nil)
			sk = &sink{}
			src = pub.sourceWith(&bytes.Buffer{}, sk)
			if err := src.Reload(context.Background()); err != nil {
				t.Fatal(err)
			}
			tt.publish(t, pub)
			sk.err = tt.sinkErr
			if err := src.Reload(context.Background()); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Reload = %v, want %q", err, tt.want)
			}
			if src.Version() != "v1" || strings.Join(sk.committed, ",") != "v1" || src.Ready() != nil {
				t.Errorf("version %q, committed %v, ready %v; want v1 kept", src.Version(), sk.committed, src.Ready())
			}
		})
	}
}
