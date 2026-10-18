package e2e

import (
	"os"
	"reflect"
	"slices"
	"testing"

	"github.com/bpalermo/cracha/common/grant"
	"gopkg.in/yaml.v3"
)

// The suite's two authorization sources say the same thing: the static
// backend reads the assignments document of e2e/values.yaml, SpiceDB holds
// what cracha-reconciler wrote from e2e/grants (E2E_AUTHZ in e2e/run.sh),
// and the tests that run in both modes expect one answer. Both files are
// data of the test; this reads them from the package directory.
const valuesFile = "values.yaml"

// assignments is the common shape of the two: the static document's
// (broker/internal/authz/static) services and workloads, keyed by name and
// subject, with the bounds every grant may carry.
type assignments struct {
	Services  map[string]service
	Workloads map[string]workload
}

type service struct {
	Team    string
	Members []string
	Grants  []bounded
}

type workload struct {
	Suspended bool
	Grants    []bounded
}

type bounded struct {
	Name      string   `yaml:"name"`
	ExpiresAt string   `yaml:"expiresAt"`
	Clusters  []string `yaml:"clusters"`
}

// staticDocument is broker.assignments.document as e2e/values.yaml holds
// it: the static backend's file, with the fields that exist today.
type staticDocument struct {
	Services []struct {
		Name    string    `yaml:"name"`
		Team    string    `yaml:"team"`
		Members []string  `yaml:"members"`
		Grants  []bounded `yaml:"grants"`
	} `yaml:"services"`
	Workloads []struct {
		Subject   string    `yaml:"subject"`
		Suspended bool      `yaml:"suspended"`
		Grants    []bounded `yaml:"grants"`
	} `yaml:"workloads"`
}

func (b bounded) canonical() bounded {
	b.Clusters = slices.Clone(b.Clusters)
	slices.Sort(b.Clusters)
	if len(b.Clusters) == 0 {
		b.Clusters = nil
	}
	return b
}

func canonicalGrants(gs []bounded) []bounded {
	out := make([]bounded, 0, len(gs))
	for _, g := range gs {
		out = append(out, g.canonical())
	}
	slices.SortFunc(out, func(a, b bounded) int { return compareStrings(a.Name, b.Name) })
	return out
}

func compareStrings(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func canonicalMembers(ms []string) []string {
	out := slices.Clone(ms)
	slices.Sort(out)
	return out
}

// fromValues reads the static document out of the chart values.
func fromValues(t *testing.T) assignments {
	t.Helper()
	raw, err := os.ReadFile(valuesFile)
	if err != nil {
		t.Fatal(err)
	}
	var values struct {
		Broker struct {
			Assignments struct {
				Document staticDocument `yaml:"document"`
			} `yaml:"assignments"`
		} `yaml:"broker"`
	}
	if err := yaml.Unmarshal(raw, &values); err != nil {
		t.Fatalf("decoding %s: %v", valuesFile, err)
	}
	doc := values.Broker.Assignments.Document
	a := assignments{Services: map[string]service{}, Workloads: map[string]workload{}}
	for _, s := range doc.Services {
		a.Services[s.Name] = service{Team: s.Team, Members: canonicalMembers(s.Members), Grants: canonicalGrants(s.Grants)}
	}
	for _, w := range doc.Workloads {
		a.Workloads[w.Subject] = workload{Suspended: w.Suspended, Grants: canonicalGrants(w.Grants)}
	}
	return a
}

// fromSource reads the same out of the grant source tree: its Services as
// they are, its Assignments merged per subject the way the reconciler and
// the lints see them.
func fromSource(t *testing.T) assignments {
	t.Helper()
	src, err := grant.Load(grantSource)
	if err != nil {
		t.Fatalf("loading %s: %v", grantSource, err)
	}
	a := assignments{Services: map[string]service{}, Workloads: map[string]workload{}}
	for _, s := range src.Services {
		var gs []bounded
		for _, g := range s.Spec.Grants {
			gs = append(gs, bounded{Name: g.Name, ExpiresAt: g.ExpiresAt, Clusters: g.Clusters})
		}
		a.Services[s.Name()] = service{Team: s.Spec.Team, Members: canonicalMembers(s.Spec.Members), Grants: canonicalGrants(gs)}
	}
	for _, as := range src.Assignments {
		w := a.Workloads[as.Spec.Subject]
		w.Suspended = w.Suspended || as.Spec.Suspended
		for _, g := range as.Spec.Grants {
			w.Grants = append(w.Grants, bounded{Name: g, ExpiresAt: as.Spec.ExpiresAt, Clusters: as.Spec.Clusters})
		}
		w.Grants = canonicalGrants(w.Grants)
		a.Workloads[as.Spec.Subject] = w
	}
	return a
}

func TestStaticAssignmentsMatchGrantSource(t *testing.T) {
	static, source := fromValues(t), fromSource(t)
	if !reflect.DeepEqual(static, source) {
		t.Fatalf("broker.assignments.document in %s and the Services and Assignments of %s disagree:\nvalues:  %+v\nsource:  %+v",
			valuesFile, grantSource, static, source)
	}
	if len(static.Services) == 0 {
		t.Fatal("no service in either; the suite's assigned workload must hold a grant through one")
	}
}
