package grants

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Fixture is a development file of already resolved grants. It is not the
// compiled bundle of common/grant: no templates, no signature, no shapes
// section; the compiled bundle loader replaces it in a later slice. Shape:
//
//	version: dev-1
//	grants:
//	  - name: payments-ledger-rw
//	    account: "111122223333"
//	    baseRole: arn:aws:iam::111122223333:role/broker/shape-dynamo-rw
//	    sessionPolicy:                 # a JSON string, or the document as YAML
//	      Version: "2012-10-17"
//	      Statement:
//	        - Effect: Allow
//	          Action: [dynamodb:GetItem, dynamodb:PutItem]
//	          Resource: arn:aws:dynamodb:*:111122223333:table/payments-ledger
//	    managedPolicyArns: []
//	    sessionTags: {team: payments}
//	    durationSeconds: 3600
//	    envelope:
//	      - arn:aws:dynamodb:*:111122223333:table/payments-*
type Fixture struct {
	Version string         `yaml:"version"`
	Grants  []FixtureGrant `yaml:"grants"`
}

// FixtureGrant is one grant of a Fixture.
type FixtureGrant struct {
	Name              string            `yaml:"name"`
	Account           string            `yaml:"account"`
	BaseRole          string            `yaml:"baseRole"`
	SessionPolicy     yaml.Node         `yaml:"sessionPolicy"`
	ManagedPolicyARNs []string          `yaml:"managedPolicyArns"`
	SessionTags       map[string]string `yaml:"sessionTags"`
	DurationSeconds   int32             `yaml:"durationSeconds"`
	Envelope          []string          `yaml:"envelope"`
}

// LoadFixture reads a fixture file into a Static source.
func LoadFixture(path string) (*Static, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("grants: fixture: %w", err)
	}
	s, err := ParseFixture(data)
	if err != nil {
		return nil, fmt.Errorf("grants: fixture %s: %w", path, err)
	}
	return s, nil
}

// ParseFixture parses the contents of a fixture file.
func ParseFixture(data []byte) (*Static, error) {
	var f Fixture
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, err
	}
	if f.Version == "" {
		return nil, fmt.Errorf("version is required")
	}
	seen := map[string]bool{}
	resolved := make([]ResolvedGrant, 0, len(f.Grants))
	for i, g := range f.Grants {
		if g.Name == "" {
			return nil, fmt.Errorf("grants[%d]: name is required", i)
		}
		if seen[g.Name] {
			return nil, fmt.Errorf("grant %q listed twice", g.Name)
		}
		seen[g.Name] = true
		if g.BaseRole == "" || g.Account == "" {
			return nil, fmt.Errorf("grant %q: account and baseRole are required", g.Name)
		}
		policy, err := policyJSON(g.SessionPolicy)
		if err != nil {
			return nil, fmt.Errorf("grant %q: sessionPolicy: %w", g.Name, err)
		}
		resolved = append(resolved, ResolvedGrant{
			Name:              g.Name,
			Account:           g.Account,
			BaseRole:          g.BaseRole,
			SessionPolicy:     policy,
			ManagedPolicyARNs: g.ManagedPolicyARNs,
			SessionTags:       g.SessionTags,
			DurationSeconds:   g.DurationSeconds,
			Envelope:          g.Envelope,
		})
	}
	return NewStatic(f.Version, resolved...), nil
}

// policyJSON renders a sessionPolicy node: absent or null gives "", a
// scalar is taken as a JSON string, a mapping is converted to JSON.
func policyJSON(n yaml.Node) (string, error) {
	switch n.Kind {
	case 0:
		return "", nil
	case yaml.ScalarNode:
		if n.Tag == "!!null" {
			return "", nil
		}
		if !json.Valid([]byte(n.Value)) {
			return "", fmt.Errorf("not valid JSON")
		}
		return n.Value, nil
	case yaml.MappingNode:
		var v map[string]any
		if err := n.Decode(&v); err != nil {
			return "", err
		}
		b, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		return string(b), nil
	default:
		return "", fmt.Errorf("must be a JSON string or a mapping")
	}
}
