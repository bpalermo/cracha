package grants

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const fixture = `
version: dev-1
grants:
  - name: payments-ledger-rw
    account: "111122223333"
    baseRole: arn:aws:iam::111122223333:role/broker/shape-dynamo-rw
    sessionPolicy:
      Version: "2012-10-17"
      Statement:
        - Effect: Allow
          Action: [dynamodb:GetItem, dynamodb:PutItem]
          Resource: arn:aws:dynamodb:*:111122223333:table/payments-ledger
    sessionTags: {team: payments}
    durationSeconds: 3600
    envelope:
      - arn:aws:dynamodb:*:111122223333:table/payments-*
  - name: payments-outbox-r
    account: "111122223333"
    baseRole: arn:aws:iam::111122223333:role/broker/shape-dynamo-rw
    sessionPolicy: '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"dynamodb:Query","Resource":"arn:aws:dynamodb:*:111122223333:table/payments-outbox"}]}'
    managedPolicyArns: [arn:aws:iam::111122223333:policy/outbox]
    envelope:
      - arn:aws:dynamodb:*:111122223333:table/payments-*
  - name: managed-only
    account: "111122223333"
    baseRole: arn:aws:iam::111122223333:role/broker/shape-dynamo-rw
    managedPolicyArns: [arn:aws:iam::111122223333:policy/managed]
`

func TestLoadFixture(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grants.yaml")
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := LoadFixture(path)
	if err != nil {
		t.Fatal(err)
	}
	if src.Version() != "dev-1" {
		t.Errorf("version %q", src.Version())
	}
	if !reflect.DeepEqual(src.Names(), []string{"managed-only", "payments-ledger-rw", "payments-outbox-r"}) {
		t.Errorf("names %v", src.Names())
	}

	ledger, ok := src.Lookup("payments-ledger-rw")
	if !ok {
		t.Fatal("ledger missing")
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(ledger.SessionPolicy), &doc); err != nil {
		t.Fatalf("mapping policy %q: %v", ledger.SessionPolicy, err)
	}
	if doc["Version"] != "2012-10-17" {
		t.Errorf("policy %s", ledger.SessionPolicy)
	}
	if ledger.SessionTags["team"] != "payments" || ledger.DurationSeconds != 3600 || len(ledger.Envelope) != 1 {
		t.Errorf("ledger %+v", ledger)
	}

	outbox, _ := src.Lookup("payments-outbox-r")
	if outbox.SessionPolicy == "" || !json.Valid([]byte(outbox.SessionPolicy)) {
		t.Errorf("string policy %q", outbox.SessionPolicy)
	}
	managed, _ := src.Lookup("managed-only")
	if managed.SessionPolicy != "" {
		t.Errorf("absent policy gave %q", managed.SessionPolicy)
	}

	// The fixture composes through the same path as everything else.
	c, err := Compose(src, []string{"payments-ledger-rw", "payments-outbox-r"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Shape != "shape-dynamo-rw" {
		t.Errorf("shape %q", c.Shape)
	}
}

func TestParseFixtureRejects(t *testing.T) {
	base := "version: v\ngrants:\n  - name: g\n    account: '1'\n    baseRole: r\n"
	tests := map[string]string{
		"no version":       "grants: []\n",
		"unknown field":    base + "    colour: blue\n",
		"no name":          "version: v\ngrants:\n  - account: '1'\n    baseRole: r\n",
		"no role":          "version: v\ngrants:\n  - name: g\n    account: '1'\n",
		"twice":            base + "  - name: g\n    account: '1'\n    baseRole: r\n",
		"policy not json":  base + "    sessionPolicy: 'not json'\n",
		"policy is a list": base + "    sessionPolicy: [a]\n",
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseFixture([]byte(in)); err == nil {
				t.Fatalf("accepted:\n%s", in)
			}
		})
	}
	if _, err := LoadFixture(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("loaded a missing file")
	}
}
