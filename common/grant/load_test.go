package grant

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const goodDir = "testdata/good"

func loadGood(t *testing.T) *Source {
	t.Helper()
	src, err := Load(goodDir)
	if err != nil {
		t.Fatalf("Load(%s): %v", goodDir, err)
	}
	return src
}

func TestLoadGood(t *testing.T) {
	src := loadGood(t)

	var grants []string
	for _, g := range src.Grants {
		grants = append(grants, g.Name())
	}
	if got, want := strings.Join(grants, ","), "billing-reports,payments-ledger-rw,payments-outbox-r"; got != want {
		t.Errorf("grants = %s, want %s (sorted by name)", got, want)
	}
	var assignments []string
	for _, a := range src.Assignments {
		assignments = append(assignments, a.Name())
	}
	if got, want := strings.Join(assignments, ","), "batch-suspended,billing-reports,legacy-expired,payments-ledger,payments-ledger-temp"; got != want {
		t.Errorf("assignments = %s, want %s", got, want)
	}
	if len(src.Services) != 1 || src.Services[0].Name() != "payments-api" || src.Services[0].Path != filepath.Join("services", "payments-api.yaml") {
		t.Errorf("services = %+v, want payments-api", src.Services)
	}
	if svc := src.ServiceOf("prod/payments/api"); svc == nil || svc.Spec.Team != "payments" || len(svc.Spec.Members) != 2 ||
		len(svc.Spec.Grants) != 2 || svc.Spec.Grants[1].ExpiresAt != "2030-01-01T00:00:00Z" {
		t.Errorf("ServiceOf(prod/payments/api) = %+v", svc)
	}
	if src.ServiceOf("prod/payments/batch") != nil {
		t.Error("ServiceOf(prod/payments/batch) should be nil")
	}
	if suspended := src.Assignments[0]; !suspended.Spec.Suspended || len(suspended.Spec.Grants) != 0 {
		t.Errorf("batch-suspended spec = %+v", suspended.Spec)
	}
	if got, want := len(src.Templates), 2; got != want {
		t.Errorf("templates = %d, want %d", got, want)
	}
	if tmpl := src.Templates["dynamo-table-rw"]; tmpl == nil {
		t.Error("template dynamo-table-rw not loaded")
	} else if tmpl.Params["region"].Default == nil || tmpl.Params["region"].Default.String != "*" {
		t.Errorf("region default = %+v, want *", tmpl.Params["region"].Default)
	}

	g := src.Grant("payments-ledger-rw")
	if g == nil {
		t.Fatal("grant payments-ledger-rw not loaded")
	}
	if g.Path != filepath.Join("grants", "payments-ledger-rw.yaml") {
		t.Errorf("Path = %q", g.Path)
	}
	tables := g.Spec.SessionPolicy.Params["tables"]
	if !tables.IsList || strings.Join(tables.List, ",") != "payments-ledger,payments-ledger-outbox" {
		t.Errorf("tables = %+v", tables)
	}
	if g.Spec.SessionTags["team"] != "payments" || g.Spec.Duration != 3600 {
		t.Errorf("spec = %+v", g.Spec)
	}
	if got := src.Grant("billing-reports").Spec.EffectiveDuration(); got != 1800 {
		t.Errorf("billing-reports duration = %d, want 1800", got)
	}
	temp := src.Assignments[4]
	if temp.Spec.ExpiresAt != "2030-01-01T00:00:00Z" || len(temp.Spec.Clusters) != 1 {
		t.Errorf("payments-ledger-temp spec = %+v", temp.Spec)
	}
	if src.Grant("nope") != nil {
		t.Error("Grant(nope) should be nil")
	}
}

func TestLoadBad(t *testing.T) {
	tests := []struct {
		dir  string
		want string
	}{
		{"unknown-field", `unknown field "durationSeconds"`},
		{"unknown-kind", `unknown kind "Shape"`},
		{"duplicate-grant", `grant "payments-ledger-rw" already defined`},
		{"duplicate-service", `service "payments-api" already defined`},
		{"service-unknown-field", `unknown field "owner"`},
		{"bad-template", `unknown field "extra"`},
		{"no-name", "metadata.name is required"},
		{"stray-template-file", "only *.json templates belong under templates"},
	}
	for _, tt := range tests {
		t.Run(tt.dir, func(t *testing.T) {
			_, err := Load(filepath.Join("testdata/bad", tt.dir))
			if err == nil {
				t.Fatal("Load succeeded, want an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

// Problems found between documents are ValidateSource's, not Load's.
func TestValidateSourceReferences(t *testing.T) {
	tests := []struct {
		dir  string
		want string
	}{
		{"missing-template", `template "dynamo-table-rw" not found`},
		{"unknown-grant", `grant "nonexistent" not found`},
		{"service-unknown-grant", `service payments-api (services/a.yaml): grant "nonexistent" not found`},
		{"shared-member", `service payments-batch (services/b.yaml): "prod/payments/ledger" is already a member of service payments-api (services/a.yaml)`},
	}
	for _, tt := range tests {
		t.Run(tt.dir, func(t *testing.T) {
			src, err := Load(filepath.Join("testdata/bad", tt.dir))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			err = ValidateSource(src)
			if err == nil {
				t.Fatal("ValidateSource succeeded, want an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
	if err := ValidateSource(loadGood(t)); err != nil {
		t.Errorf("ValidateSource(good): %v", err)
	}
}

func TestLoadMissingDir(t *testing.T) {
	if _, err := Load("testdata/does-not-exist"); err == nil {
		t.Error("Load of a missing directory succeeded")
	}
}

// Problems the checked-in bad trees do not cover: a second definition of an
// assignment or a template, and a document that cannot be read.
func TestLoadDuplicatesAndUnreadable(t *testing.T) {
	const assignment = "kind: Assignment\nmetadata:\n  name: payments\nspec:\n  subject: prod/payments/ledger\n  grants: [payments-ledger-rw]\n"
	const template = `{"policy": {"Version": "2012-10-17"}}`
	write := func(t *testing.T, dir, name, content string) {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name  string
		setup func(t *testing.T, dir string)
		want  string
	}{
		{"duplicate assignment", func(t *testing.T, dir string) {
			write(t, dir, "assignments/a.yaml", assignment)
			write(t, dir, "assignments/b.yml", assignment)
		}, `assignments/b.yml: assignment "payments" already defined in assignments/a.yaml`},
		{"duplicate template", func(t *testing.T, dir string) {
			write(t, dir, "templates/t.json", template)
			write(t, dir, "templates/z/t.json", template)
		}, `templates/z/t.json: template "t" already defined in `},
		{"unreadable document", func(t *testing.T, dir string) {
			if err := os.Symlink(filepath.Join(dir, "missing.yaml"), filepath.Join(dir, "dangling.yaml")); err != nil {
				t.Skipf("symlink: %v", err)
			}
		}, "dangling.yaml"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			tt.setup(t, dir)
			_, err := Load(dir)
			if err == nil {
				t.Fatal("Load succeeded, want an error")
			}
			if !strings.Contains(err.Error(), filepath.FromSlash(tt.want)) {
				t.Errorf("error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestParseDocument(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want string
	}{
		{"no kind", "metadata:\n  name: x\n", "kind is required"},
		{"not yaml", "kind: Grant\n  bad: [", "yaml"},
		{"assignment unknown field", "kind: Assignment\nmetadata:\n  name: a\nspec:\n  subject: s\n  grants: [g]\n  cluster: x\n", `unknown field "cluster"`},
		{"param type", "kind: Grant\nmetadata:\n  name: g\nspec:\n  sessionPolicy:\n    template: t\n    params:\n      n: 1\n", "quote numbers"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseDocument([]byte(tt.doc))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestParseTemplate(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want string
	}{
		{"no policy", `{"params": {}}`, "policy is required"},
		{"policy not object", `{"policy": []}`, "policy must be a JSON object"},
		{"bad type", `{"params": {"x": {"type": "number"}}, "policy": {}}`, `type must be "string" or "list"`},
		{"default mismatch", `{"params": {"x": {"type": "list", "default": "a"}}, "policy": {}}`, "default does not match type list"},
		{"account declared", `{"params": {"account": {"type": "string"}}, "policy": {}}`, "implicit"},
		{"bad name", `{"params": {"my param": {"type": "string"}}, "policy": {}}`, "parameter name"},
		{"trailing", `{"policy": {}} {}`, "trailing data"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseTemplate([]byte(tt.doc))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
	if _, err := ParseTemplate([]byte(`{"policy": {"Version": "2012-10-17"}}`)); err != nil {
		t.Errorf("template without params: %v", err)
	}
}
