package grant

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"
)

// TemplatesDir is the directory, at the root of a source tree, that holds
// the session policy templates.
const TemplatesDir = "templates"

// Source is a loaded grant source tree.
type Source struct {
	// Grants, sorted by name.
	Grants []*Grant
	// Assignments, sorted by name.
	Assignments []*Assignment
	// Templates by name.
	Templates map[string]*Template
}

// Grant returns the grant with the given name, or nil.
func (s *Source) Grant(name string) *Grant {
	for _, g := range s.Grants {
		if g.Name() == name {
			return g
		}
	}
	return nil
}

// Template is a session policy template (see the package documentation).
type Template struct {
	// Name is the file's base name without its extension.
	Name string `json:"-"`
	// Path is where the template was loaded from, for messages.
	Path string `json:"-"`
	// Params are the parameters the policy may reference.
	Params map[string]ParamSpec `json:"params"`
	// Policy is the policy document, with ${name} references in its strings.
	Policy json.RawMessage `json:"policy"`
}

// ParamSpec declares a template parameter.
type ParamSpec struct {
	// Type is "string" or "list".
	Type string `json:"type"`
	// Description is for humans.
	Description string `json:"description,omitempty"`
	// Default, when set, is used when a grant does not supply the parameter.
	Default *Param `json:"default,omitempty"`
}

// Parameter types.
const (
	ParamString = "string"
	ParamList   = "list"
)

// Load reads a source tree (see the package documentation): every *.yaml and
// *.yml file under dir is a Grant or an Assignment, and every *.json file
// under dir/templates is a template. It reports every problem it finds, not
// only the first.
func Load(dir string) (*Source, error) {
	src := &Source{Templates: map[string]*Template{}}
	var errs []error
	seenGrants := map[string]string{}
	seenAssignments := map[string]string{}

	templatesDir := filepath.Join(dir, TemplatesDir)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			rel = path
		}
		inTemplates := path == templatesDir || strings.HasPrefix(path, templatesDir+string(filepath.Separator))
		switch ext := filepath.Ext(path); {
		case inTemplates && ext == ".json":
			t, err := LoadTemplate(path)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", rel, err))
				return nil
			}
			if prev, dup := src.Templates[t.Name]; dup {
				errs = append(errs, fmt.Errorf("%s: template %q already defined in %s", rel, t.Name, prev.Path))
				return nil
			}
			src.Templates[t.Name] = t
		case inTemplates:
			errs = append(errs, fmt.Errorf("%s: only *.json templates belong under %s", rel, TemplatesDir))
		case ext == ".yaml" || ext == ".yml":
			data, err := os.ReadFile(path)
			if err != nil {
				errs = append(errs, err)
				return nil
			}
			obj, err := ParseDocument(data)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", rel, err))
				return nil
			}
			switch o := obj.(type) {
			case *Grant:
				o.Path = rel
				if prev, dup := seenGrants[o.Name()]; dup {
					errs = append(errs, fmt.Errorf("%s: grant %q already defined in %s", rel, o.Name(), prev))
					return nil
				}
				seenGrants[o.Name()] = rel
				src.Grants = append(src.Grants, o)
			case *Assignment:
				o.Path = rel
				if prev, dup := seenAssignments[o.Name()]; dup {
					errs = append(errs, fmt.Errorf("%s: assignment %q already defined in %s", rel, o.Name(), prev))
					return nil
				}
				seenAssignments[o.Name()] = rel
				src.Assignments = append(src.Assignments, o)
			}
		}
		return nil
	})
	if err != nil {
		errs = append(errs, err)
	}
	sort.Slice(src.Grants, func(i, j int) bool { return src.Grants[i].Name() < src.Grants[j].Name() })
	sort.Slice(src.Assignments, func(i, j int) bool { return src.Assignments[i].Name() < src.Assignments[j].Name() })
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return src, nil
}

// ParseDocument parses one YAML document into a *Grant or an *Assignment,
// chosen by its kind. Unknown fields are an error.
func ParseDocument(data []byte) (any, error) {
	var head struct {
		Kind string `json:"kind"`
	}
	if err := yaml.Unmarshal(data, &head); err != nil {
		return nil, err
	}
	switch head.Kind {
	case KindGrant:
		var g Grant
		if err := yaml.UnmarshalStrict(data, &g); err != nil {
			return nil, err
		}
		if g.Name() == "" {
			return nil, errors.New("metadata.name is required")
		}
		return &g, nil
	case KindAssignment:
		var a Assignment
		if err := yaml.UnmarshalStrict(data, &a); err != nil {
			return nil, err
		}
		if a.Name() == "" {
			return nil, errors.New("metadata.name is required")
		}
		return &a, nil
	case "":
		return nil, errors.New("kind is required")
	default:
		return nil, fmt.Errorf("unknown kind %q (want %s or %s)", head.Kind, KindGrant, KindAssignment)
	}
}

// LoadTemplate reads one template file. The template's name is the file's
// base name without extension.
func LoadTemplate(path string) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	t, err := ParseTemplate(data)
	if err != nil {
		return nil, err
	}
	t.Name = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	t.Path = path
	if err := validateName("template name", t.Name); err != nil {
		return nil, err
	}
	return t, nil
}

// ParseTemplate parses a template document. Unknown fields are an error.
func ParseTemplate(data []byte) (*Template, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var t Template
	if err := dec.Decode(&t); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing data after the template object")
	}
	if len(t.Policy) == 0 {
		return nil, errors.New("policy is required")
	}
	var policy map[string]any
	if err := json.Unmarshal(t.Policy, &policy); err != nil {
		return nil, fmt.Errorf("policy must be a JSON object: %w", err)
	}
	for name, spec := range t.Params {
		if err := validateParamName(name); err != nil {
			return nil, err
		}
		if name == implicitAccountParam {
			return nil, fmt.Errorf("parameter %q is implicit and cannot be declared", name)
		}
		switch spec.Type {
		case ParamString, ParamList:
		default:
			return nil, fmt.Errorf("parameter %q: type must be %q or %q, got %q", name, ParamString, ParamList, spec.Type)
		}
		if spec.Default != nil && spec.Default.IsList != (spec.Type == ParamList) {
			return nil, fmt.Errorf("parameter %q: default does not match type %s", name, spec.Type)
		}
	}
	return &t, nil
}
