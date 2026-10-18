// The chart's objects as the pinned helm renders them, for the assertions
// helm_template_test cannot make: it only renders. Each rendering is a
// helm_template target of BUILD.bazel, named for the values it renders
// with, and a test reads it through rendered.
package cracha

import (
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/bazelbuild/rules_go/go/runfiles"
	"gopkg.in/yaml.v3"
)

// document is one rendered object.
type document map[string]any

func (d document) kind() string {
	kind, _ := d["kind"].(string)
	return kind
}

func (d document) name() string {
	meta, _ := d["metadata"].(map[string]any)
	name, _ := meta["name"].(string)
	return name
}

// rendered decodes the objects of the rendering named, a :rendered_<name>
// target of BUILD.bazel.
func rendered(t *testing.T, name string) []document {
	t.Helper()
	path, err := runfiles.Rlocation(fmt.Sprintf("_main/charts/cracha/rendered_%s.yaml", name))
	if err != nil {
		t.Fatalf("the %s rendering is not in the runfiles: %v", name, err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	var docs []document
	for {
		// Into a plain map, so that the nested mappings are plain maps
		// too (yaml decodes them as the type it was given).
		var d map[string]any
		err := dec.Decode(&d)
		if errors.Is(err, io.EOF) {
			return docs
		}
		if err != nil {
			t.Fatalf("decoding the %s rendering: %v", name, err)
		}
		if d != nil {
			docs = append(docs, document(d))
		}
	}
}

// object returns the one rendered object of that kind and name.
func object(t *testing.T, docs []document, kind, name string) document {
	t.Helper()
	for _, d := range docs {
		if d.kind() == kind && d.name() == name {
			return d
		}
	}
	t.Fatalf("no %s %q in the rendering", kind, name)
	return nil
}

// path walks nested maps and lists: a string key indexes a map, an int a
// list. It returns nil when any step is missing.
func path(v any, steps ...any) any {
	for _, step := range steps {
		if d, ok := v.(document); ok {
			v = map[string]any(d)
		}
		switch s := step.(type) {
		case string:
			m, ok := v.(map[string]any)
			if !ok {
				return nil
			}
			v = m[s]
		case int:
			l, ok := v.([]any)
			if !ok || s < 0 || s >= len(l) {
				return nil
			}
			v = l[s]
		default:
			return nil
		}
	}
	return v
}

// stringList returns a list of strings, or nil when v is not one.
func stringList(v any) []string {
	l, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(l))
	for _, e := range l {
		s, ok := e.(string)
		if !ok {
			return nil
		}
		out = append(out, s)
	}
	return out
}
