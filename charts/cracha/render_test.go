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
	"slices"
	"strings"
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

// The broker serves SPIFFE mTLS with its own X.509-SVID (design 6.5): no
// certificate from the chart, no TLS flag, the probes on the plaintext
// health port, and the agent's identity given or left to be derived from
// the namespace the downward API hands the broker.
func TestBrokerServesSPIFFEMTLS(t *testing.T) {
	tests := map[string]struct {
		name       string // the release's resource prefix
		healthPort int
		agentID    string // "" when left to the broker to derive
	}{
		"defaults":  {"cracha", 8081, ""},
		"overrides": {"custom", 9081, "spiffe://prod.example.org/ns/cracha-system/sa/custom-agent"},
	}
	for rendering, tt := range tests {
		t.Run(rendering, func(t *testing.T) {
			docs := rendered(t, rendering)
			dep := object(t, docs, "Deployment", tt.name+"-broker")
			container := path(dep, "spec", "template", "spec", "containers", 0)
			args := stringList(path(container, "args"))
			if args == nil {
				t.Fatalf("args = %v", path(container, "args"))
			}
			var agentArg string
			for _, arg := range args {
				switch {
				case strings.HasPrefix(arg, "--tls-"), arg == "--insecure-plaintext":
					t.Errorf("the broker takes %s", arg)
				case strings.HasPrefix(arg, "--agent-spiffe-id="):
					agentArg = strings.TrimPrefix(arg, "--agent-spiffe-id=")
				}
			}
			if agentArg != tt.agentID {
				t.Errorf("--agent-spiffe-id %q, want %q", agentArg, tt.agentID)
			}
			if !slices.Contains(args, fmt.Sprintf("--health-listen=:%d", tt.healthPort)) {
				t.Errorf("args %q lack the health listener on %d", args, tt.healthPort)
			}
			if got := path(container, "env", 0, "valueFrom", "fieldRef", "fieldPath"); got != "metadata.namespace" || path(container, "env", 0, "name") != "CRACHA_NAMESPACE" {
				t.Errorf("the first env is %v, want CRACHA_NAMESPACE from the downward API", path(container, "env", 0))
			}
			for _, probe := range []string{"readinessProbe", "livenessProbe"} {
				if port := path(container, probe, "httpGet", "port"); port != "health" {
					t.Errorf("%s on port %v, want health", probe, port)
				}
				if scheme := path(container, probe, "httpGet", "scheme"); scheme != nil {
					t.Errorf("%s has scheme %v, want plain HTTP", probe, scheme)
				}
			}
			for _, port := range stringListOf(path(container, "ports"), "name") {
				if port == "health" {
					return
				}
			}
			t.Errorf("no health container port in %v", path(container, "ports"))
		})
	}
}

// The broker has no certificate from the chart, in any TLS mode: no mount,
// no Secret, no cert-manager Certificate; the webhook's are not asserted
// here.
func TestBrokerHasNoChartCertificate(t *testing.T) {
	for rendering, name := range map[string]string{"defaults": "cracha", "overrides": "custom"} {
		t.Run(rendering, func(t *testing.T) {
			docs := rendered(t, rendering)
			dep := object(t, docs, "Deployment", name+"-broker")
			spec := path(dep, "spec", "template", "spec")
			for _, volume := range stringListOf(path(spec, "volumes"), "name") {
				if volume == "tls" {
					t.Error("the broker mounts a tls volume")
				}
			}
			for _, mount := range stringListOf(path(spec, "containers", 0, "volumeMounts"), "mountPath") {
				if strings.HasPrefix(mount, "/etc/cracha/tls") {
					t.Errorf("the broker mounts %s", mount)
				}
			}
			for _, d := range docs {
				if (d.kind() == "Secret" || d.kind() == "Certificate") && d.name() == name+"-broker-tls" || d.kind() == "Certificate" && d.name() == name+"-broker" {
					t.Errorf("the chart renders a %s %s for the broker", d.kind(), d.name())
				}
			}
		})
	}
}

// stringListOf returns the string field key of every map in the list v.
func stringListOf(v any, key string) []string {
	l, _ := v.([]any)
	var out []string
	for _, e := range l {
		if s, ok := path(e, key).(string); ok {
			out = append(out, s)
		}
	}
	return out
}
