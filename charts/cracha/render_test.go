// The chart's objects as the pinned helm renders them, for the assertions
// helm_template_test cannot make: it only renders. Each rendering is a
// helm_template target of BUILD.bazel, named for the values it renders
// with, and a test reads it through rendered.
package cracha

import (
	"errors"
	"fmt"
	"io"
	"maps"
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

// The broker has no certificate from the chart: no mount, no Secret, no
// Certificate object; TestWebhookDeployment asserts the same of the webhook.
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

// The webhook configuration (design 7.5): rendered without a caBundle, which
// the webhook publishes itself, with failurePolicy Fail, and excluding the
// release's namespace and the namespaces the values list, each once.
// webhookEntry is what TestWebhookConfiguration expects of one webhook of
// the configuration.
type webhookEntry struct {
	name                    string
	namespaceLabels, labels map[string]any
}

func TestWebhookConfiguration(t *testing.T) {
	optIn := map[string]any{"cracha.dev/enabled": "true"}
	for _, tc := range []struct {
		rendering, name string
		excluded        []string
		entries         []webhookEntry
	}{
		{
			"defaults", "cracha-webhook",
			[]string{"default", "spire-system", "spire-server", "spire-mgmt", "kube-system"},
			[]webhookEntry{{name: "pods.cracha.dev"}},
		},
		{
			"overrides", "custom-webhook",
			[]string{"default", "spire", "kube-system"},
			[]webhookEntry{{name: "pods.cracha.dev", namespaceLabels: optIn}, {name: "labelled-pods.cracha.dev", labels: optIn}},
		},
		{
			"pod_labels", "cracha-webhook",
			[]string{"default", "spire-system", "spire-server", "spire-mgmt", "kube-system"},
			[]webhookEntry{{name: "labelled-pods.cracha.dev", labels: optIn}},
		},
	} {
		t.Run(tc.rendering, func(t *testing.T) {
			cfg := object(t, rendered(t, tc.rendering), "MutatingWebhookConfiguration", tc.name)
			if ann := path(cfg, "metadata", "annotations"); ann != nil {
				t.Errorf("annotations %v, want none (no CA injector)", ann)
			}
			hooks, _ := path(cfg, "webhooks").([]any)
			if len(hooks) != len(tc.entries) {
				t.Fatalf("%d webhooks, want %d", len(hooks), len(tc.entries))
			}
			for i, want := range tc.entries {
				checkWebhookEntry(t, hooks[i], want, tc.name, tc.excluded)
			}
		})
	}
}

// checkWebhookEntry checks one webhook of the configuration.
func checkWebhookEntry(t *testing.T, hook any, want webhookEntry, service string, excluded []string) {
	t.Helper()
	if got := path(hook, "name"); got != want.name {
		t.Errorf("webhook %v, want %s", got, want.name)
	}
	if _, ok := path(hook, "clientConfig", "caBundle").(string); ok {
		t.Errorf("%s carries a caBundle; the webhook publishes it itself", want.name)
	}
	if got := path(hook, "failurePolicy"); got != "Fail" {
		t.Errorf("%s failurePolicy %v, want Fail", want.name, got)
	}
	if got := path(hook, "clientConfig", "service", "name"); got != service {
		t.Errorf("%s clientConfig.service.name %v, want %s", want.name, got, service)
	}
	exprs, _ := path(hook, "namespaceSelector", "matchExpressions").([]any)
	if len(exprs) != 1 {
		t.Fatalf("%s: %d selector expressions, want 1", want.name, len(exprs))
	}
	if key, op := path(exprs[0], "key"), path(exprs[0], "operator"); key != "kubernetes.io/metadata.name" || op != "NotIn" {
		t.Errorf("%s selector is %v %v, want kubernetes.io/metadata.name NotIn", want.name, key, op)
	}
	if got := stringList(path(exprs[0], "values")); !slices.Equal(got, excluded) {
		t.Errorf("%s excluded namespaces %q, want %q", want.name, got, excluded)
	}
	nsLabels, _ := path(hook, "namespaceSelector", "matchLabels").(map[string]any)
	if !maps.Equal(nsLabels, want.namespaceLabels) {
		t.Errorf("%s namespaceSelector.matchLabels %v, want %v", want.name, nsLabels, want.namespaceLabels)
	}
	podLabels, _ := path(hook, "objectSelector", "matchLabels").(map[string]any)
	if !maps.Equal(podLabels, want.labels) {
		t.Errorf("%s objectSelector.matchLabels %v, want %v", want.name, podLabels, want.labels)
	}
}

// webhookArgs are the webhook container's arguments in a rendering.
func webhookArgs(t *testing.T, rendering, name string) []string {
	t.Helper()
	deploy := object(t, rendered(t, rendering), "Deployment", name)
	containers, _ := path(deploy, "spec", "template", "spec", "containers").([]any)
	if len(containers) != 1 {
		t.Fatalf("%d containers, want 1", len(containers))
	}
	return stringList(path(containers[0], "args"))
}

// The webhook is told what the agent values say (design 7.5): the loopback
// port, the enrolment mode and, in the init mode only, the agent image by
// digest with the enrolment port, timeout and the init container's
// resources; its serving identity comes from the Workload API, not from a
// Secret.
func TestWebhookDeployment(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		args := webhookArgs(t, "defaults", "cracha-webhook")
		for _, want := range []string{
			"--workload-api-socket=unix:///spiffe-workload-api/spire-agent.sock",
			"--webhook-config-name=cracha-webhook",
			"--service-dns-name=cracha-webhook.default.svc",
			"--agent-port=9797",
			"--enrol=init",
			"--enrol-port=9798",
			"--enrol-timeout=2m",
			"--enrol-cpu=100m",
			"--enrol-memory=32Mi",
			"--default-region=us-east-1",
		} {
			if !slices.Contains(args, want) {
				t.Errorf("args %q lack %q", args, want)
			}
		}
		image := ""
		for _, a := range args {
			if strings.HasPrefix(a, "--agent-image=") {
				image = strings.TrimPrefix(a, "--agent-image=")
			}
			if strings.HasPrefix(a, "--tls-") || strings.HasPrefix(a, "--broker-url") {
				t.Errorf("args carry %q, which the webhook no longer takes", a)
			}
		}
		// The agent image's repository and digest are stamped at package
		// time from //agent:image_push; the reference is by digest.
		if image == "" || !strings.Contains(image, "@") {
			t.Errorf("--agent-image=%q, want a reference by digest", image)
		}
	})
	t.Run("overrides", func(t *testing.T) {
		args := webhookArgs(t, "overrides", "custom-webhook")
		for _, want := range []string{
			"--workload-api-socket=unix:///spiffe-workload-api/socket",
			"--webhook-config-name=custom-webhook",
			"--service-dns-name=custom-webhook.default.svc",
			"--agent-port=17171",
			"--enrol=init",
			"--agent-image=registry.example.com/cracha/agent@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"--enrol-port=17172",
			"--enrol-timeout=30s",
			"--enrol-cpu=200m",
			"--enrol-memory=64Mi",
			"--conflicting-env=strip",
		} {
			if !slices.Contains(args, want) {
				t.Errorf("args %q lack %q", args, want)
			}
		}
	})
	t.Run("cni", func(t *testing.T) {
		args := webhookArgs(t, "cni", "cracha-webhook")
		for _, want := range []string{"--agent-port=9797", "--enrol=cni"} {
			if !slices.Contains(args, want) {
				t.Errorf("args %q lack %q", args, want)
			}
		}
		for _, a := range args {
			for _, prefix := range []string{"--agent-image=", "--enrol-port=", "--enrol-timeout=", "--enrol-cpu=", "--enrol-memory="} {
				if strings.HasPrefix(a, prefix) {
					t.Errorf("args carry %q in the cni mode", a)
				}
			}
		}
	})
	// A rollout loses no admission (design 7.5): the new pod is Ready for
	// minReadySeconds before the old one is told to stop, the old one
	// drains for webhook.drain and then waits webhook.shutdownTimeout for
	// what is in flight, and its grace period covers the two with a
	// margin; no preStop hook is involved.
	t.Run("rollout", func(t *testing.T) {
		for _, tc := range []struct {
			rendering, name              string
			drain, shutdownTimeout       string
			minReadySeconds, gracePeriod int
		}{
			{"defaults", "cracha-webhook", "5s", "10s", 5, 20},
			{"overrides", "custom-webhook", "2s", "1m", 10, 67},
		} {
			deploy := object(t, rendered(t, tc.rendering), "Deployment", tc.name)
			if got := path(deploy, "spec", "strategy", "type"); got != "RollingUpdate" {
				t.Errorf("%s: strategy %v, want RollingUpdate", tc.rendering, got)
			}
			if got := path(deploy, "spec", "strategy", "rollingUpdate", "maxUnavailable"); got != 0 {
				t.Errorf("%s: maxUnavailable %v, want 0", tc.rendering, got)
			}
			if got := path(deploy, "spec", "strategy", "rollingUpdate", "maxSurge"); got != 1 {
				t.Errorf("%s: maxSurge %v, want 1", tc.rendering, got)
			}
			if got := path(deploy, "spec", "minReadySeconds"); got != tc.minReadySeconds {
				t.Errorf("%s: minReadySeconds %v, want %d", tc.rendering, got, tc.minReadySeconds)
			}
			if got := path(deploy, "spec", "template", "spec", "terminationGracePeriodSeconds"); got != tc.gracePeriod {
				t.Errorf("%s: terminationGracePeriodSeconds %v, want %d", tc.rendering, got, tc.gracePeriod)
			}
			args := webhookArgs(t, tc.rendering, tc.name)
			for _, want := range []string{"--drain=" + tc.drain, "--shutdown-timeout=" + tc.shutdownTimeout} {
				if !slices.Contains(args, want) {
					t.Errorf("%s: args %q lack %q", tc.rendering, args, want)
				}
			}
			containers, _ := path(deploy, "spec", "template", "spec", "containers").([]any)
			if len(containers) == 1 && path(containers[0], "lifecycle") != nil {
				t.Errorf("%s: the container has a lifecycle (%v); the binary drains, not a preStop hook", tc.rendering, path(containers[0], "lifecycle"))
			}
		}
	})
	t.Run("no TLS Secret", func(t *testing.T) {
		for _, tc := range []struct{ rendering, name string }{{"defaults", "cracha-webhook"}, {"overrides", "custom-webhook"}} {
			deploy := object(t, rendered(t, tc.rendering), "Deployment", tc.name)
			volumes, _ := path(deploy, "spec", "template", "spec", "volumes").([]any)
			var names []string
			for _, v := range volumes {
				name, _ := path(v, "name").(string)
				names = append(names, name)
				if path(v, "secret") != nil {
					t.Errorf("%s: volume %s is a Secret; the webhook's certificate is its SVID", tc.rendering, name)
				}
			}
			if !slices.Equal(names, []string{"spire-workload-api"}) {
				t.Errorf("%s: volumes %q, want the Workload API only", tc.rendering, names)
			}
			for _, d := range rendered(t, tc.rendering) {
				if d.kind() == "Secret" && strings.Contains(d.name(), "webhook") {
					t.Errorf("%s: Secret %s rendered for the webhook", tc.rendering, d.name())
				}
			}
		}
	})
}
