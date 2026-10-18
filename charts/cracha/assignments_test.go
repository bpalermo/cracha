package cracha

import (
	"slices"
	"strings"
	"testing"
)

// Where the static backend's assignments come from (broker.assignments.
// source): by default the chart's ConfigMap, mounted and named by
// --assignments; published, nothing of the kind, the broker reading them
// from the bundle source; with SpiceDB, neither.
func TestBrokerAssignmentsSource(t *testing.T) {
	tests := map[string]struct {
		name      string // the release's resource prefix
		source    string // the --assignments-source given; "" for none
		file      bool   // whether --assignments, the volume and the chart's ConfigMap are rendered
		configMap bool
	}{
		"defaults":  {"cracha", "file", true, true},
		"published": {"cracha", "published", false, false},
		"overrides": {"custom", "", false, false},
	}
	for rendering, tt := range tests {
		t.Run(rendering, func(t *testing.T) {
			docs := rendered(t, rendering)
			dep := object(t, docs, "Deployment", tt.name+"-broker")
			args := stringList(path(dep, "spec", "template", "spec", "containers", 0, "args"))
			var source string
			file := false
			for _, arg := range args {
				if v, ok := strings.CutPrefix(arg, "--assignments-source="); ok {
					source = v
				}
				file = file || strings.HasPrefix(arg, "--assignments=")
			}
			if source != tt.source || file != tt.file {
				t.Errorf("--assignments-source %q and --assignments %t, want %q and %t: %q", source, file, tt.source, tt.file, args)
			}
			_, mounted := volumes(t, dep)["assignments"]
			if mounted != tt.file {
				t.Errorf("assignments volume rendered %t, want %t", mounted, tt.file)
			}
			hasConfigMap := slices.ContainsFunc(docs, func(d document) bool {
				return d.kind() == "ConfigMap" && d.name() == tt.name+"-assignments"
			})
			if hasConfigMap != tt.configMap {
				t.Errorf("assignments ConfigMap rendered %t, want %t", hasConfigMap, tt.configMap)
			}
		})
	}
}

// broker.bundle.verifyKey takes several keys, as a string of PEM blocks
// (test/overrides.yaml) or a list of them (test/assignments-published.yaml),
// and the Secret the broker reads them from holds every one.
func TestBundleVerifyKeys(t *testing.T) {
	for rendering, name := range map[string]string{"overrides": "custom", "published": "cracha"} {
		t.Run(rendering, func(t *testing.T) {
			secret := object(t, rendered(t, rendering), "Secret", name+"-bundle-key")
			pem, _ := path(secret, "stringData", "public.pem").(string)
			if n := strings.Count(pem, "-----BEGIN PUBLIC KEY-----"); n != 2 || strings.Count(pem, "-----END PUBLIC KEY-----") != 2 {
				t.Errorf("public.pem holds %d keys, want 2:\n%s", n, pem)
			}
			if strings.Contains(pem, "KEY----------BEGIN") {
				t.Errorf("keys run together:\n%s", pem)
			}
		})
	}
}
