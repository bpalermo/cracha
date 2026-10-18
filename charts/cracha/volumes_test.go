package cracha

import (
	"reflect"
	"slices"
	"testing"
)

// workloads are the kinds with a pod template.
var workloads = []string{"Deployment", "DaemonSet", "StatefulSet"}

// volumes returns a workload's pod volumes, by name.
func volumes(t *testing.T, w document) map[string]map[string]any {
	t.Helper()
	list, ok := path(w, "spec", "template", "spec", "volumes").([]any)
	if !ok {
		t.Fatalf("%s %s has no volumes", w.kind(), w.name())
	}
	out := map[string]map[string]any{}
	for _, v := range list {
		m, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("%s %s: volume %v is not a mapping", w.kind(), w.name(), v)
		}
		name, _ := m["name"].(string)
		out[name] = m
	}
	return out
}

// sources are the keys of a volume besides its name: its sources, of which
// the apiserver accepts exactly one.
func sources(v map[string]any) []string {
	var out []string
	for k := range v {
		if k != "name" {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

// Every volume of every workload has exactly one source, in every rendering.
// Helm merges an install's values into the defaults, so a volume rendered
// from a map the defaults fill in would carry the default source beside the
// one the install chose (test/overrides.yaml chooses csi for the broker's
// Workload API, whose default is a hostPath), and the apiserver would refuse
// the pod.
func TestVolumesHaveOneSource(t *testing.T) {
	for _, rendering := range []string{"defaults", "overrides"} {
		t.Run(rendering, func(t *testing.T) {
			checked := 0
			for _, w := range rendered(t, rendering) {
				if !slices.Contains(workloads, w.kind()) {
					continue
				}
				for name, v := range volumes(t, w) {
					checked++
					if s := sources(v); len(s) != 1 {
						t.Errorf("%s %s: volume %q has the sources %q, want exactly one", w.kind(), w.name(), name, s)
					}
				}
			}
			if checked == 0 {
				t.Fatal("no volumes checked")
			}
		})
	}
}

// The broker's Workload API volume is the one source
// broker.workloadAPI.volume.type names: the hostPath by default, the SPIFFE
// CSI driver with test/overrides.yaml.
func TestBrokerWorkloadAPIVolume(t *testing.T) {
	for _, tc := range []struct {
		rendering, broker, source string
		want                      map[string]any
	}{
		{"defaults", "cracha-broker", "hostPath", map[string]any{"path": "/run/spire/agent-sockets", "type": "Directory"}},
		{"overrides", "custom-broker", "csi", map[string]any{"driver": "csi.spiffe.io", "readOnly": true}},
	} {
		t.Run(tc.rendering, func(t *testing.T) {
			broker := object(t, rendered(t, tc.rendering), "Deployment", tc.broker)
			v, ok := volumes(t, broker)["spire-workload-api"]
			if !ok {
				t.Fatal("the broker has no spire-workload-api volume")
			}
			if s := sources(v); !slices.Equal(s, []string{tc.source}) {
				t.Fatalf("volume sources = %q, want %q alone", s, tc.source)
			}
			if got := v[tc.source]; !reflect.DeepEqual(got, tc.want) {
				t.Errorf("%s = %v, want %v", tc.source, got, tc.want)
			}
		})
	}
}
