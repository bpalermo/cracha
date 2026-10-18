package cracha

import (
	"slices"
	"strings"
	"testing"
)

// The agent's DaemonSet as design 7.8 has it: host network, no host PID,
// CAP_SYS_ADMIN and nothing else, read-only root, and host mounts limited
// to the CRI socket, the runtime's namespace directory and the issuer's
// sockets.
func TestAgentDaemonSetHardening(t *testing.T) {
	ds := object(t, rendered(t, "defaults"), "DaemonSet", "cracha-agent")
	spec := path(ds, "spec", "template", "spec")
	if path(spec, "hostNetwork") != true {
		t.Error("the agent is not in the host network")
	}
	if path(spec, "hostPID") == true {
		t.Error("the agent is in the host PID namespace")
	}
	if path(spec, "serviceAccountName") != "cracha-agent" {
		t.Errorf("serviceAccountName = %v", path(spec, "serviceAccountName"))
	}
	containers, _ := path(spec, "containers").([]any)
	if len(containers) != 1 {
		t.Fatalf("%d containers, want the agent alone (the CNI installer is a later slice)", len(containers))
	}
	sc := path(containers[0], "securityContext")
	if got := stringList(path(sc, "capabilities", "add")); !slices.Equal(got, []string{"SYS_ADMIN"}) {
		t.Errorf("capabilities added = %v, want SYS_ADMIN alone", got)
	}
	if got := stringList(path(sc, "capabilities", "drop")); !slices.Equal(got, []string{"ALL"}) {
		t.Errorf("capabilities dropped = %v, want ALL", got)
	}
	if path(sc, "readOnlyRootFilesystem") != true || path(sc, "allowPrivilegeEscalation") != false {
		t.Errorf("securityContext = %v", sc)
	}
	// The volumes are the four host paths the design allows in init mode
	// (volumes_test.go holds every volume to one source).
	want := map[string]string{
		"cri-socket":         "/run/containerd/containerd.sock",
		"netns-dir":          "/var/run/netns",
		"spire-workload-api": "/run/spire/agent-sockets",
		"spire-broker-api":   "/run/spire/broker-sockets",
	}
	got := map[string]string{}
	for name, v := range volumes(t, ds) {
		got[name], _ = path(v, "hostPath", "path").(string)
	}
	for name, p := range want {
		if got[name] != p {
			t.Errorf("volume %s = %q, want hostPath %q", name, got[name], p)
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			t.Errorf("volume %s is mounted, which the design does not allow", name)
		}
	}
	// The namespace directory follows the host's mounts, read-only, at the
	// same path.
	mounts, _ := path(containers[0], "volumeMounts").([]any)
	var netns any
	for _, m := range mounts {
		if path(m, "name") == "netns-dir" {
			netns = m
		}
	}
	if netns == nil || path(netns, "mountPath") != "/var/run/netns" || path(netns, "readOnly") != true ||
		path(netns, "mountPropagation") != "HostToContainer" {
		t.Errorf("netns-dir mount = %v", netns)
	}
	for _, m := range mounts {
		if path(m, "name") == "cri-socket" && path(m, "readOnly") != true {
			t.Error("the CRI socket is not mounted read-only")
		}
	}
}

// The agent's arguments follow the values: the mode, the ports, the broker
// derived from the release in the defaults and taken from the values in
// the overrides.
func TestAgentArgs(t *testing.T) {
	args := func(name string) []string {
		ds := object(t, rendered(t, name), "DaemonSet", strings.Replace("cracha-agent", "cracha", map[string]string{"defaults": "cracha", "overrides": "custom", "cni": "cracha"}[name], 1))
		containers, _ := path(ds, "spec", "template", "spec", "containers").([]any)
		return stringList(path(containers[0], "args"))
	}
	has := func(t *testing.T, args []string, want ...string) {
		t.Helper()
		for _, w := range want {
			if !slices.Contains(args, w) {
				t.Errorf("args lack %q: %v", w, args)
			}
		}
	}
	lacks := func(t *testing.T, args []string, prefix string) {
		t.Helper()
		for _, a := range args {
			if strings.HasPrefix(a, prefix) {
				t.Errorf("args carry %q, which this mode does not take", a)
			}
		}
	}
	t.Run("defaults", func(t *testing.T) {
		a := args("defaults")
		has(t, a, "--port=9797", "--enrol=init", "--enrol-listen=:9798", "--cri-socket=/run/containerd/containerd.sock",
			"--broker-spiffe-id=/ns/default/sa/cracha-broker", "--broker-url=https://cracha-broker.default.svc:8443",
			"--fetch-deadline=3s", "--broker-timeout=10s", "--healthz=:9799", "--log-level=info",
			"--issuer-broker-socket=/run/spire/broker/broker.sock", "--workload-api=unix:///spiffe-workload-api/spire-agent.sock")
		lacks(t, a, "--cni-socket")
	})
	t.Run("overrides", func(t *testing.T) {
		a := args("overrides")
		has(t, a, "--port=17171", "--enrol=init", "--enrol-listen=:17172", "--cri-socket=/var/run/crio/crio.sock",
			"--broker-spiffe-id=spiffe://prod.example.org/ns/cracha/sa/broker", "--broker-url=https://credentials.example.org:9443",
			"--fetch-deadline=1500ms", "--broker-timeout=5s", "--healthz=:17173", "--log-level=warn",
			"--issuer-broker-socket=/run/spire/broker/api.sock", "--workload-api=unix:///spiffe-workload-api/api.sock")
	})
	t.Run("cni", func(t *testing.T) {
		a := args("cni")
		has(t, a, "--enrol=cni", "--cni-socket=/run/cracha/cni.sock")
		lacks(t, a, "--enrol-listen")
	})
}

// In cni mode the agent's socket directory is mounted for the plugin, and
// nothing else changes: no installer yet (a later slice), no TokenReview.
func TestAgentCNIMode(t *testing.T) {
	docs := rendered(t, "cni")
	ds := object(t, docs, "DaemonSet", "cracha-agent")
	spec := path(ds, "spec", "template", "spec")
	socketDir, _ := path(volumes(t, ds)["cni-socket-dir"], "hostPath", "path").(string)
	if socketDir != "/run/cracha" {
		t.Errorf("cni-socket-dir = %q, want the socket's directory", socketDir)
	}
	if init, _ := path(spec, "initContainers").([]any); len(init) != 0 {
		t.Errorf("initContainers = %v, want none until the installer slice lands", init)
	}
	role := object(t, docs, "ClusterRole", "cracha-agent")
	for _, rule := range path(role, "rules").([]any) {
		if slices.Contains(stringList(path(rule, "resources")), "tokenreviews") {
			t.Error("cni mode grants TokenReview, which only init mode uses")
		}
	}
	if _, ok := object(t, docs, "DaemonSet", "cracha-agent")["kind"]; !ok {
		t.Fatal("no DaemonSet")
	}
}

// The agent's ClusterRole grants exactly design 7.8: pods get, list and
// watch, and tokenreviews create in init mode.
func TestAgentClusterRole(t *testing.T) {
	role := object(t, rendered(t, "defaults"), "ClusterRole", "cracha-agent")
	want := map[string][]string{
		"pods":         {"get", "list", "watch"},
		"tokenreviews": {"create"},
	}
	groups := map[string]string{"pods": "", "tokenreviews": "authentication.k8s.io"}
	got := map[string][]string{}
	for i, rule := range path(role, "rules").([]any) {
		verbs := stringList(path(rule, "verbs"))
		for _, resource := range stringList(path(rule, "resources")) {
			got[resource] = append(got[resource], verbs...)
			if g := stringList(path(rule, "apiGroups")); !slices.Equal(g, []string{groups[resource]}) {
				t.Errorf("rule %d grants %s on API groups %q", i, resource, g)
			}
		}
	}
	for resource, verbs := range want {
		if !slices.Equal(got[resource], verbs) {
			t.Errorf("verbs on %s = %q, want %q", resource, got[resource], verbs)
		}
	}
	for resource := range got {
		if _, ok := want[resource]; !ok {
			t.Errorf("the role grants %q on %s, which the agent does not use", got[resource], resource)
		}
	}
	binding := object(t, rendered(t, "defaults"), "ClusterRoleBinding", "cracha-agent")
	if path(binding, "subjects", 0, "name") != "cracha-agent" || path(binding, "roleRef", "name") != "cracha-agent" {
		t.Errorf("binding = %v", binding)
	}
}

// The CSI driver is gone: nothing of it is rendered.
func TestNoCSIDriverRemains(t *testing.T) {
	for _, d := range rendered(t, "defaults") {
		if d.kind() == "CSIDriver" || strings.Contains(d.name(), "csi") {
			t.Errorf("%s %s is still rendered", d.kind(), d.name())
		}
	}
}
