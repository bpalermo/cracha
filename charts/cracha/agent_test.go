package cracha

import (
	"fmt"
	"reflect"
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
		t.Fatalf("%d containers, want the agent alone", len(containers))
	}
	if init, _ := path(spec, "initContainers").([]any); len(init) != 0 {
		t.Errorf("initContainers = %v, want none in init mode", init)
	}
	// The template says its mode, for the retire hook of a pod that was
	// in cni mode; the hook itself is cni mode's.
	if got := path(ds, "spec", "template", "metadata", "annotations", "cracha.dev/enrol"); got != "init" {
		t.Errorf("template annotation cracha.dev/enrol = %v, want init", got)
	}
	if path(containers[0], "lifecycle") != nil {
		t.Errorf("lifecycle = %v, want none in init mode", path(containers[0], "lifecycle"))
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
			"--fetch-deadline=3s", "--prewarm=true", "--broker-timeout=10s", "--healthz=:9799", "--log-level=info",
			"--issuer-broker-socket=/run/spire/broker/broker.sock", "--workload-api=unix:///spiffe-workload-api/spire-agent.sock")
		lacks(t, a, "--cni-socket")
	})
	t.Run("overrides", func(t *testing.T) {
		a := args("overrides")
		has(t, a, "--port=17171", "--enrol=init", "--enrol-listen=:17172", "--cri-socket=/var/run/crio/crio.sock",
			"--broker-spiffe-id=spiffe://prod.example.org/ns/cracha/sa/broker", "--broker-url=https://credentials.example.org:9443",
			"--fetch-deadline=1500ms", "--prewarm=false", "--broker-timeout=5s", "--healthz=:17173", "--log-level=warn",
			"--issuer-broker-socket=/run/spire/broker/api.sock", "--workload-api=unix:///spiffe-workload-api/api.sock")
	})
	t.Run("cni", func(t *testing.T) {
		a := args("cni")
		has(t, a, "--enrol=cni", "--cni-socket=/run/cracha/cni.sock")
		lacks(t, a, "--enrol-listen")
	})
}

// In cni mode the agent's socket directory is mounted for the plugin, the
// cni-install init container puts the plugin on the node from the agent
// image with the CNI directories mounted read-write, the agent container
// mounts the same two directories for its cni-retire preStop hook, which
// reads the DaemonSet the template annotation names the mode of, under a
// grace period that covers it, and there is no TokenReview.
func TestAgentCNIMode(t *testing.T) {
	docs := rendered(t, "cni")
	ds := object(t, docs, "DaemonSet", "cracha-agent")
	spec := path(ds, "spec", "template", "spec")
	vols := volumes(t, ds)
	hostPath := func(name string) string {
		p, _ := path(vols[name], "hostPath", "path").(string)
		return p
	}
	if hostPath("cni-socket-dir") != "/run/cracha" {
		t.Errorf("cni-socket-dir = %q, want the socket's directory", hostPath("cni-socket-dir"))
	}
	if hostPath("cni-bin-dir") != "/usr/libexec/cni" || hostPath("cni-conf-dir") != "/etc/kubernetes/cni/net.d" {
		t.Errorf("CNI directories = %q, %q, want the values'", hostPath("cni-bin-dir"), hostPath("cni-conf-dir"))
	}
	containers, _ := path(spec, "containers").([]any)
	init, _ := path(spec, "initContainers").([]any)
	if len(init) != 1 || path(init[0], "name") != "cni-install" {
		t.Fatalf("initContainers = %v, want cni-install alone", init)
	}
	if path(init[0], "image") != path(containers[0], "image") {
		t.Errorf("cni-install runs %v, not the agent image %v", path(init[0], "image"), path(containers[0], "image"))
	}
	args := stringList(path(init[0], "args"))
	for _, want := range []string{"cni-install", "--bin-dir=/usr/libexec/cni", "--conf-dir=/etc/kubernetes/cni/net.d", "--socket=/run/cracha/cni.sock"} {
		if !slices.Contains(args, want) {
			t.Errorf("cni-install args lack %q: %v", want, args)
		}
	}
	sc := path(init[0], "securityContext")
	if got := stringList(path(sc, "capabilities", "drop")); !slices.Equal(got, []string{"ALL"}) || path(sc, "capabilities", "add") != nil {
		t.Errorf("cni-install capabilities = %v", path(sc, "capabilities"))
	}
	if path(sc, "readOnlyRootFilesystem") != true || path(sc, "allowPrivilegeEscalation") != false {
		t.Errorf("cni-install securityContext = %v", sc)
	}
	// The installer mounts the two directories read-write, at their host
	// paths, and nothing else; the agent container mounts the same two
	// read-write for the retire hook (design 7.8).
	cniMounts := func(container any) map[string]string {
		mounted := map[string]string{}
		for _, m := range mountsOf(container) {
			name, _ := path(m, "name").(string)
			if name != "cni-bin-dir" && name != "cni-conf-dir" {
				continue
			}
			if path(m, "readOnly") == true {
				t.Errorf("%v is mounted read-only in %v", name, path(container, "name"))
			}
			mounted[name], _ = path(m, "mountPath").(string)
		}
		return mounted
	}
	want := map[string]string{"cni-bin-dir": "/usr/libexec/cni", "cni-conf-dir": "/etc/kubernetes/cni/net.d"}
	for _, c := range []any{init[0], containers[0]} {
		if got := cniMounts(c); !reflect.DeepEqual(got, want) {
			t.Errorf("%v mounts the CNI directories at %v, want %v", path(c, "name"), got, want)
		}
	}
	if n := len(mountsOf(init[0])); n != 2 {
		t.Errorf("cni-install has %d mounts, want the two CNI directories alone", n)
	}
	// The retire hook, told the DaemonSet and the directories, with the
	// namespace from the downward API, under a grace period that covers
	// its 20 s budget; and the template says the mode the hook compares.
	hook := stringList(path(containers[0], "lifecycle", "preStop", "exec", "command"))
	for _, want := range []string{"/cracha-agent", "cni-retire", "--daemonset=cracha-agent", "--bin-dir=/usr/libexec/cni", "--conf-dir=/etc/kubernetes/cni/net.d"} {
		if !slices.Contains(hook, want) {
			t.Errorf("preStop hook %v lacks %q", hook, want)
		}
	}
	var podNamespace any
	for _, e := range path(containers[0], "env").([]any) {
		if path(e, "name") == "POD_NAMESPACE" {
			podNamespace = path(e, "valueFrom", "fieldRef", "fieldPath")
		}
	}
	if podNamespace != "metadata.namespace" {
		t.Errorf("POD_NAMESPACE = %v, want metadata.namespace from the downward API", podNamespace)
	}
	if grace, _ := path(spec, "terminationGracePeriodSeconds").(int); grace < 40 {
		t.Errorf("terminationGracePeriodSeconds = %v, want one that covers the hook's 20 s budget and the shutdown", path(spec, "terminationGracePeriodSeconds"))
	}
	if got := path(ds, "spec", "template", "metadata", "annotations", "cracha.dev/enrol"); got != "cni" {
		t.Errorf("template annotation cracha.dev/enrol = %v, want cni", got)
	}
	role := object(t, docs, "ClusterRole", "cracha-agent")
	for _, rule := range path(role, "rules").([]any) {
		if slices.Contains(stringList(path(rule, "resources")), "tokenreviews") {
			t.Error("cni mode grants TokenReview, which only init mode uses")
		}
	}
}

// mountsOf is a container's volume mounts.
func mountsOf(container any) []any {
	mounts, _ := path(container, "volumeMounts").([]any)
	return mounts
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

// The agent's Role, in both modes, grants exactly what the retire hook
// reads: its own DaemonSet, by name, and nothing else.
func TestAgentRole(t *testing.T) {
	for rendering, name := range map[string]string{"defaults": "cracha", "overrides": "custom", "cni": "cracha"} {
		t.Run(rendering, func(t *testing.T) {
			docs := rendered(t, rendering)
			role := object(t, docs, "Role", name+"-agent")
			rules, _ := path(role, "rules").([]any)
			if len(rules) != 1 {
				t.Fatalf("%d rules, want one", len(rules))
			}
			rule := rules[0]
			if g, r, v, n := stringList(path(rule, "apiGroups")), stringList(path(rule, "resources")), stringList(path(rule, "verbs")), stringList(path(rule, "resourceNames")); !slices.Equal(g, []string{"apps"}) || !slices.Equal(r, []string{"daemonsets"}) || !slices.Equal(v, []string{"get"}) || !slices.Equal(n, []string{name + "-agent"}) {
				t.Errorf("rule = %v, want get on apps/daemonsets named %s-agent", rule, name)
			}
			binding := object(t, docs, "RoleBinding", name+"-agent")
			if path(binding, "roleRef", "kind") != "Role" || path(binding, "roleRef", "name") != name+"-agent" ||
				path(binding, "subjects", 0, "kind") != "ServiceAccount" || path(binding, "subjects", 0, "name") != name+"-agent" {
				t.Errorf("binding = %v", binding)
			}
		})
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

// TestAgentTolerations: by default the agent tolerates no taint, so it never
// lands on a node the identity issuer's agent does not run on (a control
// plane); the overrides give it the issuer agent's toleration.
func TestAgentTolerations(t *testing.T) {
	for _, tc := range []struct {
		rendering, name string
		want            int
	}{
		{"defaults", "cracha-agent", 0},
		{"overrides", "custom-agent", 1},
	} {
		ds := object(t, rendered(t, tc.rendering), "DaemonSet", tc.name)
		tols, _ := path(ds, "spec", "template", "spec", "tolerations").([]any)
		if len(tols) != tc.want {
			t.Errorf("%s: %d tolerations %v, want %d", tc.rendering, len(tols), tols, tc.want)
		}
		for _, tol := range tols {
			if path(tol, "key") == nil && path(tol, "operator") == "Exists" {
				t.Errorf("%s: a toleration of every taint", tc.rendering)
			}
		}
	}
}

// TestAgentBrokerAPIGroup: agent.brokerAPI.group becomes the agent pod's one
// supplementary group, so it can open an issuer socket another user owns;
// the defaults add none.
func TestAgentBrokerAPIGroup(t *testing.T) {
	for _, tc := range []struct {
		rendering, name string
		want            []any
	}{
		{"defaults", "cracha-agent", nil},
		{"overrides", "custom-agent", []any{1000}},
	} {
		ds := object(t, rendered(t, tc.rendering), "DaemonSet", tc.name)
		got, _ := path(ds, "spec", "template", "spec", "securityContext", "supplementalGroups").([]any)
		if fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("%s: supplementalGroups %v, want %v", tc.rendering, got, tc.want)
		}
	}
}
