package install

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// kindnet is kind's primary conflist, as the node has it.
const kindnet = `{
	"cniVersion": "0.3.1",
	"name": "kindnet",
	"plugins": [
	{
		"type": "ptp",
		"ipMasq": false,
		"ipam": {
			"type": "host-local",
			"dataDir": "/run/cni-ipam-state",
			"routes": [{ "dst": "0.0.0.0/0" }],
			"ranges": [[{ "subnet": "10.244.0.0/24" }]]
		},
		"mtu": 1500
	},
	{
		"type": "portmap",
		"capabilities": {
			"portMappings": true
		}
	}
	]
}
`

// node is a node's CNI directories and the image's plugin, in a temp dir.
type node struct {
	cfg                Config
	plugin             string
	binDir, confDir    string
	pluginInImage      string
	pluginInImageBytes []byte
}

func newNode(t *testing.T, conflists map[string]string) *node {
	t.Helper()
	root := t.TempDir()
	n := &node{
		binDir: filepath.Join(root, "opt", "cni", "bin"), confDir: filepath.Join(root, "etc", "cni", "net.d"),
		pluginInImage: filepath.Join(root, "image", "cracha-cni"), pluginInImageBytes: []byte("#!/bin/sh\necho plugin\n"),
	}
	for _, d := range []string{n.binDir, n.confDir, filepath.Dir(n.pluginInImage)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(n.pluginInImage, n.pluginInImageBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range conflists {
		if err := os.WriteFile(filepath.Join(n.confDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	n.plugin = filepath.Join(n.binDir, "cracha-cni")
	n.cfg = Config{
		Plugin: n.pluginInImage, BinDir: n.binDir, ConfDir: n.confDir, Socket: "/run/cracha/cni.sock",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	return n
}

// plugins is the plugin list of the conflist at path.
func plugins(t *testing.T, path string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var conf struct {
		CNIVersion string           `json:"cniVersion"`
		Name       string           `json:"name"`
		Plugins    []map[string]any `json:"plugins"`
	}
	if err := json.Unmarshal(data, &conf); err != nil {
		t.Fatalf("%s: %v\n%s", path, err, data)
	}
	if conf.CNIVersion != "0.3.1" || conf.Name != "kindnet" {
		t.Errorf("the conflist lost its version or name: %+v", conf)
	}
	return conf.Plugins
}

func inode(t *testing.T, path string) uint64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Ino
}

func TestInstallChainsThePluginAfterThePrimary(t *testing.T) {
	n := newNode(t, map[string]string{"10-kindnet.conflist": kindnet})
	if err := Run(n.cfg); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(n.plugin)
	if err != nil || string(got) != string(n.pluginInImageBytes) {
		t.Errorf("installed plugin = %q, %v", got, err)
	}
	if fi, _ := os.Stat(n.plugin); fi.Mode().Perm() != 0o755 {
		t.Errorf("plugin mode = %v, want 0755", fi.Mode())
	}
	ps := plugins(t, filepath.Join(n.confDir, "10-kindnet.conflist"))
	if len(ps) != 3 || ps[0]["type"] != "ptp" || ps[1]["type"] != "portmap" {
		t.Fatalf("plugins = %v, want the primary's two then cracha-cni", ps)
	}
	entry, _ := json.Marshal(ps[2])
	if want := `{"socket":"/run/cracha/cni.sock","timeout":"5s","type":"cracha-cni"}`; string(entry) != want {
		t.Errorf("entry = %s, want %s", entry, want)
	}
	// The primary's numbers and nested objects survive the rewrite as
	// written.
	if ps[0]["mtu"] != 1500.0 || ps[0]["ipam"].(map[string]any)["dataDir"] != "/run/cni-ipam-state" {
		t.Errorf("the primary entry changed: %v", ps[0])
	}
	// The entry is written in the documented order.
	data, _ := os.ReadFile(filepath.Join(n.confDir, "10-kindnet.conflist"))
	if want := "\"type\": \"cracha-cni\",\n      \"socket\": \"/run/cracha/cni.sock\",\n      \"timeout\": \"5s\""; !bytes.Contains(data, []byte(want)) {
		t.Errorf("conflist:\n%s\nlacks\n%s", data, want)
	}
	if entries, _ := os.ReadDir(n.confDir); len(entries) != 1 {
		t.Errorf("the conf directory holds %d entries, want the conflist alone (no temp file left)", len(entries))
	}
}

// A second run leaves both files alone: same inode, same bytes.
func TestInstallIsIdempotent(t *testing.T) {
	n := newNode(t, map[string]string{"10-kindnet.conflist": kindnet})
	if err := Run(n.cfg); err != nil {
		t.Fatal(err)
	}
	conflist := filepath.Join(n.confDir, "10-kindnet.conflist")
	before, pluginBefore := inode(t, conflist), inode(t, n.plugin)
	data, _ := os.ReadFile(conflist)
	if err := Run(n.cfg); err != nil {
		t.Fatal(err)
	}
	if inode(t, conflist) != before {
		t.Error("an unchanged conflist was rewritten")
	}
	if inode(t, n.plugin) != pluginBefore {
		t.Error("an unchanged plugin was rewritten")
	}
	if after, _ := os.ReadFile(conflist); string(after) != string(data) {
		t.Errorf("the conflist changed:\n%s", after)
	}
	if ps := plugins(t, conflist); len(ps) != 3 {
		t.Errorf("%d plugins after two runs, want 3", len(ps))
	}
}

// A competing writer putting the primary's conflist back strips the entry;
// the next run chains it again. A changed plugin binary is replaced.
func TestInstallRechainsAStrippedEntryAndReplacesAChangedPlugin(t *testing.T) {
	n := newNode(t, map[string]string{"10-kindnet.conflist": kindnet})
	if err := Run(n.cfg); err != nil {
		t.Fatal(err)
	}
	conflist := filepath.Join(n.confDir, "10-kindnet.conflist")
	if err := os.WriteFile(conflist, []byte(kindnet), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(n.plugin, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Run(n.cfg); err != nil {
		t.Fatal(err)
	}
	if ps := plugins(t, conflist); len(ps) != 3 || ps[2]["type"] != "cracha-cni" {
		t.Errorf("plugins = %v, want cracha-cni chained again", ps)
	}
	if got, _ := os.ReadFile(n.plugin); string(got) != string(n.pluginInImageBytes) {
		t.Errorf("plugin = %q, want the image's", got)
	}
}

// An entry naming another socket is replaced, not duplicated.
func TestInstallReplacesAnEntryWithAnotherSocket(t *testing.T) {
	n := newNode(t, map[string]string{"10-kindnet.conflist": kindnet})
	n.cfg.Socket = "/var/run/cracha/old.sock"
	if err := Run(n.cfg); err != nil {
		t.Fatal(err)
	}
	n.cfg.Socket = "/run/cracha/cni.sock"
	if err := Run(n.cfg); err != nil {
		t.Fatal(err)
	}
	ps := plugins(t, filepath.Join(n.confDir, "10-kindnet.conflist"))
	if len(ps) != 3 || ps[2]["socket"] != "/run/cracha/cni.sock" {
		t.Errorf("plugins = %v", ps)
	}
}

// The primary is the lexically first configuration, whatever its name,
// and it has to be a conflist.
func TestInstallPicksThePrimary(t *testing.T) {
	n := newNode(t, map[string]string{
		"10-kindnet.conflist": kindnet,
		"05-other.conflist":   `{"cniVersion":"0.3.1","name":"kindnet","plugins":[{"type":"bridge"}]}`,
		"99-last.conflist":    kindnet,
		"README":              "not a configuration",
	})
	if err := Run(n.cfg); err != nil {
		t.Fatal(err)
	}
	if ps := plugins(t, filepath.Join(n.confDir, "05-other.conflist")); len(ps) != 2 || ps[1]["type"] != "cracha-cni" {
		t.Errorf("05-other.conflist plugins = %v", ps)
	}
	for _, other := range []string{"10-kindnet.conflist", "99-last.conflist"} {
		if data, _ := os.ReadFile(filepath.Join(n.confDir, other)); string(data) != kindnet {
			t.Errorf("%s was touched", other)
		}
	}
}

func TestInstallErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		conflists map[string]string
		mutate    func(*node)
	}{
		"no conflist":            {conflists: nil},
		"only a README":          {conflists: map[string]string{"README": "nope"}},
		"primary is a .conf":     {conflists: map[string]string{"05-bridge.conf": `{"cniVersion":"0.3.1","name":"n","type":"bridge"}`, "10-kindnet.conflist": kindnet}},
		"primary is not json":    {conflists: map[string]string{"10-kindnet.conflist": "{"}},
		"primary has no plugins": {conflists: map[string]string{"10-kindnet.conflist": `{"cniVersion":"0.3.1","name":"n"}`}},
		"no plugin in the image": {conflists: map[string]string{"10-kindnet.conflist": kindnet}, mutate: func(n *node) { n.cfg.Plugin = n.pluginInImage + ".missing" }},
		"no socket":              {conflists: map[string]string{"10-kindnet.conflist": kindnet}, mutate: func(n *node) { n.cfg.Socket = "" }},
	} {
		t.Run(name, func(t *testing.T) {
			n := newNode(t, tc.conflists)
			if tc.mutate != nil {
				tc.mutate(n)
			}
			if err := Run(n.cfg); err == nil {
				t.Fatal("installed")
			}
			if entries, _ := os.ReadDir(n.confDir); len(entries) != len(tc.conflists) {
				t.Errorf("the conf directory changed: %v", entries)
			}
		})
	}
}

func TestUninstall(t *testing.T) {
	n := newNode(t, map[string]string{"10-kindnet.conflist": kindnet})
	if err := Run(n.cfg); err != nil {
		t.Fatal(err)
	}
	if err := Uninstall(n.cfg); err != nil {
		t.Fatal(err)
	}
	if ps := plugins(t, filepath.Join(n.confDir, "10-kindnet.conflist")); len(ps) != 2 {
		t.Errorf("plugins = %v, want the primary's alone", ps)
	}
	if _, err := os.Stat(n.plugin); !os.IsNotExist(err) {
		t.Errorf("the plugin is still installed: %v", err)
	}
	// Again: nothing to do, no error.
	if err := Uninstall(n.cfg); err != nil {
		t.Fatal(err)
	}
}
