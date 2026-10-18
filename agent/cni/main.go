// Command cracha-cni is the chained CNI plugin of cni-mode enrolment
// (docs/design.md, section 7.2). `cracha-agent cni-install` copies it from
// the agent image into the node's CNI bin directory and chains it after the
// node's primary plugin; the runtime then execs it on every sandbox's ADD,
// DEL and CHECK, and it tells the agent over its Unix socket (internal/plugin).
package main

import (
	"log/slog"
	"os"

	"github.com/containernetworking/cni/pkg/skel"
	cniversion "github.com/containernetworking/cni/pkg/version"

	"github.com/bpalermo/cracha/agent/cni/internal/plugin"
	"github.com/bpalermo/cracha/common/version"
)

func main() {
	// The runtime keeps the plugin's stderr; stdout is the protocol's.
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil)).With("plugin", "cracha-cni")
	p := &plugin.Plugin{Stdout: os.Stdout, Log: log}
	// From 0.3.0, the first with chaining and a prevResult. GC and STATUS
	// (1.1.0) are not implemented and succeed as no-ops: the agent owns
	// every listener, and a plugin that answered STATUS by the agent's
	// health would make the node's network not ready whenever the agent
	// restarts.
	skel.PluginMainFuncs(skel.CNIFuncs{Add: p.Add, Check: p.Check, Del: p.Del},
		cniversion.PluginSupports("0.3.0", "0.3.1", "0.4.0", "1.0.0", "1.1.0"),
		"cracha-cni "+version.Version)
}
