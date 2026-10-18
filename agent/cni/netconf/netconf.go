// Package netconf is the network configuration of the cracha-cni plugin
// (docs/design.md, section 7.2): the entry the installer appends to the
// node's primary conflist and the plugin reads from its stdin on every ADD,
// DEL and CHECK. Both sides import it so the shape on disk cannot drift
// from what the plugin parses.
//
// The entry is
//
//	{"type": "cracha-cni", "socket": "/run/cracha/cni.sock", "timeout": "5s"}
//
// chained after the node's primary plugin. The conflist owns cniVersion and
// name, so the entry carries neither; the runtime adds them, and prevResult,
// to what the plugin reads.
package netconf

import (
	"encoding/json"
	"fmt"
	"time"
)

// PluginType is the plugin's "type" in the conflist, and the name of its
// binary in the CNI bin directory.
const PluginType = "cracha-cni"

// DefaultTimeout bounds one call of the plugin to the agent when the entry
// gives no timeout.
const DefaultTimeout = 5 * time.Second

// Conf is the plugin's configuration as the runtime hands it over: the
// entry, with what the conflist and the runtime add.
type Conf struct {
	CNIVersion string `json:"cniVersion"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	// PrevResult is the previous plugin's result as the runtime gave it,
	// untouched: ADD prints it as its own.
	PrevResult json.RawMessage `json:"prevResult,omitempty"`
	// Socket is the agent's Unix socket (agent.cni.socket).
	Socket string `json:"socket"`
	// Timeout bounds one call to the agent, as a Go duration; empty is
	// DefaultTimeout.
	Timeout string `json:"timeout,omitempty"`
}

// Entry is the conflist entry the installer writes: the type, the socket
// and the default timeout, marshalled in that order.
type Entry struct {
	Type    string `json:"type"`
	Socket  string `json:"socket"`
	Timeout string `json:"timeout"`
}

// NewEntry is the entry naming socket.
func NewEntry(socket string) Entry {
	return Entry{Type: PluginType, Socket: socket, Timeout: DefaultTimeout.String()}
}

// Parse decodes the plugin's stdin. It requires the socket and a parseable
// timeout; the previous plugin's result is left raw.
func Parse(stdin []byte) (*Conf, error) {
	var c Conf
	if err := json.Unmarshal(stdin, &c); err != nil {
		return nil, fmt.Errorf("unreadable network configuration: %w", err)
	}
	if c.Type != PluginType {
		return nil, fmt.Errorf("network configuration is for %q, not %s", c.Type, PluginType)
	}
	if c.Socket == "" {
		return nil, fmt.Errorf("network configuration names no agent socket")
	}
	if _, err := c.CallTimeout(); err != nil {
		return nil, err
	}
	return &c, nil
}

// CallTimeout is Timeout parsed, or DefaultTimeout.
func (c *Conf) CallTimeout() (time.Duration, error) {
	if c.Timeout == "" {
		return DefaultTimeout, nil
	}
	d, err := time.ParseDuration(c.Timeout)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("network configuration timeout %q is not a positive duration", c.Timeout)
	}
	return d, nil
}
