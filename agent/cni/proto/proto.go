// Package proto is the protocol between the cracha-cni plugin and
// cracha-agent in cni-mode enrolment (docs/design.md, section 7.2): JSON
// over HTTP on the agent's Unix socket (agent.cni.socket). The plugin is a
// later slice; this is what it will speak and what the agent's server side
// (agent/internal/cni/server) serves.
//
// On CNI ADD the plugin POSTs AddPath with an AddRequest: the network
// namespace path of the sandbox (CNI_NETNS) and the pod reference from the
// runtime's CNI args (K8S_POD_NAMESPACE, K8S_POD_NAME, K8S_POD_UID). The
// agent answers 200 with an AddResponse: Enrolled false means the pod does
// not carry the enrolment label and the plugin does nothing; Enrolled true
// means the listener is bound in that namespace. Any other status is a
// failed ADD, which fails the sandbox and kubelet retries.
//
// On CNI DEL the plugin POSTs DelPath with a DelRequest; the agent closes
// the pod's listener if it had one and answers 200 either way. A DEL that
// cannot reach the agent is not an error for the plugin: the agent's pod
// watch closes the listener when the pod goes.
package proto

import (
	"context"
	"net"
	"net/http"
	"time"
)

// Paths of the agent's CNI endpoint.
const (
	AddPath = "/v1/add"
	DelPath = "/v1/del"
)

// Host is the HTTP host of every request; the socket, not the name, routes
// it.
const Host = "cracha-agent"

// PodRef names the pod the sandbox belongs to.
type PodRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
}

// AddRequest is the body of ADD.
type AddRequest struct {
	Pod PodRef `json:"pod"`
	// Netns is the sandbox's network namespace path, as the runtime gave it
	// to the plugin (CNI_NETNS).
	Netns string `json:"netns"`
}

// AddResponse is the answer to a successful ADD.
type AddResponse struct {
	// Enrolled is whether the pod carries the enrolment label and now has
	// its listener bound.
	Enrolled bool `json:"enrolled"`
	// Port is the listener's port when Enrolled.
	Port int `json:"port,omitempty"`
}

// DelRequest is the body of DEL.
type DelRequest struct {
	Pod PodRef `json:"pod"`
}

// NewClient returns an http.Client that reaches the agent's socket; request
// URLs are http://cracha-agent<path>. timeout bounds each request.
func NewClient(socket string, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
		},
	}
}

// URL is the request URL of path on the agent.
func URL(path string) string {
	return "http://" + Host + path
}
