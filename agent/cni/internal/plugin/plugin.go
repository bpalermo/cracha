// Package plugin is cracha-cni, the chained CNI plugin of cni-mode enrolment
// (docs/design.md, section 7.2). The runtime execs it after the node's
// primary plugin on every sandbox's ADD, DEL and CHECK; it tells the agent
// over its Unix socket (agent/cni/proto) and returns the previous plugin's
// result unchanged. It configures nothing itself: the agent decides whether
// the pod is enrolled and binds the listener.
//
// ADD fails closed: an agent that is unreachable, refuses the pod or cannot
// bind fails the ADD with an error naming the socket, and kubelet tears the
// sandbox down and retries. DEL is best effort: the agent's pod watch closes
// the listener of a pod that goes, so a DEL that cannot reach the agent is
// logged and succeeds rather than holding the teardown. CHECK does nothing.
package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/version"

	"github.com/bpalermo/cracha/agent/cni/netconf"
	"github.com/bpalermo/cracha/agent/cni/proto"
)

// maxBody bounds an answer of the agent; its are a few dozen bytes.
const maxBody = 64 << 10

// Plugin is the plugin's three commands.
type Plugin struct {
	// Stdout is where ADD prints the result, os.Stdout when nil.
	Stdout io.Writer
	// Log is the plugin's logger, slog's default when nil.
	Log *slog.Logger
}

// podArgs is what the runtime puts in CNI_ARGS for a pod (containerd and
// CRI-O both; the field names are the keys).
type podArgs struct {
	types.CommonArgs
	K8S_POD_NAMESPACE types.UnmarshallableString
	K8S_POD_NAME      types.UnmarshallableString
	K8S_POD_UID       types.UnmarshallableString
}

// ref is the pod reference of CNI_ARGS; every part is required, since the
// agent names the pod by all three.
func ref(args string) (proto.PodRef, error) {
	var a podArgs
	a.IgnoreUnknown = true
	if err := types.LoadArgs(args, &a); err != nil {
		return proto.PodRef{}, fmt.Errorf("unreadable CNI_ARGS: %w", err)
	}
	r := proto.PodRef{Namespace: string(a.K8S_POD_NAMESPACE), Name: string(a.K8S_POD_NAME), UID: string(a.K8S_POD_UID)}
	if r.Namespace == "" || r.Name == "" || r.UID == "" {
		return proto.PodRef{}, fmt.Errorf("CNI_ARGS name no pod: K8S_POD_NAMESPACE, K8S_POD_NAME and K8S_POD_UID are required, got %q", args)
	}
	return r, nil
}

func (p *Plugin) log() *slog.Logger {
	if p.Log == nil {
		return slog.Default()
	}
	return p.Log
}

// Add is CNI ADD: the agent is told the pod and its namespace path, and
// the previous plugin's result is printed as this plugin's, byte for byte.
func (p *Plugin) Add(args *skel.CmdArgs) error {
	conf, err := netconf.Parse(args.StdinData)
	if err != nil {
		return err
	}
	if len(conf.PrevResult) == 0 {
		return errors.New("cracha-cni must be chained after the node's primary plugin: no prevResult")
	}
	if _, err := version.NewResult(conf.CNIVersion, conf.PrevResult); err != nil {
		return fmt.Errorf("unreadable prevResult: %w", err)
	}
	pod, err := ref(args.Args)
	if err != nil {
		return err
	}
	if args.Netns == "" {
		return fmt.Errorf("no CNI_NETNS for pod %s/%s", pod.Namespace, pod.Name)
	}
	var resp proto.AddResponse
	if err := p.call(conf, proto.AddPath, proto.AddRequest{Pod: pod, Netns: args.Netns}, &resp); err != nil {
		return fmt.Errorf("ADD of pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	p.log().Info("ADD", "pod", pod.Namespace+"/"+pod.Name, "uid", pod.UID, "netns", args.Netns, "enrolled", resp.Enrolled, "port", resp.Port)
	out := p.Stdout
	if out == nil {
		out = os.Stdout
	}
	_, err = out.Write(conf.PrevResult)
	return err
}

// Del is CNI DEL: the agent is told to close the pod's listener. Nothing
// here fails the teardown.
func (p *Plugin) Del(args *skel.CmdArgs) error {
	log := p.log()
	conf, err := netconf.Parse(args.StdinData)
	if err != nil {
		log.Warn("DEL: not telling the agent", "error", err)
		return nil
	}
	pod, err := ref(args.Args)
	if err != nil {
		log.Warn("DEL: not telling the agent", "error", err)
		return nil
	}
	if err := p.call(conf, proto.DelPath, proto.DelRequest{Pod: pod}, nil); err != nil {
		log.Warn("DEL: the agent was not told; its pod watch closes the listener", "pod", pod.Namespace+"/"+pod.Name, "uid", pod.UID, "error", err)
		return nil
	}
	log.Info("DEL", "pod", pod.Namespace+"/"+pod.Name, "uid", pod.UID)
	return nil
}

// Check is CNI CHECK: nothing to verify, the agent owns the listener.
func (p *Plugin) Check(*skel.CmdArgs) error {
	return nil
}

// call POSTs body to the agent at path and decodes a 200's answer into
// out (when out is not nil). Any other outcome is an error naming the
// socket.
func (p *Plugin) call(conf *netconf.Conf, path string, body, out any) error {
	timeout, err := conf.CallTimeout()
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, proto.URL(path), &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := proto.NewClient(conf.Socket, timeout).Do(req)
	if err != nil {
		return fmt.Errorf("cracha-agent at %s is unreachable: %w", conf.Socket, err)
	}
	defer resp.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return fmt.Errorf("reading cracha-agent's answer from %s: %w", conf.Socket, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("cracha-agent at %s refused: %s: %s", conf.Socket, resp.Status, bytes.TrimSpace(answer))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(answer, out); err != nil {
		return fmt.Errorf("unreadable answer from cracha-agent at %s: %w", conf.Socket, err)
	}
	return nil
}
