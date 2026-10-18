// Package cri resolves a pod's network namespace path through the container
// runtime (docs/design.md, sections 7.2 and 7.4): ListPodSandbox by the pod's
// UID, PodSandboxStatus for the namespace path. A pod on another node names
// no sandbox here, which keeps init-mode enrolment node-local without
// trusting the caller's address.
//
// The namespace path is not part of the CRI status proper; it is in the
// runtime's verbose info, where containerd and CRI-O both report the OCI
// runtime spec (`info.runtimeSpec.linux.namespaces`, the entry of type
// network). Both forms are read; nothing else of the runtime is assumed.
package cri

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// PodUIDLabel is the sandbox label the kubelet sets to the pod's UID.
const PodUIDLabel = "io.kubernetes.pod.uid"

// Errors a resolution ends in.
var (
	// ErrNoSandbox: the runtime has no ready sandbox for the pod on this
	// node.
	ErrNoSandbox = errors.New("no ready sandbox for the pod on this node")
	// ErrHostNetwork: the sandbox uses the node's network namespace, which
	// has no path of its own.
	ErrHostNetwork = errors.New("the sandbox uses the host's network namespace")
	// ErrNoNetnsPath: the runtime did not report the namespace path in a
	// form this package reads.
	ErrNoNetnsPath = errors.New("the runtime's sandbox status reports no network namespace path")
)

// Resolver resolves a pod's network namespace path by its UID.
type Resolver interface {
	NetnsPath(ctx context.Context, podUID string) (string, error)
}

// ResolverFunc adapts a function to Resolver.
type ResolverFunc func(ctx context.Context, podUID string) (string, error)

// NetnsPath implements Resolver.
func (f ResolverFunc) NetnsPath(ctx context.Context, podUID string) (string, error) {
	return f(ctx, podUID)
}

// Client resolves through the CRI runtime service.
type Client struct {
	rt   runtimeapi.RuntimeServiceClient
	conn *grpc.ClientConn
}

// Dial returns a Client over the CRI socket at path. Nothing is connected
// until the first call.
func Dial(socket string) (*Client, error) {
	if socket == "" {
		return nil, errors.New("the CRI socket path is required")
	}
	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("creating the CRI client for %s: %w", socket, err)
	}
	return &Client{rt: runtimeapi.NewRuntimeServiceClient(conn), conn: conn}, nil
}

// NewWithService returns a Client over an already built runtime service.
func NewWithService(rt runtimeapi.RuntimeServiceClient) *Client {
	return &Client{rt: rt}
}

// Close releases the connection.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// NetnsPath implements Resolver.
func (c *Client) NetnsPath(ctx context.Context, podUID string) (string, error) {
	if podUID == "" {
		return "", errors.New("the pod UID is required")
	}
	id, err := c.sandbox(ctx, podUID)
	if err != nil {
		return "", err
	}
	resp, err := c.rt.PodSandboxStatus(ctx, &runtimeapi.PodSandboxStatusRequest{PodSandboxId: id, Verbose: true})
	if err != nil {
		return "", fmt.Errorf("PodSandboxStatus of %s: %w", id, err)
	}
	if opts := resp.GetStatus().GetLinux().GetNamespaces().GetOptions(); opts != nil &&
		opts.GetNetwork() == runtimeapi.NamespaceMode_NODE {
		return "", ErrHostNetwork
	}
	path, err := netnsFromInfo(resp.GetInfo())
	if err != nil {
		return "", fmt.Errorf("sandbox %s of pod %s: %w", id, podUID, err)
	}
	return path, nil
}

// sandbox returns the ID of the pod's ready sandbox; the newest when the
// runtime lists several.
func (c *Client) sandbox(ctx context.Context, podUID string) (string, error) {
	ready := runtimeapi.PodSandboxState_SANDBOX_READY
	resp, err := c.rt.ListPodSandbox(ctx, &runtimeapi.ListPodSandboxRequest{
		Filter: &runtimeapi.PodSandboxFilter{
			State:         &runtimeapi.PodSandboxStateValue{State: ready},
			LabelSelector: map[string]string{PodUIDLabel: podUID},
		},
	})
	if err != nil {
		return "", fmt.Errorf("ListPodSandbox for pod %s: %w", podUID, err)
	}
	items := resp.GetItems()
	if len(items) == 0 {
		return "", ErrNoSandbox
	}
	newest := slices.MaxFunc(items, func(a, b *runtimeapi.PodSandbox) int {
		return int(a.GetCreatedAt() - b.GetCreatedAt())
	})
	return newest.GetId(), nil
}

// runtimeInfo is the part of the runtime's verbose sandbox info that names
// the network namespace: the OCI runtime spec's namespaces. containerd and
// CRI-O both put the spec under runtimeSpec.
type runtimeInfo struct {
	RuntimeSpec struct {
		Linux struct {
			Namespaces []struct {
				Type string `json:"type"`
				Path string `json:"path"`
			} `json:"namespaces"`
		} `json:"linux"`
	} `json:"runtimeSpec"`
}

// netnsFromInfo reads the network namespace path out of the verbose info
// map (its "info" entry is a JSON document).
func netnsFromInfo(info map[string]string) (string, error) {
	raw, ok := info["info"]
	if !ok {
		return "", ErrNoNetnsPath
	}
	var ri runtimeInfo
	if err := json.Unmarshal([]byte(raw), &ri); err != nil {
		return "", fmt.Errorf("%w: unreadable info: %v", ErrNoNetnsPath, err)
	}
	for _, ns := range ri.RuntimeSpec.Linux.Namespaces {
		if ns.Type != "network" {
			continue
		}
		if ns.Path == "" {
			// A network namespace entry without a path is a new, anonymous
			// one in the OCI spec; runtimes give sandboxes a named one. No
			// path means nothing the agent can enter.
			return "", ErrNoNetnsPath
		}
		return ns.Path, nil
	}
	// No network namespace entry at all: the sandbox shares the host's.
	return "", ErrHostNetwork
}
