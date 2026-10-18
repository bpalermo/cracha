package cri

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// fakeRuntime is a RuntimeServiceClient with the two calls the resolver
// makes; every other method panics with a nil interface.
type fakeRuntime struct {
	runtimeapi.RuntimeServiceClient
	sandboxes []*runtimeapi.PodSandbox
	listErr   error
	status    map[string]*runtimeapi.PodSandboxStatusResponse
	listCalls []*runtimeapi.ListPodSandboxRequest
}

func (f *fakeRuntime) ListPodSandbox(_ context.Context, req *runtimeapi.ListPodSandboxRequest, _ ...grpc.CallOption) (*runtimeapi.ListPodSandboxResponse, error) {
	f.listCalls = append(f.listCalls, req)
	if f.listErr != nil {
		return nil, f.listErr
	}
	var items []*runtimeapi.PodSandbox
	for _, s := range f.sandboxes {
		if s.GetLabels()[PodUIDLabel] == req.GetFilter().GetLabelSelector()[PodUIDLabel] &&
			s.GetState() == req.GetFilter().GetState().GetState() {
			items = append(items, s)
		}
	}
	return &runtimeapi.ListPodSandboxResponse{Items: items}, nil
}

func (f *fakeRuntime) PodSandboxStatus(_ context.Context, req *runtimeapi.PodSandboxStatusRequest, _ ...grpc.CallOption) (*runtimeapi.PodSandboxStatusResponse, error) {
	resp, ok := f.status[req.GetPodSandboxId()]
	if !ok {
		return nil, errors.New("no such sandbox")
	}
	if !req.GetVerbose() {
		return &runtimeapi.PodSandboxStatusResponse{Status: resp.Status}, nil
	}
	return resp, nil
}

func sandbox(id, uid string, state runtimeapi.PodSandboxState, created int64) *runtimeapi.PodSandbox {
	return &runtimeapi.PodSandbox{Id: id, State: state, CreatedAt: created, Labels: map[string]string{PodUIDLabel: uid}}
}

// containerdInfo is the shape of containerd's verbose sandbox info, cut to
// what matters, as CRI-O's is.
const containerdInfo = `{"pid":12345,"processStatus":"running","runtimeType":"io.containerd.runc.v2",` +
	`"runtimeSpec":{"ociVersion":"1.1.0","linux":{"namespaces":[{"type":"pid"},{"type":"ipc"},` +
	`{"type":"uts"},{"type":"mount"},{"type":"network","path":"/var/run/netns/cni-0a1b2c3d"}]}}}`

const crioInfo = `{"image":"registry.k8s.io/pause:3.10","pid":777,"runtimeSpec":{"linux":{"namespaces":` +
	`[{"type":"network","path":"/var/run/netns/3f2a9b1c-ipc"},{"type":"ipc","path":"/var/run/ipcns/x"}]}}}`

func statusWithInfo(info string) *runtimeapi.PodSandboxStatusResponse {
	return &runtimeapi.PodSandboxStatusResponse{
		Status: &runtimeapi.PodSandboxStatus{Linux: &runtimeapi.LinuxPodSandboxStatus{
			Namespaces: &runtimeapi.Namespace{Options: &runtimeapi.NamespaceOption{Network: runtimeapi.NamespaceMode_POD}},
		}},
		Info: map[string]string{"info": info},
	}
}

func TestNetnsPathContainerdAndCRIO(t *testing.T) {
	for name, tc := range map[string]struct {
		info string
		want string
	}{
		"containerd": {containerdInfo, "/var/run/netns/cni-0a1b2c3d"},
		"cri-o":      {crioInfo, "/var/run/netns/3f2a9b1c-ipc"},
	} {
		t.Run(name, func(t *testing.T) {
			rt := &fakeRuntime{
				sandboxes: []*runtimeapi.PodSandbox{sandbox("sb1", "uid-1", runtimeapi.PodSandboxState_SANDBOX_READY, 1)},
				status:    map[string]*runtimeapi.PodSandboxStatusResponse{"sb1": statusWithInfo(tc.info)},
			}
			got, err := NewWithService(rt).NetnsPath(context.Background(), "uid-1")
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("NetnsPath = %q, want %q", got, tc.want)
			}
			if len(rt.listCalls) != 1 || rt.listCalls[0].GetFilter().GetLabelSelector()[PodUIDLabel] != "uid-1" {
				t.Errorf("ListPodSandbox was not filtered by the pod UID: %v", rt.listCalls)
			}
		})
	}
}

func TestNetnsPathTakesTheNewestReadySandbox(t *testing.T) {
	rt := &fakeRuntime{
		sandboxes: []*runtimeapi.PodSandbox{
			sandbox("old", "uid-1", runtimeapi.PodSandboxState_SANDBOX_READY, 1),
			sandbox("gone", "uid-1", runtimeapi.PodSandboxState_SANDBOX_NOTREADY, 3),
			sandbox("new", "uid-1", runtimeapi.PodSandboxState_SANDBOX_READY, 2),
		},
		status: map[string]*runtimeapi.PodSandboxStatusResponse{
			"old": statusWithInfo(crioInfo),
			"new": statusWithInfo(containerdInfo),
		},
	}
	got, err := NewWithService(rt).NetnsPath(context.Background(), "uid-1")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/var/run/netns/cni-0a1b2c3d" {
		t.Fatalf("NetnsPath = %q, want the newest ready sandbox's", got)
	}
}

func TestNetnsPathRefusals(t *testing.T) {
	hostNet := statusWithInfo(containerdInfo)
	hostNet.Status.Linux.Namespaces.Options.Network = runtimeapi.NamespaceMode_NODE
	for name, tc := range map[string]struct {
		rt   *fakeRuntime
		uid  string
		want error
	}{
		"no sandbox on this node": {
			rt:  &fakeRuntime{sandboxes: []*runtimeapi.PodSandbox{sandbox("sb", "other", runtimeapi.PodSandboxState_SANDBOX_READY, 1)}},
			uid: "uid-1", want: ErrNoSandbox,
		},
		"host network by status": {
			rt: &fakeRuntime{
				sandboxes: []*runtimeapi.PodSandbox{sandbox("sb", "uid-1", runtimeapi.PodSandboxState_SANDBOX_READY, 1)},
				status:    map[string]*runtimeapi.PodSandboxStatusResponse{"sb": hostNet},
			},
			uid: "uid-1", want: ErrHostNetwork,
		},
		"host network by spec": {
			rt: &fakeRuntime{
				sandboxes: []*runtimeapi.PodSandbox{sandbox("sb", "uid-1", runtimeapi.PodSandboxState_SANDBOX_READY, 1)},
				status:    map[string]*runtimeapi.PodSandboxStatusResponse{"sb": statusWithInfo(`{"runtimeSpec":{"linux":{"namespaces":[{"type":"pid"}]}}}`)},
			},
			uid: "uid-1", want: ErrHostNetwork,
		},
		"no path": {
			rt: &fakeRuntime{
				sandboxes: []*runtimeapi.PodSandbox{sandbox("sb", "uid-1", runtimeapi.PodSandboxState_SANDBOX_READY, 1)},
				status:    map[string]*runtimeapi.PodSandboxStatusResponse{"sb": statusWithInfo(`{"runtimeSpec":{"linux":{"namespaces":[{"type":"network"}]}}}`)},
			},
			uid: "uid-1", want: ErrNoNetnsPath,
		},
		"no info": {
			rt: &fakeRuntime{
				sandboxes: []*runtimeapi.PodSandbox{sandbox("sb", "uid-1", runtimeapi.PodSandboxState_SANDBOX_READY, 1)},
				status:    map[string]*runtimeapi.PodSandboxStatusResponse{"sb": {Status: &runtimeapi.PodSandboxStatus{}}},
			},
			uid: "uid-1", want: ErrNoNetnsPath,
		},
		"unreadable info": {
			rt: &fakeRuntime{
				sandboxes: []*runtimeapi.PodSandbox{sandbox("sb", "uid-1", runtimeapi.PodSandboxState_SANDBOX_READY, 1)},
				status:    map[string]*runtimeapi.PodSandboxStatusResponse{"sb": statusWithInfo(`not json`)},
			},
			uid: "uid-1", want: ErrNoNetnsPath,
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewWithService(tc.rt).NetnsPath(context.Background(), tc.uid)
			if !errors.Is(err, tc.want) {
				t.Fatalf("NetnsPath = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestNetnsPathReportsRuntimeErrors(t *testing.T) {
	rt := &fakeRuntime{listErr: errors.New("connection refused")}
	if _, err := NewWithService(rt).NetnsPath(context.Background(), "uid-1"); err == nil || errors.Is(err, ErrNoSandbox) {
		t.Fatalf("NetnsPath = %v, want the runtime's error", err)
	}
	if _, err := NewWithService(rt).NetnsPath(context.Background(), ""); err == nil {
		t.Fatal("an empty UID was resolved")
	}
	if _, err := Dial(""); err == nil {
		t.Fatal("Dial of an empty socket succeeded")
	}
}
