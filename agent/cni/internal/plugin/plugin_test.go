package plugin

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"

	"github.com/bpalermo/cracha/agent/cni/proto"
)

// fakeAgent is the agent's endpoint over a Unix socket: it records what the
// plugin sent and answers as told.
type fakeAgent struct {
	socket string
	mu     sync.Mutex
	adds   []proto.AddRequest
	dels   []proto.DelRequest
	// answer is the ADD's status and body; 0 answers 200 with enrolled.
	status int
	body   string
}

func newFakeAgent(t *testing.T) *fakeAgent {
	t.Helper()
	a := &fakeAgent{socket: filepath.Join(t.TempDir(), "cni.sock")}
	lis, err := net.Listen("unix", a.socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(a.serve))
	srv.Listener = lis
	srv.Start()
	t.Cleanup(srv.Close)
	return a
}

func (a *fakeAgent) serve(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	switch r.URL.Path {
	case proto.AddPath:
		var req proto.AddRequest
		_ = json.Unmarshal(body, &req)
		a.adds = append(a.adds, req)
		if a.status != 0 {
			http.Error(w, a.body, a.status)
			return
		}
		enrolled := req.Pod.Name != "plain"
		_ = json.NewEncoder(w).Encode(proto.AddResponse{Enrolled: enrolled, Port: 9797})
	case proto.DelPath:
		var req proto.DelRequest
		_ = json.Unmarshal(body, &req)
		a.dels = append(a.dels, req)
	default:
		http.NotFound(w, r)
	}
}

const prevResult = `{"cniVersion":"0.3.1","interfaces":[{"name":"eth0","sandbox":"/var/run/netns/cni-1"}],"ips":[{"version":"4","address":"10.244.0.5/24","gateway":"10.244.0.1"}],"routes":[{"dst":"0.0.0.0/0"}],"dns":{}}`

func stdin(socket string, chained bool) []byte {
	conf := `{"cniVersion":"0.3.1","name":"kindnet","type":"cracha-cni","socket":"` + socket + `","timeout":"2s"`
	if chained {
		conf += `,"prevResult":` + prevResult
	}
	return []byte(conf + "}")
}

func cmdArgs(socket string, chained bool, name string) *skel.CmdArgs {
	return &skel.CmdArgs{
		ContainerID: "c1", Netns: "/var/run/netns/cni-1", IfName: "eth0",
		Args:      "IgnoreUnknown=1;K8S_POD_NAMESPACE=apps;K8S_POD_NAME=" + name + ";K8S_POD_INFRA_CONTAINER_ID=c1;K8S_POD_UID=uid-1",
		StdinData: stdin(socket, chained),
	}
}

func newPlugin(out *bytes.Buffer) *Plugin {
	return &Plugin{Stdout: out, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func TestAddEnrolledReturnsThePreviousResultUnchanged(t *testing.T) {
	agent := newFakeAgent(t)
	var out bytes.Buffer
	if err := newPlugin(&out).Add(cmdArgs(agent.socket, true, "api")); err != nil {
		t.Fatal(err)
	}
	if out.String() != prevResult {
		t.Errorf("stdout = %s, want the previous result byte for byte", out.String())
	}
	if len(agent.adds) != 1 || agent.adds[0].Netns != "/var/run/netns/cni-1" ||
		agent.adds[0].Pod != (proto.PodRef{Namespace: "apps", Name: "api", UID: "uid-1"}) {
		t.Errorf("the agent got %+v", agent.adds)
	}
}

func TestAddNotEnrolledReturnsThePreviousResultUnchanged(t *testing.T) {
	agent := newFakeAgent(t)
	var out bytes.Buffer
	if err := newPlugin(&out).Add(cmdArgs(agent.socket, true, "plain")); err != nil {
		t.Fatal(err)
	}
	if out.String() != prevResult {
		t.Errorf("stdout = %s, want the previous result byte for byte", out.String())
	}
}

// An agent that is down, or refuses, fails the ADD (kubelet retries the
// sandbox), with the socket in the message.
func TestAddFailsClosed(t *testing.T) {
	down := filepath.Join(t.TempDir(), "down.sock")
	refusing := newFakeAgent(t)
	refusing.status = http.StatusForbidden
	refusing.body = "no such pod"
	failing := newFakeAgent(t)
	failing.status = http.StatusInternalServerError
	failing.body = "bind: EPERM"
	for name, tc := range map[string]struct {
		socket string
		want   string
	}{
		"agent down":    {down, "unreachable"},
		"agent refuses": {refusing.socket, "403 Forbidden: no such pod"},
		"bind failed":   {failing.socket, "500 Internal Server Error: bind: EPERM"},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			err := newPlugin(&out).Add(cmdArgs(tc.socket, true, "api"))
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), tc.socket) {
				t.Fatalf("err = %v, want %q naming %s", err, tc.want, tc.socket)
			}
			if out.Len() != 0 {
				t.Errorf("a failed ADD printed %s", out.String())
			}
		})
	}
}

func TestAddRefusesMalformedInput(t *testing.T) {
	agent := newFakeAgent(t)
	good := cmdArgs(agent.socket, true, "api")
	for name, args := range map[string]*skel.CmdArgs{
		"not chained":     cmdArgs(agent.socket, false, "api"),
		"no uid":          {Netns: good.Netns, Args: "K8S_POD_NAMESPACE=apps;K8S_POD_NAME=api", StdinData: good.StdinData},
		"no namespace":    {Netns: good.Netns, Args: "K8S_POD_NAME=api;K8S_POD_UID=u", StdinData: good.StdinData},
		"no args":         {Netns: good.Netns, StdinData: good.StdinData},
		"unreadable args": {Netns: good.Netns, Args: "K8S_POD_NAMESPACE", StdinData: good.StdinData},
		"no netns":        {Args: good.Args, StdinData: good.StdinData},
		"bad conf":        {Netns: good.Netns, Args: good.Args, StdinData: []byte(`{"cniVersion":"0.3.1","name":"n","type":"cracha-cni"}`)},
		"bad prevResult":  {Netns: good.Netns, Args: good.Args, StdinData: []byte(`{"cniVersion":"0.3.1","name":"n","type":"cracha-cni","socket":"/s","prevResult":"nope"}`)},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			if err := newPlugin(&out).Add(args); err == nil {
				t.Fatal("the ADD succeeded")
			}
			if len(agent.adds) != 0 {
				t.Errorf("the agent was called: %+v", agent.adds)
			}
		})
	}
}

func TestDelTellsTheAgent(t *testing.T) {
	agent := newFakeAgent(t)
	if err := newPlugin(nil).Del(cmdArgs(agent.socket, false, "api")); err != nil {
		t.Fatal(err)
	}
	if len(agent.dels) != 1 || agent.dels[0].Pod != (proto.PodRef{Namespace: "apps", Name: "api", UID: "uid-1"}) {
		t.Errorf("the agent got %+v", agent.dels)
	}
}

// A DEL never fails the teardown: not with the agent down, not with
// unreadable input.
func TestDelIsBestEffort(t *testing.T) {
	down := filepath.Join(t.TempDir(), "down.sock")
	for name, args := range map[string]*skel.CmdArgs{
		"agent down": cmdArgs(down, false, "api"),
		"no args":    {StdinData: stdin(down, false)},
		"bad conf":   {Args: "K8S_POD_UID=u", StdinData: []byte(`{`)},
	} {
		t.Run(name, func(t *testing.T) {
			if err := newPlugin(nil).Del(args); err != nil {
				t.Fatalf("DEL failed: %v", err)
			}
		})
	}
}

func TestCheckIsANoOp(t *testing.T) {
	if err := newPlugin(nil).Check(cmdArgs(filepath.Join(t.TempDir(), "down.sock"), true, "api")); err != nil {
		t.Fatal(err)
	}
}
