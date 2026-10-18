package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/bpalermo/cracha/agent/cni/proto"
	"github.com/bpalermo/cracha/agent/enrolapi"
	"github.com/bpalermo/cracha/agent/internal/enrol"
	"github.com/bpalermo/cracha/agent/internal/listener"
)

type fakeRegistry struct {
	mu     sync.Mutex
	bound  map[string]string
	fail   error
	closed []string
}

func (r *fakeRegistry) Bind(pod listener.Pod, netnsPath string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail != nil {
		return r.fail
	}
	r.bound[pod.UID] = netnsPath
	return nil
}

func (r *fakeRegistry) Close(uid string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = append(r.closed, uid)
	_, ok := r.bound[uid]
	delete(r.bound, uid)
	return ok
}

func pod(name, uid string, enrolled bool) *corev1.Pod {
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: name, UID: types.UID(uid)}}
	if enrolled {
		p.Labels = map[string]string{enrolapi.Label: enrolapi.LabelValue}
	}
	return p
}

func newServer(reg *fakeRegistry) *Server {
	client := fake.NewClientset(pod("api", "uid-1", true), pod("plain", "uid-2", false))
	return New(enrol.NewEnroller(client, reg, nil), 9797, nil)
}

func call(h http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if s, ok := body.(string); ok {
		buf.WriteString(s)
	} else if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, proto.URL(path), &buf)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAddBindsAnEnrolledPod(t *testing.T) {
	reg := &fakeRegistry{bound: map[string]string{}}
	srv := newServer(reg)
	rec := call(srv, http.MethodPost, proto.AddPath, proto.AddRequest{
		Pod: proto.PodRef{Namespace: "apps", Name: "api", UID: "uid-1"}, Netns: "/var/run/netns/cni-1",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	var resp proto.AddResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || !resp.Enrolled || resp.Port != 9797 {
		t.Fatalf("response = %s (%v)", rec.Body.String(), err)
	}
	if reg.bound["uid-1"] != "/var/run/netns/cni-1" {
		t.Fatalf("bound = %v, want the path the plugin gave", reg.bound)
	}
}

func TestAddAnswersNotEnrolledForAPlainPod(t *testing.T) {
	reg := &fakeRegistry{bound: map[string]string{}}
	rec := call(newServer(reg), http.MethodPost, proto.AddPath, proto.AddRequest{
		Pod: proto.PodRef{Namespace: "apps", Name: "plain", UID: "uid-2"}, Netns: "/var/run/netns/cni-2",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	var resp proto.AddResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.Enrolled {
		t.Fatalf("response = %s (%v), want not enrolled", rec.Body.String(), err)
	}
	if len(reg.bound) != 0 {
		t.Error("a plain pod was bound")
	}
}

func TestAddFailures(t *testing.T) {
	for name, tc := range map[string]struct {
		body any
		fail error
		want int
	}{
		"recycled name":  {proto.AddRequest{Pod: proto.PodRef{Namespace: "apps", Name: "api", UID: "uid-old"}, Netns: "/n"}, nil, http.StatusForbidden},
		"unknown pod":    {proto.AddRequest{Pod: proto.PodRef{Namespace: "apps", Name: "nope", UID: "u"}, Netns: "/n"}, nil, http.StatusForbidden},
		"bind failed":    {proto.AddRequest{Pod: proto.PodRef{Namespace: "apps", Name: "api", UID: "uid-1"}, Netns: "/n"}, errors.New("EPERM"), http.StatusInternalServerError},
		"no netns":       {proto.AddRequest{Pod: proto.PodRef{Namespace: "apps", Name: "api", UID: "uid-1"}}, nil, http.StatusBadRequest},
		"no uid":         {proto.AddRequest{Pod: proto.PodRef{Namespace: "apps", Name: "api"}, Netns: "/n"}, nil, http.StatusBadRequest},
		"not json":       {"{", nil, http.StatusBadRequest},
		"too large body": {strings.Repeat(" ", maxBody+1) + "{}", nil, http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			reg := &fakeRegistry{bound: map[string]string{}, fail: tc.fail}
			rec := call(newServer(reg), http.MethodPost, proto.AddPath, tc.body)
			if rec.Code != tc.want {
				t.Fatalf("got %d %s, want %d", rec.Code, rec.Body.String(), tc.want)
			}
			if len(reg.bound) != 0 {
				t.Error("a failed ADD bound a listener")
			}
		})
	}
}

func TestDelClosesTheListener(t *testing.T) {
	reg := &fakeRegistry{bound: map[string]string{"uid-1": "/n"}}
	srv := newServer(reg)
	for _, uid := range []string{"uid-1", "uid-1", "never-bound"} {
		rec := call(srv, http.MethodPost, proto.DelPath, proto.DelRequest{Pod: proto.PodRef{Namespace: "apps", Name: "api", UID: uid}})
		if rec.Code != http.StatusOK {
			t.Fatalf("DEL %s: got %d %s", uid, rec.Code, rec.Body.String())
		}
	}
	if len(reg.bound) != 0 || len(reg.closed) != 3 {
		t.Errorf("bound = %v, closed = %v", reg.bound, reg.closed)
	}
	if rec := call(srv, http.MethodPost, proto.DelPath, proto.DelRequest{}); rec.Code != http.StatusBadRequest {
		t.Errorf("DEL without a UID: %d", rec.Code)
	}
}

func TestOnlyAddAndDelArePosted(t *testing.T) {
	srv := newServer(&fakeRegistry{bound: map[string]string{}})
	if rec := call(srv, http.MethodGet, proto.AddPath, nil); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET add: %d", rec.Code)
	}
	if rec := call(srv, http.MethodPost, "/v1/other", nil); rec.Code != http.StatusNotFound {
		t.Errorf("other path: %d", rec.Code)
	}
}

func TestServeOverTheUnixSocket(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "cni.sock")
	reg := &fakeRegistry{bound: map[string]string{}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, socket, newServer(reg), nil) }()

	client := proto.NewClient(socket, 2*time.Second)
	var resp *http.Response
	var err error
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var body bytes.Buffer
		_ = json.NewEncoder(&body).Encode(proto.AddRequest{Pod: proto.PodRef{Namespace: "apps", Name: "api", UID: "uid-1"}, Netns: "/n"})
		if resp, err = client.Post(proto.URL(proto.AddPath), "application/json", &body); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || reg.bound["uid-1"] != "/n" {
		t.Fatalf("ADD over the socket: %d, bound %v", resp.StatusCode, reg.bound)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
