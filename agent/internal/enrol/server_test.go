package enrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/bpalermo/cracha/agent/enrolapi"
	"github.com/bpalermo/cracha/agent/internal/cri"
	"github.com/bpalermo/cracha/agent/internal/tokenreview"
)

// reviewer accepts "good" as a token bound to apps/api uid-1.
var reviewer = &tokenreview.Fake{Fn: func(token, audience string) (tokenreview.Result, error) {
	if audience != enrolapi.Audience {
		return tokenreview.Result{}, errors.New("wrong audience " + audience)
	}
	switch token {
	case "good":
		return tokenreview.Result{Username: "system:serviceaccount:apps:api", PodName: "api", PodUID: "uid-1"}, nil
	case "unbound":
		return tokenreview.Result{Username: "system:serviceaccount:apps:api"}, nil
	case "other-node":
		return tokenreview.Result{Username: "system:serviceaccount:apps:far", PodName: "far", PodUID: "uid-far"}, nil
	case "apiserver-down":
		return tokenreview.Result{}, fmt.Errorf("%w: dial tcp: connection refused", tokenreview.ErrUnavailable)
	}
	return tokenreview.Result{}, errors.New("invalid token")
}}

// resolver knows uid-1's sandbox and nothing else's.
var resolver = cri.ResolverFunc(func(_ context.Context, uid string) (string, error) {
	switch uid {
	case "uid-1":
		return "/run/netns/cni-1", nil
	case "uid-cri-down":
		return "", errors.New("connection refused")
	}
	return "", cri.ErrNoSandbox
})

func newServer(t *testing.T, reg *fakeRegistry, cfg ServerConfig) *Server {
	t.Helper()
	client := fake.NewClientset(enrolledPod("apps", "api", "uid-1"), enrolledPod("apps", "far", "uid-far"))
	cfg.Port = 9797
	return NewServer(reviewer, NewEnroller(client, reg, nil), resolver, cfg)
}

func post(h http.Handler, method, path, auth string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestEnrolEndpointBindsTheTokensPod(t *testing.T) {
	reg := newFakeRegistry()
	srv := newServer(t, reg, ServerConfig{})
	rec := post(srv, http.MethodPost, enrolapi.Path, "Bearer good")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	var ack enrolapi.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &ack); err != nil || ack.Port != 9797 {
		t.Fatalf("ack = %s (%v)", rec.Body.String(), err)
	}
	if reg.netnsOf("uid-1") != "/run/netns/cni-1" {
		t.Fatalf("bound = %v", reg.bound)
	}
	// Case-insensitive scheme, as HTTP has it.
	if rec := post(srv, http.MethodPost, enrolapi.Path, "bearer good"); rec.Code != http.StatusOK {
		t.Errorf("lowercase bearer: %d", rec.Code)
	}
}

func TestEnrolEndpointRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		method, path, auth string
		want               int
	}{
		"no token":            {http.MethodPost, enrolapi.Path, "", http.StatusUnauthorized},
		"not a bearer":        {http.MethodPost, enrolapi.Path, "Basic good", http.StatusUnauthorized},
		"bad token":           {http.MethodPost, enrolapi.Path, "Bearer bad", http.StatusUnauthorized},
		"unbound token":       {http.MethodPost, enrolapi.Path, "Bearer unbound", http.StatusUnauthorized},
		"no sandbox here":     {http.MethodPost, enrolapi.Path, "Bearer other-node", http.StatusForbidden},
		"apiserver down":      {http.MethodPost, enrolapi.Path, "Bearer apiserver-down", http.StatusServiceUnavailable},
		"GET":                 {http.MethodGet, enrolapi.Path, "Bearer good", http.StatusMethodNotAllowed},
		"other path":          {http.MethodPost, "/v1/other", "Bearer good", http.StatusNotFound},
		"credentials path":    {http.MethodPost, "/v1/credentials", "Bearer good", http.StatusNotFound},
		"the root":            {http.MethodPost, "/", "Bearer good", http.StatusNotFound},
		"healthz is not here": {http.MethodGet, "/healthz", "", http.StatusNotFound},
	} {
		t.Run(name, func(t *testing.T) {
			reg := newFakeRegistry()
			rec := post(newServer(t, reg, ServerConfig{}), tc.method, tc.path, tc.auth)
			if rec.Code != tc.want {
				t.Fatalf("got %d %s, want %d", rec.Code, rec.Body.String(), tc.want)
			}
			if len(reg.bound) != 0 {
				t.Error("a refused enrolment bound a listener")
			}
			for _, detail := range []string{"uid-", "connection refused", "invalid token", "no such pod"} {
				if strings.Contains(rec.Body.String(), detail) {
					t.Errorf("the body tells an unauthenticated caller %q: %s", detail, rec.Body.String())
				}
			}
		})
	}
}

func TestEnrolEndpointLimitsPerSourceBeforeTheReview(t *testing.T) {
	reg := newFakeRegistry()
	calls := &tokenreview.Fake{Fn: reviewer.Fn}
	client := fake.NewClientset(enrolledPod("apps", "api", "uid-1"))
	srv := NewServer(calls, NewEnroller(client, reg, nil), resolver, ServerConfig{Port: 1, SourceRate: rate.Every(time.Hour), SourceBurst: 2})
	from := func(addr, auth string) int {
		req := httptest.NewRequest(http.MethodPost, enrolapi.Path, nil)
		req.RemoteAddr = addr
		req.Header.Set("Authorization", auth)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec.Code
	}
	for i := range 2 {
		if code := from("10.0.0.7:4000", "Bearer garbage"); code != http.StatusUnauthorized {
			t.Fatalf("request %d: %d", i, code)
		}
	}
	if code := from("10.0.0.7:4001", "Bearer garbage"); code != http.StatusTooManyRequests {
		t.Fatalf("third request from the flooding address: %d, want 429", code)
	}
	if calls.Calls() != 2 {
		t.Errorf("%d TokenReviews, want the limited request to cost none", calls.Calls())
	}
	// Another address is not held back by the flood.
	if code := from("10.0.0.8:4000", "Bearer good"); code != http.StatusOK {
		t.Fatalf("another pod: %d, want 200", code)
	}
}

func TestEnrolEndpointNotEnrolledIs403(t *testing.T) {
	pod := enrolledPod("apps", "api", "uid-1")
	pod.Labels = nil
	reg := newFakeRegistry()
	srv := NewServer(reviewer, NewEnroller(fake.NewClientset(pod), reg, nil), resolver, ServerConfig{Port: 1})
	if rec := post(srv, http.MethodPost, enrolapi.Path, "Bearer good"); rec.Code != http.StatusForbidden {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
}

func TestEnrolEndpointFailuresAre503(t *testing.T) {
	// The CRI is down: retryable.
	r := &tokenreview.Fake{Fn: func(string, string) (tokenreview.Result, error) {
		return tokenreview.Result{Username: "system:serviceaccount:apps:api", PodName: "api", PodUID: "uid-cri-down"}, nil
	}}
	reg := newFakeRegistry()
	srv := NewServer(r, NewEnroller(fake.NewClientset(enrolledPod("apps", "api", "uid-cri-down")), reg, nil), resolver, ServerConfig{Port: 1})
	if rec := post(srv, http.MethodPost, enrolapi.Path, "Bearer x"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("CRI down: got %d %s", rec.Code, rec.Body.String())
	}
	// The bind failed: retryable.
	reg = newFakeRegistry()
	reg.fail = errors.New("EPERM")
	srv = newServer(t, reg, ServerConfig{})
	if rec := post(srv, http.MethodPost, enrolapi.Path, "Bearer good"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("bind failed: got %d %s", rec.Code, rec.Body.String())
	}
}

func TestEnrolEndpointGlobalLimitPrecedesTheReview(t *testing.T) {
	reg := newFakeRegistry()
	calls := &tokenreview.Fake{Fn: reviewer.Fn}
	client := fake.NewClientset(enrolledPod("apps", "api", "uid-1"))
	srv := NewServer(calls, NewEnroller(client, reg, nil), resolver, ServerConfig{Port: 1, GlobalRate: rate.Every(time.Hour), GlobalBurst: 2})
	for i := range 2 {
		if rec := post(srv, http.MethodPost, enrolapi.Path, "Bearer good"); rec.Code != http.StatusOK {
			t.Fatalf("request %d: %d", i, rec.Code)
		}
	}
	if rec := post(srv, http.MethodPost, enrolapi.Path, "Bearer garbage"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("third request: %d, want 429", rec.Code)
	}
	if calls.Calls() != 2 {
		t.Errorf("%d TokenReviews, want the limited request to cost none", calls.Calls())
	}
}

func TestEnrolEndpointRateLimitsPerPod(t *testing.T) {
	reg := newFakeRegistry()
	srv := newServer(t, reg, ServerConfig{Rate: rate.Every(time.Hour), Burst: 2})
	now := time.Now()
	srv.now = func() time.Time { return now }
	for i := range 2 {
		if rec := post(srv, http.MethodPost, enrolapi.Path, "Bearer good"); rec.Code != http.StatusOK {
			t.Fatalf("request %d: %d", i, rec.Code)
		}
	}
	if rec := post(srv, http.MethodPost, enrolapi.Path, "Bearer good"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("third request: %d, want 429", rec.Code)
	}
	// Another pod is not held back by the first.
	if rec := post(srv, http.MethodPost, enrolapi.Path, "Bearer other-node"); rec.Code != http.StatusForbidden {
		t.Fatalf("other pod: %d, want its own verdict", rec.Code)
	}
	// Idle limiters are dropped, after which the pod starts afresh.
	now = now.Add(limiterTTL + time.Second)
	if rec := post(srv, http.MethodPost, enrolapi.Path, "Bearer good"); rec.Code != http.StatusOK {
		t.Fatalf("after the TTL: %d", rec.Code)
	}
}
