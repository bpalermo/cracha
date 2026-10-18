package enrol

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bpalermo/cracha/agent/enrolapi"
)

// agentStub answers the enrolment endpoint from a queue of statuses, the
// last one repeating, and records the bearers it saw.
type agentStub struct {
	statuses []int
	calls    atomic.Int32
	bearers  chan string
	body     string
}

func (a *agentStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n := int(a.calls.Add(1)) - 1
	select {
	case a.bearers <- r.Header.Get("Authorization"):
	default:
	}
	if r.Method != http.MethodPost || r.URL.Path != enrolapi.Path {
		http.Error(w, "wrong call", http.StatusNotFound)
		return
	}
	status := a.statuses[min(n, len(a.statuses)-1)]
	w.WriteHeader(status)
	if status == http.StatusOK {
		body := a.body
		if body == "" {
			body = `{"port":9797}`
		}
		w.Write([]byte(body))
	}
}

// clientFor returns a ClientConfig pointed at the stub, with a token file.
func clientFor(t *testing.T, stub *agentStub, accept bool) ClientConfig {
	t.Helper()
	srv := httptest.NewServer(stub)
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("tok.en\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var enrolPort int
	for _, c := range port {
		enrolPort = enrolPort*10 + int(c-'0')
	}
	return ClientConfig{
		HostIP: host, EnrolPort: enrolPort, Port: 9797, TokenFile: tokenFile,
		Timeout: 2 * time.Second, Initial: time.Millisecond, Max: 5 * time.Millisecond,
		Dial: pipeDialer(accept),
	}
}

func TestClientEnrolsAndConfirmsTheListener(t *testing.T) {
	stub := &agentStub{statuses: []int{http.StatusOK}, bearers: make(chan string, 1)}
	if err := Run(context.Background(), clientFor(t, stub, true)); err != nil {
		t.Fatal(err)
	}
	if got := <-stub.bearers; got != "Bearer tok.en" {
		t.Errorf("bearer = %q", got)
	}
	if stub.calls.Load() != 1 {
		t.Errorf("%d calls, want 1", stub.calls.Load())
	}
}

func TestClientRetriesRetryableAnswers(t *testing.T) {
	stub := &agentStub{statuses: []int{http.StatusServiceUnavailable, http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusOK}}
	if err := Run(context.Background(), clientFor(t, stub, true)); err != nil {
		t.Fatal(err)
	}
	if stub.calls.Load() != 4 {
		t.Errorf("%d calls, want 4", stub.calls.Load())
	}
}

func TestClientRetriesAFailedConnection(t *testing.T) {
	stub := &agentStub{statuses: []int{http.StatusOK}}
	cfg := clientFor(t, stub, true)
	// Nothing listens there yet: the agent is down.
	lis, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.EnrolPort = lis.Addr().(*net.TCPAddr).Port
	lis.Close()
	cfg.Timeout = 300 * time.Millisecond
	err = Run(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "giving up") {
		t.Fatalf("Run = %v, want to give up after retries", err)
	}
}

func TestClientFailsFastOnARefusal(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		stub := &agentStub{statuses: []int{status, http.StatusOK}}
		err := Run(context.Background(), clientFor(t, stub, true))
		if !errors.Is(err, ErrRefused) {
			t.Fatalf("%d: Run = %v, want ErrRefused", status, err)
		}
		if stub.calls.Load() != 1 {
			t.Errorf("%d: %d calls, want no retry", status, stub.calls.Load())
		}
	}
}

func TestClientRefusesAnUnexpectedPort(t *testing.T) {
	stub := &agentStub{statuses: []int{http.StatusOK}, body: `{"port":1234}`}
	if err := Run(context.Background(), clientFor(t, stub, true)); err == nil || !strings.Contains(err.Error(), "1234") {
		t.Fatalf("Run = %v, want a port mismatch", err)
	}
}

func TestClientFailsWhenTheListenerDoesNotAccept(t *testing.T) {
	stub := &agentStub{statuses: []int{http.StatusOK}}
	cfg := clientFor(t, stub, false)
	cfg.Timeout = 200 * time.Millisecond
	err := Run(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "does not accept") {
		t.Fatalf("Run = %v, want the confirmation to fail", err)
	}
}

func TestClientRequiresItsConfiguration(t *testing.T) {
	if err := Run(context.Background(), ClientConfig{HostIP: "10.0.0.1"}); err == nil {
		t.Fatal("Run without ports succeeded")
	}
}
