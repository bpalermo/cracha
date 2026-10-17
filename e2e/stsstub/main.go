// Command stsstub stands in for AWS STS in the end-to-end suite. It speaks
// enough of the STS query API for aws-sdk-go-v2's sts client to complete an
// AssumeRole, hands out fixed fake credentials with the requested expiry, and
// remembers every request so the tests can read back exactly what the broker
// asked for (GET /requests).
//
// Not a general STS emulator: nothing is authenticated, every role exists and
// every policy is accepted.
package main

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// The fixed credentials every AssumeRole gets. The tests assert on the
// access key ID.
const (
	AccessKeyID     = "ASIACRACHAE2ESTUB000"
	SecretAccessKey = "cracha-e2e-stub-secret"
	SessionToken    = "cracha-e2e-stub-session-token"
)

// Request is one recorded AssumeRole, as the broker sent it.
type Request struct {
	// Received is when the stub got it.
	Received time.Time `json:"received"`
	// Action is the Action parameter, AssumeRole for everything recorded.
	Action          string            `json:"action"`
	RoleArn         string            `json:"roleArn"`
	RoleSessionName string            `json:"roleSessionName"`
	SourceIdentity  string            `json:"sourceIdentity"`
	Policy          string            `json:"policy"`
	PolicyArns      []string          `json:"policyArns"`
	DurationSeconds int               `json:"durationSeconds"`
	Tags            map[string]string `json:"tags"`
	// TransitiveTagKeys is what the request marked transitive, if anything.
	TransitiveTagKeys []string `json:"transitiveTagKeys"`
	// Form is the whole decoded form, for anything the fields above miss.
	Form map[string]string `json:"form"`
}

type recorder struct {
	mu       sync.Mutex
	requests []Request
}

func (r *recorder) add(req Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, req)
}

func (r *recorder) list() []Request {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Request, len(r.requests))
	copy(out, r.requests)
	return out
}

func (r *recorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = nil
}

// AssumeRoleResponse is the STS query-protocol answer the SDK deserializes.
type AssumeRoleResponse struct {
	XMLName          xml.Name         `xml:"https://sts.amazonaws.com/doc/2011-06-15/ AssumeRoleResponse"`
	Result           assumeRoleResult `xml:"AssumeRoleResult"`
	ResponseMetadata struct {
		RequestID string `xml:"RequestId"`
	} `xml:"ResponseMetadata"`
}

type assumeRoleResult struct {
	Credentials struct {
		AccessKeyID     string `xml:"AccessKeyId"`
		SecretAccessKey string `xml:"SecretAccessKey"`
		SessionToken    string `xml:"SessionToken"`
		Expiration      string `xml:"Expiration"`
	} `xml:"Credentials"`
	AssumedRoleUser struct {
		AssumedRoleID string `xml:"AssumedRoleId"`
		Arn           string `xml:"Arn"`
	} `xml:"AssumedRoleUser"`
	SourceIdentity   string `xml:"SourceIdentity,omitempty"`
	PackedPolicySize int    `xml:"PackedPolicySize"`
}

// errorResponse is the query-protocol error shape, for anything but
// AssumeRole.
type errorResponse struct {
	XMLName xml.Name `xml:"https://sts.amazonaws.com/doc/2011-06-15/ ErrorResponse"`
	Error   struct {
		Type    string `xml:"Type"`
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	} `xml:"Error"`
	RequestID string `xml:"RequestId"`
}

func main() {
	listen := parseFlags()
	srv := &http.Server{Addr: listen, Handler: newStub().handler(), ReadHeaderTimeout: 5 * time.Second}
	log.Printf("stsstub listening on %s", listen)
	if err := serve(srv); err != nil {
		fmt.Fprintf(os.Stderr, "stsstub: %v\n", err)
		os.Exit(1)
	}
}

// parseFlags reads the command line: the address to listen on.
func parseFlags() (listen string) {
	flag.StringVar(&listen, "listen", ":8080", "address to listen on")
	flag.Parse()
	return listen
}

// serve runs srv until SIGINT or SIGTERM, then gives it 5 seconds to drain.
// A server that was stopped this way is not an error.
func serve(srv *http.Server) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// stub is the server's state: the recording, and the sequence that numbers
// each AssumeRole in its session token and request ID.
type stub struct {
	rec   recorder
	seqMu sync.Mutex
	seq   uint64
}

func newStub() *stub {
	return &stub{}
}

// next numbers an AssumeRole, from 1.
func (s *stub) next() uint64 {
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	s.seq++
	return s.seq
}

// handler routes the stub's endpoints: the health check, the recording's
// read and reset, and the STS query API itself.
func (s *stub) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthz)
	mux.HandleFunc("GET /requests", s.listRequests)
	mux.HandleFunc("DELETE /requests", s.resetRequests)
	mux.HandleFunc("POST /", s.assumeRole)
	return mux
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("ok\n"))
}

func (s *stub) listRequests(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.rec.list())
}

func (s *stub) resetRequests(w http.ResponseWriter, _ *http.Request) {
	s.rec.reset()
	w.WriteHeader(http.StatusNoContent)
}

// assumeRole serves the STS query API: an AssumeRole is recorded, numbered
// and answered with the fixed credentials; anything else is refused the way
// STS refuses it.
func (s *stub) assumeRole(w http.ResponseWriter, r *http.Request) {
	req, refusal := parseAssumeRole(r)
	if refusal != nil {
		writeError(w, refusal.status, refusal.code, refusal.message)
		return
	}
	s.rec.add(req)
	n := s.next()
	log.Printf("AssumeRole #%d role=%s session=%s source_identity=%s tags=%v policy_bytes=%d",
		n, req.RoleArn, req.RoleSessionName, req.SourceIdentity, req.Tags, len(req.Policy))
	w.Header().Set("Content-Type", "text/xml")
	_, _ = w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(assumeRoleResponse(req, n))
}

// refusal is a query-protocol error answer: the HTTP status and the Sender
// error's code and message.
type refusal struct {
	status  int
	code    string
	message string
}

// parseAssumeRole decodes the form of an AssumeRole as the broker sends it.
// It refuses a form that does not parse, an action other than AssumeRole, a
// DurationSeconds that is not a number, and a request without RoleArn or
// RoleSessionName, in that order.
func parseAssumeRole(r *http.Request) (Request, *refusal) {
	if err := r.ParseForm(); err != nil {
		return Request{}, &refusal{http.StatusBadRequest, "MalformedInput", err.Error()}
	}
	form := map[string]string{}
	for k, v := range r.PostForm {
		form[k] = strings.Join(v, ",")
	}
	action := form["Action"]
	if action != "AssumeRole" {
		return Request{}, &refusal{http.StatusBadRequest, "InvalidAction", fmt.Sprintf("the stub only serves AssumeRole, not %q", action)}
	}
	req := Request{
		Received:        time.Now().UTC(),
		Action:          action,
		RoleArn:         form["RoleArn"],
		RoleSessionName: form["RoleSessionName"],
		SourceIdentity:  form["SourceIdentity"],
		Policy:          form["Policy"],
		PolicyArns:      members(form, "PolicyArns", "arn"),
		Tags:            tags(form),
		Form:            form,
	}
	req.TransitiveTagKeys = members(form, "TransitiveTagKeys", "")
	req.DurationSeconds = 3600
	if d := form["DurationSeconds"]; d != "" {
		n, err := strconv.Atoi(d)
		if err != nil {
			return Request{}, &refusal{http.StatusBadRequest, "ValidationError", "DurationSeconds: " + err.Error()}
		}
		req.DurationSeconds = n
	}
	if req.RoleArn == "" || req.RoleSessionName == "" {
		return Request{}, &refusal{http.StatusBadRequest, "ValidationError", "RoleArn and RoleSessionName are required"}
	}
	return req, nil
}

// assumeRoleResponse is the answer to req, the n-th AssumeRole served: the
// fixed credentials, expiring DurationSeconds after the request was
// received, under a session token and request ID that carry n.
func assumeRoleResponse(req Request, n uint64) AssumeRoleResponse {
	var resp AssumeRoleResponse
	resp.Result.Credentials.AccessKeyID = AccessKeyID
	resp.Result.Credentials.SecretAccessKey = SecretAccessKey
	resp.Result.Credentials.SessionToken = fmt.Sprintf("%s-%d", SessionToken, n)
	resp.Result.Credentials.Expiration = req.Received.Add(time.Duration(req.DurationSeconds) * time.Second).Format(time.RFC3339)
	resp.Result.AssumedRoleUser.AssumedRoleID = "AROACRACHAE2ESTUB000:" + req.RoleSessionName
	resp.Result.AssumedRoleUser.Arn = assumedRoleArn(req.RoleArn, req.RoleSessionName)
	resp.Result.SourceIdentity = req.SourceIdentity
	resp.Result.PackedPolicySize = len(req.Policy) / 32
	resp.ResponseMetadata.RequestID = fmt.Sprintf("stub-%d", n)
	return resp
}

// assumedRoleArn turns arn:aws:iam::ACCOUNT:role/PATH/NAME into
// arn:aws:sts::ACCOUNT:assumed-role/NAME/SESSION, as STS does.
func assumedRoleArn(roleArn, session string) string {
	parts := strings.SplitN(roleArn, ":", 6)
	if len(parts) != 6 {
		return "arn:aws:sts::000000000000:assumed-role/unknown/" + session
	}
	name := parts[5]
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	return fmt.Sprintf("arn:aws:sts::%s:assumed-role/%s/%s", parts[4], name, session)
}

// members collects a query-protocol list: <prefix>.member.<n>[.<field>], in
// order of n.
func members(form map[string]string, prefix, field string) []string {
	type item struct {
		n int
		v string
	}
	var items []item
	for k, v := range form {
		rest, ok := strings.CutPrefix(k, prefix+".member.")
		if !ok {
			continue
		}
		idx := rest
		if field != "" {
			idx, ok = strings.CutSuffix(rest, "."+field)
			if !ok {
				continue
			}
		}
		n, err := strconv.Atoi(idx)
		if err != nil {
			continue
		}
		items = append(items, item{n, v})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].n < items[j].n })
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.v)
	}
	return out
}

// tags collects Tags.member.<n>.Key / .Value pairs.
func tags(form map[string]string) map[string]string {
	keys := members(form, "Tags", "Key")
	values := members(form, "Tags", "Value")
	out := make(map[string]string, len(keys))
	for i, k := range keys {
		if i < len(values) {
			out[k] = values[i]
		}
	}
	return out
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	var resp errorResponse
	resp.Error.Type = "Sender"
	resp.Error.Code = code
	resp.Error.Message = message
	resp.RequestID = "stub-error"
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(resp)
}
