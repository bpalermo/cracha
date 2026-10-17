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
	listen := flag.String("listen", ":8080", "address to listen on")
	flag.Parse()

	rec := &recorder{}
	var seq uint64
	var seqMu sync.Mutex
	next := func() uint64 {
		seqMu.Lock()
		defer seqMu.Unlock()
		seq++
		return seq
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /requests", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rec.list())
	})
	mux.HandleFunc("DELETE /requests", func(w http.ResponseWriter, _ *http.Request) {
		rec.reset()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusBadRequest, "MalformedInput", err.Error())
			return
		}
		form := map[string]string{}
		for k, v := range r.PostForm {
			form[k] = strings.Join(v, ",")
		}
		action := form["Action"]
		if action != "AssumeRole" {
			writeError(w, http.StatusBadRequest, "InvalidAction", fmt.Sprintf("the stub only serves AssumeRole, not %q", action))
			return
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
				writeError(w, http.StatusBadRequest, "ValidationError", "DurationSeconds: "+err.Error())
				return
			}
			req.DurationSeconds = n
		}
		if req.RoleArn == "" || req.RoleSessionName == "" {
			writeError(w, http.StatusBadRequest, "ValidationError", "RoleArn and RoleSessionName are required")
			return
		}
		rec.add(req)
		n := next()
		log.Printf("AssumeRole #%d role=%s session=%s source_identity=%s tags=%v policy_bytes=%d",
			n, req.RoleArn, req.RoleSessionName, req.SourceIdentity, req.Tags, len(req.Policy))

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
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(xml.Header))
		_ = xml.NewEncoder(w).Encode(resp)
	})

	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	log.Printf("stsstub listening on %s", *listen)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "stsstub: %v\n", err)
		os.Exit(1)
	}
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
