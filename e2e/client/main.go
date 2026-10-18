// Command client is the workload of the end-to-end suite: an AWS SDK user
// with no configuration of its own. It loads the SDK's default configuration,
// so the only reason it finds credentials is the environment the webhook
// injected (AWS_CONTAINER_CREDENTIALS_FULL_URI, the loopback listener the
// node agent bound in this pod's network namespace) and nothing else: no
// token, no CA, no volume (docs/design.md, section 7.7).
//
// Its first action is the credential fetch, and the SDK's provider is told
// not to retry: the listener must be there at first use (design 7.2,
// "Ordering"), and the report says how many requests the first credentials
// took and how long. It prints one JSON report line to stdout with the credentials it
// got, the broker's raw HTTP answer as the agent relayed it (status,
// Cracha-* headers, body) and the request count, then one line with the
// answer to GET /v1/grants, the inspection endpoint of design 6.5, through
// the same listener. With E2E_FETCH_INTERVAL set to a duration it then asks
// for credentials again at that interval, the way the SDK would once a
// session ran out, and prints a line per answer or failure, which is how
// the suite observes a revocation take effect and an agent restart go by.
// It exits only on a signal.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/endpointcreds"
)

// credentialsPath and grantsPath are the broker's two endpoints (design
// 6.5), which the agent relays and nothing else (design 7.1).
const (
	credentialsPath = "/v1/credentials"
	grantsPath      = "/v1/grants"
)

// Report is the first line printed.
type Report struct {
	Kind string `json:"kind"` // "report"
	// Credentials is what the SDK returned; nil when retrieval failed.
	Credentials *Credentials `json:"credentials,omitempty"`
	// Error is the SDK's error when retrieval failed.
	Error string `json:"error,omitempty"`
	// Exchange is the last HTTP exchange with the credentials URI.
	Exchange *Exchange `json:"exchange,omitempty"`
	// Attempts is how many HTTP requests the SDK's provider made for the
	// first credentials: one, when the listener was there at first use.
	Attempts int `json:"attempts"`
	// LatencyMillis is how long the SDK took to retrieve the first
	// credentials, in milliseconds: what the provider's timeout is up
	// against.
	LatencyMillis float64 `json:"latencyMillis"`
}

// Credentials is the SDK's view, secrets included: this is a test fixture
// talking to a stub.
type Credentials struct {
	AccessKeyID     string    `json:"accessKeyId"`
	SecretAccessKey string    `json:"secretAccessKey"`
	SessionToken    string    `json:"sessionToken"`
	Source          string    `json:"source"`
	CanExpire       bool      `json:"canExpire"`
	Expires         time.Time `json:"expires"`
}

// Exchange is one HTTP response from the listener.
type Exchange struct {
	URL     string              `json:"url"`
	Status  int                 `json:"status"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
}

// Fetch is one answer to a request of the client's own: the grants line
// (kind "grants", once, after the report) and the credential fetches of
// E2E_FETCH_INTERVAL (kind "fetch"): the exchange, or the error that
// prevented one.
type Fetch struct {
	Kind     string    `json:"kind"`
	At       time.Time `json:"at"`
	Exchange *Exchange `json:"exchange,omitempty"`
	Error    string    `json:"error,omitempty"`
}

// recording is the HTTP client the SDK's container-credentials provider uses;
// it keeps the last response and counts the requests.
type recording struct {
	inner    http.Client
	mu       sync.Mutex
	last     *Exchange
	attempts int
}

func (r *recording) Do(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.attempts++
	r.mu.Unlock()
	resp, err := r.inner.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(strings.NewReader(string(body)))
	r.mu.Lock()
	r.last = &Exchange{URL: req.URL.String(), Status: resp.StatusCode, Headers: resp.Header.Clone(), Body: string(body)}
	r.mu.Unlock()
	return resp, nil
}

func (r *recording) exchange() (*Exchange, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last, r.attempts
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	out := json.NewEncoder(os.Stdout)
	uri := os.Getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI")
	report := Report{Kind: "report"}

	rec := &recording{inner: http.Client{Timeout: 30 * time.Second}}
	start := time.Now()
	retrieve(ctx, rec, &report)
	report.LatencyMillis = float64(time.Since(start).Microseconds()) / 1000
	report.Exchange, report.Attempts = rec.exchange()
	if err := out.Encode(report); err != nil {
		fmt.Fprintf(os.Stderr, "client: %v\n", err)
		os.Exit(1)
	}
	_ = out.Encode(fetch(ctx, rec, "grants", strings.TrimSuffix(uri, credentialsPath)+grantsPath))

	// When asked, fetch credentials again at an interval: a line per answer.
	fetches, stopFetching := fetchTicker()
	defer stopFetching()
	for {
		select {
		case <-ctx.Done():
			return
		case <-fetches:
			_ = out.Encode(fetch(ctx, rec, "fetch", uri))
		}
	}
}

// retrieve has the SDK obtain credentials and records the outcome in the
// report. Nothing but the environment chooses the provider; the options only
// swap the HTTP client of the container-credentials provider for one that
// keeps the answer, so the suite can assert on it, and turn the provider's
// retries off, so the first use of the listener is its first request.
func retrieve(ctx context.Context, rec *recording, report *Report) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithEndpointCredentialOptions(func(o *endpointcreds.Options) {
			o.HTTPClient = rec
			o.Retryer = aws.NopRetryer{}
		}))
	if err != nil {
		report.Error = "load config: " + err.Error()
		return
	}
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		report.Error = "retrieve: " + err.Error()
		return
	}
	report.Credentials = &Credentials{
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
		Source:          creds.Source,
		CanExpire:       creds.CanExpire,
		Expires:         creds.Expires,
	}
}

// fetchTicker is the ticker of the fetches E2E_FETCH_INTERVAL asks for: a
// nil channel, which never fires, when it is unset.
func fetchTicker() (<-chan time.Time, func()) {
	interval := os.Getenv("E2E_FETCH_INTERVAL")
	if interval == "" {
		return nil, func() {}
	}
	d, err := time.ParseDuration(interval)
	if err != nil || d <= 0 {
		fmt.Fprintf(os.Stderr, "client: E2E_FETCH_INTERVAL %q is not a positive duration\n", interval)
		os.Exit(1)
	}
	t := time.NewTicker(d)
	return t.C, t.Stop
}

// fetch asks the listener the way the SDK's provider does: a plain GET of
// the URI, nothing else, since nothing in the pod carries identity (design
// 7.1).
func fetch(ctx context.Context, rec *recording, kind, uri string) Fetch {
	f := Fetch{Kind: kind, At: time.Now().UTC()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		f.Error = err.Error()
		return f
	}
	resp, err := rec.Do(req)
	if err != nil {
		f.Error = err.Error()
		return f
	}
	_ = resp.Body.Close()
	f.Exchange, _ = rec.exchange()
	return f
}
