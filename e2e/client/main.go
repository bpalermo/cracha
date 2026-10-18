// Command client is the workload of the end-to-end suite: an AWS SDK user
// with no configuration of its own. It loads the SDK's default configuration,
// so the only reason it finds credentials is the environment the webhook
// injected (AWS_CONTAINER_CREDENTIALS_FULL_URI and
// AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE) and the token the CSI plugin wrote.
//
// It prints one JSON report line to stdout with the credentials it got, the
// broker's raw HTTP answer (status, Cracha-* headers, body) and the claims of
// the token file, then keeps watching the token file and prints a line each
// time the CSI plugin replaces it, which is how the suite observes rotation.
// With E2E_FETCH_INTERVAL set to a duration it also asks the broker for
// credentials again at that interval, the way the SDK would once a session
// ran out, and prints a line per answer, which is how the suite observes
// a revocation take effect. It exits only on a signal.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/endpointcreds"
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
	// Token is the token file as it was at the first fetch.
	Token *Token `json:"token,omitempty"`
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

// Exchange is one HTTP response from the broker.
type Exchange struct {
	URL     string              `json:"url"`
	Status  int                 `json:"status"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
}

// Fetch is one answer of the broker to a fetch of its own, printed per
// E2E_FETCH_INTERVAL: the exchange, or the error that prevented one.
type Fetch struct {
	Kind     string    `json:"kind"` // "fetch"
	At       time.Time `json:"at"`
	Exchange *Exchange `json:"exchange,omitempty"`
	Error    string    `json:"error,omitempty"`
}

// Token is the token file's claims, read without verification: the broker
// verifies, this only reports.
type Token struct {
	Kind    string    `json:"kind"` // "token" on the rotation lines
	Path    string    `json:"path"`
	Subject string    `json:"sub"`
	Aud     []string  `json:"aud"`
	Iat     int64     `json:"iat"`
	Exp     int64     `json:"exp"`
	ReadAt  time.Time `json:"readAt"`
	Error   string    `json:"error,omitempty"`
	Changed bool      `json:"changed"`
}

// recording is the HTTP client the SDK's container-credentials provider uses;
// it keeps the last response.
type recording struct {
	inner http.Client
	mu    sync.Mutex
	last  *Exchange
}

func (r *recording) Do(req *http.Request) (*http.Response, error) {
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

func (r *recording) exchange() *Exchange {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	out := json.NewEncoder(os.Stdout)
	tokenPath := os.Getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")
	report := Report{Kind: "report"}
	report.Token = readToken(tokenPath)

	rec := &recording{inner: http.Client{Timeout: 30 * time.Second}}
	retrieve(ctx, rec, &report)
	report.Exchange = rec.exchange()
	if err := out.Encode(report); err != nil {
		fmt.Fprintf(os.Stderr, "client: %v\n", err)
		os.Exit(1)
	}

	// Watch the token file: a line per change, so the rotation is visible in
	// the pod's log without an exec. And, when asked, fetch credentials again
	// at an interval: a line per answer.
	last := report.Token
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	fetches, stopFetching := fetchTicker()
	defer stopFetching()
	for {
		select {
		case <-ctx.Done():
			return
		case <-fetches:
			_ = out.Encode(fetch(ctx, rec, tokenPath, os.Getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI")))
			continue
		case <-ticker.C:
		}
		cur := readToken(tokenPath)
		if last != nil && cur.Error == last.Error && cur.Iat == last.Iat && cur.Exp == last.Exp && cur.Subject == last.Subject {
			continue
		}
		cur.Changed = last != nil
		last = cur
		_ = out.Encode(cur)
	}
}

// retrieve has the SDK obtain credentials and records the outcome in the
// report. Nothing but the environment chooses the provider; the option only
// swaps the HTTP client of the container-credentials provider for one that
// keeps the broker's answer, so the suite can assert on it.
func retrieve(ctx context.Context, rec *recording, report *Report) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithEndpointCredentialOptions(func(o *endpointcreds.Options) {
			o.HTTPClient = rec
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

// fetch asks the broker for credentials the way the SDK's provider does:
// the token file's contents as the Authorization header, nothing else.
func fetch(ctx context.Context, rec *recording, tokenPath, uri string) Fetch {
	f := Fetch{Kind: "fetch", At: time.Now().UTC()}
	raw, err := os.ReadFile(tokenPath)
	if err != nil {
		f.Error = "token: " + err.Error()
		return f
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		f.Error = err.Error()
		return f
	}
	req.Header.Set("Authorization", strings.TrimSpace(string(raw)))
	resp, err := rec.Do(req)
	if err != nil {
		f.Error = err.Error()
		return f
	}
	_ = resp.Body.Close()
	f.Exchange = rec.exchange()
	return f
}

// readToken reads the token file's claims without verifying anything.
func readToken(path string) *Token {
	t := &Token{Kind: "token", Path: path, ReadAt: time.Now().UTC()}
	if path == "" {
		t.Error = "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE is not set"
		return t
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Error = err.Error()
		return t
	}
	parts := strings.Split(strings.TrimSpace(string(raw)), ".")
	if len(parts) != 3 {
		t.Error = "not a JWS compact serialization"
		return t
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Error = "claims: " + err.Error()
		return t
	}
	var claims struct {
		Sub string          `json:"sub"`
		Aud json.RawMessage `json:"aud"`
		Iat int64           `json:"iat"`
		Exp int64           `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Error = "claims: " + err.Error()
		return t
	}
	t.Subject, t.Iat, t.Exp = claims.Sub, claims.Iat, claims.Exp
	var one string
	if err := json.Unmarshal(claims.Aud, &one); err == nil {
		t.Aud = []string{one}
	} else if err := json.Unmarshal(claims.Aud, &t.Aud); err != nil {
		t.Error = "aud: " + errors.New("neither a string nor a list").Error()
	}
	return t
}
