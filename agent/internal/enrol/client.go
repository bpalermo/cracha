package enrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/bpalermo/cracha/agent/enrolapi"
)

// ClientConfig is what the cracha-enrol init container knows (enrolapi).
type ClientConfig struct {
	// HostIP is the node's address, EnrolPort the agent's enrolment port.
	HostIP    string
	EnrolPort int
	// Port is the loopback listener's port, confirmed after enrolment.
	Port int
	// TokenFile holds the projected token; it is read on every attempt,
	// since kubelet rotates it.
	TokenFile string
	// Timeout bounds the whole enrolment, retries included (agent.enrolTimeout).
	Timeout time.Duration
	// Logger; the default logger when nil.
	Logger *slog.Logger

	// For tests: the HTTP client and the dialer that confirms the listener.
	HTTPClient *http.Client
	Dial       func(ctx context.Context, addr string) (net.Conn, error)
	// Initial is the first wait between attempts, doubling to Max.
	Initial time.Duration
	Max     time.Duration
}

// Defaults of ClientConfig.
const (
	DefaultEnrolTimeout = 2 * time.Minute
	defaultInitial      = 250 * time.Millisecond
	defaultMax          = 5 * time.Second
	requestTimeout      = 10 * time.Second
	// confirmTimeout bounds the connect that confirms the listener accepts.
	confirmTimeout = 15 * time.Second
)

// ErrRefused is an enrolment the agent refused for good (401, 403): the
// container exits at once rather than retry what will not change.
var ErrRefused = errors.New("enrolment refused")

func (c ClientConfig) withDefaults() ClientConfig {
	if c.TokenFile == "" {
		c.TokenFile = enrolapi.DefaultTokenFile
	}
	if c.Timeout <= 0 {
		c.Timeout = DefaultEnrolTimeout
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: requestTimeout}
	}
	if c.Dial == nil {
		c.Dial = func(ctx context.Context, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp4", addr)
		}
	}
	if c.Initial <= 0 {
		c.Initial = defaultInitial
	}
	if c.Max <= 0 {
		c.Max = defaultMax
	}
	return c
}

// Run enrols the pod this process runs in: it POSTs the token to the agent,
// retrying a failed connection or a retryable answer with backoff until the
// timeout, then confirms the listener accepts a connection from inside the
// pod (a connect, not a request), so a missed bind cannot start the app.
// It returns nil once the listener is confirmed; the init container exits
// with its error otherwise and kubelet restarts it.
func Run(ctx context.Context, cfg ClientConfig) error {
	cfg = cfg.withDefaults()
	if cfg.HostIP == "" || cfg.EnrolPort <= 0 || cfg.Port <= 0 {
		return errors.New("the host IP, the enrolment port and the listener port are required")
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	url := fmt.Sprintf("http://%s%s", net.JoinHostPort(cfg.HostIP, fmt.Sprint(cfg.EnrolPort)), enrolapi.Path)
	port, err := retry(ctx, cfg, func() (int, error) { return enrol(ctx, cfg, url) })
	if err != nil {
		return err
	}
	if port != cfg.Port {
		return fmt.Errorf("the agent bound port %d, this pod expects %d", port, cfg.Port)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	_, err = retry(ctx, cfg, func() (int, error) { return port, confirm(ctx, cfg, addr) })
	if err != nil {
		return fmt.Errorf("the listener at %s does not accept a connection: %w", addr, err)
	}
	cfg.Logger.Info("enrolled", "listener", addr)
	return nil
}

// retry runs attempt with jittered exponential backoff until it succeeds,
// fails with ErrRefused or ctx is done.
func retry(ctx context.Context, cfg ClientConfig, attempt func() (int, error)) (int, error) {
	wait := cfg.Initial
	for n := 1; ; n++ {
		port, err := attempt()
		if err == nil {
			return port, nil
		}
		if errors.Is(err, ErrRefused) {
			return 0, err
		}
		cfg.Logger.Warn("enrolment attempt failed; retrying", "attempt", n, "wait", wait.String(), "error", err)
		t := time.NewTimer(wait)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return 0, fmt.Errorf("giving up after %d attempts within %s: %w", n, cfg.Timeout, err)
		}
		wait = min(wait*2, cfg.Max)
	}
}

// enrol is one POST; it returns the port the agent acknowledged.
func enrol(ctx context.Context, cfg ClientConfig, url string) (int, error) {
	token, err := os.ReadFile(cfg.TokenFile)
	if err != nil {
		return 0, fmt.Errorf("reading the token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	switch resp.StatusCode {
	case http.StatusOK:
		var ack enrolapi.Response
		if err := json.Unmarshal(body, &ack); err != nil {
			return 0, fmt.Errorf("unreadable acknowledgement: %w", err)
		}
		if ack.Port <= 0 {
			return 0, errors.New("the acknowledgement names no port")
		}
		return ack.Port, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return 0, fmt.Errorf("%w: %d %s", ErrRefused, resp.StatusCode, strings.TrimSpace(string(body)))
	default:
		return 0, fmt.Errorf("the agent answered %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
}

// confirm connects to the listener from inside the pod and closes.
func confirm(ctx context.Context, cfg ClientConfig, addr string) error {
	ctx, cancel := context.WithTimeout(ctx, confirmTimeout)
	defer cancel()
	c, err := cfg.Dial(ctx, addr)
	if err != nil {
		return err
	}
	return c.Close()
}
