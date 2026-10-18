// Package broker is cracha-agent's client of the credential broker
// (docs/design.md, section 7.3, step 3): GET /v1/credentials and /v1/grants
// over SPIFFE mTLS, the agent's own X509-SVID as the client certificate and
// the broker verified by SPIFFE ID, with a pod's JWT-SVID as the bearer. No
// DNS SAN and no CA bundle exist on either side. One connection pool serves
// every pod.
package broker

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// DefaultTimeout bounds one call to the broker.
const DefaultTimeout = 10 * time.Second

// Source is the agent's own identity (internal/identity): the SVID it
// presents and the bundle it verifies the broker with.
type Source interface {
	x509svid.Source
	x509bundle.Source
}

// Config locates and identifies the broker.
type Config struct {
	// URL is the broker's base URL (agent.brokerUrl), https.
	URL string
	// SPIFFEID is the identity the broker must present (agent.brokerSpiffeID):
	// a full SPIFFE ID, or a path (/ns/<namespace>/sa/cracha-broker) in the
	// agent's own trust domain, resolved at handshake time.
	SPIFFEID string
	// Timeout bounds one call; zero means DefaultTimeout.
	Timeout time.Duration
}

// Client calls the broker.
type Client struct {
	base *url.URL
	http *http.Client
}

// New returns a Client for cfg over source.
func New(cfg Config, source Source) (*Client, error) {
	base, err := parseURL(cfg.URL)
	if err != nil {
		return nil, err
	}
	authorizer, err := Authorizer(cfg.SPIFFEID, source)
	if err != nil {
		return nil, err
	}
	if source == nil {
		return nil, errors.New("the agent's identity source is required")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsconfig.MTLSClientConfig(source, source, authorizer)
	transport.ForceAttemptHTTP2 = true
	return &Client{base: base, http: &http.Client{Transport: transport, Timeout: timeout}}, nil
}

// parseURL checks the broker URL: https, a host, no query.
func parseURL(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, errors.New("the broker URL is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("broker URL %q: %w", raw, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("broker URL %q: must be https, the broker serves SPIFFE mTLS", raw)
	}
	if u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("broker URL %q: a scheme, a host and an optional path only", raw)
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	return u, nil
}

// Authorizer returns the tlsconfig.Authorizer for want: a full SPIFFE ID is
// matched as it is; a path is completed with the trust domain of source's
// SVID when the handshake happens, so the agent's own trust domain is the
// broker's without being configured twice.
func Authorizer(want string, source x509svid.Source) (tlsconfig.Authorizer, error) {
	switch {
	case want == "":
		return nil, errors.New("the broker's SPIFFE ID is required")
	case strings.HasPrefix(want, "/"):
		if err := spiffeid.ValidatePath(want); err != nil {
			return nil, fmt.Errorf("broker SPIFFE ID path %q: %w", want, err)
		}
		return func(actual spiffeid.ID, _ [][]*x509.Certificate) error {
			own, err := source.GetX509SVID()
			if err != nil {
				return fmt.Errorf("cannot authorize the broker without the agent's own SVID: %w", err)
			}
			expected, err := spiffeid.FromPath(own.ID.TrustDomain(), want)
			if err != nil {
				return err
			}
			return matchID(expected, actual)
		}, nil
	default:
		expected, err := spiffeid.FromString(want)
		if err != nil {
			return nil, fmt.Errorf("broker SPIFFE ID %q: %w", want, err)
		}
		return func(actual spiffeid.ID, _ [][]*x509.Certificate) error {
			return matchID(expected, actual)
		}, nil
	}
}

func matchID(expected, actual spiffeid.ID) error {
	if actual != expected {
		return fmt.Errorf("the broker presented %q, want %q", actual, expected)
	}
	return nil
}

// Get calls GET <base><path> with token as the bearer and returns the
// broker's response as it is; the caller relays and closes it. The pod's
// request is exactly what the SDK sent, relayed with the token added: no
// body, no query, nothing workload-specific.
func (c *Client) Get(ctx context.Context, path, token string) (*http.Response, error) {
	u := *c.base
	u.Path += path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling the broker: %w", err)
	}
	return resp, nil
}

// URL is the broker's base URL, for logs.
func (c *Client) URL() string { return c.base.String() }
