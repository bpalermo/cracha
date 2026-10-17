// Package spire is the reference issuer adapter (docs/design.md, section 4.2):
// per-pod JWT-SVIDs through the SPIFFE Broker API served by the node's SPIRE
// agent, authenticated with the plugin's own X509-SVID from the Workload API.
//
// It is the only package of cracha-csi that imports the Broker API; the rest
// of the plugin sees issuer.Issuer.
package spire

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	brokerpb "github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/bpalermo/cracha/csi/internal/issuer"
)

// Every request to a SPIFFE Broker Endpoint must carry this metadata. It is an
// SSRF guard: the server rejects a request without it with InvalidArgument, so
// something that can make the plugin emit a request without controlling its
// metadata cannot reach the endpoint.
const (
	brokerHeaderKey   = "broker.spiffe.io"
	brokerHeaderValue = "true"
)

// spireAgentPathPrefix is the SPIFFE ID path prefix of a SPIRE agent's own
// SVID. The server of the Broker Endpoint must present an ID in the plugin's
// own trust domain under this prefix: not merely any member of the trust
// domain, which would let any workload that can bind the socket path pose as
// the agent and hand the plugin forged tokens.
const spireAgentPathPrefix = "/spire/agent/"

// A pod is a core resource, which the Broker API spells as the literal group
// "core", not the Kubernetes API's empty string.
const (
	kubernetesPodsPlural = "pods"
	kubernetesCoreGroup  = "core"
)

// Config locates the agent.
type Config struct {
	// BrokerSocket is the path of the Broker API Unix socket.
	BrokerSocket string
	// WorkloadAPI is the Workload API address, as go-spiffe takes it
	// (unix:///path or tcp://host:port).
	WorkloadAPI string
}

// Issuer is the SPIRE issuer adapter.
type Issuer struct {
	api    brokerpb.APIClient
	conn   *grpc.ClientConn
	source *lazySource
	log    *slog.Logger
}

var _ issuer.Issuer = (*Issuer)(nil)

// connectParams is the broker connection's redial policy. gRPC's default (1 s
// base, 120 s cap) is for remote servers; this is a node-local socket whose
// handshakes fail for a known local reason until the plugin's own SVID lands,
// and a pod's start waits on it.
var connectParams = grpc.ConnectParams{
	Backoff: backoff.Config{
		BaseDelay:  50 * time.Millisecond,
		Multiplier: 1.6,
		Jitter:     0.2,
		MaxDelay:   250 * time.Millisecond,
	},
	MinConnectTimeout: 5 * time.Second,
}

// New returns an Issuer for the agent at cfg. Nothing is dialled and nothing
// blocks: the plugin's own identity is fetched from the Workload API in the
// background for as long as ctx lives, and until it lands every fetch fails
// as Unavailable, which the retry policy absorbs. Close releases the
// connection.
func New(ctx context.Context, cfg Config, log *slog.Logger) (*Issuer, error) {
	if cfg.BrokerSocket == "" {
		return nil, errors.New("the Broker API socket path is required")
	}
	if cfg.WorkloadAPI == "" {
		return nil, errors.New("the Workload API address is required")
	}
	if log == nil {
		log = slog.Default()
	}

	source := &lazySource{}
	go source.run(ctx, cfg.WorkloadAPI, log)

	tlsCfg := tlsconfig.MTLSClientConfig(source, source, authorizeSPIREAgent(source))
	conn, err := grpc.NewClient(
		"unix://"+cfg.BrokerSocket,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithConnectParams(connectParams),
	)
	if err != nil {
		return nil, fmt.Errorf("creating the Broker API client for %s: %w", cfg.BrokerSocket, err)
	}
	return &Issuer{api: brokerpb.NewAPIClient(conn), conn: conn, source: source, log: log}, nil
}

// newWithClient is New for tests, over an already built client.
func newWithClient(api brokerpb.APIClient, log *slog.Logger) *Issuer {
	if log == nil {
		log = slog.Default()
	}
	return &Issuer{api: api, log: log}
}

// Close releases the connection and the Workload API source.
func (i *Issuer) Close() error {
	var errs []error
	if i.conn != nil {
		errs = append(errs, i.conn.Close())
	}
	if i.source != nil {
		errs = append(errs, i.source.Close())
	}
	return errors.Join(errs...)
}

// FetchJWTSVID implements issuer.Issuer.
func (i *Issuer) FetchJWTSVID(ctx context.Context, ref issuer.PodRef, audience string) (string, time.Time, error) {
	req, err := fetchRequest(ref, audience)
	if err != nil {
		return "", time.Time{}, issuer.NewError(issuer.Permanent, err)
	}
	ctx = metadata.AppendToOutgoingContext(ctx, brokerHeaderKey, brokerHeaderValue)
	resp, err := i.api.FetchJWTSVID(ctx, req)
	if err != nil {
		return "", time.Time{}, classify(ref, err)
	}
	svids := resp.GetSvids()
	if len(svids) == 0 {
		// The pod resolved but no registration entry matched it. For a new pod
		// that is the entry still on its way to the agent, so it is retried.
		return "", time.Time{}, issuer.NewError(issuer.NotFoundYet,
			fmt.Errorf("the issuer has no JWT-SVID for %s", ref))
	}
	if len(svids) > 1 {
		// The ID scheme (design, section 4) gives a pod exactly one identity.
		// If the issuer's registration gives it several, the first is taken
		// and the token check (internal/token) decides whether it is the pod's.
		i.log.Warn("the issuer returned several JWT-SVIDs; using the first",
			"pod", ref.String(), "count", len(svids), "spiffe_id", svids[0].GetSpiffeId())
	}
	token := svids[0].GetSvid()
	parsed, err := jwtsvid.ParseInsecure(token, []string{audience})
	if err != nil {
		return "", time.Time{}, issuer.NewError(issuer.Permanent,
			fmt.Errorf("the issuer returned an unusable JWT-SVID for %s: %w", ref, err))
	}
	return token, parsed.Expiry, nil
}

// classify maps a Broker API failure to the adapter contract's kinds.
func classify(ref issuer.PodRef, err error) error {
	wrapped := fmt.Errorf("fetching the JWT-SVID of %s: %w", ref, err)
	switch status.Code(err) {
	case codes.NotFound:
		return issuer.NewError(issuer.NotFoundYet, wrapped)
	case codes.Unavailable, codes.DeadlineExceeded, codes.Canceled:
		// Canceled and DeadlineExceeded from the server side are transport
		// trouble; the caller's own context is checked by the retry loop.
		return issuer.NewError(issuer.Unavailable, wrapped)
	case codes.PermissionDenied:
		return issuer.NewError(issuer.PermissionDenied, wrapped)
	default:
		return issuer.NewError(issuer.Permanent, wrapped)
	}
}

// fetchRequest wraps ref as the Broker API's KubernetesObjectReference.
func fetchRequest(ref issuer.PodRef, audience string) (*brokerpb.FetchJWTSVIDRequest, error) {
	if ref.Namespace == "" || ref.Name == "" || ref.UID == "" {
		return nil, fmt.Errorf("pod reference %s is incomplete: namespace, name and UID are all required", ref)
	}
	if audience == "" {
		return nil, errors.New("the audience is required")
	}
	packed, err := anypb.New(&brokerpb.KubernetesObjectReference{
		Type: &brokerpb.KubernetesObjectType{Plural: kubernetesPodsPlural, Group: kubernetesCoreGroup},
		Key:  &brokerpb.KubernetesObjectKey{Namespace: ref.Namespace, Name: ref.Name},
		Uid:  ref.UID,
	})
	if err != nil {
		return nil, fmt.Errorf("packing the pod reference for %s: %w", ref, err)
	}
	return &brokerpb.FetchJWTSVIDRequest{
		Reference: &brokerpb.WorkloadReference{Reference: packed},
		Audience:  []string{audience},
	}, nil
}

// identitySource is the plugin's own identity: the SVID it presents as the
// mTLS client certificate and the bundle it validates the agent with.
type identitySource interface {
	x509svid.Source
	x509bundle.Source
}

// authorizeSPIREAgent accepts a Broker Endpoint server whose SPIFFE ID is in
// the plugin's own trust domain (read at handshake time, since there may be no
// SVID at dial time) under the SPIRE agent path.
func authorizeSPIREAgent(source identitySource) tlsconfig.Authorizer {
	return func(id spiffeid.ID, _ [][]*x509.Certificate) error {
		own, err := source.GetX509SVID()
		if err != nil {
			return fmt.Errorf("cannot authorize the Broker Endpoint without the plugin's own SVID: %w", err)
		}
		if id.TrustDomain() != own.ID.TrustDomain() {
			return fmt.Errorf("the Broker Endpoint presented %q, which is not in the plugin's trust domain %q",
				id, own.ID.TrustDomain())
		}
		if !strings.HasPrefix(id.Path(), spireAgentPathPrefix) {
			return fmt.Errorf("the Broker Endpoint presented %q, which is not a SPIRE agent identity (path must start with %q)",
				id, spireAgentPathPrefix)
		}
		return nil
	}
}

// errNoIdentityYet is what the lazy source answers until the Workload API has
// issued the plugin's SVID. It makes the mTLS handshake fail, which gRPC
// reports as Unavailable, which the retry policy waits out.
var errNoIdentityYet = errors.New("the plugin's own X509-SVID has not been issued yet")

// lazySource is an identitySource that becomes ready when the Workload API
// delivers the first SVID, instead of blocking construction on it. The
// Workload API's own watch retries Unavailable and PermissionDenied (no
// identity yet) with backoff; run only has to restart it on the rare fatal
// error.
type lazySource struct {
	source atomic.Pointer[workloadapi.X509Source]
}

func (s *lazySource) run(ctx context.Context, addr string, log *slog.Logger) {
	wait := time.Second
	for {
		src, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(addr)))
		if err == nil {
			svid, _ := src.GetX509SVID()
			log.Info("the plugin's own identity is available", "spiffe_id", svid.ID.String())
			s.source.Store(src)
			return
		}
		if ctx.Err() != nil {
			return
		}
		log.Error("cannot get the plugin's own identity from the Workload API; retrying",
			"workload_api", addr, "wait", wait, "error", err)
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return
		}
		wait = min(wait*2, 30*time.Second)
	}
}

// GetX509SVID implements x509svid.Source.
func (s *lazySource) GetX509SVID() (*x509svid.SVID, error) {
	src := s.source.Load()
	if src == nil {
		return nil, errNoIdentityYet
	}
	return src.GetX509SVID()
}

// GetX509BundleForTrustDomain implements x509bundle.Source.
func (s *lazySource) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	src := s.source.Load()
	if src == nil {
		return nil, errNoIdentityYet
	}
	return src.GetX509BundleForTrustDomain(td)
}

// Close closes the Workload API source if it was ever established.
func (s *lazySource) Close() error {
	if src := s.source.Load(); src != nil {
		return src.Close()
	}
	return nil
}
