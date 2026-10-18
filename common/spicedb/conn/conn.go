// Package conn is how every Crachá client reaches SpiceDB (docs/design.md,
// section 6.4): over SPIFFE mTLS to the gateway in front of it, which
// authorizes the client's SPIFFE ID and the gRPC method it calls and adds
// SpiceDB's preshared key on the way in. A client presents its own
// X.509-SVID, verifies the gateway by SPIFFE ID against its trust bundles,
// and never holds the key.
package conn

import (
	"crypto/tls"
	"errors"
	"fmt"

	authzed "github.com/authzed/authzed-go/v1"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// GatewayServiceAccount is the service account of the pods that serve
// SpiceDB behind the gateway, which names the gateway's default SPIFFE ID
// (design 4.2): spiffe://<trust domain>/ns/<namespace>/sa/cracha-spicedb.
const GatewayServiceAccount = "cracha-spicedb"

// Config is how Dial reaches the gateway.
type Config struct {
	// Endpoint is the gateway's gRPC address, host:port.
	Endpoint string
	// Server is the SPIFFE ID the gateway must present; any other fails
	// the handshake.
	Server spiffeid.ID
	// SVIDs is the client's own X.509-SVID, presented to the gateway and
	// followed as it rotates.
	SVIDs x509svid.Source
	// Bundles verify the gateway's SVID.
	Bundles x509bundle.Source
}

// DefaultServerID is the gateway's SPIFFE ID in a trust domain and
// namespace when none is configured.
func DefaultServerID(td spiffeid.TrustDomain, namespace string) (spiffeid.ID, error) {
	id, err := spiffeid.FromSegments(td, "ns", namespace, "sa", GatewayServiceAccount)
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("spicedb gateway SPIFFE ID in namespace %q: %w", namespace, err)
	}
	return id, nil
}

// TLSConfig is the client side of the gateway's mTLS: the client's SVID,
// the gateway verified as Server, TLS 1.2 at least.
func TLSConfig(cfg Config) *tls.Config {
	t := tlsconfig.MTLSClientConfig(cfg.SVIDs, cfg.Bundles, tlsconfig.AuthorizeID(cfg.Server))
	t.MinVersion = tls.VersionTLS12
	return t
}

// Dial opens a connection to SpiceDB through the gateway. The connection
// is lazy: a gateway that is down fails the first call, not Dial. Close
// the client to close it.
func Dial(cfg Config, opts ...grpc.DialOption) (*authzed.Client, error) {
	switch {
	case cfg.Endpoint == "":
		return nil, errors.New("spicedb: endpoint is required")
	case cfg.Server.IsZero():
		return nil, errors.New("spicedb: the gateway's SPIFFE ID is required")
	case cfg.SVIDs == nil || cfg.Bundles == nil:
		return nil, errors.New("spicedb: an X.509-SVID source and a bundle source are required")
	}
	opts = append([]grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(TLSConfig(cfg)))}, opts...)
	client, err := authzed.NewClient(cfg.Endpoint, opts...)
	if err != nil {
		return nil, fmt.Errorf("spicedb: dial %s: %w", cfg.Endpoint, err)
	}
	return client, nil
}
