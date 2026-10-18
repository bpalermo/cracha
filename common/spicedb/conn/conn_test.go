package conn

import (
	"context"
	"net"
	"testing"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"github.com/bpalermo/cracha/common/spiffetest"
)

const (
	gatewayID = "spiffe://cracha.test/ns/cracha-system/sa/cracha-spicedb"
	brokerID  = "spiffe://cracha.test/ns/cracha-system/sa/cracha-broker"
)

// gateway stands in for the gateway: it serves ReadSchema over SPIFFE mTLS
// and records the client's SPIFFE ID and metadata.
type gateway struct {
	v1.UnimplementedSchemaServiceServer
	client   chan string
	metadata chan metadata.MD
}

func (g *gateway) ReadSchema(ctx context.Context, _ *v1.ReadSchemaRequest) (*v1.ReadSchemaResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	g.metadata <- md
	if p, ok := peer.FromContext(ctx); ok {
		if id, err := x509svid.IDFromCert(p.AuthInfo.(credentials.TLSInfo).State.PeerCertificates[0]); err == nil {
			g.client <- id.String()
		}
	}
	return &v1.ReadSchemaResponse{SchemaText: "definition team {}"}, nil
}

func serve(t *testing.T, ca *spiffetest.CA) (string, *gateway) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	svid := ca.SVID(t, gatewayID)
	creds := credentials.NewTLS(tlsconfig.MTLSServerConfig(svid, ca.Bundle(), tlsconfig.AuthorizeAny()))
	srv := grpc.NewServer(grpc.Creds(creds))
	g := &gateway{client: make(chan string, 1), metadata: make(chan metadata.MD, 1)}
	v1.RegisterSchemaServiceServer(srv, g)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String(), g
}

func config(t *testing.T, ca *spiffetest.CA, endpoint, server string) Config {
	t.Helper()
	return Config{
		Endpoint: endpoint,
		Server:   spiffeid.RequireFromString(server),
		SVIDs:    ca.SVID(t, brokerID),
		Bundles:  ca.Bundle(),
	}
}

func readSchema(t *testing.T, cfg Config) error {
	t.Helper()
	c, err := Dial(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = c.ReadSchema(ctx, &v1.ReadSchemaRequest{})
	return err
}

// The client presents its SVID, verifies the gateway's and sends no
// credential of its own: the gateway adds SpiceDB's key.
func TestDialPresentsSVID(t *testing.T) {
	ca := spiffetest.NewCA(t, "cracha.test")
	endpoint, g := serve(t, ca)
	if err := readSchema(t, config(t, ca, endpoint, gatewayID)); err != nil {
		t.Fatal(err)
	}
	if got := <-g.client; got != brokerID {
		t.Errorf("the gateway saw client %q, want %q", got, brokerID)
	}
	if md := <-g.metadata; len(md.Get("authorization")) != 0 {
		t.Errorf("the client sent an authorization header: %v", md.Get("authorization"))
	}
}

// A gateway that presents another SPIFFE ID is refused at the handshake.
func TestDialRefusesOtherServer(t *testing.T) {
	ca := spiffetest.NewCA(t, "cracha.test")
	endpoint, _ := serve(t, ca)
	if err := readSchema(t, config(t, ca, endpoint, "spiffe://cracha.test/ns/cracha-system/sa/impostor")); err == nil {
		t.Fatal("a gateway with another SPIFFE ID was accepted")
	}
}

// A gateway of another trust domain is refused: its SVID does not verify.
func TestDialRefusesOtherTrustDomain(t *testing.T) {
	gatewayCA := spiffetest.NewCA(t, "cracha.test")
	endpoint, _ := serve(t, gatewayCA)
	other := spiffetest.NewCA(t, "cracha.test")
	if err := readSchema(t, config(t, other, endpoint, gatewayID)); err == nil {
		t.Fatal("a gateway signed by another authority was accepted")
	}
}

func TestDialRefusesIncompleteConfig(t *testing.T) {
	ca := spiffetest.NewCA(t, "cracha.test")
	good := config(t, ca, "spicedb:50051", gatewayID)
	for name, mutate := range map[string]func(*Config){
		"no endpoint":  func(c *Config) { c.Endpoint = "" },
		"no server id": func(c *Config) { c.Server = spiffeid.ID{} },
		"no svids":     func(c *Config) { c.SVIDs = nil },
		"no bundles":   func(c *Config) { c.Bundles = nil },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := good
			mutate(&cfg)
			if c, err := Dial(cfg); err == nil {
				c.Close()
				t.Fatalf("accepted %+v", cfg)
			}
		})
	}
}

func TestDefaultServerID(t *testing.T) {
	id, err := DefaultServerID(spiffeid.RequireTrustDomainFromString("cracha.test"), "cracha-system")
	if err != nil || id.String() != gatewayID {
		t.Fatalf("DefaultServerID = %v, %v; want %s", id, err, gatewayID)
	}
	if _, err := DefaultServerID(spiffeid.RequireTrustDomainFromString("cracha.test"), ""); err == nil {
		t.Fatal("an empty namespace was accepted")
	}
}

