package api

import (
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"google.golang.org/grpc"
)

// NewServer is the gRPC server of the API over SPIFFE mTLS, with
// cracha-access's own SVID: any SPIFFE ID of the trust domain may connect,
// since each request is authorized on its own in SpiceDB, and a client of
// another trust domain, or without an SVID, fails the handshake.
func NewServer(svids x509svid.Source, bundles x509bundle.Source, td spiffeid.TrustDomain, srv Server) *grpc.Server {
	creds := grpccredentials.MTLSServerCredentials(svids, bundles, tlsconfig.AuthorizeMemberOf(td))
	s := grpc.NewServer(grpc.Creds(creds), grpc.UnaryInterceptor(ReasonInterceptor))
	Register(s, srv)
	return s
}

// Dial opens a client connection to the API with the caller's SVID,
// verifying the server by its SPIFFE ID. The connection is lazy.
func Dial(target string, svids x509svid.Source, bundles x509bundle.Source, server spiffeid.ID) (*grpc.ClientConn, error) {
	creds := grpccredentials.MTLSClientCredentials(svids, bundles, tlsconfig.AuthorizeID(server))
	return grpc.NewClient(target, grpc.WithTransportCredentials(creds))
}
