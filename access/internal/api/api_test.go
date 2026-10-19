package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ca mints X.509-SVIDs of one trust domain.
type ca struct {
	td   spiffeid.TrustDomain
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t *testing.T, td string) *ca {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &ca{td: spiffeid.RequireTrustDomainFromString(td), cert: cert, key: key}
}

func (c *ca) bundle() *x509bundle.Bundle {
	return x509bundle.FromX509Authorities(c.td, []*x509.Certificate{c.cert})
}

func (c *ca) svid(t *testing.T, id string) *x509svid.SVID {
	t.Helper()
	sid := spiffeid.RequireFromString(id)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: n, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs: []*url.URL{sid.URL()},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &x509svid.SVID{ID: sid, Certificates: []*x509.Certificate{cert}, PrivateKey: key}
}

// echo answers Grant with the caller it saw and refuses everything else.
type echo struct{ Server }

func (echo) Grant(ctx context.Context, req *GrantRequest) (*WriteResponse, error) {
	id, _ := CallerFrom(ctx)
	return &WriteResponse{Status: StatusApplied, Relationship: id.String() + " " + req.Resource.Name}, nil
}

func (echo) Revoke(context.Context, *RevokeRequest) (*WriteResponse, error) {
	return nil, Refuse(codes.FailedPrecondition, "resource_outside_envelope", "no")
}

const serverID = "spiffe://example.org/ns/cracha/sa/cracha-access"

func serve(t *testing.T, authority *ca) string {
	t.Helper()
	svid := authority.svid(t, serverID)
	s := NewServer(svid, authority.bundle(), authority.td, echo{})
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)
	return lis.Addr().String()
}

func TestOverSPIFFEMTLS(t *testing.T) {
	authority := newCA(t, "example.org")
	addr := serve(t, authority)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := Dial(addr, authority.svid(t, "spiffe://example.org/ns/ci/sa/deployer"), authority.bundle(), spiffeid.RequireFromString(serverID))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c := NewClient(conn)
	resp, err := c.Grant(ctx, &GrantRequest{Resource: Resource{Kind: "s3_bucket", Name: "b"}})
	if err != nil || resp.Relationship != "spiffe://example.org/ns/ci/sa/deployer b" {
		t.Fatalf("Grant = %+v, %v", resp, err)
	}
	_, err = c.Revoke(ctx, &RevokeRequest{})
	var ce *CallError
	if !errors.As(err, &ce) || ce.Reason != "resource_outside_envelope" || status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("Revoke = %v (reason %+v)", err, ce)
	}

	// The server is verified by its SPIFFE ID.
	wrong, _ := Dial(addr, authority.svid(t, "spiffe://example.org/ns/ci/sa/deployer"), authority.bundle(), spiffeid.RequireFromString("spiffe://example.org/ns/cracha/sa/other"))
	defer wrong.Close()
	if _, err := NewClient(wrong).Grant(ctx, &GrantRequest{}); status.Code(err) != codes.Unavailable {
		t.Errorf("a server of another ID was trusted: %v", err)
	}

	// A client of another trust domain fails the handshake.
	other := newCA(t, "other.org")
	bundles := x509bundle.NewSet(authority.bundle(), other.bundle())
	foreign, _ := Dial(addr, other.svid(t, "spiffe://other.org/ns/ci/sa/deployer"), bundles, spiffeid.RequireFromString(serverID))
	defer foreign.Close()
	if _, err := NewClient(foreign).Grant(ctx, &GrantRequest{}); err == nil {
		t.Error("a client of another trust domain was served")
	}
}

func TestCodecRefusesUnknownFields(t *testing.T) {
	var req GrantRequest
	if err := (Codec{}).Unmarshal([]byte(`{"resource":{"kind":"s3_bucket","name":"b"},"relation":"reader","extra":1}`), &req); err == nil {
		t.Error("an unknown field was accepted")
	}
}
