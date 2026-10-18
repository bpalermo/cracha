// Package spiffetest is a throwaway SPIFFE certificate authority for tests:
// X509-SVIDs for any ID in one trust domain, the bundle to verify them with
// and a Source (x509svid.Source and x509bundle.Source) over one of them, so
// a test can stand up a SPIFFE mTLS server and client the way the agent and
// the broker talk.
package spiffetest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// CA signs SVIDs of one trust domain.
type CA struct {
	TrustDomain spiffeid.TrustDomain
	cert        *x509.Certificate
	key         *ecdsa.PrivateKey
	serial      int64
}

// NewCA returns a CA for the trust domain.
func NewCA(t *testing.T, trustDomain string) *CA {
	t.Helper()
	td, err := spiffeid.TrustDomainFromString(trustDomain)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "spiffetest " + trustDomain},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		URIs:                  []*url.URL{td.ID().URL()},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &CA{TrustDomain: td, cert: cert, key: key, serial: 1}
}

// Bundle is the trust bundle holding the CA.
func (ca *CA) Bundle() *x509bundle.Bundle {
	return x509bundle.FromX509Authorities(ca.TrustDomain, []*x509.Certificate{ca.cert})
}

// Issue returns an X509-SVID for the ID (a path in the CA's trust domain,
// such as /ns/cracha-system/sa/cracha-broker).
func (ca *CA) Issue(t *testing.T, path string) *x509svid.SVID {
	t.Helper()
	id, err := spiffeid.FromPath(ca.TrustDomain, path)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca.serial++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(ca.serial),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{id.URL()},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &x509svid.SVID{ID: id, Certificates: []*x509.Certificate{cert}, PrivateKey: key}
}

// Source is an identity: one SVID and the bundle of its trust domain. A nil
// SVID answers NotReady, like the agent's identity before the Workload API
// has issued it.
type Source struct {
	SVID   *x509svid.SVID
	bundle *x509bundle.Bundle
}

// NewSource returns a Source over an SVID of ca, for path.
func (ca *CA) NewSource(t *testing.T, path string) *Source {
	t.Helper()
	return &Source{SVID: ca.Issue(t, path), bundle: ca.Bundle()}
}

// GetX509SVID implements x509svid.Source.
func (s *Source) GetX509SVID() (*x509svid.SVID, error) {
	if s.SVID == nil {
		return nil, errNotReady
	}
	return s.SVID, nil
}

// GetX509BundleForTrustDomain implements x509bundle.Source.
func (s *Source) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	if s.bundle == nil {
		return nil, errNotReady
	}
	return s.bundle.GetX509BundleForTrustDomain(td)
}

type notReady struct{}

func (notReady) Error() string { return "spiffetest: no SVID yet" }

var errNotReady error = notReady{}
