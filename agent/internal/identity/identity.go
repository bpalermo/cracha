// Package identity is cracha-agent's own identity: the X509-SVID and trust
// bundle it gets from the SPIFFE Workload API (docs/design.md, section 4.1),
// which it presents to the issuer's Broker API endpoint and to the broker
// (7.3) as its mTLS client certificate.
//
// The source does not block construction on the Workload API: it becomes
// ready when the first SVID is delivered and answers ErrNotReady until then,
// which makes every mTLS handshake fail in a way the callers retry.
package identity

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// ErrNotReady is what the source answers until the Workload API has issued
// the agent's SVID.
var ErrNotReady = errors.New("the agent's own X509-SVID has not been issued yet")

// Source is the agent's identity: an x509svid.Source and x509bundle.Source
// that follow the Workload API's rotation once established.
type Source struct {
	addr   string
	log    *slog.Logger
	source atomic.Pointer[workloadapi.X509Source]
}

// New returns a Source for the Workload API at addr (unix:///path or
// tcp://host:port), not yet connected: Run establishes it.
func New(addr string, log *slog.Logger) *Source {
	if log == nil {
		log = slog.Default()
	}
	return &Source{addr: addr, log: log}
}

// Run establishes the source and returns once it is ready or ctx is done.
// The Workload API client retries Unavailable and PermissionDenied (no
// identity yet) with its own backoff; Run only restarts it on the rare
// fatal error.
func (s *Source) Run(ctx context.Context) {
	wait := time.Second
	for {
		src, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(s.addr)))
		if err == nil {
			if svid, err := src.GetX509SVID(); err == nil {
				s.log.Info("the agent's own identity is available", "spiffe_id", svid.ID.String())
			}
			s.source.Store(src)
			return
		}
		if ctx.Err() != nil {
			return
		}
		s.log.Error("cannot get the agent's own identity from the Workload API; retrying",
			"workload_api", s.addr, "wait", wait, "error", err)
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return
		}
		wait = min(wait*2, 30*time.Second)
	}
}

// Ready reports whether an SVID has been delivered.
func (s *Source) Ready() bool { return s.source.Load() != nil }

// GetX509SVID implements x509svid.Source.
func (s *Source) GetX509SVID() (*x509svid.SVID, error) {
	src := s.source.Load()
	if src == nil {
		return nil, ErrNotReady
	}
	return src.GetX509SVID()
}

// GetX509BundleForTrustDomain implements x509bundle.Source.
func (s *Source) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	src := s.source.Load()
	if src == nil {
		return nil, ErrNotReady
	}
	return src.GetX509BundleForTrustDomain(td)
}

// TrustDomain is the trust domain of the agent's SVID.
func (s *Source) TrustDomain() (spiffeid.TrustDomain, error) {
	svid, err := s.GetX509SVID()
	if err != nil {
		return spiffeid.TrustDomain{}, err
	}
	return svid.ID.TrustDomain(), nil
}

// Close closes the Workload API source if it was ever established.
func (s *Source) Close() error {
	if src := s.source.Load(); src != nil {
		return src.Close()
	}
	return nil
}
