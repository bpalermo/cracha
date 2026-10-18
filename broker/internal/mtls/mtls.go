// Package mtls is the broker's transport (docs/design.md, section 6.5):
// SPIFFE mTLS, served with the broker's own X.509-SVID from the Workload
// API and accepting exactly one client identity, the node agent's. A
// connection from any other SVID, or without one, fails at the handshake,
// before a request is read. The handler behind [Require] therefore sees
// only the agent's requests, and logs the client identity ([PeerID]) beside
// the subject of the token each one carries. No DNS name and no CA bundle
// are involved: both sides verify by SPIFFE ID.
package mtls

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// AgentServiceAccount is the service account the node agent runs as, which
// names its default SPIFFE ID (design 4.2).
const AgentServiceAccount = "cracha-agent"

// ReasonUnauthorizedClient is the reason [Require] answers 403 with.
const ReasonUnauthorizedClient = "unauthorized_client"

// DefaultAgentID is the agent's SPIFFE ID when none is configured:
// spiffe://<td>/ns/<namespace>/sa/cracha-agent, in the trust domain of the
// broker's own SVID, which svids holds.
func DefaultAgentID(svids x509svid.Source, namespace string) (spiffeid.ID, error) {
	svid, err := svids.GetX509SVID()
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("own X.509-SVID: %w", err)
	}
	id, err := spiffeid.FromSegments(svid.ID.TrustDomain(), "ns", namespace, "sa", AgentServiceAccount)
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("agent SPIFFE ID in namespace %q: %w", namespace, err)
	}
	return id, nil
}

// ServerConfig is the TLS configuration of the broker's listener: the
// broker's X.509-SVID from svids, rotated as the source rotates it, a
// client certificate required and verified against bundles, and the
// handshake refused unless the client's SPIFFE ID is agent. TLS 1.2 is the
// floor.
func ServerConfig(svids x509svid.Source, bundles x509bundle.Source, agent spiffeid.ID) *tls.Config {
	cfg := tlsconfig.MTLSServerConfig(svids, bundles, tlsconfig.AuthorizeID(agent))
	cfg.MinVersion = tls.VersionTLS12
	return cfg
}

// PeerID is the SPIFFE ID of the client certificate the TLS layer verified
// for the request, and false when the request did not come over TLS with
// a client certificate that carries one.
func PeerID(r *http.Request) (spiffeid.ID, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return spiffeid.ID{}, false
	}
	id, err := x509svid.IDFromCert(r.TLS.PeerCertificates[0])
	if err != nil {
		return spiffeid.ID{}, false
	}
	return id, true
}

// Require wraps next so that only requests whose client certificate is the
// agent's reach it; any other is refused with 403. The handshake of
// [ServerConfig] already refuses every other client, so this is the second
// line, for a listener that is ever served without it.
func Require(agent spiffeid.ID, log *slog.Logger, next http.Handler) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := PeerID(r)
		if !ok || id != agent {
			log.LogAttrs(r.Context(), slog.LevelWarn, "client is not the agent",
				slog.String("remote", r.RemoteAddr), slog.String("client", id.String()), slog.String("agent", agent.String()))
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"reason": ReasonUnauthorizedClient})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// SVIDReadiness is a readiness check that passes once an X.509-SVID source
// has been set and holds an SVID: the broker cannot serve TLS before.
type SVIDReadiness struct {
	mu     sync.RWMutex
	source x509svid.Source
}

// Set gives the check the source to consult.
func (r *SVIDReadiness) Set(source x509svid.Source) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.source = source
}

// Ready implements the readiness check.
func (r *SVIDReadiness) Ready() error {
	r.mu.RLock()
	source := r.source
	r.mu.RUnlock()
	if source == nil {
		return errors.New("waiting for the X.509-SVID from the Workload API")
	}
	if _, err := source.GetX509SVID(); err != nil {
		return fmt.Errorf("no X.509-SVID: %w", err)
	}
	return nil
}
