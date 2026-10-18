// Package cabundle keeps the caBundle of the webhook's own
// MutatingWebhookConfiguration equal to the trust bundle of the webhook's
// trust domain (docs/design.md, section 7.5).
//
// The webhook serves its X.509-SVID, so the apiserver verifies it with the
// trust domain's bundle, which the chart cannot know when it renders the
// configuration and which rotates with the issuer's keys. The webhook
// therefore publishes it itself: at start, on every update of its Workload
// API source, and on a periodic resync in case something else rewrote the
// configuration (a Helm upgrade keeps fields it does not render, but a
// rewrite from elsewhere might not). A pass reads the configuration, and
// patches every webhook's clientConfig.caBundle only when one differs from
// the bundle's PEM, so replicas do not patch over each other. A failed pass
// is logged and tried again after a short wait; until the first pass
// succeeds the webhook reports not ready (Published), because the apiserver
// cannot reach it anyway.
//
// With RBAC: get and patch on that one configuration, by resourceNames, and
// nothing else on the kind.
package cabundle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// Source is the part of a workloadapi.X509Source the publisher reads: the
// SVID, for its trust domain; the bundle of that domain; and the channel
// that is sent on whenever either changes.
type Source interface {
	GetX509SVID() (*x509svid.SVID, error)
	GetX509BundleForTrustDomain(spiffeid.TrustDomain) (*x509bundle.Bundle, error)
	Updated() <-chan struct{}
}

// Defaults for the zero values of Config.
const (
	DefaultRetry  = 5 * time.Second
	DefaultResync = time.Minute
)

// Config is the publisher's settings.
type Config struct {
	// Name is the MutatingWebhookConfiguration to patch.
	Name string
	// Retry is how long after a failed pass the next one runs. Zero means
	// DefaultRetry.
	Retry time.Duration
	// Resync is how long after a successful pass the next one runs, absent
	// an update of the source. Zero means DefaultResync.
	Resync time.Duration
	// Logger receives one record per patch and per failure. Nil means
	// slog.Default().
	Logger *slog.Logger
}

// Publisher patches the configuration.
type Publisher struct {
	cfg       Config
	client    kubernetes.Interface
	source    Source
	log       *slog.Logger
	published atomic.Bool
}

// New returns a Publisher. It patches nothing until Run or Sync is called.
func New(cfg Config, client kubernetes.Interface, source Source) (*Publisher, error) {
	if cfg.Name == "" {
		return nil, errors.New("the webhook configuration's name must be set")
	}
	if client == nil {
		return nil, errors.New("the Kubernetes client must be set")
	}
	if source == nil {
		return nil, errors.New("the X.509 source must be set")
	}
	if cfg.Retry <= 0 {
		cfg.Retry = DefaultRetry
	}
	if cfg.Resync <= 0 {
		cfg.Resync = DefaultResync
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Publisher{cfg: cfg, client: client, source: source, log: cfg.Logger}, nil
}

// Published reports whether a pass has succeeded: the configuration holds
// the bundle the webhook serves under.
func (p *Publisher) Published() bool { return p.published.Load() }

// Run syncs now, on every update of the source, after Retry when a pass
// failed and after Resync otherwise, until ctx is done.
func (p *Publisher) Run(ctx context.Context) {
	wait := time.Duration(0)
	for {
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-p.source.Updated():
			timer.Stop()
		case <-timer.C:
		}
		if err := p.Sync(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			p.log.Warn("publishing the CA bundle failed, retrying", "configuration", p.cfg.Name, "error", err, "retry", p.cfg.Retry)
			wait = p.cfg.Retry
			continue
		}
		wait = p.cfg.Resync
	}
}

// Sync runs one pass: reads the bundle and the configuration, and patches
// the configuration when any of its webhooks holds something else.
func (p *Publisher) Sync(ctx context.Context) error {
	td, pem, err := p.bundlePEM()
	if err != nil {
		return err
	}
	configs := p.client.AdmissionregistrationV1().MutatingWebhookConfigurations()
	cfg, err := configs.Get(ctx, p.cfg.Name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("reading the webhook configuration: %w", err)
	}
	ops := patchOps(cfg, pem)
	if len(ops) == 0 {
		p.published.Store(true)
		return nil
	}
	patch, err := json.Marshal(ops)
	if err != nil {
		return fmt.Errorf("encoding the patch: %w", err)
	}
	if _, err := configs.Patch(ctx, p.cfg.Name, types.JSONPatchType, patch, metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("patching the webhook configuration: %w", err)
	}
	p.published.Store(true)
	p.log.Info("published the CA bundle", "configuration", p.cfg.Name, "trust_domain", td.Name(),
		"webhooks", len(cfg.Webhooks), "bytes", len(pem))
	return nil
}

// bundlePEM is the PEM of the trust bundle of the SVID's trust domain.
func (p *Publisher) bundlePEM() (spiffeid.TrustDomain, []byte, error) {
	svid, err := p.source.GetX509SVID()
	if err != nil {
		return spiffeid.TrustDomain{}, nil, fmt.Errorf("reading the X.509-SVID: %w", err)
	}
	td := svid.ID.TrustDomain()
	bundle, err := p.source.GetX509BundleForTrustDomain(td)
	if err != nil {
		return td, nil, fmt.Errorf("reading the trust bundle of %s: %w", td, err)
	}
	if len(bundle.X509Authorities()) == 0 {
		return td, nil, fmt.Errorf("the trust bundle of %s holds no authority", td)
	}
	pem, err := bundle.Marshal()
	if err != nil {
		return td, nil, fmt.Errorf("encoding the trust bundle of %s: %w", td, err)
	}
	return td, pem, nil
}

// operation is one RFC 6902 JSON Patch operation.
type operation struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value,omitempty"`
}

// patchOps is the patch that sets pem as the caBundle of every webhook of
// cfg that does not hold it already, or nothing when all do. Each change is
// guarded by a test on the webhook's name, so a configuration reordered
// under the webhook's feet fails the patch rather than taking it.
func patchOps(cfg *admissionregistrationv1.MutatingWebhookConfiguration, pem []byte) []operation {
	var ops []operation
	for i, w := range cfg.Webhooks {
		if bytes.Equal(w.ClientConfig.CABundle, pem) {
			continue
		}
		base := fmt.Sprintf("/webhooks/%d", i)
		ops = append(ops,
			operation{Op: "test", Path: base + "/name", Value: w.Name},
			operation{Op: "add", Path: base + "/clientConfig/caBundle", Value: pem},
		)
	}
	return ops
}
