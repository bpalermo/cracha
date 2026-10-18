package cabundle

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

const configName = "cracha-webhook"

var trustDomain = spiffeid.RequireTrustDomainFromString("example.org")

// authority is a fresh self-signed CA certificate.
func authority(t *testing.T, serial int64) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "example.org"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// fakeSource is a Source over a bundle the test swaps.
type fakeSource struct {
	mu      sync.Mutex
	svidErr error
	bundle  *x509bundle.Bundle
	updated chan struct{}
}

func newSource(t *testing.T, authorities ...*x509.Certificate) *fakeSource {
	t.Helper()
	return &fakeSource{
		bundle:  x509bundle.FromX509Authorities(trustDomain, authorities),
		updated: make(chan struct{}, 1),
	}
}

func (s *fakeSource) GetX509SVID() (*x509svid.SVID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.svidErr != nil {
		return nil, s.svidErr
	}
	return &x509svid.SVID{ID: spiffeid.RequireFromPath(trustDomain, "/ns/cracha/sa/cracha-webhook")}, nil
}

func (s *fakeSource) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if td != trustDomain {
		return nil, errors.New("no bundle for " + td.String())
	}
	return s.bundle, nil
}

func (s *fakeSource) Updated() <-chan struct{} { return s.updated }

// rotate replaces the bundle and signals the update, as the Workload API
// source does.
func (s *fakeSource) rotate(authorities ...*x509.Certificate) {
	s.mu.Lock()
	s.bundle = x509bundle.FromX509Authorities(trustDomain, authorities)
	s.mu.Unlock()
	select {
	case s.updated <- struct{}{}:
	default:
	}
}

func pemOf(t *testing.T, authorities ...*x509.Certificate) []byte {
	t.Helper()
	pem, err := x509bundle.FromX509Authorities(trustDomain, authorities).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return pem
}

// configuration is the chart's: two webhooks (one is what the chart
// renders; two show that every one is patched), without a caBundle.
func configuration() *admissionregistrationv1.MutatingWebhookConfiguration {
	return &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: configName},
		Webhooks: []admissionregistrationv1.MutatingWebhook{
			{Name: "pods.cracha.dev", ClientConfig: admissionregistrationv1.WebhookClientConfig{
				Service: &admissionregistrationv1.ServiceReference{Name: "cracha-webhook", Namespace: "cracha-system"},
			}},
			{Name: "other.cracha.dev"},
		},
	}
}

// logBuffer collects log lines from several goroutines.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newPublisher(t *testing.T, client *fake.Clientset, source Source, logs *logBuffer) *Publisher {
	t.Helper()
	p, err := New(Config{
		Name:   configName,
		Retry:  20 * time.Millisecond,
		Resync: time.Hour,
		Logger: slog.New(slog.NewTextHandler(logs, nil)),
	}, client, source)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func caBundles(t *testing.T, client *fake.Clientset) [][]byte {
	t.Helper()
	cfg, err := client.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(context.Background(), configName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for _, w := range cfg.Webhooks {
		out = append(out, w.ClientConfig.CABundle)
	}
	return out
}

func patches(client *fake.Clientset) int {
	n := 0
	for _, a := range client.Actions() {
		if a.GetVerb() == "patch" && a.GetResource().Resource == "mutatingwebhookconfigurations" {
			n++
		}
	}
	return n
}

// waitFor polls until cond holds or the test's patience runs out.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestSyncPublishesOnceAndOnlyWhenNeeded(t *testing.T) {
	ca := authority(t, 1)
	client := fake.NewClientset(configuration())
	var logs logBuffer
	p := newPublisher(t, client, newSource(t, ca), &logs)
	if p.Published() {
		t.Fatal("published before any pass")
	}

	if err := p.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !p.Published() {
		t.Error("not published after a successful pass")
	}
	want := pemOf(t, ca)
	for i, got := range caBundles(t, client) {
		if !bytes.Equal(got, want) {
			t.Errorf("webhook %d holds %q, want the bundle", i, got)
		}
	}
	if n := patches(client); n != 1 {
		t.Errorf("%d patches, want 1", n)
	}
	if !strings.Contains(logs.String(), "published the CA bundle") || !strings.Contains(logs.String(), "trust_domain=example.org") {
		t.Errorf("log: %s", logs.String())
	}

	// Nothing changed: no patch.
	if err := p.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := patches(client); n != 1 {
		t.Errorf("%d patches after an unchanged pass, want still 1", n)
	}

	// Another replica (or a hand) published the same bundle already: a
	// fresh publisher sees nothing to do, and is published.
	fresh := newPublisher(t, client, newSource(t, ca), &logs)
	if err := fresh.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := patches(client); n != 1 || !fresh.Published() {
		t.Errorf("%d patches, published=%v after a fresh publisher's pass over a published configuration", n, fresh.Published())
	}
}

func TestSyncPatchesOnlyTheWebhooksThatDiffer(t *testing.T) {
	ca := authority(t, 1)
	cfg := configuration()
	cfg.Webhooks[0].ClientConfig.CABundle = pemOf(t, ca)
	cfg.Webhooks[1].ClientConfig.CABundle = []byte("stale")
	client := fake.NewClientset(cfg)
	p := newPublisher(t, client, newSource(t, ca), &logBuffer{})

	if err := p.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := patches(client); n != 1 {
		t.Fatalf("%d patches, want 1", n)
	}
	patch := client.Actions()[len(client.Actions())-1].(k8stesting.PatchAction).GetPatch()
	if strings.Contains(string(patch), "/webhooks/0/") || !strings.Contains(string(patch), "/webhooks/1/clientConfig/caBundle") {
		t.Errorf("patch %s touches the wrong webhooks", patch)
	}
	for i, got := range caBundles(t, client) {
		if !bytes.Equal(got, pemOf(t, ca)) {
			t.Errorf("webhook %d holds %q", i, got)
		}
	}
}

func TestRunPublishesOnStartAndOnChange(t *testing.T) {
	first, second := authority(t, 1), authority(t, 2)
	client := fake.NewClientset(configuration())
	source := newSource(t, first)
	p := newPublisher(t, client, source, &logBuffer{})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); p.Run(ctx) }()

	holds := func(want []byte) func() bool {
		return func() bool {
			for _, got := range caBundles(t, client) {
				if !bytes.Equal(got, want) {
					return false
				}
			}
			return true
		}
	}
	waitFor(t, "the first bundle", holds(pemOf(t, first)))
	waitFor(t, "published", p.Published)

	// The issuer rotates: the new bundle, with both authorities during the
	// overlap, is published on the update.
	source.rotate(first, second)
	waitFor(t, "the rotated bundle", holds(pemOf(t, first, second)))

	// An update that changes nothing (an SVID renewal) patches nothing.
	before := patches(client)
	source.rotate(first, second)
	time.Sleep(50 * time.Millisecond)
	if n := patches(client); n != before {
		t.Errorf("%d patches after an update without a bundle change, want %d", n, before)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}
}

func TestRunRetriesAFailedPatch(t *testing.T) {
	ca := authority(t, 1)
	client := fake.NewClientset(configuration())
	var failures int
	var mu sync.Mutex
	client.PrependReactor("patch", "mutatingwebhookconfigurations", func(k8stesting.Action) (bool, runtime.Object, error) {
		mu.Lock()
		defer mu.Unlock()
		if failures < 2 {
			failures++
			return true, nil, errors.New("apiserver hiccup")
		}
		return false, nil, nil
	})
	var logs logBuffer
	p := newPublisher(t, client, newSource(t, ca), &logs)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)

	waitFor(t, "the bundle after the retries", func() bool {
		for _, got := range caBundles(t, client) {
			if !bytes.Equal(got, pemOf(t, ca)) {
				return false
			}
		}
		return true
	})
	waitFor(t, "published", p.Published)
	if n := patches(client); n != 3 {
		t.Errorf("%d patch attempts, want 2 failures and a success", n)
	}
	log := logs.String()
	if strings.Count(log, "publishing the CA bundle failed") != 2 || !strings.Contains(log, "apiserver hiccup") {
		t.Errorf("log: %s", log)
	}
}

func TestSyncFailsWhenTheConfigurationWasReordered(t *testing.T) {
	ca := authority(t, 1)
	client := fake.NewClientset(configuration())
	// Between the read and the patch, someone reorders the webhooks: the
	// patch's test on the name refuses to land on the wrong one.
	client.PrependReactor("patch", "mutatingwebhookconfigurations", func(k8stesting.Action) (bool, runtime.Object, error) {
		cfg := configuration()
		cfg.Webhooks[0], cfg.Webhooks[1] = cfg.Webhooks[1], cfg.Webhooks[0]
		if err := client.Tracker().Update(admissionregistrationv1.SchemeGroupVersion.WithResource("mutatingwebhookconfigurations"), cfg, ""); err != nil {
			return true, nil, err
		}
		return false, nil, nil
	})
	p := newPublisher(t, client, newSource(t, ca), &logBuffer{})
	if err := p.Sync(context.Background()); err == nil {
		t.Error("Sync succeeded over a reordered configuration")
	}
	if p.Published() {
		t.Error("published after a failed pass")
	}
}

func TestSyncErrors(t *testing.T) {
	ca := authority(t, 1)
	t.Run("no configuration", func(t *testing.T) {
		p := newPublisher(t, fake.NewClientset(), newSource(t, ca), &logBuffer{})
		if err := p.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "reading the webhook configuration") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("no SVID yet", func(t *testing.T) {
		source := newSource(t, ca)
		source.svidErr = errors.New("no SVID")
		p := newPublisher(t, fake.NewClientset(configuration()), source, &logBuffer{})
		if err := p.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "no SVID") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("empty bundle", func(t *testing.T) {
		p := newPublisher(t, fake.NewClientset(configuration()), newSource(t), &logBuffer{})
		if err := p.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "no authority") {
			t.Errorf("err = %v", err)
		}
	})
}

func TestNewRejectsBadConfig(t *testing.T) {
	client := fake.NewClientset()
	source := newSource(t, authority(t, 1))
	if _, err := New(Config{}, client, source); err == nil {
		t.Error("New accepted an empty name")
	}
	if _, err := New(Config{Name: configName}, nil, source); err == nil {
		t.Error("New accepted a nil client")
	}
	if _, err := New(Config{Name: configName}, client, nil); err == nil {
		t.Error("New accepted a nil source")
	}
	p, err := New(Config{Name: configName}, client, source)
	if err != nil {
		t.Fatal(err)
	}
	if p.cfg.Retry != DefaultRetry || p.cfg.Resync != DefaultResync || p.cfg.Logger == nil {
		t.Errorf("defaults not applied: %+v", p.cfg)
	}
}
