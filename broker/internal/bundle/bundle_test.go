package bundle

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bpalermo/cracha/common/grant"
)

// testBundle is a bundle of one grant under the given version, built the
// way grantc compile would (grant.Marshal's canonical bytes).
func testBundle(t *testing.T, version string, names ...string) []byte {
	t.Helper()
	b := &grant.Bundle{Version: version, GeneratedAt: "2026-01-01T00:00:00Z", Grants: []grant.BundleGrant{}}
	for _, name := range names {
		b.Grants = append(b.Grants, grant.BundleGrant{
			Name:              name,
			Account:           "111122223333",
			BaseRole:          "arn:aws:iam::111122223333:role/broker/shape-dynamo-rw",
			SessionPolicy:     `{"Statement":[{"Action":"dynamodb:GetItem","Effect":"Allow","Resource":"arn:aws:dynamodb:*:111122223333:table/payments-ledger"}],"Version":"2012-10-17"}`,
			ManagedPolicyArns: []string{"arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"},
			SessionTags:       map[string]string{"team": "payments"},
			Duration:          1800,
			Envelope:          []string{"arn:aws:dynamodb:*:111122223333:table/payments-*"},
		})
	}
	data, err := grant.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// publication is a signing key and a directory grantc publish would write
// into.
type publication struct {
	key      *ecdsa.PrivateKey
	verifier grant.Verifier
	root     string
}

func newPublication(t *testing.T) *publication {
	t.Helper()
	key, err := grant.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := grant.NewLocalVerifier(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &publication{key: key, verifier: verifier, root: t.TempDir()}
}

// publish signs data with key (the publication's own unless another is
// given) and publishes it through grant.LocalPublisher.
func (p *publication) publish(t *testing.T, data []byte, key *ecdsa.PrivateKey) {
	t.Helper()
	if key == nil {
		key = p.key
	}
	signer, err := grant.NewLocalSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.Sign(context.Background(), data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&grant.LocalPublisher{Root: p.root}).Publish(context.Background(), grant.Publication{Bundle: data, BundleSignature: sig}); err != nil {
		t.Fatal(err)
	}
}

// overwrite replaces a published file in place, the way a publisher never
// would, to make the publication inconsistent.
func (p *publication) overwrite(t *testing.T, rel string, data []byte) {
	t.Helper()
	name := filepath.Join(p.root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// source makes a Source over the publication, logging into buf.
func (p *publication) source(buf *bytes.Buffer) *Source {
	return New(&Local{Root: p.root}, p.verifier, Options{Log: slog.New(slog.NewTextHandler(buf, nil))})
}

func TestLoadsSignedBundle(t *testing.T) {
	pub := newPublication(t)
	pub.publish(t, testBundle(t, "v1", "payments-ledger-rw", "payments-outbox-r"), nil)
	var logs bytes.Buffer
	src := pub.source(&logs)

	if err := src.Ready(); !errors.Is(err, errNotLoaded) {
		t.Errorf("Ready before load = %v, want not loaded", err)
	}
	if v := src.Version(); v != "" {
		t.Errorf("Version before load = %q", v)
	}
	if err := src.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := src.Ready(); err != nil {
		t.Errorf("Ready = %v", err)
	}
	if v := src.Version(); v != "v1" {
		t.Errorf("Version = %q, want v1", v)
	}
	g, ok := src.Lookup("payments-ledger-rw")
	if !ok {
		t.Fatal("grant not found")
	}
	if g.Name != "payments-ledger-rw" || g.Account != "111122223333" || g.BaseRole != "arn:aws:iam::111122223333:role/broker/shape-dynamo-rw" ||
		!strings.Contains(g.SessionPolicy, "dynamodb:GetItem") || len(g.ManagedPolicyARNs) != 1 ||
		g.SessionTags["team"] != "payments" || g.DurationSeconds != 1800 || len(g.Envelope) != 1 {
		t.Errorf("resolved grant = %+v", g)
	}
	if _, ok := src.Lookup("nope"); ok {
		t.Error("unknown grant found")
	}
	if !strings.Contains(logs.String(), "grant bundle loaded") || !strings.Contains(logs.String(), "new_version=v1") {
		t.Errorf("log = %s", logs.String())
	}
}

func TestBadSignatureKeptOut(t *testing.T) {
	pub := newPublication(t)
	pub.publish(t, testBundle(t, "v1", "a"), nil)
	var logs bytes.Buffer
	src := pub.source(&logs)
	if err := src.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}

	// A new version signed by another key: rejected, v1 stays.
	other, _ := grant.GenerateKey()
	pub.publish(t, testBundle(t, "v2", "a", "b"), other)
	err := src.Reload(context.Background())
	if err == nil || !strings.Contains(err.Error(), "signature by key") {
		t.Fatalf("Reload = %v, want a signature rejection", err)
	}
	if src.Version() != "v1" {
		t.Errorf("Version = %q, want v1 kept", src.Version())
	}
	if _, ok := src.Lookup("b"); ok {
		t.Error("the rejected bundle's grant is served")
	}
	if err := src.Ready(); err != nil {
		t.Errorf("Ready = %v, want ready on the last good bundle", err)
	}

	// Tampered bytes under a valid envelope: the digest no longer matches.
	pub.publish(t, testBundle(t, "v3", "a", "c"), nil)
	bundleKey, _ := grant.BundleKeys("v3")
	pub.overwrite(t, bundleKey, testBundle(t, "v3", "a", "c", "d"))
	if err := src.Reload(context.Background()); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("Reload = %v, want a digest rejection", err)
	}
	if src.Version() != "v1" {
		t.Errorf("Version = %q, want v1 kept", src.Version())
	}
}

func TestUnparsableBundleKeptOut(t *testing.T) {
	pub := newPublication(t)
	pub.publish(t, testBundle(t, "v1", "a"), nil)
	src := pub.source(&bytes.Buffer{})
	if err := src.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Signed, but not a bundle: an unknown field. The signature is over
	// the bytes, so this is what a compiler bug or a schema drift looks
	// like, and the signature verifies.
	bad := []byte(strings.Replace(string(testBundle(t, "v2", "a")), `"generatedAt"`, `"generated"`, 1))
	signer, _ := grant.NewLocalSigner(pub.key)
	sig, _ := signer.Sign(context.Background(), bad)
	sigData, _ := sig.Marshal()
	bundleKey, sigKey := grant.BundleKeys("v2")
	pub.overwrite(t, bundleKey, bad)
	pub.overwrite(t, sigKey, sigData)
	pub.overwrite(t, grant.LatestFile, []byte(`{"version":"v2","bundle":"`+bundleKey+`","signature":"`+sigKey+`"}`))
	if err := src.Reload(context.Background()); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("Reload = %v, want a parse rejection", err)
	}
	if src.Version() != "v1" {
		t.Errorf("Version = %q, want v1 kept", src.Version())
	}

	// A bundle whose version is not the pointer's.
	pub.publish(t, testBundle(t, "v3", "a"), nil)
	pub.overwrite(t, grant.LatestFile, []byte(`{"version":"v3","bundle":"bundles/v3/bundle.json","signature":"bundles/v3/bundle.json.sig"}`))
	v3Key, _ := grant.BundleKeys("v3")
	bundleV9 := testBundle(t, "v9", "a")
	sig9, _ := signer.Sign(context.Background(), bundleV9)
	sig9Data, _ := sig9.Marshal()
	pub.overwrite(t, v3Key, bundleV9)
	pub.overwrite(t, v3Key+".sig", sig9Data)
	if err := src.Reload(context.Background()); err == nil || !strings.Contains(err.Error(), `bundle says version "v9"`) {
		t.Fatalf("Reload = %v, want a version mismatch rejection", err)
	}
	if src.Version() != "v1" {
		t.Errorf("Version = %q, want v1 kept", src.Version())
	}
}

func TestVersionUnchangedIsNoOpAndChangeSwaps(t *testing.T) {
	pub := newPublication(t)
	pub.publish(t, testBundle(t, "v1", "a"), nil)
	var logs bytes.Buffer
	src := pub.source(&logs)
	if err := src.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := src.current.Load()
	logs.Reset()

	// The same version again: nothing swaps, nothing is logged.
	if err := src.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if src.current.Load() != before {
		t.Error("the snapshot was replaced for an unchanged version")
	}
	if logs.Len() != 0 {
		t.Errorf("unchanged version logged: %s", logs.String())
	}

	// A new version: the whole set swaps, old and new in the log.
	pub.publish(t, testBundle(t, "v2", "b"), nil)
	if err := src.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if src.Version() != "v2" {
		t.Errorf("Version = %q, want v2", src.Version())
	}
	if _, ok := src.Lookup("a"); ok {
		t.Error("the old bundle's grant is still served")
	}
	if _, ok := src.Lookup("b"); !ok {
		t.Error("the new bundle's grant is not served")
	}
	if !strings.Contains(logs.String(), "old_version=v1") || !strings.Contains(logs.String(), "new_version=v2") {
		t.Errorf("log = %s", logs.String())
	}
}

func TestFirstLoadFailureIsNotReady(t *testing.T) {
	pub := newPublication(t)
	var logs bytes.Buffer
	src := pub.source(&logs)

	// Nothing published yet.
	if err := src.Reload(context.Background()); err == nil {
		t.Fatal("Reload of an empty directory succeeded")
	}
	if err := src.Ready(); !errors.Is(err, errNotLoaded) || !strings.Contains(err.Error(), grant.LatestFile) {
		t.Errorf("Ready = %v, want not loaded with the fetch error", err)
	}
	if src.Version() != "" {
		t.Errorf("Version = %q, want empty", src.Version())
	}
	if _, ok := src.Lookup("a"); ok {
		t.Error("a grant was found with no bundle")
	}

	// The same failure again is not logged again; a different one is.
	if err := src.Reload(context.Background()); err == nil {
		t.Fatal("Reload succeeded")
	}
	if n := strings.Count(logs.String(), "grant bundle rejected"); n != 1 {
		t.Errorf("the same rejection was logged %d times: %s", n, logs.String())
	}
	other, _ := grant.GenerateKey()
	pub.publish(t, testBundle(t, "v1", "a"), other)
	if err := src.Reload(context.Background()); err == nil {
		t.Fatal("Reload accepted a bundle signed by another key")
	}
	_ = src.Reload(context.Background())
	if n := strings.Count(logs.String(), "grant bundle rejected"); n != 2 {
		t.Errorf("rejections logged %d times, want 2: %s", n, logs.String())
	}
	if err := src.Ready(); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Errorf("Ready = %v, want the signature rejection", err)
	}

	// Then a good publication puts it in service.
	pub.publish(t, testBundle(t, "v1", "a"), nil)
	if err := src.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := src.Ready(); err != nil {
		t.Errorf("Ready = %v", err)
	}
}

func TestRunPollsAndStops(t *testing.T) {
	pub := newPublication(t)
	pub.publish(t, testBundle(t, "v1", "a"), nil)
	src := New(&Local{Root: pub.root}, pub.verifier, Options{PollInterval: 10 * time.Millisecond, Log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		src.Run(ctx)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for src.Version() != "v1" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if src.Version() != "v1" {
		t.Fatal("Run did not load the bundle")
	}
	pub.publish(t, testBundle(t, "v2", "a"), nil)
	for src.Version() != "v2" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if src.Version() != "v2" {
		t.Fatal("Run did not pick up the new version")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestConvertRejectsDuplicates(t *testing.T) {
	b := &grant.Bundle{Version: "v1", Grants: []grant.BundleGrant{{Name: "a"}, {Name: "a"}}}
	if _, err := convert(b); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("convert = %v", err)
	}
	b = &grant.Bundle{Version: "v1", Grants: []grant.BundleGrant{{Name: ""}}}
	if _, err := convert(b); err == nil {
		t.Error("convert accepted a nameless grant")
	}
	b = &grant.Bundle{Version: "v1", Grants: []grant.BundleGrant{{Name: "a", Duration: -1}}}
	if _, err := convert(b); err == nil {
		t.Error("convert accepted a negative duration")
	}
}

func TestConvertLookupGrant(t *testing.T) {
	lookup := &grant.BundleLookup{
		Param: "bucket", Kind: "s3_bucket", Permission: "read", MaxResources: 3,
		Template: grant.BundleTemplate{
			Name: "t", Params: map[string]grant.ParamSpec{"bucket": {Type: grant.ParamString}},
			Policy: []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::${bucket}/*"}]}`),
		},
		Params: map[string]grant.Param{},
	}
	b := &grant.Bundle{Version: "v1", Grants: []grant.BundleGrant{{Name: "a", Account: "111122223333", Lookup: lookup}}}
	snap, err := convert(b)
	if err != nil {
		t.Fatal(err)
	}
	l := snap.grants["a"].Lookup
	if l == nil || l.Kind != "s3_bucket" || l.Permission != "read" || l.MaxResources != 3 {
		t.Fatalf("lookup = %+v", l)
	}
	policy, err := l.Render([]string{"data-a", "data-b"})
	if err != nil || !strings.Contains(policy, "arn:aws:s3:::data-a/*") || !strings.Contains(policy, "arn:aws:s3:::data-b/*") {
		t.Errorf("rendered %s, %v", policy, err)
	}
	for name, bad := range map[string]grant.BundleGrant{
		"a rendered policy": {Name: "a", SessionPolicy: "{}", Lookup: lookup},
		"an unknown kind":   {Name: "a", Lookup: &grant.BundleLookup{Kind: "sqs_queue", Permission: "read", MaxResources: 1}},
		"no maximum":        {Name: "a", Lookup: &grant.BundleLookup{Kind: "s3_bucket", Permission: "read"}},
	} {
		if _, err := convert(&grant.Bundle{Version: "v1", Grants: []grant.BundleGrant{bad}}); err == nil {
			t.Errorf("a lookup grant with %s converted", name)
		}
	}
}
