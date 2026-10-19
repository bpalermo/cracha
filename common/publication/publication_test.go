package publication

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bpalermo/cracha/common/grant"
)

func TestObjectSizeIsBounded(t *testing.T) {
	huge := bytes.Repeat([]byte("x"), maxObjectBytes+1)
	if _, err := readAll(bytes.NewReader(huge)); err == nil {
		t.Error("an oversized object was read")
	}
	if got, err := readAll(bytes.NewReader(huge[:maxObjectBytes])); err != nil || len(got) != maxObjectBytes {
		t.Errorf("an object at the limit: %d bytes, %v", len(got), err)
	}
}

// publish signs a bundle of one grant at version and publishes it under
// root.
func publish(t *testing.T, root, version string, key *ecdsa.PrivateKey) {
	t.Helper()
	data, err := grant.Marshal(&grant.Bundle{Version: version, GeneratedAt: "2026-10-18T00:00:00Z", Grants: []grant.BundleGrant{{
		Name: "g", Account: "111122223333", BaseRole: "arn:aws:iam::111122223333:role/shape",
		ManagedPolicyArns: []string{}, SessionTags: map[string]string{}, Duration: 3600, Envelope: []string{"arn:aws:s3:::x"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := grant.NewLocalSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.Sign(context.Background(), data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&grant.LocalPublisher{Root: root}).Publish(context.Background(), grant.Publication{Bundle: data, BundleSignature: sig}); err != nil {
		t.Fatal(err)
	}
}

func TestPollerKeepsLastGood(t *testing.T) {
	root := t.TempDir()
	key, _ := grant.GenerateKey()
	other, _ := grant.GenerateKey()
	pem, _ := grant.EncodeECPublicKey(&key.PublicKey)
	keyFile := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(keyFile, pem, 0o600); err != nil {
		t.Fatal(err)
	}
	ring, err := LoadKeyRing([]string{keyFile})
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	p := NewPoller(&Local{Root: root}, ring, 0, slog.New(slog.NewTextHandler(&logs, nil)))
	if p.Bundle() != nil || p.Ready() == nil {
		t.Fatal("ready before a load")
	}
	if err := p.Reload(context.Background()); err == nil {
		t.Fatal("an empty publication loaded")
	}
	publish(t, root, "v1", key)
	if err := p.Reload(context.Background()); err != nil || p.Bundle().Version != "v1" || p.Ready() != nil {
		t.Fatalf("Reload = %v, bundle %+v", err, p.Bundle())
	}
	publish(t, root, "v2", other)
	if err := p.Reload(context.Background()); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Errorf("a bundle signed by another key: %v", err)
	}
	if p.Bundle().Version != "v1" {
		t.Errorf("in service %q after a rejection, want v1", p.Bundle().Version)
	}
	_ = p.Reload(context.Background())
	if n := strings.Count(logs.String(), "rejected"); n != 2 {
		t.Errorf("logged %d rejections, want one per publication (2):\n%s", n, logs.String())
	}
}

func TestLoadKeyRingErrors(t *testing.T) {
	if _, err := LoadKeyRing([]string{filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Error("a missing file loaded")
	}
	bad := filepath.Join(t.TempDir(), "bad.pem")
	_ = os.WriteFile(bad, []byte("not pem"), 0o600)
	if _, err := LoadKeyRing([]string{bad}); err == nil {
		t.Error("a file without a key loaded")
	}
}
