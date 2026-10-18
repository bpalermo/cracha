package grant

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestLocalSignVerify(t *testing.T) {
	ctx := context.Background()
	key := mustKey(t)
	signer, err := NewLocalSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewLocalVerifier(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	bundle := []byte(`{"version":"v1"}` + "\n")
	sig, err := signer.Sign(ctx, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if sig.Version != 1 || sig.Algorithm != "ECDSA_SHA_256" || sig.KeyID != signer.KeyID() || sig.KeyID != verifier.KeyID() ||
		!strings.HasPrefix(sig.KeyID, "sha256:") || sig.Digest != Digest(bundle) {
		t.Errorf("signature = %+v", sig)
	}
	if err := verifier.Verify(ctx, bundle, sig); err != nil {
		t.Errorf("Verify: %v", err)
	}

	// The envelope survives a round trip through its file form.
	data, err := sig.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSignature(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(ctx, bundle, parsed); err != nil {
		t.Errorf("Verify(parsed): %v", err)
	}

	tests := []struct {
		name   string
		bundle []byte
		mutate func(s *Signature)
		want   string
	}{
		{"tampered bundle", []byte(`{"version":"v2"}` + "\n"), func(*Signature) {}, "digest"},
		{"digest rewritten", []byte(`{"version":"v2"}` + "\n"), func(s *Signature) { s.Digest = Digest([]byte(`{"version":"v2"}` + "\n")) }, "does not verify"},
		{"wrong version", bundle, func(s *Signature) { s.Version = 2 }, "signature version 2"},
		{"wrong algorithm", bundle, func(s *Signature) { s.Algorithm = "RSASSA_PSS_SHA_256" }, "algorithm"},
		{"wrong key", bundle, func(s *Signature) { s.KeyID = "sha256:00" }, "signature by key"},
		{"not base64", bundle, func(s *Signature) { s.Signature = "***" }, "not base64"},
		{"garbage signature", bundle, func(s *Signature) { s.Signature = "AAAA" }, "does not verify"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := *sig
			tt.mutate(&s)
			err := verifier.Verify(ctx, tt.bundle, &s)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Verify = %v, want it to contain %q", err, tt.want)
			}
		})
	}
	if err := verifier.Verify(ctx, bundle, nil); err == nil {
		t.Error("Verify(nil) succeeded")
	}

	other := mustKey(t)
	otherVerifier, _ := NewLocalVerifier(&other.PublicKey)
	if err := otherVerifier.Verify(ctx, bundle, sig); err == nil {
		t.Error("another key verified the signature")
	}
}

func TestLocalKeysMustBeP256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewLocalSigner(key); err == nil {
		t.Error("NewLocalSigner accepted P-384")
	}
	if _, err := NewLocalVerifier(&key.PublicKey); err == nil {
		t.Error("NewLocalVerifier accepted P-384")
	}
}

func TestKeyPEM(t *testing.T) {
	key := mustKey(t)
	priv, err := EncodeECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := EncodeECPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	parsedPriv, err := ParseECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	parsedPub, err := ParseECPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if !parsedPriv.Equal(key) || !parsedPub.Equal(&key.PublicKey) {
		t.Error("keys changed through PEM")
	}
	if _, err := ParseECPrivateKey(pub); err == nil {
		t.Error("ParseECPrivateKey accepted a public key")
	}
	if _, err := ParseECPublicKey(priv); err == nil {
		t.Error("ParseECPublicKey accepted a private key")
	}
	if _, err := ParseECPrivateKey([]byte("junk")); err == nil || !strings.Contains(err.Error(), "no PEM block") {
		t.Errorf("error = %v", err)
	}
}

func TestParseSignature(t *testing.T) {
	if _, err := ParseSignature([]byte(`{"version":1,"extra":true}`)); err == nil || !strings.Contains(err.Error(), `unknown field "extra"`) {
		t.Errorf("error = %v", err)
	}
	if _, err := ParseSignature([]byte(`{"version":1} {}`)); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Errorf("error = %v", err)
	}
}

// fakeKMS signs with a real P-256 key, the way KMS does for an
// ECC_NIST_P256 key (an ASN.1 DER signature over the digest), and exports
// its public key as DER SubjectPublicKeyInfo, as kms:GetPublicKey does. It
// has no Verify: nothing may call kms:Verify.
type fakeKMS struct {
	key      *ecdsa.PrivateKey
	keyARN   string
	signIn   *kms.SignInput
	getCalls int
	err      error
	getErr   error
}

func (f *fakeKMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	f.signIn = in
	if f.err != nil {
		return nil, f.err
	}
	if aws.ToString(in.KeyId) != f.keyARN {
		return nil, errors.New("NotFoundException")
	}
	if in.MessageType != kmstypes.MessageTypeDigest || in.SigningAlgorithm != kmstypes.SigningAlgorithmSpecEcdsaSha256 || len(in.Message) != sha256.Size {
		return nil, errors.New("ValidationException")
	}
	raw, err := ecdsa.SignASN1(rand.Reader, f.key, in.Message)
	if err != nil {
		return nil, err
	}
	return &kms.SignOutput{KeyId: in.KeyId, Signature: raw, SigningAlgorithm: in.SigningAlgorithm}, nil
}

func (f *fakeKMS) GetPublicKey(_ context.Context, in *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	f.getCalls++
	if f.getErr != nil {
		return nil, f.getErr
	}
	if aws.ToString(in.KeyId) != f.keyARN {
		return nil, errors.New("NotFoundException")
	}
	der, err := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &kms.GetPublicKeyOutput{KeyId: in.KeyId, PublicKey: der, KeySpec: kmstypes.KeySpecEccNistP256}, nil
}

func TestKMSSignVerify(t *testing.T) {
	ctx := context.Background()
	const alias = "alias/test-signing"
	api := &fakeKMS{key: mustKey(t), keyARN: alias}
	signer := NewKMSSigner(api, alias)
	bundle := []byte(`{"version":"v1"}` + "\n")

	sig, err := signer.Sign(ctx, bundle)
	if err != nil {
		t.Fatal(err)
	}
	// The keyId is the public key's identity, not the KMS name.
	want, _ := KeyID(&api.key.PublicKey)
	if sig.KeyID != want || sig.Algorithm != AlgorithmECDSASHA256 || sig.Digest != Digest(bundle) {
		t.Errorf("signature = %+v, want keyId %s", sig, want)
	}

	// The exported PEM alone verifies it, offline, as a broker does.
	pemData, _ := EncodeECPublicKey(&api.key.PublicKey)
	pubs, err := ParseECPublicKeys(pemData)
	if err != nil {
		t.Fatal(err)
	}
	ring, _ := NewKeyRing(pubs...)
	if err := ring.Verify(ctx, bundle, sig); err != nil {
		t.Errorf("the exported PEM does not verify a KMS signature: %v", err)
	}
	if err := ring.Verify(ctx, []byte("tampered"), sig); err == nil {
		t.Error("tampered bundle verified")
	}

	// KMSVerifier fetches the public key once and verifies locally: the
	// fake has no Verify to call.
	verifier := NewKMSVerifier(api, alias)
	api.getCalls = 0
	for range 3 {
		if err := verifier.Verify(ctx, bundle, sig); err != nil {
			t.Errorf("Verify: %v", err)
		}
	}
	if api.getCalls != 1 {
		t.Errorf("GetPublicKey called %d times, want once", api.getCalls)
	}
	bad := *sig
	bad.Signature = "AAAA"
	if err := verifier.Verify(ctx, bundle, &bad); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("Verify(garbage) = %v", err)
	}
	// A local signature by the same key verifies through the KMS verifier.
	localSigner, _ := NewLocalSigner(api.key)
	lsig, _ := localSigner.Sign(ctx, bundle)
	if err := verifier.Verify(ctx, bundle, lsig); err != nil {
		t.Errorf("KMS verifier on a local signature: %v", err)
	}
	// Another key's signature does not.
	other, _ := NewLocalSigner(mustKey(t))
	osig, _ := other.Sign(ctx, bundle)
	if err := verifier.Verify(ctx, bundle, osig); err == nil || !strings.Contains(err.Error(), "signature by key") {
		t.Errorf("Verify of another key's signature = %v", err)
	}

	// Errors: a failed GetPublicKey is not kept; a failed Sign is reported.
	fresh := &fakeKMS{key: api.key, keyARN: alias, getErr: errors.New("AccessDeniedException")}
	v2 := NewKMSVerifier(fresh, alias)
	if err := v2.Verify(ctx, bundle, sig); err == nil || !strings.Contains(err.Error(), "kms GetPublicKey") {
		t.Errorf("Verify = %v", err)
	}
	fresh.getErr = nil
	if err := v2.Verify(ctx, bundle, sig); err != nil {
		t.Errorf("Verify after GetPublicKey recovered = %v", err)
	}
	api.err = errors.New("AccessDeniedException")
	if _, err := signer.Sign(ctx, bundle); err == nil || !strings.Contains(err.Error(), "kms Sign") {
		t.Errorf("Sign = %v", err)
	}
	// A KMS key that signs with another key than it exports is caught.
	api.err = nil
	liar := &fakeKMS{key: mustKey(t), keyARN: alias}
	liarSigner := NewKMSSigner(&mixedKMS{sign: liar, pub: api}, alias)
	if _, err := liarSigner.Sign(ctx, bundle); err == nil || !strings.Contains(err.Error(), "does not verify with the key's public key") {
		t.Errorf("Sign with a mismatched public key = %v", err)
	}
}

// mixedKMS signs with one fake and exports the other's public key.
type mixedKMS struct{ sign, pub *fakeKMS }

func (m *mixedKMS) Sign(ctx context.Context, in *kms.SignInput, o ...func(*kms.Options)) (*kms.SignOutput, error) {
	return m.sign.Sign(ctx, in, o...)
}

func (m *mixedKMS) GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, o ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	return m.pub.GetPublicKey(ctx, in, o...)
}

func TestKeyRing(t *testing.T) {
	ctx := context.Background()
	old, current, stranger := mustKey(t), mustKey(t), mustKey(t)
	ring, err := NewKeyRing(&old.PublicKey, &current.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if ids := ring.KeyIDs(); len(ids) != 2 {
		t.Errorf("KeyIDs = %v", ids)
	}
	data := []byte(`{"version":"v1"}`)
	for name, key := range map[string]*ecdsa.PrivateKey{"old": old, "current": current} {
		signer, _ := NewLocalSigner(key)
		sig, err := signer.Sign(ctx, data)
		if err != nil {
			t.Fatal(err)
		}
		if err := ring.Verify(ctx, data, sig); err != nil {
			t.Errorf("signed by the %s key: %v", name, err)
		}
		if err := ring.Verify(ctx, append(data, ' '), sig); err == nil {
			t.Errorf("signed by the %s key: tampered data verified", name)
		}
	}
	signer, _ := NewLocalSigner(stranger)
	sig, _ := signer.Sign(ctx, data)
	if err := ring.Verify(ctx, data, sig); err == nil || !strings.Contains(err.Error(), "not one of the 2 verification keys") {
		t.Errorf("a stranger's signature: %v", err)
	}
	// A signature that names a ring key but was made by another fails the
	// signature check, not the key lookup.
	forged := *sig
	forged.KeyID = ring.KeyIDs()[0]
	if err := ring.Verify(ctx, data, &forged); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("a forged keyId: %v", err)
	}
	if err := ring.Verify(ctx, data, nil); err == nil {
		t.Error("no signature verified")
	}
	if _, err := NewKeyRing(); err == nil {
		t.Error("an empty key ring was made")
	}
	if _, err := NewKeyRing(&old.PublicKey, &old.PublicKey); err == nil || !strings.Contains(err.Error(), "listed twice") {
		t.Errorf("a key listed twice: %v", err)
	}
}

func TestParseECPublicKeys(t *testing.T) {
	a, b := mustKey(t), mustKey(t)
	pa, _ := EncodeECPublicKey(&a.PublicKey)
	pb, _ := EncodeECPublicKey(&b.PublicKey)
	keys, err := ParseECPublicKeys([]byte("# the old key\n" + string(pa) + "\n# the new key\n" + string(pb)))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || !keys[0].Equal(&a.PublicKey) || !keys[1].Equal(&b.PublicKey) {
		t.Errorf("keys = %v", keys)
	}
	if _, err := ParseECPublicKeys([]byte("junk")); err == nil || !strings.Contains(err.Error(), "no PEM block") {
		t.Errorf("error = %v", err)
	}
	priv, _ := EncodeECPrivateKey(b)
	if _, err := ParseECPublicKeys(append(pa, priv...)); err == nil || !strings.Contains(err.Error(), "key 2") {
		t.Errorf("error = %v", err)
	}
}
