package grant

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// Signature envelope constants (see the package documentation).
const (
	SignatureVersion     = 1
	AlgorithmECDSASHA256 = "ECDSA_SHA_256"
)

// Signature is the detached signature envelope of a bundle.
type Signature struct {
	Version   int    `json:"version"`
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"keyId"`
	Digest    string `json:"digest"`
	Signature string `json:"signature"`
}

// Marshal encodes the envelope as indented JSON with a trailing newline.
func (s *Signature) Marshal() ([]byte, error) {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// ParseSignature decodes a signature envelope. Unknown fields are an error.
func ParseSignature(data []byte) (*Signature, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s Signature
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	if dec.More() {
		return nil, errors.New("signature: trailing data")
	}
	return &s, nil
}

// Signer signs bundle bytes.
type Signer interface {
	Sign(ctx context.Context, bundle []byte) (*Signature, error)
}

// Verifier checks a signature over bundle bytes. A nil error means the
// bundle is authentic.
type Verifier interface {
	Verify(ctx context.Context, bundle []byte, sig *Signature) error
}

// Digest is the "sha256:<hex>" digest of the bundle bytes, as written in
// the envelope.
func Digest(bundle []byte) string {
	sum := sha256.Sum256(bundle)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// checkEnvelope verifies everything about a signature that does not need
// the key: version, algorithm, digest and key identity. It returns the raw
// signature bytes.
func checkEnvelope(bundle []byte, sig *Signature, keyID string) ([]byte, error) {
	if sig == nil {
		return nil, errors.New("no signature")
	}
	if sig.Version != SignatureVersion {
		return nil, fmt.Errorf("signature version %d, want %d", sig.Version, SignatureVersion)
	}
	if sig.Algorithm != AlgorithmECDSASHA256 {
		return nil, fmt.Errorf("signature algorithm %q, want %s", sig.Algorithm, AlgorithmECDSASHA256)
	}
	if sig.KeyID != keyID {
		return nil, fmt.Errorf("signature by key %q, want %q", sig.KeyID, keyID)
	}
	if want := Digest(bundle); sig.Digest != want {
		return nil, fmt.Errorf("bundle digest %s does not match the signature's %s", want, sig.Digest)
	}
	raw, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil {
		return nil, fmt.Errorf("signature is not base64: %w", err)
	}
	return raw, nil
}

// KeyID identifies a public key: "sha256:<hex>" of its PKIX DER encoding.
func KeyID(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// LocalSigner signs with an ECDSA P-256 private key held in memory.
type LocalSigner struct {
	key   *ecdsa.PrivateKey
	keyID string
}

// NewLocalSigner wraps a P-256 private key.
func NewLocalSigner(key *ecdsa.PrivateKey) (*LocalSigner, error) {
	if key.Curve != elliptic.P256() {
		return nil, errors.New("signing key must be ECDSA P-256")
	}
	id, err := KeyID(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &LocalSigner{key: key, keyID: id}, nil
}

// KeyID returns the signer's key identity.
func (s *LocalSigner) KeyID() string { return s.keyID }

// Sign implements Signer.
func (s *LocalSigner) Sign(_ context.Context, bundle []byte) (*Signature, error) {
	sum := sha256.Sum256(bundle)
	raw, err := ecdsa.SignASN1(rand.Reader, s.key, sum[:])
	if err != nil {
		return nil, err
	}
	return &Signature{
		Version:   SignatureVersion,
		Algorithm: AlgorithmECDSASHA256,
		KeyID:     s.keyID,
		Digest:    Digest(bundle),
		Signature: base64.StdEncoding.EncodeToString(raw),
	}, nil
}

// LocalVerifier verifies with an ECDSA P-256 public key: a local signer's,
// or a KMS key's exported public key.
type LocalVerifier struct {
	pub   *ecdsa.PublicKey
	keyID string
}

// NewLocalVerifier wraps a P-256 public key.
func NewLocalVerifier(pub *ecdsa.PublicKey) (*LocalVerifier, error) {
	if pub.Curve != elliptic.P256() {
		return nil, errors.New("verification key must be ECDSA P-256")
	}
	id, err := KeyID(pub)
	if err != nil {
		return nil, err
	}
	return &LocalVerifier{pub: pub, keyID: id}, nil
}

// KeyID returns the verifier's key identity.
func (v *LocalVerifier) KeyID() string { return v.keyID }

// Verify implements Verifier.
func (v *LocalVerifier) Verify(_ context.Context, bundle []byte, sig *Signature) error {
	raw, err := checkEnvelope(bundle, sig, v.keyID)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(bundle)
	if !ecdsa.VerifyASN1(v.pub, sum[:], raw) {
		return errors.New("signature does not verify")
	}
	return nil
}

// KeyRing verifies with any one of several public keys, the one whose key
// identity the envelope names: what makes rotating the signing key
// possible, since a reader trusts the old and the new key while the
// publication moves from one to the other.
type KeyRing struct {
	keys map[string]*LocalVerifier
	ids  []string
}

// NewKeyRing makes a key ring of P-256 public keys. Listing a key twice is
// an error, as is an empty ring.
func NewKeyRing(pubs ...*ecdsa.PublicKey) (*KeyRing, error) {
	if len(pubs) == 0 {
		return nil, errors.New("no verification key")
	}
	r := &KeyRing{keys: map[string]*LocalVerifier{}}
	for _, pub := range pubs {
		v, err := NewLocalVerifier(pub)
		if err != nil {
			return nil, err
		}
		if _, dup := r.keys[v.keyID]; dup {
			return nil, fmt.Errorf("verification key %s listed twice", v.keyID)
		}
		r.keys[v.keyID] = v
		r.ids = append(r.ids, v.keyID)
	}
	return r, nil
}

// KeyIDs returns the identities of the ring's keys, in the order given.
func (r *KeyRing) KeyIDs() []string { return append([]string(nil), r.ids...) }

// Verify implements Verifier: the envelope's keyId selects the key.
func (r *KeyRing) Verify(ctx context.Context, data []byte, sig *Signature) error {
	if sig == nil {
		return errors.New("no signature")
	}
	v, ok := r.keys[sig.KeyID]
	if !ok {
		return fmt.Errorf("signature by key %q, which is not one of the %d verification keys", sig.KeyID, len(r.keys))
	}
	return v.Verify(ctx, data, sig)
}

// ParseECPublicKeys reads every PEM-encoded ("PUBLIC KEY", PKIX) ECDSA
// public key in pemData, in order; at least one is required, and anything
// but PEM blocks between them (comments, blank lines) is ignored.
func ParseECPublicKeys(pemData []byte) ([]*ecdsa.PublicKey, error) {
	var keys []*ecdsa.PublicKey
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		key, err := ParseECPublicKey(pem.EncodeToMemory(block))
		if err != nil {
			return nil, fmt.Errorf("key %d: %w", len(keys)+1, err)
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, errors.New("no PEM block")
	}
	return keys, nil
}

// KMSAPI is the part of the KMS client the signer and verifier use, so
// tests can substitute a fake. Nothing here calls kms:Verify: signatures
// are verified with the key's public key, the way a broker does offline.
type KMSAPI interface {
	Sign(ctx context.Context, in *kms.SignInput, opts ...func(*kms.Options)) (*kms.SignOutput, error)
	GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
}

// kmsPublicKey fetches a KMS key's public key once, through
// kms:GetPublicKey, and keeps it. A failure is not kept: the next call
// tries again.
type kmsPublicKey struct {
	api   KMSAPI
	keyID string

	mu       sync.Mutex
	verifier *LocalVerifier
}

// get returns the verifier of the key's public key, fetching it the first
// time. The key must be an ECC_NIST_P256 signing key.
func (k *kmsPublicKey) get(ctx context.Context) (*LocalVerifier, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.verifier != nil {
		return k.verifier, nil
	}
	out, err := k.api.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(k.keyID)})
	if err != nil {
		return nil, fmt.Errorf("kms GetPublicKey %s: %w", k.keyID, err)
	}
	pub, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("kms key %s: public key: %w", k.keyID, err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("kms key %s: public key is %T, want ECDSA P-256", k.keyID, pub)
	}
	v, err := NewLocalVerifier(ec)
	if err != nil {
		return nil, fmt.Errorf("kms key %s: %w", k.keyID, err)
	}
	k.verifier = v
	return v, nil
}

// KMSSigner signs with an asymmetric KMS key (ECC_NIST_P256, SIGN_VERIFY)
// through kms:Sign over the document's digest. The envelope's keyId is the
// identity of the key's public key (KeyID), which it fetches once through
// kms:GetPublicKey: exactly what a LocalVerifier of the exported PEM
// computes, so a KMS signature verifies with the PEM alone, offline.
type KMSSigner struct {
	api KMSAPI
	pub kmsPublicKey
}

// NewKMSSigner makes a signer for the KMS key: its ARN, ID or alias.
func NewKMSSigner(api KMSAPI, keyID string) *KMSSigner {
	return &KMSSigner{api: api, pub: kmsPublicKey{api: api, keyID: keyID}}
}

// Sign implements Signer. The signature KMS returns is checked against the
// public key before it is handed out.
func (s *KMSSigner) Sign(ctx context.Context, data []byte) (*Signature, error) {
	verifier, err := s.pub.get(ctx)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	out, err := s.api.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(s.pub.keyID),
		Message:          sum[:],
		MessageType:      kmstypes.MessageTypeDigest,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return nil, fmt.Errorf("kms Sign: %w", err)
	}
	sig := &Signature{
		Version:   SignatureVersion,
		Algorithm: AlgorithmECDSASHA256,
		KeyID:     verifier.KeyID(),
		Digest:    Digest(data),
		Signature: base64.StdEncoding.EncodeToString(out.Signature),
	}
	if err := verifier.Verify(ctx, data, sig); err != nil {
		return nil, fmt.Errorf("kms Sign: the signature does not verify with the key's public key: %w", err)
	}
	return sig, nil
}

// KMSVerifier verifies with a KMS key's public key, fetched once through
// kms:GetPublicKey (the only KMS permission it needs) and then used as a
// LocalVerifier would: no kms:Verify, no AWS call per verification.
type KMSVerifier struct {
	pub kmsPublicKey
}

// NewKMSVerifier makes a verifier for the KMS key: its ARN, ID or alias.
func NewKMSVerifier(api KMSAPI, keyID string) *KMSVerifier {
	return &KMSVerifier{pub: kmsPublicKey{api: api, keyID: keyID}}
}

// Verify implements Verifier.
func (v *KMSVerifier) Verify(ctx context.Context, data []byte, sig *Signature) error {
	verifier, err := v.pub.get(ctx)
	if err != nil {
		return err
	}
	return verifier.Verify(ctx, data, sig)
}

// ParseECPrivateKey reads a PEM-encoded ECDSA private key, in PKCS #8
// ("PRIVATE KEY") or SEC 1 ("EC PRIVATE KEY") form.
func ParseECPrivateKey(pemData []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		ec, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is %T, want ECDSA", key)
		}
		return ec, nil
	default:
		return nil, fmt.Errorf("PEM block is %q, want PRIVATE KEY or EC PRIVATE KEY", block.Type)
	}
}

// ParseECPublicKey reads a PEM-encoded ("PUBLIC KEY", PKIX) ECDSA public
// key, such as the one kms:GetPublicKey exports.
func ParseECPublicKey(pemData []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("PEM block is %q, want PUBLIC KEY", block.Type)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is %T, want ECDSA", key)
	}
	return ec, nil
}

// EncodeECPrivateKey writes a private key as PKCS #8 PEM.
func EncodeECPrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// EncodeECPublicKey writes a public key as PKIX PEM.
func EncodeECPublicKey(pub *ecdsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// GenerateKey makes a new ECDSA P-256 key for the local signer.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
