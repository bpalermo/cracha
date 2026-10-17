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

// KMSAPI is the part of the KMS client the signer and verifier use, so
// tests can substitute a fake.
type KMSAPI interface {
	Sign(ctx context.Context, in *kms.SignInput, opts ...func(*kms.Options)) (*kms.SignOutput, error)
	Verify(ctx context.Context, in *kms.VerifyInput, opts ...func(*kms.Options)) (*kms.VerifyOutput, error)
}

// KMSSigner signs with an asymmetric KMS key (ECC_NIST_P256, SIGN_VERIFY)
// through kms:Sign over the bundle's digest. keyID is the key's ARN, and is
// what the envelope carries.
type KMSSigner struct {
	api   KMSAPI
	keyID string
}

// NewKMSSigner makes a signer for the KMS key.
func NewKMSSigner(api KMSAPI, keyID string) *KMSSigner {
	return &KMSSigner{api: api, keyID: keyID}
}

// Sign implements Signer.
func (s *KMSSigner) Sign(ctx context.Context, bundle []byte) (*Signature, error) {
	sum := sha256.Sum256(bundle)
	out, err := s.api.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(s.keyID),
		Message:          sum[:],
		MessageType:      kmstypes.MessageTypeDigest,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return nil, fmt.Errorf("kms Sign: %w", err)
	}
	return &Signature{
		Version:   SignatureVersion,
		Algorithm: AlgorithmECDSASHA256,
		KeyID:     s.keyID,
		Digest:    Digest(bundle),
		Signature: base64.StdEncoding.EncodeToString(out.Signature),
	}, nil
}

// KMSVerifier verifies through kms:Verify with the same key.
type KMSVerifier struct {
	api   KMSAPI
	keyID string
}

// NewKMSVerifier makes a verifier for the KMS key; keyID must be what the
// signer used, the key's ARN.
func NewKMSVerifier(api KMSAPI, keyID string) *KMSVerifier {
	return &KMSVerifier{api: api, keyID: keyID}
}

// Verify implements Verifier.
func (v *KMSVerifier) Verify(ctx context.Context, bundle []byte, sig *Signature) error {
	raw, err := checkEnvelope(bundle, sig, v.keyID)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(bundle)
	out, err := v.api.Verify(ctx, &kms.VerifyInput{
		KeyId:            aws.String(v.keyID),
		Message:          sum[:],
		MessageType:      kmstypes.MessageTypeDigest,
		Signature:        raw,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return fmt.Errorf("kms Verify: %w", err)
	}
	if !out.SignatureValid {
		return errors.New("signature does not verify")
	}
	return nil
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
