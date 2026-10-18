package grant

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// Publication layout (see the package documentation).
const (
	BundleFile               = "bundle.json"
	SignatureFile            = "bundle.json.sig"
	AssignmentsFile          = "assignments.json"
	AssignmentsSignatureFile = "assignments.json.sig"
	LatestFile               = "latest"
	bundlesDir               = "bundles"
)

// Latest is the pointer file at the root of a publication: the current
// version and where its bundle and signature are, relative to the root.
// A version's assignments are where the layout puts them
// (AssignmentsKeys); the pointer does not name them, so that a reader
// which predates them, and decodes the pointer strictly, keeps working.
type Latest struct {
	Version   string `json:"version"`
	Bundle    string `json:"bundle"`
	Signature string `json:"signature"`
}

// ParseLatest decodes a latest pointer. Unknown fields are ignored: the
// pointer is not signed and nothing in it but the version is trusted, so
// a later field (as the next additive change to the layout would bring)
// does not stop this reader.
func ParseLatest(data []byte) (*Latest, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	var l Latest
	if err := dec.Decode(&l); err != nil {
		return nil, fmt.Errorf("%s: %w", LatestFile, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%s: trailing data", LatestFile)
	}
	return &l, nil
}

// PublishResult says where a publisher put a version, relative to its
// root. Assignments and AssignmentsSignature are empty when the version
// was published without assignments.
type PublishResult struct {
	Version              string
	Bundle               string
	Signature            string
	Assignments          string
	AssignmentsSignature string
	Latest               string
}

// Publication is one version to publish: the bundle and its signature,
// and optionally the assignments document of the same version and its
// signature.
type Publication struct {
	Bundle               []byte
	BundleSignature      *Signature
	Assignments          []byte
	AssignmentsSignature *Signature
}

// Publisher writes a signed version where the broker reads it.
type Publisher interface {
	Publish(ctx context.Context, pub Publication) (*PublishResult, error)
}

// BundleKeys returns the relative paths of a version's bundle and signature.
func BundleKeys(version string) (bundle, signature string) {
	return path.Join(bundlesDir, version, BundleFile), path.Join(bundlesDir, version, SignatureFile)
}

// AssignmentsKeys returns the relative paths of a version's assignments
// document and its signature, beside its bundle.
func AssignmentsKeys(version string) (assignments, signature string) {
	return path.Join(bundlesDir, version, AssignmentsFile), path.Join(bundlesDir, version, AssignmentsSignatureFile)
}

// file is one object of a publication: its relative key and bytes.
type file struct {
	rel  string
	data []byte
}

// prepared is a checked publication and the files to write, in order: the
// versioned ones first, the latest pointer last.
type prepared struct {
	result PublishResult
	files  []file
}

// prepare checks the documents and signatures belong together (each
// signature's digest is of its document, the assignments are of the
// bundle's version) and lays out what to write.
func prepare(pub Publication) (*prepared, error) {
	b, err := ParseBundle(pub.Bundle)
	if err != nil {
		return nil, err
	}
	sigData, err := signatureFor(pub.Bundle, pub.BundleSignature)
	if err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	bundleKey, sigKey := BundleKeys(b.Version)
	p := &prepared{
		result: PublishResult{Version: b.Version, Bundle: bundleKey, Signature: sigKey, Latest: LatestFile},
		files:  []file{{bundleKey, pub.Bundle}, {sigKey, sigData}},
	}
	if pub.Assignments != nil || pub.AssignmentsSignature != nil {
		if err := p.addAssignments(pub); err != nil {
			return nil, err
		}
	}
	pointer, err := json.MarshalIndent(Latest{Version: b.Version, Bundle: bundleKey, Signature: sigKey}, "", "  ")
	if err != nil {
		return nil, err
	}
	p.files = append(p.files, file{LatestFile, append(pointer, '\n')})
	return p, nil
}

func (p *prepared) addAssignments(pub Publication) error {
	a, err := ParseAssignments(pub.Assignments)
	if err != nil {
		return err
	}
	if a.Version != p.result.Version {
		return fmt.Errorf("assignments are version %q, the bundle %q", a.Version, p.result.Version)
	}
	sigData, err := signatureFor(pub.Assignments, pub.AssignmentsSignature)
	if err != nil {
		return fmt.Errorf("assignments: %w", err)
	}
	key, sigKey := AssignmentsKeys(a.Version)
	p.result.Assignments, p.result.AssignmentsSignature = key, sigKey
	p.files = append(p.files, file{key, pub.Assignments}, file{sigKey, sigData})
	return nil
}

// signatureFor checks a signature is over data and encodes it.
func signatureFor(data []byte, sig *Signature) ([]byte, error) {
	if sig == nil {
		return nil, errors.New("no signature")
	}
	if want := Digest(data); sig.Digest != want {
		return nil, fmt.Errorf("signature digest %s does not match the document's %s", sig.Digest, want)
	}
	return sig.Marshal()
}

// LocalPublisher publishes into a directory.
type LocalPublisher struct {
	Root string
}

// Publish implements Publisher: the versioned files are written first, each
// through a rename, and the latest pointer last.
func (p *LocalPublisher) Publish(_ context.Context, pub Publication) (*PublishResult, error) {
	prep, err := prepare(pub)
	if err != nil {
		return nil, err
	}
	for _, f := range prep.files {
		if err := writeAtomic(filepath.Join(p.Root, filepath.FromSlash(f.rel)), f.data); err != nil {
			return nil, err
		}
	}
	return &prep.result, nil
}

func writeAtomic(name string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(name), "."+filepath.Base(name)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), name)
}

// S3API is the part of the S3 client the publisher uses, so tests can
// substitute a fake.
type S3API interface {
	PutObject(ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

// S3Publisher publishes into a bucket under a key prefix.
type S3Publisher struct {
	api    S3API
	bucket string
	prefix string
}

// NewS3Publisher makes a publisher for s3://bucket/prefix.
func NewS3Publisher(api S3API, bucket, prefix string) *S3Publisher {
	return &S3Publisher{api: api, bucket: bucket, prefix: strings.Trim(prefix, "/")}
}

// Publish implements Publisher: the versioned objects are written first and
// the latest pointer last, so a reader that follows the pointer finds a
// complete version: its bundle, its assignments and their signatures.
// Objects are written with a SHA-256 checksum.
func (p *S3Publisher) Publish(ctx context.Context, pub Publication) (*PublishResult, error) {
	prep, err := prepare(pub)
	if err != nil {
		return nil, err
	}
	for _, f := range prep.files {
		key := f.rel
		if p.prefix != "" {
			key = p.prefix + "/" + f.rel
		}
		_, err := p.api.PutObject(ctx, &s3.PutObjectInput{
			Bucket:            aws.String(p.bucket),
			Key:               aws.String(key),
			Body:              bytes.NewReader(f.data),
			ContentType:       aws.String("application/json"),
			ChecksumAlgorithm: s3types.ChecksumAlgorithmSha256,
		})
		if err != nil {
			return nil, fmt.Errorf("s3 PutObject %s: %w", key, err)
		}
	}
	return &prep.result, nil
}
