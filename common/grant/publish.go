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
	BundleFile    = "bundle.json"
	SignatureFile = "bundle.json.sig"
	LatestFile    = "latest"
	bundlesDir    = "bundles"
)

// Latest is the pointer file at the root of a publication: the current
// version and where its bundle and signature are, relative to the root.
type Latest struct {
	Version   string `json:"version"`
	Bundle    string `json:"bundle"`
	Signature string `json:"signature"`
}

// ParseLatest decodes a latest pointer. Unknown fields are an error.
func ParseLatest(data []byte) (*Latest, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var l Latest
	if err := dec.Decode(&l); err != nil {
		return nil, fmt.Errorf("%s: %w", LatestFile, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%s: trailing data", LatestFile)
	}
	return &l, nil
}

// PublishResult says where a publisher put a bundle, relative to its root.
type PublishResult struct {
	Version   string
	Bundle    string
	Signature string
	Latest    string
}

// Publisher writes a signed bundle where the broker reads it.
type Publisher interface {
	Publish(ctx context.Context, bundle []byte, sig *Signature) (*PublishResult, error)
}

// BundleKeys returns the relative paths of a version's bundle and signature.
func BundleKeys(version string) (bundle, signature string) {
	return path.Join(bundlesDir, version, BundleFile), path.Join(bundlesDir, version, SignatureFile)
}

// publication checks the bundle and signature belong together and lays out
// what to write.
type publication struct {
	result  PublishResult
	bundle  []byte
	sig     []byte
	pointer []byte
}

func prepare(bundle []byte, sig *Signature) (*publication, error) {
	b, err := ParseBundle(bundle)
	if err != nil {
		return nil, err
	}
	if sig == nil {
		return nil, errors.New("no signature")
	}
	if want := Digest(bundle); sig.Digest != want {
		return nil, fmt.Errorf("signature digest %s does not match the bundle's %s", sig.Digest, want)
	}
	sigData, err := sig.Marshal()
	if err != nil {
		return nil, err
	}
	bundleKey, sigKey := BundleKeys(b.Version)
	pointer, err := json.MarshalIndent(Latest{Version: b.Version, Bundle: bundleKey, Signature: sigKey}, "", "  ")
	if err != nil {
		return nil, err
	}
	return &publication{
		result:  PublishResult{Version: b.Version, Bundle: bundleKey, Signature: sigKey, Latest: LatestFile},
		bundle:  bundle,
		sig:     sigData,
		pointer: append(pointer, '\n'),
	}, nil
}

// LocalPublisher publishes into a directory.
type LocalPublisher struct {
	Root string
}

// Publish implements Publisher: the versioned files are written first, each
// through a rename, and the latest pointer last.
func (p *LocalPublisher) Publish(_ context.Context, bundle []byte, sig *Signature) (*PublishResult, error) {
	pub, err := prepare(bundle, sig)
	if err != nil {
		return nil, err
	}
	for _, f := range []struct {
		rel  string
		data []byte
	}{
		{pub.result.Bundle, pub.bundle},
		{pub.result.Signature, pub.sig},
		{pub.result.Latest, pub.pointer},
	} {
		if err := writeAtomic(filepath.Join(p.Root, filepath.FromSlash(f.rel)), f.data); err != nil {
			return nil, err
		}
	}
	return &pub.result, nil
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
// complete bundle and its signature. Objects are written with a SHA-256
// checksum.
func (p *S3Publisher) Publish(ctx context.Context, bundle []byte, sig *Signature) (*PublishResult, error) {
	pub, err := prepare(bundle, sig)
	if err != nil {
		return nil, err
	}
	for _, f := range []struct {
		rel  string
		data []byte
	}{
		{pub.result.Bundle, pub.bundle},
		{pub.result.Signature, pub.sig},
		{pub.result.Latest, pub.pointer},
	} {
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
	return &pub.result, nil
}
