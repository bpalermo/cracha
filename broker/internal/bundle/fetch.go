package bundle

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/bpalermo/cracha/common/grant"
)

// maxObjectBytes bounds what a fetcher reads for any one object, so a
// publication that is not a bundle cannot exhaust the broker's memory. A
// bundle is tens of kilobytes at most.
const maxObjectBytes = 16 << 20

// Fetched is one publication as found behind the latest pointer: the
// version the pointer names and the exact bytes of the versioned bundle and
// signature objects.
type Fetched struct {
	Version   string
	Bundle    []byte
	Signature []byte
}

// Fetcher reads the current publication: it resolves the latest pointer
// and then the versioned objects it names (common/grant's publication
// layout). It does no verification.
type Fetcher interface {
	Fetch(ctx context.Context) (*Fetched, error)
}

// Location is a parsed bundle source: a local directory or an S3 prefix.
type Location struct {
	// Dir is the root directory of a local source; empty for S3.
	Dir string
	// Bucket and Prefix name an S3 source; Bucket is empty for a local one.
	Bucket string
	Prefix string
}

// IsS3 reports whether the location is an S3 prefix.
func (l Location) IsS3() bool { return l.Bucket != "" }

// ParseSource parses a bundle source: "local:<dir>" or
// "s3://bucket[/prefix]".
func ParseSource(source string) (Location, error) {
	switch {
	case strings.HasPrefix(source, "local:"):
		dir := strings.TrimPrefix(source, "local:")
		if dir == "" {
			return Location{}, errors.New("bundle source: local: needs a directory")
		}
		return Location{Dir: dir}, nil
	case strings.HasPrefix(source, "s3://"):
		bucket, prefix, _ := strings.Cut(strings.TrimPrefix(source, "s3://"), "/")
		if bucket == "" {
			return Location{}, errors.New("bundle source: s3:// needs a bucket")
		}
		return Location{Bucket: bucket, Prefix: strings.Trim(prefix, "/")}, nil
	default:
		return Location{}, fmt.Errorf("bundle source %q: want local:<dir> or s3://bucket[/prefix]", source)
	}
}

// readObject is what the two fetchers differ in: a relative key of the
// publication to its bytes.
type readObject func(ctx context.Context, key string) ([]byte, error)

// resolve follows the latest pointer and reads the versioned objects. The
// pointer is not signed, so nothing in it is trusted beyond the version:
// the objects read are the ones the layout gives that version, and the
// pointer has to agree.
func resolve(ctx context.Context, read readObject) (*Fetched, error) {
	data, err := read(ctx, grant.LatestFile)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", grant.LatestFile, err)
	}
	latest, err := grant.ParseLatest(data)
	if err != nil {
		return nil, err
	}
	if !grant.ValidVersion(latest.Version) {
		return nil, fmt.Errorf("%s: version %q is not a bundle version", grant.LatestFile, latest.Version)
	}
	bundleKey, sigKey := grant.BundleKeys(latest.Version)
	if latest.Bundle != bundleKey || latest.Signature != sigKey {
		return nil, fmt.Errorf("%s: points version %s at %s and %s, want %s and %s",
			grant.LatestFile, latest.Version, latest.Bundle, latest.Signature, bundleKey, sigKey)
	}
	bundle, err := read(ctx, bundleKey)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", bundleKey, err)
	}
	sig, err := read(ctx, sigKey)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", sigKey, err)
	}
	return &Fetched{Version: latest.Version, Bundle: bundle, Signature: sig}, nil
}

// Local fetches from a directory laid out the way grant.LocalPublisher
// writes it.
type Local struct {
	Root string
}

// Fetch implements Fetcher.
func (l *Local) Fetch(ctx context.Context) (*Fetched, error) {
	return resolve(ctx, func(_ context.Context, key string) ([]byte, error) {
		f, err := os.Open(filepath.Join(l.Root, filepath.FromSlash(key)))
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return readAll(f)
	})
}

// S3API is the part of the S3 client the fetcher uses, so tests can
// substitute a fake.
type S3API interface {
	GetObject(ctx context.Context, in *s3.GetObjectInput, opts ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// S3 fetches from a bucket under a key prefix, as grant.S3Publisher writes
// it.
type S3 struct {
	api    S3API
	bucket string
	prefix string
}

// NewS3 makes a fetcher for s3://bucket/prefix.
func NewS3(api S3API, bucket, prefix string) *S3 {
	return &S3{api: api, bucket: bucket, prefix: strings.Trim(prefix, "/")}
}

// Fetch implements Fetcher.
func (s *S3) Fetch(ctx context.Context) (*Fetched, error) {
	return resolve(ctx, func(ctx context.Context, key string) ([]byte, error) {
		if s.prefix != "" {
			key = s.prefix + "/" + key
		}
		out, err := s.api.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
		if err != nil {
			return nil, fmt.Errorf("s3 GetObject: %w", err)
		}
		defer out.Body.Close()
		return readAll(out.Body)
	})
}

// readAll reads an object, refusing one over maxObjectBytes.
func readAll(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxObjectBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxObjectBytes {
		return nil, fmt.Errorf("over %d bytes", maxObjectBytes)
	}
	return data, nil
}
