package bundle

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/bpalermo/cracha/common/grant"
)

func TestParseSource(t *testing.T) {
	tests := map[string]struct {
		want Location
		err  bool
	}{
		"local:/etc/cracha/bundle": {want: Location{Dir: "/etc/cracha/bundle"}},
		"local:relative/dir":       {want: Location{Dir: "relative/dir"}},
		"s3://bucket":              {want: Location{Bucket: "bucket"}},
		"s3://bucket/":             {want: Location{Bucket: "bucket"}},
		"s3://bucket/some/prefix/": {want: Location{Bucket: "bucket", Prefix: "some/prefix"}},
		"local:":                   {err: true},
		"s3://":                    {err: true},
		"s3:///prefix":             {err: true},
		"/etc/cracha/bundle":       {err: true},
		"http://example.com":       {err: true},
		"":                         {err: true},
	}
	for in, tc := range tests {
		got, err := ParseSource(in)
		if tc.err {
			if err == nil {
				t.Errorf("ParseSource(%q) = %+v, want an error", in, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("ParseSource(%q) = %+v, %v; want %+v", in, got, err, tc.want)
		}
		if got.IsS3() != (tc.want.Bucket != "") {
			t.Errorf("ParseSource(%q).IsS3() = %t", in, got.IsS3())
		}
	}
}

// fakeS3 serves objects from a map, recording the keys asked for.
type fakeS3 struct {
	bucket  string
	objects map[string][]byte
	keys    []string
	err     error
}

func (f *fakeS3) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	f.keys = append(f.keys, aws.ToString(in.Key))
	if f.err != nil {
		return nil, f.err
	}
	if aws.ToString(in.Bucket) != f.bucket {
		return nil, fmt.Errorf("bucket %q, want %q", aws.ToString(in.Bucket), f.bucket)
	}
	data, ok := f.objects[aws.ToString(in.Key)]
	if !ok {
		return nil, errors.New("NoSuchKey")
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(data))}, nil
}

// publishToFake publishes a signed bundle into the fake through
// grant.S3Publisher, so the layout is the real one.
func publishToFake(t *testing.T, f *fakeS3, prefix string, data []byte, sig *grant.Signature) {
	t.Helper()
	put := &fakePut{objects: f.objects}
	if _, err := grant.NewS3Publisher(put, f.bucket, prefix).Publish(context.Background(), grant.Publication{Bundle: data, BundleSignature: sig}); err != nil {
		t.Fatal(err)
	}
}

type fakePut struct {
	objects map[string][]byte
}

func (p *fakePut) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	data, err := io.ReadAll(in.Body)
	if err != nil {
		return nil, err
	}
	p.objects[aws.ToString(in.Key)] = data
	return &s3.PutObjectOutput{}, nil
}

func TestS3Fetcher(t *testing.T) {
	pub := newPublication(t)
	data := testBundle(t, "abc123", "a")
	signer, _ := grant.NewLocalSigner(pub.key)
	sig, _ := signer.Sign(context.Background(), data)
	fake := &fakeS3{bucket: "grants", objects: map[string][]byte{}}
	publishToFake(t, fake, "/cracha/prod/", data, sig)

	f := NewS3(fake, "grants", "/cracha/prod/")
	got, err := f.Fetch(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != "abc123" || !bytes.Equal(got.Bundle, data) {
		t.Errorf("fetched %+v", got)
	}
	parsed, err := grant.ParseSignature(got.Signature)
	if err != nil || parsed.Signature != sig.Signature {
		t.Errorf("signature = %+v, %v", parsed, err)
	}
	want := []string{"cracha/prod/latest", "cracha/prod/bundles/abc123/bundle.json", "cracha/prod/bundles/abc123/bundle.json.sig"}
	if strings.Join(fake.keys, " ") != strings.Join(want, " ") {
		t.Errorf("keys read = %v, want %v", fake.keys, want)
	}

	// The whole source works over it too.
	src := New(f, pub.verifier, Options{Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err := src.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if src.Version() != "abc123" {
		t.Errorf("Version = %q", src.Version())
	}

	// A bucket without a prefix, and an unreachable bucket.
	fake2 := &fakeS3{bucket: "grants", objects: map[string][]byte{}}
	publishToFake(t, fake2, "", data, sig)
	if got, err := NewS3(fake2, "grants", "").Fetch(context.Background(), false); err != nil || got.Version != "abc123" || fake2.keys[0] != "latest" {
		t.Errorf("no prefix: %+v, %v, keys %v", got, err, fake2.keys)
	}
	fake2.err = errors.New("AccessDenied")
	if _, err := NewS3(fake2, "grants", "").Fetch(context.Background(), false); err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Errorf("error not passed through: %v", err)
	}
}

func TestPointerIsNotTrusted(t *testing.T) {
	pub := newPublication(t)
	pub.publish(t, testBundle(t, "v1", "a"), nil)
	f := &Local{Root: pub.root}
	for name, pointer := range map[string]string{
		"other path":      `{"version":"v1","bundle":"../../etc/passwd","signature":"bundles/v1/bundle.json.sig"}`,
		"other signature": `{"version":"v1","bundle":"bundles/v1/bundle.json","signature":"bundles/v2/bundle.json.sig"}`,
		"bad version":     `{"version":"../v1","bundle":"v1/bundle.json","signature":"v1/bundle.json.sig"}`,
		"not json":        `latest: v1`,
		"missing version": `{"version":"v9","bundle":"bundles/v9/bundle.json","signature":"bundles/v9/bundle.json.sig"}`,
	} {
		pub.overwrite(t, grant.LatestFile, []byte(pointer))
		if _, err := f.Fetch(context.Background(), false); err == nil {
			t.Errorf("%s: the pointer was followed", name)
		}
	}
	// A field this reader does not know is ignored, so that a later
	// additive change to the layout does not stop it; only the version is
	// trusted anyway.
	for name, pointer := range map[string]string{
		"well-formed":   `{"version":"v1","bundle":"bundles/v1/bundle.json","signature":"bundles/v1/bundle.json.sig"}`,
		"unknown field": `{"version":"v1","bundle":"bundles/v1/bundle.json","signature":"bundles/v1/bundle.json.sig","x":1}`,
	} {
		pub.overwrite(t, grant.LatestFile, []byte(pointer))
		if got, err := f.Fetch(context.Background(), false); err != nil || got.Version != "v1" {
			t.Errorf("%s pointer: %+v, %v", name, got, err)
		}
	}
}

func TestObjectSizeIsBounded(t *testing.T) {
	huge := bytes.Repeat([]byte("x"), maxObjectBytes+1)
	if _, err := readAll(bytes.NewReader(huge)); err == nil {
		t.Error("an oversized object was read")
	}
	if got, err := readAll(bytes.NewReader(huge[:maxObjectBytes])); err != nil || len(got) != maxObjectBytes {
		t.Errorf("an object at the limit: %d bytes, %v", len(got), err)
	}
}

// The S3 fetcher reads a version's assignments beside its bundle when
// asked, and fails when they are not there.
func TestS3FetcherAssignments(t *testing.T) {
	pub := newPublication(t)
	bundle, assignments := testBundle(t, "v1", "a"), testAssignments(t, "v1", "a")
	signer, _ := grant.NewLocalSigner(pub.key)
	bsig, _ := signer.Sign(context.Background(), bundle)
	asig, _ := signer.Sign(context.Background(), assignments)
	fake := &fakeS3{bucket: "grants", objects: map[string][]byte{}}
	if _, err := grant.NewS3Publisher(&fakePut{objects: fake.objects}, "grants", "p").Publish(context.Background(),
		grant.Publication{Bundle: bundle, BundleSignature: bsig, Assignments: assignments, AssignmentsSignature: asig}); err != nil {
		t.Fatal(err)
	}
	got, err := NewS3(fake, "grants", "p").Fetch(context.Background(), true)
	if err != nil || !bytes.Equal(got.Assignments, assignments) || len(got.AssignmentsSignature) == 0 {
		t.Fatalf("Fetch = %+v, %v", got, err)
	}
	if strings.Join(fake.keys, " ") != "p/latest p/bundles/v1/bundle.json p/bundles/v1/bundle.json.sig p/bundles/v1/assignments.json p/bundles/v1/assignments.json.sig" {
		t.Errorf("keys = %v", fake.keys)
	}
	delete(fake.objects, "p/bundles/v1/assignments.json")
	if _, err := NewS3(fake, "grants", "p").Fetch(context.Background(), true); err == nil || !strings.Contains(err.Error(), "publishes no readable assignments") {
		t.Errorf("Fetch without assignments = %v", err)
	}
	if _, err := NewS3(fake, "grants", "p").Fetch(context.Background(), false); err != nil {
		t.Errorf("Fetch of the bundle alone = %v", err)
	}
}
