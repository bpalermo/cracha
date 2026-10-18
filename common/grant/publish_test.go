package grant

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func signedBundle(t *testing.T) ([]byte, *Signature) {
	t.Helper()
	_, data := compileGood(t, "abc123")
	signer, err := NewLocalSigner(mustKey(t))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.Sign(context.Background(), data)
	if err != nil {
		t.Fatal(err)
	}
	return data, sig
}

// signedVersion is the good tree's bundle and assignments, version abc123,
// each signed.
func signedVersion(t *testing.T) Publication {
	t.Helper()
	c := compileGoodAll(t, "abc123")
	signer, err := NewLocalSigner(mustKey(t))
	if err != nil {
		t.Fatal(err)
	}
	var pub Publication
	if pub.Bundle, err = Marshal(c.Bundle); err != nil {
		t.Fatal(err)
	}
	if pub.Assignments, err = MarshalAssignments(c.Assignments); err != nil {
		t.Fatal(err)
	}
	if pub.BundleSignature, err = signer.Sign(context.Background(), pub.Bundle); err != nil {
		t.Fatal(err)
	}
	if pub.AssignmentsSignature, err = signer.Sign(context.Background(), pub.Assignments); err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestPublishWithAssignments(t *testing.T) {
	pub := signedVersion(t)
	root := t.TempDir()
	res, err := (&LocalPublisher{Root: root}).Publish(context.Background(), pub)
	if err != nil {
		t.Fatal(err)
	}
	if res.Assignments != "bundles/abc123/assignments.json" || res.AssignmentsSignature != "bundles/abc123/assignments.json.sig" {
		t.Errorf("result = %+v", res)
	}
	got, err := os.ReadFile(filepath.Join(root, "bundles", "abc123", "assignments.json"))
	if err != nil || string(got) != string(pub.Assignments) {
		t.Errorf("published assignments = %q, %v", got, err)
	}
	sigData, err := os.ReadFile(filepath.Join(root, "bundles", "abc123", "assignments.json.sig"))
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := ParseSignature(sigData); err != nil || parsed.Digest != Digest(pub.Assignments) {
		t.Errorf("published assignments signature = %+v, %v", parsed, err)
	}
	// The pointer is unchanged by the assignments: a reader that predates
	// them decodes it as before.
	latestData, _ := os.ReadFile(filepath.Join(root, "latest"))
	if strings.Contains(string(latestData), "assignments") {
		t.Errorf("latest names the assignments: %s", latestData)
	}

	api := &fakeS3{}
	if _, err := NewS3Publisher(api, "bucket", "p").Publish(context.Background(), pub); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, put := range api.puts {
		keys = append(keys, aws.ToString(put.Key))
	}
	if got, want := strings.Join(keys, " "), "p/bundles/abc123/bundle.json p/bundles/abc123/bundle.json.sig p/bundles/abc123/assignments.json p/bundles/abc123/assignments.json.sig p/latest"; got != want {
		t.Errorf("keys = %s, want %s", got, want)
	}
}

func TestPublishRejectsAssignments(t *testing.T) {
	ctx := context.Background()
	p := &LocalPublisher{Root: t.TempDir()}
	pub := signedVersion(t)
	noSig := pub
	noSig.AssignmentsSignature = nil
	if _, err := p.Publish(ctx, noSig); err == nil || !strings.Contains(err.Error(), "assignments: no signature") {
		t.Errorf("error = %v", err)
	}
	swapped := pub
	swapped.AssignmentsSignature = pub.BundleSignature
	if _, err := p.Publish(ctx, swapped); err == nil || !strings.Contains(err.Error(), "assignments: signature digest") {
		t.Errorf("error = %v", err)
	}
	other := pub
	other.Assignments = []byte(strings.Replace(string(pub.Assignments), `"version": "abc123"`, `"version": "def456"`, 1))
	if _, err := p.Publish(ctx, other); err == nil || !strings.Contains(err.Error(), `assignments are version "def456"`) {
		t.Errorf("error = %v", err)
	}
	if _, err := p.Publish(ctx, Publication{Bundle: pub.Bundle, BundleSignature: pub.BundleSignature, Assignments: []byte("junk"), AssignmentsSignature: pub.AssignmentsSignature}); err == nil || !strings.Contains(err.Error(), "assignments:") {
		t.Errorf("error = %v", err)
	}
}

func TestParseLatestIgnoresUnknownFields(t *testing.T) {
	l, err := ParseLatest([]byte(`{"version":"v1","bundle":"bundles/v1/bundle.json","signature":"bundles/v1/bundle.json.sig","later":"x"}`))
	if err != nil || l.Version != "v1" {
		t.Errorf("ParseLatest = %+v, %v", l, err)
	}
	if _, err := ParseLatest([]byte(`{"version":"v1"} {}`)); err == nil {
		t.Error("ParseLatest accepted trailing data")
	}
}

func TestLocalPublisher(t *testing.T) {
	bundle, sig := signedBundle(t)
	root := t.TempDir()
	p := &LocalPublisher{Root: root}
	res, err := p.Publish(context.Background(), Publication{Bundle: bundle, BundleSignature: sig})
	if err != nil {
		t.Fatal(err)
	}
	if res.Version != "abc123" || res.Bundle != "bundles/abc123/bundle.json" || res.Signature != "bundles/abc123/bundle.json.sig" || res.Latest != "latest" {
		t.Errorf("result = %+v", res)
	}
	got, err := os.ReadFile(filepath.Join(root, "bundles", "abc123", "bundle.json"))
	if err != nil || string(got) != string(bundle) {
		t.Errorf("published bundle = %q, %v", got, err)
	}
	sigData, err := os.ReadFile(filepath.Join(root, "bundles", "abc123", "bundle.json.sig"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSignature(sigData)
	if err != nil || parsed.Signature != sig.Signature {
		t.Errorf("published signature = %+v, %v", parsed, err)
	}
	latestData, err := os.ReadFile(filepath.Join(root, "latest"))
	if err != nil {
		t.Fatal(err)
	}
	var latest Latest
	if err := json.Unmarshal(latestData, &latest); err != nil {
		t.Fatal(err)
	}
	if latest.Version != "abc123" || latest.Bundle != res.Bundle || latest.Signature != res.Signature {
		t.Errorf("latest = %+v", latest)
	}
	entries, _ := os.ReadDir(filepath.Join(root, "bundles", "abc123"))
	if len(entries) != 2 {
		t.Errorf("temporary files left behind: %v", entries)
	}

	// Publishing again, another version, moves the pointer and keeps the
	// old version.
	bundle2 := []byte(strings.Replace(string(bundle), `"version": "abc123"`, `"version": "def456"`, 1))
	signer, _ := NewLocalSigner(mustKey(t))
	sig2, _ := signer.Sign(context.Background(), bundle2)
	if _, err := p.Publish(context.Background(), Publication{Bundle: bundle2, BundleSignature: sig2}); err != nil {
		t.Fatal(err)
	}
	latestData, _ = os.ReadFile(filepath.Join(root, "latest"))
	if !strings.Contains(string(latestData), `"version": "def456"`) {
		t.Errorf("latest = %s", latestData)
	}
	if _, err := os.Stat(filepath.Join(root, "bundles", "abc123", "bundle.json")); err != nil {
		t.Errorf("old version gone: %v", err)
	}
}

func TestPublishRejects(t *testing.T) {
	bundle, sig := signedBundle(t)
	p := &LocalPublisher{Root: t.TempDir()}
	ctx := context.Background()
	if _, err := p.Publish(ctx, Publication{Bundle: bundle, BundleSignature: nil}); err == nil || !strings.Contains(err.Error(), "no signature") {
		t.Errorf("error = %v", err)
	}
	if _, err := p.Publish(ctx, Publication{Bundle: []byte("junk"), BundleSignature: sig}); err == nil || !strings.Contains(err.Error(), "bundle:") {
		t.Errorf("error = %v", err)
	}
	if _, err := p.Publish(ctx, Publication{Bundle: []byte(`{"version":"x","generatedAt":"t","grants":[]}`), BundleSignature: sig}); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Errorf("error = %v", err)
	}
}

type fakeS3 struct {
	puts []*s3.PutObjectInput
	body map[string][]byte
	err  error
}

func (f *fakeS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.puts = append(f.puts, in)
	data, err := io.ReadAll(in.Body)
	if err != nil {
		return nil, err
	}
	if f.body == nil {
		f.body = map[string][]byte{}
	}
	f.body[aws.ToString(in.Key)] = data
	return &s3.PutObjectOutput{}, nil
}

func TestS3Publisher(t *testing.T) {
	bundle, sig := signedBundle(t)
	api := &fakeS3{}
	p := NewS3Publisher(api, "bucket", "/cracha/prod/")
	res, err := p.Publish(context.Background(), Publication{Bundle: bundle, BundleSignature: sig})
	if err != nil {
		t.Fatal(err)
	}
	if res.Version != "abc123" {
		t.Errorf("result = %+v", res)
	}
	var keys []string
	for _, put := range api.puts {
		keys = append(keys, aws.ToString(put.Key))
		if aws.ToString(put.Bucket) != "bucket" || aws.ToString(put.ContentType) != "application/json" || put.ChecksumAlgorithm != s3types.ChecksumAlgorithmSha256 {
			t.Errorf("put = %+v", put)
		}
	}
	// The pointer is written last.
	if got, want := strings.Join(keys, " "), "cracha/prod/bundles/abc123/bundle.json cracha/prod/bundles/abc123/bundle.json.sig cracha/prod/latest"; got != want {
		t.Errorf("keys = %s, want %s", got, want)
	}
	if string(api.body["cracha/prod/bundles/abc123/bundle.json"]) != string(bundle) {
		t.Error("bundle body differs")
	}
	var latest Latest
	if err := json.Unmarshal(api.body["cracha/prod/latest"], &latest); err != nil || latest.Bundle != "bundles/abc123/bundle.json" {
		t.Errorf("latest = %+v, %v", latest, err)
	}

	noPrefix := NewS3Publisher(&fakeS3{}, "bucket", "")
	if _, err := noPrefix.Publish(context.Background(), Publication{Bundle: bundle, BundleSignature: sig}); err != nil {
		t.Fatal(err)
	}

	failing := NewS3Publisher(&fakeS3{err: errors.New("AccessDenied")}, "bucket", "p")
	if _, err := failing.Publish(context.Background(), Publication{Bundle: bundle, BundleSignature: sig}); err == nil || !strings.Contains(err.Error(), "s3 PutObject p/bundles/abc123/bundle.json: AccessDenied") {
		t.Errorf("error = %v", err)
	}
}
