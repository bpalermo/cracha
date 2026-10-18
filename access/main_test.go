package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bpalermo/cracha/access/internal/api"
)

func noEnv(string) (string, bool) { return "", false }

func envOf(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

var serveArgs = []string{
	"--spicedb-endpoint", "cracha-spicedb:50051", "--spicedb-spiffe-id", "spiffe://example.org/ns/cracha/sa/cracha-spicedb",
	"--bundle-source", "s3://grants/prod", "--bundle-verify-key", "/k/a.pem,/k/b.pem",
}

func TestParseServe(t *testing.T) {
	c, err := parseServe(append(serveArgs, "--max-expiry", "s3_bucket=720h,service=24h"), noEnv, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if c.bundle.Bucket != "grants" || len(c.verifyKeys()) != 2 || c.maxByKind["s3_bucket"] != 720*time.Hour || c.maxByKind["service"] != 24*time.Hour ||
		c.breakGlassMax != 4*time.Hour || !c.watchAudit || c.accessAnalyzer || c.spicedb.id.String() != "spiffe://example.org/ns/cracha/sa/cracha-spicedb" {
		t.Errorf("config = %+v", c)
	}
	env := envOf(map[string]string{
		"CRACHA_SPICEDB_ENDPOINT": "x:1", "CRACHA_SPICEDB_SPIFFE_ID": "spiffe://example.org/x", "CRACHA_BUNDLE_SOURCE": "local:/b",
		"CRACHA_BUNDLE_KMS_KEY": "alias/k", "CRACHA_ACCESS_ANALYZER": "true", "CRACHA_BREAK_GLASS_MAX": "1h",
	})
	c, err = parseServe(nil, env, &bytes.Buffer{})
	if err != nil || !c.accessAnalyzer || c.breakGlassMax != time.Hour || c.bundle.Dir != "/b" || c.bundleKMSKey != "alias/k" {
		t.Errorf("from the environment: %+v, %v", c, err)
	}
	for name, extra := range map[string][]string{
		"both keys":      {"--bundle-kms-key", "k"},
		"unknown kind":   {"--max-expiry", "queue=1h"},
		"bad duration":   {"--max-expiry", "s3_bucket=soon"},
		"bad source":     {"--bundle-source", "/tmp"},
		"bad spicedb id": {"--spicedb-spiffe-id", "nope"},
		"bad labels":     {"--trust-domain-labels", "x"},
		"zero cap":       {"--break-glass-max", "0s"},
		"stray argument": {"extra"},
	} {
		if _, err := parseServe(append(append([]string{}, serveArgs...), extra...), noEnv, &bytes.Buffer{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := parseServe(nil, noEnv, &bytes.Buffer{}); err == nil {
		t.Error("no SpiceDB accepted")
	}
}

// fake records the request the CLI built.
type fake struct {
	accessAPI
	got any
	err error
}

func (f *fake) Grant(_ context.Context, r *api.GrantRequest) (*api.WriteResponse, error) {
	f.got = r
	return &api.WriteResponse{Status: api.StatusApplied}, f.err
}

func (f *fake) Revoke(_ context.Context, r *api.RevokeRequest) (*api.WriteResponse, error) {
	f.got = r
	return &api.WriteResponse{Status: api.StatusRevoked}, f.err
}

func (f *fake) Approve(_ context.Context, r *api.DecideRequest) (*api.WriteResponse, error) {
	f.got = r
	return &api.WriteResponse{Status: api.StatusApplied}, f.err
}

func (f *fake) Reject(_ context.Context, r *api.DecideRequest) (*api.WriteResponse, error) {
	f.got = r
	return &api.WriteResponse{Status: api.StatusRejected}, f.err
}

func (f *fake) List(_ context.Context, r *api.ListRequest) (*api.ListResponse, error) {
	f.got = r
	return &api.ListResponse{}, f.err
}

func (f *fake) Explain(_ context.Context, r *api.ExplainRequest) (*api.ExplainResponse, error) {
	f.got = r
	return &api.ExplainResponse{}, f.err
}

func (f *fake) Pending(_ context.Context, r *api.PendingRequest) (*api.PendingResponse, error) {
	f.got = r
	return &api.PendingResponse{}, f.err
}

func withFake(t *testing.T, f *fake) {
	t.Helper()
	old := dial
	dial = func(context.Context, connFlags) (accessAPI, func(), error) { return f, func() {}, nil }
	t.Cleanup(func() { dial = old })
}

func TestCLI(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{
			[]string{
				"grant", "--subject", "prod/a/b", "--resource", "s3_bucket:data-a", "--relation", "reader", "--expires-at", "2026-12-31T00:00:00Z",
				"--clusters", "a, b", "--reason", "r", "--break-glass",
			},
			`{"subject":"prod/a/b","resource":{"kind":"s3_bucket","name":"data-a"},"relation":"reader","expiresAt":"2026-12-31T00:00:00Z","clusters":["a","b"],"reason":"r","requester":"alice","breakGlass":true}`,
		},
		{
			[]string{"revoke", "--service", "payments", "--resource", "dynamodb_table:orders", "--relation", "writer", "--reason", "r"},
			`{"service":"payments","resource":{"kind":"dynamodb_table","name":"orders"},"relation":"writer","reason":"r","requester":"alice"}`,
		},
		{[]string{"approve", "--reason", "ok", "abc"}, `{"id":"abc","reason":"ok","requester":"alice"}`},
		{[]string{"reject", "--id", "abc", "--reason", "no"}, `{"id":"abc","reason":"no","requester":"alice"}`},
		{[]string{"list", "--resource", "service:payments"}, `{"resource":{"kind":"service","name":"payments"}}`},
		{[]string{"explain", "--subject", "prod/a/b", "--cluster", "c"}, `{"subject":"prod/a/b","cluster":"c"}`},
		{[]string{"pending"}, `{}`},
	}
	for _, tt := range tests {
		f := &fake{}
		withFake(t, f)
		var out, errOut bytes.Buffer
		if code := run(context.Background(), tt.args, envOf(map[string]string{"CRACHA_REQUESTER": "alice"}), &out, &errOut); code != 0 {
			t.Errorf("%v: exit %d: %s", tt.args, code, errOut.String())
			continue
		}
		got, _ := json.Marshal(f.got)
		if string(got) != tt.want {
			t.Errorf("%s request = %s\nwant %s", tt.args[0], got, tt.want)
		}
		if !json.Valid(out.Bytes()) {
			t.Errorf("%s printed %q", tt.args[0], out.String())
		}
	}
}

func TestCLIErrors(t *testing.T) {
	f := &fake{err: &api.CallError{Reason: "not_authorized", Err: errors.New("rpc error: code = PermissionDenied desc = not_authorized: no")}}
	withFake(t, f)
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"grant", "--resource", "s3_bucket:x", "--subject", "a/b/c", "--relation", "reader", "--reason", "r"}, noEnv, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "not_authorized") {
		t.Errorf("exit %d: %s", code, errOut.String())
	}
	if code := run(context.Background(), []string{"grant", "--resource", "nokind"}, noEnv, &out, &errOut); code != 2 {
		t.Errorf("bad resource: exit %d", code)
	}
	if code := run(context.Background(), []string{"frobnicate"}, noEnv, &out, &errOut); code != 2 {
		t.Errorf("unknown command: exit %d", code)
	}
	if code := run(context.Background(), nil, noEnv, &out, &errOut); code != 2 {
		t.Errorf("no command: exit %d", code)
	}
	out.Reset()
	if code := run(context.Background(), []string{"version"}, noEnv, &out, &errOut); code != 0 || !strings.HasPrefix(out.String(), "cracha-access ") {
		t.Errorf("version: %d %q", code, out.String())
	}
}

func TestDialNeedsServer(t *testing.T) {
	if _, _, err := dial(context.Background(), connFlags{}); err == nil {
		t.Error("dialed nothing")
	}
	if _, _, err := dial(context.Background(), connFlags{server: "x:1", serverID: "nope"}); err == nil {
		t.Error("dialed a bad SPIFFE ID")
	}
}
