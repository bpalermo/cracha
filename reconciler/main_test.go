package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bpalermo/cracha/common/spicedb"
	"github.com/bpalermo/cracha/reconciler/internal/fakespicedb"
)

// fakeDial hands every command the same fake, recording the flags it was
// given.
func fakeDial(c *fakespicedb.Client) (dialer, *connFlags) {
	var got connFlags
	return func(_ context.Context, f *connFlags) (*clients, error) {
		got = *f
		return &clients{permissions: c, schema: c, close: func() error { return nil }}, nil
	}, &got
}

// noDial fails the test when a command connects.
func noDial(t *testing.T) dialer {
	return func(context.Context, *connFlags) (*clients, error) {
		t.Error("the command connected to SpiceDB")
		return nil, errors.New("no connection")
	}
}

func writeToken(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunUsage(t *testing.T) {
	tests := []struct {
		name string
		args []string
		code int
		want string // in stdout or stderr
	}{
		{"no command", nil, 2, "usage:"},
		{"unknown", []string{"nope"}, 2, `unknown command "nope"`},
		{"help", []string{"help"}, 0, "usage:"},
		{"version", []string{"--version"}, 0, "cracha-reconciler "},
		{"schema help", []string{"schema", "-h"}, 0, "-token-file"},
		{"schema argument", []string{"schema", "x"}, 2, "takes no arguments"},
		{"schema no flags", []string{"schema"}, 2, "-endpoint and -token-file are required"},
		{"apply no source", []string{"apply", "-endpoint", "e", "-token-file", "t"}, 2, "-source is required"},
		{"apply no endpoint", []string{"apply", "-source", "testdata/good"}, 2, "-endpoint and -token-file are required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(tt.args, &stdout, &stderr, noDial(t)); code != tt.code {
				t.Errorf("exit %d, want %d; stderr: %s", code, tt.code, stderr.String())
			}
			if out := stdout.String() + stderr.String(); !strings.Contains(out, tt.want) {
				t.Errorf("output %q does not contain %q", out, tt.want)
			}
		})
	}
}

func TestSchemaDryRunPrints(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"schema", "-dry-run"}, &stdout, &stderr, noDial(t)); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if stdout.String() != spicedb.Schema {
		t.Errorf("stdout = %q, want the schema", stdout.String())
	}
}

func TestSchemaWrites(t *testing.T) {
	c := fakespicedb.New()
	dial, flags := fakeDial(c)
	var stdout, stderr bytes.Buffer
	args := []string{"schema", "-endpoint", "localhost:50051", "-token-file", "t", "-ca", "ca.pem", "-insecure"}
	if code := run(args, &stdout, &stderr, dial); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if c.SchemaWrites != 1 || c.Schema != spicedb.Schema {
		t.Errorf("schema writes = %d", c.SchemaWrites)
	}
	if flags.endpoint != "localhost:50051" || flags.tokenFile != "t" || flags.ca != "ca.pem" || !flags.insecure {
		t.Errorf("flags = %+v", *flags)
	}
	if !strings.Contains(stdout.String(), "wrote the schema to localhost:50051") {
		t.Errorf("stdout = %q", stdout.String())
	}
}

func TestApplyRejectedTree(t *testing.T) {
	for _, source := range []string{"testdata/rejected", "testdata/missing"} {
		var stdout, stderr bytes.Buffer
		args := []string{"apply", "-source", source, "-endpoint", "e", "-token-file", "t"}
		if code := run(args, &stdout, &stderr, noDial(t)); code != 1 {
			t.Errorf("%s: exit %d, want 1; stderr: %s", source, code, stderr.String())
		}
		if !strings.Contains(stderr.String(), "source tree rejected") {
			t.Errorf("%s: stderr = %q", source, stderr.String())
		}
	}
}

func TestApply(t *testing.T) {
	c := fakespicedb.New()
	dial, _ := fakeDial(c)
	args := []string{"apply", "-source", "testdata/good", "-endpoint", "e", "-token-file", "t"}

	var stdout, stderr bytes.Buffer
	if code := run(append(args, "-dry-run"), &stdout, &stderr, dial); code != 0 {
		t.Fatalf("dry run: exit %d: %s", code, stderr.String())
	}
	if len(c.Writes) != 0 || len(c.Relationships()) != 0 || !strings.Contains(stdout.String(), "dry run: 7 relationships to write and 0 to delete; nothing written") {
		t.Errorf("dry run: writes = %d, stdout = %q", len(c.Writes), stdout.String())
	}
	if !strings.Contains(stderr.String(), "msg=touch relationship=grant:ledger-r#assignee_service@service:payments-api") {
		t.Errorf("dry run: stderr does not log the diff: %q", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run(args, &stdout, &stderr, dial); code != 0 {
		t.Fatalf("apply: exit %d: %s", code, stderr.String())
	}
	if len(c.Writes) != 1 || len(c.Relationships()) != 7 || !strings.Contains(stdout.String(), "wrote 7 of 7 updates (7 to write, 0 to delete) in 1 batches, at rev-1") {
		t.Errorf("apply: writes = %d, held = %d, stdout = %q", len(c.Writes), len(c.Relationships()), stdout.String())
	}

	stdout.Reset()
	if code := run(args, &stdout, &stderr, dial); code != 0 {
		t.Fatalf("second apply: exit %d: %s", code, stderr.String())
	}
	if len(c.Writes) != 1 || !strings.Contains(stdout.String(), "nothing to change") {
		t.Errorf("second apply: writes = %d, stdout = %q", len(c.Writes), stdout.String())
	}
}

func TestApplyWriteFails(t *testing.T) {
	c := fakespicedb.New()
	c.FailWrite = 1
	dial, _ := fakeDial(c)
	var stdout, stderr bytes.Buffer
	args := []string{"apply", "-source", "testdata/good", "-endpoint", "e", "-token-file", "t"}
	if code := run(args, &stdout, &stderr, dial); code != 2 {
		t.Errorf("exit %d, want 2", code)
	}
	if !strings.Contains(stdout.String(), "wrote 0 of 7 updates") || !strings.Contains(stderr.String(), "write batch 1 (7 updates) failed after 0 of 7") {
		t.Errorf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

func TestDial(t *testing.T) {
	token := writeToken(t)
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, []byte(" \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	notPEM := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		flags connFlags
		want  string // error substring; empty for success
	}{
		{"insecure", connFlags{endpoint: "localhost:1", tokenFile: token, insecure: true}, ""},
		{"tls with system roots", connFlags{endpoint: "localhost:1", tokenFile: token}, ""},
		{"missing token", connFlags{endpoint: "localhost:1", tokenFile: filepath.Join(t.TempDir(), "none")}, "token file"},
		{"empty token", connFlags{endpoint: "localhost:1", tokenFile: empty}, "is empty"},
		{"missing ca", connFlags{endpoint: "localhost:1", tokenFile: token, ca: filepath.Join(t.TempDir(), "none")}, "ca:"},
		{"ca not pem", connFlags{endpoint: "localhost:1", tokenFile: token, ca: notPEM}, "no certificate in"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := dial(context.Background(), &tt.flags)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("dial: %v", err)
				}
				if err := c.close(); err != nil {
					t.Errorf("close: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestBearer(t *testing.T) {
	b := bearer{token: "secret"}
	md, err := b.GetRequestMetadata(context.Background())
	if err != nil || md["authorization"] != "Bearer secret" {
		t.Errorf("metadata = %v, %v", md, err)
	}
	if !b.RequireTransportSecurity() || (bearer{plaintext: true}).RequireTransportSecurity() {
		t.Error("the key is sent in clear without -insecure, or refused with it")
	}
}
