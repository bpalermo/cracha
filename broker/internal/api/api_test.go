package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bpalermo/cracha/broker/internal/authn"
	"github.com/bpalermo/cracha/broker/internal/authn/authntest"
	"github.com/bpalermo/cracha/broker/internal/authz"
	"github.com/bpalermo/cracha/broker/internal/grants"
	"github.com/bpalermo/cracha/broker/internal/issuer"
	"github.com/bpalermo/cracha/broker/internal/sts"
	"github.com/bpalermo/cracha/common/idenc"
)

const (
	subject    = "spiffe://example.org/ns/payments/sa/ledger"
	dynamoRole = "arn:aws:iam::111122223333:role/broker/shape-dynamo-rw"
	s3Role     = "arn:aws:iam::111122223333:role/broker/shape-s3-reader"
)

type fakeStore struct {
	decisions map[string]authz.Decision // by subject ID
	err       error
}

func (f *fakeStore) ListGrants(_ context.Context, s authz.Subject, _ authz.Consistency) (authz.Decision, error) {
	if f.err != nil {
		return authz.Decision{}, f.err
	}
	d, ok := f.decisions[s.ID]
	if !ok {
		return authz.Decision{Token: "tok"}, nil
	}
	return d, nil
}

func (f *fakeStore) Check(context.Context, authz.Subject, string, authz.Consistency) (authz.CheckResult, error) {
	return authz.CheckResult{}, errors.New("not used")
}

type fakeSTS struct {
	calls int
	err   error
	exp   time.Time
}

func (f *fakeSTS) AssumeRole(_ context.Context, req sts.Request) (sts.Credentials, error) {
	f.calls++
	if f.err != nil {
		return sts.Credentials{}, f.err
	}
	return sts.Credentials{AccessKeyID: "AKIA" + req.SessionName, SecretAccessKey: "secret", SessionToken: "token", Expiration: f.exp}, nil
}

func grant(name, role string, policy string, envelope ...string) grants.ResolvedGrant {
	return grants.ResolvedGrant{
		Name: name, Account: "111122223333", BaseRole: role, SessionPolicy: policy,
		SessionTags: map[string]string{"team": "payments"}, DurationSeconds: 3600, Envelope: envelope,
	}
}

func policyFor(resource string) string {
	return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"dynamodb:GetItem","Resource":"` + resource + `"}]}`
}

type fixture struct {
	issuer  *authntest.Issuer
	store   *fakeStore
	sts     *fakeSTS
	handler http.Handler
	exp     time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ti := authntest.NewIssuer(t, "example.org")
	labels, err := idenc.NewLabels(map[string]string{"example.org": "prod"})
	if err != nil {
		t.Fatal(err)
	}
	envelope := "arn:aws:dynamodb:*:111122223333:table/payments-*"
	src := grants.NewStatic("bundle-3",
		grant("payments-ledger-rw", dynamoRole, policyFor("arn:aws:dynamodb:*:111122223333:table/payments-ledger"), envelope),
		grant("payments-outbox-r", dynamoRole, policyFor("arn:aws:dynamodb:*:111122223333:table/payments-outbox"), envelope),
		grant("s3-reader", s3Role, "", "arn:aws:s3:::payments-*"),
		grant("escaped", dynamoRole, policyFor("arn:aws:dynamodb:*:111122223333:table/billing"), envelope),
		grant("huge", dynamoRole, policyFor("arn:aws:dynamodb:*:111122223333:table/payments-"+strings.Repeat("x", 2100)), envelope),
	)
	store := &fakeStore{decisions: map[string]authz.Decision{
		"prod/payments/ledger":  {Grants: []string{"payments-ledger-rw", "payments-outbox-r"}, Tags: map[string]string{"service": "payments-api", "team": "payments"}, Token: "tok-9", Trace: []string{"ok"}},
		"prod/payments/mixed":   {Grants: []string{"payments-ledger-rw", "s3-reader"}, Token: "tok-9"},
		"prod/payments/escaped": {Grants: []string{"escaped"}, Token: "tok-9"},
		"prod/payments/huge":    {Grants: []string{"huge"}, Token: "tok-9"},
	}}
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	assumer := &fakeSTS{exp: exp}
	direct := &issuer.Direct{
		Store: store, Grants: src, STS: assumer, Labels: labels, Cluster: "prod-a",
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	h := New(authn.New(ti.Bundle(t)), direct, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return &fixture{issuer: ti, store: store, sts: assumer, handler: h, exp: exp}
}

func (f *fixture) get(t *testing.T, path, token string, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	return f.do(t, http.MethodGet, path, token, headers...)
}

func (f *fixture) do(t *testing.T, method, path, token string, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", token)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Add(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func reason(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct{ Reason string }
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}
	return body.Reason
}

func TestCredentials(t *testing.T) {
	f := newFixture(t)
	rec := f.get(t, "/v1/credentials", f.issuer.ValidToken(t, subject))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["AccessKeyId"] != "AKIAw.prod.payments.ledger" || body["SecretAccessKey"] != "secret" || body["Token"] != "token" {
		t.Errorf("body %v", body)
	}
	if body["Expiration"] != f.exp.Format(time.RFC3339) {
		t.Errorf("Expiration %q, want %q", body["Expiration"], f.exp.Format(time.RFC3339))
	}
	for k := range body {
		switch k {
		case "AccessKeyId", "SecretAccessKey", "Token", "Expiration":
		default:
			t.Errorf("unexpected field %q", k)
		}
	}
	h := rec.Header()
	if h.Get(HeaderShape) != "shape-dynamo-rw" || h.Get(HeaderGrants) != "payments-ledger-rw, payments-outbox-r" ||
		h.Get(HeaderBundleVersion) != "bundle-3" || h.Get(HeaderConsistencyToken) != "tok-9" {
		t.Errorf("headers %v", h)
	}
	if h.Get("Cache-Control") != "no-store" || !strings.HasPrefix(h.Get("Content-Type"), "application/json") {
		t.Errorf("headers %v", h)
	}
	if f.sts.calls != 1 {
		t.Errorf("sts calls %d", f.sts.calls)
	}

	// The same token with a Bearer prefix works too.
	if rec := f.get(t, "/v1/credentials", "Bearer "+f.issuer.ValidToken(t, subject)); rec.Code != http.StatusOK {
		t.Errorf("bearer: %d", rec.Code)
	}
}

func TestUnauthenticated(t *testing.T) {
	f := newFixture(t)
	other := authntest.NewIssuer(t, "example.org") // same trust domain, unknown key
	tests := []struct {
		name    string
		token   string
		headers []string
	}{
		{"no token", "", nil},
		{"garbage", "nope", nil},
		{"expired", f.issuer.Token(t, authntest.Claims{Subject: subject, Audience: []string{authn.Audience}, Expiry: time.Now().Add(-time.Minute)}), nil},
		{"wrong audience", f.issuer.Token(t, authntest.Claims{Subject: subject, Audience: []string{"other"}, Expiry: time.Now().Add(time.Minute)}), nil},
		{"unknown key", other.ValidToken(t, subject), nil},
		{"off-scheme subject", f.issuer.ValidToken(t, "spiffe://example.org/payments/ledger"), nil},
		{"proxy headers are not identity", "", []string{"X-Forwarded-Client-Cert", "By=spiffe://example.org/ns/payments/sa/ledger", "X-Spiffe-Id", subject, "X-Forwarded-For", "10.0.0.1"}},
		{"two authorization headers", f.issuer.ValidToken(t, subject), []string{"Authorization", f.issuer.ValidToken(t, subject)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, path := range []string{"/v1/credentials", "/v1/grants"} {
				rec := f.get(t, path, tt.token, tt.headers...)
				if rec.Code != http.StatusUnauthorized {
					t.Errorf("%s: status %d, want 401: %s", path, rec.Code, rec.Body.String())
				}
				if r := reason(t, rec); r != ReasonUnauthenticated {
					t.Errorf("%s: reason %q", path, r)
				}
			}
		})
	}
	if f.sts.calls != 0 {
		t.Errorf("sts called %d times without authentication", f.sts.calls)
	}
}

func TestForbidden(t *testing.T) {
	f := newFixture(t)
	tests := []struct {
		name   string
		sa     string
		reason string
	}{
		{"no_grant", "nobody", "no_grant"},
		{"ambiguous", "mixed", "ambiguous"},
		{"envelope_violation", "escaped", "envelope_violation"},
		{"policy_too_large", "huge", "policy_too_large"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := f.issuer.ValidToken(t, "spiffe://example.org/ns/payments/sa/"+tt.sa)
			for _, path := range []string{"/v1/credentials", "/v1/grants"} {
				rec := f.get(t, path, token)
				if rec.Code != http.StatusForbidden {
					t.Errorf("%s: status %d: %s", path, rec.Code, rec.Body.String())
				}
				if r := reason(t, rec); r != tt.reason {
					t.Errorf("%s: reason %q, want %q", path, r, tt.reason)
				}
			}
		})
	}
	t.Run("subject_suspended", func(t *testing.T) {
		f.store.err = authz.ErrSubjectSuspended
		defer func() { f.store.err = nil }()
		rec := f.get(t, "/v1/credentials", f.issuer.ValidToken(t, subject))
		if rec.Code != http.StatusForbidden || reason(t, rec) != "subject_suspended" {
			t.Errorf("status %d: %s", rec.Code, rec.Body.String())
		}
	})
	if f.sts.calls != 0 {
		t.Errorf("sts called %d times on denials", f.sts.calls)
	}
}

func TestUnavailable(t *testing.T) {
	f := newFixture(t)
	f.store.err = errors.New("store down")
	rec := f.get(t, "/v1/credentials", f.issuer.ValidToken(t, subject))
	if rec.Code != http.StatusServiceUnavailable || reason(t, rec) != ReasonUnavailable {
		t.Errorf("store down: status %d: %s", rec.Code, rec.Body.String())
	}
	if f.sts.calls != 0 {
		t.Error("sts called while the store was down")
	}
	f.store.err = nil
	f.sts.err = errors.New("throttled")
	rec = f.get(t, "/v1/credentials", f.issuer.ValidToken(t, subject))
	if rec.Code != http.StatusServiceUnavailable || reason(t, rec) != ReasonUnavailable {
		t.Errorf("sts down: status %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "throttled") {
		t.Error("internal error leaked to the caller")
	}
}

func TestGrants(t *testing.T) {
	f := newFixture(t)
	rec := f.get(t, "/v1/grants", f.issuer.ValidToken(t, subject))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		SPIFFEID          string            `json:"spiffeId"`
		SourceIdentity    string            `json:"sourceIdentity"`
		Subject           string            `json:"subject"`
		Cluster           string            `json:"cluster"`
		Shape             string            `json:"shape"`
		BaseRole          string            `json:"baseRole"`
		Grants            []string          `json:"grants"`
		SessionPolicy     map[string]any    `json:"sessionPolicy"`
		ManagedPolicyARNs []string          `json:"managedPolicyArns"`
		SessionTags       map[string]string `json:"sessionTags"`
		DurationSeconds   int32             `json:"durationSeconds"`
		BundleVersion     string            `json:"bundleVersion"`
		ConsistencyToken  string            `json:"consistencyToken"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("%s: %v", rec.Body.String(), err)
	}
	if body.SPIFFEID != subject || body.SourceIdentity != "w.prod.payments.ledger" || body.Subject != "prod/payments/ledger" || body.Cluster != "prod-a" {
		t.Errorf("identity fields %+v", body)
	}
	if body.Shape != "shape-dynamo-rw" || body.BaseRole != dynamoRole || len(body.Grants) != 2 || body.DurationSeconds != 3600 {
		t.Errorf("composition %+v", body)
	}
	if stmts, _ := body.SessionPolicy["Statement"].([]any); len(stmts) != 2 {
		t.Errorf("policy %v", body.SessionPolicy)
	}
	if body.ManagedPolicyARNs == nil || body.SessionTags["service"] != "payments-api" || body.SessionTags["spiffe-sa"] != "ledger" {
		t.Errorf("tags %+v managed %v", body.SessionTags, body.ManagedPolicyARNs)
	}
	if body.BundleVersion != "bundle-3" || body.ConsistencyToken != "tok-9" {
		t.Errorf("versions %+v", body)
	}
	if rec.Header().Get(HeaderShape) != "shape-dynamo-rw" || rec.Header().Get(HeaderGrants) == "" {
		t.Errorf("headers %v", rec.Header())
	}
	if f.sts.calls != 0 {
		t.Error("/v1/grants called STS")
	}
}

func TestMethodsAndPaths(t *testing.T) {
	f := newFixture(t)
	token := f.issuer.ValidToken(t, subject)
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodHead} {
		for _, path := range []string{"/v1/credentials", "/v1/grants"} {
			rec := f.do(t, method, path, token)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s: status %d", method, path, rec.Code)
			}
		}
	}
	if rec := f.get(t, "/v1/other", token); rec.Code != http.StatusNotFound {
		t.Errorf("unknown path: %d", rec.Code)
	}
	if rec := f.get(t, "/healthz", ""); rec.Code != http.StatusOK {
		t.Errorf("healthz: %d", rec.Code)
	}
	if f.sts.calls != 0 {
		t.Error("sts called")
	}
}
