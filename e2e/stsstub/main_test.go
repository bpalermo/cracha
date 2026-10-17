package main

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// post sends an STS query-protocol request to the stub.
func post(t *testing.T, h http.Handler, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func assumeRoleForm() url.Values {
	return url.Values{
		"Action":                     {"AssumeRole"},
		"Version":                    {"2011-06-15"},
		"RoleArn":                    {"arn:aws:iam::123456789012:role/team/web"},
		"RoleSessionName":            {"web-1"},
		"SourceIdentity":             {"spiffe://example.org/ns/team-a/sa/web"},
		"Policy":                     {`{"Version":"2012-10-17","Statement":[]}`},
		"DurationSeconds":            {"900"},
		"PolicyArns.member.1.arn":    {"arn:aws:iam::123456789012:policy/a"},
		"PolicyArns.member.2.arn":    {"arn:aws:iam::123456789012:policy/b"},
		"Tags.member.1.Key":          {"ns"},
		"Tags.member.1.Value":        {"team-a"},
		"Tags.member.2.Key":          {"sa"},
		"Tags.member.2.Value":        {"web"},
		"TransitiveTagKeys.member.1": {"ns"},
	}
}

func TestAssumeRole(t *testing.T) {
	h := newStub().handler()
	before := time.Now().UTC()

	w := post(t, h, assumeRoleForm())
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/xml" {
		t.Errorf("Content-Type %q, want text/xml", ct)
	}
	if !strings.HasPrefix(w.Body.String(), xml.Header) {
		t.Errorf("body does not start with the XML header: %s", w.Body)
	}
	var resp AssumeRoleResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding the response: %v\n%s", err, w.Body)
	}
	creds := resp.Result.Credentials
	if creds.AccessKeyID != AccessKeyID || creds.SecretAccessKey != SecretAccessKey || creds.SessionToken != SessionToken+"-1" {
		t.Errorf("credentials %+v", creds)
	}
	expiry, err := time.Parse(time.RFC3339, creds.Expiration)
	if err != nil {
		t.Fatalf("Expiration %q: %v", creds.Expiration, err)
	}
	if lifetime := expiry.Sub(before.Truncate(time.Second)); lifetime < 900*time.Second || lifetime > 901*time.Second {
		t.Errorf("Expiration %s is %s after the request, want DurationSeconds (900s)", creds.Expiration, lifetime)
	}
	if got, want := resp.Result.AssumedRoleUser.Arn, "arn:aws:sts::123456789012:assumed-role/web/web-1"; got != want {
		t.Errorf("AssumedRoleUser.Arn %q, want %q", got, want)
	}
	if got, want := resp.Result.AssumedRoleUser.AssumedRoleID, "AROACRACHAE2ESTUB000:web-1"; got != want {
		t.Errorf("AssumedRoleId %q, want %q", got, want)
	}
	if resp.Result.SourceIdentity != "spiffe://example.org/ns/team-a/sa/web" {
		t.Errorf("SourceIdentity %q", resp.Result.SourceIdentity)
	}
	if resp.ResponseMetadata.RequestID != "stub-1" {
		t.Errorf("RequestId %q, want stub-1", resp.ResponseMetadata.RequestID)
	}

	// The second call is numbered 2.
	w = post(t, h, assumeRoleForm())
	if !strings.Contains(w.Body.String(), "<SessionToken>"+SessionToken+"-2</SessionToken>") {
		t.Errorf("second response does not carry session token 2: %s", w.Body)
	}
}

func TestRecording(t *testing.T) {
	h := newStub().handler()
	post(t, h, assumeRoleForm())

	list := func() []Request {
		t.Helper()
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/requests", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("GET /requests: %d", w.Code)
		}
		if ct := w.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("GET /requests Content-Type %q, want application/json", ct)
		}
		var out []Request
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decoding GET /requests: %v\n%s", err, w.Body)
		}
		return out
	}

	got := list()
	if len(got) != 1 {
		t.Fatalf("recorded %d requests, want 1", len(got))
	}
	want := Request{
		Received:          got[0].Received,
		Action:            "AssumeRole",
		RoleArn:           "arn:aws:iam::123456789012:role/team/web",
		RoleSessionName:   "web-1",
		SourceIdentity:    "spiffe://example.org/ns/team-a/sa/web",
		Policy:            `{"Version":"2012-10-17","Statement":[]}`,
		PolicyArns:        []string{"arn:aws:iam::123456789012:policy/a", "arn:aws:iam::123456789012:policy/b"},
		DurationSeconds:   900,
		Tags:              map[string]string{"ns": "team-a", "sa": "web"},
		TransitiveTagKeys: []string{"ns"},
		Form:              got[0].Form,
	}
	if gotJSON, wantJSON := toJSON(t, got[0]), toJSON(t, want); gotJSON != wantJSON {
		t.Errorf("recorded request:\n%s\nwant:\n%s", gotJSON, wantJSON)
	}
	if got[0].Form["Version"] != "2011-06-15" {
		t.Errorf("the form is not recorded whole: %v", got[0].Form)
	}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/requests", nil))
	if w.Code != http.StatusNoContent {
		t.Errorf("DELETE /requests: %d, want 204", w.Code)
	}
	if got := list(); len(got) != 0 {
		t.Errorf("after the reset %d requests are recorded, want none", len(got))
	}
}

func toJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestRefusals(t *testing.T) {
	cases := []struct {
		name string
		form func(url.Values)
		code string
		msg  string
	}{
		{
			name: "another action", form: func(f url.Values) { f.Set("Action", "GetCallerIdentity") },
			code: "InvalidAction", msg: `the stub only serves AssumeRole, not "GetCallerIdentity"`,
		},
		{
			name: "no action", form: func(f url.Values) { f.Del("Action") },
			code: "InvalidAction", msg: `not ""`,
		},
		{
			name: "duration not a number", form: func(f url.Values) { f.Set("DurationSeconds", "soon") },
			code: "ValidationError", msg: "DurationSeconds: ",
		},
		{
			name: "no role", form: func(f url.Values) { f.Del("RoleArn") },
			code: "ValidationError", msg: "RoleArn and RoleSessionName are required",
		},
		{
			name: "no session name", form: func(f url.Values) { f.Del("RoleSessionName") },
			code: "ValidationError", msg: "RoleArn and RoleSessionName are required",
		},
		// The duration is checked before the required parameters.
		{
			name: "bad duration and no role", form: func(f url.Values) { f.Set("DurationSeconds", "x"); f.Del("RoleArn") },
			code: "ValidationError", msg: "DurationSeconds: ",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newStub()
			form := assumeRoleForm()
			tc.form(form)
			w := post(t, s.handler(), form)
			checkRefusal(t, w, tc.code, tc.msg)
			if n := len(s.rec.list()); n != 0 {
				t.Errorf("a refused request was recorded (%d)", n)
			}
		})
	}
}

func TestMalformedForm(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	newStub().handler().ServeHTTP(w, req)
	checkRefusal(t, w, "MalformedInput", "")
}

// checkRefusal asserts a 400 query-protocol error with the code and a
// message containing msg.
func checkRefusal(t *testing.T, w *httptest.ResponseRecorder, code, msg string) {
	t.Helper()
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400; body %s", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/xml" {
		t.Errorf("Content-Type %q, want text/xml", ct)
	}
	var resp errorResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding the error: %v\n%s", err, w.Body)
	}
	if resp.Error.Type != "Sender" || resp.Error.Code != code || !strings.Contains(resp.Error.Message, msg) {
		t.Errorf("error %+v, want Sender %s containing %q", resp.Error, code, msg)
	}
	if resp.RequestID != "stub-error" {
		t.Errorf("RequestId %q, want stub-error", resp.RequestID)
	}
}

func TestHealthz(t *testing.T) {
	w := httptest.NewRecorder()
	newStub().handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != http.StatusOK || w.Body.String() != "ok\n" {
		t.Errorf("GET /healthz: %d %q", w.Code, w.Body)
	}
}

func TestAssumedRoleArn(t *testing.T) {
	cases := []struct{ role, want string }{
		{"arn:aws:iam::123456789012:role/web", "arn:aws:sts::123456789012:assumed-role/web/s"},
		{"arn:aws:iam::123456789012:role/team/a/web", "arn:aws:sts::123456789012:assumed-role/web/s"},
		{"not an arn", "arn:aws:sts::000000000000:assumed-role/unknown/s"},
	}
	for _, tc := range cases {
		if got := assumedRoleArn(tc.role, "s"); got != tc.want {
			t.Errorf("assumedRoleArn(%q) = %q, want %q", tc.role, got, tc.want)
		}
	}
}
