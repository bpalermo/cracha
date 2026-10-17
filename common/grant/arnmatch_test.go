package grant

import "testing"

func TestMatchARN(t *testing.T) {
	tests := []struct {
		pattern, s string
		want       bool
	}{
		{"arn:aws:dynamodb:*:111122223333:table/payments-*", "arn:aws:dynamodb:us-east-1:111122223333:table/payments-ledger", true},
		{"arn:aws:dynamodb:*:111122223333:table/payments-*", "arn:aws:dynamodb::111122223333:table/payments-", true},
		{"arn:aws:dynamodb:*:111122223333:table/payments-*", "arn:aws:dynamodb:us-east-1:111122223333:table/payments-ledger/index/x", true},
		{"arn:aws:dynamodb:*:111122223333:table/payments-*", "arn:aws:dynamodb:us-east-1:111122223333:table/other", false},
		{"arn:aws:dynamodb:*:111122223333:table/payments-*", "arn:aws:dynamodb:us-east-1:999999999999:table/payments-ledger", false},
		{"arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/", true},
		{"arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket", false},
		{"arn:aws:s3:::bucket", "arn:aws:s3:::bucket", true},
		{"arn:aws:s3:::bucket", "arn:aws:s3:::Bucket", false},
		{"arn:aws:s3:::bucket-?", "arn:aws:s3:::bucket-1", true},
		{"arn:aws:s3:::bucket-?", "arn:aws:s3:::bucket-12", false},
		{"*", "anything at all", true},
		{"*", "", true},
		{"", "", true},
		{"", "a", false},
		{"a*b*c", "abc", true},
		{"a*b*c", "axxbyyc", true},
		{"a*b*c", "axxbyy", false},
		{"**", "x", true},
		{"a**", "a", true},
	}
	for _, tt := range tests {
		if got := MatchARN(tt.pattern, tt.s); got != tt.want {
			t.Errorf("MatchARN(%q, %q) = %v, want %v", tt.pattern, tt.s, got, tt.want)
		}
	}
}

func TestMatchesEnvelope(t *testing.T) {
	env := []string{"arn:aws:s3:::bucket/*", "arn:aws:dynamodb:*:111122223333:table/payments-*"}
	tests := []struct {
		envelope []string
		resource string
		want     bool
	}{
		{env, "arn:aws:s3:::bucket/key", true},
		{env, "arn:aws:dynamodb:eu-west-1:111122223333:table/payments-x", true},
		{env, "arn:aws:dynamodb:eu-west-1:111122223333:table/other", false},
		{env, "*", false},
		{env, "bucket/key", false},
		{[]string{"*"}, "*", true},
		{[]string{"*"}, "anything", true},
		{[]string{"arn:*"}, "*", false},
		{nil, "arn:aws:s3:::bucket/key", false},
	}
	for _, tt := range tests {
		if got := MatchesEnvelope(tt.envelope, tt.resource); got != tt.want {
			t.Errorf("MatchesEnvelope(%q, %q) = %v, want %v", tt.envelope, tt.resource, got, tt.want)
		}
	}
}

func TestIsARNPattern(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"*", true},
		{"arn:aws:s3:::bucket", true},
		{"arn:aws:s3:::bucket/*", true},
		{"arn:aws:dynamodb:*:111122223333:table/payments-*", true},
		{"arn:aws:iam::111122223333:role/x", true},
		{"arn:aws:s3:::", false},
		{"arn:aws:s3::", false},
		{"arn::s3:::bucket", false},
		{"arn:aws::::bucket", false},
		{"aws:s3:::bucket", false},
		{"arn:aws:s3:::buc ket", false},
		{"arn:aws:s3:::bucket\n", false},
		{"", false},
		{"**", false},
	}
	for _, tt := range tests {
		if got := IsARNPattern(tt.s); got != tt.want {
			t.Errorf("IsARNPattern(%q) = %v, want %v", tt.s, got, tt.want)
		}
	}
}
