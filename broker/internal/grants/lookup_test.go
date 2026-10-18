package grants

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// bucketReader is a lookup grant of the dynamo shape (so that it composes
// with ledgerRW) reading the buckets the store relates the workload to.
func bucketReader(max int) ResolvedGrant {
	return ResolvedGrant{
		Name:     "data-read",
		Account:  "111122223333",
		BaseRole: dynamoRole,
		Envelope: []string{"arn:aws:s3:::data-*"},
		Lookup: &Lookup{
			Kind: "s3_bucket", Permission: "read", MaxResources: max,
			Render: func(resources []string) (string, error) {
				arns := make([]string, len(resources))
				for i, r := range resources {
					arns[i] = `"arn:aws:s3:::` + r + `/*"`
				}
				return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":[` + strings.Join(arns, ",") + `]}]}`, nil
			},
		},
	}
}

// finder answers from a fixed map of kind#permission, counting calls.
type finder struct {
	answers map[string][]string
	err     error
	calls   int
}

func (f *finder) find(kind, permission string) ([]string, error) {
	f.calls++
	return f.answers[kind+"#"+permission], f.err
}

func TestComposeLookup(t *testing.T) {
	f := &finder{answers: map[string][]string{"s3_bucket#read": {"data-b", "data-a", "data-b"}}}
	other := bucketReader(10)
	other.Name = "data-read-too"
	c, err := Compose(NewStatic("v1", ledgerRW(), bucketReader(10), other), []string{"payments-ledger-rw", "data-read", "data-read-too"}, f.find)
	if err != nil {
		t.Fatal(err)
	}
	if f.calls != 1 {
		t.Errorf("the store was asked %d times, want once per kind and permission", f.calls)
	}
	if want := []string{"data-read", "data-read-too", "payments-ledger-rw"}; !reflect.DeepEqual(c.Grants, want) {
		t.Errorf("grants = %v, want %v", c.Grants, want)
	}
	if want := map[string][]string{"data-read": {"data-a", "data-b"}, "data-read-too": {"data-a", "data-b"}}; !reflect.DeepEqual(c.Resources, want) {
		t.Errorf("resources = %v, want %v", c.Resources, want)
	}
	if !strings.Contains(c.Policy, `"arn:aws:s3:::data-a/*","arn:aws:s3:::data-b/*"`) || !strings.Contains(c.Policy, "payments-ledger") {
		t.Errorf("policy = %s", c.Policy)
	}
}

func TestComposeLookupDenials(t *testing.T) {
	tests := []struct {
		name    string
		grants  []ResolvedGrant
		found   []string
		reason  Reason
		dropped []string
	}{
		{"outside the envelope", []ResolvedGrant{ledgerRW(), bucketReader(10)}, []string{"data-a", "other-bucket"}, ReasonResourceOutsideEnvelope, nil},
		{"over the compiled maximum", []ResolvedGrant{bucketReader(2)}, []string{"data-a", "data-b", "data-c"}, ReasonPolicyTooLarge, nil},
		{"over the budget", []ResolvedGrant{bucketReader(1000)}, many(40), ReasonPolicyTooLarge, nil},
		{"lookups only, nothing found", []ResolvedGrant{bucketReader(10)}, nil, ReasonNoResources, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			names := grantNames(tt.grants)
			f := &finder{answers: map[string][]string{"s3_bucket#read": tt.found}}
			_, err := Compose(NewStatic("v1", tt.grants...), names, f.find)
			if got := denyReason(t, err); got != tt.reason {
				t.Errorf("reason = %s, want %s (%v)", got, tt.reason, err)
			}
		})
	}
}

func many(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "data-" + strings.Repeat("x", 50) + string(rune('a'+i%26)) + string(rune('a'+i/26))
	}
	return out
}

func TestComposeDropsLookupWithoutResources(t *testing.T) {
	f := &finder{}
	c, err := Compose(NewStatic("v1", ledgerRW(), bucketReader(10)), []string{"payments-ledger-rw", "data-read"}, f.find)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.Grants, []string{"payments-ledger-rw"}) || !reflect.DeepEqual(c.Dropped, []string{"data-read"}) || c.Resources != nil {
		t.Errorf("composed %+v, want the ledger grant alone and data-read dropped", c)
	}
}

func TestComposeLookupErrors(t *testing.T) {
	storeDown := errors.New("store down")
	f := &finder{err: storeDown}
	if _, err := Compose(NewStatic("v1", bucketReader(10)), []string{"data-read"}, f.find); !errors.Is(err, storeDown) {
		t.Errorf("a failed lookup: %v, want the store's error", err)
	}
	if _, err := Compose(NewStatic("v1", bucketReader(10)), []string{"data-read"}, nil); err == nil {
		t.Error("a lookup grant composed without a finder")
	}
	broken := bucketReader(10)
	broken.Lookup.Render = func([]string) (string, error) { return "", errors.New("bad template") }
	f = &finder{answers: map[string][]string{"s3_bucket#read": {"data-a"}}}
	if _, err := Compose(NewStatic("v1", broken), []string{"data-read"}, f.find); err == nil || errors.As(err, new(*DenyError)) {
		t.Errorf("a broken renderer: %v, want an error that is not a denial", err)
	}
}
