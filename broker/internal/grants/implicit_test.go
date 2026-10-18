package grants

import (
	"errors"
	"reflect"
	"testing"
)

// accounts is an ImplicitSource over a Static: implicit grants, and the
// resources each account holds, with only the account of every resource
// no map entry places.
type accounts struct {
	*Static
	implicit []ResolvedGrant
	placed   map[string]string
	only     string
}

func (a *accounts) ImplicitGrants() []ResolvedGrant { return a.implicit }

func (a *accounts) AccountOf(kind, name string) (string, bool) {
	if id, ok := a.placed[kind+":"+name]; ok {
		return id, true
	}
	return a.only, a.only != ""
}

// implicitRead is an account's implicit grant for s3_bucket#read, on the
// account role, the dynamo shape role in 111122223333 so that it composes
// with ledgerRW.
func implicitRead(account, role string) ResolvedGrant {
	g := bucketReader(10)
	g.Name = "account:" + account + ":s3_bucket:read"
	g.Account = account
	g.BaseRole = role
	g.Implicit = true
	return g
}

func TestComposeImplicit(t *testing.T) {
	one := func(held ...ResolvedGrant) *accounts {
		return &accounts{Static: NewStatic("v1", held...), implicit: []ResolvedGrant{implicitRead("111122223333", dynamoRole)}, only: "111122223333"}
	}
	t.Run("relations alone", func(t *testing.T) {
		f := &finder{answers: map[string][]string{"s3_bucket#read": {"data-b", "data-a"}}}
		c, err := Compose(one(), nil, f.find)
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"account:111122223333:s3_bucket:read"}; !reflect.DeepEqual(c.Grants, want) {
			t.Errorf("grants = %v, want %v", c.Grants, want)
		}
		if want := map[string][]string{"account:111122223333:s3_bucket:read": {"data-a", "data-b"}}; !reflect.DeepEqual(c.Resources, want) {
			t.Errorf("resources = %v, want %v", c.Resources, want)
		}
		if c.BaseRole != dynamoRole || c.Dropped != nil {
			t.Errorf("base role %s, dropped %v", c.BaseRole, c.Dropped)
		}
	})
	t.Run("beside an explicit grant on the account role", func(t *testing.T) {
		f := &finder{answers: map[string][]string{"s3_bucket#read": {"data-a"}}}
		c, err := Compose(one(ledgerRW()), []string{"payments-ledger-rw"}, f.find)
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"account:111122223333:s3_bucket:read", "payments-ledger-rw"}; !reflect.DeepEqual(c.Grants, want) {
			t.Errorf("grants = %v, want %v", c.Grants, want)
		}
	})
	t.Run("no relation and no grant", func(t *testing.T) {
		_, err := Compose(one(), nil, (&finder{}).find)
		if r := reasonOf(err); r != ReasonNoGrant {
			t.Errorf("reason = %q (%v), want %q", r, err, ReasonNoGrant)
		}
	})
	t.Run("no relation keeps the explicit grants", func(t *testing.T) {
		c, err := Compose(one(ledgerRW()), []string{"payments-ledger-rw"}, (&finder{}).find)
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"payments-ledger-rw"}; !reflect.DeepEqual(c.Grants, want) || c.Dropped != nil {
			t.Errorf("grants = %v, dropped = %v, want %v and none", c.Grants, c.Dropped, want)
		}
	})
	t.Run("a held lookup grant of the kind wins", func(t *testing.T) {
		f := &finder{answers: map[string][]string{"s3_bucket#read": {"data-a"}}}
		c, err := Compose(one(bucketReader(10)), []string{"data-read"}, f.find)
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"data-read"}; !reflect.DeepEqual(c.Grants, want) {
			t.Errorf("grants = %v, want %v", c.Grants, want)
		}
	})
	t.Run("a dedicated shape beside the account role", func(t *testing.T) {
		src := &accounts{Static: NewStatic("v1", ledgerRW()), implicit: []ResolvedGrant{implicitRead("111122223333", s3Role)}, only: "111122223333"}
		f := &finder{answers: map[string][]string{"s3_bucket#read": {"data-a"}}}
		_, err := Compose(src, []string{"payments-ledger-rw"}, f.find)
		if r := reasonOf(err); r != ReasonAmbiguous {
			t.Errorf("reason = %q (%v), want %q", r, err, ReasonAmbiguous)
		}
	})
	t.Run("a store failure is returned", func(t *testing.T) {
		boom := errors.New("boom")
		_, err := Compose(one(), nil, (&finder{err: boom}).find)
		if !errors.Is(err, boom) {
			t.Errorf("err = %v, want %v", err, boom)
		}
	})
}

func TestComposeImplicitAccounts(t *testing.T) {
	src := &accounts{
		Static:   NewStatic("v1"),
		implicit: []ResolvedGrant{implicitRead("111122223333", dynamoRole), implicitRead("444455556666", "arn:aws:iam::444455556666:role/broker/apps")},
		placed:   map[string]string{"s3_bucket:data-a": "111122223333", "s3_bucket:data-b": "444455556666"},
	}
	t.Run("one account's resources", func(t *testing.T) {
		f := &finder{answers: map[string][]string{"s3_bucket#read": {"data-b", "data-stray"}}}
		c, err := Compose(src, nil, f.find)
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"account:444455556666:s3_bucket:read"}; !reflect.DeepEqual(c.Grants, want) {
			t.Errorf("grants = %v, want %v", c.Grants, want)
		}
		if want := map[string][]string{"account:444455556666:s3_bucket:read": {"data-b"}}; !reflect.DeepEqual(c.Resources, want) {
			t.Errorf("resources = %v, want %v", c.Resources, want)
		}
		if want := []string{"s3_bucket:data-stray"}; !reflect.DeepEqual(c.Unplaced, want) {
			t.Errorf("unplaced = %v, want %v", c.Unplaced, want)
		}
	})
	t.Run("both accounts", func(t *testing.T) {
		f := &finder{answers: map[string][]string{"s3_bucket#read": {"data-a", "data-b"}}}
		_, err := Compose(src, nil, f.find)
		if r := reasonOf(err); r != ReasonAccountsMixed {
			t.Errorf("reason = %q (%v), want %q", r, err, ReasonAccountsMixed)
		}
	})
	t.Run("unplaced only", func(t *testing.T) {
		f := &finder{answers: map[string][]string{"s3_bucket#read": {"data-stray"}}}
		_, err := Compose(src, nil, f.find)
		if r := reasonOf(err); r != ReasonNoGrant {
			t.Errorf("reason = %q (%v), want %q", r, err, ReasonNoGrant)
		}
	})
}

func reasonOf(err error) Reason {
	var deny *DenyError
	if errors.As(err, &deny) {
		return deny.Reason
	}
	return ""
}
