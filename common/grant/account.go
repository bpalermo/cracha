package grant

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ImplicitGrantName is the name of an account's implicit grant for a kind
// and a permission: account:<account document's name>:<kind>:<permission>,
// such as account:payments:s3_bucket:read. A colon is in no name a Grant
// document may have, so an implicit grant can be neither written nor
// assigned under its name.
func ImplicitGrantName(account, kind, permission string) string {
	return "account:" + account + ":" + kind + ":" + permission
}

// Account returns the Account document of the 12-digit account id, or nil.
func (s *Source) Account(id string) *Account {
	for _, a := range s.Accounts {
		if a.Spec.ID == id {
			return a
		}
	}
	return nil
}

// ResourceAccount is the account a resource named by an Access document is
// in: its resource.account, or the tree's only Account when it names none.
// Empty when neither says (a tree without Account documents, or one with
// several, which the lints refuse).
func (s *Source) ResourceAccount(r Resource) string {
	switch {
	case r.Account != "":
		return r.Account
	case len(s.Accounts) == 1:
		return s.Accounts[0].Spec.ID
	}
	return ""
}

// CompiledGrants are the grants the bundle holds, sorted by name: every
// Grant with its account's defaults applied (the account role for a grant
// that names no baseRole, the account's envelope for one that sets none),
// and every Account's implicit grants, one per entry of its access table.
// The source must have validated (ValidateSource).
func (s *Source) CompiledGrants() []*Grant {
	out := make([]*Grant, 0, len(s.Grants))
	for _, g := range s.Grants {
		out = append(out, s.effective(g))
	}
	for _, a := range s.Accounts {
		for _, e := range a.Spec.Access {
			out = append(out, implicitGrant(a, e, s.Templates[e.Template]))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// effective is the grant with its account's defaults applied; the grant
// itself when it takes none.
func (s *Source) effective(g *Grant) *Grant {
	acct := s.Account(g.Spec.Account)
	if acct == nil || (g.Spec.BaseRole != "" && len(g.Spec.Envelope) > 0) {
		return g
	}
	c := *g
	if c.Spec.BaseRole == "" {
		c.Spec.BaseRole = acct.Spec.Role
	}
	if len(c.Spec.Envelope) == 0 {
		c.Spec.Envelope = acct.Spec.Envelope
	}
	return &c
}

// implicitGrant is the lookup grant an entry of an account's access table
// stands for: the entry's template, with its parameter left to the
// resources of the kind the workload holds the permission on, issued on
// the account role inside the account's envelope. t is the entry's
// template, nil when it is missing (which validation reports).
func implicitGrant(a *Account, e AccountAccess, t *Template) *Grant {
	params := make(map[string]Param, len(e.Params)+1)
	for k, v := range e.Params {
		params[k] = v
	}
	if param, err := implicitParam(e, t); err == nil {
		params[param] = LookupParam(e.Kind, e.Permission)
	}
	return &Grant{
		Kind:     KindGrant,
		Metadata: Metadata{Name: ImplicitGrantName(a.Name(), e.Kind, e.Permission)},
		Path:     a.Path,
		implicit: true,
		Spec: GrantSpec{
			Account:       a.Spec.ID,
			BaseRole:      a.Spec.Role,
			SessionPolicy: &SessionPolicy{Template: e.Template, Params: params},
			SessionTags:   e.SessionTags,
			Duration:      e.Duration,
			Envelope:      a.Spec.Envelope,
		},
	}
}

// implicitParam is the template parameter an access entry's resources
// fill: the one it names, or the one parameter of the template the entry
// neither gives nor that has a default.
func implicitParam(e AccountAccess, t *Template) (string, error) {
	if t == nil {
		return "", fmt.Errorf("template %q not found under %s/", e.Template, TemplatesDir)
	}
	if e.Param != "" {
		if _, ok := t.Params[e.Param]; !ok {
			return "", fmt.Errorf("param %q is not declared by template %s", e.Param, t.Name)
		}
		if _, given := e.Params[e.Param]; given {
			return "", fmt.Errorf("param %q is the resources' and cannot be given in params", e.Param)
		}
		return e.Param, nil
	}
	var open []string
	for _, name := range sortedKeys(t.Params) {
		if _, given := e.Params[name]; !given && t.Params[name].Default == nil {
			open = append(open, name)
		}
	}
	if len(open) != 1 {
		return "", fmt.Errorf("template %s leaves %d parameters without a value (%s); name the one the resources fill in param", t.Name, len(open), strings.Join(open, ", "))
	}
	return open[0], nil
}

// ValidateAccount checks an Account document's own fields; its templates
// and the grants its access table stands for are checked by
// ValidateSource.
func ValidateAccount(a *Account) error {
	var errs errList
	if a.Kind != KindAccount {
		errs.addf("kind must be %s", KindAccount)
	}
	errs.add(validateName("account name", a.Name()))
	s := &a.Spec
	if !accountRE.MatchString(s.ID) {
		errs.addf("id %q: must be 12 digits", s.ID)
	} else {
		errs = append(errs, validateRole("role", s.Role, s.ID, "the account")...)
	}
	for _, err := range validateEnvelope(s.Envelope) {
		errs.add(err)
	}
	if len(s.Access) > 0 && len(s.Envelope) == 0 {
		errs.addf("envelope is required with access: it is the envelope of every implicit grant")
	}
	seen := map[string]bool{}
	for _, e := range s.Access {
		key := e.Kind + "#" + e.Permission
		if seen[key] {
			errs.addf("access: %s listed twice", key)
		}
		seen[key] = true
		for _, err := range validateAccessEntry(e) {
			errs.addf("access %s: %w", key, err)
		}
	}
	return errors.Join(errs...)
}

// validateAccessEntry checks one entry of an access table on its own.
func validateAccessEntry(e AccountAccess) errList {
	var errs errList
	errs.add(validateLookup(&Lookup{Kind: e.Kind, Permission: e.Permission}))
	errs.add(validateName("template", e.Template))
	if e.Param != "" {
		errs.add(validateParamName(e.Param))
	}
	for _, name := range sortedKeys(e.Params) {
		if err := validateParamName(name); err != nil {
			errs.addf("params: %w", err)
		}
		if e.Params[name].Lookup != nil {
			errs.addf("params: %s: a lookup; the entry's kind and permission are its lookup", name)
		}
	}
	return errs
}

// validateSourceAccounts validates every Account document and, when it is
// valid, that no other document is of the same account and that each
// entry of its access table makes a valid grant: its template exists and
// declares the parameter the resources fill, and the grant passes the
// rules every grant does.
func validateSourceAccounts(src *Source) errList {
	var errs errList
	byID := map[string]*Account{}
	for _, a := range src.Accounts {
		if err := ValidateAccount(a); err != nil {
			errs.addf("account %s (%s): %w", a.Name(), a.Path, err)
			continue
		}
		if prev, dup := byID[a.Spec.ID]; dup {
			errs.addf("account %s (%s): account %s already has Account document %s (%s)", a.Name(), a.Path, a.Spec.ID, prev.Name(), prev.Path)
			continue
		}
		byID[a.Spec.ID] = a
		for _, e := range a.Spec.Access {
			errs = append(errs, validateImplicitGrant(src, a, e)...)
		}
	}
	return errs
}

// validateImplicitGrant checks the grant one access entry stands for.
func validateImplicitGrant(src *Source, a *Account, e AccountAccess) errList {
	var errs errList
	prefix := fmt.Sprintf("account %s (%s): access %s#%s", a.Name(), a.Path, e.Kind, e.Permission)
	if _, err := implicitParam(e, src.Templates[e.Template]); err != nil {
		errs.addf("%s: %w", prefix, err)
		return errs
	}
	for _, err := range validateGrantSpec(implicitGrant(a, e, src.Templates[e.Template]), a) {
		errs.addf("%s: %w", prefix, err)
	}
	return errs
}

// validatePlacement checks that every resource the Access documents name is
// in one account: a name relates one resource, so two documents may not
// place it in two.
func validatePlacement(src *Source) errList {
	var errs errList
	placed := map[Resource]*Access{}
	for _, a := range src.Accesses {
		r := Resource{Kind: a.Spec.Resource.Kind, Name: a.Spec.Resource.Name}
		account := src.ResourceAccount(a.Spec.Resource)
		if account == "" {
			continue
		}
		prev, ok := placed[r]
		if ok && src.ResourceAccount(prev.Spec.Resource) != account {
			errs.addf("access %s (%s): %s is in account %s, but access %s (%s) puts it in %s; the store relates a resource by its name, which must name one resource", a.Name(), a.Path, r, account, prev.Name(), prev.Path, src.ResourceAccount(prev.Spec.Resource))
			continue
		}
		placed[r] = a
	}
	return errs
}

// bundleAccounts are the tree's Account documents as the bundle carries
// them, sorted by name: with more than one, each with the resources the
// Access documents place in it, which is how the broker tells which
// account's implicit grant a resource is rendered into.
func bundleAccounts(src *Source) []BundleAccount {
	if len(src.Accounts) == 0 {
		return nil
	}
	resources := map[string][]Resource{}
	if len(src.Accounts) > 1 {
		for _, a := range src.Accesses {
			id := src.ResourceAccount(a.Spec.Resource)
			resources[id] = append(resources[id], Resource{Kind: a.Spec.Resource.Kind, Name: a.Spec.Resource.Name})
		}
	}
	out := make([]BundleAccount, 0, len(src.Accounts))
	for _, a := range src.Accounts {
		out = append(out, BundleAccount{
			Name:      a.Name(),
			ID:        a.Spec.ID,
			Role:      a.Spec.Role,
			Envelope:  nonNil(a.Spec.Envelope),
			Resources: sortedResources(resources[a.Spec.ID]),
		})
	}
	return out
}

// sortedResources returns the resources sorted by kind and name, without
// repeats; nil for none.
func sortedResources(in []Resource) []Resource {
	if len(in) == 0 {
		return nil
	}
	seen := map[Resource]bool{}
	var out []Resource
	for _, r := range in {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
