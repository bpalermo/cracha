package grant

// BundleSource is the part of a source tree a compiled bundle carries, in
// the form LintComposition reads: its grants as Grant documents (the
// account defaults already applied, the implicit ones marked implicit), its
// accounts without their access tables (the implicit grants they make are
// among the grants), and the rendered policies and lookups the lint takes
// beside the tree. It is how a check that holds only the published bundle,
// and the assignments from elsewhere, runs the pipeline's composition lint
// (cracha-access, design 6.9): the caller adds the Services, Assignments
// and Access documents to the source. An Access document's resource is
// placed in the account the bundle lists it in (BundleResourceAccount).
func BundleSource(b *Bundle) (src *Source, rendered map[string]string, lookups map[string]*BundleLookup) {
	src = &Source{}
	rendered, lookups = map[string]string{}, map[string]*BundleLookup{}
	for _, a := range b.Accounts {
		src.Accounts = append(src.Accounts, &Account{
			Kind: KindAccount, Metadata: Metadata{Name: a.Name},
			Spec: AccountSpec{ID: a.ID, Role: a.Role, Envelope: a.Envelope},
		})
	}
	for _, g := range b.Grants {
		src.Grants = append(src.Grants, &Grant{Kind: KindGrant, Metadata: Metadata{Name: g.Name}, implicit: g.Implicit, Spec: GrantSpec{
			Account: g.Account, BaseRole: g.BaseRole, ManagedPolicyArns: g.ManagedPolicyArns,
			SessionTags: g.SessionTags, Duration: g.Duration, Envelope: g.Envelope,
		}})
		if g.Lookup != nil {
			lookups[g.Name] = g.Lookup
		} else {
			rendered[g.Name] = g.SessionPolicy
		}
	}
	return src, rendered, lookups
}

// BundleResourceAccount is the account a bundle places a resource in: the
// one account whose resources list it, or the bundle's only account, which
// lists none. Empty when neither says.
func BundleResourceAccount(b *Bundle, r Resource) string {
	if len(b.Accounts) == 1 {
		return b.Accounts[0].ID
	}
	for _, a := range b.Accounts {
		for _, res := range a.Resources {
			if res.Kind == r.Kind && res.Name == r.Name {
				return a.ID
			}
		}
	}
	return ""
}
