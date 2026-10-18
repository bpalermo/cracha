package cracha

import (
	"slices"
	"testing"
)

// The webhook's ClusterRole grants exactly what the webhook does with the
// API (design 7.4): read ServiceAccounts for the opt-in annotation and
// watch Namespaces for the region override, nothing more.
func TestWebhookClusterRole(t *testing.T) {
	role := object(t, rendered(t, "defaults"), "ClusterRole", "cracha-webhook")
	rules, ok := path(role, "rules").([]any)
	if !ok {
		t.Fatalf("rules = %v", path(role, "rules"))
	}
	want := map[string][]string{
		"serviceaccounts": {"get"},
		"namespaces":      {"get", "list", "watch"},
	}
	got := map[string][]string{}
	for i, rule := range rules {
		groups := stringList(path(rule, "apiGroups"))
		if !slices.Equal(groups, []string{""}) {
			t.Errorf("rule %d is on API groups %q, want the core group only", i, groups)
		}
		verbs := stringList(path(rule, "verbs"))
		for _, resource := range stringList(path(rule, "resources")) {
			got[resource] = append(got[resource], verbs...)
		}
	}
	for resource, verbs := range want {
		if !slices.Equal(got[resource], verbs) {
			t.Errorf("verbs on %s = %q, want %q", resource, got[resource], verbs)
		}
	}
	for resource := range got {
		if _, ok := want[resource]; !ok {
			t.Errorf("the role grants %q on %s, which the webhook does not use", got[resource], resource)
		}
	}
}
