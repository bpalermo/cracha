package cracha

import (
	"slices"
	"testing"
)

// The webhook's ClusterRole grants exactly what the webhook does with the
// API (design 7.5): read ServiceAccounts for the opt-in annotation, watch
// Namespaces for the region override, and get and patch its own
// MutatingWebhookConfiguration, by name, for the caBundle. Nothing more.
func TestWebhookClusterRole(t *testing.T) {
	for _, tc := range []struct {
		rendering, name string
	}{{"defaults", "cracha-webhook"}, {"overrides", "custom-webhook"}} {
		t.Run(tc.rendering, func(t *testing.T) {
			role := object(t, rendered(t, tc.rendering), "ClusterRole", tc.name)
			rules, ok := path(role, "rules").([]any)
			if !ok {
				t.Fatalf("rules = %v", path(role, "rules"))
			}
			type grant struct{ group, resource string }
			want := map[grant][]string{
				{"", "serviceaccounts"}: {"get"},
				{"", "namespaces"}:      {"get", "list", "watch"},
				{"admissionregistration.k8s.io", "mutatingwebhookconfigurations"}: {"get", "patch"},
			}
			got := map[grant][]string{}
			for i, rule := range rules {
				groups := stringList(path(rule, "apiGroups"))
				if len(groups) != 1 {
					t.Errorf("rule %d is on API groups %q, want one", i, groups)
					continue
				}
				verbs := stringList(path(rule, "verbs"))
				for _, resource := range stringList(path(rule, "resources")) {
					g := grant{groups[0], resource}
					got[g] = append(got[g], verbs...)
					if resource == "mutatingwebhookconfigurations" {
						if names := stringList(path(rule, "resourceNames")); !slices.Equal(names, []string{tc.name}) {
							t.Errorf("rule %d on %s names %q, want only the chart's %q", i, resource, names, tc.name)
						}
					} else if path(rule, "resourceNames") != nil {
						t.Errorf("rule %d on %s is restricted by resourceNames, which the webhook cannot work with", i, resource)
					}
				}
			}
			for g, verbs := range want {
				if !slices.Equal(got[g], verbs) {
					t.Errorf("verbs on %s/%s = %q, want %q", g.group, g.resource, got[g], verbs)
				}
			}
			for g := range got {
				if _, ok := want[g]; !ok {
					t.Errorf("the role grants %q on %s/%s, which the webhook does not use", got[g], g.group, g.resource)
				}
			}
		})
	}
}
