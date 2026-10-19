package cracha

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The gateway's method table (design 6.4): what each client SPIFFE ID may
// call, and nothing else.
var (
	readMethods = []string{
		"/authzed.api.v1.PermissionsService/CheckPermission",
		"/authzed.api.v1.PermissionsService/LookupResources",
		"/authzed.api.v1.PermissionsService/ReadRelationships",
		"/authzed.api.v1.WatchService/Watch",
	}
	accessMethods = append(slices.Clone(readMethods),
		"/authzed.api.v1.PermissionsService/WriteRelationships",
		"/authzed.api.v1.PermissionsService/DeleteRelationships",
	)
	schemaMethods = []string{
		"/authzed.api.v1.SchemaService/WriteSchema",
		"/authzed.api.v1.SchemaService/ReadSchema",
	}
)

// envoyConfig decodes the gateway's Envoy configuration from its ConfigMap.
func envoyConfig(t *testing.T, docs []document, name string) document {
	t.Helper()
	cm := object(t, docs, "ConfigMap", name+"-spicedb-gateway")
	text, ok := path(cm, "data", "envoy.yaml").(string)
	if !ok {
		t.Fatalf("no envoy.yaml in %s-spicedb-gateway", name)
	}
	var cfg map[string]any
	if err := yaml.Unmarshal([]byte(text), &cfg); err != nil {
		t.Fatalf("envoy.yaml: %v", err)
	}
	return document(cfg)
}

// listener returns the listener of that name.
func listener(t *testing.T, cfg document, name string) any {
	t.Helper()
	for _, l := range path(cfg, "static_resources", "listeners").([]any) {
		if path(l, "name") == name {
			return l
		}
	}
	t.Fatalf("no listener %q", name)
	return nil
}

// httpFilter returns the filter of that name of the listener's connection
// manager.
func httpFilter(t *testing.T, l any, name string) any {
	t.Helper()
	for _, f := range path(l, "filter_chains", 0, "filters", 0, "typed_config", "http_filters").([]any) {
		if path(f, "name") == name {
			return f
		}
	}
	t.Fatalf("no http filter %q", name)
	return nil
}

// The RBAC policy names exactly the three client identities, each with
// exactly its methods, by exact SPIFFE ID and exact path, and allows
// nothing else.
func TestGatewayRBAC(t *testing.T) {
	tests := map[string]struct {
		name       string
		identities map[string]string
	}{
		"spicedb_memory": {"cracha", map[string]string{
			"broker":     "spiffe://cracha.test/ns/default/sa/cracha-broker",
			"access":     "spiffe://cracha.test/ns/default/sa/cracha-access",
			"reconciler": "spiffe://cracha.test/ns/default/sa/cracha-reconciler",
		}},
		"overrides": {"custom", map[string]string{
			"broker":     "spiffe://prod.example.org/ns/cracha-system/sa/custom-broker",
			"access":     "spiffe://prod.example.org/ns/cracha-system/sa/custom-access",
			"reconciler": "spiffe://prod.example.org/ci/cracha-reconciler",
		}},
		"spicedb_postgres": {"cracha", map[string]string{
			"broker":     "spiffe://prod.example.org/ns/default/sa/cracha-broker",
			"access":     "spiffe://prod.example.org/ns/default/sa/cracha-access",
			"reconciler": "spiffe://prod.example.org/ns/default/sa/cracha-reconciler",
		}},
	}
	methods := map[string][]string{"broker": readMethods, "access": accessMethods, "reconciler": schemaMethods}
	for rendering, tt := range tests {
		t.Run(rendering, func(t *testing.T) {
			cfg := envoyConfig(t, rendered(t, rendering), tt.name)
			rbac := httpFilter(t, listener(t, cfg, "spicedb"), "envoy.filters.http.rbac")
			rules := path(rbac, "typed_config", "rules")
			if path(rules, "action") != "ALLOW" {
				t.Fatalf("RBAC action %v, want ALLOW: everything else is denied", path(rules, "action"))
			}
			policies, _ := path(rules, "policies").(map[string]any)
			if got := slices.Sorted(maps.Keys(policies)); !slices.Equal(got, []string{"access", "broker", "reconciler"}) {
				t.Fatalf("policies %v, want exactly broker, access and reconciler", got)
			}
			for client, policy := range policies {
				principals, _ := path(policy, "principals").([]any)
				if len(principals) != 1 || path(principals[0], "authenticated", "principal_name", "exact") != tt.identities[client] {
					t.Errorf("%s: principals %v, want exactly %s", client, principals, tt.identities[client])
				}
				var got []string
				for _, p := range path(policy, "permissions").([]any) {
					exact, ok := path(p, "url_path", "path", "exact").(string)
					if !ok || len(p.(map[string]any)) != 1 {
						t.Errorf("%s: permission %v is not one exact path", client, p)
					}
					got = append(got, exact)
				}
				if !slices.Equal(got, methods[client]) {
					t.Errorf("%s: methods %q, want %q", client, got, methods[client])
				}
			}
			// The RBAC filter runs before the router, and nothing but the
			// router follows it.
			filters := stringListOf(path(listener(t, cfg, "spicedb"), "filter_chains", 0, "filters", 0, "typed_config", "http_filters"), "name")
			if !slices.Equal(filters, []string{"envoy.filters.http.rbac", "envoy.filters.http.router"}) {
				t.Errorf("http filters %q", filters)
			}
		})
	}
}

// The gateway's listener requires a client certificate, gets its SVID and
// bundle from the SPIRE agent's SDS, adds the key from the environment
// (never the key itself), and forwards to SpiceDB on the pod's loopback;
// the admin interface is on the loopback too.
func TestGatewayTransport(t *testing.T) {
	for rendering, tt := range map[string]struct {
		name               string
		port, upstreamPort int
	}{
		"spicedb_memory": {"cracha", 50051, 50052},
		"overrides":      {"custom", 15051, 50061},
	} {
		t.Run(rendering, func(t *testing.T) {
			cfg := envoyConfig(t, rendered(t, rendering), tt.name)
			l := listener(t, cfg, "spicedb")
			if got := path(l, "address", "socket_address", "port_value"); got != tt.port {
				t.Errorf("listener port %v, want %d", got, tt.port)
			}
			tls := path(l, "filter_chains", 0, "transport_socket", "typed_config")
			if path(tls, "require_client_certificate") != true {
				t.Error("the gateway does not require a client certificate")
			}
			common := path(tls, "common_tls_context")
			if path(common, "tls_certificate_sds_secret_configs", 0, "name") != "default" ||
				path(common, "validation_context_sds_secret_config", "name") != "ROOTCA" {
				t.Errorf("SDS names %v and %v, want SPIRE's default and ROOTCA",
					path(common, "tls_certificate_sds_secret_configs", 0, "name"), path(common, "validation_context_sds_secret_config", "name"))
			}
			if got := stringList(path(common, "alpn_protocols")); !slices.Equal(got, []string{"h2"}) {
				t.Errorf("ALPN %v, want h2 (gRPC clients require it)", got)
			}
			header := path(l, "filter_chains", 0, "filters", 0, "typed_config", "route_config", "request_headers_to_add", 0)
			if path(header, "header", "key") != "authorization" || path(header, "header", "value") != "Bearer %ENVIRONMENT(SPICEDB_PRESHARED_KEY)%" ||
				path(header, "append_action") != "OVERWRITE_IF_EXISTS_OR_ADD" {
				t.Errorf("the key header is %v", header)
			}
			if path(cfg, "admin", "address", "socket_address", "address") != "127.0.0.1" {
				t.Errorf("admin on %v, want the loopback", path(cfg, "admin", "address"))
			}
			for _, c := range path(cfg, "static_resources", "clusters").([]any) {
				if path(c, "name") != "spicedb" {
					continue
				}
				addr := path(c, "load_assignment", "endpoints", 0, "lb_endpoints", 0, "endpoint", "address", "socket_address")
				if path(addr, "address") != "127.0.0.1" || path(addr, "port_value") != tt.upstreamPort {
					t.Errorf("SpiceDB upstream %v, want 127.0.0.1:%d", addr, tt.upstreamPort)
				}
			}
		})
	}
}

// SpiceDB listens on the pod's loopback only and exposes no port; the
// gateway is the pod's one listener; the key comes from the Secret, which
// only this pod mounts, and never reaches the broker.
func TestSpiceDBPod(t *testing.T) {
	for rendering, tt := range map[string]struct {
		name, keySecret string
		replicas        int
	}{
		"spicedb_memory": {"cracha", "spicedb-key", 1},
		"overrides":      {"custom", "spicedb-key", 3},
	} {
		t.Run(rendering, func(t *testing.T) {
			docs := rendered(t, rendering)
			dep := object(t, docs, "Deployment", tt.name+"-spicedb")
			if got := path(dep, "spec", "replicas"); got != tt.replicas {
				t.Errorf("replicas %v, want %d", got, tt.replicas)
			}
			spec := path(dep, "spec", "template", "spec")
			if path(spec, "serviceAccountName") != tt.name+"-spicedb" {
				t.Errorf("service account %v", path(spec, "serviceAccountName"))
			}
			containers := path(spec, "containers").([]any)
			if names := stringListOf(containers, "name"); !slices.Equal(names, []string{"spicedb", "gateway"}) {
				t.Fatalf("containers %q", names)
			}
			spicedb, gateway := containers[0], containers[1]
			if ports := path(spicedb, "ports"); ports != nil {
				t.Errorf("SpiceDB exposes %v", ports)
			}
			args := stringList(path(spicedb, "args"))
			if !slices.ContainsFunc(args, func(a string) bool { return strings.HasPrefix(a, "--grpc-addr=127.0.0.1:") }) ||
				!slices.Contains(args, "--http-enabled=false") || !slices.Contains(args, "--metrics-addr=127.0.0.1:9090") ||
				!slices.Contains(args, "--telemetry-endpoint=") {
				t.Errorf("SpiceDB args %q: not loopback-only", args)
			}
			if got := stringListOf(path(gateway, "ports"), "name"); !slices.Equal(got, []string{"grpc", "health"}) {
				t.Errorf("gateway ports %q", got)
			}
			for _, c := range containers {
				for _, e := range path(c, "env").([]any) {
					if path(e, "name") == "SPICEDB_GRPC_PRESHARED_KEY" || path(e, "name") == "SPICEDB_PRESHARED_KEY" {
						if path(e, "valueFrom", "secretKeyRef", "name") != tt.keySecret || path(e, "value") != nil {
							t.Errorf("%v: the key does not come from %s", e, tt.keySecret)
						}
					}
				}
			}
			for _, probe := range []string{"readinessProbe", "livenessProbe"} {
				if path(gateway, probe, "httpGet", "port") != "health" {
					t.Errorf("gateway %s on %v", probe, path(gateway, probe, "httpGet", "port"))
				}
				if cmd := stringList(path(spicedb, probe, "exec", "command")); len(cmd) == 0 || cmd[0] != "grpc_health_probe" {
					t.Errorf("SpiceDB %s %v", probe, cmd)
				}
			}
			svc := object(t, docs, "Service", tt.name+"-spicedb")
			if path(svc, "spec", "ports", 0, "targetPort") != "grpc" || len(path(svc, "spec", "ports").([]any)) != 1 {
				t.Errorf("the Service exposes %v, want the gateway alone", path(svc, "spec", "ports"))
			}
			broker := object(t, docs, "Deployment", tt.name+"-broker")
			for _, v := range volumes(t, broker) {
				if s, ok := v["secret"].(map[string]any); ok && s["secretName"] == tt.keySecret {
					t.Error("the broker mounts SpiceDB's key")
				}
			}
		})
	}
}

// The broker dials the chart's gateway by default and verifies it by its
// ServiceAccount's SPIFFE ID; an install names another.
func TestBrokerSpiceDBArgs(t *testing.T) {
	for rendering, tt := range map[string]struct{ name, endpoint, server string }{
		"spicedb_memory": {"cracha", "cracha-spicedb.default.svc:50051", "/ns/default/sa/cracha-spicedb"},
		"overrides":      {"custom", "spicedb.authz.svc:50051", "spiffe://prod.example.org/ns/authz/sa/spicedb"},
	} {
		t.Run(rendering, func(t *testing.T) {
			dep := object(t, rendered(t, rendering), "Deployment", tt.name+"-broker")
			args := stringList(path(dep, "spec", "template", "spec", "containers", 0, "args"))
			for _, want := range []string{"--authz-backend=spicedb", "--spicedb-endpoint=" + tt.endpoint, "--spicedb-server-spiffe-id=" + tt.server} {
				if !slices.Contains(args, want) {
					t.Errorf("args %q lack %s", args, want)
				}
			}
			for _, a := range args {
				if strings.HasPrefix(a, "--spicedb-token-file") || strings.HasPrefix(a, "--spicedb-ca") || a == "--spicedb-insecure" {
					t.Errorf("the broker takes %s", a)
				}
			}
		})
	}
}

// The migration Job is the one migration owner: a pre-install and
// pre-upgrade hook with the datastore's URI and authority, absent for the
// memory engine; SSL_CERT_FILE names the mounted CA, and postgres mounts
// the client certificate.
func TestSpiceDBDatastore(t *testing.T) {
	for rendering, tt := range map[string]struct {
		name, engine, caFile string
		job, clientCert      bool
	}{
		"spicedb_memory":   {"cracha", "memory", "", false, false},
		"overrides":        {"custom", "mysql", "/etc/spicedb/datastore-ca/root.pem", true, false},
		"spicedb_postgres": {"cracha", "postgres", "/etc/spicedb/datastore-ca/ca.pem", true, true},
	} {
		t.Run(rendering, func(t *testing.T) {
			docs := rendered(t, rendering)
			dep := object(t, docs, "Deployment", tt.name+"-spicedb")
			pods := []any{path(dep, "spec", "template", "spec")}
			hasJob := slices.ContainsFunc(docs, func(d document) bool { return d.kind() == "Job" && d.name() == tt.name+"-spicedb-migrate" })
			if hasJob != tt.job {
				t.Fatalf("migration Job rendered %t, want %t", hasJob, tt.job)
			}
			if tt.job {
				job := object(t, docs, "Job", tt.name+"-spicedb-migrate")
				if hook := path(job, "metadata", "annotations", "helm.sh/hook"); hook != "pre-install,pre-upgrade" {
					t.Errorf("hook %v", hook)
				}
				if args := stringList(path(job, "spec", "template", "spec", "containers", 0, "args")); !slices.Equal(args[:3], []string{"migrate", "head", "--datastore-engine=" + tt.engine}) {
					t.Errorf("migrate args %q", args)
				}
				pods = append(pods, path(job, "spec", "template", "spec"))
			}
			for _, pod := range pods {
				c := path(pod, "containers", 0)
				env := map[string]any{}
				for _, e := range path(c, "env").([]any) {
					env[path(e, "name").(string)] = e
				}
				_, hasURI := env["SPICEDB_DATASTORE_CONN_URI"]
				if hasURI != (tt.engine != "memory") {
					t.Errorf("datastore URI in env %t for %s", hasURI, tt.engine)
				}
				if got, _ := path(env["SSL_CERT_FILE"], "value").(string); got != tt.caFile {
					t.Errorf("SSL_CERT_FILE %q, want %q", got, tt.caFile)
				}
				mounts := stringListOf(path(c, "volumeMounts"), "mountPath")
				if slices.Contains(mounts, "/etc/spicedb/datastore-client") != tt.clientCert {
					t.Errorf("client certificate mounted %v, want %t", mounts, tt.clientCert)
				}
			}
		})
	}
}

// With spicedb.datastore.spiffe, SpiceDB and the migration Job log in with
// their SPIFFE IDs from the Workload API: the flags, the socket mounted, the
// label the issuer's entry selects, the Job's own ServiceAccount created
// before it, and no CA.
func TestSpiceDBDatastoreSPIFFE(t *testing.T) {
	docs := rendered(t, "spicedb_mysql_spiffe")
	dep := object(t, docs, "Deployment", "cracha-spicedb")
	job := object(t, docs, "Job", "cracha-spicedb-migrate")
	sa := object(t, docs, "ServiceAccount", "cracha-spicedb-migrate")
	if hook := path(sa, "metadata", "annotations", "helm.sh/hook"); hook != "pre-install,pre-upgrade" {
		t.Errorf("migration ServiceAccount hook %v", hook)
	}
	if w := path(sa, "metadata", "annotations", "helm.sh/hook-weight"); w != "-1" {
		t.Errorf("migration ServiceAccount hook weight %v, want -1 (before the Job's 0)", w)
	}
	if got := path(job, "spec", "template", "spec", "serviceAccountName"); got != "cracha-spicedb-migrate" {
		t.Errorf("Job serviceAccountName %v", got)
	}
	for _, tt := range []struct {
		what string
		obj  document
		id   string
	}{
		{"SpiceDB", dep, "spiffe://prod.example.org/ns/default/sa/cracha-spicedb"},
		{"the migration Job", job, "spiffe://prod.example.org/spicedb/migrate"},
	} {
		pod := path(tt.obj, "spec", "template")
		if l := path(pod, "metadata", "labels", "cracha.dev/datastore-client"); l != "true" {
			t.Errorf("%s: label cracha.dev/datastore-client %v", tt.what, l)
		}
		c := path(pod, "spec", "containers", 0)
		args := stringList(path(c, "args"))
		for _, want := range []string{
			"--datastore-spiffe",
			"--datastore-spiffe-socket=unix:///spiffe-workload-api/spire-agent.sock",
			"--datastore-spiffe-id=" + tt.id,
			"--datastore-spiffe-server-id=spiffe://db.example.org/mysql/server",
		} {
			if !slices.Contains(args, want) {
				t.Errorf("%s: args %q lack %s", tt.what, args, want)
			}
		}
		if !slices.Contains(stringListOf(path(c, "volumeMounts"), "mountPath"), "/spiffe-workload-api") {
			t.Errorf("%s: the Workload API socket is not mounted", tt.what)
		}
		for _, e := range path(c, "env").([]any) {
			if path(e, "name") == "SSL_CERT_FILE" {
				t.Errorf("%s: SSL_CERT_FILE set with spiffe", tt.what)
			}
		}
		var csi bool
		for _, v := range path(pod, "spec", "volumes").([]any) {
			if path(v, "name") == "spire-workload-api" {
				csi = path(v, "csi") != nil && path(v, "hostPath") == nil
			}
		}
		if !csi {
			t.Errorf("%s: no spire-workload-api volume of the csi source", tt.what)
		}
	}
	// Without spiffe, nothing of it.
	for _, rendering := range []string{"overrides", "spicedb_postgres"} {
		for _, d := range rendered(t, rendering) {
			if d.kind() == "ServiceAccount" && strings.HasSuffix(d.name(), "-spicedb-migrate") {
				t.Errorf("%s: migration ServiceAccount rendered without spiffe", rendering)
			}
			if d.kind() == "Deployment" || d.kind() == "Job" {
				if l := path(d, "spec", "template", "metadata", "labels", "cracha.dev/datastore-client"); l != nil {
					t.Errorf("%s: %s %s labelled cracha.dev/datastore-client without spiffe", rendering, d.kind(), d.name())
				}
			}
		}
	}
}

// The static backend renders no SpiceDB at all.
func TestNoSpiceDBWithStatic(t *testing.T) {
	for _, d := range rendered(t, "defaults") {
		if strings.Contains(d.name(), "spicedb") {
			t.Errorf("%s %s rendered with the static backend", d.kind(), d.name())
		}
	}
}
