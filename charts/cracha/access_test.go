package cracha

import (
	"slices"
	"testing"
)

// cracha-access is off by default: an install without the spicedb backend
// has nothing for it to write.
func TestAccessOffByDefault(t *testing.T) {
	for _, d := range rendered(t, "defaults") {
		if d.name() == "cracha-access" {
			t.Errorf("the defaults render %s %s", d.kind(), d.name())
		}
	}
}

// One writer, reading the broker's publication with the broker's keys, and
// reaching SpiceDB through the chart's gateway unless told otherwise.
func TestAccessDeployment(t *testing.T) {
	for _, tc := range []struct {
		rendering, name string
		args            []string
		volumes         []string
	}{
		{"access", "cracha-access", []string{
			"serve", "--listen=:8443", "--health-listen=:8081",
			"--workload-api-socket=unix:///spiffe-workload-api/spire-agent.sock",
			"--spicedb-endpoint=cracha-spicedb.default.svc:50051",
			"--spicedb-server-spiffe-id=/ns/default/sa/cracha-spicedb",
			"--spicedb-timeout=10s",
			"--bundle-source=s3://grant-bundles/cracha/prod",
			"--bundle-kms-key=arn:aws:kms:eu-west-1:111122223333:key/0123abcd-0123-0123-0123-0123456789ab",
			"--bundle-poll-interval=60s",
			"--pending-ttl=72h", "--break-glass-max=4h",
			"--access-analyzer=false", "--watch-audit=true", "--log-level=info",
		}, []string{"spire-workload-api"}},
		{"overrides", "custom-access", []string{
			"serve", "--listen=:9444", "--health-listen=:9082",
			"--workload-api-socket=unix:///spiffe-workload-api/socket",
			"--trust-domain-labels=partner.example.net=partner,prod.example.org=prod",
			"--spicedb-endpoint=spicedb-gateway.spicedb.svc:443",
			"--spicedb-server-spiffe-id=spiffe://prod.example.org/ns/spicedb/sa/gateway",
			"--spicedb-timeout=3s",
			"--bundle-source=local:/var/lib/cracha/bundle",
			"--bundle-verify-key=/etc/cracha/bundle-key/public.pem",
			"--bundle-poll-interval=5m",
			"--pending-ttl=24h", "--break-glass-max=1h",
			"--max-expiry=s3_bucket=720h,service=2160h",
			"--access-analyzer=true", "--watch-audit=false", "--aws-region=eu-west-1", "--log-level=debug",
		}, []string{"bundle", "bundle-key", "spire-workload-api"}},
	} {
		t.Run(tc.rendering, func(t *testing.T) {
			docs := rendered(t, tc.rendering)
			dep := object(t, docs, "Deployment", tc.name)
			if path(dep, "spec", "replicas") != 1 || path(dep, "spec", "strategy", "type") != "Recreate" {
				t.Errorf("replicas %v, strategy %v: want one writer, never two", path(dep, "spec", "replicas"), path(dep, "spec", "strategy"))
			}
			pod := path(dep, "spec", "template", "spec")
			if path(pod, "serviceAccountName") != tc.name || path(pod, "automountServiceAccountToken") != false {
				t.Errorf("service account %v, automount %v", path(pod, "serviceAccountName"), path(pod, "automountServiceAccountToken"))
			}
			if got := stringList(path(pod, "containers", 0, "args")); !slices.Equal(got, tc.args) {
				t.Errorf("args =\n%q\nwant\n%q", got, tc.args)
			}
			var volumes []string
			for _, v := range path(pod, "volumes").([]any) {
				volumes = append(volumes, path(v, "name").(string))
			}
			if !slices.Equal(volumes, tc.volumes) {
				t.Errorf("volumes = %q, want %q", volumes, tc.volumes)
			}
			object(t, docs, "ServiceAccount", tc.name)
			if svc := object(t, docs, "Service", tc.name); path(svc, "spec", "ports", 0, "targetPort") != "grpc" {
				t.Errorf("service ports = %v", path(svc, "spec", "ports"))
			}
		})
	}
}
