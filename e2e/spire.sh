#!/usr/bin/env bash
# Deploys SPIRE into the current cluster and registers the identities the
# end-to-end suite needs (see run.sh): Crachá's own components and the test
# workloads of the e2e namespace.
#
# Every identity follows the scheme of docs/design.md, section 4:
# spiffe://<trust-domain>/ns/<namespace>/sa/<serviceaccount>, keyed on the
# pod's namespace and service account, which are the selectors available
# before any container has started (section 7.3).
set -euo pipefail

cd "$(dirname "$0")/.."

trust_domain="cracha.test"

# The JWT-SVID lifetime of the test workloads, in seconds. The design caps a
# token on disk at 5 minutes and cracha-csi refuses anything longer; the
# suite's rotation test waits for a replacement, which cracha-csi writes at
# the first kubelet republish after half the lifetime has passed. Kubelet
# republishes every 60-90 s (its sync frequency with jitter), so the lifetime
# must leave more than 90 s after its halfway point: 240 s does, and keeps
# the wait under four minutes. e2e/rotation_test.go assumes this value.
jwt_ttl=240

kubectl apply -f e2e/spire.yaml
kubectl rollout status deployment/spire-server -n spire --timeout=180s
kubectl rollout status daemonset/spire-agent -n spire --timeout=180s

server() {
	kubectl exec -n spire deployment/spire-server -- /opt/spire/bin/spire-server "$@"
}

# Entries survive a rerun on a kept cluster only as long as the server's pod
# does; creating one that exists is an error, so ask first.
existing="$(server entry show || true)"
register() {
	local id="$1"
	shift
	if grep -qF "${id}" <<<"${existing}"; then
		return
	fi
	server entry create -spiffeID "${id}" "$@"
}

# Every agent of this cluster, under one name the workloads can hang from.
register "spiffe://${trust_domain}/node" -node -selector k8s_psat:cluster:cracha-e2e

# Crachá's components: cracha-csi presents its X509-SVID to the agent's
# Broker API endpoint, and the broker reads the trust bundle from the
# Workload API, which only answers attested workloads.
for sa in cracha-csi cracha-broker; do
	register "spiffe://${trust_domain}/ns/cracha-system/sa/${sa}" \
		-parentID "spiffe://${trust_domain}/node" \
		-selector k8s:ns:cracha-system \
		-selector "k8s:sa:${sa}"
done

# The test workloads: client holds a grant (e2e/manifests/cracha-system.yaml,
# the assignments ConfigMap), unassigned holds none.
for sa in client unassigned; do
	register "spiffe://${trust_domain}/ns/e2e/sa/${sa}" \
		-parentID "spiffe://${trust_domain}/node" \
		-selector k8s:ns:e2e \
		-selector "k8s:sa:${sa}" \
		-jwtSVIDTTL "${jwt_ttl}"
done
