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

# The JWT-SVID lifetime of the test workloads, in seconds. cracha-agent holds
# a pod's token in memory and fetches it again within a minute of its expiry
# (design 7.3). 240 s was chosen for the CSI plugin's kubelet republish
# cadence; e2e/rotation_test.go still assumes it and is rewritten with the
# suite, so the value stays until then.
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

# Crachá's components: cracha-agent presents its X509-SVID to the agent's
# Broker API endpoint, and the broker reads the trust bundle from the
# Workload API, which only answers attested workloads.
for sa in cracha-agent cracha-broker; do
	register "spiffe://${trust_domain}/ns/cracha-system/sa/${sa}" \
		-parentID "spiffe://${trust_domain}/node" \
		-selector k8s:ns:cracha-system \
		-selector "k8s:sa:${sa}"
done

# The test workloads: client holds a grant (e2e/values.yaml, the chart's
# assignments document), unassigned holds none.
for sa in client unassigned; do
	register "spiffe://${trust_domain}/ns/e2e/sa/${sa}" \
		-parentID "spiffe://${trust_domain}/node" \
		-selector k8s:ns:e2e \
		-selector "k8s:sa:${sa}" \
		-jwtSVIDTTL "${jwt_ttl}"
done
