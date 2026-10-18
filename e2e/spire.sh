#!/usr/bin/env bash
# Deploys SPIRE into the current cluster and registers the identities the
# end-to-end suite needs (see run.sh): Crachá's own components and the test
# workloads of the e2e namespace.
#
# Every identity follows the scheme of docs/design.md, section 4:
# spiffe://<trust-domain>/ns/<namespace>/sa/<serviceaccount>, keyed on the
# pod's namespace and service account. Token lifetimes are SPIRE's defaults:
# nothing in the pod holds a token (design 4.2), so the suite caps nothing.
set -euo pipefail

cd "$(dirname "$0")/.."

trust_domain="cracha.test"

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

# Crachá's components, each with the X.509-SVID of its own service account:
# cracha-agent presents its SVID to the SPIRE agent's Broker API endpoint
# (e2e/spire.yaml authorises that one ID as a broker) and to the broker over
# mTLS; the broker admits the agent's ID and nothing else, and verifies the
# pods' JWT-SVIDs against the trust bundle its Workload API serves.
for sa in cracha-agent cracha-broker; do
	register "spiffe://${trust_domain}/ns/cracha-system/sa/${sa}" \
		-parentID "spiffe://${trust_domain}/node" \
		-selector k8s:ns:cracha-system \
		-selector "k8s:sa:${sa}"
done

# The webhook serves the apiserver with its X.509-SVID, which the apiserver
# verifies by the Service name (design 7.5): the entry carries that name as
# a DNS SAN, the short form the webhook configuration uses and the full one
# for good measure (design 4.2; a ClusterSPIFFEID's dnsNameTemplates in
# production).
register "spiffe://${trust_domain}/ns/cracha-system/sa/cracha-webhook" \
	-parentID "spiffe://${trust_domain}/node" \
	-selector k8s:ns:cracha-system \
	-selector k8s:sa:cracha-webhook \
	-dns cracha-webhook.cracha-system.svc \
	-dns cracha-webhook.cracha-system.svc.cluster.local

# The test workloads: client holds a grant (e2e/values.yaml, the chart's
# assignments document), unassigned holds none. The agent fetches their
# JWT-SVIDs through the Broker API, with the server's default lifetime.
for sa in client unassigned; do
	register "spiffe://${trust_domain}/ns/e2e/sa/${sa}" \
		-parentID "spiffe://${trust_domain}/node" \
		-selector k8s:ns:e2e \
		-selector "k8s:sa:${sa}"
done
