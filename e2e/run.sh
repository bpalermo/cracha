#!/usr/bin/env bash
# Runs the end-to-end suite against a kind cluster.
#
# Builds the images from this checkout, loads them into the kind node, deploys
# SPIRE (e2e/spire.sh) and Crachá (e2e/manifests) and runs the tests tagged
# e2e. Creates the cluster if it does not exist; a cluster this script created
# is deleted on exit unless E2E_KEEP_CLUSTER=1.
#
# Needs docker, kind, kubectl and openssl on PATH. Extra arguments are passed
# to every bazel invocation, e.g. --config=ci.
set -euo pipefail

cd "$(dirname "$0")/.."

cluster="${KIND_CLUSTER:-cracha-e2e}"
# <image name>=<load target>: the go_image load targets and the names they
# load under (their load_tag), which the manifests and the tests use.
images=(
	cracha-broker=//broker:image_load
	cracha-csi=//csi:image_load
	cracha-webhook=//webhook:image_load
	cracha-e2e-stsstub=//e2e/stsstub:image_load
	cracha-e2e-client=//e2e/client:image_load
)

created=0
kubeconfig="$(mktemp)"
certs="$(mktemp -d)"
cleanup() {
	rm -rf "${kubeconfig}" "${certs}"
	if [[ "${created}" == 1 && "${E2E_KEEP_CLUSTER:-0}" != 1 ]]; then
		kind delete cluster --name "${cluster}"
	fi
}
trap cleanup EXIT

if ! kind get clusters | grep -qx "${cluster}"; then
	kind create cluster --name "${cluster}" --wait 120s
	created=1
fi

# The tests use the ambient kubeconfig; point it at this cluster only.
kind get kubeconfig --name "${cluster}" >"${kubeconfig}"
export KUBECONFIG="${kubeconfig}"

# The images, built here and loaded into the node. The load target loads the
# host platform's manifest of the index into the local daemon.
for image in "${images[@]}"; do
	bazel run "$@" "${image#*=}"
done
for image in "${images[@]}"; do
	kind load docker-image --name "${cluster}" "localhost/${image%%=*}:e2e"
done

# The identity issuer, with the entries of every component and test workload.
e2e/spire.sh

# A CA of the suite's own, trusted by the client pods (SSL_CERT_FILE, not
# AWS_CA_BUNDLE: section 6.5) and by the apiserver for the webhook. The
# broker's and the webhook's certificates are issued by it for their Service
# names. Regenerated on every run; the Secrets are replaced in place.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
	-subj "/CN=cracha e2e CA" -keyout "${certs}/ca.key" -out "${certs}/ca.crt" 2>/dev/null
for component in broker webhook; do
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
		-subj "/CN=cracha-${component}" \
		-addext "subjectAltName=DNS:cracha-${component}.cracha-system.svc,DNS:cracha-${component}.cracha-system.svc.cluster.local" \
		-CA "${certs}/ca.crt" -CAkey "${certs}/ca.key" \
		-keyout "${certs}/${component}.key" -out "${certs}/${component}.crt" 2>/dev/null
done

kubectl create namespace cracha-system --dry-run=client -o yaml | kubectl apply -f -
for component in broker webhook; do
	kubectl create secret tls "cracha-${component}-tls" -n cracha-system \
		--cert="${certs}/${component}.crt" --key="${certs}/${component}.key" \
		--dry-run=client -o yaml | kubectl apply -f -
done
kubectl apply -f e2e/manifests/cracha-system.yaml

# The image tag is fixed, so on a kept cluster restart every workload to make
# it pick up the images just loaded. The STS stub starts with an empty record
# either way.
workloads=(daemonset/cracha-csi deployment/cracha-broker deployment/cracha-webhook deployment/cracha-stsstub)
for workload in "${workloads[@]}"; do
	kubectl rollout restart "${workload}" -n cracha-system
done
for workload in "${workloads[@]}"; do
	kubectl rollout status "${workload}" -n cracha-system --timeout=300s
done

# The webhook is registered only once it answers: with failurePolicy Fail,
# registering it earlier would refuse every pod of the namespaces it covers.
ca_bundle="$(base64 -w0 <"${certs}/ca.crt")"
sed "s|\${CA_BUNDLE}|${ca_bundle}|" e2e/manifests/webhook.yaml | kubectl apply -f -

# The test namespace, its identities and the CA its pods trust.
kubectl apply -f e2e/manifests/e2e.yaml
kubectl create configmap cracha-ca -n e2e --from-file=ca.crt="${certs}/ca.crt" \
	--dry-run=client -o yaml | kubectl apply -f -

# E2E_FILTER runs only the tests whose name matches, for working on one.
tests=()
if [[ -n "${E2E_FILTER:-}" ]]; then
	tests=(--test_filter="${E2E_FILTER}")
fi
bazel test "$@" --config=e2e "${tests[@]}" //e2e/...
