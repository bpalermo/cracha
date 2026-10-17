#!/usr/bin/env bash
# Runs the end-to-end suite against a kind cluster.
#
# Builds the images from this checkout, loads them into the kind node, deploys
# SPIRE (e2e/spire.sh), compiles, signs and publishes the grant bundle from
# e2e/grants with the grantc Bazel builds, installs the chart Bazel builds
# from this checkout (charts/cracha, with e2e/values.yaml) and the STS
# stand-in (e2e/manifests) and runs the tests tagged e2e. Creates the cluster
# if it does not exist; a cluster this script created is deleted on exit
# unless E2E_KEEP_CLUSTER=1.
#
# Needs docker, kind, kubectl and openssl on PATH; helm and grantc come from
# Bazel (@helm//:helm, the version MODULE.bazel pins, and //grantc). Extra
# arguments are passed to every bazel invocation, e.g. --config=ci.
set -euo pipefail

cd "$(dirname "$0")/.."

cluster="${KIND_CLUSTER:-cracha-e2e}"
# <image name>=<load target>: the go_image load targets and the names they
# load under (their load_tag), which e2e/values-local.yaml, the STS stand-in
# manifest and the tests use.
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
bundle="$(mktemp -d)"
cleanup() {
	rm -rf "${kubeconfig}" "${certs}" "${bundle}"
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

# Install the chart Bazel builds, with Bazel's pinned helm (no helm on PATH
# needed). e2e/values.yaml is the suite's configuration; values-local.yaml
# points every image at the ones just loaded. The release is created or
# upgraded in place, so a kept cluster is reused.
#
# The chart's TLS mode is left at generated: it makes a CA of its own and
# issues the broker's and the webhook's certificates from it, and the test
# workloads are handed that CA below (SSL_CERT_FILE, not AWS_CA_BUNDLE:
# design 6.5). The CA lives in the Secret cracha-ca, which an upgrade keeps.
bazel build "$@" //charts/cracha:cracha @helm//:helm //grantc
bin="$(bazel info "$@" bazel-bin)"
execroot="$(bazel info "$@" execution_root)"
helm="${execroot}/$(bazel cquery "$@" @helm//:helm --output=files 2>/dev/null)"
grantc="${execroot}/$(bazel cquery "$@" //grantc --output=files 2>/dev/null)"
chart="${bin}/charts/cracha/cracha.tgz"

# The grants, the production way (design 6.2): the bundle is compiled from
# e2e/grants, signed with a throwaway P-256 key, published in the layout the
# broker polls (latest, bundles/<version>/bundle.json and .sig) and handed
# to the broker as a ConfigMap mounted at broker.bundle.source, with the
# public key in the chart's Secret. The version is the content hash grantc
# gives a bundle, which the test reads back from the ConfigMap's latest
# pointer and expects in Cracha-Bundle-Version.
openssl ecparam -name prime256v1 -genkey -noout -out "${bundle}/key.pem"
openssl ec -in "${bundle}/key.pem" -pubout -out "${bundle}/pub.pem" 2>/dev/null
"${grantc}" compile -o "${bundle}/bundle.json" e2e/grants
"${grantc}" sign -key "${bundle}/key.pem" "${bundle}/bundle.json"
"${grantc}" verify -pub "${bundle}/pub.pem" "${bundle}/bundle.json"
"${grantc}" publish -dir "${bundle}/published" "${bundle}/bundle.json"
version="$(sed -n 's/^ *"version": *"\([^"]*\)".*/\1/p' "${bundle}/published/latest")"
[[ -n "${version}" ]] || {
	echo "e2e: no version in ${bundle}/published/latest" >&2
	exit 1
}
kubectl create namespace cracha-system --dry-run=client -o yaml | kubectl apply -f -
kubectl create configmap cracha-e2e-bundle -n cracha-system \
	--from-file=latest="${bundle}/published/latest" \
	--from-file=bundle.json="${bundle}/published/bundles/${version}/bundle.json" \
	--from-file=bundle.json.sig="${bundle}/published/bundles/${version}/bundle.json.sig" \
	--dry-run=client -o yaml | kubectl apply -f -
cat >"${bundle}/values.yaml" <<EOF
# Written by e2e/run.sh: the published bundle's layout in the ConfigMap and
# the key it was signed with. See broker.bundle in e2e/values.yaml.
broker:
  bundle:
    volume:
      configMap:
        name: cracha-e2e-bundle
        items:
          - key: latest
            path: latest
          - key: bundle.json
            path: bundles/${version}/bundle.json
          - key: bundle.json.sig
            path: bundles/${version}/bundle.json.sig
EOF

"${helm}" upgrade --install cracha "${chart}" \
	--namespace cracha-system --create-namespace \
	--values e2e/values.yaml --values e2e/values-local.yaml \
	--values "${bundle}/values.yaml" --set-file broker.bundle.verifyKey="${bundle}/pub.pem" \
	--wait --timeout 300s

# The STS stand-in the broker talks to: a fixture of the suite, not part of
# the chart.
kubectl apply -f e2e/manifests/stsstub.yaml

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

# The test namespace, its identities and the CA its pods trust: the chart's,
# from the Secret it keeps it in.
kubectl apply -f e2e/manifests/e2e.yaml
kubectl get secret cracha-ca -n cracha-system -o jsonpath='{.data.tls\.crt}' | base64 -d >"${certs}/ca.crt"
kubectl create configmap cracha-ca -n e2e --from-file=ca.crt="${certs}/ca.crt" \
	--dry-run=client -o yaml | kubectl apply -f -

# E2E_FILTER runs only the tests whose name matches, for working on one.
tests=()
if [[ -n "${E2E_FILTER:-}" ]]; then
	tests=(--test_filter="${E2E_FILTER}")
fi
bazel test "$@" --config=e2e "${tests[@]}" //e2e/...
