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
# E2E_AUTHZ chooses the broker's authorization backend: static (the default)
# reads the assignments grantc compiled from e2e/grants and published with
# the bundle (broker.assignments.source published); spicedb installs the
# chart with e2e/values-spicedb.yaml on top, which has it deploy SpiceDB on
# its memory datastore behind its SPIFFE gateway, with a preshared key made
# here that only the SpiceDB pod sees. The suite reaches the gateway from
# the host through a port-forward, with X.509-SVIDs the SPIRE server mints
# here for the identities it plays (spire-server x509 mint): the
# reconciler, built from this checkout, writes the schema with its own, and
# the tests write the suite's relationships with the access identity's and
# probe the gateway's method table with all of them. The tests learn the
# mode, the port-forward and the SVIDs from the environment (.bazelrc's
# test:e2e); those that need SpiceDB skip in static mode.
#
# E2E_ENROL chooses how the agent enrols a pod (design 7.2): init (the
# default, the chart's) has the webhook inject the cracha-enrol init
# container; cni installs the chart with e2e/values-cni.yaml on top, which
# switches the agent to the cracha-cni plugin. The tests learn the mode the
# same way; those that look at one mode's wiring skip in the other.
#
# Nothing is trusted or mounted by the test workloads: the broker and the
# webhook serve their X.509-SVIDs from SPIRE, the agent reaches the broker
# over SPIFFE mTLS, and a pod sees only the loopback listener the agent
# binds in its network namespace, over plain HTTP. There is no CA to hand
# out.
#
# E2E_CHART=<version> runs the suite against a published chart instead of
# the one built here: the package is pulled from the registry
# bazel/registry.bzl names, at that version, with the same pinned helm, and
# installed as it is, with the images it pins (public, on the registry; the
# node pulls them). The checkout's broker, agent and webhook images are then
# neither built nor loaded and e2e/values-local.yaml is not passed; the
# suite's own images (e2e/client, e2e/stsstub) still are. The log starts
# with the chart's digest and the image references it pins, so it says what
# was tested. Everything else is the same: the suite, SPIRE, the bundle and
# the STS stand-in come from this checkout, so run it from a checkout whose
# suite matches the chart.
#
# Needs docker, kind, kubectl and openssl on PATH (the cluster is created
# from the node image in e2e/kind-node-image); helm, grantc and the
# reconciler come from Bazel (@helm//:helm, the version MODULE.bazel pins,
# //grantc and //reconciler). Extra arguments are passed to every bazel
# invocation, e.g. --config=ci.
set -euo pipefail

cd "$(dirname "$0")/.."

cluster="${KIND_CLUSTER:-cracha-e2e}"
authz="${E2E_AUTHZ:-static}"
enrol="${E2E_ENROL:-init}"
chart_version="${E2E_CHART:-}"
case "${authz}" in
static | spicedb) ;;
*)
	echo "e2e: E2E_AUTHZ must be static or spicedb, not '${authz}'" >&2
	exit 2
	;;
esac
case "${enrol}" in
init | cni) ;;
*)
	echo "e2e: E2E_ENROL must be init or cni, not '${enrol}'" >&2
	exit 2
	;;
esac
# <image name>=<load target>: the go_image load targets and the names they
# load under (their load_tag), which e2e/values-local.yaml, the STS stand-in
# manifest and the tests use. Against a published chart only the suite's
# own: the chart's images are the ones it pins.
images=(
	cracha-e2e-stsstub=//e2e/stsstub:image_load
	cracha-e2e-client=//e2e/client:image_load
)
if [[ -z "${chart_version}" ]]; then
	images=(
		cracha-broker=//broker:image_load
		cracha-agent=//agent:image_load
		cracha-webhook=//webhook:image_load
		cracha-access=//access:image_load
		"${images[@]}"
	)
fi

created=0
kubeconfig="$(mktemp)"
bundle="$(mktemp -d)"
spicedb="$(mktemp -d)"
pulled="$(mktemp -d)"
port_forwards=()
forwarded=""
cleanup() {
	for port_forward in "${port_forwards[@]}"; do
		# The loop first, then the kubectl it is waiting for.
		children="$(pgrep -P "${port_forward}" || true)"
		kill "${port_forward}" 2>/dev/null || true
		if [[ -n "${children}" ]]; then
			# shellcheck disable=SC2086 # one PID per word
			kill ${children} 2>/dev/null || true
		fi
	done
	rm -rf "${kubeconfig}" "${bundle}" "${spicedb}" "${pulled}"
	if [[ "${created}" == 1 && "${E2E_KEEP_CLUSTER:-0}" != 1 ]]; then
		kind delete cluster --name "${cluster}"
	fi
}
trap cleanup EXIT

# The tools from Bazel and the chart: the one Bazel builds from this
# checkout, installed below with the images loaded here (values-local.yaml),
# or, with E2E_CHART, the published one at that version, pulled with the
# same pinned helm (no helm on PATH needed) and installed with the images it
# pins. helm prints the digest of the manifest it pulled; that and the pins
# (read the way the publish workflow's check reads them, bazel/chart-pin.sh)
# are the record of what was tested, first in the log and before a cluster
# exists.
chart_targets=(//charts/cracha:cracha)
if [[ -n "${chart_version}" ]]; then
	chart_targets=()
fi
bazel build "$@" "${chart_targets[@]}" @helm//:helm //grantc //reconciler
bin="$(bazel info "$@" bazel-bin)"
execroot="$(bazel info "$@" execution_root)"
helm="${execroot}/$(bazel cquery "$@" @helm//:helm --output=files 2>/dev/null)"
grantc="${execroot}/$(bazel cquery "$@" //grantc --output=files 2>/dev/null)"
reconciler="${execroot}/$(bazel cquery "$@" //reconciler --output=files 2>/dev/null)"
chart_values=(--values e2e/values-local.yaml)
chart="${bin}/charts/cracha/cracha.tgz"
if [[ -n "${chart_version}" ]]; then
	chart_values=()
	repository="$(bazel/registry.sh chart-ref cracha)"
	"${helm}" pull "oci://${repository}" --version "${chart_version}" --destination "${pulled}" 2>&1 | tee "${pulled}/pull.log"
	digest="$(sed -n 's/^Digest: \(sha256:[0-9a-f]\{64\}\)$/\1/p' "${pulled}/pull.log" | tail -1)"
	chart="${pulled}/cracha-${chart_version}.tgz"
	if [[ -z "${digest}" || ! -s "${chart}" ]]; then
		echo "e2e: helm pull of oci://${repository} ${chart_version} reported no digest or left no package at ${chart}" >&2
		exit 1
	fi
	echo "e2e: testing the published chart ${repository}:${chart_version}@${digest}"
	for component in broker agent webhook; do
		ref="$(bazel/registry.sh ref "${component}")"
		echo "e2e: the chart pins ${ref}@$(bazel/chart-pin.sh "${chart}" cracha "${ref}")"
	done
fi

# The node image is e2e/kind-node-image, the one ci.yml gives
# helm/kind-action too. An existing cluster (one kept with E2E_KEEP_CLUSTER=1,
# or the one CI creates) is reused as it is, whatever image it was made from.
if ! kind get clusters | grep -qx "${cluster}"; then
	node_image="$(grep -v '^#' e2e/kind-node-image)"
	kind create cluster --name "${cluster}" --image "${node_image}" --wait 120s
	created=1
fi

# The tests use the ambient kubeconfig; point it at this cluster only.
kind get kubeconfig --name "${cluster}" >"${kubeconfig}"
export KUBECONFIG="${kubeconfig}"

# A kept cluster that ran in cni mode has cracha-cni chained in its node's
# conflist; the helm upgrade below to init mode has the agent's preStop
# hook take it off the node (design 7.2), so the cluster switches modes
# through the chart like any install.

# The images, built here and loaded into the node. The load target loads the
# host platform's manifest of the index into the local daemon.
for image in "${images[@]}"; do
	bazel run "$@" "${image#*=}"
done
for image in "${images[@]}"; do
	kind load docker-image --name "${cluster}" "localhost/${image%%=*}:e2e"
done

# The identity issuer, with the entries of every component and test workload.
# The SPIRE agent runs as 1000:1000, as on a real install of the SPIRE chart,
# so the directories it puts its sockets in on the node are made its own
# first (a hostPath DirectoryOrCreate is created root-owned).
for node in $(kind get nodes --name "${cluster}"); do
	docker exec "${node}" sh -c 'mkdir -p /run/spire/agent-sockets /run/spire/broker-sockets && chown 1000:1000 /run/spire/agent-sockets /run/spire/broker-sockets'
done
e2e/spire.sh

# The grants and the assignments, the production way (design 6.2): grantc
# compiles e2e/grants into the bundle and, beside it, the assignments of
# its Services and Assignments, signs both with a throwaway P-256 key,
# publishes them as one version in the layout the broker polls (latest,
# bundles/<version>/bundle.json, assignments.json and their .sig) and hands
# the publication to the broker as a ConfigMap mounted at
# broker.bundle.source, with the public key in the chart's Secret. The
# version is the content hash grantc gives a compilation, which the tests
# read back from the ConfigMap's latest pointer and expect in
# Cracha-Bundle-Version. The volume also lays out, optionally, a second
# version, e2e-republished, under keys the ConfigMap does not have yet:
# the test that republishes the tree (published_test.go) compiles it under
# that version with the private key (E2E_BUNDLE_KEY) and adds the keys, so
# the new version reaches the running broker without a change to its pod.
openssl ecparam -name prime256v1 -genkey -noout -out "${bundle}/key.pem"
openssl ec -in "${bundle}/key.pem" -pubout -out "${bundle}/pub.pem" 2>/dev/null
"${grantc}" compile -o "${bundle}/bundle.json" e2e/grants
"${grantc}" sign -key "${bundle}/key.pem" "${bundle}/bundle.json" "${bundle}/assignments.json"
"${grantc}" verify -pub "${bundle}/pub.pem" "${bundle}/bundle.json" "${bundle}/assignments.json"
"${grantc}" publish -dir "${bundle}/published" "${bundle}/bundle.json" "${bundle}/assignments.json"
version="$(sed -n 's/^ *"version": *"\([^"]*\)".*/\1/p' "${bundle}/published/latest")"
[[ -n "${version}" ]] || {
	echo "e2e: no version in ${bundle}/published/latest" >&2
	exit 1
}
republished=e2e-republished
published="${bundle}/published/bundles/${version}"
kubectl create namespace cracha-system --dry-run=client -o yaml | kubectl apply -f -
kubectl create configmap cracha-e2e-bundle -n cracha-system \
	--from-file=latest="${bundle}/published/latest" \
	--from-file=bundle.json="${published}/bundle.json" \
	--from-file=bundle.json.sig="${published}/bundle.json.sig" \
	--from-file=assignments.json="${published}/assignments.json" \
	--from-file=assignments.json.sig="${published}/assignments.json.sig" \
	--dry-run=client -o yaml | kubectl apply -f -
{
	cat <<EOF
# Written by e2e/run.sh: the published version's layout in the ConfigMap,
# and the slot of the version a test republishes, whose keys are absent
# until it does (optional). See broker.bundle in e2e/values.yaml.
broker:
  bundle:
    volume:
      configMap:
        name: cracha-e2e-bundle
        optional: true
        items:
          - key: latest
            path: latest
EOF
	for file in bundle.json bundle.json.sig assignments.json assignments.json.sig; do
		cat <<EOF
          - key: ${file}
            path: bundles/${version}/${file}
          - key: ${republished}.${file}
            path: bundles/${republished}/${file}
EOF
	done
} >"${bundle}/values.yaml"
export E2E_BUNDLE_KEY="${bundle}/key.pem"

# The authorization backend. In spicedb mode the chart deploys SpiceDB, on
# its memory datastore, behind the gateway; its preshared key is made here,
# in a Secret only the SpiceDB pod mounts. The schema and the suite's
# relationships are written once the release is up (below).
authz_values=()
if [[ "${authz}" == spicedb ]]; then
	# One line, no newline: the gateway sends it as a header value.
	openssl rand -hex 32 | tr -d "\n" >"${spicedb}/token"
	kubectl create secret generic cracha-e2e-spicedb -n cracha-system \
		--from-file=token="${spicedb}/token" --dry-run=client -o yaml | kubectl apply -f -
	rm -f "${spicedb}/token"
	authz_values=(--values e2e/values-spicedb.yaml)
fi
export E2E_AUTHZ="${authz}"

# The enrolment mode: the chart's default is init; cni is one values file.
enrol_values=()
if [[ "${enrol}" == cni ]]; then
	enrol_values=(--values e2e/values-cni.yaml)
fi
export E2E_ENROL="${enrol}"
# The helm and the chart package the release is installed from, for the
# test that switches the release's mode with helm upgrade and back
# (enrol_test.go).
export E2E_HELM="${helm}" E2E_CHART_PACKAGE="${chart}"

# Install the chart. e2e/values.yaml is the suite's configuration. The
# release is created or upgraded in place, so a kept cluster is reused.
# --wait holds until every workload is ready, which for the webhook means
# it has published its trust bundle into its own configuration (design
# 7.5): from here on the apiserver can reach it.
"${helm}" upgrade --install cracha "${chart}" \
	--namespace cracha-system --create-namespace \
	--values e2e/values.yaml "${chart_values[@]}" \
	--values "${bundle}/values.yaml" --set-file broker.bundle.verifyKey="${bundle}/pub.pem" \
	"${authz_values[@]}" "${enrol_values[@]}" \
	--wait --timeout 300s

# The STS stand-in the broker talks to: a fixture of the suite, not part of
# the chart.
kubectl apply -f e2e/manifests/stsstub.yaml

# The image tag is fixed, so on a kept cluster restart every workload to make
# it pick up the images just loaded (against a published chart its workloads
# are pinned by digest and the restart changes nothing). The STS stub starts
# with an empty record either way.
# In spicedb mode SpiceDB restarts first, which empties its memory
# datastore and has it read the key just made (the schema is written
# after), so that the broker restarted next connects to the new pod.
if [[ "${authz}" == spicedb ]]; then
	kubectl rollout restart deployment/cracha-spicedb -n cracha-system
	kubectl rollout status deployment/cracha-spicedb -n cracha-system --timeout=300s
fi
workloads=(daemonset/cracha-agent deployment/cracha-broker deployment/cracha-webhook deployment/cracha-stsstub)
if [[ "${authz}" == spicedb ]]; then
	workloads+=(deployment/cracha-access)
fi
for workload in "${workloads[@]}"; do
	kubectl rollout restart "${workload}" -n cracha-system
done
for workload in "${workloads[@]}"; do
	kubectl rollout status "${workload}" -n cracha-system --timeout=300s
done

# The test namespace and its identities.
kubectl apply -f e2e/manifests/e2e.yaml

# forward <service> <port> keeps a port-forward to the service of
# cracha-system open for the tests, on a local port kubectl picks, and sets
# forwarded to that port. kubectl port-forward ends at the first connection the
# pod side resets, which a refused handshake does: it is started again, on
# the port it picked the first time.
forward() {
	local svc="$1" remote="$2" log="${spicedb}/port-forward-$1.log" port=""
	(
		target=":${remote}"
		while true; do
			kubectl port-forward -n cracha-system "svc/${svc}" "${target}" >>"${log}" 2>&1 || true
			picked="$(sed -n "s/^Forwarding from 127\.0\.0\.1:\([0-9]*\) -> ${remote}\$/\1/p" "${log}" | head -1)"
			if [[ -n "${picked}" ]]; then
				target="${picked}:${remote}"
			fi
			sleep 0.5
		done
	) >/dev/null 2>&1 &
	port_forwards+=($!)
	for _ in $(seq 1 60); do
		port="$(sed -n "s/^Forwarding from 127\.0\.0\.1:\([0-9]*\) -> ${remote}\$/\1/p" "${log}" 2>/dev/null | head -1)"
		if [[ -n "${port}" ]]; then
			forwarded="${port}"
			return
		fi
		sleep 0.5
	done
	echo "e2e: kubectl port-forward to ${svc} did not report a port:" >&2
	cat "${log}" >&2
	exit 1
}

# SpiceDB's gateway, from the host: a port-forward kubectl picks a local
# port for, which stays open for the tests, and an X.509-SVID for each
# identity the suite plays, minted by the SPIRE server: the three the
# gateway admits, under the release's service accounts (the reconciler's
# runs nowhere: it is the identity of whoever writes the schema, CI or an
# operator), and one it does not. Each is a directory of svid.pem, key.pem
# and bundle.pem, the shape cracha-reconciler's -svid, -svid-key and
# -bundle take. The reconciler writes the schema; the suite writes its
# relationships as the access identity (e2e/spicedb_access_test.go).
if [[ "${authz}" == spicedb ]]; then
	forward cracha-spicedb 50051
	spicedb_endpoint="127.0.0.1:${forwarded}"
	# cracha-access's API, which the access tests call with the CLI.
	forward cracha-access 8443
	access_endpoint="127.0.0.1:${forwarded}"
	trust_domain=cracha.test
	mint() {
		local dir="${spicedb}/svids/$1"
		mkdir -p "${dir}"
		kubectl exec -n spire deployment/spire-server -- \
			/opt/spire/bin/spire-server x509 mint -spiffeID "spiffe://${trust_domain}/$2" -ttl 1h >"${dir}/minted"
		awk -v dir="${dir}" '
			/^X509-SVID:/ { out = dir "/svid.pem"; next }
			/^Private key:/ { out = dir "/key.pem"; next }
			/^Root CAs:/ { out = dir "/bundle.pem"; next }
			out != "" && NF { print > out }
		' "${dir}/minted"
		for file in svid.pem key.pem bundle.pem; do
			[[ -s "${dir}/${file}" ]] || {
				echo "e2e: spire-server x509 mint gave no ${file} for $2:" >&2
				cat "${dir}/minted" >&2
				exit 1
			}
		done
	}
	mint broker ns/cracha-system/sa/cracha-broker
	mint access ns/cracha-system/sa/cracha-access
	mint reconciler ns/cracha-system/sa/cracha-reconciler
	mint intruder ns/e2e/sa/intruder
	# The callers of cracha-access: a target's owner, its approver, and
	# a workload that is neither (e2e/write_path_test.go).
	mint access-owner ns/e2e/sa/access-owner
	mint access-approver ns/e2e/sa/access-approver
	mint access-stranger ns/e2e/sa/access-stranger
	"${reconciler}" schema -endpoint "${spicedb_endpoint}" \
		-server-spiffe-id "spiffe://${trust_domain}/ns/cracha-system/sa/cracha-spicedb" \
		-svid "${spicedb}/svids/reconciler/svid.pem" -svid-key "${spicedb}/svids/reconciler/key.pem" \
		-bundle "${spicedb}/svids/reconciler/bundle.pem"
	export E2E_SPICEDB_ENDPOINT="${spicedb_endpoint}" E2E_SPICEDB_SVIDS="${spicedb}/svids" E2E_ACCESS_ENDPOINT="${access_endpoint}"
fi

# E2E_FILTER runs only the tests whose name matches, for working on one.
tests=()
if [[ -n "${E2E_FILTER:-}" ]]; then
	tests=(--test_filter="${E2E_FILTER}")
fi
bazel test "$@" --config=e2e "${tests[@]}" //e2e/...
