#!/usr/bin/env bash
# What check-registry-config.sh decides, on fixture checkouts: a tree whose
# only registry literal is the setting passes; a literal anywhere else, a chart
# default that is not derived from its image_push, and a setting the parser
# cannot read each fail the way the script promises (1, 1 and 2).
#
# The script hunts with `git grep`, so each fixture is a git repository with
# the real scripts, the real setting and the real values.yaml committed.
set -euo pipefail

src="$(cd "$(dirname "$0")" && pwd)"
[ -r "${src}/check-registry-config.sh" ] || src="${TEST_SRCDIR}/_main/bazel"
values="${src}/../charts/cracha/values.yaml"

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1

# fixture <dir>: a checkout with the scripts, the setting and the chart values.
fixture() {
	mkdir -p "$1/bazel" "$1/charts/cracha"
	cp "${src}/registry.bzl" "${src}/registry.sh" "${src}/check-registry-config.sh" "$1/bazel/"
	cp "${values}" "$1/charts/cracha/values.yaml"
	git -C "$1" init --quiet .
	git -C "$1" config user.email test@example.com
	git -C "$1" config user.name test
}

# commit <dir>: everything in the tree, tracked.
commit() {
	git -C "$1" add -A
	git -C "$1" commit --quiet --allow-empty -m fixture
}

host="$("${src}/registry.sh" host)"
namespace="$("${src}/registry.sh" repo agent)"
namespace="${namespace%/agent}"

fail=0
expect() {
	local dir="$1" want="$2" what="$3" rc=0 out
	out="$(bash "${dir}/bazel/check-registry-config.sh" 2>&1)" || rc=$?
	if [ "${rc}" != "${want}" ]; then
		echo "FAIL: ${what}: exit ${rc}, want ${want}" >&2
		printf '%s\n' "${out}" | sed 's/^/  /' >&2
		fail=1
	fi
}

clean="${work}/clean"
fixture "${clean}"
commit "${clean}"
expect "${clean}" 0 "the setting alone"

literal="${work}/literal"
fixture "${literal}"
printf 'image: %s/%s/agent:dev\n' "${host}" "${namespace}" >"${literal}/manifest.yaml"
commit "${literal}"
expect "${literal}" 1 "a registry literal in a tracked file"

# An untracked file is not published, so it is not hunted: the hunt is over
# what a commit contains.
untracked="${work}/untracked"
fixture "${untracked}"
commit "${untracked}"
printf 'image: %s/%s/agent:dev\n' "${host}" "${namespace}" >"${untracked}/scratch.yaml"
expect "${untracked}" 0 "a registry literal in an untracked file"

readme="${work}/readme"
fixture "${readme}"
printf 'helm install cracha oci://%s/%s/cracha\n' "${host}" "${namespace}" >"${readme}/README.md"
commit "${readme}"
expect "${readme}" 0 "the README, which is allowed the literal"

# A longer name that merely starts with the namespace is not the namespace.
prefix="${work}/prefix"
fixture "${prefix}"
printf 'image: %s/%s-other/agent:dev\n' "${host}" "${namespace}" >"${prefix}/manifest.yaml"
commit "${prefix}"
expect "${prefix}" 0 "a namespace that only starts with ours"

spelled="${work}/spelled"
fixture "${spelled}"
sed -i "s|\"{@//agent:image_push.repository}\"|\"${host}/${namespace}/agent\"|" "${spelled}/charts/cracha/values.yaml"
commit "${spelled}"
expect "${spelled}" 1 "a chart default spelled out instead of derived"

unparsable="${work}/unparsable"
fixture "${unparsable}"
printf 'IMAGE_REGISTRY = "%s"\n' "${host}" >>"${unparsable}/bazel/registry.bzl"
commit "${unparsable}"
expect "${unparsable}" 2 "a setting assigned twice"

[ "${fail}" = 0 ]
echo "check-registry-config: the literal hunt and the derived defaults decide as promised"
