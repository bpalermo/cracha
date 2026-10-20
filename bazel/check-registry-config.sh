#!/usr/bin/env bash
# The registry is ONE setting: bazel/registry.bzl.
#
# Moving registries is only a one-file edit while nothing else spells the
# registry out, and a review cannot be trusted to keep that true: a literal
# pasted into a workflow keeps working until the day a move leaves it pointing
# at the old registry. So this asserts, on every change:
#
#   1. bazel/registry.sh parses the setting.
#   2. charts/cracha/values.yaml takes every component's repository and digest
#      from its image_push target (which gets them from registry.bzl) instead
#      of spelling them out. The values are data, so they cannot be Starlark;
#      the package-time substitution is what derives them, and
#      //charts/cracha:pin_test asserts the result equals image_reference().
#   3. Every image a BUILD file publishes (`image_repository("<name>")`) is
#      one bazel/registry.sh prints as <NAME>_IMAGE: the workflows push, sign
#      and verify what that prints, so an image missing from it is published
#      by nothing.
#   4. No tracked file outside the allow-list contains `<host>/<namespace>`,
#      computed from the setting, not typed here.
#
# The literal hunt runs a positive control first, so it cannot pass by matching
# nothing.
#
# ALLOW-LIST:
#   bazel/registry.bzl             the setting
#   bazel/registry.sh              its usage text
#   bazel/check-registry-config.sh
#   README.md                      install commands people copy
# Documentation that tells a user what to pull (docs/) is not exempt by
# default: add it here, with the reason, when it first needs the literal.
#
# Run from a checkout: the hunt is a `git grep` over the tracked files of the
# repository this script is in (the `lint` job of ci.yml runs it on every
# change; //bazel:check_registry_config_test runs it on fixtures). No network,
# no Bazel. Exit 0 clean, 1 on a violation, 2 when the check itself cannot run.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

fail=0
bad() {
	echo "::error::$*"
	fail=1
}

# --- 1. the setting parses ---------------------------------------------------
if ! host="$(bazel/registry.sh host)" || ! agent="$(bazel/registry.sh ref agent)" ||
	! ns_repo="$(bazel/registry.sh repo agent)" || [ -z "$host" ] || [ -z "$agent" ]; then
	echo "::error::bazel/registry.sh cannot parse bazel/registry.bzl" >&2
	exit 2
fi
namespace="${ns_repo%/agent}"
echo "setting: ${host}/${namespace}"

esc() { printf '%s' "$1" | sed -E 's/[][\.^$*+?(){}|/]/\\&/g'; }

# --- 2. the chart's image defaults are derived --------------------------------
values=charts/cracha/values.yaml
for target in //broker:image_push //agent:image_push //webhook:image_push //access:image_push //bazel/spicedb:image_push; do
	t="$(esc "$target")"
	n_repo="$(grep -cE "^[[:space:]]*repository:[[:space:]]*\"\{@${t}\.repository\}\"[[:space:]]*\$" "$values" || true)"
	n_digest="$(grep -cE "^[[:space:]]*digest:[[:space:]]*\"\{@${t}\.digest\}\"[[:space:]]*\$" "$values" || true)"
	if [ "$n_repo" != 1 ] || [ "$n_digest" != 1 ]; then
		bad "${values} must default one image's repository to \"{@${target}.repository}\" and its digest to \"{@${target}.digest}\" (found ${n_repo} and ${n_digest}) -- that default would not come from bazel/registry.bzl and the pushed digest"
	else
		echo "ok: ${values} derives an image from ${target}"
	fi
done

# --- 3. every published image is in registry.sh's environment ---------------
if ! env_lines="$(bazel/registry.sh)"; then
	echo "::error::bazel/registry.sh cannot print its environment" >&2
	exit 2
fi
components="$(git grep -hoP -- 'image_repository\("\K[a-z0-9._-]+(?="\))' -- '*BUILD.bazel' '*BUILD' | sort -u)"
if [ -z "$components" ]; then
	echo "::error::no BUILD file publishes an image with image_repository(...) -- the search is broken" >&2
	exit 2
fi
for component in $components; do
	key="$(printf '%s' "$component" | tr 'a-z.-' 'A-Z__')_IMAGE"
	want="${key}=${host}/${namespace}/${component}"
	if ! grep -qxF -- "$want" <<<"$env_lines"; then
		bad "a BUILD file publishes image_repository(\"${component}\"), but bazel/registry.sh does not print ${want}: add it, and the image to the lists of ci.yml and publish.yml"
	else
		echo "ok: bazel/registry.sh prints ${key}"
	fi
done

# --- 4. no literal outside the allow-list ------------------------------------
allow=(
	':(exclude)bazel/registry.bzl'
	':(exclude)bazel/registry.sh'
	':(exclude)bazel/check-registry-config.sh'
	# People copy install commands from the README, so it may spell the
	# registry out. Moving registries is bazel/registry.bzl plus this file.
	':(exclude)README.md'
)
pattern="$(esc "${host}/${namespace}")(?![[:alnum:]_.-])"
for probe in "registry: ${host}/${namespace}" "image=${agent}@sha256:0"; do
	if ! printf '%s\n' "$probe" | grep -qP -- "$pattern"; then
		echo "::error::the literal hunt does not match '${probe}' -- the pattern is broken" >&2
		exit 2
	fi
done
hits="$(git grep -nP -- "$pattern" -- . "${allow[@]}")"
rc=$?
case "$rc" in
0)
	bad "the registry is spelled out outside bazel/registry.bzl. Derive it (Bazel: load //bazel:registry.bzl; shell and workflows: bazel/registry.sh), or add the path to the allow-list in bazel/check-registry-config.sh with a reason:"
	printf '%s\n' "$hits" | sed 's/^/  /'
	;;
1) echo "ok: no registry literal outside the allow-list" ;;
*)
	echo "::error::git grep failed (exit ${rc})" >&2
	exit 2
	;;
esac

[ "$fail" -eq 0 ] || exit 1
echo "registry config: one setting, bazel/registry.bzl"
