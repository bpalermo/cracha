#!/usr/bin/env bash
# The pinned cosign is the version the bazel_dep says it is. A cosign 2 here
# would read cosign 3 signatures as "no signatures found", so the major matters.
# --- begin runfiles.bash initialization v3 ---
# shellcheck disable=SC1090
set -uo pipefail
set +e
f=bazel_tools/tools/bash/runfiles/runfiles.bash
source "${RUNFILES_DIR:-/dev/null}/$f" 2>/dev/null ||
	source "$(grep -sm1 "^$f " "${RUNFILES_MANIFEST_FILE:-/dev/null}" | cut -f2- -d' ')" 2>/dev/null ||
	source "$0.runfiles/$f" 2>/dev/null ||
	source "$(grep -sm1 "^$f " "$0.runfiles_manifest" | cut -f2- -d' ')" 2>/dev/null ||
	source "$(grep -sm1 "^$f " "$0.exe.runfiles_manifest" | cut -f2- -d' ')" 2>/dev/null ||
	{
		echo >&2 "ERROR: cannot find $f"
		exit 1
	}
f=
set -e
# --- end runfiles.bash initialization v3 ---
cosign="$(rlocation "${COSIGN_RLOCATIONPATH:?set by the BUILD target}")"
workflow="$(rlocation "${WORKFLOW_RLOCATIONPATH:?set by the BUILD target}")"
[ -s "$workflow" ] || {
	echo "grants.yml not found in runfiles (${WORKFLOW_RLOCATIONPATH})" >&2
	exit 1
}

# pinned <key>: the value of `<key>: <value>` in the workflow, once.
pinned() {
	local values
	values="$(sed -nE "s/^[[:space:]]*$1:[[:space:]]*([^[:space:]#]+).*/\1/p" "$workflow")"
	if [ "$(grep -c . <<<"$values")" != 1 ]; then
		echo "grants.yml: want exactly one $1, have: ${values:-none}" >&2
		exit 1
	fi
	echo "$values"
}

want="$("$cosign" version 2>&1 | awk '/^GitVersion:/ {print $2}')"
got="$(pinned COSIGN_VERSION)"
if [ "$got" != "$want" ]; then
	echo "grants.yml pins cosign ${got}, //bazel/cosign is ${want}: move them together" >&2
	exit 1
fi
echo "cosign ${got}"

case "$(uname -s)_$(uname -m)" in
Linux_x86_64) key=COSIGN_SHA256_LINUX_AMD64 ;;
Linux_aarch64) key=COSIGN_SHA256_LINUX_ARM64 ;;
*)
	echo "no sha256 pinned for this host; the version matches"
	exit 0
	;;
esac
sum="$(sha256sum "$cosign" | cut -d' ' -f1)"
got="$(pinned "$key")"
if [ "$got" != "$sum" ]; then
	echo "grants.yml pins ${key} ${got}, the Bazel cosign is ${sum}" >&2
	exit 1
fi
echo "${key} ${sum}"
