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
# Checks each grantc release binary (//grantc:grantc_<os>_<arch>) by its
# header: an ELF or Mach-O executable of the platform it is named for, and on
# linux one with no program interpreter, so static. The arguments are
# <os>_<arch>=<rlocationpath>. The binary of the host's platform is
# also run.

# u <file> <offset> <bytes>: the little-endian unsigned integer there.
u() {
	od -An -tu"$3" -j"$2" -N"$3" "$1" | tr -d ' \n'
}

# hex <file> <offset> <bytes>: the bytes there, in hex.
hex() {
	od -An -tx1 -j"$2" -N"$3" "$1" | tr -d ' \n'
}

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

check_elf() {
	local name="$1" file="$2" machine="$3" phoff phentsize phnum i type
	[ "$(hex "$file" 0 5)" = "7f454c4602" ] || fail "${name}: not a 64-bit ELF file"
	[ "$(u "$file" 16 2)" = 2 ] || fail "${name}: not an executable (ET_EXEC)"
	[ "$(u "$file" 18 2)" = "$machine" ] || fail "${name}: machine $(u "$file" 18 2), want ${machine}"
	phoff="$(u "$file" 32 8)"
	phentsize="$(u "$file" 54 2)"
	phnum="$(u "$file" 56 2)"
	for ((i = 0; i < phnum; i++)); do
		type="$(u "$file" $((phoff + i * phentsize)) 4)"
		# PT_INTERP: a dynamically linked executable names its loader.
		[ "$type" != 3 ] || fail "${name}: has a program interpreter, so it is not static"
	done
}

check_macho() {
	local name="$1" file="$2" cputype="$3"
	[ "$(hex "$file" 0 4)" = "cffaedfe" ] || fail "${name}: not a 64-bit Mach-O file"
	[ "$(u "$file" 4 4)" = "$cputype" ] || fail "${name}: cputype $(u "$file" 4 4), want ${cputype}"
	# MH_EXECUTE
	[ "$(u "$file" 12 4)" = 2 ] || fail "${name}: not an executable (MH_EXECUTE)"
}

host="$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m)"
case "$host" in
linux_x86_64) host=linux_amd64 ;;
linux_aarch64) host=linux_arm64 ;;
darwin_arm64) ;;
*) host="" ;;
esac

[ "$#" -gt 0 ] || fail "no binaries given"
for arg in "$@"; do
	platform="${arg%%=*}"
	path="${arg#*=}"
	file="$(rlocation "$path")"
	[ -n "$file" ] && [ -s "$file" ] || fail "${platform}: ${path} not found in runfiles"
	case "$platform" in
	linux_amd64) check_elf "$platform" "$file" 62 ;;          # EM_X86_64
	linux_arm64) check_elf "$platform" "$file" 183 ;;         # EM_AARCH64
	darwin_arm64) check_macho "$platform" "$file" 16777228 ;; # CPU_TYPE_ARM64
	*) fail "unknown platform ${platform}" ;;
	esac
	if [ "$platform" = "$host" ]; then
		out="$("$file" --version)" || fail "${platform}: --version failed"
		[[ "$out" == "cracha-grantc "* ]] || fail "${platform}: --version printed '${out}'"
		echo "${platform}: ${out}"
	fi
	echo "ok ${platform}"
done
