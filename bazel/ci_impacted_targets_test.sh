#!/usr/bin/env bash
# The decision of ci-impacted-targets.sh after bazel-diff: `classify` turns
# an impacted list and the three candidate lists into impacted_build.txt,
# impacted_test.txt, impacted_e2e.txt and the flags has_any, has_test and
# has_e2e. Fed with fixture lists, so the logic is covered without bazel-diff,
# Bazel or a cluster.
set -euo pipefail

script="$(cd "$(dirname "$0")" && pwd)/ci-impacted-targets.sh"
[ -r "${script}" ] || script="${TEST_SRCDIR}/_main/bazel/ci-impacted-targets.sh"
# The script is linted on its own, through //bazel:scripts.
# shellcheck source=/dev/null
source "${script}"

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

# The candidate lists, as the queries would answer them: the buildable rules
# (no `manual` rule, so no //:gazelle), the tests `bazel test //...` runs (no
# e2e test) and the e2e-relevant set.
cat >"${work}/rules.txt" <<'EOF'
//broker:broker
//broker:broker_test
//broker:image_load
//broker:image_push
//charts/cracha:cracha
//charts/cracha:pin_test
//common/idenc:idenc
//common/idenc:idenc_test
//agent:agent
//agent:image_load
//agent:image_push
//agent/internal/listener:listener
//agent/internal/listener:listener_test
//e2e:e2e_test
//e2e:scripts
//e2e/stsstub:image_load
//webhook:image_load
EOF
cat >"${work}/tests.txt" <<'EOF'
//broker:broker_test
//charts/cracha:pin_test
//common/idenc:idenc_test
//agent/internal/listener:listener_test
EOF
cat >"${work}/e2e.txt" <<'EOF'
//broker:image_load
//charts/cracha:cracha
//agent:image_load
//e2e:e2e_test
//e2e:scripts
//e2e/stsstub:image_load
//webhook:image_load
EOF

fail=0
# expect <case> <impacted lines> <want build> <want test> <want e2e>: runs
# classify over the fixture lists and compares the three lists and flags.
# The lists are given one label per line, as bazel-diff sorts them.
expect() {
	local name="$1" impacted="$2" want_build="$3" want_test="$4" want_e2e="$5"
	local out="${work}/${name}" want_any want_has_test want_has_e2e
	mkdir -p "${out}"
	printf '%s' "${impacted}" >"${out}/impacted.txt"
	has_any='' has_test='' has_e2e=''
	if ! classify "${out}/impacted.txt" "${work}/rules.txt" "${work}/tests.txt" "${work}/e2e.txt" "${out}"; then
		echo "FAIL: ${name}: classify failed" >&2
		fail=1
		return
	fi
	check_list "${name}" impacted_build.txt "${out}" "${want_build}"
	check_list "${name}" impacted_test.txt "${out}" "${want_test}"
	check_list "${name}" impacted_e2e.txt "${out}" "${want_e2e}"
	want_any=false
	[ -n "${want_build}" ] && want_any=true
	want_has_test=false
	[ -n "${want_test}" ] && want_has_test=true
	want_has_e2e=false
	[ -n "${want_e2e}" ] && want_has_e2e=true
	check_flag "${name}" has_any "${has_any}" "${want_any}"
	check_flag "${name}" has_test "${has_test}" "${want_has_test}"
	check_flag "${name}" has_e2e "${has_e2e}" "${want_has_e2e}"
}
check_list() { # case file dir want
	local got
	got="$(cat "$3/$2")"
	if [ "${got}" != "$4" ]; then
		echo "FAIL: $1: $2 is:" >&2
		sed 's/^/    /' "$3/$2" >&2
		echo "  want:" >&2
		printf '%s\n' "$4" | sed 's/^/    /' >&2
		fail=1
	fi
}
check_flag() { # case name got want
	if [ "$3" != "$4" ]; then
		echo "FAIL: $1: $2 is '$3', want '$4'" >&2
		fail=1
	fi
}

# Nothing impacted (a documentation-only change): every list empty, every
# flag false, and it is the classification saying so, not a failure.
expect nothing "" "" "" ""

# A change under agent/: its library, binary, test and image, the chart that
# pins the image, and the e2e test through the image. Source-file labels
# (//agent:main.go) and a `manual` rule (//:gazelle) are in no candidate list
# and are dropped; the e2e test is a rule to build but not a test to run.
expect agent "//:gazelle
//charts/cracha:cracha
//agent:agent
//agent:image_index
//agent:image_load
//agent:image_push
//agent:main.go
//agent/internal/listener:listener
//agent/internal/listener:listener_test
//e2e:e2e_test
" "//charts/cracha:cracha
//agent:agent
//agent:image_load
//agent:image_push
//agent/internal/listener:listener
//agent/internal/listener:listener_test
//e2e:e2e_test" "//agent/internal/listener:listener_test" "//charts/cracha:cracha
//agent:image_load
//e2e:e2e_test"

# A unit test and its library only: built and tested, no e2e.
expect unit "//common/idenc:idenc
//common/idenc:idenc_test
" "//common/idenc:idenc
//common/idenc:idenc_test" "//common/idenc:idenc_test" ""

# An e2e fixture (a manifest in the test's data) only: the test is built,
# nothing is unit-tested, the e2e runs.
expect fixture "//e2e:e2e_test
//e2e:manifests/e2e.yaml
" "//e2e:e2e_test" "" "//e2e:e2e_test"

# e2e/run.sh only: the scripts library and the test's data.
expect script "//e2e:e2e_test
//e2e:run.sh
//e2e:scripts
" "//e2e:e2e_test
//e2e:scripts" "" "//e2e:e2e_test
//e2e:scripts"

# Labels in no candidate list (an external target, a removed-looking label):
# nothing to build, and still a classification.
expect foreign "@rules_go//go:def.bzl
//gone:gone
" "" "" ""

# An impacted test is matched whole: //broker:broker_test is not matched by
# the prefix //broker:broker, and the reverse.
expect whole "//broker:broker
" "//broker:broker" "" ""

# classify fails, rather than answering, when a candidate list is unreadable.
if classify "${work}/agent/impacted.txt" "${work}/missing.txt" "${work}/tests.txt" "${work}/e2e.txt" "${work}/agent" 2>/dev/null; then
	echo "FAIL: classify succeeded with a missing candidate list" >&2
	fail=1
fi

[ "${fail}" -eq 0 ] || exit 1
echo PASS
