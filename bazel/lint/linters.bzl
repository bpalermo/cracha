"""Linters that run as aspects, with `--config=lint`.

The Go analyzers are not here: nogo runs them as part of compiling (//:nogo).
Nor is buf's lint of the protos, which is a test beside them.
"""

load("@aspect_rules_lint//lint:lint_test.bzl", "lint_test")
load("@aspect_rules_lint//lint:shellcheck.bzl", "lint_shellcheck_aspect")
load("//bazel/lint:gocognit.bzl", "lint_gocognit_aspect")

shellcheck = lint_shellcheck_aspect(
    binary = Label("@aspect_rules_lint//lint:shellcheck_bin"),
    config = Label("//:.shellcheckrc"),
)

shellcheck_test = lint_test(aspect = shellcheck)

# gocognit reports Go functions over a cognitive-complexity threshold, in
# production code only (go_library and go_binary). See bazel/lint/gocognit.bzl.
#
# 15 is the target, reached on 2026-10-17 after the aspect was introduced as a
# ratchet at 38 and the 20 functions over 15 were simplified. It never goes up.
gocognit = lint_gocognit_aspect(
    binary = Label("@com_github_uudashr_gocognit//cmd/gocognit"),
    threshold = 15,
)

gocognit_test = lint_test(aspect = gocognit)
