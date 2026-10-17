# AGENTS.md

Guidance for agents working in this repository.

## What this is

Crachá issues AWS credentials to Kubernetes workloads from their SPIFFE
identity. Three binaries: the credential broker (`broker`), the CSI node plugin
that writes a pod's JWT-SVID where the AWS SDK reads it (`csi`), and the
mutating webhook that wires pods up (`webhook`). [docs/design.md](docs/design.md)
is the design; read it before changing behaviour, and update it in the same
pull request when behaviour changes. Its invariants (section 11) must hold in
every change.

## Build and test

```bash
bazel test //...            # builds and runs the unit tests
bazel run //:gazelle        # after adding, removing or renaming any .go file
bazel run //:format         # format Starlark, Go and shell; CI runs //:format.check
bazel mod tidy              # after changing go.mod or a bazel_dep
bazel build --config=ci //...   # what CI builds: lockfile must be current, shellcheck on
```

### End to end

```bash
e2e/run.sh                      # the whole system in a kind cluster
E2E_FILTER=TestName e2e/run.sh  # only the tests whose name matches
E2E_KEEP_CLUSTER=1 e2e/run.sh   # leave the cluster up to look around
```

Needs docker, kind and kubectl; helm comes from Bazel. The suite in `e2e/` is
tagged `e2e` and excluded from `bazel test //...`; `e2e/run.sh` creates or
reuses the kind cluster `cracha-e2e`, loads the images built from the
checkout, deploys SPIRE (`e2e/spire.sh`), installs the chart built from the
checkout with `e2e/values.yaml` (the suite's assignments, grants, SPIRE socket
paths and STS endpoint) and `e2e/values-local.yaml` (the images just loaded),
deploys the STS stand-in (`e2e/manifests/stsstub.yaml`, `e2e/stsstub`) and
runs the tests against the ambient kubeconfig. The chart's generated CA is
what the test workloads trust: run.sh copies it from the `cracha-ca` Secret
into a ConfigMap of the test namespace. CI runs the same script. Every change
that adds user-visible behaviour extends the suite, and a change to how
Crachá is deployed goes in the chart, not in a manifest.

Bazel is the only build. Never run the host `go` tool: not `go mod tidy`, not
`go get`, not `go test`. Change a Go dependency through rules_go's SDK:

```bash
bazel run @rules_go//go -- get github.com/some/module@v1.2.3
```

Follow it with `bazel mod tidy` and `bazel run //:gazelle`. Go modules are
fetched directly from their repositories in the user's Go environment
(`GOPROXY=direct`); the untracked `user.bazelrc` points Bazel's own fetches at
the public proxy instead.

Linting is part of the build. Every Go package is compiled with the analyzers
of `//:nogo` (`go vet`'s and staticcheck's), and a finding is a compile error:
fix it rather than excluding the file. Go functions are also held under a
cognitive-complexity ceiling by gocognit (`bazel/lint/linters.bzl`, a ratchet
heading for 15; lower it when you simplify something, never raise it). Shell
scripts are checked by shellcheck, an aspect that `--config=ci` turns on; a script is only seen through a Bazel
target, so a new directory of scripts needs an `sh_library` like
`//bazel:scripts`.

CI runs with `--config=ci`, which fails if `MODULE.bazel.lock` is out of date,
and requires that Gazelle leaves no diff. Regenerate BUILD files rather than
hand-editing what Gazelle owns.

### What CI runs for a change

CI builds and tests only what a change impacts. The `diff` job hashes the
build graph at the base and the head of the change with bazel-diff
(`bazel/ci-impacted-targets.sh`) and hands `build` the impacted rules to
build and the impacted tests to run; `build` is skipped when nothing is
impacted, and the `e2e (kind)` job runs only when the impacted set reaches
something the suite deploys or runs: anything under `//e2e/...`, the chart
`//charts/cracha:cracha` or a component's `image_load`. The suite's
manifests, values files, `spire.sh` and `run.sh` are `data` of
`//e2e:e2e_test`, so editing one of them is an e2e-relevant change; a new
fixture the suite deploys goes in that glob. A documentation-only change
builds nothing and creates no kind cluster; the formatter and the Gazelle
check run on every change regardless. A change to the files CI itself
depends on and Bazel does not hash (`.bazelrc`, `.bazelversion`,
`MODULE.bazel` and its lock, `ci.yml`, the script) runs everything, as does
any error in the computation: the fallback is always a full run, never a
smaller one. To see what a change would run, from a clone (the script checks
revisions out, so not the checkout you are working in) with bazel-diff from
its GitHub release at the version `ci.yml` pins:

```bash
BASE_SHA=origin/main BAZEL_DIFF=~/bin/bazel-diff bazel/ci-impacted-targets.sh
```

The decision after bazel-diff is covered by `//bazel:ci_impacted_targets_test`.

## Layout

- No `cmd/`. Each binary lives in a root-level directory with its `main.go`:
  `broker/`, `csi/`, `webhook/`, `grantc/`.
- Code private to a binary goes under its `internal/`.
- Code shared between binaries goes under `common/`. `common/idenc` is the
  single identity-encoding library (design 4.3): nothing else formats a
  SourceIdentity or an authorization subject ID.
- `common/grant` is the grant bundle model and compiler (design 6.2): loading,
  validation, templates, lints, the compiled bundle, signing and publishing.
- `grantc/` is the grant compiler CLI over `common/grant` (lint, compile,
  sign, verify, publish); it runs in CI and has no container image.
- `bazel/` holds build rules; `docs/` the design; `charts/cracha` the Helm
  chart; `e2e/` the end-to-end suite with its values files, the fixtures it
  deploys beside the chart and the two images only it uses.

## Images and versions

- The registry is named in one build file, `bazel/registry.bzl`. Nothing else
  may spell it out.
- Images are built with the `go_image` macro in `bazel/image/defs.bzl`, from
  pure-Go binaries on a digest-pinned distroless base. Image repositories are
  `broker`, `csi` and `webhook`.
- `VERSION` holds the release being worked towards. Binaries report the commit
  they were built from, stamped by `bazel/workspace_status.sh`.

## Chart

- `charts/cracha` is the Helm chart: the CSIDriver, the CSI DaemonSet, the
  broker and the webhook with their TLS. It is built, linted, templated and
  installed with the helm that rules_helm pins (`@helm//:helm`, the version
  in `MODULE.bazel` and `.bazelrc`); never a helm from PATH.
  `bazel build //charts/cracha:cracha` packages it as
  `bazel-bin/charts/cracha/cracha.tgz`; `bazel test //charts/cracha/...`
  runs the lint, template (defaults, every override, cert-manager) and pin
  tests.
- The chart's version and image pins are stamped at package time: the
  version from `STABLE_CHART_VERSION`, each image's repository and digest
  from its `image_push` target (`{@//csi:image_push.digest}` in
  `values.yaml`). Do not write a version or a digest into `Chart.yaml.in` or
  `values.yaml` by hand; `//charts/cracha:pin_test` checks the result with
  `bazel/chart-pin.sh`. The registrar sidecar is the one image pinned by
  hand, by tag and digest.
- `test/overrides.yaml` must exercise every non-default knob: a new value
  goes there too. A value every install must give (`broker.cluster`,
  `webhook.defaultRegion`) is `required` in the templates and listed in
  `test/required.yaml`.
- The default TLS mode generates a CA at render time, for development and
  kind only: the broker's certificate must be trusted by the workload images
  (design 6.5), so production uses `existing` or `cert-manager`.
- The chart is published to `chart_registry_url("cracha")` of
  `bazel/registry.bzl`; there is no publish workflow yet.

## Pull requests

- `main` takes squash merges with a linear history; the `ci` check aggregates
  the jobs.
- GitHub Actions are pinned by commit SHA, with the version in a comment.
- Keep a pull request to one slice of behaviour, with its tests.
