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
E2E_AUTHZ=spicedb e2e/run.sh    # with SpiceDB as the authorization backend
E2E_FILTER=TestName e2e/run.sh  # only the tests whose name matches
E2E_KEEP_CLUSTER=1 e2e/run.sh   # leave the cluster up to look around
```

Needs docker, kind and kubectl; helm comes from Bazel. The suite in `e2e/` is
tagged `e2e` and excluded from `bazel test //...`; `e2e/run.sh` creates or
reuses the kind cluster `cracha-e2e`, loads the images built from the
checkout, deploys SPIRE (`e2e/spire.sh`), installs the chart built from the
checkout with `e2e/values.yaml` (the suite's assignments, SPIRE socket paths
and STS endpoint), `e2e/values-local.yaml` (the images just loaded) and a
values file it writes for the grant bundle it compiled from `e2e/grants`,
signed with a throwaway key and published into a ConfigMap,
deploys the STS stand-in (`e2e/manifests/stsstub.yaml`, `e2e/stsstub`) and
runs the tests against the ambient kubeconfig. The chart's generated CA is
what the test workloads trust: run.sh copies it from the `cracha-ca` Secret
into a ConfigMap of the test namespace. `E2E_AUTHZ` picks the broker's
authorization backend: `static` (the default) is the assignments document
in `e2e/values.yaml`; `spicedb` also deploys SpiceDB from
`e2e/manifests/spicedb.yaml` (memory datastore, plaintext gRPC, a preshared
key the script makes), runs `cracha-reconciler` built from the checkout on
the host through a `kubectl port-forward` to write the schema and the
relationships of `e2e/grants`, and installs the chart with
`e2e/values-spicedb.yaml` on top. The tests that need SpiceDB (revocation
through Watch, suspension, the cache's mode) skip in static mode; the rest
run in both, and one of them checks that the static document and the grant
tree assign the same things. CI runs the script once per backend. Every
change that adds user-visible behaviour extends the suite, and a change to
how Crachá is deployed goes in the chart, not in a manifest.

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
cognitive-complexity ceiling of 15 by gocognit (`bazel/lint/linters.bzl`;
never raise it). Shell
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
depends on and no target does (`.bazelrc`, `.bazelversion`, `MODULE.bazel`
and its lock, `ci.yml`, the script, the lint aspects under `bazel/lint/` and
`.shellcheckrc`, which `.bazelrc` attaches to every build) runs everything, as does
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
  `broker/`, `csi/`, `webhook/`, `grantc/`, `reconciler/`.
- Code private to a binary goes under its `internal/`.
- Code shared between binaries goes under `common/`. `common/idenc` is the
  single identity-encoding library (design 4.3): nothing else formats a
  SourceIdentity or an authorization subject ID.
- `common/grant` is the grant bundle model and compiler (design 6.2): loading,
  validation, templates, lints, the compiled bundle, signing and publishing.
  Its source tree holds three kinds: `Grant`, `Assignment` (a workload's own
  grants, optionally bounded, or its `suspended: true`) and `Service` (a
  team's workloads and the grants they share, each bounded like an
  Assignment; a workload is a member of at most one service). The
  composition lint unions a subject's grants from both. Names are DNS labels
  without dots, because they become SpiceDB object IDs.
- `common/spicedb` is the SpiceDB schema (design 6.4), embedded from
  `schema.zed`, and the constants for every object type, relation,
  permission, caveat and caveat context key in it: the broker's adapter and
  the reconciler spell nothing in the schema twice.
- `grantc/` is the grant compiler CLI over `common/grant` (lint, compile,
  sign, verify, publish); it runs in CI and has no container image.
- The broker's authorization store is one of two backends, chosen by
  `--authz-backend`: `static` (`broker/internal/authz/static`, the
  assignments file `--assignments`) or `spicedb`
  (`broker/internal/authz/spicedb`, the adapter over the reference model of
  design 6.4: the preshared key is read from `--spicedb-token-file`, never a
  flag value; every query carries the caveat context `now` and `cluster`;
  every error is a deny; its Watch feeds the cache). The contract both
  answer is `broker/internal/authz`, and the SpiceDB tests hold the adapter
  to the static backend's answers for the same assignments.
- `reconciler/` is `cracha-reconciler`, the `authz-reconciler` writer of
  design 6.4: `schema` writes the embedded schema, `apply` makes SpiceDB's
  relationships match a grant source tree (`reconciler/internal/reconcile`
  computes the desired set and the diff; `reconciler/internal/fakespicedb`
  is the in-memory SpiceDB its tests use). Like `grantc` it runs from CI or
  an operator's machine and has no container image; the e2e will run it
  from the host against a port-forwarded SpiceDB.
- The broker gets its grants from one of two sources, exactly one of which
  is configured. In production it is the compiled bundle `grantc` publishes
  (`--bundle-source local:<dir>` or `s3://bucket/prefix`,
  `broker/internal/bundle`): polled, its signature verified over the
  published bytes with a public key PEM (`--bundle-verify-key`) or a KMS
  key (`--bundle-kms-key`), swapped atomically when the version changes,
  and kept at the last good version on any failure; `/readyz` reports not
  ready until a bundle has verified. For development it is the
  resolved-grants fixture (`--grants-fixture`,
  `broker/internal/grants/fixture.go`), which the chart's default
  `broker.grants` renders; `broker.bundle` switches an install to the
  bundle. The e2e installs the bundle path.
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
- `broker.authz.backend` picks the authorization store: `static` (the
  default) renders the assignments ConfigMap and its mount; `spicedb` takes
  `broker.authz.spicedb` (endpoint, `tokenSecret` naming a Secret the
  operator keeps, whose key is mounted as a file and never put in the
  environment, an optional `ca` the chart puts in a ConfigMap, `insecure`
  for kind only, `timeout`).
- `test/overrides.yaml` must exercise every non-default knob: a new value
  goes there too. A value every install must give (`broker.cluster`,
  `webhook.defaultRegion`) is `required` in the templates and listed in
  `test/required.yaml`.
- The default TLS mode generates a CA at render time, for development and
  kind only: the broker's certificate must be trusted by the workload images
  (design 6.5), so production uses `existing` or `cert-manager`.
- The chart is published to `chart_registry_url("cracha")` of
  `bazel/registry.bzl` by the publish workflow (below).

## Publishing

- Every published coordinate comes from `bazel/registry.bzl`: the registry
  host, the organization, the three image repositories and the chart's.
  Bazel loads it; shell and the workflows read it through `bazel/registry.sh`
  (`bazel/registry.sh` prints `KEY=VALUE` lines, `bazel/registry.sh ref csi`
  one reference). `bazel/check-registry-config.sh`, run by the `lint` job of
  `ci.yml`, fails a change that spells the registry out anywhere else; the
  README is the one file allowed to, because people copy install commands
  from it. Moving registries is an edit to `bazel/registry.bzl` and nothing
  else.
- `.github/workflows/publish.yml` publishes on every push to `main` and on
  every `v*` tag, in the GitHub environment `release`, which only `main` and
  `v*` tags may use. It builds everything it will push in one
  `bazel build --config=ci` before any credential exists on the runner,
  refuses an unstamped chart or a chart whose pins are not the digests it is
  about to push, logs in to the registry once (`docker/login-action`, which
  `image_push` and cosign both read), pushes the three images, signs each
  index and its platform manifests keyless by digest with the pinned cosign
  (`cosign sign --recursive`), verifies them before signing (so an unchanged
  digest is not signed twice) and after, then pushes the chart with
  `//charts/cracha:cracha.push_registry` and signs and verifies it the same
  way. A `check` job pulls the chart back by its version with the pinned helm,
  asserts it is the manifest the push reported and pins the digests that were
  pushed, and verifies every signature without credentials. The workflow
  cannot be exercised from a pull request, so read a change to it twice and
  watch the run after merge. It reads files from `bazel-out`: an output that
  is not a target's default output is absent there on a cache hit, so request
  its output group in the build step (see `--output_groups=+digest`).
- The credentials are a Quay robot account of the `cracha` organization that
  can write (not create) the repositories, in the secrets `QUAY_USERNAME` and
  `QUAY_TOKEN` of the `release` environment; nothing else is configured
  outside the repository. The repositories are public, and they are created
  by hand: a new image needs its quay.io repository, an entry in
  `bazel/registry.sh` and the comments of `bazel/registry.bzl`, the build
  lists of `ci.yml` and `publish.yml` (build, push, record, sign, verify,
  check, release notes) and, if the chart deploys it, `values.yaml`, the
  chart's `images` and `PINNED_COMPONENTS`, and
  `bazel/check-registry-config.sh`.
- cosign is the release binary the `rules_img_signer_cosign` bazel_dep pins by
  sha256, wrapped as `//bazel/cosign`; `//bazel/cosign:version_test` fails
  when the pin and the test's `EXPECTED` disagree, so bump both together. To
  verify a published image (the index and every platform manifest, and that
  the signature is a referrer as `SIGNATURE_LAYOUT` promises) or the chart:

  ```bash
  bazel run //bazel/cosign:verify_image -- "$(bazel/registry.sh ref csi)@sha256:<digest>"
  bazel run //bazel/cosign:verify_image -- --single "$(bazel/registry.sh chart-ref cracha)@sha256:<digest>"
  bazel run //bazel/cosign -- verify "$(bazel/registry.sh ref csi)@sha256:<digest>" \
    --certificate-identity-regexp '^https://github.com/bpalermo/cracha/.github/workflows/publish.yml@refs/(heads/main|tags/v.*)$' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  ```

### Releasing

- `VERSION` holds the release being worked towards. Every commit to `main`
  publishes a snapshot of it: the chart as `<VERSION>-dev.<commit time>.g<commit>`,
  the images under the mutable tag `dev` and the immutable `dev-<commit>`.
- A release is a tag `v<VERSION>` on a commit of `main`, pushed by a person.
  Cut a candidate first, `v<VERSION>-rc.<n>`, since the tag path of the
  workflow runs only on a real tag. The tag publishes the images under
  `v<VERSION>` (and `v<VERSION>-<commit>`), the chart as `<VERSION>`, signs
  them, and once `check` passes creates the GitHub Release with the pinned
  references and the `cosign verify` command in its notes. A tag that is not
  on `main`, or that does not match `VERSION` (the workspace status then
  reports a snapshot, not the release), is refused.
- After the release, set `VERSION` to the next one in a pull request.
- In 0.x a release may break the protocol between components or the chart's
  values; say so in the release notes when one does.

## Pull requests

- `main` takes squash merges with a linear history; the `ci` check aggregates
  the jobs.
- GitHub Actions are pinned by commit SHA, with the version in a comment.
- Keep a pull request to one slice of behaviour, with its tests.
