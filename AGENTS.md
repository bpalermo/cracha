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
fix it rather than excluding the file. Shell scripts are checked by shellcheck,
an aspect that `--config=ci` turns on; a script is only seen through a Bazel
target, so a new directory of scripts needs an `sh_library` like
`//bazel:scripts`.

CI runs with `--config=ci`, which fails if `MODULE.bazel.lock` is out of date,
and requires that Gazelle leaves no diff. Regenerate BUILD files rather than
hand-editing what Gazelle owns.

## Layout

- No `cmd/`. Each binary lives in a root-level directory with its `main.go`:
  `broker/`, `csi/`, `webhook/`, `grantc/`.
- Code private to a binary goes under its `internal/`.
- Code shared between binaries goes under `common/`.
- `common/grant` is the grant bundle model and compiler (design 6.2): loading,
  validation, templates, lints, the compiled bundle, signing and publishing.
- `grantc/` is the grant compiler CLI over `common/grant` (lint, compile,
  sign, verify, publish); it runs in CI and has no container image.
- `bazel/` holds build rules; `docs/` the design.

## Images and versions

- The registry is named in one build file, `bazel/registry.bzl`. Nothing else
  may spell it out.
- Images are built with the `go_image` macro in `bazel/image/defs.bzl`, from
  pure-Go binaries on a digest-pinned distroless base. Image repositories are
  `broker`, `csi` and `webhook`.
- `VERSION` holds the release being worked towards. Binaries report the commit
  they were built from, stamped by `bazel/workspace_status.sh`.

## Pull requests

- `main` takes squash merges with a linear history; the `ci` check aggregates
  the jobs.
- GitHub Actions are pinned by commit SHA, with the version in a comment.
- Keep a pull request to one slice of behaviour, with its tests.
