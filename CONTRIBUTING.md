# Contributing to openvox-ca

Thanks for your interest in improving **openvox-ca**. This guide covers building,
testing, and submitting changes. If you are deploying openvox-ca rather than
working on it, start with the [README](README.md) and the user-facing
[documentation](docs/).

[`AGENTS.md`](AGENTS.md) is the **authoritative** reference for repository
conventions (testing framework, compatibility contracts, commit style). This
guide is the human-friendly entry point; where the two overlap, AGENTS.md wins.

## Prerequisites

- Go 1.25+ (see [`go.mod`](go.mod) for the exact version)
- git (any supported version — the magefile suite's fixtures isolate themselves
  from your own git config by redirecting `HOME` as well as setting
  `GIT_CONFIG_GLOBAL`, so they do not depend on the 2.32+ variables alone)
- [Mage](https://magefile.org/), the build tool this repo uses instead of Make:
  `go install github.com/magefile/mage@latest` (or run targets with
  `go run mage.go <Target>`)
- A C compiler (gcc or clang; `build-essential` on Debian/Ubuntu, the Xcode
  Command Line Tools on macOS), because `mage test:unit` and
  `mage test:backendsRedisGo` run their suites under the race detector, which
  needs cgo — see
  [Testing](docs/development/testing.md). Present by default on most systems; a
  slim container image may not have one. The product build is unaffected — it
  is still `CGO_ENABLED=0`.
- Docker or Podman with the Compose plugin, for the integration and stack tests
- Only if you are changing the Helm chart under [`charts/`](charts/):
  [Helm](https://helm.sh/docs/intro/install/) and
  [kubeconform](https://github.com/yannh/kubeconform)
  (`go install github.com/yannh/kubeconform/cmd/kubeconform@v0.8.0`)

## Building

```bash
git clone https://github.com/voxpupuli/openvox-ca.git
cd openvox-ca

# Build both binaries to bin/
mage build:all

# Or with plain Go
go build -o bin/openvox-ca     ./cmd/openvox-ca
go build -o bin/openvox-ca-ctl ./cmd/openvox-ca-ctl
```

### FIPS build (Linux/amd64)

The core CA uses the Go standard library only and builds with `CGO_ENABLED=0`
by default. A FIPS-mode build links BoringCrypto:

```bash
mage build:fips   # → bin/openvox-ca + bin/openvox-ca-ctl  (GOEXPERIMENT=boringcrypto, CGO_ENABLED=1)
```

## Testing

```bash
# Run all unit tests (with coverage, under -race; needs cgo and a C compiler)
mage test:unit

# Format, vet, tidy modules, lint, and check the workflows for drift (the CI gate)
mage dev:check

# Run integration tests using the compose stack
mage test:integCompose
```

The full set of suites — unit, compose integration, the OpenVox stack test, load
tests, and the per-backend integration suites — is documented in
[development/testing.md](docs/development/testing.md).

Markdown documentation is linted with
[markdownlint-cli2](https://github.com/DavidAnson/markdownlint-cli2) against
[`.markdownlint-cli2.yaml`](.markdownlint-cli2.yaml). Run it (and auto-fix most
issues) before pushing doc changes:

```bash
markdownlint-cli2 --fix
```

## Repository conventions

See [`AGENTS.md`](AGENTS.md) for the details. The essentials:

- **Tests use [Ginkgo](https://onsi.github.io/ginkgo/) v2 + [Gomega](https://onsi.github.io/gomega/)** — no plain `testing.T` tests (beyond the one suite bootstrap per package) and no other assertion library.
- **Compatibility contracts must not be renamed.** openvox-ca is a drop-in for the Puppet CA, so the `/puppet-ca/v1` route prefix, the `PUPPET_CA_` / `PUPPET_CA_CTL_` environment prefixes, the `puppetca_` metric namespace, and the `puppet-ca` path spelling (`/etc/puppet-ca`, `/var/lib/puppet-ca`) are deliberately preserved. It is a contract about **names, not defaults** — a default path may move where there is a reason, as the packaged `cadir` has, but nothing spelled `puppet-ca` may be rebranded to `openvox-ca`. See [`AGENTS.md`](AGENTS.md) for the one exception and why it is one.
- **Non-test code logs through `log/slog`** — no other logging library, and no in-tree `slog.Handler`. slog's handlers escape control characters, which is what the CodeQL `go/log-injection` exclusion depends on; the lint rule that backs this is a denylist, so it will not stop you reaching for an unlisted one.
- **Route test artifacts to `.test-output/`** (gitignored).
- **British English** in prose (docs, comments, commit messages, PR text); code identifiers follow the surrounding codebase.

## Submitting changes

- Branch off `main`; open pull requests against `main`. A change that builds
  on another unmerged branch may instead be stacked — branch off that branch
  and target it — in which case say so in the PR description and note that it
  cannot merge until its base does. CI and CodeQL run on pull requests
  whatever their base, so a stacked PR is exercised before it merges into its
  base — but only pull requests targeting `main` are gated by the repository
  ruleset, so on a stacked one read the results rather than relying on a
  merge block.
- Keep commits focused: imperative subject ≤ 72 characters, with a body that
  explains *why*. Stage files by name and review `git diff --staged` before
  committing.
- Make sure `mage dev:check`, `mage test:unit`, `mage test:magefile`, and
  `markdownlint-cli2` pass.
- `lefthook install` adds git hooks that cover *part* of the above: pre-commit
  runs gofmt and golangci-lint, and pre-push runs `go test -race ./...`, the
  build-tagged `go test -tags mage .`, and a refusal of any `v*` tag whose
  version does not match the tree. An untidy `go.mod`, a drifted chart pin or a
  markdownlint violation is not among them — those stay with `mage dev:check`,
  `markdownlint-cli2` and CI. Each hook check stands aside with a SKIP when the
  tool it drives is absent from `PATH`. On Linux the test run additionally needs a
  C compiler, since `-race` requires cgo there, and fails rather than skipping
  without one; macOS builds `-race` without cgo.
- The pre-push run is a *different environment* from a bare `mage test:magefile`:
  git exports `GIT_DIR` and friends to the hooks it runs, which is a hazard for
  any test that shells out to git. See the testing conventions in
  [AGENTS.md](AGENTS.md).
- Changed the Helm chart? `mage chart:validate` and `mage chart:test` are
  required checks too. A new template branch needs a fixture under
  `charts/openvox-ca/ci/`, and anything a reader has to trust needs a case in
  `chart:test`. `chart:validate` caches the remote Kubernetes schemas under
  `.test-output/`; that cache never revalidates, so if it passes locally and
  fails in CI, clear it with `mage dev:clean` and re-run.
- Internal design notes live under [docs/development/](docs/development/); update
  them when you change the behaviour they describe.
