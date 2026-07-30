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
- [Mage](https://magefile.org/), the build tool this repo uses instead of Make:
  `go install github.com/magefile/mage@latest` (or run targets with
  `go run mage.go <Target>`)
- Docker or Podman with the Compose plugin, for the integration and stack tests
- Only if you are changing the Helm chart under [`charts/`](charts/):
  [Helm](https://helm.sh/docs/intro/install/) and
  [kubeconform](https://github.com/yannh/kubeconform)
  (`go install github.com/yannh/kubeconform/cmd/kubeconform@v0.7.0`)

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
# Run all unit tests
mage test:unit

# Format, vet, tidy modules, and lint (the CI gate)
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
- **Compatibility contracts must not be renamed.** openvox-ca is a drop-in for the Puppet CA, so the `/puppet-ca/v1` route prefix, the `PUPPET_CA_` / `PUPPET_CA_CTL_` environment prefixes, the `puppetca_` metric namespace, and the default `puppet-ca` / `/etc/puppet-ca` / `/var/lib/puppet-ca` paths are deliberately preserved.
- **Route test artifacts to `.test-output/`** (gitignored).
- **British English** in prose (docs, comments, commit messages, PR text); code identifiers follow the surrounding codebase.

## Submitting changes

- Branch off `main`; open pull requests against `main`.
- Keep commits focused: imperative subject ≤ 72 characters, with a body that
  explains *why*. Stage files by name and review `git diff --staged` before
  committing.
- Make sure `mage dev:check`, `mage test:unit`, and `markdownlint-cli2` pass.
- Changed the Helm chart? `mage chart:validate` and `mage chart:test` are
  required checks too. A new template branch needs a fixture under
  `charts/openvox-ca/ci/`, and anything a reader has to trust needs a case in
  `chart:test`.
- If you touched `mixin/`, run `mage dev:mixin` too — it renders the Jsonnet and
  checks the rules with `promtool`, which nothing else does.
- Internal design notes live under [docs/development/](docs/development/); update
  them when you change the behaviour they describe.
