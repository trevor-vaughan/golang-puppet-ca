# AGENTS.md

Guidance for AI agents and human contributors working on **openvox-ca**, a
Puppet-compatible X.509 Certificate Authority written in Go.

This file is authoritative for repository conventions. Where it is silent, match
the surrounding code.

## Build, test, lint

The build system is [Mage](https://magefile.dev) (`magefile.go`), not Make or
Task. Invoke targets with `go run mage.go <Target>` or the `mage` binary:

| Command | What it does |
| --- | --- |
| `mage build:all` | Build `openvox-ca` and `openvox-ca-ctl` binaries |
| `mage test:unit` | Run the unit suite (all packages, coverage to `coverage.out`) |
| `mage dev:lint` | Run `golangci-lint` (gate; see `.golangci.yml`) |
| `mage dev:mixin` | Render the Prometheus mixin and check the rules with `promtool` (gate; skips when the tools are absent) |
| `mage test:backendsPostgres` | SQL backend integration suite against PostgreSQL |
| `mage test:backendsMySQL` | SQL backend integration suite against MySQL |
| `mage test:backendsEtcd` | etcd backend integration suite (embedded etcd) |
| `mage test:backendsRedis` | Redis backend full-stack bash TAP suite (Puppet topology) |
| `mage test:backendsRedisGo` | Redis backend Go integration suite (build tag `redis_integration`) |
| `mage test:backendsOpenBao` | OpenBao Transit signer integration suite (build tag `openbao_integration`, `compose-backends-openbao.yml`) |
| `mage chart:validate` | Lint the Helm chart and check every rendered fixture against the Kubernetes schemas (needs `helm` and `kubeconform`) |
| `mage chart:test` | Assert what the chart renders, and that each precondition refuses what it claims to |
| `mage chart:version` | Assert `charts/openvox-ca/Chart.yaml` still tracks `internal/version` |

`golangci-lint` is pinned in CI (`.github/workflows/ci.yml`). Build it with the
repository's Go toolchain (`go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@<pinned>`);
a prebuilt binary compiled against an older Go can panic when analysing newer
language constructs.

Route all test artifacts (logs, coverage, results) to `.test-output/` (gitignored).

## Testing: Ginkgo + Gomega only

**All tests in this repository use [Ginkgo](https://onsi.github.io/ginkgo/) v2
with [Gomega](https://onsi.github.io/gomega/) matchers.** This is a hard
convention — do not add plain `testing.T` test functions (other than the single
suite bootstrap per package), and do not introduce `testify` or any other
assertion library.

### Suite bootstrap

Each test binary has **exactly one** `RunSpecs` entry point, conventionally in
`<pkg>_suite_test.go`:

```go
package ca_test // or `package ca` for white-box suites — see below

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestCa(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Ca Suite")
}
```

A test binary must contain **only one** `RunSpecs` call. Ginkgo's spec registry
is process-global, so `Describe` blocks declared in *either* the `<pkg>` (white-box)
or `<pkg>_test` (black-box) package compile into the same binary and run under
that single bootstrap. Never add a second `func Test…` that calls `RunSpecs`.

### White-box vs black-box

Choose the package declaration by what the test needs to reach:

- **Black-box** (`package foo_test`): the test exercises only the exported API.
  Preferred for behavioural tests. Existing examples: `internal/ca`,
  `internal/api`, `internal/metrics`, and the `internal/storage` service suite.
- **White-box** (`package foo`): the test must reach unexported identifiers
  (internal helpers, struct fields). Existing examples: `internal/signer`,
  `cmd/openvox-ca` (`package main`), and the `internal/storage` backend units.

A single package may contain both `foo` and `foo_test` test files; they share
the one bootstrap. Keep a test black-box unless it genuinely needs internals.

### Spec structure

```go
var _ = Describe("Subject", func() {
	var (
		tmpDir string
		subj   *Thing
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-test")
		Expect(err).NotTo(HaveOccurred())
		subj = New(tmpDir)
	})

	AfterEach(func() {
		Expect(os.RemoveAll(tmpDir)).To(Succeed())
	})

	It("does the thing", func() {
		Expect(subj.Do()).To(Equal("expected"))
	})
})
```

Conventions:

- Group related behaviour with nested `Describe`/`Context`; one assertion theme
  per `It`. `Context` descriptions read as conditions ("when the CA has expired").
- Use `DescribeTable`/`Entry` for table-driven cases instead of in-test loops.
- Per-spec setup/teardown belongs in `BeforeEach`/`AfterEach` (or `DeferCleanup`),
  never in package-level `var` initialisers — specs must be isolated.
- Mutating process state: prefer hermetic alternatives. When a test must set an
  environment variable, save and restore it in `BeforeEach`/`DeferCleanup` so it
  never leaks into sibling specs (Go's `t.Setenv` is unavailable inside Ginkgo
  nodes). Do not rely on tests running serially.
- Prefer `Eventually(...).Should(...)` over `time.Sleep` for asynchronous
  conditions; sleeps make the suite flaky on loaded CI runners.
- Keep negative and edge cases first-class: every security-relevant branch
  (rejection paths, tamper detection, auth denial) needs an explicit `It`.

### Integration suites (build-tagged)

Backend integration tests are gated behind Go build tags and live in the same
package as the unit tests. Preserve the tag on conversion; the `Describe` blocks
register into the package's existing suite under that tag:

```go
//go:build etcd_integration

package storage

var _ = Describe("etcd backend", func() { /* … */ })
```

The build tags in use are `etcd_integration`, `redis_integration`,
`postgres_integration`, `mysql_integration`, and `openbao_integration`. Each backend integration suite
must be reachable from a `magefile.go` `Test.Backends*` target so it runs in CI;
a build-tagged suite wired to no target is dead code.

## Compatibility contracts (do not rename)

openvox-ca is a drop-in for the OpenVox/Puppet Server CA. The following
identifiers are deliberately preserved for backward compatibility and **must
not** be rebranded:

- HTTP route prefix `/puppet-ca/v1`
- Environment-variable prefix `PUPPET_CA_` (and `PUPPET_CA_CTL_` for the CLI)
- Prometheus metric namespace `puppetca_`
- Storage key prefixes / default paths (`puppet-ca`, `/etc/puppet-ca`, `/var/lib/puppet-ca`)

## Helm chart

The chart in `charts/openvox-ca/` releases in lockstep with the binaries: its
`version` and `appVersion` are both the `internal/version` constant. Four
places parse those two lines (`mage chart:version`, the shared
`verify-release-tag` action, the pre-push hook, and the publish workflow, which
keys its main-vs-tag decision on the version) and `mage release:prepare`
rewrites them together — so never hand-edit one of the version lines on its
own, and never assume a chart version is `-dev` just because it has a hyphen.

The chart deliberately does **not** enumerate the server's settings as values.
`config` is written verbatim to `/etc/puppet-ca/config.yaml`, and the
convenience blocks (`tls`, `ca`, `metrics`, `kubernetesExport`, …) do the
Kubernetes wiring *and* set the config keys pointing at it, deep-merged with
`config` winning. Adding a server setting to `docs/configuration.md` therefore
needs no chart change; adding a value that duplicates one is a regression.

Every fixture under `charts/openvox-ca/ci/` is linted and schema-checked in CI.
A new template branch needs a fixture that exercises it, or it is untested —
and schema validity is not correctness, so anything a reader has to *trust*
(tag resolution, merge precedence, which kind a value selects) needs a case in
`chart:test` as well.

Preconditions live in one place, the `openvox-ca.validate` helper, and are
checked from `deployment.yaml`. When a value combination would render something
a cluster silently mishandles — a route to a port that does not exist, a
binding to the `default` ServiceAccount — `fail` at install time with the
remedy in the message, rather than rendering it. Each one needs a matching
reject case in `chart:test`.

## Commits

- Imperative subject ≤ 72 chars; body explains *why*.
- Stage files by name; never `git add -A`. Review `git diff --staged` first.
- Commit at logical checkpoints, not one big drop.
