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
| `mage build:dist` | Cross-compile all release tarballs (and `checksums.txt`) to `dist/` |
| `mage build:distVariant <name>` | Build one release tarball variant (e.g. `linux_arm64_fips`) into `dist/` |
| `mage build:packages` | Build the `.deb` and `.rpm` from the tarballs already in `dist/` (builds no binaries) |
| `mage build:unit <bindir>` | Render the systemd unit template for a bindir into `dist/` |
| `mage release:prepare <version>` | Open the version-bump PR that must precede a release tag — see [releasing](docs/development/releasing.md) |
| `mage test:unit` | Run the unit suite (all packages, coverage to `coverage.out`), under `-race` — needs cgo and a C compiler |
| `mage test:magefile` | Run the magefile's own build-tagged suite (invisible to `go test ./...`) |
| `mage dev:lint` | Run `golangci-lint` (gate; see `.golangci.yml`) |
| `mage test:backendsPostgres` | SQL backend integration suite against PostgreSQL, under `-race` — needs cgo and a C compiler |
| `mage test:backendsMySQL` | SQL backend integration suite against MySQL, under `-race` — needs cgo and a C compiler |
| `mage test:backendsEtcd` | etcd backend integration suite (embedded etcd), under `-race` — needs cgo and a C compiler |
| `mage test:backendsRedis` | Redis backend full-stack bash TAP suite (Puppet topology) |
| `mage test:backendsRedisGo` | Redis backend Go integration suite (build tag `redis_integration`), under `-race` — needs cgo and a C compiler |
| `mage test:backendsOpenBao` | OpenBao Transit signer integration suite (build tag `openbao_integration`, `test/compose-backends-openbao.yml`) |
| `mage chart:lint` | Run `helm lint --strict` over the Helm chart, once per fixture in `charts/openvox-ca/ci/` |
| `mage chart:validate` | Lint the Helm chart and check every rendered fixture against the Kubernetes schemas (needs `helm` and `kubeconform`; caches the remote schemas under `.test-output/kubeconform-cache/`, which `mage dev:clean` removes) |
| `mage chart:test` | Assert what the chart renders, and that each precondition refuses what it claims to |
| `mage chart:version` | Assert `charts/openvox-ca/Chart.yaml` still tracks `internal/version` |
| `mage chart:package` | Package the Helm chart to `dist/openvox-ca-<version>.tgz`, as CI does before the publish workflow pushes it |

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
  `Ordered`/`BeforeAll` is a standing exception for one container, the
  `Authorisation baseline` table in `internal/api/authbaseline_test.go`, which
  states its own case: a shared RSA key pool that would otherwise cost minutes
  per spec, and `ContinueOnFailure` (which needs `Ordered`) so a change reports
  every cell it moves rather than the first. Another one needs a reason of that
  kind rather than convenience — a fixture that merely replays cached PEMs is
  affordable per spec, as the configuration-axes block below it and
  `auth_test.go` both show.
- Mutating process state: prefer hermetic alternatives. When a test must set an
  environment variable, use `GinkgoT().Setenv`, or save and restore it in
  `BeforeEach`/`DeferCleanup` so it never leaks into sibling specs (Go's bare
  `t.Setenv` needs a `*testing.T`, which Ginkgo nodes do not have; `GinkgoT()`
  supplies the same save-and-restore semantics). Do not rely on tests running
  serially.
- A spec that shells out to `git` — or to anything that may itself run `git`, a
  hook script included, which is where this was missed twice — must build its
  environment by *stripping*
  `GIT_*` from `os.Environ()`, never by appending to it. git exports `GIT_DIR`,
  `GIT_WORK_TREE`, `GIT_INDEX_FILE` and `GIT_OBJECT_DIRECTORY` to the hooks it
  runs, and they outrank `cmd.Dir` — so under the pre-push hook an inherited
  environment makes the fixture operate on the real repository. This has already
  cost one branch: see `fixtureEnv` in [`magefile_chart_test.go`](magefile_chart_test.go).
  A hook is the only thing that leaks that environment naturally, so a spec has
  to plant it deliberately to be covered — see the decoy repository in the same
  file, which is what makes this class visible to `mage test:magefile` and CI at
  all. Without one, neither can reproduce it.
- Prefer `Eventually(...).Should(...)` over `time.Sleep` for asynchronous
  conditions; sleeps make the suite flaky on loaded CI runners.
- Keep negative and edge cases first-class: every security-relevant branch
  (rejection paths, tamper detection, auth denial) needs an explicit `It`.
- `internal/api/authbaseline_test.go` is the recorded authorisation baseline:
  every client class against every covered route, as the middleware behaves
  today. A change that deliberately alters who may reach an endpoint updates the
  affected row, records the responsible change in `changedBy`, and refreshes
  that row's `fingerprint` — all in the same commit, in that order (the suite
  withholds the digest you need while `changedBy` is empty).

  Each row also carries a `baseline` digest of its originally committed
  outcomes. Do not edit it: no legitimate change to an existing row touches a
  `baseline:` line, which is what makes one in a diff worth stopping on.

  Two cases the above does not cover. A *new* row needs **both** digests, not
  just one: add its name to `expectedRoutes`, write `baseline: ""`, and run the
  suite, which prints a paste-ready `fingerprint`/`baseline` pair. Leave
  `changedBy` empty — a new row has not moved, and attributing it from birth
  permanently retires its baseline check. "Do not edit `baseline`" applies from
  its second commit onwards.

  Adding or removing a *client class* re-digests every row, so that commit sets
  `changedBy` on all of them naming the class, even though no authorisation
  behaviour changed. Note what that costs: an attributed row's `baseline` is
  never compared again, so a class change retires the baseline layer repo-wide.
  Such a commit also updates `expectedClientClasses`, gives the class a property
  function in the fixture-property spec, and records its outcome on every row —
  the suite enforces all three, but only after the digests stop it first.

  The suite cannot judge whether an attribution is *accurate*, nor whether a
  fixture still means what its class name says; reviewers should.
  `docs/api.md#authorization-tiers` publishes the tier assignment to operators,
  so update it when a change moves a route between tiers — it is a tier table,
  not this matrix, and most cells here have no counterpart there.
- `internal/api/authseam_test.go` is the second structural gate in that package.
  It parses `internal/api`'s own non-test files and fails if any of them names
  `AuthGrant`, `PpCliAuth`, `GenerateOptions` or `GenerateWithOptions` — the
  in-process seam for minting a `pp_cli_auth` credential, which the CSR path
  deliberately strips so that no request can ask for one. If it fires, revisit
  the security argument in `internal/ca/authgrant.go` before touching the gate.
  Renaming any of those identifiers breaks the compile-time bindings at the top
  of that file: update the bindings and the `forbidden` map together, and do not
  delete either to restore the build.

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

## Locking and concurrency

Any change that reads or mutates shared CA state (certificates, CSRs, the CRL,
the inventory, in-memory caches) must follow
[docs/development/locking.md](docs/development/locking.md). The short form:

- Mutations serialise on cluster-wide named locks via `StorageService.WithLock`
  (`bootstrap`, `crl`, `subject:<name>`, `hmac-key`); the check that justifies a mutation
  must run inside the same lock as the mutation. Backend-internal locks taken
  directly via `Backend.AcquireLock` (e.g. etcd's `inventory-decompose`) are a
  second recognised pattern — see locking.md for when each applies.
- **One running instance, unless the backend has distributed locking.** A
  backend without it permits exactly one, because nothing reconciles the serial
  index, OCSP cache and cached CRL each process holds. `StorageService.
  AcquireInstanceLock` takes a store-wide `store-instance` lock for the life of
  the process, gated on `SupportsDistributedLocking` — **on the capability,
  never on a backend name**, so a new backend inherits the right behaviour. It
  is taken *outside* `WithLock` and never reaches a cross-node lock. Two things
  to keep right when touching it: release it after closing the backend, not
  before; and take it once per *instance* — the launcher forks children that
  open the store for themselves, so a lock taken per process deadlocks the
  default topology against itself.
- Read-only paths must **not** take `WithLock` — they use in-memory caches and
  read locks only.
- On `filesystem` and `sqlite` a lock name also derives a lock *filename*
  (`sha256(name).lock` under the operator's store), so adding one creates a file
  in every operator's cadir and the mapping is protocol too.
- On `postgres` and `mysql` a lock name derives a *key* in a partitioned space,
  and a new singleton name **that can reach a SQL backend** must be registered
  in `reservedLockOrdinals` (`internal/storage/sql.go`) or it lands in the
  hashed half. "Can reach a SQL backend" is the test, not "is a singleton": a
  backend-internal name like etcd's `inventory-decompose` must *not* be
  registered, since that would claim a key nothing uses. The ordinals and the
  derivation are protocol; changing either needs a full cluster restart, not a
  rolling one.
- Lock ordering is `subject:<name>` → `crl` → `c.mu`, plus `bootstrap` → `crl`
  on the CA-import path and `bootstrap` → `hmac-key` on the migration path; all
  are one-way and `bootstrap` is never held with a subject lock. Lock names are a stable cross-replica protocol — never invent or
  rename one casually.
- Holding two *different* named locks at once is protocol as well, not just the
  names. Such a pair must appear in locking.md's **Lock ordering** section and
  in `allowedLockNesting` (`internal/ca/lockorder_test.go`), added together. A
  spec catches an unlisted pair *when it drives the caller that takes it* — it
  drives a minority of them, so a green suite is not confirmation you had
  nothing to add. One documented exception: `bootstrap` → `hmac-key` is taken
  only by `MigrateService`, in `internal/storage`. `allowedLockNesting` keys
  pairs by lock name rather than (store, name), so that path is out of its scope
  by design — locking.md carries it in prose and the table must not gain it.

## Logging: `log/slog` only

**Non-test code logs through `log/slog`.** This is a hard convention — do not
introduce `logrus`, `zap`, `zerolog`, `hclog`, `go-logr` or any other logging
library, and do not implement your own `slog.Handler`.

The reason is a security property, not taste. `slog`'s `TextHandler` and
`JSONHandler` escape control characters in every position — message, attribute
key, attribute value, group name, group-prefixed key and slice element — so a
newline in a certname cannot terminate a record and forge a second log entry.
That is why CodeQL's `go/log-injection` rule is excluded in
[.github/codeql/codeql-config.yml](.github/codeql/codeql-config.yml): the query
models sinks rather than handlers, and would otherwise report every untrusted
value reaching a log call, for ever. The exclusion is sound only while this
convention holds.

Two guards back it up, and neither is complete on its own:

- `.golangci.yml`'s `only-slog-logs` depguard rule denies the known unescaped
  logging libraries. It is a **denylist** — an unlisted library, or an
  `slog.Handler` written in this tree, passes lint. That gap is why this
  section exists.
- `cmd/openvox-ca/main_test.go` ("control characters in logged data cannot
  forge a second entry") pins the escaping behaviour itself, so a stdlib
  regression fails CI.

Output that is operator-facing but not `slog` — such as
`internal/storage/migrate.go`'s `Logf`, which the CLI writes straight to stderr
— gets no escaping from anything. Format values that have not passed
`ca.ValidateSubject` with `%q` there — including values decoded from a server
response, which nothing re-validates. `import-cert`'s summary lines are the
worked example, and `cmd/openvox-ca-ctl/importcert_test.go` pins them.

**The rule of thumb: if the server chose the value, quote it.** `import-cert`'s
summary, `checkHTTP`'s error body and `sign --all`'s list are all quoted for
that reason, and each has a spec that fails if the quoting is removed.

Two kinds of unquoted output are deliberately left alone, for two *different*
reasons:

- **The `sign` / `clean` / `revoke` single-value confirmations** echo the
  operator's own `--certname` / `--serial` input, so there is no untrusted
  value to escape. Not "escaping declined" — out of scope.
- **`generate`'s certificate output** (`fmt.Print(result.Certificate)`) is the
  PEM itself on stdout, while its human-readable line goes to stderr. That
  split is a contract — `openvox-ca-ctl generate … > cert.pem` must yield a
  usable file — so quoting would corrupt every consumer that redirects. This
  convention covers operator-facing *messages*; that is data.

`list`'s status table used to be a third exception, on the grounds that
quoting would wreck its column alignment. **That reason was false** —
`printTable` derives its width from the strings it is given, so quoting before
the row is built leaves the columns correct — and the table is now quoted like
everything else the server chose. `cmd/openvox-ca-ctl/list_test.go` pins both
the escaping and the alignment, so the exemption cannot return on a rationale
that does not hold.

## Compatibility contracts (do not rename)

openvox-ca is a drop-in for the OpenVox/Puppet Server CA. The following
identifiers are deliberately preserved for backward compatibility and **must
not** be rebranded:

- HTTP route prefix `/puppet-ca/v1`
- Environment-variable prefix `PUPPET_CA_` (and `PUPPET_CA_CTL_` for the CLI)
- Prometheus metric namespace `puppetca_`
- Storage key prefixes and the config-file location (`puppet-ca`, `/etc/puppet-ca`)
- The `puppet-ca` spelling itself, wherever a path uses it — `/var/lib/puppet-ca`
  included

**This is a contract about names, not about which path is the default.** A
default may move; the spelling may not be rebranded to `openvox-ca`.
`/var/lib/puppet-ca` is the case where the two are easy to confuse: it is still
a supported `--cadir`, and it remains the Helm chart's `persistence.mountPath`
default — but it is no longer what the packages or the systemd unit default to.
Those default to `/etc/puppetlabs/puppet/ssl/ca`, which is the Clojure CA's own
layout and the one path the hardened unit grants under `ProtectSystem=strict`
(see [docs/systemd.md](docs/systemd.md)). Neither of those is a rename, so
neither breaches this contract.

One deliberate exception, and it is the only path in the tree spelled the new
way: the packages record whether they have enabled their provisioning oneshot
under **`/var/lib/openvox-ca`** (`packaging/scripts/postinstall`). It is not a
rebrand of `/var/lib/puppet-ca` but a different directory for a different
thing — packaging bookkeeping that never existed in Puppet Server, so there is
nothing to be a drop-in for. It must not be moved under `/var/lib/puppet-ca`,
which is a cadir on hosts that have one there already — it is the Helm
chart's `persistence.mountPath` default; a marker file
dropped inside somebody's CA directory is the confusion this avoids.

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
