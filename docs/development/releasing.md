# Cutting a release

> This is a maintainer reference. It describes how to publish a tagged release
> of OpenVox CA, what the automation does, and how to rehearse the whole thing
> on a personal fork before touching the upstream repository.

A release is two actions: **land a change setting the release version, then
push an annotated `v*` tag** pointing at it. Everything else is automation —
there is no release branch and no manual artefact upload.

The `Version` constant in
[`internal/version`](../../internal/version/version.go) is the single source
of truth: artefact names embed it, both binaries report it via `--version`,
the Helm chart's `version` and `appVersion` track it, and the Release workflow
refuses to publish a tag that does not equal `"v" + Version`. Between releases
the constant carries a `-dev` suffix, so a stray tag on an unprepared commit
fails the gate instead of shipping mislabelled artefacts.

## What a release produces

| Artefact | Produced by | Where it lands |
| --- | --- | --- |
| `openvox-ca_X.Y.Z_linux_amd64.tar.gz` | `mage build:distVariant` (Release workflow) | GitHub release assets |
| `openvox-ca_X.Y.Z_linux_arm64.tar.gz` | `mage build:distVariant` (Release workflow) | GitHub release assets |
| `openvox-ca_X.Y.Z_linux_amd64_fips.tar.gz` | `mage build:distVariant` (`GOEXPERIMENT=boringcrypto`) | GitHub release assets |
| `openvox-ca_X.Y.Z_linux_arm64_fips.tar.gz` | `mage build:distVariant` (`GOEXPERIMENT=boringcrypto`) | GitHub release assets |
| `openvox-ca_X.Y.Z_<variant>.spdx.json` / `.cdx.json` | Syft, via [`generate-sbom`](../../.github/actions/generate-sbom/action.yml) (one pair per variant) | GitHub release assets |
| `openvox-ca_X.Y.Z_<arch>.deb` (one per non-FIPS variant) | `mage build:packages` (Release workflow, packaging job) | GitHub release assets |
| `openvox-ca-X.Y.Z-<release>.<arch>.rpm` (one per non-FIPS variant) | `mage build:packages` (Release workflow, packaging job) | GitHub release assets |
| `checksums.txt` (SHA-256, covers the tarballs, the SBOMs and the packages) | Release workflow (`sha256sum` aggregate step) | GitHub release assets |
| `provenance.sigstore.json` | `actions/attest`, over every line of `checksums.txt` | GitHub release assets |
| GitHub release + auto-generated notes | `gh release create --generate-notes` | Releases page |
| `ghcr.io/voxpupuli/openvox-ca:{X.Y.Z,X.Y,latest}` | *Container images* workflow | GHCR |
| `…:{X.Y.Z,X.Y,latest}-alpine` | *Container images* workflow | GHCR |
| `ghcr.io/voxpupuli/openvox-ca-charts/openvox-ca:X.Y.Z` | *Helm chart* workflow | GHCR (OCI, separate package) |

Every tarball, SBOM and package above, plus each published image and the chart,
carries SLSA v1.0 build provenance signed through Sigstore; the images and the chart are
additionally signed with `cosign sign`. `checksums.txt` is not itself an
attestation subject — its lines *are* the signed subject list, so it is
authenticated by the bundle rather than alongside it — and
`provenance.sigstore.json` is that bundle. See [verifying a
release](#verifying-a-release).

Each tarball contains both binaries, `openvox-ca` and `openvox-ca-ctl` (mode
0755), and the systemd unit `openvox-ca.service` (mode 0644) — see [running
under systemd](../systemd.md). Only Linux is built: there are no macOS or
Windows release artefacts. To build the same four tarballs (plus a
tarballs-only `checksums.txt`) locally in one go, run `mage build:dist`. Once
[#282](https://github.com/voxpupuli/openvox-ca/pull/282) merges,
`mage build:packages` will build the packages from those tarballs the same way
— it is an ordinary local target, not a workflow-only step. The SBOMs and the
provenance bundle are the two things that will still not build locally: they
are produced by the release workflow only.

### Packages

The `.deb` and `.rpm` are built from the tarballs, not from a separate compile:
the binaries inside `openvox-ca_X.Y.Z_amd64.deb` are byte-for-byte the ones
inside `openvox-ca_X.Y.Z_linux_amd64.tar.gz`. What follows from that:

- **No package-specific SBOM.** The variant's existing SPDX and CycloneDX pair
  already describes the package's contents. The cost is a mapping step: a
  consumer holding only `openvox-ca-X.Y.Z-1.x86_64.rpm` has to know that
  `x86_64` is the `linux_amd64` variant before it can find the matching
  `openvox-ca_X.Y.Z_linux_amd64.spdx.json`. The rpm and deb architecture
  spellings are the ones each format uses natively — `x86_64`/`aarch64` for
  rpm, `amd64`/`arm64` for deb — and neither is the variant name.
- **The packages are attested with no extra step.** They are listed in
  `checksums.txt`, and the attestation's subjects are exactly that file's
  lines, so they acquire the same SLSA provenance the tarballs have.
- **The exact filenames are nfpm's, and #250 fixes them.** The shapes above are
  the conventional ones each format uses, but the rpm `release` field (the
  `-1`) and any epoch are nfpm configuration, so treat the worked examples here
  as illustrative until #282 has merged. Nothing in the repository checks them:
  `verifyDistVariants` reads the workflows, not this file, and even there it
  matches only globbed extensions by design — so a filename written in prose
  cannot satisfy a guard by being written down.
- **`packageFormats` in `magefile.go` is the list of formats, and #250 must
  build from it.** `verifyDistVariants` holds `release.yml`'s package counts
  and globs to that variable, but it cannot see the packaging code, so nothing
  stops an implementation of `mage build:packages` carrying a second list of
  its own — which is the drift the `packaged` field was made a field to avoid.
  Whoever implements #250 should read the formats from `packageFormats`.
- **The FIPS variants are not packaged.** An operator under a FIPS obligation
  installs into a controlled estate rather than from a repository, so
  `linux_amd64_fips` and `linux_arm64_fips` ship as tarballs only. This is
  recorded as `packaged` on `distVariantSpec` in `magefile.go`, and
  `verifyDistVariants` holds `release.yml`'s package counts to it.

> **Not yet implemented — do not push a `v*` tag until
> [#282](https://github.com/voxpupuli/openvox-ca/pull/282) has merged.**
> `mage build:packages` and the package payload — the unit, the provisioning
> helper, the maintainer scripts — are [#250](https://github.com/voxpupuli/openvox-ca/issues/250), implemented by #282. The PR
> is named for the gate because a merge is what the gate waits on; the issue is
> named for the deliverable, and stays true if the PR is ever closed and
> reopened. Until #282 merges the packaging job has nothing to call, and the
> Release workflow fails there.
>
> Within the Release workflow that failure is clean: it is before the
> attestation and before `gh release create`, so no release, no assets and no
> provenance are published. **The tag as a whole is not clean, though.** The
> three `v*` workflows are independent (see the table below): *Container
> images* and *Helm chart* have no dependency on *Release*, so they publish
> their images — including the mutable `latest` tags — and the chart anyway.
> Recovering from that means deleting GHCR package versions, not re-tagging.
> The [rehearsal](#rehearsing-on-your-own-fork) section's teardown steps are the
> shape of it, but they are written for a fork: they delete through
> `/user/packages/container/...`, and the upstream packages are org-owned, so
> the real path is `/orgs/voxpupuli/packages/container/...` and needs org admin
> — or the package's *Versions* page in the web UI. Which is why the
> instruction is "do not tag", not "re-tag after".

The major-only container tag (`:1`, `:2`) is deliberately suppressed while the
version is `v0.*`, because a `0.x` major carries no compatibility promise.

## The machinery

Three workflows fire off the same tag push. None re-runs the CI suite — each
starts with the shared verify gate described below, which checks that CI
already passed. Release and Container images then run independently; the Helm
chart build waits for the alpine image before publishing, so that a published
chart can never name an image that does not exist.

| Workflow | File | What it does on a `v*` tag |
| --- | --- | --- |
| **Release** | [`release.yml`](../../.github/workflows/release.yml) | Verifies the tag equals `"v" +` the `internal/version` constant, builds each variant on a runner native to its architecture (`mage build:distVariant`, no cross toolchain), verifies each built artefact (binaries execute, FIPS variants carry boringcrypto build info), generates each variant's SBOM pair, packages the non-FIPS variants as `.deb` and `.rpm` on a single runner, then aggregates the lot, generates `checksums.txt`, attests provenance over everything it lists, and runs `gh release create` |
| **Container images** | [`container-images.yml`](../../.github/workflows/container-images.yml) | After the same verify gate, builds both image variants on native amd64 and arm64 runners, attests provenance and an SBOM pair per architecture, publishes multi-arch manifests, then attests and `cosign sign`s each published index. See [publishing container images](publishing-images.md) |
| **Helm chart** | [`helm-chart.yml`](../../.github/workflows/helm-chart.yml) | After the same verify gate, packages `charts/openvox-ca`, waits for the tag's alpine image to appear, pushes the chart to `ghcr.io/voxpupuli/openvox-ca-charts` as an OCI artefact, attests and signs it against the digest the push reported, then pulls it back to prove the reference resolves |

> **CI's full suite does not re-run on tags.** Instead, all three
> tag-triggered workflows start with the shared
> [`verify-release-tag`](../../.github/actions/verify-release-tag/action.yml)
> gate: the tag must equal `"v" +` the `internal/version` constant, the Helm
> chart's `version` and `appVersion` must equal it too, and the tagged commit
> must already have a passing *CI success* check run — i.e. it went green on
> `main`. Tagging an unprepared, unmerged, or red commit fails the gate instead
> of publishing. (The artefact builds themselves are also exercised on every PR
> by CI's per-variant *Release artefact build* jobs, and the chart by its
> *Helm chart* job. **The packaging step is the exception**: nothing runs
> `mage build:packages` on a pull request, so a green CI run says nothing
> about it, and a packaging defect would first appear on a tag. Adding that
> leg is [#254](https://github.com/voxpupuli/openvox-ca/issues/254).)

## Before you tag

> **Blocked until [#282](https://github.com/voxpupuli/openvox-ca/pull/282)
> merges.** `mage build:packages` does not exist yet, so the Release workflow
> fails at its packaging job while *Container images* and *Helm chart* publish
> regardless — including the mutable `latest` tags. Check that `mage
> build:packages` runs before you go any further; the reasoning and the
> recovery are under [Packages](#packages).

1. **Land the version bump.** Run:

   ```console
   $ mage release:prepare 0.9.0
   ```

   It creates a `release/v0.9.0` branch off `origin/main`, sets the `Version`
   constant in
   [`internal/version/version.go`](../../internal/version/version.go) and the
   `version`/`appVersion` fields in
   [`charts/openvox-ca/Chart.yaml`](../../charts/openvox-ca/Chart.yaml) to
   match, pushes the branch, and opens the release PR with a preview of the
   auto-generated release notes in its body. Merge that PR. The verify gate
   refuses a tag whose version does not match the constant — or the chart — at
   the tagged commit, so this must land first.

   Merging it also triggers the *Helm chart* workflow, which will deliberately
   publish nothing and say so: only `-dev` versions publish from `main`, since
   any other version is one somebody means to tag, and the chart for it belongs
   to that tag's gated build. (The manual equivalent: edit all
   three to the release version without the `v` prefix and open a PR yourself;
   `mage chart:version` checks they agree.)

2. **Confirm the target commit is green on `main`.**

   ```console
   $ git fetch origin
   $ git log --oneline -1 origin/main
   $ gh run list --branch main --limit 5
   ```

   The *CI success* job is the aggregate gate — that is the one that must be
   green, and it is also what the verify gate checks for on the tagged
   commit, so an un-green commit cannot be released by accident. Wait for it
   before tagging.

3. **Check the tree builds the release artefacts.** This catches
   cross-compilation breakage before the workflow does:

   ```console
   $ mage build:dist
   $ ls -l dist/
   ```

   **This only completes on Linux.** The two pure-Go variants
   (`CGO_ENABLED=0`) cross-compile from anywhere, but the FIPS variants are
   `cgo` builds and need a Linux C toolchain per target architecture (the
   cross ones on Debian/Ubuntu: `gcc-aarch64-linux-gnu` /
   `gcc-x86-64-linux-gnu`) — on macOS the FIPS builds fail up front with
   `cgo: C compiler "x86_64-linux-gnu-gcc" not found` (and the aarch64
   equivalent), after the pure-Go tarballs have already been written, leaving
   `dist/` incomplete. That is expected, not a regression.

   From macOS, either check the pure-Go variants only:

   ```console
   $ CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /dev/null ./cmd/...
   $ CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /dev/null ./cmd/...
   ```

   …and leave the FIPS builds to CI (a single variant can also be built with
   `mage build:distVariant linux_amd64`), or run the full thing in a
   container:

   ```console
   $ docker run --rm -v "$PWD:/src" -w /src golang:1-bookworm \
       sh -c 'go install github.com/magefile/mage@v1.17.2 && mage build:dist'
   ```

   The FIPS variants are the ones most likely to break, precisely because
   they are the only `cgo` builds in the set and the only ones you cannot
   casually check from a Mac.

4. **Skim the commits since the previous tag** so you know what the release
   notes ought to say (for the first release, since the start of history):

   ```console
   $ git log --oneline --no-merges v0.8.0..origin/main   # or: origin/main, for the first tag
   ```

5. **Decide whether this is a pre-release.** See
   [Pre-1.0 and pre-release tags](#pre-10-and-pre-release-tags) below —
   a `v0.9.0` tag is *not* treated as a pre-release by the automation, and
   will claim the `latest` container tag.

## Cutting the release

```console
$ git fetch origin
$ git tag -a v0.9.0 <commit-sha> -m "OpenVox CA 0.9.0"
$ git show v0.9.0                      # sanity-check the target and signature
$ git push origin v0.9.0
```

Notes:

- Use an **annotated** tag (`-a`). The workflows key off `github.ref_name`, so
  a lightweight tag technically works, but annotated tags carry the tagger,
  date, and message, and are what `git describe` prefers.
- Tags are signed automatically if you have `tag.gpgsign = true` set (this
  repository's maintainers do).
- Push the tag to **`origin` (`voxpupuli/openvox-ca`)**, not to a fork, when
  making a real release.
- `<commit-sha>` is optional; without it you tag `HEAD`, which is only correct
  if your local `main` is exactly `origin/main`. Being explicit is safer.
- If you have the repository's git hooks installed (`lefthook install`), the
  pre-push hook runs the version-match checks locally — both the
  `internal/version` constant and the chart's `version`/`appVersion` — and
  refuses a mismatching `v*` tag before it ever reaches the remote, the same
  checks the server-side gate would fail, minus the delete/fix/re-tag round
  trip.

Then watch all three workflows:

```console
$ gh run list --limit 5
$ gh run watch <run-id>
```

The release build takes a few minutes; the container build is the slowest of
the three (four image builds plus two manifest merges). The chart build waits
for the alpine image before publishing, so it finishes shortly after the
container build does.

After the release is out, return `main` to a development version so builds
from `main` stop identifying as the release:

```console
$ mage release:prepare 0.10.0-dev
```

This opens a small "Bump version to 0.10.0-dev" PR; merge it.

## Verifying a release

Every artefact published from a `v*` tag — each tarball, each SBOM, each
package, each image and the chart — carries SLSA v1.0 build provenance, signed through Sigstore's
public-good instance with a short-lived certificate. There is
no signing key held anywhere: the identity in the certificate is the workflow
that produced the artefact, which is what a verifier should be checking anyway.

| Artefact | Provenance | SBOM | `cosign sign` signature |
| --- | --- | --- | --- |
| Release tarballs | `provenance.sigstore.json`, one bundle over every line of `checksums.txt` | Published as assets, both formats | — (the bundle is the signature) |
| Release packages (`.deb`, `.rpm`) | The same bundle — they are lines of `checksums.txt` too | — (the variant tarball's pair describes the same binaries) | — (the bundle is the signature; rpm header signing is a separate question, see below) |
| Container images, per architecture | Registry attestation on the digest | Registry attestation, both formats | Yes — written by the index's `--recursive` signing, not a separate call |
| Container image indexes | Registry attestation on the index digest | — (per-architecture SBOMs are the meaningful ones) | Yes, `--recursive` over the index and its children |
| Helm chart | Registry attestation on the pushed digest | — (no dependencies, nothing to catalogue) | Yes |

The reader-facing commands are in the [README](../../README.md#verifying-what-you-downloaded).
Three things worth knowing that belong here rather than there:

- **Verify against a digest, or against a pinned identity — not a bare tag.**
  Images are built for pull requests too, and those runs mint certificates whose
  identity ends `@refs/pull/N/merge`. `--certificate-identity-regexp` anchored to
  `@refs/tags/v` is what distinguishes a release build from a PR build.
- **`cosign sign` accepts a tag, and signing one would be a mistake.** A tag is
  mutable; the whole publishing path is careful to sign only digests it learned
  from the push itself — `imagetools create --metadata-file` for the image
  indexes, `helm push`'s reported digest for the chart. Nothing re-resolves a tag
  between publishing and signing. After signing, each workflow asserts that the
  tags it published still resolve to the digest it signed, which converts a lost
  race into a red build rather than a silently unsigned tag.
- **The `.rpm` carries no rpm header signature.** `dnf` with `gpgcheck=1`
  verifies a signature *inside* the package, and there is not one; what the
  packages carry is the Sigstore bundle over `checksums.txt`, which `dnf` does
  not know how to check. `apt` is unaffected — it verifies the repository
  index, not the individual `.deb`, and Debian's own archive does not sign
  `.deb` files either. Signing rpm headers is
  [#256](https://github.com/voxpupuli/openvox-ca/issues/256), deferred on the
  question of whose key: an rpm signed with a key nobody publishes is
  verification theatre.

## Release notes

`release.yml` calls `gh release create --generate-notes`, which asks GitHub to
build the notes from the **merged pull requests** between the previous release
tag and this one. It produces a flat "What's Changed" list plus a new
contributors section and a full changelog link.

Two consequences worth knowing:

- **On the first-ever tag there is no previous release**, so GitHub generates
  notes covering the entire history of the repository. For this repository
  that is 300-plus commits, the majority of them Renovate and Dependabot
  dependency bumps. The generated notes for `v0.9.0` will be a very long,
  very noisy list.
- **The notes are generated once, at release-creation time.** They are not
  regenerated later, so editing them afterwards is safe and permanent.

### Curating the notes after the fact

The generated notes are a starting point, not the finished product. The
expected workflow is to let the automation create the release, then edit it:

```console
$ gh release view v0.9.0                       # read what was generated
$ gh release edit v0.9.0 --notes-file NOTES.md # replace wholesale
```

For a first release in particular, write a short human summary at the top —
what OpenVox CA is, what state it is in, what the notable capabilities are —
and either trim the dependency churn or fold the auto-generated list into a
collapsed `<details>` block beneath it.

To see what GitHub *would* generate before you tag, ask for it directly:

```console
$ gh api repos/voxpupuli/openvox-ca/releases/generate-notes \
    -f tag_name=v0.9.0 -f target_commitish=main --jq .body
```

That call is read-only and creates nothing, so it is a safe dry run.

### What the generated notes include

[`.github/release.yml`](../../.github/release.yml) configures the generated
notes: everything authored by `renovate[bot]` and `dependabot[bot]` is
excluded outright (dependency bumps dominate the merge history), and the
remaining PRs are grouped by label — `breaking`, `enhancement`/`feature`,
`bug`, `documentation` — with unlabelled PRs falling through to "Other
changes". Labelling PRs as they merge is what keeps the notes usable without
hand-editing.

## Pre-1.0 and pre-release tags

A **semver pre-release tag** — any tag with a hyphen, e.g. `v0.9.0-rc1` — is
handled specially by the Release and Container images workflows: the GitHub
release is created with `--prerelease` (it will not appear as the latest stable
release), and `docker/metadata-action` withholds the `latest` container tags.
The Helm chart workflow treats it like any other tag — the chart publishes at
that exact version — and because only `-dev` versions publish from `main`,
merging the `-rc1` release-prep PR deliberately publishes nothing. Use a
pre-release tag for anything you do not want users upgrading to by default.

A plain `v0.9.0`, by contrast, is **not** a pre-release in semver terms
despite the `0.` major: it publishes as the latest stable GitHub release and
claims `ghcr.io/voxpupuli/openvox-ca:latest` and `:latest-alpine`. The only
`v0.*` concession is the suppressed major-only container tag. If you want a
`0.x` release marked as a GitHub pre-release anyway, fix it afterwards with
`gh release edit v0.9.0 --prerelease`.

## Rehearsing on your own fork

The workflows derive everything they need from the repository they run in —
the image name is computed from `github.repository`, and the release is created
with the run's own `GITHUB_TOKEN` — so a fork is a complete, self-contained
rehearsal environment. Nothing points back at the upstream repository.

A fork run publishes to `ghcr.io/<you>/<fork-name>` and creates a release on
your fork. Both are throwaway.

### Setup (once)

1. Confirm the fork is **public** — the free `ubuntu-24.04-arm` runners used
   for the arm64 image builds are only free on public repositories. On a
   private fork the arm64 jobs queue indefinitely.
2. Confirm Actions are enabled and the five workflows are active:

   ```console
   $ gh api repos/<you>/<fork>/actions/workflows --jq '.workflows[] | {name, state}'
   ```

3. Confirm the fork's `GITHUB_TOKEN` may write packages: Settings → Actions →
   General → *Workflow permissions* → **Read and write permissions**.
4. Check your remote actually points where you think. If you renamed the fork
   on GitHub, the local remote URL may still carry the old name and work only
   via GitHub's redirect:

   ```console
   $ git remote -v
   $ git remote set-url <remote> git@github.com:<you>/<fork>.git
   ```

### The rehearsal

The verify gate applies on the fork too, so the rehearsal runs the real
process end to end — version-bump PR, merge, green CI, tag:

```console
$ git push <fork-remote> main            # fork main must match what you'll tag
$ OPENVOX_CA_RELEASE_REMOTE=<fork-remote> mage release:prepare 0.9.0-test1
# merge the PR it opens on the fork, wait for CI on the fork's main to go
# green (the verify gate checks for a passing "CI success" run), then:
$ git fetch <fork-remote>
$ git tag -a v0.9.0-test1 <fork-remote>/main -m "release rehearsal"
$ git push <fork-remote> v0.9.0-test1
$ gh run list --repo <you>/<fork> --limit 5
```

Use a tag name you will never want upstream (`v0.9.0-test1`, `v0.0.1-rehearsal`)
so there is no chance of it being confused with the real thing later — the
hyphen also makes it a semver pre-release, so the rehearsal release is marked
as a pre-release and the fork's `latest` container tags stay untouched.

Then verify the results end to end:

```console
$ gh release view v0.9.0-test1 --repo <you>/<fork>
$ gh release download v0.9.0-test1 --repo <you>/<fork> --dir /tmp/rehearsal
$ cd /tmp/rehearsal && sha256sum -c checksums.txt
$ tar tzf openvox-ca_0.9.0-test1_linux_amd64.tar.gz
$ docker run --rm ghcr.io/<you>/<fork>:0.9.0-test1 --version
```

Worth checking specifically:

- All four tarballs are present, and one `.deb` and one `.rpm` for each of the
  two non-FIPS variants. Run `sha256sum -c` **without** `--ignore-missing`, so
  that a file listed in `checksums.txt` and absent from the download is a
  failure rather than a silent skip — that is the check, rather than a count
  to compare against a number written here, which would be one more
  hand-maintained copy of a quantity `verifyDistVariants` already owns:

  ```console
  $ sha256sum -c checksums.txt
  $ ls -1 *.deb *.rpm
  ```

- **Open one package of each format.** Nothing in the pipeline does: the
  tarballs are unpacked and executed by `verify-dist-artifact` before they are
  attested, and the packages have no counterpart, so a well-formed package
  with the wrong contents would be checksummed, attested and published. Until
  [#254](https://github.com/voxpupuli/openvox-ca/issues/254) adds
  install-and-verify legs, this is the only place anyone looks inside one:

  ```console
  $ dpkg-deb -c openvox-ca_*_amd64.deb
  $ rpm -qlp openvox-ca-*.x86_64.rpm
  ```

  Both binaries should be present and executable, the systemd unit should be
  there, and the version in the filename should be the rehearsal version. Note
  that nfpm rewrites a pre-release version for both formats — `0.9.0-test1`
  becomes `0.9.0~test1`, which sorts *before* `0.9.0` as it should — so the
  package filenames will not match the tarballs' character for character.

- Each tarball contains both `openvox-ca` and `openvox-ca-ctl`, and both
  report the rehearsal version (with commit metadata) via `--version`.
- Each tarball also contains `openvox-ca.service`, and `tar tvzf` shows it as
  `-rw-r--r--` while the two binaries are `-rwxr-xr-x`.
- The FIPS binaries are genuinely boringcrypto builds:

  ```console
  $ go version -m openvox-ca | grep -E 'boringcrypto|GOEXPERIMENT'
  ```

- The published manifest really is multi-arch:

  ```console
  $ docker buildx imagetools inspect ghcr.io/<you>/<fork>:0.9.0-test1
  ```

- All eight SBOMs are present, both formats for each variant, and each one
  actually catalogues the Go modules rather than being an empty document:

  ```console
  $ ls *.spdx.json *.cdx.json | wc -l          # expect 8
  $ jq '[.packages[].externalRefs[]?.referenceLocator
         | select(startswith("pkg:golang/"))] | length' \
      openvox-ca_0.9.0-test1_linux_amd64.spdx.json
  ```

- Provenance verifies, both ways — through GitHub and offline through the
  published bundle:

  ```console
  $ gh attestation verify openvox-ca_0.9.0-test1_linux_amd64.tar.gz --repo <you>/<fork> \
      --signer-workflow <you>/<fork>/.github/workflows/release.yml \
      --source-ref refs/tags/v0.9.0-test1
  $ cosign verify-blob-attestation openvox-ca_0.9.0-test1_linux_amd64.tar.gz \
      --bundle provenance.sigstore.json --type slsaprovenance1 \
      --certificate-identity https://github.com/<you>/<fork>/.github/workflows/release.yml@refs/tags/v0.9.0-test1 \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com
  ```

  The second command is the one that matters most: it is the only check that
  the bundle published as a release asset is usable on its own. It also proves
  the multi-subject bundle resolves for an individual file — verify a second
  artefact against the *same* bundle to confirm that:

  ```console
  $ cosign verify-blob-attestation openvox-ca_0.9.0-test1_linux_arm64_fips.tar.gz \
      --bundle provenance.sigstore.json --type slsaprovenance1 \
      --certificate-identity https://github.com/<you>/<fork>/.github/workflows/release.yml@refs/tags/v0.9.0-test1 \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com
  ```

- The image signature and attestations are discoverable on GHCR. This is the
  assumption the whole GitHub-native-attestation choice rests on — that cosign
  finds attestations GitHub pushed to the registry — so it is worth checking
  explicitly rather than inferring from a green build:

  ```console
  $ ident='^https://github\.com/<you>/<fork>/\.github/workflows/container-images\.yml@refs/tags/v'
  $ cosign verify ghcr.io/<you>/<fork>:0.9.0-test1 \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      --certificate-identity-regexp "$ident"
  $ cosign verify-attestation ghcr.io/<you>/<fork>:0.9.0-test1 \
      --type slsaprovenance1 \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      --certificate-identity-regexp "$ident"
  $ gh attestation verify oci://ghcr.io/<you>/<fork>:0.9.0-test1 --repo <you>/<fork> \
      --signer-workflow <you>/<fork>/.github/workflows/container-images.yml \
      --source-ref refs/tags/v0.9.0-test1
  ```

- `cosign sign --recursive` reached the children, not just the index. Signing an
  index assembled by `imagetools create` (rather than pushed directly by buildx)
  is the step most likely to surprise, so check a child manifest by digest:

  ```console
  $ child="$(docker buildx imagetools inspect ghcr.io/<you>/<fork>:0.9.0-test1 \
      --format '{{range .Manifest.Manifests}}{{if eq .Platform.Architecture "amd64"}}{{.Digest}}{{end}}{{end}}')"
  $ cosign verify "ghcr.io/<you>/<fork>@${child}" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      --certificate-identity-regexp "$ident"
  ```

- The per-architecture SBOM attestations are discoverable, which is the one
  verification command a rehearsal would otherwise never exercise — the index
  carries provenance only, so a check against the tag passes without ever
  touching an SBOM:

  ```console
  $ gh attestation verify "oci://ghcr.io/<you>/<fork>@${child}" --repo <you>/<fork> \
      --signer-workflow <you>/<fork>/.github/workflows/container-images.yml \
      --source-ref refs/tags/v0.9.0-test1 \
      --predicate-type https://spdx.dev/Document/v2.3
  $ gh attestation verify "oci://ghcr.io/<you>/<fork>@${child}" --repo <you>/<fork> \
      --signer-workflow <you>/<fork>/.github/workflows/container-images.yml \
      --source-ref refs/tags/v0.9.0-test1 \
      --predicate-type https://cyclonedx.org/bom
  ```

- The chart is signed too:

  ```console
  $ cosign verify ghcr.io/<you>/<fork>-charts/openvox-ca:0.9.0-test1 \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      --certificate-identity-regexp \
        '^https://github\.com/<you>/<fork>/\.github/workflows/helm-chart\.yml@refs/tags/v'
  ```

- The chart published, and installs the image the release actually produced:

  ```console
  $ helm show chart oci://ghcr.io/<you>/<fork>-charts/openvox-ca --version 0.9.0-test1
  $ helm template openvox-ca oci://ghcr.io/<you>/<fork>-charts/openvox-ca \
      --version 0.9.0-test1 | grep 'image:'
  ```

  The chart's `version` and `appVersion` should both be `0.9.0-test1`, and the
  rendered image reference `ghcr.io/voxpupuli/openvox-ca:0.9.0-test1-alpine`.
  Note that the chart's default `image.repository` is the upstream one — a fork
  rehearsal publishes the chart to the fork but the chart still points at the
  upstream image, which is correct: the chart's image default is not derived
  from the repository it was built in.

### Cleaning up

```console
$ gh release delete v0.9.0-test1 --repo <you>/<fork> --yes
$ git push <fork-remote> --delete v0.9.0-test1 release/v0.9.0-test1
$ git tag -d v0.9.0-test1
$ git branch -D release/v0.9.0-test1
```

The GHCR package versions have to be deleted separately, from the package's
*Versions* page on GitHub, or with:

```console
$ gh api --method DELETE /user/packages/container/<fork-name>/versions/<version-id>
```

The chart lives in a package of its own, `<fork-name>-charts/openvox-ca`, which
has to be cleaned up separately:

```console
$ gh api --method DELETE /user/packages/container/<fork-name>-charts%2Fopenvox-ca/versions/<version-id>
```

Deleting the rehearsal tags is not strictly necessary, but leaving them behind
means a later `git fetch --tags` from the fork pollutes your local tag list.

## Known gaps

These are current limitations of the release machinery rather than things you
can work around at release time. Some are worth closing before 1.0; others are
accepted trade-offs, recorded here so that the limitation is not a surprise
rather than because anyone intends to fix them. (Two entries that stood here
previously — unsigned artefacts, and tag builds restoring Go caches saved on
`main` — were closed together; see [verifying a
release](#verifying-a-release).)

| Gap | Impact |
| --- | --- |
| **`helm verify` has nothing to check.** | The chart is signed with cosign and carries SLSA provenance like everything else, but it is packaged without `helm package --sign`, so there is no `.prov` file for `helm push` to upload. Helm's own provenance mechanism is PGP: it wants a long-lived keyring, which is the thing Sigstore's short-lived certificates exist to avoid. Anyone whose tooling asserts specifically on `helm verify`, rather than on a cosign signature, is not served. |
| **Packaging is not implemented, so no tag can be cut.** | `mage build:packages` is [#250](https://github.com/voxpupuli/openvox-ca/issues/250), implemented by [#282](https://github.com/voxpupuli/openvox-ca/pull/282), and is not on `main` yet, so the Release workflow's packaging job fails and no release is published — while *Container images* and *Helm chart*, which trigger on the same tag and do not depend on Release, publish anyway. This is the one gap here that blocks releasing outright rather than degrading it. See [Before you tag](#before-you-tag). |
| **`dnf` with `gpgcheck=1` has nothing to check either.** | The same gap in a second ecosystem, and for the same reason. The `.rpm` carries no rpm header signature, so a `gpgcheck=1` repository rejects it; what it carries instead is the Sigstore bundle over `checksums.txt`, which `dnf` cannot read. `apt` is unaffected, because it verifies the repository index rather than the individual `.deb`, as Debian's own archive does. Signing rpm headers is [#256](https://github.com/voxpupuli/openvox-ca/issues/256), deferred on the question of whose key. See [verifying a release](#verifying-a-release). |
| **Nothing verifies what is inside a package.** | Tarballs are unpacked and their binaries executed by `verify-dist-artifact` before they are attested. The packages have no counterpart, so a well-formed package with the wrong contents is checksummed, attested and published, and the first person to find out runs `apt install`. The install-and-verify legs that close it are [#254](https://github.com/voxpupuli/openvox-ca/issues/254); until then the [rehearsal checklist](#rehearsing-on-your-own-fork) asks a maintainer to open one by hand. |
