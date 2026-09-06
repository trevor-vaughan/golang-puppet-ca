//go:build mage

// Copyright (C) 2026 Chris Boot
// Copyright (C) 2026 Vox Pupuli and contributors
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sassoftware/go-rpmutils"

	"github.com/voxpupuli/openvox-ca/internal/version"
)

var _ = Describe("releaseVersion", func() {
	// go test runs with the package directory (the repository root) as the
	// working directory, so the real internal/version/version.go is read:
	// this pins the textual parse against the actual constant, catching any
	// reformatting of the Version line that would break the workflows' and
	// hook's sed-based parsers of the same shape.
	It("round-trips the real Version constant", func() {
		ver, err := releaseVersion()
		Expect(err).NotTo(HaveOccurred())
		Expect(ver).To(Equal(version.Version))
	})
})

var _ = Describe("bareSemverRe", func() {
	DescribeTable("accepts bare semver with optional pre-release suffix",
		func(v string) { Expect(bareSemverRe.MatchString(v)).To(BeTrue()) },
		Entry("release", "0.9.0"),
		Entry("release candidate", "0.9.0-rc1"),
		Entry("development version", "0.10.0-dev"),
		Entry("dotted pre-release", "1.2.3-alpha.1"),
	)

	DescribeTable("rejects anything else",
		func(v string) { Expect(bareSemverRe.MatchString(v)).To(BeFalse()) },
		Entry("v prefix", "v0.9.0"),
		Entry("two components", "0.9"),
		Entry("four components", "0.9.0.1"),
		Entry("empty", ""),
		Entry("trailing space", "0.9.0 "),
		Entry("bare suffix", "-rc1"),
	)
})

var _ = Describe("fipsCrossCC", func() {
	// The CC environment variable changes the result, so pin it to unset for
	// each spec and restore whatever the caller had afterwards.
	BeforeEach(func() {
		if orig, ok := os.LookupEnv("CC"); ok {
			Expect(os.Unsetenv("CC")).To(Succeed())
			DeferCleanup(os.Setenv, "CC", orig)
		}
	})

	It("returns empty when CC is already set in the environment", func() {
		Expect(os.Setenv("CC", "clang")).To(Succeed())
		DeferCleanup(os.Unsetenv, "CC")
		Expect(fipsCrossCC("arm64")).To(BeEmpty())
	})

	It("returns empty for an unknown architecture", func() {
		Expect(fipsCrossCC("riscv64")).To(BeEmpty())
	})

	// Pin the exact cross-compiler names: CI only ever builds each FIPS
	// variant natively, so a wrong name here would otherwise go undetected
	// until someone cross-builds locally.
	DescribeTable("maps cross architectures to the GNU cross compilers",
		func(goarch, cc string) {
			if runtime.GOOS == "linux" && runtime.GOARCH == goarch {
				Skip("native on this host: covered by the native-build spec")
			}
			Expect(fipsCrossCC(goarch)).To(Equal(cc))
		},
		Entry("amd64", "amd64", "x86_64-linux-gnu-gcc"),
		Entry("arm64", "arm64", "aarch64-linux-gnu-gcc"),
	)

	It("returns empty for a native Linux build", func() {
		if runtime.GOOS != "linux" {
			Skip("native FIPS builds only exist on Linux")
		}
		Expect(fipsCrossCC(runtime.GOARCH)).To(BeEmpty())
	})
})

var _ = Describe("repoSlugFromURL", func() {
	DescribeTable("derives owner/repo",
		func(url, want string) {
			slug, err := repoSlugFromURL(url)
			Expect(err).NotTo(HaveOccurred())
			Expect(slug).To(Equal(want))
		},
		Entry("SSH scp-like", "git@github.com:voxpupuli/openvox-ca.git", "voxpupuli/openvox-ca"),
		Entry("SSH scp-like without .git", "git@github.com:bootc/openvox-ca", "bootc/openvox-ca"),
		Entry("HTTPS", "https://github.com/voxpupuli/openvox-ca.git", "voxpupuli/openvox-ca"),
		Entry("HTTPS without .git", "https://github.com/voxpupuli/openvox-ca", "voxpupuli/openvox-ca"),
		Entry("ssh scheme", "ssh://git@github.com/owner/repo.git", "owner/repo"),
	)

	It("rejects a URL it cannot parse", func() {
		_, err := repoSlugFromURL("not-a-url")
		Expect(err).To(MatchError(ContainSubstring("could not derive owner/repo")))
	})
})

var _ = Describe("distVariants", func() {
	It("defines the four release variants with coherent build environments", func() {
		variants := distVariants()
		Expect(variants).To(HaveLen(4))

		names := map[string]bool{}
		for _, v := range variants {
			Expect(names).NotTo(HaveKey(v.name), "duplicate variant name")
			names[v.name] = true

			Expect(v.name).To(MatchRegexp(`^linux_(amd64|arm64)(_fips)?$`))
			Expect(v.env["GOOS"]).To(Equal("linux"))
			Expect(v.name).To(ContainSubstring(v.env["GOARCH"]))

			if _, fips := v.env["GOEXPERIMENT"]; fips {
				Expect(v.name).To(HaveSuffix("_fips"))
				Expect(v.env["GOEXPERIMENT"]).To(Equal("boringcrypto"))
				Expect(v.env["CGO_ENABLED"]).To(Equal("1"))
			} else {
				Expect(v.name).NotTo(HaveSuffix("_fips"))
				Expect(v.env["CGO_ENABLED"]).To(Equal("0"))
			}
		}
	})
})

var _ = Describe("release archive contents", func() {
	// These replace a CI job that built all four variants, unpacked each
	// tarball and grepped `tar -tvz` for the entries and their modes. The
	// properties it checked are properties of the manifest and of the archive
	// writer, neither of which needs a release build to exercise.
	Describe("distArchiveFiles", func() {
		files := distArchiveFiles([]string{"openvox-ca", "openvox-ca-ctl"})

		It("ships both binaries executable and the unit not", func() {
			Expect(files).To(Equal([]archiveEntry{
				{name: "openvox-ca", mode: 0755},
				{name: "openvox-ca-ctl", mode: 0755},
				{name: "openvox-ca.service", mode: 0644},
			}))
		})

		It("names a unit that is actually in the repository", func() {
			// The manifest names a file that is copied in at build time; a
			// rename under packaging/ would otherwise break nothing until a
			// tag is pushed, at which point the tag exists and no artefacts do.
			Expect(filepath.Join("packaging", "systemd", distUnitFile)).To(BeAnExistingFile())
		})
	})

	Describe("createTarGz", func() {
		It("writes each entry with the mode the manifest asked for", func() {
			// Not the mode of the staged file: the release must extract the
			// same way whatever umask it was built under.
			srcDir := GinkgoT().TempDir()
			for _, name := range []string{"openvox-ca", "openvox-ca.service"} {
				Expect(os.WriteFile(filepath.Join(srcDir, name), []byte(name), 0600)).To(Succeed())
			}
			archive := filepath.Join(GinkgoT().TempDir(), "out.tar.gz")

			Expect(createTarGz(archive, srcDir, []archiveEntry{
				{name: "openvox-ca", mode: 0755},
				{name: "openvox-ca.service", mode: 0644},
			})).To(Succeed())

			Expect(tarEntries(archive)).To(Equal(map[string]tarEntry{
				"openvox-ca":         {mode: 0755, body: "openvox-ca"},
				"openvox-ca.service": {mode: 0644, body: "openvox-ca.service"},
			}))
		})

		It("reports a source file that is not there", func() {
			archive := filepath.Join(GinkgoT().TempDir(), "out.tar.gz")
			err := createTarGz(archive, GinkgoT().TempDir(), []archiveEntry{{name: "absent", mode: 0755}})
			Expect(err).To(MatchError(os.ErrNotExist))
		})
	})
})

// tarEntry is one unpacked archive member: the mode it would extract as and
// its contents.
type tarEntry struct {
	mode int64
	body string
}

// tarEntries reads a gzipped tarball back into a name-keyed map, so a spec can
// assert the whole archive in one comparison rather than walking it.
func tarEntries(path string) map[string]tarEntry {
	GinkgoHelper()

	f, err := os.Open(path)
	Expect(err).NotTo(HaveOccurred())
	defer f.Close()

	gz, err := gzip.NewReader(f)
	Expect(err).NotTo(HaveOccurred())
	defer gz.Close()

	entries := map[string]tarEntry{}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		Expect(err).NotTo(HaveOccurred())

		body, err := io.ReadAll(tr)
		Expect(err).NotTo(HaveOccurred())
		entries[hdr.Name] = tarEntry{mode: hdr.Mode, body: string(body)}
	}
	return entries
}

var _ = Describe("Release.Prepare", func() {
	// The bare-semver guard is Prepare's first statement, returning before
	// any git, gh, or filesystem side effect, so the rejection path is
	// hermetic — this pins both the wiring and that validation stays ahead
	// of the side effects.
	It("rejects a non-bare-semver version before any side effect", func() {
		err := Release{}.Prepare("v0.9.0")
		Expect(err).To(MatchError(ContainSubstring("is not bare semver")))
	})
})

var _ = Describe("Build.DistVariant", func() {
	It("rejects an unknown variant before building anything", func() {
		err := Build{}.DistVariant("nonsense")
		Expect(err).To(MatchError(ContainSubstring(`unknown dist variant "nonsense"`)))
		Expect(err).To(MatchError(ContainSubstring("linux_arm64_fips")), "error should list the known variants")
	})
})

var _ = Describe("workflowMatrixVariants", func() {
	yamlSrc := []byte(`
jobs:
  dist:
    strategy:
      matrix:
        include:
          - variant: linux_amd64
            runner: ubuntu-latest
          - variant: linux_arm64
            runner: ubuntu-24.04-arm
  other:
    runs-on: ubuntu-latest
`)

	It("extracts the variant names from a job's matrix include list", func() {
		names, err := workflowMatrixVariants(yamlSrc, "dist")
		Expect(err).NotTo(HaveOccurred())
		Expect(names).To(Equal([]string{"linux_amd64", "linux_arm64"}))
	})

	It("errors on a missing job", func() {
		_, err := workflowMatrixVariants(yamlSrc, "absent")
		Expect(err).To(MatchError(ContainSubstring(`"absent" not found`)))
	})

	It("errors on a job without variant matrix entries", func() {
		_, err := workflowMatrixVariants(yamlSrc, "other")
		Expect(err).To(MatchError(ContainSubstring("no matrix include entries")))
	})
})

var _ = Describe("shellVariantList", func() {
	It("extracts the loop's variant names", func() {
		names, err := shellVariantList([]byte(`for variant in linux_amd64 linux_arm64_fips; do`))
		Expect(err).NotTo(HaveOccurred())
		Expect(names).To(Equal([]string{"linux_amd64", "linux_arm64_fips"}))
	})

	It("errors when no loop is present", func() {
		_, err := shellVariantList([]byte("nothing here"))
		Expect(err).To(MatchError(ContainSubstring("no 'for variant in")))
	})
})

var _ = Describe("verifyAutomergeLabelExclusion", func() {
	// Against the repository's real ci.yml: the clause must actually be there.
	It("finds the real auto-merge job excluding the signing-review label", func() {
		Expect(verifyAutomergeLabelExclusion()).To(Succeed())
	})

	Describe("drift detection", func() {
		good := []byte(`
jobs:
  automerge:
    if: >-
      github.event_name == 'pull_request'
      && !contains(github.event.pull_request.labels.*.name, 'review-signing-path')
      && github.event.pull_request.user.login == 'renovate[bot]'
    steps:
      - run: gh pr merge --auto --merge "$PR_URL"
`)

		It("accepts a merging job that excludes the label", func() {
			Expect(verifyAutomergeLabelExclusionIn("ci.yml", good)).To(Succeed())
		})

		// The whole point: the clause is droppable in a tidy-up, and nothing
		// else in the repository would notice it had gone.
		It("rejects a merging job whose condition drops the label clause", func() {
			bad := bytes.Replace(good,
				[]byte("      && !contains(github.event.pull_request.labels.*.name, 'review-signing-path')\n"), nil, 1)
			// Both clauses are gone, and the error must name both — this is
			// the spec that distinguishes "clause deleted" from the
			// partial-match case below.
			Expect(verifyAutomergeLabelExclusionIn("ci.yml", bad)).To(MatchError(
				And(ContainSubstring(`job "automerge"`),
					ContainSubstring("github.event.pull_request.labels"),
					ContainSubstring("review-signing-path"))))
		})

		// Naming the label but not reading it from the PR's labels is not an
		// exclusion, however plausibly it reads.
		It("rejects a condition that names the label without consulting the PR's labels", func() {
			bad := bytes.Replace(good,
				[]byte("!contains(github.event.pull_request.labels.*.name, 'review-signing-path')"),
				[]byte("github.event.pull_request.title != 'review-signing-path'"), 1)
			Expect(verifyAutomergeLabelExclusionIn("ci.yml", bad)).To(MatchError(
				ContainSubstring("never consults")))
		})

		// The clause is required whole, not in fragments. Flipping it while an
		// unrelated !contains(...) sits elsewhere leaves every fragment present
		// — the label name, the labels context, a negation — and inverts the
		// meaning anyway. This mutation passed an earlier fragment-based
		// version of the guard, which is why the contract is the whole clause.
		It("rejects an inverted clause even when another negation is present", func() {
			bad := bytes.Replace(good,
				[]byte("      && !contains(github.event.pull_request.labels.*.name, 'review-signing-path')"),
				[]byte("      && contains(github.event.pull_request.labels.*.name, 'review-signing-path')\n"+
					"      && !contains(github.event.pull_request.title, 'WIP')"), 1)
			Expect(verifyAutomergeLabelExclusionIn("ci.yml", bad)).To(MatchError(
				ContainSubstring("never consults")))
		})

		// Exact on shape, free on spacing: the condition is a YAML block
		// scalar that people wrap and indent to taste, and a guard that failed
		// on a reflow would be reformatted away rather than obeyed.
		It("accepts the clause however it is spaced", func() {
			spaced := bytes.Replace(good,
				[]byte("!contains(github.event.pull_request.labels.*.name, 'review-signing-path')"),
				[]byte("!contains(  github.event.pull_request.labels.*.name,   'review-signing-path'  )"), 1)
			Expect(verifyAutomergeLabelExclusionIn("ci.yml", spaced)).To(Succeed())
		})

		// Dropping the '!' does not weaken the exclusion, it reverses it: the
		// job would then merge signing bumps unattended and nothing else. A
		// guard that passes the exact inversion of what it checks for is not
		// worth having, which is why the negation is a required clause and
		// not left to "consults, not constrains".
		It("rejects a condition whose label check is not negated", func() {
			bad := bytes.Replace(good, []byte("&& !contains("), []byte("&& contains("), 1)
			Expect(verifyAutomergeLabelExclusionIn("ci.yml", bad)).To(MatchError(
				And(ContainSubstring(`job "automerge"`), ContainSubstring("!contains("))))
			// And the reported clause is the whole expression a maintainer
			// must restore, not a fragment of it.
			Expect(verifyAutomergeLabelExclusionIn("ci.yml", bad)).To(MatchError(
				ContainSubstring("labels.*.name, 'review-signing-path')")))
		})

		// Comments never reach the parsed `if:` scalar, so naming the clauses
		// in one cannot satisfy the guard. Asserted rather than assumed: the
		// immunity comes from parsing the document instead of grepping it,
		// and a future rewrite to a text search would silently lose it.
		It("is not satisfied by a comment naming the required clauses", func() {
			bad := bytes.Replace(good,
				[]byte("      && !contains(github.event.pull_request.labels.*.name, 'review-signing-path')\n"),
				[]byte(""), 1)
			bad = bytes.Replace(bad, []byte("jobs:\n"),
				[]byte("jobs:\n  # github.event.pull_request.labels review-signing-path !contains(\n"), 1)
			Expect(verifyAutomergeLabelExclusionIn("ci.yml", bad)).To(MatchError(
				ContainSubstring("never consults")))
		})

		// A guard that finds nothing to guard has abstained, not passed. If
		// auto-merge is renamed or rewritten to merge some other way, this
		// must go red rather than quiet — that is the failure mode where a
		// green check is actively misleading. The cost is accepted knowingly:
		// legitimately removing auto-merge will fail this until the guard goes
		// too. See the note at the merging == 0 branch.
		It("refuses to pass when no job merges pull requests at all", func() {
			bad := bytes.Replace(good, []byte("gh pr merge --auto --merge"), []byte("echo nothing to do"), 1)
			Expect(verifyAutomergeLabelExclusionIn("ci.yml", bad)).To(MatchError(
				ContainSubstring("no job runs `gh pr merge`")))
		})
	})
})

var _ = Describe("verifyDistVariants", func() {
	// Runs against the repository's real workflow files: this is the
	// cross-check that keeps ci.yml, release.yml, and distVariants() from
	// drifting apart (it also runs as part of `mage dev:check`).
	It("finds all hand-maintained variant lists in agreement", func() {
		Expect(verifyDistVariants()).To(Succeed())
	})

	// The failure branches are what make the guard a guard: feed synthetic
	// workflow contents with exactly one list out of agreement and assert
	// the error names the disagreeing location.
	Describe("drift detection", func() {
		// Synthetic workflow fragments agreeing with distVariants()
		// (linux_amd64, linux_arm64, linux_amd64_fips, linux_arm64_fips).
		goodCI := []byte(`
jobs:
  dist:
    strategy:
      matrix:
        include:
          - variant: linux_amd64
          - variant: linux_arm64
          - variant: linux_amd64_fips
          - variant: linux_arm64_fips
`)
		goodRel := []byte(`
jobs:
  build:
    strategy:
      matrix:
        include:
          - variant: linux_amd64
          - variant: linux_arm64
          - variant: linux_amd64_fips
          - variant: linux_arm64_fips
  release:
    steps:
      - run: |
          for variant in linux_amd64 linux_arm64 linux_amd64_fips linux_arm64_fips; do
            ls -- openvox-ca_*_"$variant".tar.gz > /dev/null
            ls -- openvox-ca_*_"$variant".spdx.json > /dev/null
            ls -- openvox-ca_*_"$variant".cdx.json > /dev/null
          done
          if [ "$tarballs" -ne 4 ]; then
            exit 1
          fi
          if [ "$sboms" -ne 8 ]; then
            exit 1
          fi
          sha256sum -- *.tar.gz *.spdx.json *.cdx.json > checksums.txt
`)

		// The generate-sbom action's output formats, whose count must equal
		// sbomFormatsPerVariant.
		goodSBOM := []byte(`
        "$SYFT" scan "dir:$scan" \
          -o "spdx-json=dist/${base}.spdx.json" \
          -o "cyclonedx-json=dist/${base}.cdx.json"
`)

		It("accepts synthetic workflows that agree with distVariants", func() {
			Expect(verifyDistVariantsIn(goodCI, goodRel, goodSBOM)).To(Succeed())
		})

		It("rejects a drifted ci.yml dist matrix and names it", func() {
			badCI := bytes.Replace(goodCI, []byte("- variant: linux_arm64_fips"), []byte("- variant: linux_riscv64_fips"), 1)
			Expect(verifyDistVariantsIn(badCI, goodRel, goodSBOM)).To(MatchError(ContainSubstring("ci.yml dist job matrix")))
		})

		It("rejects a drifted release.yml build matrix and names it", func() {
			badRel := bytes.Replace(goodRel, []byte("          - variant: linux_amd64_fips\n"), nil, 1)
			Expect(verifyDistVariantsIn(goodCI, badRel, goodSBOM)).To(MatchError(ContainSubstring("release.yml build job matrix")))
		})

		It("rejects a drifted checksum-step shell loop and names it", func() {
			badRel := bytes.Replace(goodRel, []byte("for variant in linux_amd64 "), []byte("for variant in "), 1)
			Expect(verifyDistVariantsIn(goodCI, badRel, goodSBOM)).To(MatchError(ContainSubstring("checksum-step shell loop")))
		})

		It("rejects a stale tarball-count literal and names the counts", func() {
			badRel := bytes.Replace(goodRel, []byte(`-ne 4`), []byte(`-ne 3`), 1)
			Expect(verifyDistVariantsIn(goodCI, badRel, goodSBOM)).To(MatchError(ContainSubstring("expects 3 tarballs")))
		})

		// The SBOM count is a multiple of the variant count rather than equal
		// to it, so it drifts independently of the tarball count: a variant
		// added everywhere else but missed in this literal lands here. (A
		// format added to generate-sbom is caught by the format-count specs
		// below, not by this one.)
		It("rejects a stale SBOM-count literal and names the counts", func() {
			badRel := bytes.Replace(goodRel, []byte(`-ne 8`), []byte(`-ne 4`), 1)
			Expect(verifyDistVariantsIn(goodCI, badRel, goodSBOM)).To(MatchError(ContainSubstring("expects 4 SBOMs")))
		})

		// -lt rather than -ne: the check is present but no longer the shape
		// the guard parses, which is the same branch a deleted line takes.
		// The message quotes the pattern it wanted, so the operator mismatch
		// is visible rather than leaving a maintainer staring at a check that
		// is plainly on screen.
		It("rejects an SBOM-count check the guard cannot parse", func() {
			badRel := bytes.Replace(goodRel, []byte(`"$sboms" -ne 8`), []byte(`"$sboms" -lt 8`), 1)
			Expect(verifyDistVariantsIn(goodCI, badRel, goodSBOM)).To(MatchError(ContainSubstring(`no SBOMs-count check matching`)))
		})

		// sbomFormatsPerVariant is the multiplier the SBOM count is derived
		// from, and it mirrors the generate-sbom action. These two specs are
		// what stop it becoming an unchecked copy: they are the reason a
		// format added to the action alone cannot leave every other count
		// self-consistent and wrong.
		It("rejects a generate-sbom action emitting more formats than the constant", func() {
			badSBOM := bytes.Replace(goodSBOM, []byte(`-o "cyclonedx-json=dist/${base}.cdx.json"`),
				[]byte("-o \"cyclonedx-json=dist/${base}.cdx.json\" \\\n          -o \"syft-json=dist/${base}.syft.json\""), 1)
			Expect(verifyDistVariantsIn(goodCI, goodRel, badSBOM)).To(MatchError(
				And(ContainSubstring("emits 3 SBOM format(s)"), ContainSubstring("syft-json"))))
		})

		It("rejects a generate-sbom action emitting fewer formats than the constant", func() {
			badSBOM := bytes.Replace(goodSBOM, []byte(`          -o "cyclonedx-json=dist/${base}.cdx.json"`), nil, 1)
			Expect(verifyDistVariantsIn(goodCI, goodRel, badSBOM)).To(MatchError(ContainSubstring("emits 1 SBOM format(s)")))
		})

		// Zero matches is not a miscount: the guard's own pattern stopped
		// matching, which is a different problem with a different fix, so it
		// gets a message naming the pattern rather than "emits 0".
		It("says which pattern stopped matching when it can see no output flags", func() {
			badSBOM := bytes.ReplaceAll(goodSBOM, []byte(`-o "`), []byte("--output "))
			Expect(verifyDistVariantsIn(goodCI, goodRel, badSBOM)).To(MatchError(
				And(ContainSubstring("no SBOM output flags matching"), ContainSubstring("[a-z0-9-]"))))
		})

		// The counts can agree while the names do not. Renaming one format's
		// output file leaves sbomFormatsPerVariant satisfied and still breaks
		// the release, because release.yml globs for the old extension — and
		// it breaks it at tag time, which is the failure this whole guard
		// family exists to move earlier.
		It("rejects a renamed SBOM output whose extension release.yml never globs for", func() {
			badSBOM := bytes.Replace(goodSBOM, []byte(`${base}.cdx.json`), []byte(`${base}.bom.json`), 1)
			Expect(verifyDistVariantsIn(goodCI, goodRel, badSBOM)).To(MatchError(
				And(ContainSubstring(".bom.json"), ContainSubstring("but release.yml names"))))
		})

		It("rejects a release.yml that globs for an extension the action never writes", func() {
			badRel := bytes.Replace(goodRel, []byte(`"$variant".cdx.json`), []byte(`"$variant".bom.json`), 1)
			Expect(verifyDistVariantsIn(goodCI, badRel, goodSBOM)).To(MatchError(
				ContainSubstring("but release.yml names")))
		})

		// release.yml names each document in five places. Dropping one of them
		// keeps every name valid and every count above satisfied, so nothing
		// else here would notice — but the document would go unlisted at that
		// site. Drop it from the sha256sum operands and it is published without
		// a checksum line, which means it is also missing from the attestation,
		// whose subjects are exactly those lines.
		It("rejects a release.yml that lists one SBOM document at a site but not the other", func() {
			badRel := bytes.Replace(goodRel, []byte(`sha256sum -- *.tar.gz *.spdx.json *.cdx.json`),
				[]byte(`sha256sum -- *.tar.gz *.spdx.json`), 1)
			Expect(verifyDistVariantsIn(goodCI, badRel, goodSBOM)).To(MatchError(
				ContainSubstring("every place that lists one SBOM document must list them all")))
		})
	})
})

var _ = Describe("verifyWorkflowBaseScoping", func() {
	// Runs against the repository's real ci.yml and codeql.yml: both triggers
	// are unfiltered by base and the auto-merge job carries its pin (this also
	// runs as part of `mage dev:check`).
	It("finds the real workflows unfiltered by base and the merge job pinned", func() {
		Expect(verifyWorkflowBaseScoping()).To(Succeed())
	})

	// Which files get checked is itself logic, and the real-tree spec above
	// passes just as happily for a dispatcher that checks nothing. These drive
	// it over synthetic sources so both halves of the dispatch are pinned.
	Describe("dispatch", func() {
		clean := []byte("on:\n  pull_request:\njobs: {}\n")

		It("checks every workflow it is given, not only the first", func() {
			// Pins codeql.yml's membership: drop it from baseScopedWorkflows
			// and it could be re-filtered with nothing to catch it.
			err := verifyWorkflowBaseScopingIn(map[string][]byte{
				"ci.yml":     clean,
				"codeql.yml": []byte("on:\n  pull_request:\n    branches: [\"main\"]\njobs: {}\n"),
			})
			Expect(err).To(MatchError(ContainSubstring("codeql.yml")))
		})

		It("applies the pin check, not only the trigger check", func() {
			err := verifyWorkflowBaseScopingIn(map[string][]byte{
				"ci.yml": []byte(`
on:
  pull_request:
jobs:
  automerge:
    steps:
      - run: gh pr merge --auto "$PR_URL"
`),
				"codeql.yml": clean,
			})
			Expect(err).To(MatchError(ContainSubstring(`job "automerge"`)))
		})

		// The pin check is no longer special-cased to ci.yml, so a merging job
		// that moves into another listed workflow is still caught, and the
		// error names the file it is actually in.
		It("names the workflow a misplaced merging job landed in", func() {
			err := verifyWorkflowBaseScopingIn(map[string][]byte{
				"ci.yml": clean,
				"codeql.yml": []byte(`
on:
  pull_request:
jobs:
  automerge:
    steps:
      - run: gh pr merge --auto "$PR_URL"
`),
			})
			Expect(err).To(MatchError(ContainSubstring("codeql.yml job")))
		})

		// Asserted on the branch's own message, not just the file name: a nil
		// source parses as an empty document and reaches the missing-trigger
		// error, which also names codeql.yml, so matching the name alone
		// would pass with the !ok guard deleted.
		It("reports a workflow whose source was not supplied", func() {
			Expect(verifyWorkflowBaseScopingIn(map[string][]byte{"ci.yml": clean})).To(
				MatchError(ContainSubstring("no source supplied for codeql.yml")))
		})
	})

	// The pin half. Fixtures are synthetic so the failure branches are driven
	// without touching the real workflow files.
	Describe("auto-merge base pin", func() {
		const pinClause = "      && github.event.pull_request.base.ref == github.event.repository.default_branch\n"

		unfiltered := []byte(`
on:
  push:
    branches: ["main"]
  pull_request:

jobs:
  automerge:
    if: >-
      github.event_name == 'pull_request'
      && github.event.pull_request.base.ref == github.event.repository.default_branch
      && (github.event.pull_request.user.login == 'dependabot[bot]'
      || github.event.pull_request.user.login == 'renovate[bot]')
    steps:
      - run: gh pr merge --auto --merge "$PR_URL"
`)

		It("accepts a merging job that carries the pin", func() {
			Expect(verifyAutomergeBasePinIn("ci.yml", unfiltered)).To(Succeed())
		})

		It("rejects a dropped pin and names the job", func() {
			bad := bytes.Replace(unfiltered, []byte(pinClause), nil, 1)
			err := verifyAutomergeBasePinIn("ci.yml", bad)
			Expect(err).To(MatchError(ContainSubstring(`job "automerge"`)))
			Expect(err).To(MatchError(ContainSubstring("merges pull requests")))
		})

		// Losing the condition wholesale is the same defect as losing the
		// clause, and it is what a botched edit to the folded block leaves
		// behind most often.
		It("rejects a merging job with no 'if:' at all, and names the job", func() {
			bad := bytes.Replace(unfiltered, []byte(`    if: >-
      github.event_name == 'pull_request'
      && github.event.pull_request.base.ref == github.event.repository.default_branch
      && (github.event.pull_request.user.login == 'dependabot[bot]'
      || github.event.pull_request.user.login == 'renovate[bot]')
`), nil, 1)
			Expect(verifyAutomergeBasePinIn("ci.yml", bad)).To(MatchError(ContainSubstring(`job "automerge"`)))
		})

		// Pins the anti-pin branch. (It no longer pins the operator folded
		// into automergeBasePin: the anti-pin fires first for any inverted
		// fixture, so the operand-only spec below is what covers that.)
		It("rejects an inverted comparison, and names the job", func() {
			bad := bytes.Replace(unfiltered,
				[]byte("github.event.pull_request.base.ref == github.event.repository.default_branch"),
				[]byte("github.event.pull_request.base.ref != github.event.repository.default_branch"), 1)
			err := verifyAutomergeBasePinIn("ci.yml", bad)
			Expect(err).To(MatchError(ContainSubstring(`job "automerge"`)))
			Expect(err).To(MatchError(ContainSubstring("the inverse of the pin")))
		})

		// Killed by dropping `==` from automergeBasePin and by nothing else.
		// The base ref is conjoined, so the conjunct requirement is satisfied
		// and cannot be what rejects it; only the operator can. Semantically a
		// non-empty string is truthy, so this pins nothing at all.
		It("rejects a bare truthy conjunct on the base ref", func() {
			bad := bytes.Replace(unfiltered,
				[]byte("github.event.pull_request.base.ref == github.event.repository.default_branch"),
				[]byte("github.event.pull_request.base.ref"), 1)
			err := verifyAutomergeBasePinIn("ci.yml", bad)
			Expect(err).To(MatchError(ContainSubstring(`job "automerge"`)))
			Expect(err).To(MatchError(ContainSubstring("never compares")))
		})

		// The ref is consulted but never compared, so it constrains nothing.
		// Both error paths name the job, so this asserts the one substring only
		// the missing-comparison path emits.
		It("rejects a condition that consults the base ref without comparing it", func() {
			bad := bytes.Replace(unfiltered,
				[]byte("github.event.pull_request.base.ref == github.event.repository.default_branch"),
				[]byte("startsWith(github.event.pull_request.base.ref, 'release/')"), 1)
			err := verifyAutomergeBasePinIn("ci.yml", bad)
			Expect(err).To(MatchError(ContainSubstring(`job "automerge"`)))
			Expect(err).To(MatchError(ContainSubstring("never compares")))
		})

		// Spacing is not spelling in the direction that matters: GitHub reads
		// `a!=b` as `a != b`, so a tight inversion plus a spaced decoy must
		// still be refused. Collapsing whitespace rather than removing it let
		// this through.
		It("rejects a tight inverted pin even with a spaced decoy", func() {
			bad := bytes.Replace(unfiltered,
				[]byte("      && github.event.pull_request.base.ref == github.event.repository.default_branch\n"),
				[]byte("      && github.event.pull_request.base.ref!=github.event.repository.default_branch\n"+
					"      && !(github.event.pull_request.base.ref == 'gh-pages')\n"), 1)
			Expect(verifyAutomergeBasePinIn("ci.yml", bad)).To(
				MatchError(ContainSubstring("the inverse of the pin")))
		})

		// The same asymmetry misfired upward: a correct pin written tight is
		// a valid spelling and must not be reported as drift.
		It("accepts an upright pin written with no spaces", func() {
			tight := bytes.Replace(unfiltered,
				[]byte("github.event.pull_request.base.ref == github.event.repository.default_branch"),
				[]byte("github.event.pull_request.base.ref==github.event.repository.default_branch"), 1)
			Expect(verifyAutomergeBasePinIn("ci.yml", tight)).To(Succeed())
		})

		// One keystroke, `&&` to `||`. GitHub binds && tighter, so this reads
		// as `A || (B && C)` with A true for every pull_request event: the job
		// loses the base pin *and* the author gate. The comparison is still
		// present, so only requiring it as a conjunct catches this.
		It("rejects a pin that is disjoined rather than conjoined", func() {
			bad := bytes.Replace(unfiltered,
				[]byte("      github.event_name == 'pull_request'\n      && github.event.pull_request.base.ref"),
				[]byte("      github.event_name == 'pull_request'\n      || github.event.pull_request.base.ref"), 1)
			Expect(verifyAutomergeBasePinIn("ci.yml", bad)).To(
				MatchError(ContainSubstring("outside any parenthesised group")))
		})

		// The same slip one operator along: the pin stays where it was and the
		// `||` moves after it. Caught for the same reason -- the disjunction is
		// top-level -- which the earlier conjunct-adjacency form missed.
		It("rejects a disjunction that follows the pin", func() {
			bad := bytes.Replace(unfiltered,
				[]byte("github.event.repository.default_branch\n      && (github.event.pull_request.user.login"),
				[]byte("github.event.repository.default_branch\n      || (github.event.pull_request.user.login"), 1)
			Expect(verifyAutomergeBasePinIn("ci.yml", bad)).To(
				MatchError(ContainSubstring("outside any parenthesised group")))
		})

		// Documented limit, pinned so the comment and the code cannot drift:
		// a negation wrapped around the comparison keeps it and inverts anyway.
		// Not caught, on purpose -- nobody writes it by accident, and anyone
		// writing it deliberately would delete the guard instead.
		It("does not catch a comparison negated as a whole", func() {
			bad := bytes.Replace(unfiltered,
				[]byte("&& github.event.pull_request.base.ref == github.event.repository.default_branch"),
				[]byte("&& !(github.event.pull_request.base.ref == github.event.repository.default_branch)"), 1)
			Expect(verifyAutomergeBasePinIn("ci.yml", bad)).To(Succeed())
		})

		// Spellings a maintainer plausibly writes, all semantically identical
		// to the baseline. The conjunct-adjacency form rejected every one.
		It("accepts the comparison parenthesised", func() {
			ok := bytes.Replace(unfiltered,
				[]byte("&& github.event.pull_request.base.ref == github.event.repository.default_branch"),
				[]byte("&& (github.event.pull_request.base.ref == github.event.repository.default_branch)"), 1)
			Expect(verifyAutomergeBasePinIn("ci.yml", ok)).To(Succeed())
		})

		It("accepts the operands in either order", func() {
			ok := bytes.Replace(unfiltered,
				[]byte("github.event.pull_request.base.ref == github.event.repository.default_branch"),
				[]byte("github.event.repository.default_branch == github.event.pull_request.base.ref"), 1)
			Expect(verifyAutomergeBasePinIn("ci.yml", ok)).To(Succeed())
		})

		It("accepts a condition wrapped in ${{ }}", func() {
			ok := bytes.Replace(unfiltered, []byte("    if: >-\n"),
				[]byte("    if: >-\n      ${{\n"), 1)
			ok = bytes.Replace(ok, []byte("|| github.event.pull_request.user.login == 'renovate[bot]')\n"),
				[]byte("|| github.event.pull_request.user.login == 'renovate[bot]')\n      }}\n"), 1)
			Expect(verifyAutomergeBasePinIn("ci.yml", ok)).To(Succeed())
		})

		// The decoy: invert the real pin and let a plausible neighbouring
		// clause supply the required substring. Requiring the pin alone passed
		// this, because a substring says nothing about which clause produced
		// it.
		It("rejects an inverted pin even when another clause supplies the substring", func() {
			bad := bytes.Replace(unfiltered,
				[]byte("      && github.event.pull_request.base.ref == github.event.repository.default_branch\n"),
				[]byte("      && github.event.pull_request.base.ref != github.event.repository.default_branch\n"+
					"      && !(github.event.pull_request.base.ref == 'gh-pages')\n"), 1)
			// The fixture really is a decoy: the required substring is present,
			// so a guard checking only for it would pass this.
			Expect(string(bad)).To(ContainSubstring("github.event.pull_request.base.ref =="))
			err := verifyAutomergeBasePinIn("ci.yml", bad)
			Expect(err).To(MatchError(ContainSubstring(`job "automerge"`)))
			Expect(err).To(MatchError(ContainSubstring("the inverse of the pin")))
		})

		// Spacing is not spelling: the required comparison is matched on its
		// tokens, so an extra space around the operator is not drift.
		It("accepts extra whitespace around the operator", func() {
			spaced := bytes.Replace(unfiltered,
				[]byte("github.event.pull_request.base.ref == github.event.repository.default_branch"),
				[]byte("github.event.pull_request.base.ref   ==   github.event.repository.default_branch"), 1)
			Expect(verifyAutomergeBasePinIn("ci.yml", spaced)).To(Succeed())
		})

		// The guard checks that the condition makes the comparison, not what it
		// compares against: ci.yml uses default_branch so the pin tracks the
		// ruleset, but a literal confines the job just as well and must not be
		// reported as drift.
		It("accepts a pin written against a literal branch name", func() {
			literal := bytes.Replace(unfiltered,
				[]byte("github.event.pull_request.base.ref == github.event.repository.default_branch"),
				[]byte("github.event.pull_request.base.ref == 'main'"), 1)
			Expect(verifyAutomergeBasePinIn("ci.yml", literal)).To(Succeed())
		})

		// Matching on what the job does, not on the name "automerge", means a
		// rename cannot quietly retire the guard.
		It("still requires the pin when the merging job is renamed", func() {
			bad := bytes.Replace(unfiltered, []byte("  automerge:\n"), []byte("  land-bot-prs:\n"), 1)
			bad = bytes.Replace(bad, []byte(pinClause), nil, 1)
			Expect(verifyAutomergeBasePinIn("ci.yml", bad)).To(MatchError(ContainSubstring(`job "land-bot-prs"`)))
		})

		// A step that enables auto-merge through an action rather than an
		// inline `gh pr merge` is the same job wearing a different hat.
		It("still requires the pin when auto-merge is enabled via an action", func() {
			bad := bytes.Replace(unfiltered,
				[]byte(`      - run: gh pr merge --auto --merge "$PR_URL"`),
				[]byte(`      - uses: peter-evans/enable-pull-request-automerge@v3`), 1)
			bad = bytes.Replace(bad, []byte(pinClause), nil, 1)
			Expect(verifyAutomergeBasePinIn("ci.yml", bad)).To(MatchError(ContainSubstring(`job "automerge"`)))
		})

		// A job that calls a reusable workflow has no steps at all, so a
		// matcher walking only steps would skip it -- while the caller job is
		// still where the if:, the permissions and the pin live.
		It("still requires the pin when the job itself calls an auto-merge workflow", func() {
			bad := []byte(`
on:
  pull_request:

jobs:
  automerge:
    uses: ./.github/workflows/automerge.yml
`)
			Expect(verifyAutomergeBasePinIn("ci.yml", bad)).To(MatchError(ContainSubstring(`job "automerge"`)))
		})

		// The pin is required whatever the trigger looks like: a filter is
		// only equivalent to it when it names the default branch alone, so
		// disarming on any filter would retire the guard exactly when a
		// widened filter started to matter.
		It("still requires the pin when the trigger filters by base", func() {
			filtered := bytes.Replace(unfiltered,
				[]byte("  pull_request:\n"), []byte("  pull_request:\n    branches: [\"main\", \"release/**\"]\n"), 1)
			filtered = bytes.Replace(filtered, []byte(pinClause), nil, 1)
			Expect(verifyAutomergeBasePinIn("ci.yml", filtered)).To(MatchError(ContainSubstring(`job "automerge"`)))
		})

		// The parse-error branch, which only a direct call reaches:
		// verifyWorkflowBaseScopingIn runs verifyPullRequestUnfilteredIn first
		// on the same bytes, so malformed YAML always fails there in practice.
		// Specced anyway because the branch exists and the test surface can
		// reach it -- and asserted on `yaml:` rather than the file name, since
		// every error this function returns leads with the workflow name.
		It("reports malformed YAML, though only a direct call reaches this", func() {
			Expect(verifyAutomergeBasePinIn("ci.yml", []byte("on: [\n"))).To(
				MatchError(ContainSubstring("ci.yml: yaml:")))
		})

		It("ignores jobs that do not merge pull requests", func() {
			noMerge := bytes.Replace(unfiltered,
				[]byte(`      - run: gh pr merge --auto --merge "$PR_URL"`),
				[]byte(`      - run: gh pr view "$PR_URL"`), 1)
			noMerge = bytes.Replace(noMerge, []byte(pinClause), nil, 1)
			Expect(verifyAutomergeBasePinIn("ci.yml", noMerge)).To(Succeed())
		})

		// Two offenders: the reported job must be the alphabetically first,
		// so the message does not change from run to run with map order. The
		// non-merging job sorts before both and must be skipped.
		It("names the first offending job when several are unpinned", func() {
			bad := []byte(`
on:
  pull_request:

jobs:
  aardvark-lint:
    steps:
      - run: gh pr view "$PR_URL"
  merge-zulu:
    steps:
      - run: gh pr merge --auto "$PR_URL"
  merge-alpha:
    steps:
      - run: gh pr merge --auto "$PR_URL"
`)
			for range 20 {
				Expect(verifyAutomergeBasePinIn("ci.yml", bad)).To(MatchError(ContainSubstring(`job "merge-alpha"`)))
			}
		})
	})

	// The trigger half: what stops the widening this guard accompanies from
	// being silently reverted.
	Describe("pull_request trigger", func() {
		It("accepts a trigger with no base filter", func() {
			Expect(verifyPullRequestUnfilteredIn("ci.yml", []byte("on:\n  pull_request:\njobs: {}\n"))).To(Succeed())
		})

		It("accepts a trigger that filters on event type but not base", func() {
			src := []byte("on:\n  pull_request:\n    types: [opened, synchronize]\njobs: {}\n")
			Expect(verifyPullRequestUnfilteredIn("ci.yml", src)).To(Succeed())
		})

		It("rejects a base filter and names the workflow and the branches", func() {
			src := []byte("on:\n  pull_request:\n    branches: [\"main\"]\njobs: {}\n")
			err := verifyPullRequestUnfilteredIn("codeql.yml", src)
			Expect(err).To(MatchError(ContainSubstring("codeql.yml")))
			Expect(err).To(MatchError(ContainSubstring("branches: [main]")))
		})

		// branches-ignore filters on the same field -- the PR's base -- so a
		// re-narrowing written that way skips stacked PRs exactly as silently.
		It("rejects a branches-ignore filter and names the key", func() {
			src := []byte("on:\n  pull_request:\n    branches-ignore: [\"feature/**\"]\njobs: {}\n")
			err := verifyPullRequestUnfilteredIn("ci.yml", src)
			Expect(err).To(MatchError(ContainSubstring("branches-ignore: [feature/**]")))
		})

		// Deleting the trigger skips stacked PRs just as thoroughly as
		// filtering it, so it must not read as "no filter, therefore fine".
		It("rejects a workflow with no pull_request trigger at all", func() {
			src := []byte("on:\n  push:\n    branches: [\"main\"]\njobs: {}\n")
			Expect(verifyPullRequestUnfilteredIn("ci.yml", src)).To(
				MatchError(ContainSubstring("declares no pull_request trigger")))
		})

		// Asserted on the parse failure, not just the file name: every error
		// this function returns leads with the workflow name, so matching the
		// name alone would pass with the yaml.Unmarshal check deleted — the
		// malformed input would then fall through to the missing-trigger
		// error, which names ci.yml too. Same trap as the missing-source spec.
		It("reports a malformed workflow against its file name", func() {
			Expect(verifyPullRequestUnfilteredIn("ci.yml", []byte("on: [\n"))).To(
				MatchError(ContainSubstring("ci.yml: yaml:")))
		})

		// The trigger key present but carrying a scalar rather than a mapping:
		// the one error path the specs above do not reach.
		It("reports a pull_request trigger that is not a mapping", func() {
			src := []byte("on:\n  pull_request: main\njobs: {}\n")
			Expect(verifyPullRequestUnfilteredIn("ci.yml", src)).To(
				MatchError(ContainSubstring("on.pull_request")))
		})
	})
})

var _ = Describe("the packaged variant set", func() {
	It("packages the two pure-Go variants and neither FIPS variant", func() {
		var names []string
		for _, v := range packagedDistVariants() {
			names = append(names, v.name)
		}
		Expect(names).To(ConsistOf("linux_amd64", "linux_arm64"))
	})

	DescribeTable("keeps the packaged set a subset of the variant set",
		func(name string) {
			all := map[string]bool{}
			for _, v := range distVariants() {
				all[v.name] = true
			}
			Expect(all).To(HaveKey(name))
		},
		Entry("linux_amd64", "linux_amd64"),
		Entry("linux_arm64", "linux_arm64"),
	)

	It("names the formats in the order release.yml's counts assume", func() {
		Expect(packageFormats).To(Equal([]string{"deb", "rpm"}))
	})

	// packageExtensions could be written as a literal that happens to agree
	// with packageFormats today, and every assertion above would still pass.
	// Substituting the list is what tells a derivation from a copy.
	It("derives the extensions from packageFormats rather than restating them", func() {
		original := packageFormats
		DeferCleanup(func() { packageFormats = original })

		packageFormats = []string{"deb", "rpm", "apk"}
		Expect(packageExtensions()).To(Equal([]string{".deb", ".rpm", ".apk"}))

		packageFormats = []string{"rpm"}
		Expect(packageExtensions()).To(Equal([]string{".rpm"}))
	})
})

var _ = Describe("renderUnit", func() {
	It("renders the repository's own template for both channels", func() {
		tarball, err := renderUnit(tarballUnitBindir)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(tarball)).To(ContainSubstring("ExecStart=" + tarballUnitBindir + "/openvox-ca"))

		pkg, err := renderUnit(packageUnitBindir)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(pkg)).To(ContainSubstring("ExecStart=" + packageUnitBindir + "/openvox-ca"))
	})

	It("leaves no placeholder behind in either rendering", func() {
		for _, bindir := range []string{tarballUnitBindir, packageUnitBindir} {
			out, err := renderUnit(bindir)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(out)).NotTo(ContainSubstring(unitBindirPlaceholder), "rendered for %s", bindir)
		}
	})

	// The two channels differ in exactly one line. If they ever differ in
	// more, the template has stopped being one file's worth of truth.
	It("produces two renderings that differ only in ExecStart", func() {
		tarball, err := renderUnit(tarballUnitBindir)
		Expect(err).NotTo(HaveOccurred())
		pkg, err := renderUnit(packageUnitBindir)
		Expect(err).NotTo(HaveOccurred())

		normalise := func(b []byte) string {
			return strings.ReplaceAll(string(b), "ExecStart="+tarballUnitBindir, "ExecStart="+packageUnitBindir)
		}
		Expect(normalise(tarball)).To(Equal(normalise(pkg)))
	})

	// The unit the packages install must not need a writable path the unit
	// no longer asks for: StateDirectory= was removed in favour of naming the
	// CA directory outright, and a service under ProtectSystem=strict with
	// neither cannot write a signed certificate at all.
	It("gives the long-running service exactly one writable path, the CA directory", func() {
		out, err := renderUnit(packageUnitBindir)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(out)).To(ContainSubstring("\nReadWritePaths=/etc/puppetlabs/puppet/ssl/ca\n"))
		Expect(string(out)).NotTo(ContainSubstring("\nStateDirectory="))
	})
})

var _ = Describe("mageTargetNames", func() {
	It("finds the namespaced targets the command line uses", func() {
		src, err := os.ReadFile("magefile.go")
		Expect(err).NotTo(HaveOccurred())
		targets, err := mageTargetNames(src)
		Expect(err).NotTo(HaveOccurred())
		Expect(targets).To(ContainElements("build:dist", "build:packages", "build:unit", "dev:check"))
	})

	It("takes methods on namespace types and leaves methods on other types alone", func() {
		src := []byte(`package main

import "github.com/magefile/mage/mg"

type Build mg.Namespace
type helper struct{}

func (Build) Packages() error { return nil }
func (Build) unexported() error { return nil }
func (helper) Packages() error { return nil }
func Standalone() error { return nil }
`)
		targets, err := mageTargetNames(src)
		Expect(err).NotTo(HaveOccurred())
		Expect(targets).To(ConsistOf("build:packages", "standalone"))
	})
})

var _ = Describe("workflowMageTargets", func() {
	It("reads the run: steps and not the comments quoting them", func() {
		src := []byte(`
jobs:
  gate:
    steps:
      - run: mage dev:check
      - run: |
          # This comment says mage build:invented and must not be believed.
          mage test:unit
`)
		Expect(workflowMageTargets(src)).To(ConsistOf("dev:check", "test:unit"))
	})

	// The trap that made the first version of the workflow floor fire on a
	// correct file: "image " ends in "mage ". Pinned in both directions so a
	// future widening of the leading class cannot reintroduce it.
	It("does not mistake a word ending in mage for an invocation", func() {
		src := []byte(`
jobs:
  images:
    steps:
      - run: docker build -t image .
      - run: echo "publishing the image now"
`)
		Expect(workflowMageTargets(src)).To(BeEmpty())
		Expect(mageInvocationRE.Match(src)).To(BeFalse())
	})

	It("finds an invocation by an explicit path as well as a bare one", func() {
		src := []byte(`
jobs:
  gate:
    steps:
      - run: |
          "$HOME"/go/bin/mage dev:check
`)
		Expect(workflowMageTargets(src)).To(ConsistOf("dev:check"))
	})

	It("skips invocations no static reading can resolve", func() {
		src := []byte(`
jobs:
  matrix:
    steps:
      - run: mage "$MAGE_TARGET"
      - run: mage -l
      - run: mage build:distVariant ${{ matrix.variant }}
`)
		// The target of the third is resolvable even though its argument is
		// not; the first two name no target at all.
		Expect(workflowMageTargets(src)).To(ConsistOf("build:distvariant"))
	})
})

var _ = Describe("verifyMageTargets", func() {
	// Against the repository's real magefile and workflows, which is what
	// `mage dev:check` runs.
	It("finds every mage target named outside Go resolving", func() {
		Expect(verifyMageTargets()).To(Succeed())
	})

	Describe("drift detection", func() {
		goodMage := []byte(`package main

import "github.com/magefile/mage/mg"

type Build mg.Namespace
type Dev mg.Namespace

func (Build) Dist() error { return nil }
func (Build) Packages() error { return nil }
func (Dev) Check() error { return nil }
`)
		goodWorkflow := []byte(`
jobs:
  release:
    steps:
      - run: mage build:packages
`)

		It("accepts a magefile and a workflow in agreement", func() {
			Expect(verifyMageTargetsIn(goodMage, map[string][]byte{"release.yml": goodWorkflow})).To(Succeed())
		})

		// The deliverable: release.yml's packaging job calls this by name,
		// and nothing in Go would notice it going away.
		It("rejects a magefile that has lost build:packages, naming the target", func() {
			without := bytes.Replace(goodMage, []byte("func (Build) Packages() error { return nil }\n"), nil, 1)
			err := verifyMageTargetsIn(without, map[string][]byte{"release.yml": goodWorkflow})
			Expect(err).To(MatchError(ContainSubstring(`mage target "build:packages" does not exist`)))
		})

		It("rejects a workflow calling a target the magefile does not define", func() {
			bad := []byte(`
jobs:
  release:
    steps:
      - run: mage build:packages
      - run: mage build:invented
`)
			err := verifyMageTargetsIn(goodMage, map[string][]byte{"release.yml": bad})
			Expect(err).To(MatchError(And(
				ContainSubstring("release.yml runs `mage build:invented`"),
				ContainSubstring("not a target magefile.go defines"))))
		})

		// The floor on the magefile parse. Every check is a membership test
		// against the parsed set, so a parse that returns nothing would make
		// all of them pass.
		It("rejects a magefile it could parse but found no build:dist in", func() {
			src := []byte(`package main

func main() {}
`)
			err := verifyMageTargetsIn(src, map[string][]byte{"release.yml": goodWorkflow})
			Expect(err).To(MatchError(ContainSubstring("build:dist was not among them")))
		})

		// The floor on the workflow parse, calibrated against the file it is
		// reading rather than against a fixed count.
		It("rejects a workflow that mentions mage where the parse finds none", func() {
			// A `mage ` outside any run: step -- which is what a workflow
			// looks like when the steps have moved somewhere the parse below
			// does not reach.
			bad := []byte(`
# mage build:packages is run somewhere else now
jobs:
  release:
    steps:
      - uses: ./.github/actions/build-packages
`)
			err := verifyMageTargetsIn(goodMage, map[string][]byte{"release.yml": bad})
			Expect(err).To(MatchError(And(
				ContainSubstring("mentions `mage `"),
				ContainSubstring("no-op"))))
		})

		It("does not fire that floor on a workflow that never mentions mage", func() {
			quiet := []byte(`
jobs:
  lint:
    steps:
      - run: echo hello
`)
			Expect(verifyMageTargetsIn(goodMage, map[string][]byte{"release.yml": quiet})).To(Succeed())
		})
	})
})

var _ = Describe("packaging helpers", func() {
	Describe("variantGOARCH", func() {
		DescribeTable("takes the architecture from the environment that compiled the binaries",
			func(name, arch string) {
				var found bool
				for _, v := range packagedDistVariants() {
					if v.name != name {
						continue
					}
					found = true
					got, err := variantGOARCH(v)
					Expect(err).NotTo(HaveOccurred())
					Expect(got).To(Equal(arch))
				}
				Expect(found).To(BeTrue(), "%s is no longer a packaged variant", name)
			},
			Entry("linux_amd64", "linux_amd64", "amd64"),
			Entry("linux_arm64", "linux_arm64", "arm64"),
		)

		It("refuses a variant with no GOARCH rather than guessing one", func() {
			_, err := variantGOARCH(distVariantSpec{name: "linux_amd64", env: map[string]string{}})
			Expect(err).To(MatchError(ContainSubstring("sets no GOARCH")))
		})
	})

	Describe("verifyPackagesWritten", func() {
		var dir string

		BeforeEach(func() {
			dir = GinkgoT().TempDir()
		})

		// The paths a packaging run reports having written. They must exist,
		// because the check now confirms that too.
		write := func(names ...string) []string {
			var paths []string
			for _, name := range names {
				full := filepath.Join(dir, name)
				Expect(os.WriteFile(full, []byte("x"), 0o644)).To(Succeed())
				paths = append(paths, full)
			}
			return paths
		}

		It("accepts one package per format per packaged variant", func() {
			written := write(
				"openvox-ca_1.2.3-1_amd64.deb", "openvox-ca_1.2.3-1_arm64.deb",
				"openvox-ca-1.2.3-1.x86_64.rpm", "openvox-ca-1.2.3-1.aarch64.rpm",
			)
			Expect(verifyPackagesWritten(written, 2)).To(Succeed())
		})

		It("rejects a short count and names the format that came up short", func() {
			written := write(
				"openvox-ca_1.2.3-1_amd64.deb",
				"openvox-ca-1.2.3-1.x86_64.rpm", "openvox-ca-1.2.3-1.aarch64.rpm",
			)
			err := verifyPackagesWritten(written, 2)
			Expect(err).To(MatchError(And(
				ContainSubstring("expected 2 .deb packages"),
				ContainSubstring("wrote 1"))))
		})

		// The collision the check exists for: two variants resolving to one
		// filename, so the second overwrote the first.
		It("rejects the same path written twice", func() {
			written := write("openvox-ca_1.2.3-1_amd64.deb", "openvox-ca-1.2.3-1.x86_64.rpm")
			written = append(written, written[0])
			err := verifyPackagesWritten(written, 2)
			Expect(err).To(MatchError(And(
				ContainSubstring("written twice"),
				ContainSubstring("the second overwrote the first"))))
		})

		// A leftover package from an earlier version used to fail a correct
		// build, because the check censused the directory instead of the run.
		It("ignores an unrelated package left in the directory from an earlier build", func() {
			written := write(
				"openvox-ca_2.0.0-1_amd64.deb", "openvox-ca_2.0.0-1_arm64.deb",
				"openvox-ca-2.0.0-1.x86_64.rpm", "openvox-ca-2.0.0-1.aarch64.rpm",
			)
			// Not part of this run.
			Expect(os.WriteFile(filepath.Join(dir, "openvox-ca_1.2.3-1_amd64.deb"),
				[]byte("stale"), 0o644)).To(Succeed())
			Expect(verifyPackagesWritten(written, 2)).To(Succeed())
		})

		It("rejects a path the run claimed but did not leave behind", func() {
			written := write(
				"openvox-ca_1.2.3-1_amd64.deb", "openvox-ca_1.2.3-1_arm64.deb",
				"openvox-ca-1.2.3-1.x86_64.rpm", "openvox-ca-1.2.3-1.aarch64.rpm",
			)
			Expect(os.Remove(written[0])).To(Succeed())
			Expect(verifyPackagesWritten(written, 2)).To(MatchError(
				ContainSubstring("was reported written but is not there")))
		})
	})

	Describe("extractTarGz", func() {
		var archive string

		BeforeEach(func() {
			dir := GinkgoT().TempDir()
			src := filepath.Join(dir, "src")
			Expect(os.MkdirAll(src, 0o755)).To(Succeed())
			for _, name := range []string{"openvox-ca", "openvox-ca-ctl", "openvox-ca.service"} {
				Expect(os.WriteFile(filepath.Join(src, name), []byte(name), 0o644)).To(Succeed())
			}
			archive = filepath.Join(dir, "a.tar.gz")
			Expect(createTarGz(archive, src, []archiveEntry{
				{name: "openvox-ca", mode: 0o755},
				{name: "openvox-ca-ctl", mode: 0o755},
				{name: "openvox-ca.service", mode: 0o644},
			})).To(Succeed())
		})

		It("extracts only the entries asked for", func() {
			dest := GinkgoT().TempDir()
			Expect(extractTarGz(archive, dest, []string{"openvox-ca", "openvox-ca-ctl"})).To(Succeed())

			entries, err := os.ReadDir(dest)
			Expect(err).NotTo(HaveOccurred())
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			Expect(names).To(ConsistOf("openvox-ca", "openvox-ca-ctl"))
		})

		// A tarball missing a binary would otherwise produce a package that
		// is well formed and installs a service with nothing to run.
		It("refuses an archive missing one of them, naming it", func() {
			dest := GinkgoT().TempDir()
			err := extractTarGz(archive, dest, []string{"openvox-ca", "openvox-ca-agent"})
			Expect(err).To(MatchError(ContainSubstring(`holds no "openvox-ca-agent"`)))
		})
	})
})

// arEntry is one member of a .deb's outer `ar` archive.
type arEntry struct {
	name string
	data []byte
}

// readAr parses the `ar` container a .deb is. Small enough to do here, and
// worth doing: without reading the payload back, a packaging test can only
// assert that some file appeared with the right name, which is satisfied by a
// package containing nothing.
func readAr(path string) ([]arEntry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	const magic = "!<arch>\n"
	if !bytes.HasPrefix(raw, []byte(magic)) {
		return nil, fmt.Errorf("%s is not an ar archive", path)
	}
	var out []arEntry
	for off := len(magic); off+60 <= len(raw); {
		hdr := raw[off : off+60]
		name := strings.TrimSpace(string(hdr[0:16]))
		size, err := strconv.Atoi(strings.TrimSpace(string(hdr[48:58])))
		if err != nil {
			return nil, fmt.Errorf("bad ar member size at %d: %w", off, err)
		}
		start := off + 60
		if start+size > len(raw) {
			return nil, fmt.Errorf("ar member %q runs past end of file", name)
		}
		out = append(out, arEntry{name: strings.TrimSuffix(name, "/"), data: raw[start : start+size]})
		off = start + size
		if size%2 == 1 {
			off++ // members are padded to an even offset
		}
	}
	return out, nil
}

// debMember returns one named member of a .deb's ar container.
func debMember(path, name string) ([]byte, error) {
	members, err := readAr(path)
	if err != nil {
		return nil, err
	}
	for _, m := range members {
		if m.name == name {
			return m.data, nil
		}
	}
	return nil, fmt.Errorf("%s has no %s", path, name)
}

// debTarGz walks a gzipped tar member of a .deb and calls fn for each entry.
// The tar records paths relative to the archive root ("./usr/bin/openvox-ca"),
// so they are rewritten to the absolute path dpkg installs, and a directory's
// trailing slash is stripped: a caller names a directory the way it names a
// file.
func debTarGz(data []byte, fn func(hdr *tar.Header, name string, r io.Reader) error) error {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name := strings.TrimPrefix(hdr.Name, ".")
		if name != "/" {
			name = strings.TrimSuffix(name, "/")
		}
		if err := fn(hdr, name, tr); err != nil {
			return err
		}
	}
}

// debControl returns the .deb's control archive: name -> contents. That is
// where the maintainer scripts and the conffiles list live, neither of which
// appears in the payload dpkg unpacks.
func debControl(path string) (map[string]string, error) {
	data, err := debMember(path, "control.tar.gz")
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	err = debTarGz(data, func(hdr *tar.Header, name string, r io.Reader) error {
		if hdr.Typeflag != tar.TypeReg {
			return nil
		}
		body, err := io.ReadAll(r)
		if err != nil {
			return err
		}
		out[strings.TrimPrefix(name, "/")] = string(body)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// debOwners returns path -> "user:group" as recorded in the payload. dpkg
// writes what it is told here, so a wrong owner is not corrected at install
// time the way rpm corrects one it cannot resolve.
func debOwners(path string) (map[string]string, error) {
	data, err := debMember(path, "data.tar.gz")
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	err = debTarGz(data, func(hdr *tar.Header, name string, _ io.Reader) error {
		out[name] = hdr.Uname + ":" + hdr.Gname
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// debPayload returns a .deb's installed files: path -> mode, and path ->
// contents.
func debPayload(path string) (map[string]int64, map[string]string, error) {
	data, err := debMember(path, "data.tar.gz")
	if err != nil {
		return nil, nil, err
	}

	modes := map[string]int64{}
	contents := map[string]string{}
	err = debTarGz(data, func(hdr *tar.Header, name string, r io.Reader) error {
		modes[name] = hdr.Mode
		if hdr.Typeflag == tar.TypeReg {
			body, err := io.ReadAll(r)
			if err != nil {
				return err
			}
			contents[name] = string(body)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return modes, contents, nil
}

var _ = Describe("checkPackagingInputs", func() {
	// Both branches stop a release that publishes nothing while exiting 0, so
	// each error message is asserted rather than just the fact of an error: a
	// guard that fires with the other one's message sends the reader to the
	// wrong list.
	good := []distVariantSpec{{name: "linux_amd64", env: map[string]string{"GOARCH": "amd64"}, packaged: true}}

	It("accepts the real lists", func() {
		Expect(checkPackagingInputs(packagedDistVariants(), packageFormats)).To(Succeed())
	})

	It("refuses when no variant is marked packaged", func() {
		Expect(checkPackagingInputs(nil, packageFormats)).To(MatchError(And(
			ContainSubstring("no dist variant is marked packaged"),
			ContainSubstring("drop the packaged field"))))
	})

	It("refuses when no format is configured", func() {
		Expect(checkPackagingInputs(good, nil)).To(MatchError(And(
			ContainSubstring("packageFormats lists no formats"),
			ContainSubstring("drop packageFormats too"))))
	})
})

var _ = Describe("buildVariantPackages", func() {
	// End to end over the real nfpm configuration: stages a tarball the way
	// build:dist writes one, then builds both formats from it. No compilation
	// -- the "binaries" are fixtures, which is the point.
	//
	// This block owns what a run produces: the filenames, that both formats
	// appear, and the failure when an input is missing. What is inside a
	// package is asserted by "the deb's payload" nested below and by "the
	// rpm's payload", both of which build through this same function.
	var (
		distDir string
		variant distVariantSpec
	)
	const ver = "9.9.9"

	BeforeEach(func() {
		distDir = GinkgoT().TempDir()
		variant = distVariantSpec{
			name:     "linux_amd64",
			env:      map[string]string{"GOOS": "linux", "GOARCH": "amd64"},
			packaged: true,
		}

		src := GinkgoT().TempDir()
		for _, name := range []string{"openvox-ca", "openvox-ca-ctl"} {
			Expect(os.WriteFile(filepath.Join(src, name), []byte("#!/bin/true\n"), 0o755)).To(Succeed())
		}
		unit, err := renderUnit(tarballUnitBindir)
		Expect(err).NotTo(HaveOccurred())
		Expect(os.WriteFile(filepath.Join(src, distUnitFile), unit, 0o644)).To(Succeed())

		archive := filepath.Join(distDir, fmt.Sprintf("openvox-ca_%s_%s.tar.gz", ver, variant.name))
		Expect(createTarGz(archive, src, distArchiveFiles([]string{"openvox-ca", "openvox-ca-ctl"}))).To(Succeed())
	})

	It("writes one package per format, under the names apt and dnf expect", func() {
		written, err := buildVariantPackages(distDir, ver, variant)
		Expect(err).NotTo(HaveOccurred())

		Expect(filepath.Join(distDir, "openvox-ca_9.9.9-1_amd64.deb")).To(BeAnExistingFile())
		Expect(filepath.Join(distDir, "openvox-ca-9.9.9-1.x86_64.rpm")).To(BeAnExistingFile())
		Expect(verifyPackagesWritten(written, 1)).To(Succeed())
	})

	Describe("the deb's payload", func() {
		var (
			modes    map[string]int64
			contents map[string]string
		)

		BeforeEach(func() {
			_, err := buildVariantPackages(distDir, ver, variant)
			Expect(err).NotTo(HaveOccurred())
			modes, contents, err = debPayload(filepath.Join(distDir, "openvox-ca_9.9.9-1_amd64.deb"))
			Expect(err).NotTo(HaveOccurred())
		})

		DescribeTable("installs the payload entry",
			func(path string, mode int64) {
				Expect(modes).To(HaveKey(path))
				Expect(modes[path]).To(Equal(mode), "mode of %s", path)
			},
			Entry("the server binary", "/usr/bin/openvox-ca", int64(0o755)),
			Entry("the operator CLI", "/usr/bin/openvox-ca-ctl", int64(0o755)),
			Entry("the service unit", "/usr/lib/systemd/system/openvox-ca.service", int64(0o644)),
			Entry("the provisioning oneshot", "/usr/lib/systemd/system/openvox-ca-first-boot.service", int64(0o644)),
			Entry("the provisioning script", "/usr/libexec/openvox-ca/first-boot", int64(0o755)),
			Entry("the sysusers declaration", "/usr/lib/sysusers.d/openvox-ca.conf", int64(0o644)),
		)

		// The tarball in the fixture carries the unit rendered for
		// /usr/local/bin. If the package ever shipped that copy instead of
		// re-rendering, every packaged install would point at a path the
		// package does not own -- and nothing else would say so.
		It("ships the unit rendered for /usr/bin, not the tarball's copy", func() {
			unit := contents["/usr/lib/systemd/system/openvox-ca.service"]
			Expect(unit).To(ContainSubstring("ExecStart=" + packageUnitBindir + "/openvox-ca"))
			Expect(unit).NotTo(ContainSubstring("ExecStart=" + tarballUnitBindir + "/openvox-ca"))
			Expect(unit).NotTo(ContainSubstring(unitBindirPlaceholder))
		})

		It("carries the documentation tree with its repository layout", func() {
			Expect(contents).To(HaveKey("/usr/share/doc/openvox-ca/LICENSE"))
			Expect(contents).To(HaveKey("/usr/share/doc/openvox-ca/README.md"))
			Expect(contents).To(HaveKey("/usr/share/doc/openvox-ca/docs/systemd.md"))
		})

		// The modes, not just the paths. 0771 lets an agent's group traverse
		// the ssl root without listing it; 0770 keeps the CA directory to its
		// owner and group. Asserting existence alone is the same weakness that
		// let a regular file stand in for the certs/ca.pem symlink -- the
		// check passes for a directory with any permissions at all.
		DescribeTable("creates the ssl tree the units bind-mount, with the modes that matter",
			func(path string, mode int64) {
				Expect(modes).To(HaveKey(path))
				Expect(modes[path]).To(Equal(mode), "mode of %s", path)
			},
			Entry("the ssl root", "/etc/puppetlabs/puppet/ssl", int64(0o771)),
			Entry("the CA directory", "/etc/puppetlabs/puppet/ssl/ca", int64(0o770)),
		)

		// The packaged default that the binary's own default gets wrong: a
		// package is what gets installed beside OpenVox Server, and Server
		// binds 8140.
		It("sets the packaged port in the configuration file, at 0640", func() {
			Expect(contents).To(HaveKey("/etc/puppet-ca/config.yaml"))
			Expect(contents["/etc/puppet-ca/config.yaml"]).To(MatchRegexp(`(?m)^port: 8141$`))
			Expect(modes["/etc/puppet-ca/config.yaml"]).To(Equal(int64(0o640)))
		})

		// Every setting the server refuses to start without. Each of these was
		// missing at some point in this branch's life and each produced the
		// same symptom -- a package that installs cleanly and whose service
		// then exits -- so they are asserted by name rather than by the file
		// merely being present.
		DescribeTable("sets the settings a packaged install cannot start without",
			func(pattern string) {
				Expect(contents["/etc/puppet-ca/config.yaml"]).To(MatchRegexp(pattern))
			},
			// No built-in default: "cadir is required".
			Entry("cadir", `(?m)^cadir: /etc/puppetlabs/puppet/ssl/ca$`),
			// Without these the server refuses plain HTTP on 0.0.0.0.
			Entry("tls_cert", `(?m)^tls_cert: /etc/puppetlabs/puppet/ssl/certs/openvox-ca-server\.pem$`),
			Entry("tls_key", `(?m)^tls_key: /etc/puppetlabs/puppet/ssl/private_keys/openvox-ca-server\.pem$`),
		)

		// The configuration names fixed paths because a shipped file cannot
		// know this host's certname; provisioning links them. If the two ever
		// disagree the service starts and exits, so they are checked against
		// each other rather than each against a literal.
		It("names serving paths that the provisioning script links", func() {
			cfg := contents["/etc/puppet-ca/config.yaml"]
			script, err := os.ReadFile(firstBootScript)
			Expect(err).NotTo(HaveOccurred())

			// Compared on the part below the ssl root, because that is the
			// part both sides spell the same way: the config file needs an
			// absolute path, and the script builds one from $SSLDIR so it can
			// be run against a scratch directory.
			const sslRoot = "/etc/puppetlabs/puppet/ssl/"
			for _, key := range []string{"tls_cert", "tls_key"} {
				m := regexp.MustCompile(`(?m)^` + key + `: (\S+)$`).FindStringSubmatch(cfg)
				Expect(m).To(HaveLen(2), "%s is not set in the packaged config", key)
				Expect(m[1]).To(HavePrefix(sslRoot), "%s must live under the ssl tree", key)

				suffix := strings.TrimPrefix(m[1], sslRoot)
				Expect(string(script)).To(ContainSubstring(suffix),
					"%s names %s, which the provisioning script never links", key, m[1])
			}
		})

		// It has to be a configuration file rather than a flag in the unit or
		// a variable in the environment: the server resolves the port as file,
		// then environment, then flag, so either of those would beat the file
		// and silently ignore an operator who edited it. A default belongs at
		// the layer an operator can override.
		It("does not set the port anywhere that would outrank the file", func() {
			unit := contents["/usr/lib/systemd/system/openvox-ca.service"]
			Expect(unit).NotTo(ContainSubstring("--port"))
			Expect(unit).NotTo(ContainSubstring("PUPPET_CA_PORT"))
			Expect(contents).NotTo(HaveKey("/usr/lib/systemd/system/openvox-ca.service.d/port.conf"))
		})
	})

	// dpkg reads the maintainer scripts and the conffiles list from the
	// control archive, which is a separate ar member from the payload -- so
	// every assertion above this point would hold for a package that shipped
	// neither. A package with no postinst installs cleanly and leaves no
	// `puppet` account, no enabled oneshot and an unreadable configuration
	// file; a package with no conffiles entry overwrites an operator's edits
	// on the next upgrade. Both are silent at build time.
	Describe("the deb's control archive", func() {
		var control map[string]string

		BeforeEach(func() {
			_, err := buildVariantPackages(distDir, ver, variant)
			Expect(err).NotTo(HaveOccurred())
			control, err = debControl(filepath.Join(distDir, "openvox-ca_9.9.9-1_amd64.deb"))
			Expect(err).NotTo(HaveOccurred())
		})

		// Byte-identical to the source, not merely present: nfpm copies the
		// script in verbatim, so anything else means the wrong file was
		// packaged.
		DescribeTable("ships the maintainer script dpkg will run",
			func(member, src string) {
				want, err := os.ReadFile(src)
				Expect(err).NotTo(HaveOccurred())
				Expect(control).To(HaveKey(member))
				Expect(control[member]).To(Equal(string(want)),
					"%s is not the script at %s", member, src)
			},
			Entry("postinst", "postinst", "packaging/scripts/postinstall"),
			Entry("prerm", "prerm", "packaging/scripts/preremove"),
			Entry("postrm", "postrm", "packaging/scripts/postremove"),
		)

		// The dpkg half of the config|noreplace declaration. The rpm half is
		// asserted in "the rpm's payload"; one line in nfpm.yaml produces
		// both, and reading only one of them would not notice the other
		// silently stopping.
		It("registers the configuration file as a conffile, and nothing else", func() {
			Expect(control).To(HaveKey("conffiles"))
			var listed []string
			for _, line := range strings.Split(control["conffiles"], "\n") {
				if line = strings.TrimSpace(line); line != "" {
					listed = append(listed, line)
				}
			}
			Expect(listed).To(ConsistOf("/etc/puppet-ca/config.yaml"))
		})
	})

	// dpkg writes the owner it is given and does not correct one it cannot
	// resolve, so a wrong owner here is a configuration file the service
	// cannot read -- and it is 0640, so root:root means openvox-ca exits at
	// startup without reading its own cadir.
	It("gives the deb's configuration file to root:puppet", func() {
		_, err := buildVariantPackages(distDir, ver, variant)
		Expect(err).NotTo(HaveOccurred())
		owners, err := debOwners(filepath.Join(distDir, "openvox-ca_9.9.9-1_amd64.deb"))
		Expect(err).NotTo(HaveOccurred())
		Expect(owners).To(HaveKeyWithValue("/etc/puppet-ca/config.yaml", "root:puppet"))
	})

	// nfpm stamps every payload entry, and the rpm's BUILDTIME, with the
	// current time unless SOURCE_DATE_EPOCH says otherwise -- so a rebuild
	// differs from the build before it, and no checksum over a package means
	// anything across one. nfpm reads that variable itself; what is checked
	// here is that this code path does not defeat it, which is the property a
	// release job that publishes checksums would depend on.
	//
	// Both halves are needed. "Two builds agree" is true on its own of a
	// package built twice inside the same second, which is exactly what this
	// spec does -- it passed with the variable unset. So it is paired with a
	// build at a different epoch, which must differ. Together they say the
	// stamp reaches the bytes AND that pinning it is what makes a rebuild
	// identical.
	It("stamps packages from SOURCE_DATE_EPOCH, so a rebuild is identical", func() {
		sum := func(epoch string) map[string]string {
			GinkgoT().Setenv("SOURCE_DATE_EPOCH", epoch)
			out := map[string]string{}
			written, err := buildVariantPackages(distDir, ver, variant)
			Expect(err).NotTo(HaveOccurred())
			for _, path := range written {
				body, err := os.ReadFile(path)
				Expect(err).NotTo(HaveOccurred())
				out[filepath.Base(path)] = fmt.Sprintf("%x", sha256.Sum256(body))
			}
			return out
		}

		first := sum("1700000000")
		Expect(first).To(HaveLen(len(packageFormats)))
		Expect(sum("1700000000")).To(Equal(first),
			"a rebuild at the same epoch produced different bytes")
		Expect(sum("1600000000")).NotTo(Equal(first),
			"the epoch does not reach the packages, so the check above proves nothing")
	})

	// The tarball channel keeps the binary's 8140. Only the packages move,
	// because only a package assumes the CA may share a host with Server.
	Describe("the tarball channel", func() {
		It("is left on the binary's own default port", func() {
			unit, err := renderUnit(tarballUnitBindir)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(unit)).NotTo(ContainSubstring("8141"))
			Expect(string(unit)).NotTo(ContainSubstring("--port"))
		})

		It("ships no configuration file at all", func() {
			// distArchiveFiles is the tarball's whole manifest.
			var names []string
			for _, e := range distArchiveFiles([]string{"openvox-ca", "openvox-ca-ctl"}) {
				names = append(names, e.name)
			}
			Expect(names).To(ConsistOf("openvox-ca", "openvox-ca-ctl", distUnitFile))
		})
	})

	// The target does not build binaries, so a missing tarball has to be an
	// error naming the target that produces one rather than a silent rebuild.
	It("refuses a variant whose tarball is not there, naming how to build it", func() {
		missing := distVariantSpec{name: "linux_arm64", env: map[string]string{"GOARCH": "arm64"}, packaged: true}
		_, err := buildVariantPackages(distDir, ver, missing)
		Expect(err).To(MatchError(And(
			ContainSubstring("does not build binaries"),
			ContainSubstring("mage build:distVariant linux_arm64"))))
	})
})

var _ = Describe("stageDocTree", func() {
	It("stages LICENSE, README and docs/ at their repository paths", func() {
		dest := GinkgoT().TempDir()
		Expect(stageDocTree(dest)).To(Succeed())

		for _, want := range []string{"LICENSE", "README.md", filepath.Join("docs", "systemd.md")} {
			Expect(filepath.Join(dest, want)).To(BeAnExistingFile())
		}
	})

	// The whole reason this enumerates through `git ls-files` rather than
	// walking docs/. A working tree routinely holds untracked drafts, notes
	// and scratch files under docs/, and a walk would package every one of
	// them into /usr/share/doc on every user's machine. Nothing else would
	// notice: the package builds, installs and works.
	It("stages tracked files only, not an untracked draft under docs/", func() {
		draft := filepath.Join("docs", "zz-untracked-spec-draft.md")
		Expect(os.WriteFile(draft, []byte("not for packaging\n"), 0o644)).To(Succeed())
		DeferCleanup(func() { Expect(os.Remove(draft)).To(Succeed()) })

		// The premise: git must actually consider this untracked. A spec that
		// silently ran against a tracked file would pass without testing
		// anything.
		out, err := exec.Command("git", "ls-files", "--", draft).Output()
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(string(out))).To(BeEmpty(),
			"the fixture is tracked, so this spec proves nothing")

		dest := GinkgoT().TempDir()
		Expect(stageDocTree(dest)).To(Succeed())
		Expect(filepath.Join(dest, draft)).NotTo(BeAnExistingFile())
		// And the tracked neighbour in the same directory did get staged, so
		// the absence above is exclusion rather than a doc tree that failed to
		// stage at all.
		Expect(filepath.Join(dest, "docs", "systemd.md")).To(BeAnExistingFile())
	})

	// The floor exists because `git ls-files` says nothing and exits 0 when
	// its pathspec matches nothing, which would package an empty doc tree.
	Describe("checkDocTreeFloor", func() {
		It("accepts an enumeration carrying the files that must be there", func() {
			Expect(checkDocTreeFloor([]string{"LICENSE", "README.md", "docs/systemd.md"})).To(Succeed())
		})

		DescribeTable("rejects an enumeration that is wrong rather than empty",
			func(paths []string, missing string) {
				err := checkDocTreeFloor(paths)
				Expect(err).To(MatchError(And(
					ContainSubstring(fmt.Sprintf("git tracks no %q", missing)),
					ContainSubstring("wrong rather than empty"))))
			},
			Entry("nothing at all", []string(nil), "LICENSE"),
			Entry("docs but no LICENSE", []string{"README.md", "docs/systemd.md"}, "LICENSE"),
			Entry("LICENSE but no README", []string{"LICENSE", "docs/systemd.md"}, "README.md"),
		)

		// The case the floor previously could not fail on. docs/ is the one
		// entry whose pathspec can stop matching by itself -- a rename, a run
		// from a subdirectory -- and it was the one entry the floor did not
		// check, so LICENSE and README would have shipped beside an empty
		// tree. Its own It because it fails with its own message.
		It("rejects an enumeration carrying the two files but nothing from docs/", func() {
			err := checkDocTreeFloor([]string{"LICENSE", "README.md"})
			Expect(err).To(MatchError(And(
				ContainSubstring(`git tracks no path under "docs/"`),
				ContainSubstring("wrong rather than empty"))))
		})
	})
})

var _ = Describe("renderUnitFrom", func() {
	// The guard exists so that deleting the placeholder cannot render
	// "successfully" and ship a unit naming the wrong prefix. Reaching it
	// needs a template without one, which is why renderUnit was split.
	It("refuses a template with no placeholder, rather than rendering it unchanged", func() {
		_, err := renderUnitFrom([]byte("[Service]\nExecStart=/usr/bin/openvox-ca\n"), packageUnitBindir)
		Expect(err).To(MatchError(And(
			ContainSubstring("contains no "+unitBindirPlaceholder),
			ContainSubstring("hard-coded"))))
	})

	It("substitutes every occurrence, not just the first", func() {
		out, err := renderUnitFrom([]byte("A=@BINDIR@/x\nB=@BINDIR@/y\n"), "/usr/bin")
		Expect(err).NotTo(HaveOccurred())
		Expect(string(out)).To(Equal("A=/usr/bin/x\nB=/usr/bin/y\n"))
	})
})

var _ = Describe("Build.Unit", func() {
	It("refuses a bindir that is not absolute, naming both channels", func() {
		err := Build{}.Unit("usr/bin")
		Expect(err).To(MatchError(And(
			ContainSubstring("is not an absolute path"),
			ContainSubstring(tarballUnitBindir),
			ContainSubstring(packageUnitBindir))))
	})

	// The success path goes through writeRenderedUnit against a temporary
	// directory, so no spec writes into the repository's own dist/.
	Describe("writeRenderedUnit", func() {
		It("writes a unit rendered for the bindir it was given", func() {
			dir := GinkgoT().TempDir()
			out, err := writeRenderedUnit(dir, "/opt/openvox/bin")
			Expect(err).NotTo(HaveOccurred())
			Expect(out).To(Equal(filepath.Join(dir, distUnitFile)))

			body, err := os.ReadFile(out)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(body)).To(ContainSubstring("ExecStart=/opt/openvox/bin/openvox-ca"))
			Expect(string(body)).NotTo(ContainSubstring(unitBindirPlaceholder))
		})

		It("trims a trailing slash rather than doubling it", func() {
			dir := GinkgoT().TempDir()
			out, err := writeRenderedUnit(dir, "/opt/openvox/bin/")
			Expect(err).NotTo(HaveOccurred())

			body, err := os.ReadFile(out)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(body)).To(ContainSubstring("ExecStart=/opt/openvox/bin/openvox-ca"))
			Expect(string(body)).NotTo(ContainSubstring("//openvox-ca"))
		})

		It("creates the destination directory when it is not there", func() {
			dir := filepath.Join(GinkgoT().TempDir(), "nested", "dist")
			_, err := writeRenderedUnit(dir, packageUnitBindir)
			Expect(err).NotTo(HaveOccurred())
			Expect(filepath.Join(dir, distUnitFile)).To(BeAnExistingFile())
		})
	})
})

var _ = Describe("extractTarGz", func() {
	// The guard refuses an entry whose name is not a plain filename. The
	// archives this reads are ones the build just wrote, so reaching it needs
	// an archive built to reach it -- which is the point: a check only present
	// for trusted input is a check absent when it is needed.
	It("refuses an entry that is not a plain filename", func() {
		dir := GinkgoT().TempDir()
		archive := filepath.Join(dir, "evil.tar.gz")

		f, err := os.Create(archive)
		Expect(err).NotTo(HaveOccurred())
		gz := gzip.NewWriter(f)
		tw := tar.NewWriter(gz)
		body := []byte("owned")
		Expect(tw.WriteHeader(&tar.Header{
			Name: "../../openvox-ca", Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg,
		})).To(Succeed())
		_, err = tw.Write(body)
		Expect(err).NotTo(HaveOccurred())
		Expect(tw.Close()).To(Succeed())
		Expect(gz.Close()).To(Succeed())
		Expect(f.Close()).To(Succeed())

		dest := GinkgoT().TempDir()
		err = extractTarGz(archive, dest, []string{"../../openvox-ca"})
		Expect(err).To(MatchError(ContainSubstring("is not a plain filename")))

		// And nothing was written outside the destination.
		Expect(filepath.Join(filepath.Dir(dest), "openvox-ca")).NotTo(BeAnExistingFile())
	})
})

// firstBootScript is the provisioning script as installed. The specs below run
// its own functions rather than a copy of them: the shell is the artefact, and
// a Go reimplementation of an allow-list would be testing the wrong thing.
const firstBootScript = "packaging/scripts/first-boot"

// runFirstBootFunc sources the script far enough to define its functions, then
// evaluates one shell expression against them.
//
// The script guards its executable section behind the binaries check, so
// sourcing it outright would run provisioning. Instead everything up to the
// "-- Run --" banner is taken, which is definitions only.
func runFirstBootFunc(expr string) (bool, error) {
	src, err := os.ReadFile(firstBootScript)
	if err != nil {
		return false, err
	}
	const banner = "# -- Run ---"
	i := bytes.Index(src, []byte(banner))
	if i < 0 {
		return false, fmt.Errorf("%s has no %q banner, so the definitions cannot be separated from "+
			"the code that runs provisioning", firstBootScript, banner)
	}

	script := string(src[:i]) + "\n" + expr + "\n"
	cmd := exec.Command("sh", "-c", script)
	cmd.Env = append(os.Environ(), "OPENVOX_CA_SSLDIR=/nonexistent", "OPENVOX_CA_BINDIR=/nonexistent")
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

var _ = Describe("first-boot's certname allow-list", func() {
	// The certificate name is joined to a path and passed to --cert-out and
	// --key-out, and two of its three sources are not under this host's
	// control in the way they look: `hostname -f` is whatever reverse DNS
	// answers, and puppet.conf is writable by anything with access to it.
	//
	// This runs the shipped shell function, not a restatement of it.
	DescribeTable("is_safe_certname",
		func(name string, want bool) {
			got, err := runFirstBootFunc(fmt.Sprintf("is_safe_certname %q", name))
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(Equal(want), "is_safe_certname %q", name)
		},
		Entry("an ordinary FQDN", "ca.example.com", true),
		Entry("a short name", "ca", true),
		Entry("digits, dots, dashes and underscores", "ca-01_test.example.com", true),

		// The traversal this allow-list exists for: it has a dot and is not a
		// localhost form, so the reachability check accepts it.
		Entry("a relative traversal", "../../../etc/x.example.com", false),
		Entry("an absolute path", "/etc/puppetlabs/x.example.com", false),
		Entry("a bare slash", "a/b.example.com", false),
		Entry("a backslash", `a\b.example.com`, false),
		Entry("empty", "", false),
		Entry("a leading dash, which a command could read as an option", "-rf.example.com", false),
		Entry("dot", ".", false),
		Entry("dot-dot", "..", false),
		Entry("a shell metacharacter", "a;rm -rf /.example.com", false),
		Entry("a newline", "ca.example.com\nevil", false),
		Entry("a space", "ca example.com", false),
	)

	// The reachability check is a separate question from safety, and every
	// source is put through both.
	DescribeTable("is_localhost_name covers both callers' patterns",
		func(name string, want bool) {
			got, err := runFirstBootFunc(fmt.Sprintf("is_localhost_name %q", name))
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(Equal(want), "is_localhost_name %q", name)
		},
		Entry("localhost", "localhost", true),
		Entry("localhost.localdomain", "localhost.localdomain", true),
		Entry("localhost6", "localhost6", true),
		// The pattern the two duplicated copies disagreed about: it was
		// rejected as an FQDN and accepted as a short hostname.
		Entry("any .localdomain name", "box.localdomain", true),
		Entry("a real name", "ca.example.com", false),
	)
})

// rpmFile is one entry of an rpm's payload, with the metadata that decides how
// it is installed.
type rpmFile struct {
	mode      int
	owner     string
	group     string
	config    bool
	noreplace bool
}

// rpmPayload returns an rpm's installed files by path.
//
// The deb has a hand-written ar/tar reader above because its container is two
// formats deep and both are in the standard library. The rpm's is neither, so
// this uses the reader nfpm already depends on rather than a second
// hand-rolled header parser -- the risk in parsing an rpm header by hand is
// getting it subtly wrong and asserting against the mistake.
func rpmPayload(path string) (map[string]rpmFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r, err := rpmutils.ReadRpm(f)
	if err != nil {
		return nil, err
	}
	entries, err := r.Header.GetFiles()
	if err != nil {
		return nil, err
	}

	out := make(map[string]rpmFile, len(entries))
	for _, e := range entries {
		out[e.Name()] = rpmFile{
			mode:      e.Mode() & 0o7777,
			owner:     e.UserName(),
			group:     e.GroupName(),
			config:    e.Flags()&rpmutils.RPMFILE_CONFIG != 0,
			noreplace: e.Flags()&rpmutils.RPMFILE_NOREPLACE != 0,
		}
	}
	return out, nil
}

// rpmScriptlets returns the rpm's scriptlets by tag name. They live in the
// header rather than the payload, so a package can carry every file this
// suite asserts and still run nothing at install or erase time.
func rpmScriptlets(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r, err := rpmutils.ReadRpm(f)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for name, tag := range map[string]int{
		"postin": rpmutils.POSTIN,
		"preun":  rpmutils.PREUN,
		"postun": rpmutils.POSTUN,
	} {
		// A missing tag is not an error here: reporting it as an absent key
		// is what lets a spec say which scriptlet is missing.
		if !r.Header.HasTag(tag) {
			continue
		}
		body, err := r.Header.GetString(tag)
		if err != nil {
			return nil, fmt.Errorf("reading the %s scriptlet: %w", name, err)
		}
		out[name] = body
	}
	return out, nil
}

var _ = Describe("the rpm's payload", func() {
	// The deb and the rpm come out of one code path, but "one code path" is an
	// argument, not a check: nfpm renders per-format metadata differently for
	// each, and only the deb's was ever opened. Everything asserted of the deb
	// is asserted here too.
	var (
		distDir string
		files   map[string]rpmFile
	)
	const ver = "9.9.9"

	BeforeEach(func() {
		distDir = GinkgoT().TempDir()
		variant := distVariantSpec{
			name:     "linux_amd64",
			env:      map[string]string{"GOOS": "linux", "GOARCH": "amd64"},
			packaged: true,
		}

		src := GinkgoT().TempDir()
		for _, name := range []string{"openvox-ca", "openvox-ca-ctl"} {
			Expect(os.WriteFile(filepath.Join(src, name), []byte("#!/bin/true\n"), 0o755)).To(Succeed())
		}
		unit, err := renderUnit(tarballUnitBindir)
		Expect(err).NotTo(HaveOccurred())
		Expect(os.WriteFile(filepath.Join(src, distUnitFile), unit, 0o644)).To(Succeed())
		archive := filepath.Join(distDir, fmt.Sprintf("openvox-ca_%s_%s.tar.gz", ver, variant.name))
		Expect(createTarGz(archive, src, distArchiveFiles([]string{"openvox-ca", "openvox-ca-ctl"}))).To(Succeed())

		_, err = buildVariantPackages(distDir, ver, variant)
		Expect(err).NotTo(HaveOccurred())
		files, err = rpmPayload(filepath.Join(distDir, "openvox-ca-9.9.9-1.x86_64.rpm"))
		Expect(err).NotTo(HaveOccurred())
	})

	DescribeTable("installs the payload entry",
		func(path string, mode int) {
			Expect(files).To(HaveKey(path))
			Expect(files[path].mode).To(Equal(mode), "mode of %s", path)
		},
		Entry("the server binary", "/usr/bin/openvox-ca", 0o755),
		Entry("the operator CLI", "/usr/bin/openvox-ca-ctl", 0o755),
		Entry("the service unit", "/usr/lib/systemd/system/openvox-ca.service", 0o644),
		Entry("the provisioning oneshot", "/usr/lib/systemd/system/openvox-ca-first-boot.service", 0o644),
		Entry("the provisioning script", "/usr/libexec/openvox-ca/first-boot", 0o755),
		Entry("the sysusers declaration", "/usr/lib/sysusers.d/openvox-ca.conf", 0o644),
		Entry("the configuration file", "/etc/puppet-ca/config.yaml", 0o640),
	)

	// The claim the PR body previously made by citing nfpm's source rather
	// than by inspecting a built package. An rpm that installed the config
	// without noreplace would overwrite an operator's edits on every update.
	It("marks the configuration file %config(noreplace)", func() {
		cfg := files["/etc/puppet-ca/config.yaml"]
		Expect(cfg.config).To(BeTrue(), "config.yaml is not marked %%config")
		Expect(cfg.noreplace).To(BeTrue(), "config.yaml is %%config but not noreplace")
	})

	It("marks nothing else as configuration", func() {
		for path, f := range files {
			if path == "/etc/puppet-ca/config.yaml" {
				continue
			}
			Expect(f.config).To(BeFalse(), "%s is marked %%config and should not be", path)
		}
	})

	It("gives the configuration file to root:puppet", func() {
		Expect(files["/etc/puppet-ca/config.yaml"].owner).To(Equal("root"))
		Expect(files["/etc/puppet-ca/config.yaml"].group).To(Equal("puppet"))
	})

	It("carries the documentation tree and the ssl directories", func() {
		Expect(files).To(HaveKey("/usr/share/doc/openvox-ca/LICENSE"))
		Expect(files).To(HaveKey("/usr/share/doc/openvox-ca/README.md"))
		Expect(files).To(HaveKey("/usr/share/doc/openvox-ca/docs/systemd.md"))
		Expect(files).To(HaveKey("/etc/puppetlabs/puppet/ssl"))
		Expect(files).To(HaveKey("/etc/puppetlabs/puppet/ssl/ca"))
	})

	// The rpm half of what "the deb's control archive" asserts. Scriptlets are
	// header tags rather than payload entries, so an rpm can carry every file
	// checked above and still create no account, enable nothing, and stop
	// nothing on erase.
	Describe("the scriptlets", func() {
		var scriptlets map[string]string

		BeforeEach(func() {
			var err error
			scriptlets, err = rpmScriptlets(filepath.Join(distDir, "openvox-ca-9.9.9-1.x86_64.rpm"))
			Expect(err).NotTo(HaveOccurred())
		})

		DescribeTable("carries the scriptlet rpm will run",
			func(tag, src string) {
				want, err := os.ReadFile(src)
				Expect(err).NotTo(HaveOccurred())
				Expect(scriptlets).To(HaveKey(tag))
				Expect(scriptlets[tag]).To(Equal(string(want)),
					"the %s scriptlet is not the script at %s", tag, src)
			},
			Entry("%post", "postin", "packaging/scripts/postinstall"),
			Entry("%preun", "preun", "packaging/scripts/preremove"),
			Entry("%postun", "postun", "packaging/scripts/postremove"),
		)
	})
})

// firstBootDefs returns the provisioning script's definitions -- everything
// above the "-- Run --" banner -- so a spec can call one function without
// running provisioning.
func firstBootDefs() (string, error) {
	src, err := os.ReadFile(firstBootScript)
	if err != nil {
		return "", err
	}
	const banner = "# -- Run ---"
	i := bytes.Index(src, []byte(banner))
	if i < 0 {
		return "", fmt.Errorf("%s has no %q banner, so the definitions cannot be separated from the "+
			"code that runs provisioning", firstBootScript, banner)
	}
	return string(src[:i]), nil
}

// firstBootResult is what a spec gets back from driving the script.
type firstBootResult struct {
	ok     bool
	output string
}

// runFirstBootIn evaluates a shell expression against the script's definitions
// with a scratch ssldir and bindir, and returns whether it succeeded plus
// everything it wrote to either stream.
func runFirstBootIn(sslDir, binDir, expr string, extraEnv ...string) (firstBootResult, error) {
	defs, err := firstBootDefs()
	if err != nil {
		return firstBootResult{}, err
	}
	cmd := exec.Command("sh", "-c", defs+"\n"+expr+"\n")
	cmd.Env = append(os.Environ(),
		"OPENVOX_CA_SSLDIR="+sslDir,
		"OPENVOX_CA_BINDIR="+binDir,
	)
	cmd.Env = append(cmd.Env, extraEnv...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return firstBootResult{ok: false, output: string(out)}, nil
		}
		return firstBootResult{}, err
	}
	return firstBootResult{ok: true, output: string(out)}, nil
}

// stubOpenvoxCA writes a fake openvox-ca whose --help output does or does not
// list a `generate` subcommand, which is the only thing has_generate_subcommand
// reads.
func stubOpenvoxCA(binDir string, withGenerate bool) {
	listing := "Available Commands:\n  csr            Emit a certificate signing request\n"
	if withGenerate {
		listing += "  generate       Mint a certificate offline, without a running server\n"
	}
	listing += "  help           Help about any command\n"

	script := "#!/bin/sh\ncase \"${1:-}\" in\n--help) printf '%s' " +
		shellQuote(listing) + "; exit 0 ;;\nesac\nexit 0\n"
	Expect(os.WriteFile(filepath.Join(binDir, "openvox-ca"), []byte(script), 0o755)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(binDir, "openvox-ca-ctl"), []byte("#!/bin/sh\nexit 0\n"), 0o755)).To(Succeed())
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// firstBootUnit is the provisioning oneshot as shipped. Unlike the service
// unit it is not a template: it is packaged verbatim, so what is asserted here
// is what gets installed.
const firstBootUnit = "packaging/systemd/openvox-ca-first-boot.service"

// unitDirectives returns a unit file's directives as key -> values, with every
// occurrence of a key kept: systemd treats a repeated directive as additive
// for some settings and last-wins for others, and a spec that read only the
// first would pass for a unit that overrode it two lines later.
func unitDirectives(path string) (map[string][]string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[k] = append(out[k], v)
	}
	return out, nil
}

var _ = Describe("the provisioning oneshot's unit", func() {
	// Everything asserted here is a property the packaging depends on and
	// nothing else checks. The payload specs prove the file is installed; they
	// say nothing about what is in it, and each of these directives has a
	// failure mode that is silent at build time and at install time.
	var directives map[string][]string

	BeforeEach(func() {
		var err error
		directives, err = unitDirectives(firstBootUnit)
		Expect(err).NotTo(HaveOccurred())
	})

	// RequiredBy=, and no WantedBy=. With a WantedBy=multi-user.target the
	// oneshot would provision on the next boot after an install, which is the
	// thing this design refuses: installing a package is not consent to create
	// a certificate authority.
	It("is required by the service and wanted by nothing", func() {
		Expect(directives).To(HaveKeyWithValue("RequiredBy", []string{"openvox-ca.service"}))
		Expect(directives).NotTo(HaveKey("WantedBy"),
			"a WantedBy= would provision on the next boot rather than on the first deliberate start")
	})

	// Before=, not After=. This writes to storage directly, so running it
	// beside a live server makes it a second writer to a backend that permits
	// exactly one.
	It("is ordered before the service", func() {
		Expect(directives).To(HaveKeyWithValue("Before", []string{"openvox-ca.service"}))
		for _, v := range directives["After"] {
			Expect(v).NotTo(ContainSubstring("openvox-ca.service"),
				"ordering this after the service makes provisioning a second writer against a live CA")
		}
	})

	// RemainAfterExit=yes is what makes "required by an already-active unit"
	// a no-op, so the oneshot does not re-run on every restart of the service.
	It("is a oneshot that stays active once it has succeeded", func() {
		Expect(directives).To(HaveKeyWithValue("Type", []string{"oneshot"}))
		Expect(directives).To(HaveKeyWithValue("RemainAfterExit", []string{"yes"}))
	})

	// The script is packaged at this path and invoked from nowhere else, so
	// the two have to agree; nothing else would notice a rename.
	It("runs the provisioning script at the path the package installs it to", func() {
		Expect(directives).To(HaveKeyWithValue("ExecStart", []string{"/usr/libexec/openvox-ca/first-boot"}))

		nfpm, err := os.ReadFile("packaging/nfpm.yaml")
		Expect(err).NotTo(HaveOccurred())
		Expect(string(nfpm)).To(ContainSubstring("dst: /usr/libexec/openvox-ca/first-boot"))
	})

	// It links certs/ca.pem and crl.pem above the CA directory, so it needs
	// the parent -- and the service, which never writes there, must not have
	// it. A ReadWritePaths= that named only the CA directory would fail every
	// link step under ProtectSystem=strict.
	It("gets the parent ssl tree, where the service gets only the CA directory", func() {
		Expect(directives).To(HaveKeyWithValue("ReadWritePaths", []string{"/etc/puppetlabs/puppet/ssl"}))

		service, err := unitDirectives(filepath.Join("packaging", "systemd", distUnitFile))
		Expect(err).NotTo(HaveOccurred())
		Expect(service).To(HaveKeyWithValue("ReadWritePaths", []string{"/etc/puppetlabs/puppet/ssl/ca"}))
	})

	// Both units run as the account the postinstall creates. A unit naming an
	// account nothing creates fails to start with a message about an unknown
	// user, and neither the package build nor the install says anything.
	DescribeTable("runs as the account the packaging creates",
		func(path string) {
			d, err := unitDirectives(path)
			Expect(err).NotTo(HaveOccurred())
			Expect(d).To(HaveKeyWithValue("User", []string{"puppet"}))
			Expect(d).To(HaveKeyWithValue("Group", []string{"puppet"}))
		},
		Entry("the service", filepath.Join("packaging", "systemd", distUnitFile)),
		Entry("the oneshot", firstBootUnit),
	)

	// RemoveIPC= acts on the UID rather than the unit, and this account is
	// shared with openvox-agent and openvox-server -- so stopping the CA would
	// reap IPC objects belonging to a neighbouring service. It protects
	// nothing here either: openvox-ca's only IPC is an AF_UNIX socketpair,
	// which RemoveIPC= does not cover. Both units must stay without it, and a
	// hardening sweep that adds it back to either is the regression this
	// catches.
	DescribeTable("does not set RemoveIPC, which would reach a shared account",
		func(path string) {
			d, err := unitDirectives(path)
			Expect(err).NotTo(HaveOccurred())
			Expect(d).NotTo(HaveKey("RemoveIPC"),
				"%s sets RemoveIPC on an account shared with openvox-server", path)
		},
		Entry("the service", filepath.Join("packaging", "systemd", distUnitFile)),
		Entry("the oneshot", firstBootUnit),
	)

	// The oneshot handles the CA private key for as long as it takes to sign,
	// so it is no less sensitive than the service -- and the two hardening
	// blocks are maintained by hand in two files. Drift here is silent: the
	// unit still starts, it is simply less confined than the comment in it
	// claims. ReadWritePaths= is excluded because it differs deliberately,
	// and that difference has its own spec above.
	It("keeps the same hardening as the service, bar the writable path", func() {
		hardening := []string{
			"LimitCORE", "NoNewPrivileges", "PrivateTmp", "PrivateDevices",
			"ProtectSystem", "ProtectHome", "ProtectProc", "ProtectClock",
			"ProtectHostname", "ProtectKernelLogs", "ProtectKernelModules",
			"ProtectKernelTunables", "ProtectControlGroups", "RestrictNamespaces",
			"RestrictRealtime", "RestrictSUIDSGID", "LockPersonality",
			"RestrictAddressFamilies", "SystemCallArchitectures", "SystemCallFilter",
			"SystemCallErrorNumber", "CapabilityBoundingSet", "AmbientCapabilities",
		}
		service, err := unitDirectives(filepath.Join("packaging", "systemd", distUnitFile))
		Expect(err).NotTo(HaveOccurred())

		for _, key := range hardening {
			Expect(service).To(HaveKey(key), "the service no longer sets %s, so this list is stale", key)
			Expect(directives).To(HaveKeyWithValue(key, service[key]),
				"%s differs between the two units", key)
		}
	})
})

var _ = Describe("the service account the packages create", func() {
	// The postinstall creates the account twice over: declaratively through
	// systemd-sysusers, and imperatively through groupadd/useradd where
	// systemd-sysusers is absent. Both paths run on real hosts, and a host
	// that took the fallback must not end up with a different account from one
	// that did not -- a different home directory or shell is the kind of
	// divergence that surfaces months later, on the host nobody tested on.
	//
	// The postinstall's own comment claimed this was asserted here. It was
	// not, until now.
	var sysusers, postinstall string

	BeforeEach(func() {
		body, err := os.ReadFile("packaging/sysusers/openvox-ca.conf")
		Expect(err).NotTo(HaveOccurred())
		sysusers = string(body)

		body, err = os.ReadFile("packaging/scripts/postinstall")
		Expect(err).NotTo(HaveOccurred())
		postinstall = string(body)
	})

	// The sysusers `u` line is: type, name, id, GECOS, home, shell.
	userLine := func() []string {
		for _, line := range strings.Split(sysusers, "\n") {
			if strings.HasPrefix(line, "u ") {
				return strings.Fields(line)
			}
		}
		Fail("packaging/sysusers/openvox-ca.conf declares no user")
		return nil
	}

	It("declares the same account in both, or the fallback host gets a different one", func() {
		// u name id GECOS home shell, and the GECOS is quoted and has spaces
		// in it -- so home and shell are taken from the end rather than by
		// index.
		fields := userLine()
		Expect(len(fields)).To(BeNumerically(">=", 6), "the u line should be: u name id GECOS home shell")
		name, home, shell := fields[1], fields[len(fields)-2], fields[len(fields)-1]

		Expect(name).To(Equal("puppet"))
		Expect(postinstall).To(ContainSubstring("--home-dir " + home))
		Expect(postinstall).To(ContainSubstring("--shell " + shell))
		Expect(postinstall).To(MatchRegexp(`(?m)^\t\t\t`+name+`\b`),
			"the useradd fallback should create %q", name)
	})

	// The units name this account, and systemd refuses to start a unit whose
	// User= does not exist.
	It("is the account both units run as", func() {
		fields := userLine()
		for _, path := range []string{filepath.Join("packaging", "systemd", distUnitFile), firstBootUnit} {
			d, err := unitDirectives(path)
			Expect(err).NotTo(HaveOccurred())
			Expect(d).To(HaveKeyWithValue("User", []string{fields[1]}), "User= in %s", path)
		}
	})
})

var _ = Describe("first-boot's node-certificate step", func() {
	var sslDir, binDir string

	BeforeEach(func() {
		sslDir = GinkgoT().TempDir()
		binDir = GinkgoT().TempDir()
		for _, d := range []string{"certs", "private_keys", "ca"} {
			Expect(os.MkdirAll(filepath.Join(sslDir, d), 0o755)).To(Succeed())
		}
	})

	writePair := func(cert, key bool) {
		if cert {
			Expect(os.WriteFile(filepath.Join(sslDir, "certs", "ca.example.com.pem"), []byte("cert"), 0o644)).To(Succeed())
		}
		if key {
			Expect(os.WriteFile(filepath.Join(sslDir, "private_keys", "ca.example.com.pem"), []byte("key"), 0o600)).To(Succeed())
		}
	}

	// The probe reads the root command's listing rather than invoking
	// `generate --help`, because that exits 0 on a build without the
	// subcommand -- cobra answers --help from the root before validating
	// arguments. A probe built the obvious way reports every build as capable,
	// so both directions are pinned here.
	Describe("has_generate_subcommand", func() {
		It("finds the subcommand when the listing has it", func() {
			stubOpenvoxCA(binDir, true)
			r, err := runFirstBootIn(sslDir, binDir, "has_generate_subcommand")
			Expect(err).NotTo(HaveOccurred())
			Expect(r.ok).To(BeTrue())
		})

		It("does not find it when the listing does not", func() {
			stubOpenvoxCA(binDir, false)
			r, err := runFirstBootIn(sslDir, binDir, "has_generate_subcommand")
			Expect(err).NotTo(HaveOccurred())
			Expect(r.ok).To(BeFalse())
		})
	})

	Describe("ensure_node_certificate", func() {
		It("adopts an existing pair without minting", func() {
			stubOpenvoxCA(binDir, true)
			writePair(true, true)
			r, err := runFirstBootIn(sslDir, binDir, `NAME=ca.example.com; ensure_node_certificate`)
			Expect(err).NotTo(HaveOccurred())
			Expect(r.ok).To(BeTrue())
			Expect(r.output).To(ContainSubstring("adopting the existing certificate"))
		})

		// Half a credential is the case where guessing is worse than stopping:
		// minting over a key whose certificate is missing, or vice versa,
		// silently replaces material an operator may still need.
		DescribeTable("refuses half a credential rather than guessing",
			func(cert, key bool) {
				stubOpenvoxCA(binDir, true)
				writePair(cert, key)
				r, err := runFirstBootIn(sslDir, binDir, `NAME=ca.example.com; ensure_node_certificate`)
				Expect(err).NotTo(HaveOccurred())
				Expect(r.ok).To(BeFalse())
				Expect(r.output).To(ContainSubstring("half a credential"))
			},
			Entry("a certificate with no key", true, false),
			Entry("a key with no certificate", false, true),
		)

		// A build that cannot mint leaves the service with no certificate to
		// serve, so this stops with the cause named rather than letting the
		// service fail later about TLS.
		It("stops when the build cannot mint, naming the binary", func() {
			stubOpenvoxCA(binDir, false)
			r, err := runFirstBootIn(sslDir, binDir, `NAME=ca.example.com; ensure_node_certificate`)
			Expect(err).NotTo(HaveOccurred())
			Expect(r.ok).To(BeFalse())
			Expect(r.output).To(And(
				ContainSubstring("no 'generate' subcommand"),
				ContainSubstring(filepath.Join(binDir, "openvox-ca")),
			))
		})
	})

	// First usable answer wins, and the order is the whole point: an explicit
	// answer beats the resolver, and the resolver's dotted answer beats the
	// short name.
	Describe("resolve_certname", func() {
		It("takes an explicit answer ahead of anything the resolver says", func() {
			stubOpenvoxCA(binDir, true)
			r, err := runFirstBootIn(sslDir, binDir, "resolve_certname 2>/dev/null",
				"OPENVOX_CA_CERTNAME=explicit.example.com")
			Expect(err).NotTo(HaveOccurred())
			Expect(r.ok).To(BeTrue())
			Expect(strings.TrimSpace(r.output)).To(Equal("explicit.example.com"))
		})

		// An unsafe explicit answer stops rather than falling through to the
		// next source: it is a mistake in a hand-written file, and quietly
		// provisioning under a different name would hide it.
		It("stops on an unsafe explicit answer rather than falling through", func() {
			stubOpenvoxCA(binDir, true)
			r, err := runFirstBootIn(sslDir, binDir, "resolve_certname",
				"OPENVOX_CA_CERTNAME=../../../etc/evil.example.com")
			Expect(err).NotTo(HaveOccurred())
			Expect(r.ok).To(BeFalse())
			Expect(r.output).To(ContainSubstring("not a usable certificate name"))
		})
	})
})

var _ = Describe("the packages' maintainer scripts", func() {
	// What is exercised here is the argument handling and the enable-once
	// decision: which invocations act at all, and whether an upgrade re-enables
	// a unit the operator disabled. Every external command is a stub that logs
	// its arguments, so nothing touches this machine's accounts.
	//
	// What is NOT exercised, deliberately: whether systemd-sysusers actually
	// creates the account it is handed. That needs a real /etc/passwd and a
	// real systemd, which is the packaging CI leg (#254). A test that stubbed
	// systemd-sysusers and then asserted the stub had been called would be
	// asserting its own fixture.
	var stubBin, log, systemdRuntime, stateDir string

	BeforeEach(func() {
		stubBin = GinkgoT().TempDir()
		systemdRuntime = GinkgoT().TempDir()
		stateDir = GinkgoT().TempDir()
		log = filepath.Join(GinkgoT().TempDir(), "calls.log")

		for _, name := range []string{
			"systemctl", "systemd-sysusers", "getent", "groupadd", "useradd", "chown", "chmod",
			// Not called by anything, and that is the point: they are here so
			// that a maintainer script which grew a call to one would show up
			// in the log rather than silently failing to resolve.
			"userdel", "groupdel",
		} {
			body := fmt.Sprintf("#!/bin/sh\necho \"%s $*\" >> %s\nexit 0\n", name, log)
			// getent must report the account as absent so the creation branch
			// is the one taken; every other stub succeeds.
			if name == "getent" {
				body = fmt.Sprintf("#!/bin/sh\necho \"getent $*\" >> %s\nexit 2\n", log)
			}
			Expect(os.WriteFile(filepath.Join(stubBin, name), []byte(body), 0o755)).To(Succeed())
		}
	})

	run := func(script string, args ...string) (firstBootResult, string) {
		cmd := exec.Command("sh", append([]string{script}, args...)...)
		// A directory standing in for /run/systemd/system, so the systemd
		// branch is reachable on a host that has no systemd. Without it the
		// scripts correctly do nothing here and the "acts on a removal" half
		// of the table below could not be asserted at all.
		cmd.Env = append(os.Environ(),
			"PATH="+stubBin+":/usr/bin:/bin",
			"OPENVOX_CA_SYSTEMD_RUNTIME="+systemdRuntime,
			"OPENVOX_CA_STATEDIR="+stateDir,
		)
		out, err := cmd.CombinedOutput()
		res := firstBootResult{ok: true, output: string(out)}
		if err != nil {
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				res.ok = false
			} else {
				Expect(err).NotTo(HaveOccurred())
			}
		}
		calls, readErr := os.ReadFile(log)
		if readErr != nil {
			calls = nil
		}
		return res, string(calls)
	}

	// dpkg's prerm never receives "purge" -- that is a postrm argument -- so
	// the accepted set is exactly dpkg's `remove` and rpm's remaining-count 0.
	// shouldAct is read. The previous version of this table declared it and
	// never used it, so all six entries asserted the same thing -- that the
	// script exited 0 -- which is true of a stubbed systemctl whatever the
	// script decides. A table named "acts only on a real removal" would have
	// passed had preremove done nothing at all, or disabled the service on
	// every upgrade. Go does not warn on an unused function parameter, so
	// nothing caught it but a reader.
	DescribeTable("preremove acts only on a real removal",
		func(arg string, shouldAct bool) {
			r, calls := run("packaging/scripts/preremove", arg)
			Expect(r.ok).To(BeTrue(), "preremove %q exited non-zero: %s", arg, r.output)
			if shouldAct {
				Expect(calls).To(ContainSubstring("systemctl"),
					"preremove %q should have stopped and disabled the units", arg)
				Expect(calls).To(ContainSubstring("openvox-ca.service"))
				Expect(calls).To(ContainSubstring("openvox-ca-first-boot.service"))
			} else {
				Expect(calls).To(BeEmpty(),
					"preremove %q must not touch the units: stopping the service on an upgrade is an "+
						"outage nobody asked for", arg)
			}
		},
		Entry("dpkg remove", "remove", true),
		Entry("rpm erase", "0", true),
		Entry("dpkg upgrade", "upgrade", false),
		Entry("rpm upgrade", "1", false),
		Entry("dpkg failed-upgrade", "failed-upgrade", false),
		Entry("no argument at all", "", false),
	)

	It("preremove does not accept purge, which dpkg sends to postrm", func() {
		src, err := os.ReadFile("packaging/scripts/preremove")
		Expect(err).NotTo(HaveOccurred())
		Expect(string(src)).To(MatchRegexp(`(?m)^0 \| remove\) ;;$`),
			"the accepted set should be dpkg's remove and rpm's 0, and nothing else")
	})

	DescribeTable("postinstall runs on install and upgrade, and stops on a rollback",
		func(args []string, shouldAct bool) {
			r, calls := run("packaging/scripts/postinstall", args...)
			Expect(r.ok).To(BeTrue(), "postinstall %v exited non-zero: %s", args, r.output)
			if shouldAct {
				Expect(calls).To(ContainSubstring("systemd-sysusers"),
					"postinstall %v should have provisioned the account", args)
			} else {
				Expect(calls).To(BeEmpty(),
					"postinstall %v should have done nothing at all", args)
			}
		},
		Entry("dpkg configure", []string{"configure"}, true),
		Entry("rpm install", []string{"1"}, true),
		Entry("rpm upgrade", []string{"2"}, true),
		// dpkg's rollback arguments: re-running here would fight the state
		// being rolled back to.
		Entry("dpkg abort-upgrade", []string{"abort-upgrade", "1.0.0"}, false),
		Entry("dpkg abort-remove", []string{"abort-remove"}, false),
	)

	// The finding behind this: without an argument guard, every upgrade
	// re-enabled the oneshot and silently undid a deliberate
	// `systemctl disable openvox-ca-first-boot`.
	// Executed, not grepped. An earlier version of this read the script's
	// source and asserted the guard's *shape*, justified by systemd being
	// absent here -- but the SYSTEMD_RUNTIME seam added in the same round made
	// the branch reachable, and the justification was stale from the moment it
	// was written. A test that inspects source text cannot fail for the
	// property it names: it passes for a script whose condition is spelled
	// correctly and does the wrong thing.
	// The enable decision is the marker, not the package manager's arguments.
	// dpkg passes the previously-configured version in $2 for a package that
	// was removed but not purged as well as for an upgrade, so the arguments
	// alone cannot tell a reinstall from an update -- and a reinstall must
	// re-enable, because our own preremove disabled the unit on the way out.
	markerPath := func() string { return filepath.Join(stateDir, "first-boot-enabled") }

	DescribeTable("enables the provisioning oneshot exactly once, and again after a removal",
		func(args []string, markerPresent, shouldEnable bool) {
			if markerPresent {
				Expect(os.WriteFile(markerPath(), nil, 0o644)).To(Succeed())
			}

			_, calls := run("packaging/scripts/postinstall", args...)
			if shouldEnable {
				Expect(calls).To(ContainSubstring("systemctl enable openvox-ca-first-boot.service"),
					"postinstall %v should have enabled the oneshot", args)
				Expect(markerPath()).To(BeAnExistingFile(),
					"a successful enable must record itself, or the next upgrade re-enables")
			} else {
				Expect(calls).NotTo(ContainSubstring("systemctl enable"),
					"postinstall %v re-enabled the oneshot, overriding an operator's disable", args)
			}
		},
		Entry("dpkg first install", []string{"configure"}, false, true),
		Entry("rpm first install", []string{"1"}, false, true),
		Entry("dpkg upgrade, already enabled once", []string{"configure", "1.0.0"}, true, false),
		Entry("rpm upgrade, already enabled once", []string{"2"}, true, false),
		// preremove deletes the marker, so this is what a reinstall looks
		// like: dpkg still passes a version in $2, but the unit is disabled
		// and must be enabled again.
		Entry("dpkg reinstall after remove", []string{"configure", "1.0.0"}, false, true),
	)

	// Enabling is on-disk symlink work. Gating it on a running systemd meant a
	// chroot, image build or mounted-root install never enabled the oneshot,
	// and because its only [Install] directive is RequiredBy=, never ran it.
	It("enables the oneshot even where systemd is not running", func() {
		absent := filepath.Join(GinkgoT().TempDir(), "no-such-runtime")
		cmd := exec.Command("/bin/sh", "packaging/scripts/postinstall", "configure")
		// SSLDIR and CONFIG are left at their defaults: they do not exist
		// here, so those guards skip and what remains under test is the
		// enable.
		cmd.Env = append(os.Environ(),
			"PATH="+stubBin,
			"OPENVOX_CA_SYSTEMD_RUNTIME="+absent,
			"OPENVOX_CA_STATEDIR="+stateDir,
		)
		out, err := cmd.CombinedOutput()
		Expect(err).NotTo(HaveOccurred(), "postinstall failed: %s", out)

		calls, readErr := os.ReadFile(log)
		Expect(readErr).NotTo(HaveOccurred())
		Expect(string(calls)).To(ContainSubstring("systemctl enable openvox-ca-first-boot.service"))
		// daemon-reload genuinely needs a running systemd, so it stays behind
		// the guard and must NOT have been attempted.
		Expect(string(calls)).NotTo(ContainSubstring("daemon-reload"))
	})

	// The outcome decides whether provisioning ever runs, so it is reported
	// rather than swallowed -- and the install still succeeds.
	It("warns rather than failing when the oneshot cannot be enabled", func() {
		Expect(os.WriteFile(filepath.Join(stubBin, "systemctl"),
			[]byte("#!/bin/sh\nexit 1\n"), 0o755)).To(Succeed())

		r, _ := run("packaging/scripts/postinstall", "configure")
		Expect(r.ok).To(BeTrue(), "a failed enable must not fail the install")
		Expect(r.output).To(And(
			ContainSubstring("could not enable openvox-ca-first-boot.service"),
			ContainSubstring("systemctl enable openvox-ca-first-boot"),
		))
		Expect(markerPath()).NotTo(BeAnExistingFile(),
			"a failed enable must not record itself, or the next upgrade will not retry")
	})

	// What postremove does NOT do is the whole point of it, and asserting only
	// that it exits 0 is satisfied by a script that deletes the `puppet`
	// account and the CA tree with it. So the call log is matched exactly: the
	// one thing it may do is tell systemd the units are gone.
	DescribeTable("postremove reloads systemd and does nothing else",
		func(arg string) {
			r, calls := run("packaging/scripts/postremove", arg)
			Expect(r.ok).To(BeTrue(), "postremove %q exited non-zero: %s", arg, r.output)
			Expect(strings.Fields(calls)).To(Equal([]string{"systemctl", "daemon-reload"}),
				"postremove %q did something other than reloading systemd: %s", arg, calls)
		},
		Entry("dpkg remove", "remove"),
		// purge above all: this is where dpkg would expect a package to delete
		// what it left behind, and where this one deliberately does not.
		Entry("dpkg purge", "purge"),
		Entry("dpkg upgrade", "upgrade"),
		Entry("rpm erase", "0"),
		Entry("rpm upgrade", "1"),
		Entry("no argument at all", ""),
	)

	// daemon-reload needs a running systemd, so on a host without one the
	// script must do nothing rather than fail the removal.
	It("postremove does nothing at all where systemd is not running", func() {
		absent := filepath.Join(GinkgoT().TempDir(), "no-such-runtime")
		cmd := exec.Command("/bin/sh", "packaging/scripts/postremove", "remove")
		cmd.Env = append(os.Environ(),
			"PATH="+stubBin,
			"OPENVOX_CA_SYSTEMD_RUNTIME="+absent,
		)
		out, err := cmd.CombinedOutput()
		Expect(err).NotTo(HaveOccurred(), "postremove failed: %s", out)
		Expect(log).NotTo(BeAnExistingFile(), "postremove called something")
	})
})

var _ = Describe("first-boot's certname fallback tiers", func() {
	// resolve_certname is first-usable-wins across four tiers, and only the
	// first was reachable before: a spec had no way to control what `hostname`
	// returns. A stub on PATH is the unlock -- the same technique the
	// maintainer-script specs use -- and it makes the tier that matters most
	// testable: the localhost fallback, whose whole purpose is to flag a CA
	// that looks healthy while no agent can reach it.
	var sslDir, binDir, stubBin string

	BeforeEach(func() {
		sslDir = GinkgoT().TempDir()
		binDir = GinkgoT().TempDir()
		stubBin = GinkgoT().TempDir()
		for _, d := range []string{"certs", "private_keys", "ca"} {
			Expect(os.MkdirAll(filepath.Join(sslDir, d), 0o755)).To(Succeed())
		}
		stubOpenvoxCA(binDir, true)
	})

	// stubHostname writes a `hostname` that answers -f and -s as told. An
	// empty answer stands for the command failing to produce one.
	stubHostname := func(fqdn, short string) {
		body := fmt.Sprintf(`#!/bin/sh
case "${1:-}" in
-f) [ -n %s ] && printf '%%s\n' %s || exit 1 ;;
-s) [ -n %s ] && printf '%%s\n' %s || exit 1 ;;
*)  [ -n %s ] && printf '%%s\n' %s || exit 1 ;;
esac
`, shellQuote(fqdn), shellQuote(fqdn), shellQuote(short), shellQuote(short), shellQuote(short), shellQuote(short))
		Expect(os.WriteFile(filepath.Join(stubBin, "hostname"), []byte(body), 0o755)).To(Succeed())
	}

	resolve := func() firstBootResult {
		defs, err := firstBootDefs()
		Expect(err).NotTo(HaveOccurred())
		cmd := exec.Command("sh", "-c", defs+"\nresolve_certname\n")
		cmd.Env = append(os.Environ(),
			"OPENVOX_CA_SSLDIR="+sslDir,
			"OPENVOX_CA_BINDIR="+binDir,
			// puppet.conf is the tier above the hostname tiers, and it
			// defaults to /etc/puppetlabs/puppet/puppet.conf -- a real path on
			// any machine that has run an agent, this developer's and a CI
			// runner's alike. Left unset, a host with a certname in it would
			// answer every case below from that file and none of the tiers
			// this block exists to exercise would run.
			"OPENVOX_CA_PUPPET_CONF="+filepath.Join(GinkgoT().TempDir(), "no-puppet.conf"),
			"PATH="+stubBin+":/usr/bin:/bin",
			"OPENVOX_CA_CERTNAME=",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				return firstBootResult{ok: false, output: string(out)}
			}
			Expect(err).NotTo(HaveOccurred())
		}
		return firstBootResult{ok: true, output: string(out)}
	}

	// Tier 2: the resolver's fully qualified answer.
	It("takes a dotted hostname -f", func() {
		stubHostname("ca.example.com", "ca")
		r := resolve()
		Expect(r.ok).To(BeTrue())
		Expect(r.output).To(ContainSubstring("ca.example.com"))
		Expect(r.output).NotTo(ContainSubstring("WARNING"))
	})

	// Tier 3: the short hostname, which works only for whatever reaches this
	// host by the same short name -- so it warns rather than passing silently.
	It("falls back to the short hostname and warns about what will not work", func() {
		stubHostname("", "ca")
		r := resolve()
		Expect(r.ok).To(BeTrue())
		Expect(r.output).To(And(
			ContainSubstring("ca"),
			ContainSubstring("no fully qualified domain name"),
			ContainSubstring("re-mint"),
		))
	})

	// A localhost form from the resolver is not a usable FQDN, so it must not
	// satisfy tier 2 -- this is the pattern the two duplicated lists used to
	// disagree about.
	It("does not accept a localhost form as the resolver's answer", func() {
		stubHostname("localhost.localdomain", "localhost")
		r := resolve()
		Expect(r.ok).To(BeTrue())
		Expect(strings.TrimSpace(lastLine(r.output))).To(Equal("localhost"))
	})

	// Tier 4: nothing usable at all.
	It("falls back to localhost when the resolver answers nothing", func() {
		stubHostname("", "")
		r := resolve()
		Expect(r.ok).To(BeTrue())
		Expect(r.output).To(And(
			ContainSubstring("could not determine this host's name"),
			ContainSubstring("appear healthy"),
		))
		Expect(strings.TrimSpace(lastLine(r.output))).To(Equal("localhost"))
	})

	// The marker is the part that matters: a CA under an unusable name looks
	// healthy in systemctl status, so something has to say otherwise on disk.
	Describe("write_unresolved_marker", func() {
		It("records what is wrong and how to recover", func() {
			defs, err := firstBootDefs()
			Expect(err).NotTo(HaveOccurred())
			cmd := exec.Command("sh", "-c", defs+"\nwrite_unresolved_marker\n")
			cmd.Env = append(os.Environ(),
				"OPENVOX_CA_SSLDIR="+sslDir,
				"OPENVOX_CA_BINDIR="+binDir,
			)
			Expect(cmd.Run()).To(Succeed())

			body, err := os.ReadFile(filepath.Join(sslDir, "openvox-ca-certname-unresolved"))
			Expect(err).NotTo(HaveOccurred())
			Expect(string(body)).To(And(
				ContainSubstring("could not determine this host's fully qualified domain name"),
				ContainSubstring("No agent will be able to use it"),
				ContainSubstring("systemctl stop openvox-ca"),
			))
			// The recovery destroys a CA, so it must say what that costs.
			Expect(string(body)).To(ContainSubstring("stops being trusted"))
		})
	})
})

// lastLine returns the final non-empty line of s, which is where
// resolve_certname's answer lands: its warnings go to stderr and the name to
// stdout, and CombinedOutput interleaves them.
func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) != "" {
			return lines[i]
		}
	}
	return ""
}

var _ = Describe("Build.Packages", func() {
	// The target itself, not just the per-variant helper underneath it. It
	// orchestrates: resolve the version, check the inputs, loop the packaged
	// variants, then count what landed. Nothing exercised that assembly.
	//
	// It writes into dist/, which is the repository's own -- so this runs only
	// when the tarballs a real build would have left are already there, and
	// asserts against what it finds rather than creating them.
	It("refuses to run when the tarballs it consumes are absent", func() {
		ver, err := releaseVersion()
		Expect(err).NotTo(HaveOccurred())

		missing := true
		for _, v := range packagedDistVariants() {
			if _, statErr := os.Stat(filepath.Join("dist", fmt.Sprintf("openvox-ca_%s_%s.tar.gz", ver, v.name))); statErr == nil {
				missing = false
			}
		}
		if !missing {
			Skip("dist/ already holds this version's tarballs; this spec covers the empty case")
		}

		err = Build{}.Packages()
		Expect(err).To(MatchError(And(
			ContainSubstring("does not build binaries"),
			ContainSubstring("mage build:distVariant"),
		)))
	})
})

// runFirstBootScript runs the whole provisioning script -- not one function --
// against a scratch ssl tree with stub binaries, and returns what it did.
//
// The stubs stand in for the CA, not for the script: openvox-ca-ctl `setup`
// creates the files a bootstrapped cadir has, and `generate` writes the
// credential it is asked for. What is under test is the script's own
// behaviour, which is what the packages ship and what no CI leg installs.
func runFirstBootScript(sslDir, binDir, certname string) firstBootResult {
	cmd := exec.Command("sh", firstBootScript)
	cmd.Env = append(os.Environ(),
		"OPENVOX_CA_SSLDIR="+sslDir,
		"OPENVOX_CA_BINDIR="+binDir,
		"OPENVOX_CA_CERTNAME="+certname,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return firstBootResult{ok: false, output: string(out)}
		}
		Expect(err).NotTo(HaveOccurred())
	}
	return firstBootResult{ok: true, output: string(out)}
}

// stubCA writes an openvox-ca-ctl whose `setup` bootstraps a cadir, and an
// openvox-ca whose `generate` writes the cert and key it is told to.
func stubCA(binDir string) {
	ctl := `#!/bin/sh
cadir=""
prev=""
for a in "$@"; do
  case "$prev" in --cadir) cadir=$a ;; esac
  prev=$a
done
[ -n "$cadir" ] || exit 1
mkdir -p "$cadir/private" "$cadir/signed"
printf 'CA-CERT\n' > "$cadir/ca_crt.pem"
printf 'CA-CRL\n'  > "$cadir/ca_crl.pem"
exit 0
`
	ca := `#!/bin/sh
case "${1:-}" in
--help) printf 'Available Commands:\n  generate       Mint a certificate offline\n'; exit 0 ;;
generate) ;;
*) exit 0 ;;
esac
certout=""; keyout=""; prev=""
for a in "$@"; do
  case "$prev" in --cert-out) certout=$a ;; --key-out) keyout=$a ;; esac
  prev=$a
done
[ -n "$certout" ] && printf 'NODE-CERT\n' > "$certout"
[ -n "$keyout" ]  && { printf 'NODE-KEY\n' > "$keyout"; chmod 0600 "$keyout"; }
exit 0
`
	Expect(os.WriteFile(filepath.Join(binDir, "openvox-ca-ctl"), []byte(ctl), 0o755)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(binDir, "openvox-ca"), []byte(ca), 0o755)).To(Succeed())
}

var _ = Describe("first-boot's provisioning steps", func() {
	var sslDir, binDir string

	BeforeEach(func() {
		sslDir = GinkgoT().TempDir()
		binDir = GinkgoT().TempDir()
		// The package ships these two; the script refuses without them.
		Expect(os.MkdirAll(filepath.Join(sslDir, "ca"), 0o755)).To(Succeed())
		stubCA(binDir)
	})

	Describe("a first boot on an empty tree", func() {
		BeforeEach(func() {
			r := runFirstBootScript(sslDir, binDir, "ca.example.com")
			Expect(r.ok).To(BeTrue(), "provisioning failed: %s", r.output)
		})

		// Step 1, with the mode that matters: private_keys is created 0750
		// rather than created 0755 and narrowed afterwards.
		DescribeTable("creates the ssl tree",
			func(dir string, mode os.FileMode) {
				info, err := os.Stat(filepath.Join(sslDir, dir))
				Expect(err).NotTo(HaveOccurred())
				Expect(info.IsDir()).To(BeTrue())
				Expect(info.Mode().Perm()).To(Equal(mode), "mode of %s", dir)
			},
			Entry("certs", "certs", os.FileMode(0o755)),
			Entry("public_keys", "public_keys", os.FileMode(0o755)),
			Entry("private_keys", "private_keys", os.FileMode(0o750)),
		)

		It("bootstraps the CA", func() {
			Expect(filepath.Join(sslDir, "ca", "ca_crt.pem")).To(BeAnExistingFile())
		})

		It("mints this host's credential", func() {
			Expect(filepath.Join(sslDir, "certs", "ca.example.com.pem")).To(BeAnExistingFile())
			Expect(filepath.Join(sslDir, "private_keys", "ca.example.com.pem")).To(BeAnExistingFile())
		})

		// Step 4 and step 5. Asserted as symlinks with their targets, not
		// merely as existing paths: the defect this covers was a regular file
		// sitting where the alias belongs, which every "does it exist" check
		// passes.
		DescribeTable("links the aliases into place",
			func(path, target string) {
				full := filepath.Join(sslDir, path)
				info, err := os.Lstat(full)
				Expect(err).NotTo(HaveOccurred())
				Expect(info.Mode()&os.ModeSymlink).NotTo(BeZero(), "%s is not a symlink", path)

				got, err := os.Readlink(full)
				Expect(err).NotTo(HaveOccurred())
				Expect(got).To(Equal(target))
				Expect(full).To(BeAnExistingFile(), "%s does not resolve", path)
			},
			Entry("the CA certificate alias", "certs/ca.pem", "../ca/ca_crt.pem"),
			Entry("the CRL alias", "crl.pem", "ca/ca_crl.pem"),
			Entry("the serving certificate", "certs/openvox-ca-server.pem", "ca.example.com.pem"),
			Entry("the serving key", "private_keys/openvox-ca-server.pem", "ca.example.com.pem"),
		)

		It("writes no unresolved-name marker when the name resolved", func() {
			Expect(filepath.Join(sslDir, "openvox-ca-certname-unresolved")).NotTo(BeAnExistingFile())
		})
	})

	// The marker's text tells the operator to `rm -rf $CADIR` and start over.
	// That is sound advice about a CA this run just minted under an unusable
	// name, and it is an instruction to destroy a working CA on a host that
	// already had one -- so it is written only when this run created the CA.
	// The guard reads the cadir before ensure_ca and nothing else does, which
	// makes it exactly the kind of ordering a later edit moves without
	// noticing.
	Describe("the unresolved-name marker", func() {
		var sslDir, binDir, marker string

		BeforeEach(func() {
			sslDir = GinkgoT().TempDir()
			binDir = GinkgoT().TempDir()
			marker = filepath.Join(sslDir, "openvox-ca-certname-unresolved")
			Expect(os.MkdirAll(filepath.Join(sslDir, "ca"), 0o755)).To(Succeed())
			stubCA(binDir)
		})

		It("is written when this run mints the CA under \"localhost\"", func() {
			r := runFirstBootScript(sslDir, binDir, "localhost")
			Expect(r.ok).To(BeTrue(), "provisioning failed: %s", r.output)
			Expect(marker).To(BeAnExistingFile())

			body, err := os.ReadFile(marker)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(body)).To(ContainSubstring("rm -rf"),
				"the marker's recovery steps are what make writing it on a takeover dangerous")
		})

		// A takeover: the CA is already there, so every step is a no-op and
		// this run issued nothing. Writing the marker here would tell an
		// operator to delete a CA that is working.
		It("is not written on a takeover of an existing CA", func() {
			Expect(os.WriteFile(filepath.Join(sslDir, "ca", "ca_crt.pem"),
				[]byte("CA-CERT\n"), 0o644)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(sslDir, "ca", "ca_crl.pem"),
				[]byte("CA-CRL\n"), 0o644)).To(Succeed())

			r := runFirstBootScript(sslDir, binDir, "localhost")
			Expect(r.ok).To(BeTrue(), "provisioning failed: %s", r.output)
			Expect(marker).NotTo(BeAnExistingFile(),
				"the marker tells the operator to rm -rf a CA this run did not create")
		})
	})

	It("is idempotent: a second run adopts and changes nothing", func() {
		Expect(runFirstBootScript(sslDir, binDir, "ca.example.com").ok).To(BeTrue())
		before, err := os.ReadFile(filepath.Join(sslDir, "certs", "ca.example.com.pem"))
		Expect(err).NotTo(HaveOccurred())

		r := runFirstBootScript(sslDir, binDir, "ca.example.com")
		Expect(r.ok).To(BeTrue(), "second run failed: %s", r.output)
		Expect(r.output).To(And(
			ContainSubstring("a CA already exists"),
			ContainSubstring("adopting the existing certificate"),
		))

		after, err := os.ReadFile(filepath.Join(sslDir, "certs", "ca.example.com.pem"))
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before), "the second run re-minted rather than adopting")
	})

	// The certname that collides with an alias this script maintains. Before
	// the check, provisioning succeeded and left certs/ca.pem a regular file
	// holding a NODE certificate -- where every agent on this host looks for
	// the CA certificate, and with nothing logged, because each step had done
	// exactly what it was told.
	Describe("a certname that collides with an alias", func() {
		DescribeTable("is refused rather than silently displacing the alias",
			func(certname string) {
				r := runFirstBootScript(sslDir, binDir, certname)
				Expect(r.ok).To(BeFalse(), "provisioning should have refused %q", certname)
				Expect(r.output).To(And(
					ContainSubstring("cannot be used as this host's certificate name"),
					ContainSubstring("reserves it"),
				))
				Expect(filepath.Join(sslDir, "certs", certname+".pem")).NotTo(BeAnExistingFile())
			},
			Entry("the CA alias", "ca"),
			Entry("the serving alias", "openvox-ca-server"),
		)

		// The property the collision violated, stated on its own so a
		// regression is named for what it breaks rather than for the input
		// that triggers it.
		It("keeps certs/ca.pem a symlink to the CA certificate", func() {
			Expect(runFirstBootScript(sslDir, binDir, "ca.example.com").ok).To(BeTrue())

			info, err := os.Lstat(filepath.Join(sslDir, "certs", "ca.pem"))
			Expect(err).NotTo(HaveOccurred())
			Expect(info.Mode()&os.ModeSymlink).NotTo(BeZero(),
				"certs/ca.pem is a regular file; agents fetching the CA certificate would get whatever it holds")

			body, err := os.ReadFile(filepath.Join(sslDir, "certs", "ca.pem"))
			Expect(err).NotTo(HaveOccurred())
			Expect(string(body)).To(Equal("CA-CERT\n"), "certs/ca.pem does not resolve to the CA certificate")
		})
	})
})

var _ = Describe("postinstall's ownership and permission hardening", func() {
	// The branch that hands the shipped files to `puppet` after sysusers has
	// created it. Nothing could reach it before: it operates on absolute paths,
	// so a spec had no way in without a container. The seam makes the
	// hardening itself assertable -- --no-dereference, the symlink refusal, and
	// mode 0640 on a file that will hold credentials.
	var stubBin, log, sslDir, configPath, systemdRuntime, stateDir string

	run := func(args ...string) (firstBootResult, string) {
		// /bin/sh by absolute path, because PATH below deliberately holds
		// nothing but the stubs.
		cmd := exec.Command("/bin/sh", append([]string{"packaging/scripts/postinstall"}, args...)...)
		// The stub directory ALONE. Leaving /usr/bin on PATH meant that
		// removing the systemd-sysusers stub did not make the command absent
		// on a host that has a real one -- `command -v` found /usr/bin's, ran
		// it, and the script died under `set -e`. That passed on a machine
		// with no systemd and failed on CI: a test passing for the wrong
		// reason, and the wrong reason was the platform.
		//
		// Every external command postinstall calls is stubbed below, so this
		// exercises the script's branching on any platform rather than the
		// host's idea of which tools exist.
		cmd.Env = append(os.Environ(),
			"PATH="+stubBin,
			"OPENVOX_CA_SYSTEMD_RUNTIME="+systemdRuntime,
			"OPENVOX_CA_SSLDIR="+sslDir,
			"OPENVOX_CA_CONFIG="+configPath,
			"OPENVOX_CA_STATEDIR="+stateDir,
		)
		out, err := cmd.CombinedOutput()
		res := firstBootResult{ok: true, output: string(out)}
		if err != nil {
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				res.ok = false
			} else {
				Expect(err).NotTo(HaveOccurred())
			}
		}
		calls, readErr := os.ReadFile(log)
		if readErr != nil {
			calls = nil
		}
		return res, string(calls)
	}

	BeforeEach(func() {
		stubBin = GinkgoT().TempDir()
		sslDir = GinkgoT().TempDir()
		systemdRuntime = GinkgoT().TempDir()
		stateDir = GinkgoT().TempDir()
		log = filepath.Join(GinkgoT().TempDir(), "calls.log")
		configPath = filepath.Join(GinkgoT().TempDir(), "config.yaml")

		// chown and chmod are stubs: this runs as an ordinary user, and the
		// question is which arguments the script passes, not whether the
		// kernel honours them.
		for _, name := range []string{"systemctl", "systemd-sysusers", "getent", "groupadd", "useradd", "chown", "chmod"} {
			body := fmt.Sprintf("#!/bin/sh\necho \"%s $*\" >> %s\nexit 0\n", name, log)
			if name == "getent" {
				body = fmt.Sprintf("#!/bin/sh\necho \"getent $*\" >> %s\nexit 2\n", log)
			}
			Expect(os.WriteFile(filepath.Join(stubBin, name), []byte(body), 0o755)).To(Succeed())
		}
		Expect(os.MkdirAll(filepath.Join(sslDir, "ca"), 0o755)).To(Succeed())
	})

	It("hands the ssl tree to puppet without following symlinks", func() {
		_, calls := run("configure")
		Expect(calls).To(ContainSubstring("chown --no-dereference puppet:puppet " + sslDir))
		// --no-dereference is the point: this runs as root over a directory
		// `puppet` can write, so a planted symlink would otherwise redirect it.
		Expect(calls).NotTo(MatchRegexp(`(?m)^chown puppet:puppet`))
	})

	It("gives the configuration file to root:puppet at 0640", func() {
		Expect(os.WriteFile(configPath, []byte("port: 8141\n"), 0o644)).To(Succeed())
		_, calls := run("configure")
		Expect(calls).To(ContainSubstring("chown --no-dereference root:puppet " + configPath))
		Expect(calls).To(ContainSubstring("chmod 0640 " + configPath))
	})

	// The case chmod cannot be made safe for: GNU chmod has no portable -h, so
	// the script refuses rather than following the link.
	It("refuses to touch the configuration file when it is a symlink", func() {
		target := filepath.Join(GinkgoT().TempDir(), "elsewhere.yaml")
		Expect(os.WriteFile(target, []byte("port: 9999\n"), 0o644)).To(Succeed())
		Expect(os.Symlink(target, configPath)).To(Succeed())

		r, calls := run("configure")
		Expect(r.ok).To(BeTrue(), "postinstall exited non-zero: %s", r.output)
		Expect(r.output).To(ContainSubstring("is a symlink"))
		Expect(calls).NotTo(ContainSubstring("chmod 0640 "+configPath),
			"chmod on a symlink changes the target's mode, which is not ours to alter")
		Expect(calls).NotTo(ContainSubstring("chown --no-dereference root:puppet " + configPath))
	})

	// Both fixups are non-fatal by design: a maintainer script that exits
	// non-zero leaves the package half-configured.
	It("warns rather than failing when the ownership fixup cannot be applied", func() {
		Expect(os.WriteFile(configPath, []byte("port: 8141\n"), 0o644)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(stubBin, "chown"),
			[]byte("#!/bin/sh\nexit 1\n"), 0o755)).To(Succeed())

		r, _ := run("configure")
		Expect(r.ok).To(BeTrue(), "a failed chown must not fail the install")
		Expect(r.output).To(And(
			ContainSubstring("WARNING"),
			ContainSubstring("root:puppet"),
		))
	})

	// The account-creation fallback for hosts with no systemd-sysusers. The
	// stub set deliberately omits it so `command -v` misses and the
	// groupadd/useradd path is the one taken.
	It("falls back to groupadd and useradd where systemd-sysusers is absent", func() {
		Expect(os.Remove(filepath.Join(stubBin, "systemd-sysusers"))).To(Succeed())
		// The premise, asserted rather than assumed: with PATH holding only
		// the stub directory, removing the stub is what makes the command
		// absent. If PATH ever widens again this fails here, naming the
		// reason, instead of quietly testing the host's real systemd-sysusers.
		Expect(exec.Command("/bin/sh", "-c",
			"PATH="+stubBin+" command -v systemd-sysusers").Run()).To(HaveOccurred(),
			"systemd-sysusers is still reachable, so this spec is not exercising the fallback")

		r, calls := run("configure")
		Expect(r.ok).To(BeTrue(), "postinstall exited non-zero: %s", r.output)
		Expect(calls).NotTo(ContainSubstring("systemd-sysusers"))
		Expect(calls).To(ContainSubstring("groupadd --system puppet"))
		Expect(calls).To(ContainSubstring("useradd --system --gid puppet"))
	})

	// Idempotent: an account that already exists is left exactly as it is,
	// which matters on upgrade and on a host where OpenVox Server got there
	// first -- its account is the one we want, not one to correct.
	It("creates nothing when the account already exists", func() {
		Expect(os.Remove(filepath.Join(stubBin, "systemd-sysusers"))).To(Succeed())
		Expect(os.WriteFile(filepath.Join(stubBin, "getent"),
			[]byte("#!/bin/sh\nexit 0\n"), 0o755)).To(Succeed())

		_, calls := run("configure")
		Expect(calls).NotTo(ContainSubstring("groupadd"))
		Expect(calls).NotTo(ContainSubstring("useradd"))
	})
})

var _ = Describe("first-boot's puppet.conf certname tier", func() {
	var sslDir, binDir, stubBin, puppetConf string

	BeforeEach(func() {
		sslDir = GinkgoT().TempDir()
		binDir = GinkgoT().TempDir()
		stubBin = GinkgoT().TempDir()
		puppetConf = filepath.Join(GinkgoT().TempDir(), "puppet.conf")
		stubOpenvoxCA(binDir, true)
		// hostname answers nothing, so the only name available is whichever
		// tier is under test -- and, critically, the specs below cannot fall
		// through to this developer's own hostname.
		Expect(os.WriteFile(filepath.Join(stubBin, "hostname"),
			[]byte("#!/bin/sh\nexit 1\n"), 0o755)).To(Succeed())
	})

	resolve := func() firstBootResult {
		defs, err := firstBootDefs()
		Expect(err).NotTo(HaveOccurred())
		cmd := exec.Command("sh", "-c", defs+"\nresolve_certname\n")
		cmd.Env = append(os.Environ(),
			"OPENVOX_CA_SSLDIR="+sslDir,
			"OPENVOX_CA_BINDIR="+binDir,
			"OPENVOX_CA_PUPPET_CONF="+puppetConf,
			"PATH="+stubBin+":/usr/bin:/bin",
			"OPENVOX_CA_CERTNAME=",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				return firstBootResult{ok: false, output: string(out)}
			}
			Expect(err).NotTo(HaveOccurred())
		}
		return firstBootResult{ok: true, output: string(out)}
	}

	It("takes certname from puppet.conf when there is no explicit answer", func() {
		Expect(os.WriteFile(puppetConf,
			[]byte("[main]\ncertname = agent.example.com\nserver = puppet\n"), 0o644)).To(Succeed())
		Expect(strings.TrimSpace(lastLine(resolve().output))).To(Equal("agent.example.com"))
	})

	// Not a general INI parser: the last uncommented certname wins, which is
	// what puppet itself would resolve for any section this file can set it in.
	It("takes the last uncommented certname and ignores commented ones", func() {
		Expect(os.WriteFile(puppetConf,
			[]byte("[main]\n#certname = commented.example.com\ncertname = first.example.com\n"+
				"[agent]\ncertname = last.example.com\n"), 0o644)).To(Succeed())
		Expect(strings.TrimSpace(lastLine(resolve().output))).To(Equal("last.example.com"))
	})

	// An unsafe name from a file anything with write access can edit must not
	// be used, and must not stop provisioning either -- it falls through.
	It("ignores an unsafe certname from puppet.conf and says so", func() {
		Expect(os.WriteFile(puppetConf,
			[]byte("[main]\ncertname = ../../../etc/evil.example.com\n"), 0o644)).To(Succeed())
		r := resolve()
		Expect(r.output).To(ContainSubstring("ignoring certname"))
		Expect(strings.TrimSpace(lastLine(r.output))).To(Equal("localhost"))
	})

	It("falls through when there is no puppet.conf at all", func() {
		Expect(strings.TrimSpace(lastLine(resolve().output))).To(Equal("localhost"))
	})
})

var _ = Describe("buildPackagesInto", func() {
	// Build.Packages' orchestration on its success path: resolve the version,
	// check the inputs, loop every packaged variant, count what landed. The
	// per-variant work has its own specs; what had none was the assembly.
	It("builds every packaged variant's formats and accepts the result", func() {
		distDir := GinkgoT().TempDir()
		ver, err := releaseVersion()
		Expect(err).NotTo(HaveOccurred())

		src := GinkgoT().TempDir()
		for _, name := range []string{"openvox-ca", "openvox-ca-ctl"} {
			Expect(os.WriteFile(filepath.Join(src, name), []byte("#!/bin/true\n"), 0o755)).To(Succeed())
		}
		unit, err := renderUnit(tarballUnitBindir)
		Expect(err).NotTo(HaveOccurred())
		Expect(os.WriteFile(filepath.Join(src, distUnitFile), unit, 0o644)).To(Succeed())

		// A tarball per packaged variant, named as build:dist writes them.
		for _, v := range packagedDistVariants() {
			archive := filepath.Join(distDir, fmt.Sprintf("openvox-ca_%s_%s.tar.gz", ver, v.name))
			Expect(createTarGz(archive, src, distArchiveFiles([]string{"openvox-ca", "openvox-ca-ctl"}))).To(Succeed())
		}

		Expect(buildPackagesInto(distDir)).To(Succeed())

		// One package per format per packaged variant, and nothing else.
		for _, ext := range packageExtensions() {
			found, err := filepath.Glob(filepath.Join(distDir, "*"+ext))
			Expect(err).NotTo(HaveOccurred())
			Expect(found).To(HaveLen(len(packagedDistVariants())), "%s packages", ext)
		}
	})

	// The FIPS variants are not packaged, and the count above would not notice
	// if they suddenly were -- it is derived from the same list.
	It("packages the non-FIPS variants only", func() {
		distDir := GinkgoT().TempDir()
		ver, err := releaseVersion()
		Expect(err).NotTo(HaveOccurred())

		src := GinkgoT().TempDir()
		for _, name := range []string{"openvox-ca", "openvox-ca-ctl"} {
			Expect(os.WriteFile(filepath.Join(src, name), []byte("#!/bin/true\n"), 0o755)).To(Succeed())
		}
		unit, err := renderUnit(tarballUnitBindir)
		Expect(err).NotTo(HaveOccurred())
		Expect(os.WriteFile(filepath.Join(src, distUnitFile), unit, 0o644)).To(Succeed())

		// Tarballs for EVERY variant, including the FIPS pair, so that
		// packaging them would succeed if the code tried.
		for _, v := range distVariants() {
			archive := filepath.Join(distDir, fmt.Sprintf("openvox-ca_%s_%s.tar.gz", ver, v.name))
			Expect(createTarGz(archive, src, distArchiveFiles([]string{"openvox-ca", "openvox-ca-ctl"}))).To(Succeed())
		}

		Expect(buildPackagesInto(distDir)).To(Succeed())

		debs, err := filepath.Glob(filepath.Join(distDir, "*.deb"))
		Expect(err).NotTo(HaveOccurred())
		Expect(debs).To(HaveLen(2), "four tarballs were available; only the two non-FIPS may be packaged")
	})
})
