//go:build mage

// Copyright (C) 2026 Trevor Vaughan
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
	"bufio"
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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"

	"github.com/caarlos0/env/v11"
	openbao "github.com/openbao/openbao/api/v2"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	daemon "github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// -- Namespaces ----------------------------------------------------------------

type Build mg.Namespace   // build:all  build:fips  build:dist  build:distVariant
type Test mg.Namespace    // test:unit  test:integcompose  test:integcomposefips  test:loadcompose  test:bench  test:puppet  test:puppetfips  test:migration  test:backendsRedis  test:backendsEtcd
type Dev mg.Namespace     // dev:check  dev:lint  dev:mixin  dev:tidy  dev:clean  dev:container
type Release mg.Namespace // release:prepare
type Chart mg.Namespace   // chart:version  chart:lint  chart:validate  chart:package

// -- Helpers ------------------------------------------------------------------─

func ensureBinDir() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return "", err
	}
	return binDir, nil
}

// systemInfo returns REPORT_* environment variables describing the host system
// so they can be passed to k6 containers and included in benchmark reports.
// Values are best-effort; any item that cannot be determined is omitted.
func systemInfo() map[string]string {
	info := map[string]string{}

	if h, err := os.Hostname(); err == nil {
		info["REPORT_HOST"] = h
	}
	info["REPORT_CPUS"] = strconv.Itoa(runtime.NumCPU())

	// Memory total: /proc/meminfo on Linux, sysctl on macOS/BSD.
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.SplitN(string(data), "\n", 50) {
			if strings.HasPrefix(line, "MemTotal:") {
				if fields := strings.Fields(line); len(fields) >= 2 {
					if kb, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
						info["REPORT_MEM_GB"] = fmt.Sprintf("%.1f", float64(kb)/1048576)
					}
				}
				break
			}
		}
	} else if out, err := exec.Command("sysctl", "-n", "hw.memsize").Output(); err == nil {
		if n, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64); err == nil {
			info["REPORT_MEM_GB"] = fmt.Sprintf("%.1f", float64(n)/1073741824)
		}
	}

	// Kernel/OS: uname -sr works on Linux, macOS, and BSDs.
	if out, err := exec.Command("uname", "-sr").Output(); err == nil {
		info["REPORT_KERNEL"] = strings.TrimSpace(string(out))
	}

	return info
}

// -- build:* ------------------------------------------------------------------─

// All compiles both binaries (openvox-ca and openvox-ca-ctl) to bin/.
func (Build) All() error {
	env := map[string]string{"CGO_ENABLED": "0"}

	fmt.Println("Building...")
	binDir, err := ensureBinDir()
	if err != nil {
		return err
	}

	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}

	if err := sh.RunWithV(env, "go", "build",
		"-o", filepath.Join(binDir, "openvox-ca"+ext),
		"./cmd/openvox-ca"); err != nil {
		return err
	}

	return sh.RunWithV(env, "go", "build",
		"-o", filepath.Join(binDir, "openvox-ca-ctl"+ext),
		"./cmd/openvox-ca-ctl")
}

// FIPS compiles openvox-ca with GOEXPERIMENT=boringcrypto for FIPS compliance
// (Linux/amd64 only). Output: bin/openvox-ca-fips.
func (Build) FIPS() error {
	fmt.Println("Building FIPS compliant binary...")

	targetOS := os.Getenv("GOOS")
	if targetOS == "windows" {
		fmt.Println("WARNING: FIPS mode (boringcrypto) is NOT supported on Windows.")
		fmt.Println("  The build will continue, but it will create a LINUX binary (GOOS=linux).")
	} else if targetOS == "" && runtime.GOOS == "windows" {
		fmt.Println("WARNING: You are building on Windows, but FIPS mode requires Linux.")
		fmt.Println("  Cross-compiling a LINUX binary (bin/openvox-ca-fips). This will not run on Windows.")
	}

	binDir, err := ensureBinDir()
	if err != nil {
		return err
	}

	env := map[string]string{
		"GOEXPERIMENT": "boringcrypto",
		"CGO_ENABLED":  "1",
		"GOOS":         "linux",
		"GOARCH":       "amd64",
	}

	if err := sh.RunWith(env, "go", "build",
		"-o", filepath.Join(binDir, "openvox-ca"),
		"./cmd/openvox-ca"); err != nil {
		return err
	}

	return sh.RunWith(env, "go", "build",
		"-o", filepath.Join(binDir, "openvox-ca-ctl"),
		"./cmd/openvox-ca-ctl")
}

// releaseVersion extracts the Version constant from internal/version, the
// single source of truth for the release version. Parsed from source rather
// than imported so that editing the constant never requires rebuilding the
// mage binary to be picked up.
func releaseVersion() (string, error) {
	src, err := os.ReadFile(filepath.Join("internal", "version", "version.go"))
	if err != nil {
		return "", err
	}
	m := regexp.MustCompile(`(?m)^const Version = "([^"]+)"$`).FindSubmatch(src)
	if m == nil {
		return "", fmt.Errorf("could not find the Version constant in internal/version/version.go")
	}
	return string(m[1]), nil
}

// fipsCrossCC returns the C compiler needed to link the boringcrypto syso for
// a FIPS build targeting goarch. Cross-linking from a different architecture
// needs the matching GNU cross toolchain (on Debian/Ubuntu: the
// gcc-aarch64-linux-gnu / gcc-x86-64-linux-gnu packages). Returns "" when the
// default compiler is fine (native Linux build) or when CC is already set in
// the environment (respected as an override).
func fipsCrossCC(goarch string) string {
	if os.Getenv("CC") != "" {
		return ""
	}
	if runtime.GOOS == "linux" && runtime.GOARCH == goarch {
		return ""
	}
	switch goarch {
	case "amd64":
		return "x86_64-linux-gnu-gcc"
	case "arm64":
		return "aarch64-linux-gnu-gcc"
	}
	return ""
}

// distVariantSpec describes one release artefact: its short name (the
// artefact-name suffix, e.g. "linux_arm64_fips") and the build environment
// that produces it.
type distVariantSpec struct {
	name string
	env  map[string]string
}

// distVariants returns the full set of release artefact variants. The FIPS
// variants are cgo builds, so they need a Linux host with a C toolchain for
// the target architecture (see fipsCrossCC); the pure-Go variants
// cross-compile from anywhere.
func distVariants() []distVariantSpec {
	fipsEnv := func(goarch string) map[string]string {
		env := map[string]string{"CGO_ENABLED": "1", "GOOS": "linux", "GOARCH": goarch, "GOEXPERIMENT": "boringcrypto"}
		if cc := fipsCrossCC(goarch); cc != "" {
			env["CC"] = cc
		}
		return env
	}
	return []distVariantSpec{
		{
			name: "linux_amd64",
			env:  map[string]string{"CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64"},
		},
		{
			name: "linux_arm64",
			env:  map[string]string{"CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "arm64"},
		},
		{
			name: "linux_amd64_fips",
			env:  fipsEnv("amd64"),
		},
		{
			name: "linux_arm64_fips",
			env:  fipsEnv("arm64"),
		},
	}
}

// buildDistVariant builds one variant's tarball into distDir and returns its
// SHA-256 checksum. The artefact is named openvox-ca_VER_NAME.tar.gz and
// contains both binaries.
func buildDistVariant(distDir, ver string, v distVariantSpec) (string, error) {
	bins := []string{"openvox-ca", "openvox-ca-ctl"}
	archive := filepath.Join(distDir, fmt.Sprintf("openvox-ca_%s_%s.tar.gz", ver, v.name))

	tmpDir, err := os.MkdirTemp("", "openvox-ca-dist-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmpDir)

	for _, cmd := range bins {
		// -trimpath keeps builder paths out of the binaries so artefacts are
		// reproducible across build machines.
		if err := sh.RunWith(v.env, "go", "build", "-trimpath",
			"-o", filepath.Join(tmpDir, cmd),
			"./cmd/"+cmd); err != nil {
			return "", fmt.Errorf("build %s for %s: %w", cmd, v.name, err)
		}
	}

	if err := createTarGz(archive, tmpDir, bins); err != nil {
		return "", fmt.Errorf("archive %s: %w", v.name, err)
	}
	return sha256File(archive)
}

// Dist cross-compiles release artifacts for all supported platforms and writes
// them to dist/. Each artifact is a .tar.gz containing openvox-ca and
// openvox-ca-ctl. A SHA-256 checksums.txt is also written to dist/.
//
// Artifacts produced (VERSION is the internal/version constant):
//
//	openvox-ca_VERSION_linux_amd64.tar.gz       (standard; CGO_ENABLED=0)
//	openvox-ca_VERSION_linux_arm64.tar.gz       (standard; CGO_ENABLED=0)
//	openvox-ca_VERSION_linux_amd64_fips.tar.gz  (FIPS; GOEXPERIMENT=boringcrypto)
//	openvox-ca_VERSION_linux_arm64_fips.tar.gz  (FIPS; GOEXPERIMENT=boringcrypto)
//
// CI and the Release workflow build one variant per (native) runner via
// build:distVariant instead; this target remains the way to build everything
// locally.
func (Build) Dist() error {
	distDir := "dist"
	if err := os.RemoveAll(distDir); err != nil {
		return err
	}
	if err := os.MkdirAll(distDir, 0755); err != nil {
		return err
	}

	ver, err := releaseVersion()
	if err != nil {
		return err
	}

	// The variants are independent, so build them concurrently; the Go build
	// and module caches are safe under concurrent use. Checksums are collected
	// per-index to keep checksums.txt in deterministic variant order, and
	// every variant runs to completion so a failure report covers all broken
	// variants, not just the first.
	variants := distVariants()
	var wg sync.WaitGroup
	sums := make([]string, len(variants))
	errs := make([]error, len(variants))
	for i, v := range variants {
		fmt.Printf("Building openvox-ca_%s_%s...\n", ver, v.name)
		wg.Add(1)
		go func(i int, v distVariantSpec) {
			defer wg.Done()
			sums[i], errs[i] = buildDistVariant(distDir, ver, v)
		}(i, v)
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return err
	}

	var checksums strings.Builder
	for i, v := range variants {
		fmt.Fprintf(&checksums, "%s  openvox-ca_%s_%s.tar.gz\n", sums[i], ver, v.name)
	}
	return os.WriteFile(
		filepath.Join(distDir, "checksums.txt"),
		[]byte(checksums.String()),
		0644,
	)
}

// DistVariant builds a single release artefact variant (by short name, e.g.
// "linux_arm64_fips") into dist/ without touching other artefacts, and prints
// its SHA-256 checksum. Used by CI and the Release workflow to build each
// variant on a native runner for its architecture; checksums.txt aggregation
// happens in the workflow, not here.
func (Build) DistVariant(name string) error {
	ver, err := releaseVersion()
	if err != nil {
		return err
	}

	for _, v := range distVariants() {
		if v.name != name {
			continue
		}
		if err := os.MkdirAll("dist", 0755); err != nil {
			return err
		}
		fmt.Printf("Building openvox-ca_%s_%s...\n", ver, v.name)
		sum, err := buildDistVariant("dist", ver, v)
		if err != nil {
			return err
		}
		fmt.Printf("%s  openvox-ca_%s_%s.tar.gz\n", sum, ver, v.name)
		return nil
	}

	var known []string
	for _, v := range distVariants() {
		known = append(known, v.name)
	}
	return fmt.Errorf("unknown dist variant %q (known: %s)", name, strings.Join(known, ", "))
}

// -- release:* -----------------------------------------------------------------

// bareSemverRe matches the versions release:prepare accepts: bare semver with
// an optional pre-release suffix (0.9.0, 0.9.0-rc1, 0.10.0-dev), never a "v"
// prefix.
var bareSemverRe = regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)

// repoSlug derives the "owner/repo" slug from a git remote URL, accepting the
// SSH (git@github.com:owner/repo.git) and HTTPS forms.
func repoSlug(remote string) (string, error) {
	url, err := sh.Output("git", "remote", "get-url", remote)
	if err != nil {
		return "", fmt.Errorf("resolving remote %q: %w", remote, err)
	}
	m := regexp.MustCompile(`[:/]([^/:]+/[^/:]+?)(\.git)?$`).FindStringSubmatch(strings.TrimSpace(url))
	if m == nil {
		return "", fmt.Errorf("could not derive owner/repo from remote URL %q", strings.TrimSpace(url))
	}
	return m[1], nil
}

// Prepare opens the version-bump pull request that must land before a release
// can be tagged: it creates a release/vVERSION branch off the remote's main,
// sets the internal/version constant and the Helm chart's version and
// appVersion to match, pushes the branch, and opens the PR
// with `gh` — including a preview of the auto-generated release notes for
// release versions (skipped for -dev bumps, which are the post-release step
// returning main to a development version).
//
// The remote defaults to origin; set OPENVOX_CA_RELEASE_REMOTE to prepare a
// release elsewhere (e.g. a fork rehearsal). Requires a clean working tree
// and an authenticated `gh`.
func (Release) Prepare(ver string) error {
	if !bareSemverRe.MatchString(ver) {
		return fmt.Errorf("version %q is not bare semver (expected e.g. 0.9.0, 0.9.0-rc1, or 0.10.0-dev, without a v prefix)", ver)
	}
	remote := os.Getenv("OPENVOX_CA_RELEASE_REMOTE")
	if remote == "" {
		remote = "origin"
	}
	slug, err := repoSlug(remote)
	if err != nil {
		return err
	}

	if out, err := sh.Output("git", "status", "--porcelain"); err != nil {
		return err
	} else if strings.TrimSpace(out) != "" {
		return fmt.Errorf("working tree is not clean; commit or stash first")
	}

	if err := sh.RunV("git", "fetch", remote); err != nil {
		return err
	}
	branch := "release/v" + ver
	if err := sh.RunV("git", "switch", "-c", branch, remote+"/main"); err != nil {
		return fmt.Errorf("creating %s from %s/main (does the branch already exist?): %w", branch, remote, err)
	}

	verFile := filepath.Join("internal", "version", "version.go")
	src, err := os.ReadFile(verFile)
	if err != nil {
		return err
	}
	re := regexp.MustCompile(`(?m)^const Version = "[^"]+"$`)
	if !re.Match(src) {
		return fmt.Errorf("could not find the Version constant in %s", verFile)
	}
	if err := os.WriteFile(verFile, re.ReplaceAll(src, fmt.Appendf(nil, "const Version = %q", ver)), 0644); err != nil {
		return err
	}

	// The Helm chart releases in lockstep, so its version and appVersion move
	// with the constant. chart:version (and the tag gates) refuse a mismatch.
	chartFile := filepath.Join(chartDir, "Chart.yaml")
	chartSrc, err := os.ReadFile(chartFile)
	if err != nil {
		return err
	}
	if !chartVersionRe.Match(chartSrc) {
		return fmt.Errorf("could not find the version field in %s", chartFile)
	}
	if !chartAppVersionRe.Match(chartSrc) {
		return fmt.Errorf("could not find the appVersion field in %s", chartFile)
	}
	chartSrc = chartVersionRe.ReplaceAll(chartSrc, fmt.Appendf(nil, "version: %s", ver))
	chartSrc = chartAppVersionRe.ReplaceAll(chartSrc, fmt.Appendf(nil, "appVersion: %q", ver))
	if err := os.WriteFile(chartFile, chartSrc, 0644); err != nil {
		return err
	}

	isDev := strings.HasSuffix(ver, "-dev")
	title := "Release v" + ver
	body := fmt.Sprintf(`Sets the release version to %s. Once this merges, cut the release by pushing the tag (see docs/development/releasing.md):

    git fetch %s
    git tag -a v%s %s/main -m "OpenVox CA %s"
    git push %s v%s
`, ver, remote, ver, remote, ver, remote, ver)
	if isDev {
		title = "Bump version to " + ver
		body = fmt.Sprintf("Post-release bump so builds from main identify as %s rather than as the release.\n", ver)
	}

	if err := sh.RunV("git", "add", verFile, chartFile); err != nil {
		return err
	}
	if err := sh.RunV("git", "commit", "-m", title); err != nil {
		return err
	}
	if err := sh.RunV("git", "push", "-u", remote, branch); err != nil {
		return err
	}

	if !isDev {
		// Preview what --generate-notes will produce so the release PR shows
		// reviewers the notes before the tag exists. Read-only and
		// best-effort: the release itself regenerates the real thing.
		notes, err := sh.Output("gh", "api", "repos/"+slug+"/releases/generate-notes",
			"-f", "tag_name=v"+ver, "-f", "target_commitish=main", "--jq", ".body")
		if err != nil {
			fmt.Println("WARNING: could not generate a release-notes preview:", err)
		} else if notes != "" {
			body += "\n<details><summary>Auto-generated release-notes preview</summary>\n\n" + notes + "\n\n</details>\n"
		}
	}

	return sh.RunV("gh", "pr", "create", "--repo", slug, "--base", "main",
		"--head", branch, "--title", title, "--body", body)
}

// -- chart:* -------------------------------------------------------------------

// chartDir is the Helm chart's source directory. The chart ships in lockstep
// with the binaries: both its version and its appVersion track the
// internal/version constant, and chart:version is the gate that says so.
const chartDir = "charts/openvox-ca"

// kubeconformVersion is the Kubernetes API version the rendered manifests are
// validated against. Bumping it is how the chart picks up newly-GA fields.
const kubeconformVersion = "1.31.0"

// kubeconformFloorVersion is the chart's declared kubeVersion floor
// (charts/openvox-ca/Chart.yaml). The minimal fixture — the chart's defaults —
// is validated against it as well, so the floor is a checked promise rather
// than a claim. Fixtures that opt into newer fields
// (unhealthyPodEvictionPolicy is 1.27+, trafficDistribution 1.31+) are only
// checked at kubeconformVersion; both values carry that note, as does the
// chart README's requirements section.
const kubeconformFloorVersion = "1.26.0"

// chartFloorFixture is the fixture that stands in for the chart's defaults and
// is therefore the one held to the floor. Named here rather than inline so
// that renaming it fails loudly instead of quietly skipping the check.
const chartFloorFixture = "minimal-values"

// crdSchemaLocation points kubeconform at community-maintained JSON schemas
// for the CRDs the chart can emit (ServiceMonitor, HTTPRoute, TLSRoute), which
// are absent from the core Kubernetes schema set.
//
// Pinned to a commit rather than a branch: this feeds a required check, and
// tracking someone else's main means an upstream reorganisation can turn CI
// red with no change of ours. It is a commit and not a tag because the
// catalogue's newest tag (v0.0.12) predates its Gateway API schemas, so a
// tagged pin cannot validate the routes the chart emits. Refresh it by hand
// when a CRD the chart uses gains a new version; Renovate has no datasource
// for a raw.githubusercontent path.
const crdSchemaCommit = "dcaa31aa03082906c0325a7a0ee7d5191e9cbe24"

const crdSchemaLocation = "https://raw.githubusercontent.com/datreeio/CRDs-catalog/" +
	crdSchemaCommit + "/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json"

var (
	chartVersionRe    = regexp.MustCompile(`(?m)^version: (.+)$`)
	chartAppVersionRe = regexp.MustCompile(`(?m)^appVersion: "(.+)"$`)
)

// chartVersions parses the version and appVersion fields out of Chart.yaml.
// Parsed textually, like releaseVersion, so that the check does not depend on
// a YAML library or on the chart being renderable.
func chartVersions() (version, appVersion string, err error) {
	path := filepath.Join(chartDir, "Chart.yaml")
	src, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}
	v := chartVersionRe.FindSubmatch(src)
	if v == nil {
		return "", "", fmt.Errorf("could not find the version field in %s", path)
	}
	a := chartAppVersionRe.FindSubmatch(src)
	if a == nil {
		return "", "", fmt.Errorf("could not find the appVersion field in %s", path)
	}
	return strings.TrimSpace(string(v[1])), strings.TrimSpace(string(a[1])), nil
}

// chartValuesFiles returns the fixture values files under the chart's ci/
// directory. Each is a distinct rendering of the chart that chart:lint and
// chart:validate exercise in full. Finding none is an error rather than a
// no-op: an empty fixture set would silently turn both targets into
// rubber stamps.
//
// Both YAML extensions are collected: globbing only *.yaml would skip a *.yml
// fixture in silence, which is that same rubber stamp one file at a time.
func chartValuesFiles() ([]string, error) {
	var files []string
	for _, ext := range []string{"*.yaml", "*.yml"} {
		matched, err := filepath.Glob(filepath.Join(chartDir, "ci", ext))
		if err != nil {
			return nil, err
		}
		files = append(files, matched...)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no fixture values files found under %s", filepath.Join(chartDir, "ci"))
	}
	sort.Strings(files)
	return files, nil
}

// requireChartTool resolves a tool the chart targets need, turning a missing
// binary into an actionable error rather than an exec failure deep in a
// pipeline.
func requireChartTool(name, install string) error {
	if _, err := exec.LookPath(name); err != nil {
		return fmt.Errorf("%s not found on PATH; install it with:\n    %s", name, install)
	}
	return nil
}

// Version verifies that the chart's version and appVersion both equal the
// internal/version constant, so the chart published for a release always
// carries that release's number and defaults to that release's image.
//
// The same check runs in CI, in the shared verify-release-tag gate, and in the
// pre-push hook.
func (Chart) Version() error {
	want, err := releaseVersion()
	if err != nil {
		return err
	}
	version, appVersion, err := chartVersions()
	if err != nil {
		return err
	}
	if version != want || appVersion != want {
		return fmt.Errorf("%s/Chart.yaml is out of step with internal/version (%s): version=%s appVersion=%s\n"+
			"Run 'mage release:prepare %s', or set both fields to %s by hand",
			chartDir, want, version, appVersion, want, want)
	}
	fmt.Printf("Chart version and appVersion match internal/version (%s)\n", want)
	return nil
}

// chartFixtureName is the label a fixture's rendering is filed under.
func chartFixtureName(path string) string {
	base := filepath.Base(path)
	return strings.TrimSuffix(strings.TrimSuffix(base, ".yaml"), ".yml")
}

// Lint runs `helm lint` over the chart once per fixture, so a fixture that
// trips the values schema or a precondition fails here rather than at install
// time.
//
// There is deliberately no bare-defaults run: the chart's preconditions reject
// an install with no TLS configuration, because the server would refuse to
// start. ci/minimal-values.yaml is the defaults plus that one required
// setting, and stands in for it.
func (Chart) Lint() error {
	if err := requireChartTool("helm", "https://helm.sh/docs/intro/install/"); err != nil {
		return err
	}
	values, err := chartValuesFiles()
	if err != nil {
		return err
	}

	for _, f := range values {
		fmt.Printf("Linting the chart with %s...\n", f)
		if err := sh.RunV("helm", "lint", "--strict", chartDir, "-f", f); err != nil {
			return err
		}
	}
	return nil
}

// Validate renders the chart with every fixture and checks the resulting
// manifests against the published Kubernetes and CRD JSON schemas. This is
// what catches a template emitting a field that does not exist, or emitting it
// at the wrong nesting level — neither of which `helm lint` sees, because to
// Helm the output is just YAML.
//
// Rendered manifests are kept in .test-output/chart/ for inspection.
func (Chart) Validate() error {
	mg.Deps(Chart.Lint)

	if err := requireChartTool("kubeconform",
		"go install github.com/yannh/kubeconform/cmd/kubeconform@v0.7.0"); err != nil {
		return err
	}
	values, err := chartValuesFiles()
	if err != nil {
		return err
	}

	outDir := filepath.Join(".test-output", "chart")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}

	floorChecked := false
	for _, f := range values {
		name := chartFixtureName(f)

		fmt.Printf("Rendering the chart with %s values...\n", name)
		manifest, err := sh.Output("helm", "template", "openvox-ca", chartDir, "-f", f)
		if err != nil {
			return err
		}
		path := filepath.Join(outDir, name+".yaml")
		if err := os.WriteFile(path, []byte(manifest+"\n"), 0644); err != nil {
			return err
		}

		// The minimal fixture is the chart's defaults, so it must also hold at
		// the kubeVersion floor Chart.yaml advertises. The others opt into
		// fields newer than that on purpose.
		targets := []string{kubeconformVersion}
		if name == chartFloorFixture {
			targets = append(targets, kubeconformFloorVersion)
			floorChecked = true
		}
		for _, kubeVersion := range targets {
			fmt.Printf("Validating %s against Kubernetes %s schemas...\n", path, kubeVersion)
			if err := sh.RunV("kubeconform",
				"-strict",
				"-summary",
				"-kubernetes-version", kubeVersion,
				"-schema-location", "default",
				"-schema-location", crdSchemaLocation,
				path,
			); err != nil {
				return err
			}
		}
	}
	if !floorChecked {
		return fmt.Errorf("no %s.yaml fixture found, so nothing was validated against the "+
			"kubeVersion floor (%s) that %s/Chart.yaml advertises; renaming that fixture "+
			"silently drops the check",
			chartFloorFixture, kubeconformFloorVersion, chartDir)
	}
	return nil
}

// chartConfigChecksum renders the chart and returns the checksum/config value
// it produced, so a case can assert that a *different* input yields a
// different checksum rather than that the annotation merely exists.
func chartConfigChecksum(sets ...string) string {
	out, err := helmTemplate(sets)
	if err != nil {
		return "<render failed>"
	}
	m := regexp.MustCompile(`checksum/config: ([0-9a-f]{64})`).FindStringSubmatch(out)
	if m == nil {
		return "<no checksum rendered>"
	}
	return m[1]
}

// chartRenderCase is one assertion over a rendering of the chart: render with
// these --set overrides, then require each `wants` string to appear in the
// output and each `notWants` string to be absent.
type chartRenderCase struct {
	name string
	sets []string
	// notes renders the post-install notes as well as the manifests. `helm
	// template` never evaluates NOTES.txt, and `helm install --dry-run`
	// reaches for a cluster on Helm 3, so this renders the openvox-ca.notes
	// template through a probe manifest instead — offline, on both majors.
	notes    bool
	wants    []string
	notWants []string
}

// chartRejectCase is one assertion that the chart refuses a configuration:
// render with these overrides and require the failure to mention `wantErr`.
type chartRejectCase struct {
	name string
	sets []string
	// valuesYAML supplies values a --set cannot express; helm's --set parser
	// swallows backslash escapes, so a value containing a real newline has to
	// come from a file.
	valuesYAML string
	wantErr    string
}

// renderWithAppVersion renders a throwaway copy of the chart whose appVersion
// has been rewritten, so the -dev-to-edge rule can be asserted on both of its
// branches whichever side of a release this tree happens to be on. Helm offers
// no way to override .Chart.AppVersion from the command line, and asserting
// only the current version's branch is what left a release-time landmine here
// the first time round.
func renderWithAppVersion(appVersion string, sets []string) (string, error) {
	tmp, err := os.MkdirTemp("", "openvox-ca-chart")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)

	dst := filepath.Join(tmp, "openvox-ca")
	if err := sh.Run("cp", "-R", chartDir, dst); err != nil {
		return "", err
	}
	chartFile := filepath.Join(dst, "Chart.yaml")
	src, err := os.ReadFile(chartFile)
	if err != nil {
		return "", err
	}
	patched := chartAppVersionRe.ReplaceAll(src, fmt.Appendf(nil, "appVersion: %q", appVersion))
	if err := os.WriteFile(chartFile, patched, 0644); err != nil {
		return "", err
	}

	args := []string{"template", "openvox-ca", dst}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	var out bytes.Buffer
	_, err = sh.Exec(nil, &out, &out, "helm", args...)
	return out.String(), err
}

// helmTemplate renders the chart with --set overrides, returning stdout and
// stderr combined. Both are needed: the rendered manifests arrive on stdout,
// but a `fail` from a precondition — the thing the reject cases assert on —
// only ever appears on stderr.
func helmTemplate(sets []string) (string, error) {
	return helmRender(false, sets, "")
}

// notesProbeTemplate renders the openvox-ca.notes template into a manifest, so
// that `helm template` — which ignores NOTES.txt — surfaces it.
const notesProbeTemplate = `apiVersion: v1
kind: ConfigMap
metadata:
  name: notes-probe
data:
  notes: |
{{ include "openvox-ca.notes" . | indent 4 }}
`

// helmRender renders the chart, optionally including the post-install notes,
// and optionally with an extra values file.
func helmRender(notes bool, sets []string, valuesYAML string) (string, error) {
	dir := chartDir
	if notes {
		tmp, err := os.MkdirTemp("", "openvox-ca-notes")
		if err != nil {
			return "", err
		}
		defer os.RemoveAll(tmp)
		dir = filepath.Join(tmp, "openvox-ca")
		if err := sh.Run("cp", "-R", chartDir, dir); err != nil {
			return "", err
		}
		probe := filepath.Join(dir, "templates", "zz-notes-probe.yaml")
		if err := os.WriteFile(probe, []byte(notesProbeTemplate), 0644); err != nil {
			return "", err
		}
	}

	args := []string{"template", "openvox-ca", dir}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	if valuesYAML != "" {
		f, err := os.CreateTemp("", "openvox-ca-values-*.yaml")
		if err != nil {
			return "", err
		}
		defer os.Remove(f.Name())
		if _, err := f.WriteString(valuesYAML); err != nil {
			f.Close()
			return "", err
		}
		if err := f.Close(); err != nil {
			return "", err
		}
		args = append(args, "-f", f.Name())
	}
	var out bytes.Buffer
	_, err := sh.Exec(nil, &out, &out, "helm", args...)
	return out.String(), err
}

// Test asserts what the chart actually renders, which neither `helm lint` nor
// kubeconform can: both are satisfied by valid YAML carrying the wrong values.
// These cases cover the logic a reader has to trust — image-tag resolution,
// config merge precedence, probe scheme selection, which kind rbac.scope
// picks — and the preconditions, which are only worth having if they really
// fire.
func (Chart) Test() error {
	if err := requireChartTool("helm", "https://helm.sh/docs/intro/install/"); err != nil {
		return err
	}

	// Every case starts from a renderable baseline: without TLS the chart
	// refuses outright, which is itself asserted in the reject cases below.
	tls := "tls.existingSecret=openvox-ca-tls"

	// Derive the expected default tag from the chart's own appVersion rather
	// than hard-coding today's. A literal here would assert the constant
	// instead of the rule, and would fail on the very commit release:prepare
	// produces — taking CI red and blocking the tag it was preparing.
	_, appVersion, err := chartVersions()
	if err != nil {
		return err
	}
	defaultTag := appVersion
	if strings.HasSuffix(appVersion, "-dev") {
		defaultTag = "edge"
	}
	defaultTag += "-alpine"

	renders := []chartRenderCase{
		{
			name:  "an unset tag resolves to the Alpine variant of the appVersion",
			sets:  []string{tls, "image.tag=", "image.digest="},
			wants: []string{"image: ghcr.io/voxpupuli/openvox-ca:" + defaultTag},
		},
		{
			name: "an explicit tag is used verbatim, selecting the CentOS variant",
			sets: []string{tls, "image.tag=0.9.0"},
			// The whole point of the rule: no suffix is appended.
			wants:    []string{"image: ghcr.io/voxpupuli/openvox-ca:0.9.0"},
			notWants: []string{"0.9.0-alpine"},
		},
		{
			name:     "a digest wins over a tag",
			sets:     []string{tls, "image.tag=0.9.0", "image.digest=sha256:" + strings.Repeat("a", 64)},
			wants:    []string{"image: ghcr.io/voxpupuli/openvox-ca@sha256:" + strings.Repeat("a", 64)},
			notWants: []string{":0.9.0"},
		},
		{
			name:  "config overrides what the tls block computes",
			sets:  []string{tls, "config.tls_cert=/custom/cert.pem", "config.tls_key=/custom/key.pem"},
			wants: []string{"tls_cert: /custom/cert.pem", "tls_key: /custom/key.pem"},
			// The secret is still mounted; only the paths move.
			notWants: []string{"tls_cert: /run/secrets/openvox-ca-tls/tls.crt"},
		},
		{
			name:     "config.verbosity beats the verbosity value, and no flag outranks either",
			sets:     []string{tls, "verbosity=1", "config.verbosity=2"},
			wants:    []string{"verbosity: 2"},
			notWants: []string{"--verbosity"},
		},
		{
			name:  "probes follow the server: HTTPS when a certificate is configured",
			sets:  []string{tls},
			wants: []string{"scheme: HTTPS"},
		},
		{
			name:     "probes follow the server: HTTP behind a terminating proxy",
			sets:     []string{"config.no_tls_required=true"},
			wants:    []string{"scheme: HTTP\n"},
			notWants: []string{"scheme: HTTPS"},
		},
		{
			name:     "rbac.scope selects the namespaced kinds by default",
			sets:     []string{tls, "kubernetesExport.enabled=true", "kubernetesExport.targets[0].kind=Secret", "kubernetesExport.targets[0].metadata.name=t", "kubernetesExport.targets[0].cert=true"},
			wants:    []string{"kind: Role\n", "kind: RoleBinding\n", "automountServiceAccountToken: true"},
			notWants: []string{"kind: ClusterRole"},
		},
		{
			name:     "rbac.scope: ClusterRole selects the cluster-scoped kinds",
			sets:     []string{tls, "kubernetesExport.enabled=true", "kubernetesExport.rbac.scope=ClusterRole", "kubernetesExport.targets[0].kind=Secret", "kubernetesExport.targets[0].metadata.name=t", "kubernetesExport.targets[0].cert=true"},
			wants:    []string{"kind: ClusterRole\n", "kind: ClusterRoleBinding\n"},
			notWants: []string{"kind: Role\n", "kind: RoleBinding\n"},
		},
		{
			name:     "the ServiceAccount token stays unmounted when nothing needs the API",
			sets:     []string{tls},
			wants:    []string{"automountServiceAccountToken: false"},
			notWants: []string{"automountServiceAccountToken: true"},
		},
		{
			name:  "OpenBao Kubernetes auth mounts the token too",
			sets:  []string{tls, "config.ca_key_provider=openbao", "config.openbao.auth_method=kubernetes"},
			wants: []string{"automountServiceAccountToken: true"},
		},
		{
			name: "a config change rolls the pods",
			// Asserting the annotation exists would pass on a constant, which
			// would roll nothing. Assert instead that a different config does
			// not produce the checksum this one does.
			sets:     []string{tls},
			wants:    []string{"checksum/config: "},
			notWants: []string{chartConfigChecksum(tls, "config.crl_validity_days=7")},
		},
		{
			name:     "an externally managed ConfigMap cannot be checksummed",
			sets:     []string{tls, "existingConfigMap=mine"},
			wants:    []string{"name: mine"},
			notWants: []string{"checksum/config:"},
		},
		{
			name:  "maxUnavailable: 0 survives the falsy-zero trap",
			sets:  []string{tls, "podDisruptionBudget.enabled=true", "podDisruptionBudget.maxUnavailable=0"},
			wants: []string{"maxUnavailable: 0"},
			// minAvailable is the fallback that a plain `if` would have taken.
			notWants: []string{"minAvailable:"},
		},
		{
			name:     "clearing both emptyDir fields still yields a valid volume source",
			sets:     []string{tls, "persistence.enabled=false", "emptyDir.medium=", "emptyDir.sizeLimit="},
			wants:    []string{"emptyDir: {}"},
			notWants: []string{"emptyDir:\n        - name"},
		},
		{
			name:  "a deny-all network policy renders an empty list, not a null",
			sets:  []string{tls, "networkPolicy.enabled=true", "networkPolicy.apiAccess=none"},
			wants: []string{"ingress: []"},
		},
		{
			name:  "export patch is held to the configured target names",
			sets:  []string{tls, "kubernetesExport.enabled=true", "kubernetesExport.targets[0].kind=Secret", "kubernetesExport.targets[0].metadata.name=trust-bundle", "kubernetesExport.targets[0].cert=true"},
			wants: []string{"resourceNames:\n      - trust-bundle"},
		},
		{
			name: "export with no targets grants no patch at all",
			// An empty resourceNames list is not a restriction — RBAC reads an
			// absent list as every resource — so the rule has to be omitted.
			sets:     []string{tls, "kubernetesExport.enabled=true"},
			wants:    []string{`verbs: ["create"]`},
			notWants: []string{`verbs: ["patch"]`},
		},
		{
			name: "export config the chart cannot read grants patch unrestricted",
			sets: []string{"existingConfigMap=mine", "kubernetesExport.enabled=true"},
			// Unrestricted, because the chart cannot know the target names —
			// but emitted as its own rule rather than an empty resourceNames
			// list, which RBAC would read as "every resource" anyway.
			wants:    []string{`verbs: ["patch"]`},
			notWants: []string{"resourceNames:\n"},
		},
		{
			name: "a falsy config value still overrides what the chart computed",
			// mergeOverwrite consults isEmptyValue on the destination only, so
			// false does win — asserted rather than assumed.
			sets:     []string{tls, "caKeyPassphrase.existingSecret=pw", "config.encrypt_ca_key=false"},
			wants:    []string{"encrypt_ca_key: false"},
			notWants: []string{"encrypt_ca_key: true"},
		},
		{
			name:     "retain: false drops the resource policy without leaving an empty annotations key",
			sets:     []string{tls, "persistence.enabled=true", "persistence.retain=false"},
			wants:    []string{"kind: PersistentVolumeClaim"},
			notWants: []string{"helm.sh/resource-policy", "annotations:\nspec:"},
		},
		{
			name:  "NOTES warns when nothing is granted admin access",
			notes: true,
			sets:  []string{tls},
			wants: []string{"no puppetServers are listed"},
		},
		{
			name:  "NOTES warns about a shared filesystem CA under autoscaling",
			notes: true,
			// The replica warning has to read the autoscaling floor, not just
			// replicaCount.
			sets:  []string{tls, "autoscaling.enabled=true", "autoscaling.minReplicas=3"},
			wants: []string{"autoscaling starts at 3 replicas", "not safe to share between replicas"},
		},
		{
			name:     "NOTES does not warn about autosign when patterns override the mode",
			notes:    true,
			sets:     []string{tls, "autosign.mode=true", "autosign.patterns[0]=*.example.com"},
			notWants: []string{"signed without review"},
		},
		{
			name:  "topology constraints default to this release's own pods",
			sets:  []string{tls},
			wants: []string{"app.kubernetes.io/name: openvox-ca\n          maxSkew: 1"},
		},
	}

	renders = append(renders,
		chartRenderCase{
			name: "self-provisioning counts as TLS, so probes render HTTPS",
			sets: []string{"config.tls_self_provision=true", "config.hostname=ca.example.com"},
			// No tls.existingSecret: this is the whole point — the chart must
			// not demand the other route.
			wants: []string{"scheme: HTTPS"},
		},
		chartRenderCase{
			name: "self-provisioning set by environment variable also counts as TLS",
			// Missing this is how a correct install renders HTTP probes against
			// an HTTPS listener and then fails its own validation.
			sets:  []string{"config.hostname=ca.example.com", "env.PUPPET_CA_TLS_SELF_PROVISION=true"},
			wants: []string{"scheme: HTTPS"},
		},
		chartRenderCase{
			name: "a hostname supplied through extraEnv satisfies the precondition",
			// The extraEnv arm of effectiveConfig, which no case reached:
			// deleting it left all 50 assertions passing while the chart
			// refused an install the server accepts.
			sets: []string{
				"config.tls_self_provision=true",
				"extraEnv[0].name=PUPPET_CA_HOSTNAME", "extraEnv[0].value=ca.example.com",
			},
			wants: []string{"scheme: HTTPS"},
		},
		chartRenderCase{
			name: "an empty extraEnv value does not count as set",
			// The extraEnv arms had no empty-value guard, so value: "" counted
			// as configured and tripped the mutual-exclusion precondition on an
			// install the server accepts.
			sets: []string{
				"config.tls_self_provision=true", "config.hostname=ca.example.com",
				"extraEnv[0].name=PUPPET_CA_TLS_CERT", "extraEnv[0].value=",
			},
			wants: []string{"scheme: HTTPS"},
		},
		chartRenderCase{
			name: "a hostname supplied through envFrom is not second-guessed",
			// envFrom is a route the chart cannot read by design. The two new
			// preconditions consulted neither configFullyKnown nor it, so they
			// refused an install that would have run.
			sets: []string{
				"config.tls_self_provision=true",
				"envFrom[0].configMapRef.name=ca-settings",
			},
			wants: []string{"scheme: HTTPS"},
		},
		chartRenderCase{
			name: "an empty environment override does not mask the config value",
			// applyServerEnv skips empty values; the chart used to overwrite
			// with them, so it failed the install on a hostname the server
			// keeps from the config file.
			sets: []string{
				"config.tls_self_provision=true", "config.hostname=ca.example.com",
				"env.PUPPET_CA_HOSTNAME=",
			},
			wants: []string{"scheme: HTTPS"},
		},
		chartRenderCase{
			name: "a hostname supplied by environment variable satisfies the precondition",
			// The other direction of the same bug: the precondition read only
			// the config file, so it refused an install the server accepts --
			// PUPPET_CA_HOSTNAME is a supported override, and with extraEnv
			// (valueFrom) there is no workaround but duplicating the value.
			sets:  []string{"config.tls_self_provision=true", "env.PUPPET_CA_HOSTNAME=ca.example.com"},
			wants: []string{"scheme: HTTPS"},
		},
		chartRenderCase{
			name:  "the startup budget covers two lock timeouts",
			sets:  []string{tls},
			wants: []string{"failureThreshold: 90"},
		},
		chartRenderCase{
			name: "self-provisioning set through extraEnv also counts as TLS",
			// extraEnv is a list of full EnvVar objects, scanned separately from
			// the .Values.env map. Only the map was exercised, so a helper that
			// ignored the list entirely would have rendered HTTP probes against
			// an HTTPS listener with the suite green.
			sets: []string{
				"config.hostname=ca.example.com",
				"extraEnv[0].name=PUPPET_CA_TLS_SELF_PROVISION",
				"extraEnv[0].value=true",
			},
			wants: []string{"scheme: HTTPS"},
		},
		chartRenderCase{
			name: "an explicit false is off, not merely present",
			// The string-parsing arm. Treating any value as enabled would make
			// PUPPET_CA_TLS_SELF_PROVISION=false render as self-provisioning,
			// which then demands no certificate and fails at startup.
			sets: []string{
				tls,
				"env.PUPPET_CA_TLS_SELF_PROVISION=false",
			},
			wants: []string{"secretName: openvox-ca-tls"},
		},
	)

	rejects := []chartRejectCase{
		{
			name:    "no TLS on a non-loopback address, which the server refuses to serve",
			sets:    []string{},
			wantErr: "refuse to start",
		},
		{
			name:    "a ServiceMonitor for an exporter that is switched off",
			sets:    []string{tls, "metrics.serviceMonitor.enabled=true"},
			wantErr: "nothing to scrape",
		},
		{
			name:    "an ingress routed to a metrics port that was never created",
			sets:    []string{tls, "ingress.enabled=true", "ingress.backendPort=metrics"},
			wantErr: "no metrics port",
		},
		{
			name:    "a TLSRoute routed to a metrics port that was never created",
			sets:    []string{tls, "gateway.tlsRoute.enabled=true", "gateway.tlsRoute.backendPort=metrics"},
			wantErr: "no metrics port",
		},
		{
			name:    "an HTTPRoute routed to a metrics port that was never created",
			sets:    []string{tls, "gateway.httpRoute.enabled=true", "gateway.httpRoute.backendPort=metrics"},
			wantErr: "no metrics port",
		},
		{
			name:       "an allow-list entry carrying a newline, which would inject a ConfigMap key",
			sets:       []string{tls},
			valuesYAML: "puppetServers:\n  - \"ca.example.com\\ninjected: value\"\n",
			wantErr:    "single non-empty line",
		},
		{
			name:       "an autosign pattern carrying a newline",
			sets:       []string{tls},
			valuesYAML: "autosign:\n  patterns:\n    - \"*.a.example.com\\n*.b.example.com\"\n",
			wantErr:    "single non-empty line",
		},
		{
			name:    "an autoscaler with no metric to act on",
			sets:    []string{tls, "autoscaling.enabled=true", "autoscaling.targetCPUUtilizationPercentage="},
			wantErr: "no metric is configured",
		},
		{
			name:    "export RBAC bound to the namespace's default ServiceAccount",
			sets:    []string{tls, "kubernetesExport.enabled=true", "serviceAccount.create=false"},
			wantErr: "default ServiceAccount",
		},
		{
			name:    "self-provisioning with no hostname to put in the certificate",
			sets:    []string{"config.tls_self_provision=true"},
			wantErr: "requires a hostname",
		},
		{
			name: "self-provisioning alongside a certificate path set by environment variable",
			// The env route is supported and the chart's own tlsConfigured
			// helper reads it, so a precondition that consults only the config
			// file lets through an install the server refuses at startup --
			// a crash-loop instead of the install-time failure this exists for.
			sets: []string{
				"config.tls_self_provision=true", "config.hostname=ca.example.com",
				"env.PUPPET_CA_TLS_CERT=/tls/tls.crt", "env.PUPPET_CA_TLS_KEY=/tls/tls.key",
			},
			wantErr: "cannot be combined",
		},
		{
			name: "an environment value the chart cannot read as a boolean",
			// The server parses this with strconv.ParseBool and keeps the
			// config-file value when it fails; the chart used to overwrite it
			// and read anything unrecognised as off, so the two would render and
			// run different configurations.
			sets: []string{
				"config.tls_self_provision=true", "config.hostname=ca.example.com",
				"env.PUPPET_CA_TLS_SELF_PROVISION=yes",
			},
			wantErr: "cannot read as a boolean",
		},
		{
			name:    "self-provisioning alongside the Secret that supplies a certificate",
			sets:    []string{tls, "config.tls_self_provision=true", "config.hostname=ca.example.com"},
			wantErr: "cannot be combined",
		},
		{
			name:    "self-provisioning alongside a certificate path",
			sets:    []string{"config.tls_self_provision=true", "config.hostname=ca.example.com", "config.tls_cert=/tls/tls.crt"},
			wantErr: "cannot be combined",
		},
		{
			name: "self-provisioning set by valueFrom, which the chart cannot read",
			// The chart decides here whether to mount tls.existingSecret and how
			// to shape the probes. A value it cannot see at render time would
			// silently produce the wrong manifests, so it refuses rather than
			// guessing — previously it read an absent .value as "off" and the
			// install failed with no clue why.
			sets: []string{
				"config.hostname=ca.example.com",
				"extraEnv[0].name=PUPPET_CA_TLS_SELF_PROVISION",
				"extraEnv[0].valueFrom.secretKeyRef.name=flags",
				"extraEnv[0].valueFrom.secretKeyRef.key=self-provision",
			},
			wantErr: "cannot read at render time",
		},
		{
			name: "self-provisioning alongside a certificate path set through extraEnv",
			// The arm effectiveConfig was written for and the one no case
			// reached: ci/self-provision-values.yaml already uses this
			// valueFrom shape for the SQL DSN, so it is the idiomatic route.
			sets: []string{
				"config.tls_self_provision=true", "config.hostname=ca.example.com",
				"extraEnv[0].name=PUPPET_CA_TLS_CERT",
				"extraEnv[0].valueFrom.secretKeyRef.name=tls",
				"extraEnv[0].valueFrom.secretKeyRef.key=crt",
			},
			wantErr: "cannot be combined",
		},
		{
			name: "self-provisioning alongside a key path alone",
			// The other half of the mutual-exclusion or: every existing case set
			// both, so $mxCert satisfied it and $mxKey was never exercised. The
			// server refuses on either.
			sets: []string{
				"config.tls_self_provision=true", "config.hostname=ca.example.com",
				"env.PUPPET_CA_TLS_KEY=/tls/tls.key",
			},
			wantErr: "cannot be combined",
		},
		{
			name: "an environment boolean the chart skips but the server honours",
			// The regression the empty-value guard introduced: Go template
			// truthiness skips boolean false and integer 0 as well as "", so an
			// unquoted false was ignored by the chart and acted on by the
			// server -- HTTPS probes rendered against a listener that never
			// came up.
			sets: []string{
				"config.tls_self_provision=true", "config.hostname=ca.example.com",
				"env.PUPPET_CA_TLS_SELF_PROVISION=false",
			},
			wantErr: "no server TLS certificate is configured",
		},
		{
			name:    "a mistyped value the schema should catch",
			sets:    []string{tls, "metric.enabled=true"},
			wantErr: "additional properties",
		},
	}

	failures := 0

	// The -dev-to-edge rule, on both of its branches. Rendered from a copy of
	// the chart with a substituted appVersion, so this asserts the rule rather
	// than whichever side of a release this tree currently sits on.
	for _, tc := range []struct{ appVersion, wantTag string }{
		{"9.9.9-dev", "edge-alpine"},
		{"9.9.9", "9.9.9-alpine"},
		{"9.9.9-rc1", "9.9.9-rc1-alpine"},
	} {
		name := fmt.Sprintf("appVersion %s resolves to %s", tc.appVersion, tc.wantTag)
		out, err := renderWithAppVersion(tc.appVersion, []string{tls})
		want := "image: ghcr.io/voxpupuli/openvox-ca:" + tc.wantTag
		switch {
		case err != nil:
			fmt.Printf("FAIL  %s\n      render failed: %v\n", name, err)
			failures++
		case !strings.Contains(out, want):
			fmt.Printf("FAIL  %s\n      expected to find: %q\n", name, want)
			failures++
		default:
			fmt.Printf("ok    %s\n", name)
		}
	}

	for _, tc := range renders {
		out, err := helmRender(tc.notes, tc.sets, "")
		if err != nil {
			fmt.Printf("FAIL  %s\n      render failed: %v\n", tc.name, err)
			failures++
			continue
		}
		ok := true
		for _, want := range tc.wants {
			if !strings.Contains(out, want) {
				fmt.Printf("FAIL  %s\n      expected to find: %q\n", tc.name, want)
				ok = false
			}
		}
		for _, notWant := range tc.notWants {
			if strings.Contains(out, notWant) {
				fmt.Printf("FAIL  %s\n      expected NOT to find: %q\n", tc.name, notWant)
				ok = false
			}
		}
		if ok {
			fmt.Printf("ok    %s\n", tc.name)
		} else {
			failures++
		}
	}

	for _, tc := range rejects {
		out, err := helmRender(false, tc.sets, tc.valuesYAML)
		switch {
		case err == nil:
			fmt.Printf("FAIL  rejects %s\n      rendered successfully instead of failing\n", tc.name)
			failures++
		case !strings.Contains(err.Error()+out, tc.wantErr):
			fmt.Printf("FAIL  rejects %s\n      failed, but not with %q: %v\n", tc.name, tc.wantErr, err)
			failures++
		default:
			fmt.Printf("ok    rejects %s\n", tc.name)
		}
	}

	if failures > 0 {
		return fmt.Errorf("%d chart assertion(s) failed", failures)
	}
	fmt.Printf("\nAll %d chart assertions passed\n", len(renders)+len(rejects)+3)
	return nil
}

// Package writes the packaged chart tarball to dist/, named for the
// internal/version constant. The publish workflow packages the chart the same
// way before pushing it to the OCI registry, so this is the local dry run.
func (Chart) Package() error {
	mg.Deps(Chart.Version)

	if err := requireChartTool("helm", "https://helm.sh/docs/intro/install/"); err != nil {
		return err
	}
	if err := os.MkdirAll("dist", 0755); err != nil {
		return err
	}
	if err := sh.RunV("helm", "package", chartDir, "--destination", "dist"); err != nil {
		return err
	}

	ver, err := releaseVersion()
	if err != nil {
		return err
	}
	tarball := filepath.Join("dist", fmt.Sprintf("openvox-ca-%s.tgz", ver))
	if _, err := os.Stat(tarball); err != nil {
		return fmt.Errorf("expected chart package %s was not produced: %w", tarball, err)
	}
	fmt.Println("Wrote", tarball)
	return nil
}

// -- test:* --------------------------------------------------------------------

// unitTestExcludes lists packages omitted from the unit-test run. Keep this set
// as small as possible: every entry is a package that runs NO coverage in CI.
//
//	internal/testutil — test helpers only, exercised transitively by the
//	                     packages that import them.
var unitTestExcludes = map[string]bool{
	"github.com/voxpupuli/openvox-ca/internal/testutil": true,
}

// unitTestPackages discovers the packages to unit-test via `go list ./...`
// rather than a hand-maintained list, then drops the explicit excludes above.
// A hand-maintained list silently drops any newly added package from CI (this
// is how internal/signer's tests went unrun); discovery makes the default
// "covered" so a new package has to be deliberately excluded to escape the gate.
func unitTestPackages() ([]string, error) {
	out, err := exec.Command("go", "list", "./...").Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("listing packages: %w: %s", err, ee.Stderr)
		}
		return nil, fmt.Errorf("listing packages: %w", err)
	}

	var pkgs []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		pkg := strings.TrimSpace(line)
		if pkg == "" || unitTestExcludes[pkg] {
			continue
		}
		pkgs = append(pkgs, pkg)
	}
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("go list ./... returned no testable packages")
	}
	return pkgs, nil
}

// Unit runs the unit test suite with coverage, piping output through tparse
// for a colorful per-package summary table. The package set is discovered
// dynamically (see unitTestPackages); only unitTestExcludes is omitted.
func (Test) Unit() error {
	fmt.Println("Running unit tests...")

	pkgs, err := unitTestPackages()
	if err != nil {
		return err
	}

	testArgs := append([]string{"test", "-json", "-cover", "-coverprofile=coverage.out"}, pkgs...)
	testCmd := exec.Command("go", testArgs...)
	tparseCmd := exec.Command("go", "tool", "tparse", "-all")

	pipe, err := testCmd.StdoutPipe()
	if err != nil {
		return err
	}
	testCmd.Stderr = os.Stderr
	tparseCmd.Stdin = pipe
	tparseCmd.Stdout = os.Stdout
	tparseCmd.Stderr = os.Stderr

	if err := testCmd.Start(); err != nil {
		return err
	}
	if err := tparseCmd.Start(); err != nil {
		testCmd.Wait() //nolint:errcheck
		return err
	}

	testErr := testCmd.Wait()
	tparseErr := tparseCmd.Wait()

	if testErr != nil {
		return testErr
	}
	return tparseErr
}

// IntegCompose builds the binaries locally then runs the multi-host compose
// integration test suite, tearing down on exit.
func (Test) IntegCompose() error {
	mg.Deps(Build{}.All)
	fmt.Println("Building compose images...")
	if err := runCompose(nil, "-f", "compose.yml", "build"); err != nil {
		return err
	}

	fmt.Println("Running compose integration tests...")
	err := runCompose(nil, "-f", "compose.yml", "up",
		"--exit-code-from", "test-runner",
		"--abort-on-container-exit")

	fmt.Println("Tearing down compose stack...")
	_ = runCompose(nil, "-f", "compose.yml", "down", "--volumes")

	return err
}

// IntegComposeFIPS is like IntegCompose but compiles with
// GOEXPERIMENT=boringcrypto so the compose integration suite runs against the
// FIPS-compliant binary.
func (Test) IntegComposeFIPS() error {
	mg.Deps(Build{}.FIPS)
	fmt.Println("Building compose images (FIPS build)...")
	if err := runCompose(nil, "-f", "compose.yml", "build"); err != nil {
		return err
	}

	fmt.Println("Running compose integration tests (FIPS build)...")
	err := runCompose(nil, "-f", "compose.yml", "up",
		"--exit-code-from", "test-runner",
		"--abort-on-container-exit")

	fmt.Println("Tearing down compose stack...")
	_ = runCompose(nil, "-f", "compose.yml", "down", "--volumes")

	return err
}

// LoadCompose is like IntegCompose but also enables the concurrency / load
// tests (DO_LOAD=true).
func (Test) LoadCompose() error {
	mg.Deps(Build{}.All)
	extra := map[string]string{"DO_LOAD": "true"}

	fmt.Println("Building compose images...")
	if err := runCompose(extra, "-f", "compose.yml", "build"); err != nil {
		return err
	}

	fmt.Println("Running compose integration + load tests...")
	err := runCompose(extra, "-f", "compose.yml", "up",
		"--exit-code-from", "test-runner",
		"--abort-on-container-exit")

	fmt.Println("Tearing down compose stack...")
	_ = runCompose(extra, "-f", "compose.yml", "down", "--volumes")

	return err
}

// Bench builds the binaries locally then runs the k6 load test suite
// (correctness, throughput, saturation ramp) against a dedicated compose stack
// (compose-bench.yml). Requires podman-compose and network access to pull
// grafana/k6:latest on first run.
func (Test) Bench() error {
	mg.Deps(Build{}.All)
	sysEnv := systemInfo()

	fmt.Println("Building compose images for benchmark...")
	if err := runCompose(sysEnv, "-f", "compose-bench.yml", "build"); err != nil {
		return err
	}

	fmt.Println("Running k6 load tests...")
	err := runCompose(sysEnv, "-f", "compose-bench.yml", "up",
		"--exit-code-from", "k6",
		"--abort-on-container-exit")

	fmt.Println("Tearing down bench stack...")
	_ = runCompose(sysEnv, "-f", "compose-bench.yml", "down", "--volumes")

	return err
}

// Puppet builds the Puppet stack images (puppet-master, puppet-client) and runs
// the full Puppet integration test suite: CA TLS, catalog application,
// PuppetDB reporting, exported resources, and CRL revocation enforcement.
//
// Requires podman-compose (or docker compose) and network access to pull
// quay.io/centos/centos:stream10, ghcr.io/openvoxproject/openvoxdb:latest,
// and docker.io/postgres:17-alpine on first run.
func (Test) Puppet() error {
	mg.Deps(Build{}.All)
	fmt.Println("Building compose images for puppet stack...")
	if err := runCompose(nil, "-f", "compose-puppet.yml", "build"); err != nil {
		return err
	}

	fmt.Println("Running puppet stack integration tests...")
	return sh.RunV("bash", "test/puppet/puppet-stack.sh", "--up")
}

// Migration builds the openvox-ca image and runs the migration integration test
// suite: imports a genuine VoxPupuli Puppet Server CA into openvox-ca, then
// verifies that the migrated CA can serve old certs, sign new ones, revoke,
// and clean.
//
// Requires a container runtime and network access to pull
// docker.io/voxpupuli/puppetserver:latest on first run.
func (Test) Migration() error {
	mg.Deps(Build{}.All)
	fmt.Println("Building compose images for migration test...")
	if err := runCompose(nil, "-f", "compose-migration.yml", "build"); err != nil {
		return err
	}

	fmt.Println("Running migration integration tests...")
	err := runCompose(nil, "-f", "compose-migration.yml", "up",
		"--exit-code-from", "test-runner",
		"--abort-on-container-exit")

	fmt.Println("Tearing down migration stack...")
	_ = runCompose(nil, "-f", "compose-migration.yml", "down", "--volumes")

	return err
}

// BackendsRedis builds the openvox-ca image and runs the full Puppet stack
// integration suite against a Redis-backed CA topology with two replicas
// sharing a single Redis prefix. Validates: catalog application end-to-end
// over Redis-backed storage; cert blobs offloaded to Redis (not local disk);
// distributed bootstrap lock when two CAs race; cross-replica state
// visibility; concurrent CSR submissions split across replicas with
// AppendLine atomicity on the inventory blob.
//
// Requires podman-compose (or docker compose) and network access to pull
// docker.io/redis:7-alpine plus the same images as Test:Puppet.
func (Test) BackendsRedis() error {
	mg.Deps(Build{}.All)
	fmt.Println("Building compose images for Redis-backend stack...")
	if err := runCompose(nil, "-f", "compose-backends-redis.yml", "build"); err != nil {
		return err
	}

	fmt.Println("Running Redis-backend integration tests...")
	return sh.RunV("bash", "test/backends/redis-stack.sh", "--up")
}

// BackendsRedisGo brings up a throwaway Redis via compose-backends-redis-go.yml
// and runs the Redis-backend Go integration suite (internal/storage, build tag
// `redis_integration`) against it, then tears Redis down. This mirrors the
// postgres/mysql/etcd Go-suite targets; it is distinct from BackendsRedis,
// which runs the full-stack bash TAP suite against a Puppet topology. Both are
// wired into CI so neither the bash suite nor the Go suite is left unrun.
//
// Requires podman-compose (or docker compose) and network access to pull
// docker.io/redis:7-alpine.
func (Test) BackendsRedisGo() error {
	const addr = "127.0.0.1:56379"

	fmt.Println("Starting Redis backend service...")
	if err := runCompose(nil, "-f", "compose-backends-redis-go.yml", "up", "-d", "--wait"); err != nil {
		return err
	}
	defer func() {
		fmt.Println("Tearing down Redis backend service...")
		_ = runCompose(nil, "-f", "compose-backends-redis-go.yml", "down", "--volumes")
	}()

	fmt.Println("Running Redis-backend Go integration tests...")
	return sh.RunWithV(
		map[string]string{"PUPPET_CA_TEST_REDIS_ADDR": addr},
		"go", "test", "-tags", "redis_integration", "-count=1", "./internal/storage/...",
	)
}

// BackendsPostgres brings up a throwaway PostgreSQL via
// compose-backends-postgres.yml and runs the SQL-backend Go integration suite
// (internal/storage, build tag `postgres_integration`) against it, then tears
// the database down. Validates the PostgreSQL dialect: upsert, FOR UPDATE
// AppendLine atomicity across two backends, and pg_advisory_lock mutual
// exclusion.
//
// Requires podman-compose (or docker compose) and network access to pull
// docker.io/postgres:16-alpine.
func (Test) BackendsPostgres() error {
	const dsn = "postgres://puppetca:puppetca@127.0.0.1:55432/puppetca?sslmode=disable"

	fmt.Println("Starting PostgreSQL backend service...")
	if err := runCompose(nil, "-f", "compose-backends-postgres.yml", "up", "-d", "--wait"); err != nil {
		return err
	}
	defer func() {
		fmt.Println("Tearing down PostgreSQL backend service...")
		_ = runCompose(nil, "-f", "compose-backends-postgres.yml", "down", "--volumes")
	}()

	fmt.Println("Running PostgreSQL-backend integration tests...")
	return sh.RunWithV(
		map[string]string{"PUPPET_CA_TEST_POSTGRES_DSN": dsn},
		"go", "test", "-tags", "postgres_integration", "-count=1", "./internal/storage/...",
	)
}

// BackendsMySQL brings up a throwaway MySQL via compose-backends-mysql.yml and
// runs the SQL-backend Go integration suite (internal/storage, build tag
// `mysql_integration`) against it, then tears the database down. Validates the
// MySQL/MariaDB dialect: LONGBLOB widening, ON DUPLICATE KEY upsert, FOR UPDATE
// AppendLine atomicity (with InnoDB deadlock retry) across two backends, and
// GET_LOCK mutual exclusion.
//
// Requires podman-compose (or docker compose) and network access to pull
// docker.io/mysql:8.
func (Test) BackendsMySQL() error {
	const dsn = "puppetca:puppetca@tcp(127.0.0.1:53306)/puppetca"

	fmt.Println("Starting MySQL backend service...")
	if err := runCompose(nil, "-f", "compose-backends-mysql.yml", "up", "-d", "--wait"); err != nil {
		return err
	}
	defer func() {
		fmt.Println("Tearing down MySQL backend service...")
		_ = runCompose(nil, "-f", "compose-backends-mysql.yml", "down", "--volumes")
	}()

	fmt.Println("Running MySQL-backend integration tests...")
	return sh.RunWithV(
		map[string]string{"PUPPET_CA_TEST_MYSQL_DSN": dsn},
		"go", "test", "-tags", "mysql_integration", "-count=1", "./internal/storage/...",
	)
}

// BackendsOpenBao brings up a throwaway OpenBao dev server via
// compose-backends-openbao.yml, configures its transit engine and an AppRole
// scoped to a "test-*" key prefix (deliberately broader than a production
// policy — it grants "create" and covers the key TestLiveGenerateThenLoad
// makes; see configureOpenBaoForTests and docs/openbao-transit.md for the
// tighter single-key policy a real deployment should use), runs the
// OpenBao-backend Go integration suite (internal/signer/openbao, build tag
// openbao_integration) against it, then tears the server down.
//
// Unlike the Postgres/MySQL/Redis-Go targets, the service needs configuring
// (transit engine, key, AppRole, policy) between "container is up" and
// "run go test" — done here via the same Go SDK internal/signer/openbao itself
// depends on, rather than shelling out to the openbao CLI inside the container.
//
// Requires podman-compose (or docker compose) and network access to pull
// docker.io/openbao/openbao:2.5.5.
func (Test) BackendsOpenBao() error {
	const (
		addr       = "http://127.0.0.1:58200"
		rootToken  = "root"
		roleName   = "test-role"
		policyName = "test-policy"
		keyName    = "test-key"
	)

	fmt.Println("Starting OpenBao backend service...")
	if err := runCompose(nil, "-f", "compose-backends-openbao.yml", "up", "-d", "--wait"); err != nil {
		return err
	}
	defer func() {
		fmt.Println("Tearing down OpenBao backend service...")
		_ = runCompose(nil, "-f", "compose-backends-openbao.yml", "down", "--volumes")
	}()

	fmt.Println("Configuring OpenBao transit engine and AppRole...")
	roleID, secretID, err := configureOpenBaoForTests(addr, rootToken, roleName, policyName, keyName)
	if err != nil {
		return fmt.Errorf("configuring OpenBao: %w", err)
	}

	// Write the secret_id into a freshly created private temp dir (0700, random
	// name) rather than a fixed, predictable path in a shared /tmp: on a shared
	// or self-hosted runner a pre-planted symlink at a known path could
	// otherwise redirect this write.
	secretIDDir, err := os.MkdirTemp("", "openvox-ca-openbao-test")
	if err != nil {
		return fmt.Errorf("creating secret_id temp dir: %w", err)
	}
	defer os.RemoveAll(secretIDDir)
	secretIDFile := filepath.Join(secretIDDir, "secret-id")
	if err := os.WriteFile(secretIDFile, []byte(secretID), 0o600); err != nil {
		return fmt.Errorf("writing secret_id file: %w", err)
	}

	fmt.Println("Running OpenBao-backend integration tests...")
	return sh.RunWithV(
		map[string]string{
			"PUPPET_CA_TEST_OPENBAO_ADDR":           addr,
			"PUPPET_CA_TEST_OPENBAO_ROLE_ID":        roleID,
			"PUPPET_CA_TEST_OPENBAO_SECRET_ID_FILE": secretIDFile,
			"PUPPET_CA_TEST_OPENBAO_KEY_NAME":       keyName,
		},
		"go", "test", "-tags", "openbao_integration", "-count=1", "./internal/signer/openbao/...",
	)
}

// configureOpenBaoForTests sets up a freshly started OpenBao dev server for the
// integration suite: mounts the transit engine, creates keyName, enables
// AppRole auth, and attaches a policy scoped to "transit/keys/test-*" and
// "transit/sign/test-*" — broad enough to cover both the pre-created key and
// the fresh one TestLiveGenerateThenLoad creates, appropriate for a
// throwaway per-run instance. A production policy should instead name its
// one key exactly; see docs/openbao-transit.md. Returns the AppRole
// role_id and a freshly generated secret_id.
func configureOpenBaoForTests(addr, rootToken, roleName, policyName, keyName string) (roleID, secretID string, err error) {
	cfg := openbao.DefaultConfig()
	if cfg.Error != nil {
		return "", "", cfg.Error
	}
	cfg.Address = addr
	client, err := openbao.NewClient(cfg)
	if err != nil {
		return "", "", err
	}
	client.SetToken(rootToken)

	if err := client.Sys().Mount("transit", &openbao.MountInput{Type: "transit"}); err != nil {
		return "", "", fmt.Errorf("mounting transit engine: %w", err)
	}

	if _, err := client.Logical().Write("transit/keys/"+keyName, map[string]interface{}{
		"type": "rsa-2048",
	}); err != nil {
		return "", "", fmt.Errorf("creating transit key %q: %w", keyName, err)
	}

	if err := client.Sys().EnableAuthWithOptions("approle", &openbao.EnableAuthOptions{Type: "approle"}); err != nil {
		return "", "", fmt.Errorf("enabling approle auth: %w", err)
	}

	const policyHCL = `
path "transit/keys/test-*" { capabilities = ["read", "create", "update"] }
path "transit/sign/test-*" { capabilities = ["update"] }
`
	if err := client.Sys().PutPolicy(policyName, policyHCL); err != nil {
		return "", "", fmt.Errorf("writing policy %q: %w", policyName, err)
	}

	if _, err := client.Logical().Write("auth/approle/role/"+roleName, map[string]interface{}{
		"token_policies": policyName,
		"token_ttl":      "5m",
		"token_max_ttl":  "15m",
	}); err != nil {
		return "", "", fmt.Errorf("creating approle role %q: %w", roleName, err)
	}

	roleIDSecret, err := client.Logical().Read("auth/approle/role/" + roleName + "/role-id")
	if err != nil {
		return "", "", fmt.Errorf("reading role_id: %w", err)
	}
	roleID, ok := roleIDSecret.Data["role_id"].(string)
	if !ok {
		return "", "", fmt.Errorf("role-id response missing role_id")
	}

	secretIDSecret, err := client.Logical().Write("auth/approle/role/"+roleName+"/secret-id", nil)
	if err != nil {
		return "", "", fmt.Errorf("generating secret_id: %w", err)
	}
	secretID, ok = secretIDSecret.Data["secret_id"].(string)
	if !ok {
		return "", "", fmt.Errorf("secret-id response missing secret_id")
	}

	return roleID, secretID, nil
}

// BackendsEtcd runs the etcd-backend Go integration suite (build tag
// etcd_integration). The suite boots an in-process embedded etcd, so unlike the
// Redis suite it needs no external service, compose stack, or network pulls.
func (Test) BackendsEtcd() error {
	fmt.Println("Running etcd-backend integration tests...")
	return sh.RunV("go", "test", "-tags", "etcd_integration", "-count=1", "./internal/storage/...")
}

// PuppetFIPS is like Puppet but compiles with GOEXPERIMENT=boringcrypto so the
// full Puppet stack integration suite runs against the FIPS-compliant binary.
func (Test) PuppetFIPS() error {
	mg.Deps(Build{}.FIPS)
	fmt.Println("Building compose images for puppet stack (FIPS build)...")
	if err := runCompose(nil, "-f", "compose-puppet.yml", "build"); err != nil {
		return err
	}

	fmt.Println("Running puppet stack integration tests (FIPS build)...")
	return sh.RunV("bash", "test/puppet/puppet-stack.sh", "--up")
}

// -- dev:* --------------------------------------------------------------------─

// Check verifies formatting, module tidiness, go vet, and the golangci-lint
// gate. Unlike `mage dev:tidy`, it is a non-mutating verifier: it reports drift
// as a failure instead of silently fixing it, so CI catches untidy code and
// modules. gofmt -l prints unformatted files without rewriting them, and the
// tidiness step runs `go mod tidy` then restores go.mod/go.sum, treating any
// change as a failure.
func (Dev) Check() error {
	fmt.Println("Running verify...")
	out, err := sh.Output("gofmt", "-l", ".")
	if err != nil {
		return err
	}
	if strings.TrimSpace(out) != "" {
		return fmt.Errorf("these files need formatting (run 'mage dev:tidy'):\n%s", out)
	}
	fmt.Println("Checking go mod tidy...")
	if err := sh.Run("go", "mod", "tidy"); err != nil {
		return err
	}
	changed, err := sh.Output("git", "diff", "--name-only", "--", "go.mod", "go.sum")
	if err != nil {
		return err
	}
	if strings.TrimSpace(changed) != "" {
		// Restore so Check leaves no side effects; the developer fixes via dev:tidy.
		if rerr := sh.Run("git", "checkout", "--", "go.mod", "go.sum"); rerr != nil {
			return fmt.Errorf("go.mod/go.sum are not tidy (%s); run 'mage dev:tidy' and commit. "+
				"Additionally failed to restore them: %w", strings.TrimSpace(changed), rerr)
		}
		return fmt.Errorf("go.mod/go.sum are not tidy (%s); run 'mage dev:tidy' and commit", strings.TrimSpace(changed))
	}
	if err := sh.Run("go", "vet", "./..."); err != nil {
		return err
	}
	return Dev{}.Lint()
}

// Lint runs golangci-lint over the whole module, teeing its output to
// .test-output/golangci-lint.log. A missing golangci-lint binary is a
// graceful skip (clear message, non-fatal) so dev:check still works in
// minimal environments; only an actual lint failure returns an error.
func (Dev) Lint() error {
	if _, err := exec.LookPath("golangci-lint"); err != nil {
		fmt.Println("SKIP: golangci-lint not found on PATH; skipping lint " +
			"(install: https://golangci-lint.run/welcome/install/)")
		return nil
	}

	fmt.Println("Running golangci-lint...")
	if err := os.MkdirAll(".test-output", 0755); err != nil {
		return err
	}
	logFile, err := os.Create(filepath.Join(".test-output", "golangci-lint.log"))
	if err != nil {
		return err
	}
	defer logFile.Close()

	out := io.MultiWriter(os.Stdout, logFile)
	errOut := io.MultiWriter(os.Stderr, logFile)
	if _, err := sh.Exec(nil, out, errOut, "golangci-lint", "run", "./..."); err != nil {
		return err
	}
	return nil
}

// Mixin renders the Prometheus mixin and validates the rules it produces.
//
// The README documents these two commands; without a target nothing runs them,
// and a mistyped $._config key or format verb is a Jsonnet error at import time
// that would otherwise reach a release unnoticed.
func (Dev) Mixin() error {
	for _, tool := range []string{"jsonnet", "promtool"} {
		if _, err := exec.LookPath(tool); err != nil {
			fmt.Printf("SKIP: %s not found on PATH; skipping mixin validation\n", tool)
			return nil
		}
	}

	fmt.Println("Rendering the Prometheus mixin...")
	if err := os.MkdirAll(".test-output", 0755); err != nil {
		return err
	}
	rules, err := sh.Output("jsonnet", "-S", "-e",
		`std.manifestYamlDoc((import 'mixin/mixin.libsonnet').prometheusAlerts)`)
	if err != nil {
		return err
	}
	out := filepath.Join(".test-output", "puppet_ca_alerts.yaml")
	if err := os.WriteFile(out, []byte(rules), 0644); err != nil {
		return err
	}

	fmt.Println("Checking rules with promtool...")
	return sh.RunV("promtool", "check", "rules", out)
}

// Tidy runs go mod tidy and go fmt on any files that need it.
func (Dev) Tidy() error {
	fmt.Println("Tidying modules...")
	if err := sh.Run("go", "mod", "tidy"); err != nil {
		return err
	}
	fmt.Println("Formatting code...")
	return sh.Run("go", "fmt", "./...")
}

// Clean removes the bin/ directory.
func (Dev) Clean() error {
	fmt.Println("Cleaning...")
	return sh.Rm("bin")
}

// Container creates a minimal scratch OCI image from the openvox-ca binary and
// loads it into the local Docker / Podman daemon.
//
// Configuration (via environment variables):
//
//	IMAGE_NAME   Target tag       (default: openvox-ca-go:latest)
//	BINARY_PATH  Source binary    (default: ./bin/openvox-ca)
func (Dev) Container() error {
	cfg := ContainerConfig{}
	if err := env.Parse(&cfg); err != nil {
		return fmt.Errorf("config parse failed: %w", err)
	}
	fmt.Printf("Building '%s' (binary: %s)...\n", cfg.Image, cfg.Binary)

	binLayer, err := tarLayer(map[string]string{"/app": cfg.Binary}, nil)
	if err != nil {
		return fmt.Errorf("failed to package binary: %w", err)
	}

	dirLayer, err := tarLayer(nil, []string{"/data"})
	if err != nil {
		return fmt.Errorf("failed to create directories: %w", err)
	}

	img, err := mutate.AppendLayers(empty.Image, binLayer, dirLayer)
	if err != nil {
		return fmt.Errorf("image mutation failed: %w", err)
	}

	img, err = mutate.Config(img, v1.Config{
		Entrypoint: []string{"/app"},
		Cmd:        []string{"-cadir", "/data", "-v", "2"},
	})
	if err != nil {
		return fmt.Errorf("failed to set image config: %w", err)
	}

	tag, err := name.NewTag(cfg.Image)
	if err != nil {
		return err
	}

	if _, err := daemon.Write(tag, img); err != nil {
		return fmt.Errorf("failed to load to daemon: %w", err)
	}

	fmt.Println("Success! Image loaded.")
	return nil
}

// -- types and helpers --------------------------------------------------------─

type ContainerConfig struct {
	Image  string `env:"IMAGE_NAME" envDefault:"openvox-ca-go:latest"`
	Binary string `env:"BINARY_PATH" envDefault:"./bin/openvox-ca"`
}

// composeCmd returns the compose command prefix, probing in order:
//
//  1. podman-compose  (standalone binary)
//  2. docker compose  (Docker v2 plugin, two-word invocation)
//  3. docker-compose  (Docker v1 standalone binary)
func composeCmd() ([]string, error) {
	if _, err := exec.LookPath("podman-compose"); err == nil {
		return []string{"podman-compose"}, nil
	}
	if _, err := exec.LookPath("docker"); err == nil {
		if exec.Command("docker", "compose", "version").Run() == nil {
			return []string{"docker", "compose"}, nil
		}
	}
	if _, err := exec.LookPath("docker-compose"); err == nil {
		return []string{"docker-compose"}, nil
	}
	return nil, fmt.Errorf("no compose tool found; install podman-compose or docker compose")
}

// runCompose runs a compose command with whichever tool composeCmd selects.
// PYTHONUNBUFFERED=1 is always set so podman-compose (Python) flushes each
// log line immediately rather than block-buffering; it is harmless for
// docker compose (Go).  Extra env vars can be supplied via extraEnv.
func runCompose(extraEnv map[string]string, args ...string) error {
	compose, err := composeCmd()
	if err != nil {
		return err
	}
	env := map[string]string{"PYTHONUNBUFFERED": "1"}
	for k, v := range extraEnv {
		env[k] = v
	}
	return sh.RunWithV(env, compose[0], append(compose[1:], args...)...)
}

// runComposeWithSpinner is like runCompose but displays an animated spinner
// between output lines so the terminal does not appear to hang during quiet
// periods (e.g. the 15-second gaps between k6 progress checkpoints).
//
// The spinner runs in its own goroutine at 100 ms intervals.  Each output
// line from the subprocess clears the spinner, prints the line, then redraws
// the spinner below it.  Falls back to plain runCompose when stdout is not a
// TTY (CI, pipes) so ANSI codes never leak into captured output.
func runComposeWithSpinner(extraEnv map[string]string, spinMsg string, args ...string) error {
	// TTY detection: character-device check works on Linux/macOS.
	fi, err := os.Stdout.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return runCompose(extraEnv, args...)
	}

	compose, err := composeCmd()
	if err != nil {
		return err
	}

	cmd := exec.Command(compose[0], append(compose[1:], args...)...)
	cmd.Env = append(os.Environ(), "PYTHONUNBUFFERED=1")
	for k, v := range extraEnv {
		cmd.Env = append(cmd.Env, k+"="+v)
	}

	// Pipe both stdout and stderr through a single in-process pipe so the
	// spinner goroutine can interleave cleanly with the subprocess output.
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw

	const erase = "\r\033[K" // carriage-return + CSI erase-to-end-of-line
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	var (
		mu    sync.Mutex
		frame int
	)

	draw := func() { fmt.Printf("\r%s %s", frames[frame], spinMsg) }

	printLine := func(line string) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Printf("%s%s\n", erase, line)
		draw()
	}

	tick := func() {
		mu.Lock()
		defer mu.Unlock()
		frame = (frame + 1) % len(frames)
		draw()
	}

	// Draw the initial spinner frame.
	mu.Lock()
	draw()
	mu.Unlock()

	// Goroutine: read lines from the subprocess and print each one.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(pr)
		for scanner.Scan() {
			printLine(scanner.Text())
		}
	}()

	// Goroutine: advance the spinner frame every 100 ms.
	stopSpinner := make(chan struct{})
	go func() {
		t := time.NewTicker(100 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				tick()
			case <-stopSpinner:
				return
			}
		}
	}()

	cmdErr := cmd.Run()
	pw.Close() // signal EOF so the scanner goroutine exits
	wg.Wait()
	close(stopSpinner)

	// Erase the spinner line so the next fmt.Println starts cleanly.
	mu.Lock()
	fmt.Print(erase)
	mu.Unlock()

	return cmdErr
}

func createTarGz(dst, srcDir string, files []string) (retErr error) {
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	defer func() {
		if err := gz.Close(); err != nil && retErr == nil {
			retErr = err
		}
	}()
	tw := tar.NewWriter(gz)
	defer func() {
		if err := tw.Close(); err != nil && retErr == nil {
			retErr = err
		}
	}()

	for _, name := range files {
		src := filepath.Join(srcDir, name)
		fi, err := os.Stat(src)
		if err != nil {
			return err
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0755, Size: fi.Size()}); err != nil {
			return err
		}
		rf, err := os.Open(src)
		if err != nil {
			return err
		}
		_, err = io.Copy(tw, rf)
		rf.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func tarLayer(files map[string]string, dirs []string) (v1.Layer, error) {
	b := new(bytes.Buffer)
	tw := tar.NewWriter(b)

	for _, dir := range dirs {
		if err := tw.WriteHeader(&tar.Header{Name: dir, Mode: 0755, Typeflag: tar.TypeDir}); err != nil {
			return nil, err
		}
	}

	for dest, src := range files {
		data, err := os.ReadFile(src)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", src, err)
		}
		if err := tw.WriteHeader(&tar.Header{Name: dest, Mode: 0755, Size: int64(len(data))}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
	}
	tw.Close()

	return tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(b.Bytes())), nil
	})
}
