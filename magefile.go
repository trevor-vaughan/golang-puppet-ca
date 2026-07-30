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
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

type Build mg.Namespace // build:all  build:fips  build:dist
type Test mg.Namespace  // test:unit  test:integcompose  test:integcomposefips  test:loadcompose  test:bench  test:puppet  test:puppetfips  test:migration  test:backendsRedis  test:backendsEtcd
type Dev mg.Namespace   // dev:check  dev:lint  dev:mixin  dev:tidy  dev:clean  dev:container

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

// Dist cross-compiles release artifacts for all supported platforms and writes
// them to dist/. Each artifact is a .tar.gz containing openvox-ca and
// openvox-ca-ctl. A SHA-256 checksums.txt is also written to dist/.
//
// Artifacts produced:
//
//	openvox-ca_linux_amd64.tar.gz       (standard; CGO_ENABLED=0)
//	openvox-ca_linux_arm64.tar.gz       (standard; CGO_ENABLED=0)
//	openvox-ca_linux_amd64_fips.tar.gz  (FIPS; GOEXPERIMENT=boringcrypto)
func (Build) Dist() error {
	distDir := "dist"
	if err := os.RemoveAll(distDir); err != nil {
		return err
	}
	if err := os.MkdirAll(distDir, 0755); err != nil {
		return err
	}

	type variant struct {
		name string
		env  map[string]string
	}
	variants := []variant{
		{
			name: "openvox-ca_linux_amd64",
			env:  map[string]string{"CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64"},
		},
		{
			name: "openvox-ca_linux_arm64",
			env:  map[string]string{"CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "arm64"},
		},
		{
			name: "openvox-ca_linux_amd64_fips",
			env:  map[string]string{"CGO_ENABLED": "1", "GOOS": "linux", "GOARCH": "amd64", "GOEXPERIMENT": "boringcrypto"},
		},
	}

	bins := []string{"openvox-ca", "openvox-ca-ctl"}

	var checksums []string
	for _, v := range variants {
		fmt.Printf("Building %s...\n", v.name)

		archive := filepath.Join(distDir, v.name+".tar.gz")
		sum, err := func() (string, error) {
			tmpDir, err := os.MkdirTemp("", "openvox-ca-dist-*")
			if err != nil {
				return "", err
			}
			defer os.RemoveAll(tmpDir)

			for _, cmd := range bins {
				if err := sh.RunWith(v.env, "go", "build",
					"-o", filepath.Join(tmpDir, cmd),
					"./cmd/"+cmd); err != nil {
					return "", fmt.Errorf("build %s for %s: %w", cmd, v.name, err)
				}
			}

			if err := createTarGz(archive, tmpDir, bins); err != nil {
				return "", fmt.Errorf("archive %s: %w", v.name, err)
			}
			return sha256File(archive)
		}()
		if err != nil {
			return err
		}
		checksums = append(checksums, fmt.Sprintf("%s  %s\n", sum, filepath.Base(archive)))
	}

	return os.WriteFile(
		filepath.Join(distDir, "checksums.txt"),
		[]byte(strings.Join(checksums, "")),
		0644,
	)
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
