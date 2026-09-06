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
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/voxpupuli/openvox-ca/internal/api"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/k8sexport"
	"github.com/voxpupuli/openvox-ca/internal/metrics"
	"github.com/voxpupuli/openvox-ca/internal/sdnotify"
	"github.com/voxpupuli/openvox-ca/internal/signer"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/version"
)

// setupLogger creates and sets the default slog logger based on config.
// Returns the log file (if any) so the caller can close it on shutdown,
// ensuring final log entries are flushed. Returns nil when logging to stderr.
// levelTrace is the level -v -v selects: below slog.LevelDebug, for the
// call-by-call detail that would drown a Debug run. Named here so the flag
// help, the switch below and the spec that pins the mapping all mean the same
// number.
const levelTrace = slog.Level(-8)

func setupLogger(cfg *serverConfig) (*os.File, error) {
	var logLevel slog.Level
	switch cfg.Verbosity {
	case 0:
		logLevel = slog.LevelInfo
	case 1:
		logLevel = slog.LevelDebug
	default:
		logLevel = levelTrace
	}

	opts := &slog.HandlerOptions{Level: logLevel}

	if cfg.LogFile != "" {
		f, err := os.OpenFile(cfg.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file %s: %w", cfg.LogFile, err)
		}
		slog.SetDefault(slog.New(slog.NewJSONHandler(f, opts)))
		return f, nil
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, opts)))
	return nil, nil
}

// buildBackendSpec derives a storage.BackendSpec from the server config. The
// spec is used to construct the StorageService in every mode (frontend,
// signer, single-process), ensuring backend selection happens in one place.
// The backend-selection logic is shared with the operator CLI's migrate
// command via config.StorageConfig.ToBackendSpec.
func buildBackendSpec(cfg *serverConfig, absCADir string) (storage.BackendSpec, error) {
	return cfg.StorageConfig.ToBackendSpec(absCADir)
}

// buildAuthConfig assembles the API's authorisation configuration: the admin CN
// allow list drawn from puppet_server and puppet_server_file, and the flags
// governing pp_cli_auth and public status.
//
// Extracted from the startup path so that what the middleware is configured
// with is separable from when it is installed. Those are different decisions —
// the caller decides whether to authorise at all, this decides how — and having
// them in one inline block is what made it easy to add a TLS mode that silently
// skipped the first.
func buildAuthConfig(cfg *serverConfig, myCA *ca.CA) (*api.AuthConfig, error) {
	// Through buildAdminAllowList, not an inline merge: that function is the
	// single construction point for this list, and reload calls it too. Two
	// implementations of the same merge is how startup and SIGHUP come to
	// disagree about who is an administrator.
	allowList, err := buildAdminAllowList(cfg.PuppetServer, cfg.PuppetServerFile)
	if err != nil {
		return nil, err
	}

	if !cfg.NoPpCliAuth {
		// SECURITY: Inform the operator that pp_cli_auth OID grants admin access.
		// Any certificate carrying this extension with value "true" will be treated
		// as an admin. Use --no-pp-cli-auth to restrict admin access to the CN allow list only.
		// NIST 800-53: AC-6 (Least Privilege)
		slog.Info("pp_cli_auth extension is enabled as an admin credential (default). " +
			"Any certificate carrying pp_cli_auth=true will have admin access. " +
			"Use --no-pp-cli-auth to disable this and require explicit CN allow list.")
	}

	// Domain zero is this CA, always, and is not configurable: an operator
	// cannot remove it, rename it, or drop their own CA out of the trust set.
	// With no client_ca configured the list has length one and authorisation
	// is exactly what it was.
	if err := cfg.ClientCAConfig.Validate(); err != nil {
		return nil, fmt.Errorf("invalid client_ca config: %w", err)
	}
	domains, err := buildTrustDomains(cfg, myCA.CACert, allowList)
	if err != nil {
		return nil, err
	}

	return &api.AuthConfig{
		Domains:                domains,
		AllowPublicStatus:      cfg.AllowPublicStatus,
		ClientRevocationPolicy: cfg.ResolvedPolicy(),
	}, nil
}

// applyCAConfig applies the common CA configuration fields from serverConfig
// to a CA instance. Used by both frontend and signer modes.
func applyCAConfig(myCA *ca.CA, cfg *serverConfig) error {
	if cfg.OCSPUrl != "" {
		myCA.OCSPURLs = []string{cfg.OCSPUrl}
	}
	if cfg.CRLUrl != "" {
		myCA.CRLURLs = []string{cfg.CRLUrl}
	}
	myCA.CRLValidityDays = cfg.CRLValidityDays
	myCA.CRLChainFile = cfg.CRLChainFile

	if cfg.CAKeyAlgo != "" || cfg.CAKeySize != 0 {
		myCA.CAKeyConfig = ca.KeyConfig{
			Algo: ca.KeyAlgo(cfg.CAKeyAlgo),
			Size: cfg.CAKeySize,
		}
		if err := ca.ValidateKeyConfig(myCA.CAKeyConfig); err != nil {
			return fmt.Errorf("invalid ca_key_algo / ca_key_size: %w", err)
		}
	}
	if cfg.LeafKeyAlgo != "" || cfg.LeafKeySize != 0 {
		myCA.LeafKeyConfig = ca.KeyConfig{
			Algo: ca.KeyAlgo(cfg.LeafKeyAlgo),
			Size: cfg.LeafKeySize,
		}
		if err := ca.ValidateKeyConfig(myCA.LeafKeyConfig); err != nil {
			return fmt.Errorf("invalid leaf_key_algo / leaf_key_size: %w", err)
		}
	}
	myCA.CASubject = ca.CASubjectConfig{
		Org:      cfg.CASubjectOrg,
		OrgUnit:  cfg.CASubjectOU,
		Country:  cfg.CASubjectCountry,
		Locality: cfg.CASubjectLocality,
		Province: cfg.CASubjectProvince,
	}
	myCA.CAPathLength = cfg.CAPathLength
	myCA.CAValidityDays = cfg.CAValidityDays
	myCA.LeafValidityDays = cfg.LeafValidityDays
	myCA.EncryptCAKey = cfg.EncryptCAKey
	myCA.PromoteCNToSAN = cfg.PromoteCNToSAN
	myCA.RevokeOnAutoRenew = cfg.RevokeOnAutoRenew
	myCA.SupersedeAfter = cfg.supersededCertRevokeAfter()
	myCA.SigningConcurrency = resolveSigningConcurrency(cfg.CASigningConcurrency)
	myCA.KeyPassphrase = ca.KeyPassphraseConfig{
		PassphraseFile: cfg.CAKeyPassphraseFile,
	}
	return nil
}

// isLoopback reports whether host is a loopback address (127.x.x.x, ::1, or
// "localhost"). Plain HTTP is only safe when the server cannot be reached from
// outside the local process.
func isLoopback(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return host == "localhost"
}

// defaultCSRRateLimit is the built-in CSR submission cap (per IP per minute)
// applied when no rate limit is configured on any layer.
const defaultCSRRateLimit = 60

// resolveCSRRateLimit maps a configured CSR rate limit to the value handed to
// the server. The config field is sentinelled to -1 ("unset") so an explicit 0
// (disable) is never confused with "not configured": only the sentinel falls
// back to defaultCSRRateLimit, while 0 and positive values pass through. This
// keeps the "0 disables, unset uses the default" contract consistent across the
// flag, environment, and file layers.
func resolveCSRRateLimit(configured int) int {
	if configured < 0 {
		return defaultCSRRateLimit
	}
	return configured
}

// minSigningConcurrency is the floor under the built-in CA signing bound.
// GOMAXPROCS alone would give a single-CPU container a bound of 1, serialising
// issuance behind the OCSP responder and making a certificate request wait on
// verifier traffic. Four keeps a small deployment working while staying far
// below anything that could saturate a signer.
const minSigningConcurrency = 4

// resolveSigningConcurrency maps a configured CA signing concurrency to the
// value handed to the CA, following the CSRRateLimit convention exactly: -1
// ("unset") takes the built-in default, an explicit 0 disables the bound, and
// positive values pass through.
//
// The default is max(4, GOMAXPROCS). Scaling with the CPU count is right for
// the two backends where a signature is CPU-bound — a software key in process,
// and the default isolated signer, where it is CPU-bound in the signer child —
// because past that point extra concurrency buys latency and memory rather
// than throughput. It is deliberately a safe ceiling and not a tuned value: the
// right number is a property of the deployment's signer, and for a remote one
// (ca_key_provider: openbao) an operator should set the limit to that signer's
// capacity. What the default guarantees is only that the number is finite,
// which is the property #274 is about.
func resolveSigningConcurrency(configured int) int {
	if configured >= 0 {
		return configured
	}
	return max(minSigningConcurrency, runtime.GOMAXPROCS(0))
}

// warnIfSigningBoundIsCPUDerived says so when the CA signing bound was left
// unset on a deployment whose signer is reached over the network.
//
// The default is CPU-shaped and the work is not. Under `ca_key_provider:
// openbao` every signature is a round trip to a Transit key, so GOMAXPROCS
// measures this host's cores and says nothing about what that key — possibly
// shared with other consumers — can sustain. On a well-provisioned node the
// derived number is likely far above what the provider wants, and the
// deployment has no way to notice.
//
// Deriving a *different* default instead would be worse: it would invent a
// number for a capacity openvox-ca cannot discover, which is exactly what #265
// declined to do and what resolveSigningConcurrency's own doc disclaims. So say
// it once, plainly, and leave the number to the operator who can measure it.
//
// Not warned for the isolated signer, which is the default topology: signing
// there is CPU-bound in the signer child, so a CPU-derived ceiling is the right
// shape and lowering it is a tuning rather than a correction.
//
// Serve only. The offline commands share applyCAConfig but sign one certificate
// at a time, so the bound never binds and the warning would be noise.
func warnIfSigningBoundIsCPUDerived(cfg *serverConfig, resolved int) {
	if !cfg.UsesOpenBao() || cfg.CASigningConcurrency >= 0 {
		return
	}
	slog.Warn("ca_signing_concurrency is unset, so the CA-key signing bound was derived from this "+
		"host's CPU count — which says nothing about what an OpenBao Transit key can sustain. "+
		"Set it to that signer's capacity; the bound is per process, so N replicas permit N times "+
		"this value against one shared key.",
		"ca_signing_concurrency", resolved,
		"derived_from", "GOMAXPROCS",
		"ca_key_provider", cfg.CAKeyProvider)
}

func main() {
	cmd := newRootCmd()
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// newRootCmd builds and returns the fully-configured root command, including
// all flag wiring. Extracted from main() so the command can be exercised in
// unit tests (e.g. argument validation) without invoking os.Exit.
func newRootCmd() *cobra.Command {
	var (
		caDir                   string
		autosignVal             string
		host                    string
		port                    int
		hostname                string
		daemon                  bool
		verbosity               int
		logFile                 string
		tlsCert                 string
		tlsKey                  string
		puppetServers           string
		puppetServerFile        string
		noPpCliAuth             bool
		clientRevocationPolicy  string
		noTLSRequired           bool
		allowPublicStatus       bool
		ocspURL                 string
		crlURL                  string
		metricsListen           string
		csrRateLimit            int
		caSigningConcurrency    int
		configFile              string
		encryptCAKey            bool
		caKeyPassphraseFile     string
		singleProcess           bool
		storageBackend          string
		etcdEndpoints           []string
		etcdKeyPrefix           string
		redisAddrs              []string
		redisSentinelMasterName string
		redisSentinelAddrs      []string
		redisKeyPrefix          string
		sqlDSN                  string
		caCertFile              string
		caKeyFile               string

		// CA key provider (--ca-key-provider) and --openbao-* flags. Grouped
		// into a struct with register/apply helpers so the flag→config mapping
		// is unit-testable (see flags_openbao_test.go); the mapping includes
		// security-relevant fields (TLS cert/key, role_id/secret_id) where a
		// silent transposition would be a credential/trust bug.
		obFlags openBaoFlagValues
	)

	cmd := &cobra.Command{
		Use:           "openvox-ca",
		Short:         "Puppet-compatible certificate authority server",
		Version:       version.Full(),
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGTERM, syscall.SIGINT)
			defer stop()

			// SIGHUP means "reload" for this service, but its default
			// disposition is to terminate. Claim it here, before any of the
			// slow startup work below — opening storage, waiting for the
			// signer to bootstrap a CA key, binding the listener — so a reload
			// that arrives while the CA is still coming up cannot kill it. The
			// channel is handed to whichever role can act on it; a signal that
			// arrives before then waits in the buffer rather than being fatal.
			// (The signer overrides this with signal.Ignore; see runSignerMode.)
			hupCh := make(chan os.Signal, 1)
			signal.Notify(hupCh, syscall.SIGHUP)
			defer signal.Stop(hupCh)

			// Service-manager notifications (sd_notify). Inert unless started
			// by a service manager that asked to be notified, so no
			// configuration or branching is needed anywhere below.
			notifier := sdnotify.New()
			defer func() { _ = notifier.Close() }()
			notifier.Status("Loading configuration")

			// --- Config loading (file → env → CLI flags) ---
			resolved := resolveConfigFile(configFile, "PUPPET_CA_CONFIG", "/etc/puppet-ca/config.yaml")
			cfg, err := loadServerConfig(resolved)
			if err != nil {
				return err
			}

			// Apply explicitly-set CLI flags (highest precedence).
			if cmd.Flags().Changed("cadir") {
				cfg.CADir = caDir
			}
			if cmd.Flags().Changed("autosign-config") {
				cfg.AutosignConfig = autosignVal
			}
			if cmd.Flags().Changed("host") {
				cfg.Host = host
			}
			if cmd.Flags().Changed("port") {
				cfg.Port = port
			}
			if cmd.Flags().Changed("hostname") {
				cfg.Hostname = hostname
			}
			if cmd.Flags().Changed("verbosity") {
				cfg.Verbosity = verbosity
			}
			if cmd.Flags().Changed("logfile") {
				cfg.LogFile = logFile
			}
			if cmd.Flags().Changed("tls-cert") {
				cfg.TLSCert = tlsCert
			}
			if cmd.Flags().Changed("tls-key") {
				cfg.TLSKey = tlsKey
			}
			if cmd.Flags().Changed("puppet-server") {
				cfg.PuppetServer = puppetServers
			}
			if cmd.Flags().Changed("puppet-server-file") {
				cfg.PuppetServerFile = puppetServerFile
			}
			if cmd.Flags().Changed("no-pp-cli-auth") {
				cfg.NoPpCliAuth = noPpCliAuth
			}
			if cmd.Flags().Changed("client-revocation-policy") {
				cfg.ClientRevocationPolicy = clientRevocationPolicy
			}
			if cmd.Flags().Changed("no-tls-required") {
				cfg.NoTLSRequired = noTLSRequired
			}
			if cmd.Flags().Changed("allow-public-status") {
				cfg.AllowPublicStatus = allowPublicStatus
			}
			if cmd.Flags().Changed("ocsp-url") {
				cfg.OCSPUrl = ocspURL
			}
			if cmd.Flags().Changed("crl-url") {
				cfg.CRLUrl = crlURL
			}
			if cmd.Flags().Changed("metrics-listen") {
				cfg.MetricsListen = metricsListen
			}
			if cmd.Flags().Changed("csr-rate-limit") {
				cfg.CSRRateLimit = csrRateLimit
			}
			if cmd.Flags().Changed("ca-signing-concurrency") {
				cfg.CASigningConcurrency = caSigningConcurrency
			}
			if cmd.Flags().Changed("encrypt-ca-key") {
				cfg.EncryptCAKey = encryptCAKey
			}
			if cmd.Flags().Changed("ca-key-passphrase-file") {
				cfg.CAKeyPassphraseFile = caKeyPassphraseFile
			}
			if cmd.Flags().Changed("storage-backend") {
				cfg.StorageBackend = storageBackend
			}
			if cmd.Flags().Changed("etcd-endpoints") {
				cfg.EtcdEndpoints = etcdEndpoints
			}
			if cmd.Flags().Changed("etcd-key-prefix") {
				cfg.EtcdKeyPrefix = etcdKeyPrefix
			}
			if cmd.Flags().Changed("redis-addrs") {
				cfg.RedisAddrs = redisAddrs
			}
			if cmd.Flags().Changed("redis-sentinel-master-name") {
				cfg.RedisSentinelMasterName = redisSentinelMasterName
			}
			if cmd.Flags().Changed("redis-sentinel-addrs") {
				cfg.RedisSentinelAddrs = redisSentinelAddrs
			}
			if cmd.Flags().Changed("redis-key-prefix") {
				cfg.RedisKeyPrefix = redisKeyPrefix
			}
			if cmd.Flags().Changed("sql-dsn") {
				cfg.SQLDSN = sqlDSN
			}
			if cmd.Flags().Changed("ca-cert-file") {
				cfg.CACertFile = caCertFile
			}
			if cmd.Flags().Changed("ca-key-file") {
				cfg.CAKeyFile = caKeyFile
			}
			applyOpenBaoFlagOverrides(cmd, cfg, &obFlags)
			// --- Validation ---
			if cfg.CADir == "" {
				return fmt.Errorf("--cadir is required (or set PUPPET_CA_CADIR / cadir in config file)")
			}
			if err := cfg.CAKeyProviderConfig.Validate(); err != nil {
				return err
			}

			absCADir, err := filepath.Abs(cfg.CADir)
			if err != nil {
				return fmt.Errorf("resolving --cadir: %w", err)
			}

			// Daemonise only when explicitly requested AND we aren't already the daemon child.
			// Note: --daemon is intentionally excluded from config file / env var support
			// because PUPPET_CA_DAEMON is used internally as the fork signal.
			if daemon && os.Getenv("PUPPET_CA_DAEMON") != "1" {
				// A service manager tracks the process it started; forking and
				// exiting makes the service look like it died the moment it
				// started. Under systemd, drop --daemon and use Type=notify.
				if notifier.Enabled() {
					slog.Warn("--daemon is incompatible with a service manager that expects notifications; " +
						"run in the foreground (Type=notify) instead")
				}
				// Check the single-instance rule here, in the process that still
				// has somewhere to print. The child's stdout and stderr are
				// discarded four lines below, so a refusal there is invisible:
				// the operator would be told "started in background", get exit 0,
				// and watch the child die silently. That is the deployment shape
				// most likely to hit a second-instance conflict getting the least
				// useful diagnostic, from the feature whose entire purpose is
				// naming the holder.
				//
				// A pre-flight rather than a handover. This takes the lock and
				// gives it straight back; the child takes the real one. Another
				// process could still win the gap between the two, and then the
				// child dies as silently as it always would have -- but the
				// ordinary case, a service already running against this store, is
				// now refused here, by name, before anything is forked.
				if err := preflightInstanceLock(ctx, cfg); err != nil {
					return err
				}

				exe, err := os.Executable()
				if err != nil {
					return fmt.Errorf("failed to determine executable: %w", err)
				}
				c := exec.Command(exe, os.Args[1:]...) //nolint:gosec // G204: re-execs this same binary (os.Executable) with the operator's own os.Args to daemonize
				c.Env = append(daemonEnv(os.Environ()), "PUPPET_CA_DAEMON=1")
				c.Stdin = nil
				c.Stdout = nil
				c.Stderr = nil
				if err := c.Start(); err != nil {
					return fmt.Errorf("failed to start daemon: %w", err)
				}
				fmt.Printf("Puppet CA started in background (PID: %d)\n", c.Process.Pid)
				return nil
			}

			// --- Role dispatch (key isolation) ---
			role := os.Getenv("PUPPET_CA_ROLE")

			// SECURITY: an unrecognised role must not fall through. Without this,
			// a typo -- a stale Environment= line, "fronted", "Frontend" -- skips
			// the launcher (role is non-empty) *and* skips the frontend's dial
			// (role is not "frontend"), so no signer is spawned, no remote signer
			// is wired, and the process serves the HTTP API with the CA private
			// key in its own address space. Exit code 0, no warning: the exact
			// inverse of the property this topology exists for, and of what
			// docs/ca-key-security.md promises. The whole fd contract is spent on
			// making a wrong *descriptor* refuse to start; a wrong role string
			// disabled the isolation those descriptors protect.
			switch role {
			case "", "signer", "frontend":
			default:
				return fmt.Errorf("unrecognised PUPPET_CA_ROLE %q: expected \"signer\", \"frontend\", or unset", role)
			}

			// --- One running instance, unless the backend can coordinate more ---
			// A backend with distributed locking may run multiple instances, on
			// one host or on many; every other backend permits exactly one,
			// because nothing reconciles the serial index, OCSP cache and cached
			// CRL each process holds. AcquireInstanceLock decides which of those
			// this backend is by capability rather than by name, and is a no-op
			// for the former, so HA deployments are untouched.
			//
			// Taken here, before the role dispatch below, because the unit of
			// exclusion is the *instance* and not the process. With
			// PUPPET_CA_ROLE unset this is either the launcher, which forks a
			// signer and a frontend that each open the store for themselves, or
			// the single-process server. Both are one instance. Taking it any
			// deeper -- in resolveRuntime, the obvious shared place -- would put
			// the launcher's two children in a race to lock their own parent
			// out, and the default topology on the default backend would
			// deadlock against itself at startup.
			//
			// Held until this process exits: the kernel drops the flock when the
			// descriptor closes, however the process ends.
			if role == "" {
				instanceLock, err := lockStoreInstance(ctx, cfg)
				if err != nil {
					return err
				}
				defer func() {
					if err := instanceLock.Unlock(); err != nil {
						slog.Warn("Failed to release the store's instance lock", "error", err)
					}
				}()
			}

			// Signer mode: load key, serve signing requests on socketpair, exit.
			if role == "signer" {
				return runSignerMode(ctx, cfg, absCADir)
			}

			// Launcher mode (default): spawn isolated signer + frontend children.
			if role == "" && !singleProcess {
				return runLauncher(cfg.shutdownDrain(), notifier, hupCh)
			}

			// Frontend mode (role=frontend) or single-process mode: run HTTP server.
			// In frontend mode, connect to the signer process via socketpair
			// (deferred to after storage setup so the CA cert can be read via
			// the overlay-aware storage service).
			var remoteSigner *signer.RemoteSigner

			// --- Logging setup ---
			logFile, err := setupLogger(cfg)
			if err != nil {
				return err
			}
			if logFile != nil {
				defer func() {
					// Report on stderr, not slog: the default logger writes to
					// this very file, which is being closed here.
					if cerr := logFile.Close(); cerr != nil {
						fmt.Fprintf(os.Stderr, "failed to close log file: %v\n", cerr)
					}
				}()
			}

			slog.Info("Starting Puppet CA",
				"cadir", absCADir,
				"host", cfg.Host,
				"port", cfg.Port,
				"verbosity", cfg.Verbosity,
			)

			// SECURITY: TLS enforcement: plain HTTP over a non-loopback
			// interface lets any on-path host inject forged certificates.
			// Refuse to start unless:
			//   (a) TLS is configured (--tls-cert + --tls-key), or
			//   (b) the bind address is loopback-only, or
			//   (c) the operator explicitly opts out with --no-tls-required.
			// NIST 800-53: SC-8 (Transmission Confidentiality and Integrity), SC-23 (Session Authenticity)
			tlsConfigured := cfg.TLSCert != "" && cfg.TLSKey != ""
			if !tlsConfigured {
				if !isLoopback(cfg.Host) && !cfg.NoTLSRequired {
					return errors.New("refusing to start: plain HTTP on a non-loopback address is vulnerable to certificate injection; enable TLS (--tls-cert/--tls-key), restrict to loopback (--host 127.0.0.1), or set --no-tls-required")
				}
				if cfg.NoTLSRequired && !isLoopback(cfg.Host) {
					slog.Warn("TLS is not configured on a non-loopback address; " +
						"certificate injection is possible. " +
						"Only use --no-tls-required behind a trusted TLS proxy or in test environments.")
				}
			}
			if !tlsConfigured && (cfg.PuppetServer != "" || cfg.PuppetServerFile != "") {
				slog.Warn("--puppet-server / --puppet-server-file have no effect without TLS; " +
					"all endpoints are accessible without authentication in plain HTTP mode.")
			}
			// The sweep's interval is added to every overlap window in the worst
			// case, because a certificate becomes due between two passes and is
			// revoked on the later one. See supersededWindowWarning.
			if msg, args, warn := supersededWindowWarning(cfg); warn {
				slog.Warn(msg, args...)
			}

			// --- Storage, and the key provider when this role may reach the key ---
			// The frontend role proxies every signature to the isolated signer
			// process and must never construct a provider of its own: doing so
			// would open a second authenticated session to the key backend for a
			// key this process is specifically not allowed to use.
			//
			// The status is set before the open rather than after it: opening
			// is the part that can block for a long time on a database or
			// cluster backend, and naming the backend is what tells a systemd
			// operator watching a hung start which one is not answering. The
			// name is parsed authoritatively inside resolveRuntime, which
			// reports an unusable one as an error; here it only decides
			// whether the status can name the backend at all.
			if kind, kindErr := storage.ParseBackendKind(cfg.StorageBackend); kindErr == nil {
				notifier.Status(fmt.Sprintf("Opening the %s storage backend", kind))
			} else {
				notifier.Status("Opening the storage backend")
			}
			rt, err := resolveRuntimeForRole(ctx, cfg, role)
			if err != nil {
				return err
			}
			defer func() { _ = rt.Close() }()
			store := rt.Store
			if err := store.EnsureDirs(ctx); err != nil {
				return fmt.Errorf("failed to create CA directories: %w", err)
			}

			// Frontend-mode signer handshake: connect to the signer, then read
			// the CA cert through the storage service so an overlay-mounted
			// cert (e.g. a Kubernetes secret volume) is honoured. The PSK
			// handshake blocks until the signer finishes Init/bootstrap, so
			// store.GetCACert is guaranteed to succeed after it returns.
			if role == "frontend" {
				// This handshake blocks until the signer has finished
				// bootstrapping, which on a first run means waiting for a CA
				// key pair to be generated — worth saying out loud, since it
				// is the longest a cold start ever takes.
				notifier.Status("Waiting for the signer process to initialise the CA")
				conn, err := signer.DialConn()
				if err != nil {
					return fmt.Errorf("connecting to signer process: %w", err)
				}
				certPEM, err := store.GetCACert(ctx)
				if err != nil {
					conn.Close()
					return fmt.Errorf("reading CA cert for remote signer: %w", err)
				}
				block, _ := pem.Decode(certPEM)
				if block == nil {
					conn.Close()
					return fmt.Errorf("failed to decode CA cert PEM")
				}
				caCert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					conn.Close()
					return fmt.Errorf("parsing CA cert: %w", err)
				}
				rs := signer.NewRemoteSigner(conn, caCert.PublicKey)
				defer rs.Close()
				remoteSigner = rs
				slog.Info("Connected to isolated signer process")
			}

			// --- Autosign ---
			asCfg := ca.AutosignConfig{Mode: "off"}
			switch cfg.AutosignConfig {
			case "", "false":
				// leave as off
			case "true":
				asCfg.Mode = "true"
				// SECURITY: Warn that autosign=true bypasses all CSR validation.
				// Any node that submits a CSR will receive a signed certificate
				// without any verification. This should only be used in isolated
				// test environments.
				// NIST 800-53: IA-5 (Authenticator Management)
				slog.Warn("SECURITY: autosign is set to 'true' -- ALL certificate signing requests will be automatically signed without validation. " +
					"This is dangerous in production. Use an autosign script or file-based allowlist instead.")
			default:
				info, err := os.Stat(cfg.AutosignConfig)
				if err != nil {
					return fmt.Errorf("autosign config invalid (path %s): %w", cfg.AutosignConfig, err)
				}
				if info.Mode().IsRegular() {
					if info.Mode().Perm()&0111 != 0 {
						asCfg.Mode = "executable"
					} else {
						asCfg.Mode = "file"
					}
					asCfg.FileOrPath = cfg.AutosignConfig
				}
			}
			// SECURITY: Validate autosign executable integrity at startup.
			// Refuses to start if the executable is world-writable or not owned
			// by root/current user. Logs SHA-256 hash for change detection.
			// NIST 800-53: CM-5 (Access Restrictions for Change), SI-7 (Software, Firmware, and Information Integrity)
			if asCfg.Mode == "executable" {
				if err := validateAutosignExecutable(asCfg.FileOrPath); err != nil {
					return fmt.Errorf("autosign executable validation failed (path %s): %w", asCfg.FileOrPath, err)
				}
			}

			slog.Debug("Autosign config", "mode", asCfg.Mode, "path", asCfg.FileOrPath)

			// --- CA Initialisation ---
			myCA := ca.New(store, asCfg, cfg.Hostname)
			if err := applyCAConfig(myCA, cfg); err != nil {
				return err
			}
			warnIfSigningBoundIsCPUDerived(cfg, myCA.SigningConcurrency)

			// SECURITY: In frontend mode, use the remote signer: the CA private
			// key is never loaded into this process's address space.
			// NIST 800-53: SC-3 (Security Function Isolation)
			if remoteSigner != nil {
				myCA.ExternalSigner = remoteSigner
			} else if rt.KeyProvider != nil {
				// Single-process mode (--single-process) with an OpenBao key
				// provider: this is the one role, other than the isolated
				// signer child, that ever reaches the CA key -- and here that
				// "key" is a Transit key that never leaves OpenBao.
				myCA.KeyProvider = rt.KeyProvider
			}

			notifier.Status("Initialising the CA")
			if err := myCA.Init(ctx); err != nil {
				return fmt.Errorf("failed to initialise CA: %w", err)
			}

			// SECURITY: Warn if any private key files have overly permissive modes.
			// The server does not modify existing file permissions; operators should
			// fix these manually (e.g. chmod 0640 or stricter).
			// NIST 800-53: SC-12 (Cryptographic Key Establishment and Management)
			if warnings := store.CheckKeyPermissions(); len(warnings) > 0 {
				for _, w := range warnings {
					slog.Warn("Private key file has overly permissive mode",
						"path", w.Path, "mode", w.Mode.String(), "expected", "0600 or stricter")
				}
			}

			// --- HTTP(S) Server ---
			srv := api.New(myCA)

			// CSR rate limiting: an explicit 0 from any layer (flag/env/file)
			// disables it; the unset sentinel (-1) falls back to the default.
			srv.CSRRateLimit = resolveCSRRateLimit(cfg.CSRRateLimit)
			srv.SignBatchLimit = 50 // Default max batch size for sign operations
			srv.PlainHTTP = !tlsConfigured && !isLoopback(cfg.Host) && !cfg.NoTLSRequired
			srv.PuppetDateTimeFormat = cfg.PuppetDateTimeFormat

			// Wire mTLS auth middleware when TLS is configured.
			if cfg.TLSCert != "" && cfg.TLSKey != "" {
				// Every trust domain this CA will accept a client from: its own
				// first, then each client_ca entry. buildAuthConfig owns the
				// assembly so that what the middleware trusts is decided in one
				// place a spec can call, rather than inline here where nothing
				// can reach it.
				authCfg, err := buildAuthConfig(cfg, myCA)
				if err != nil {
					return err
				}
				srv.AuthConfig = authCfg
			}

			addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
			slog.Info("Listening", "address", addr)

			// --- Prometheus exporter ---
			// The exporter owns a private registry holding the Go/process
			// collectors, the CA/CRL/leaf certificate collector, and the HTTP
			// request metrics. When enabled, the API handler is instrumented so
			// puppetca_http_* counts requests to the Puppet API, while /metrics is
			// served on a separate listener (see metricsServer below).
			handler := srv.Routes()
			var exporter *metrics.Exporter
			if cfg.MetricsListen != "" {
				exporter = metrics.NewExporter(myCA)
				handler = exporter.InstrumentHandler(handler)
			}

			server := &http.Server{
				Addr:              addr,
				Handler:           handler,
				ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout:       30 * time.Second,
				WriteTimeout:      60 * time.Second,
				IdleTimeout:       120 * time.Second,
				MaxHeaderBytes:    1 << 20,
			}

			// Start the metrics exporter on its own listener. It runs over plain
			// HTTP regardless of the API's TLS configuration; operators should
			// bind it to loopback or a trusted management network. A bind failure
			// is logged but does not stop the CA from serving its primary API.
			var metricsServer *http.Server
			if exporter != nil {
				metricsServer = exporter.NewServer(cfg.MetricsListen)
				slog.Info("Prometheus metrics exporter enabled", "address", cfg.MetricsListen, "path", "/metrics")
				go func() {
					if err := metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
						slog.Error("Metrics exporter failed", "error", err)
					}
				}()
			}

			// certs holds the server's TLS keypair, or stays nil without TLS.
			// It is reachable by the reload handler below so a renewed server
			// certificate can be picked up without a restart.
			var certs *certReloader
			if cfg.TLSCert != "" && cfg.TLSKey != "" {
				certs, err = newCertReloader(cfg.TLSCert, cfg.TLSKey)
				if err != nil {
					return err
				}

				caCertPEM, err := myCA.Storage.GetCACert(ctx)
				if err != nil {
					return fmt.Errorf("failed to read CA cert for TLS: %w", err)
				}
				caPool, err := buildClientCAPool(caCertPEM, srv.AuthConfig)
				if err != nil {
					return err
				}

				// SECURITY: TLS server configuration with mTLS support.
				// RequestClientCert allows public endpoints to work without a
				// client cert while the auth middleware enforces cert requirements
				// per-tier. MinVersion TLS 1.2 blocks legacy protocol downgrades.
				// The certificate comes from a callback rather than a fixed
				// list so it can be replaced on reload when it is renewed.
				// NIST 800-53: SC-8 (Transmission Confidentiality and Integrity),
				//              SC-23 (Session Authenticity), IA-3 (Device Identification)
				server.TLSConfig = &tls.Config{
					GetCertificate: certs.GetCertificate,
					ClientCAs:      caPool,
					ClientAuth:     tls.RequestClientCert,
					MinVersion:     tls.VersionTLS12,
				}

				slog.Info("TLS enabled", "cert", cfg.TLSCert)
			}

			// Foreign client CRLs reload on their own timer, gated on client_ca
			// alone: an operator trusting a foreign issuer need not be running
			// anything else. Anchors deliberately do not reload — see
			// refreshClientCRLs. Started here rather than in backgroundJobs
			// because it needs the trust domains the auth config holds, the
			// same reason the Kubernetes exporter is started here.
			if cfg.ClientCAConfig.Enabled() && srv.AuthConfig != nil {
				var crlMetrics *clientCRLMetrics
				if exporter != nil {
					crlMetrics = newClientCRLMetrics(exporter.Registry())
				}
				// Publish puppetca_client_crl_usable before serving. The sets
				// themselves are already installed by buildTrustDomains, so this
				// is not about the first request -- it is that `== 0` cannot fire
				// on a series that does not exist, so a domain whose CRLs are
				// unusable from the very first load would otherwise go unalerted
				// until the first refresh tick.
				refreshClientCRLs(cfg, srv.AuthConfig.Domains, crlMetrics)
				// A refusal is the one unambiguous statement that clients are
				// being turned away for want of a CRL; load-time coverage can
				// only estimate it. Wired here because the api package holds no
				// metrics dependency.
				srv.AuthConfig.OnRevocationRefusal = crlMetrics.recordRefusal
				go runClientCRLReloader(ctx, cfg, srv.AuthConfig.Domains, crlMetrics,
					cfg.ClientCRLRefreshInterval())
			}

			// Periodic upkeep. Which jobs a configuration runs is decided by
			// backgroundJobs, so that it can be asserted rather than inferred
			// from the shape of this block; each is bound to ctx and stops on
			// shutdown.
			for _, job := range backgroundJobs(cfg, myCA) {
				go job.run(ctx)
			}

			// Optional Kubernetes export: publish the CA cert/CRL into the
			// configured Secrets/ConfigMaps. An invalid config block is rejected at
			// startup (fail-fast, as for StorageConfig); once past validation the
			// export is auxiliary — a client-init failure or a per-cycle export
			// error is logged but never stops the CA from serving. Bound to ctx so
			// it stops on shutdown. Each replica runs its own exporter; server-side
			// apply makes concurrent writes from multiple replicas idempotent.
			if cfg.KubernetesExport.Enabled() {
				if err := cfg.KubernetesExport.Validate(); err != nil {
					return fmt.Errorf("invalid kubernetes_export config: %w", err)
				}
				// Instrument the export only when the Prometheus exporter is
				// enabled; a nil Metrics disables recording.
				var k8sMetrics *k8sexport.Metrics
				if exporter != nil {
					k8sMetrics = k8sexport.NewMetrics(exporter.Registry())
				}
				startK8sExport(ctx, myCA, cfg.KubernetesExport, k8sMetrics,
					func() (*k8sexport.Exporter, error) {
						return k8sexport.NewInCluster(cfg.KubernetesExport, store, k8sMetrics)
					})
			}

			shutdownDone := make(chan struct{})
			go func() {
				<-ctx.Done()
				drain := cfg.shutdownDrain()
				slog.Info("Shutting down")
				// Tell the service manager this is a deliberate teardown, not
				// a crash, and how long it may take — so it waits for the
				// drain instead of killing connections mid-flight.
				notifier.Stopping(fmt.Sprintf("Shutting down: draining connections (up to %s)", drain))
				shutdownCtx, cancel := context.WithTimeout(context.Background(), drain)
				defer cancel()
				if metricsServer != nil {
					if err := metricsServer.Shutdown(shutdownCtx); err != nil {
						slog.Warn("Metrics exporter shutdown error", "error", err)
					}
				}
				if err := server.Shutdown(shutdownCtx); err != nil {
					slog.Warn("HTTP server shutdown error", "error", err)
				}
				close(shutdownDone)
			}()

			// Bind the listener explicitly rather than letting ListenAndServe
			// do it, so readiness can be announced at the point the socket is
			// actually accepting connections. Anything ordered after this
			// service can then connect on its first attempt.
			notifier.Status("Starting the HTTP server")
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				return fmt.Errorf("failed to listen on %s: %w", addr, err)
			}

			// SIGHUP re-reads the file-backed configuration: the TLS keypair
			// (so a renewed server certificate does not need a restart) and
			// the admin allow list.
			reloader := &configReloader{
				certs:     certs,
				auth:      srv.AuthConfig,
				staticCNs: cfg.PuppetServer,
				cnFile:    cfg.PuppetServerFile,
			}

			status := func() string {
				return newStatusReport(myCA, addr, tlsConfigured).line(time.Now()) + reloader.statusSuffix()
			}
			notifier.Ready(status())

			// Both jobs are bound to ctx, so they stop on shutdown.
			go runNotifyHeartbeat(ctx, notifier, heartbeatInterval(notifier), status)
			go runReloadWatcher(ctx, hupCh, notifier, reloader, status)

			var serveErr error
			if cfg.TLSCert != "" && cfg.TLSKey != "" {
				serveErr = server.ServeTLS(ln, "", "")
			} else {
				serveErr = server.Serve(ln)
			}
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				return fmt.Errorf("server failed: %w", serveErr)
			}
			<-shutdownDone
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&configFile, "config", "", "Path to YAML config file (default: /etc/puppet-ca/config.yaml if it exists)")
	f.StringVar(&caDir, "cadir", "", "Directory for CA storage (or set PUPPET_CA_CADIR)")
	f.StringVar(&autosignVal, "autosign-config", "", "Autosign configuration: 'true', 'false', or path to file/executable")
	f.StringVar(&host, "host", "0.0.0.0", "Address to listen on")
	f.IntVar(&port, "port", 8140, "Port to listen on")
	f.StringVar(&hostname, "hostname", "", "Hostname for the CA certificate CN (e.g. puppet.example.com)")
	f.BoolVar(&daemon, "daemon", false, "Run in background as a daemon (not recommended in containers)")
	f.IntVarP(&verbosity, "verbosity", "v", 0, "Verbosity: 0=Info 1=Debug 2=Trace")
	f.StringVar(&logFile, "logfile", "", "Log to file instead of stderr (implies daemon log destination)")
	f.StringVar(&tlsCert, "tls-cert", "", "Path to TLS server certificate PEM (enables HTTPS)")
	f.StringVar(&tlsKey, "tls-key", "", "Path to TLS server private key PEM (enables HTTPS)")
	f.StringVar(&puppetServers, "puppet-server", "", "Comma-separated list of puppet-server CNs allowed admin access")
	f.StringVar(&puppetServerFile, "puppet-server-file", "", "Path to a file of puppet-server CNs allowed admin access (one per line; # comments and blank lines ignored)")
	f.BoolVar(&noPpCliAuth, "no-pp-cli-auth", false, "Disable pp_cli_auth extension as an admin credential; require CN allow list only")
	f.StringVar(&clientRevocationPolicy, "client-revocation-policy", "", "Revocation checking for client_ca domains: require (default), check, or skip. Our own CA always checks its own CRL")
	f.BoolVar(&noTLSRequired, "no-tls-required", false, "Allow plain HTTP on non-loopback addresses (use only behind a trusted TLS proxy or in test environments)")
	f.BoolVar(&allowPublicStatus, "allow-public-status", false, "Allow unauthenticated GET /certificate_status (by default this route is admin-only)")
	f.StringVar(&ocspURL, "ocsp-url", "", "OCSP responder URL to embed in issued certificates (e.g. http://openvox-ca:8140/ocsp)")
	f.StringVar(&crlURL, "crl-url", "", "CRL distribution point URL to embed in issued certificates (e.g. http://openvox-ca:8140/puppet-ca/v1/certificate_revocation_list/ca)")
	f.StringVar(&metricsListen, "metrics-listen", "", "Address for the Prometheus metrics exporter (e.g. 127.0.0.1:9140 or :9140); empty disables it. Serves /metrics over plain HTTP on a separate listener; restrict to a trusted network as it reveals node hostnames")
	f.IntVar(&csrRateLimit, "csr-rate-limit", -1, "Max CSR submissions per IP per minute on the public PUT /certificate_request endpoint (0 disables; unset uses the default of 60)")
	f.IntVar(&caSigningConcurrency, "ca-signing-concurrency", -1, "Max concurrent CA-key signatures across issuance, CRL re-signing and the OCSP responder (0 disables the bound; unset uses max(4, GOMAXPROCS)). Lower it to a remote signer's capacity")
	f.BoolVar(&encryptCAKey, "encrypt-ca-key", false, "Encrypt the CA private key at rest (AES-256-GCM + Argon2id); a passphrase is auto-generated if not provided")
	f.StringVar(&caKeyPassphraseFile, "ca-key-passphrase-file", "", "Path to file containing the CA key passphrase (first line used)")
	f.BoolVar(&singleProcess, "single-process", false, "Disable CA key isolation (run signer and frontend in a single process)")
	f.StringVar(&storageBackend, "storage-backend", "", "Storage backend: 'filesystem' (default), 'etcd', 'redis' (alias 'valkey'), 'sqlite', 'postgres', or 'mysql' (alias 'mariadb')")
	f.StringSliceVar(&etcdEndpoints, "etcd-endpoints", nil, "Comma-separated etcd cluster endpoints (e.g. https://etcd1:2379,https://etcd2:2379)")
	f.StringVar(&etcdKeyPrefix, "etcd-key-prefix", "", "etcd key namespace for this CA (default: /puppet-ca)")
	f.StringSliceVar(&redisAddrs, "redis-addrs", nil, "Comma-separated Redis/Valkey addresses for direct connections (e.g. redis-0:6379)")
	f.StringVar(&redisSentinelMasterName, "redis-sentinel-master-name", "", "Redis Sentinel primary name; set to enable Sentinel-managed failover")
	f.StringSliceVar(&redisSentinelAddrs, "redis-sentinel-addrs", nil, "Comma-separated Redis Sentinel addresses (e.g. sentinel-0:26379,sentinel-1:26379)")
	f.StringVar(&redisKeyPrefix, "redis-key-prefix", "", "Redis key namespace for this CA (default: puppet-ca)")
	f.StringVar(&sqlDSN, "sql-dsn", "", "SQL data source name (SQLite 'file:/var/lib/puppet-ca/ca.db', PostgreSQL 'postgres://user:pass@host:5432/db?sslmode=require', or MySQL 'user:pass@tcp(host:3306)/db')")
	f.StringVar(&caCertFile, "ca-cert-file", "", "Keep the CA certificate at this local path regardless of storage backend")
	f.StringVar(&caKeyFile, "ca-key-file", "", "Keep the CA private key at this local path regardless of storage backend")
	registerOpenBaoFlags(f, &obFlags)

	// Offline subcommands. Cobra dispatches a known subcommand before applying
	// the root command's Args validator, so bare "openvox-ca" still means "run
	// the server" and cobra.NoArgs above still rejects stray arguments.
	cmd.AddCommand(newCSRCmd())
	cmd.AddCommand(newImportCACertCmd())
	cmd.AddCommand(newGenerateCmd())
	cmd.AddCommand(newRebuildInventoryHMACCmd())

	return cmd
}

// openBaoFlagValues holds the string targets for the --ca-key-provider and
// --openbao-* flags. Grouped so registerOpenBaoFlags and
// applyOpenBaoFlagOverrides can be exercised by a unit test independently of
// the full server startup in newRootCmd's RunE.
type openBaoFlagValues struct {
	caKeyProvider       string
	addr                string
	transitMount        string
	keyName             string
	tlsCAFile           string
	tlsCertFile         string
	tlsKeyFile          string
	authMethod          string
	appRoleMount        string
	appRoleRoleID       string
	appRoleRoleIDFile   string
	appRoleSecretIDFile string
	tokenFile           string
	k8sMount            string
	k8sRole             string
	k8sJWTFile          string
}

// registerOpenBaoFlags registers the --ca-key-provider and --openbao-* flags
// on f, binding them to v.
func registerOpenBaoFlags(f *pflag.FlagSet, v *openBaoFlagValues) {
	f.StringVar(&v.caKeyProvider, "ca-key-provider", "", "CA private key custody: 'file' (default) or 'openbao' (delegate key custody and signing to an OpenBao Transit key)")
	f.StringVar(&v.addr, "openbao-addr", "", "OpenBao server address as a full URI including scheme and port, e.g. https://openbao.example.com:8200 (http:// also accepted); used when --ca-key-provider openbao")
	f.StringVar(&v.transitMount, "openbao-transit-mount", "", "OpenBao Transit secrets engine mount path (default 'transit')")
	f.StringVar(&v.keyName, "openbao-key-name", "", "Name of the OpenBao Transit key backing the CA's private key")
	f.StringVar(&v.tlsCAFile, "openbao-tls-ca-file", "", "PEM CA bundle to verify the OpenBao server's certificate")
	f.StringVar(&v.tlsCertFile, "openbao-tls-cert-file", "", "Client certificate PEM for mTLS to OpenBao")
	f.StringVar(&v.tlsKeyFile, "openbao-tls-key-file", "", "Client private key PEM for mTLS to OpenBao")
	f.StringVar(&v.authMethod, "openbao-auth-method", "", "OpenBao auth method: 'approle', 'token', or 'kubernetes' (required when --ca-key-provider openbao; no default)")
	f.StringVar(&v.appRoleMount, "openbao-approle-mount", "", "AppRole auth method mount path (default 'approle')")
	f.StringVar(&v.appRoleRoleID, "openbao-approle-role-id", "", "AppRole role_id (or use --openbao-approle-role-id-file)")
	f.StringVar(&v.appRoleRoleIDFile, "openbao-approle-role-id-file", "", "Path to a file containing the AppRole role_id, read fresh on every login")
	f.StringVar(&v.appRoleSecretIDFile, "openbao-approle-secret-id-file", "", "Path to a file containing the AppRole secret_id, read fresh on every login")
	f.StringVar(&v.tokenFile, "openbao-token-file", "", "Path to a file containing a pre-issued OpenBao token (auth method 'token')")
	f.StringVar(&v.k8sMount, "openbao-kubernetes-mount", "", "Kubernetes auth method mount path (default 'kubernetes')")
	f.StringVar(&v.k8sRole, "openbao-kubernetes-role", "", "OpenBao Kubernetes auth role name")
	f.StringVar(&v.k8sJWTFile, "openbao-kubernetes-jwt-file", "", "Path to the projected ServiceAccount token (default: the standard in-cluster path), read fresh on every login")
}

// applyOpenBaoFlagOverrides overlays each explicitly-set (Changed) flag in v
// onto the matching cfg field. Only flags the operator actually passed take
// effect, preserving any value already resolved from the config file or the
// environment.
func applyOpenBaoFlagOverrides(cmd *cobra.Command, cfg *serverConfig, v *openBaoFlagValues) {
	set := func(flag string, apply func()) {
		if cmd.Flags().Changed(flag) {
			apply()
		}
	}
	set("ca-key-provider", func() { cfg.CAKeyProvider = v.caKeyProvider })
	set("openbao-addr", func() { cfg.OpenBao.Addr = v.addr })
	set("openbao-transit-mount", func() { cfg.OpenBao.TransitMount = v.transitMount })
	set("openbao-key-name", func() { cfg.OpenBao.KeyName = v.keyName })
	set("openbao-tls-ca-file", func() { cfg.OpenBao.TLSCAFile = v.tlsCAFile })
	set("openbao-tls-cert-file", func() { cfg.OpenBao.TLSCertFile = v.tlsCertFile })
	set("openbao-tls-key-file", func() { cfg.OpenBao.TLSKeyFile = v.tlsKeyFile })
	set("openbao-auth-method", func() { cfg.OpenBao.AuthMethod = v.authMethod })
	set("openbao-approle-mount", func() { cfg.OpenBao.AppRoleMount = v.appRoleMount })
	set("openbao-approle-role-id", func() { cfg.OpenBao.AppRoleRoleID = v.appRoleRoleID })
	set("openbao-approle-role-id-file", func() { cfg.OpenBao.AppRoleRoleIDFile = v.appRoleRoleIDFile })
	set("openbao-approle-secret-id-file", func() { cfg.OpenBao.AppRoleSecretIDFile = v.appRoleSecretIDFile })
	set("openbao-token-file", func() { cfg.OpenBao.TokenFile = v.tokenFile })
	set("openbao-kubernetes-mount", func() { cfg.OpenBao.KubernetesMount = v.k8sMount })
	set("openbao-kubernetes-role", func() { cfg.OpenBao.KubernetesRole = v.k8sRole })
	set("openbao-kubernetes-jwt-file", func() { cfg.OpenBao.KubernetesJWTFile = v.k8sJWTFile })
}

// ignoreReloadSignal makes this process immune to SIGHUP.
//
// The signer holds no reloadable configuration, but SIGHUP's default action is
// to terminate. Ignoring it means a reload signal delivered to the process
// group (rather than to the launcher alone) cannot take the CA key holder down
// and force a full restart.
//
// A function rather than a bare call inside runSignerMode so a spec can drive
// it: runSignerMode needs storage, a CA directory and a socketpair peer before
// it reaches this line, which is why the disposition went unasserted.
func ignoreReloadSignal() {
	signal.Ignore(syscall.SIGHUP)
}

// runSignerMode runs the isolated CA key signer process. It initializes the CA
// (bootstrapping on first run), then serves signing requests over the inherited
// socketpair fd. The signer has no network exposure; it only communicates with
// the frontend via the pre-connected Unix socketpair.
//
// IMPORTANT: The signer calls Init() which handles bootstrapping. The PSK
// handshake in signer.Serve() happens AFTER Init completes, so the frontend
// can safely read the CA cert from disk once the handshake succeeds.
func runSignerMode(ctx context.Context, cfg *serverConfig, absCADir string) error {
	logFile, err := setupLogger(cfg)
	if err != nil {
		// Signer: fall back to stderr if log file fails.
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
		slog.Warn("Failed to open log file, using stderr", "error", err)
	}
	if logFile != nil {
		defer func() {
			// Report on stderr, not slog: the default logger writes to this
			// very file, which is being closed here.
			if cerr := logFile.Close(); cerr != nil {
				fmt.Fprintf(os.Stderr, "failed to close log file: %v\n", cerr)
			}
		}()
	}

	ignoreReloadSignal()

	slog.Info("Starting CA signer process",
		"cadir", absCADir,
		"pid", os.Getpid(),
	)

	// The signer role always holds the CA key, so it resolves its runtime with
	// the key provider enabled.
	//
	// SECURITY: when an OpenBao provider is configured the CA's own private key
	// is never loaded here at all -- it lives in the Transit engine, and only a
	// digest ever crosses the wire to sign it. That is the same security
	// posture class as the local-key case (key confined to this isolated
	// process), extended one step further: the key doesn't exist in this
	// process either.
	rt, err := resolveRuntime(ctx, cfg, true)
	if err != nil {
		return err
	}
	defer func() { _ = rt.Close() }()

	// Full CA initialization: handles bootstrap on first run, loads existing
	// CA on subsequent runs. This writes ca_crt.pem, CRL, inventory, etc.
	myCA := ca.New(rt.Store, ca.AutosignConfig{}, cfg.Hostname)
	if err := applyCAConfig(myCA, cfg); err != nil {
		return err
	}
	myCA.KeyProvider = rt.KeyProvider

	if err := myCA.Init(ctx); err != nil {
		return fmt.Errorf("CA initialization failed: %w", err)
	}

	slog.Info("CA initialized, serving signing requests")
	return signer.Serve(myCA.CAKey)
}

// validateAutosignExecutable checks the integrity of an autosign executable:
//  1. Resolves symlinks to the real path
//  2. Verifies the file is not world-writable (mode & 0002)
//  3. Verifies the file is owned by root (uid 0) or the current process user
//  4. Logs the SHA-256 hash for change detection
func validateAutosignExecutable(path string) error {
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("resolving symlinks for %s: %w", path, err)
	}
	if realPath != path {
		slog.Info("Autosign executable symlink resolved", "path", path, "realpath", realPath)
	}

	info, err := os.Stat(realPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", realPath, err)
	}

	// Check world-writable bit.
	if info.Mode().Perm()&0002 != 0 {
		return fmt.Errorf("autosign executable %s is world-writable (mode %s); "+
			"refusing to start -- fix with: chmod o-w %s", realPath, info.Mode().Perm(), realPath)
	}

	// Check file ownership: must be owned by root or the current user.
	stat, ok := info.Sys().(*syscall.Stat_t)
	if ok {
		currentUID := uint32(os.Getuid()) //nolint:gosec // G115: Linux getuid() returns a valid uid_t that always fits uint32
		if stat.Uid != 0 && stat.Uid != currentUID {
			return fmt.Errorf("autosign executable %s is owned by uid %d (expected root or current user uid %d); "+
				"refusing to start", realPath, stat.Uid, currentUID)
		}
	}

	// Compute and log SHA-256 hash.
	data, err := os.ReadFile(realPath)
	if err != nil {
		return fmt.Errorf("reading %s for hash: %w", realPath, err)
	}
	hash := sha256.Sum256(data)
	slog.Info("Autosign executable configured",
		"path", realPath,
		"sha256", hex.EncodeToString(hash[:]),
		"mode", info.Mode().Perm().String(),
	)
	return nil
}
