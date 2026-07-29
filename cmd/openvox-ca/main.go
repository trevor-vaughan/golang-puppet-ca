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
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/voxpupuli/openvox-ca/internal/api"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/k8sexport"
	"github.com/voxpupuli/openvox-ca/internal/metrics"
	"github.com/voxpupuli/openvox-ca/internal/signer"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/version"
)

// setupLogger creates and sets the default slog logger based on config.
// Returns the log file (if any) so the caller can close it on shutdown,
// ensuring final log entries are flushed. Returns nil when logging to stderr.
func setupLogger(cfg *serverConfig) (*os.File, error) {
	var logLevel slog.Level
	switch cfg.Verbosity {
	case 0:
		logLevel = slog.LevelInfo
	case 1:
		logLevel = slog.LevelDebug
	default:
		logLevel = slog.Level(-8) // Trace
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
	allowList := map[string]bool{}
	for _, cn := range splitAndTrim(cfg.PuppetServer, ",") {
		allowList[cn] = true
	}
	fileCNs, err := loadPuppetServerFile(cfg.PuppetServerFile)
	if err != nil {
		return nil, err
	}
	for _, cn := range fileCNs {
		allowList[cn] = true
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

	return &api.AuthConfig{
		CACert:            myCA.CACert,
		AllowList:         allowList,
		NoPpCliAuth:       cfg.NoPpCliAuth,
		AllowPublicStatus: cfg.AllowPublicStatus,
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
		tlsSelfProvision        bool
		tlsSelfProvisionNames   []string
		puppetServers           string
		puppetServerFile        string
		noPpCliAuth             bool
		noTLSRequired           bool
		allowPublicStatus       bool
		ocspURL                 string
		crlURL                  string
		metricsListen           string
		csrRateLimit            int
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
			if cmd.Flags().Changed("tls-self-provision") {
				cfg.TLSSelfProvision = tlsSelfProvision
			}
			if cmd.Flags().Changed("tls-self-provision-names") {
				cfg.TLSSelfProvisionNames = tlsSelfProvisionNames
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
				exe, err := os.Executable()
				if err != nil {
					return fmt.Errorf("failed to determine executable: %w", err)
				}
				c := exec.Command(exe, os.Args[1:]...) //nolint:gosec // G204: re-execs this same binary (os.Executable) with the operator's own os.Args to daemonize
				// Strip internal role/PSK vars to prevent stale values from a
				// previous run from confusing the daemon child.
				daemonEnv := filterEnv(os.Environ(), "PUPPET_CA_ROLE", "PUPPET_CA_DAEMON", "PUPPET_CA_SIGNER_PSK")
				c.Env = append(daemonEnv, "PUPPET_CA_DAEMON=1")
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

			// Signer mode: load key, serve signing requests on socketpair, exit.
			if role == "signer" {
				return runSignerMode(ctx, cfg, absCADir)
			}

			// Launcher mode (default): spawn isolated signer + frontend children.
			if role == "" && !singleProcess {
				return runLauncher(cfg.shutdownDrain())
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
			//   (a) TLS is configured (--tls-cert + --tls-key, or
			//       tls_self_provision), or
			//   (b) the bind address is loopback-only, or
			//   (c) the operator explicitly opts out with --no-tls-required.
			// NIST 800-53: SC-8 (Transmission Confidentiality and Integrity), SC-23 (Session Authenticity)
			if err := cfg.validateTLS(); err != nil {
				return err
			}
			tlsConfigured := cfg.tlsEnabled()
			if !tlsConfigured {
				if !isLoopback(cfg.Host) && !cfg.NoTLSRequired {
					return errors.New("refusing to start: plain HTTP on a non-loopback address is vulnerable to certificate injection; enable TLS (--tls-cert/--tls-key), let the CA issue its own certificate (--tls-self-provision), restrict to loopback (--host 127.0.0.1), or set --no-tls-required")
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

			// --- Storage & Directories ---
			backendSpec, err := buildBackendSpec(cfg, absCADir)
			if err != nil {
				return fmt.Errorf("invalid storage backend config: %w", err)
			}
			store, err := storage.NewServiceFromSpec(backendSpec)
			if err != nil {
				return fmt.Errorf("failed to initialise storage backend: %w", err)
			}
			defer func() { _ = store.Backend().Close() }()
			if err := store.EnsureDirs(ctx); err != nil {
				return fmt.Errorf("failed to create CA directories: %w", err)
			}

			// Frontend-mode signer handshake: connect to the signer, then read
			// the CA cert through the storage service so an overlay-mounted
			// cert (e.g. a Kubernetes secret volume) is honoured. The PSK
			// handshake blocks until the signer finishes Init/bootstrap, so
			// store.GetCACert is guaranteed to succeed after it returns.
			if role == "frontend" {
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

			// SECURITY: In frontend mode, use the remote signer: the CA private
			// key is never loaded into this process's address space.
			// NIST 800-53: SC-3 (Security Function Isolation)
			if remoteSigner != nil {
				myCA.ExternalSigner = remoteSigner
			} else if cfg.UsesOpenBao() {
				// Single-process mode (--single-process) with an OpenBao key
				// provider: this is the one role, other than the isolated
				// signer child, that ever reaches the CA key -- and here that
				// "key" is a Transit key that never leaves OpenBao.
				tm, provider, err := newOpenBaoKeyProvider(ctx, cfg)
				if err != nil {
					return fmt.Errorf("initialising OpenBao key provider: %w", err)
				}
				defer func() { _ = tm.Close() }()
				myCA.KeyProvider = provider
			}

			if err := myCA.Init(ctx); err != nil {
				return fmt.Errorf("failed to initialise CA: %w", err)
			}

			// Reconcile pending serving-certificate revocations before the
			// listener opens, and deliberately without regard to whether
			// tls_self_provision is on.
			//
			// Startup is the only moment a process reliably observes a
			// configuration change, and with self-provisioning switched off no
			// periodic task runs at all — so entries a previous configuration
			// recorded would otherwise sit in storage indefinitely and fire much
			// later if the delay were re-enabled. A failure here is logged and
			// not fatal: it is bookkeeping, and the CA can still serve.
			if err := myCA.ReconcileSuperseded(ctx, time.Duration(cfg.TLSSelfProvisionRevokeAfterSec)*time.Second); err != nil {
				slog.Warn("Could not reconcile superseded serving certificates at startup", "error", err)
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

			// Wire mTLS auth middleware when TLS is configured. Leaving
			// srv.AuthConfig nil disables the authorisation middleware for every
			// route, so this branch and cfg.tlsEnabled() must never disagree.
			if tlsConfigured {
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
			// Tasks for the shared maintenance loop. Collected as the features
			// that need them are wired up, and the loop is started below only if
			// something registered. Each task is gated by its own feature, never
			// by another's — see runMaintenance.
			var maintenanceTasks []maintenanceTask

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

			if tlsConfigured {
				// The serving certificate comes either from disk or from the CA
				// itself. Both routes end at the same holder, so GetCertificate
				// is the only path the TLS stack ever takes and self-provisioned
				// rotation needs no special case in the handshake.
				servingCerts := &servingCertHolder{}
				if cfg.TLSSelfProvision {
					// Fatal on failure: a server with no serving certificate
					// cannot serve, and failing fast beats a listener that never
					// opens. On the maintenance cycle the same failure is not
					// fatal, because there is a certificate already in place.
					if err := ensureServingCert(ctx, myCA, cfg, servingCerts); err != nil {
						return err
					}
				} else {
					serverCert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
					if err != nil {
						return fmt.Errorf("failed to load TLS cert/key (cert %s, key %s): %w", cfg.TLSCert, cfg.TLSKey, err)
					}
					servingCerts.Set(&serverCert)
				}

				caCertPEM, err := myCA.Storage.GetCACert(ctx)
				if err != nil {
					return fmt.Errorf("failed to read CA cert for TLS: %w", err)
				}
				caPool := x509.NewCertPool()
				block, _ := pem.Decode(caCertPEM)
				if block != nil {
					if caCert, err := x509.ParseCertificate(block.Bytes); err == nil {
						caPool.AddCert(caCert)
					}
				}

				// SECURITY: TLS server configuration with mTLS support.
				// RequestClientCert allows public endpoints to work without a
				// client cert while the auth middleware enforces cert requirements
				// per-tier. MinVersion TLS 1.2 blocks legacy protocol downgrades.
				// NIST 800-53: SC-8 (Transmission Confidentiality and Integrity),
				//              SC-23 (Session Authenticity), IA-3 (Device Identification)
				//
				// GetCertificate rather than Certificates: it is consulted per
				// handshake, so a renewed serving certificate takes effect on the
				// next connection with no restart.
				server.TLSConfig = &tls.Config{
					GetCertificate: servingCerts.GetCertificate,
					ClientCAs:      caPool,
					ClientAuth:     tls.RequestClientCert,
					MinVersion:     tls.VersionTLS12,
				}

				if cfg.TLSSelfProvision {
					slog.Info("TLS enabled", "certificate", "self-provisioned", "subject", cfg.Hostname)
					maintenanceTasks = append(maintenanceTasks,
						servingRenewalTask(myCA, cfg, servingCerts),
						supersededRevocationTask(myCA, cfg))
				} else {
					slog.Info("TLS enabled", "cert", cfg.TLSCert)
				}
			}

			// Background CRL refresh: keeps the CRL's NextUpdate from lapsing on a
			// low-churn CA. Safe on every replica (serialised on the shared CRL
			// lock). Bound to ctx so it stops on shutdown.
			if !cfg.DisableCRLRefresh {
				refreshBefore := myCA.DefaultCRLRefreshBefore()
				if cfg.CRLRefreshBeforeSec > 0 {
					refreshBefore = time.Duration(cfg.CRLRefreshBeforeSec) * time.Second
				}
				go runCRLRefresher(ctx, myCA, cfg.crlRefreshInterval(), refreshBefore)
			} else {
				slog.Info("CRL auto-refresh disabled by configuration")
			}

			// Shared maintenance loop. Bound to ctx so it stops on shutdown.
			if len(maintenanceTasks) > 0 {
				go runMaintenance(ctx, cfg.maintenanceInterval(), maintenanceTasks)
			}

			// Background expired-certificate cleanup (opt-in): prunes certs that
			// expired more than the retention grace period ago from the inventory
			// and CRL. Safe on every replica (serialised on the shared CRL lock).
			// Bound to ctx so it stops on shutdown.
			if cfg.EnableExpiredCertCleanup {
				go runCertCleaner(ctx, myCA, cfg.expiredCertCleanupInterval(), cfg.expiredCertRetention())
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
				k8sExporter, err := k8sexport.NewInCluster(cfg.KubernetesExport, store, k8sMetrics)
				if err != nil {
					slog.Error("Kubernetes export disabled: failed to initialise client", "error", err)
				} else {
					go runK8sExporter(ctx, myCA, k8sExporter)
				}
			}

			shutdownDone := make(chan struct{})
			go func() {
				<-ctx.Done()
				slog.Info("Shutting down")
				shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.shutdownDrain())
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

			var serveErr error
			if tlsConfigured {
				serveErr = server.ListenAndServeTLS("", "")
			} else {
				serveErr = server.ListenAndServe()
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
	f.BoolVar(&tlsSelfProvision, "tls-self-provision", false,
		"Let the CA issue and renew its own serving certificate (enables HTTPS; requires --hostname, excludes --tls-cert/--tls-key)")
	f.StringSliceVar(&tlsSelfProvisionNames, "tls-self-provision-names", nil,
		"Extra DNS names for the self-provisioned serving certificate, beyond --hostname")
	f.StringVar(&puppetServers, "puppet-server", "", "Comma-separated list of puppet-server CNs allowed admin access")
	f.StringVar(&puppetServerFile, "puppet-server-file", "", "Path to a file of puppet-server CNs allowed admin access (one per line; # comments and blank lines ignored)")
	f.BoolVar(&noPpCliAuth, "no-pp-cli-auth", false, "Disable pp_cli_auth extension as an admin credential; require CN allow list only")
	f.BoolVar(&noTLSRequired, "no-tls-required", false, "Allow plain HTTP on non-loopback addresses (use only behind a trusted TLS proxy or in test environments)")
	f.BoolVar(&allowPublicStatus, "allow-public-status", false, "Allow unauthenticated GET /certificate_status (by default, requires a CA-signed client cert)")
	f.StringVar(&ocspURL, "ocsp-url", "", "OCSP responder URL to embed in issued certificates (e.g. http://openvox-ca:8140/ocsp)")
	f.StringVar(&crlURL, "crl-url", "", "CRL distribution point URL to embed in issued certificates (e.g. http://openvox-ca:8140/puppet-ca/v1/certificate_revocation_list/ca)")
	f.StringVar(&metricsListen, "metrics-listen", "", "Address for the Prometheus metrics exporter (e.g. 127.0.0.1:9140 or :9140); empty disables it. Serves /metrics over plain HTTP on a separate listener; restrict to a trusted network as it reveals node hostnames")
	f.IntVar(&csrRateLimit, "csr-rate-limit", -1, "Max CSR submissions per IP per minute on the public PUT /certificate_request endpoint (0 disables; unset uses the default of 60)")
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

	slog.Info("Starting CA signer process",
		"cadir", absCADir,
		"pid", os.Getpid(),
	)

	backendSpec, err := buildBackendSpec(cfg, absCADir)
	if err != nil {
		return fmt.Errorf("invalid storage backend config: %w", err)
	}
	store, err := storage.NewServiceFromSpec(backendSpec)
	if err != nil {
		return fmt.Errorf("initialising storage backend: %w", err)
	}
	defer func() { _ = store.Backend().Close() }()

	// Full CA initialization: handles bootstrap on first run, loads existing
	// CA on subsequent runs. This writes ca_crt.pem, CRL, inventory, etc.
	myCA := ca.New(store, ca.AutosignConfig{}, cfg.Hostname)
	if err := applyCAConfig(myCA, cfg); err != nil {
		return err
	}

	// SECURITY: when configured, the CA's own private key is never loaded
	// here at all -- it lives in OpenBao's Transit engine, and only a digest
	// ever crosses the wire to sign it. This is the same security posture
	// class as the local-key case (key confined to this isolated process),
	// extended one step further: the key doesn't exist in this process
	// either.
	if cfg.UsesOpenBao() {
		tm, provider, err := newOpenBaoKeyProvider(ctx, cfg)
		if err != nil {
			return fmt.Errorf("initialising OpenBao key provider: %w", err)
		}
		defer func() { _ = tm.Close() }()
		myCA.KeyProvider = provider
	}

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
