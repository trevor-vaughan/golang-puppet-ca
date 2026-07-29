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
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/config"
	"github.com/voxpupuli/openvox-ca/internal/k8sexport"
	"go.yaml.in/yaml/v3"
)

// serverConfig holds all configuration for the openvox-ca server.
// Fields are populated from (lowest → highest priority):
//
//	built-in defaults → config file → env vars → CLI flags
type serverConfig struct {
	CADir             string `yaml:"cadir"`
	AutosignConfig    string `yaml:"autosign_config"`
	Host              string `yaml:"host"`
	Port              int    `yaml:"port"`
	Hostname          string `yaml:"hostname"`
	Verbosity         int    `yaml:"verbosity"`
	LogFile           string `yaml:"logfile"`
	TLSCert           string `yaml:"tls_cert"`
	TLSKey            string `yaml:"tls_key"`
	PuppetServer      string `yaml:"puppet_server"`
	PuppetServerFile  string `yaml:"puppet_server_file"`
	NoPpCliAuth       bool   `yaml:"no_pp_cli_auth"`
	NoTLSRequired     bool   `yaml:"no_tls_required"`
	AllowPublicStatus bool   `yaml:"allow_public_status"`
	OCSPUrl           string `yaml:"ocsp_url"`
	CRLUrl            string `yaml:"crl_url"`

	// TLSSelfProvision makes the CA issue its own serving certificate from its
	// own CA key and serve it from memory, instead of loading tls_cert/tls_key
	// from disk. It exists for deployments where nothing else can issue that
	// certificate: with the CA key at a provider, cert-manager cannot act as a
	// CA issuer, and "openvox-ca-ctl generate" needs an admin client
	// certificate that does not exist until the server is already serving.
	//
	// Mutually exclusive with tls_cert/tls_key — see serverConfig.validateTLS.
	TLSSelfProvision bool `yaml:"tls_self_provision"`

	// TLSSelfProvisionNames are extra DNS SANs beyond hostname, for the service
	// and ingress names clients actually dial.
	TLSSelfProvisionNames []string `yaml:"tls_self_provision_names"`

	// TLSSelfProvisionRenewBeforeSec reissues the serving certificate once its
	// remaining validity falls below this. 0 selects one third of the leaf
	// validity, matching crl_refresh_before_sec's relationship to crl_validity.
	TLSSelfProvisionRenewBeforeSec int `yaml:"tls_self_provision_renew_before_sec"`

	// TLSSelfProvisionEncryptKey encrypts the serving private key at rest, the
	// same way encrypt_ca_key does for the CA key. It requires an explicit
	// passphrase source and refuses the auto-generated one, because that lives
	// in cadir: with an ephemeral cadir each replica would encrypt under a
	// different passphrase and none could read the shared blob after a restart.
	TLSSelfProvisionEncryptKey bool `yaml:"tls_self_provision_encrypt_key"`

	// TLSSelfProvisionRevokeAfterSec revokes a superseded serving certificate
	// this long after it is replaced. Sentinelled to -1 ("unset") so an
	// explicit 0 (never revoke) is never confused with "not configured", the
	// same convention CSRRateLimit uses; resolve it with servingRevokeAfter.
	//
	// The delay exists because the swap is per-process: a sibling replica may
	// still be serving the old certificate, and revoking immediately would
	// break every client that does revocation checking.
	//
	// Unset resolves to 24h rather than "never", because leaving a second valid
	// serving credential in circulation until it expires is the worse failure,
	// and it matches this project's existing posture: RevokeOnAutoRenew is
	// already true by default so that only the newest serial for a subject
	// stays valid.
	TLSSelfProvisionRevokeAfterSec int `yaml:"tls_self_provision_revoke_after_sec"`

	// MaintenanceIntervalSec is how often the shared maintenance loop runs.
	// Named for the loop rather than for any one of its tenants: gating the
	// interval — or the goroutine — on a single feature is how the tasks that
	// do not belong to that feature stop running. 0 = built-in default (1h).
	MaintenanceIntervalSec int `yaml:"maintenance_interval_sec"`

	// MetricsListen, when non-empty, enables the Prometheus exporter on the
	// given address (e.g. "127.0.0.1:9140" or ":9140"). The exporter serves
	// /metrics over plain HTTP on a separate listener from the Puppet API and is
	// disabled by default because it reveals certificate subjects (node
	// hostnames); restrict it to a trusted network or loopback.
	MetricsListen string `yaml:"metrics_listen"`

	// ShutdownTimeoutSec bounds the frontend's graceful HTTP-drain budget on
	// SIGTERM: the time in-flight requests are given to complete before the
	// listener is torn down. 0 selects the built-in default (defaultShutdownDrain).
	// The launcher derives its own, slightly larger, hard-kill deadline from
	// this value (drain + launcherShutdownHeadroom) so a child is never killed
	// mid-drain. Operators raising this must also raise their orchestrator's
	// termination grace period (Kubernetes terminationGracePeriodSeconds
	// defaults to 30s) or the platform will SIGKILL the pod first.
	ShutdownTimeoutSec int `yaml:"shutdown_timeout_sec"`

	// Key generation options (apply only when bootstrapping a new CA).
	CAKeyAlgo   string `yaml:"ca_key_algo"`
	CAKeySize   int    `yaml:"ca_key_size"`
	LeafKeyAlgo string `yaml:"leaf_key_algo"`
	LeafKeySize int    `yaml:"leaf_key_size"`

	// CA certificate subject fields (apply only when bootstrapping a new CA).
	CASubjectOrg      string `yaml:"ca_subject_org"`
	CASubjectOU       string `yaml:"ca_subject_ou"`
	CASubjectCountry  string `yaml:"ca_subject_country"`
	CASubjectLocality string `yaml:"ca_subject_locality"`
	CASubjectProvince string `yaml:"ca_subject_province"`

	// Validity and path length options (apply only when bootstrapping a new CA,
	// except LeafValidityDays and CRLValidityDays which apply on every
	// signing/revocation operation).
	CAPathLength     int `yaml:"ca_path_length"`     // -1=unconstrained (default), 0=leaf-only, N=N levels
	CAValidityDays   int `yaml:"ca_validity_days"`   // 0 = built-in default (~5 years)
	LeafValidityDays int `yaml:"leaf_validity_days"` // 0 = built-in default (~5 years)
	CRLValidityDays  int `yaml:"crl_validity_days"`  // 0 = built-in default (30 days)
	CSRRateLimit     int `yaml:"csr_rate_limit"`     // max CSR submissions per IP per minute; 0 disables, -1/unset = built-in default (60)

	// Background CRL refresh keeps the CRL's NextUpdate from lapsing when no
	// certificates are being revoked. Safe to run on every replica: the work is
	// serialised on the shared CRL lock, so only one replica re-signs per cycle.
	DisableCRLRefresh     bool `yaml:"disable_crl_refresh"`      // true = never auto-refresh the CRL
	CRLRefreshIntervalSec int  `yaml:"crl_refresh_interval_sec"` // how often to check; 0 = built-in default (1h)
	CRLRefreshBeforeSec   int  `yaml:"crl_refresh_before_sec"`   // re-sign when remaining validity < this; 0 = crl_validity/3

	// Background expired-certificate cleanup. Disabled by default: when enabled,
	// a job periodically removes certificates that expired more than the
	// retention grace period ago from the inventory and the CRL (and deletes
	// their stored signed certificate). Safe to run on every replica: the work is
	// serialised on the shared CRL lock, so only one replica prunes per cycle.
	EnableExpiredCertCleanup      bool `yaml:"enable_expired_cert_cleanup"`       // true = run the cleanup job
	ExpiredCertRetentionSec       int  `yaml:"expired_cert_retention_sec"`        // grace period after NotAfter before removal; 0 = built-in default (30d)
	ExpiredCertCleanupIntervalSec int  `yaml:"expired_cert_cleanup_interval_sec"` // how often to run; 0 = built-in default (24h)

	// CA key encryption at rest.
	EncryptCAKey        bool   `yaml:"encrypt_ca_key"`         // encrypt the CA private key at rest (AES-256-GCM + Argon2id)
	CAKeyPassphraseFile string `yaml:"ca_key_passphrase_file"` // path to file containing the CA key passphrase

	// PromoteCNToSAN adds the CN as a DNS SAN when the CSR has no SANs (default: true).
	PromoteCNToSAN bool `yaml:"promote_cn_to_san"`
	// PuppetDateTimeFormat formats JSON date/time fields using the original Puppet CA
	// style ("2006-01-02T15:04:05MST") instead of RFC 3339 (default: false).
	PuppetDateTimeFormat bool `yaml:"puppet_datetime_format"`
	// RevokeOnAutoRenew revokes the certificate replaced by the empty-body
	// (no-CSR) /certificate_renewal auto-renewal path once its successor is
	// signed and stored, so only the newest serial per subject stays valid
	// (default: true). Set to false to match OpenVox Server's own Clojure CA,
	// which leaves the replaced certificate valid until it naturally expires.
	RevokeOnAutoRenew bool `yaml:"revoke_on_auto_renew"`

	// KubernetesExport optionally publishes the CA certificate and/or CRL into
	// one or more Kubernetes Secrets and ConfigMaps. Disabled when no targets are
	// configured. File-only: the nested target list, labels, and annotations are
	// impractical to express as flags/env. Validated at startup.
	KubernetesExport k8sexport.Config `yaml:"kubernetes_export"`

	// Storage backend selection and parameters. Embedded inline so the YAML
	// keys (storage_backend, etcd_*, redis_*, sql_*, ca_cert_file, ca_key_file)
	// remain at the top level. Shared with the operator CLI's migrate command
	// via config.StorageConfig.
	config.StorageConfig `yaml:",inline"`

	// CA key provider selection (ca_key_provider) and, when it selects
	// "openbao", the nested "openbao" settings block. Embedded inline so
	// ca_key_provider stays at the top level like StorageConfig's keys above.
	// The type lives in the shared config package (config.CAKeyProviderConfig)
	// so a future operator-CLI command can reuse it; today only the server
	// consumes it. "file" (default, unset) preserves today's local-key
	// behaviour; "openbao" delegates key custody and signing to an OpenBao
	// Transit key (internal/signer/openbao).
	config.CAKeyProviderConfig `yaml:",inline"`
}

// loadServerConfig applies built-in defaults, optionally loads a YAML config
// file, then overlays environment variables. configFile may be "" to skip file
// loading.
func loadServerConfig(configFile string) (*serverConfig, error) {
	cfg := &serverConfig{
		Host:              "0.0.0.0",
		Port:              8140,
		CAPathLength:      -1,   // unconstrained; 0 = leaf-only, N = N levels of intermediates
		CSRRateLimit:      -1,   // unset sentinel; 0 disables, -1 falls back to defaultCSRRateLimit
		PromoteCNToSAN:    true, // RFC 2818: add CN as SAN when CSR has no SANs
		RevokeOnAutoRenew: true, // only the newest serial per subject should be valid

		// unset sentinel; 0 never revokes, -1 resolves via servingRevokeAfter
		TLSSelfProvisionRevokeAfterSec: -1,
	}

	if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err != nil {
			return nil, fmt.Errorf("reading config file %s: %w", configFile, err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parsing config file %s: %w", configFile, err)
		}
	}

	applyServerEnv(cfg)
	return cfg, nil
}

// shutdownDrain resolves the frontend's graceful HTTP-drain budget, falling
// back to defaultShutdownDrain when the operator has not configured a positive
// value. See serverConfig.ShutdownTimeoutSec.
func (c *serverConfig) shutdownDrain() time.Duration {
	if c.ShutdownTimeoutSec > 0 {
		return time.Duration(c.ShutdownTimeoutSec) * time.Second
	}
	return defaultShutdownDrain
}

// defaultMaintenanceInterval is how often the shared maintenance loop runs when
// the operator has not configured an interval. One hour matches the CRL
// refresher's cadence and is well inside every window the loop's tasks care
// about; it also sets the two-hour floor on tls_self_provision_revoke_after_sec.
const defaultMaintenanceInterval = time.Hour

// maintenanceInterval resolves how often the shared maintenance loop runs.
func (c *serverConfig) maintenanceInterval() time.Duration {
	if c.MaintenanceIntervalSec > 0 {
		return time.Duration(c.MaintenanceIntervalSec) * time.Second
	}
	return defaultMaintenanceInterval
}

// defaultServingRevokeAfter is how long a superseded serving certificate stays
// valid before it is revoked, when the operator has not chosen otherwise.
const defaultServingRevokeAfter = 24 * time.Hour

// servingRevokeAfter resolves how long a superseded serving certificate stays
// valid before revocation. Three states, per the CSRRateLimit convention:
//
//	 0  never revoke — an explicit operator choice
//	>0  that duration, validated against the floor by validateTLS
//	-1  unset: the built-in default, raised to the floor if the operator has
//	    configured an unusually long maintenance interval
//
// Raising the unset value to the floor is what keeps a *default* from ever
// being the thing that refuses to start. An explicitly configured value is
// never adjusted — that one is validated and rejected instead, because
// silently lengthening a delay an operator chose would misrepresent how long a
// superseded credential stays valid.
func (c *serverConfig) servingRevokeAfter() time.Duration {
	if c.TLSSelfProvisionRevokeAfterSec >= 0 {
		return time.Duration(c.TLSSelfProvisionRevokeAfterSec) * time.Second
	}
	return max(defaultServingRevokeAfter, c.servingRevokeFloor())
}

// servingRevokeFloor is the shortest delay that does not reintroduce the
// cross-replica breakage the delay exists to prevent: a replica picks up a
// replacement within one maintenance interval, and the factor of two is margin
// for one whose cycle has only just begun.
func (c *serverConfig) servingRevokeFloor() time.Duration {
	return 2 * c.maintenanceInterval()
}

// tlsEnabled reports whether the API listener will speak TLS, by either route:
// certificate and key files on disk, or a self-provisioned certificate the CA
// issues to itself and serves from memory.
//
// This exists as one predicate because it used to be five copies of
// `cfg.TLSCert != "" && cfg.TLSKey != ""` scattered through the startup path,
// and they do very different things: refuse to serve plain HTTP off loopback,
// set Server.PlainHTTP, install the authorisation middleware, build
// tls.Config, and choose ListenAndServeTLS over ListenAndServe. Adding a second
// way to enable TLS meant teaching all five, and the cost of missing one is not
// uniform — the third gates srv.AuthConfig, and a nil AuthConfig disables the
// authorisation middleware outright, so a listener would come up on TLS with
// every endpoint unauthenticated. One predicate makes that class of omission
// unrepresentable.
func (c *serverConfig) tlsEnabled() bool {
	return c.TLSSelfProvision || (c.TLSCert != "" && c.TLSKey != "")
}

// validateTLS rejects TLS configurations that cannot mean what they say.
//
// Called before anything is opened, so a bad combination is a startup error
// rather than a silent precedence rule discovered from a packet capture.
func (c *serverConfig) validateTLS() error {
	if !c.TLSSelfProvision {
		return nil
	}

	// One route supplies the certificate in memory, the other from disk. There
	// is no sensible merge, and picking a winner silently would leave an
	// operator serving material they did not think was in play.
	if c.TLSCert != "" || c.TLSKey != "" {
		return fmt.Errorf("tls_self_provision cannot be combined with tls_cert/tls_key: " +
			"the CA either issues its own serving certificate or loads one from disk, not both")
	}

	// bootstrapCA falls back to the subject "puppet" when hostname is unset,
	// which would produce a serving certificate no client validates — surfacing
	// as a TLS handshake failure rather than as the configuration error it is.
	if c.Hostname == "" {
		return fmt.Errorf("tls_self_provision requires hostname to be set: it is the common name and " +
			"first subject alternative name of the certificate clients will verify")
	}

	// The auto-generated passphrase lives in cadir. With an ephemeral cadir --
	// the deployment this whole feature targets -- each replica would generate
	// its own and none could read the shared blob after a restart, so the
	// encrypted key would be permanently unreadable rather than merely awkward.
	if c.TLSSelfProvisionEncryptKey && c.CAKeyPassphraseFile == "" && os.Getenv("PUPPET_CA_KEY_PASSPHRASE") == "" {
		return fmt.Errorf("tls_self_provision_encrypt_key requires an explicit passphrase: set " +
			"ca_key_passphrase_file or PUPPET_CA_KEY_PASSPHRASE. The auto-generated passphrase is " +
			"written into cadir, so replicas sharing a storage backend could not read each other's key")
	}

	// A superseded certificate must stay valid long enough for every replica to
	// have noticed its replacement. Only an explicitly configured delay is
	// checked: the unset value resolves to at least the floor by construction,
	// so a default can never be what refuses to start.
	if c.TLSSelfProvisionRevokeAfterSec > 0 {
		minimum := c.servingRevokeFloor()
		if configured := time.Duration(c.TLSSelfProvisionRevokeAfterSec) * time.Second; configured < minimum {
			return fmt.Errorf("tls_self_provision_revoke_after_sec (%s) must be at least twice "+
				"maintenance_interval_sec (%s), or a replica could still be serving the superseded "+
				"certificate when it is revoked; use 0 to never revoke",
				configured, minimum)
		}
	}

	return nil
}

// defaultCRLRefreshInterval is how often the background job checks whether the
// CRL needs re-signing when the operator has not configured an interval. One
// hour is frequent enough to act well within the default refresh window (a
// third of the 30-day CRL validity) while imposing negligible load.
const defaultCRLRefreshInterval = time.Hour

// crlRefreshInterval resolves how often the background job checks the CRL,
// falling back to defaultCRLRefreshInterval when unset. The refresh window
// itself (how close to expiry triggers a re-sign) is resolved by the CA from
// CRLRefreshBeforeSec, defaulting to a third of the CRL validity.
func (c *serverConfig) crlRefreshInterval() time.Duration {
	if c.CRLRefreshIntervalSec > 0 {
		return time.Duration(c.CRLRefreshIntervalSec) * time.Second
	}
	return defaultCRLRefreshInterval
}

const (
	// defaultExpiredCertRetention is how long past a certificate's NotAfter the
	// expired-cert cleanup job waits before removing it when the operator has not
	// configured a retention. 30 days gives operators a comfortable window to
	// notice a node before its record disappears from the inventory and CRL.
	defaultExpiredCertRetention = 30 * 24 * time.Hour
	// defaultExpiredCertCleanupInterval is how often the cleanup job runs when no
	// interval is configured. Daily is ample: expiry is a slow, day-scale event.
	defaultExpiredCertCleanupInterval = 24 * time.Hour
)

// expiredCertRetention resolves the grace period the cleanup job applies after a
// certificate's NotAfter before removing it, falling back to
// defaultExpiredCertRetention when unset. A zero value selects the default; set
// a negative ExpiredCertRetentionSec is not representable, so operators wanting
// "remove as soon as expired" should set a small positive value.
func (c *serverConfig) expiredCertRetention() time.Duration {
	if c.ExpiredCertRetentionSec > 0 {
		return time.Duration(c.ExpiredCertRetentionSec) * time.Second
	}
	return defaultExpiredCertRetention
}

// expiredCertCleanupInterval resolves how often the cleanup job runs, falling
// back to defaultExpiredCertCleanupInterval when unset.
func (c *serverConfig) expiredCertCleanupInterval() time.Duration {
	if c.ExpiredCertCleanupIntervalSec > 0 {
		return time.Duration(c.ExpiredCertCleanupIntervalSec) * time.Second
	}
	return defaultExpiredCertCleanupInterval
}

// applyServerEnv overlays PUPPET_CA_* environment variables onto cfg.
func applyServerEnv(cfg *serverConfig) {
	if v := os.Getenv("PUPPET_CA_CADIR"); v != "" {
		cfg.CADir = v
	}
	if v := os.Getenv("PUPPET_CA_AUTOSIGN_CONFIG"); v != "" {
		cfg.AutosignConfig = v
	}
	if v := os.Getenv("PUPPET_CA_HOST"); v != "" {
		cfg.Host = v
	}
	if v := os.Getenv("PUPPET_CA_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Port = n
		}
	}
	if v := os.Getenv("PUPPET_CA_HOSTNAME"); v != "" {
		cfg.Hostname = v
	}
	if v := os.Getenv("PUPPET_CA_VERBOSITY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Verbosity = n
		}
	}
	if v := os.Getenv("PUPPET_CA_LOGFILE"); v != "" {
		cfg.LogFile = v
	}
	if v := os.Getenv("PUPPET_CA_TLS_CERT"); v != "" {
		cfg.TLSCert = v
	}
	if v := os.Getenv("PUPPET_CA_TLS_KEY"); v != "" {
		cfg.TLSKey = v
	}
	if v := os.Getenv("PUPPET_CA_TLS_SELF_PROVISION"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.TLSSelfProvision = b
		}
	}
	if v := os.Getenv("PUPPET_CA_TLS_SELF_PROVISION_NAMES"); v != "" {
		cfg.TLSSelfProvisionNames = splitAndTrim(v, ",")
	}
	if v := os.Getenv("PUPPET_CA_TLS_SELF_PROVISION_RENEW_BEFORE_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.TLSSelfProvisionRenewBeforeSec = n
		}
	}
	if v := os.Getenv("PUPPET_CA_TLS_SELF_PROVISION_ENCRYPT_KEY"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.TLSSelfProvisionEncryptKey = b
		}
	}
	if v := os.Getenv("PUPPET_CA_TLS_SELF_PROVISION_REVOKE_AFTER_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.TLSSelfProvisionRevokeAfterSec = n
		}
	}
	if v := os.Getenv("PUPPET_CA_MAINTENANCE_INTERVAL_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.MaintenanceIntervalSec = n
		}
	}
	if v := os.Getenv("PUPPET_CA_PUPPET_SERVER"); v != "" {
		cfg.PuppetServer = v
	}
	if v := os.Getenv("PUPPET_CA_PUPPET_SERVER_FILE"); v != "" {
		cfg.PuppetServerFile = v
	}
	if v := os.Getenv("PUPPET_CA_NO_PP_CLI_AUTH"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.NoPpCliAuth = b
		}
	}
	if v := os.Getenv("PUPPET_CA_NO_TLS_REQUIRED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.NoTLSRequired = b
		}
	}
	if v := os.Getenv("PUPPET_CA_ALLOW_PUBLIC_STATUS"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.AllowPublicStatus = b
		}
	}
	if v := os.Getenv("PUPPET_CA_OCSP_URL"); v != "" {
		cfg.OCSPUrl = v
	}
	if v := os.Getenv("PUPPET_CA_CRL_URL"); v != "" {
		cfg.CRLUrl = v
	}
	if v := os.Getenv("PUPPET_CA_METRICS_LISTEN"); v != "" {
		cfg.MetricsListen = v
	}
	if v := os.Getenv("PUPPET_CA_SHUTDOWN_TIMEOUT_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.ShutdownTimeoutSec = n
		}
	}
	if v := os.Getenv("PUPPET_CA_CA_KEY_ALGO"); v != "" {
		cfg.CAKeyAlgo = v
	}
	if v := os.Getenv("PUPPET_CA_CA_KEY_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.CAKeySize = n
		}
	}
	if v := os.Getenv("PUPPET_CA_LEAF_KEY_ALGO"); v != "" {
		cfg.LeafKeyAlgo = v
	}
	if v := os.Getenv("PUPPET_CA_LEAF_KEY_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.LeafKeySize = n
		}
	}
	if v := os.Getenv("PUPPET_CA_CA_SUBJECT_ORG"); v != "" {
		cfg.CASubjectOrg = v
	}
	if v := os.Getenv("PUPPET_CA_CA_SUBJECT_OU"); v != "" {
		cfg.CASubjectOU = v
	}
	if v := os.Getenv("PUPPET_CA_CA_SUBJECT_COUNTRY"); v != "" {
		cfg.CASubjectCountry = v
	}
	if v := os.Getenv("PUPPET_CA_CA_SUBJECT_LOCALITY"); v != "" {
		cfg.CASubjectLocality = v
	}
	if v := os.Getenv("PUPPET_CA_CA_SUBJECT_PROVINCE"); v != "" {
		cfg.CASubjectProvince = v
	}
	if v := os.Getenv("PUPPET_CA_CA_PATH_LENGTH"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.CAPathLength = n
		}
	}
	if v := os.Getenv("PUPPET_CA_CA_VALIDITY_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.CAValidityDays = n
		}
	}
	if v := os.Getenv("PUPPET_CA_LEAF_VALIDITY_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.LeafValidityDays = n
		}
	}
	if v := os.Getenv("PUPPET_CA_CRL_VALIDITY_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.CRLValidityDays = n
		}
	}
	if v := os.Getenv("PUPPET_CA_DISABLE_CRL_REFRESH"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.DisableCRLRefresh = b
		}
	}
	if v := os.Getenv("PUPPET_CA_CRL_REFRESH_INTERVAL_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.CRLRefreshIntervalSec = n
		}
	}
	if v := os.Getenv("PUPPET_CA_CRL_REFRESH_BEFORE_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.CRLRefreshBeforeSec = n
		}
	}
	if v := os.Getenv("PUPPET_CA_ENABLE_EXPIRED_CERT_CLEANUP"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.EnableExpiredCertCleanup = b
		}
	}
	if v := os.Getenv("PUPPET_CA_EXPIRED_CERT_RETENTION_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.ExpiredCertRetentionSec = n
		}
	}
	if v := os.Getenv("PUPPET_CA_EXPIRED_CERT_CLEANUP_INTERVAL_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.ExpiredCertCleanupIntervalSec = n
		}
	}
	if v := os.Getenv("PUPPET_CA_CSR_RATE_LIMIT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.CSRRateLimit = n
		}
	}
	if v := os.Getenv("PUPPET_CA_ENCRYPT_CA_KEY"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.EncryptCAKey = b
		}
	}
	if v := os.Getenv("PUPPET_CA_PROMOTE_CN_TO_SAN"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.PromoteCNToSAN = b
		}
	}
	if v := os.Getenv("PUPPET_CA_PUPPET_DATETIME_FORMAT"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.PuppetDateTimeFormat = b
		}
	}
	if v := os.Getenv("PUPPET_CA_REVOKE_ON_AUTO_RENEW"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.RevokeOnAutoRenew = b
		}
	}
	if v := os.Getenv("PUPPET_CA_KEY_PASSPHRASE_FILE"); v != "" {
		cfg.CAKeyPassphraseFile = v
	}
	if v := os.Getenv("PUPPET_CA_STORAGE_BACKEND"); v != "" {
		cfg.StorageBackend = v
	}
	if v := os.Getenv("PUPPET_CA_ETCD_ENDPOINTS"); v != "" {
		cfg.EtcdEndpoints = splitAndTrim(v, ",")
	}
	if v := os.Getenv("PUPPET_CA_ETCD_KEY_PREFIX"); v != "" {
		cfg.EtcdKeyPrefix = v
	}
	if v := os.Getenv("PUPPET_CA_ETCD_USERNAME"); v != "" {
		cfg.EtcdUsername = v
	}
	if v := os.Getenv("PUPPET_CA_ETCD_PASSWORD"); v != "" {
		cfg.EtcdPassword = v
	}
	if v := os.Getenv("PUPPET_CA_ETCD_DIAL_TIMEOUT_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.EtcdDialTimeoutSec = n
		}
	}
	if v := os.Getenv("PUPPET_CA_ETCD_REQUEST_TIMEOUT_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.EtcdRequestTimeoutSec = n
		}
	}
	if v := os.Getenv("PUPPET_CA_ETCD_TLS_CA_FILE"); v != "" {
		cfg.EtcdTLSCAFile = v
	}
	if v := os.Getenv("PUPPET_CA_ETCD_TLS_CERT_FILE"); v != "" {
		cfg.EtcdTLSCertFile = v
	}
	if v := os.Getenv("PUPPET_CA_ETCD_TLS_KEY_FILE"); v != "" {
		cfg.EtcdTLSKeyFile = v
	}
	if v := os.Getenv("PUPPET_CA_REDIS_ADDRS"); v != "" {
		cfg.RedisAddrs = splitAndTrim(v, ",")
	}
	if v := os.Getenv("PUPPET_CA_REDIS_SENTINEL_MASTER_NAME"); v != "" {
		cfg.RedisSentinelMasterName = v
	}
	if v := os.Getenv("PUPPET_CA_REDIS_SENTINEL_ADDRS"); v != "" {
		cfg.RedisSentinelAddrs = splitAndTrim(v, ",")
	}
	if v := os.Getenv("PUPPET_CA_REDIS_SENTINEL_USERNAME"); v != "" {
		cfg.RedisSentinelUsername = v
	}
	if v := os.Getenv("PUPPET_CA_REDIS_SENTINEL_PASSWORD"); v != "" {
		cfg.RedisSentinelPassword = v
	}
	if v := os.Getenv("PUPPET_CA_REDIS_DB"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			cfg.RedisDB = n
		}
	}
	if v := os.Getenv("PUPPET_CA_REDIS_USERNAME"); v != "" {
		cfg.RedisUsername = v
	}
	if v := os.Getenv("PUPPET_CA_REDIS_PASSWORD"); v != "" {
		cfg.RedisPassword = v
	}
	if v := os.Getenv("PUPPET_CA_REDIS_KEY_PREFIX"); v != "" {
		cfg.RedisKeyPrefix = v
	}
	if v := os.Getenv("PUPPET_CA_REDIS_DIAL_TIMEOUT_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.RedisDialTimeoutSec = n
		}
	}
	if v := os.Getenv("PUPPET_CA_REDIS_REQUEST_TIMEOUT_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.RedisRequestTimeoutSec = n
		}
	}
	if v := os.Getenv("PUPPET_CA_REDIS_LOCK_TTL_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.RedisLockTTLSec = n
		}
	}
	if v := os.Getenv("PUPPET_CA_REDIS_TLS_CA_FILE"); v != "" {
		cfg.RedisTLSCAFile = v
	}
	if v := os.Getenv("PUPPET_CA_REDIS_TLS_CERT_FILE"); v != "" {
		cfg.RedisTLSCertFile = v
	}
	if v := os.Getenv("PUPPET_CA_REDIS_TLS_KEY_FILE"); v != "" {
		cfg.RedisTLSKeyFile = v
	}
	if v := os.Getenv("PUPPET_CA_SQL_DSN"); v != "" {
		cfg.SQLDSN = v
	}
	if v := os.Getenv("PUPPET_CA_SQL_REQUEST_TIMEOUT_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.SQLRequestTimeoutSec = n
		}
	}
	if v := os.Getenv("PUPPET_CA_SQL_MAX_OPEN_CONNS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.SQLMaxOpenConns = n
		}
	}
	if v := os.Getenv("PUPPET_CA_SQL_MAX_IDLE_CONNS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.SQLMaxIdleConns = n
		}
	}
	if v := os.Getenv("PUPPET_CA_SQL_TLS_CA_FILE"); v != "" {
		cfg.SQLTLSCAFile = v
	}
	if v := os.Getenv("PUPPET_CA_SQL_TLS_CERT_FILE"); v != "" {
		cfg.SQLTLSCertFile = v
	}
	if v := os.Getenv("PUPPET_CA_SQL_TLS_KEY_FILE"); v != "" {
		cfg.SQLTLSKeyFile = v
	}
	if v := os.Getenv("PUPPET_CA_CA_CERT_FILE"); v != "" {
		cfg.CACertFile = v
	}
	if v := os.Getenv("PUPPET_CA_CA_KEY_FILE"); v != "" {
		cfg.CAKeyFile = v
	}
	if v := os.Getenv("PUPPET_CA_CA_KEY_PROVIDER"); v != "" {
		cfg.CAKeyProvider = v
	}
	if v := os.Getenv("PUPPET_CA_OPENBAO_ADDR"); v != "" {
		cfg.OpenBao.Addr = v
	}
	if v := os.Getenv("PUPPET_CA_OPENBAO_TRANSIT_MOUNT"); v != "" {
		cfg.OpenBao.TransitMount = v
	}
	if v := os.Getenv("PUPPET_CA_OPENBAO_KEY_NAME"); v != "" {
		cfg.OpenBao.KeyName = v
	}
	if v := os.Getenv("PUPPET_CA_OPENBAO_TLS_CA_FILE"); v != "" {
		cfg.OpenBao.TLSCAFile = v
	}
	if v := os.Getenv("PUPPET_CA_OPENBAO_TLS_CERT_FILE"); v != "" {
		cfg.OpenBao.TLSCertFile = v
	}
	if v := os.Getenv("PUPPET_CA_OPENBAO_TLS_KEY_FILE"); v != "" {
		cfg.OpenBao.TLSKeyFile = v
	}
	if v := os.Getenv("PUPPET_CA_OPENBAO_AUTH_METHOD"); v != "" {
		cfg.OpenBao.AuthMethod = v
	}
	if v := os.Getenv("PUPPET_CA_OPENBAO_APPROLE_MOUNT"); v != "" {
		cfg.OpenBao.AppRoleMount = v
	}
	if v := os.Getenv("PUPPET_CA_OPENBAO_APPROLE_ROLE_ID"); v != "" {
		cfg.OpenBao.AppRoleRoleID = v
	}
	if v := os.Getenv("PUPPET_CA_OPENBAO_APPROLE_ROLE_ID_FILE"); v != "" {
		cfg.OpenBao.AppRoleRoleIDFile = v
	}
	if v := os.Getenv("PUPPET_CA_OPENBAO_APPROLE_SECRET_ID_FILE"); v != "" {
		cfg.OpenBao.AppRoleSecretIDFile = v
	}
	if v := os.Getenv("PUPPET_CA_OPENBAO_TOKEN_FILE"); v != "" {
		cfg.OpenBao.TokenFile = v
	}
	if v := os.Getenv("PUPPET_CA_OPENBAO_KUBERNETES_MOUNT"); v != "" {
		cfg.OpenBao.KubernetesMount = v
	}
	if v := os.Getenv("PUPPET_CA_OPENBAO_KUBERNETES_ROLE"); v != "" {
		cfg.OpenBao.KubernetesRole = v
	}
	if v := os.Getenv("PUPPET_CA_OPENBAO_KUBERNETES_JWT_FILE"); v != "" {
		cfg.OpenBao.KubernetesJWTFile = v
	}
}

// splitAndTrim splits s on sep, trims whitespace around each element, and
// drops empty entries. Used for comma-separated list env vars.
func splitAndTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// loadPuppetServerFile reads a file containing puppet-server CNs, one per
// line. '#' characters and everything after them are stripped (covering both
// full-line and inline comments). Blank lines are skipped. Returns nil, nil
// when path is empty.
func loadPuppetServerFile(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading puppet-server file %s: %w", path, err)
	}
	defer f.Close()
	var cns []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		// Strip inline comments (anything from '#' onward).
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		cns = append(cns, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading puppet-server file %s: %w", path, err)
	}
	return cns, nil
}

// resolveConfigFile delegates to the shared config.ResolveConfigFile.
var resolveConfigFile = config.ResolveConfigFile
