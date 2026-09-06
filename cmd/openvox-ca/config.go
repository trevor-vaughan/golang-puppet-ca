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

	// CRLChainFile is a PEM bundle of upstream CRLs published alongside this
	// CA's own, for agents doing full-chain revocation checking (Puppet's
	// default). Re-read by the crl-chain-refresh job, so refreshing the file is
	// how an operator keeps ancestor CRLs current — every CRL in it is
	// signature-verified against the stored CA bundle before it is served.
	// Empty disables the feature.
	CRLChainFile string `yaml:"crl_chain_file"`

	// CRLChainRefreshIntervalSec is how often that file is re-read and the
	// published CRL rewritten if its upstream blocks changed. 0 = built-in
	// default (1h). Gated on crl_chain_file alone: an operator publishing an
	// upstream chain is not necessarily running any other periodic job.
	CRLChainRefreshIntervalSec int `yaml:"crl_chain_refresh_interval_sec"`

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

	// CASigningConcurrency caps concurrent CA-key signatures across issuance,
	// CRL re-signing and the OCSP responder together. Same three-state
	// convention as CSRRateLimit: 0 disables the bound (unbounded signing),
	// -1/unset takes the built-in default, positive values pass through.
	//
	// The default is a ceiling rather than a tuning — it exists to stop
	// unbounded growth, not to match any particular signer. Deployments using
	// an isolated signer over IPC or ca_key_provider: openbao should set this
	// to what that signer can actually sustain, which openvox-ca has no way to
	// discover.
	CASigningConcurrency int `yaml:"ca_signing_concurrency"`

	// Background CRL refresh keeps the CRL's NextUpdate from lapsing when no
	// certificates are being revoked. Safe to run on every replica: the work is
	// serialised on the shared CRL lock, so only one replica re-signs per cycle.
	DisableCRLRefresh     bool `yaml:"disable_crl_refresh"`      // true = never auto-refresh the CRL
	CRLRefreshIntervalSec int  `yaml:"crl_refresh_interval_sec"` // how often to check; 0 = built-in default (1h)
	CRLRefreshBeforeSec   int  `yaml:"crl_refresh_before_sec"`   // re-sign when remaining validity < this; 0 = crl_validity/3

	// CRLSyncIntervalSec is how often each replica re-reads the stored CRL into
	// the copy its revocation checks answer from, and so bounds how long a
	// certificate revoked on another replica keeps working here. Not covered by
	// disable_crl_refresh, which governs re-signing rather than propagation.
	CRLSyncIntervalSec int `yaml:"crl_sync_interval_sec"` // how often to reload the CRL; 0 = built-in default (60s)

	// OCSPIndexSyncIntervalSec is how often each replica re-reads the inventory
	// into the serial index its OCSP responder answers from, and so bounds how
	// long that responder says `unknown` about a certificate signed on another
	// replica. Separate from crl_sync_interval_sec because the two answer
	// different questions at different costs: that one re-reads a single small
	// CRL blob and bounds a certificate outliving its revocation, this one
	// re-reads the whole inventory and bounds a correct certificate being
	// reported as unrecognised.
	OCSPIndexSyncIntervalSec int `yaml:"ocsp_index_sync_interval_sec"` // how often to reload the OCSP serial index; 0 = built-in default (5m)

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
	// AllowSubjectAltNames lets a submitted CSR request Subject Alternative
	// Names of its own (default: false, matching OpenVox Server's
	// allow-subject-alt-names). When false, a CSR carrying any SAN other than a
	// lone DNS entry equal to its own certname is refused at signing time. Does
	// not affect either generate path (`openvox-ca generate --dns` or the
	// admin-only `POST /generate/{subject}?dns=`), whose names come from an
	// administrator rather than from an agent's CSR.
	AllowSubjectAltNames bool `yaml:"allow_subject_alt_names"`
	// PuppetDateTimeFormat formats JSON date/time fields using the original Puppet CA
	// style ("2006-01-02T15:04:05MST") instead of RFC 3339 (default: false).
	PuppetDateTimeFormat bool `yaml:"puppet_datetime_format"`
	// RevokeOnAutoRenew revokes the certificate replaced by the empty-body
	// (no-CSR) /certificate_renewal auto-renewal path once its successor is
	// signed and stored, so only the newest serial per subject stays valid
	// (default: true). Set to false to match OpenVox Server's own Clojure CA,
	// which leaves the replaced certificate valid until it naturally expires.
	RevokeOnAutoRenew bool `yaml:"revoke_on_auto_renew"`

	// SupersededCertRevokeAfterSec is how long a certificate a renewal has
	// replaced stays valid before it is revoked, instead of being revoked
	// inside the renewal call. Three states, per the CSRRateLimit convention:
	//
	//	 0  revoke immediately, inside the renewal — an explicit operator choice,
	//	    and the behaviour of every release before this setting existed
	//	>0  that duration
	//	-1  unset: the built-in default (24h)
	//
	// The default grants an overlap window in which both the replaced and the
	// replacement certificate verify, so relying parties can pick up the new
	// one without a gap — which is what makes a certificate other parties are
	// actively verifying safe to renew at all.
	//
	// It is also a deliberate weakening, and since it is the default it is one
	// every deployment inherits on upgrade: for the length of the window the
	// replaced certificate — and, on the CSR-based re-key path, the replaced
	// private key — is still a credential this CA accepts. Set 0 to restore the
	// previous behaviour. What keeps the window bounded rather than open-ended
	// is ca.CA.refuseIfSuperseded, which stops a certificate inside its window
	// renewing itself into a fresh full-lifetime successor.
	//
	// 24h is the same window the serving-certificate work settled on for the
	// same question asked about a different subject. That work is not in this
	// repository, so this deliberately does not name its setting: a comment
	// pointing at a config key nobody can grep for is worse than no pointer.
	//
	// It governs both renewal paths. RevokeOnAutoRenew still decides whether
	// the auto-renewal path retires its predecessor at all.
	SupersededCertRevokeAfterSec int `yaml:"superseded_cert_revoke_after_sec"`
	// SupersededCertSweepIntervalSec is how often the sweep that performs those
	// delayed revocations runs; 0 = built-in default (15m). The interval is
	// added to the effective delay in the worst case, so keep it well below
	// superseded_cert_revoke_after_sec.
	SupersededCertSweepIntervalSec int `yaml:"superseded_cert_sweep_interval_sec"`

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

	// Foreign client trust domains (client_ca) and the revocation policy that
	// applies to them. Absent by default: with no entry there is exactly one
	// trust domain, it is ours, and authorisation is what it has always been.
	config.ClientCAConfig `yaml:",inline"`

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
		Host:         "0.0.0.0",
		Port:         8140,
		CAPathLength: -1, // unconstrained; 0 = leaf-only, N = N levels of intermediates
		CSRRateLimit: -1, // unset sentinel; 0 disables, -1 falls back to defaultCSRRateLimit
		// Same sentinel convention; see resolveSigningConcurrency.
		CASigningConcurrency: -1,
		PromoteCNToSAN:       true, // RFC 2818: add CN as SAN when CSR has no SANs
		// AllowSubjectAltNames defaults to false — see the field comment. Left
		// implicit here would make the safe default look like an oversight.
		AllowSubjectAltNames: false,
		RevokeOnAutoRenew:    true, // only the newest serial per subject should be valid
		// unset sentinel; 0 revokes inside the renewal, -1 falls back to
		// defaultSupersededCertRevokeAfter
		SupersededCertRevokeAfterSec: -1,
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

// defaultCRLSyncInterval is how often each replica reloads the stored CRL into
// the copy its revocation checks read, when the operator has not configured an
// interval.
//
// It is the window in which a revoked certificate still works against a replica
// that did not perform the revocation, so it is set by how long that is
// tolerable rather than by cost: a minute is short enough that an operator
// locking out a compromised agent does not need to restart the fleet, and the
// read it costs is one small blob per replica per minute against a backend
// already serving every certificate operation.
const defaultCRLSyncInterval = time.Minute

// crlSyncInterval resolves how often the background job reloads the CRL,
// falling back to defaultCRLSyncInterval when unset.
func (c *serverConfig) crlSyncInterval() time.Duration {
	if c.CRLSyncIntervalSec > 0 {
		return time.Duration(c.CRLSyncIntervalSec) * time.Second
	}
	return defaultCRLSyncInterval
}

// defaultOCSPIndexSyncInterval is how often each replica reloads the inventory
// into the serial index its OCSP responder answers from, when the operator has
// not configured an interval.
//
// Five minutes rather than the CRL sync's one, because the two are not the same
// trade. That job reads one small blob and shortens how long a revoked
// certificate keeps authenticating, which is a security window worth paying a
// per-minute read for. This one reads the entire inventory — a line per
// certificate ever issued, so megabytes on a large fleet — and shortens how
// long the responder calls a *valid* certificate unrecognised. An `unknown` is
// not fail-open, verifiers commonly soft-fail on it, and a newly signed
// certificate is not usually OCSP-checked by a peer in its first minutes; five
// minutes bounds it well inside the four-hour life of any response and costs a
// fifth of what the CRL cadence would — twelve passes an hour rather than
// sixty.
const defaultOCSPIndexSyncInterval = 5 * time.Minute

// ocspIndexSyncInterval resolves how often the background job reloads the OCSP
// serial index, falling back to defaultOCSPIndexSyncInterval when unset.
func (c *serverConfig) ocspIndexSyncInterval() time.Duration {
	if c.OCSPIndexSyncIntervalSec > 0 {
		return time.Duration(c.OCSPIndexSyncIntervalSec) * time.Second
	}
	return defaultOCSPIndexSyncInterval
}

// defaultCRLChainRefreshInterval is how often crl_chain_file is re-read when
// the operator has not configured an interval.
//
// An hour, because the file names ancestor CRLs this CA cannot re-sign: the
// operator refreshes it by whatever mechanism already delivers it, and this job
// only notices. The cost of noticing late is that agents doing full-chain
// revocation checking keep verifying against an ancestor CRL the operator has
// already replaced; the cost of noticing often is a file read.
const defaultCRLChainRefreshInterval = time.Hour

// crlChainRefreshInterval resolves how often crl_chain_file is re-read, falling
// back to defaultCRLChainRefreshInterval when unset.
func (c *serverConfig) crlChainRefreshInterval() time.Duration {
	if c.CRLChainRefreshIntervalSec > 0 {
		return time.Duration(c.CRLChainRefreshIntervalSec) * time.Second
	}
	return defaultCRLChainRefreshInterval
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
	// defaultSupersededCertRevokeAfter is how long a certificate a renewal has
	// replaced stays valid before revocation when the operator has not chosen
	// otherwise. 24 hours comfortably exceeds the interval on which a fleet picks
	// up a replacement, while staying short enough that a replaced credential is
	// not a standing one — the same reasoning, and the same answer, the
	// serving-certificate work reached for its own subject.
	defaultSupersededCertRevokeAfter = 24 * time.Hour
	// defaultSupersededCertSweepInterval is how often the delayed-supersession
	// sweep runs when no interval is configured. The interval is the sweep's
	// own overshoot past a recorded revoke_at, so it wants to be small relative
	// to the delays operators will configure — those are pickup windows, which
	// are hour-scale at the shortest. Fifteen minutes keeps the overshoot
	// immaterial at that scale while keeping the idle cost — one absent-key read
	// per replica per quarter hour, taking no cluster lock, because
	// ReconcileSuperseded rules the work out before acquiring one — negligible
	// on a CA that has recorded nothing.
	defaultSupersededCertSweepInterval = 15 * time.Minute
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

// supersededCertRevokeAfter resolves how long a certificate a renewal has
// replaced stays valid before it is revoked.
//
// Zero is an operator's explicit "revoke immediately", not an absent value, so
// it is honoured rather than replaced by the default — which is the whole point
// of the -1 unset sentinel and the reason this cannot use the `> 0` shape its
// interval neighbours use. Any other negative value is treated as unset too:
// nothing else is representable in the YAML int, and reading a typo as the
// default is the same answer an absent key gets.
func (c *serverConfig) supersededCertRevokeAfter() time.Duration {
	if c.SupersededCertRevokeAfterSec >= 0 {
		return time.Duration(c.SupersededCertRevokeAfterSec) * time.Second
	}
	return defaultSupersededCertRevokeAfter
}

// supersededCertSweepInterval resolves how often the delayed-supersession sweep
// runs, falling back to defaultSupersededCertSweepInterval when unset.
func (c *serverConfig) supersededCertSweepInterval() time.Duration {
	if c.SupersededCertSweepIntervalSec > 0 {
		return time.Duration(c.SupersededCertSweepIntervalSec) * time.Second
	}
	return defaultSupersededCertSweepInterval
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
	if v := os.Getenv("PUPPET_CA_CRL_CHAIN_FILE"); v != "" {
		cfg.CRLChainFile = v
	}
	if v := os.Getenv("PUPPET_CA_CRL_CHAIN_REFRESH_INTERVAL_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.CRLChainRefreshIntervalSec = n
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
	if v := os.Getenv("PUPPET_CA_CLIENT_REVOCATION_POLICY"); v != "" {
		cfg.ClientRevocationPolicy = v
	}
	if v := os.Getenv("PUPPET_CA_CLIENT_CRL_REFRESH_INTERVAL_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.ClientCRLRefreshIntervalSec = n
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
	if v := os.Getenv("PUPPET_CA_CRL_SYNC_INTERVAL_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.CRLSyncIntervalSec = n
		}
	}
	if v := os.Getenv("PUPPET_CA_OCSP_INDEX_SYNC_INTERVAL_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.OCSPIndexSyncIntervalSec = n
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
	if v := os.Getenv("PUPPET_CA_SIGNING_CONCURRENCY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.CASigningConcurrency = n
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
	if v := os.Getenv("PUPPET_CA_ALLOW_SUBJECT_ALT_NAMES"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.AllowSubjectAltNames = b
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
	// n >= 0, unlike every interval setting around it. Those treat 0 as "unset,
	// use the built-in default", so refusing it costs nothing. Here 0 is the
	// feature's off switch and a distinct, meaningful value: with a positive
	// superseded_cert_revoke_after_sec in the config file, a `n > 0` guard would
	// silently drop an env override of 0 and leave the window open. That is the
	// one direction this must not fail in — the env channel is how a container
	// or Helm deployment overrides a baked-in config.yaml, and it would be able
	// to widen the weakening but never close it.
	if v := os.Getenv("PUPPET_CA_SUPERSEDED_CERT_REVOKE_AFTER_SEC"); v != "" {
		// Any integer, including negatives. supersededCertRevokeAfter already
		// reads a negative as unset, so -1 — the value this setting documents
		// as "unset" — has to reach it rather than being filtered out here. A
		// bound of n >= 0 would silently drop exactly the documented way to say
		// "go back to the default" when a config file has set a window.
		if n, err := strconv.Atoi(v); err == nil {
			cfg.SupersededCertRevokeAfterSec = n
		}
	}
	if v := os.Getenv("PUPPET_CA_SUPERSEDED_CERT_SWEEP_INTERVAL_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.SupersededCertSweepIntervalSec = n
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
	if v := os.Getenv("PUPPET_CA_SQL_MIGRATION_TIMEOUT_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.SQLMigrationTimeoutSec = n
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

// supersededWindowWarning reports whether the configured sweep interval makes
// the overlap window meaningfully longer than the operator asked for, and the
// log line to emit when it does.
//
// The interval is added to every window in the worst case: a certificate
// becomes due between two passes and is revoked on the later one. An operator
// following the docs' advice to set the window no longer than a fleet's pickup
// takes can easily land below the 15-minute default interval and get an
// effective window several times what they asked for — on a setting the docs
// call a deliberate weakening.
//
// It warns rather than refuses, because the configuration is coherent, just not
// what it looks like. Split out of the serve command so it can be asserted:
// inside a cobra RunE it was a branch nothing could reach.
func supersededWindowWarning(c *serverConfig) (string, []any, bool) {
	revokeAfter := c.supersededCertRevokeAfter()
	if revokeAfter <= 0 {
		return "", nil, false
	}
	sweep := c.supersededCertSweepInterval()
	if sweep < revokeAfter {
		return "", nil, false
	}
	return "superseded_cert_sweep_interval_sec is not shorter than " +
			"superseded_cert_revoke_after_sec, so the sweep interval sets the effective " +
			"overlap window rather than the delay does",
		[]any{
			"revoke_after", revokeAfter,
			"sweep_interval", sweep,
			"worst_case_window", revokeAfter + sweep,
		}, true
}
