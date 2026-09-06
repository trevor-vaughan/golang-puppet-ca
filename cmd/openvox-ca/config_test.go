// Copyright (C) 2026 Trevor Vaughan
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
	"os"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// setEnv sets an environment variable for the duration of the current spec,
// saving the prior value and restoring it via DeferCleanup. Equivalent to
// GinkgoT().Setenv, which is the other sanctioned form (see AGENTS.md); a bare
// t.Setenv needs a *testing.T, which Ginkgo nodes do not have.
func setEnv(key, value string) {
	GinkgoHelper()
	prior, had := os.LookupEnv(key)
	DeferCleanup(func() {
		if had {
			Expect(os.Setenv(key, prior)).To(Succeed())
		} else {
			Expect(os.Unsetenv(key)).To(Succeed())
		}
	})
	Expect(os.Setenv(key, value)).To(Succeed())
}

// clearServerEnv unsets every PUPPET_CA_* var and restores them after the spec.
//
// Enumerated from the live environment rather than from serverEnvVars, which is
// a hand-written list and had fallen well short of the ~90 the server actually
// reads. The gap mattered once specs began driving whole commands through
// resolveRuntime: PUPPET_CA_STORAGE_BACKEND or PUPPET_CA_SQL_DSN exported on a
// developer box would silently point them at a real database instead of the
// --cadir filesystem backend, and PUPPET_CA_ENCRYPT_CA_KEY would make the
// "encrypts the created key at rest when configured" spec pass without its
// config file doing anything — a test that can no longer fail. Reading the
// environment cannot drift from what the server reads.
func clearServerEnv() {
	GinkgoHelper()
	for _, entry := range os.Environ() {
		key, _, found := strings.Cut(entry, "=")
		if !found || !strings.HasPrefix(key, "PUPPET_CA_") {
			continue
		}
		// PUPPET_CA_CONFIG is the pin, not ambient state: callers set it to a
		// fixture config immediately before calling this, and clearing it would
		// send them to the host's /etc/puppet-ca/config.yaml instead.
		if key == "PUPPET_CA_CONFIG" {
			continue
		}
		setEnv(key, "") // empty string is treated as unset by applyServerEnv
	}
}

// writeTempConfig writes content to a config.yaml in a fresh temp dir and
// returns the path.
func writeTempConfig(content string) string {
	GinkgoHelper()
	dir := GinkgoT().TempDir()
	path := filepath.Join(dir, "config.yaml")
	Expect(os.WriteFile(path, []byte(content), 0644)).To(Succeed())
	return path
}

// --- resolveConfigFile ---

var _ = Describe("resolveConfigFile", func() {
	const envKey = "PUPPET_CA_CONFIG_TEST_RESOLVE"

	var (
		existing string
		missing  string
	)

	BeforeEach(func() {
		dir := GinkgoT().TempDir()
		existing = filepath.Join(dir, "exists.yaml")
		Expect(os.WriteFile(existing, []byte(""), 0644)).To(Succeed())
		missing = filepath.Join(dir, "missing.yaml")
	})

	DescribeTable("resolution precedence",
		func(cliFlag string, envVal func() string, defaultPath func() string, want func() string) {
			setEnv(envKey, envVal())
			got := resolveConfigFile(cliFlag, envKey, defaultPath())
			Expect(got).To(Equal(want()),
				"resolveConfigFile(%q, %q, %q) = %q; want %q",
				cliFlag, envKey, defaultPath(), got, want())
		},
		Entry("cli flag wins over env and default",
			"/cli/path.yaml",
			func() string { return "/env/path.yaml" },
			func() string { return existing },
			func() string { return "/cli/path.yaml" }),
		Entry("env var used when no cli flag",
			"",
			func() string { return "/env/path.yaml" },
			func() string { return existing },
			func() string { return "/env/path.yaml" }),
		Entry("default path used when it exists",
			"",
			func() string { return "" },
			func() string { return existing },
			func() string { return existing }),
		Entry("empty when default does not exist",
			"",
			func() string { return "" },
			func() string { return missing },
			func() string { return "" }),
		Entry("empty when nothing provided",
			"",
			func() string { return "" },
			func() string { return "" },
			func() string { return "" }),
	)
})

// --- loadServerConfig: built-in defaults ---

var _ = Describe("loadServerConfig built-in defaults", func() {
	It("applies the documented defaults", func() {
		clearServerEnv()

		cfg, err := loadServerConfig("")
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cfg.Host).To(Equal("0.0.0.0"), "Host = %q; want 0.0.0.0", cfg.Host)
		Expect(cfg.Port).To(Equal(8140), "Port = %d; want 8140", cfg.Port)
		Expect(cfg.CADir).To(Equal(""), "CADir = %q; want empty", cfg.CADir)
		Expect(cfg.NoTLSRequired).To(BeFalse(), "NoTLSRequired = true; want false")
		Expect(cfg.Verbosity).To(Equal(0), "Verbosity = %d; want 0", cfg.Verbosity)
		Expect(cfg.CAPathLength).To(Equal(-1), "CAPathLength = %d; want -1 (unconstrained)", cfg.CAPathLength)
		// Security-relevant default: a CSR may not name anything beyond its own
		// certname unless an operator opts in. Guard the literal — flipping it
		// would reopen the impersonation path #293 closed, and nothing else
		// here would fail.
		Expect(cfg.AllowSubjectAltNames).To(BeFalse(),
			"AllowSubjectAltNames = true; want false (CSRs may not request SANs by default)")
		// Security-relevant default: superseded certificates are revoked on
		// auto-renewal unless explicitly disabled. Guard the literal so a
		// regression flipping it to false cannot pass silently.
		Expect(cfg.RevokeOnAutoRenew).To(BeTrue(), "RevokeOnAutoRenew = false; want true (secure default)")
	})
})

// --- shutdownDrain ---

var _ = Describe("shutdownDrain", func() {
	It("returns the default when unset", func() {
		clearServerEnv()

		cfg, err := loadServerConfig("")
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cfg.shutdownDrain()).To(Equal(defaultShutdownDrain),
			"shutdownDrain() = %v; want default %v", cfg.shutdownDrain(), defaultShutdownDrain)
	})

	It("honours the env override", func() {
		clearServerEnv()
		setEnv("PUPPET_CA_SHUTDOWN_TIMEOUT_SEC", "45")

		cfg, err := loadServerConfig("")
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cfg.shutdownDrain()).To(Equal(45*time.Second),
			"shutdownDrain() = %v; want %v", cfg.shutdownDrain(), 45*time.Second)
	})

	// A non-positive value falls back to the default rather than disabling the
	// drain budget entirely (a 0s Shutdown context would abort in-flight requests
	// immediately).
	It("falls back to the default for a non-positive value", func() {
		clearServerEnv()
		setEnv("PUPPET_CA_SHUTDOWN_TIMEOUT_SEC", "0")

		cfg, err := loadServerConfig("")
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cfg.shutdownDrain()).To(Equal(defaultShutdownDrain),
			"shutdownDrain() with 0 = %v; want default %v", cfg.shutdownDrain(), defaultShutdownDrain)
	})
})

// --- crlRefreshInterval ---

var _ = Describe("crlRefreshInterval", func() {
	It("returns the default when unset", func() {
		clearServerEnv()
		cfg, err := loadServerConfig("")
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cfg.crlRefreshInterval()).To(Equal(defaultCRLRefreshInterval),
			"crlRefreshInterval() = %v; want default %v", cfg.crlRefreshInterval(), defaultCRLRefreshInterval)
	})

	It("honours the env override", func() {
		clearServerEnv()
		setEnv("PUPPET_CA_CRL_REFRESH_INTERVAL_SEC", "900")

		cfg, err := loadServerConfig("")
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cfg.crlRefreshInterval()).To(Equal(900*time.Second),
			"crlRefreshInterval() = %v; want %v", cfg.crlRefreshInterval(), 900*time.Second)
	})

	It("falls back to the default for a non-positive value", func() {
		clearServerEnv()
		setEnv("PUPPET_CA_CRL_REFRESH_INTERVAL_SEC", "0")

		cfg, err := loadServerConfig("")
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cfg.crlRefreshInterval()).To(Equal(defaultCRLRefreshInterval),
			"crlRefreshInterval() with 0 = %v; want default %v", cfg.crlRefreshInterval(), defaultCRLRefreshInterval)
	})
})

// The OCSP index sync interval bounds how long a certificate signed on another
// replica is reported `unknown` here, so its resolution is worth pinning end to
// end for the same reason crlSyncInterval's is: a typo in the env key, or a
// guard that let a non-positive value reach time.NewTicker, would both be
// invisible to a test that sets the field directly.
var _ = Describe("ocspIndexSyncInterval", func() {
	It("returns the default when unset", func() {
		clearServerEnv()
		cfg, err := loadServerConfig("")
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cfg.ocspIndexSyncInterval()).To(Equal(defaultOCSPIndexSyncInterval),
			"ocspIndexSyncInterval() = %v; want default %v",
			cfg.ocspIndexSyncInterval(), defaultOCSPIndexSyncInterval)
	})

	It("honours the env override", func() {
		clearServerEnv()
		setEnv("PUPPET_CA_OCSP_INDEX_SYNC_INTERVAL_SEC", "30")

		cfg, err := loadServerConfig("")
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cfg.ocspIndexSyncInterval()).To(Equal(30*time.Second),
			"ocspIndexSyncInterval() = %v; want %v", cfg.ocspIndexSyncInterval(), 30*time.Second)
	})

	It("falls back to the default for a non-positive value", func() {
		clearServerEnv()
		setEnv("PUPPET_CA_OCSP_INDEX_SYNC_INTERVAL_SEC", "0")

		cfg, err := loadServerConfig("")
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cfg.ocspIndexSyncInterval()).To(Equal(defaultOCSPIndexSyncInterval),
			"ocspIndexSyncInterval() with 0 = %v; want default %v",
			cfg.ocspIndexSyncInterval(), defaultOCSPIndexSyncInterval)
	})

	// It is a separate knob from the CRL sync's on purpose: the two jobs read
	// different things at different costs, and an operator lengthening one has
	// no reason to lengthen the other. Setting one must not move the other.
	It("is independent of crl_sync_interval_sec", func() {
		clearServerEnv()
		setEnv("PUPPET_CA_CRL_SYNC_INTERVAL_SEC", "15")

		cfg, err := loadServerConfig("")
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cfg.crlSyncInterval()).To(Equal(15 * time.Second))
		Expect(cfg.ocspIndexSyncInterval()).To(Equal(defaultOCSPIndexSyncInterval))
	})
})

// crl_sync_interval_sec bounds how long a certificate revoked on another
// replica keeps working here, so its resolution is worth pinning end to end
// rather than only from a struct literal: a typo in the env key, or a guard
// that let a non-positive value through to time.NewTicker, would both be
// invisible to a test that sets the field directly.
var _ = Describe("crlSyncInterval", func() {
	It("returns the default when unset", func() {
		clearServerEnv()
		cfg, err := loadServerConfig("")
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cfg.crlSyncInterval()).To(Equal(defaultCRLSyncInterval),
			"crlSyncInterval() = %v; want default %v", cfg.crlSyncInterval(), defaultCRLSyncInterval)
	})

	It("honours the env override", func() {
		clearServerEnv()
		setEnv("PUPPET_CA_CRL_SYNC_INTERVAL_SEC", "15")

		cfg, err := loadServerConfig("")
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cfg.crlSyncInterval()).To(Equal(15*time.Second),
			"crlSyncInterval() = %v; want %v", cfg.crlSyncInterval(), 15*time.Second)
	})

	It("falls back to the default for a non-positive value", func() {
		clearServerEnv()
		setEnv("PUPPET_CA_CRL_SYNC_INTERVAL_SEC", "0")

		cfg, err := loadServerConfig("")
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cfg.crlSyncInterval()).To(Equal(defaultCRLSyncInterval),
			"crlSyncInterval() with 0 = %v; want default %v", cfg.crlSyncInterval(), defaultCRLSyncInterval)
	})

	// The sync is not one of the things disable_crl_refresh turns off. This
	// pins the resolver half — the interval an operator gets is the same
	// whether or not refreshing is disabled. That the job is started at all in
	// that configuration is pinned separately, against backgroundJobs.
	It("is unaffected by disable_crl_refresh", func() {
		clearServerEnv()
		setEnv("PUPPET_CA_DISABLE_CRL_REFRESH", "true")

		cfg, err := loadServerConfig("")
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cfg.DisableCRLRefresh).To(BeTrue(), "precondition: refresh is disabled")
		Expect(cfg.crlSyncInterval()).To(Equal(defaultCRLSyncInterval),
			"disabling CRL refresh must not change how often revocations propagate")
	})
})

// --- expired-cert cleanup resolvers ---

var _ = Describe("expired-cert cleanup resolvers", func() {
	It("uses the documented defaults", func() {
		clearServerEnv()

		cfg, err := loadServerConfig("")
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cfg.EnableExpiredCertCleanup).To(BeFalse(), "EnableExpiredCertCleanup should default to false (opt-in)")
		Expect(cfg.expiredCertRetention()).To(Equal(defaultExpiredCertRetention),
			"expiredCertRetention() = %v; want default %v", cfg.expiredCertRetention(), defaultExpiredCertRetention)
		Expect(cfg.expiredCertCleanupInterval()).To(Equal(defaultExpiredCertCleanupInterval),
			"expiredCertCleanupInterval() = %v; want default %v", cfg.expiredCertCleanupInterval(), defaultExpiredCertCleanupInterval)
	})

	It("honours the env overrides", func() {
		clearServerEnv()
		setEnv("PUPPET_CA_ENABLE_EXPIRED_CERT_CLEANUP", "true")
		setEnv("PUPPET_CA_EXPIRED_CERT_RETENTION_SEC", "3600")
		setEnv("PUPPET_CA_EXPIRED_CERT_CLEANUP_INTERVAL_SEC", "900")

		cfg, err := loadServerConfig("")
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cfg.EnableExpiredCertCleanup).To(BeTrue(), "EnableExpiredCertCleanup = false; want true")
		Expect(cfg.expiredCertRetention()).To(Equal(time.Hour),
			"expiredCertRetention() = %v; want %v", cfg.expiredCertRetention(), time.Hour)
		Expect(cfg.expiredCertCleanupInterval()).To(Equal(900*time.Second),
			"expiredCertCleanupInterval() = %v; want %v", cfg.expiredCertCleanupInterval(), 900*time.Second)
	})

	// The warning exists because an operator who follows the docs' advice — set
	// the window no longer than the pickup takes — can land below the 15-minute
	// default sweep interval and silently get an effective window several times
	// what they asked for. Inside the serve command it was a branch nothing
	// could reach.
	DescribeTable("warns when the sweep interval swamps the overlap window",
		func(revokeAfterSec, sweepSec int, wantWarn bool) {
			cfg := &serverConfig{
				SupersededCertRevokeAfterSec:   revokeAfterSec,
				SupersededCertSweepIntervalSec: sweepSec,
			}
			msg, args, warn := supersededWindowWarning(cfg)
			Expect(warn).To(Equal(wantWarn))
			if !wantWarn {
				Expect(msg).To(BeEmpty())
				return
			}
			Expect(msg).To(ContainSubstring("superseded_cert_sweep_interval_sec"))
			// The worst case is what the operator actually gets, so it has to be
			// in the line rather than left for them to work out.
			Expect(args).To(ContainElement("worst_case_window"))
			Expect(args).To(ContainElement(
				time.Duration(revokeAfterSec)*time.Second + time.Duration(sweepSec)*time.Second))
		},
		Entry("interval longer than the window", 60, 900, true),
		Entry("interval equal to the window", 900, 900, true),
		Entry("interval shorter than the window", 86400, 900, false),
		// 0 is an explicit "revoke inside the renewal": there is no window for
		// an interval to swamp, so warning would be noise on the one setting
		// that turns the feature off.
		Entry("window closed", 0, 900, false),
		// Unset resolves to the 24h default, comfortably above the 15m default
		// interval — the shipped configuration must not warn.
		Entry("both unset (the shipped default)", -1, 0, false),
	)

	It("resolves the delayed-supersession settings", func() {
		clearServerEnv()
		cfg, err := loadServerConfig("")
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cfg.supersededCertRevokeAfter()).To(Equal(defaultSupersededCertRevokeAfter),
			"an unset window must resolve to the built-in default, not to zero")
		Expect(cfg.supersededCertRevokeAfter()).To(Equal(24*time.Hour),
			"and that default is 24h, matching tls_self_provision_revoke_after_sec")
		Expect(cfg.supersededCertSweepInterval()).To(Equal(defaultSupersededCertSweepInterval),
			"supersededCertSweepInterval() = %v; want default %v",
			cfg.supersededCertSweepInterval(), defaultSupersededCertSweepInterval)
		// time.NewTicker panics on a non-positive duration and the sweep runs on
		// every deployment, so the default has to be positive on its own terms
		// and not merely equal to a constant that could itself become zero.
		Expect(cfg.supersededCertSweepInterval()).To(BeNumerically(">", 0))

		clearServerEnv()
		setEnv("PUPPET_CA_SUPERSEDED_CERT_REVOKE_AFTER_SEC", "3600")
		setEnv("PUPPET_CA_SUPERSEDED_CERT_SWEEP_INTERVAL_SEC", "60")
		cfg, err = loadServerConfig("")
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cfg.supersededCertRevokeAfter()).To(Equal(time.Hour))
		Expect(cfg.supersededCertSweepInterval()).To(Equal(time.Minute))

		// Zero is an operator's explicit "revoke immediately", not an absent
		// value. This is the one setting here where the `> 0` shape its
		// neighbours use would be wrong: it would swallow the off switch and
		// hand back a 24-hour window to someone who asked for none.
		clearServerEnv()
		cfg, err = loadServerConfig("")
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		cfg.SupersededCertRevokeAfterSec = 0
		Expect(cfg.supersededCertRevokeAfter()).To(BeZero(),
			"an explicit 0 must mean revoke-inside-the-renewal, not fall back to the default")

		// Any other negative reads as unset, like an absent key.
		cfg.SupersededCertRevokeAfterSec = -5
		Expect(cfg.supersededCertRevokeAfter()).To(Equal(defaultSupersededCertRevokeAfter))
		cfg.SupersededCertSweepIntervalSec = -1
		Expect(cfg.supersededCertSweepInterval()).To(Equal(defaultSupersededCertSweepInterval))
	})

	// The env channel is how a container or Helm deployment overrides a baked-in
	// config.yaml, and this is the one setting where 0 is a meaningful value
	// rather than "unset". The `n > 0` guard its neighbours use would silently
	// drop this override and leave the overlap window open — so the env route
	// could widen the weakening but never close it.
	It("lets the environment turn the overlap window off, not just on", func() {
		clearServerEnv()
		dir := GinkgoT().TempDir()
		path := filepath.Join(dir, "config.yaml")
		Expect(os.WriteFile(path, []byte("superseded_cert_revoke_after_sec: 3600\n"), 0o600)).To(Succeed())

		cfg, err := loadServerConfig(path)
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cfg.supersededCertRevokeAfter()).To(Equal(time.Hour), "precondition: the file sets a window")

		setEnv("PUPPET_CA_SUPERSEDED_CERT_REVOKE_AFTER_SEC", "0")
		cfg, err = loadServerConfig(path)
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cfg.supersededCertRevokeAfter()).To(BeZero(),
			"an env value of 0 must override a positive file value and close the window")

		// And it must close it against the *default* too, not only against a
		// file value — that is now the case an operator restoring the previous
		// behaviour on upgrade actually hits.
		clearServerEnv()
		setEnv("PUPPET_CA_SUPERSEDED_CERT_REVOKE_AFTER_SEC", "0")
		cfg, err = loadServerConfig("")
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cfg.supersededCertRevokeAfter()).To(BeZero(),
			"an env value of 0 must also override the built-in 24h default")

		// -1 is the documented way to say "unset". A bound of n >= 0 in
		// applyServerEnv would silently drop it, so an operator whose config
		// file sets a window could not use the env channel to go back to the
		// default — only to some other explicit number.
		clearServerEnv()
		Expect(os.WriteFile(path, []byte("superseded_cert_revoke_after_sec: 3600\n"), 0o600)).To(Succeed())
		setEnv("PUPPET_CA_SUPERSEDED_CERT_REVOKE_AFTER_SEC", "-1")
		cfg, err = loadServerConfig(path)
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cfg.supersededCertRevokeAfter()).To(Equal(defaultSupersededCertRevokeAfter),
			"an env value of -1 must reach the resolver and mean the built-in default")
	})

	It("falls back to defaults for non-positive values", func() {
		clearServerEnv()
		setEnv("PUPPET_CA_EXPIRED_CERT_RETENTION_SEC", "0")
		setEnv("PUPPET_CA_EXPIRED_CERT_CLEANUP_INTERVAL_SEC", "-5")

		cfg, err := loadServerConfig("")
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cfg.expiredCertRetention()).To(Equal(defaultExpiredCertRetention),
			"expiredCertRetention() with 0 = %v; want default %v", cfg.expiredCertRetention(), defaultExpiredCertRetention)
		Expect(cfg.expiredCertCleanupInterval()).To(Equal(defaultExpiredCertCleanupInterval),
			"expiredCertCleanupInterval() with -5 = %v; want default %v", cfg.expiredCertCleanupInterval(), defaultExpiredCertCleanupInterval)
	})
})

// --- loadServerConfig: YAML file ---

var _ = Describe("loadServerConfig YAML file", func() {
	It("applies every field from the YAML document", func() {
		clearServerEnv()

		content := `
cadir: /tmp/myca
host: 127.0.0.1
port: 9090
hostname: myhost
no_tls_required: true
tls_cert: /etc/ssl/cert.pem
tls_key: /etc/ssl/key.pem
puppet_server: puppet-master
puppet_server_file: /etc/puppet-ca/servers.txt
no_pp_cli_auth: true
autosign_config: "true"
logfile: /var/log/openvox-ca.log
verbosity: 1
ocsp_url: http://ocsp.example.com/ocsp
ca_key_algo: ecdsa
ca_key_size: 384
leaf_key_algo: rsa
leaf_key_size: 3072
ca_subject_org: Example Org
ca_subject_ou: IT
ca_subject_country: US
ca_subject_locality: Springfield
ca_subject_province: IL
ca_path_length: 1
ca_validity_days: 3650
leaf_validity_days: 1825
`
		cfgFile := writeTempConfig(content)

		cfg, err := loadServerConfig(cfgFile)
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		checks := []struct {
			field string
			got   interface{}
			want  interface{}
		}{
			{"CADir", cfg.CADir, "/tmp/myca"},
			{"Host", cfg.Host, "127.0.0.1"},
			{"Port", cfg.Port, 9090},
			{"Hostname", cfg.Hostname, "myhost"},
			{"NoTLSRequired", cfg.NoTLSRequired, true},
			{"TLSCert", cfg.TLSCert, "/etc/ssl/cert.pem"},
			{"TLSKey", cfg.TLSKey, "/etc/ssl/key.pem"},
			{"PuppetServer", cfg.PuppetServer, "puppet-master"},
			{"PuppetServerFile", cfg.PuppetServerFile, "/etc/puppet-ca/servers.txt"},
			{"NoPpCliAuth", cfg.NoPpCliAuth, true},
			{"AutosignConfig", cfg.AutosignConfig, "true"},
			{"LogFile", cfg.LogFile, "/var/log/openvox-ca.log"},
			{"Verbosity", cfg.Verbosity, 1},
			{"OCSPUrl", cfg.OCSPUrl, "http://ocsp.example.com/ocsp"},
			{"CAKeyAlgo", cfg.CAKeyAlgo, "ecdsa"},
			{"CAKeySize", cfg.CAKeySize, 384},
			{"LeafKeyAlgo", cfg.LeafKeyAlgo, "rsa"},
			{"LeafKeySize", cfg.LeafKeySize, 3072},
			{"CASubjectOrg", cfg.CASubjectOrg, "Example Org"},
			{"CASubjectOU", cfg.CASubjectOU, "IT"},
			{"CASubjectCountry", cfg.CASubjectCountry, "US"},
			{"CASubjectLocality", cfg.CASubjectLocality, "Springfield"},
			{"CASubjectProvince", cfg.CASubjectProvince, "IL"},
			{"CAPathLength", cfg.CAPathLength, 1},
			{"CAValidityDays", cfg.CAValidityDays, 3650},
			{"LeafValidityDays", cfg.LeafValidityDays, 1825},
		}
		for _, c := range checks {
			Expect(c.got).To(Equal(c.want), "%s = %v; want %v", c.field, c.got, c.want)
		}
	})

	It("parses the ca_key_provider and nested openbao block", func() {
		clearServerEnv()

		content := `
ca_key_provider: openbao
openbao:
  addr: https://bao.example.com:8200
  transit_mount: transit-x
  key_name: my-ca-key
  tls_ca_file: /tls/ca.pem
  tls_cert_file: /tls/cert.pem
  tls_key_file: /tls/key.pem
  auth_method: approle
  approle_mount: approle-x
  approle_role_id: role-id-val
  approle_role_id_file: /creds/role-id
  approle_secret_id_file: /creds/secret-id
  token_file: /creds/token
  kubernetes_mount: k8s-x
  kubernetes_role: k8s-role
  kubernetes_jwt_file: /creds/sa.jwt
`
		cfgFile := writeTempConfig(content)

		cfg, err := loadServerConfig(cfgFile)
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		checks := []struct {
			field string
			got   interface{}
			want  interface{}
		}{
			{"CAKeyProvider", cfg.CAKeyProvider, "openbao"},
			{"OpenBao.Addr", cfg.OpenBao.Addr, "https://bao.example.com:8200"},
			{"OpenBao.TransitMount", cfg.OpenBao.TransitMount, "transit-x"},
			{"OpenBao.KeyName", cfg.OpenBao.KeyName, "my-ca-key"},
			{"OpenBao.TLSCAFile", cfg.OpenBao.TLSCAFile, "/tls/ca.pem"},
			{"OpenBao.TLSCertFile", cfg.OpenBao.TLSCertFile, "/tls/cert.pem"},
			{"OpenBao.TLSKeyFile", cfg.OpenBao.TLSKeyFile, "/tls/key.pem"},
			{"OpenBao.AuthMethod", cfg.OpenBao.AuthMethod, "approle"},
			{"OpenBao.AppRoleMount", cfg.OpenBao.AppRoleMount, "approle-x"},
			{"OpenBao.AppRoleRoleID", cfg.OpenBao.AppRoleRoleID, "role-id-val"},
			{"OpenBao.AppRoleRoleIDFile", cfg.OpenBao.AppRoleRoleIDFile, "/creds/role-id"},
			{"OpenBao.AppRoleSecretIDFile", cfg.OpenBao.AppRoleSecretIDFile, "/creds/secret-id"},
			{"OpenBao.TokenFile", cfg.OpenBao.TokenFile, "/creds/token"},
			{"OpenBao.KubernetesMount", cfg.OpenBao.KubernetesMount, "k8s-x"},
			{"OpenBao.KubernetesRole", cfg.OpenBao.KubernetesRole, "k8s-role"},
			{"OpenBao.KubernetesJWTFile", cfg.OpenBao.KubernetesJWTFile, "/creds/sa.jwt"},
		}
		for _, c := range checks {
			Expect(c.got).To(Equal(c.want), "%s = %v; want %v", c.field, c.got, c.want)
		}
	})

	// A config with no ca_key_provider key parses to the empty default, which
	// UsesOpenBao()/Validate() treat as local-file custody. This pins that an
	// omitted key does not accidentally select openbao (or fail to parse).
	It("defaults ca_key_provider to empty (file custody) when the key is absent", func() {
		clearServerEnv()

		cfgFile := writeTempConfig("cadir: /tmp/partial\n")
		cfg, err := loadServerConfig(cfgFile)
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cfg.CAKeyProvider).To(BeEmpty(), "CAKeyProvider = %q; want empty", cfg.CAKeyProvider)
		Expect(cfg.UsesOpenBao()).To(BeFalse(), "UsesOpenBao() = true; want false for an absent key")
	})

	// Unset YAML keys keep built-in defaults.
	It("keeps built-in defaults for unset keys", func() {
		clearServerEnv()

		cfgFile := writeTempConfig("cadir: /tmp/partial\n")
		cfg, err := loadServerConfig(cfgFile)
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cfg.Host).To(Equal("0.0.0.0"), "Host = %q; want default 0.0.0.0", cfg.Host)
		Expect(cfg.Port).To(Equal(8140), "Port = %d; want default 8140", cfg.Port)
		Expect(cfg.CADir).To(Equal("/tmp/partial"), "CADir = %q; want /tmp/partial", cfg.CADir)
	})

	It("parses a kubernetes_export block", func() {
		clearServerEnv()

		content := `
cadir: /tmp/myca
kubernetes_export:
  field_manager: my-ca
  targets:
    - kind: Secret
      metadata:
        name: openvox-ca-trust
        namespace: puppet
        labels:
          app: openvox-ca
        annotations:
          owner: platform
      type: Opaque
      cert: true
      crl: true
      cert_key: ca.crt
      crl_key: ca.crl
      cert_scope: chain
      crl_scope: chain
    - kind: configmap
      metadata:
        name: openvox-ca-crl
      crl: true
`
		cfgFile := writeTempConfig(content)
		cfg, err := loadServerConfig(cfgFile)
		Expect(err).NotTo(HaveOccurred(), "unexpected error")

		Expect(cfg.KubernetesExport.Enabled()).To(BeTrue())
		Expect(cfg.KubernetesExport.FieldManager).To(Equal("my-ca"))
		Expect(cfg.KubernetesExport.Targets).To(HaveLen(2))

		first := cfg.KubernetesExport.Targets[0]
		Expect(first.Kind).To(Equal("Secret"))
		Expect(first.Metadata.Name).To(Equal("openvox-ca-trust"))
		Expect(first.Metadata.Namespace).To(Equal("puppet"))
		Expect(first.Cert).To(BeTrue())
		Expect(first.CRL).To(BeTrue())
		Expect(first.Metadata.Labels).To(HaveKeyWithValue("app", "openvox-ca"))
		Expect(first.Metadata.Annotations).To(HaveKeyWithValue("owner", "platform"))

		Expect(cfg.KubernetesExport.Validate()).To(Succeed())
		// The lowercase kind is accepted and normalised to the canonical form.
		Expect(cfg.KubernetesExport.Targets[1].Kind).To(Equal("ConfigMap"))
		// Validate preserves explicitly-set values and applies defaults.
		Expect(cfg.KubernetesExport.Targets[0].Type).To(Equal("Opaque"))
		Expect(cfg.KubernetesExport.Targets[0].CertKey).To(Equal("ca.crt"))
		// The scope tags themselves: every other scope spec builds the struct in
		// Go, so renaming either yaml tag silently disabled the one documented
		// remedy for the behaviour break these fields introduce.
		Expect(cfg.KubernetesExport.Targets[0].CertScope).To(Equal("chain"))
		Expect(cfg.KubernetesExport.Targets[0].CRLScope).To(Equal("chain"))
		Expect(cfg.KubernetesExport.Targets[1].CRLKey).To(Equal("ca.crl")) // defaulted
	})

	It("rejects an invalid kubernetes_export block", func() {
		clearServerEnv()

		// A target with neither cert nor crl is invalid.
		content := `
cadir: /tmp/myca
kubernetes_export:
  targets:
    - kind: Secret
      metadata:
        name: openvox-ca-trust
        namespace: puppet
`
		cfgFile := writeTempConfig(content)
		cfg, err := loadServerConfig(cfgFile)
		Expect(err).NotTo(HaveOccurred(), "unexpected error")

		Expect(cfg.KubernetesExport.Enabled()).To(BeTrue())
		Expect(cfg.KubernetesExport.Validate()).To(MatchError(ContainSubstring("at least one of cert or crl")))
	})
})

// --- loadServerConfig: env vars override YAML ---

var _ = Describe("loadServerConfig env overrides YAML", func() {
	It("prefers env values over YAML values", func() {
		clearServerEnv()

		cfgFile := writeTempConfig("host: 10.0.0.1\nport: 9090\n")
		setEnv("PUPPET_CA_HOST", "192.168.1.1")
		setEnv("PUPPET_CA_PORT", "7777")

		cfg, err := loadServerConfig(cfgFile)
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cfg.Host).To(Equal("192.168.1.1"), "Host = %q; want env value 192.168.1.1", cfg.Host)
		Expect(cfg.Port).To(Equal(7777), "Port = %d; want env value 7777", cfg.Port)
	})

	It("prefers the ca_key_provider env value over YAML", func() {
		clearServerEnv()

		cfgFile := writeTempConfig("ca_key_provider: file\n")
		setEnv("PUPPET_CA_CA_KEY_PROVIDER", "openbao")

		cfg, err := loadServerConfig(cfgFile)
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cfg.CAKeyProvider).To(Equal("openbao"),
			"CAKeyProvider = %q; want env value openbao", cfg.CAKeyProvider)
	})
})

// --- loadServerConfig: error cases ---

var _ = Describe("loadServerConfig error cases", func() {
	It("errors on a missing config file", func() {
		_, err := loadServerConfig("/nonexistent/path/config.yaml")
		Expect(err).To(HaveOccurred(), "expected error for missing config file, got nil")
	})

	It("errors on invalid YAML", func() {
		cfgFile := writeTempConfig("host: [unclosed\n")
		_, err := loadServerConfig(cfgFile)
		Expect(err).To(HaveOccurred(), "expected error for invalid YAML, got nil")
	})
})

// --- applyServerEnv: each variable ---

var _ = Describe("applyServerEnv each variable", func() {
	DescribeTable("applies the variable to the config",
		func(envKey, envVal string, check func(*serverConfig) bool, desc string) {
			clearServerEnv()
			setEnv(envKey, envVal)
			cfg := &serverConfig{}
			applyServerEnv(cfg)
			Expect(check(cfg)).To(BeTrue(), "%s not applied from %s=%s", desc, envKey, envVal)
		},
		Entry("CADIR", "PUPPET_CA_CADIR", "/some/dir",
			func(c *serverConfig) bool { return c.CADir == "/some/dir" }, "CADir"),
		Entry("CLIENT_REVOCATION_POLICY", "PUPPET_CA_CLIENT_REVOCATION_POLICY", "check",
			func(c *serverConfig) bool { return c.ClientRevocationPolicy == "check" }, "ClientRevocationPolicy"),
		Entry("CLIENT_CRL_REFRESH_INTERVAL_SEC", "PUPPET_CA_CLIENT_CRL_REFRESH_INTERVAL_SEC", "300",
			func(c *serverConfig) bool { return c.ClientCRLRefreshIntervalSec == 300 },
			"ClientCRLRefreshIntervalSec"),
		Entry("AUTOSIGN_CONFIG", "PUPPET_CA_AUTOSIGN_CONFIG", "true",
			func(c *serverConfig) bool { return c.AutosignConfig == "true" }, "AutosignConfig"),
		Entry("HOST", "PUPPET_CA_HOST", "1.2.3.4",
			func(c *serverConfig) bool { return c.Host == "1.2.3.4" }, "Host"),
		Entry("PORT", "PUPPET_CA_PORT", "9999",
			func(c *serverConfig) bool { return c.Port == 9999 }, "Port"),
		Entry("HOSTNAME", "PUPPET_CA_HOSTNAME", "puppet.test",
			func(c *serverConfig) bool { return c.Hostname == "puppet.test" }, "Hostname"),
		Entry("VERBOSITY", "PUPPET_CA_VERBOSITY", "2",
			func(c *serverConfig) bool { return c.Verbosity == 2 }, "Verbosity"),
		Entry("LOGFILE", "PUPPET_CA_LOGFILE", "/var/log/puppet.log",
			func(c *serverConfig) bool { return c.LogFile == "/var/log/puppet.log" }, "LogFile"),
		Entry("TLS_CERT", "PUPPET_CA_TLS_CERT", "/etc/tls/cert.pem",
			func(c *serverConfig) bool { return c.TLSCert == "/etc/tls/cert.pem" }, "TLSCert"),
		Entry("TLS_KEY", "PUPPET_CA_TLS_KEY", "/etc/tls/key.pem",
			func(c *serverConfig) bool { return c.TLSKey == "/etc/tls/key.pem" }, "TLSKey"),
		Entry("PUPPET_SERVER", "PUPPET_CA_PUPPET_SERVER", "puppet-master",
			func(c *serverConfig) bool { return c.PuppetServer == "puppet-master" }, "PuppetServer"),
		Entry("PUPPET_SERVER_FILE", "PUPPET_CA_PUPPET_SERVER_FILE", "/etc/puppet-ca/servers.txt",
			func(c *serverConfig) bool { return c.PuppetServerFile == "/etc/puppet-ca/servers.txt" }, "PuppetServerFile"),
		Entry("NO_PP_CLI_AUTH_true", "PUPPET_CA_NO_PP_CLI_AUTH", "true",
			func(c *serverConfig) bool { return c.NoPpCliAuth }, "NoPpCliAuth=true"),
		Entry("NO_TLS_REQUIRED_true", "PUPPET_CA_NO_TLS_REQUIRED", "true",
			func(c *serverConfig) bool { return c.NoTLSRequired }, "NoTLSRequired=true"),
		Entry("NO_TLS_REQUIRED_1", "PUPPET_CA_NO_TLS_REQUIRED", "1",
			func(c *serverConfig) bool { return c.NoTLSRequired }, "NoTLSRequired=1"),
		Entry("OCSP_URL", "PUPPET_CA_OCSP_URL", "http://ocsp.example.com",
			func(c *serverConfig) bool { return c.OCSPUrl == "http://ocsp.example.com" }, "OCSPUrl"),
		Entry("SHUTDOWN_TIMEOUT_SEC", "PUPPET_CA_SHUTDOWN_TIMEOUT_SEC", "45",
			func(c *serverConfig) bool { return c.ShutdownTimeoutSec == 45 }, "ShutdownTimeoutSec"),
		Entry("CA_KEY_ALGO", "PUPPET_CA_CA_KEY_ALGO", "ecdsa",
			func(c *serverConfig) bool { return c.CAKeyAlgo == "ecdsa" }, "CAKeyAlgo"),
		Entry("CA_KEY_SIZE", "PUPPET_CA_CA_KEY_SIZE", "384",
			func(c *serverConfig) bool { return c.CAKeySize == 384 }, "CAKeySize"),
		Entry("LEAF_KEY_ALGO", "PUPPET_CA_LEAF_KEY_ALGO", "rsa",
			func(c *serverConfig) bool { return c.LeafKeyAlgo == "rsa" }, "LeafKeyAlgo"),
		Entry("LEAF_KEY_SIZE", "PUPPET_CA_LEAF_KEY_SIZE", "3072",
			func(c *serverConfig) bool { return c.LeafKeySize == 3072 }, "LeafKeySize"),
		Entry("CA_SUBJECT_ORG", "PUPPET_CA_CA_SUBJECT_ORG", "Example Org",
			func(c *serverConfig) bool { return c.CASubjectOrg == "Example Org" }, "CASubjectOrg"),
		Entry("CA_SUBJECT_OU", "PUPPET_CA_CA_SUBJECT_OU", "IT",
			func(c *serverConfig) bool { return c.CASubjectOU == "IT" }, "CASubjectOU"),
		Entry("CA_SUBJECT_COUNTRY", "PUPPET_CA_CA_SUBJECT_COUNTRY", "US",
			func(c *serverConfig) bool { return c.CASubjectCountry == "US" }, "CASubjectCountry"),
		Entry("CA_SUBJECT_LOCALITY", "PUPPET_CA_CA_SUBJECT_LOCALITY", "Springfield",
			func(c *serverConfig) bool { return c.CASubjectLocality == "Springfield" }, "CASubjectLocality"),
		Entry("CA_SUBJECT_PROVINCE", "PUPPET_CA_CA_SUBJECT_PROVINCE", "IL",
			func(c *serverConfig) bool { return c.CASubjectProvince == "IL" }, "CASubjectProvince"),
		Entry("CA_PATH_LENGTH_0", "PUPPET_CA_CA_PATH_LENGTH", "0",
			func(c *serverConfig) bool { return c.CAPathLength == 0 }, "CAPathLength=0"),
		Entry("CA_PATH_LENGTH_1", "PUPPET_CA_CA_PATH_LENGTH", "1",
			func(c *serverConfig) bool { return c.CAPathLength == 1 }, "CAPathLength=1"),
		Entry("CA_PATH_LENGTH_neg1", "PUPPET_CA_CA_PATH_LENGTH", "-1",
			func(c *serverConfig) bool { return c.CAPathLength == -1 }, "CAPathLength=-1 (unconstrained)"),
		Entry("CA_VALIDITY_DAYS", "PUPPET_CA_CA_VALIDITY_DAYS", "3650",
			func(c *serverConfig) bool { return c.CAValidityDays == 3650 }, "CAValidityDays"),
		Entry("LEAF_VALIDITY_DAYS", "PUPPET_CA_LEAF_VALIDITY_DAYS", "1825",
			func(c *serverConfig) bool { return c.LeafValidityDays == 1825 }, "LeafValidityDays"),
		Entry("DISABLE_CRL_REFRESH", "PUPPET_CA_DISABLE_CRL_REFRESH", "true",
			func(c *serverConfig) bool { return c.DisableCRLRefresh }, "DisableCRLRefresh"),
		Entry("CRL_REFRESH_INTERVAL_SEC", "PUPPET_CA_CRL_REFRESH_INTERVAL_SEC", "900",
			func(c *serverConfig) bool { return c.CRLRefreshIntervalSec == 900 }, "CRLRefreshIntervalSec"),
		Entry("CRL_REFRESH_BEFORE_SEC", "PUPPET_CA_CRL_REFRESH_BEFORE_SEC", "86400",
			func(c *serverConfig) bool { return c.CRLRefreshBeforeSec == 86400 }, "CRLRefreshBeforeSec"),
		Entry("CRL_SYNC_INTERVAL_SEC", "PUPPET_CA_CRL_SYNC_INTERVAL_SEC", "15",
			func(c *serverConfig) bool { return c.CRLSyncIntervalSec == 15 }, "CRLSyncIntervalSec"),
		Entry("OCSP_INDEX_SYNC_INTERVAL_SEC", "PUPPET_CA_OCSP_INDEX_SYNC_INTERVAL_SEC", "300",
			func(c *serverConfig) bool { return c.OCSPIndexSyncIntervalSec == 300 }, "OCSPIndexSyncIntervalSec"),
		// The zero value of RevokeOnAutoRenew is already false, so assert the
		// env var flips it to true — a value distinct from the zero value —
		// which proves the env key is parsed and wired to the right field. A
		// typo in the env key would then leave it false and fail this entry.
		Entry("REVOKE_ON_AUTO_RENEW", "PUPPET_CA_REVOKE_ON_AUTO_RENEW", "true",
			func(c *serverConfig) bool { return c.RevokeOnAutoRenew }, "RevokeOnAutoRenew"),
		// Same reasoning as above: false is the zero value, so assert the env
		// var flips it to true. A typo in the key leaves it false and fails.
		Entry("ALLOW_SUBJECT_ALT_NAMES", "PUPPET_CA_ALLOW_SUBJECT_ALT_NAMES", "true",
			func(c *serverConfig) bool { return c.AllowSubjectAltNames }, "AllowSubjectAltNames"),
		// Distinct values, because these two are adjacent ints with adjacent
		// names: swapping the destinations would turn a 12-hour overlap window
		// into a 12-hour sweep interval on a 90-second delay, and both would
		// still "work".
		Entry("SUPERSEDED_CERT_REVOKE_AFTER_SEC", "PUPPET_CA_SUPERSEDED_CERT_REVOKE_AFTER_SEC", "43200",
			func(c *serverConfig) bool { return c.SupersededCertRevokeAfterSec == 43200 },
			"SupersededCertRevokeAfterSec"),
		Entry("SUPERSEDED_CERT_SWEEP_INTERVAL_SEC", "PUPPET_CA_SUPERSEDED_CERT_SWEEP_INTERVAL_SEC", "90",
			func(c *serverConfig) bool { return c.SupersededCertSweepIntervalSec == 90 },
			"SupersededCertSweepIntervalSec"),
		// CA key provider selection and OpenBao settings. Each entry uses a
		// distinct value and asserts the specific destination field, so a
		// wrong target (e.g. role-id <-> secret-id, or tls_cert <-> tls_key —
		// both security-relevant) fails rather than passing silently.
		Entry("CA_KEY_PROVIDER", "PUPPET_CA_CA_KEY_PROVIDER", "openbao",
			func(c *serverConfig) bool { return c.CAKeyProvider == "openbao" }, "CAKeyProvider"),
		Entry("OPENBAO_ADDR", "PUPPET_CA_OPENBAO_ADDR", "https://bao:8200",
			func(c *serverConfig) bool { return c.OpenBao.Addr == "https://bao:8200" }, "OpenBao.Addr"),
		Entry("OPENBAO_TRANSIT_MOUNT", "PUPPET_CA_OPENBAO_TRANSIT_MOUNT", "transit-x",
			func(c *serverConfig) bool { return c.OpenBao.TransitMount == "transit-x" }, "OpenBao.TransitMount"),
		Entry("OPENBAO_KEY_NAME", "PUPPET_CA_OPENBAO_KEY_NAME", "ca-key",
			func(c *serverConfig) bool { return c.OpenBao.KeyName == "ca-key" }, "OpenBao.KeyName"),
		Entry("OPENBAO_TLS_CA_FILE", "PUPPET_CA_OPENBAO_TLS_CA_FILE", "/tls/ca.pem",
			func(c *serverConfig) bool { return c.OpenBao.TLSCAFile == "/tls/ca.pem" }, "OpenBao.TLSCAFile"),
		Entry("OPENBAO_TLS_CERT_FILE", "PUPPET_CA_OPENBAO_TLS_CERT_FILE", "/tls/cert.pem",
			func(c *serverConfig) bool { return c.OpenBao.TLSCertFile == "/tls/cert.pem" }, "OpenBao.TLSCertFile"),
		Entry("OPENBAO_TLS_KEY_FILE", "PUPPET_CA_OPENBAO_TLS_KEY_FILE", "/tls/key.pem",
			func(c *serverConfig) bool { return c.OpenBao.TLSKeyFile == "/tls/key.pem" }, "OpenBao.TLSKeyFile"),
		Entry("OPENBAO_AUTH_METHOD", "PUPPET_CA_OPENBAO_AUTH_METHOD", "kubernetes",
			func(c *serverConfig) bool { return c.OpenBao.AuthMethod == "kubernetes" }, "OpenBao.AuthMethod"),
		Entry("OPENBAO_APPROLE_MOUNT", "PUPPET_CA_OPENBAO_APPROLE_MOUNT", "approle-x",
			func(c *serverConfig) bool { return c.OpenBao.AppRoleMount == "approle-x" }, "OpenBao.AppRoleMount"),
		Entry("OPENBAO_APPROLE_ROLE_ID", "PUPPET_CA_OPENBAO_APPROLE_ROLE_ID", "role-id-val",
			func(c *serverConfig) bool { return c.OpenBao.AppRoleRoleID == "role-id-val" }, "OpenBao.AppRoleRoleID"),
		Entry("OPENBAO_APPROLE_ROLE_ID_FILE", "PUPPET_CA_OPENBAO_APPROLE_ROLE_ID_FILE", "/creds/role-id",
			func(c *serverConfig) bool { return c.OpenBao.AppRoleRoleIDFile == "/creds/role-id" }, "OpenBao.AppRoleRoleIDFile"),
		Entry("OPENBAO_APPROLE_SECRET_ID_FILE", "PUPPET_CA_OPENBAO_APPROLE_SECRET_ID_FILE", "/creds/secret-id",
			func(c *serverConfig) bool { return c.OpenBao.AppRoleSecretIDFile == "/creds/secret-id" }, "OpenBao.AppRoleSecretIDFile"),
		Entry("OPENBAO_TOKEN_FILE", "PUPPET_CA_OPENBAO_TOKEN_FILE", "/creds/token",
			func(c *serverConfig) bool { return c.OpenBao.TokenFile == "/creds/token" }, "OpenBao.TokenFile"),
		Entry("OPENBAO_KUBERNETES_MOUNT", "PUPPET_CA_OPENBAO_KUBERNETES_MOUNT", "k8s-x",
			func(c *serverConfig) bool { return c.OpenBao.KubernetesMount == "k8s-x" }, "OpenBao.KubernetesMount"),
		Entry("OPENBAO_KUBERNETES_ROLE", "PUPPET_CA_OPENBAO_KUBERNETES_ROLE", "k8s-role",
			func(c *serverConfig) bool { return c.OpenBao.KubernetesRole == "k8s-role" }, "OpenBao.KubernetesRole"),
		Entry("OPENBAO_KUBERNETES_JWT_FILE", "PUPPET_CA_OPENBAO_KUBERNETES_JWT_FILE", "/creds/sa.jwt",
			func(c *serverConfig) bool { return c.OpenBao.KubernetesJWTFile == "/creds/sa.jwt" }, "OpenBao.KubernetesJWTFile"),
	)

	// Malformed values are silently ignored.
	It("silently ignores malformed values", func() {
		clearServerEnv()
		setEnv("PUPPET_CA_PORT", "not-a-number")
		setEnv("PUPPET_CA_VERBOSITY", "bad")
		setEnv("PUPPET_CA_NO_TLS_REQUIRED", "maybe")
		setEnv("PUPPET_CA_CA_VALIDITY_DAYS", "not-a-number")
		setEnv("PUPPET_CA_LEAF_VALIDITY_DAYS", "bad")
		setEnv("PUPPET_CA_CA_PATH_LENGTH", "not-a-number")

		cfg := &serverConfig{Port: 8140, Verbosity: 0, CAPathLength: -1}
		applyServerEnv(cfg)

		Expect(cfg.Port).To(Equal(8140), "Port changed on bad input: got %d, want 8140", cfg.Port)
		Expect(cfg.Verbosity).To(Equal(0), "Verbosity changed on bad input: got %d, want 0", cfg.Verbosity)
		Expect(cfg.NoTLSRequired).To(BeFalse(), "NoTLSRequired changed on bad input: want false")
		Expect(cfg.CAValidityDays).To(Equal(0), "CAValidityDays changed on bad input: got %d, want 0", cfg.CAValidityDays)
		Expect(cfg.LeafValidityDays).To(Equal(0), "LeafValidityDays changed on bad input: got %d, want 0", cfg.LeafValidityDays)
		Expect(cfg.CAPathLength).To(Equal(-1), "CAPathLength changed on bad input: got %d, want -1", cfg.CAPathLength)
	})

	// A zero or negative value for PUPPET_CA_CA_VALIDITY_DAYS and
	// PUPPET_CA_LEAF_VALIDITY_DAYS is silently ignored (only positive values are
	// applied).
	It("ignores zero or negative validity-day values", func() {
		clearServerEnv()
		setEnv("PUPPET_CA_CA_VALIDITY_DAYS", "0")
		setEnv("PUPPET_CA_LEAF_VALIDITY_DAYS", "-5")

		cfg := &serverConfig{}
		applyServerEnv(cfg)

		Expect(cfg.CAValidityDays).To(Equal(0), "CAValidityDays should stay 0 when env is 0, got %d", cfg.CAValidityDays)
		Expect(cfg.LeafValidityDays).To(Equal(0), "LeafValidityDays should stay 0 when env is negative, got %d", cfg.LeafValidityDays)
	})
})

// --- loadPuppetServerFile ---

var _ = Describe("loadPuppetServerFile", func() {
	It("returns a nil slice for an empty path", func() {
		cns, err := loadPuppetServerFile("")
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cns).To(BeNil(), "expected nil slice for empty path, got %v", cns)
	})

	It("errors on a missing file", func() {
		_, err := loadPuppetServerFile("/nonexistent/path/servers.txt")
		Expect(err).To(HaveOccurred(), "expected error for missing file, got nil")
	})

	It("parses server CNs, skipping blanks and comments", func() {
		content := `
# primary puppet server
puppet.example.com

# compile masters
compile-01.example.com
compile-02.example.com

`
		dir := GinkgoT().TempDir()
		path := filepath.Join(dir, "servers.txt")
		Expect(os.WriteFile(path, []byte(content), 0644)).To(Succeed())

		cns, err := loadPuppetServerFile(path)
		Expect(err).NotTo(HaveOccurred(), "unexpected error")

		want := []string{"puppet.example.com", "compile-01.example.com", "compile-02.example.com"}
		Expect(cns).To(HaveLen(len(want)), "got %d CNs, want %d: %v", len(cns), len(want), cns)
		for i, cn := range cns {
			Expect(cn).To(Equal(want[i]), "cns[%d] = %q; want %q", i, cn, want[i])
		}
	})

	It("ignores comment-only and blank lines", func() {
		content := "# comment\n\n  \n# another comment\npuppet.example.com\n"
		dir := GinkgoT().TempDir()
		path := filepath.Join(dir, "servers.txt")
		Expect(os.WriteFile(path, []byte(content), 0644)).To(Succeed())

		cns, err := loadPuppetServerFile(path)
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cns).To(Equal([]string{"puppet.example.com"}), "got %v; want [puppet.example.com]", cns)
	})

	It("strips inline comments", func() {
		content := "puppet.example.com # primary\ncompile-01.example.com # compile master\n"
		dir := GinkgoT().TempDir()
		path := filepath.Join(dir, "servers.txt")
		Expect(os.WriteFile(path, []byte(content), 0644)).To(Succeed())

		cns, err := loadPuppetServerFile(path)
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		want := []string{"puppet.example.com", "compile-01.example.com"}
		Expect(cns).To(HaveLen(len(want)), "got %v; want %v", cns, want)
		for i, cn := range cns {
			Expect(cn).To(Equal(want[i]), "cns[%d] = %q; want %q", i, cn, want[i])
		}
	})

	It("returns an empty slice for a comment-only file", func() {
		dir := GinkgoT().TempDir()
		path := filepath.Join(dir, "empty.txt")
		Expect(os.WriteFile(path, []byte("# just a comment\n\n"), 0644)).To(Succeed())

		cns, err := loadPuppetServerFile(path)
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cns).To(BeEmpty(), "expected empty slice for comment-only file, got %v", cns)
	})
})

var _ = Describe("crlChainRefreshInterval", func() {
	// The interval the crl-chain-refresh job actually runs on. Setting the
	// field directly would prove nothing about the two names an operator uses:
	// a typo in the yaml tag or the env key leaves the job silently on the 1h
	// default, and a guard that let a non-positive value through would reach
	// time.NewTicker, which panics.
	It("returns the default when unset", func() {
		clearServerEnv()
		cfg, err := loadServerConfig("")
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cfg.crlChainRefreshInterval()).To(Equal(defaultCRLChainRefreshInterval),
			"crlChainRefreshInterval() = %v; want default %v",
			cfg.crlChainRefreshInterval(), defaultCRLChainRefreshInterval)
	})

	It("is read from the config file", func() {
		clearServerEnv()
		cfg, err := loadServerConfig(writeTempConfig("crl_chain_refresh_interval_sec: 300\n"))
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cfg.crlChainRefreshInterval()).To(Equal(5*time.Minute),
			"crlChainRefreshInterval() = %v; want %v", cfg.crlChainRefreshInterval(), 5*time.Minute)
	})

	It("falls back to the default for a non-positive env value", func() {
		// The guard is load-bearing rather than tidy: a zero or negative
		// interval reaches time.NewTicker, which panics. The comment above has
		// claimed as much since this Describe was written while only the yaml
		// path was driven, so the env key -- the likelier place for an operator
		// to put a "0" meaning "off" -- could have been let through unnoticed.
		for _, v := range []string{"0", "-30"} {
			clearServerEnv()
			setEnv("PUPPET_CA_CRL_CHAIN_REFRESH_INTERVAL_SEC", v)
			cfg, err := loadServerConfig("")
			Expect(err).NotTo(HaveOccurred(), "unexpected error")
			Expect(cfg.crlChainRefreshInterval()).To(Equal(defaultCRLChainRefreshInterval),
				"%s must not reach time.NewTicker", v)
		}
	})

	It("honours the env override", func() {
		clearServerEnv()
		setEnv("PUPPET_CA_CRL_CHAIN_REFRESH_INTERVAL_SEC", "15")

		cfg, err := loadServerConfig("")
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cfg.crlChainRefreshInterval()).To(Equal(15*time.Second),
			"crlChainRefreshInterval() = %v; want %v", cfg.crlChainRefreshInterval(), 15*time.Second)
	})

	// The two knobs are independent: sharing a resolver by mistake would leave
	// the chain refreshed every minute, or revocations propagating hourly, with
	// nothing else to notice.
	It("is independent of crl_sync_interval_sec", func() {
		clearServerEnv()
		setEnv("PUPPET_CA_CRL_SYNC_INTERVAL_SEC", "15")

		cfg, err := loadServerConfig("")
		Expect(err).NotTo(HaveOccurred(), "unexpected error")
		Expect(cfg.crlSyncInterval()).To(Equal(15 * time.Second))
		Expect(cfg.crlChainRefreshInterval()).To(Equal(defaultCRLChainRefreshInterval),
			"crl_sync_interval_sec must not decide how often the chain file is re-read")
	})
})

// --- allow_subject_alt_names wiring ---

var _ = Describe("allow_subject_alt_names wiring", func() {
	// File-and-environment only, no CLI flag, and its failure mode is silent in
	// both directions: a value that never reaches ca.AllowSubjectAltNames
	// either strands the operator who turned it on (their agents keep being
	// refused) or leaves the gate off while they believe they configured
	// something, which is the impersonation path #293 exists to close. Nothing
	// in internal/ca can catch that — those specs set the field in Go and never
	// go through config loading at all.
	BeforeEach(func() { clearServerEnv() })

	It("is false by default", func() {
		cfg, err := loadServerConfig("")
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.AllowSubjectAltNames).To(BeFalse())
	})

	It("is read from the config file", func() {
		path := writeTempConfig("allow_subject_alt_names: true\n")
		cfg, err := loadServerConfig(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.AllowSubjectAltNames).To(BeTrue())
	})

	It("is read from the environment, which outranks the file", func() {
		path := writeTempConfig("allow_subject_alt_names: false\n")
		setEnv("PUPPET_CA_ALLOW_SUBJECT_ALT_NAMES", "true")
		cfg, err := loadServerConfig(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.AllowSubjectAltNames).To(BeTrue())
	})

	It("reaches the CA, which is the step whose absence is silent", func() {
		cfg, err := loadServerConfig(writeTempConfig("allow_subject_alt_names: true\n"))
		Expect(err).NotTo(HaveOccurred())

		myCA := ca.New(storage.New(GinkgoT().TempDir()), ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(applyCAConfig(myCA, cfg)).To(Succeed())
		Expect(myCA.AllowSubjectAltNames).To(BeTrue())
	})

	It("leaves the CA refusing when the file says false", func() {
		// The direction that matters for the vulnerability: a wiring defect
		// that ignored the file would be invisible above, since true is what
		// every other spec here asserts.
		cfg, err := loadServerConfig(writeTempConfig("allow_subject_alt_names: false\n"))
		Expect(err).NotTo(HaveOccurred())

		myCA := ca.New(storage.New(GinkgoT().TempDir()), ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(applyCAConfig(myCA, cfg)).To(Succeed())
		Expect(myCA.AllowSubjectAltNames).To(BeFalse())
	})
})

// --- crl_chain_file wiring ---

var _ = Describe("crl_chain_file wiring", func() {
	// The setting is file-and-environment only, and its failure mode is total
	// silence: a value that never reaches ca.CRLChainFile leaves the feature
	// off with no error, no warning and no metric — the published chain simply
	// never gains the ancestor CRLs the operator configured.
	BeforeEach(func() { clearServerEnv() })

	It("is empty by default", func() {
		cfg, err := loadServerConfig("")
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.CRLChainFile).To(BeEmpty())
	})

	It("is read from the config file", func() {
		path := writeTempConfig("crl_chain_file: /etc/puppet-ca/upstream-crls.pem\n")
		cfg, err := loadServerConfig(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.CRLChainFile).To(Equal("/etc/puppet-ca/upstream-crls.pem"))
	})

	It("is read from the environment, which outranks the file", func() {
		path := writeTempConfig("crl_chain_file: /from/file.pem\n")
		setEnv("PUPPET_CA_CRL_CHAIN_FILE", "/from/env.pem")
		cfg, err := loadServerConfig(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.CRLChainFile).To(Equal("/from/env.pem"))
	})

	It("reaches the CA, which is the step whose absence is silent", func() {
		cfg, err := loadServerConfig(writeTempConfig("crl_chain_file: /etc/puppet-ca/upstream-crls.pem\n"))
		Expect(err).NotTo(HaveOccurred())

		myCA := ca.New(storage.New(GinkgoT().TempDir()), ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(applyCAConfig(myCA, cfg)).To(Succeed())
		Expect(myCA.CRLChainFile).To(Equal("/etc/puppet-ca/upstream-crls.pem"))
	})
})
