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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// serverEnvVars is the full list of env vars read by applyServerEnv.
var serverEnvVars = []string{
	"PUPPET_CA_CADIR",
	"PUPPET_CA_AUTOSIGN_CONFIG",
	"PUPPET_CA_HOST",
	"PUPPET_CA_PORT",
	"PUPPET_CA_HOSTNAME",
	"PUPPET_CA_VERBOSITY",
	"PUPPET_CA_LOGFILE",
	"PUPPET_CA_TLS_CERT",
	"PUPPET_CA_TLS_KEY",
	"PUPPET_CA_TLS_SELF_PROVISION",
	"PUPPET_CA_TLS_SELF_PROVISION_NAMES",
	"PUPPET_CA_TLS_SELF_PROVISION_RENEW_BEFORE_SEC",
	"PUPPET_CA_TLS_SELF_PROVISION_ENCRYPT_KEY",
	"PUPPET_CA_TLS_SELF_PROVISION_REVOKE_AFTER_SEC",
	"PUPPET_CA_MAINTENANCE_INTERVAL_SEC",
	"PUPPET_CA_PUPPET_SERVER",
	"PUPPET_CA_PUPPET_SERVER_FILE",
	"PUPPET_CA_NO_PP_CLI_AUTH",
	"PUPPET_CA_NO_TLS_REQUIRED",
	"PUPPET_CA_OCSP_URL",
	"PUPPET_CA_CA_KEY_ALGO",
	"PUPPET_CA_CA_KEY_SIZE",
	"PUPPET_CA_LEAF_KEY_ALGO",
	"PUPPET_CA_LEAF_KEY_SIZE",
	"PUPPET_CA_CA_SUBJECT_ORG",
	"PUPPET_CA_CA_SUBJECT_OU",
	"PUPPET_CA_CA_SUBJECT_COUNTRY",
	"PUPPET_CA_CA_SUBJECT_LOCALITY",
	"PUPPET_CA_CA_SUBJECT_PROVINCE",
	"PUPPET_CA_CA_PATH_LENGTH",
	"PUPPET_CA_CA_VALIDITY_DAYS",
	"PUPPET_CA_LEAF_VALIDITY_DAYS",
	"PUPPET_CA_SHUTDOWN_TIMEOUT_SEC",
	"PUPPET_CA_DISABLE_CRL_REFRESH",
	"PUPPET_CA_CRL_REFRESH_INTERVAL_SEC",
	"PUPPET_CA_CRL_REFRESH_BEFORE_SEC",
	"PUPPET_CA_REVOKE_ON_AUTO_RENEW",
	"PUPPET_CA_ENABLE_EXPIRED_CERT_CLEANUP",
	"PUPPET_CA_EXPIRED_CERT_RETENTION_SEC",
	"PUPPET_CA_EXPIRED_CERT_CLEANUP_INTERVAL_SEC",
	"PUPPET_CA_CA_KEY_PROVIDER",
	"PUPPET_CA_OPENBAO_ADDR",
	"PUPPET_CA_OPENBAO_TRANSIT_MOUNT",
	"PUPPET_CA_OPENBAO_KEY_NAME",
	"PUPPET_CA_OPENBAO_TLS_CA_FILE",
	"PUPPET_CA_OPENBAO_TLS_CERT_FILE",
	"PUPPET_CA_OPENBAO_TLS_KEY_FILE",
	"PUPPET_CA_OPENBAO_AUTH_METHOD",
	"PUPPET_CA_OPENBAO_APPROLE_MOUNT",
	"PUPPET_CA_OPENBAO_APPROLE_ROLE_ID",
	"PUPPET_CA_OPENBAO_APPROLE_ROLE_ID_FILE",
	"PUPPET_CA_OPENBAO_APPROLE_SECRET_ID_FILE",
	"PUPPET_CA_OPENBAO_TOKEN_FILE",
	"PUPPET_CA_OPENBAO_KUBERNETES_MOUNT",
	"PUPPET_CA_OPENBAO_KUBERNETES_ROLE",
	"PUPPET_CA_OPENBAO_KUBERNETES_JWT_FILE",
}

// setEnv sets an environment variable for the duration of the current spec,
// saving the prior value and restoring it via DeferCleanup. Go's t.Setenv is
// unavailable inside Ginkgo nodes, so this preserves the same save/restore
// semantics without leaking into sibling specs.
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

// clearServerEnv unsets all PUPPET_CA_* vars and restores them after the spec.
func clearServerEnv() {
	GinkgoHelper()
	for _, key := range serverEnvVars {
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
		// The zero value of RevokeOnAutoRenew is already false, so assert the
		// env var flips it to true — a value distinct from the zero value —
		// which proves the env key is parsed and wired to the right field. A
		// typo in the env key would then leave it false and fail this entry.
		Entry("REVOKE_ON_AUTO_RENEW", "PUPPET_CA_REVOKE_ON_AUTO_RENEW", "true",
			func(c *serverConfig) bool { return c.RevokeOnAutoRenew }, "RevokeOnAutoRenew"),
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
