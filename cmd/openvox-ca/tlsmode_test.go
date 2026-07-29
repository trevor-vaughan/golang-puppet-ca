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
	"crypto/tls"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

var _ = Describe("serverConfig.tlsEnabled", func() {
	It("is false with neither certificate nor key", func() {
		Expect((&serverConfig{}).tlsEnabled()).To(BeFalse())
	})

	It("is true with both certificate and key", func() {
		Expect((&serverConfig{TLSCert: "c.pem", TLSKey: "k.pem"}).tlsEnabled()).To(BeTrue())
	})

	// Half-configured TLS stays off rather than erroring here, which is the
	// pre-existing behaviour: the listener comes up on plain HTTP and the
	// non-loopback guard is what refuses to start. Pinned because the whole
	// point of the helper is that every call site agrees on this answer.
	It("is false with only a certificate", func() {
		Expect((&serverConfig{TLSCert: "c.pem"}).tlsEnabled()).To(BeFalse())
	})

	It("is false with only a key", func() {
		Expect((&serverConfig{TLSKey: "k.pem"}).tlsEnabled()).To(BeFalse())
	})
})

var _ = Describe("buildAuthConfig", func() {
	var (
		myCA *ca.CA
		cfg  *serverConfig
	)

	BeforeEach(func() {
		store := storage.New(GinkgoT().TempDir())
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.example.com")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(context.Background())).To(Succeed())
		cfg = &serverConfig{}
	})

	It("pins the CA certificate the middleware verifies against", func() {
		authCfg, err := buildAuthConfig(cfg, myCA)
		Expect(err).NotTo(HaveOccurred())
		Expect(authCfg.CACert).To(BeIdenticalTo(myCA.CACert))
	})

	It("builds the allow list from puppet_server, trimming whitespace", func() {
		cfg.PuppetServer = "one.example.com, two.example.com ,,three.example.com"
		authCfg, err := buildAuthConfig(cfg, myCA)
		Expect(err).NotTo(HaveOccurred())
		Expect(authCfg.AllowList).To(HaveLen(3))
		Expect(authCfg.AllowList).To(HaveKey("two.example.com"))
	})

	It("merges puppet_server_file entries with puppet_server", func() {
		path := filepath.Join(GinkgoT().TempDir(), "servers.txt")
		Expect(os.WriteFile(path, []byte("# comment\nfromfile.example.com\n\n"), 0o644)).To(Succeed())
		cfg.PuppetServer = "inline.example.com"
		cfg.PuppetServerFile = path

		authCfg, err := buildAuthConfig(cfg, myCA)
		Expect(err).NotTo(HaveOccurred())
		Expect(authCfg.AllowList).To(HaveKey("inline.example.com"))
		Expect(authCfg.AllowList).To(HaveKey("fromfile.example.com"))
	})

	It("propagates an unreadable puppet_server_file rather than authorising nobody", func() {
		// Returning an empty allow list here would come up serving with no
		// admin able to reach the CA, which reads as a broken deployment
		// rather than as the configuration error it is.
		cfg.PuppetServerFile = filepath.Join(GinkgoT().TempDir(), "absent.txt")
		_, err := buildAuthConfig(cfg, myCA)
		Expect(err).To(HaveOccurred())
	})

	It("carries the pp_cli_auth and public-status flags through", func() {
		cfg.NoPpCliAuth = true
		cfg.AllowPublicStatus = true
		authCfg, err := buildAuthConfig(cfg, myCA)
		Expect(err).NotTo(HaveOccurred())
		Expect(authCfg.NoPpCliAuth).To(BeTrue())
		Expect(authCfg.AllowPublicStatus).To(BeTrue())
	})
})

var _ = Describe("serverConfig.validateTLS", func() {
	var cfg *serverConfig

	BeforeEach(func() {
		cfg = &serverConfig{TLSSelfProvision: true, Hostname: "puppet.example.com"}
	})

	It("accepts a minimal self-provision configuration", func() {
		Expect(cfg.validateTLS()).To(Succeed())
	})

	It("is a no-op when self-provision is off", func() {
		// Everything below is scoped to self-provision; the file route keeps
		// its long-standing behaviour of accepting whatever it is given.
		Expect((&serverConfig{TLSCert: "c.pem"}).validateTLS()).To(Succeed())
	})

	It("rejects self-provision alongside tls_cert", func() {
		// A silent precedence rule would leave the operator serving material
		// they did not think was in play.
		cfg.TLSCert = "c.pem"
		Expect(cfg.validateTLS()).To(MatchError(ContainSubstring("cannot be combined")))
	})

	It("rejects self-provision alongside tls_key", func() {
		cfg.TLSKey = "k.pem"
		Expect(cfg.validateTLS()).To(MatchError(ContainSubstring("cannot be combined")))
	})

	It("requires a hostname", func() {
		// Without it bootstrapCA's "puppet" fallback would produce a
		// certificate no client validates — a handshake failure presenting as
		// anything but the configuration error it is.
		cfg.Hostname = ""
		Expect(cfg.validateTLS()).To(MatchError(ContainSubstring("requires hostname")))
	})

	Describe("encrypted serving key", func() {
		It("refuses the auto-generated passphrase", func() {
			// It is written into cadir, so with an ephemeral cadir each replica
			// would encrypt under a different passphrase and none could read
			// the shared blob after a restart.
			cfg.TLSSelfProvisionEncryptKey = true
			Expect(cfg.validateTLS()).To(MatchError(ContainSubstring("requires an explicit passphrase")))
		})

		It("accepts an explicit passphrase file", func() {
			cfg.TLSSelfProvisionEncryptKey = true
			cfg.CAKeyPassphraseFile = "/etc/puppet-ca/passphrase"
			Expect(cfg.validateTLS()).To(Succeed())
		})

		It("accepts a passphrase from the environment", func() {
			cfg.TLSSelfProvisionEncryptKey = true
			GinkgoT().Setenv("PUPPET_CA_KEY_PASSPHRASE", "hunter2")
			Expect(cfg.validateTLS()).To(Succeed())
		})
	})

	Describe("revocation delay", func() {
		// Three states, per the csr_rate_limit convention already in this file:
		// unset (-1) takes the built-in default, 0 never revokes, and a
		// positive value is the operator's own choice.

		It("is unset by default, so 0 stays reachable", func() {
			cfg, err := loadServerConfig("")
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.TLSSelfProvisionRevokeAfterSec).To(Equal(-1))
		})

		It("resolves unset to 24 hours", func() {
			// Not "never": a second valid serving credential in circulation is
			// the worse outcome, and revoke_on_auto_renew already defaults to
			// keeping only the newest serial valid.
			cfg.TLSSelfProvisionRevokeAfterSec = -1
			Expect(cfg.servingRevokeAfter()).To(Equal(24 * time.Hour))
		})

		It("resolves an explicit 0 to never revoke", func() {
			cfg.TLSSelfProvisionRevokeAfterSec = 0
			Expect(cfg.servingRevokeAfter()).To(BeZero())
			Expect(cfg.validateTLS()).To(Succeed())
		})

		It("honours an explicit 0 from the config file", func() {
			// The point of the sentinel: a default must never make 0
			// unreachable.
			path := writeTempConfig("tls_self_provision_revoke_after_sec: 0\n")
			loaded, err := loadServerConfig(path)
			Expect(err).NotTo(HaveOccurred())
			Expect(loaded.TLSSelfProvisionRevokeAfterSec).To(BeZero())
			Expect(loaded.servingRevokeAfter()).To(BeZero())
		})

		It("honours an explicit 0 from the environment", func() {
			clearServerEnv()
			setEnv("PUPPET_CA_TLS_SELF_PROVISION_REVOKE_AFTER_SEC", "0")
			loaded, err := loadServerConfig("")
			Expect(err).NotTo(HaveOccurred())
			Expect(loaded.servingRevokeAfter()).To(BeZero())
		})

		It("resolves a configured value verbatim", func() {
			cfg.TLSSelfProvisionRevokeAfterSec = 7200
			Expect(cfg.servingRevokeAfter()).To(Equal(2 * time.Hour))
		})

		It("rejects a configured delay under twice the maintenance interval", func() {
			// A sibling replica notices a replacement within one maintenance
			// interval; revoking sooner breaks exactly what the delay protects.
			cfg.TLSSelfProvisionRevokeAfterSec = 3600
			Expect(cfg.validateTLS()).To(MatchError(ContainSubstring("at least twice")))
		})

		It("accepts a configured delay of exactly twice the interval", func() {
			cfg.TLSSelfProvisionRevokeAfterSec = 7200
			Expect(cfg.validateTLS()).To(Succeed())
		})

		It("scales the floor with a configured maintenance interval", func() {
			cfg.MaintenanceIntervalSec = 300
			cfg.TLSSelfProvisionRevokeAfterSec = 900
			Expect(cfg.validateTLS()).To(Succeed())

			cfg.TLSSelfProvisionRevokeAfterSec = 500
			Expect(cfg.validateTLS()).To(MatchError(ContainSubstring("at least twice")))
		})

		It("raises the unset default to the floor instead of refusing to start", func() {
			// The reason for the sentinel rather than a plain 86400 default:
			// with a long maintenance interval the floor exceeds 24h, and a
			// value the operator never set must not be what fails startup.
			cfg.MaintenanceIntervalSec = 13 * 60 * 60
			cfg.TLSSelfProvisionRevokeAfterSec = -1

			Expect(cfg.validateTLS()).To(Succeed())
			Expect(cfg.servingRevokeAfter()).To(Equal(26 * time.Hour))
		})

		It("never shortens the unset default below 24 hours", func() {
			cfg.MaintenanceIntervalSec = 60
			cfg.TLSSelfProvisionRevokeAfterSec = -1
			Expect(cfg.servingRevokeAfter()).To(Equal(24 * time.Hour))
		})
	})
})

var _ = Describe("servingCertHolder", func() {
	It("errors rather than returning nil when nothing is installed", func() {
		// nil, nil makes crypto/tls report a confusing internal error to the
		// client instead of naming the problem.
		_, err := (&servingCertHolder{}).GetCertificate(nil)
		Expect(err).To(MatchError(ContainSubstring("no serving certificate")))
	})

	It("returns the installed certificate, and the replacement after a swap", func() {
		holder := &servingCertHolder{}
		first := &tls.Certificate{Certificate: [][]byte{{1}}}
		second := &tls.Certificate{Certificate: [][]byte{{2}}}

		holder.Set(first)
		got, err := holder.GetCertificate(nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(BeIdenticalTo(first))

		holder.Set(second)
		got, err = holder.GetCertificate(nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(BeIdenticalTo(second))
	})
})
