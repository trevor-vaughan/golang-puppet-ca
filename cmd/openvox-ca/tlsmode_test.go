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
	"os"
	"path/filepath"

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
