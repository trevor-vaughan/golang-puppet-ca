// Copyright (C) 2026 Trevor Vaughan
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

package ca_test

import (
	"crypto/x509"
	"encoding/pem"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/tvaughan/puppet-ca/internal/ca"
	"github.com/tvaughan/puppet-ca/internal/storage"
	"github.com/tvaughan/puppet-ca/internal/testutil"
)

var _ = Describe("ImportCA", func() {
	var tmpDir string

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-import-test")
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	It("writes cert, key, and CRL files and initialises serial and inventory", func() {
		store := storage.New(tmpDir)
		Expect(ca.ImportCA(store, cachedCrtPEM, cachedKeyPEM, cachedCrlPEM)).To(Succeed())

		// All expected files must exist.
		for _, path := range []string{
			store.CACertPath(),
			store.CAKeyPath(),
			store.CRLPath(),
			store.InventoryPath(),
			store.SerialPath(),
		} {
			_, err := os.Stat(path)
			Expect(err).NotTo(HaveOccurred(), "expected file to exist: %s", path)
		}

		// File contents must round-trip correctly.
		certData, _ := os.ReadFile(store.CACertPath())
		Expect(certData).To(Equal(cachedCrtPEM))
		keyData, _ := os.ReadFile(store.CAKeyPath())
		Expect(keyData).To(Equal(cachedKeyPEM))
	})

	It("generates a fresh CRL when crlPEM is nil", func() {
		store := storage.New(tmpDir)
		Expect(ca.ImportCA(store, cachedCrtPEM, cachedKeyPEM, nil)).To(Succeed())

		crlData, err := store.GetCRL()
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(crlData)
		Expect(block).NotTo(BeNil())
		_, err = x509.ParseRevocationList(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
	})

	It("does not overwrite an existing serial file", func() {
		store := storage.New(tmpDir)
		Expect(store.EnsureDirs()).To(Succeed())
		Expect(store.WriteSerial("00FF")).To(Succeed())

		Expect(ca.ImportCA(store, cachedCrtPEM, cachedKeyPEM, nil)).To(Succeed())

		serialData, err := os.ReadFile(store.SerialPath())
		Expect(err).NotTo(HaveOccurred())
		Expect(string(serialData)).To(Equal("00FF"))
	})

	It("rejects a cert/key mismatch", func() {
		// Generate a second CA — the cert from it will not match cachedKeyPEM.
		altKeyPEM, altCertPEM, _, err := testutil.GenerateTestCA()
		Expect(err).NotTo(HaveOccurred())
		_ = altKeyPEM

		store := storage.New(tmpDir)
		// Pass the alt CA cert but the original key — they don't match.
		err = ca.ImportCA(store, altCertPEM, cachedKeyPEM, nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("does not match"))
	})

	It("rejects a non-CA certificate", func() {
		// Import the cached CA first so we can generate a leaf cert from it.
		store := storage.New(tmpDir)
		Expect(ca.ImportCA(store, cachedCrtPEM, cachedKeyPEM, nil)).To(Succeed())

		// Bootstrap a CA from the imported files and generate a leaf cert.
		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(myCA.Init()).To(Succeed())
		leafResult, err := myCA.Generate("leaf-for-import-test", nil)
		Expect(err).NotTo(HaveOccurred())

		// Now try to import the leaf cert as a CA cert.
		store2 := storage.New(tmpDir + "-v2")
		err = ca.ImportCA(store2, leafResult.CertificatePEM, leafResult.PrivateKeyPEM, nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("IsCA"))
	})
})
