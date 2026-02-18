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
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/tvaughan/puppet-ca/internal/ca"
	"github.com/tvaughan/puppet-ca/internal/storage"
)

var _ = Describe("CA Generate", func() {
	var (
		tmpDir string
		myCA   *ca.CA
		store  *storage.StorageService
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-generate-test")
		Expect(err).NotTo(HaveOccurred())

		store = storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")

		Expect(store.EnsureDirs()).To(Succeed())
		Expect(os.WriteFile(store.CAKeyPath(), cachedKeyPEM, 0640)).To(Succeed())
		Expect(os.WriteFile(store.CACertPath(), cachedCrtPEM, 0644)).To(Succeed())
		Expect(store.UpdateCRL(cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial("0001")).To(Succeed())
		Expect(os.WriteFile(store.InventoryPath(), []byte{}, 0644)).To(Succeed())
		Expect(myCA.Init()).To(Succeed())
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	It("creates a valid cert and key for a new subject", func() {
		result, err := myCA.Generate("gen-node", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(result).NotTo(BeNil())

		// Key PEM must be parseable.
		keyBlock, _ := pem.Decode(result.PrivateKeyPEM)
		Expect(keyBlock).NotTo(BeNil())
		key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(key.N.BitLen()).To(Equal(2048))

		// Cert PEM must be parseable and signed by the CA.
		certBlock, _ := pem.Decode(result.CertificatePEM)
		Expect(certBlock).NotTo(BeNil())
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(cert.Subject.CommonName).To(Equal("gen-node"))

		caCertBlock, _ := pem.Decode(cachedCrtPEM)
		caCert, _ := x509.ParseCertificate(caCertBlock.Bytes)
		Expect(cert.CheckSignatureFrom(caCert)).To(Succeed())

		// Private key must be on disk.
		_, err = os.Stat(store.PrivateKeyPath("gen-node"))
		Expect(err).NotTo(HaveOccurred())

		// Cert must be in the signed dir.
		Expect(store.HasCert("gen-node")).To(BeTrue())
		// No pending CSR should remain after signing.
		Expect(store.HasCSR("gen-node")).To(BeFalse())
	})

	It("includes DNS alt names when requested", func() {
		result, err := myCA.Generate("gen-san-node", []string{"alt1.example.com", "alt2.example.com"})
		Expect(err).NotTo(HaveOccurred())

		certBlock, _ := pem.Decode(result.CertificatePEM)
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(cert.DNSNames).To(ConsistOf("alt1.example.com", "alt2.example.com"))
	})

	It("returns ErrCertExists when cert already exists for subject", func() {
		_, err := myCA.Generate("gen-dup", nil)
		Expect(err).NotTo(HaveOccurred())

		_, err = myCA.Generate("gen-dup", nil)
		Expect(err).To(HaveOccurred())
		Expect(errors.Is(err, ca.ErrCertExists)).To(BeTrue())
	})

	It("returns error for invalid subject name", func() {
		_, err := myCA.Generate("INVALID/Name", nil)
		Expect(err).To(HaveOccurred())
	})

	It("generated private key matches the certificate's public key", func() {
		result, err := myCA.Generate("gen-key-match", nil)
		Expect(err).NotTo(HaveOccurred())

		keyBlock, _ := pem.Decode(result.PrivateKeyPEM)
		key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())

		certBlock, _ := pem.Decode(result.CertificatePEM)
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())

		certPub, ok := cert.PublicKey.(*rsa.PublicKey)
		Expect(ok).To(BeTrue(), "cert public key should be RSA")
		Expect(key.PublicKey.N.Cmp(certPub.N)).To(Equal(0))
		Expect(key.PublicKey.E).To(Equal(certPub.E))
	})

	It("private key file exists on disk at expected path", func() {
		_, err := myCA.Generate("gen-disk-key", nil)
		Expect(err).NotTo(HaveOccurred())

		keyPath := filepath.Join(tmpDir, "private", "gen-disk-key_key.pem")
		data, err := os.ReadFile(keyPath)
		Expect(err).NotTo(HaveOccurred())
		Expect(data).To(ContainSubstring("RSA PRIVATE KEY"))
	})
})
