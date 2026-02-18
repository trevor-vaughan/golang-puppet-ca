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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/tvaughan/puppet-ca/internal/ca"
	"github.com/tvaughan/puppet-ca/internal/storage"
	"github.com/tvaughan/puppet-ca/internal/testutil"
)

var (
	cachedKeyPEM []byte
	cachedCrtPEM []byte
	cachedCrlPEM []byte
)

var _ = BeforeSuite(func() {
	var err error
	cachedKeyPEM, cachedCrtPEM, cachedCrlPEM, err = testutil.GenerateTestCA()
	Expect(err).NotTo(HaveOccurred())
})

var _ = Describe("CA Lifecycle", func() {
	var (
		tmpDir string
		myCA   *ca.CA
		store  *storage.StorageService
		asCfg  ca.AutosignConfig
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-test")
		Expect(err).NotTo(HaveOccurred())

		store = storage.New(tmpDir)
		asCfg = ca.AutosignConfig{Mode: "off"}
		myCA = ca.New(store, asCfg, "puppet.test")

		// Optimization: Pre-seed the CA with keys generated in BeforeSuite
		// This avoids generating 4096-bit keys for every test case.
		err = store.EnsureDirs()
		Expect(err).NotTo(HaveOccurred())

		err = os.WriteFile(store.CAKeyPath(), cachedKeyPEM, 0640)
		Expect(err).NotTo(HaveOccurred())
		err = os.WriteFile(store.CACertPath(), cachedCrtPEM, 0644)
		Expect(err).NotTo(HaveOccurred())
		err = store.UpdateCRL(cachedCrlPEM)
		Expect(err).NotTo(HaveOccurred())

		// Also pre-seed Serial and Inventory which are normally created by bootstrapCA
		err = store.WriteSerial("0001")
		Expect(err).NotTo(HaveOccurred())
		err = os.WriteFile(store.InventoryPath(), []byte{}, 0644)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	Context("Initialization", func() {
		It("should load existing CA successfully", func() {
			err := myCA.Init()
			Expect(err).NotTo(HaveOccurred())

			// Verify they are the same
			loadedCert, err := os.ReadFile(store.CACertPath())
			Expect(err).NotTo(HaveOccurred())
			Expect(loadedCert).To(Equal(cachedCrtPEM))
		})
	})

	Context("CSR Handling", func() {
		var csrPEM []byte

		BeforeEach(func() {
			var err error
			err = myCA.Init()
			Expect(err).NotTo(HaveOccurred())
			csrPEM, err = testutil.GenerateCSR("test-node")
			Expect(err).NotTo(HaveOccurred())
		})

		It("should save a valid CSR but not sign it when autosign is off", func() {
			saved, err := myCA.SaveRequest("test-node", csrPEM)
			Expect(err).NotTo(HaveOccurred())
			Expect(saved).To(BeFalse(), "Expected saved=false (autosign off)")

			_, err = os.Stat(filepath.Join(tmpDir, "requests", "test-node.pem"))
			Expect(os.IsNotExist(err)).To(BeFalse(), "CSR file should be created")
		})

		It("should sign a valid CSR", func() {
			_, err := myCA.SaveRequest("test-node", csrPEM)
			Expect(err).NotTo(HaveOccurred())

			certPEM, err := myCA.Sign("test-node")
			Expect(err).NotTo(HaveOccurred())

			// Verify Cert on disk
			_, err = os.Stat(filepath.Join(tmpDir, "signed", "test-node.pem"))
			Expect(os.IsNotExist(err)).To(BeFalse(), "Signed cert file should be created")

			// Verify Cert Validity
			block, _ := pem.Decode(certPEM)
			Expect(block).NotTo(BeNil(), "Failed to decode generated cert PEM")

			cert, err := x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())

			Expect(cert.Subject.CommonName).To(Equal("test-node"))

			// Verify it is signed by CA
			caCertPEM, err := os.ReadFile(filepath.Join(tmpDir, "ca_crt.pem"))
			Expect(err).NotTo(HaveOccurred())
			caBlock, _ := pem.Decode(caCertPEM)
			caCert, _ := x509.ParseCertificate(caBlock.Bytes)

			err = cert.CheckSignatureFrom(caCert)
			Expect(err).NotTo(HaveOccurred(), "Certificate validation against CA failed")
		})
	})

	Context("Negative Tests", func() {
		BeforeEach(func() {
			err := myCA.Init()
			Expect(err).NotTo(HaveOccurred())
		})

		It("should fail to sign non-existent CSR", func() {
			_, err := myCA.Sign("ghost-node")
			Expect(err).To(HaveOccurred())
		})

		It("should fail to sign invalid subject name", func() {
			_, err := myCA.Sign("bad/name")
			Expect(err).To(HaveOccurred())
		})

		It("should fail to save invalid subject name", func() {
			csrPEM, _ := testutil.GenerateCSR("bad/name")
			_, err := myCA.SaveRequest("bad/name", csrPEM)
			Expect(err).To(HaveOccurred())
		})

		It("should fail to sign garbage CSR data", func() {
			// Save garbage manually
			err := store.SaveCSR("garbage-node", []byte("GARBAGE"))
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.Sign("garbage-node")
			Expect(err).To(HaveOccurred())
		})

		It("should reject a subject containing ..", func() {
			_, err := myCA.Sign("a..b")
			Expect(err).To(HaveOccurred())
			_, err = myCA.SaveRequest("a..b", []byte("fake"))
			Expect(err).To(HaveOccurred())
		})
	})
})

// --- CA Bootstrap ---

var _ = Describe("CA Bootstrap", func() {
	It("bootstraps a new CA when no files exist", func() {
		tmpDir, err := os.MkdirTemp("", "puppet-ca-bootstrap-test")
		Expect(err).NotTo(HaveOccurred())
		defer os.RemoveAll(tmpDir)

		store := storage.New(tmpDir)
		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.bootstrap.test")
		Expect(myCA.Init()).To(Succeed())

		Expect(myCA.CACert).NotTo(BeNil())
		Expect(myCA.CAKey).NotTo(BeNil())
		Expect(myCA.CACert.Subject.CommonName).To(Equal("Puppet CA: puppet.bootstrap.test"))
		Expect(myCA.CACert.IsCA).To(BeTrue())

		// All expected files should exist on disk.
		for _, path := range []string{store.CACertPath(), store.CAKeyPath(), store.CRLPath(), store.InventoryPath()} {
			_, err := os.Stat(path)
			Expect(err).NotTo(HaveOccurred(), "expected file to exist: %s", path)
		}
	})
})

// --- Revocation ---

var _ = Describe("CA Revocation", func() {
	var (
		tmpDir string
		myCA   *ca.CA
		store  *storage.StorageService
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-revoke-test")
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

	It("marks a signed certificate as revoked in the CRL", func() {
		csrPEM, err := testutil.GenerateCSR("revoke-node")
		Expect(err).NotTo(HaveOccurred())

		_, err = myCA.SaveRequest("revoke-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.Sign("revoke-node")
		Expect(err).NotTo(HaveOccurred())

		Expect(myCA.IsRevoked("revoke-node")).To(BeFalse())

		Expect(myCA.Revoke("revoke-node")).To(Succeed())
		Expect(myCA.IsRevoked("revoke-node")).To(BeTrue())
	})

	It("IsRevoked returns false for a node that was never signed", func() {
		Expect(myCA.IsRevoked("ghost-node")).To(BeFalse())
	})

	It("returns an error when revoking a subject with no inventory entry", func() {
		Expect(myCA.Revoke("never-signed")).To(HaveOccurred())
	})
})

// --- SaveRequest edge cases ---

var _ = Describe("CA SaveRequest edge cases", func() {
	var (
		tmpDir string
		myCA   *ca.CA
		store  *storage.StorageService
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-savereq-test")
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

	It("returns ErrCertExists when a valid cert already exists for the subject", func() {
		csrPEM, err := testutil.GenerateCSR("dup-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest("dup-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.Sign("dup-node")
		Expect(err).NotTo(HaveOccurred())

		// Second SaveRequest should fail with ErrCertExists.
		csrPEM2, err := testutil.GenerateCSR("dup-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest("dup-node", csrPEM2)
		Expect(err).To(HaveOccurred())
		Expect(errors.Is(err, ca.ErrCertExists)).To(BeTrue())

		// Malformed CSR must not be written to disk.
		Expect(store.HasCSR("dup-node")).To(BeFalse())
	})

	It("allows re-registration after a certificate is revoked", func() {
		csrPEM, err := testutil.GenerateCSR("rereg-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest("rereg-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.Sign("rereg-node")
		Expect(err).NotTo(HaveOccurred())

		Expect(myCA.Revoke("rereg-node")).To(Succeed())

		csrPEM2, err := testutil.GenerateCSR("rereg-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest("rereg-node", csrPEM2)
		Expect(err).NotTo(HaveOccurred())

		// Old cert must be gone.
		Expect(store.HasCert("rereg-node")).To(BeFalse())
		// New CSR must be on disk.
		Expect(store.HasCSR("rereg-node")).To(BeTrue())
	})

	It("rejects a malformed CSR without writing anything to disk", func() {
		_, err := myCA.SaveRequest("bad-csr-node", []byte("NOT PEM"))
		Expect(err).To(HaveOccurred())
		Expect(store.HasCSR("bad-csr-node")).To(BeFalse())
	})
})

// --- Autosign ---

var _ = Describe("CA Autosign", func() {
	var (
		tmpDir string
		store  *storage.StorageService
	)

	newCA := func(cfg ca.AutosignConfig) *ca.CA {
		myCA := ca.New(store, cfg, "puppet.test")
		Expect(os.WriteFile(store.CAKeyPath(), cachedKeyPEM, 0640)).To(Succeed())
		Expect(os.WriteFile(store.CACertPath(), cachedCrtPEM, 0644)).To(Succeed())
		Expect(store.UpdateCRL(cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial("0001")).To(Succeed())
		Expect(os.WriteFile(store.InventoryPath(), []byte{}, 0644)).To(Succeed())
		Expect(myCA.Init()).To(Succeed())
		return myCA
	}

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-autosign-test")
		Expect(err).NotTo(HaveOccurred())
		store = storage.New(tmpDir)
		Expect(store.EnsureDirs()).To(Succeed())
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	It("autosign=true immediately signs the CSR", func() {
		myCA := newCA(ca.AutosignConfig{Mode: "true"})
		csrPEM, err := testutil.GenerateCSR("auto-node")
		Expect(err).NotTo(HaveOccurred())

		signed, err := myCA.SaveRequest("auto-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		Expect(signed).To(BeTrue())
		Expect(store.HasCert("auto-node")).To(BeTrue())
		Expect(store.HasCSR("auto-node")).To(BeFalse(), "CSR should be deleted after signing")
	})

	It("autosign=file signs when CN matches a glob pattern", func() {
		autosignFile, err := os.CreateTemp(tmpDir, "autosign-*.conf")
		Expect(err).NotTo(HaveOccurred())
		_, err = autosignFile.WriteString("# comment\n*.example.com\n")
		Expect(err).NotTo(HaveOccurred())
		autosignFile.Close()

		myCA := newCA(ca.AutosignConfig{Mode: "file", FileOrPath: autosignFile.Name()})

		matchingCSR, err := testutil.GenerateCSR("host.example.com")
		Expect(err).NotTo(HaveOccurred())
		signed, err := myCA.SaveRequest("host.example.com", matchingCSR)
		Expect(err).NotTo(HaveOccurred())
		Expect(signed).To(BeTrue())
	})

	It("autosign=file queues CSR when CN does not match any pattern", func() {
		autosignFile, err := os.CreateTemp(tmpDir, "autosign-*.conf")
		Expect(err).NotTo(HaveOccurred())
		_, err = autosignFile.WriteString("*.example.com\n")
		Expect(err).NotTo(HaveOccurred())
		autosignFile.Close()

		myCA := newCA(ca.AutosignConfig{Mode: "file", FileOrPath: autosignFile.Name()})

		noMatchCSR, err := testutil.GenerateCSR("other.org")
		Expect(err).NotTo(HaveOccurred())
		signed, err := myCA.SaveRequest("other.org", noMatchCSR)
		Expect(err).NotTo(HaveOccurred())
		Expect(signed).To(BeFalse())
		Expect(store.HasCSR("other.org")).To(BeTrue())
	})
})

// --- ValidateSubject ---

var _ = Describe("ValidateSubject", func() {
	DescribeTable("valid subjects",
		func(s string) { Expect(ca.ValidateSubject(s)).To(Succeed()) },
		Entry("simple hostname", "puppet"),
		Entry("FQDN", "node.example.com"),
		Entry("with hyphens", "my-node-01"),
		Entry("with underscores", "my_node"),
	)

	DescribeTable("invalid subjects",
		func(s string) { Expect(ca.ValidateSubject(s)).To(HaveOccurred()) },
		Entry("contains slash", "bad/name"),
		Entry("contains double-dot", "a..b"),
		Entry("double-dot only", ".."),
		Entry("uppercase letters", "BadNode"),
		Entry("empty string", ""),
	)
})

// --- CA:TRUE rejection ---

var _ = Describe("CA sign rejects CA:TRUE extension", func() {
	var (
		tmpDir string
		myCA   *ca.CA
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-catrue-test")
		Expect(err).NotTo(HaveOccurred())

		store := storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")

		Expect(store.EnsureDirs()).To(Succeed())
		Expect(os.WriteFile(store.CAKeyPath(), cachedKeyPEM, 0640)).To(Succeed())
		Expect(os.WriteFile(store.CACertPath(), cachedCrtPEM, 0644)).To(Succeed())
		Expect(store.UpdateCRL(cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial("0001")).To(Succeed())
		Expect(os.WriteFile(store.InventoryPath(), []byte{}, 0644)).To(Succeed())
		Expect(myCA.Init()).To(Succeed())
	})

	AfterEach(func() { os.RemoveAll(tmpDir) })

	It("returns an error containing the OID when BasicConstraints CA:TRUE is present", func() {
		// Build a CSR with BasicConstraints CA:TRUE (OID 2.5.29.19).
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())

		bcVal, err := asn1.Marshal(struct {
			IsCA bool `asn1:"optional"`
		}{IsCA: true})
		Expect(err).NotTo(HaveOccurred())

		csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "evil-ca"},
			ExtraExtensions: []pkix.Extension{{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
				Critical: true,
				Value:    bcVal,
			}},
		}, key)
		Expect(err).NotTo(HaveOccurred())

		csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

		// Submit the CSR (valid for storage purposes).
		_, err = myCA.SaveRequest("evil-ca", csrPEM)
		Expect(err).NotTo(HaveOccurred())

		// Signing must fail with a message that matches Puppet CA's response.
		_, err = myCA.Sign("evil-ca")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Found extensions"))
		Expect(err.Error()).To(ContainSubstring("2.5.29.19"))
	})
})
