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

package storage_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/tvaughan/puppet-ca/internal/storage"
)

var _ = Describe("StorageService", func() {
	var (
		tmpDir string
		store  *storage.StorageService
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-storage-test")
		Expect(err).NotTo(HaveOccurred())
		store = storage.New(tmpDir)
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	// --- Path helpers ---

	Describe("Path helpers", func() {
		It("returns paths rooted in baseDir", func() {
			Expect(store.CADir()).To(Equal(tmpDir))
			Expect(store.CACertPath()).To(Equal(filepath.Join(tmpDir, "ca_crt.pem")))
			Expect(store.CAKeyPath()).To(Equal(filepath.Join(tmpDir, "private", "ca_key.pem")))
			Expect(store.CAPubKeyPath()).To(Equal(filepath.Join(tmpDir, "ca_pub.pem")))
			Expect(store.CRLPath()).To(Equal(filepath.Join(tmpDir, "ca_crl.pem")))
			Expect(store.InventoryPath()).To(Equal(filepath.Join(tmpDir, "inventory.txt")))
			Expect(store.CSRDir()).To(Equal(filepath.Join(tmpDir, "requests")))
			Expect(store.SignedDir()).To(Equal(filepath.Join(tmpDir, "signed")))
		})
	})

	// --- EnsureDirs ---

	Describe("EnsureDirs", func() {
		It("creates all required subdirectories", func() {
			Expect(store.EnsureDirs()).To(Succeed())
			for _, sub := range []string{"signed", "requests", "private"} {
				info, err := os.Stat(filepath.Join(tmpDir, sub))
				Expect(err).NotTo(HaveOccurred(), "missing subdirectory: %s", sub)
				Expect(info.IsDir()).To(BeTrue())
			}
		})

		It("is idempotent", func() {
			Expect(store.EnsureDirs()).To(Succeed())
			Expect(store.EnsureDirs()).To(Succeed())
		})
	})

	// --- Serial ---

	Describe("Serial", func() {
		BeforeEach(func() {
			Expect(store.EnsureDirs()).To(Succeed())
			Expect(store.WriteSerial("0001")).To(Succeed())
		})

		It("IncrementSerial returns the current value and advances the file", func() {
			val, err := store.IncrementSerial()
			Expect(err).NotTo(HaveOccurred())
			Expect(val).To(Equal("0001"))

			val2, err := store.IncrementSerial()
			Expect(err).NotTo(HaveOccurred())
			Expect(val2).To(Equal("0002"))
		})

		It("returns an error when the serial file is missing", func() {
			Expect(os.Remove(filepath.Join(tmpDir, "serial"))).To(Succeed())
			_, err := store.IncrementSerial()
			Expect(err).To(HaveOccurred())
		})

		It("returns an error when the serial file contains invalid data", func() {
			Expect(os.WriteFile(filepath.Join(tmpDir, "serial"), []byte("ZZZZ"), 0644)).To(Succeed())
			_, err := store.IncrementSerial()
			Expect(err).To(HaveOccurred())
		})
	})

	// --- Inventory ---

	Describe("Inventory", func() {
		BeforeEach(func() {
			Expect(store.EnsureDirs()).To(Succeed())
			f, err := os.Create(store.InventoryPath())
			Expect(err).NotTo(HaveOccurred())
			f.Close()
		})

		It("AppendInventory and ReadInventory roundtrip", func() {
			Expect(store.AppendInventory("0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1")).To(Succeed())
			Expect(store.AppendInventory("0002 2024-01-02T00:00:00UTC 2029-01-02T00:00:00UTC /node2")).To(Succeed())

			data, err := store.ReadInventory()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(data)).To(ContainSubstring("/node1"))
			Expect(string(data)).To(ContainSubstring("/node2"))
		})

		It("ReadInventory returns an error when inventory file is missing", func() {
			Expect(os.Remove(store.InventoryPath())).To(Succeed())
			_, err := store.ReadInventory()
			Expect(err).To(HaveOccurred())
		})

		It("AppendInventory is safe under concurrent writes", func() {
			const n = 20
			var wg sync.WaitGroup
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func(idx int) {
					defer wg.Done()
					entry := fmt.Sprintf("%04X 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node-%d", idx, idx)
					Expect(store.AppendInventory(entry)).To(Succeed())
				}(i)
			}
			wg.Wait()

			data, err := store.ReadInventory()
			Expect(err).NotTo(HaveOccurred())
			lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
			Expect(lines).To(HaveLen(n))
		})
	})

	// --- CRL ---

	Describe("CRL", func() {
		BeforeEach(func() {
			Expect(store.EnsureDirs()).To(Succeed())
		})

		It("UpdateCRL and GetCRL roundtrip", func() {
			data := []byte("-----BEGIN X509 CRL-----\nfakedata\n-----END X509 CRL-----\n")
			Expect(store.UpdateCRL(data)).To(Succeed())

			got, err := store.GetCRL()
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(Equal(data))
		})

		It("GetCRL returns an error when no CRL file exists", func() {
			_, err := store.GetCRL()
			Expect(err).To(HaveOccurred())
		})
	})

	// --- CSR operations ---

	Describe("CSR operations", func() {
		const subject = "test-node"
		csrData := []byte("-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----\n")

		BeforeEach(func() {
			Expect(store.EnsureDirs()).To(Succeed())
		})

		It("SaveCSR / GetCSR roundtrip", func() {
			Expect(store.SaveCSR(subject, csrData)).To(Succeed())
			got, err := store.GetCSR(subject)
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(Equal(csrData))
		})

		It("HasCSR reflects presence on disk", func() {
			Expect(store.HasCSR(subject)).To(BeFalse())
			Expect(store.SaveCSR(subject, csrData)).To(Succeed())
			Expect(store.HasCSR(subject)).To(BeTrue())
			Expect(store.DeleteCSR(subject)).To(Succeed())
			Expect(store.HasCSR(subject)).To(BeFalse())
		})

		It("GetCSR returns an error for a missing subject", func() {
			_, err := store.GetCSR(subject)
			Expect(err).To(HaveOccurred())
		})

		It("DeleteCSR returns an error for a missing subject", func() {
			err := store.DeleteCSR(subject)
			Expect(err).To(HaveOccurred())
		})
	})

	// --- Certificate operations ---

	Describe("Certificate operations", func() {
		const subject = "test-node"
		certData := []byte("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n")

		BeforeEach(func() {
			Expect(store.EnsureDirs()).To(Succeed())
		})

		It("SaveCert / GetCert roundtrip", func() {
			Expect(store.SaveCert(subject, certData)).To(Succeed())
			got, err := store.GetCert(subject)
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(Equal(certData))
		})

		It("HasCert reflects presence on disk", func() {
			Expect(store.HasCert(subject)).To(BeFalse())
			Expect(store.SaveCert(subject, certData)).To(Succeed())
			Expect(store.HasCert(subject)).To(BeTrue())
			Expect(store.DeleteCert(subject)).To(Succeed())
			Expect(store.HasCert(subject)).To(BeFalse())
		})

		It("GetCert returns an error for a missing subject", func() {
			_, err := store.GetCert(subject)
			Expect(err).To(HaveOccurred())
		})

		It("DeleteCert returns an error for a missing subject", func() {
			err := store.DeleteCert(subject)
			Expect(err).To(HaveOccurred())
		})
	})
})
