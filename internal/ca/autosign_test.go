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
	"encoding/pem"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/tvaughan/puppet-ca/internal/ca"
)

// buildCSR returns a PEM-encoded CSR and parsed *x509.CertificateRequest for
// the given Common Name, using a freshly generated RSA key.
func buildCSR(cn string) ([]byte, *x509.CertificateRequest) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())

	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	derBytes, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	Expect(err).NotTo(HaveOccurred())

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: derBytes})
	csr, err := x509.ParseCertificateRequest(derBytes)
	Expect(err).NotTo(HaveOccurred())

	return pemBytes, csr
}

var _ = Describe("CheckAutosign", func() {
	var (
		tmpDir string
		csrPEM []byte
		csr    *x509.CertificateRequest
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-autosign-check-test")
		Expect(err).NotTo(HaveOccurred())
		csrPEM, csr = buildCSR("test-node.example.com")
	})

	AfterEach(func() { os.RemoveAll(tmpDir) })

	// ── mode = off ────────────────────────────────────────────────────────────
	Describe("mode=off (default)", func() {
		It("never signs", func() {
			ok, err := ca.CheckAutosign(ca.AutosignConfig{}, csr, csrPEM)
			Expect(err).NotTo(HaveOccurred())
			Expect(ok).To(BeFalse())
		})

		It("explicitly off mode never signs", func() {
			ok, err := ca.CheckAutosign(ca.AutosignConfig{Mode: "off"}, csr, csrPEM)
			Expect(err).NotTo(HaveOccurred())
			Expect(ok).To(BeFalse())
		})
	})

	// ── mode = true ───────────────────────────────────────────────────────────
	Describe("mode=true", func() {
		It("always signs", func() {
			ok, err := ca.CheckAutosign(ca.AutosignConfig{Mode: "true"}, csr, csrPEM)
			Expect(err).NotTo(HaveOccurred())
			Expect(ok).To(BeTrue())
		})
	})

	// ── mode = file ───────────────────────────────────────────────────────────
	Describe("mode=file", func() {
		writeConf := func(content string) string {
			path := filepath.Join(tmpDir, "autosign.conf")
			Expect(os.WriteFile(path, []byte(content), 0644)).To(Succeed())
			return path
		}

		It("signs when CN matches a glob pattern", func() {
			ok, err := ca.CheckAutosign(
				ca.AutosignConfig{Mode: "file", FileOrPath: writeConf("*.example.com\n")},
				csr, csrPEM)
			Expect(err).NotTo(HaveOccurred())
			Expect(ok).To(BeTrue())
		})

		It("denies when CN does not match any pattern", func() {
			ok, err := ca.CheckAutosign(
				ca.AutosignConfig{Mode: "file", FileOrPath: writeConf("*.test.org\n")},
				csr, csrPEM)
			Expect(err).NotTo(HaveOccurred())
			Expect(ok).To(BeFalse())
		})

		It("skips blank lines and # comments", func() {
			ok, err := ca.CheckAutosign(
				ca.AutosignConfig{Mode: "file", FileOrPath: writeConf("# comment\n\n*.example.com\n")},
				csr, csrPEM)
			Expect(err).NotTo(HaveOccurred())
			Expect(ok).To(BeTrue())
		})

		It("denies for an empty pattern file (no patterns)", func() {
			ok, err := ca.CheckAutosign(
				ca.AutosignConfig{Mode: "file", FileOrPath: writeConf("")},
				csr, csrPEM)
			Expect(err).NotTo(HaveOccurred())
			Expect(ok).To(BeFalse())
		})

		It("returns false (not error) when file does not exist", func() {
			ok, err := ca.CheckAutosign(
				ca.AutosignConfig{Mode: "file", FileOrPath: "/no/such/autosign.conf"},
				csr, csrPEM)
			Expect(err).NotTo(HaveOccurred())
			Expect(ok).To(BeFalse())
		})

		It("matches the CN exactly with a literal-name entry", func() {
			ok, err := ca.CheckAutosign(
				ca.AutosignConfig{Mode: "file", FileOrPath: writeConf("test-node.example.com\n")},
				csr, csrPEM)
			Expect(err).NotTo(HaveOccurred())
			Expect(ok).To(BeTrue())
		})
	})

	// ── mode = executable ─────────────────────────────────────────────────────
	Describe("mode=executable", func() {
		writeScript := func(content string) string {
			path := filepath.Join(tmpDir, "autosign.sh")
			Expect(os.WriteFile(path, []byte(content), 0755)).To(Succeed())
			return path
		}

		It("signs when executable exits 0", func() {
			ok, err := ca.CheckAutosign(
				ca.AutosignConfig{Mode: "executable", FileOrPath: writeScript("#!/bin/sh\nexit 0\n")},
				csr, csrPEM)
			Expect(err).NotTo(HaveOccurred())
			Expect(ok).To(BeTrue())
		})

		It("denies (no error) when executable exits non-zero", func() {
			ok, err := ca.CheckAutosign(
				ca.AutosignConfig{Mode: "executable", FileOrPath: writeScript("#!/bin/sh\nexit 1\n")},
				csr, csrPEM)
			Expect(err).NotTo(HaveOccurred())
			Expect(ok).To(BeFalse())
		})

		It("passes the subject CN as argv[1]", func() {
			// Script exits 0 only when argv[1] is the expected CN.
			script := writeScript("#!/bin/sh\n[ \"$1\" = \"test-node.example.com\" ] && exit 0 || exit 1\n")
			ok, err := ca.CheckAutosign(
				ca.AutosignConfig{Mode: "executable", FileOrPath: script},
				csr, csrPEM)
			Expect(err).NotTo(HaveOccurred())
			Expect(ok).To(BeTrue())
		})

		It("receives the CSR PEM on stdin", func() {
			// Script exits 0 only when stdin contains the PEM header.
			script := writeScript("#!/bin/sh\ngrep -q 'BEGIN CERTIFICATE REQUEST' && exit 0 || exit 1\n")
			ok, err := ca.CheckAutosign(
				ca.AutosignConfig{Mode: "executable", FileOrPath: script},
				csr, csrPEM)
			Expect(err).NotTo(HaveOccurred())
			Expect(ok).To(BeTrue())
		})

		It("uses both argv[1] and stdin together for a real policy decision", func() {
			// Realistic plugin: sign only *.example.com and only if CSR PEM is present.
			script := writeScript(`#!/bin/sh
stdin=$(cat)
echo "$stdin" | grep -q "BEGIN CERTIFICATE REQUEST" || exit 2
case "$1" in
  *.example.com) exit 0 ;;
  *)             exit 1 ;;
esac
`)
			// Matching CN — should sign.
			ok, err := ca.CheckAutosign(
				ca.AutosignConfig{Mode: "executable", FileOrPath: script},
				csr, csrPEM)
			Expect(err).NotTo(HaveOccurred())
			Expect(ok).To(BeTrue())

			// Non-matching CN — should deny.
			csrPEM2, csr2 := buildCSR("other.org")
			ok, err = ca.CheckAutosign(
				ca.AutosignConfig{Mode: "executable", FileOrPath: script},
				csr2, csrPEM2)
			Expect(err).NotTo(HaveOccurred())
			Expect(ok).To(BeFalse())
		})

		It("returns an error when executable is not found", func() {
			_, err := ca.CheckAutosign(
				ca.AutosignConfig{Mode: "executable", FileOrPath: "/no/such/plugin.sh"},
				csr, csrPEM)
			Expect(err).To(HaveOccurred())
		})

		It("returns an error when path exists but is not executable", func() {
			// Write a file without execute permission.
			path := filepath.Join(tmpDir, "not_exec.sh")
			Expect(os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0644)).To(Succeed())
			_, err := ca.CheckAutosign(
				ca.AutosignConfig{Mode: "executable", FileOrPath: path},
				csr, csrPEM)
			Expect(err).To(HaveOccurred())
		})
	})
})
