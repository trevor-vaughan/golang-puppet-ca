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

package api_test

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	xocsp "golang.org/x/crypto/ocsp"

	"github.com/tvaughan/puppet-ca/internal/api"
	"github.com/tvaughan/puppet-ca/internal/ca"
	"github.com/tvaughan/puppet-ca/internal/storage"
	"github.com/tvaughan/puppet-ca/internal/testutil"
)

// setupOCSPServer creates a CA + API server pair backed by dir.
func setupOCSPServer(dir string) (*ca.CA, http.Handler) {
	store := storage.New(dir)
	myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
	Expect(store.EnsureDirs()).To(Succeed())
	Expect(os.WriteFile(store.CAKeyPath(), cachedKeyPEM, 0640)).To(Succeed())
	Expect(os.WriteFile(store.CACertPath(), cachedCrtPEM, 0644)).To(Succeed())
	Expect(store.UpdateCRL(cachedCrlPEM)).To(Succeed())
	Expect(store.WriteSerial("0001")).To(Succeed())
	Expect(os.WriteFile(store.InventoryPath(), []byte{}, 0644)).To(Succeed())
	Expect(myCA.Init()).To(Succeed())
	srv := api.New(myCA)
	return myCA, srv.Routes()
}

// signCert is a helper that submits a CSR and signs it, returning the leaf cert.
func signCert(myCA *ca.CA, subject string) *x509.Certificate {
	csrPEM, err := testutil.GenerateCSR(subject)
	Expect(err).NotTo(HaveOccurred())
	_, err = myCA.SaveRequest(subject, csrPEM)
	Expect(err).NotTo(HaveOccurred())
	certPEM, err := myCA.Sign(subject)
	Expect(err).NotTo(HaveOccurred())
	block, _ := pem.Decode(certPEM)
	Expect(block).NotTo(BeNil())
	cert, err := x509.ParseCertificate(block.Bytes)
	Expect(err).NotTo(HaveOccurred())
	return cert
}

// ocspReqDER builds a basic OCSP request DER for cert issued by issuer.
func ocspReqDER(cert, issuer *x509.Certificate) []byte {
	der, err := testutil.BuildOCSPRequest(cert, issuer)
	Expect(err).NotTo(HaveOccurred())
	return der
}

var _ = Describe("OCSP HTTP Handler", func() {
	var (
		tmpDir string
		myCA   *ca.CA
		mux    http.Handler
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-ocsp-api-test")
		Expect(err).NotTo(HaveOccurred())
		myCA, mux = setupOCSPServer(tmpDir)
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	// --- POST ---

	It("POST /ocsp → 200, application/ocsp-response, Good status", func() {
		cert := signCert(myCA, "post-ocsp-node")
		reqDER := ocspReqDER(cert, myCA.CACert)

		req := httptest.NewRequest(http.MethodPost, "/ocsp", bytes.NewReader(reqDER))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		Expect(rr.Code).To(Equal(http.StatusOK))
		Expect(rr.Header().Get("Content-Type")).To(Equal("application/ocsp-response"))

		resp, err := xocsp.ParseResponse(rr.Body.Bytes(), myCA.CACert)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.Status).To(Equal(xocsp.Good))
	})

	// --- GET ---

	It("GET /ocsp/{b64} → 200, same content as POST (percent-encoded StdEncoding)", func() {
		cert := signCert(myCA, "get-ocsp-node")
		reqDER := ocspReqDER(cert, myCA.CACert)
		// Percent-encode the standard base64 so that '/' and '+' don't confuse
		// the path-based mux routing (they would be treated as path separators
		// or query delimiters respectively).
		b64Escaped := url.PathEscape(base64.StdEncoding.EncodeToString(reqDER))

		req := httptest.NewRequest(http.MethodGet, "/ocsp/"+b64Escaped, nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		Expect(rr.Code).To(Equal(http.StatusOK))
		Expect(rr.Header().Get("Content-Type")).To(Equal("application/ocsp-response"))

		resp, err := xocsp.ParseResponse(rr.Body.Bytes(), myCA.CACert)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.Status).To(Equal(xocsp.Good))
	})

	It("GET /ocsp/{b64} → 200 with unpadded URL-safe base64 (RFC 6960 §A.1 conformant)", func() {
		cert := signCert(myCA, "get-ocsp-rawurl-node")
		reqDER := ocspReqDER(cert, myCA.CACert)
		// RFC 6960 §A.1: GET path uses URL-safe base64 without padding.
		// The '-' and '_' characters are legal URL path characters and require
		// no percent-encoding.
		b64RawURL := base64.RawURLEncoding.EncodeToString(reqDER)

		req := httptest.NewRequest(http.MethodGet, "/ocsp/"+b64RawURL, nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		Expect(rr.Code).To(Equal(http.StatusOK))
		Expect(rr.Header().Get("Content-Type")).To(Equal("application/ocsp-response"))

		resp, err := xocsp.ParseResponse(rr.Body.Bytes(), myCA.CACert)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.Status).To(Equal(xocsp.Good))
	})

	// --- Puppet-prefixed path ---

	It("POST /puppet-ca/v1/ocsp → 200", func() {
		cert := signCert(myCA, "prefix-ocsp-node")
		reqDER := ocspReqDER(cert, myCA.CACert)

		req := httptest.NewRequest(http.MethodPost, "/puppet-ca/v1/ocsp", bytes.NewReader(reqDER))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		Expect(rr.Code).To(Equal(http.StatusOK))
		resp, err := xocsp.ParseResponse(rr.Body.Bytes(), myCA.CACert)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.Status).To(Equal(xocsp.Good))
	})

	// --- Revoked ---

	It("returns Revoked after the cert is revoked", func() {
		cert := signCert(myCA, "revoke-ocsp-node")
		Expect(myCA.Revoke("revoke-ocsp-node")).To(Succeed())

		reqDER := ocspReqDER(cert, myCA.CACert)
		req := httptest.NewRequest(http.MethodPost, "/ocsp", bytes.NewReader(reqDER))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		Expect(rr.Code).To(Equal(http.StatusOK))
		resp, err := xocsp.ParseResponse(rr.Body.Bytes(), myCA.CACert)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.Status).To(Equal(xocsp.Revoked))
	})

	// --- Unknown ---

	It("returns Unknown for an unknown serial", func() {
		_, ephCertPEM, _, err := testutil.GenerateTestCA()
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(ephCertPEM)
		ephCert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())

		reqDER := ocspReqDER(ephCert, myCA.CACert)
		req := httptest.NewRequest(http.MethodPost, "/ocsp", bytes.NewReader(reqDER))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		Expect(rr.Code).To(Equal(http.StatusOK))
		resp, err := xocsp.ParseResponse(rr.Body.Bytes(), myCA.CACert)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.Status).To(Equal(xocsp.Unknown))
	})

	// --- Bad request ---

	It("returns 400 for an unparseable POST body", func() {
		req := httptest.NewRequest(http.MethodPost, "/ocsp", strings.NewReader("not DER"))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		Expect(rr.Code).To(Equal(http.StatusBadRequest))
	})

	It("returns 400 for invalid base64 in the GET path", func() {
		req := httptest.NewRequest(http.MethodGet, "/ocsp/!!!notbase64!!!", nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		Expect(rr.Code).To(Equal(http.StatusBadRequest))
	})

	// --- Public access (no client cert) ---

	It("is accessible without a client certificate (tierPublic)", func() {
		// No TLS config → auth middleware is nil → public access automatic.
		// Verify it still works (no 403).
		cert := signCert(myCA, "public-ocsp-node")
		reqDER := ocspReqDER(cert, myCA.CACert)

		req := httptest.NewRequest(http.MethodPost, "/ocsp", bytes.NewReader(reqDER))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		Expect(rr.Code).To(Equal(http.StatusOK))
	})

	// --- Cache-Control ---

	It("GET response carries Cache-Control: max-age=..., public", func() {
		cert := signCert(myCA, "cc-ocsp-node")
		reqDER := ocspReqDER(cert, myCA.CACert)
		b64Escaped := url.PathEscape(base64.StdEncoding.EncodeToString(reqDER))

		req := httptest.NewRequest(http.MethodGet, "/ocsp/"+b64Escaped, nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		Expect(rr.Code).To(Equal(http.StatusOK))
		cc := rr.Header().Get("Cache-Control")
		Expect(cc).To(ContainSubstring("max-age="))
		Expect(cc).To(ContainSubstring("public"))
	})

	It("POST response does NOT carry a Cache-Control header", func() {
		cert := signCert(myCA, "no-cc-ocsp-node")
		reqDER := ocspReqDER(cert, myCA.CACert)

		req := httptest.NewRequest(http.MethodPost, "/ocsp", bytes.NewReader(reqDER))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		Expect(rr.Code).To(Equal(http.StatusOK))
		Expect(rr.Header().Get("Cache-Control")).To(BeEmpty())
	})

	// --- Nonce ---

	It("echoes the nonce from the request into the response", func() {
		cert := signCert(myCA, "nonce-ocsp-node")

		nonce := make([]byte, 16)
		_, err := rand.Read(nonce)
		Expect(err).NotTo(HaveOccurred())

		reqDER, err := testutil.BuildOCSPRequestWithNonce(cert, myCA.CACert, nonce)
		Expect(err).NotTo(HaveOccurred())

		req := httptest.NewRequest(http.MethodPost, "/ocsp", bytes.NewReader(reqDER))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		Expect(rr.Code).To(Equal(http.StatusOK))
		resp, err := xocsp.ParseResponse(rr.Body.Bytes(), myCA.CACert)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.Status).To(Equal(xocsp.Good))

		// The nonce OID must appear in the response's singleExtensions.
		oidNonce := []int{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}
		found := false
		for _, ext := range resp.Extensions {
			if ext.Id.Equal(oidNonce) {
				found = true
				break
			}
		}
		Expect(found).To(BeTrue(), "expected nonce extension in OCSP response")
	})
})
