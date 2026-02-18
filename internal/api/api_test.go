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
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/tvaughan/puppet-ca/internal/api"
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

var _ = Describe("API Workflow", func() {
	var (
		tmpDir string
		myCA   *ca.CA
		server *api.Server
		mux    http.Handler
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-api-test")
		Expect(err).NotTo(HaveOccurred())

		store := storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")

		// Pre-seed CA
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

		err = myCA.Init()
		Expect(err).NotTo(HaveOccurred())

		server = api.New(myCA)
		mux = server.Routes()
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	Context("Certificate Request", func() {
		var (
			subject string
			csrPEM  []byte
		)

		BeforeEach(func() {
			subject = "api-node"
			var err error
			csrPEM, err = testutil.GenerateCSR(subject)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should handle the full certificate lifecycle", func() {
			// 1. PUT /certificate_request/{subject}
			req := httptest.NewRequest("PUT", "/certificate_request/"+subject, bytes.NewReader(csrPEM))
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))

			// 2. GET /certificate_status/{subject} (Should be 'requested')
			req = httptest.NewRequest("GET", "/certificate_status/"+subject, nil)
			rr = httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))

			var statusResp api.CertStatusResponse
			err := json.Unmarshal(rr.Body.Bytes(), &statusResp)
			Expect(err).NotTo(HaveOccurred())
			Expect(statusResp.State).To(Equal("requested"))
			Expect(statusResp.Name).To(Equal(subject))

			// 3. PUT /certificate_status/{subject} (Sign it)
			body := api.PutStatusBody{DesiredState: "signed"}
			bodyBytes, _ := json.Marshal(body)
			req = httptest.NewRequest("PUT", "/certificate_status/"+subject, bytes.NewReader(bodyBytes))
			rr = httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusNoContent))

			// 4. GET /certificate_status/{subject} (Should be 'signed')
			req = httptest.NewRequest("GET", "/certificate_status/"+subject, nil)
			rr = httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))

			err = json.Unmarshal(rr.Body.Bytes(), &statusResp)
			Expect(err).NotTo(HaveOccurred())
			Expect(statusResp.State).To(Equal("signed"))

			// 5. PUT /certificate_status/{subject} (Revoke it)
			body = api.PutStatusBody{DesiredState: "revoked"}
			bodyBytes, _ = json.Marshal(body)
			req = httptest.NewRequest("PUT", "/certificate_status/"+subject, bytes.NewReader(bodyBytes))
			rr = httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusNoContent))
		})
	})

	Context("Negative Tests", func() {
		It("should return 404 for missing status", func() {
			req := httptest.NewRequest("GET", "/certificate_status/missing-node", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusNotFound))
		})

		It("should return 400 for invalid subject on GET", func() {
			req := httptest.NewRequest("GET", "/certificate_status/Invalid%2FName", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusBadRequest))
		})

		It("should return 400 for invalid subject on PUT status", func() {
			body := api.PutStatusBody{DesiredState: "signed"}
			bodyBytes, _ := json.Marshal(body)
			req := httptest.NewRequest("PUT", "/certificate_status/Invalid%2FName", bytes.NewReader(bodyBytes))
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusBadRequest))
		})

		It("should return 400 for invalid desired_state", func() {
			body := api.PutStatusBody{DesiredState: "destroyed"}
			bodyBytes, _ := json.Marshal(body)
			req := httptest.NewRequest("PUT", "/certificate_status/valid-node", bytes.NewReader(bodyBytes))
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusBadRequest))
		})

		It("should return 400 for malformed JSON", func() {
			req := httptest.NewRequest("PUT", "/certificate_status/valid-node", bytes.NewReader([]byte("{bad-json")))
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusBadRequest))
		})
	})

	Context("GET endpoints", func() {
		var (
			subject string
			csrPEM  []byte
		)

		BeforeEach(func() {
			subject = "get-node"
			var err error
			csrPEM, err = testutil.GenerateCSR(subject)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should return the pending CSR PEM via GET /certificate_request/{subject}", func() {
			req := httptest.NewRequest("PUT", "/certificate_request/"+subject, bytes.NewReader(csrPEM))
			httptest.NewRecorder() // discard
			mux.ServeHTTP(httptest.NewRecorder(), req)

			req = httptest.NewRequest("GET", "/certificate_request/"+subject, nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
			Expect(rr.Body.String()).To(ContainSubstring("CERTIFICATE REQUEST"))
		})

		It("should return 404 for a missing CSR", func() {
			req := httptest.NewRequest("GET", "/certificate_request/ghost-node", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusNotFound))
		})

		It("should return the signed cert PEM via GET /certificate/{subject}", func() {
			mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("PUT", "/certificate_request/"+subject, bytes.NewReader(csrPEM)))
			body, _ := json.Marshal(api.PutStatusBody{DesiredState: "signed"})
			mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("PUT", "/certificate_status/"+subject, bytes.NewReader(body)))

			req := httptest.NewRequest("GET", "/certificate/"+subject, nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
			Expect(rr.Body.String()).To(ContainSubstring("CERTIFICATE"))
		})

		It("should return the CA cert PEM via GET /certificate/ca", func() {
			req := httptest.NewRequest("GET", "/certificate/ca", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
			Expect(rr.Body.String()).To(ContainSubstring("CERTIFICATE"))
		})

		It("should return 404 for a missing signed cert", func() {
			req := httptest.NewRequest("GET", "/certificate/ghost-node", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusNotFound))
		})

		It("should return the CRL PEM via GET /certificate_revocation_list/ca", func() {
			req := httptest.NewRequest("GET", "/certificate_revocation_list/ca", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
			Expect(rr.Body.String()).To(ContainSubstring("X509 CRL"))
		})

		It("should return 304 Not Modified when CRL has not changed since If-Modified-Since", func() {
			req := httptest.NewRequest("GET", "/certificate_revocation_list/ca", nil)
			req.Header.Set("If-Modified-Since", time.Now().Add(1*time.Hour).UTC().Format(http.TimeFormat))
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusNotModified))
		})

		It("should return 200 when CRL was modified after If-Modified-Since", func() {
			req := httptest.NewRequest("GET", "/certificate_revocation_list/ca", nil)
			req.Header.Set("If-Modified-Since", time.Now().Add(-1*time.Hour).UTC().Format(http.TimeFormat))
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})
	})

	Context("Status edge cases", func() {
		It("should report state=revoked for a revoked certificate", func() {
			subject := "revoked-api-node"
			csrPEM, err := testutil.GenerateCSR(subject)
			Expect(err).NotTo(HaveOccurred())

			mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("PUT", "/certificate_request/"+subject, bytes.NewReader(csrPEM)))
			body, _ := json.Marshal(api.PutStatusBody{DesiredState: "signed"})
			mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("PUT", "/certificate_status/"+subject, bytes.NewReader(body)))
			body, _ = json.Marshal(api.PutStatusBody{DesiredState: "revoked"})
			mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("PUT", "/certificate_status/"+subject, bytes.NewReader(body)))

			req := httptest.NewRequest("GET", "/certificate_status/"+subject, nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
			var resp api.CertStatusResponse
			Expect(json.Unmarshal(rr.Body.Bytes(), &resp)).To(Succeed())
			Expect(resp.State).To(Equal("revoked"))
		})

		It("should return 409 when submitting a CSR for a subject with an active certificate", func() {
			subject := "conflict-node"
			csrPEM, err := testutil.GenerateCSR(subject)
			Expect(err).NotTo(HaveOccurred())

			mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("PUT", "/certificate_request/"+subject, bytes.NewReader(csrPEM)))
			body, _ := json.Marshal(api.PutStatusBody{DesiredState: "signed"})
			mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("PUT", "/certificate_status/"+subject, bytes.NewReader(body)))

			csrPEM2, err := testutil.GenerateCSR(subject)
			Expect(err).NotTo(HaveOccurred())
			req := httptest.NewRequest("PUT", "/certificate_request/"+subject, bytes.NewReader(csrPEM2))
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusConflict))
		})
	})

	Context("Prefixed paths (/puppet-ca/v1/)", func() {
		It("should serve GET /puppet-ca/v1/certificate_status/{subject}", func() {
			req := httptest.NewRequest("GET", "/puppet-ca/v1/certificate_status/missing-node", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusNotFound))
		})

		It("should serve GET /puppet-ca/v1/certificate_revocation_list/ca", func() {
			req := httptest.NewRequest("GET", "/puppet-ca/v1/certificate_revocation_list/ca", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
			Expect(rr.Body.String()).To(ContainSubstring("X509 CRL"))
		})

		It("should serve PUT /puppet-ca/v1/certificate_request/{subject}", func() {
			subject := "prefixed-node"
			csrPEM, err := testutil.GenerateCSR(subject)
			Expect(err).NotTo(HaveOccurred())

			req := httptest.NewRequest("PUT", "/puppet-ca/v1/certificate_request/"+subject, bytes.NewReader(csrPEM))
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})
	})

	Context("Invalid subject validation", func() {
		It("should return 400 for invalid subject on GET /certificate/{subject}", func() {
			// URL-encoded slash becomes %2F; Go's mux passes it decoded, so use double-dot instead.
			req := httptest.NewRequest("GET", "/certificate/a..b", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusBadRequest))
		})

		It("should return 400 for invalid subject on GET /certificate_request/{subject}", func() {
			req := httptest.NewRequest("GET", "/certificate_request/a..b", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusBadRequest))
		})
	})

	Context("DELETE /certificate_request/{subject}", func() {
		It("should return 204 and remove the pending CSR", func() {
			subject := "delete-node"
			csrPEM, err := testutil.GenerateCSR(subject)
			Expect(err).NotTo(HaveOccurred())

			mux.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest("PUT", "/certificate_request/"+subject, bytes.NewReader(csrPEM)))

			req := httptest.NewRequest("DELETE", "/certificate_request/"+subject, nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusNoContent))

			// CSR should be gone.
			getReq := httptest.NewRequest("GET", "/certificate_request/"+subject, nil)
			getRR := httptest.NewRecorder()
			mux.ServeHTTP(getRR, getReq)
			Expect(getRR.Code).To(Equal(http.StatusNotFound))
		})

		It("should return 404 when the CSR does not exist", func() {
			req := httptest.NewRequest("DELETE", "/certificate_request/ghost-node", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusNotFound))
		})

		It("should serve DELETE /puppet-ca/v1/certificate_request/{subject}", func() {
			subject := "delete-pfx-node"
			csrPEM, err := testutil.GenerateCSR(subject)
			Expect(err).NotTo(HaveOccurred())

			mux.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest("PUT", "/puppet-ca/v1/certificate_request/"+subject, bytes.NewReader(csrPEM)))

			req := httptest.NewRequest("DELETE", "/puppet-ca/v1/certificate_request/"+subject, nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusNoContent))
		})
	})

	Context("authorization_extensions in status response", func() {
		It("should include authorization_extensions as an empty map for a plain CSR", func() {
			subject := "auth-ext-node"
			csrPEM, err := testutil.GenerateCSR(subject)
			Expect(err).NotTo(HaveOccurred())

			mux.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest("PUT", "/certificate_request/"+subject, bytes.NewReader(csrPEM)))

			req := httptest.NewRequest("GET", "/certificate_status/"+subject, nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))

			var resp api.CertStatusResponse
			Expect(json.Unmarshal(rr.Body.Bytes(), &resp)).To(Succeed())
			Expect(resp.AuthorizationExtensions).NotTo(BeNil())
			Expect(resp.AuthorizationExtensions).To(BeEmpty())
		})

		It("should include authorization_extensions with Puppet auth OID values", func() {
			// Build a CSR carrying a Puppet auth extension (pp_auth_role = 1.3.6.1.4.1.34380.1.3.13).
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).NotTo(HaveOccurred())

			authVal, err := asn1.Marshal("my-role")
			Expect(err).NotTo(HaveOccurred())

			csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
				Subject: pkix.Name{CommonName: "auth-role-node"},
				ExtraExtensions: []pkix.Extension{{
					Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 3, 13},
					Value: authVal,
				}},
			}, key)
			Expect(err).NotTo(HaveOccurred())

			csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
			mux.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest("PUT", "/certificate_request/auth-role-node", bytes.NewReader(csrPEM)))

			req := httptest.NewRequest("GET", "/certificate_status/auth-role-node", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))

			var resp api.CertStatusResponse
			Expect(json.Unmarshal(rr.Body.Bytes(), &resp)).To(Succeed())
			Expect(resp.AuthorizationExtensions).To(HaveKeyWithValue("pp_auth_role", "my-role"))
		})
	})

	Context("DELETE /certificate_status/{subject}", func() {
		It("should revoke and delete the certificate (puppet cert clean)", func() {
			subject := "clean-node"
			csrPEM, err := testutil.GenerateCSR(subject)
			Expect(err).NotTo(HaveOccurred())

			mux.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest("PUT", "/certificate_request/"+subject, bytes.NewReader(csrPEM)))
			body, _ := json.Marshal(api.PutStatusBody{DesiredState: "signed"})
			mux.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest("PUT", "/certificate_status/"+subject, bytes.NewReader(body)))

			req := httptest.NewRequest("DELETE", "/certificate_status/"+subject, nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusNoContent))

			// Certificate should be gone.
			getReq := httptest.NewRequest("GET", "/certificate_status/"+subject, nil)
			getRR := httptest.NewRecorder()
			mux.ServeHTTP(getRR, getReq)
			Expect(getRR.Code).To(Equal(http.StatusNotFound))
		})

		It("should return 404 when neither cert nor CSR exists", func() {
			req := httptest.NewRequest("DELETE", "/certificate_status/ghost-node", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusNotFound))
		})

		It("should also clean a pending CSR with no signed cert", func() {
			subject := "clean-csr-node"
			csrPEM, err := testutil.GenerateCSR(subject)
			Expect(err).NotTo(HaveOccurred())

			mux.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest("PUT", "/certificate_request/"+subject, bytes.NewReader(csrPEM)))

			req := httptest.NewRequest("DELETE", "/certificate_status/"+subject, nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusNoContent))
		})
	})

	Context("GET /certificate_statuses/{ignored}", func() {
		It("should return an empty JSON array when no certs or CSRs exist", func() {
			req := httptest.NewRequest("GET", "/certificate_statuses/any", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))

			var statuses []api.CertStatusResponse
			Expect(json.Unmarshal(rr.Body.Bytes(), &statuses)).To(Succeed())
			Expect(statuses).To(BeEmpty())
		})

		It("should list all pending CSRs and signed certs", func() {
			// One pending CSR.
			csrPEM1, err := testutil.GenerateCSR("list-node-a")
			Expect(err).NotTo(HaveOccurred())
			mux.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest("PUT", "/certificate_request/list-node-a", bytes.NewReader(csrPEM1)))

			// One signed cert.
			csrPEM2, err := testutil.GenerateCSR("list-node-b")
			Expect(err).NotTo(HaveOccurred())
			mux.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest("PUT", "/certificate_request/list-node-b", bytes.NewReader(csrPEM2)))
			body, _ := json.Marshal(api.PutStatusBody{DesiredState: "signed"})
			mux.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest("PUT", "/certificate_status/list-node-b", bytes.NewReader(body)))

			req := httptest.NewRequest("GET", "/certificate_statuses/any", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))

			var statuses []api.CertStatusResponse
			Expect(json.Unmarshal(rr.Body.Bytes(), &statuses)).To(Succeed())
			Expect(statuses).To(HaveLen(2))

			byName := map[string]api.CertStatusResponse{}
			for _, s := range statuses {
				byName[s.Name] = s
			}
			Expect(byName["list-node-a"].State).To(Equal("requested"))
			Expect(byName["list-node-b"].State).To(Equal("signed"))
		})

		It("should include dns_alt_names as [] not null", func() {
			subject := "dns-node"
			csrPEM, err := testutil.GenerateCSR(subject)
			Expect(err).NotTo(HaveOccurred())
			mux.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest("PUT", "/certificate_request/"+subject, bytes.NewReader(csrPEM)))

			req := httptest.NewRequest("GET", "/certificate_statuses/any", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
			// Raw JSON must not contain "null" for dns_alt_names.
			Expect(rr.Body.String()).To(ContainSubstring(`"dns_alt_names":[]`))
		})
	})

	Context("GET /expirations", func() {
		It("should return CA cert and CRL expiration dates", func() {
			req := httptest.NewRequest("GET", "/expirations", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))

			var resp api.ExpirationsResponse
			Expect(json.Unmarshal(rr.Body.Bytes(), &resp)).To(Succeed())
			Expect(resp.CACertificate.Expiration).NotTo(BeEmpty())
			Expect(resp.CACrl.NextUpdate).NotTo(BeEmpty())
		})
	})

	Context("POST /sign", func() {
		It("should sign the listed CSRs and return a SignResult", func() {
			for _, sub := range []string{"sign-node-a", "sign-node-b"} {
				csrPEM, err := testutil.GenerateCSR(sub)
				Expect(err).NotTo(HaveOccurred())
				mux.ServeHTTP(httptest.NewRecorder(),
					httptest.NewRequest("PUT", "/certificate_request/"+sub, bytes.NewReader(csrPEM)))
			}

			body, _ := json.Marshal(map[string][]string{"certnames": {"sign-node-a", "sign-node-b", "ghost-node"}})
			req := httptest.NewRequest("POST", "/sign", bytes.NewReader(body))
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))

			var result struct {
				Signed        []string `json:"signed"`
				NoCSR         []string `json:"no-csr"`
				SigningErrors []string `json:"signing-errors"`
			}
			Expect(json.Unmarshal(rr.Body.Bytes(), &result)).To(Succeed())
			Expect(result.Signed).To(ConsistOf("sign-node-a", "sign-node-b"))
			Expect(result.NoCSR).To(ConsistOf("ghost-node"))
			Expect(result.SigningErrors).To(BeEmpty())
		})

		It("should return 400 for an empty certnames list", func() {
			body, _ := json.Marshal(map[string][]string{"certnames": {}})
			req := httptest.NewRequest("POST", "/sign", bytes.NewReader(body))
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusBadRequest))
		})
	})

	Context("POST /sign/all", func() {
		It("should sign all pending CSRs and return a SignResult", func() {
			for _, sub := range []string{"signall-node-a", "signall-node-b"} {
				csrPEM, err := testutil.GenerateCSR(sub)
				Expect(err).NotTo(HaveOccurred())
				mux.ServeHTTP(httptest.NewRecorder(),
					httptest.NewRequest("PUT", "/certificate_request/"+sub, bytes.NewReader(csrPEM)))
			}

			req := httptest.NewRequest("POST", "/sign/all", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))

			var result struct {
				Signed        []string `json:"signed"`
				NoCSR         []string `json:"no-csr"`
				SigningErrors []string `json:"signing-errors"`
			}
			Expect(json.Unmarshal(rr.Body.Bytes(), &result)).To(Succeed())
			Expect(result.Signed).To(ConsistOf("signall-node-a", "signall-node-b"))
			Expect(result.SigningErrors).To(BeEmpty())
		})

		It("should return an empty signed list when no CSRs are pending", func() {
			req := httptest.NewRequest("POST", "/sign/all", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))

			var result struct {
				Signed []string `json:"signed"`
			}
			Expect(json.Unmarshal(rr.Body.Bytes(), &result)).To(Succeed())
			Expect(result.Signed).To(BeEmpty())
		})
	})

	Context("dns_alt_names serializes as [] not null", func() {
		It("should return [] for dns_alt_names on a plain CSR status", func() {
			subject := "dns-status-node"
			csrPEM, err := testutil.GenerateCSR(subject)
			Expect(err).NotTo(HaveOccurred())
			mux.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest("PUT", "/certificate_request/"+subject, bytes.NewReader(csrPEM)))

			req := httptest.NewRequest("GET", "/certificate_status/"+subject, nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
			Expect(rr.Body.String()).To(ContainSubstring(`"dns_alt_names":[]`))
		})
	})

	Context("CA:TRUE extension rejection", func() {
		It("should return 409 when signing a CSR with BasicConstraints CA:TRUE", func() {
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
			mux.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest("PUT", "/certificate_request/evil-ca", bytes.NewReader(csrPEM)))

			body, _ := json.Marshal(api.PutStatusBody{DesiredState: "signed"})
			req := httptest.NewRequest("PUT", "/certificate_status/evil-ca", bytes.NewReader(body))
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusConflict))
			Expect(rr.Body.String()).To(ContainSubstring("Found extensions"))
			Expect(rr.Body.String()).To(ContainSubstring("2.5.29.19"))
		})
	})

	Context("POST /generate/{subject}", func() {
		It("should return key and cert PEM for a new subject", func() {
			req := httptest.NewRequest("POST", "/generate/gen-node", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))

			var resp struct {
				PrivateKey  string `json:"private_key"`
				Certificate string `json:"certificate"`
			}
			Expect(json.Unmarshal(rr.Body.Bytes(), &resp)).To(Succeed())
			Expect(resp.PrivateKey).To(ContainSubstring("RSA PRIVATE KEY"))
			Expect(resp.Certificate).To(ContainSubstring("CERTIFICATE"))
		})

		It("should return 409 if cert already exists for the subject", func() {
			// First generate.
			mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/generate/gen-dup", nil))
			// Second generate should conflict.
			req := httptest.NewRequest("POST", "/generate/gen-dup", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusConflict))
		})

		It("should return 400 for an invalid subject", func() {
			req := httptest.NewRequest("POST", "/generate/bad..subject", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusBadRequest))
		})
	})

	Context("GET /certificate_statuses with ?state= filter", func() {
		BeforeEach(func() {
			// Submit one pending CSR and sign another.
			csrA, err := testutil.GenerateCSR("state-pending")
			Expect(err).NotTo(HaveOccurred())
			mux.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest("PUT", "/certificate_request/state-pending", bytes.NewReader(csrA)))

			csrB, err := testutil.GenerateCSR("state-signed")
			Expect(err).NotTo(HaveOccurred())
			mux.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest("PUT", "/certificate_request/state-signed", bytes.NewReader(csrB)))
			body, _ := json.Marshal(api.PutStatusBody{DesiredState: "signed"})
			mux.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest("PUT", "/certificate_status/state-signed", bytes.NewReader(body)))
		})

		It("should return only requested certs when ?state=requested", func() {
			req := httptest.NewRequest("GET", "/certificate_statuses/all?state=requested", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))

			var statuses []api.CertStatusResponse
			Expect(json.Unmarshal(rr.Body.Bytes(), &statuses)).To(Succeed())
			for _, s := range statuses {
				Expect(s.State).To(Equal("requested"))
			}
		})

		It("should return only signed certs when ?state=signed", func() {
			req := httptest.NewRequest("GET", "/certificate_statuses/all?state=signed", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))

			var statuses []api.CertStatusResponse
			Expect(json.Unmarshal(rr.Body.Bytes(), &statuses)).To(Succeed())
			for _, s := range statuses {
				Expect(s.State).To(Equal("signed"))
			}
		})

		It("should return all certs when no ?state= param", func() {
			req := httptest.NewRequest("GET", "/certificate_statuses/all", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))

			var statuses []api.CertStatusResponse
			Expect(json.Unmarshal(rr.Body.Bytes(), &statuses)).To(Succeed())
			Expect(statuses).To(HaveLen(2))
		})
	})

	Context("PUT /certificate_status with cert_ttl", func() {
		It("should sign with custom TTL when cert_ttl is provided", func() {
			subject := "ttl-node"
			csrPEM, err := testutil.GenerateCSR(subject)
			Expect(err).NotTo(HaveOccurred())
			mux.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest("PUT", "/certificate_request/"+subject, bytes.NewReader(csrPEM)))

			ttl := 3600 // 1 hour
			body, _ := json.Marshal(api.PutStatusBody{DesiredState: "signed", CertTTL: &ttl})
			req := httptest.NewRequest("PUT", "/certificate_status/"+subject, bytes.NewReader(body))
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusNoContent))

			// Verify the cert has a short validity.
			certReq := httptest.NewRequest("GET", "/certificate/"+subject, nil)
			certRR := httptest.NewRecorder()
			mux.ServeHTTP(certRR, certReq)
			Expect(certRR.Code).To(Equal(http.StatusOK))

			block, _ := pem.Decode(certRR.Body.Bytes())
			Expect(block).NotTo(BeNil())
			cert, err := x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())
			// Should expire around 1 hour from now (with 24h backdating, 1h into the future).
			// NotAfter should be < 2 hours from now, not 5 years.
			Expect(cert.NotAfter).To(BeTemporally("<", time.Now().Add(2*time.Hour)))
		})
	})

	Context("subject_alt_names in status response", func() {
		It("should include subject_alt_names identical to dns_alt_names", func() {
			subject := "san-node"
			csrPEM, err := testutil.GenerateCSR(subject)
			Expect(err).NotTo(HaveOccurred())
			mux.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest("PUT", "/certificate_request/"+subject, bytes.NewReader(csrPEM)))

			req := httptest.NewRequest("GET", "/certificate_status/"+subject, nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))

			var resp api.CertStatusResponse
			Expect(json.Unmarshal(rr.Body.Bytes(), &resp)).To(Succeed())
			Expect(resp.SubjectAltNames).NotTo(BeNil())
			Expect(resp.SubjectAltNames).To(Equal(resp.DNSAltNames))
		})
	})

	Context("CSR CN mismatch rejection", func() {
		It("should return 400 when CSR CN does not match URL subject", func() {
			// Generate a CSR with CN "other-node" but submit it as "cn-mismatch-node".
			csrPEM, err := testutil.GenerateCSR("other-node")
			Expect(err).NotTo(HaveOccurred())

			req := httptest.NewRequest("PUT", "/certificate_request/cn-mismatch-node", bytes.NewReader(csrPEM))
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusBadRequest))
			Expect(rr.Body.String()).To(ContainSubstring("does not match"))
		})
	})

	Context("PUT /certificate_status sign when no CSR exists", func() {
		It("should return 409 when trying to sign a subject with no pending CSR", func() {
			body, _ := json.Marshal(api.PutStatusBody{DesiredState: "signed"})
			req := httptest.NewRequest("PUT", "/certificate_status/ghost-node", bytes.NewReader(body))
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusConflict))
		})
	})

	Context("PUT /certificate_status revoke when no cert exists", func() {
		It("should return 409 when revoking a subject that was never signed", func() {
			body, _ := json.Marshal(api.PutStatusBody{DesiredState: "revoked"})
			req := httptest.NewRequest("PUT", "/certificate_status/never-signed-node", bytes.NewReader(body))
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusConflict))
		})
	})

	Context("PUT /certificate_request with empty body", func() {
		It("should return 400 when submitting an empty (non-PEM) body", func() {
			req := httptest.NewRequest("PUT", "/certificate_request/empty-body-node", bytes.NewReader([]byte{}))
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusBadRequest))
		})
	})

})
