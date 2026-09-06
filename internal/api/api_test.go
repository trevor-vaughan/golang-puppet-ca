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

package api_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/api"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
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
		tmpDir, err = os.MkdirTemp("", "openvox-ca-api-test")
		Expect(err).NotTo(HaveOccurred())

		store := storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")

		// Pre-seed CA
		err = store.EnsureDirs(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(store.SaveCAKey(context.Background(), cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(context.Background(), cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(context.Background(), cachedCrlPEM)).To(Succeed())

		// Also pre-seed Serial and Inventory which are normally created by bootstrapCA
		Expect(store.WriteSerial(context.Background(), "0001")).To(Succeed())
		Expect(store.TouchInventory(context.Background())).To(Succeed())

		err = myCA.Init(context.Background())
		Expect(err).NotTo(HaveOccurred())

		server = api.New(myCA)
		mux = server.Routes()
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	Context("CRL reissue endpoint", func() {
		parseCRL := func(pemBytes []byte) *x509.RevocationList {
			block, _ := pem.Decode(pemBytes)
			Expect(block).NotTo(BeNil())
			crl, err := x509.ParseRevocationList(block.Bytes)
			Expect(err).NotTo(HaveOccurred())
			return crl
		}

		It("returns 409 with the actionable message when the stored CRL is not ours", func() {
			// The 409 translation is a documented contract in docs/api.md, and
			// nothing exercised it: deleting the errors.Is branch restores the
			// bare 500 that the review identified as the defect, with the CA-layer
			// specs still green — they only prove ReissueCRL returns the sentinel.
			// The message content is the whole point, so assert it, not just the code.
			ctx := context.Background()
			Expect(myCA.Storage.UpdateCRL(ctx, foreignCRL())).To(Succeed())

			req := httptest.NewRequest("PUT", "/certificate_revocation_list/ca", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusConflict))
			Expect(rr.Body.String()).To(ContainSubstring("needs a restart"))
		})

		It("keeps the generic 500 generic when the failure is not the sentinel", func() {
			// The other arm of the same branch. It matters that this one does
			// *not* surface err.Error(): the sentinel's message is written for
			// an operator, and everything else is internal detail on a route
			// reachable from the network. A regression that replaced this with
			// err.Error() -- the obvious "improvement" once the sibling arm
			// shows a real message -- would leak storage internals, and no
			// existing spec drives ReissueCRL into a non-sentinel failure.
			ctx := context.Background()
			Expect(myCA.Storage.UpdateCRL(ctx, []byte("not a PEM block at all"))).To(Succeed())

			req := httptest.NewRequest("PUT", "/certificate_revocation_list/ca", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusInternalServerError))
			Expect(rr.Body.String()).To(ContainSubstring("failed to reissue CRL"))
			Expect(rr.Body.String()).NotTo(ContainSubstring("PEM"),
				"the generic arm must not surface the underlying error")
		})

		It("re-signs the CRL on PUT and returns the fresh CRL", func() {
			getReq := httptest.NewRequest("GET", "/certificate_revocation_list/ca", nil)
			getRR := httptest.NewRecorder()
			mux.ServeHTTP(getRR, getReq)
			Expect(getRR.Code).To(Equal(http.StatusOK))
			before := parseCRL(getRR.Body.Bytes())

			putReq := httptest.NewRequest("PUT", "/certificate_revocation_list/ca", nil)
			putRR := httptest.NewRecorder()
			mux.ServeHTTP(putRR, putReq)
			Expect(putRR.Code).To(Equal(http.StatusOK))

			after := parseCRL(putRR.Body.Bytes())
			Expect(after.Number.Cmp(before.Number)).To(Equal(1))
			Expect(after.NextUpdate).To(BeTemporally(">", time.Now()))
		})
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

		It("gives revoke the same actionable 409 as reissue-crl, and shows what clean does instead", func() {
			// The revoke branch changes only the response body — the status is
			// 409 either way — so a status-code assertion cannot see a revert,
			// and revoke is the boundary an operator reaches far more often
			// than reissue-crl. In this state the CA cannot record revocations
			// at all.
			//
			// Clean is different, and this spec exists partly to record why: it
			// deliberately swallows the revoke failure and proceeds with the
			// delete, so it answers 204 rather than 409. That means the
			// certificate is removed while still unrevoked. A branch keying on
			// the sentinel in handleDeleteStatus would be dead code.
			ctx := context.Background()

			// Sign a certificate so revoke/clean get past their lookups.
			req := httptest.NewRequest("PUT", "/certificate_request/"+subject, bytes.NewReader(csrPEM))
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
			signBody, _ := json.Marshal(api.PutStatusBody{DesiredState: "signed"})
			req = httptest.NewRequest("PUT", "/certificate_status/"+subject, bytes.NewReader(signBody))
			rr = httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusNoContent))

			// Replace the stored CRL with one this CA did not sign.
			Expect(myCA.Storage.UpdateCRL(ctx, foreignCRL())).To(Succeed())

			revokeBody, _ := json.Marshal(api.PutStatusBody{DesiredState: "revoked"})
			req = httptest.NewRequest("PUT", "/certificate_status/"+subject, bytes.NewReader(revokeBody))
			rr = httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusConflict))
			Expect(rr.Body.String()).To(ContainSubstring("needs a restart"),
				"revoke must carry the diagnosis, not a bare conflict")

			req = httptest.NewRequest("DELETE", "/certificate_status/"+subject, nil)
			rr = httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusNoContent),
				"clean proceeds with the delete despite the failed revoke")
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

		// End-to-end path-traversal rejection: a certname carrying directory
		// traversal must be rejected at the boundary (400), confirming that Go's
		// PathValue URL-decoding combined with ValidateSubject fails closed before
		// the subject ever reaches storage. Covers both percent-encoded and literal
		// "../" forms.
		It("should return 400 for a percent-encoded traversal certname on GET status", func() {
			req := httptest.NewRequest("GET", "/puppet-ca/v1/certificate_status/..%2f..%2fetc%2fpasswd", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusBadRequest))
		})

		// Literal "../" never reaches the handler: net/http.ServeMux path-cleans
		// "/certificate_status/.." to "/" and answers with a redirect BEFORE
		// dispatching to the handler, so the traversal segment is collapsed by the
		// standard library and never reaches ValidateSubject or storage. The
		// security guarantee is that it is neither served as a status (200) nor
		// triggers a server error (500) — the traversal is neutralised and
		// redirected to the cleaned root path. The exact redirect status is a
		// ServeMux implementation detail that changed across Go versions (301
		// Moved Permanently through Go 1.25, 307 Temporary Redirect from Go 1.26),
		// so we assert the 3xx class and the safe Location rather than a fixed code.
		It("neutralises a literal '..' traversal certname on GET status (no 200/500)", func() {
			req := httptest.NewRequest("GET", "/certificate_status/..", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).NotTo(Equal(http.StatusOK))
			Expect(rr.Code).NotTo(Equal(http.StatusInternalServerError))
			Expect(rr.Code).To(BeNumerically(">=", http.StatusMultipleChoices)) // 300
			Expect(rr.Code).To(BeNumerically("<", http.StatusBadRequest))       // 400
			Expect(rr.Header().Get("Location")).To(Equal("/"))
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

		It("serves the whole stored chain, not just this CA's own block", func() {
			// The point of chain preservation is that the chain reaches an
			// agent: Puppet's default certificate_revocation = chain makes the
			// agent parse all of it. Every other spec verifies storage state;
			// this is the one that would catch a future change normalising the
			// response to a single block, which would break full-chain
			// revocation checking fleet-wide.
			ctx := context.Background()
			stored, err := myCA.Storage.GetCRL(ctx)
			Expect(err).NotTo(HaveOccurred())

			// Append a second, unrelated CRL as an ancestor would appear.
			ancestorKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			Expect(err).NotTo(HaveOccurred())
			tmpl := &x509.Certificate{
				SerialNumber:          big.NewInt(99),
				Subject:               pkix.Name{CommonName: "Ancestor CA"},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
				BasicConstraintsValid: true,
				IsCA:                  true,
			}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ancestorKey.PublicKey, ancestorKey)
			Expect(err).NotTo(HaveOccurred())
			ancestorCert, err := x509.ParseCertificate(der)
			Expect(err).NotTo(HaveOccurred())
			crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
				Number:     big.NewInt(3),
				ThisUpdate: time.Now().UTC(),
				NextUpdate: time.Now().UTC().Add(24 * time.Hour),
			}, ancestorCert, ancestorKey)
			Expect(err).NotTo(HaveOccurred())
			ancestorCRL := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})

			Expect(myCA.Storage.UpdateCRL(ctx, append(append([]byte{}, stored...), ancestorCRL...))).To(Succeed())

			req := httptest.NewRequest("GET", "/certificate_revocation_list/ca", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))

			blocks := 0
			rest := rr.Body.Bytes()
			for {
				var block *pem.Block
				block, rest = pem.Decode(rest)
				if block == nil {
					break
				}
				if block.Type == "X509 CRL" {
					blocks++
				}
			}
			Expect(blocks).To(Equal(2), "the response must carry every stored CRL block")
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

		It("should return 200 when submitting a CSR for a subject with an active certificate", func() {
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
			// 200 so the node continues to poll and retrieves its cert via GET
			// rather than treating the re-submission as a fatal conflict.
			Expect(rr.Code).To(Equal(http.StatusOK))
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

		It("returns 503, not 404, when the delete fails for a reason other than absence", func() {
			// The 404 used to be the answer to every error from this endpoint,
			// including a lock timeout or an unreachable backend — telling the
			// operator their rejection landed while the CSR was still queued and
			// still signable. Nothing above exercises the distinction: collapse
			// the errors.Is branch in the handler and the CA-layer specs stay
			// green, because they only prove DeleteRequest returns the sentinel.
			// 503 rather than 500 follows the rule handlePutStatusBySerial
			// already wrote down for this class: nothing was deleted, so the
			// fault is transient and the retry is safe.
			subject := "delete-fault-node"
			csrPEM, err := testutil.GenerateCSR(subject)
			Expect(err).NotTo(HaveOccurred())

			faultDir, err := os.MkdirTemp("", "openvox-ca-api-delete-fault")
			Expect(err).NotTo(HaveOccurred())
			defer os.RemoveAll(faultDir)

			backend := &deleteFaultBackend{
				Backend: storage.NewFilesystemBackend(faultDir),
				key:     storage.CSRKey(subject),
				err:     errors.New("backend unavailable"),
			}
			faultStore := storage.NewWithBackend(backend, filepath.Join(faultDir, "private"))
			faultCA := ca.New(faultStore, ca.AutosignConfig{Mode: "off"}, "puppet.test")

			ctx := context.Background()
			Expect(faultStore.EnsureDirs(ctx)).To(Succeed())
			Expect(faultStore.SaveCAKey(ctx, cachedKeyPEM)).To(Succeed())
			Expect(faultStore.SaveCACert(ctx, cachedCrtPEM)).To(Succeed())
			Expect(faultStore.UpdateCRL(ctx, cachedCrlPEM)).To(Succeed())
			Expect(faultStore.WriteSerial(ctx, "0001")).To(Succeed())
			Expect(faultStore.TouchInventory(ctx)).To(Succeed())
			Expect(faultCA.Init(ctx)).To(Succeed())
			faultMux := api.New(faultCA).Routes()

			faultMux.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest("PUT", "/certificate_request/"+subject, bytes.NewReader(csrPEM)))
			Expect(faultStore.HasCSR(ctx, subject)).To(BeTrue())

			rr := httptest.NewRecorder()
			faultMux.ServeHTTP(rr, httptest.NewRequest("DELETE", "/certificate_request/"+subject, nil))
			Expect(rr.Code).To(Equal(http.StatusServiceUnavailable))
			// The backend's own message names a path; it must not reach the client.
			Expect(rr.Body.String()).NotTo(ContainSubstring("backend unavailable"))
			// And the CSR the operator was not told about is still there.
			Expect(faultStore.HasCSR(ctx, subject)).To(BeTrue())
		})
		It("names the client as a principal on the delete-fault record, not as a bare CN", func() {
			// docs/api.md points the operator at this log line as the
			// authoritative record of an ambiguous delete, and the handler's own
			// comment says so. It was the last site in the package still calling
			// clientCN(r) for a log field, two lines below a sibling already
			// using clientOf(r) -- so the one record the documentation promises
			// carried an unsanitised name and no vouching domain.
			subject := "delete-fault-log"
			csrPEM, err := testutil.GenerateCSR(subject)
			Expect(err).NotTo(HaveOccurred())

			faultDir, err := os.MkdirTemp("", "openvox-ca-api-delete-fault-log")
			Expect(err).NotTo(HaveOccurred())
			defer os.RemoveAll(faultDir)

			backend := &deleteFaultBackend{
				Backend: storage.NewFilesystemBackend(faultDir),
				key:     storage.CSRKey(subject),
				err:     errors.New("backend unavailable"),
			}
			faultStore := storage.NewWithBackend(backend, filepath.Join(faultDir, "private"))
			faultCA := ca.New(faultStore, ca.AutosignConfig{Mode: "off"}, "puppet.test")

			ctx := context.Background()
			Expect(faultStore.EnsureDirs(ctx)).To(Succeed())
			Expect(faultStore.SaveCAKey(ctx, cachedKeyPEM)).To(Succeed())
			Expect(faultStore.SaveCACert(ctx, cachedCrtPEM)).To(Succeed())
			Expect(faultStore.UpdateCRL(ctx, cachedCrlPEM)).To(Succeed())
			Expect(faultStore.WriteSerial(ctx, "0001")).To(Succeed())
			Expect(faultStore.TouchInventory(ctx)).To(Succeed())
			Expect(faultCA.Init(ctx)).To(Succeed())
			faultMux := api.New(faultCA).Routes()

			faultMux.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest("PUT", "/certificate_request/"+subject, bytes.NewReader(csrPEM)))

			hostile := &x509.Certificate{
				Subject: pkix.Name{CommonName: "ops\nlevel=ERROR msg=\"forged\""},
			}

			var buf bytes.Buffer
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError})))
			defer slog.SetDefault(orig)

			req := httptest.NewRequest("DELETE", "/certificate_request/"+subject, nil)
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{hostile}}
			rr := httptest.NewRecorder()
			faultMux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusServiceUnavailable))

			// Anchored on the record itself: a buffer-wide assertion would pass
			// on the Debug line above, which already used the principal.
			var record string
			for _, line := range strings.Split(buf.String(), "\n") {
				if strings.Contains(line, "DeleteRequest failed") {
					record = line
				}
			}
			Expect(record).NotTo(BeEmpty())
			Expect(record).To(MatchRegexp(`client\.cn=[^\n]*client\.domain=`),
				"the record must carry the principal, not a bare name")
			Expect(record).NotTo(ContainSubstring(`msg="forged"`),
				"and the name must not be able to close the record and open another")
		})

		It("should return 400 for an invalid subject", func() {
			// The handler's own guard, distinct from the one inside
			// DeleteRequest. Both exist, and only this spec tells them apart:
			// remove the handler's and the request reaches the CA layer, which
			// refuses it too — but as a 503, not a 400.
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, httptest.NewRequest("DELETE", "/certificate_request/a..b", nil))
			Expect(rr.Code).To(Equal(http.StatusBadRequest))
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

		It("should return 503 when the CA is not yet initialised", func() {
			// Construct a fresh server whose CA has no cert loaded. Without
			// the readiness guard, the handler would dereference a nil
			// CACert and panic the entire process.
			emptyDir, err := os.MkdirTemp("", "openvox-ca-not-ready-test")
			Expect(err).NotTo(HaveOccurred())
			defer os.RemoveAll(emptyDir)

			emptyStore := storage.New(emptyDir)
			Expect(emptyStore.EnsureDirs(context.Background())).To(Succeed())
			emptyCA := ca.New(emptyStore, ca.AutosignConfig{Mode: "off"}, "puppet.test")
			emptyServer := api.New(emptyCA)
			emptyMux := emptyServer.Routes()

			req := httptest.NewRequest("GET", "/expirations", nil)
			rr := httptest.NewRecorder()
			Expect(func() { emptyMux.ServeHTTP(rr, req) }).NotTo(Panic())
			Expect(rr.Code).To(Equal(http.StatusServiceUnavailable))
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

	Context("POST /sign/all with SignBatchLimit", func() {
		It("should sign all CSRs in batches when batch limit is set", func() {
			// Create a server with a small batch limit.
			batchServer := api.New(myCA)
			batchServer.SignBatchLimit = 2
			batchMux := batchServer.Routes()

			// Submit 5 CSRs.
			subjects := []string{"batch-a", "batch-b", "batch-c", "batch-d", "batch-e"}
			for _, sub := range subjects {
				csrPEM, err := testutil.GenerateCSR(sub)
				Expect(err).NotTo(HaveOccurred())
				batchMux.ServeHTTP(httptest.NewRecorder(),
					httptest.NewRequest("PUT", "/certificate_request/"+sub, bytes.NewReader(csrPEM)))
			}

			req := httptest.NewRequest("POST", "/sign/all", nil)
			rr := httptest.NewRecorder()
			batchMux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))

			var result struct {
				Signed        []string `json:"signed"`
				SigningErrors []string `json:"signing-errors"`
			}
			Expect(json.Unmarshal(rr.Body.Bytes(), &result)).To(Succeed())
			Expect(result.Signed).To(ConsistOf(subjects))
			Expect(result.SigningErrors).To(BeEmpty())
		})

		It("should sign all CSRs in one pass when batch limit is zero (disabled)", func() {
			batchServer := api.New(myCA)
			batchServer.SignBatchLimit = 0
			batchMux := batchServer.Routes()

			for _, sub := range []string{"nobatch-a", "nobatch-b", "nobatch-c"} {
				csrPEM, err := testutil.GenerateCSR(sub)
				Expect(err).NotTo(HaveOccurred())
				batchMux.ServeHTTP(httptest.NewRecorder(),
					httptest.NewRequest("PUT", "/certificate_request/"+sub, bytes.NewReader(csrPEM)))
			}

			req := httptest.NewRequest("POST", "/sign/all", nil)
			rr := httptest.NewRecorder()
			batchMux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))

			var result struct {
				Signed []string `json:"signed"`
			}
			Expect(json.Unmarshal(rr.Body.Bytes(), &result)).To(Succeed())
			Expect(result.Signed).To(ConsistOf("nobatch-a", "nobatch-b", "nobatch-c"))
		})

		It("should work correctly when batch limit equals the number of CSRs", func() {
			batchServer := api.New(myCA)
			batchServer.SignBatchLimit = 2
			batchMux := batchServer.Routes()

			for _, sub := range []string{"exact-a", "exact-b"} {
				csrPEM, err := testutil.GenerateCSR(sub)
				Expect(err).NotTo(HaveOccurred())
				batchMux.ServeHTTP(httptest.NewRecorder(),
					httptest.NewRequest("PUT", "/certificate_request/"+sub, bytes.NewReader(csrPEM)))
			}

			req := httptest.NewRequest("POST", "/sign/all", nil)
			rr := httptest.NewRecorder()
			batchMux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))

			var result struct {
				Signed []string `json:"signed"`
			}
			Expect(json.Unmarshal(rr.Body.Bytes(), &result)).To(Succeed())
			Expect(result.Signed).To(ConsistOf("exact-a", "exact-b"))
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
			Expect(rr.Body.String()).To(ContainSubstring("found extensions"))
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

	Context("POST /generate/{subject} over plain HTTP", func() {
		It("should return 403 when PlainHTTP is true", func() {
			plainServer := api.New(myCA)
			plainServer.PlainHTTP = true
			plainMux := plainServer.Routes()

			req := httptest.NewRequest("POST", "/generate/plain-node", nil)
			rr := httptest.NewRecorder()
			plainMux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
			Expect(rr.Body.String()).To(ContainSubstring("requires TLS"))
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

	Context("renewal CSR requesting disallowed subject alternative names", func() {
		// The CA-layer refusal is covered in sangate_test.go; what is covered
		// here is the mapping, which is where the property the gate was built
		// for actually holds or fails. A refusal reaching an agent as 500 reads
		// as a server fault it should retry, and this endpoint's whole point is
		// that a renewal which can never succeed stops.
		It("answers 400, not the catch-all 500", func() {
			subject := "renew-san-node"

			csrPEM, err := testutil.GenerateCSR(subject)
			Expect(err).NotTo(HaveOccurred())
			mux.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest("PUT", "/certificate_request/"+subject, bytes.NewReader(csrPEM)))
			body, _ := json.Marshal(api.PutStatusBody{DesiredState: "signed"})
			mux.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest("PUT", "/certificate_status/"+subject, bytes.NewReader(body)))

			certPEM, err := myCA.Storage.GetCert(context.Background(), subject)
			Expect(err).NotTo(HaveOccurred())
			block, _ := pem.Decode(certPEM)
			Expect(block).NotTo(BeNil())
			clientCert, err := x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())

			// A name the presented certificate does not carry, so the renewal
			// baseline cannot excuse it.
			renewCSR := generateCSRWithSANs(subject, []string{"puppet.example.com"})
			req := httptest.NewRequest("POST", "/certificate_renewal", bytes.NewReader(renewCSR))
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}}
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusBadRequest),
				"a policy refusal must not surface as a server fault the agent will retry")
			Expect(rr.Body.String()).To(ContainSubstring(ca.ErrDisallowedSubjectAltNames.Error()))
			Expect(rr.Body.String()).NotTo(ContainSubstring("puppet.example.com"))
		})
	})

	Context("manual signing of a CSR requesting disallowed subject alternative names", func() {
		It("answers 409 naming the refusal, not a bare conflict", func() {
			// Autosign is off in this fixture, so the CSR queues and an
			// operator meets the refusal at the signing step instead.
			subject := "manual-san-node"
			csrPEM := generateCSRWithSANs(subject, []string{"puppet.example.com"})
			mux.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest("PUT", "/certificate_request/"+subject, bytes.NewReader(csrPEM)))

			body, _ := json.Marshal(api.PutStatusBody{DesiredState: "signed"})
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, httptest.NewRequest("PUT", "/certificate_status/"+subject, bytes.NewReader(body)))

			Expect(rr.Code).To(Equal(http.StatusConflict))
			Expect(rr.Body.String()).To(ContainSubstring(ca.ErrDisallowedSubjectAltNames.Error()),
				"a bare \"conflict\" sends the operator to the logs of whichever replica served them")
		})
	})

	Context("CSR requesting disallowed subject alternative names", func() {
		// The branch only fires where SaveRequest itself signs, so this needs an
		// autosigning CA rather than the suite's manual-signing fixture. That is
		// also the configuration the refusal exists for: with autosign off an
		// operator sees the CSR before it becomes a certificate.
		autosignMux := func() http.Handler {
			GinkgoHelper()
			dir := GinkgoT().TempDir()
			autoStore := storage.New(dir)
			autoCA := ca.New(autoStore, ca.AutosignConfig{Mode: "true"}, "puppet.test")

			ctx := context.Background()
			Expect(autoStore.EnsureDirs(ctx)).To(Succeed())
			Expect(autoStore.SaveCAKey(ctx, cachedKeyPEM)).To(Succeed())
			Expect(autoStore.SaveCACert(ctx, cachedCrtPEM)).To(Succeed())
			Expect(autoStore.UpdateCRL(ctx, cachedCrlPEM)).To(Succeed())
			Expect(autoStore.WriteSerial(ctx, "0001")).To(Succeed())
			Expect(autoStore.TouchInventory(ctx)).To(Succeed())
			Expect(autoCA.Init(ctx)).To(Succeed())
			return api.New(autoCA).Routes()
		}

		It("should return 400 without echoing the refused name back", func() {
			// 400 rather than 500: the CSR is well-formed and the request can
			// never succeed, so the agent should stop rather than retry.
			csrPEM := generateCSRWithSANs("san-refused-node", []string{"puppet.example.com"})

			req := httptest.NewRequest("PUT", "/certificate_request/san-refused-node", bytes.NewReader(csrPEM))
			rr := httptest.NewRecorder()
			autosignMux().ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusBadRequest))
			// Generic by design: this endpoint is unauthenticated, so a refusal
			// must not tell a caller which names the CA would have issued.
			Expect(rr.Body.String()).To(ContainSubstring(ca.ErrDisallowedSubjectAltNames.Error()))
			Expect(rr.Body.String()).NotTo(ContainSubstring("puppet.example.com"))
		})
	})

	Context("PUT /certificate_status sign when no CSR exists", func() {
		It("should return 404 when trying to sign a subject with no pending CSR", func() {
			body, _ := json.Marshal(api.PutStatusBody{DesiredState: "signed"})
			req := httptest.NewRequest("PUT", "/certificate_status/ghost-node", bytes.NewReader(body))
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusNotFound))
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

	Context("per-IP rate limiting on CSR submission", func() {
		It("should return 429 when the per-IP limit is exceeded within the window", func() {
			// Build a server with a tight limit of 2 requests/minute.
			limitedServer := api.New(myCA)
			limitedServer.CSRRateLimit = 2
			limitedMux := limitedServer.Routes()

			// First two requests succeed (200 or 409, both mean the limiter allowed them through).
			for range 2 {
				csrPEM, err := testutil.GenerateCSR("rl-node")
				Expect(err).NotTo(HaveOccurred())
				req := httptest.NewRequest("PUT", "/certificate_request/rl-node", bytes.NewReader(csrPEM))
				rr := httptest.NewRecorder()
				limitedMux.ServeHTTP(rr, req)
				Expect(rr.Code).NotTo(Equal(http.StatusTooManyRequests))
			}

			// Third request from the same IP must be rate-limited.
			csrPEM, err := testutil.GenerateCSR("rl-node")
			Expect(err).NotTo(HaveOccurred())
			req := httptest.NewRequest("PUT", "/certificate_request/rl-node", bytes.NewReader(csrPEM))
			rr := httptest.NewRecorder()
			limitedMux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusTooManyRequests))
		})

		It("should not rate-limit when CSRRateLimit is zero (default)", func() {
			// The shared server has no rate limit set; submit many requests.
			for range 5 {
				csrPEM, err := testutil.GenerateCSR("nolimit-node")
				Expect(err).NotTo(HaveOccurred())
				req := httptest.NewRequest("PUT", "/certificate_request/nolimit-node", bytes.NewReader(csrPEM))
				rr := httptest.NewRecorder()
				mux.ServeHTTP(rr, req)
				Expect(rr.Code).NotTo(Equal(http.StatusTooManyRequests))
			}
		})
	})

	Context("serial_number in status response is a full decimal string", func() {
		It("should return serial_number as a non-empty decimal string without truncation", func() {
			subject := "serial-node"
			csrPEM, err := testutil.GenerateCSR(subject)
			Expect(err).NotTo(HaveOccurred())

			// Submit CSR and sign it.
			mux.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest("PUT", "/certificate_request/"+subject, bytes.NewReader(csrPEM)))
			body, _ := json.Marshal(api.PutStatusBody{DesiredState: "signed"})
			mux.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest("PUT", "/certificate_status/"+subject, bytes.NewReader(body)))

			// Fetch the signed cert and parse its serial for comparison.
			certRR := httptest.NewRecorder()
			mux.ServeHTTP(certRR, httptest.NewRequest("GET", "/certificate/"+subject, nil))
			Expect(certRR.Code).To(Equal(http.StatusOK))
			block, _ := pem.Decode(certRR.Body.Bytes())
			Expect(block).NotTo(BeNil())
			cert, err := x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())
			expectedSerial := cert.SerialNumber.Text(10)

			// Fetch status and confirm serial_number matches exactly.
			statusRR := httptest.NewRecorder()
			mux.ServeHTTP(statusRR, httptest.NewRequest("GET", "/certificate_status/"+subject, nil))
			Expect(statusRR.Code).To(Equal(http.StatusOK))

			var resp api.CertStatusResponse
			Expect(json.Unmarshal(statusRR.Body.Bytes(), &resp)).To(Succeed())
			Expect(resp.SerialNumber).NotTo(BeNil())
			// Must be a pure decimal string.
			Expect(*resp.SerialNumber).To(MatchRegexp(`^[0-9]+$`))
			// Must be the full, un-truncated value.
			Expect(*resp.SerialNumber).To(Equal(expectedSerial))
		})
	})

	Context("PUT /clean", func() {
		sign := func(subject string) {
			csrPEM, err := testutil.GenerateCSR(subject)
			Expect(err).NotTo(HaveOccurred())
			mux.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest("PUT", "/certificate_request/"+subject, bytes.NewReader(csrPEM)))
			body, _ := json.Marshal(api.PutStatusBody{DesiredState: "signed"})
			mux.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest("PUT", "/certificate_status/"+subject, bytes.NewReader(body)))
		}

		It("cleans listed subjects and returns a CleanResult", func() {
			sign("clean-node-a")
			sign("clean-node-b")

			body, _ := json.Marshal(map[string][]string{"certnames": {"clean-node-a", "clean-node-b", "ghost-node"}})
			req := httptest.NewRequest("PUT", "/clean", bytes.NewReader(body))
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))

			var result struct {
				Cleaned     []string `json:"cleaned"`
				NotFound    []string `json:"not-found"`
				CleanErrors []string `json:"clean-errors"`
			}
			Expect(json.Unmarshal(rr.Body.Bytes(), &result)).To(Succeed())
			Expect(result.Cleaned).To(ConsistOf("clean-node-a", "clean-node-b"))
			Expect(result.NotFound).To(ConsistOf("ghost-node"))
			Expect(result.CleanErrors).To(BeEmpty())
		})

		It("reports subjects as cleaned when only a CSR is pending", func() {
			csrPEM, err := testutil.GenerateCSR("clean-csr-only")
			Expect(err).NotTo(HaveOccurred())
			mux.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest("PUT", "/certificate_request/clean-csr-only", bytes.NewReader(csrPEM)))

			body, _ := json.Marshal(map[string][]string{"certnames": {"clean-csr-only"}})
			req := httptest.NewRequest("PUT", "/clean", bytes.NewReader(body))
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))

			var result struct {
				Cleaned  []string `json:"cleaned"`
				NotFound []string `json:"not-found"`
			}
			Expect(json.Unmarshal(rr.Body.Bytes(), &result)).To(Succeed())
			Expect(result.Cleaned).To(ConsistOf("clean-csr-only"))
			Expect(result.NotFound).To(BeEmpty())
		})

		It("also responds on the /puppet-ca/v1/clean path", func() {
			sign("clean-prefix-node")

			body, _ := json.Marshal(map[string][]string{"certnames": {"clean-prefix-node"}})
			req := httptest.NewRequest("PUT", "/puppet-ca/v1/clean", bytes.NewReader(body))
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})

		It("returns 400 for an empty certnames list", func() {
			body, _ := json.Marshal(map[string][]string{"certnames": {}})
			req := httptest.NewRequest("PUT", "/clean", bytes.NewReader(body))
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusBadRequest))
		})

		It("returns 400 for malformed JSON", func() {
			req := httptest.NewRequest("PUT", "/clean", bytes.NewReader([]byte("{bad")))
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusBadRequest))
		})
	})

	Context("POST /certificate_renewal", func() {
		var (
			subject    string
			clientCert *x509.Certificate
		)

		BeforeEach(func() {
			subject = "renew-node"

			// Submit and sign a certificate for the subject.
			csrPEM, err := testutil.GenerateCSR(subject)
			Expect(err).NotTo(HaveOccurred())
			mux.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest("PUT", "/certificate_request/"+subject, bytes.NewReader(csrPEM)))
			body, _ := json.Marshal(api.PutStatusBody{DesiredState: "signed"})
			mux.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest("PUT", "/certificate_status/"+subject, bytes.NewReader(body)))

			// Retrieve the signed cert so we can simulate mTLS with it.
			certPEM, err := myCA.Storage.GetCert(context.Background(), subject)
			Expect(err).NotTo(HaveOccurred())
			block, _ := pem.Decode(certPEM)
			Expect(block).NotTo(BeNil())
			clientCert, err = x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())
		})

		// The two handler branches that map ErrForeignCertificate to 403 are
		// unreachable while the middleware's trust anchor and this CA's own
		// certificate are the same object: the middleware rejects a foreign
		// certificate before any handler runs. They become reachable exactly
		// when those two diverge, which is the topology the intermediate-CA
		// work introduces — so the fixture makes them diverge deliberately,
		// trusting a second issuer for authentication while the CA still
		// refuses to renew its certificates.
		Context("when the middleware trusts an issuer the CA did not", func() {
			var (
				splitMux      http.Handler
				logBuf        *bytes.Buffer
				foreignCert   *x509.Certificate
				foreignCACert *x509.Certificate
				foreignCAPriv *rsa.PrivateKey
			)

			BeforeEach(func() {
				foreignCAKey, err := rsa.GenerateKey(rand.Reader, 2048)
				Expect(err).NotTo(HaveOccurred())
				foreignCATmpl := &x509.Certificate{
					SerialNumber:          big.NewInt(99),
					Subject:               pkix.Name{CommonName: "Second Issuer"},
					NotBefore:             time.Now().Add(-time.Hour),
					NotAfter:              time.Now().Add(24 * time.Hour),
					KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
					BasicConstraintsValid: true,
					IsCA:                  true,
				}
				foreignCADER, err := x509.CreateCertificate(rand.Reader, foreignCATmpl, foreignCATmpl,
					&foreignCAKey.PublicKey, foreignCAKey)
				Expect(err).NotTo(HaveOccurred())
				foreignCA, err := x509.ParseCertificate(foreignCADER)
				Expect(err).NotTo(HaveOccurred())
				foreignCACert, foreignCAPriv = foreignCA, foreignCAKey

				leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
				Expect(err).NotTo(HaveOccurred())
				leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
					SerialNumber: big.NewInt(100),
					Subject:      pkix.Name{CommonName: subject},
					NotBefore:    time.Now().Add(-time.Hour),
					NotAfter:     time.Now().Add(time.Hour),
					ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
				}, foreignCA, &leafKey.PublicKey, foreignCAKey)
				Expect(err).NotTo(HaveOccurred())
				foreignCert, err = x509.ParseCertificate(leafDER)
				Expect(err).NotTo(HaveOccurred())

				// Domain zero's anchor is the *foreign* issuer, so the
				// middleware attributes the certificate to our own domain and
				// tierOwnClient admits it — while the CA still knows it did not
				// issue it. That divergence is what makes the handler's
				// ErrForeignCertificate branch reachable at all.
				splitServer := api.New(myCA)
				// A CA that trusts an issuer other than itself: domain zero is
				// the foreign certificate, so a client this CA issued does not
				// verify and the renewal refusal below is reachable.
				splitServer.AuthConfig = &api.AuthConfig{
					Domains: []api.TrustDomain{api.OwnTrustDomain(foreignCA, nil, true)},
				}
				splitMux = splitServer.Routes()

				// The eligibility refusals are logged, and the migration guide
				// tells operators to grep for them, so capture the default
				// logger for these specs.
				logBuf = &bytes.Buffer{}
				orig := slog.Default()
				slog.SetDefault(slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelWarn})))
				DeferCleanup(func() { slog.SetDefault(orig) })
			})

			It("refuses an empty-body renewal with 403 from the handler", func() {
				req := httptest.NewRequest("POST", "/certificate_renewal", bytes.NewReader(nil))
				req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{foreignCert}}
				rr := httptest.NewRecorder()
				splitMux.ServeHTTP(rr, req)

				Expect(rr.Code).To(Equal(http.StatusForbidden))
				// Not the middleware's wording: this rejection came from the
				// handler, and the authorisation oracle relies on telling them
				// apart.
				Expect(rr.Body.String()).To(ContainSubstring("not eligible for renewal"))

				// The migration guide publishes this string as a grep target,
				// which makes it a contract like the middleware's own denial
				// log. The empty-body form has its own message: an operator
				// filtering for one must not silently miss the other.
				Expect(logBuf.String()).To(ContainSubstring("Auto-renewal rejected: certificate not eligible"))
				Expect(logBuf.String()).To(ContainSubstring("subject=" + subject))
				Expect(logBuf.String()).To(ContainSubstring(`error="`+ca.ErrForeignCertificate.Error()),
					"the guide promises the reason in error=, so pin the key and the sentinel "+
						"the value opens with; the wrapped cause follows it")
			})

			It("refuses a CSR-based renewal with 403 from the handler", func() {
				renewCSR, err := testutil.GenerateCSR(subject)
				Expect(err).NotTo(HaveOccurred())
				req := httptest.NewRequest("POST", "/certificate_renewal", bytes.NewReader(renewCSR))
				req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{foreignCert}}
				rr := httptest.NewRecorder()
				splitMux.ServeHTTP(rr, req)

				Expect(rr.Code).To(Equal(http.StatusForbidden))
				Expect(rr.Body.String()).To(ContainSubstring("not eligible for renewal"))

				Expect(logBuf.String()).To(ContainSubstring("Renewal rejected: certificate not eligible"))
				Expect(logBuf.String()).To(ContainSubstring("subject=" + subject))
				Expect(logBuf.String()).To(ContainSubstring(`error="`+ca.ErrForeignCertificate.Error()),
					"the guide promises the reason in error=, so pin the key and the sentinel "+
						"the value opens with; the wrapped cause follows it")
			})

			It("refuses a foreign certificate whose CN is not certname-shaped with 403, not 500", func() {
				// A second issuer's leaf need not respect this CA's lowercase
				// certname grammar. ValidateSubject would reject "Monitoring
				// Host" with an unsentinelled error the handler can only render
				// as a 500 — so the gate has to answer provenance first for the
				// documented 403 to be what an operator actually sees.
				leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
				Expect(err).NotTo(HaveOccurred())
				leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
					SerialNumber: big.NewInt(101),
					Subject:      pkix.Name{CommonName: "Monitoring Host"},
					NotBefore:    time.Now().Add(-time.Hour),
					NotAfter:     time.Now().Add(time.Hour),
					ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
				}, foreignCACert, &leafKey.PublicKey, foreignCAPriv)
				Expect(err).NotTo(HaveOccurred())
				oddName, err := x509.ParseCertificate(leafDER)
				Expect(err).NotTo(HaveOccurred())

				req := httptest.NewRequest("POST", "/certificate_renewal", bytes.NewReader(nil))
				req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{oddName}}
				rr := httptest.NewRecorder()
				splitMux.ServeHTTP(rr, req)

				Expect(rr.Code).To(Equal(http.StatusForbidden))
				Expect(rr.Body.String()).To(ContainSubstring("not eligible for renewal"))
			})
		})

		// The renewal handler's own log lines. It keys them on "subject" rather
		// than "client" -- the name being renewed, not the principal asking --
		// so they do not go through the principal's LogValue, and nine of them
		// carried the common name verbatim while clientCN's doc comment implied
		// the class was closed.
		//
		// Not safe by construction either: ImportCertificate accepts any
		// certificate this CA's key signed and matches the path subject against
		// the CN *or a DNS SAN*, so a CN of arbitrary bytes can be registered
		// under a validated name. slog's handlers quote control characters, so
		// this is defence in depth rather than a live forgery -- but the branch
		// advertises that a CN cannot reach a record unsanitised, and an
		// invariant with nine exceptions is not one.
		//
		// Both halves of the handler, because they are separate code paths with
		// separate log sites: the empty-body auto-renewal and the CSR renewal.
		Context("logging a hostile common name", func() {
			const hostile = "evil\nlevel=ERROR msg=\"forged\""

			// A leaf carrying the hostile CN, self-signed so this CA did not
			// issue it: renewal then refuses it and the rejection lines are
			// reached. The middleware is bypassed here (api.New leaves
			// AuthConfig nil), so what the certificate chains to does not
			// matter -- clientCN reads the CN straight off the presented cert,
			// which is the whole point of sanitising it.
			hostileLeaf := func() (*x509.Certificate, *rsa.PrivateKey) {
				GinkgoHelper()
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				Expect(err).NotTo(HaveOccurred())
				tmpl := &x509.Certificate{
					SerialNumber: big.NewInt(20260823),
					Subject:      pkix.Name{CommonName: hostile},
					NotBefore:    time.Now().Add(-time.Hour),
					NotAfter:     time.Now().Add(time.Hour),
					KeyUsage:     x509.KeyUsageDigitalSignature,
					ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
				}
				der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
				Expect(err).NotTo(HaveOccurred())
				leaf, err := x509.ParseCertificate(der)
				Expect(err).NotTo(HaveOccurred())
				return leaf, key
			}

			// recordFor isolates one log line. A buffer-wide assertion would pass
			// with the line under test left raw, because every other line in the
			// handler already carries a neutralised name.
			recordFor := func(buf *bytes.Buffer, msg string) string {
				GinkgoHelper()
				for _, line := range strings.Split(buf.String(), "\n") {
					if strings.Contains(line, msg) {
						return line
					}
				}
				Fail("no log record matching " + msg)
				return ""
			}

			capture := func(fn func()) *bytes.Buffer {
				GinkgoHelper()
				var buf bytes.Buffer
				orig := slog.Default()
				slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
				defer slog.SetDefault(orig)
				fn()
				return &buf
			}

			It("neutralises it on the auto-renewal path", func() {
				leaf, _ := hostileLeaf()

				buf := capture(func() {
					req := httptest.NewRequest("POST", "/certificate_renewal", bytes.NewReader(nil))
					req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
					mux.ServeHTTP(httptest.NewRecorder(), req)
				})

				record := recordFor(buf, "Auto-renewal rejected")
				Expect(record).NotTo(ContainSubstring("msg=\"forged\""),
					"the name must not be able to close the record and open another")
				Expect(record).To(ContainSubstring("\uFFFD"),
					"sanitiseForLog replaces the control character rather than dropping the field")
			})

			It("neutralises it on the CSR renewal path", func() {
				leaf, key := hostileLeaf()

				// The CSR has to carry the same name, or the handler refuses at
				// the comparison before any of these lines is reached.
				csrDER, err := x509.CreateCertificateRequest(rand.Reader,
					&x509.CertificateRequest{Subject: pkix.Name{CommonName: hostile}}, key)
				Expect(err).NotTo(HaveOccurred())
				csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

				buf := capture(func() {
					req := httptest.NewRequest("POST", "/certificate_renewal", bytes.NewReader(csrPEM))
					req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
					mux.ServeHTTP(httptest.NewRecorder(), req)
				})

				record := recordFor(buf, "Renewal rejected")
				Expect(record).NotTo(ContainSubstring("msg=\"forged\""))
				Expect(record).To(ContainSubstring("\uFFFD"))
			})
		})

		Context("when the CA has not finished initialising", func() {
			// The 503 mapping added alongside the gate's 403s. Its sibling is
			// covered at this layer and so is the import path it copies, but
			// this was pinned only at the CA boundary — delete either handler
			// block and nothing failed.
			var bareMux http.Handler

			BeforeEach(func() {
				bare := api.New(ca.New(storage.New(GinkgoT().TempDir()), ca.AutosignConfig{Mode: "off"}, "puppet.test"))
				bareMux = bare.Routes()
			})

			It("answers 503 rather than 500 for an empty-body renewal", func() {
				req := httptest.NewRequest("POST", "/certificate_renewal", bytes.NewReader(nil))
				req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}}
				rr := httptest.NewRecorder()
				bareMux.ServeHTTP(rr, req)
				Expect(rr.Code).To(Equal(http.StatusServiceUnavailable))
			})

			It("answers 503 rather than 500 for a CSR-based renewal", func() {
				renewCSR, err := testutil.GenerateCSR(subject)
				Expect(err).NotTo(HaveOccurred())
				req := httptest.NewRequest("POST", "/certificate_renewal", bytes.NewReader(renewCSR))
				req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}}
				rr := httptest.NewRecorder()
				bareMux.ServeHTTP(rr, req)
				Expect(rr.Code).To(Equal(http.StatusServiceUnavailable))
			})
		})

		It("should renew the certificate and return PEM", func() {
			renewCSR, err := testutil.GenerateCSR(subject)
			Expect(err).NotTo(HaveOccurred())
			req := httptest.NewRequest("POST", "/certificate_renewal", bytes.NewReader(renewCSR))
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}}
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
			Expect(rr.Body.String()).To(ContainSubstring("CERTIFICATE"))
		})

		It("should also work via the /puppet-ca/v1/certificate_renewal path", func() {
			renewCSR, err := testutil.GenerateCSR(subject)
			Expect(err).NotTo(HaveOccurred())
			req := httptest.NewRequest("POST", "/puppet-ca/v1/certificate_renewal", bytes.NewReader(renewCSR))
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}}
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})

		It("should return 403 when no client certificate is presented", func() {
			renewCSR, err := testutil.GenerateCSR(subject)
			Expect(err).NotTo(HaveOccurred())
			req := httptest.NewRequest("POST", "/certificate_renewal", bytes.NewReader(renewCSR))
			// No r.TLS — simulates plain HTTP or missing client cert.
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		It("should return 403 when the CSR CN does not match the client CN", func() {
			mismatchCSR, err := testutil.GenerateCSR("other-node")
			Expect(err).NotTo(HaveOccurred())
			req := httptest.NewRequest("POST", "/certificate_renewal", bytes.NewReader(mismatchCSR))
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}}
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		It("should return 400 for an invalid CSR body", func() {
			req := httptest.NewRequest("POST", "/certificate_renewal", bytes.NewReader([]byte("not a csr")))
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}}
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusBadRequest))
		})

		// Real Puppet/OpenVox agents POST an empty body by default
		// (hostcert_renewal_interval), relying solely on the mTLS-presented
		// client cert. This must reissue the SAME key, not require a CSR.
		It("should auto-renew the presented certificate's own key when the body is empty", func() {
			req := httptest.NewRequest("POST", "/certificate_renewal", bytes.NewReader(nil))
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}}
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))

			block, _ := pem.Decode(rr.Body.Bytes())
			Expect(block).NotTo(BeNil())
			renewed, err := x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(renewed.PublicKey).To(Equal(clientCert.PublicKey),
				"auto-renewal via empty body must not rotate the key")
			Expect(renewed.SerialNumber.Cmp(clientCert.SerialNumber)).NotTo(Equal(0))

			// Default RevokeOnAutoRenew=true: the pre-renewal serial must no
			// longer be usable once the renewed cert is safely stored.
			revoked, err := myCA.IsRevokedSerial(context.Background(), clientCert.SerialNumber)
			Expect(err).NotTo(HaveOccurred())
			Expect(revoked).To(BeTrue(),
				"the pre-renewal serial must be revoked by default after auto-renewal")
		})

		// The routing decision uses strings.TrimSpace, so a whitespace-only body
		// (some clients send a trailing newline) must take the same auto-renewal
		// path as a truly-empty one — not be treated as a malformed CSR. Guards
		// against the check regressing to a bare len(body)==0.
		It("should auto-renew when the body is whitespace only", func() {
			req := httptest.NewRequest("POST", "/certificate_renewal", bytes.NewReader([]byte("  \n\t")))
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}}
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))

			block, _ := pem.Decode(rr.Body.Bytes())
			Expect(block).NotTo(BeNil())
			renewed, err := x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(renewed.PublicKey).To(Equal(clientCert.PublicKey),
				"whitespace-only body must route to auto-renewal and reissue the same key")
			Expect(renewed.SerialNumber.Cmp(clientCert.SerialNumber)).NotTo(Equal(0))
		})

		// Renewal must refuse a revoked certificate with a clean 403 rather than
		// a 500, on both branches of the route. Guards the
		// errors.Is(err, ca.ErrCertRevoked) mappings at the HTTP layer, which
		// the CA-layer specs cannot exercise. Revoking through the CA the server
		// holds means its cache is already current here; the cross-replica case,
		// where only storage knows, is covered in internal/ca/crlsync_test.go.
		It("should return 403 when renewing a revoked certificate (empty body)", func() {
			Expect(myCA.Revoke(context.Background(), subject)).To(Succeed())

			req := httptest.NewRequest("POST", "/certificate_renewal", bytes.NewReader(nil))
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}}
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		It("should return 403 when renewing a revoked certificate (CSR body)", func() {
			Expect(myCA.Revoke(context.Background(), subject)).To(Succeed())

			csrPEM, err := testutil.GenerateCSR(subject)
			Expect(err).NotTo(HaveOccurred())

			req := httptest.NewRequest("POST", "/certificate_renewal", bytes.NewReader(csrPEM))
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}}
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		// A legacy-imported node may present a cert whose key predates this CA's
		// key-strength policy. The empty-body auto-renewal path must surface that
		// as a client-actionable 422 (re-key via CSR), not mask it behind a 500.
		// This guards the errors.Is(err, ca.ErrKeyPolicy) mapping at the HTTP
		// layer, which the CA-layer AutoRenew test cannot exercise.
		It("should return 422 when the presented certificate's key is below policy (empty body)", func() {
			weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
			Expect(err).NotTo(HaveOccurred())
			template := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				Subject:      pkix.Name{CommonName: subject},
				NotBefore:    time.Now().Add(-time.Hour),
				NotAfter:     time.Now().Add(time.Hour),
				DNSNames:     []string{subject},
			}
			// Signed by this CA, not self-signed. The scenario is a node whose
			// certificate we issued before the key-strength policy existed, so
			// the renewal gate must pass and the policy check must be what
			// rejects it. A self-signed fixture here only ever reached the
			// policy check because nothing verified the issuer.
			der, err := x509.CreateCertificate(rand.Reader, template, myCA.CACert, &weakKey.PublicKey, myCA.CAKey)
			Expect(err).NotTo(HaveOccurred())
			weakCert, err := x509.ParseCertificate(der)
			Expect(err).NotTo(HaveOccurred())

			req := httptest.NewRequest("POST", "/certificate_renewal", bytes.NewReader(nil))
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{weakCert}}
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusUnprocessableEntity))
		})

		// The same key-strength policy applies to a re-key CSR: a CSR carrying a
		// sub-policy key must yield 422, not the generic 400 (invalid CSR) or a
		// 500. Guards the second errors.Is(err, ca.ErrKeyPolicy) branch.
		It("should return 422 when the renewal CSR key is below policy", func() {
			weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
			Expect(err).NotTo(HaveOccurred())
			csrDER, err := x509.CreateCertificateRequest(rand.Reader,
				&x509.CertificateRequest{Subject: pkix.Name{CommonName: subject}}, weakKey)
			Expect(err).NotTo(HaveOccurred())
			weakCSR := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

			req := httptest.NewRequest("POST", "/certificate_renewal", bytes.NewReader(weakCSR))
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}}
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusUnprocessableEntity))
		})
	})

	Context("PuppetDateTimeFormat", func() {
		const puppetFmt = "2006-01-02T15:04:05MST"

		signSubject := func(subject string) {
			csrPEM, err := testutil.GenerateCSR(subject)
			Expect(err).NotTo(HaveOccurred())
			mux.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest("PUT", "/certificate_request/"+subject, bytes.NewReader(csrPEM)))
			body, _ := json.Marshal(api.PutStatusBody{DesiredState: "signed"})
			mux.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest("PUT", "/certificate_status/"+subject, bytes.NewReader(body)))
		}

		It("defaults to RFC 3339 format for not_before / not_after", func() {
			signSubject("fmt-default-node")
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, httptest.NewRequest("GET", "/certificate_status/fmt-default-node", nil))
			Expect(rr.Code).To(Equal(http.StatusOK))

			var resp api.CertStatusResponse
			Expect(json.Unmarshal(rr.Body.Bytes(), &resp)).To(Succeed())
			Expect(resp.NotBefore).NotTo(BeNil())
			// RFC 3339 uses a numeric offset or Z, not a timezone abbreviation.
			_, err := time.Parse(time.RFC3339, *resp.NotBefore)
			Expect(err).NotTo(HaveOccurred(), "not_before should parse as RFC 3339")
		})

		It("uses Puppet CA format for not_before / not_after when enabled", func() {
			server.PuppetDateTimeFormat = true
			mux = server.Routes()

			signSubject("fmt-puppet-node")
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, httptest.NewRequest("GET", "/certificate_status/fmt-puppet-node", nil))
			Expect(rr.Code).To(Equal(http.StatusOK))

			var resp api.CertStatusResponse
			Expect(json.Unmarshal(rr.Body.Bytes(), &resp)).To(Succeed())
			Expect(resp.NotBefore).NotTo(BeNil())
			_, err := time.Parse(puppetFmt, *resp.NotBefore)
			Expect(err).NotTo(HaveOccurred(), "not_before should parse as Puppet CA format")
			_, err = time.Parse(time.RFC3339, *resp.NotBefore)
			Expect(err).To(HaveOccurred(), "not_before should not be valid RFC 3339 in Puppet mode")
		})

		It("uses Puppet CA format for expirations when enabled", func() {
			server.PuppetDateTimeFormat = true
			mux = server.Routes()

			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, httptest.NewRequest("GET", "/expirations", nil))
			Expect(rr.Code).To(Equal(http.StatusOK))

			var resp struct {
				CACertificate struct {
					Expiration string `json:"expiration"`
				} `json:"ca_certificate"`
			}
			Expect(json.Unmarshal(rr.Body.Bytes(), &resp)).To(Succeed())
			_, err := time.Parse(puppetFmt, resp.CACertificate.Expiration)
			Expect(err).NotTo(HaveOccurred(), "expiration should parse as Puppet CA format")
		})
	})

})

// foreignCRL returns a PEM CRL signed by a CA unrelated to the one under test,
// which is what readStoredCRL refuses.
func foreignCRL() []byte {
	GinkgoHelper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(4242),
		Subject:               pkix.Name{CommonName: "Unrelated CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	Expect(err).NotTo(HaveOccurred())
	cert, err := x509.ParseCertificate(der)
	Expect(err).NotTo(HaveOccurred())
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(6),
		ThisUpdate: time.Now().UTC(),
		NextUpdate: time.Now().UTC().Add(24 * time.Hour),
	}, cert, key)
	Expect(err).NotTo(HaveOccurred())
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})
}

// deleteFaultBackend fails Delete on one CSR key with something that is not
// os.ErrNotExist — a backend that is reachable but refusing writes, which is
// the case the endpoint used to report as "CSR not found".
type deleteFaultBackend struct {
	storage.Backend
	key string
	err error
}

func (b *deleteFaultBackend) Delete(ctx context.Context, key string) error {
	if key == b.key {
		return b.err
	}
	return b.Backend.Delete(ctx, key)
}
