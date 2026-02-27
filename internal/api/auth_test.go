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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
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

// issueClientCert creates a leaf cert with the given CN, signed by caCert/caKey,
// with ExtKeyUsageClientAuth so the middleware's x509.Verify call accepts it.
func issueClientCert(cn string, caCert *x509.Certificate, caKey *rsa.PrivateKey) *x509.Certificate {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	Expect(err).NotTo(HaveOccurred())
	cert, err := x509.ParseCertificate(certBytes)
	Expect(err).NotTo(HaveOccurred())
	return cert
}

// withClientCert returns a shallow clone of r with r.TLS set to present cert as the peer.
func withClientCert(r *http.Request, cert *x509.Certificate) *http.Request {
	r = r.Clone(r.Context())
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	return r
}

var _ = Describe("Auth Middleware", func() {
	var (
		tmpDir string
		myCA   *ca.CA
		store  *storage.StorageService
		mux    http.Handler
		caCert *x509.Certificate
		caKey  *rsa.PrivateKey
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-auth-test")
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

		// Parse CA cert and key so we can issue test client certs.
		block, _ := pem.Decode(cachedCrtPEM)
		caCert, err = x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		block, _ = pem.Decode(cachedKeyPEM)
		caKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		Expect(err).NotTo(HaveOccurred())

		// "puppet-server" is the sole admin CN in the allow list.
		server := api.New(myCA)
		server.AuthConfig = &api.AuthConfig{
			CACert:    caCert,
			AllowList: map[string]bool{"puppet-server": true},
		}
		mux = server.Routes()
	})

	AfterEach(func() { os.RemoveAll(tmpDir) })

	// ── Public endpoints bypass all cert checks ────────────────────────────────

	Context("public endpoints pass through without any client cert", func() {
		It("allows GET /certificate/ca with no TLS connection state", func() {
			req := httptest.NewRequest("GET", "/certificate/ca", nil)
			// r.TLS is nil; the public tier check fires before the TLS check.
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})

		It("allows PUT /certificate_request/{subject} with no client cert", func() {
			csrPEM, err := testutil.GenerateCSR("public-node")
			Expect(err).NotTo(HaveOccurred())
			req := httptest.NewRequest("PUT", "/certificate_request/public-node", bytes.NewReader(csrPEM))
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})

		It("allows GET /certificate_revocation_list/ca with no client cert", func() {
			req := httptest.NewRequest("GET", "/certificate_revocation_list/ca", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})
	})

	// ── No client cert on protected endpoints ──────────────────────────────────

	Context("no client cert presented to a protected endpoint", func() {
		It("returns 403 for GET /certificate_status/{subject} (self-or-admin tier)", func() {
			req := httptest.NewRequest("GET", "/certificate_status/some-node", nil)
			req.TLS = &tls.ConnectionState{}
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		It("returns 403 for POST /sign/all (admin-only tier)", func() {
			req := httptest.NewRequest("POST", "/sign/all", nil)
			req.TLS = &tls.ConnectionState{}
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})
	})

	// ── Client cert from an unrecognised CA ────────────────────────────────────

	Context("client cert signed by a different CA", func() {
		It("returns 403 even if the CN is in the allow list", func() {
			// Generate an independent CA not trusted by AuthConfig.
			altKeyPEM, altCertPEM, _, err := testutil.GenerateTestCA()
			Expect(err).NotTo(HaveOccurred())
			altCACertBlock, _ := pem.Decode(altCertPEM)
			altCACert, err := x509.ParseCertificate(altCACertBlock.Bytes)
			Expect(err).NotTo(HaveOccurred())
			altKeyBlock, _ := pem.Decode(altKeyPEM)
			altCAKey, err := x509.ParsePKCS1PrivateKey(altKeyBlock.Bytes)
			Expect(err).NotTo(HaveOccurred())

			// CN matches the admin allow list, but chain is wrong.
			clientCert := issueClientCert("puppet-server", altCACert, altCAKey)
			req := httptest.NewRequest("POST", "/sign/all", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})
	})

	// ── Certificate validity period enforcement ────────────────────────────────

	Context("certificate validity period enforcement", func() {
		It("returns 403 when client presents an expired certificate", func() {
			// Issue a cert whose validity window lies entirely in the past.
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).NotTo(HaveOccurred())
			template := &x509.Certificate{
				SerialNumber: big.NewInt(time.Now().UnixNano()),
				Subject:      pkix.Name{CommonName: "expired-node"},
				NotBefore:    time.Now().Add(-2 * time.Hour),
				NotAfter:     time.Now().Add(-1 * time.Hour), // already expired
				ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}
			certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
			Expect(err).NotTo(HaveOccurred())
			expiredCert, err := x509.ParseCertificate(certBytes)
			Expect(err).NotTo(HaveOccurred())

			req := httptest.NewRequest("GET", "/certificate_status/expired-node", nil)
			req = withClientCert(req, expiredCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		It("returns 403 when client presents a not-yet-valid certificate", func() {
			// Issue a cert whose NotBefore is in the future.
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).NotTo(HaveOccurred())
			template := &x509.Certificate{
				SerialNumber: big.NewInt(time.Now().UnixNano()),
				Subject:      pkix.Name{CommonName: "future-node"},
				NotBefore:    time.Now().Add(1 * time.Hour), // not yet valid
				NotAfter:     time.Now().Add(2 * time.Hour),
				ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}
			certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
			Expect(err).NotTo(HaveOccurred())
			futureCert, err := x509.ParseCertificate(certBytes)
			Expect(err).NotTo(HaveOccurred())

			req := httptest.NewRequest("GET", "/certificate_status/future-node", nil)
			req = withClientCert(req, futureCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})
	})

	// ── Revoked client cert ────────────────────────────────────────────────────

	Context("revoked client cert", func() {
		It("returns 403 even though the cert is CA-signed", func() {
			// Register the CN in the CA so Revoke can find it in inventory.
			csrPEM, err := testutil.GenerateCSR("revoked-client")
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.SaveRequest("revoked-client", csrPEM)
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.Sign("revoked-client")
			Expect(err).NotTo(HaveOccurred())
			Expect(myCA.Revoke("revoked-client")).To(Succeed())

			// Issue a fresh TLS cert with the revoked CN.
			// IsRevoked looks up the on-disk cert for the CN, reads its serial
			// number, and checks whether that serial is in the CRL.  The TLS-
			// presented cert's serial is not consulted; only the CN is used to
			// locate the revoked record on disk.
			clientCert := issueClientCert("revoked-client", caCert, caKey)
			req := httptest.NewRequest("GET", "/certificate_status/revoked-client", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})
	})

	// ── Non-admin on admin-only endpoints ──────────────────────────────────────

	Context("non-admin client accessing admin-only endpoints", func() {
		It("returns 403 for POST /sign/all", func() {
			clientCert := issueClientCert("regular-node", caCert, caKey)
			req := httptest.NewRequest("POST", "/sign/all", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		It("returns 403 for DELETE /certificate_status/{subject}", func() {
			clientCert := issueClientCert("regular-node", caCert, caKey)
			req := httptest.NewRequest("DELETE", "/certificate_status/some-node", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		It("returns 403 for GET /certificate_statuses (admin-only tier)", func() {
			clientCert := issueClientCert("regular-node", caCert, caKey)
			req := httptest.NewRequest("GET", "/certificate_statuses/all", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		It("returns 403 for POST /generate/{subject} (admin-only tier)", func() {
			clientCert := issueClientCert("regular-node", caCert, caKey)
			req := httptest.NewRequest("POST", "/generate/some-node", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		It("returns 403 for DELETE /certificate_request/{subject} (admin-only tier)", func() {
			clientCert := issueClientCert("regular-node", caCert, caKey)
			req := httptest.NewRequest("DELETE", "/certificate_request/some-node", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		It("returns 403 for PUT /certificate_status/{subject} (admin-only tier)", func() {
			clientCert := issueClientCert("regular-node", caCert, caKey)
			body, _ := json.Marshal(api.PutStatusBody{DesiredState: "signed"})
			req := httptest.NewRequest("PUT", "/certificate_status/some-node", bytes.NewReader(body))
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		It("returns 403 for POST /sign (admin-only tier)", func() {
			clientCert := issueClientCert("regular-node", caCert, caKey)
			body, _ := json.Marshal(map[string][]string{"certnames": {"some-node"}})
			req := httptest.NewRequest("POST", "/sign", bytes.NewReader(body))
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})
	})

	// ── Non-self client on self-or-admin endpoints ─────────────────────────────

	Context("non-self client accessing another node's self-or-admin endpoint", func() {
		It("returns 403 for GET /certificate_status/{other-node}", func() {
			clientCert := issueClientCert("node-a", caCert, caKey)
			req := httptest.NewRequest("GET", "/certificate_status/node-b", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		It("returns 403 for GET /certificate_request/{other-node}", func() {
			clientCert := issueClientCert("node-a", caCert, caKey)
			req := httptest.NewRequest("GET", "/certificate_request/node-b", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})
	})

	// ── GET /certificate/{subject} is public ───────────────────────────────────
	// Signed certificates contain no secrets; Puppet Server 8 allows
	// unauthenticated access so that bootstrapping nodes can fetch their own
	// cert before they have a client cert to present.

	Context("GET /certificate/{subject} is public", func() {
		It("allows retrieval with no TLS connection state", func() {
			req := httptest.NewRequest("GET", "/certificate/some-node", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			// 404 because the cert doesn't exist, but not 403.
			Expect(rr.Code).NotTo(Equal(http.StatusForbidden))
		})

		It("allows retrieval over TLS with no peer cert", func() {
			req := httptest.NewRequest("GET", "/certificate/some-node", nil)
			req.TLS = &tls.ConnectionState{}
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).NotTo(Equal(http.StatusForbidden))
		})

		It("allows node-a to retrieve node-b's cert", func() {
			clientCert := issueClientCert("node-a", caCert, caKey)
			req := httptest.NewRequest("GET", "/certificate/node-b", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).NotTo(Equal(http.StatusForbidden))
		})
	})

	// ── Positive: CRL is public, accessible with or without a cert ───────────

	Context("CRL endpoint is public", func() {
		It("returns CRL without presenting any cert", func() {
			req := httptest.NewRequest("GET", "/certificate_revocation_list/ca", nil)
			// r.TLS is nil; the public tier check fires before the TLS check.
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})

		It("returns CRL over a TLS connection with no peer certificate", func() {
			req := httptest.NewRequest("GET", "/certificate_revocation_list/ca", nil)
			// Simulate a TLS connection where the client chose not to send a cert.
			req.TLS = &tls.ConnectionState{} // no PeerCertificates
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})

		It("returns CRL when a valid CA-signed cert is presented", func() {
			clientCert := issueClientCert("regular-node", caCert, caKey)
			req := httptest.NewRequest("GET", "/certificate_revocation_list/ca", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})

		It("returns CRL even when a revoked cert is presented", func() {
			// Revoked nodes must still be able to fetch the CRL — it is the
			// mechanism by which they (and others) learn they are revoked.
			// The public tier check must fire before the revocation check.
			csrPEM, err := testutil.GenerateCSR("revoked-crl-fetcher")
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.SaveRequest("revoked-crl-fetcher", csrPEM)
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.Sign("revoked-crl-fetcher")
			Expect(err).NotTo(HaveOccurred())
			Expect(myCA.Revoke("revoked-crl-fetcher")).To(Succeed())

			clientCert := issueClientCert("revoked-crl-fetcher", caCert, caKey)
			req := httptest.NewRequest("GET", "/certificate_revocation_list/ca", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})

		It("returns CRL even when a cert from an untrusted CA is presented", func() {
			// The public tier bypasses cert chain verification entirely.
			altKeyPEM, altCertPEM, _, err := testutil.GenerateTestCA()
			Expect(err).NotTo(HaveOccurred())
			altCACertBlock, _ := pem.Decode(altCertPEM)
			altCACert, err := x509.ParseCertificate(altCACertBlock.Bytes)
			Expect(err).NotTo(HaveOccurred())
			altKeyBlock, _ := pem.Decode(altKeyPEM)
			altCAKey, err := x509.ParsePKCS1PrivateKey(altKeyBlock.Bytes)
			Expect(err).NotTo(HaveOccurred())

			clientCert := issueClientCert("some-node", altCACert, altCAKey)
			req := httptest.NewRequest("GET", "/certificate_revocation_list/ca", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})
	})

	// ── Non-GET methods on the CRL path are NOT public ─────────────────────────

	Context("non-GET methods on /certificate_revocation_list/ca require auth", func() {
		It("returns 403 for POST /certificate_revocation_list/ca with no cert", func() {
			req := httptest.NewRequest("POST", "/certificate_revocation_list/ca", nil)
			req.TLS = &tls.ConnectionState{}
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		It("returns 403 for DELETE /certificate_revocation_list/ca with no cert", func() {
			req := httptest.NewRequest("DELETE", "/certificate_revocation_list/ca", nil)
			req.TLS = &tls.ConnectionState{}
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		It("returns 403 for POST /certificate_revocation_list/ca even with a valid non-admin cert", func() {
			clientCert := issueClientCert("regular-node", caCert, caKey)
			req := httptest.NewRequest("POST", "/certificate_revocation_list/ca", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})
	})

	// ── Prefixed paths honour the same tier rules ──────────────────────────────

	Context("prefixed paths (/puppet-ca/v1/) respect auth tiers", func() {
		It("returns 403 for non-admin on PUT /puppet-ca/v1/certificate_status/{subject}", func() {
			clientCert := issueClientCert("regular-node", caCert, caKey)
			body, _ := json.Marshal(api.PutStatusBody{DesiredState: "signed"})
			req := httptest.NewRequest("PUT", "/puppet-ca/v1/certificate_status/some-node", bytes.NewReader(body))
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		It("allows PUT /puppet-ca/v1/certificate_request/{subject} with no cert (public tier)", func() {
			csrPEM, err := testutil.GenerateCSR("pfx-public-node")
			Expect(err).NotTo(HaveOccurred())
			req := httptest.NewRequest("PUT", "/puppet-ca/v1/certificate_request/pfx-public-node", bytes.NewReader(csrPEM))
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})

		It("allows GET /puppet-ca/v1/certificate_revocation_list/ca with no cert (public tier)", func() {
			req := httptest.NewRequest("GET", "/puppet-ca/v1/certificate_revocation_list/ca", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})
	})

	// ── Positive: admin and self-cert pass ─────────────────────────────────────

	Context("admin cert passes admin-only endpoints", func() {
		It("POST /sign/all is not rejected (returns 200, not 403)", func() {
			clientCert := issueClientCert("puppet-server", caCert, caKey)
			req := httptest.NewRequest("POST", "/sign/all", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).NotTo(Equal(http.StatusForbidden))
		})

		It("GET /certificate_status for any subject is not rejected for admin", func() {
			clientCert := issueClientCert("puppet-server", caCert, caKey)
			req := httptest.NewRequest("GET", "/certificate_status/any-node", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			// 404 because the node does not exist, but not 403.
			Expect(rr.Code).NotTo(Equal(http.StatusForbidden))
		})
	})

	Context("self cert passes own subject on self-or-admin endpoints", func() {
		It("GET /certificate_status/{own-node} is not rejected", func() {
			clientCert := issueClientCert("my-node", caCert, caKey)
			req := httptest.NewRequest("GET", "/certificate_status/my-node", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			// 404 because the node does not exist, but not 403.
			Expect(rr.Code).NotTo(Equal(http.StatusForbidden))
		})
	})
})
