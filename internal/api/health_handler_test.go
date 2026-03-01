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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/tvaughan/puppet-ca/internal/api"
	"github.com/tvaughan/puppet-ca/internal/ca"
	"github.com/tvaughan/puppet-ca/internal/storage"
)

var _ = Describe("Health Endpoints", func() {
	var (
		tmpDir string
		mux    http.Handler
	)

	newMux := func(initialized bool) http.Handler {
		store := storage.New(tmpDir)
		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")

		if initialized {
			Expect(store.EnsureDirs()).To(Succeed())
			Expect(os.WriteFile(store.CAKeyPath(), cachedKeyPEM, 0640)).To(Succeed())
			Expect(os.WriteFile(store.CACertPath(), cachedCrtPEM, 0644)).To(Succeed())
			Expect(store.UpdateCRL(cachedCrlPEM)).To(Succeed())
			Expect(store.WriteSerial("0001")).To(Succeed())
			Expect(os.WriteFile(store.InventoryPath(), []byte{}, 0644)).To(Succeed())
			Expect(myCA.Init()).To(Succeed())
		}

		srv := api.New(myCA)
		return srv.Routes()
	}

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-health-test")
		Expect(err).NotTo(HaveOccurred())
		mux = newMux(true)
	})

	AfterEach(func() { os.RemoveAll(tmpDir) })

	// newAuthedMux wires AuthConfig onto the mux so the auth middleware is active.
	// Used to confirm health endpoints are tierPublic even under mTLS enforcement.
	newAuthedMux := func() http.Handler {
		store := storage.New(tmpDir)
		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(store.EnsureDirs()).To(Succeed())
		Expect(os.WriteFile(store.CAKeyPath(), cachedKeyPEM, 0640)).To(Succeed())
		Expect(os.WriteFile(store.CACertPath(), cachedCrtPEM, 0644)).To(Succeed())
		Expect(store.UpdateCRL(cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial("0001")).To(Succeed())
		Expect(os.WriteFile(store.InventoryPath(), []byte{}, 0644)).To(Succeed())
		Expect(myCA.Init()).To(Succeed())
		srv := api.New(myCA)
		srv.AuthConfig = &api.AuthConfig{
			CACert:    myCA.CACert,
			AllowList: map[string]bool{"puppet-server": true},
		}
		return srv.Routes()
	}

	// ── Liveness ──────────────────────────────────────────────────────────────

	Describe("GET /healthz/live", func() {
		It("returns 200 and status ok", func() {
			req := httptest.NewRequest("GET", "/healthz/live", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))

			var resp map[string]string
			Expect(json.Unmarshal(rr.Body.Bytes(), &resp)).To(Succeed())
			Expect(resp["status"]).To(Equal("ok"))
		})

		It("sets Content-Type: application/json", func() {
			req := httptest.NewRequest("GET", "/healthz/live", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Header().Get("Content-Type")).To(ContainSubstring("application/json"))
		})

		It("returns 200 even when CA is not initialized", func() {
			uninitMux := newMux(false)
			req := httptest.NewRequest("GET", "/healthz/live", nil)
			rr := httptest.NewRecorder()
			uninitMux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})

		It("is accessible without a client cert (public tier)", func() {
			req := httptest.NewRequest("GET", "/healthz/live", nil)
			// r.TLS is nil — auth middleware must not block public tier.
			rr := httptest.NewRecorder()
			newAuthedMux().ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})

		DescribeTable("rejects non-GET methods with 405",
			func(method string) {
				req := httptest.NewRequest(method, "/healthz/live", nil)
				rr := httptest.NewRecorder()
				mux.ServeHTTP(rr, req)
				Expect(rr.Code).To(Equal(http.StatusMethodNotAllowed))
			},
			Entry("POST", "POST"),
			Entry("PUT", "PUT"),
			Entry("DELETE", "DELETE"),
			Entry("PATCH", "PATCH"),
		)
	})

	// ── Readiness ─────────────────────────────────────────────────────────────

	Describe("GET /healthz/ready", func() {
		It("returns 200 when CA is initialized", func() {
			req := httptest.NewRequest("GET", "/healthz/ready", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))

			var resp map[string]string
			Expect(json.Unmarshal(rr.Body.Bytes(), &resp)).To(Succeed())
			Expect(resp["status"]).To(Equal("ok"))
		})

		It("sets Content-Type: application/json", func() {
			req := httptest.NewRequest("GET", "/healthz/ready", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Header().Get("Content-Type")).To(ContainSubstring("application/json"))
		})

		It("returns 503 when CA is not initialized", func() {
			uninitMux := newMux(false)
			req := httptest.NewRequest("GET", "/healthz/ready", nil)
			rr := httptest.NewRecorder()
			uninitMux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusServiceUnavailable))

			var resp map[string]string
			Expect(json.Unmarshal(rr.Body.Bytes(), &resp)).To(Succeed())
			Expect(resp["status"]).To(Equal("not_ready"))
		})

		It("sets Content-Type: application/json even on 503", func() {
			uninitMux := newMux(false)
			req := httptest.NewRequest("GET", "/healthz/ready", nil)
			rr := httptest.NewRecorder()
			uninitMux.ServeHTTP(rr, req)
			Expect(rr.Header().Get("Content-Type")).To(ContainSubstring("application/json"))
		})

		It("is accessible without a client cert (public tier)", func() {
			req := httptest.NewRequest("GET", "/healthz/ready", nil)
			rr := httptest.NewRecorder()
			newAuthedMux().ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})

		DescribeTable("rejects non-GET methods with 405",
			func(method string) {
				req := httptest.NewRequest(method, "/healthz/ready", nil)
				rr := httptest.NewRecorder()
				mux.ServeHTTP(rr, req)
				Expect(rr.Code).To(Equal(http.StatusMethodNotAllowed))
			},
			Entry("POST", "POST"),
			Entry("PUT", "PUT"),
			Entry("DELETE", "DELETE"),
			Entry("PATCH", "PATCH"),
		)
	})

	// ── Startup ───────────────────────────────────────────────────────────────

	Describe("GET /healthz/startup", func() {
		It("returns 200 when CA is initialized", func() {
			req := httptest.NewRequest("GET", "/healthz/startup", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))

			var resp map[string]string
			Expect(json.Unmarshal(rr.Body.Bytes(), &resp)).To(Succeed())
			Expect(resp["status"]).To(Equal("ok"))
		})

		It("sets Content-Type: application/json", func() {
			req := httptest.NewRequest("GET", "/healthz/startup", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Header().Get("Content-Type")).To(ContainSubstring("application/json"))
		})

		It("returns 503 when CA is not initialized", func() {
			uninitMux := newMux(false)
			req := httptest.NewRequest("GET", "/healthz/startup", nil)
			rr := httptest.NewRecorder()
			uninitMux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusServiceUnavailable))
		})

		It("is accessible without a client cert (public tier)", func() {
			req := httptest.NewRequest("GET", "/healthz/startup", nil)
			rr := httptest.NewRecorder()
			newAuthedMux().ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})

		DescribeTable("rejects non-GET methods with 405",
			func(method string) {
				req := httptest.NewRequest(method, "/healthz/startup", nil)
				rr := httptest.NewRecorder()
				mux.ServeHTTP(rr, req)
				Expect(rr.Code).To(Equal(http.StatusMethodNotAllowed))
			},
			Entry("POST", "POST"),
			Entry("PUT", "PUT"),
			Entry("DELETE", "DELETE"),
			Entry("PATCH", "PATCH"),
		)
	})
})
