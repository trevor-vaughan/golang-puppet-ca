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

package api

import (
	"crypto/x509"
	"log/slog"
	"net/http"
	"strings"

	"github.com/tvaughan/puppet-ca/internal/ca"
)

type authTier int

const (
	tierPublic      authTier = iota // no client cert required
	tierAnyClient                   // any cert signed by this CA
	tierSelfOrAdmin                 // own cert or an admin CN
	tierAdminOnly                   // admin CN only
)

// newAuthMiddleware returns an http.Handler that wraps next with mTLS authorization.
// If cfg is nil (no TLS configured) all requests pass through unconditionally,
// preserving plain HTTP / dev-mode compatibility.
func newAuthMiddleware(cfg *AuthConfig, myCA *ca.CA, next http.Handler) http.Handler {
	if cfg == nil {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tier := lookupTier(r.Method, r.URL.Path)

		// Public endpoints need no cert.
		if tier == tierPublic {
			next.ServeHTTP(w, r)
			return
		}

		// Non-TLS connections (shouldn't happen when TLS is configured, but be safe).
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "client certificate required", http.StatusForbidden)
			return
		}

		clientCert := r.TLS.PeerCertificates[0]

		// Verify the client cert was signed by our CA.
		pool := x509.NewCertPool()
		pool.AddCert(cfg.CACert)
		if _, err := clientCert.Verify(x509.VerifyOptions{
			Roots:     pool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}); err != nil {
			slog.Debug("Auth: client cert verification failed",
				"cn", clientCert.Subject.CommonName, "error", err)
			http.Error(w, "access denied", http.StatusForbidden)
			return
		}

		clientCN := clientCert.Subject.CommonName

		// Check whether the client cert has been revoked.
		if myCA.IsRevoked(clientCN) {
			slog.Debug("Auth: client cert is revoked", "cn", clientCN)
			http.Error(w, "access denied", http.StatusForbidden)
			return
		}

		switch tier {
		case tierAnyClient:
			next.ServeHTTP(w, r)

		case tierSelfOrAdmin:
			subject := extractPathSubject(r.URL.Path)
			if cfg.AllowList[clientCN] || (subject != "" && clientCN == subject) {
				next.ServeHTTP(w, r)
			} else {
				http.Error(w, "access denied", http.StatusForbidden)
			}

		case tierAdminOnly:
			if cfg.AllowList[clientCN] {
				next.ServeHTTP(w, r)
			} else {
				http.Error(w, "access denied", http.StatusForbidden)
			}

		default:
			http.Error(w, "access denied", http.StatusForbidden)
		}
	})
}

// lookupTier classifies a request into an authorization tier based on method and path.
func lookupTier(method, path string) authTier {
	// Strip the /puppet-ca/v1 prefix if present for uniform matching.
	p := strings.TrimPrefix(path, "/puppet-ca/v1")

	switch {
	// Public — no cert needed.
	// Signed certs contain no secrets; bootstrapping nodes fetch their cert
	// before they have a client cert, matching Puppet Server 8 behaviour.
	case method == "GET" && strings.HasPrefix(p, "/certificate/"):
		return tierPublic
	case method == "GET" && strings.HasPrefix(p, "/certificate_revocation_list/"):
		return tierPublic
	case method == "PUT" && strings.HasPrefix(p, "/certificate_request/"):
		return tierPublic

	// Self or admin.
	case method == "GET" && strings.HasPrefix(p, "/certificate_status/"):
		return tierSelfOrAdmin
	case method == "GET" && strings.HasPrefix(p, "/certificate_request/"):
		return tierSelfOrAdmin

	// Admin only — all other operations.
	default:
		return tierAdminOnly
	}
}

// extractPathSubject returns the {subject} segment from certificate/status/request paths.
func extractPathSubject(path string) string {
	path = strings.TrimPrefix(path, "/puppet-ca/v1")
	for _, prefix := range []string{
		"/certificate/",
		"/certificate_status/",
		"/certificate_request/",
	} {
		if strings.HasPrefix(path, prefix) {
			return strings.TrimPrefix(path, prefix)
		}
	}
	return ""
}
