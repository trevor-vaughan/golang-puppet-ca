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
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	xocsp "golang.org/x/crypto/ocsp"

	"github.com/tvaughan/puppet-ca/internal/ca"
)

// handleOCSP serves RFC 6960 OCSP requests on both the POST and GET endpoints:
//
//	POST /ocsp                 — DER-encoded OCSPRequest in the body
//	GET  /ocsp/{request}       — base64-encoded (standard or URL-safe) DER in path
//
// Both paths are also registered under the /puppet-ca/v1 prefix via Routes().
func (s *Server) handleOCSP(w http.ResponseWriter, r *http.Request) {
	var (
		reqDER []byte
		err    error
	)

	switch r.Method {
	case http.MethodGet:
		encoded := r.PathValue("request")
		reqDER, err = base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			// RFC 6960 §A.1: GET path uses URL-safe base64 without padding.
			// Try RawURLEncoding (no padding, URL-safe alphabet) as the conformant fallback.
			reqDER, err = base64.RawURLEncoding.DecodeString(encoded)
			if err != nil {
				http.Error(w, "invalid base64 in OCSP GET request path", http.StatusBadRequest)
				return
			}
		}

	case http.MethodPost:
		reqDER, err = io.ReadAll(io.LimitReader(r.Body, 1<<16))
		if err != nil {
			http.Error(w, "failed to read OCSP request body: "+err.Error(), http.StatusInternalServerError)
			return
		}

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	respDER, err := s.CA.OCSPResponse(reqDER)
	if err != nil {
		w.Header().Set("Content-Type", "application/ocsp-response")
		if errors.Is(err, ca.ErrInternal) {
			slog.Error("OCSP internal error", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(xocsp.InternalErrorErrorResponse) //nolint:errcheck
		} else {
			slog.Warn("OCSP request error", "error", err)
			w.WriteHeader(http.StatusBadRequest)
			w.Write(xocsp.MalformedRequestErrorResponse) //nolint:errcheck
		}
		return
	}

	w.Header().Set("Content-Type", "application/ocsp-response")
	if r.Method == http.MethodGet {
		maxAge := int(ca.OCSPValidity.Seconds())
		w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d, public", maxAge))
	}
	w.Write(respDER) //nolint:errcheck
}
