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
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tvaughan/puppet-ca/internal/ca"
)

// AuthConfig is the mTLS authorization configuration wired into the server.
// Nil means no mTLS enforcement (plain HTTP / dev mode).
type AuthConfig struct {
	CACert    *x509.Certificate
	AllowList map[string]bool // admin CNs (puppet-server hostnames)
}

type Server struct {
	CA         *ca.CA
	AuthConfig *AuthConfig
}

func New(c *ca.CA) *Server {
	return &Server{CA: c}
}

// Routes registers all handlers and returns the handler (with auth middleware if configured).
// Puppet agents use the /puppet-ca/v1/ prefix; we support both bare and prefixed paths
// so the Go CA can be used directly or behind a stripping proxy.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	routes := []struct {
		method, path string
		handler      http.HandlerFunc
	}{
		{"GET", "/certificate_status/{subject}", s.handleGetStatus},
		{"PUT", "/certificate_status/{subject}", s.handlePutStatus},
		{"DELETE", "/certificate_status/{subject}", s.handleDeleteStatus},
		{"GET", "/certificate_statuses/{ignored}", s.handleGetStatuses},
		{"GET", "/certificate_request/{subject}", s.handleGetRequest},
		{"PUT", "/certificate_request/{subject}", s.handlePutRequest},
		{"DELETE", "/certificate_request/{subject}", s.handleDeleteRequest},
		{"GET", "/certificate/{subject}", s.handleGetCert},
		{"GET", "/certificate_revocation_list/ca", s.handleGetCRL},
		{"POST", "/ocsp", s.handleOCSP},
		{"GET", "/ocsp/{request}", s.handleOCSP},
		{"GET", "/expirations", s.handleGetExpirations},
		{"POST", "/sign", s.handlePostSign},
		{"POST", "/sign/all", s.handlePostSignAll},
		{"POST", "/generate/{subject}", s.handlePostGenerate},
	}

	prefixes := []string{"", "/puppet-ca/v1"}
	for _, r := range routes {
		for _, pfx := range prefixes {
			mux.HandleFunc(r.method+" "+pfx+r.path, r.handler)
		}
	}

	// Health check endpoints are registered only at bare paths (no /puppet-ca/v1
	// prefix) since they are infrastructure probes, not Puppet CA protocol paths.
	mux.HandleFunc("GET /healthz/live", s.handleLive)
	mux.HandleFunc("GET /healthz/ready", s.handleReady)
	mux.HandleFunc("GET /healthz/startup", s.handleStartup)

	return newAuthMiddleware(s.AuthConfig, s.CA, mux)
}

// --- Status ---

type CertStatusResponse struct {
	Name            string            `json:"name"`
	State           string            `json:"state"`
	Fingerprint     string            `json:"fingerprint"`
	Fingerprints    map[string]string `json:"fingerprints"`
	DNSAltNames     []string          `json:"dns_alt_names"`
	SubjectAltNames []string          `json:"subject_alt_names"`
	// AuthorizationExtensions contains Puppet auth-arc OID values keyed by short
	// name (e.g. "pp_auth_role") or raw OID string when no short name is known.
	// Always present, empty map when none exist.
	AuthorizationExtensions map[string]string `json:"authorization_extensions"`
	// Populated when signed or revoked.
	SerialNumber *int64  `json:"serial_number,omitempty"`
	NotBefore    *string `json:"not_before,omitempty"`
	NotAfter     *string `json:"not_after,omitempty"`
}

func (s *Server) handleGetStatus(w http.ResponseWriter, r *http.Request) {
	subject := r.PathValue("subject")
	if err := ca.ValidateSubject(subject); err != nil {
		http.Error(w, "invalid subject", http.StatusBadRequest)
		return
	}
	slog.Debug("GET certificate_status", "subject", subject)

	// Check signed dir first.
	certPEM, err := s.CA.Storage.GetCert(subject)
	if err == nil {
		state := "signed"
		if s.CA.IsRevoked(subject) {
			state = "revoked"
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(certStatusFromCert(subject, certPEM, state))
		return
	}

	// Check CSR (requested).
	csrPEM, err := s.CA.Storage.GetCSR(subject)
	if err == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(certStatusFromCSR(subject, csrPEM))
		return
	}

	http.Error(w, "not found", http.StatusNotFound)
}

type PutStatusBody struct {
	DesiredState string `json:"desired_state"`
	CertTTL      *int   `json:"cert_ttl,omitempty"` // seconds; 0/absent → default validity
}

func (s *Server) handlePutStatus(w http.ResponseWriter, r *http.Request) {
	subject := r.PathValue("subject")
	if err := ca.ValidateSubject(subject); err != nil {
		http.Error(w, "invalid subject", http.StatusBadRequest)
		return
	}
	slog.Debug("PUT certificate_status", "subject", subject)

	var body PutStatusBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	switch body.DesiredState {
	case "signed":
		var err error
		if body.CertTTL != nil && *body.CertTTL > 0 {
			_, err = s.CA.SignWithTTL(subject, time.Duration(*body.CertTTL)*time.Second)
		} else {
			_, err = s.CA.Sign(subject)
		}
		if err != nil {
			slog.Warn("Sign failed", "subject", subject, "error", err)
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	case "revoked":
		if err := s.CA.Revoke(subject); err != nil {
			slog.Warn("Revoke failed", "subject", subject, "error", err)
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "desired_state must be 'signed' or 'revoked'", http.StatusBadRequest)
	}
}

// --- Certificate ---

func (s *Server) handleGetCert(w http.ResponseWriter, r *http.Request) {
	subject := r.PathValue("subject")
	slog.Debug("GET certificate", "subject", subject)

	// Special case: "ca" returns the CA cert.
	if subject == "ca" {
		certPEM, err := os.ReadFile(s.CA.Storage.CACertPath())
		if err != nil {
			http.Error(w, "CA cert not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write(certPEM)
		return
	}

	if err := ca.ValidateSubject(subject); err != nil {
		http.Error(w, "invalid subject", http.StatusBadRequest)
		return
	}

	certPEM, err := s.CA.Storage.GetCert(subject)
	if err != nil {
		http.Error(w, "certificate not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write(certPEM)
}

// --- CRL ---

func (s *Server) handleGetCRL(w http.ResponseWriter, r *http.Request) {
	slog.Debug("GET certificate_revocation_list/ca")

	crlPath := s.CA.Storage.CRLPath()

	// Honor If-Modified-Since.
	if ims := r.Header.Get("If-Modified-Since"); ims != "" {
		if t, err := http.ParseTime(ims); err == nil {
			if info, err := os.Stat(crlPath); err == nil {
				if !info.ModTime().After(t) {
					w.WriteHeader(http.StatusNotModified)
					return
				}
			}
		}
	}

	crlPEM, err := s.CA.Storage.GetCRL()
	if err != nil {
		http.Error(w, "CRL not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write(crlPEM)
}

// --- CSR ---

func (s *Server) handleGetRequest(w http.ResponseWriter, r *http.Request) {
	subject := r.PathValue("subject")
	if err := ca.ValidateSubject(subject); err != nil {
		http.Error(w, "invalid subject", http.StatusBadRequest)
		return
	}
	slog.Debug("GET certificate_request", "subject", subject)

	csrPEM, err := s.CA.Storage.GetCSR(subject)
	if err != nil {
		http.Error(w, "CSR not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write(csrPEM)
}

func (s *Server) handlePutRequest(w http.ResponseWriter, r *http.Request) {
	subject := r.PathValue("subject")
	if err := ca.ValidateSubject(subject); err != nil {
		http.Error(w, "invalid subject", http.StatusBadRequest)
		return
	}
	slog.Debug("PUT certificate_request", "subject", subject)

	csrPEM, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "failed to read body: "+err.Error(), http.StatusInternalServerError)
		return
	}

	signed, err := s.CA.SaveRequest(subject, csrPEM)
	if err != nil {
		slog.Warn("SaveRequest failed", "subject", subject, "error", err)
		if errors.Is(err, ca.ErrCertExists) {
			http.Error(w, err.Error(), http.StatusConflict)
		} else {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		return
	}

	// Puppet CA always returns 200 for PUT /certificate_request, regardless of
	// whether the CSR was autosigned immediately or queued for manual signing.
	_ = signed
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDeleteRequest(w http.ResponseWriter, r *http.Request) {
	subject := r.PathValue("subject")
	if err := ca.ValidateSubject(subject); err != nil {
		http.Error(w, "invalid subject", http.StatusBadRequest)
		return
	}
	slog.Debug("DELETE certificate_request", "subject", subject)

	if err := s.CA.Storage.DeleteCSR(subject); err != nil {
		http.Error(w, "CSR not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Server-side cert generation ---

type generateResponse struct {
	PrivateKey  string `json:"private_key"`
	Certificate string `json:"certificate"`
}

func (s *Server) handlePostGenerate(w http.ResponseWriter, r *http.Request) {
	subject := r.PathValue("subject")
	if err := ca.ValidateSubject(subject); err != nil {
		http.Error(w, "invalid subject: "+err.Error(), http.StatusBadRequest)
		return
	}
	slog.Debug("POST generate", "subject", subject)

	// Optional DNS alt names from query params (?dns=a&dns=b).
	dnsAltNames := r.URL.Query()["dns"]

	result, err := s.CA.Generate(subject, dnsAltNames)
	if err != nil {
		if errors.Is(err, ca.ErrCertExists) {
			http.Error(w, err.Error(), http.StatusConflict)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(generateResponse{
		PrivateKey:  string(result.PrivateKeyPEM),
		Certificate: string(result.CertificatePEM),
	})
}

// --- Helpers ---

func parseCert(pemData []byte) *x509.Certificate {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return &x509.Certificate{}
	}
	c, _ := x509.ParseCertificate(block.Bytes)
	if c == nil {
		return &x509.Certificate{}
	}
	return c
}

func parseCSR(pemData []byte) *x509.CertificateRequest {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return &x509.CertificateRequest{}
	}
	c, _ := x509.ParseCertificateRequest(block.Bytes)
	if c == nil {
		return &x509.CertificateRequest{}
	}
	return c
}

// authExtensions extracts Puppet authorization extensions (OID arc 1.3.6.1.4.1.34380.1.3)
// from a certificate or CSR extension list and returns them as a name→value map.
// The key is the Puppet short name when known (e.g. "pp_auth_role"), otherwise
// the raw dotted OID string. The value is the decoded UTF-8 string.
// Always returns a non-nil map (empty when no auth extensions are present).
func authExtensions(exts []pkix.Extension) map[string]string {
	result := make(map[string]string)
	for _, ext := range exts {
		if !ca.IsAuthOID(ext.Id) {
			continue
		}
		key := ca.OIDKey(ext.Id)
		var s string
		if _, err := asn1.Unmarshal(ext.Value, &s); err == nil {
			result[key] = s
		} else {
			result[key] = hex.EncodeToString(ext.Value)
		}
	}
	return result
}

func fingerprint(data []byte) string {
	block, _ := pem.Decode(data)
	if block == nil {
		return ""
	}
	sum := sha256.Sum256(block.Bytes)
	// Puppet formats fingerprints as colon-separated hex pairs.
	raw := hex.EncodeToString(sum[:])
	var parts []string
	for i := 0; i < len(raw); i += 2 {
		parts = append(parts, raw[i:i+2])
	}
	return "SHA256:" + strings.Join(parts, ":")
}

// noNilSlice returns s unchanged when non-nil, or an empty non-nil slice.
// This ensures dns_alt_names serialises as [] rather than null in JSON.
func noNilSlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// certStatusFromCert builds a CertStatusResponse from a signed or revoked certificate.
func certStatusFromCert(subject string, certPEM []byte, state string) CertStatusResponse {
	cert := parseCert(certPEM)
	fp := fingerprint(certPEM)
	serial := cert.SerialNumber.Int64()
	nb := cert.NotBefore.UTC().Format(time.RFC3339)
	na := cert.NotAfter.UTC().Format(time.RFC3339)
	dnsNames := noNilSlice(cert.DNSNames)
	return CertStatusResponse{
		Name:                    subject,
		State:                   state,
		Fingerprint:             fp,
		Fingerprints:            map[string]string{"SHA256": fp, "default": fp},
		DNSAltNames:             dnsNames,
		SubjectAltNames:         dnsNames,
		AuthorizationExtensions: authExtensions(cert.Extensions),
		SerialNumber:            &serial,
		NotBefore:               &nb,
		NotAfter:                &na,
	}
}

// certStatusFromCSR builds a CertStatusResponse for a pending (requested) CSR.
func certStatusFromCSR(subject string, csrPEM []byte) CertStatusResponse {
	csr := parseCSR(csrPEM)
	fp := fingerprint(csrPEM)
	dnsNames := noNilSlice(csr.DNSNames)
	return CertStatusResponse{
		Name:                    subject,
		State:                   "requested",
		Fingerprint:             fp,
		Fingerprints:            map[string]string{"SHA256": fp, "default": fp},
		DNSAltNames:             dnsNames,
		SubjectAltNames:         dnsNames,
		AuthorizationExtensions: authExtensions(csr.Extensions),
	}
}

// --- Delete status (puppet cert clean) ---

func (s *Server) handleDeleteStatus(w http.ResponseWriter, r *http.Request) {
	subject := r.PathValue("subject")
	if err := ca.ValidateSubject(subject); err != nil {
		http.Error(w, "invalid subject", http.StatusBadRequest)
		return
	}
	slog.Debug("DELETE certificate_status", "subject", subject)

	if err := s.CA.Clean(subject); err != nil {
		slog.Warn("Clean failed", "subject", subject, "error", err)
		if errors.Is(err, ca.ErrNotFound) {
			http.Error(w, err.Error(), http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusConflict)
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Certificate statuses (list all) ---

func (s *Server) handleGetStatuses(w http.ResponseWriter, r *http.Request) {
	slog.Debug("GET certificate_statuses")

	stateFilter := r.URL.Query().Get("state") // "requested", "signed", "revoked", or ""

	certs, err := s.CA.Storage.ListCerts()
	if err != nil {
		http.Error(w, "failed to list certs: "+err.Error(), http.StatusInternalServerError)
		return
	}
	csrs, err := s.CA.Storage.ListCSRs()
	if err != nil {
		http.Error(w, "failed to list CSRs: "+err.Error(), http.StatusInternalServerError)
		return
	}

	statuses := make([]CertStatusResponse, 0, len(certs)+len(csrs))

	seen := make(map[string]bool)
	for _, subject := range certs {
		seen[subject] = true
		certPEM, err := s.CA.Storage.GetCert(subject)
		if err != nil {
			continue
		}
		state := "signed"
		if s.CA.IsRevoked(subject) {
			state = "revoked"
		}
		if stateFilter != "" && state != stateFilter {
			continue
		}
		statuses = append(statuses, certStatusFromCert(subject, certPEM, state))
	}
	for _, subject := range csrs {
		if seen[subject] {
			continue
		}
		if stateFilter != "" && stateFilter != "requested" {
			continue
		}
		csrPEM, err := s.CA.Storage.GetCSR(subject)
		if err != nil {
			continue
		}
		statuses = append(statuses, certStatusFromCSR(subject, csrPEM))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(statuses)
}

// --- Expirations ---

type ExpirationsResponse struct {
	CACrl         CRLExpiration  `json:"ca_crl"`
	CACertificate CertExpiration `json:"ca_certificate"`
}

type CRLExpiration struct {
	NextUpdate string `json:"next_update"`
}

type CertExpiration struct {
	Expiration string `json:"expiration"`
}

func (s *Server) handleGetExpirations(w http.ResponseWriter, r *http.Request) {
	slog.Debug("GET expirations")

	certExp := s.CA.CACert.NotAfter.UTC().Format(time.RFC3339)

	crlNextUpdate := ""
	if crlPEM, err := s.CA.Storage.GetCRL(); err == nil {
		if block, _ := pem.Decode(crlPEM); block != nil {
			if crl, err := x509.ParseRevocationList(block.Bytes); err == nil {
				crlNextUpdate = crl.NextUpdate.UTC().Format(time.RFC3339)
			}
		}
	}

	resp := ExpirationsResponse{
		CACrl:         CRLExpiration{NextUpdate: crlNextUpdate},
		CACertificate: CertExpiration{Expiration: certExp},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// --- Bulk sign ---

type SignRequestBody struct {
	Certnames []string `json:"certnames"`
}

func (s *Server) handlePostSign(w http.ResponseWriter, r *http.Request) {
	slog.Debug("POST sign")

	var body SignRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(body.Certnames) == 0 {
		http.Error(w, "certnames must not be empty", http.StatusBadRequest)
		return
	}

	result := s.CA.SignMultiple(body.Certnames)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *Server) handlePostSignAll(w http.ResponseWriter, r *http.Request) {
	slog.Debug("POST sign/all")

	result, err := s.CA.SignAll()
	if err != nil {
		http.Error(w, "failed to sign all: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
