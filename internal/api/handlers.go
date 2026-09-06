// Copyright (C) 2026 Trevor Vaughan
// Copyright (C) 2026 Chris Boot
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

package api

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// maxJSONBody caps the size of JSON request bodies accepted by the POST/PUT
// handlers, matching the 1 MiB limit already applied to CSR submissions. It
// prevents an authenticated client from streaming an unbounded body (e.g. a
// huge certnames array) and exhausting server memory.
const maxJSONBody = 1 << 20 // 1 MiB

// AuthConfig is the mTLS authorization configuration wired into the server.
// Nil means no mTLS enforcement (plain HTTP / dev mode).
//
// AuthConfig must be used through a pointer, though no longer for the reason
// this comment used to give: it carried a lock, and does not any more. What
// requires it now is that each TrustDomain holds a *clientCRLs whose contents
// the reload job swaps while requests read them -- so a copy of the config is
// not a copy of the trust state, and two copies would diverge silently, one
// enforcing revocations the other had already replaced.
type AuthConfig struct {
	// Domains are the trust domains a client certificate may be attributed to,
	// in the order they are tried. Domain zero is always this CA's own; see
	// TrustDomain and attribute for why the order is part of the contract.
	//
	// This replaced a single CACert field. The rename is deliberate: the
	// meaning genuinely changed from "the certificate every client must chain
	// to" to "one of several issuers, each with its own authority", and a
	// silent semantic change on a field named CACert is exactly the kind of
	// thing that survives review.
	Domains []TrustDomain

	AllowPublicStatus bool // when true, GET /certificate_status is public (no client cert required)

	// ClientRevocationPolicy governs revocation checking for foreign domains.
	// Empty means require. Our own domain always checks its own CRL and is
	// unaffected by this setting.
	ClientRevocationPolicy string

	// OnRevocationRefusal, when set, is called with the domain name each time a
	// foreign client is refused for want of a usable CRL.
	//
	// A callback rather than a counter because this package holds no metrics
	// dependency. It exists because load-time coverage cannot tell which anchors
	// matter -- that depends on chains not yet presented -- so the only
	// unambiguous statement that clients are being turned away is made here,
	// when one is.
	OnRevocationRefusal func(domain string)
}

// revocationPolicy resolves the policy for foreign domains.
//
// config.ClientCAConfig.Policy() applies the same default, and main.go passes
// its result in, so in production this arm is not reached. It stays because
// AuthConfig is constructible without going through that path -- every spec in
// this package does exactly that -- and the fail-closed default has to be a
// property of the thing making the decision, not of one of its callers.
func (c *AuthConfig) revocationPolicy() string {
	if c.ClientRevocationPolicy == "" {
		return RevocationRequire
	}
	return c.ClientRevocationPolicy
}

// NewAuthConfig returns an AuthConfig that trusts exactly this CA, with allowList
// as domain zero's administrators and pp_cli_auth honoured.
//
// The single-issuer shape, so that "trust this CA" stays one call rather than a
// domain list an author has to assemble correctly.
//
// No production caller: the server builds its domains through
// buildTrustDomains, which handles the client_ca entries this cannot express.
// What this is for is the tests and any future embedder that wants the default
// trust set without assembling one -- keeping it means the single-issuer shape
// stays expressible in one call, which is the shape most of the suite needs.
func NewAuthConfig(caCert *x509.Certificate, allowList map[string]bool) *AuthConfig {
	return &AuthConfig{
		Domains: []TrustDomain{OwnTrustDomain(caCert, allowList, true)},
	}
}

// IsOwnAdminCN reports whether cn is an administrator in domain zero. It is the
// read half of SetOwnAdminCNs, and takes the same lock: a reload may be
// replacing the set as this runs.
func (c *AuthConfig) IsOwnAdminCN(cn string) bool {
	for i := range c.Domains {
		if c.Domains[i].IsOwn() {
			return c.Domains[i].IsAdminCN(cn)
		}
	}
	return false
}

// SetOwnAdminCNs replaces domain zero's admin CNs and returns the previous set.
// It is what `systemctl reload` calls to add or withdraw a compile server's
// admin rights without dropping connections.
//
// Domain zero only. A client_ca entry's admin_cns are read once at startup:
// changing them means changing a file this process does not re-read, and
// re-reading it would mean re-parsing that issuer's anchors too, which is a
// larger promise than reload makes today. docs/configuration.md says so.
func (c *AuthConfig) SetOwnAdminCNs(cns map[string]bool) map[string]bool {
	for i := range c.Domains {
		if c.Domains[i].IsOwn() {
			return c.Domains[i].SetAdminCNs(cns)
		}
	}
	return nil
}

type Server struct {
	CA         *ca.CA
	AuthConfig *AuthConfig
	// CSRRateLimit is the maximum number of CSR submissions allowed per IP
	// address per minute on the unauthenticated PUT /certificate_request
	// endpoint. Zero (the default) disables rate limiting.
	CSRRateLimit int
	// PlainHTTP is set when the server is running without TLS.
	// The /generate endpoint refuses to serve private keys when this is true.
	PlainHTTP bool
	// SignBatchLimit is the maximum number of certificates that can be signed
	// in a single POST /sign or POST /sign/all request. Zero disables the limit.
	SignBatchLimit int
	// PuppetDateTimeFormat when true formats date/time fields using the original
	// Puppet CA style ("2006-01-02T15:04:05MST") instead of RFC 3339. Useful
	// when integrating with tooling that expects exact Puppet Server output.
	PuppetDateTimeFormat bool

	csrLimiter     *ipRateLimiter
	destructiveOps *destructiveOpTracker
}

func New(c *ca.CA) *Server {
	return &Server{
		CA:             c,
		destructiveOps: newDestructiveOpTracker(5, time.Minute),
	}
}

// Routes registers all handlers and returns the handler (with auth middleware if configured).
// Puppet agents use the /puppet-ca/v1/ prefix; we support both bare and prefixed paths
// so the Go CA can be used directly or behind a stripping proxy.
func (s *Server) Routes() http.Handler {
	if s.CSRRateLimit > 0 {
		s.csrLimiter = newIPRateLimiter(s.CSRRateLimit, time.Minute)
	}

	mux := http.NewServeMux()

	routes := []struct {
		method, path string
		handler      http.HandlerFunc
	}{
		{"GET", "/certificate_status/{subject}", s.handleGetStatus},
		{"PUT", "/certificate_status/{subject}", s.handlePutStatus},
		{"DELETE", "/certificate_status/{subject}", s.handleDeleteStatus},
		{"PUT", "/certificate_status_by_serial/{serial}", s.handlePutStatusBySerial},
		{"GET", "/certificate_statuses/{ignored}", s.handleGetStatuses},
		{"GET", "/certificate_request/{subject}", s.handleGetRequest},
		{"PUT", "/certificate_request/{subject}", s.handlePutRequest},
		{"DELETE", "/certificate_request/{subject}", s.handleDeleteRequest},
		{"GET", "/certificate/{subject}", s.handleGetCert},
		{"PUT", "/certificate/{subject}", s.handlePutCert},
		{"GET", "/certificate_revocation_list/ca", s.handleGetCRL},
		{"PUT", "/certificate_revocation_list/ca", s.handleReissueCRL},
		{"POST", "/ocsp", s.handleOCSP},
		{"GET", "/ocsp/{request}", s.handleOCSP},
		{"GET", "/expirations", s.handleGetExpirations},
		{"POST", "/sign", s.handlePostSign},
		{"POST", "/sign/all", s.handlePostSignAll},
		{"PUT", "/clean", s.handlePutClean},
		{"POST", "/generate/{subject}", s.handlePostGenerate},
		{"POST", "/certificate_renewal", s.handlePostCertificateRenewal},
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
	// SerialNumber is a decimal string to preserve the full 128-bit value
	// without loss; int64 would silently truncate random CA/B-Forum serials.
	SerialNumber *string `json:"serial_number,omitempty"`
	NotBefore    *string `json:"not_before,omitempty"`
	NotAfter     *string `json:"not_after,omitempty"`
}

func (s *Server) handleGetStatus(w http.ResponseWriter, r *http.Request) {
	subject := r.PathValue("subject")
	if err := ca.ValidateSubject(subject); err != nil {
		http.Error(w, "invalid subject", http.StatusBadRequest)
		return
	}
	slog.Debug("GET certificate_status", "subject", subject, "client", clientOf(r))

	// Check signed dir first.
	certPEM, err := s.CA.Storage.GetCert(r.Context(), subject)
	if err == nil {
		state := "signed"
		if s.CA.IsRevoked(r.Context(), subject) {
			state = "revoked"
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(certStatusFromCert(subject, certPEM, state, s.timeFormat())); err != nil {
			slog.Warn("encode response failed", "error", err)
		}
		return
	}

	// Check CSR (requested).
	csrPEM, err := s.CA.Storage.GetCSR(r.Context(), subject)
	if err == nil {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(certStatusFromCSR(subject, csrPEM)); err != nil {
			slog.Warn("encode response failed", "error", err)
		}
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
	slog.Debug("PUT certificate_status", "subject", subject, "client", clientOf(r))

	var body PutStatusBody
	if !decodeJSONBody(w, r, &body) {
		return
	}

	switch body.DesiredState {
	case "signed":
		var err error
		if body.CertTTL != nil && *body.CertTTL > 0 {
			_, err = s.CA.SignWithTTL(r.Context(), subject, time.Duration(*body.CertTTL)*time.Second)
		} else {
			_, err = s.CA.Sign(r.Context(), subject)
		}
		if err != nil {
			slog.Warn("Sign failed", "subject", subject, "error", err)
			if strings.Contains(err.Error(), "CSR not found") {
				http.Error(w, "CSR not found", http.StatusNotFound)
			} else if errors.Is(err, ca.ErrDisallowedSubjectAltNames) {
				// 409 rather than the 400 the CSR-submission path uses, because
				// here the operator's request is well-formed — it is the stored
				// CSR that policy refuses, which is a conflict with the CA's
				// state rather than a bad request. That matches the sibling
				// signing-policy rejection immediately below, and the message
				// is surfaced for the same reason: an admin-tier caller acting
				// on a queued CSR needs to know why it will not sign, and a
				// bare "conflict" sends them to the logs of whichever replica
				// served them.
				http.Error(w, ca.ErrDisallowedSubjectAltNames.Error(), http.StatusConflict)
			} else if strings.Contains(err.Error(), "found extensions that disallow signing") {
				// Signing-policy rejection: the message lists only disallowed
				// OIDs (no filesystem paths), so it is safe to surface and is a
				// useful operator signal.
				http.Error(w, err.Error(), http.StatusConflict)
			} else {
				http.Error(w, "conflict", http.StatusConflict)
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)

	case "revoked":
		if err := s.CA.Revoke(r.Context(), subject); err != nil {
			slog.Warn("Revoke failed", "subject", subject, "error", err)
			// This is the boundary an operator reaches first and most often, so
			// it needs the diagnosis more than reissue-crl does. In this state
			// the CA cannot record revocations at all, and a bare "conflict"
			// leaves the cause in the logs of whichever replica served the
			// request.
			if errors.Is(err, ca.ErrForeignStoredCRL) {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			http.Error(w, "conflict", http.StatusConflict)
			return
		}
		if p := clientOf(r); p.cn != "" && s.destructiveOps != nil && s.destructiveOps.Record(p.Key()) {
			slog.Warn("High rate of destructive operations detected",
				"client", p, "operation", "revoke")
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "desired_state must be 'signed' or 'revoked'", http.StatusBadRequest)
	}
}

// PutStatusBySerialBody is the request body for PUT
// /certificate_status_by_serial/{serial}.
type PutStatusBySerialBody struct {
	DesiredState string `json:"desired_state"`
	// Force revokes the serial even when it is the certificate currently
	// stored for its subject. Absent/false is the safe default; see
	// ca.ErrSerialIsCurrent.
	Force bool `json:"force,omitempty"`
}

// handlePutStatusBySerial revokes one specific serial number.
//
// The subject-keyed PUT /certificate_status/{subject} cannot express this: it
// resolves to whatever serial is newest for the name, so a superseded
// certificate becomes unreachable as soon as a replacement exists — and asking
// for the subject then revokes the replacement instead, which is worse than
// doing nothing. This route exists for that state and no other, which is why it
// accepts only desired_state "revoked": there is no by-serial signing operation
// for the field to select between, and rejecting the rest keeps an unrecognised
// value from being read as a request to revoke.
//
// Admin-only, via lookupTier's default. The path deliberately does not sit under
// /certificate_status/, though nothing would misclassify it there today:
// lookupTier's arm for that prefix is GET-only, so a PUT already falls to the
// admin-only default, and extractPathSubject is reached only under
// tierSelfOrAdmin, which no PUT on that prefix takes. The reason is forward
// defence, not a present bug — two mechanisms read a segment under that prefix
// as a *subject*, one to grant self-access and one to hand it to
// --allow-public-status, and a serial has no business sitting where either might
// later read it as a name.
func (s *Server) handlePutStatusBySerial(w http.ResponseWriter, r *http.Request) {
	// Normalise before anything is logged or acted on, so every line this
	// request produces names the same serial the CA acted on. Logging the raw
	// path value instead put a different string in the handler's lines than in
	// the CA's for the same operation — "0a" against "A" — and the serial is
	// what an operator correlates them by. (docs/metrics.md sends them to the
	// log to read a serial out of a warning; it greps by message prefix, not by
	// serial, so it is where the serial matters, not a citation for the grep.)
	//
	// It also keeps an unvalidated path segment out of *this handler's* lines.
	// Not out of the log: the authorisation middleware logs r.URL.Path verbatim
	// when it denies a request (auth.go, "Request denied by authorisation
	// middleware"), and on an admin-only route that is exactly the untrusted
	// caller. So this is tidiness rather than containment — and containment is
	// not needed, because slog's Text and JSON handlers are the only two this
	// project installs and both escape, so a newline cannot forge an entry.
	// That escaping is pinned by cmd/openvox-ca/main_test.go ("control
	// characters in logged data cannot forge a second entry") and is what the
	// CodeQL go/log-injection exclusion in .github/codeql/codeql-config.yml
	// rests on; AGENTS.md carries the convention that keeps it true.
	//
	// RevokeSerial normalises again. It has no non-HTTP caller today; keeping it
	// is forward defence for an exported entry point, and it is what produces the
	// value the CA's own lines and SubjectForSerial use. The function is
	// idempotent, so the second pass is free.
	normalised, err := storage.NormaliseSerial(r.PathValue("serial"))
	if err != nil {
		slog.Debug("PUT certificate_status_by_serial: malformed serial", "client", clientOf(r))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	slog.Debug("PUT certificate_status_by_serial", "serial", normalised, "client", clientOf(r))

	var body PutStatusBySerialBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if body.DesiredState != "revoked" {
		http.Error(w, "desired_state must be 'revoked'", http.StatusBadRequest)
		return
	}

	if err := s.CA.RevokeSerial(r.Context(), normalised, body.Force); err != nil {
		slog.Warn("RevokeSerial failed", "serial", normalised, "force", body.Force, "error", err)
		switch {
		case errors.Is(err, ca.ErrSerialUnknown):
			http.Error(w, err.Error(), http.StatusNotFound)
		case errors.Is(err, ca.ErrSerialIsCurrent):
			// The message names the subject and the remedy, which is the whole
			// value of the guard; this route is admin-only, so disclosing a
			// subject the caller may already list is not a widening.
			http.Error(w, err.Error(), http.StatusConflict)
		case errors.Is(err, ca.ErrSerialStateUnknown):
			// The guard could not run. Distinct from the case above because the
			// remedy is different — wait for storage to recover, rather than
			// decide the live certificate really should go — and answering both
			// with the same bare status would send an operator to --force for a
			// reason that was never the live-certificate guard. The CA builds
			// this message without the underlying storage error for that reason.
			http.Error(w, err.Error(), http.StatusConflict)
		case errors.Is(err, ca.ErrForeignStoredCRL):
			// Same reasoning as the subject-keyed revoke: this is the boundary
			// an operator hits first, and a bare "conflict" leaves the cause in
			// the log of whichever replica served the request.
			http.Error(w, err.Error(), http.StatusConflict)
		default:
			// Everything left is a CA-side failure — an inventory read (including
			// an integrity failure), a CRL read/sign/write, a lock that could not
			// be taken. Its message may name storage paths, so it stays in the log
			// above rather than the response.
			//
			// 503, not 409: a transient CA-side fault is not a conflict with the
			// request, which is what separates this from the subject-keyed
			// route's blanket 409 for the same class of failure. Two of this
			// route's three 409s — ErrSerialIsCurrent and ErrSerialStateUnknown
			// — name force as the way forward; the foreign-CRL one does not. So
			// answering a storage fault with 409 as well would leave force the
			// likeliest thing an operator reaches for, disarming the
			// live-certificate guard for a reason that was never that guard.
			http.Error(w, "the CA could not service this request; see the server log",
				http.StatusServiceUnavailable)
		}
		return
	}

	// Per-request client identity is a Debug-level detail everywhere else, rising
	// above it only when a threshold or a rejection fires (the destructive-op
	// warning just below, the middleware's denials). That convention is left
	// alone — except here, this being the one unconditional success-path
	// attribution, because force has just disarmed the guard that stops a working
	// credential being taken out of circulation. The
	// CA layer logs the revocation but cannot see who asked for it, so without
	// this the one act on this route worth reconstructing afterwards has no
	// attribution at the default level.
	if body.Force {
		slog.Info("Forced revocation by serial", "serial", normalised, "client", clientOf(r))
	}

	// Keyed on the principal, like every other destructive-op site: two issuers
	// may each have an "ops-admin", and a bare CN would put them in one bucket
	// and one audit identity. This route was missed when the rest of the handler
	// set moved to principals.
	if p := clientOf(r); p.cn != "" && s.destructiveOps != nil && s.destructiveOps.Record(p.Key()) {
		slog.Warn("High rate of destructive operations detected",
			"client", p, "operation", "revoke")
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Certificate ---

func (s *Server) handleGetCert(w http.ResponseWriter, r *http.Request) {
	subject := r.PathValue("subject")
	// Sanitised, unlike its siblings, because this is the one subject log that
	// runs *before* ValidateSubject -- the "ca" branch below returns without
	// ever reaching it, so validating first would cost the log line for the
	// most common request on the endpoint. GET /certificate is also reachable
	// unauthenticated, which makes this the least constrained path segment the
	// API logs.
	slog.Debug("GET certificate", "subject", sanitiseForLog(subject), "client", clientOf(r))

	// Special case: "ca" returns the CA cert.
	if subject == "ca" {
		certPEM, err := s.CA.Storage.GetCACert(r.Context())
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

	certPEM, err := s.CA.Storage.GetCert(r.Context(), subject)
	if err != nil {
		http.Error(w, "certificate not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write(certPEM)
}

// ImportResponse is returned by PUT /certificate/{subject} on success.
type ImportResponse struct {
	Subject   string `json:"subject"`
	Serial    string `json:"serial"`
	NotBefore string `json:"not_before"` // UTC timestamp, rendered with the server's configured time format (timeFormat())
	NotAfter  string `json:"not_after"`  // UTC timestamp, rendered with the server's configured time format (timeFormat())
	Imported  bool   `json:"imported"`   // false if this was a no-op (already tracked)
}

// handlePutCert imports a certificate that was issued OUTSIDE this CA's
// normal signing flow (e.g. migrated from a legacy CA sharing this CA's
// key) into the inventory under subject, so it appears in listings, has its
// lifetime tracked, and can be revoked via the normal PUT
// certificate_status desired_state=revoked mechanism. This is the only way
// to directly set a subject's certificate outside the CSR-based signing
// flow, hence sharing this path with GET certificate/{subject}. Admin-only
// (enforced by the auth middleware, which defaults non-GET methods on this
// path to tierAdminOnly).
func (s *Server) handlePutCert(w http.ResponseWriter, r *http.Request) {
	subject := r.PathValue("subject")
	if err := ca.ValidateSubject(subject); err != nil {
		http.Error(w, "invalid subject", http.StatusBadRequest)
		return
	}
	slog.Debug("PUT certificate (import)", "subject", subject, "client", clientOf(r))

	certPEM, err := io.ReadAll(io.LimitReader(r.Body, maxJSONBody))
	if err != nil {
		slog.Error("read import cert body failed", "subject", subject, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	result, err := s.CA.ImportCertificate(r.Context(), subject, certPEM)
	if err != nil {
		switch {
		case errors.Is(err, ca.ErrNotInitialized):
			http.Error(w, "CA not ready", http.StatusServiceUnavailable)
		case errors.Is(err, ca.ErrImportInvalid):
			slog.Warn("Import rejected", "subject", subject, "error", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.Is(err, ca.ErrSerialExists), errors.Is(err, ca.ErrCertExists):
			slog.Warn("Import conflict", "subject", subject, "error", err)
			http.Error(w, err.Error(), http.StatusConflict)
		default:
			slog.Error("Import failed", "subject", subject, "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(ImportResponse{
		Subject:   result.Subject,
		Serial:    result.Serial,
		NotBefore: result.NotBefore.UTC().Format(s.timeFormat()),
		NotAfter:  result.NotAfter.UTC().Format(s.timeFormat()),
		Imported:  result.Imported,
	}); err != nil {
		slog.Warn("encode response failed", "error", err)
	}
}

// --- CRL ---

func (s *Server) handleGetCRL(w http.ResponseWriter, r *http.Request) {
	slog.Debug("GET certificate_revocation_list/ca", "client", clientOf(r))

	// Honor If-Modified-Since.
	if ims := r.Header.Get("If-Modified-Since"); ims != "" {
		if t, err := http.ParseTime(ims); err == nil {
			if mt, err := s.CA.Storage.CRLModTime(r.Context()); err == nil && !mt.IsZero() {
				if !mt.After(t) {
					w.WriteHeader(http.StatusNotModified)
					return
				}
			}
		}
	}

	crlPEM, err := s.CA.Storage.GetCRL(r.Context())
	if err != nil {
		http.Error(w, "CRL not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write(crlPEM)
}

// handleReissueCRL re-signs the CRL with a fresh validity window, preserving
// all existing revocation entries. Admin-only (enforced by the auth middleware,
// which defaults non-GET methods on this path to tierAdminOnly). This lets an
// operator refresh a CRL whose NextUpdate has lapsed (or is about to) without
// having to revoke a certificate.
func (s *Server) handleReissueCRL(w http.ResponseWriter, r *http.Request) {
	slog.Debug("PUT certificate_revocation_list/ca", "client", clientOf(r))

	if err := s.CA.ReissueCRL(r.Context()); err != nil {
		slog.Warn("CRL reissue failed", "error", err)
		if errors.Is(err, ca.ErrForeignStoredCRL) {
			// Operator-fixable, and the CA's own message names the cause and the
			// remedy. Surfacing it is the difference between "reissue-crl
			// returned 500" and knowing the replica needs a restart; a 500 would
			// leave that in the logs of whichever replica served the request.
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		http.Error(w, "failed to reissue CRL", http.StatusInternalServerError)
		return
	}

	crlPEM, err := s.CA.Storage.GetCRL(r.Context())
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
	slog.Debug("GET certificate_request", "subject", subject, "client", clientOf(r))

	csrPEM, err := s.CA.Storage.GetCSR(r.Context(), subject)
	if err != nil {
		http.Error(w, "CSR not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write(csrPEM)
}

func (s *Server) handlePutRequest(w http.ResponseWriter, r *http.Request) {
	// SECURITY: Per-IP rate limiting on the unauthenticated CSR submission
	// endpoint. Prevents CSR flooding denial-of-service attacks.
	// NIST 800-53: SC-5 (Denial-of-Service Protection)
	if s.csrLimiter != nil && !s.csrLimiter.Allow(clientIP(r)) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	subject := r.PathValue("subject")
	if err := ca.ValidateSubject(subject); err != nil {
		http.Error(w, "invalid subject", http.StatusBadRequest)
		return
	}
	slog.Debug("PUT certificate_request", "subject", subject, "client", clientOf(r))

	// SECURITY: Limit CSR body to 1 MiB to prevent memory exhaustion.
	// NIST 800-53: SC-5 (Denial-of-Service Protection)
	csrPEM, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		slog.Error("read CSR body failed", "subject", subject, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	signed, err := s.CA.SaveRequest(r.Context(), subject, csrPEM)
	if err != nil {
		if errors.Is(err, ca.ErrCertExists) {
			// A signed certificate already exists for this subject. Return 200 so
			// the node continues its poll loop and retrieves its cert via GET.
			// Returning 409 here causes the node (e.g. openvox-agent) to treat the
			// submission as fatal and abort the run entirely.
			w.WriteHeader(http.StatusOK)
		} else if errors.Is(err, ca.ErrDisallowedSubjectAltNames) {
			// Policy refusal, not a fault: the CSR is well-formed but asks for
			// names it may not have. 400 rather than 500 so the agent stops
			// rather than retrying a request that can never succeed, and the
			// sentinel's own message rather than err.Error() so the response
			// stays generic — which entries were refused is in the CA's log.
			slog.Warn("SaveRequest refused: disallowed subject alternative names", "subject", subject)
			http.Error(w, ca.ErrDisallowedSubjectAltNames.Error(), http.StatusBadRequest)
		} else if csrValidationError(err) {
			// Client-actionable validation failure (malformed or mis-signed CSR,
			// or CN/subject mismatch). The message is path-free and useful to the
			// agent, so surface it as a 400.
			slog.Warn("SaveRequest rejected", "subject", subject, "error", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
		} else {
			// Internal storage/autosign fault whose message embeds absolute
			// filesystem paths. On this unauthenticated endpoint we must not leak
			// it: log the detail and return a generic 500.
			slog.Error("SaveRequest internal failure", "subject", subject, "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
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
	slog.Debug("DELETE certificate_request", "subject", subject, "client", clientOf(r))

	if err := s.CA.DeleteRequest(r.Context(), subject); err != nil {
		if errors.Is(err, ca.ErrNoCSR) {
			http.Error(w, "CSR not found", http.StatusNotFound)
			return
		}
		// Anything else and the CSR is still there, still signable. Reporting
		// "CSR not found" here would tell the operator their rejection landed
		// when it did not — the same misreport the subject lock on this path
		// exists to prevent. Storage and lock failures also embed absolute
		// paths and backend addresses, so log the detail and answer generically.
		//
		// 503 for the same reason handlePutStatusBySerial gives above: what is
		// left here is a CA-side fault — a storage error, or a lock that could
		// not be taken — and none of it is a conflict with the request. Nothing
		// was deleted in any of those cases, so the operator's retry is safe
		// and 503 is the code that says so.
		//
		// Carries the client CN because docs/api.md points the operator at this
		// line as the authoritative record of an ambiguous delete: on an
		// admin-only route there is always a CN, and a destructive operation
		// whose record cannot say who asked for it is a weaker record than the
		// documentation claims.
		slog.Error("DeleteRequest failed", "subject", subject, "client", clientOf(r), "error", err)
		http.Error(w, "the CA could not service this request; see the server log",
			http.StatusServiceUnavailable)
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
	// SECURITY: Refuse to serve private keys over plain HTTP: the response
	// body contains the generated private key in cleartext. Without TLS, any
	// on-path observer can capture the key.
	// NIST 800-53: SC-8 (Transmission Confidentiality and Integrity), SC-12 (Cryptographic Key Establishment and Management)
	if s.PlainHTTP {
		http.Error(w, "private key delivery requires TLS", http.StatusForbidden)
		return
	}

	subject := r.PathValue("subject")
	if err := ca.ValidateSubject(subject); err != nil {
		http.Error(w, "invalid subject", http.StatusBadRequest)
		return
	}
	slog.Debug("POST generate", "subject", subject, "client", clientOf(r))

	// Optional DNS alt names from query params (?dns=a&dns=b).
	dnsAltNames := r.URL.Query()["dns"]

	result, err := s.CA.Generate(r.Context(), subject, dnsAltNames)
	if err != nil {
		if errors.Is(err, ca.ErrCertExists) {
			slog.Warn("Generate conflict", "subject", subject, "error", err)
			http.Error(w, "certificate already exists", http.StatusConflict)
		} else {
			slog.Error("Generate failed", "subject", subject, "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(generateResponse{
		PrivateKey:  string(result.PrivateKeyPEM),
		Certificate: string(result.CertificatePEM),
	}); err != nil {
		slog.Warn("encode response failed", "error", err)
	}
}

// decodeJSONBody caps the request body at maxJSONBody and decodes it into dst.
// On success it returns true. On failure it writes an appropriate error
// response (413 when the size cap is exceeded, otherwise 400 with a safe static
// message) and returns false; the caller must stop processing the request.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return false
		}
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return false
	}
	return true
}

// csrValidationError reports whether err from CA.SaveRequest is a
// client-actionable CSR validation failure whose message is safe to return
// verbatim. These messages contain only the (already-validated) subject name
// and crypto/ASN.1 detail — no filesystem paths. SaveRequest's other failures
// (storage writes, autosign execution) wrap absolute paths, so the handler
// treats anything NOT matched here as internal and returns a generic message.
// Matching is fail-safe: an unrecognised error is treated as internal (no leak),
// at worst returning a less specific message.
func csrValidationError(err error) bool {
	s := err.Error()
	return strings.Contains(s, "does not match requested key") ||
		strings.Contains(s, "failed to decode CSR PEM") ||
		strings.Contains(s, "failed to parse CSR") ||
		strings.Contains(s, "invalid CSR signature")
}

// clientCN returns the presented certificate's common name, verbatim. Empty
// when TLS is not configured or no client certificate was presented.
//
// Verbatim, because this is an *identity*: the renewal handler compares it
// against a CSR's subject and passes it to Renew as the name to issue for.
// Sanitising it here looked like closing the log-injection class at its source
// and was not -- the middleware reads the field directly anyway, so the class
// stayed open -- while sanitiseForLog truncates at 256 bytes, which this CA's
// certname grammar permits. The effect was that an agent with a long certname
// got a permanent 403 on a re-key renewal, comparing a truncated name against
// its own correct CSR.
//
// Use clientOf anywhere the client is displayed or counted rather than
// compared. It carries the vouching domain as well as the name, and it is the
// only way either reaches a log record -- which is what a display *function*
// beside this one was not. That form left the choice at every call site, and the
// sweep that introduced it missed fourteen of them.
//
// The callers that remain here are the renewal handler's CSR comparison and the
// subject it passes to Renew. Both sit behind tierOwnClient, so the domain is
// ours by construction and the bare name is exactly what is wanted.
//
// It reaches log records in that handler too, and this comment used to imply it
// did not. Those lines key on "subject" rather than "client" -- the name being
// renewed, not the principal asking -- so they are sanitised at the call site
// with sanitiseForLog rather than routed through the principal, which would
// rename a published field. Truncation is harmless there: it is a log line, not
// the comparison, and the comparison is what the 256-byte limit broke.
//
// The bare name is not safe by construction, which is why this is not left
// alone. ImportCertificate accepts any certificate this CA's key genuinely
// signed and requires only that the path subject match the CN *or a DNS SAN* --
// so a certificate whose Subject.CommonName holds arbitrary bytes can be
// registered under a validated name, exactly the migrated-from-a-legacy-CA case
// it documents, and its CN then reaches these lines. slog's own handlers quote
// control characters, so this is defence in depth rather than a live forgery,
// but the invariant this branch advertises is that a CN cannot reach a record
// unsanitised, and that has to be true everywhere or it is not an invariant.
func clientCN(r *http.Request) string {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return r.TLS.PeerCertificates[0].Subject.CommonName
	}
	return ""
}

// signInBatches signs subjects in chunks of SignBatchLimit (if set) and merges
// the results. This prevents unbounded bulk signing while still completing the
// full request rather than rejecting it.
func (s *Server) signInBatches(ctx context.Context, subjects []string) ca.SignResult {
	if s.SignBatchLimit <= 0 || len(subjects) <= s.SignBatchLimit {
		return s.CA.SignMultiple(ctx, subjects)
	}

	merged := ca.SignResult{
		Signed:        []string{},
		NoCSR:         []string{},
		SigningErrors: []string{},
	}
	for i := 0; i < len(subjects); i += s.SignBatchLimit {
		end := min(i+s.SignBatchLimit, len(subjects))
		batch := s.CA.SignMultiple(ctx, subjects[i:end])
		merged.Signed = append(merged.Signed, batch.Signed...)
		merged.NoCSR = append(merged.NoCSR, batch.NoCSR...)
		merged.SigningErrors = append(merged.SigningErrors, batch.SigningErrors...)
	}
	return merged
}

// --- Helpers ---

func parseCert(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return c, nil
}

func parseCSR(pemData []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CSR PEM")
	}
	c, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}
	return c, nil
}

// authExtensions extracts Puppet authorization extensions (OID arc 1.3.6.1.4.1.34380.1.3)
// from a certificate or CSR extension list and returns them as a name→value map.
// See ca.AuthExtensionMap, which is shared with the certificate index
// projection so the two can never disagree on the display form.
func authExtensions(exts []pkix.Extension) map[string]string {
	return ca.AuthExtensionMap(exts)
}

// fingerprint renders the SHA-256 fingerprint of a PEM-encoded certificate or
// CSR as Puppet's colon-separated hex pairs, or "" when data is not PEM. The
// digest formatting is shared with the certificate index projection (see
// ca.SHA256ColonFingerprint).
func fingerprint(data []byte) string {
	block, _ := pem.Decode(data)
	if block == nil {
		return ""
	}
	return ca.SHA256ColonFingerprint(block.Bytes)
}

// noNilSlice returns s unchanged when non-nil, or an empty non-nil slice.
// This ensures dns_alt_names serialises as [] rather than null in JSON.
func noNilSlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// timeFormat returns the time layout string to use for JSON date/time fields.
func (s *Server) timeFormat() string {
	if s.PuppetDateTimeFormat {
		return "2006-01-02T15:04:05MST"
	}
	return time.RFC3339
}

// certStatusFromCert builds a CertStatusResponse from a signed or revoked certificate.
func certStatusFromCert(subject string, certPEM []byte, state string, timeFmt string) CertStatusResponse {
	cert, err := parseCert(certPEM)
	if err != nil {
		slog.Warn("Failed to parse cert for status response", "subject", subject, "error", err)
		fp := fingerprint(certPEM)
		return CertStatusResponse{
			Name:                    subject,
			State:                   state,
			Fingerprint:             fp,
			Fingerprints:            map[string]string{"SHA256": fp, "default": fp},
			DNSAltNames:             []string{},
			SubjectAltNames:         []string{},
			AuthorizationExtensions: map[string]string{},
		}
	}
	fp := fingerprint(certPEM)
	serial := cert.SerialNumber.Text(10) // decimal string; preserves full 128-bit value
	nb := cert.NotBefore.UTC().Format(timeFmt)
	na := cert.NotAfter.UTC().Format(timeFmt)
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

// normaliseSerial renders an inventory serial the way the CA's revoked-serial map
// keys it, so a legacy zero-padded form still matches. Reports false when the
// serial is not hex at all, which certStatusFromRecord also rejects.
func normaliseSerial(serial string) (string, bool) {
	n := new(big.Int)
	if _, ok := n.SetString(serial, 16); !ok {
		return "", false
	}
	return fmt.Sprintf("%X", n), true
}

// certSerialIs reports whether cert is the certificate the given inventory
// serial names. Serials are compared through big.Int so a legacy zero-padded
// form still matches, exactly as the index repair compares them.
func certSerialIs(cert *x509.Certificate, serial string) bool {
	want := new(big.Int)
	if _, ok := want.SetString(serial, 16); !ok {
		return false
	}
	return want.Cmp(cert.SerialNumber) == 0
}

// certStatusFromRecord builds a CertStatusResponse from a certificate-index
// record without touching the stored PEM. ok=false means the record cannot
// stand alone — its display projection was never populated (legacy inventory
// import) or a canonical field does not parse — and the caller should fall
// back to the PEM path for that subject.
func certStatusFromRecord(rec storage.CertRecord, timeFmt string) (CertStatusResponse, bool) {
	if rec.Fingerprint == "" {
		return CertStatusResponse{}, false
	}
	serialInt := new(big.Int)
	if _, ok := serialInt.SetString(rec.Serial, 16); !ok {
		return CertStatusResponse{}, false
	}
	nb, err := time.Parse(storage.InventoryTimeFormat, rec.NotBefore)
	if err != nil {
		return CertStatusResponse{}, false
	}
	na, err := time.Parse(storage.InventoryTimeFormat, rec.NotAfter)
	if err != nil {
		return CertStatusResponse{}, false
	}

	serial := serialInt.Text(10) // decimal string; preserves full 128-bit value
	nbs := nb.UTC().Format(timeFmt)
	nas := na.UTC().Format(timeFmt)
	dnsNames := noNilSlice(rec.DNSAltNames)
	authExts := rec.AuthExtensions
	if authExts == nil {
		authExts = map[string]string{}
	}
	return CertStatusResponse{
		Name:                    rec.Subject,
		State:                   rec.State,
		Fingerprint:             rec.Fingerprint,
		Fingerprints:            map[string]string{"SHA256": rec.Fingerprint, "default": rec.Fingerprint},
		DNSAltNames:             dnsNames,
		SubjectAltNames:         dnsNames,
		AuthorizationExtensions: authExts,
		SerialNumber:            &serial,
		NotBefore:               &nbs,
		NotAfter:                &nas,
	}, true
}

// certStatusFromCSR builds a CertStatusResponse for a pending (requested) CSR.
func certStatusFromCSR(subject string, csrPEM []byte) CertStatusResponse {
	fp := fingerprint(csrPEM)
	csr, err := parseCSR(csrPEM)
	if err != nil {
		slog.Warn("Failed to parse CSR for status response", "subject", subject, "error", err)
		return CertStatusResponse{
			Name:                    subject,
			State:                   "requested",
			Fingerprint:             fp,
			Fingerprints:            map[string]string{"SHA256": fp, "default": fp},
			DNSAltNames:             []string{},
			SubjectAltNames:         []string{},
			AuthorizationExtensions: map[string]string{},
		}
	}
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
	slog.Debug("DELETE certificate_status", "subject", subject, "client", clientOf(r))

	if err := s.CA.Clean(r.Context(), subject); err != nil {
		slog.Warn("Clean failed", "subject", subject, "error", err)
		if errors.Is(err, ca.ErrNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
		} else {
			http.Error(w, "conflict", http.StatusConflict)
		}
		return
	}
	if p := clientOf(r); p.cn != "" && s.destructiveOps != nil && s.destructiveOps.Record(p.Key()) {
		slog.Warn("High rate of destructive operations detected",
			"client", p, "operation", "clean")
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Certificate statuses (list all) ---

func (s *Server) handleGetStatuses(w http.ResponseWriter, r *http.Request) {
	slog.Debug("GET certificate_statuses", "client", clientOf(r))

	stateFilter := r.URL.Query().Get("state") // "requested", "signed", "revoked", or ""

	statuses := []CertStatusResponse{}
	seen := make(map[string]bool)

	// Signed/revoked certificates. Backends with a certificate index answer
	// this from indexed columns — one query instead of a read-PEM-parse-and-
	// CRL-check per subject; all others walk the stored PEMs. Either way,
	// every subject holding a certificate lands in seen, so that under a
	// "requested" filter a pending re-submission for an already-certified
	// subject is not listed (the certificate wins until it is cleaned).
	//
	// The index is queried unfiltered: the state filter is applied against
	// each record below, which both keeps seen complete and pins filter
	// semantics to the same value the response would show.
	records, indexed, err := s.CA.Storage.CertStatuses(r.Context(), "")
	if err != nil {
		slog.Error("certificate index statuses failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if indexed {
		// State comes from the signed CRL, not from the index row. The row is a
		// projection, and the write that maintains it is best-effort -- a
		// swallowed SetRevoked leaves the CRL correct and the row saying signed,
		// and the repair pass that reconciles them runs only at startup. Every
		// other status path in this file derives state from the CRL; deriving it
		// from the row here made the list view disagree with the single-subject
		// view for as long as the process ran. One pass over the CRL plus a map
		// lookup per record keeps the O(N) PEM scan the index removed.
		revoked := s.CA.RevokedSerials()
		for _, rec := range records {
			seen[rec.Subject] = true
			state := storage.CertStateSigned
			if normalised, ok := normaliseSerial(rec.Serial); ok {
				if _, inCRL := revoked[normalised]; inCRL {
					state = storage.CertStateRevoked
				}
			}
			resp, ok := certStatusFromRecord(rec, s.timeFormat())
			if ok {
				resp.State = state
			} else {
				// Projection not (yet) populated for this record — fall back to
				// the stored PEM for this one subject.
				certPEM, err := s.CA.Storage.GetCert(r.Context(), rec.Subject)
				if err != nil {
					slog.Warn("statuses: reading stored certificate failed, omitting subject",
						"subject", rec.Subject, "error", err)
					continue
				}
				// Warned but still served, and the distinction matters. The index
				// repair refuses this same pairing because it would *write* the
				// PEM's fields onto the row, making the row assert something about
				// a certificate it does not describe. Here nothing of the row is
				// used: every display field comes from the authoritative PEM, and
				// the state — derived above from the *row's* serial, which this
				// branch has just proven names a different certificate — is
				// re-derived from the serial of the certificate actually served,
				// so the response describes the stored certificate accurately.
				// Omitting instead would drop a real certificate from the listing,
				// which is the divergence from the scan path this branch exists to
				// avoid.
				if cert, perr := parseCert(certPEM); perr == nil && !certSerialIs(cert, rec.Serial) {
					state = storage.CertStateSigned
					if _, inCRL := revoked[fmt.Sprintf("%X", cert.SerialNumber)]; inCRL {
						state = storage.CertStateRevoked
					}
					slog.Warn("statuses: stored certificate does not match the index record's serial; "+
						"answering from the stored certificate",
						"subject", rec.Subject, "index_serial", rec.Serial)
				}
				resp = certStatusFromCert(rec.Subject, certPEM, state, s.timeFormat())
			}
			// The filter runs against the state the response actually carries,
			// which the fallback above may have re-derived — filtering on the
			// row-derived state would sort a certificate under a state the
			// response itself contradicts.
			if stateFilter != "" && resp.State != stateFilter {
				continue
			}
			statuses = append(statuses, resp)
		}

		// The index reports the *intersection* of stored certificates and
		// inventory rows, so a subject whose certificate was written and whose row
		// was not -- the crash window between those two writes, which
		// backfillCertProjection's own doc names -- is missing from it entirely.
		// The scan branch lists that subject from the blobs, so without this the
		// same endpoint answers differently by backend: the certificate vanishes,
		// it never lands in seen, and the pending CSR is then reported as
		// "requested" for a host that already holds a certificate the CA serves.
		certs, err := s.CA.Storage.ListCerts(r.Context())
		if err != nil {
			slog.Error("list certs failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		for _, subject := range certs {
			if seen[subject] {
				continue
			}
			seen[subject] = true
			certPEM, err := s.CA.Storage.GetCert(r.Context(), subject)
			if err != nil {
				slog.Warn("statuses: reading stored certificate failed, omitting subject",
					"subject", subject, "error", err)
				continue
			}
			state := storage.CertStateSigned
			if s.CA.IsRevoked(r.Context(), subject) {
				state = storage.CertStateRevoked
			}
			// Detection only: the filter below may still drop the subject from
			// this particular response, but the anomaly is worth surfacing
			// either way — nothing self-heals a certificate without a row.
			slog.Warn("statuses: stored certificate has no index row",
				"subject", subject)
			if stateFilter != "" && state != stateFilter {
				continue
			}
			statuses = append(statuses, certStatusFromCert(subject, certPEM, state, s.timeFormat()))
		}
	} else {
		certs, err := s.CA.Storage.ListCerts(r.Context())
		if err != nil {
			slog.Error("list certs failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		for _, subject := range certs {
			seen[subject] = true
			certPEM, err := s.CA.Storage.GetCert(r.Context(), subject)
			if err != nil {
				slog.Warn("statuses: reading stored certificate failed, omitting subject",
					"subject", subject, "error", err)
				continue
			}
			state := "signed"
			if s.CA.IsRevoked(r.Context(), subject) {
				state = "revoked"
			}
			if stateFilter != "" && state != stateFilter {
				continue
			}
			statuses = append(statuses, certStatusFromCert(subject, certPEM, state, s.timeFormat()))
		}
	}

	csrs, err := s.CA.Storage.ListCSRs(r.Context())
	if err != nil {
		slog.Error("list CSRs failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	for _, subject := range csrs {
		if seen[subject] {
			continue
		}
		if stateFilter != "" && stateFilter != "requested" {
			continue
		}
		csrPEM, err := s.CA.Storage.GetCSR(r.Context(), subject)
		if err != nil {
			continue
		}
		statuses = append(statuses, certStatusFromCSR(subject, csrPEM))
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(statuses); err != nil {
		slog.Warn("encode response failed", "error", err)
	}
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
	slog.Debug("GET expirations", "client", clientOf(r))

	// Without this guard a request that reaches the handler before Init()
	// finishes would dereference a nil CACert below and panic the server.
	if !s.CA.IsReady() {
		http.Error(w, "CA not ready", http.StatusServiceUnavailable)
		return
	}
	certExp := s.CA.CACert.NotAfter.UTC().Format(s.timeFormat())

	crlNextUpdate := ""
	if crlPEM, err := s.CA.Storage.GetCRL(r.Context()); err == nil {
		if block, _ := pem.Decode(crlPEM); block != nil {
			if crl, err := x509.ParseRevocationList(block.Bytes); err == nil {
				crlNextUpdate = crl.NextUpdate.UTC().Format(s.timeFormat())
			}
		}
	}

	resp := ExpirationsResponse{
		CACrl:         CRLExpiration{NextUpdate: crlNextUpdate},
		CACertificate: CertExpiration{Expiration: certExp},
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Warn("encode response failed", "error", err)
	}
}

// --- Bulk sign ---

type SignRequestBody struct {
	Certnames []string `json:"certnames"`
}

func (s *Server) handlePostSign(w http.ResponseWriter, r *http.Request) {
	client := clientOf(r)
	slog.Debug("POST sign", "client", client)

	var body SignRequestBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if len(body.Certnames) == 0 {
		http.Error(w, "certnames must not be empty", http.StatusBadRequest)
		return
	}

	slog.Debug("Signing certificates", "count", len(body.Certnames),
		"subjects", sanitiseAllForLog(body.Certnames), "client", client)
	result := s.signInBatches(r.Context(), body.Certnames)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		slog.Warn("encode response failed", "error", err)
	}
}

// --- Certificate renewal ---

func (s *Server) handlePostCertificateRenewal(w http.ResponseWriter, r *http.Request) {
	// Renewal requires an authenticated client cert to establish identity.
	// cn is the identity: it is compared against the CSR's subject below and is
	// the name Renew issues for, so it must be the certificate's value. client is
	// what every log line in this handler names, sanitised and domain-qualified.
	cn := clientCN(r)
	if cn == "" {
		http.Error(w, "client certificate required for renewal", http.StatusForbidden)
		return
	}
	client := clientOf(r)
	slog.Debug("POST certificate_renewal", "client", client)

	// SECURITY: Limit body to 1 MiB to prevent memory exhaustion.
	// NIST 800-53: SC-5 (Denial-of-Service Protection)
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		slog.Error("read renewal body failed", "client", client, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	var certPEM []byte
	if strings.TrimSpace(string(body)) == "" {
		// Wire-compatible with real Puppet/OpenVox agents: by default
		// (hostcert_renewal_interval) they POST an empty body here, relying
		// solely on the mTLS-presented client cert to prove identity and key
		// possession, and expect the SAME key reissued with a fresh serial
		// and validity.
		//
		// Reissuing without a fresh proof-of-possession is safe because the
		// certificate is checked twice over. newAuthMiddleware attributes it to
		// a trust domain, and the tierOwnClient path guarding this route admits
		// only domain zero — our own CA — having also confirmed it is not
		// revoked. AutoRenew then verifies independently that this CA issued it
		// and has not revoked it, rejecting with ErrForeignCertificate
		// otherwise.
		//
		// The second check is not redundant with the first. They are enforced in
		// different packages against different state, and renewal is the
		// operation that mints a new credential from an old one — the place
		// where a foreign certificate crossing into our namespace would be
		// hardest to notice afterwards. clientCN(r) only reads the CN.
		certPEM, err = s.CA.AutoRenew(r.Context(), r.TLS.PeerCertificates[0])
		if err != nil {
			// A revoked certificate must not be renewed into a fresh one. This
			// is reachable even though the middleware checks revocation: it
			// reads the in-memory CRL, and on a replica that did not perform the
			// revocation that copy can be up to crl_sync_interval_sec behind.
			if errors.Is(err, ca.ErrCertRevoked) {
				slog.Warn("Auto-renewal rejected: certificate is revoked", "subject", sanitiseForLog(cn))
				http.Error(w, "access denied", http.StatusForbidden)
				return
			}
			// A key-strength rejection is client-actionable: the presented
			// cert (e.g. imported from a legacy CA) carries a key below policy
			// and the agent must re-key via the CSR-based renewal path. Report
			// it as such rather than masking it behind a 500.
			if errors.Is(err, ca.ErrKeyPolicy) {
				slog.Warn("Auto-renewal rejected: key policy", "subject", sanitiseForLog(cn), "error", err)
				http.Error(w, "certificate key does not meet policy; renew with a new CSR", http.StatusUnprocessableEntity)
				return
			}
			if errors.Is(err, ca.ErrForeignCertificate) {
				// Deliberately not "access denied": that is the middleware's
				// wording, and the authorisation oracle keys on it to tell a
				// middleware rejection from a handler one. Sharing the string
				// would make the oracle blind to the middleware's own checks.
				slog.Warn("Auto-renewal rejected: certificate not eligible", "subject", sanitiseForLog(cn), "error", err)
				http.Error(w, "certificate not eligible for renewal", http.StatusForbidden)
				return
			}
			if errors.Is(err, ca.ErrNotInitialized) {
				// Same answer as the import path: not ready is a retryable
				// condition, not a server fault.
				http.Error(w, "CA not ready", http.StatusServiceUnavailable)
				return
			}
			slog.Warn("Auto-renewal failed", "subject", sanitiseForLog(cn), "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
	} else {
		csr, err := parseCSR(body)
		if err != nil {
			http.Error(w, "invalid CSR: "+err.Error(), http.StatusBadRequest)
			return
		}

		// SECURITY: CSR CN must match the authenticated client CN. Without this
		// check an agent could renew another agent's certificate by sending a CSR
		// with a different CN while authenticating as itself.
		// NIST 800-53: IA-5(2) (PKI-Based Authentication)
		if csr.Subject.CommonName != cn {
			// The CSR's CN is chosen by the requester and nothing has validated it
			// at this point -- this is the mismatch branch, before Renew runs. Any
			// agent holding one of our certificates reaches it, and the record it
			// would forge is itself a security event.
			slog.Warn("Renewal rejected: CN mismatch",
				"client", client,
				"csr_cn", sanitiseForLog(csr.Subject.CommonName))
			http.Error(w, "CSR CN does not match authenticated client CN", http.StatusForbidden)
			return
		}

		certPEM, err = s.CA.Renew(r.Context(), cn, body, r.TLS.PeerCertificates[0])
		if err != nil {
			// A revoked certificate must not be re-keyed either. This branch
			// matters more than the auto-renewal one it mirrors: it issues a
			// certificate for a key the client chose, so a revoked agent
			// getting through would end up holding a credential this CA has
			// never seen the private key of.
			if errors.Is(err, ca.ErrCertRevoked) {
				slog.Warn("Renewal rejected: certificate is revoked", "subject", sanitiseForLog(cn))
				http.Error(w, "access denied", http.StatusForbidden)
				return
			}
			// Same key-strength policy applies to the re-key CSR: surface it as
			// a client error instead of a 500.
			if errors.Is(err, ca.ErrKeyPolicy) {
				slog.Warn("Renewal rejected: key policy", "subject", sanitiseForLog(cn), "error", err)
				http.Error(w, "CSR key does not meet policy", http.StatusUnprocessableEntity)
				return
			}
			if errors.Is(err, ca.ErrRenewalSubjectMismatch) {
				// Same 403 body as below — the client learns no more either way
				// — but logged apart, because this one is an authenticated
				// caller reaching for another node's identity rather than a
				// topology problem.
				//
				// Unreachable from this handler by construction: it passes cn
				// and the certificate cn came from, so the two always agree.
				// Unlike the foreign-certificate branch below, no topology
				// change makes it reachable — only a future caller that passes
				// subject and certificate separately. It is here so that such a
				// caller gets a 403 rather than a 500.
				slog.Warn("Renewal rejected: presented certificate is for another subject",
					"subject", sanitiseForLog(cn), "error", err)
				http.Error(w, "certificate not eligible for renewal", http.StatusForbidden)
				return
			}
			if errors.Is(err, ca.ErrForeignCertificate) {
				// See the auto-renewal branch: the body must not collide with
				// the middleware's "access denied".
				slog.Warn("Renewal rejected: certificate not eligible", "subject", sanitiseForLog(cn), "error", err)
				http.Error(w, "certificate not eligible for renewal", http.StatusForbidden)
				return
			}
			if errors.Is(err, ca.ErrNotInitialized) {
				// See the auto-renewal branch.
				http.Error(w, "CA not ready", http.StatusServiceUnavailable)
				return
			}
			if errors.Is(err, ca.ErrDisallowedSubjectAltNames) {
				// 400 as on PUT /certificate_request, and for the same reason:
				// the client supplied this CSR, the refusal is a policy
				// decision rather than a fault, and it can never succeed as
				// submitted — so the agent must stop rather than retry a 500
				// forever. Without this arm the catch-all below answers 500 and
				// the agent reads a deliberate refusal as a server problem.
				slog.Warn("Renewal refused: disallowed subject alternative names",
					"subject", sanitiseForLog(cn))
				http.Error(w, ca.ErrDisallowedSubjectAltNames.Error(), http.StatusBadRequest)
				return
			}
			slog.Warn("Renewal failed", "subject", sanitiseForLog(cn), "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(certPEM)
}

func (s *Server) handlePostSignAll(w http.ResponseWriter, r *http.Request) {
	// Display only -- nothing here compares or acts on the name.
	client := clientOf(r)
	slog.Debug("POST sign/all", "client", client)

	pending, err := s.CA.Storage.ListCSRs(r.Context())
	if err != nil {
		slog.Error("list pending CSRs failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	result := s.signInBatches(r.Context(), pending)
	slog.Debug("Signed all pending CSRs", "signed", len(result.Signed), "errors", len(result.SigningErrors), "client", client)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		slog.Warn("encode response failed", "error", err)
	}
}

// --- Bulk clean ---

func (s *Server) handlePutClean(w http.ResponseWriter, r *http.Request) {
	client := clientOf(r)
	slog.Debug("PUT clean", "client", client)

	var body SignRequestBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if len(body.Certnames) == 0 {
		http.Error(w, "certnames must not be empty", http.StatusBadRequest)
		return
	}

	slog.Debug("Cleaning certificates", "count", len(body.Certnames),
		"subjects", sanitiseAllForLog(body.Certnames), "client", client)
	result := s.CA.CleanMultiple(r.Context(), body.Certnames)
	if client.cn != "" && s.destructiveOps != nil && s.destructiveOps.Record(client.Key()) {
		slog.Warn("High rate of destructive operations detected", "client", client, "operation", "bulk-clean")
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		slog.Warn("encode response failed", "error", err)
	}
}
