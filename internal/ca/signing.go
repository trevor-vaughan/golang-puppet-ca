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

package ca

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

const (
	// certValidity is the lifetime issued to CA and leaf certificates.
	certValidity = 5 * 365 * 24 * time.Hour
	// CRLValidity is the default validity window written into every CRL.
	CRLValidity = 30 * 24 * time.Hour
)

// CRLValidityDuration returns the CA's configured CRL validity period.
// When CRLValidityDays is zero the package-level CRLValidity default is used.
//
// Exported because offline commands re-sign a CRL outside the CA's own signing
// paths and must use the same window; duplicating the defaulting rule there is
// how the two quietly diverge.
func (c *CA) CRLValidityDuration() time.Duration {
	if c.CRLValidityDays > 0 {
		return time.Duration(c.CRLValidityDays) * 24 * time.Hour
	}
	return CRLValidity
}

// serialHexStr formats a serial number as uppercase hexadecimal without
// leading zeros. This is the canonical key used in the serial index and
// OCSP cache, and the form written to the inventory file.
func serialHexStr(n *big.Int) string {
	return fmt.Sprintf("%X", n)
}

// ErrCertExists is returned by SaveRequest when a valid (non-revoked) certificate
// already exists for the requested subject.
var ErrCertExists = errors.New("certificate already exists")

// ErrCertRevoked is returned by the renewal paths when the certificate
// presented for renewal is on the CRL. A sentinel because the HTTP layer has to
// turn it into a 403 rather than a 500: the request is well formed and the
// answer is a refusal, not a failure.
var ErrCertRevoked = errors.New("certificate is revoked")

// refuseIfRevoked re-checks presentedCert against the CRL in storage, rather
// than against the cached copy the auth middleware consulted on the way in, and
// returns ErrCertRevoked when it is listed. A nil presentedCert is a no-op:
// there is no credential to check.
//
// SECURITY: this is the read-through revocation check both renewal paths rely
// on; without it the propagation window does not bound a compromised agent's
// access, for the reason set out below.
//
// Both renewal paths call it, and renewal is the reason it exists. Every other
// decision made from an out-of-date CRL is self-limiting: it admits a revoked
// certificate for at most one sync interval, after which the same certificate
// is rejected. Renewal mints a *new* certificate — fresh serial, full leaf
// validity, every authorisation OID carried forward, and on the CSR path a key
// of the client's choosing — that no CRL will ever list, because the serial the
// renewal revokes is the one it replaces. A revocation racing a renewal on a
// lagging replica would otherwise leave the agent a credential outliving its
// lockout by years, which is not a window anyone would call 60 seconds.
//
// So this path pays for a storage read the general auth path cannot: renewals
// are rare, and the alternative is that the propagation window this CA
// advertises does not actually bound a compromised agent's access.
//
// It also refuses a certificate that a previous renewal already replaced and
// that is waiting out its overlap window — absent from the CRL by design, so
// the revocation check alone would admit it. See refuseIfSuperseded.
//
// A failed refresh is not itself a refusal. The check below still runs against
// the CRL already held, which is exactly the pre-sync behaviour and no worse, so
// a storage blip costs freshness rather than every renewal in the fleet. What
// does refuse is an unusable CRL: IsRevokedSerial errors when none is loaded,
// and that is treated as a denial, matching the middleware.
//
// NIST 800-53: IA-5(2) (PKI-Based Authentication), AC-3 (Access Enforcement)
func (c *CA) refuseIfRevoked(ctx context.Context, presentedCert *x509.Certificate, subject string) error {
	if presentedCert == nil {
		return nil
	}
	if _, err := c.SyncCRLCache(ctx); err != nil {
		// Counted and logged by SyncCRLCache; noted here so the renewal that
		// proceeded on a possibly stale CRL is attributable.
		slog.Warn("Renewal: could not refresh the CRL first; checking against the CRL in memory",
			"subject", subject, "error", err)
	}
	revoked, err := c.IsRevokedSerial(ctx, presentedCert.SerialNumber)
	if err != nil {
		return fmt.Errorf("rejecting renewal for %s: cannot determine revocation status: %w", subject, err)
	}
	if revoked {
		slog.Warn("Renewal: refusing to renew a revoked certificate",
			"subject", subject, "serial", serialHexStr(presentedCert.SerialNumber))
		return fmt.Errorf("rejecting renewal for %s: %w", subject, ErrCertRevoked)
	}
	// A certificate inside its supersession window is deliberately absent from
	// the CRL, so the check above cannot see it. It is still a credential on its
	// way out and must not be able to mint a successor that outlives the window
	// — see refuseIfSuperseded, which is why this sits inside the function both
	// renewal paths call twice rather than at either call site.
	return c.refuseIfSuperseded(ctx, presentedCert, subject)
}

// ErrNotInitialized is returned by signing helpers when the CA's certificate
// or private key has not been loaded — typically because Init has not been
// called or it failed. Exposed as a sentinel so HTTP handlers can detect the
// init-order case via errors.Is and answer with a controlled status (e.g.
// 503 Service Unavailable) rather than treating it as a generic signing
// failure.
var ErrNotInitialized = errors.New("CA not initialized")

// evictRevokedLocked checks whether a certificate already exists for subject.
//   - No cert on disk → returns nil (proceed with issuance).
//   - Cert exists and is NOT revoked → returns ErrCertExists (block issuance).
//   - Cert exists and IS revoked → deletes it and returns nil (allow re-issuance).
//
// c.mu must be held by the caller. This method checks revocation via the
// in-memory CRL cache directly to avoid re-acquiring the lock.
func (c *CA) evictRevokedLocked(ctx context.Context, subject string) error {
	if !c.Storage.HasCert(ctx, subject) {
		return nil
	}

	// Check revocation against cachedCRL directly (no lock acquisition).
	certPEM, err := c.Storage.GetCert(ctx, subject)
	if err != nil {
		return fmt.Errorf("certificate already exists for %s: %w", subject, ErrCertExists)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("certificate already exists for %s: %w", subject, ErrCertExists)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("certificate already exists for %s: %w", subject, ErrCertExists)
	}

	revoked := c.cachedCRL != nil && serialInCRL(c.cachedCRL, cert.SerialNumber)

	if !revoked {
		return fmt.Errorf("certificate already exists for %s: %w", subject, ErrCertExists)
	}
	slog.Debug("Removing revoked certificate", "subject", subject)
	if err := c.Storage.DeleteCert(ctx, subject); err != nil {
		slog.Warn("Could not remove revoked certificate", "subject", subject, "error", err)
	}
	return nil
}

// subjectRegex forbids a leading '-' so a certname can never be misread as a
// flag by an operator's autosign script (argv flag injection); the first
// character must be a letter, digit, underscore, or dot.
//
// COMPATIBILITY: this is deliberately broader than a strict RFC 1123 DNS
// hostname. Puppet certnames are usually FQDNs, but Puppet permits operators
// to configure an arbitrary certname (puppet.conf `certname`), and underscores
// in particular appear in real-world node names even though they are not legal
// DNS labels. Tightening to strict RFC 1123 (rejecting '_', a leading '.', a
// trailing '-', labels >63 chars, names >253 chars) would reject certnames that
// existing deployments may already have signed, so it is held back pending a
// deliberate compatibility decision rather than folded into this hardening pass.
//
// The set permitted here is still path-safe: combined with the explicit ".."
// rejection in ValidateSubject below, a subject can never escape its storage
// directory or be misread as a CLI flag. A leading '.' is permitted by the
// pattern (so an operator-chosen ".name" works) but only ever yields a dotfile
// within the CA's own request/signed directories, never a traversal.
var subjectRegex = regexp.MustCompile(`^[a-z0-9_.][a-z0-9._-]*$`)

// ValidateSubject returns an error if subject contains unsafe characters.
// It is the single source of truth for subject name validation used by both
// the CA layer and the API layer. Rejects path traversal (e.g. "..") and
// any characters outside the safe set. See subjectRegex for the deliberate
// compatibility tradeoff against strict RFC 1123 hostnames.
// NIST 800-53: SI-10 (Information Input Validation)
func ValidateSubject(subject string) error {
	if !subjectRegex.MatchString(subject) || strings.Contains(subject, "..") {
		return fmt.Errorf("invalid subject name %q: must match ^[a-z0-9_.][a-z0-9._-]*$ and must not contain path traversal", subject)
	}
	return nil
}

// ErrForeignCertificate is returned when an operation that is only meaningful
// for a certificate this CA issued is attempted with one it did not issue.
var ErrForeignCertificate = errors.New("certificate was not issued by this CA")

// ErrRenewalSubjectMismatch is returned when the presented certificate is a
// live one of ours, but for a different subject than the one being renewed.
//
// Separate from ErrForeignCertificate deliberately: that sentinel's message
// asserts the certificate is not ours, which would be false here and is the
// kind of false statement its own doc comment argues against. Keeping them
// apart also separates the two in logs — a cross-subject re-key is an
// authenticated caller reaching for another node's identity, while a foreign
// certificate is usually a topology or migration problem.
var ErrRenewalSubjectMismatch = errors.New("presented certificate is for a different subject")

// ErrDisallowedSubjectAltNames is returned when a submitted CSR requests
// Subject Alternative Names that the AllowSubjectAltNames policy does not
// permit.
//
// The message is deliberately generic. It names neither the entries refused nor
// anything else the requester supplied: the specifics go to the CA's log, where
// an operator can read them and the requester cannot. A refusal that listed them
// back would double as an oracle for which names this CA will and will not
// issue, on an endpoint reachable before any certificate has been granted.
var ErrDisallowedSubjectAltNames = errors.New("CSR requests subject alternative names that are not allowed; set allow_subject_alt_names to permit them")

// assertOwnCertificate proves that cert was issued by this CA, and is the
// issuer half of the gate on both renewal paths. The revocation half is
// refuseIfRevoked, which runs immediately after it and re-reads the CRL from
// storage first — fresher than anything this could ask, and the reason the two
// are separate rather than one check.
//
// Neither half checks the validity window. Expiry is the middleware's:
// newAuthMiddleware's Verify call enforces NotBefore/NotAfter against
// time.Now() for every mTLS route, and the own-ca-expired client class in the
// authorisation baseline pins that.
//
// Renewal reissues under this CA's authority using the presented certificate's
// own subject — and, on the empty-body path only, its Puppet OID extensions.
// That is safe only while this CA is the only thing that could have produced
// it: the subject was drawn from a namespace we control, and on that path the
// extensions were vetted by us at issuance. Neither holds for a certificate
// some other CA issued, so renewing one would let its issuer choose names, and
// attributes, inside our namespace.
//
// The CSR path does not rely on prior vetting for its extensions — it takes
// them from the submitted CSR and strips the authorisation arc — but it still
// needs this gate for the subject, which it reissues from the presented
// certificate's namespace.
//
// CheckSignatureFrom answers "did we issue this" with a signature check rather
// than an issuer-name comparison, because a distinguished name is not a
// credential — under a shared root a sibling CA can hold the same one. It
// deliberately says nothing about validity or revocation, which is why
// importcert.go can use it to archive expired certificates; a revoked
// certificate this CA issued satisfies it, and is refused by refuseIfRevoked on
// the next line of both callers.
//
// The caller must NOT hold c.mu.
func (c *CA) assertOwnCertificate(cert *x509.Certificate) error {
	if c.CACert == nil {
		return ErrNotInitialized
	}
	if err := cert.CheckSignatureFrom(c.CACert); err != nil {
		return fmt.Errorf("%w: %v", ErrForeignCertificate, err)
	}
	return nil
}

// Sign creates and persists a certificate for the pending CSR of subject.
// The caller must NOT hold c.mu. Serialises on the cluster-wide per-subject
// lock so concurrent sign attempts from different replicas cannot produce
// two certificates for the same subject.
func (c *CA) Sign(ctx context.Context, subject string) ([]byte, error) {
	if err := ValidateSubject(subject); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, LockTimeout)
	defer cancel()
	var out []byte
	err := c.Storage.WithLock(ctx, subjectLockName(subject), func() error {
		c.mu.Lock()
		defer c.mu.Unlock()
		pem, err := c.signWithDuration(ctx, subject, 0, nil)
		if err != nil {
			return err
		}
		out = pem
		return nil
	})
	return out, err
}

// SignWithTTL signs subject's pending CSR with a custom validity duration.
// ttl=0 falls back to the default certValidity.
// The caller must NOT hold c.mu. Same cross-node guarantees as Sign.
func (c *CA) SignWithTTL(ctx context.Context, subject string, ttl time.Duration) ([]byte, error) {
	if err := ValidateSubject(subject); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, LockTimeout)
	defer cancel()
	var out []byte
	err := c.Storage.WithLock(ctx, subjectLockName(subject), func() error {
		c.mu.Lock()
		defer c.mu.Unlock()
		pem, err := c.signWithDuration(ctx, subject, ttl, nil)
		if err != nil {
			return err
		}
		out = pem
		return nil
	})
	return out, err
}

// sign is the internal (unlocked) signing implementation using the default TTL.
// c.mu must be held by the caller.
func (c *CA) sign(ctx context.Context, subject string) ([]byte, error) {
	return c.signWithDuration(ctx, subject, 0, nil)
}

// asciiLower lowercases A-Z and leaves every other byte alone, which is the
// case-insensitivity DNS actually has. Deliberately not strings.ToLower: see
// sanStrings.
func asciiLower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// sanStrings renders a SAN set as canonical "type:value" strings, so entries of
// different kinds can be compared and reported as one set.
//
// Only DNS names are case-folded, because only DNS names are case-insensitive
// by specification, and they are folded as ASCII rather than as Unicode.
// strings.ToLower folds U+212A KELVIN SIGN to "k", which would make
// "web01<U+212A>" compare equal to the subject "web01k" while the certificate
// carried bytes no TLS peer matches -- an equivalence broader than the
// consumer's, which is the direction a control for refusing names must not fail
// in.
//
// No CSR can reach that, and the reason is worth recording so the same finding
// is not filed twice: dNSName and rfc822Name are IA5Strings, so crypto/x509
// refuses to encode a non-ASCII value into a request at all
// ("cannot be encoded as an IA5String") and rejects one on parse; a URI is
// percent-escaped to ASCII by url.URL.String() before it is encoded. Every
// value arriving here from a parsed CSR is therefore ASCII, where the two folds
// are identical. asciiLower is kept because it is the fold DNS actually
// specifies -- correct by construction rather than by an encoding rule enforced
// two layers away -- and because a future caller building a SAN set in Go
// rather than parsing one would not inherit that guarantee. Email local-parts and URI paths are not, so they are
// compared verbatim: over-folding here would make two entries that a TLS peer
// treats as different compare equal, and every such comparison in this file
// decides whether something is already permitted. Where the normalisation is
// unsure, it must say "different" and let the gate refuse. A URI is compared on
// its unnormalised String() for that reason: two spellings of one resource read
// as two names, and the gate refuses rather than guesses.
//
// IP addresses go through net.IP.String() so the comparison is on a canonical
// form rather than on raw bytes. That is defensive rather than load-bearing:
// every address reaching this function has been through DER, and encoding
// normalises an IPv4 address to four octets, so an IPv4-in-IPv6 spelling has
// already collapsed to the same value by the time it arrives. Nothing on this
// path can observe the difference -- which is why no spec pins it. It stays
// because a future caller that builds a SAN set in Go rather than parsing one
// would not have that guarantee.
func sanStrings(dns []string, ips []net.IP, emails []string, uris []*url.URL) []string {
	out := make([]string, 0, len(dns)+len(ips)+len(emails)+len(uris))
	for _, d := range dns {
		out = append(out, "DNS:"+asciiLower(d))
	}
	for _, ip := range ips {
		out = append(out, "IP:"+ip.String())
	}
	for _, e := range emails {
		out = append(out, "email:"+e)
	}
	for _, u := range uris {
		out = append(out, "URI:"+u.String())
	}
	return out
}

// maxLoggedSANs bounds how many refused entries reach a log record, and
// maxLoggedSANValue how long each one may be. The set is requester-supplied and
// a CSR can carry a great many of them, at whatever length it likes: the body
// cap on the submission endpoint is a mebibyte, so bounding the count alone
// still lets one refused CSR write about that much into a single record, on a
// path reachable without a client certificate. The operator needs enough to
// recognise what was asked for, not all of it.
//
// These mirror maxLoggedValues/maxLoggedValue in internal/api, which bound the
// same class for the same reason. That helper cannot be reused here — internal/api
// imports this package, so the dependency would cycle.
const (
	maxLoggedSANs     = 10
	maxLoggedSANValue = 256
)

// truncateSAN bounds one rendered entry for logging, cutting back to a rune
// boundary so a multi-byte name is not sliced mid-character. Defensive for the
// same reason as the fold above: the IA5String constraint means no multi-byte
// value reaches this from a parsed CSR, so the boundary logic cannot be
// exercised through the signing path and has no spec. It costs three lines and
// makes the function correct for any caller, rather than only for the ones the
// encoding happens to constrain.
func truncateSAN(s string) string {
	if len(s) <= maxLoggedSANValue {
		return s
	}
	cut := maxLoggedSANValue
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "...(truncated)"
}

// checkSubjectAltNames enforces the AllowSubjectAltNames policy against a
// submitted CSR. It is the single gate for every path that signs one, which is
// why it lives on signWithDuration's doorstep rather than at an entry point.
//
// baseline, when non-nil, is the certificate this request renews. SANs it
// already carries were vetted when it was issued, so they are carried forward
// rather than re-judged: without that, turning the policy on would strand
// exactly the nodes it was turned on for — a certificate legitimately holding
// SANs could never be renewed, because its own CSR would be refused. Only
// entries the presented certificate does not already have face the gate, so a
// renewal cannot be used to launder a new name past it.
//
// A DNS entry equal to the subject never counts against a CSR, per RFC 2818
// §3.1 (upstream's SERVER-2338): an agent that puts its own certname in the SAN
// set is complying with the standard, not asking for anything. It is exempt
// wherever it appears rather than only when it appears alone — a CSR asking for
// its own name beside another is refused for the other one, not for its own.
// That is distinct from PromoteCNToSAN, which adds that entry when a CSR
// carries none; this tolerates it when the CSR carries it itself.
func (c *CA) checkSubjectAltNames(subject string, csr *x509.CertificateRequest, baseline *x509.Certificate) error {
	if c.AllowSubjectAltNames {
		return nil
	}
	requested := sanStrings(csr.DNSNames, csr.IPAddresses, csr.EmailAddresses, csr.URIs)
	if len(requested) == 0 {
		return nil
	}

	// Unlike upstream, which reads a CSR's SANs through a helper that
	// enumerates only DNS and IP names — so an email- or URI-only CSR reads as
	// having none and passes its gate untouched — this covers all four kinds
	// crypto/x509 parses.
	//
	// That coverage is enforcement only, and stops at the short-circuit above.
	// signWithDuration threads nothing but DNS names onto the certificate, so
	// with the policy ON a CSR requesting an IP, email or URI SAN signs and
	// loses it silently — #241's defect, not something this gate repairs. What
	// four-kind coverage buys is that with the policy OFF such a request is
	// refused rather than quietly trimmed. When #241 lands and all four kinds
	// are carried through, this comment stops needing the qualification.
	own := "DNS:" + asciiLower(subject)
	carried := make(map[string]struct{})
	if baseline != nil {
		for _, name := range sanStrings(baseline.DNSNames, baseline.IPAddresses, baseline.EmailAddresses, baseline.URIs) {
			carried[name] = struct{}{}
		}
	}

	disallowed := make([]string, 0, len(requested))
	for _, name := range requested {
		if name == own {
			continue
		}
		if _, ok := carried[name]; ok {
			continue
		}
		disallowed = append(disallowed, name)
	}
	if len(disallowed) == 0 {
		return nil
	}

	logged := disallowed
	if len(logged) > maxLoggedSANs {
		logged = logged[:maxLoggedSANs]
	}
	// Bound each surviving entry as well as the list: the count cap alone
	// leaves the record's size in the requester's hands.
	logged = slices.Clone(logged)
	for i := range logged {
		logged[i] = truncateSAN(logged[i])
	}
	slog.Warn("Refusing CSR: requested subject alternative names are not allowed",
		"subject", subject,
		"disallowed", logged,
		"disallowed_count", len(disallowed),
		"renewal", baseline != nil,
		"setting", "allow_subject_alt_names")
	return ErrDisallowedSubjectAltNames
}

// signWithDuration is the actual internal signing implementation.
// ttl=0 means use the default certValidity.
// c.mu must be held by the caller.
func (c *CA) signWithDuration(ctx context.Context, subject string, ttl time.Duration, baseline *x509.Certificate) ([]byte, error) {
	// Fail fast on an uninitialised CA (caller skipped Init(), or it failed)
	// before we bother reading a CSR from storage, so Sign() returns a clear
	// ErrNotInitialized rather than a misleading "CSR not found". The actual
	// c.CACert dereference happens later in issueLeafLocked, which carries the
	// same guard for callers (e.g. AutoRenew) that reach it by other paths.
	if c.CACert == nil || c.CAKey == nil {
		return nil, ErrNotInitialized
	}
	if err := ValidateSubject(subject); err != nil {
		return nil, err
	}

	slog.Debug("Signing certificate", "subject", subject)

	csrPEM, err := c.Storage.GetCSR(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("CSR not found for %s: %w", subject, err)
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CSR PEM for %s", subject)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR for %s: %w", subject, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid CSR signature for %s: %w", subject, err)
	}

	// The key-strength policy is enforced by issueLeafLocked, the tail every
	// issuance path shares, so a submitted CSR carrying a weak key is rejected
	// there rather than here.

	// SECURITY: Reject CSRs that request CA capabilities (BasicConstraints:
	// CA:TRUE, OID 2.5.29.19). Without this check a submitted CSR could produce
	// a subordinate CA certificate, enabling the holder to sign arbitrary certs.
	// NIST 800-53: CM-7 (Least Functionality), IA-5(2) (PKI-Based Authentication)
	oidBasicConstraints := asn1.ObjectIdentifier{2, 5, 29, 19}
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(oidBasicConstraints) {
			var bc struct {
				IsCA bool `asn1:"optional"`
			}
			if _, err := asn1.Unmarshal(ext.Value, &bc); err == nil && bc.IsCA {
				return nil, fmt.Errorf("found extensions that disallow signing: [2.5.29.19]")
			}
		}
	}

	// SECURITY: refuse a CSR that names anything it has not been permitted to
	// name, before any of it reaches a certificate template. TLS peers match on
	// the SAN set, so an unconstrained request here is a request to be somebody
	// else — including this CA's own server name.
	// NIST 800-53: AC-6 (Least Privilege), IA-5(2) (PKI-Based Authentication)
	if err := c.checkSubjectAltNames(subject, csr, baseline); err != nil {
		return nil, err
	}

	dnsNames := csr.DNSNames
	// RFC 2818 §3.1: TLS clients match the server name against SANs, not the
	// CN. When the CSR carries no SANs and promotion is enabled, add the CN as
	// a DNS SAN so that the issued certificate works with modern TLS stacks.
	if c.PromoteCNToSAN && len(dnsNames) == 0 && csr.Subject.CommonName != "" {
		dnsNames = []string{csr.Subject.CommonName}
	}

	// SECURITY: Copy Puppet OID extensions from the CSR, excluding
	// authorization-arc OIDs (1.3.6.1.4.1.34380.1.3.*). Allowing CSRs to
	// inject auth OIDs like pp_cli_auth would let any agent request admin
	// privileges, which is a direct privilege escalation.
	// NIST 800-53: AC-6 (Least Privilege), CM-7 (Least Functionality)
	var extraExtensions []pkix.Extension
	for _, ext := range csr.Extensions {
		if IsPuppetOID(ext.Id) && !IsAuthOID(ext.Id) {
			extraExtensions = append(extraExtensions, ext)
		}
	}

	certPEM, err := c.issueLeafLocked(ctx, subject, csr.Subject, csr.PublicKey, subjectAltNames{DNSNames: dnsNames}, extraExtensions, ttl)
	if err != nil {
		return nil, err
	}

	// Remove the pending CSR now that we have a signed cert.
	if err := c.Storage.DeleteCSR(ctx, subject); err != nil {
		slog.Warn("Could not delete CSR after signing", "subject", subject, "error", err)
	}

	return certPEM, nil
}

// subjectAltNames carries the full set of Subject Alternative Name entries
// copied onto an issued leaf certificate. Bundling them keeps issueLeafLocked's
// signature manageable and ensures every SAN type is threaded through together,
// rather than DNS names alone.
type subjectAltNames struct {
	DNSNames       []string
	IPAddresses    []net.IP
	EmailAddresses []string
	URIs           []*url.URL
}

// issueLeafLocked builds, signs, and persists a leaf certificate for subject
// from the given public key, SANs, and extra (Puppet OID) extensions, then
// appends the inventory entry and updates the in-memory serial index.
// ttl=0 means use the default certValidity. c.mu must be held by the caller.
//
// This is the tail shared by signWithDuration (inputs come from a submitted
// CSR, after CSR-specific validation), AutoRenew (inputs come from an
// already-issued certificate's public key, with no CSR involved at all), and
// GenerateWithOptions (inputs come from a key this CA just generated, with no
// client involved at all).
func (c *CA) issueLeafLocked(ctx context.Context, subject string, subjectName pkix.Name, pubKey any, sans subjectAltNames, extraExtensions []pkix.Extension, ttl time.Duration) ([]byte, error) {
	// Defensive: a nil CACert here means the caller skipped Init() (or it
	// failed). Without this guard the c.CACert.NotAfter dereference below
	// would panic the entire frontend.
	if c.CACert == nil || c.CAKey == nil {
		return nil, ErrNotInitialized
	}

	// SECURITY: Enforce the CA's key-strength policy (RSA >= 2048, ECDSA on an
	// approved NIST curve), mirroring the policy ValidateKeyConfig applies to
	// server-side key generation. This is the issuance chokepoint every path
	// shares — a submitted CSR (signWithDuration), an already-issued
	// certificate's key (AutoRenew), and a freshly generated one
	// (GenerateWithOptions) — so no signing path can produce a certificate over
	// a weak key without deleting this check. It runs before the serial is
	// allocated and before anything is written, so a rejected key consumes
	// nothing. NIST 800-53: SC-12, SC-13 (Cryptographic Protection)
	if err := validatePublicKey(pubKey); err != nil {
		return nil, fmt.Errorf("rejecting certificate for %s: %w", subject, err)
	}

	// SECURITY: Generate a random 128-bit serial number (CA/Browser Forum guidance).
	// NIST 800-53: SC-12 (Cryptographic Key Establishment and Management)
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialInt, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial for %s: %w", subject, err)
	}
	serialStr := serialHexStr(serialInt)

	now := time.Now().UTC()

	validity := certValidity
	if ttl > 0 {
		validity = ttl
	} else if c.LeafValidityDays > 0 {
		validity = time.Duration(c.LeafValidityDays) * 24 * time.Hour
	}

	// Cap validity to the CA certificate's remaining lifetime.
	// A leaf cert must never outlive the CA that signed it; if it did, the cert
	// would appear valid after the CA cert expired, breaking chain verification.
	caRemaining := time.Until(c.CACert.NotAfter)
	if caRemaining <= 0 {
		return nil, fmt.Errorf("ca certificate has expired")
	}
	validity = min(validity, caRemaining)

	// SubjectKeyIdentifier: SHA1 of the SubjectPublicKeyInfo DER (RFC 5280 §4.2.1.2).
	pubKeyDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key for %s: %w", subject, err)
	}
	subjectKeyID := sha1.Sum(pubKeyDER)

	template := &x509.Certificate{
		SerialNumber: serialInt,
		Subject:      subjectName,
		NotBefore:    now.Add(-24 * time.Hour),
		NotAfter:     now.Add(validity),

		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},

		BasicConstraintsValid: true,
		IsCA:                  false,

		SubjectKeyId:   subjectKeyID[:],
		AuthorityKeyId: c.CACert.SubjectKeyId,

		DNSNames:       sans.DNSNames,
		IPAddresses:    sans.IPAddresses,
		EmailAddresses: sans.EmailAddresses,
		URIs:           sans.URIs,
	}

	// CRL Distribution Points: embed CRL URL(s) when configured so that
	// verifiers can automatically fetch the CRL (RFC 5280 §4.2.1.13).
	if len(c.CRLURLs) > 0 {
		template.CRLDistributionPoints = c.CRLURLs
	}

	// Authority Information Access: embed OCSP URL when configured.
	if len(c.OCSPURLs) > 0 {
		aiaValue, err := buildAIAExtension(c.OCSPURLs)
		if err != nil {
			return nil, fmt.Errorf("failed to build AIA extension for %s: %w", subject, err)
		}
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
			Id:    OIDAIA,
			Value: aiaValue,
		})
	}

	template.ExtraExtensions = append(template.ExtraExtensions, extraExtensions...)

	// SECURITY: two complementary controls guard against signing under a key
	// that doesn't match the CA certificate (e.g. an OpenBao Transit key
	// rotated out from under a running CA):
	//   1. loadCA pins c.CAKey.Public() to c.CACert at startup (init.go), so a
	//      key that already doesn't match the CA cert is caught before serving.
	//   2. x509.CreateCertificate re-verifies the signature the signer returned
	//      against c.CAKey.Public() before handing the certificate back. So if
	//      the provider's key is rotated while running — the cached Public()
	//      still matches the CA cert, but the provider now signs with the new
	//      key — the returned signature fails that re-verification and this
	//      call errors rather than emitting a certificate no verifier could
	//      validate. (CreateCertificate does not itself compare priv.Public()
	//      against the parent cert; control 1 is what ties the key to the cert.)
	// For the OpenBao provider the signer additionally self-verifies the
	// returned signature against its published public key (see
	// verifyTransitSignature), so the same drift surfaces as a clear error at
	// the signer too. This is a purely in-process check: no extra provider
	// round trip, and under key isolation no RPC beyond the one Sign this call
	// already makes.
	// NIST 800-53: SC-12 (Cryptographic Key Establishment and Management)
	// Take a CA-key signing slot for the signature below. Issuance queues for
	// one rather than shedding: the client asked for this certificate and is
	// authenticated, so refusing it to protect an unauthenticated responder
	// would be the wrong way round. The wait honours ctx, so a client that has
	// given up does not leave this holding c.mu on its behalf — see
	// signbound.go, where that is half of what makes waiting here safe.
	if err := c.acquireSigningSlot(ctx); err != nil {
		return nil, fmt.Errorf("waiting for a CA signing slot to sign for %s: %w", subject, err)
	}
	// Released by a deferred call inside this closure; see releaseSigningSlot.
	// The same shape rule 4 of docs/development/locking.md prescribes for the
	// mutexes, and for the same reason: a panic must not wedge the thing it was
	// holding.
	certBytes, err := func() ([]byte, error) {
		defer c.releaseSigningSlot()
		return x509.CreateCertificate(rand.Reader, template, c.CACert, pubKey, c.CAKey)
	}()
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate for %s: %w", subject, err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	if err := c.Storage.SaveCert(ctx, subject, certPEM); err != nil {
		return nil, fmt.Errorf("failed to save cert for %s: %w", subject, err)
	}

	// Denormalise the display projection for the certificate index from the
	// certificate as actually signed (parsed back from the DER, not the
	// template, so the recorded extensions are exactly what verifiers see).
	// A parse failure here is unreachable for bytes CreateCertificate just
	// produced; degrade to a projection-less record rather than failing the
	// issuance.
	var proj *storage.CertProjection
	if signedCert, perr := x509.ParseCertificate(certBytes); perr == nil {
		p := certProjectionFor(signedCert)
		proj = &p
	} else {
		slog.Warn("Failed to parse just-signed certificate for index projection",
			"subject", subject, "error", perr)
	}

	inventoryEntry := storage.FormatInventoryLine(serialStr, template.NotBefore, template.NotAfter, subject)
	if err := c.Storage.AppendInventoryRecord(ctx, inventoryEntry, proj); err != nil {
		// Roll back the cert so storage and inventory stay in sync. Log but don't
		// propagate the cleanup error; the caller already has an error to handle.
		if delErr := c.Storage.DeleteCert(ctx, subject); delErr != nil {
			slog.Warn("Failed to roll back cert after inventory write failure",
				"subject", subject, "error", delErr)
		}
		return nil, fmt.Errorf("failed to update inventory for %s: %w", subject, err)
	}

	// Update in-memory serial index for O(1) OCSP lookups.
	c.indexSerialLocked(serialStr, subject)

	slog.Debug("Certificate signed",
		"subject", subject,
		"serial", serialStr,
		"not_before", template.NotBefore.Format(time.RFC3339),
		"not_after", template.NotAfter.Format(time.RFC3339),
	)
	return certPEM, nil
}

// Clean revokes (if signed) and removes both the certificate and any pending CSR
// for subject. It is the "puppet cert clean" equivalent: the subject must have at
// least a cert or CSR on disk, otherwise ErrNotFound is returned.
//
// Errors from individual operations (revoke, delete) are best-effort and logged
// but do not prevent the others from running.
var ErrNotFound = fmt.Errorf("certificate or CSR not found")

func (c *CA) Clean(ctx context.Context, subject string) error {
	if err := ValidateSubject(subject); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, LockTimeout)
	defer cancel()

	// Hold the per-subject lock for the entire check+revoke+delete sequence to
	// prevent TOCTOU races with concurrent Sign() or SaveRequest() calls. Without
	// the lock, a Sign() completing between HasCert() and DeleteCert() would leave
	// an unrevoked certificate in storage after Clean() returns.
	//
	// Lock ordering: subject-lock (distributed) → CRL-lock (distributed) → c.mu.
	// No existing code path acquires CRL-lock then subject-lock, so no deadlock.
	lockErr := c.Storage.WithLock(ctx, subjectLockName(subject), func() error {
		hasCert := c.Storage.HasCert(ctx, subject)
		hasCSR := c.Storage.HasCSR(ctx, subject)

		if !hasCert && !hasCSR {
			return ErrNotFound
		}

		if hasCert {
			// Revoke first so the CRL is updated before the file is removed.
			// Acquire the CRL lock directly here (inside the subject lock) and
			// call revokeLocked to avoid double-locking via the public Revoke().
			// Deliberately not withCRLLockCounted. Most failures inside this
			// closure are already counted -- revokeLocked and signCRLLocked both
			// do it -- so what
			// wrapping would add is the arm where the lock could not be taken at
			// all, and a contended lock during a best-effort revoke is not a
			// revocation that did not happen. Note revokeLocked has its own
			// uncounted arm besides, and hasCert above is what makes it
			// interesting: the certificate is in storage, so reaching
			// revokeLocked's fs.ErrNotExist means the *inventory* has no entry
			// for it. That divergence is classed as never-issued rather than as
			// a failed revocation. docs/metrics.md names this path as uncounted
			// on the lock arm.
			if err := c.Storage.WithLock(ctx, lockNameCRL, func() error {
				c.mu.Lock()
				defer c.mu.Unlock()
				return c.revokeLocked(ctx, subject)
			}); err != nil {
				// Deliberately not fatal: clean's job is to remove the
				// certificate. But say what that leaves behind — the
				// certificate is gone from storage while still unrevoked, so
				// it remains a valid credential until it expires. A foreign
				// stored CRL now reaches here (readStoredCRL refuses to
				// re-sign a list this CA did not issue), which is a newly
				// reachable way into this state and is fixed by restarting
				// the replica that holds the stale CA certificate.
				slog.Warn("Clean: revoke failed, deleting the certificate anyway; it stays a valid "+
					"credential until it expires", "subject", subject, "error", err)
			}
			if err := c.Storage.DeleteCert(ctx, subject); err != nil {
				slog.Warn("Clean: delete cert failed", "subject", subject, "error", err)
			}
		}

		if hasCSR {
			if err := c.Storage.DeleteCSR(ctx, subject); err != nil {
				slog.Warn("Clean: delete CSR failed", "subject", subject, "error", err)
			}
		}

		return nil
	})
	if lockErr != nil {
		return lockErr
	}

	slog.Debug("Certificate cleaned", "subject", subject)
	return nil
}

// SignResult holds the outcome of a bulk signing operation.
type SignResult struct {
	Signed        []string `json:"signed"`
	NoCSR         []string `json:"no-csr"`
	SigningErrors []string `json:"signing-errors"`
}

// SignMultiple signs the CSRs for the given subjects.
// Subjects with no pending CSR are collected in NoCSR; those that fail signing
// are collected in SigningErrors.
func (c *CA) SignMultiple(ctx context.Context, subjects []string) SignResult {
	result := SignResult{
		Signed:        []string{},
		NoCSR:         []string{},
		SigningErrors: []string{},
	}
	for _, subject := range subjects {
		if !c.Storage.HasCSR(ctx, subject) {
			result.NoCSR = append(result.NoCSR, subject)
			continue
		}
		if _, err := c.Sign(ctx, subject); err != nil {
			slog.Warn("Bulk sign failed", "subject", subject, "error", err)
			result.SigningErrors = append(result.SigningErrors, subject)
		} else {
			result.Signed = append(result.Signed, subject)
		}
	}
	return result
}

// SignAll signs every pending CSR currently on disk.
func (c *CA) SignAll(ctx context.Context) (SignResult, error) {
	subjects, err := c.Storage.ListCSRs(ctx)
	if err != nil {
		return SignResult{}, fmt.Errorf("listing CSRs: %w", err)
	}
	return c.SignMultiple(ctx, subjects), nil
}

// CleanResult holds the outcome of a bulk clean operation.
type CleanResult struct {
	Cleaned     []string `json:"cleaned"`
	NotFound    []string `json:"not-found"`
	CleanErrors []string `json:"clean-errors"`
}

// CleanMultiple revokes and removes the cert and CSR for each subject.
// Subjects not found are collected in NotFound; other errors in CleanErrors.
func (c *CA) CleanMultiple(ctx context.Context, subjects []string) CleanResult {
	result := CleanResult{
		Cleaned:     []string{},
		NotFound:    []string{},
		CleanErrors: []string{},
	}
	for _, subject := range subjects {
		if err := c.Clean(ctx, subject); err != nil {
			if errors.Is(err, ErrNotFound) {
				result.NotFound = append(result.NotFound, subject)
			} else {
				slog.Warn("Bulk clean failed", "subject", subject, "error", err)
				result.CleanErrors = append(result.CleanErrors, subject)
			}
		} else {
			result.Cleaned = append(result.Cleaned, subject)
		}
	}
	return result
}

// SaveRequest validates, persists the CSR, and triggers autosigning if configured.
func (c *CA) SaveRequest(ctx context.Context, subject string, csrPEM []byte) (bool, error) {
	if err := ValidateSubject(subject); err != nil {
		return false, err
	}

	// Validate the CSR PEM before writing anything to disk.
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return false, fmt.Errorf("failed to decode CSR PEM for %s", subject)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse CSR for %s: %w", subject, err)
	}

	// SECURITY: Verify the CSR's proof-of-possession signature before storing.
	// Without this check an attacker can submit a CSR with someone else's
	// public key (identity theft). The signature proves the submitter holds
	// the private key corresponding to the CSR's public key.
	// NIST 800-53: IA-5(2) (PKI-Based Authentication)
	if err := csr.CheckSignature(); err != nil {
		return false, fmt.Errorf("invalid CSR signature for %s: %w", subject, err)
	}

	// SECURITY: CN in the CSR must match the URL subject. Without this check
	// an attacker could submit a CSR for "admin.example.com" via the URL path
	// for "node1.example.com", obtaining a certificate for a different identity.
	// NIST 800-53: IA-5(2) (PKI-Based Authentication), SI-10 (Information Input Validation)
	if csr.Subject.CommonName != subject {
		return false, fmt.Errorf("instance name %s does not match requested key %s",
			csr.Subject.CommonName, subject)
	}

	// SECURITY: Warn if the CSR carries authorization-arc OIDs. These will be
	// stripped during signing but the submission itself is suspicious and may
	// indicate a privilege escalation attempt.
	// NIST 800-53: AU-6 (Audit Record Review, Analysis, and Reporting)
	for _, ext := range csr.Extensions {
		if IsAuthOID(ext.Id) {
			slog.Warn("CSR contains authorization extension that will be stripped",
				"subject", subject, "oid", ext.Id.String())
		}
	}

	slog.Debug("Received CSR", "subject", subject)

	// Acquire the cluster-wide per-subject lock for the entire evict + save +
	// autosign sequence. This prevents TOCTOU races where two concurrent
	// SaveRequest calls (same or different replicas) both pass eviction and
	// produce duplicate certificates.
	ctx, cancel := context.WithTimeout(ctx, LockTimeout)
	defer cancel()
	var autosigned bool
	lockErr := c.Storage.WithLock(ctx, subjectLockName(subject), func() error {
		c.mu.Lock()
		defer c.mu.Unlock()

		// Reject if a cert already exists and is not revoked; clear it if
		// revoked so the node can re-register with a fresh key.
		if err := c.evictRevokedLocked(ctx, subject); err != nil {
			return err
		}

		if err := c.Storage.SaveCSR(ctx, subject, csrPEM); err != nil {
			return fmt.Errorf("failed to save CSR for %s: %w", subject, err)
		}

		shouldSign, err := CheckAutosign(c.AutosignConfig, csr, csrPEM)
		if err != nil {
			return fmt.Errorf("autosign check failed for %s: %w", subject, err)
		}

		if shouldSign {
			slog.Debug("Autosigning CSR", "subject", subject)
			if _, err := c.sign(ctx, subject); err != nil {
				return err
			}
			autosigned = true
			return nil
		}

		slog.Debug("CSR saved, awaiting manual signing", "subject", subject)
		return nil
	})
	if lockErr != nil {
		return false, lockErr
	}
	return autosigned, nil
}

// ErrNoCSR is returned by DeleteRequest when subject has no pending CSR. A
// sentinel because the HTTP layer has to separate "there was nothing to delete"
// from "the deletion could not be performed": answering 404 to both tells the
// operator the request is gone at the very moment it is still there and still
// signable.
var ErrNoCSR = errors.New("no pending CSR")

// DeleteRequest removes the pending CSR for subject — the operator rejecting a
// request rather than signing it.
//
// The delete runs under the cluster-wide per-subject lock, which is what makes
// it an ordering rather than a race. Sign, SignWithTTL and SaveRequest's
// autosign all read the CSR inside that lock and write the certificate later
// in the same critical section, so an unlocked delete could land in between:
// the request the operator rejected was signed anyway, and the 204 told them
// otherwise. It also stops the delete landing inside SaveRequest's
// evict/save/autosign section, where it turned an agent's submission into a
// "CSR not found" failure.
//
// The two orderings the lock leaves are both answers rather than races. A
// delete that wins the lock against a pending Sign leaves it nothing to sign,
// and it fails with ErrNoCSR. A delete that loses usually finds the CSR
// already gone — signWithDuration removes it once the certificate is stored —
// so it returns ErrNoCSR too, and the operator gets a 404 with the certificate
// issued. That removal is best-effort and only warns on failure, so when it
// fails this delete removes the CSR instead and answers 204 for a subject that
// already has a certificate. What the lock rules out is the case that made
// this a bug: a 204 concurrent with an issuance for the same request.
//
// The caller must NOT hold c.mu, and this takes no CA-level lock: a pending CSR
// backs no in-memory cache, so there is nothing to keep in step with the write.
//
// Lock ordering: the subject lock only, nothing nested — see
// docs/development/locking.md.
func (c *CA) DeleteRequest(ctx context.Context, subject string) error {
	if err := ValidateSubject(subject); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, LockTimeout)
	defer cancel()

	if err := c.Storage.WithLock(ctx, subjectLockName(subject), func() error {
		if err := c.Storage.DeleteCSR(ctx, subject); err != nil {
			// Backend.Delete wraps os.ErrNotExist when the key is absent; any
			// other error is a backend fault, not an empty queue.
			if errors.Is(err, fs.ErrNotExist) {
				return ErrNoCSR
			}
			return fmt.Errorf("failed to delete CSR for %s: %w", subject, err)
		}
		return nil
	}); err != nil {
		return err
	}

	slog.Debug("Certificate request deleted", "subject", subject)
	return nil
}

// Renew issues a replacement certificate for subject from the provided CSR,
// bypassing the pending-CSR queue and autosign check. The existing certificate
// (if any) is replaced atomically under the per-subject distributed lock, and
// retired once its successor is safely signed and stored: a CSR-based renewal
// is a genuine re-key, so the old key/cert must not remain a valid credential
// once the new one takes over.
//
// "Retired" is immediate revocation unless CA.SupersedeAfter is set, in which
// case the replaced serial is recorded for revocation that far in the future
// and a sweep performs it — see supersedeReplaced. Note what a delay costs on
// this path in particular: because this is a re-key, the window leaves the
// *previous private key* usable as well as the previous certificate. That is
// the price of an overlap in which relying parties can pick up the replacement,
// and it is why the delay is off by default.
//
// presentedCert is the client certificate the caller authenticated with. It is
// required, and it must be one this CA issued and has not revoked: renewal
// mints a new credential from an old one, so the old one has to be ours. A nil,
// foreign or revoked certificate returns ErrForeignCertificate.
//
// It must also be the certificate *for* subject. Renewing one subject while
// presenting another's returns ErrRenewalSubjectMismatch. Callers map both to
// 403.
//
// The caller is responsible for verifying that the CSR CN matches the
// authenticated client's CN before calling Renew; this method enforces that
// invariant a second time as defence-in-depth.
//
// presentedCert is the certificate the client authenticated with, and is
// re-checked against the CRL in storage before anything is issued — see
// refuseIfRevoked. It matters more here than on the auto-renewal path: this one
// also re-keys, so a revoked agent slipping through would walk away with a
// credential the CA has never seen the private key of.
//
// A nil presentedCert skips that check, because there is no credential to
// check. That is not a way to opt out of it: the HTTP layer reaches this only
// through the tierAnyClient middleware, which has already established a peer
// certificate, and passes it. Nil is for callers with no authenticated peer at
// all — today, only tests.
func (c *CA) Renew(ctx context.Context, subject string, csrPEM []byte, presentedCert *x509.Certificate) ([]byte, error) {
	// SECURITY: only a certificate this CA issued may be renewed. Without this
	// the CN check below constrains the caller to a name some *other* CA gave
	// them, while the certificate produced is issued by us — so a foreign
	// issuer's namespace would become ours, and any name it hands out could be
	// claimed here, including one already held by an agent.
	//
	// Ahead of ValidateSubject on purpose. Once a second issuer is trusted for
	// client authentication, a foreign certificate is the one least likely to
	// respect this CA's lowercase certname grammar — and ValidateSubject
	// returns an unsentinelled error the handler can only render as a 500. The
	// provenance question has to be answered first for the refusal to come out
	// as the 403 the gate exists to give.
	// NIST 800-53: AC-6 (Least Privilege), IA-5(2) (PKI-Based Authentication)
	if presentedCert == nil {
		return nil, fmt.Errorf("%w: no client certificate was presented", ErrForeignCertificate)
	}
	if err := c.assertOwnCertificate(presentedCert); err != nil {
		return nil, err
	}
	if err := c.refuseIfRevoked(ctx, presentedCert, subject); err != nil {
		return nil, err
	}
	// SECURITY: and it must be *this* subject's certificate. Provenance alone
	// says the caller holds something we issued, not that they hold the thing
	// they are renewing — without this, any live certificate we issued could
	// re-key any other subject and revoke the incumbent's.
	//
	// The one shipping caller cannot trip this: it passes subject=clientCN and
	// the same certificate, so it satisfies the invariant by construction
	// rather than by checking it. (What the handler does check is the CSR's CN
	// against the client's.) That is precisely why the check belongs here —
	// the guarantee should not rest on every future caller happening to pass
	// the two consistently.
	// NIST 800-53: AC-3 (Access Enforcement), IA-5(2) (PKI-Based Authentication)
	if presentedCert.Subject.CommonName != subject {
		return nil, fmt.Errorf("%w: presented certificate is for %q, not %q",
			ErrRenewalSubjectMismatch, presentedCert.Subject.CommonName, subject)
	}

	// After the gate: this guards a caller-supplied string that becomes a
	// storage path, so it still has to run.
	if err := ValidateSubject(subject); err != nil {
		return nil, err
	}

	// Validate and parse the CSR before acquiring any lock.
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CSR PEM for %s", subject)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR for %s: %w", subject, err)
	}
	// SECURITY: Verify the CSR's proof-of-possession signature.
	// NIST 800-53: IA-5(2) (PKI-Based Authentication)
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid CSR signature for %s: %w", subject, err)
	}
	// SECURITY: CN must match subject — defence-in-depth; handler also checks.
	// NIST 800-53: IA-5(2) (PKI-Based Authentication), SI-10 (Information Input Validation)
	if csr.Subject.CommonName != subject {
		return nil, fmt.Errorf("CSR CN %q does not match subject %q", csr.Subject.CommonName, subject)
	}

	ctx, cancel := context.WithTimeout(ctx, LockTimeout)
	defer cancel()
	var out []byte
	err = c.Storage.WithLock(ctx, subjectLockName(subject), func() error {
		// SECURITY: ask the revocation question again, now the lock is held.
		// The gate above answered it before this Storage.WithLock, and
		// acquiring that lock can take a while — see StorageService.WithLock's
		// godoc for what that wait is, and is not, bounded by. A revocation
		// landing inside the window would otherwise be outrun: the gate has
		// already decided, and nothing between it and the signing below looks
		// again.
		//
		// This is deliberately the second storage read of the CRL on this path:
		// refuseIfRevoked syncs the cache unconditionally, so the gate now costs
		// two GetCRLs and two signature checks rather than one, and this one is
		// inside the critical section. (The revoke step below adds a third of
		// each whenever it retires a predecessor, which is the ordinary case.)
		// Both earn their place. The gate above
		// turns a revoked agent away before it queues on a lock this change
		// makes slower to get, and only this one is authoritative, because only
		// this one runs where nothing can revoke behind it. Renewals are rare
		// (see refuseIfRevoked's godoc), so the extra parse under a contended
		// lock is the cheaper of the two costs.
		// NIST 800-53: IA-5(2) (PKI-Based Authentication), AC-3 (Access Enforcement)
		if err := c.refuseIfRevoked(ctx, presentedCert, subject); err != nil {
			return err
		}

		// Capture the serial of the certificate being replaced, if any, before
		// signing overwrites the cert blob and appends a new inventory row —
		// afterwards LatestSerialForSubject would resolve to the *new* serial,
		// not the one being retired.
		oldSerial, hadOldCert := "", false
		switch s, err := c.Storage.LatestSerialForSubject(ctx, subject); {
		case err == nil:
			oldSerial, hadOldCert = s, true
		case !errors.Is(err, fs.ErrNotExist):
			return fmt.Errorf("looking up existing certificate for %s: %w", subject, err)
		}

		// Save the renewal CSR and sign the replacement while holding c.mu,
		// releasing it via defer before the revoke step below re-acquires it
		// (c.mu is non-reentrant). The closure keeps the unlock panic-safe: a
		// panic mid-sign still frees the lock rather than wedging the CA.
		certPEM, err := func() ([]byte, error) {
			c.mu.Lock()
			defer c.mu.Unlock()
			if err := c.Storage.SaveCSR(ctx, subject, csrPEM); err != nil {
				return nil, fmt.Errorf("saving renewal CSR: %w", err)
			}
			// The certificate being renewed is the baseline: SANs it already
			// carries are carried forward, anything new faces the gate.
			//
			// SECURITY: that is only safe because presentedCert has been
			// authenticated by the time it gets here — issued by us, not
			// revoked, and for this subject. The revocation half of that is
			// asked twice, and the second ask (above, inside this lock) is what
			// this depends on: the first answers before the lock is acquired,
			// so on its own a revocation landing in that window would be
			// outrun, and a revoked agent's SAN set would become a baseline
			// that carries its names onto a fresh certificate. Do not collapse
			// the two checks into one on the grounds that they look redundant.
			// NIST 800-53: IA-5(2) (PKI-Based Authentication), AC-3 (Access Enforcement)
			return c.signWithDuration(ctx, subject, 0, presentedCert)
		}()
		if err != nil {
			return err
		}
		out = certPEM

		if !hadOldCert {
			return nil
		}
		// Retire the certificate just replaced so its serial can no longer pass
		// CRL/OCSP checks now that it is no longer the cert served for this
		// subject. With SupersedeAfter unset that is an immediate revocation,
		// as it always was; with a delay configured the serial is recorded and
		// the sweep revokes it later — see supersedeReplaced, and note that on
		// this path the delay leaves the *replaced key* usable for the window
		// too, since a CSR-based renewal re-keys.
		//
		// Best-effort either way, like Clean's revoke-then-delete: a failure
		// here shouldn't undo the renewal the caller is waiting on.
		// Lock ordering: subject-lock (held) -> CRL-lock -> c.mu, matching Clean.
		if err := c.supersedeReplaced(ctx, subject, oldSerial); err != nil {
			// The failure is already counted — into crlUpdateFailures by
			// revokeSerialLocked/signCRLLocked on the immediate path, and into
			// supersedeFailures on the delayed one. Here we only note it and
			// let the renewal stand.
			slog.Warn("Renew: failed to retire replaced certificate", "subject", subject, "serial", oldSerial, "error", err)
		}
		return nil
	})
	return out, err
}

// AutoRenew reissues a certificate for the same public key as presentedCert —
// the certificate that authenticated this request over mTLS — instead of
// requiring a fresh CSR. This is the wire-compatible counterpart to the "no
// CSR" renewal flow real Puppet/OpenVox agents use by default (see
// Puppet's `hostcert_renewal_interval`, default 30 days): the mTLS handshake
// already proved possession of the private key, so a second
// proof-of-possession isn't required. presentedCert's SANs and Puppet OID
// extensions — including any auth OIDs such as pp_cli_auth — are carried
// forward verbatim, since they were already vetted when presentedCert itself
// was issued; only the serial, validity window, and key identifiers are
// refreshed.
//
// That vetting argument holds only because assertOwnCertificate has
// already established that this CA issued presentedCert. The two are a pair:
// removing the issuer gate while keeping the unfiltered carry-forward would let
// any CA trusted for client authentication have a pp_cli_auth certificate
// reissued under *our* authority here, so that it survives as ours.
//
// Note what this does not close. isAdmin reads pp_cli_auth straight off
// whatever certificate the middleware admitted, without regard to issuer, so
// once a second anchor is trusted for client authentication a foreign leaf
// carrying pp_cli_auth is already an admin — no reissue needed. Binding
// isAdmin to certificates this CA issued is a separate control the
// multi-anchor work still has to add; this gate does not substitute for it.
//
// By default the certificate being replaced is revoked once its successor is
// safely signed and stored, so only the newest serial for a subject is ever
// valid (see c.RevokeOnAutoRenew). OpenVox Server's own Clojure CA
// (renew-certificate! in certificate_authority.clj) does not do this — both
// the old and new certificates (same key) remain valid until the old one
// naturally expires; set RevokeOnAutoRenew to false to match that exactly.
//
// CA.SupersedeAfter sits between those two: the predecessor is still retired,
// but after a delay rather than in this call. RevokeOnAutoRenew decides
// whether; SupersedeAfter decides when.
//
// The caller must NOT hold c.mu. Same cross-node guarantees as Sign.
func (c *CA) AutoRenew(ctx context.Context, presentedCert *x509.Certificate) ([]byte, error) {
	// Guarded before the dereference, and for the same reason as Renew's: a
	// caller that reaches here without a client certificate has no identity to
	// renew, and panicking on it would turn an authorisation question into a
	// crash.
	if presentedCert == nil {
		return nil, fmt.Errorf("%w: no client certificate was presented", ErrForeignCertificate)
	}
	// SECURITY: only a certificate this CA issued may be renewed. The
	// carry-forward of authorisation OIDs below depends on it; see
	// assertOwnCertificate. Ahead of ValidateSubject for the reason given
	// in Renew: a foreign certificate's CN need not be certname-shaped, and
	// answering grammar first would turn the gate's 403 into a 500.
	// NIST 800-53: AC-6 (Least Privilege), IA-5(2) (PKI-Based Authentication)
	if err := c.assertOwnCertificate(presentedCert); err != nil {
		return nil, err
	}

	subject := presentedCert.Subject.CommonName
	if err := ValidateSubject(subject); err != nil {
		return nil, err
	}

	// Revocation ahead of the key-strength policy, and in the same order as
	// Renew. Both checks refuse, so the order only decides which answer the
	// client is given — and for a certificate that is both revoked and below
	// policy, "renew with a new CSR" (422) is the wrong one: it points a revoked
	// identity at the re-key path without mentioning that it is revoked. A
	// revoked certificate is refused as revoked, whatever else is wrong with it.
	//
	// That ordering still holds now the key-strength check has moved into
	// issueLeafLocked, which this path reaches only after the refusal above:
	// the policy check is enforced no less, but it can no longer answer first.
	if err := c.refuseIfRevoked(ctx, presentedCert, subject); err != nil {
		return nil, err
	}

	// The key-strength policy is enforced by issueLeafLocked, the tail every
	// issuance path shares. It matters most on this path: a cert imported from
	// a legacy CA (see the migrate command) may predate this CA's key policy,
	// and auto-renewal must not be a backdoor to indefinitely extend a
	// substandard key — the operator/agent should re-key via the CSR-based Renew
	// path instead. The rejection now happens after the subject lock is taken
	// rather than before it, which is acceptable: this route is
	// mTLS-authenticated and the lock is scoped to the caller's own subject.
	//
	// A pointer, not a control: this is deliberately a plain comment, matching
	// the equivalent signpost in signWithDuration. The SECURITY / NIST 800-53
	// SC-12, SC-13 annotation belongs with the check itself, in
	// issueLeafLocked, so that enumerating the annotations in this tree maps
	// each one to the line implementing it rather than to the timeout below.

	ctx, cancel := context.WithTimeout(ctx, LockTimeout)
	defer cancel()

	var extraExtensions []pkix.Extension
	for _, ext := range presentedCert.Extensions {
		// Carry EVERY Puppet OID forward, including authorization-arc OIDs
		// (pp_cli_auth et al.). Unlike signWithDuration's CSR path — which adds
		// `&& !IsAuthOID(ext.Id)` here to strip auth OIDs as an anti-escalation
		// control — these were already vetted when presentedCert was issued, so
		// preserving them is required for wire-compat (e.g. OpenVox Server's own
		// cert keeps pp_cli_auth across renewal, or the CA CLI stops
		// authenticating). Do NOT add an IsAuthOID filter here; see this
		// method's godoc.
		//
		// This is safe only because assertOwnCertificate above established
		// that we issued presentedCert. Do not remove that check while leaving
		// this carry-forward in place. NIST 800-53: AC-6, CM-7.
		if IsPuppetOID(ext.Id) {
			extraExtensions = append(extraExtensions, ext)
		}
	}
	oldSerial := serialHexStr(presentedCert.SerialNumber)

	var out []byte
	err := c.Storage.WithLock(ctx, subjectLockName(subject), func() error {
		// SECURITY: ask again under the lock, for the reason given on the
		// re-key path above — the gate ran before this acquisition, and a
		// revocation landing during it must bind the renewal it overlaps
		// rather than lose a race with it.
		// NIST 800-53: IA-5(2) (PKI-Based Authentication), AC-3 (Access Enforcement)
		if err := c.refuseIfRevoked(ctx, presentedCert, subject); err != nil {
			return err
		}

		// Issue the replacement while holding c.mu, releasing it via defer
		// before the revoke step below re-acquires it (c.mu is non-reentrant).
		// The closure keeps the unlock panic-safe: a panic mid-issue still
		// frees the lock rather than wedging the CA.
		certPEM, err := func() ([]byte, error) {
			c.mu.Lock()
			defer c.mu.Unlock()
			// Carry forward every SAN type from the certificate being renewed,
			// not just DNS names: a leaf imported from a legacy CA may carry IP,
			// email, or URI SANs that services still depend on, and auto-renewal
			// must not silently drop them.
			sans := subjectAltNames{
				DNSNames:       presentedCert.DNSNames,
				IPAddresses:    presentedCert.IPAddresses,
				EmailAddresses: presentedCert.EmailAddresses,
				URIs:           presentedCert.URIs,
			}
			return c.issueLeafLocked(ctx, subject, presentedCert.Subject, presentedCert.PublicKey, sans, extraExtensions, 0)
		}()
		if err != nil {
			return err
		}
		out = certPEM

		if !c.RevokeOnAutoRenew {
			return nil
		}
		// Retire the certificate just replaced, same as Renew's rekey path:
		// only the newest serial should ever be valid for a subject, allowing
		// for whatever overlap SupersedeAfter grants. Best effort: a failure
		// here shouldn't undo the renewal the agent is waiting on.
		// Lock ordering: subject-lock (held) -> CRL-lock -> c.mu, matching Clean.
		if err := c.supersedeReplaced(ctx, subject, oldSerial); err != nil {
			// Counted already — crlUpdateFailures on the immediate path,
			// supersedeFailures on the delayed one. Here we only note it and
			// let the renewal stand.
			slog.Warn("AutoRenew: failed to retire replaced certificate", "subject", subject, "serial", oldSerial, "error", err)
		}
		return nil
	})
	return out, err
}
