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

package ca

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"regexp"
	"strings"
	"time"
)

const (
	// certValidity is the lifetime issued to CA and leaf certificates.
	certValidity = 5 * 365 * 24 * time.Hour
	// CRLValidity is the validity window written into every CRL.
	CRLValidity = 30 * 24 * time.Hour
)

// ErrCertExists is returned by SaveRequest when a valid (non-revoked) certificate
// already exists for the requested subject.
var ErrCertExists = errors.New("certificate already exists")

// evictRevoked checks whether a certificate already exists for subject.
//   - No cert on disk → returns nil (proceed with issuance).
//   - Cert exists and is NOT revoked → returns ErrCertExists (block issuance).
//   - Cert exists and IS revoked → deletes it and returns nil (allow re-issuance).
//
// Must NOT be called while holding c.mu.
func (c *CA) evictRevoked(subject string) error {
	if !c.Storage.HasCert(subject) {
		return nil
	}
	if !c.IsRevoked(subject) {
		return fmt.Errorf("certificate already exists for %s: %w", subject, ErrCertExists)
	}
	slog.Info("Removing revoked certificate", "subject", subject)
	if err := c.Storage.DeleteCert(subject); err != nil {
		slog.Warn("Could not remove revoked certificate", "subject", subject, "error", err)
	}
	return nil
}

var subjectRegex = regexp.MustCompile(`^[a-z0-9._-]+$`)

// ValidateSubject returns an error if subject contains unsafe characters.
// It is the single source of truth for subject name validation used by both
// the CA layer and the API layer.
func ValidateSubject(subject string) error {
	if !subjectRegex.MatchString(subject) || strings.Contains(subject, "..") {
		return fmt.Errorf("invalid subject name %q: must match ^[a-z0-9._-]+$ and must not contain ..", subject)
	}
	return nil
}

// Sign creates and persists a certificate for the pending CSR of subject.
// The caller must NOT hold c.mu.
func (c *CA) Sign(subject string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sign(subject)
}

// SignWithTTL signs subject's pending CSR with a custom validity duration.
// ttl=0 falls back to the default certValidity.
// The caller must NOT hold c.mu.
func (c *CA) SignWithTTL(subject string, ttl time.Duration) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.signWithDuration(subject, ttl)
}

// sign is the internal (unlocked) signing implementation using the default TTL.
// c.mu must be held by the caller.
func (c *CA) sign(subject string) ([]byte, error) {
	return c.signWithDuration(subject, 0)
}

// signWithDuration is the actual internal signing implementation.
// ttl=0 means use the default certValidity.
// c.mu must be held by the caller.
func (c *CA) signWithDuration(subject string, ttl time.Duration) ([]byte, error) {
	if err := ValidateSubject(subject); err != nil {
		return nil, err
	}

	slog.Debug("Signing certificate", "subject", subject)

	csrPEM, err := c.Storage.GetCSR(subject)
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

	// Reject CSRs that request CA capabilities (BasicConstraints: CA:TRUE, OID 2.5.29.19).
	// Matches the Puppet CA's behavior: returns an error whose message starts with
	// "Found extensions" and contains the OID string so callers can return 409.
	oidBasicConstraints := asn1.ObjectIdentifier{2, 5, 29, 19}
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(oidBasicConstraints) {
			var bc struct {
				IsCA bool `asn1:"optional"`
			}
			if _, err := asn1.Unmarshal(ext.Value, &bc); err == nil && bc.IsCA {
				return nil, fmt.Errorf("Found extensions that disallow signing: [2.5.29.19]")
			}
		}
	}

	serialStr, err := c.Storage.IncrementSerial()
	if err != nil {
		return nil, fmt.Errorf("failed to get serial: %w", err)
	}
	serialInt := new(big.Int)
	fmt.Sscanf(serialStr, "%x", serialInt)

	now := time.Now().UTC()

	validity := certValidity
	if ttl > 0 {
		validity = ttl
	}

	// Cap validity to the CA certificate's remaining lifetime.
	// A leaf cert must never outlive the CA that signed it; if it did, the cert
	// would appear valid after the CA cert expired, breaking chain verification.
	caRemaining := time.Until(c.CACert.NotAfter)
	if caRemaining <= 0 {
		return nil, fmt.Errorf("CA certificate has expired")
	}
	if validity > caRemaining {
		validity = caRemaining
	}

	// SubjectKeyIdentifier: SHA1 of the SubjectPublicKeyInfo DER (RFC 5280 §4.2.1.2).
	pubKeyDER, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key for %s: %w", subject, err)
	}
	subjectKeyID := sha1.Sum(pubKeyDER)

	template := &x509.Certificate{
		SerialNumber: serialInt,
		Subject:      csr.Subject,
		NotBefore:    now.Add(-24 * time.Hour),
		NotAfter:     now.Add(validity),

		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},

		BasicConstraintsValid: true,
		IsCA:                  false,

		SubjectKeyId:   subjectKeyID[:],
		AuthorityKeyId: c.CACert.SubjectKeyId,

		DNSNames: csr.DNSNames,
	}

	// Netscape Comment extension (OID 2.16.840.1.113730.1.13).
	nsComment, _ := asn1.Marshal("Puppet Server Internal Certificate")
	template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
		Id:    OIDNetscapeComment,
		Value: nsComment,
	})

	// Copy all Puppet OID extensions from the CSR.
	for _, ext := range csr.Extensions {
		if IsPuppetOID(ext.Id) {
			template.ExtraExtensions = append(template.ExtraExtensions, ext)
		}
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, c.CACert, csr.PublicKey, c.CAKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate for %s: %w", subject, err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	if err := c.Storage.SaveCert(subject, certPEM); err != nil {
		return nil, fmt.Errorf("failed to save cert for %s: %w", subject, err)
	}

	inventoryEntry := fmt.Sprintf("%s %s %s /%s",
		serialStr,
		template.NotBefore.Format("2006-01-02T15:04:05UTC"),
		template.NotAfter.Format("2006-01-02T15:04:05UTC"),
		subject,
	)
	if err := c.Storage.AppendInventory(inventoryEntry); err != nil {
		return nil, fmt.Errorf("failed to update inventory for %s: %w", subject, err)
	}

	// Remove the pending CSR now that we have a signed cert.
	if err := c.Storage.DeleteCSR(subject); err != nil {
		slog.Warn("Could not delete CSR after signing", "subject", subject, "error", err)
	}

	slog.Info("Certificate signed", "subject", subject, "serial", serialStr)
	return certPEM, nil
}

// Clean revokes (if signed) and removes both the certificate and any pending CSR
// for subject. It is the "puppet cert clean" equivalent: the subject must have at
// least a cert or CSR on disk, otherwise ErrNotFound is returned.
//
// Errors from individual operations (revoke, delete) are best-effort and logged
// but do not prevent the others from running.
var ErrNotFound = fmt.Errorf("certificate or CSR not found")

func (c *CA) Clean(subject string) error {
	if err := ValidateSubject(subject); err != nil {
		return err
	}

	hasCert := c.Storage.HasCert(subject)
	hasCSR := c.Storage.HasCSR(subject)

	if !hasCert && !hasCSR {
		return ErrNotFound
	}

	if hasCert {
		// Revoke first so the CRL is updated before the file is removed.
		if err := c.Revoke(subject); err != nil {
			slog.Warn("Clean: revoke failed (proceeding with delete)", "subject", subject, "error", err)
		}
		if err := c.Storage.DeleteCert(subject); err != nil {
			slog.Warn("Clean: delete cert failed", "subject", subject, "error", err)
		}
	}

	if hasCSR {
		if err := c.Storage.DeleteCSR(subject); err != nil {
			slog.Warn("Clean: delete CSR failed", "subject", subject, "error", err)
		}
	}

	slog.Info("Certificate cleaned", "subject", subject)
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
func (c *CA) SignMultiple(subjects []string) SignResult {
	result := SignResult{
		Signed:        []string{},
		NoCSR:         []string{},
		SigningErrors: []string{},
	}
	for _, subject := range subjects {
		if !c.Storage.HasCSR(subject) {
			result.NoCSR = append(result.NoCSR, subject)
			continue
		}
		if _, err := c.Sign(subject); err != nil {
			slog.Warn("Bulk sign failed", "subject", subject, "error", err)
			result.SigningErrors = append(result.SigningErrors, subject)
		} else {
			result.Signed = append(result.Signed, subject)
		}
	}
	return result
}

// SignAll signs every pending CSR currently on disk.
func (c *CA) SignAll() (SignResult, error) {
	subjects, err := c.Storage.ListCSRs()
	if err != nil {
		return SignResult{}, fmt.Errorf("listing CSRs: %w", err)
	}
	return c.SignMultiple(subjects), nil
}

// SaveRequest validates, persists the CSR, and triggers autosigning if configured.
func (c *CA) SaveRequest(subject string, csrPEM []byte) (bool, error) {
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

	// CN in the CSR must match the URL subject — Puppet CA enforces this.
	if csr.Subject.CommonName != subject {
		return false, fmt.Errorf("Instance name %s does not match requested key %s",
			csr.Subject.CommonName, subject)
	}

	slog.Debug("Received CSR", "subject", subject)

	// Reject if a cert already exists and is not revoked; clear it if revoked
	// so the node can re-register with a fresh key.
	if err := c.evictRevoked(subject); err != nil {
		return false, err
	}

	if err := c.Storage.SaveCSR(subject, csrPEM); err != nil {
		return false, fmt.Errorf("failed to save CSR for %s: %w", subject, err)
	}

	shouldSign, err := CheckAutosign(c.AutosignConfig, csr, csrPEM)
	if err != nil {
		return false, fmt.Errorf("autosign check failed for %s: %w", subject, err)
	}

	if shouldSign {
		slog.Debug("Autosigning CSR", "subject", subject)
		c.mu.Lock()
		defer c.mu.Unlock()
		if _, err := c.sign(subject); err != nil {
			return false, err
		}
		return true, nil
	}

	slog.Info("CSR saved, awaiting manual signing", "subject", subject)
	return false, nil
}
