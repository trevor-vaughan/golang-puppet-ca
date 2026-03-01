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
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
)

// GenerateResult holds the PEM-encoded private key and signed certificate
// produced by a server-side Generate call.
type GenerateResult struct {
	PrivateKeyPEM  []byte
	CertificatePEM []byte
}

// Generate creates a fresh RSA key pair for subject, signs a certificate for it
// without requiring a client-submitted CSR, saves the private key to
// private/{subject}_key.pem, and returns both PEMs.
//
// Returns ErrCertExists (wrapped) if a valid (non-revoked) certificate already
// exists for subject.
func (c *CA) Generate(subject string, dnsAltNames []string) (*GenerateResult, error) {
	if err := ValidateSubject(subject); err != nil {
		return nil, err
	}

	if err := c.evictRevoked(subject); err != nil {
		return nil, err
	}

	// Generate a 2048-bit RSA key (leaf cert; CA uses 4096).
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key for %s: %w", subject, err)
	}

	// Build an internal CSR so sign() can process it normally.
	csrTemplate := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: subject},
		DNSNames: dnsAltNames,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create internal CSR for %s: %w", subject, err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	if err := c.Storage.SaveCSR(subject, csrPEM); err != nil {
		return nil, fmt.Errorf("failed to save internal CSR for %s: %w", subject, err)
	}

	// Sign using the internal (unlocked) path — acquire mu first.
	c.mu.Lock()
	defer c.mu.Unlock()

	certPEM, err := c.sign(subject)
	if err != nil {
		_ = c.Storage.DeleteCSR(subject)
		return nil, fmt.Errorf("failed to sign generated cert for %s: %w", subject, err)
	}

	// Save the private key to private/{subject}_key.pem (mode 0640).
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err := c.Storage.SavePrivateKey(subject, keyPEM); err != nil {
		return nil, fmt.Errorf("failed to save private key for %s: %w", subject, err)
	}

	slog.Debug("Certificate generated", "subject", subject)
	return &GenerateResult{
		PrivateKeyPEM:  keyPEM,
		CertificatePEM: certPEM,
	}, nil
}
