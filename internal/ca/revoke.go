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
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"time"
)

func (c *CA) Revoke(subject string) error {
	if err := ValidateSubject(subject); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	slog.Debug("Revoking certificate", "subject", subject)

	// 1. Find Serial
	serialStr, err := c.findSerialForSubject(subject)
	if err != nil {
		return fmt.Errorf("could not find certificate for subject %s: %w", subject, err)
	}

	serialInt := new(big.Int)
	fmt.Sscanf(serialStr, "%x", serialInt)

	// 2. Load CRL
	crlPEM, err := c.Storage.GetCRL()
	if err != nil {
		return fmt.Errorf("failed to load CRL: %w", err)
	}
	block, _ := pem.Decode(crlPEM)
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CRL: %w", err)
	}

	// 3. Prepare New CRL
	newRevoked := x509.RevocationListEntry{
		SerialNumber:   serialInt,
		RevocationTime: time.Now(),
	}

	// Copy existing revoked
	revokedCerts := crl.RevokedCertificateEntries
	revokedCerts = append(revokedCerts, newRevoked)

	// Increment CRL Number
	nextNum := big.NewInt(1)
	if crl.Number != nil {
		nextNum.Add(crl.Number, big.NewInt(1))
	}

	template := &x509.RevocationList{
		Number:                    nextNum,
		RevokedCertificateEntries: revokedCerts,
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().Add(CRLValidity),
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, template, c.CACert, c.CAKey)
	if err != nil {
		return fmt.Errorf("failed to sign CRL: %w", err)
	}

	newCRLPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes})
	if err := c.Storage.UpdateCRL(newCRLPEM); err != nil {
		return fmt.Errorf("failed to write CRL: %w", err)
	}

	// Invalidate the cached OCSP response for this serial so the next query
	// returns the correct Revoked status instead of a stale Good response.
	delete(c.ocspCache, serialStr)

	slog.Info("Certificate revoked", "subject", subject, "serial", serialStr)
	return nil
}

// parseInventoryLine parses a single line of the certificate inventory file.
// The format is: SERIAL NOT_BEFORE NOT_AFTER /SUBJECT
// Returns (serial, subject, true) on success; ("", "", false) for blank or malformed lines.
// The returned subject has its leading "/" stripped.
func parseInventoryLine(line string) (serial, subject string, ok bool) {
	parts := strings.Fields(line)
	if len(parts) < 4 {
		return "", "", false
	}
	return parts[0], strings.TrimPrefix(parts[3], "/"), true
}

// findSerialForSubject returns the most-recently issued serial for subject.
// It reads through storage to honour the inventory mutex.
func (c *CA) findSerialForSubject(subject string) (string, error) {
	data, err := c.Storage.ReadInventory()
	if err != nil {
		return "", err
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	last := ""
	for scanner.Scan() {
		if serial, subj, ok := parseInventoryLine(scanner.Text()); ok && subj == subject {
			last = serial
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if last == "" {
		return "", fmt.Errorf("subject %s not found in inventory", subject)
	}
	return last, nil
}

// IsRevoked checks whether the certificate for subject appears in the CRL.
// Returns false (not an error) if the subject has no signed cert.
func (c *CA) IsRevoked(subject string) bool {
	certPEM, err := c.Storage.GetCert(subject)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}

	crlPEM, err := c.Storage.GetCRL()
	if err != nil {
		return false
	}
	crlBlock, _ := pem.Decode(crlPEM)
	if crlBlock == nil {
		return false
	}
	crl, err := x509.ParseRevocationList(crlBlock.Bytes)
	if err != nil {
		return false
	}

	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return true
		}
	}
	return false
}
