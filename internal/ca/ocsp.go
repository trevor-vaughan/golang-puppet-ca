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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/ocsp"
)

// ErrInternal is returned by OCSPResponse when a server-side failure (e.g. a
// CRL read error) prevents determining certificate status. The HTTP handler
// uses this to write an OCSP InternalError response instead of MalformedRequest.
var ErrInternal = errors.New("internal CA error")

// OCSPValidity is the NextUpdate window written into every OCSP response.
// Pre-signed responses are cached for this duration; GET responses include
// a matching Cache-Control: max-age header for downstream HTTP caches.
const OCSPValidity = 4 * time.Hour

// ocspCacheEntry holds a pre-signed OCSP response DER and its expiry.
type ocspCacheEntry struct {
	der       []byte
	expiresAt time.Time
}

// oidNonce is the OCSP nonce extension OID (RFC 8954 §2).
var oidNonce = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}

// ocspTBSReqWithExts mirrors the TBSRequest ASN.1 structure including the
// optional requestExtensions field (tag 2) not exposed by x/crypto/ocsp.
type ocspTBSReqWithExts struct {
	Version       int              `asn1:"explicit,tag:0,default:0,optional"`
	RequestorName asn1.RawValue    `asn1:"explicit,tag:1,optional"`
	RequestList   asn1.RawValue    // SEQUENCE OF Request — opaque
	Extensions    []pkix.Extension `asn1:"explicit,tag:2,optional"`
}

type ocspReqWithExts struct {
	TBSRequest ocspTBSReqWithExts
}

// extractNonce parses the raw DER-encoded OCSPRequest and returns the nonce
// extension (OID 1.3.6.1.5.5.7.48.1.2) if present in requestExtensions.
func extractNonce(reqDER []byte) (pkix.Extension, bool) {
	var req ocspReqWithExts
	if _, err := asn1.Unmarshal(reqDER, &req); err != nil {
		return pkix.Extension{}, false
	}
	for _, ext := range req.TBSRequest.Extensions {
		if ext.Id.Equal(oidNonce) {
			return ext, true
		}
	}
	return pkix.Extension{}, false
}

// buildSerialIndex populates c.serialIndex from the on-disk inventory file.
// It must be called while c.mu is already held by the caller.
func (c *CA) buildSerialIndex() error {
	data, err := c.Storage.ReadInventory()
	if err != nil {
		return err
	}

	c.serialIndex = make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		if serial, subject, ok := parseInventoryLine(scanner.Text()); ok {
			c.serialIndex[serial] = subject
		}
	}
	return scanner.Err()
}

// OCSPResponse builds a DER-encoded OCSPResponse for the given DER-encoded
// OCSPRequest. The CA key signs the response directly (RFC 6960 §2.6).
//
// Responses are cached by serial for OCSPValidity; the cache is bypassed when
// a nonce is present in the request (RFC 8954). The caller must NOT hold c.mu.
func (c *CA) OCSPResponse(reqDER []byte) ([]byte, error) {
	// Extract nonce before acquiring any lock (pure DER parse, no shared state).
	nonce, hasNonce := extractNonce(reqDER)

	req, err := ocsp.ParseRequest(reqDER)
	if err != nil {
		return nil, fmt.Errorf("parsing OCSP request: %w", err)
	}

	// Compute the cache key in the same format used by signWithDuration/revoke.
	serialHex := fmt.Sprintf("%04X", req.SerialNumber)

	// Fast path: check cache with a read lock (only when no nonce).
	if !hasNonce {
		c.mu.RLock()
		entry, ok := c.ocspCache[serialHex]
		c.mu.RUnlock()
		if ok && time.Now().Before(entry.expiresAt) {
			return entry.der, nil
		}
	}

	// Slow path: acquire write lock for status lookup + cache write.
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring the write lock.
	if !hasNonce {
		if entry, ok := c.ocspCache[serialHex]; ok && time.Now().Before(entry.expiresAt) {
			return entry.der, nil
		}
	}

	now := time.Now().UTC()
	template := ocsp.Response{
		SerialNumber: req.SerialNumber,
		ThisUpdate:   now,
		NextUpdate:   now.Add(OCSPValidity),
	}

	if _, known := c.serialIndex[serialHex]; !known {
		template.Status = ocsp.Unknown
	} else {
		revoked, revokedAt, err := c.isRevokedSerial(req.SerialNumber)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInternal, err)
		}
		if revoked {
			template.Status = ocsp.Revoked
			template.RevokedAt = revokedAt
		} else {
			template.Status = ocsp.Good
		}
	}

	// Echo the nonce extension into the response's singleExtensions.
	if hasNonce {
		template.ExtraExtensions = append(template.ExtraExtensions, nonce)
	}

	respDER, err := ocsp.CreateResponse(c.CACert, c.CACert, template, c.CAKey)
	if err != nil {
		return nil, fmt.Errorf("creating OCSP response: %w", err)
	}

	// Cache the response only when there is no nonce (RFC 8954 §3).
	if !hasNonce {
		c.ocspCache[serialHex] = ocspCacheEntry{
			der:       respDER,
			expiresAt: now.Add(OCSPValidity),
		}
	}

	return respDER, nil
}

// isRevokedSerial checks the current CRL for the given serial number.
// Returns (true, revocationTime, nil) if found, (false, zero, nil) if not,
// or (false, zero, error) if the CRL cannot be read or parsed.
// Must be called while c.mu is already held by the caller.
func (c *CA) isRevokedSerial(serial *big.Int) (bool, time.Time, error) {
	crlPEM, err := c.Storage.GetCRL()
	if err != nil {
		return false, time.Time{}, fmt.Errorf("reading CRL: %w", err)
	}
	block, _ := pem.Decode(crlPEM)
	if block == nil {
		return false, time.Time{}, fmt.Errorf("CRL is empty or not PEM-encoded")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return false, time.Time{}, fmt.Errorf("parsing CRL: %w", err)
	}
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(serial) == 0 {
			return true, entry.RevocationTime, nil
		}
	}
	return false, time.Time{}, nil
}

// buildAIAExtension constructs the DER-encoded value of an Authority Information
// Access extension (RFC 5280 §4.2.2.1) pointing each URL at the OCSP responder.
func buildAIAExtension(urls []string) ([]byte, error) {
	type accessDescription struct {
		AccessMethod   asn1.ObjectIdentifier
		AccessLocation asn1.RawValue
	}

	ads := make([]accessDescription, 0, len(urls))
	for _, u := range urls {
		ads = append(ads, accessDescription{
			AccessMethod: OIDAdOCSP,
			AccessLocation: asn1.RawValue{
				Class: asn1.ClassContextSpecific,
				Tag:   6, // uniformResourceIdentifier [6] IMPLICIT IA5String
				Bytes: []byte(u),
			},
		})
	}
	return asn1.Marshal(ads)
}
