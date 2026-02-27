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

package testutil

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"time"

	"golang.org/x/crypto/ocsp"
)

// GenerateTestCA generates a lighter-weight CA (2048-bit) for testing purposes.
// Returns PEM-encoded Key, Cert, and empty CRL.
func GenerateTestCA() ([]byte, []byte, []byte, error) {
	// 1. Generate Key (2048 instead of 4096 for speed)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}

	// 2. Generate CA Cert
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	pubBytes, _ := asn1.Marshal(key.PublicKey)
	subjectKeyID := sha1.Sum(pubBytes)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Puppet CA: Test",
			Organization: []string{"Puppet Test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          subjectKeyID[:],
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}

	// Parse back to get a usable certificate object for CRL signing
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, nil, err
	}

	// 3. Generate Empty CRL using the non-deprecated API.
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}
	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, cert, key)
	if err != nil {
		return nil, nil, nil, err
	}

	// Encode
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes})

	return keyPEM, certPEM, crlPEM, nil
}

// BuildOCSPRequest creates a DER-encoded OCSPRequest for cert signed by issuer.
// Uses SHA256 as the hash algorithm.
func BuildOCSPRequest(cert, issuer *x509.Certificate) ([]byte, error) {
	return ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{Hash: crypto.SHA256})
}

// oidNonceTestutil is the OCSP nonce OID (RFC 8954 §2).
var oidNonceTestutil = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}

// BuildOCSPRequestWithNonce creates a DER-encoded OCSPRequest including a nonce
// extension in requestExtensions. The nonce value must be 1–32 bytes (RFC 8954).
func BuildOCSPRequestWithNonce(cert, issuer *x509.Certificate, nonce []byte) ([]byte, error) {
	// Compute IssuerNameHash = SHA1(issuer.RawSubject)
	issuerNameHash := sha1.Sum(issuer.RawSubject)

	// Extract SubjectPublicKey bit string from SubjectPublicKeyInfo.
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &spki); err != nil {
		return nil, err
	}
	// IssuerKeyHash = SHA1(SubjectPublicKey bit string bytes)
	issuerKeyHash := sha1.Sum(spki.PublicKey.Bytes)

	// Build certID using id-sha1 (OID 1.3.14.3.2.26).
	hashAlgID := pkix.AlgorithmIdentifier{
		Algorithm:  asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26},
		Parameters: asn1.RawValue{Tag: 5}, // NULL
	}

	// Build the nonce extension value: extnValue contains DER(OCTET STRING(nonce)).
	nonceValueDER, err := asn1.Marshal(nonce)
	if err != nil {
		return nil, err
	}
	nonceExt := pkix.Extension{
		Id:    oidNonceTestutil,
		Value: nonceValueDER,
	}

	// Build the full OCSPRequest with requestExtensions.
	type certIDASN1 struct {
		HashAlgorithm pkix.AlgorithmIdentifier
		NameHash      []byte
		IssuerKeyHash []byte
		SerialNumber  *big.Int
	}
	type requestItemASN1 struct {
		Cert certIDASN1
	}
	type tbsRequestASN1 struct {
		RequestList []requestItemASN1
		Extensions  []pkix.Extension `asn1:"explicit,tag:2,optional"`
	}
	type ocspRequestASN1 struct {
		TBSRequest tbsRequestASN1
	}

	return asn1.Marshal(ocspRequestASN1{
		TBSRequest: tbsRequestASN1{
			RequestList: []requestItemASN1{{
				Cert: certIDASN1{
					HashAlgorithm: hashAlgID,
					NameHash:      issuerNameHash[:],
					IssuerKeyHash: issuerKeyHash[:],
					SerialNumber:  cert.SerialNumber,
				},
			}},
			Extensions: []pkix.Extension{nonceExt},
		},
	})
}

// GenerateCSR generates a standard CSR for testing.
func GenerateCSR(commonName string) ([]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes}), nil
}
