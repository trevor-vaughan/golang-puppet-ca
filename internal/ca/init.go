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
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"time"

	"github.com/tvaughan/puppet-ca/internal/storage"
)

func (c *CA) Init() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.Storage.EnsureDirs(); err != nil {
		return err
	}

	// Try loading existing CA first.
	if err := c.loadCA(); err == nil {
		slog.Info("Loaded existing CA", "cert", c.Storage.CACertPath())
		if err := c.buildSerialIndex(); err != nil {
			slog.Warn("Failed to build OCSP serial index", "error", err)
		}
		return nil
	}

	_, errCert := os.Stat(c.Storage.CACertPath())
	_, errKey := os.Stat(c.Storage.CAKeyPath())

	if os.IsNotExist(errCert) || os.IsNotExist(errKey) {
		slog.Info("No existing CA found, bootstrapping new CA")
		return c.bootstrapCA()
	}

	return fmt.Errorf("failed to load existing CA: files exist but could not be parsed")
}

func (c *CA) loadCA() error {
	keyPEM, err := os.ReadFile(c.Storage.CAKeyPath())
	if err != nil {
		return err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return fmt.Errorf("failed to decode CA key PEM")
	}
	// Accept both PKCS1 ("BEGIN RSA PRIVATE KEY") and PKCS8 ("BEGIN PRIVATE KEY").
	// Bootstrapped keys are always PKCS1; imported keys may be PKCS8 (openssl-3.x default).
	var key *rsa.PrivateKey
	if k1, err1 := x509.ParsePKCS1PrivateKey(block.Bytes); err1 == nil {
		key = k1
	} else if k8, err8 := x509.ParsePKCS8PrivateKey(block.Bytes); err8 == nil {
		var ok bool
		key, ok = k8.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("CA private key is not an RSA key")
		}
	} else {
		return fmt.Errorf("failed to parse CA private key (PKCS1: %v; PKCS8: %v)", err1, err8)
	}

	certPEM, err := os.ReadFile(c.Storage.CACertPath())
	if err != nil {
		return err
	}
	block, _ = pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to decode CA cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	c.CAKey = key
	c.CACert = cert
	return nil
}

func (c *CA) bootstrapCA() error {
	hostname := c.Hostname
	if hostname == "" {
		hostname = "puppet"
	}

	slog.Debug("Generating CA key (4096-bit RSA) — this may take a moment")
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("failed to generate CA key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	// SubjectKeyIdentifier: SHA1 of the DER-encoded public key.
	pubBytes, _ := asn1.Marshal(key.PublicKey)
	subjectKeyID := sha1.Sum(pubBytes)

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Puppet CA: " + hostname,
		},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(certValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          subjectKeyID[:],
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("failed to create CA cert: %w", err)
	}

	parsedCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return fmt.Errorf("failed to parse generated CA cert: %w", err)
	}
	c.CAKey = key
	c.CACert = parsedCert

	// Save private key (mode 0640).
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(c.Storage.CAKeyPath(), keyPEM, storage.FilePermPrivate); err != nil {
		return fmt.Errorf("failed to write CA key: %w", err)
	}

	// Save CA cert (mode 0644).
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err := os.WriteFile(c.Storage.CACertPath(), certPEM, storage.FilePermPublic); err != nil {
		return fmt.Errorf("failed to write CA cert: %w", err)
	}

	// Write a public key file alongside the cert.
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err == nil {
		pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})
		_ = os.WriteFile(c.Storage.CAPubKeyPath(), pubKeyPEM, storage.FilePermPublic)
	}

	// Generate empty CRL using the non-deprecated API.
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now,
		NextUpdate: now.Add(CRLValidity),
	}
	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, c.CACert, c.CAKey)
	if err != nil {
		return fmt.Errorf("failed to create initial CRL: %w", err)
	}
	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes})
	if err := c.Storage.UpdateCRL(crlPEM); err != nil {
		return fmt.Errorf("failed to write initial CRL: %w", err)
	}

	// Initialise serial file.
	if err := c.Storage.WriteSerial("0001"); err != nil {
		return fmt.Errorf("failed to write serial: %w", err)
	}

	// Touch inventory.
	f, err := os.OpenFile(c.Storage.InventoryPath(), os.O_CREATE|os.O_RDONLY, storage.FilePermPublic)
	if err != nil {
		return fmt.Errorf("failed to create inventory: %w", err)
	}
	f.Close()

	slog.Info("CA bootstrapped", "cn", template.Subject.CommonName, "cadir", c.Storage.CADir())
	return nil
}
