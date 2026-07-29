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
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"slices"
	"time"
)

// ServingConfig governs the CA's own serving certificate: the one the API
// listener presents when tls_self_provision is on.
//
// Zero values are meaningful defaults throughout, so a caller that only sets
// Subject gets sensible behaviour.
type ServingConfig struct {
	// Subject is the certificate's common name and first DNS SAN. Required.
	Subject string

	// ExtraNames are additional DNS SANs — service and ingress names clients
	// actually dial.
	ExtraNames []string

	// RenewBefore reissues once remaining validity falls below this. Zero
	// selects a third of the certificate's total lifetime.
	RenewBefore time.Duration

	// EncryptKey encrypts the stored private key at rest, using the same
	// passphrase machinery as the CA key (see keyenc.go).
	EncryptKey bool

	// RevokeAfter revokes a superseded certificate this long after it is
	// replaced. Zero never revokes.
	RevokeAfter time.Duration

	// KeyConfig selects the serving key's algorithm and size. Zero uses
	// DefaultLeafKeyConfig.
	KeyConfig KeyConfig
}

// ServingCertificate is a serving certificate and its private key, ready to be
// handed to crypto/tls.
type ServingCertificate struct {
	CertPEM []byte
	KeyPEM  []byte
	Leaf    *x509.Certificate
	Key     crypto.Signer
	// Issued reports whether this pass minted a new certificate, as opposed to
	// reusing the one already in storage.
	Issued bool
}

// EnsureServingCert resolves the CA's serving certificate, minting one if the
// stored material is missing or no longer usable.
//
// # Lock discipline
//
// This is the authoritative statement; getting it wrong deadlocks startup with
// no deadline to break it, presenting as a listener that never opens.
//
//	Holder                          Subject lock   c.mu
//	EnsureServingCert, whole body   acquires       —
//	  …evaluating reuse             held           must NOT hold
//	  …around the mint call only    held           acquires, releases
//	issueServingCertLocked          caller's       caller's — takes neither
//
// Two independent non-reentrancy hazards force this. The reuse predicate calls
// IsRevokedSerial, which takes c.mu.RLock(); an RLock taken while the same
// goroutine holds the write lock deadlocks. And StorageService.WithLock hands
// out either an advisory lock or a bare sync.Mutex, neither reentrant, so
// nothing below this function may take the subject lock again — which rules out
// Sign, SignWithTTL and Generate, all of which take it themselves.
//
// # Failure policy
//
// Any single unusable-material condition mints a replacement rather than
// erroring. That is deliberate: a torn write between the two Put calls, or a
// rotated passphrase leaving the stored key undecryptable, would otherwise be
// unrecoverable without deleting rows by hand. The material is derived, not
// authoritative — the CA can always issue itself another one.
func (c *CA) EnsureServingCert(ctx context.Context, cfg ServingConfig) (*ServingCertificate, error) {
	if cfg.Subject == "" {
		return nil, fmt.Errorf("serving certificate subject is required")
	}
	if err := ValidateSubject(cfg.Subject); err != nil {
		return nil, fmt.Errorf("serving certificate subject: %w", err)
	}

	lockCtx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()

	var result *ServingCertificate
	err := c.Storage.WithLock(lockCtx, subjectLockName(cfg.Subject), func() error {
		existing, why := c.loadUsableServingCert(ctx, cfg)
		if existing != nil {
			result = existing
			return nil
		}
		slog.Info("Issuing serving certificate", "subject", cfg.Subject, "reason", why)

		c.mu.Lock()
		defer c.mu.Unlock()
		minted, err := c.issueServingCertLocked(ctx, cfg)
		if err != nil {
			return err
		}
		result = minted
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// loadUsableServingCert returns the stored serving certificate when every reuse
// condition holds, or nil plus a human-readable reason when it must be
// replaced. The reason is logged, so a certificate churning between replicas is
// diagnosable from one line rather than by comparing serials.
//
// The subject lock is held; c.mu must NOT be, because IsRevokedSerial takes it
// for reading.
func (c *CA) loadUsableServingCert(ctx context.Context, cfg ServingConfig) (*ServingCertificate, string) {
	certPEM, err := c.Storage.GetServingCert(ctx)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, "no serving certificate in storage"
		}
		return nil, fmt.Sprintf("serving certificate unreadable: %v", err)
	}
	keyPEM, err := c.Storage.GetServingKey(ctx)
	if err != nil {
		// A torn write between the two Put calls lands here. Mint again.
		return nil, fmt.Sprintf("serving key unreadable: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, "stored serving certificate is not PEM"
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Sprintf("stored serving certificate does not parse: %v", err)
	}

	key, err := c.parseServingKey(keyPEM)
	if err != nil {
		// A rotated passphrase lands here. Mint again rather than crash-loop.
		return nil, fmt.Sprintf("stored serving key unusable: %v", err)
	}
	if !publicKeysEqual(leaf.PublicKey, key.Public()) {
		return nil, "stored serving key does not match the stored certificate"
	}

	// Verify against the CA certificate this process actually loaded, not
	// against the AuthorityKeyId. The SKI is derived from the public key, so a
	// CA certificate re-signed by a new parent over the same key keeps the same
	// SKI — and a stale serving certificate would be silently retained.
	if c.CACert == nil {
		return nil, "CA certificate not loaded"
	}
	if err := leaf.CheckSignatureFrom(c.CACert); err != nil {
		return nil, "stored serving certificate was not issued by the current CA certificate"
	}

	if remaining := time.Until(leaf.NotAfter); remaining <= servingRenewBefore(cfg, leaf) {
		return nil, fmt.Sprintf("within the renewal window (%s remaining)", remaining.Round(time.Minute))
	}

	if missing := missingNames(leaf, servingNames(cfg)); missing != "" {
		return nil, fmt.Sprintf("does not cover the configured name %q", missing)
	}

	revoked, err := c.IsRevokedSerial(ctx, leaf.SerialNumber)
	if err != nil {
		return nil, fmt.Sprintf("cannot determine revocation status: %v", err)
	}
	if revoked {
		// This is the recovery route after `openvox-ca-ctl revoke` on the CA's
		// own hostname, which is the documented way to replace a compromised
		// serving key.
		return nil, "stored serving certificate has been revoked"
	}

	return &ServingCertificate{CertPEM: certPEM, KeyPEM: keyPEM, Leaf: leaf, Key: key}, ""
}

// publicKeysEqual compares two public keys by marshalled SubjectPublicKeyInfo,
// so it is algorithm-agnostic rather than a type switch per algorithm.
func publicKeysEqual(a, b any) bool {
	aDER, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false
	}
	bDER, err := x509.MarshalPKIXPublicKey(b)
	if err != nil {
		return false
	}
	return bytes.Equal(aDER, bDER)
}

// issueServingCertLocked mints and stores a serving certificate.
//
// The Locked suffix is load-bearing: the caller holds both the subject lock and
// c.mu, and this function takes neither. It is unexported for the same reason —
// it mirrors Generate, and Generate's siblings Sign and SignWithTTL take the
// subject lock themselves. Copying either would deadlock every backend on the
// startup path.
func (c *CA) issueServingCertLocked(ctx context.Context, cfg ServingConfig) (*ServingCertificate, error) {
	keyCfg := cfg.KeyConfig
	if keyCfg.Algo == "" {
		keyCfg = c.LeafKeyConfig
	}
	if keyCfg.Algo == "" {
		keyCfg = DefaultLeafKeyConfig
	}

	key, err := generateKey(keyCfg)
	if err != nil {
		return nil, fmt.Errorf("generating serving key: %w", err)
	}

	names := servingNames(cfg)
	// serverAuth only. The common name is the CA's own hostname, and where that
	// hostname also appears in puppet_server a clientAuth certificate sitting in
	// the storage backend would be a usable admin credential.
	certPEM, err := c.issueLeafLocked(ctx, cfg.Subject, pkix.Name{CommonName: cfg.Subject},
		key.Public(), subjectAltNames{DNSNames: names}, nil, 0, x509.ExtKeyUsageServerAuth)
	if err != nil {
		return nil, fmt.Errorf("signing serving certificate: %w", err)
	}

	keyPEM, err := c.marshalServingKey(key, cfg)
	if err != nil {
		return nil, err
	}

	// Key first: a crash between the two writes then leaves a key with no
	// certificate, which the reuse predicate reads as "mint again". The other
	// order would leave a certificate whose key is missing, which is the same
	// outcome by a longer route — but this way the private material is never
	// the thing left dangling.
	if err := c.Storage.SaveServingKey(ctx, keyPEM); err != nil {
		return nil, fmt.Errorf("writing serving key: %w", err)
	}
	if err := c.Storage.SaveServingCert(ctx, certPEM); err != nil {
		return nil, fmt.Errorf("writing serving certificate: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing freshly issued serving certificate: %w", err)
	}

	c.servingCertIssued.Add(1)
	return &ServingCertificate{CertPEM: certPEM, KeyPEM: keyPEM, Leaf: leaf, Key: key, Issued: true}, nil
}

// servingNames is the deduplicated SAN list: the subject first, then the
// configured extras in order. Subject leads because it is the common name and
// the name an operator expects to see first in the certificate.
func servingNames(cfg ServingConfig) []string {
	names := make([]string, 0, len(cfg.ExtraNames)+1)
	names = append(names, cfg.Subject)
	for _, n := range cfg.ExtraNames {
		if n != "" && !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	return names
}

// missingNames returns the first configured name the certificate does not
// cover, or "" when it covers all of them.
func missingNames(leaf *x509.Certificate, want []string) string {
	for _, n := range want {
		if !slices.Contains(leaf.DNSNames, n) {
			return n
		}
	}
	return ""
}

// servingRenewBefore resolves how much remaining validity triggers a reissue,
// defaulting to a third of the certificate's own lifetime. Deriving it from the
// certificate rather than from a constant means a deployment that shortens
// leaf_validity_days gets a proportionally earlier renewal for free, which is
// the same relationship crl_refresh_before_sec has to crl_validity.
func servingRenewBefore(cfg ServingConfig, leaf *x509.Certificate) time.Duration {
	if cfg.RenewBefore > 0 {
		return cfg.RenewBefore
	}
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
	if lifetime <= 0 {
		return 0
	}
	return lifetime / 3
}

// marshalServingKey encodes a freshly generated serving key for storage,
// applying at-rest encryption when configured.
func (c *CA) marshalServingKey(key crypto.Signer, cfg ServingConfig) ([]byte, error) {
	if !cfg.EncryptKey {
		keyPEM, err := marshalPrivateKeyPEM(key)
		if err != nil {
			return nil, fmt.Errorf("marshalling serving key: %w", err)
		}
		return keyPEM, nil
	}
	passphrase, _, err := resolvePassphrase(c.KeyPassphrase, c.Storage.CADir())
	if err != nil {
		return nil, fmt.Errorf("resolving serving key passphrase: %w", err)
	}
	keyPEM, err := encryptAndMarshalKey(key, passphrase)
	if err != nil {
		return nil, fmt.Errorf("encrypting serving key: %w", err)
	}
	return keyPEM, nil
}

// parseServingKey decodes a stored serving key, decrypting it when it is an
// encrypted PEM block.
//
// It keys on the block itself rather than on cfg.EncryptKey, so turning
// encryption on or off is not a hard failure: the stored key is read either
// way, and the next reissue writes it in the newly configured form.
func (c *CA) parseServingKey(keyPEM []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("not PEM-encoded")
	}
	der := block.Bytes
	blockType := block.Type
	if isEncryptedPEM(block) {
		passphrase, _, err := resolvePassphrase(c.KeyPassphrase, c.Storage.CADir())
		if err != nil {
			return nil, fmt.Errorf("resolving passphrase: %w", err)
		}
		plain, err := decryptKeyDER(block.Bytes, passphrase)
		if err != nil {
			return nil, fmt.Errorf("decrypting: %w", err)
		}
		// decryptKeyDER always yields PKCS#8, whatever the key was before.
		der = plain
		blockType = "PRIVATE KEY"
	}
	return parsePrivateKeyDER(blockType, der)
}
