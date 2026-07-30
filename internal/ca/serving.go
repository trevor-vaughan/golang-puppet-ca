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
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/big"
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

	// Shadow ctx rather than bounding acquisition alone: the deadline has to
	// cover the work under the lock, not just the wait for it. Matches Sign,
	// Renew, AutoRenew, Clean and Revoke. The caller here is the maintenance
	// goroutine, whose context has no deadline at all.
	ctx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()

	var result *ServingCertificate
	err := c.Storage.WithLock(ctx, subjectLockName(cfg.Subject), func() error {
		existing, why := c.loadUsableServingCert(ctx, cfg)
		if existing != nil {
			result = existing
			return nil
		}
		// Distinguish "the material is unusable" from "we could not read it".
		// Only the first justifies minting over what is there; the second is
		// I/O to retry, and minting on it would replace a certificate that may
		// be perfectly good.
		if why.Code == reasonCertUnreadable || why.Code == reasonKeyUnreadable ||
			why.Code == reasonRevocationCheck {
			return fmt.Errorf("reading the stored serving certificate: %s", why.Code)
		}
		slog.Info("Issuing serving certificate", "subject", cfg.Subject, "reason", why)

		// Whatever is being replaced, if anything. Read before the mint so the
		// old serial is still available; recorded after it succeeds, so a
		// failed mint never schedules a revocation of the certificate still in
		// use.
		superseded := c.storedServingLeaf(ctx)

		c.mu.Lock()
		minted, err := c.issueServingCertLocked(ctx, cfg)
		c.mu.Unlock()
		if err != nil {
			return err
		}
		result = minted

		if superseded != nil && superseded.SerialNumber.Cmp(minted.Leaf.SerialNumber) != 0 {
			if err := c.recordSuperseded(ctx, superseded, cfg.RevokeAfter); err != nil {
				// Not fatal: the new certificate is in place and serving. The
				// cost is a superseded certificate staying valid until it
				// expires, which is strictly better than refusing to serve.
				slog.Warn("Could not record the superseded serving certificate for revocation",
					"serial", serialHexStr(superseded.SerialNumber), "error", err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// storedServingLeaf parses whatever serving certificate is in storage, or nil
// when there is none. Used to identify what a mint is about to replace.
//
// A nil result means there is nothing to supersede, and the caller acts on
// that: it skips recording a revocation. So the absent case and the
// cannot-read case must not look the same. Absent is nil with no noise;
// anything else is logged and counted, because silently skipping the record
// leaves the certificate being replaced valid for its full life — years — with
// nothing anywhere saying it should not be.
func (c *CA) storedServingLeaf(ctx context.Context) *x509.Certificate {
	certPEM, err := c.Storage.GetServingCert(ctx)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		// Without the error text: a SQL driver's connection error can carry
		// the DSN.
		slog.Warn("Serving certificate unreadable while recording supersession; " +
			"the certificate being replaced will not be scheduled for revocation")
		c.IncServingRevocationFailures()
		return nil
	}
	// The two parse arms below deliberately do not count a revocation failure.
	// That counter drives an alert whose text tells the operator a replaced
	// certificate "remains a valid credential" -- but bytes that do not parse
	// as a certificate are not a credential in circulation, so there is nothing
	// at risk and nothing to revoke. Only the read failure above is a genuine
	// "we could not tell".
	block, _ := pem.Decode(certPEM)
	if block == nil {
		slog.Warn("Stored serving certificate is not PEM; nothing to supersede")
		return nil
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		slog.Warn("Stored serving certificate is unparseable; nothing to supersede", "error", err)
		return nil
	}
	return leaf
}

// Reasons a stored serving certificate cannot be reused. Stable identifiers
// rather than prose, so an operator can grep or alert on them and so that
// nothing arbitrary ends up in the log line — see servingReason.
const (
	reasonNoCert          = "no-stored-certificate"
	reasonCertUnreadable  = "certificate-unreadable"
	reasonKeyMissing      = "key-missing"
	reasonKeyUnreadable   = "key-unreadable"
	reasonCertNotPEM      = "certificate-not-pem"
	reasonCertUnparseable = "certificate-unparseable"
	reasonKeyUnusable     = "key-unusable"
	reasonKeyMismatch     = "key-does-not-match-certificate"
	reasonNoCACert        = "ca-certificate-not-loaded"
	reasonForeignIssuer   = "not-issued-by-current-ca-certificate"
	reasonRenewalWindow   = "within-renewal-window"
	reasonMissingName     = "missing-configured-name"
	reasonRevocationCheck = "revocation-status-unknown"
	reasonRevoked         = "certificate-revoked"
)

// servingReason is why a stored serving certificate must be replaced: a stable
// code, plus optional detail for a human reading the log.
//
// The two are separate deliberately. Folding an arbitrary wrapped error into
// one free-form string made the log line unpredictable — it could carry a
// filesystem path, and on a SQL backend a driver error can carry the DSN, which
// carries a password. Keeping the code fixed means the log line's shape does
// not depend on what failed underneath, and confines anything variable to one
// field that callers can choose not to emit.
type servingReason struct {
	// Code is one of the reason* constants above. Always safe to log.
	Code string
	// Detail is supplementary and may be empty. It is derived from configured
	// values (a name, a duration) and never from an error whose text this code
	// does not control.
	Detail string
}

// LogValue renders the reason for slog, omitting an empty detail.
func (r servingReason) LogValue() slog.Value {
	if r.Detail == "" {
		return slog.StringValue(r.Code)
	}
	return slog.StringValue(r.Code + " (" + r.Detail + ")")
}

// loadUsableServingCert returns the stored serving certificate when every reuse
// condition holds, or nil plus the reason it must be replaced. The reason is
// logged, so a certificate churning between replicas is diagnosable from one
// line rather than by comparing serials.
//
// The subject lock is held; c.mu must NOT be, because IsRevokedSerial takes it
// for reading.
func (c *CA) loadUsableServingCert(ctx context.Context, cfg ServingConfig) (*ServingCertificate, servingReason) {
	certPEM, err := c.Storage.GetServingCert(ctx)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, servingReason{Code: reasonNoCert}
		}
		// A read failure is not evidence that the stored certificate is
		// unusable — it is evidence that we could not look. Treating it like
		// unusable material would let a degraded backend, where a read times
		// out under load but a write later succeeds, rotate the certificate
		// every replica is serving and schedule the good one it replaced for
		// revocation. Surfacing it instead leaves the running listener on the
		// certificate it already holds, counts a renewal failure, and retries
		// next pass, which is what the counter and its alert are for.
		//
		// Deliberately without the error text: this comes from the storage
		// backend, and a SQL driver's connection error can carry the DSN.
		return nil, servingReason{Code: reasonCertUnreadable}
	}
	keyPEM, err := c.Storage.GetServingKey(ctx)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// A torn write between the two Put calls: the certificate is
			// there and the key never landed. Genuinely unusable material,
			// so mint again.
			return nil, servingReason{Code: reasonKeyMissing}
		}
		// A read failure, which says nothing about the stored key. Same
		// reasoning as the certificate above: surface it, do not mint over it.
		return nil, servingReason{Code: reasonKeyUnreadable}
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, servingReason{Code: reasonCertNotPEM}
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, servingReason{Code: reasonCertUnparseable}
	}

	key, err := c.parseServingKey(keyPEM)
	if err != nil {
		// A rotated passphrase lands here. Mint again rather than crash-loop.
		//
		// The error is withheld for the same reason as above and one more: it
		// wraps resolvePassphrase, which names the configured passphrase file.
		// That is a path rather than a secret, but it has no business in a
		// routine Info line about certificate rotation.
		return nil, servingReason{Code: reasonKeyUnusable}
	}
	if !publicKeysEqual(leaf.PublicKey, key.Public()) {
		return nil, servingReason{Code: reasonKeyMismatch}
	}

	// Verify against the CA certificate this process actually loaded, not
	// against the AuthorityKeyId. The SKI is derived from the public key, so a
	// CA certificate re-signed by a new parent over the same key keeps the same
	// SKI — and a stale serving certificate would be silently retained.
	if c.CACert == nil {
		return nil, servingReason{Code: reasonNoCACert}
	}
	if err := leaf.CheckSignatureFrom(c.CACert); err != nil {
		return nil, servingReason{Code: reasonForeignIssuer}
	}

	if remaining := time.Until(leaf.NotAfter); remaining <= servingRenewBefore(cfg, leaf) {
		// Detail from our own clock arithmetic, not from an error.
		return nil, servingReason{
			Code:   reasonRenewalWindow,
			Detail: remaining.Round(time.Minute).String() + " remaining",
		}
	}

	if missing := missingNames(leaf, servingNames(cfg)); missing != "" {
		// Detail is a configured name, which the operator supplied and which
		// is already in the certificate this process serves.
		return nil, servingReason{Code: reasonMissingName, Detail: missing}
	}

	revoked, err := c.IsRevokedSerial(ctx, leaf.SerialNumber)
	if err != nil {
		return nil, servingReason{Code: reasonRevocationCheck}
	}
	if revoked {
		// This is the recovery route after `openvox-ca-ctl revoke` on the CA's
		// own hostname, which is the documented way to replace a compromised
		// serving key.
		return nil, servingReason{Code: reasonRevoked}
	}

	return &ServingCertificate{CertPEM: certPEM, KeyPEM: keyPEM, Leaf: leaf, Key: key}, servingReason{}
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
	// The serving key follows the leaf key configuration. No separate setting
	// selects its algorithm: nothing distinguishes the CA's own serving
	// certificate from any other leaf it issues, and an unused knob on a new
	// API is the cheapest kind not to have.
	keyCfg := c.LeafKeyConfig
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
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
	if lifetime <= 0 {
		return 0
	}
	if cfg.RenewBefore <= 0 {
		return lifetime / 3
	}

	// Clamped to half the certificate's actual lifetime, which configuration
	// validation cannot do on its own: issueLeafLocked caps every certificate at
	// the CA certificate's *remaining* life, so a window that was comfortably
	// inside the configured lifetime becomes larger than the real one as the CA
	// certificate ages. Without the clamp the certificate is due for renewal the
	// moment it is signed, and the maintenance task reissues on every pass —
	// each one signing, appending to the inventory, and growing and re-signing
	// the CRL. Renewing at half-life instead is the conservative reading of an
	// over-large window, and it converges.
	if cfg.RenewBefore >= lifetime {
		return lifetime / 2
	}
	return cfg.RenewBefore
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

// supersededEntry records a serving certificate awaiting revocation.
type supersededEntry struct {
	Serial   string    `json:"serial"`
	RevokeAt time.Time `json:"revoke_at"`
}

// recordSuperseded appends leaf to the pending-revocation list.
//
// Not named *Locked: in this package that suffix means c.mu is held, and this
// runs with c.mu released. It needs only the subject lock, which the caller
// holds.
//
// The list is durable and shared rather than held in memory: the replica that
// minted the replacement may die before the delay elapses, and a restarted
// replica would otherwise never know a supersession was pending. It also cannot
// be derived from the inventory, because issueLeafLocked backdates NotBefore by
// a fixed 24 hours, so the recorded timestamp is not the issue time.
//
// The subject lock is held by the caller, which is what serialises this against
// concurrent mints.
func (c *CA) recordSuperseded(ctx context.Context, leaf *x509.Certificate, revokeAfter time.Duration) error {
	if revokeAfter <= 0 || leaf == nil {
		return nil
	}
	entries, err := c.readSuperseded(ctx)
	if err != nil {
		// Appending to what we could not read would write a one-entry list over
		// however many were pending, so every one of those certificates would
		// stay valid with nothing recording that it should not be.
		return err
	}
	entries = append(entries, supersededEntry{
		Serial:   serialHexStr(leaf.SerialNumber),
		RevokeAt: time.Now().UTC().Add(revokeAfter),
	})
	return c.writeSuperseded(ctx, entries)
}

// ReconcileSuperseded revokes serving certificates whose delay has elapsed and
// prunes the list.
//
// It reconciles rather than merely draining. With the delay set back to zero —
// or tls_self_provision switched off — entries already recorded would otherwise
// sit there indefinitely and fire much later if the delay were re-enabled. So a
// zero delay discards the list without revoking.
//
// Revocation is by recorded serial, never by subject. CA.Revoke resolves
// subject to *current* certificate, so calling it here would revoke the live
// serving certificate — the exact opposite of the intent.
//
// Idempotent and self-healing: revoking an already-revoked serial is a no-op,
// and any replica completes work the minting replica started.
//
// # Lock discipline
//
// The whole read-modify-write runs under the *subject* lock, which is the same
// lock EnsureServingCert holds while it appends. That is the point: without it
// the two serialise on different locks and so do not exclude each other, and a
// replica minting between this function's read and its write has its new entry
// erased by the write — leaving a superseded certificate valid for its full
// remaining life with nothing recording that it should not be. On a filesystem
// or SQLite backend WithLock is process-local and the window is invisible; on
// etcd, Redis or SQL — the multi-replica deployment this feature exists for —
// it is real.
//
// Subject lock → CRL lock → c.mu, the order Clean and AutoRenew already use.
// Taking them in any other order risks deadlocking against them.
func (c *CA) ReconcileSuperseded(ctx context.Context, cfg ServingConfig) error {
	if cfg.Subject == "" {
		return fmt.Errorf("serving certificate subject is required")
	}
	// Shadowed, not a separate acquisition context: this critical section does
	// a CRL read-modify-write, so the deadline has to cover the work as well as
	// the wait. See EnsureServingCert.
	ctx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()

	return c.Storage.WithLock(ctx, subjectLockName(cfg.Subject), func() error {
		entries, err := c.readSuperseded(ctx)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			return nil
		}

		if cfg.RevokeAfter <= 0 {
			slog.Info("Discarding pending serving-certificate revocations; revocation is disabled",
				"count", len(entries))
			return c.writeSuperseded(ctx, nil)
		}

		now := time.Now().UTC()
		var due, pending []supersededEntry
		for _, e := range entries {
			if now.After(e.RevokeAt) {
				due = append(due, e)
			} else {
				pending = append(pending, e)
			}
		}
		if len(due) == 0 {
			return nil
		}

		err = c.Storage.WithLock(ctx, lockNameCRL, func() error {
			c.mu.Lock()
			defer c.mu.Unlock()
			for _, e := range due {
				if err := c.revokeSerialLocked(ctx, e.Serial); err != nil {
					return fmt.Errorf("revoking superseded serving certificate %s: %w", e.Serial, err)
				}
				slog.Info("Revoked superseded serving certificate", "serial", e.Serial)
			}
			return nil
		})
		if err != nil {
			// Leave the list intact so the next pass retries; a failed
			// revocation that was pruned anyway would leave a valid credential
			// in circulation with nothing recording that fact.
			return err
		}
		return c.writeSuperseded(ctx, pending)
	})
}

// readSuperseded loads the pending-revocation list.
//
// An absent list is empty and not an error: that is the steady state before the
// first supersession. A read that *fails*, though, is reported, because both
// callers go on to write the list back — and a failed read reported as "empty"
// would have them persist an empty list over entries that are still there,
// silently un-scheduling every pending revocation.
//
// An unparseable list is still treated as empty, deliberately and with a
// warning: those bytes are already unusable, nothing can be recovered from
// them, and failing closed on a corrupt blob would take the listener down over
// a certificate that at worst stays valid until it expires.
func (c *CA) readSuperseded(ctx context.Context) ([]supersededEntry, error) {
	data, err := c.Storage.GetServingSuperseded(ctx)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		// Without the backend's error text, for the reason storedServingLeaf
		// gives: a SQL driver's connection error can carry the DSN, and this
		// error reaches a Warn line on the mint path.
		return nil, errors.New("reading pending serving-certificate revocations")
	}
	var entries []supersededEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		slog.Warn("Discarding unparseable pending serving-certificate revocations", "error", err)
		return nil, nil
	}
	return entries, nil
}

// writeSuperseded persists the pending-revocation list.
func (c *CA) writeSuperseded(ctx context.Context, entries []supersededEntry) error {
	if len(entries) == 0 {
		entries = []supersededEntry{}
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("encoding pending serving-certificate revocations: %w", err)
	}
	return c.Storage.SaveServingSuperseded(ctx, data)
}

// servingSerialMatches reports whether serial is the one in the certificate the
// listener is currently serving.
//
// Used to stop routine per-subject administration revoking the CA's own serving
// certificate when a node has taken the CA's hostname. Failure to read or parse
// is reported as "no match": this guards a revocation that is otherwise correct,
// so it must not suppress it on a storage blip.
func (c *CA) servingSerialMatches(ctx context.Context, serial string) bool {
	if serial == "" {
		return false
	}
	certPEM, err := c.Storage.GetServingCert(ctx)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	// Normalise both sides: the inventory string and serialHexStr can differ in
	// padding, which is why deleteStoredCertIfSerialMatches does the same.
	want := new(big.Int)
	if _, ok := want.SetString(serial, 16); !ok {
		return false
	}
	return serialHexStr(leaf.SerialNumber) == serialHexStr(want)
}
