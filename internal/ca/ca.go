// Copyright (C) 2026 Trevor Vaughan
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
	"crypto"
	"crypto/x509"
	"sync"
	"sync/atomic"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// CASubjectConfig holds optional X.509 subject fields for a bootstrapped CA
// certificate. Zero fields use defaults; CommonName in the signed cert is
// always derived from Hostname as "Puppet CA: <hostname>" unless overridden
// by the Org/OrgUnit/Country/Locality/Province fields below.
type CASubjectConfig struct {
	Org      string
	OrgUnit  string
	Country  string
	Locality string
	Province string
}

type CA struct {
	Storage        *storage.StorageService
	CACert         *x509.Certificate
	CAKey          crypto.Signer
	AutosignConfig AutosignConfig
	Hostname       string

	// CAKeyConfig controls the algorithm and key size used when bootstrapping a
	// new CA certificate. Zero value uses DefaultCAKeyConfig (RSA 4096).
	// Ignored when a CA already exists on disk.
	CAKeyConfig KeyConfig

	// LeafKeyConfig controls the algorithm and key size for server-side
	// generated leaf certificates (Generate). Zero value uses
	// DefaultLeafKeyConfig (RSA 2048).
	LeafKeyConfig KeyConfig

	// CASubject holds optional subject DN fields for a bootstrapped CA
	// certificate. Ignored when a CA already exists on disk.
	CASubject CASubjectConfig

	// CAPathLength sets the BasicConstraints pathLenConstraint on a bootstrapped
	// CA certificate. -1 (the default) means no constraint (unconstrained). 0
	// means no intermediate CAs are allowed. N > 0 means up to N levels of
	// intermediate CAs. Ignored when a CA already exists on disk.
	CAPathLength int

	// CAValidityDays overrides the default CA certificate lifetime when
	// bootstrapping a new CA. Zero uses the built-in default (~5 years).
	// Ignored when a CA already exists on disk.
	CAValidityDays int

	// LeafValidityDays overrides the default leaf certificate lifetime used
	// when signing CSRs and generating server-side key pairs. Zero uses the
	// built-in default (~5 years). A per-request cert_ttl always takes
	// precedence over this value.
	LeafValidityDays int

	// OCSPURLs, when non-nil, causes newly issued certs to embed an AIA
	// extension pointing at the OCSP responder. Set before calling Init().
	OCSPURLs []string

	// CRLURLs, when non-nil, causes newly issued certs to embed a CRL
	// Distribution Points extension (RFC 5280 §4.2.1.13) so that verifiers
	// can automatically retrieve the CRL. Set before calling Init().
	CRLURLs []string

	// CRLValidityDays overrides the default CRL validity window. Zero uses the
	// built-in default (30 days).
	CRLValidityDays int

	// KeyPassphrase configures how the CA private key is encrypted at rest.
	// When set, the key is stored as an encrypted PEM (AES-256-GCM + Argon2id).
	// When nil/zero, keys are stored as unencrypted PEM (backward compatible).
	KeyPassphrase KeyPassphraseConfig

	// EncryptCAKey controls whether the CA key is encrypted at rest.
	// When true, the key is encrypted using the resolved passphrase.
	EncryptCAKey bool

	// PromoteCNToSAN, when true (the default), adds the CSR's Common Name as a
	// DNS Subject Alternative Name when the CSR carries no SANs. RFC 2818 §3.1
	// deprecated CN-based hostname verification in favour of the SAN extension;
	// modern TLS clients (Go stdlib, Chrome, etc.) ignore the CN entirely. Set
	// to false only when issuing certificates to legacy clients that cannot
	// handle the SAN extension.
	PromoteCNToSAN bool

	// RevokeOnAutoRenew, when true (the default), revokes the certificate
	// being replaced by AutoRenew (the empty-body /certificate_renewal path)
	// once its successor is safely signed and stored, so only the newest
	// serial for a subject is ever valid. OpenVox Server's own Clojure CA
	// does not do this — both the old and new certs (same key) stay valid
	// until the old one naturally expires. Set to false to match that
	// behaviour exactly. This does not affect the CSR-based Renew path
	// (a genuine re-key), which always revokes the certificate it replaces.
	RevokeOnAutoRenew bool

	// ExternalSigner, when non-nil, is used instead of loading the CA private
	// key from disk. This enables key isolation: the private key lives in a
	// separate process and signing requests are proxied over IPC.
	// Set before calling Init(). When set, Init() skips key file loading and
	// the key-cert match verification (the signer process verifies this).
	ExternalSigner crypto.Signer

	// KeyProvider, when non-nil, is consulted instead of the local PEM-file
	// logic (loadCAKeyFromDisk/generateKey/SaveCAKey) for loading or
	// bootstrapping the CA's private key — e.g. internal/signer/openbao's
	// OpenBao Transit-backed provider. Set before calling Init(), only in
	// the process that actually holds/reaches the key (the isolated signer
	// child, or the single-process role); mutually exclusive with
	// ExternalSigner, which is used by the frontend instead. See
	// keyprovider.go.
	KeyProvider KeyProvider
	serialIndex map[string]string         // uppercase hex serial (no leading zeros) → subject; protected by mu
	ocspCache   map[string]ocspCacheEntry // same key; protected by mu
	cachedCRL   *x509.RevocationList      // in-memory CRL for auth checks; protected by mu
	mu          sync.RWMutex

	// crlUpdateFailures counts failures to amend the CRL: a revocation that
	// could not be recorded (bad serial, unreadable CRL) or a CRL that could
	// not be re-signed or written (during revoke, cleanup, reissue or refresh).
	// Some callers treat these as fatal and return the error; others — notably
	// the best-effort revoke of a superseded certificate on renewal — swallow
	// it so the primary operation still succeeds. Either way a rising count
	// means the CRL is not being maintained and, for revocations, that a
	// superseded certificate may still be a valid credential. Exposed via the
	// metrics exporter (puppetca_crl_update_failures_total) for alerting.
	crlUpdateFailures atomic.Uint64

	// servingCertIssued counts serving certificates this process has minted.
	// Exposed as puppetca_serving_cert_issued_total, and it is a rate rather
	// than a total that matters: two replicas can disagree about which CA
	// certificate is current — one restarted after a re-issue, one not — and
	// each will then mint over the other's work on every pass. That shows up
	// here as sustained churn, where inferring it from certificate serials
	// would mean noticing an inventory growing for no reason.
	servingCertIssued atomic.Uint64

	// servingRenewalFailures counts maintenance passes that could not renew the
	// serving certificate. The existing certificate stays in place and the next
	// cycle retries, so a single failure is harmless — but a persistently
	// failing pass is invisible until the certificate expires, and it also
	// breaks the assumption behind tls_self_provision_revoke_after_sec, which
	// bounds a superseded certificate's exposure on the belief that every
	// replica notices its replacement within one interval. Alert on this.
	servingRenewalFailures atomic.Uint64

	// crlNotify carries a coalesced signal each time the CRL is re-signed (see
	// signCRLLocked). It is buffered to depth 1 and written non-blockingly, so a
	// burst of revocations collapses to a single pending notification and an
	// absent consumer never blocks signing. Consume it via CRLUpdated().
	crlNotify chan struct{}
}

func New(s *storage.StorageService, autosignCfg AutosignConfig, hostname string) *CA {
	return &CA{
		Storage:           s,
		AutosignConfig:    autosignCfg,
		Hostname:          hostname,
		CAPathLength:      -1,   // unconstrained by default
		PromoteCNToSAN:    true, // on by default; RFC 2818 deprecates CN-only certs
		RevokeOnAutoRenew: true, // on by default; only the newest serial should be valid
		serialIndex:       make(map[string]string),
		ocspCache:         make(map[string]ocspCacheEntry),
		crlNotify:         make(chan struct{}, 1),
	}
}

// CRLUpdateFailures returns the number of times the CA failed to amend the
// CRL — a revocation it could not record, or a CRL it could not re-sign or
// write (across the revoke, cleanup, reissue and refresh paths). A rising
// value means the CRL is not being maintained; the metrics exporter surfaces
// it as puppetca_crl_update_failures_total.
func (c *CA) CRLUpdateFailures() uint64 {
	return c.crlUpdateFailures.Load()
}

// ServingCertIssued returns how many serving certificates this process has
// minted. Surfaced as puppetca_serving_cert_issued_total; a sustained rate
// rather than a one-off increment indicates replicas disagreeing about which CA
// certificate is current, which a fleet restart resolves.
func (c *CA) ServingCertIssued() uint64 {
	return c.servingCertIssued.Load()
}

// IncServingRenewalFailures records a maintenance pass that could not renew the
// serving certificate. Called by the maintenance loop, which owns the retry
// policy; the CA itself has no periodic tasks.
func (c *CA) IncServingRenewalFailures() {
	c.servingRenewalFailures.Add(1)
}

// ServingRenewalFailureCount returns how many maintenance passes failed to
// renew the serving certificate. Surfaced as
// puppetca_serving_cert_renewal_failures_total.
func (c *CA) ServingRenewalFailureCount() uint64 {
	return c.servingRenewalFailures.Load()
}

// CRLUpdated returns a channel that receives a value each time the CRL is
// re-signed (revoke, reissue, background refresh, or expired-cert cleanup).
// Notifications are coalesced: the channel is buffered to depth 1 and written
// non-blockingly, so when several CRL updates happen before the consumer reads,
// only a single pending signal is observed. Intended for a single consumer
// (e.g. the Kubernetes exporter) that re-reads the current CRL on each wake-up.
func (c *CA) CRLUpdated() <-chan struct{} {
	return c.crlNotify
}

// IsReady reports whether the CA has been fully initialized and can serve requests.
func (c *CA) IsReady() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.CACert != nil && c.CAKey != nil
}

// LoadKey loads the CA private key and certificate from disk without full
// initialization (no HMAC, serial index, or CRL cache).
func (c *CA) LoadKey(ctx context.Context) (crypto.Signer, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.loadCA(ctx); err != nil {
		return nil, err
	}
	return c.CAKey, nil
}
