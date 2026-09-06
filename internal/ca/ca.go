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
	"crypto/x509/pkix"
	"sync"
	"sync/atomic"
	"time"

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

// CASubjectName builds the X.509 subject DN for this CA's own certificate.
//
// It is exported and used from two places that MUST agree: bootstrapCA, which
// self-signs a certificate carrying this DN, and the certificate signing
// request emitted for an external parent to sign. A CSR whose subject differs
// from the DN the CA would otherwise use produces an intermediate certificate
// issued for the wrong name — discovered only after a third party has signed
// it, which is expensive to undo. Keeping one builder makes the two
// structurally incapable of disagreeing.
func CASubjectName(hostname string, cfg CASubjectConfig) pkix.Name {
	subject := pkix.Name{
		CommonName: "Puppet CA: " + hostname,
	}
	if cfg.Org != "" {
		subject.Organization = []string{cfg.Org}
	}
	if cfg.OrgUnit != "" {
		subject.OrganizationalUnit = []string{cfg.OrgUnit}
	}
	if cfg.Country != "" {
		subject.Country = []string{cfg.Country}
	}
	if cfg.Locality != "" {
		subject.Locality = []string{cfg.Locality}
	}
	if cfg.Province != "" {
		subject.Province = []string{cfg.Province}
	}
	return subject
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

	// AllowSubjectAltNames, when true, lets a submitted CSR request Subject
	// Alternative Names of its own. When false (the default), a CSR carrying any
	// SAN other than a lone DNS entry equal to its own certname is refused at
	// signing time rather than being trimmed or honoured.
	//
	// SECURITY: TLS peers match the name they dialled against the SAN set, not
	// the Common Name, so an unconstrained SAN request is a request to be
	// somebody else. A node autosigned as web01 asking for
	// DNS:puppet.example.com would otherwise be handed a certificate that
	// impersonates the CA server to everything trusting this PKI. Defaults to
	// false to match OpenVox Server's own allow-subject-alt-names, which an
	// operator arriving from Puppet Server expects to exist and to be off.
	// NIST 800-53: AC-6 (Least Privilege), IA-5(2) (PKI-Based Authentication)
	//
	// Enforcement only: it decides what a CSR may *ask* for, not what is
	// issued. Only DNS names are carried onto a certificate today, so with this
	// set to true a request for an IP, email or URI SAN is signed and the SAN
	// dropped — see #241, which adds the carry-through this gate assumes.
	//
	// The boundary is the CSR, not the caller: this governs names carried on a
	// submitted certificate request, wherever it arrives from. Minting reaches
	// issueLeafLocked directly, never through signWithDuration, so it is not
	// gated: one direct caller, GenerateWithOptions, which Generate delegates to
	// -- issuanceseam_test.go pins that caller set. Both entry points into it
	// take names an administrator supplied. The offline `openvox-ca generate --dns` takes its names from an
	// operator on the CA host; POST /generate/{subject}?dns= takes them from a
	// query string, and *is* a request, admitted by lookupTier's tierAdminOnly
	// default. Both mint from names an administrator supplied directly rather
	// than from an agent's CSR, which is the distinction that makes the
	// exemption safe -- not the fact that one of them is offline.
	AllowSubjectAltNames bool

	// NoBootstrap makes Init refuse to create a new CA when none is found,
	// rather than bootstrapping one. For tools that operate on an existing CA
	// and have nothing sensible to do without it: minting a fresh root because
	// a path was mistyped is far worse than an error, since the operator ends
	// up with certificates nobody trusts and no obvious sign of why.
	//
	// This is a backstop, not a read-only mode. Init writes before it reaches
	// the bootstrap decision — EnsureDirs, InitHMAC (which regenerates the
	// inventory HMAC key if the stored one is the wrong length), and the CRL
	// seeding on the load path — so a caller that must not touch storage at all
	// has to check before calling Init, not rely on this.
	NoBootstrap bool

	// RevokeOnAutoRenew, when true (the default), revokes the certificate
	// being replaced by AutoRenew (the empty-body /certificate_renewal path)
	// once its successor is safely signed and stored, so only the newest
	// serial for a subject is ever valid. OpenVox Server's own Clojure CA
	// does not do this — both the old and new certs (same key) stay valid
	// until the old one naturally expires. Set to false to match that
	// behaviour exactly. This does not affect the CSR-based Renew path
	// (a genuine re-key), which always retires the certificate it replaces.
	//
	// It is a whether, not a when: SupersedeAfter decides how long the
	// replaced certificate stays valid before the revocation lands.
	RevokeOnAutoRenew bool

	// SupersedeAfter delays the revocation of a certificate a renewal has
	// replaced by this long, instead of revoking it in the renewal call. The
	// replaced serial is recorded on a durable, cross-subject list and a
	// periodic sweep (ReconcileSuperseded) revokes it once the delay elapses.
	//
	// Zero is the behaviour that predates the list: the replaced certificate is
	// revoked immediately, inside the renewal, and nothing is recorded. It is
	// this type's zero value, so a CA constructed without setting it — the
	// offline commands and openvox-ca-ctl — retires immediately, which is the
	// right default for a deliberate operator action at a terminal.
	//
	// It is *not* what the server does. `openvox-ca serve` sets this from
	// superseded_cert_revoke_after_sec, which defaults to 24h, so an ordinary
	// deployment grants a window. The two differ deliberately: a fleet renewing
	// on a timer needs the overlap, and an operator revoking by hand does not.
	//
	// A positive value is a deliberate weakening of that: for the length of the
	// window the replaced certificate — and, on the CSR-based re-key path, the
	// replaced *private key* — remains a credential this CA accepts. It buys
	// the overlap a fleet needs to pick up a replacement without a gap, which is
	// what makes a renewal safe to perform on a certificate other parties are
	// actively verifying. Set it no longer than that pickup takes.
	//
	// It applies to both renewal paths: the CSR-based Renew and, subject to
	// RevokeOnAutoRenew, AutoRenew. RevokeOnAutoRenew still decides whether
	// AutoRenew retires its predecessor at all; this decides when.
	SupersedeAfter time.Duration

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

	// SigningConcurrency caps how many CA-key signatures may be in flight at
	// once, across issuance, CRL re-signing and the OCSP responder together.
	// Zero (the type's zero value) means unbounded. Set before calling Init(),
	// which is what sizes the bound.
	//
	// The cap is shared deliberately: there is one key, and what needs bounding
	// is the load on whatever holds it, not the load on any one endpoint. The
	// two halves behave differently under it, which is the substance rather
	// than a detail — issuance and CRL work waits for a slot, the OCSP
	// responder sheds. See signbound.go for why, and
	// docs/development/locking.md for what it does and does not protect.
	//
	// The right size is a property of the deployment's signer: an in-process
	// software key, an isolated signer over IPC and an OpenBao Transit key have
	// very different concurrency envelopes. `openvox-ca serve` resolves an
	// unset ca_signing_concurrency to a ceiling that is safe rather than tuned;
	// an operator running a remote signer should lower it to that signer's
	// capacity.
	SigningConcurrency int

	// signSlots is the signing bound itself: a token per permitted concurrent
	// signature. Nil means unbounded, which is what every helper in
	// signbound.go checks for, so a CA that never had Init called — or one
	// configured with a non-positive limit — signs exactly as it did before the
	// bound existed. Sized by initSigningBound.
	signSlots chan struct{}

	// signWait is how long acquireSigningSlotOrShed waits for a slot before
	// shedding. Set to ocspSigningWait by initSigningBound; overridden in tests
	// so a spec that must observe a shed does not spend a real second doing it,
	// the same seam destructiveOpTracker's now() provides in internal/api.
	signWait time.Duration

	serialIndex map[string]string         // uppercase hex serial (no leading zeros) → subject; protected by mu
	ocspCache   map[string]ocspCacheEntry // same key; protected by mu
	cachedCRL   *x509.RevocationList      // in-memory CRL for auth checks; protected by mu
	mu          sync.RWMutex

	// serialIndexEpoch counts in-process mutations of serialIndex (issuance and
	// cleanup, via indexSerialLocked/unindexSerialLocked). SyncSerialIndex
	// samples it before its storage read and again after taking the lock, so it
	// can tell whether the inventory it read is still a complete account of
	// what this process knows. Protected by mu; not atomic, because every
	// reader and writer holds the lock anyway and an atomic would suggest
	// otherwise.
	serialIndexEpoch uint64

	// serialIndexRemovalEpoch counts serials leaving serialIndex, by any route:
	// a local prune via unindexSerialLocked, or a sync pass applying a removal
	// storage has already made. It gates the *addition* half of a reconcile,
	// where serialIndexEpoch gates the removal half.
	//
	// Two counters rather than one because the two halves fail in opposite
	// directions. A pass that races an issuance must still add — that is the
	// common case and the whole point of the job. A pass that races a *removal*
	// must not add, because the serials it read are no longer all live and it
	// cannot tell which. One counter cannot express both: gating additions on
	// serialIndexEpoch would make every issuance defer the additions it exists
	// to deliver. Protected by mu.
	serialIndexRemovalEpoch uint64

	// serialIndexSyncFailures counts failures to refresh the OCSP serial index
	// from the inventory (see SyncSerialIndex): an unreadable inventory, or on a
	// blob backend one whose HMAC no longer verifies. While it rises, this
	// replica's OCSP responder answers `unknown` for any certificate signed
	// elsewhere since the last successful pass — not a revocation bypass, but a
	// verifier that hard-fails on `unknown` sees one replica reject what the
	// others accept. Exposed via the metrics exporter
	// (puppetca_ocsp_index_sync_failures_total) for alerting.
	serialIndexSyncFailures atomic.Uint64

	// crlUpdateFailures counts failures to amend the CRL: a CRL that could not
	// be re-signed, written or read, on any of the five paths that write one
	// (revoke by subject, revoke by serial, cleanup, reissue, refresh) — the
	// read half centrally, in readStoredCRL, which is what makes this cover all
	// five — plus, on the revoke paths only, a bad serial or a failed inventory
	// read while resolving
	// the subject's serial. That last one is how a revocation which merely
	// queued past LockTimeout lands here on the single-node backends, where the
	// spent deadline is not spotted until the read; one refused at a lock
	// acquisition fails earlier and is not counted — every backend's cross-node
	// acquisition, and on the single-node ones a wait for another process on the
	// same host. See docs/metrics.md.
	// Some callers treat these as fatal and return the error; others — notably
	// the best-effort revoke of a superseded certificate on renewal — swallow
	// it so the primary operation still succeeds. Either way a rising count
	// means the CRL is not being maintained and, for revocations, that a
	// superseded certificate may still be a valid credential. Exposed via the
	// metrics exporter (puppetca_crl_update_failures_total) for alerting.
	crlUpdateFailures atomic.Uint64

	// crlSyncFailures counts failures to refresh the in-memory CRL from storage
	// (see SyncCRLCache): an unreadable or unparseable stored CRL, or one this
	// CA did not sign. Distinct from crlUpdateFailures, which counts failures to
	// *amend* the CRL — this one is about a replica falling behind an amendment
	// some other replica made. While it rises, this process is deciding
	// revocation from a CRL that may predate a revocation elsewhere in the
	// fleet, so a certificate revoked there may still be admitted here. Exposed
	// via the metrics exporter (puppetca_crl_sync_failures_total) for alerting.
	crlSyncFailures atomic.Uint64

	// supersedeFailures counts failures to schedule or carry out a delayed
	// revocation: a supersession the renewal path could not record, a
	// pending-revocation list that could not be read or parsed, a sweep pass
	// that could not take the CRL lock or write the list back, and each pass
	// that left an entry unrevoked or discarded one whose serial it could never
	// revoke. A pass counts once however many entries it failed on. Distinct from crlUpdateFailures, which counts failures to
	// amend the CRL — an entry can be lost here without the CRL ever being
	// touched. While it rises, a certificate that a renewal replaced may still
	// be a valid credential, and on a lost entry nothing else records that it
	// should not be. Exposed via the metrics exporter
	// (puppetca_supersede_failures_total) for alerting.
	supersedeFailures atomic.Uint64

	// Four counters, because their remedies differ: crlChainFailures points at
	// the file itself, crlChainDiscarded at the CA bundle, crlChainRegressed at
	// whatever writes the file, and crlChainRemoved at either the file or the
	// bundle, being the one with two causes. (The file's *mount* is a fifth
	// question, and it is crlChainLastRead below, a gauge rather than a counter,
	// because "never opened" is a state and not an event.)
	//
	// crlChainRemoved is the one with two causes, because it is named for an
	// outcome rather than a fault: an ancestor's CRL stops being published
	// either because the file stopped listing it, or because the ancestor's
	// certificate left the CA bundle and nothing signs its CRL any more. The
	// second points at the bundle, like crlChainDiscarded, so an incomplete
	// bundle can move both at once -- discarded for the file's copy, removed for
	// the published one. The log line names which fired.
	//
	// Three of the four are per *evaluation*, not per pass: crl_chain_file is
	// evaluated on every CRL amendment as well as on each refresh pass, so on a
	// busy CA they track revocation rate rather than the number of bad CRLs in
	// the file. crlChainFailures counts the whole file once per evaluation.
	// crlChainDiscarded and crlChainRegressed count once per CRL per evaluation.
	// All three describe what the file currently *holds*, which is a standing
	// condition worth re-counting for as long as it stands.
	//
	// crlChainRemoved is the exception, because it reports a transition rather
	// than a standing condition: an ancestor that is published and is about to
	// stop being. It deduplicates by *ancestor* -- its main arm keys on the
	// signing certificate, its bundle-attribution arm on the issuer DN, because
	// there is no signer left to key on -- and it counts only on the pass that
	// publishes. RefreshCRLChainFile evaluates twice per rewrite, once to decide
	// and once inside reissueCRLLocked to build what it publishes, and the
	// ancestor is still in the published chain both times; counting on both made
	// one lost ancestor read as 2. See upstreamPass in crlchainfile.go.
	//
	// Do not assume an ordering between them. An unreadable or unparseable file
	// increments crlChainFailures alone, because upstreamCRLs returns before the
	// per-CRL loops are reached.
	//
	// What an alert window can be sized against is the floor they share: a quiet
	// CA evaluates the file once per crl_chain_refresh_interval_sec. See
	// mixin/config.libsonnet, which says the same thing.
	//
	// crlChainFailures counts refresh passes that could not publish the upstream
	// chain at all -- unreadable, unparseable, truncated or oversized. The
	// published chain is left alone and the next pass retries.
	//
	// crlChainDiscarded counts CRLs dropped from crl_chain_file because nothing
	// in the CA bundle signed them. This is the case where the chain quietly
	// *shrinks*: the file is authoritative, so a CRL the operator put there and
	// this CA would not accept simply stops being published.
	//
	// crlChainRegressed counts CRLs in crl_chain_file that were older than the
	// one already published for the same ancestor, and so were not used -- see
	// monotonicUpstream. It is deliberately not folded into crlChainDiscarded:
	// the two have opposite remedies. A discard means the CA bundle is missing
	// an ancestor, so the operator checks the bundle; a regression means the
	// file itself is stale, rolled back or replayed, so the operator checks
	// whatever writes it. One counter would have sent a paged responder to
	// verify a bundle that was already complete.
	//
	// crlChainRemoved counts ancestors whose published CRL has been dropped from
	// the chain: either the file stopped listing them, or their certificate left
	// the CA bundle so nothing signs that CRL any more. Honoured rather than
	// refused, unrecoverable here, and a `cat` glob that matched one file fewer
	// produces the first just as readily as a deliberate removal does. It
	// overlaps crlChainDiscarded rather than being distinct from it: an
	// incomplete bundle moves both, discarded for the copy the file carries and
	// removed for the copy already published.
	//
	// Surfaced as puppetca_crl_chain_refresh_failures_total,
	// puppetca_crl_chain_discarded_total, puppetca_crl_chain_regressed_total and
	// puppetca_crl_chain_removed_total.
	crlChainFailures  atomic.Uint64
	crlChainDiscarded atomic.Uint64
	crlChainRegressed atomic.Uint64
	crlChainRemoved   atomic.Uint64

	// crlChainLastRead is the Unix time of the last successful read of
	// crl_chain_file, or zero if it has never been read.
	//
	// It exists for the case the counters cannot reach: an absent file is
	// deliberately not a failure -- it makes no statement -- so a crl_chain_file
	// pointing at a path that never mounted leaves every counter at zero and
	// every series flat and healthy while the ancestors age out. This series
	// stays at zero, which is the signal.
	//
	// It does *not* detect a subPath mount, and an earlier revision of this
	// comment wrongly claimed it did. A subPath mount is read successfully
	// forever, so the stamp advances every cycle exactly as it does on a healthy
	// file; the two are indistinguishable here. What catches a frozen mount is
	// the upstream CRL's own nextUpdate marching towards expiry --
	// PuppetCAUpstreamCRLExpiringSoon firing on a CA that has crl_chain_file
	// configured *is* the subPath signature.
	crlChainLastRead atomic.Int64

	// CRLChainFile is a PEM bundle of upstream CRLs merged into the published
	// chain. Empty disables the feature, which is the whole of it for a CA that
	// issues its own root. Every CRL in the file is signature-verified against
	// the stored CA bundle before it is published — see upstreamCRLs.
	CRLChainFile string

	// signingShed counts OCSP responses refused because the CA-key signing
	// bound was full for longer than ocspSigningWait. Only the OCSP path can
	// raise it; issuance and CRL re-signing queue rather than shed, so they
	// never appear here however long they waited.
	//
	// A rising value is the bound working, not a fault — but it is the only
	// signal that distinguishes "this deployment never approaches its limit"
	// from "this deployment is refusing revocation-status answers continuously",
	// and those want very different responses from an operator. Exposed via the
	// metrics exporter (puppetca_ca_signing_shed_total) for alerting.
	signingShed atomic.Uint64

	// crlNotify carries a coalesced signal each time the CRL is re-signed (see
	// signCRLLocked). It is buffered to depth 1 and written non-blockingly, so a
	// burst of revocations collapses to a single pending notification and an
	// absent consumer never blocks signing. Consume it via CRLUpdated().
	crlNotify chan struct{}
}

func New(s *storage.StorageService, autosignCfg AutosignConfig, hostname string) *CA {
	return &CA{
		Storage:        s,
		AutosignConfig: autosignCfg,
		Hostname:       hostname,
		CAPathLength:   -1,   // unconstrained by default
		PromoteCNToSAN: true, // on by default; RFC 2818 deprecates CN-only certs
		// AllowSubjectAltNames is deliberately left false: a CSR may not name
		// itself anything it likes. See the field's comment.
		RevokeOnAutoRenew: true, // on by default; only the newest serial should be valid
		serialIndex:       make(map[string]string),
		ocspCache:         make(map[string]ocspCacheEntry),
		crlNotify:         make(chan struct{}, 1),
	}
}

// CRLUpdateFailures returns the number of times the CA failed to amend the
// CRL — a revocation it could not record, or a CRL it could not re-sign or
// write (across the revoke-by-subject, revoke-by-serial, cleanup, reissue and
// refresh paths). A rising
// value means the CRL is not being maintained; the metrics exporter surfaces
// it as puppetca_crl_update_failures_total.
func (c *CA) CRLUpdateFailures() uint64 {
	return c.crlUpdateFailures.Load()
}

// CRLSyncFailures returns the number of times the CA failed to refresh its
// in-memory CRL from storage (see SyncCRLCache). A rising value means this
// replica's revocation checks are answering from a CRL that may be behind the
// stored one, so a certificate revoked on another replica may still be
// accepted here; the metrics exporter surfaces it as
// puppetca_crl_sync_failures_total.
func (c *CA) CRLSyncFailures() uint64 {
	return c.crlSyncFailures.Load()
}

// SerialIndexSyncFailures returns the number of times the CA failed to refresh
// its OCSP serial index from the inventory (see SyncSerialIndex). A rising
// value means this replica's OCSP responder is answering `unknown` for
// certificates issued elsewhere since the last successful pass; the metrics
// exporter surfaces it as puppetca_ocsp_index_sync_failures_total.
func (c *CA) SerialIndexSyncFailures() uint64 {
	return c.serialIndexSyncFailures.Load()
}

// SerialIndexSize returns how many serials this replica's OCSP responder
// recognises. A serial it does not hold is answered `unknown` before the CRL is
// consulted, so this is the size of what the responder will speak about at all;
// the metrics exporter surfaces it as puppetca_ocsp_index_serials, and specs
// use it to assert a sync pass landed without reaching into unexported state.
func (c *CA) SerialIndexSize() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.serialIndex)
}

// CRLChainFailures returns how many reads of crl_chain_file failed --
// unreadable, unparseable, not ending on a PEM block boundary, or holding more
// CRLs than the entry bound allows.
//
// Counted where the file is read, which is not only the refresh pass: every CRL
// amendment goes through crlChainLocked and reads it too, so this moves on
// revocations and re-signs as well. The Prometheus HELP text says the same, and
// this comment used to say "refresh passes" alone, which undersold it by the
// larger half.
//
// Surfaced as puppetca_crl_chain_refresh_failures_total.
func (c *CA) CRLChainFailures() uint64 { return c.crlChainFailures.Load() }

// CRLChainDiscarded returns how many CRLs have been dropped from
// crl_chain_file because no certificate in the CA bundle signed them. Surfaced
// as puppetca_crl_chain_discarded_total; a rising value means the published
// chain is smaller than the operator's file says it should be.
func (c *CA) CRLChainDiscarded() uint64 { return c.crlChainDiscarded.Load() }

// CRLChainRegressed returns how many CRLs in crl_chain_file have been passed
// over because the published chain already carried a newer one from the same
// ancestor. Surfaced as puppetca_crl_chain_regressed_total; a rising value means
// the file is stale, rolled back or replayed, and points at whatever writes it
// rather than at the CA bundle.
func (c *CA) CRLChainRegressed() uint64 { return c.crlChainRegressed.Load() }

// CRLChainRemoved returns how many ancestors have had their published CRL
// dropped from the chain, whether because crl_chain_file stopped listing them or
// because their certificate left the CA bundle. Surfaced as
// puppetca_crl_chain_removed_total; the removal is honoured because the file is
// authoritative, but it cannot be undone here, so a rising value wants checking
// against whether the operator meant it -- and the log line says which of the
// two causes fired, because the remedies differ.
func (c *CA) CRLChainRemoved() uint64 { return c.crlChainRemoved.Load() }

// CRLChainLastRead returns when crl_chain_file was last read successfully, or
// the zero time if it never has been. See the field comment for why a feature
// whose whole value is "the file is re-read" needs to say whether it is.
func (c *CA) CRLChainLastRead() time.Time {
	sec := c.crlChainLastRead.Load()
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0)
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
