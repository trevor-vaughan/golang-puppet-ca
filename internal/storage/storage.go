// Copyright (C) 2026 Trevor Vaughan
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

package storage

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// StorageService provides the higher-level storage API used by the CA and
// API layers. It delegates all blob I/O to a pluggable Backend and handles
// inventory HMAC sequencing, append/read locks, and the per-subject private
// key directory (always local).
type StorageService struct {
	backend     Backend
	serialMu    sync.Mutex
	inventoryMu sync.RWMutex
	crlMu       sync.RWMutex
	fileMu      sync.RWMutex
	hmacKey     []byte // set by InitHMAC; nil disables integrity checks

	// localPrivateKeyDir holds server-generated per-subject private keys.
	// These are kept on the local filesystem regardless of the configured
	// backend: they are client material that operators don't want exposed
	// through a shared remote store.
	localPrivateKeyDir string

	// localLocks is the process-local fallback for WithLock when the
	// underlying backend does not implement Locker. One sync.Mutex per
	// lock name, lazily created.
	localLocks sync.Map
}

// WithLock runs fn while holding the named lock, taking the strongest lock the
// backend offers. The lock is always released when fn returns, including on
// panic. Three tiers, tried in order:
//
//  1. Locker — coordinated across every replica sharing the backend
//     (etcd, Redis, PostgreSQL, MySQL).
//  2. SameHostLocker — coordinated across every process on this host, an
//     flock(2) on the single-node backends (filesystem, SQLite). Enough to
//     stop an `openvox-ca-ctl` command corrupting a running server's state;
//     no promise at all across hosts, which is what those backends are
//     scoped to.
//  3. A process-local named mutex, for a backend offering neither.
//
// Names should be stable and descriptive (e.g. "bootstrap", "crl",
// "subject:<name>") since all callers using the same name contend on the
// same lock.
//
// ctx bounds only the *other-process* half of an acquisition. Callers inside
// one process serialise on a plain mutex first — the tier-3 fallback below, and
// inside each tier-1/tier-2 implementation's own acquisition — and
// sync.Mutex.Lock takes no context. A deadline therefore caps how long this
// waits for another replica or another process, not for another goroutine here,
// which is why an inverted lock order deadlocks rather than timing out. See
// docs/development/locking.md.
//
// For the same reason WithLock is *not reentrant*, at any tier: re-acquiring a
// name this goroutine already holds blocks on a mutex only this goroutine can
// release, and no deadline ends that wait, so it hangs rather than failing.
// Work that must run under a lock the caller may already hold belongs in a
// ...Locked variant the caller selects — CA.finishLoadExisting takes its
// seeding function from its caller for exactly this reason (issue #201).
func (s *StorageService) WithLock(ctx context.Context, name string, fn func() error) error {
	if lk, ok := s.backend.(Locker); ok {
		ul, err := lk.AcquireLock(ctx, name)
		if err == nil {
			defer func() {
				if err := ul.Unlock(); err != nil {
					slog.Warn("Failed to release distributed lock", "name", name, "error", err)
				}
			}()
			return fn()
		}
		if !errors.Is(err, ErrDistributedLockingUnsupported) {
			return fmt.Errorf("acquiring distributed lock %q: %w", name, err)
		}
		// Backend advertises Locker but cannot actually provide one (SQLite;
		// OverlayBackend wrapping a base without one). Try the same-host tier,
		// which those two backends do provide.
	}
	if hl, ok := s.backend.(SameHostLocker); ok {
		ul, err := hl.AcquireSameHostLock(ctx, name)
		if err == nil {
			defer func() {
				if err := ul.Unlock(); err != nil {
					slog.Warn("Failed to release same-host lock", "name", name, "error", err)
				}
			}()
			return fn()
		}
		if !errors.Is(err, ErrSameHostLockingUnsupported) {
			// A contended lock that outlasts ctx arrives here, and failing is
			// the point of the tier: an operator running a second process
			// against a live store gets told so, instead of both writing.
			return fmt.Errorf("acquiring same-host lock %q: %w", name, err)
		}
		// No same-host lock either (an in-memory SQLite database, a platform
		// without flock(2), an overlay over a base with neither): fall through.
	}
	m := s.localNamedLock(name)
	m.Lock()
	defer m.Unlock()
	return fn()
}

// lockProbeName is the throwaway lock SupportsDistributedLocking acquires and
// immediately releases. It is deliberately outside the namespaces real callers
// use ("bootstrap", "crl", "subject:<name>") so a probe can never contend with
// an operation in flight.
const lockProbeName = "capability-probe"

// SupportsDistributedLocking reports whether WithLock actually coordinates
// across processes for the configured backend.
//
// This deliberately does NOT answer `_, ok := backend.(Locker)`, which is a
// different and misleading question. SQLBackend implements Locker but reports
// ErrDistributedLockingUnsupported for SQLite, and OverlayBackend implements it
// but delegates to a base that may not — so a type assertion says "yes" for
// SQLite and for any backend an overlay wraps over a filesystem base, both of
// which fall through to a process-local mutex. Callers that use this to decide
// whether it is safe to run a second process against the same storage would be
// told exactly the wrong thing.
//
// Instead it reproduces WithLock's decision by making the same AcquireLock call
// and classifying the outcome the same way, releasing the lock immediately. The
// probe cannot live inside WithLock: that would add a lock round trip to every
// Sign. Keeping the two in step is a test's job (see the storage suite), not
// the type system's.
//
// The three outcomes are distinct, and the error case matters: WithLock treats
// a non-sentinel AcquireLock failure as fatal, so reporting it as "false" would
// tell an operator their backend does not do distributed locking when the truth
// is that it is unreachable.
func (s *StorageService) SupportsDistributedLocking(ctx context.Context) (bool, error) {
	lk, ok := s.backend.(Locker)
	if !ok {
		return false, nil
	}
	ul, err := lk.AcquireLock(ctx, lockProbeName)
	switch {
	case err == nil:
		// Release at once. A probe that leaked would hold a Postgres advisory
		// lock on a pooled connection, or a Redis lease with a heartbeat
		// goroutine, for the lifetime of the process.
		if unlockErr := ul.Unlock(); unlockErr != nil {
			slog.Warn("Failed to release capability probe lock", "error", unlockErr)
		}
		return true, nil
	case errors.Is(err, ErrDistributedLockingUnsupported):
		return false, nil
	default:
		return false, fmt.Errorf("probing distributed locking: %w", err)
	}
}

// SupportsAtomicInventory reports whether AppendInventory is atomic with
// respect to writers in other processes.
//
// Only structured (InventoryStore) backends are: they append a row and advance
// the integrity chain in one transaction. Blob backends read the whole
// inventory, append, and rewrite an HMAC computed over their own
// reconstruction, so two concurrent appenders leave an HMAC covering a blob
// that never existed — which fails the integrity check at the next startup.
//
// Needed as a method because asInventoryStore unwraps OverlayBackend, so a
// caller-side type assertion would answer "no" for a SQL backend that happens
// to be wrapped by ca_cert_file/ca_key_file.
func (s *StorageService) SupportsAtomicInventory() bool {
	_, ok := asInventoryStore(s.backend)
	return ok
}

// localNamedLock returns the process-local mutex for name, creating it
// on first use. Mutexes are never removed from the map; the namespace
// is small and bounded.
func (s *StorageService) localNamedLock(name string) *sync.Mutex {
	if v, ok := s.localLocks.Load(name); ok {
		return v.(*sync.Mutex)
	}
	v, _ := s.localLocks.LoadOrStore(name, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// New constructs a StorageService backed by a filesystem rooted at baseDir.
// Per-subject generated private keys are stored in baseDir/private alongside
// the filesystem backend's other private files.
func New(baseDir string) *StorageService {
	return NewWithBackend(NewFilesystemBackend(baseDir), filepath.Join(baseDir, "private"))
}

// NewWithBackend constructs a StorageService with an explicit backend and a
// local directory for per-subject private keys. The private key directory is
// always on the local filesystem regardless of the chosen backend.
func NewWithBackend(backend Backend, localPrivateKeyDir string) *StorageService {
	return &StorageService{
		backend:            backend,
		localPrivateKeyDir: localPrivateKeyDir,
	}
}

// Backend returns the underlying Backend. Exposed for advanced use cases
// (diagnostic output, backend-specific tuning). Most callers should prefer
// the higher-level methods on StorageService.
func (s *StorageService) Backend() Backend { return s.backend }

// EnsureDirs prepares the backend and the local private-key directory for use.
func (s *StorageService) EnsureDirs(ctx context.Context) error {
	if err := s.backend.EnsureReady(ctx); err != nil {
		return err
	}
	if s.localPrivateKeyDir != "" {
		if err := os.MkdirAll(s.localPrivateKeyDir, DirPerm); err != nil {
			return err
		}
	}
	return nil
}

// --- Serial ---

func (s *StorageService) WriteSerial(ctx context.Context, val string) error {
	s.serialMu.Lock()
	defer s.serialMu.Unlock()
	return s.backend.Put(ctx, KeySerial, []byte(val), BlobPublic)
}

func (s *StorageService) GetSerial(ctx context.Context) ([]byte, error) {
	s.serialMu.Lock()
	defer s.serialMu.Unlock()
	return s.backend.Get(ctx, KeySerial)
}

func (s *StorageService) HasSerial(ctx context.Context) (bool, error) {
	s.serialMu.Lock()
	defer s.serialMu.Unlock()
	return s.backend.Exists(ctx, KeySerial)
}

// --- Inventory ---

// InitHMAC loads or generates the inventory HMAC key and verifies the
// existing inventory. Call this once during CA initialisation.
func (s *StorageService) InitHMAC(ctx context.Context) error {
	key, err := s.EnsureHMACKey(ctx)
	if err != nil {
		return err
	}
	s.hmacKey = key
	return s.VerifyInventoryHMAC(ctx, key)
}

// ErrDuplicateSerial is returned by AppendInventory when the entry's serial
// number already exists in the inventory. SQL backends detect this via their
// unique index (translated from the dialect-specific driver error); the etcd
// backend via a by-serial marker key whose absence is a condition of the
// append transaction; the redis backend via a by-serial hash field the append
// script refuses to overwrite. All three are true cluster-wide guarantees. The
// filesystem backend — the only remaining blob one — detects it via an
// explicit scan performed under the same inventoryMu that already serialises
// every append within a process. That is a narrower guarantee rather than a
// bare gap: filesystem is single-node by construction, so no cross-replica
// case arises, and SameHostLocker gives its WithLock names cross-process reach
// on the host. What that reach does not extend to is the AppendInventory call
// itself, which no lock wraps (see the blob-fallback HMAC-update comment
// below, which documents a similar limitation for that path).
var ErrDuplicateSerial = errors.New("serial number already exists in inventory")

// AppendInventory adds entry (a single inventory.txt line, without a trailing
// newline) to the inventory. On backends that implement InventoryStore the
// entry is stored as a structured record and the integrity head is advanced by
// a hash chain in O(1); otherwise the line is appended to the KeyInventory blob
// and the whole-blob HMAC is recomputed. Returns ErrDuplicateSerial (wrapped)
// if the entry's serial is already present anywhere in the inventory.
func (s *StorageService) AppendInventory(ctx context.Context, entry string) error {
	return s.AppendInventoryRecord(ctx, entry, nil)
}

// AppendInventoryRecord is AppendInventory with an optional certificate-index
// projection. Issuance paths (signing, import) pass the display fields
// denormalised from the certificate they just stored; backends with the
// CertIndex capability persist them on the new row (state "signed"), all
// others ignore them. A nil proj records the entry without a projection,
// which index readers treat as "fall back to the stored PEM".
func (s *StorageService) AppendInventoryRecord(ctx context.Context, entry string, proj *CertProjection) error {
	s.inventoryMu.Lock()
	defer s.inventoryMu.Unlock()

	parsed, ok := parseInventoryEntry(entry)
	if !ok {
		return fmt.Errorf("malformed inventory entry %q", entry)
	}

	if store, ok := asInventoryStore(s.backend); ok {
		rec := CertRecord{InventoryEntry: parsed, State: CertStateSigned}
		if proj != nil {
			rec.CertProjection = *proj
		}
		var newHead func(prev []byte) []byte
		if s.hmacKey != nil {
			key := s.hmacKey
			newHead = func(prev []byte) []byte { return chainInventoryMAC(key, prev, entry) }
		}
		if err := store.AppendEntry(ctx, rec, newHead); err != nil {
			// The etcd and redis backends already wrap ErrDuplicateSerial
			// themselves; SQL backends surface the dialect's unique-index
			// violation instead and are translated here.
			if !errors.Is(err, ErrDuplicateSerial) && isUniqueSerialViolation(err) {
				return fmt.Errorf("%w: %s", ErrDuplicateSerial, parsed.Serial)
			}
			return err
		}
		return nil
	}

	// Blob backends have no native uniqueness constraint on serial, so scan the
	// current inventory under inventoryMu (already held) before appending. Read
	// the whole blob once here and reuse those bytes for both the duplicate scan
	// and the HMAC recompute below, so the append path does a single whole-blob
	// read rather than reading it again inside updateInventoryHMACLocked.
	data, err := s.readInventoryForHMAC(ctx)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if e, ok := parseInventoryEntry(line); ok && e.Serial == parsed.Serial {
			return fmt.Errorf("%w: %s", ErrDuplicateSerial, parsed.Serial)
		}
	}

	if err := s.backend.AppendLine(ctx, KeyInventory, []byte(entry+"\n"), BlobPrivate); err != nil {
		return err
	}

	if s.hmacKey != nil {
		// AppendLine is a literal byte-append, so the stored blob is now exactly
		// data + entry + "\n". Hash that reconstruction directly instead of
		// re-reading the blob (which computeInventoryHMAC would do), keeping the
		// value byte-identical to a fresh whole-blob recompute.
		newBlob := make([]byte, 0, len(data)+len(entry)+1)
		newBlob = append(newBlob, data...)
		newBlob = append(newBlob, entry...)
		newBlob = append(newBlob, '\n')
		if err := s.backend.Put(ctx, KeyInventoryHMAC, wholeBlobInventoryMAC(s.hmacKey, newBlob), BlobPrivate); err != nil {
			// The line is already durably appended, but the stored HMAC now
			// lags the inventory: the next verify would falsely report
			// tampering. Surface the failure so the caller can react (e.g.
			// roll back the just-written cert) rather than hiding it.
			//
			// We deliberately do not try to make the line-append and the
			// HMAC-write a single atomic unit here (e.g. stage both in temp
			// files and rename-swap). A rename only narrows, not closes, the
			// window — a crash between the two renames still leaves the pair
			// inconsistent — and the structured InventoryStore backends (see
			// the AppendEntry path above) already advance the integrity head
			// atomically via an O(1) hash chain, which is the durable path
			// operators should prefer. For the whole-blob fallback the honest
			// contract is: report the failure so the caller decides, not
			// silently leave a mismatch behind.
			return fmt.Errorf("updating inventory HMAC after append: %w", err)
		}
	}
	return nil
}

// SerialExists reports whether any inventory entry — for any subject, current
// or historical — already carries the given serial number. This is a
// best-effort, non-authoritative check: callers needing a real guarantee
// must rely on AppendInventory's own atomic duplicate check
// (ErrDuplicateSerial), not this method, since SerialExists does not hold
// inventoryMu across its caller's subsequent write.
func (s *StorageService) SerialExists(ctx context.Context, serial string) (bool, error) {
	s.inventoryMu.RLock()
	defer s.inventoryMu.RUnlock()
	entries, err := s.inventoryEntriesLocked(ctx)
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		if e.Serial == serial {
			return true, nil
		}
	}
	return false, nil
}

// SubjectForSerial returns the subject of the inventory entry carrying serial,
// current or historical. Wraps fs.ErrNotExist when no entry carries it, and
// returns an error for a serial that is not hexadecimal.
//
// Unlike SerialExists, the comparison is on the *normalised* value (uppercase
// hex, no leading zeros) rather than the stored string. SerialExists can insist
// on an exact match because both sides are written by this CA in one format; a
// serial reaching this method was typed by an operator, who may reasonably
// write it in the lowercase, zero-padded or colon-free form some other tool
// printed. Normalising here is also what lets a modern random serial and a
// zero-padded sequential one from an older inventory be looked up the same way.
//
// Integrity matches LatestSerialForSubject, the by-subject lookup this is the
// twin of: on a blob backend the HMAC is verified before the scan, so an
// inventory whose rows were altered surfaces ErrInventoryTampered rather than
// answering from it. The guarantee is exactly as strong as the stored MAC's
// presence — verifyInventoryHMACLocked treats an absent one as first-run and
// re-baselines over whatever is there, so deleting the MAC blob alongside the
// edit still verifies clean. That is a property of the shared verifier, not of
// this path (LatestSerialForSubject inherits it too), and closing it would mean
// a read-only verify mode for every caller. It is left alone here rather than
// papered over: the barrier stops an edited inventory, not an edited inventory
// whose sibling MAC was also removed. That
// matters more here than for a plain read — the answer decides whether a serial
// may be revoked at all, and which subject's stored certificate the live
// certificate guard compares against, so an unverified row could both admit a
// serial this CA never issued (a CRL entry no expiry sweep can ever remove) and
// point the guard at the wrong certificate. InventoryStore backends are not
// verified here, exactly as LatestSerialForSubject does not verify them: their
// integrity head is advanced atomically per append rather than recomputed over a
// blob, and re-verifying would cost a second full fetch of every row.
//
// The scan is linear in the inventory. An indexed by-serial lookup is NOT
// available even on backends that have the index: the schema's unique index on
// serial is an exact-match index over the stored text, while this lookup must
// match on the normalised value, because an inventory written by an older
// version — or migrated from Puppet Server — carries zero-padded sequential
// serials (see buildSerialIndex's comment in internal/ca/ocsp.go). An indexed
// exact match would silently miss precisely the historical certificates most
// likely to need retiring. A fast path that tried the canonical rendering first
// and fell back to this scan would be sound; it is deliberately left for later,
// since this answers an operator-initiated single revocation rather than a hot
// path, and on blob backends the verification above reads everything regardless.
func (s *StorageService) SubjectForSerial(ctx context.Context, serial string) (string, error) {
	want, err := NormaliseSerial(serial)
	if err != nil {
		return "", err
	}

	s.inventoryMu.RLock()
	defer s.inventoryMu.RUnlock()

	if _, indexed := asInventoryStore(s.backend); !indexed && s.hmacKey != nil {
		if err := s.verifyInventoryHMACLocked(ctx, s.hmacKey); err != nil {
			return "", err
		}
	}

	entries, err := s.inventoryEntriesLocked(ctx)
	if err != nil {
		return "", err
	}

	// Malformed serials are counted and reported once, not once per row: a
	// migrated inventory can carry many, and this runs under the cluster CRL
	// lock while an operator watches the log for the outcome of one revocation.
	// latestSerialFromBlob aggregates the same condition the same way.
	//
	// Deferred so every return path reports the same way and the count means one
	// thing: rows skipped before the scan stopped. Emitting at each return
	// instead made the number silently depend on where the match landed.
	skipped := 0
	defer func() {
		if skipped > 0 {
			slog.Warn("Inventory contains entries with unparseable serials", "count", skipped)
		}
	}()

	for _, e := range entries {
		got, err := NormaliseSerial(e.Serial)
		if err != nil {
			skipped++
			continue
		}
		if got == want {
			return e.Subject, nil
		}
	}
	return "", fmt.Errorf("serial %s not found in inventory: %w", want, fs.ErrNotExist)
}

// ErrMalformedSerial marks input that is not a hexadecimal serial number, so
// callers taking a serial from an operator can answer "you typed it wrong"
// rather than reporting a server fault.
var ErrMalformedSerial = errors.New("malformed serial")

// NormaliseSerial parses a hexadecimal serial number and re-renders it in the
// canonical form this CA stores and logs: uppercase hex, no leading zeros, and
// no separators. It rejects anything that is not a non-negative hexadecimal
// integer, so it doubles as the input validator for operator-supplied serials.
//
// It is the storage-layer twin of the ca package's serialHexStr, which
// canonicalises a *big.Int that has already been parsed; this one starts from
// text.
func NormaliseSerial(serial string) (string, error) {
	trimmed := strings.TrimSpace(serial)
	n, ok := new(big.Int).SetString(trimmed, 16)
	if trimmed == "" || !ok || n.Sign() < 0 {
		return "", fmt.Errorf("%w: %q is not a hexadecimal serial number", ErrMalformedSerial, serial)
	}
	return strings.ToUpper(n.Text(16)), nil
}

// LatestSerialForSubject returns the most recently issued serial for subject.
// On InventoryStore backends this is an indexed lookup; otherwise it scans the
// inventory blob (verifying its HMAC first, via ReadInventory). Wraps
// os.ErrNotExist when the subject has no entry.
func (s *StorageService) LatestSerialForSubject(ctx context.Context, subject string) (string, error) {
	if store, ok := asInventoryStore(s.backend); ok {
		s.inventoryMu.RLock()
		defer s.inventoryMu.RUnlock()
		return store.LatestSerialForSubject(ctx, subject)
	}

	data, err := s.ReadInventory(ctx)
	if err != nil {
		return "", err
	}
	return latestSerialFromBlob(data, subject)
}

func (s *StorageService) ReadInventory(ctx context.Context) ([]byte, error) {
	s.inventoryMu.RLock()
	defer s.inventoryMu.RUnlock()

	if s.hmacKey != nil {
		if err := s.verifyInventoryHMACLocked(ctx, s.hmacKey); err != nil {
			return nil, err
		}
	}
	return s.backend.Get(ctx, KeyInventory)
}

// InventoryEntries returns every inventory entry in issuance order, verifying
// the stored integrity value before returning them.
//
// The structured twin of ReadInventory, for a caller that wants the entries
// rather than the rendered blob — and the one to reach for on a timer.
// ReadInventory verifies and *then* fetches, and its verification recomputes
// from storage, so every call materialises the whole inventory twice: on a blob
// backend two full blob reads, and on an InventoryStore backend a full row
// fetch plus a hash chain followed by every row again through the render shim.
// This fetches once and folds the integrity value over what it already holds,
// so the cost is one materialisation plus the small stored-MAC read, on every
// backend family.
//
// Verification is not skipped anywhere, which is the difference between this
// and SubjectForSerial: that method declines to verify on InventoryStore
// backends precisely because doing so "would cost a second full fetch of every
// row", and here it costs no fetch at all. The distinction matters for this
// caller, which drives removals — a deleted row silently downgrades the OCSP
// responder's answer for that serial from revoked to unknown and evicts the
// pre-signed response, so tampering must fail closed rather than be absorbed.
func (s *StorageService) InventoryEntries(ctx context.Context) ([]InventoryEntry, error) {
	s.inventoryMu.RLock()
	defer s.inventoryMu.RUnlock()

	if store, ok := asInventoryStore(s.backend); ok {
		entries, err := store.Entries(ctx)
		if err != nil {
			return nil, err
		}
		if s.hmacKey != nil {
			// The same fold computeInventoryHMAC performs, over the rows in
			// hand rather than over a second fetch of them.
			var head []byte
			for _, e := range entries {
				head = chainInventoryMAC(s.hmacKey, head, canonicalInventoryLine(e))
			}
			if err := s.compareInventoryMACLocked(ctx, head); err != nil {
				return nil, err
			}
		}
		return entries, nil
	}

	data, err := s.readInventoryForHMAC(ctx)
	if err != nil {
		return nil, err
	}
	if s.hmacKey != nil {
		// Hashed over the bytes as stored, never over a re-render of the parsed
		// entries: the blob scheme covers the blob, and a round trip through
		// parse-and-render need not reproduce it byte for byte.
		if err := s.compareInventoryMACLocked(ctx, wholeBlobInventoryMAC(s.hmacKey, data)); err != nil {
			return nil, err
		}
	}
	return parseInventoryBlob(data), nil
}

// compareInventoryMACLocked checks an already-computed integrity value against
// the stored one, with verifyInventoryHMACLocked's first-run behaviour: a
// missing stored value is a baseline to establish rather than a failure.
//
// Split out so a caller holding the inventory can verify without recomputing
// from storage. verifyInventoryHMACLocked is the same comparison for a caller
// that has not computed the value itself.
//
// It takes no HMAC key, deliberately: the key has already been consumed in
// producing computed, and a parameter that looks like it participates in the
// comparison but does not is how the two sides come to be keyed differently
// without anything failing.
//
// It differs from verifyInventoryHMACLocked in one way, also deliberately: a
// missing stored value is accepted without establishing one. That function
// baselines because its callers hold the write lock and one of them is
// InitHMAC, whose job that is; this one is reached from InventoryEntries under
// a *read* lock, and a read path writing to storage — from every replica at
// once, on a timer — is not worth leaving available for the sake of a state
// InitHMAC has already ruled out before the CA serves anything. The security
// posture is unchanged either way: an inventory whose MAC was deleted alongside
// the edit verifies clean, which SubjectForSerial's comment above sets out at
// length as a known, accepted limit of the scheme.
//
// Caller must hold inventoryMu (read or write).
func (s *StorageService) compareInventoryMACLocked(ctx context.Context, computed []byte) error {
	storedMAC, err := s.backend.Get(ctx, KeyInventoryHMAC)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			slog.Warn("No inventory HMAC stored; skipping the integrity check for this read")
			return nil
		}
		return fmt.Errorf("reading inventory HMAC: %w", err)
	}
	if !hmac.Equal(storedMAC, computed) {
		scheme := s.inventoryScheme()
		slog.Warn("inventory HMAC mismatch; integrity check failed", "scheme", scheme,
			"repair", inventoryRepairHint)
		return ErrInventoryTampered
	}
	return nil
}

// inventoryEntriesLocked returns every inventory entry in issuance order. On
// InventoryStore backends it reads the structured rows; otherwise it parses the
// rendered blob. Caller must hold inventoryMu (read or write).
func (s *StorageService) inventoryEntriesLocked(ctx context.Context) ([]InventoryEntry, error) {
	if store, ok := asInventoryStore(s.backend); ok {
		return store.Entries(ctx)
	}
	data, err := s.readInventoryForHMAC(ctx)
	if err != nil {
		return nil, err
	}
	return parseInventoryBlob(data), nil
}

// parseInventoryBlob parses a rendered inventory into entries, skipping blank
// and malformed lines. Shared by the two readers of the blob form so they
// cannot disagree about what counts as an entry.
func parseInventoryBlob(data []byte) []InventoryEntry {
	entries, _ := parseInventoryBlobCounting(data)
	return entries
}

// parseInventoryBlobCounting is parseInventoryBlob, also reporting how many
// non-blank lines it discarded. One pass rather than two: the caller that wants
// the count is InventoryIntegrityReport, whose whole restructuring was to read
// the inventory once, and a second strings.Split over the same bytes to count
// what this loop has already seen undoes that on every blob-backend call.
func parseInventoryBlobCounting(data []byte) (entries []InventoryEntry, unparseable int) {
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if e, ok := parseInventoryEntry(line); ok {
			entries = append(entries, e)
			continue
		}
		unparseable++
	}
	return entries, unparseable
}

// PruneInventory removes every inventory entry for which keep returns false,
// rewriting the inventory and its integrity head together under the inventory
// write lock. It returns the removed entries (in issuance order) so the caller
// can act on them — drop their CRL revocations, invalidate caches, delete the
// stored cert. The returned slice is authoritative even when err is non-nil:
// any path that has durably removed entries before failing still returns
// them, so the caller can finish cleaning up after them. A backend may bound
// how much one call removes (see the PruneEntries contract); deferred matches
// stay in the inventory for later calls. When nothing is removed the
// inventory and head are left untouched and (nil, nil) is returned.
//
// The current inventory integrity is verified before pruning, so a tampered
// inventory surfaces ErrInventoryTampered rather than being silently rewritten.
//
// Concurrency: appends (AppendInventory) and reads (ReadInventory) take the
// same inventoryMu, so within a process a prune never interleaves with them.
// Structured backends prune through PruneEntries (see the contract in
// backend.go: SQL in one transaction, redis in one atomic script, etcd in
// individually-consistent batches); the blob fallback below rewrites the whole
// inventory with a single Backend.Put, which blob backends service as an
// atomic file swap.
// Callers needing cross-replica serialisation against revocation should hold
// the cluster CRL lock around this (see ca.CA.CleanupExpiredCerts).
func (s *StorageService) PruneInventory(ctx context.Context, keep func(InventoryEntry) bool) ([]InventoryEntry, error) {
	s.inventoryMu.Lock()
	defer s.inventoryMu.Unlock()

	if s.hmacKey != nil {
		if err := s.verifyInventoryHMACLocked(ctx, s.hmacKey); err != nil {
			return nil, err
		}
	}

	// Structured backends prune rows and rewrite the chained integrity head
	// so the two are never observed out of sync across replicas: SQL in a
	// single transaction, redis in a single script, etcd in batches whose
	// every commit is internally consistent (see the PruneEntries contract in
	// backend.go).
	if store, ok := asInventoryStore(s.backend); ok {
		var advanceHead func(prev []byte, e InventoryEntry) []byte
		if s.hmacKey != nil {
			key := s.hmacKey
			advanceHead = func(prev []byte, e InventoryEntry) []byte {
				return chainInventoryMAC(key, prev, canonicalInventoryLine(e))
			}
		}
		return store.PruneEntries(ctx, keep, advanceHead)
	}

	// Blob backends: read, filter, and rewrite the whole inventory, then
	// recompute the whole-blob HMAC. This matches their (non-atomic) append path
	// and is correct for the single-node filesystem backend, the only blob
	// backend without distributed appends.
	entries, err := s.inventoryEntriesLocked(ctx)
	if err != nil {
		return nil, err
	}

	kept := make([]InventoryEntry, 0, len(entries))
	var removed []InventoryEntry
	for _, e := range entries {
		if keep(e) {
			kept = append(kept, e)
		} else {
			removed = append(removed, e)
		}
	}
	if len(removed) == 0 {
		return nil, nil
	}

	var buf strings.Builder
	for _, e := range kept {
		buf.WriteString(canonicalInventoryLine(e))
		buf.WriteByte('\n')
	}
	if err := s.backend.Put(ctx, KeyInventory, []byte(buf.String()), BlobPrivate); err != nil {
		return nil, fmt.Errorf("rewriting inventory: %w", err)
	}

	if s.hmacKey != nil {
		if err := s.updateInventoryHMACLocked(ctx, s.hmacKey); err != nil {
			// The inventory is already rewritten but the stored head now lags
			// it; surface the failure so the operator/job can react rather
			// than leave a mismatch the next verify would flag as tampering.
			// The entries are durably removed, so return them alongside the
			// error per this method's contract — the caller's CRL/blob
			// cleanup must still run for them.
			return removed, fmt.Errorf("updating inventory HMAC after prune: %w", err)
		}
	}
	return removed, nil
}

// --- Certificate index ---
//
// The methods below expose the optional CertIndex backend capability. On
// backends without it they degrade gracefully: reads report ok=false so the
// caller keeps its list-and-parse path, writes are silent no-ops. The index is
// a projection of authoritative artefacts (certificate PEMs, the signed CRL),
// so a lost index write is at worst a stale display value that the CA's index
// repair pass reconciles at the next startup.

// CertStatuses answers the certificate-status listing from the certificate
// index. ok reports whether the backend has the capability at all; when false
// the caller must fall back to enumerating and parsing the stored PEMs.
// stateFilter narrows the records to CertStateSigned or CertStateRevoked; ""
// returns everything the index tracks.
func (s *StorageService) CertStatuses(ctx context.Context, stateFilter string) (records []CertRecord, ok bool, err error) {
	idx, ok := asCertIndex(s.backend)
	if !ok {
		return nil, false, nil
	}
	records, err = idx.Statuses(ctx, stateFilter)
	return records, true, err
}

// MarkCertRevoked projects a revocation into the certificate index; no-op
// when the backend has no index.
func (s *StorageService) MarkCertRevoked(ctx context.Context, serial string, at time.Time) error {
	idx, ok := asCertIndex(s.backend)
	if !ok {
		return nil
	}
	return idx.SetRevoked(ctx, serial, at)
}

// ClearCertRevoked removes a revocation projection from the certificate
// index; no-op when the backend has no index.
func (s *StorageService) ClearCertRevoked(ctx context.Context, serial string) error {
	idx, ok := asCertIndex(s.backend)
	if !ok {
		return nil
	}
	return idx.ClearRevoked(ctx, serial)
}

// SetCertProjection backfills the denormalised display fields for serial in
// the certificate index; no-op when the backend has no index.
func (s *StorageService) SetCertProjection(ctx context.Context, serial string, proj CertProjection) error {
	idx, ok := asCertIndex(s.backend)
	if !ok {
		return nil
	}
	return idx.SetProjection(ctx, serial, proj)
}

// TouchInventory creates an empty inventory blob if one does not already
// exist. Called during CA bootstrap and import to seed the inventory.
func (s *StorageService) TouchInventory(ctx context.Context) error {
	s.inventoryMu.Lock()
	defer s.inventoryMu.Unlock()
	ok, err := s.backend.Exists(ctx, KeyInventory)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	return s.backend.Put(ctx, KeyInventory, []byte{}, BlobPrivate)
}

func (s *StorageService) HasInventory(ctx context.Context) (bool, error) {
	s.inventoryMu.RLock()
	defer s.inventoryMu.RUnlock()
	return s.backend.Exists(ctx, KeyInventory)
}

// readInventoryForHMAC returns the inventory bytes, treating an absent blob
// as empty so that a missing inventory hashes the same as an empty one.
// Caller must hold inventoryMu (read or write).
func (s *StorageService) readInventoryForHMAC(ctx context.Context) ([]byte, error) {
	data, err := s.backend.Get(ctx, KeyInventory)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return []byte{}, nil
		}
		return nil, err
	}
	return data, nil
}

// --- CRL ---

func (s *StorageService) UpdateCRL(ctx context.Context, pemData []byte) error {
	s.crlMu.Lock()
	defer s.crlMu.Unlock()
	return s.backend.Put(ctx, KeyCRL, pemData, BlobPrivate)
}

func (s *StorageService) GetCRL(ctx context.Context) ([]byte, error) {
	s.crlMu.RLock()
	defer s.crlMu.RUnlock()
	return s.backend.Get(ctx, KeyCRL)
}

// CRLModTime returns the last-modified time of the CRL blob, for
// If-Modified-Since handling. Backends that don't track mtime return zero.
func (s *StorageService) CRLModTime(ctx context.Context) (time.Time, error) {
	s.crlMu.RLock()
	defer s.crlMu.RUnlock()
	return s.backend.ModTime(ctx, KeyCRL)
}

// --- Pending supersessions ---

// GetSuperseded returns the stored list of certificates awaiting delayed
// revocation, wrapping fs.ErrNotExist when no supersession has ever been
// recorded. The bytes are opaque here; ca.CA owns the encoding.
//
// Callers must serialise their read-modify-write on the cluster "crl" lock —
// this mutex only orders goroutines inside one process, and the list is shared
// across replicas. See ca.CA.ReconcileSuperseded.
func (s *StorageService) GetSuperseded(ctx context.Context) ([]byte, error) {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	return s.backend.Get(ctx, KeySuperseded)
}

// SaveSuperseded replaces the stored list of certificates awaiting delayed
// revocation. See GetSuperseded for the locking the caller still owes.
func (s *StorageService) SaveSuperseded(ctx context.Context, data []byte) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	return s.backend.Put(ctx, KeySuperseded, data, BlobPrivate)
}

// --- CA material ---

func (s *StorageService) GetCACert(ctx context.Context) ([]byte, error) {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	return s.backend.Get(ctx, KeyCACert)
}

func (s *StorageService) SaveCACert(ctx context.Context, data []byte) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	return s.backend.Put(ctx, KeyCACert, data, BlobPublic)
}

func (s *StorageService) HasCACert(ctx context.Context) (bool, error) {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	return s.backend.Exists(ctx, KeyCACert)
}

func (s *StorageService) GetCAKey(ctx context.Context) ([]byte, error) {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	return s.backend.Get(ctx, KeyCAKey)
}

func (s *StorageService) SaveCAKey(ctx context.Context, data []byte) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	return s.backend.Put(ctx, KeyCAKey, data, BlobPrivate)
}

func (s *StorageService) HasCAKey(ctx context.Context) (bool, error) {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	return s.backend.Exists(ctx, KeyCAKey)
}

func (s *StorageService) SaveCAPubKey(ctx context.Context, data []byte) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	return s.backend.Put(ctx, KeyCAPubKey, data, BlobPublic)
}

// --- CSR / Cert per subject ---

func (s *StorageService) SaveCSR(ctx context.Context, subject string, pemData []byte) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	return s.backend.Put(ctx, CSRKey(subject), pemData, BlobPublic)
}

func (s *StorageService) GetCSR(ctx context.Context, subject string) ([]byte, error) {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	return s.backend.Get(ctx, CSRKey(subject))
}

func (s *StorageService) SaveCert(ctx context.Context, subject string, pemData []byte) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	return s.backend.Put(ctx, CertKey(subject), pemData, BlobPublic)
}

func (s *StorageService) GetCert(ctx context.Context, subject string) ([]byte, error) {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	return s.backend.Get(ctx, CertKey(subject))
}

func (s *StorageService) DeleteCSR(ctx context.Context, subject string) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	return s.backend.Delete(ctx, CSRKey(subject))
}

func (s *StorageService) DeleteCert(ctx context.Context, subject string) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	return s.backend.Delete(ctx, CertKey(subject))
}

// HasCert reports whether a signed certificate exists for subject.
func (s *StorageService) HasCert(ctx context.Context, subject string) bool {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	ok, _ := s.backend.Exists(ctx, CertKey(subject))
	return ok
}

// HasCSR reports whether a pending CSR exists for subject.
func (s *StorageService) HasCSR(ctx context.Context, subject string) bool {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	ok, _ := s.backend.Exists(ctx, CSRKey(subject))
	return ok
}

// ListCSRs returns the subject names of all pending certificate requests.
func (s *StorageService) ListCSRs(ctx context.Context) ([]string, error) {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	keys, err := s.backend.List(ctx, csrPrefix)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, strings.TrimPrefix(k, csrPrefix))
	}
	return out, nil
}

// ListCerts returns the subject names of all signed certificates.
func (s *StorageService) ListCerts(ctx context.Context) ([]string, error) {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	keys, err := s.backend.List(ctx, certPrefix)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, strings.TrimPrefix(k, certPrefix))
	}
	return out, nil
}

// --- Per-subject private keys (always local) ---

// PrivateKeyPath returns the filesystem path to subject's server-generated
// private key. Private keys are always stored on the local filesystem.
func (s *StorageService) PrivateKeyPath(subject string) string {
	return filepath.Join(s.localPrivateKeyDir, subject+"_key.pem")
}

// SavePrivateKey persists a server-generated private key for subject. The
// key is always written to the local filesystem, never the configured backend.
func (s *StorageService) SavePrivateKey(ctx context.Context, subject string, pemData []byte) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	if err := os.MkdirAll(s.localPrivateKeyDir, DirPerm); err != nil {
		return err
	}
	return os.WriteFile(s.PrivateKeyPath(subject), pemData, FilePermPrivate)
}

// CheckKeyPermissions reports private key files whose permissions are more
// permissive than expected (0600). Scans the local private-key directory,
// which for the filesystem backend also contains the CA key.
func (s *StorageService) CheckKeyPermissions() []KeyPermWarning {
	if s.localPrivateKeyDir == "" {
		return nil
	}
	entries, err := os.ReadDir(s.localPrivateKeyDir)
	if err != nil {
		return nil
	}
	var warnings []KeyPermWarning
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_key.pem") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		perm := info.Mode().Perm()
		if perm&^os.FileMode(FilePermPrivate) != 0 {
			warnings = append(warnings, KeyPermWarning{
				Path: filepath.Join(s.localPrivateKeyDir, e.Name()),
				Mode: perm,
			})
		}
	}
	return warnings
}

// --- Legacy path accessors (filesystem-backend only) ---
//
// These return empty strings when the backend is not filesystem-rooted.
// They exist for diagnostic logging and test fixtures; core code should
// use the content-oriented methods above.

// CADir returns the filesystem root of the backend, or "" for non-filesystem backends.
func (s *StorageService) CADir() string {
	if p, ok := s.backend.(PathProvider); ok {
		return p.BaseDir()
	}
	return ""
}

func (s *StorageService) fsPath(key string) string {
	if p, ok := s.backend.(PathProvider); ok {
		return p.Path(key)
	}
	return ""
}

func (s *StorageService) CACertPath() string    { return s.fsPath(KeyCACert) }
func (s *StorageService) CAKeyPath() string     { return s.fsPath(KeyCAKey) }
func (s *StorageService) CAPubKeyPath() string  { return s.fsPath(KeyCAPubKey) }
func (s *StorageService) CRLPath() string       { return s.fsPath(KeyCRL) }
func (s *StorageService) SerialPath() string    { return s.fsPath(KeySerial) }
func (s *StorageService) InventoryPath() string { return s.fsPath(KeyInventory) }
func (s *StorageService) HMACKeyPath() string   { return s.fsPath(KeyHMACKey) }

// CSRDir returns the directory where pending CSRs are stored (filesystem backend only).
func (s *StorageService) CSRDir() string {
	if p, ok := s.backend.(PathProvider); ok {
		return filepath.Join(p.BaseDir(), "requests")
	}
	return ""
}

// SignedDir returns the directory where signed certificates are stored (filesystem backend only).
func (s *StorageService) SignedDir() string {
	if p, ok := s.backend.(PathProvider); ok {
		return filepath.Join(p.BaseDir(), "signed")
	}
	return ""
}

// --- Inventory HMAC integrity ---

const hmacKeyLen = 32

// lockNameHMACKey is the lock name EnsureHMACKey holds while it generates and
// persists a fresh inventory HMAC key. Like every other name passed to
// WithLock it has to stay stable across releases, since replicas exclude one
// another only by agreeing on the string.
//
// Deliberately *not* "bootstrap", the name CA.Init and MigrateService use.
// WithLock is not reentrant at any tier (see its godoc), and MigrateService
// already reaches RebuildInventoryHMAC -> EnsureHMACKey from inside
// WithLock(ctx, migrateLockName), which is "bootstrap". Sharing the name would
// turn a corrupt stored key met during a migration into a hang. The two names
// are never taken in the other order, so this introduces no lock inversion.
const lockNameHMACKey = "hmac-key"

// EnsureHMACKey loads or generates the HMAC key used for inventory integrity.
// The key is stored via the backend under KeyHMACKey.
//
// A transient backend error (network blip, deadline exceeded, ...) is
// distinguished from a genuine "not present" via fs.ErrNotExist; otherwise a
// momentary failure on Get would silently regenerate the key and invalidate
// every existing inventory MAC.
//
// Generation is a read-modify-write, so it runs under WithLock(lockNameHMACKey)
// and reads the key *again* after winning the lock. Without that, two replicas
// cold-starting against a fresh shared backend both see the key absent, both
// generate and both Put: last write wins, and the loser goes on to MAC its
// inventory under a key no other replica can reproduce. The second read is the
// half that matters — the lock only orders the two attempts, and it is the
// re-read that makes the loser adopt the winner's key rather than write over
// it.
//
// The lock is taken only on the path that would write. A store whose key is
// already present *and of the expected length* takes no lock at all, so every
// restart after the first still costs one Get and no cross-replica round trip.
// A present-but-wrong-length blob is not that case: it regenerates, and so it
// locks.
//
// How much of a cross-replica promise that lock is depends on the backend, and
// WithLock's tiers are the whole answer: etcd, Redis and the server SQL
// dialects exclude every replica; filesystem and SQLite exclude every process
// on the host; an in-memory SQLite database or a platform without flock(2)
// falls back to a process-local mutex. Read that last tier as single-*process*,
// not single-node: an in-memory SQLite database really is private to this
// process, but a filesystem store on a platform without flock(2) (Windows, AIX,
// Solaris, js/wasm — see filelock_other.go) is not, and two openvox-ca processes
// over one cadir there can still fork the key. Across hosts the question does
// not arise for either: shared storage is unsupported for them, as
// docs/storage-backends.md scopes it.
//
// ctx bounds the wait for the lock, but only its cross-process half; see
// WithLock. Callers that must not hang on a peer's cold start should pass a
// deadline, as ca.Init does.
func (s *StorageService) EnsureHMACKey(ctx context.Context) ([]byte, error) {
	key, _, err := s.loadHMACKey(ctx)
	if err != nil {
		return nil, err
	}
	if key != nil {
		return key, nil
	}

	var out []byte
	if err := s.WithLock(ctx, lockNameHMACKey, func() error {
		// Another replica may have generated and persisted a key between our
		// first look and our winning the lock. Adopting theirs is what keeps
		// the two from forking.
		key, stored, err := s.loadHMACKey(ctx)
		if err != nil {
			return err
		}
		if key != nil {
			// Another replica won. Say so: this is the exact event #202 is
			// about, and without a line here there is no way to confirm after
			// the fact that the coordination engaged.
			slog.Info("Adopted the inventory HMAC key generated by another replica")
			out = key
			return nil
		}
		if stored != nil {
			// Truncated or corrupted. Regenerating is the right call, but it
			// invalidates every existing inventory MAC, so the verification a
			// moment later reports ErrInventoryTampered — "possible tampering"
			// — for something the CA itself just did. Without this line the
			// operator is pointed at the wrong culprit. It is logged here, and
			// not in loadHMACKey, because this is where the decision is
			// actually taken: the unlocked read above only decides to lock.
			slog.Warn("Stored inventory HMAC key is the wrong length; generating a new one, which invalidates the existing inventory MAC",
				"key", KeyHMACKey, "length", len(stored), "expected", hmacKeyLen)
		}

		fresh := make([]byte, hmacKeyLen)
		if _, err := rand.Read(fresh); err != nil {
			return fmt.Errorf("generating HMAC key: %w", err)
		}
		if err := s.backend.Put(ctx, KeyHMACKey, fresh, BlobPrivate); err != nil {
			return fmt.Errorf("writing HMAC key: %w", err)
		}
		slog.Info("Generated a new inventory HMAC key")
		out = fresh
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// loadHMACKey reads the stored inventory HMAC key and reports what it found.
//
// key is non-nil only when the stored blob is usable — present and exactly
// hmacKeyLen bytes — and a nil key with a nil error is the caller's signal to
// generate a fresh one. stored carries the raw blob whenever there was one, so
// the caller can tell the two generate-worthy states apart: absent (first boot,
// stored nil) from present-but-wrong-length (truncated or corrupted, stored
// non-nil). Only the caller knows which of its two reads is the one that acts,
// so the diagnostics for that live there rather than here.
//
// Every other backend failure comes back as an error, so a momentary outage is
// never mistaken for absence.
func (s *StorageService) loadHMACKey(ctx context.Context) (key, stored []byte, err error) {
	data, err := s.backend.Get(ctx, KeyHMACKey)
	switch {
	case err == nil:
		if len(data) == hmacKeyLen {
			return data, data, nil
		}
		// A blob existed, so stored must be non-nil even when it is empty: a
		// zero-length blob is corruption worth reporting, and returning nil
		// for it would make the caller read it as first boot.
		if data == nil {
			data = []byte{}
		}
		return nil, data, nil
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil, nil
	default:
		return nil, nil, fmt.Errorf("reading HMAC key: %w", err)
	}
}

// computeInventoryHMAC computes the integrity value for the current inventory.
// On InventoryStore backends it folds a hash chain over the entries in issuance
// order (the head MAC); otherwise it is HMAC-SHA256 of the whole blob. An empty
// inventory yields an empty head in the structured case, mirroring how a
// missing blob hashes the same as an empty one.
// Caller must hold inventoryMu.
func (s *StorageService) computeInventoryHMAC(ctx context.Context, hmacKey []byte) ([]byte, error) {
	if store, ok := asInventoryStore(s.backend); ok {
		entries, err := store.Entries(ctx)
		if err != nil {
			return nil, err
		}
		return foldInventoryHead(hmacKey, entries, nil, true), nil
	}

	data, err := s.readInventoryForHMAC(ctx)
	if err != nil {
		return nil, err
	}
	return foldInventoryHead(hmacKey, nil, data, false), nil
}

// inventoryScheme names the integrity scheme this backend computes under. One
// definition for the same reason foldInventoryHead has one: the value is now
// operator-facing on both the report and the two mismatch warnings, and a
// predicate that changed at one site would give an operator a report whose
// scheme contradicts the log line that sent them to it.
func (s *StorageService) inventoryScheme() string {
	if _, ok := asInventoryStore(s.backend); ok {
		return "hash-chain"
	}
	return "whole-blob-hmac"
}

// foldInventoryHead computes the integrity value from inventory contents
// already in hand: the hash chain over entries when chained, otherwise the
// whole-blob MAC over blob.
//
// One definition for the same reason wholeBlobInventoryMAC and
// canonicalInventoryLine each have one. Those keep the primitives from
// diverging; this keeps the *composition* from diverging, which
// InventoryIntegrityReport made possible by folding from its own single read
// rather than paying for a second one. A change to the fold order, a
// domain-separation prefix, or the branch predicate now has one site.
func foldInventoryHead(key []byte, entries []InventoryEntry, blob []byte, chained bool) []byte {
	if !chained {
		return wholeBlobInventoryMAC(key, blob)
	}
	var head []byte
	for _, e := range entries {
		head = chainInventoryMAC(key, head, canonicalInventoryLine(e))
	}
	return head
}

// wholeBlobInventoryMAC is the whole-blob inventory integrity value:
// HMAC-SHA256(key, blob). It is the single definition of the blob-backend HMAC
// so the recompute-from-storage path (computeInventoryHMAC) and the
// append-in-place path (AppendInventory) cannot diverge.
func wholeBlobInventoryMAC(key, blob []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(blob)
	return mac.Sum(nil)
}

// chainInventoryMAC advances the inventory hash chain by one entry:
//
//	mac_i = HMAC-SHA256(key, mac_{i-1} ‖ line_i)
//
// where line_i is the canonical inventory.txt line (no trailing newline) and
// prev is the previous head (nil/empty for the first entry).
func chainInventoryMAC(key, prev []byte, line string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(prev)
	mac.Write([]byte(line))
	return mac.Sum(nil)
}

// InventoryTimeFormat is the layout for the NotBefore/NotAfter timestamps in
// an inventory.txt line. It is part of the on-disk wire format. The trailing
// "UTC" is a literal in the layout (Go's zone token is "MST"), so formatting a
// UTC time records its wall-clock digits and parsing yields them back as UTC.
const InventoryTimeFormat = "2006-01-02T15:04:05UTC"

// canonicalInventoryLine renders e to its inventory.txt line (without the
// trailing newline). It is the single source of truth for the on-disk blob
// format and the input to the integrity hash chain, so the two cannot drift.
func canonicalInventoryLine(e InventoryEntry) string {
	return fmt.Sprintf("%s %s %s /%s", e.Serial, e.NotBefore, e.NotAfter, e.Subject)
}

// FormatInventoryLine builds the canonical inventory.txt line (without the
// trailing newline) from the semantic fields, formatting the timestamps in UTC
// via InventoryTimeFormat. Issuance paths (signing, import) must construct
// inventory lines through this single constructor so they cannot drift from the
// reader/writer/HMAC format owned by canonicalInventoryLine.
func FormatInventoryLine(serial string, notBefore, notAfter time.Time, subject string) string {
	return canonicalInventoryLine(InventoryEntry{
		Serial:    serial,
		NotBefore: notBefore.UTC().Format(InventoryTimeFormat),
		NotAfter:  notAfter.UTC().Format(InventoryTimeFormat),
		Subject:   subject,
	})
}

// parseInventoryEntry parses a single inventory.txt line into an InventoryEntry.
// The format is "SERIAL NOT_BEFORE NOT_AFTER /SUBJECT"; the leading "/" on the
// subject is stripped. Returns ok=false for blank or malformed lines.
func parseInventoryEntry(line string) (InventoryEntry, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return InventoryEntry{}, false
	}
	return InventoryEntry{
		Serial:    fields[0],
		NotBefore: fields[1],
		NotAfter:  fields[2],
		Subject:   strings.TrimPrefix(fields[3], "/"),
	}, true
}

// latestSerialFromBlob scans a rendered inventory blob and returns the serial
// of the last entry matching subject. Wraps os.ErrNotExist when none match.
func latestSerialFromBlob(data []byte, subject string) (string, error) {
	last := ""
	badLines := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		e, ok := parseInventoryEntry(line)
		if !ok {
			badLines++
			continue
		}
		if e.Subject == subject {
			last = e.Serial
		}
	}
	if badLines > 0 {
		slog.Warn("Inventory contains unparseable lines", "count", badLines)
	}
	if last == "" {
		return "", fmt.Errorf("subject %s not found in inventory: %w", subject, fs.ErrNotExist)
	}
	return last, nil
}

// UpdateInventoryHMAC recomputes and writes the HMAC for the current inventory.
// It is safe to call externally (e.g. after migrating an existing inventory).
func (s *StorageService) UpdateInventoryHMAC(ctx context.Context, hmacKey []byte) error {
	s.inventoryMu.Lock()
	defer s.inventoryMu.Unlock()
	return s.updateInventoryHMACLocked(ctx, hmacKey)
}

// RebuildInventoryHMAC recomputes the inventory integrity head from the current
// inventory contents using the stored HMAC key, and writes it.
//
// Two callers, with different reasons. After a migration: the destination's
// integrity scheme (whole-blob HMAC vs. the structured backends' hash chain)
// may differ from the source's, so the copied inventory_hmac value is not
// meaningful for the destination and must be recomputed. And from the offline
// "openvox-ca rebuild-inventory-hmac", as the supported repair for a CA whose
// stored value has stopped verifying — there it re-asserts integrity over the
// inventory as it stands rather than verifying anything, which is why that
// command gates it behind an explicit confirmation.
//
// It is a no-op when no HMAC key is present (a CA that never initialised
// integrity), leaving the store untouched. That branch is contractual, not
// incidental: the CLI checks the same condition first and refuses, because a
// silent no-op here would report a repair it did not perform.
func (s *StorageService) RebuildInventoryHMAC(ctx context.Context) error {
	hasKey, err := s.backend.Exists(ctx, KeyHMACKey)
	if err != nil {
		return fmt.Errorf("checking inventory HMAC key: %w", err)
	}
	if !hasKey {
		return nil
	}
	key, err := s.EnsureHMACKey(ctx)
	if err != nil {
		return err
	}
	return s.UpdateInventoryHMAC(ctx, key)
}

// HMACKeyState describes the stored inventory HMAC key as found, without
// changing it. EnsureHMACKey regenerates a present-but-wrong-length key, which
// is itself one of the ways an inventory stops verifying; a report that called
// it would perform the very act it exists to describe.
type HMACKeyState int

const (
	// HMACKeyUnknown is the zero value: nothing has been read yet. It exists so
	// that a zero-valued report does not assert the most reassuring answer --
	// InventoryIntegrityReport returns a partly-filled report alongside every
	// error, and on the arms that fail before the key is read, a zero value
	// meaning "usable" would be a lie a caller could act on.
	HMACKeyUnknown HMACKeyState = iota
	// HMACKeyUsable means the stored key is present and the expected length.
	HMACKeyUsable
	// HMACKeyAbsent means no key is stored: integrity was never initialised.
	HMACKeyAbsent
	// HMACKeyWrongLength means a key is stored but is not hmacKeyLen bytes.
	// Every existing MAC was computed under a key that no longer exists, so no
	// rebuild can reproduce them and one would mint a new key as a side effect.
	HMACKeyWrongLength
)

// String names the state for operator-facing output.
func (s HMACKeyState) String() string {
	switch s {
	case HMACKeyUnknown:
		return "unknown"
	case HMACKeyUsable:
		return "usable"
	case HMACKeyAbsent:
		return "absent"
	case HMACKeyWrongLength:
		return "wrong-length"
	default:
		return "unknown"
	}
}

// InventoryIntegrityReport is the inventory's integrity state as it currently
// stands. Every field is what was found, never what was repaired.
type InventoryIntegrityReport struct {
	// Scheme is the integrity scheme this backend computes under:
	// "hash-chain" on InventoryStore backends, "whole-blob-hmac" otherwise.
	Scheme string
	// Entries is the number of inventory entries the value covers.
	Entries int
	// KeyState is the stored HMAC key as found.
	KeyState HMACKeyState
	// StoredHead is the persisted integrity value, nil when none is stored.
	StoredHead []byte
	// ComputedHead is the value recomputed from the inventory as it now
	// stands, nil when KeyState is not HMACKeyUsable.
	ComputedHead []byte
	// LegacyUndecomposed reports a structured backend still holding an
	// undecomposed legacy inventory blob. Entries() reads only the decomposed
	// rows, so such a store answers "no entries" while its real inventory sits
	// in the blob and its stored head is a whole-blob MAC. Rebuilding there
	// would write an empty hash-chain head over the only baseline that can
	// validate the blob, which is destruction rather than repair.
	//
	// It can be true only because this report is reached without EnsureReady:
	// the server decomposes on start (CA.Init -> EnsureDirs -> EnsureReady),
	// and an offline command that reports rather than starts does not.
	LegacyUndecomposed bool
	// UnparseableLines counts lines the inventory blob holds that are not
	// entry-shaped. Always zero on a structured backend, whose entries are
	// rows. It is not a curiosity: the blob scheme MACs the whole blob, so
	// those lines are covered by the value a rebuild re-asserts while being
	// invisible in Entries — which is the operator's only quantitative view of
	// what they are about to sign over.
	UnparseableLines int
	// Verifies reports whether StoredHead and ComputedHead agree. False
	// whenever either is missing.
	Verifies bool
}

// InventoryIntegrityReport describes the inventory's integrity state without
// verifying it and without writing anything.
//
// It exists because every ordinary read path is fail-closed: ReadInventory and
// InventoryEntries return ErrInventoryTampered on a mismatch, which is correct
// for serving and useless for diagnosis. An operator whose CA will not start
// needs to see what does not verify *before* deciding whether to re-assert it,
// and the fail-closed paths will not show them.
//
// What it deliberately cannot answer: which entry diverged. The backends
// persist one head MAC (KeyInventoryHMAC) and no per-entry value — an inventory
// row carries the four canonical columns plus a display projection, none of
// them a MAC — so nothing records what any prefix should have hashed to.
// Localising a divergence would need a schema change, and a report that implied
// otherwise would be inviting an operator to trust a bisection it never
// performed. See docs/development/inventory-store.md for the row's shape; do
// not re-enumerate the columns here, which is how this comment was wrong once
// already (read off the initial migration rather than the current model).
func (s *StorageService) InventoryIntegrityReport(ctx context.Context) (InventoryIntegrityReport, error) {
	s.inventoryMu.RLock()
	defer s.inventoryMu.RUnlock()

	rep := InventoryIntegrityReport{Scheme: s.inventoryScheme()}

	// Read the inventory once and keep what is needed to fold the head from it.
	// computeInventoryHMAC would re-read the whole thing, and this method runs
	// twice per repair (before and after), so deferring to it turned one
	// operator command into five full inventory scans -- against a store whose
	// owner is trying to get it back into service, and, since reporting is
	// offered against a live CA, not only against a downed one.
	var (
		entries []InventoryEntry
		blob    []byte
		chained bool
	)
	if store, ok := asInventoryStore(s.backend); ok {
		chained = true
		got, err := store.Entries(ctx)
		if err != nil {
			return rep, fmt.Errorf("reading inventory entries: %w", err)
		}
		entries = got
	} else {
		data, err := s.readInventoryForHMAC(ctx)
		if err != nil {
			return rep, fmt.Errorf("reading inventory: %w", err)
		}
		blob = data
		entries, rep.UnparseableLines = parseInventoryBlobCounting(data)
	}
	rep.Entries = len(entries)

	if chained && len(entries) == 0 {
		// Distinguish "structured and empty" from "structured but not yet
		// decomposed". Backend-agnostic: after decomposition the blob key
		// renders the rows, so entries and blob agree; before it, the rows are
		// absent and the blob holds everything. A SQL backend's blob key is an
		// empty presence marker, so it cannot false-positive here.
		if legacy, err := s.readInventoryForHMAC(ctx); err == nil && len(parseInventoryBlob(legacy)) > 0 {
			rep.LegacyUndecomposed = true
		}
	}

	key, stored, err := s.loadHMACKey(ctx)
	if err != nil {
		return rep, fmt.Errorf("reading inventory HMAC key: %w", err)
	}
	switch {
	case key != nil:
		rep.KeyState = HMACKeyUsable
	case stored != nil:
		rep.KeyState = HMACKeyWrongLength
	default:
		rep.KeyState = HMACKeyAbsent
	}

	switch storedHead, err := s.backend.Get(ctx, KeyInventoryHMAC); {
	case err == nil:
		rep.StoredHead = storedHead
	case errors.Is(err, fs.ErrNotExist):
		// No baseline yet. Not an error: a CA that has never run the
		// verification path has nothing stored, and the caller must be able to
		// tell that apart from a mismatch.
	default:
		return rep, fmt.Errorf("reading inventory HMAC: %w", err)
	}

	if rep.KeyState == HMACKeyUsable {
		// The same fold computeInventoryHMAC performs, over what was read above
		// rather than over a second fetch of it.
		computed := foldInventoryHead(key, entries, blob, chained)
		rep.ComputedHead = computed
		// StoredHead != nil is load-bearing beyond the obvious: an empty
		// structured inventory folds to a nil head, and hmac.Equal(nil, nil) is
		// true, so without it a store that never wrote a baseline would report
		// as verifying.
		rep.Verifies = rep.StoredHead != nil && hmac.Equal(rep.StoredHead, computed)
	}

	return rep, nil
}

func (s *StorageService) updateInventoryHMACLocked(ctx context.Context, hmacKey []byte) error {
	sum, err := s.computeInventoryHMAC(ctx, hmacKey)
	if err != nil {
		return fmt.Errorf("computing inventory HMAC: %w", err)
	}
	return s.backend.Put(ctx, KeyInventoryHMAC, sum, BlobPrivate)
}

// VerifyInventoryHMAC checks the inventory against its stored HMAC. Returns
// ErrInventoryTampered on mismatch, or initialises a baseline HMAC on first run.
func (s *StorageService) VerifyInventoryHMAC(ctx context.Context, hmacKey []byte) error {
	s.inventoryMu.Lock()
	defer s.inventoryMu.Unlock()
	return s.verifyInventoryHMACLocked(ctx, hmacKey)
}

func (s *StorageService) verifyInventoryHMACLocked(ctx context.Context, hmacKey []byte) error {
	storedMAC, err := s.backend.Get(ctx, KeyInventoryHMAC)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			slog.Info("No inventory HMAC found; initializing integrity baseline")
			return s.updateInventoryHMACLocked(ctx, hmacKey)
		}
		return fmt.Errorf("reading inventory HMAC: %w", err)
	}

	computedMAC, err := s.computeInventoryHMAC(ctx, hmacKey)
	if err != nil {
		return fmt.Errorf("computing inventory HMAC for verification: %w", err)
	}

	if !hmac.Equal(storedMAC, computedMAC) {
		// Name the integrity scheme we computed under. A mismatch usually means
		// genuine tampering, but it also fires when a backend is served under a
		// different scheme than the stored value was written with (e.g. a
		// ca_key_file/ca_cert_file server on a build before the InventoryStore
		// unwrap fix stored a whole-blob HMAC over what is now read as a hash
		// chain). Surfacing the scheme lets an operator tell the two apart.
		scheme := s.inventoryScheme()
		slog.Warn("inventory HMAC mismatch; integrity check failed", "scheme", scheme,
			"repair", inventoryRepairHint)
		return ErrInventoryTampered
	}
	return nil
}

// inventoryRepairHint names the supported repair on the two log lines an
// operator actually reads when a CA will not start. One definition rather than
// two copies: it names a flag defined in another package, and a rename that
// updated only one site would leave the other pointing at a flag that no longer
// exists — the same reason wholeBlobInventoryMAC is defined once.
const inventoryRepairHint = "openvox-ca rebuild-inventory-hmac reports the state and, with " +
	"--yes-re-bless, re-asserts integrity over the inventory as it stands"

// ErrInventoryTampered is returned when the inventory HMAC verification fails.
var ErrInventoryTampered = fmt.Errorf("inventory file integrity check failed: HMAC mismatch (possible tampering)")
