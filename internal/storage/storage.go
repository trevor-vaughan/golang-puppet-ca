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

// WithLock runs fn while holding the named lock. When the underlying
// backend implements Locker, the lock is coordinated across nodes;
// otherwise it falls back to a process-local named mutex, sufficient for
// single-node backends. The lock is always released when fn returns,
// including on panic.
//
// Names should be stable and descriptive (e.g. "bootstrap", "crl",
// "subject:<name>") since all callers using the same name contend on the
// same lock.
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
		// Backend advertises Locker but cannot actually provide one (e.g.
		// OverlayBackend wrapping a filesystem base); fall through to the
		// process-local mutex, which is correct for single-node backends.
	}
	m := s.localNamedLock(name)
	m.Lock()
	defer m.Unlock()
	return fn()
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
// unique index (translated from the dialect-specific driver error); blob
// backends via an explicit scan performed under the same inventoryMu that
// already serialises every append within a process.
//
// This is NOT a cross-replica guarantee on non-SQL backends: nothing today
// wraps the whole AppendInventory call in a distributed lock for
// filesystem/etcd/redis backends (see the blob-fallback HMAC-update comment
// below, which already documents a similar limitation for that path).
// Structured (SQL) backends remain the only ones with a true cluster-wide
// guarantee, via the database's own unique index.
var ErrDuplicateSerial = errors.New("serial number already exists in inventory")

// AppendInventory adds entry (a single inventory.txt line, without a trailing
// newline) to the inventory. On backends that implement InventoryStore the
// entry is stored as a structured record and the integrity head is advanced by
// a hash chain in O(1); otherwise the line is appended to the KeyInventory blob
// and the whole-blob HMAC is recomputed. Returns ErrDuplicateSerial (wrapped)
// if the entry's serial is already present anywhere in the inventory.
func (s *StorageService) AppendInventory(ctx context.Context, entry string) error {
	s.inventoryMu.Lock()
	defer s.inventoryMu.Unlock()

	parsed, ok := parseInventoryEntry(entry)
	if !ok {
		return fmt.Errorf("malformed inventory entry %q", entry)
	}

	if store, ok := asInventoryStore(s.backend); ok {
		var newHead func(prev []byte) []byte
		if s.hmacKey != nil {
			key := s.hmacKey
			newHead = func(prev []byte) []byte { return chainInventoryMAC(key, prev, entry) }
		}
		if err := store.AppendEntry(ctx, parsed, newHead); err != nil {
			if isUniqueSerialViolation(err) {
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
	var entries []InventoryEntry
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if e, ok := parseInventoryEntry(line); ok {
			entries = append(entries, e)
		}
	}
	return entries, nil
}

// PruneInventory removes every inventory entry for which keep returns false,
// rewriting the inventory and its integrity head together under the inventory
// write lock. It returns the removed entries (in issuance order) so the caller
// can act on them — drop their CRL revocations, invalidate caches, delete the
// stored cert. When nothing is removed the inventory and head are left
// untouched and (nil, nil) is returned.
//
// The current inventory integrity is verified before pruning, so a tampered
// inventory surfaces ErrInventoryTampered rather than being silently rewritten.
//
// Concurrency: appends (AppendInventory) and reads (ReadInventory) take the same
// inventoryMu, so within a process a prune never interleaves with them. The
// rewrite is a single Backend.Put on KeyInventory, which structured backends
// service as an atomic table replacement and blob backends as an atomic file
// swap; callers needing cross-replica serialisation against revocation should
// hold the cluster CRL lock around this (see ca.CA.CleanupExpiredCerts).
func (s *StorageService) PruneInventory(ctx context.Context, keep func(InventoryEntry) bool) ([]InventoryEntry, error) {
	s.inventoryMu.Lock()
	defer s.inventoryMu.Unlock()

	if s.hmacKey != nil {
		if err := s.verifyInventoryHMACLocked(ctx, s.hmacKey); err != nil {
			return nil, err
		}
	}

	// Structured backends prune rows and rewrite the chained integrity head in a
	// single transaction, so the two can never be observed out of sync across
	// replicas (mirroring the atomic AppendEntry path).
	if store, ok := asInventoryStore(s.backend); ok {
		var recomputeHead func(survivors []InventoryEntry) []byte
		if s.hmacKey != nil {
			key := s.hmacKey
			recomputeHead = func(survivors []InventoryEntry) []byte {
				var head []byte
				for _, e := range survivors {
					head = chainInventoryMAC(key, head, canonicalInventoryLine(e))
				}
				return head
			}
		}
		return store.PruneEntries(ctx, keep, recomputeHead)
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
			// The inventory is already rewritten but the stored head now lags it;
			// surface the failure so the operator/job can react rather than leave
			// a mismatch that the next verify would flag as tampering.
			return nil, fmt.Errorf("updating inventory HMAC after prune: %w", err)
		}
	}
	return removed, nil
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

// --- Serving certificate (tls_self_provision) ---
//
// The certificate the API listener presents, and its private key. Held as
// dedicated blobs rather than per-subject material so that administrative
// operations on the CA's own hostname cannot delete what the listener is using.
//
// The key is BlobPrivate, exactly as the CA key already is. An operator running
// a SQL backend without tls_self_provision_encrypt_key stores this key in their
// database in plaintext — the same posture ca_key has by default, since
// encrypt_ca_key is also off unless enabled. It is one blob over, not a new
// class of exposure.

func (s *StorageService) GetServingCert(ctx context.Context) ([]byte, error) {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	return s.backend.Get(ctx, KeyServingCert)
}

func (s *StorageService) SaveServingCert(ctx context.Context, pemData []byte) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	return s.backend.Put(ctx, KeyServingCert, pemData, BlobPublic)
}

func (s *StorageService) GetServingKey(ctx context.Context) ([]byte, error) {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	return s.backend.Get(ctx, KeyServingKey)
}

func (s *StorageService) SaveServingKey(ctx context.Context, pemData []byte) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	return s.backend.Put(ctx, KeyServingKey, pemData, BlobPrivate)
}

// GetServingSuperseded returns the pending-revocation list, wrapping
// fs.ErrNotExist when none has been written.
func (s *StorageService) GetServingSuperseded(ctx context.Context) ([]byte, error) {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	return s.backend.Get(ctx, KeyServingSuperseded)
}

func (s *StorageService) SaveServingSuperseded(ctx context.Context, data []byte) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	return s.backend.Put(ctx, KeyServingSuperseded, data, BlobPrivate)
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

// EnsureHMACKey loads or generates the HMAC key used for inventory integrity.
// The key is stored via the backend under KeyHMACKey.
//
// A transient backend error (network blip, deadline exceeded, ...) is
// distinguished from a genuine "not present" via fs.ErrNotExist; otherwise a
// momentary failure on Get would silently regenerate the key and invalidate
// every existing inventory MAC.
func (s *StorageService) EnsureHMACKey(ctx context.Context) ([]byte, error) {
	data, err := s.backend.Get(ctx, KeyHMACKey)
	switch {
	case err == nil:
		if len(data) == hmacKeyLen {
			return data, nil
		}
		// Stored blob is the wrong length (truncated / corrupted): fall
		// through to regeneration. Operators see the new key on next read.
	case errors.Is(err, fs.ErrNotExist):
		// First boot: fall through to generate and persist a fresh key.
	default:
		return nil, fmt.Errorf("reading HMAC key: %w", err)
	}

	key := make([]byte, hmacKeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating HMAC key: %w", err)
	}
	if err := s.backend.Put(ctx, KeyHMACKey, key, BlobPrivate); err != nil {
		return nil, fmt.Errorf("writing HMAC key: %w", err)
	}
	return key, nil
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
		var head []byte
		for _, e := range entries {
			head = chainInventoryMAC(hmacKey, head, canonicalInventoryLine(e))
		}
		return head, nil
	}

	data, err := s.readInventoryForHMAC(ctx)
	if err != nil {
		return nil, err
	}
	return wholeBlobInventoryMAC(hmacKey, data), nil
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
// inventory contents using the stored HMAC key, and writes it. It is meant to
// run after a migration: the destination's integrity scheme (whole-blob HMAC
// vs. the structured backends' hash chain) may differ from the source's, so the
// copied inventory_hmac value is not meaningful for the destination and must be
// recomputed. It is a no-op when no HMAC key is present (a CA that never
// initialised integrity), leaving the destination untouched.
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
		scheme := "whole-blob-hmac"
		if _, ok := asInventoryStore(s.backend); ok {
			scheme = "hash-chain"
		}
		slog.Warn("inventory HMAC mismatch; integrity check failed", "scheme", scheme)
		return ErrInventoryTampered
	}
	return nil
}

// ErrInventoryTampered is returned when the inventory HMAC verification fails.
var ErrInventoryTampered = fmt.Errorf("inventory file integrity check failed: HMAC mismatch (possible tampering)")
