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

package testutil

import (
	"context"
	"sync"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// RecordingBackend notes the order in which a store is given back: its own
// Close, and the release of the store-wide instance lock through the unlocker
// it hands out.
//
// It exists for one assertion, made in two packages: the instance lock must be
// released *after* the backend it protects is closed, never before. Releasing
// first reopens the window the lock exists to close — another process may take
// a store this one still holds an open handle to, which on SQLite is a pooled
// connection to the database file itself. Both `openvox-ca` and
// `openvox-ca-ctl` reach that invariant through their own helper
// (`holdInstanceLock` and `lockStore` respectively), so both need to assert it
// and neither owns the other's.
//
// Only Close and AcquireInstanceLock are overridden; every other method comes
// from the embedded backend, so this records the ordering without altering what
// the store does.
type RecordingBackend struct {
	storage.Backend
	base *storage.FilesystemBackend

	mu  sync.Mutex
	log []string
}

// NewRecordingBackend wraps a filesystem backend rooted at dir.
func NewRecordingBackend(dir string) *RecordingBackend {
	base := storage.NewFilesystemBackend(dir)
	return &RecordingBackend{Backend: base, base: base}
}

func (b *RecordingBackend) note(event string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.log = append(b.log, event)
}

// Events returns what has been given back so far, in order.
func (b *RecordingBackend) Events() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.log...)
}

// Close records the close and performs it.
func (b *RecordingBackend) Close() error {
	b.note("close")
	return b.base.Close()
}

// AcquireInstanceLock hands out an unlocker that records its release.
func (b *RecordingBackend) AcquireInstanceLock() (storage.Unlocker, error) {
	ul, err := b.base.AcquireInstanceLock()
	if err != nil {
		return nil, err
	}
	return &recordingUnlocker{backend: b, wrapped: ul}, nil
}

// NOTE: recordingUnlocker does not forward storage's unexported
// enforcesInstance predicate, so storage.LockIsEnforced answers false for a
// RecordingBackend even when the wrapped lock is a real flock. That is the
// fail-closed direction and harmless for the ordering this type exists to
// record, but it means RecordingBackend must NOT be used in specs that assert
// on holdInstanceLock's `enforced` return: such a spec would see the
// unenforceable-lock refusal and be "fixed" by passing --replicas-stopped,
// quietly retiring the gate it was meant to pin.
type recordingUnlocker struct {
	backend *RecordingBackend
	wrapped storage.Unlocker
}

func (u *recordingUnlocker) Unlock() error {
	u.backend.note("unlock")
	return u.wrapped.Unlock()
}

// UnreachableLockBackend advertises distributed locking and never delivers it,
// which is what a cluster backend having a bad moment looks like to a
// capability probe.
//
// The distinction it exists to test is the one that matters most about
// SupportsDistributedLocking: its error is a third answer, not a "no". Reporting
// an unreachable lock service as "this backend has no distributed locking"
// would apply the single-instance rule to a deployment that is entitled to run
// many, which is the one restriction #275 forbids.
type UnreachableLockBackend struct {
	storage.Backend
	err error
}

// NewUnreachableLockBackend wraps a filesystem backend rooted at dir whose lock
// acquisition always fails with err.
func NewUnreachableLockBackend(dir string, err error) *UnreachableLockBackend {
	return &UnreachableLockBackend{Backend: storage.NewFilesystemBackend(dir), err: err}
}

// AcquireLock always fails, and never with a sentinel — a sentinel would be
// classified as "no distributed locking" rather than "could not tell".
func (b *UnreachableLockBackend) AcquireLock(context.Context, string) (storage.Unlocker, error) {
	return nil, b.err
}
