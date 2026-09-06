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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Same-host locking, shared by the two single-node backends. The mechanism is
// an exclusive flock(2) on one file per lock name, chosen over an O_EXCL
// lockfile because the kernel releases it when the descriptor closes or the
// process dies: there is no stale lock to clean up and no PID liveness to
// guess at, which is the maintenance burden that makes lockfiles a poor fit
// for a CA that operators restart and kill.
//
// Platform support is in filelock_unix.go / filelock_other.go.

const (
	// fileLockRetryInitial and fileLockRetryMax bound the backoff between
	// non-blocking acquisition attempts. Blocking flock(2) would ignore the
	// caller's context, and WithLock callers pass a lockTimeout-bounded one, so
	// the wait is a poll rather than a park. The floor keeps an uncontended
	// hand-off quick; the ceiling keeps a long wait from spinning.
	fileLockRetryInitial = 5 * time.Millisecond
	fileLockRetryMax     = 250 * time.Millisecond
)

// tryLock is indirected through a variable so a spec can drive acquire's
// handling of errno classes the test environment cannot produce on demand: a
// filesystem that rejects BSD locks outright answers EOPNOTSUPP, and no
// temporary directory available to `go test` does that. The path it guards
// turns a graceful degradation into a total CA outage if it regresses, which is
// worth one seam. Production always uses the platform implementation.
var tryLock = tryLockFile

// fileLocks hands out same-host locks as flock(2) holds on files in one
// directory. A backend owns one of these; every process addressing the same
// store must derive the same directory, which is what makes the lock mutual.
type fileLocks struct {
	dir string

	// local holds a *sync.Mutex per lock name, serialising this process's own
	// callers before any of them touches the filesystem. Same pattern, and the
	// same reason, as the etcd/Redis/SQL backends: only one goroutine then
	// contends for the flock, so in-process waiters queue on a mutex instead of
	// each running its own retry loop.
	local sync.Map

	// warnOnce keeps the "store is not writable" warning to one line per lock
	// set rather than one per acquisition.
	warnOnce sync.Once
}

// newFileLocks returns a lock set rooted at dir, which is created on first use.
//
// The path is made absolute here rather than at each call site: two processes
// must agree on it, and a server and a `ctl` command may well be given the same
// store as differently spelled configuration. Two residual ways to defeat that
// remain, both documented in docs/development/locking.md — a relative path
// resolved from two different working directories, and one store reached
// through two different symlinks — because the lock identity is the path, not
// the inode.
func newFileLocks(dir string) *fileLocks {
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}
	return &fileLocks{dir: abs}
}

// fileLockFileName maps a lock name to the file representing it. Hashing
// sidesteps every question about which characters a lock name may contain:
// "subject:<name>" carries a colon, and the subject alphabet ValidateSubject
// admits is not the filesystem's. It also means no name can escape the lock
// directory or collide with another's file by way of path separators.
//
// The mapping is protocol, in the same sense the lock names themselves are: a
// server and a `ctl` command exclude each other only by deriving the same file
// from the same name, so it must stay stable across releases.
func fileLockFileName(name string) string {
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:]) + ".lock"
}

// acquire takes the same-host lock called name, waiting until ctx expires.
// Returns ErrSameHostLockingUnsupported when this lock set cannot lock at all,
// so callers can report the capability honestly rather than appearing to lock.
func (l *fileLocks) acquire(ctx context.Context, name string) (Unlocker, error) {
	// The nil check is for a backend that holds no lock set at all — SQLite with
	// an in-memory database constructs none — so a caller need not repeat it.
	if !fileLockingSupported || l == nil {
		return nil, ErrSameHostLockingUnsupported
	}

	// Deliberately no up-front ctx.Err() check. ctx bounds the *wait* for
	// another process, not the acquisition itself, exactly as the process-local
	// mutex this tier replaces bounds nothing at all: an uncontended lock is
	// granted even to a caller whose deadline has already gone, so the caller
	// fails on its own first storage read rather than here. Revoke's failure
	// accounting is built on that distinction — a revocation that reached the
	// CRL work and failed is counted, one refused at a cross-node acquisition
	// is not (see docs/metrics.md) — and checking here would silently move the
	// single-node backends from one side of it to the other.

	// Like the distributed implementations — and like WithLock's own fallback —
	// this half is a plain sync.Mutex and does not honour ctx, so same-process
	// waiters queue unboundedly while ctx bounds only the wait for another
	// process. Taking it first is what keeps a re-entrant acquisition
	// deadlocking here rather than in the kernel: flock(2) is per open file
	// description, so a second descriptor in this same process would otherwise
	// block against the first.
	local := l.localFor(name)
	local.Lock()

	path := filepath.Join(l.dir, fileLockFileName(name))
	if err := os.MkdirAll(l.dir, DirPerm); err != nil {
		local.Unlock()
		return nil, l.unwritableStore(err, "creating same-host lock directory "+l.dir)
	}
	//nolint:gosec // G703: filepath.Join of the operator-configured store root and a hex sha256 digest, which cannot contain a separator, so the path cannot leave the lock directory
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, FilePermPrivate)
	if err != nil {
		local.Unlock()
		return nil, l.inaccessibleLockFile(err, path)
	}

	backoff := fileLockRetryInitial
	waiting := false
	for {
		locked, lockErr := tryLock(f)
		if lockErr != nil {
			_ = f.Close()
			local.Unlock()
			if isLockingUnavailableError(lockErr) {
				l.warnOnce.Do(func() {
					slog.Warn("Same-host locking is unavailable: this filesystem or kernel cannot provide flock(2)",
						"lock_dir", l.dir, "error", lockErr)
				})
				return nil, ErrSameHostLockingUnsupported
			}
			return nil, fmt.Errorf("locking %s: %w", path, lockErr)
		}
		if locked {
			if waiting {
				slog.Info("Acquired the CA lock the other process was holding", "name", name)
			}
			return &fileUnlocker{f: f, local: local, path: path}, nil
		}

		if !waiting {
			// Say so on the first refusal, once. An `openvox-ca-ctl migrate`
			// inherits a context with no deadline at all, so without this an
			// operator who forgot to stop the server watches a command that
			// prints nothing and never returns, with no way to tell a lock wait
			// from a hang. Mirrors the announcement EnsureReady makes before its
			// own migration lock.
			waiting = true
			slog.Info("Waiting for the CA lock: another process on this host holds it",
				"name", name, "lock_file", path)
		}

		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			_ = f.Close()
			local.Unlock()
			return nil, fmt.Errorf(
				"another process on this host holds the CA lock %q (%s): %w", name, path, ctx.Err())
		case <-timer.C:
		}
		backoff = min(backoff*2, fileLockRetryMax)
	}
}

// unwritableStore classifies a failure to *create the lock directory*, which is
// the one place a permission error genuinely proves the store cannot be written.
// It reports ErrSameHostLockingUnsupported for that case and a hard error for
// everything else.
//
// A store this process cannot write to has no writer for a lock to exclude, so
// refusing to proceed would break a real and read-only-safe operation for no
// gain: `openvox-ca-ctl migrate` takes the "bootstrap" lock on its *source*
// store, which it then only reads, and a source may legitimately be a read-only
// snapshot or a backup mount. Every path that would actually mutate the store
// fails on its own writes moments later, with a clearer error than this one.
//
// Anything else — ENOSPC, a lock path shadowed by a plain file, an I/O error —
// is reported, because it leaves the question of whether another process is
// writing unanswered.
func (l *fileLocks) unwritableStore(err error, what string) error {
	if !errors.Is(err, fs.ErrPermission) && !isReadOnlyFSError(err) {
		return fmt.Errorf("%s: %w", what, err)
	}
	l.warnOnce.Do(func() {
		slog.Warn("Same-host locking is unavailable: the store is not writable by this process",
			"lock_dir", l.dir, "error", err)
	})
	return ErrSameHostLockingUnsupported
}

// inaccessibleLockFile classifies a failure to open a lock file inside a lock
// directory that already exists. Unlike unwritableStore, a permission error here
// is a hard error, and the distinction is the whole point of splitting the two.
//
// os.MkdirAll returns nil for a directory that already exists without checking
// whether it can be written, so EACCES at this point does not mean "the store is
// read-only" — it means this lock directory or lock file belongs to another
// user. That is a reachable configuration, not a hypothetical: the server runs
// as `puppet-ca` under systemd, and an operator running `openvox-ca-ctl` under
// sudo against the same cadir creates the lock directory as root. Treating that
// as "no locking needed" would silently return the server to its pre-#187
// behaviour for the rest of its life (warnOnce says it once and never again)
// while the root process goes on taking flocks it believes are exclusive —
// strictly worse than not having the feature, because both sides now think they
// are safe. Failing loudly is recoverable in one chown; a silent downgrade is
// not detectable from either side.
//
// A read-only filesystem still reports the capability as absent: EROFS says
// nothing about ownership, and a lock directory left behind on a since-remounted
// store is exactly the read-only snapshot unwritableStore exists for.
func (l *fileLocks) inaccessibleLockFile(err error, path string) error {
	if isReadOnlyFSError(err) {
		l.warnOnce.Do(func() {
			slog.Warn("Same-host locking is unavailable: the store is on a read-only filesystem",
				"lock_dir", l.dir, "error", err)
		})
		return ErrSameHostLockingUnsupported
	}
	if errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("opening same-host lock file %s: %w (%s, and this process runs as uid %d; "+
			"another user — typically a ctl command run under sudo — owns it, so `chown -R` the lock "+
			"directory back to the user openvox-ca runs as)", path, err, obstruction(path, l.dir), os.Geteuid())
	}
	return fmt.Errorf("opening same-host lock file %s: %w", path, err)
}

// obstruction names whichever of the lock file and its directory this process
// cannot get past, and who owns it.
//
// Which one it is matters, and both happen. A `ctl` command run under sudo
// against a cadir that has no lock directory yet creates the *directory* as
// root; run against one the server already made, it creates a root-owned
// *file* inside a directory the server owns perfectly well. Blaming the
// directory in the second case sends the operator to chown something that is
// already correct.
//
// Stat is cheap and this only ever decorates an error already being returned,
// so it degrades rather than failing: an unstattable path, or a platform with
// no uid, still leaves the caller with the path itself.
func obstruction(path, dir string) string {
	if uid, ok := ownerUID(path); ok {
		return fmt.Sprintf("the lock file is owned by uid %d", uid)
	}
	if uid, ok := ownerUID(dir); ok {
		return fmt.Sprintf("the lock directory %s is owned by uid %d", dir, uid)
	}
	return "the lock path is inaccessible"
}

func ownerUID(path string) (uint32, bool) {
	//nolint:gosec // G703: the same lock path acquire just built -- the configured store root joined with a hex digest -- and this only reads its owner for a message
	info, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	return statUID(info)
}

// localFor returns the process-local mutex for lock name, creating it on first
// use. Mutexes are never removed; the namespace is small and bounded.
func (l *fileLocks) localFor(name string) *sync.Mutex {
	if v, ok := l.local.Load(name); ok {
		return v.(*sync.Mutex)
	}
	v, _ := l.local.LoadOrStore(name, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// fileUnlocker releases the flock by closing the descriptor that holds it, then
// releases the process-local mutex — in that order, so no in-process waiter can
// be handed the mutex while the kernel still considers the file locked.
//
// The lock file itself is deliberately never removed. Unlinking it while
// another process is blocked on the same path lets a third process create a
// fresh inode at that name and take a lock the blocked one is still waiting
// for, so both would believe they hold it. A handful of empty 0600 files, one
// per distinct lock name, is the cheaper side of that trade.
type fileUnlocker struct {
	f     *os.File
	local *sync.Mutex
	path  string
}

// enforcesInstance is true: an flock(2) really does exclude a second process on
// this host. See LockIsEnforced for why this is answered positively.
func (u *fileUnlocker) enforcesInstance() bool { return true }

func (u *fileUnlocker) Unlock() error {
	// close(2) drops every flock this descriptor holds; there is no window
	// between the two where the lock is held without an owner.
	err := u.f.Close()
	u.local.Unlock()
	if err != nil {
		return fmt.Errorf("releasing same-host lock %s: %w", u.path, err)
	}
	return nil
}
