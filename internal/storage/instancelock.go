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
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

// The store-wide instance lock, which permits exactly one running instance on a
// backend that cannot coordinate several.
//
// A backend with proper distributed locking may run multiple instances, on one
// host or on many; every other backend permits exactly one. The rule is a
// property of the backend's locking rather than of its name, so this gates on
// StorageService.SupportsDistributedLocking and a backend that gains or loses
// that capability gets the right behaviour without anyone remembering to update
// a list.
//
// Why exclusion rather than finer-grained locking. Each ca.CA holds state no
// other process sees or invalidates — the serial index, the OCSP cache, and the
// CRL its own revocation checks read. A second instance issues certificates the
// first never learns of, and a revocation performed on one leaves the other
// still authenticating the revoked certificate. Making individual writes atomic
// would correct what lands on disk and none of that; reconciling cached state
// across processes is what the distributed backends do through shared storage,
// and the single-node backends have no such mechanism by design.
//
// This is the same flock(2) primitive as the per-name same-host locks in
// filelock.go, at a different granularity: one lock for the whole store, held
// for the lifetime of the process rather than for one operation.
//
// It is deliberately best-effort, and cannot be otherwise. An advisory lock says
// nothing useful over NFS, and a second process on another host cannot be
// excluded at all — which is why the documentation half of this rule cannot be
// replaced by the code half. See docs/storage-backends.md.

// instanceLockName is the reserved lock naming the store as a whole.
//
// It sits outside every namespace real operations use ("bootstrap", "crl",
// "subject:<name>") and outside lockProbeName, so nothing an instance does
// while running can contend with the lock proving it is the only instance.
const instanceLockName = "store-instance"

// instanceProbeTimeout bounds the SupportsDistributedLocking probe that decides
// whether the instance lock applies at all.
//
// Bounded here rather than left to callers because forgetting it converts a
// safety check into an outage: the probe takes and releases a real lock, so on
// an unreachable cluster backend an unbounded one would hang startup for ever
// instead of failing. A caller's own deadline still applies if it is shorter.
//
// A variable rather than a constant so a spec can drive the bound itself, in the
// same way and for the same reason tryLock is indirected in filelock.go: the
// property worth pinning is that a probe which never returns cannot hang a
// startup, and a ten-second wait is not something a unit suite can sit through.
// Production never changes it.
var instanceProbeTimeout = 10 * time.Second

// instanceHolderLimit caps how much of a lock file is read back when reporting
// who holds it. The record is one short line; anything longer is not ours.
const instanceHolderLimit = 512

// StoreLockedError reports that another process already holds the store's
// instance lock, and names it. Holder is what that process recorded about
// itself, and is empty when the record could not be read.
//
// A distinct type rather than a formatted string so callers can tell "somebody
// else is running" from "the lock could not be taken", and so tests assert on
// the condition rather than on wording.
type StoreLockedError struct {
	// Path is the lock file the refusal came from.
	Path string
	// Holder describes the process holding it, as that process recorded
	// itself. Empty when the record was missing or unreadable.
	Holder string
}

func (e *StoreLockedError) Error() string {
	who := e.Holder
	if who == "" {
		// The holder took the lock but had not yet written its record, or the
		// record was truncated. Still a refusal, and still worth reporting as
		// one: the lock file names the store even when its contents do not name
		// the process.
		who = "an unidentified process"
	}
	return fmt.Sprintf(
		"another openvox-ca process is already running against this store: %s (lock file %s). "+
			"This storage backend has no distributed locking, so exactly one instance may run at a time; "+
			"stop the running one first",
		who, e.Path)
}

// InstanceLocker is implemented by backends that can hold a store-wide
// exclusive lock excluding another process on the same host.
//
// Deliberately not part of Backend: a backend that cannot provide one is not
// broken, it is simply one where this rule has to rest on the operator instead.
//
// No context parameter, unlike Locker and SameHostLocker, and that is the
// contract rather than an oversight: this acquisition never waits. A caller
// starting a server wants to be told that another instance is running, not to
// queue behind it until a timeout it would then have to explain.
type InstanceLocker interface {
	AcquireInstanceLock() (Unlocker, error)
}

// AcquireInstanceLock takes the store-wide lock permitting exactly one running
// instance, and returns an Unlocker the caller must hold for as long as it is
// running.
//
// It reports StoreLockedError when another process already holds the store, and
// a nil error in every case where the rule does not apply or cannot be
// enforced. Those two are not the same answer and the caller must not conflate
// them: only the error means "do not run".
//
// The three no-op cases:
//
//   - The backend has distributed locking. Multiple instances are a supported,
//     designed-for configuration there, so there is nothing to enforce and this
//     must not interfere with it.
//   - The capability could not be determined. See below.
//   - The backend has no instance lock to take: an in-memory SQLite database
//     private to this process, a platform without flock(2), a store on a
//     read-only mount. Warned about, then allowed, because refusing to start
//     over a lock that is unavailable rather than held would take down a CA
//     that worked before this check existed.
//
// A caller that has already asked SupportsDistributedLocking may pass the
// answer with WithKnownDistributedLocking and skip the probe here; without it
// this method probes for itself, so it is always safe to call knowing nothing.
//
// # Releasing it
//
// Release the lock AFTER closing the backend it protects, never before. Between
// the two, a second process that took the store would find this one still
// holding an open handle to it -- on SQLite a pooled connection to the very
// database file the lock exists to keep to one writer.
//
// The mechanism differs by caller because their lifetimes do, and neither can
// borrow the other's: `openvox-ca` hangs the release off a runtime whose closer
// list runs in reverse, so it inserts the release at the front
// (cmd/openvox-ca/runtime.go, holdInstanceLock); `openvox-ca-ctl` has no such
// list and returns one cleanup that does both in order
// (cmd/openvox-ca-ctl/migrate.go, lockStore). What they share is this rule and
// the spec helper that asserts it, testutil.RecordingBackend -- so the
// invariant is stated once here rather than argued twice there.
//
// On a probe error it warns and permits, which is the safe direction here even
// though it reads like the unsafe one. The error path is unreachable for the
// backends this rule governs: FilesystemBackend implements no Locker at all, so
// the probe answers (false, nil); SQLite implements one but reports
// ErrDistributedLockingUnsupported, likewise (false, nil); and an
// OverlayBackend over either returns the same sentinel. A non-nil error can
// therefore only come from a backend that does have distributed locking and is
// momentarily unreachable — where refusing to start would be a restriction on
// precisely the deployments this rule exempts, and where the process will fail
// loudly on its own first locked operation anyway if the backend is really down.
func (s *StorageService) AcquireInstanceLock(ctx context.Context, opts ...InstanceLockOption) (Unlocker, error) {
	var cfg instanceLockConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	distributed, err := cfg.knownDistributed, error(nil)
	if cfg.known == nil {
		probeCtx, cancel := context.WithTimeout(ctx, instanceProbeTimeout)
		defer cancel()
		distributed, err = s.SupportsDistributedLocking(probeCtx)
	}

	switch {
	case err != nil:
		slog.Warn("Could not determine whether this storage backend coordinates locks across processes; "+
			"not enforcing the single-instance rule. Backends without distributed locking support "+
			"exactly one running instance",
			"error", err)
		return noopUnlocker{}, nil
	case distributed:
		// Nothing to enforce, and nothing to log: this is the ordinary state of
		// every HA deployment.
		return noopUnlocker{}, nil
	}

	il, ok := s.backend.(InstanceLocker)
	if !ok {
		slog.Warn("This storage backend has no distributed locking and offers no store-wide lock, " +
			"so a second running instance cannot be prevented. Exactly one instance is supported; " +
			"do not start another")
		return noopUnlocker{}, nil
	}

	ul, err := il.AcquireInstanceLock()
	switch {
	case err == nil:
		return ul, nil
	case errors.Is(err, ErrSameHostLockingUnsupported):
		slog.Warn("The store-wide lock is unavailable, so a second running instance cannot be prevented. " +
			"This backend has no distributed locking, so exactly one instance is supported; " +
			"do not start another")
		return noopUnlocker{}, nil
	default:
		// Includes StoreLockedError, which is the point of the whole exercise.
		return nil, err
	}
}

// LockIsEnforced reports whether u is a lock that actually excludes another
// instance, as opposed to one of the no-ops AcquireInstanceLock returns when it
// has nothing to enforce.
//
// It exists because those two are indistinguishable to a caller: both arrive as
// a nil error and a usable Unlocker, and the only notice of the difference is an
// slog warning, which an offline subcommand has usually just repointed at the
// server's logfile. A caller whose correctness depends on being alone — the
// inventory rebuild, whose head is computed from a snapshot — needs to be able
// to ask.
func LockIsEnforced(u Unlocker) bool {
	el, ok := u.(enforcingUnlocker)
	return ok && el.enforcesInstance()
}

// enforcingUnlocker is implemented by an Unlocker that really does exclude a
// second instance. Asserting this positively rather than testing "is not the
// no-op" is the whole point: the negative form answered "enforced" for every
// type it had not been told about -- a future no-op variant, a pointer form, a
// wrapper placed over a no-op -- and the direction of that mistake is to
// convert "cannot be shown to be quiet" into "proceed", on the one command
// whose correctness depends on the store being quiet. An unrecognised Unlocker
// now reads as unenforced, which is the safe answer.
type enforcingUnlocker interface {
	enforcesInstance() bool
}

// InstanceLockOption adjusts one AcquireInstanceLock call.
type InstanceLockOption func(*instanceLockConfig)

type instanceLockConfig struct {
	// known is nil unless a caller supplied the capability, so that "not told"
	// and "told false" stay distinguishable.
	known            *bool
	knownDistributed bool
}

// WithKnownDistributedLocking supplies an answer the caller has already had
// from SupportsDistributedLocking, so this call does not buy it twice.
//
// Optional by design. The probe acquires and releases a real lock, so on a
// cluster backend it is a round trip, and `openvox-ca generate` was paying for
// two: one for the capability report it prints, one for the lock. But a caller
// that knows nothing must stay able to call AcquireInstanceLock and get a
// correct answer -- csr and import-ca-cert do exactly that -- so this is a hint
// rather than a parameter. Making it required would push the probe out to the
// call sites that currently do the right thing by not thinking about it.
//
// Pass only a definite answer. SupportsDistributedLocking has three outcomes,
// and its error is not a "false": a caller whose own probe failed should omit
// this and let AcquireInstanceLock re-probe, so the documented warn-and-permit
// policy for an undetermined capability applies in one place rather than being
// reimplemented by each caller.
func WithKnownDistributedLocking(distributed bool) InstanceLockOption {
	return func(c *instanceLockConfig) {
		c.known = &distributed
		c.knownDistributed = distributed
	}
}

// noopUnlocker stands in wherever the instance rule does not apply, so callers
// can defer Unlock unconditionally rather than nil-checking an Unlocker.
type noopUnlocker struct{}

func (noopUnlocker) Unlock() error { return nil }

// enforcesInstance is false: a no-op excludes nobody. Stated explicitly rather
// than left to a type assertion elsewhere, so a new no-op variant has to answer
// the question rather than inherit the wrong answer by default.
func (noopUnlocker) enforcesInstance() bool { return false }

// acquireInstance takes the store-wide lock without waiting, and records who
// took it so a later refusal can say.
//
// Returns StoreLockedError when another process holds it, and
// ErrSameHostLockingUnsupported when this lock set cannot lock at all — the
// same classification acquire makes, for the same reasons.
func (l *fileLocks) acquireInstance() (Unlocker, error) {
	// The nil check covers a backend that holds no lock set: SQLite with an
	// in-memory database constructs none, and such a database is private to
	// this process, so there is no second instance for a lock to exclude.
	if !fileLockingSupported || l == nil {
		return nil, ErrSameHostLockingUnsupported
	}

	// TryLock rather than Lock, so a second acquisition within one process is
	// reported as the programming error it is rather than deadlocking. flock(2)
	// is per open file description, so without this the process would refuse
	// itself and report its own pid as the holder, which is a baffling thing to
	// put in front of an operator.
	local := l.localFor(instanceLockName)
	if !local.TryLock() {
		return nil, fmt.Errorf("this process already holds the instance lock for %s", l.dir)
	}

	path := filepath.Join(l.dir, fileLockFileName(instanceLockName))
	if err := os.MkdirAll(l.dir, DirPerm); err != nil {
		local.Unlock()
		return nil, l.unwritableStore(err, "creating same-host lock directory "+l.dir)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, FilePermPrivate)
	if err != nil {
		local.Unlock()
		return nil, l.inaccessibleLockFile(err, path)
	}

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
	if !locked {
		// Read the holder's record before dropping the descriptor. The read
		// needs no lock of its own: whoever holds it wrote its record before
		// this process could reach here.
		holder := readInstanceHolder(f)
		_ = f.Close()
		local.Unlock()
		return nil, &StoreLockedError{Path: path, Holder: holder}
	}

	// Record who we are, for the next process that is refused. Best-effort:
	// failing to write the record loses the name in somebody else's error
	// message, which is not worth surrendering a lock we hold.
	if err := writeHolder(f); err != nil {
		slog.Warn("Could not record this process in the store's instance lock file; "+
			"another process refused by it will not be able to name this one",
			"lock_file", path, "error", err)
	}

	return &fileUnlocker{f: f, local: local, path: path}, nil
}

// writeHolder is indirected through a variable so a spec can drive the
// best-effort branch above, which no filesystem `go test` can reach on demand:
// the descriptor is open O_RDWR and valid, so the write does not fail. The
// branch matters out of proportion to its size — getting it wrong surrenders a
// lock this process holds over a cosmetic failure — which is worth one seam.
// Same pattern, and the same reason, as tryLock in filelock.go. Production
// always uses the real implementation.
var writeHolder = writeInstanceHolder

// writeInstanceHolder replaces the lock file's contents with a description of
// this process.
//
// Truncate-then-write rather than append: the file outlives every process that
// ever held it — fileUnlocker deliberately never unlinks one — so appending
// would accumulate the record of every instance that has ever run and leave a
// reader unable to tell which line is current.
func writeInstanceHolder(f *os.File) error {
	if err := f.Truncate(0); err != nil {
		return fmt.Errorf("truncating: %w", err)
	}
	if _, err := f.WriteAt([]byte(instanceHolderRecord()), 0); err != nil {
		return fmt.Errorf("writing: %w", err)
	}
	return nil
}

// instanceHolderRecord describes this process for the benefit of the next one
// refused by its lock.
//
// The command name is the binary's, never its arguments: a command line can
// carry a passphrase file path or another operational detail, and this record
// lands in a 0600 file that an error message then prints. The pid, host and
// start time are enough to find the process, which is all the reader needs.
func instanceHolderRecord() string {
	name := "openvox-ca"
	if len(os.Args) > 0 && os.Args[0] != "" {
		name = filepath.Base(os.Args[0])
	}
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "an unknown host"
	}
	return fmt.Sprintf("%s (pid %d) on %s since %s",
		name, os.Getpid(), host, time.Now().UTC().Format(time.RFC3339))
}

// readInstanceHolder returns the holder's record, or "" when there is nothing
// usable to report.
//
// Every failure degrades to "": the caller is already returning a refusal, and
// a refusal that cannot name the holder is still a refusal. The record is
// sanitised because it is about to be interpolated into an error a terminal
// renders — the writer is another instance of this program, but the file is
// only as trustworthy as the directory it sits in.
func readInstanceHolder(f *os.File) string {
	buf := make([]byte, instanceHolderLimit)
	n, err := f.ReadAt(buf, 0)
	if n == 0 && err != nil {
		return ""
	}
	record := strings.TrimSpace(string(buf[:n]))
	if i := strings.IndexAny(record, "\r\n"); i >= 0 {
		record = record[:i]
	}
	return strings.Map(func(r rune) rune {
		// unicode.IsPrint rather than a control-character range. The range
		// caught C0 and DEL and let every Unicode format character through --
		// U+202E RIGHT-TO-LEFT OVERRIDE and the isolates U+2066..U+2069 among
		// them, which reorder the text a terminal draws around them. IsPrint
		// excludes category Cf as well as Cc, so those go, and it keeps letters
		// outside ASCII, so a legitimate non-ASCII hostname in a holder record
		// survives intact. Enumerating the dangerous ranges instead would be
		// incomplete again the next time somebody looked.
		if !unicode.IsPrint(r) {
			return -1
		}
		return r
	}, record)
}
