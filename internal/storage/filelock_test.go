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
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Two backend values over one store stand in for two processes throughout this
// file, and the substitution is exact rather than convenient: flock(2) is held
// by an *open file description*, not by a process, so two independent
// os.OpenFile calls exclude each other whether or not a fork separates them.
// What a second value does not model is the process-local mutex each backend
// takes first — which is the point, since that mutex is what would otherwise
// hide the flock from a single-process test. The genuine two-process case is
// covered by "excludes a real second process" below, which re-executes this
// test binary.

var _ = Describe("Same-host locking", func() {
	var ctx context.Context

	BeforeEach(func() { ctx = context.Background() })

	// A short deadline for the contended attempts. Long enough that a slow
	// machine does not report contention where there is none, short enough that
	// a regression fails the suite rather than hanging it.
	//
	// What it is sized against is a lock acquisition: one that loses, and so is
	// waited out for the whole budget, or one that is uncontended and returns at
	// once. Four sites below do bound an acquisition asserted to succeed (the
	// uncontended and distinct-name cases, the post-panic release, and the
	// Eventually attempt) and are in bounds precisely because an uncontended
	// flock costs microseconds.
	//
	// What it must never bound is work whose successful cost is open-ended -- a
	// schema migration, an index build -- because that cost is a property of the
	// schema and the machine, not of this constant. One was observed taking
	// 1.508s under -race on a loaded runner. The migration spec below is where
	// this had drifted onto a success path, which is the whole of #298.
	const contendedTimeout = 750 * time.Millisecond

	// How long a spec here waits for open-ended work that must succeed. It is
	// not a migration budget: the migration keeps the production one, since that
	// is what a real deployment gets and what #298 asked for. This bounds only
	// how patient the *spec* is, which is a separate question and the one that
	// got conflated with the other in #298.
	//
	// It matters that it is well under ten minutes. sqlMigrationTimeout is
	// exactly ten minutes, and so is go test's default binary timeout, which
	// nothing here overrides -- magefile.go passes no -timeout anywhere. This
	// file is untagged, and unitTestExcludes holds only internal/testutil, so
	// every job that builds the package runs it: test:unit as well as the four
	// backend targets, five in all, plus the pre-push hook's `go test -race
	// ./...`. Left unbounded, a regression in lock *release* would therefore
	// race those two deadlines and most likely surface as "panic: test timed
	// out after 10m0s" for the whole package, naming nothing, in all of them --
	// including the one job every change runs. Twenty times the worst migration
	// yet observed, and a twentieth of the binary's budget.
	const specPatience = 30 * time.Second

	svc := func(b Backend) *StorageService {
		return NewWithBackend(b, filepath.Join(GinkgoT().TempDir(), "private"))
	}

	Describe("the capability it advertises", func() {
		// The filesystem backend must stay a non-Locker. Anything asking whether
		// the store coordinates across replicas -- an operator pre-flight, an HA
		// readiness check -- probes Locker, and answering "yes" because a second
		// *process* is now handled would recommend a multi-node deployment this
		// backend cannot serve. Same-host locking is a separate capability
		// precisely so this answer does not move.
		It("does not make the filesystem backend a distributed Locker", func() {
			var b any = NewFilesystemBackend(GinkgoT().TempDir())

			_, isLocker := b.(Locker)
			Expect(isLocker).To(BeFalse(),
				"FilesystemBackend must not implement Locker: it cannot coordinate across hosts")

			_, isSameHost := b.(SameHostLocker)
			Expect(isSameHost).To(BeTrue(), "FilesystemBackend must implement SameHostLocker")
		})

		// SQLite keeps answering ErrDistributedLockingUnsupported. The same
		// reasoning as above, plus: WithLock's tier order depends on it, since
		// the same-host tier is only reached through that sentinel.
		It("leaves SQLite reporting distributed locking as unsupported", func() {
			b := newSQLiteBackend()

			_, err := b.AcquireLock(ctx, "crl")
			Expect(err).To(MatchError(ErrDistributedLockingUnsupported))

			ul, err := b.AcquireSameHostLock(ctx, "crl")
			Expect(err).NotTo(HaveOccurred(), "but the same-host lock is available")
			Expect(ul.Unlock()).To(Succeed())
		})
	})

	Describe("the filesystem backend", func() {
		It("creates the lock directory at EnsureReady, not lazily", func() {
			// So the server owns it from first boot. Left to the lazy path it is
			// created by whichever process first needs a lock, and on an
			// upgraded CA — where Init takes the fast load path and takes no
			// lock at all — that could be a `ctl` command run under sudo, which
			// manufactures the root-owned directory acquire then has to refuse.
			// Creating it here also turns an unwritable cadir into a startup
			// failure rather than one that surfaces on a request weeks later.
			dir := GinkgoT().TempDir()
			Expect(NewFilesystemBackend(dir).EnsureReady(ctx)).To(Succeed())

			info, err := os.Stat(filepath.Join(dir, fsLockDir))
			Expect(err).NotTo(HaveOccurred(), "EnsureReady must create the lock directory")
			Expect(info.IsDir()).To(BeTrue())
		})

		It("excludes a second holder of the same lock name", func() {
			dir := GinkgoT().TempDir()
			first, second := NewFilesystemBackend(dir), NewFilesystemBackend(dir)

			held, err := first.AcquireSameHostLock(ctx, "crl")
			Expect(err).NotTo(HaveOccurred())

			deadline, cancel := context.WithTimeout(ctx, contendedTimeout)
			defer cancel()
			_, err = second.AcquireSameHostLock(deadline, "crl")
			Expect(err).To(HaveOccurred(), "the second holder must not be granted a held lock")
			Expect(err).To(MatchError(context.DeadlineExceeded))
			// The message has to name the situation, not just the timeout: this
			// is what an operator sees when they run a ctl command against a
			// live server, and "context deadline exceeded" alone would send them
			// looking for a network problem.
			Expect(err.Error()).To(ContainSubstring("another process on this host holds the CA lock"))
			Expect(err.Error()).To(ContainSubstring(`"crl"`))

			Expect(held.Unlock()).To(Succeed())
		})

		It("grants the lock once the first holder releases it", func() {
			dir := GinkgoT().TempDir()
			first, second := NewFilesystemBackend(dir), NewFilesystemBackend(dir)

			held, err := first.AcquireSameHostLock(ctx, "crl")
			Expect(err).NotTo(HaveOccurred())
			Expect(held.Unlock()).To(Succeed())

			deadline, cancel := context.WithTimeout(ctx, contendedTimeout)
			defer cancel()
			again, err := second.AcquireSameHostLock(deadline, "crl")
			Expect(err).NotTo(HaveOccurred())
			Expect(again.Unlock()).To(Succeed())
		})

		It("does not make distinct lock names contend", func() {
			dir := GinkgoT().TempDir()
			first, second := NewFilesystemBackend(dir), NewFilesystemBackend(dir)

			held, err := first.AcquireSameHostLock(ctx, "subject:node1.test")
			Expect(err).NotTo(HaveOccurred())

			deadline, cancel := context.WithTimeout(ctx, contendedTimeout)
			defer cancel()
			other, err := second.AcquireSameHostLock(deadline, "subject:node2.test")
			Expect(err).NotTo(HaveOccurred(), "distinct names must not contend")

			Expect(other.Unlock()).To(Succeed())
			Expect(held.Unlock()).To(Succeed())
		})

		It("keeps lock files inside the lock directory, whatever the name", func() {
			// ValidateSubject runs before a subject reaches a lock name, so this
			// is defence in depth rather than the only barrier -- but the whole
			// reason the mapping hashes is that no name should be able to
			// address a path, and a test is cheaper than trusting that twice.
			dir := GinkgoT().TempDir()
			b := NewFilesystemBackend(dir)

			for _, name := range []string{"crl", "subject:../../etc/shadow", "subject:a/b", strings.Repeat("x", 512)} {
				ul, err := b.AcquireSameHostLock(ctx, name)
				Expect(err).NotTo(HaveOccurred(), "acquiring %q", name)
				Expect(ul.Unlock()).To(Succeed())
			}

			// The literal, not the constant: the directory half of the path is
			// protocol for the same reason the file half is, and
			// docs/storage-backends.md publishes it in the on-disk layout. Every
			// other reference here goes through fsLockDir, so a rename would
			// otherwise keep the suite green.
			Expect(fsLockDir).To(Equal("locks"))

			entries, err := os.ReadDir(filepath.Join(dir, "locks"))
			Expect(err).NotTo(HaveOccurred())
			Expect(entries).To(HaveLen(4), "one file per distinct lock name, all inside the lock directory")
			for _, e := range entries {
				Expect(e.Name()).To(HaveSuffix(".lock"))
				Expect(e.Name()).To(HaveLen(64+len(".lock")), "a sha256 hex digest, not the name itself")

				info, err := e.Info()
				Expect(err).NotTo(HaveOccurred())
				Expect(info.Mode().Perm()).To(Equal(os.FileMode(FilePermPrivate)),
					"docs/storage-backends.md documents these as 0600")
			}
		})

		DescribeTable("maps a lock name to a fixed file name",
			// The mapping is cross-release protocol: a server and a `ctl`
			// command exclude each other only by deriving the same file from the
			// same name, so an upgrade that changed it would silently stop the
			// two coordinating — the exact double-write this change prevents,
			// with a green suite. Asserting the shape (64 hex characters) does
			// not pin that; a different digest, a salt, or hashing name+"\n"
			// all keep the shape. These literals are the pin. Regenerate them
			// only alongside a deliberate compatibility story.
			func(name, want string) {
				Expect(fileLockFileName(name)).To(Equal(want))
			},
			Entry("crl", "crl",
				"861aaa0731bdaea1fa598d1750466ef6210c4a1cc1e39d3ea4f3ee4f1bc9e5a2.lock"),
			Entry("bootstrap", "bootstrap",
				"333c04dd151a2a6831c039cb9a651df29198be8a04e16ce861d4b6a34a11c954.lock"),
			Entry("a subject lock", "subject:node1.test",
				"3d5323adb88053356f4fe3797846b0268d1b0fef11f5205e248e6435475201ab.lock"),
		)

		It("resolves the same lock directory from equivalent spellings of the root", func() {
			// Two processes are given the same store as differently written
			// configuration. They exclude each other only if both land on the
			// same file.
			dir := GinkgoT().TempDir()
			plain := NewFilesystemBackend(dir)
			awkward := NewFilesystemBackend(filepath.Join(dir, "signed", ".."))

			held, err := plain.AcquireSameHostLock(ctx, "bootstrap")
			Expect(err).NotTo(HaveOccurred())

			deadline, cancel := context.WithTimeout(ctx, contendedTimeout)
			defer cancel()
			_, err = awkward.AcquireSameHostLock(deadline, "bootstrap")
			Expect(err).To(MatchError(context.DeadlineExceeded))

			Expect(held.Unlock()).To(Succeed())
		})

		It("stores the lock directory as an absolute path", func() {
			// The spec above is satisfied by filepath.Join's own cleaning and
			// would pass without any normalisation at all. This is the half that
			// needs asserting directly: a relative root is resolved once, at
			// construction, so it cannot mean two different directories to two
			// processes started from different working directories. Asserted on
			// the field rather than behaviourally because reproducing the
			// failure would mean chdir'ing the test process.
			Expect(filepath.IsAbs(newFileLocks(filepath.Join("relative", "cadir", "locks")).dir)).
				To(BeTrue(), "a relative lock directory must be resolved at construction")
		})

		// Each failing acquisition below re-attempts on the *same* backend value
		// afterwards. That second call is not redundant: `acquire` takes the
		// per-name mutex before it touches the filesystem and has to hand it
		// back on every error path by hand, and a missed `local.Unlock()` is
		// invisible to a spec that acquires once and discards the backend. The
		// consequence in production is not a slow lock but a permanent one —
		// sync.Mutex honours no context, so the process wedges on that lock name
		// for its lifetime after a single transient failure.
		expectRetryable := func(b *FilesystemBackend, name string) {
			GinkgoHelper()
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done)
				if ul, err := b.AcquireSameHostLock(ctx, name); err == nil {
					_ = ul.Unlock()
				}
			}()
			Eventually(done, 5*time.Second).Should(BeClosed(),
				"the failed acquisition leaked its per-name mutex: this lock name is now wedged for the process's lifetime")
		}

		It("reports the lock unsupported rather than failing on a read-only store", func() {
			// `openvox-ca-ctl migrate` takes the bootstrap lock on a source it
			// only reads, and that source may be a read-only snapshot. A store
			// nothing can write to has no writer to exclude, so the capability
			// is absent rather than broken.
			if os.Geteuid() == 0 {
				Skip("root ignores the directory mode this case depends on")
			}
			dir := GinkgoT().TempDir()
			Expect(os.Chmod(dir, 0500)).To(Succeed())
			DeferCleanup(func() { _ = os.Chmod(dir, 0700) })

			b := NewFilesystemBackend(dir)
			_, err := b.AcquireSameHostLock(ctx, "bootstrap")
			Expect(err).To(MatchError(ErrSameHostLockingUnsupported))
			expectRetryable(b, "bootstrap")
		})

		It("reports a genuine filesystem failure rather than hiding it", func() {
			// The complement of the case above: if the lock cannot be taken for
			// any reason other than "nothing here is writable", whether another
			// process is mutating the store is unknown, and silently proceeding
			// would be the corruption this change exists to prevent. A plain
			// file where the lock directory belongs stands in for that class.
			dir := GinkgoT().TempDir()
			Expect(os.WriteFile(filepath.Join(dir, fsLockDir), []byte("not a directory"), 0600)).To(Succeed())

			b := NewFilesystemBackend(dir)
			_, err := b.AcquireSameHostLock(ctx, "bootstrap")
			Expect(err).To(HaveOccurred())
			Expect(err).NotTo(MatchError(ErrSameHostLockingUnsupported))
			Expect(err.Error()).To(ContainSubstring("same-host lock"))
			expectRetryable(b, "bootstrap")
		})

		DescribeTable("reports the capability absent on a read-only filesystem",
			// EROFS degrades at *both* call sites, and the reasoning differs
			// from the permission case beside it: EROFS says nothing about
			// ownership, and a store nothing can write has no writer to
			// exclude. The documented case is `openvox-ca-ctl migrate` reading a
			// source on a read-only snapshot whose lock directory already
			// exists, so MkdirAll succeeds and the open is what fails. Neither
			// arm is reachable from a temp directory, so the classifiers are
			// called directly -- this file is package storage.
			func(classify func(*fileLocks, error) error) {
				l := newFileLocks(GinkgoT().TempDir())
				err := classify(l, &fs.PathError{Op: "open", Path: "x", Err: syscall.EROFS})
				Expect(err).To(MatchError(ErrSameHostLockingUnsupported))
			},
			Entry("creating the lock directory", func(l *fileLocks, err error) error {
				return l.unwritableStore(err, "creating same-host lock directory")
			}),
			Entry("opening a lock file in a directory that already exists", func(l *fileLocks, err error) error {
				return l.inaccessibleLockFile(err, "x.lock")
			}),
		)

		It("fails loudly when the lock directory belongs to another user", func() {
			// The distinction the two specs above turn on. os.MkdirAll returns
			// nil for a directory that already exists without checking whether
			// it can be written, so a permission error at the *file* is not
			// evidence the store is read-only — it is evidence the lock
			// directory belongs to someone else, which is what an
			// `openvox-ca-ctl` run under sudo leaves behind for a server running
			// as puppet-ca. Downgrading there would return that server to its
			// pre-#187 behaviour permanently and silently, while the root
			// process went on taking flocks it believed were exclusive.
			if os.Geteuid() == 0 {
				Skip("root ignores the directory mode this case depends on")
			}
			dir := GinkgoT().TempDir()
			locks := filepath.Join(dir, fsLockDir)
			Expect(os.MkdirAll(locks, DirPerm)).To(Succeed())
			Expect(os.Chmod(locks, 0500)).To(Succeed())
			DeferCleanup(func() { _ = os.Chmod(locks, 0700) })

			b := NewFilesystemBackend(dir)
			_, err := b.AcquireSameHostLock(ctx, "bootstrap")
			Expect(err).To(HaveOccurred())
			Expect(err).NotTo(MatchError(ErrSameHostLockingUnsupported),
				"an unwritable lock directory that already exists is not a read-only store")
			Expect(err.Error()).To(ContainSubstring("chown"),
				"the error must tell the operator how to fix it")
			Expect(err.Error()).To(ContainSubstring("the lock directory "+locks+" is owned by uid"),
				"and must diagnose the directory, which is the thing to chown here")
			expectRetryable(b, "bootstrap")
		})

		It("blames the lock file, not its directory, when the file is the obstruction", func() {
			// The other half of the same scenario, and the likelier one: a `ctl`
			// command run under sudo against a cadir that already has a lock
			// directory creates a root-owned *file* inside a directory the
			// server owns perfectly well. An error blaming the directory sends
			// the operator to chown something that is already correct.
			if os.Geteuid() == 0 {
				Skip("root ignores the file mode this case depends on")
			}
			dir := GinkgoT().TempDir()
			locks := filepath.Join(dir, fsLockDir)
			Expect(os.MkdirAll(locks, DirPerm)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(locks, fileLockFileName("crl")), nil, 0000)).To(Succeed())

			b := NewFilesystemBackend(dir)
			_, err := b.AcquireSameHostLock(ctx, "crl")
			Expect(err).To(HaveOccurred())
			Expect(err).NotTo(MatchError(ErrSameHostLockingUnsupported))
			Expect(err.Error()).To(ContainSubstring("the lock file is owned by uid"))
			// The remedy sentence mentions the lock directory legitimately, so
			// the negative has to target the *diagnosis* clause, which names a
			// path: "the lock directory <path> is owned by uid N".
			Expect(err.Error()).NotTo(ContainSubstring("the lock directory "+locks),
				"the directory is fine; diagnosing it would send the operator to the wrong place")
			expectRetryable(b, "crl")
		})

		DescribeTable("reports the capability absent when the filesystem cannot lock at all",
			// A store on a mount that rejects BSD locks, or a kernel out of lock
			// records, is the runtime form of a platform without flock(2), and
			// gets the same answer: warn, report absent, let WithLock fall
			// through to the mutex. Failing hard instead would break bootstrap,
			// signing, revocation and CRL refresh on a store that worked before
			// this tier existed — a whole-CA outage introduced by a lock nobody
			// asked that filesystem to take.
			func(errno error) {
				orig := tryLock
				tryLock = func(*os.File) (bool, error) { return false, errno }
				DeferCleanup(func() { tryLock = orig })

				b := NewFilesystemBackend(GinkgoT().TempDir())
				_, err := b.AcquireSameHostLock(ctx, "crl")
				Expect(err).To(MatchError(ErrSameHostLockingUnsupported))

				// And the tier being absent must not wedge the next caller.
				expectRetryable(b, "crl")
			},
			Entry("ENOLCK, the kernel is out of lock records", syscall.ENOLCK),
			Entry("EOPNOTSUPP, the filesystem rejects BSD locks", syscall.EOPNOTSUPP),
			Entry("ENOSYS, the call is unimplemented", syscall.ENOSYS),
		)

		It("still fails hard on an flock error it cannot classify", func() {
			// The complement: an errno that is not "this filesystem cannot
			// lock" leaves it unknown whether another process is writing, and
			// proceeding on that is the corruption this tier exists to prevent.
			orig := tryLock
			tryLock = func(*os.File) (bool, error) { return false, syscall.EIO }
			DeferCleanup(func() { tryLock = orig })

			b := NewFilesystemBackend(GinkgoT().TempDir())
			_, err := b.AcquireSameHostLock(ctx, "crl")
			Expect(err).To(MatchError(syscall.EIO))
			Expect(err).NotTo(MatchError(ErrSameHostLockingUnsupported))
			expectRetryable(b, "crl")
		})

		It("grants an uncontended lock even to a caller whose deadline has gone", func() {
			// ctx bounds the wait for another process, not the acquisition, so
			// this matches the process-local mutex the tier replaces: that
			// mutex honours no deadline either, and a caller arriving with a
			// spent one still enters its critical section and fails on its own
			// first storage read.
			//
			// The distinction is not cosmetic. Revoke counts a failure that
			// reached the CRL work and does not count one refused at lock
			// acquisition (docs/metrics.md, and the alert built on it), so
			// rejecting here would move the filesystem and SQLite backends from
			// one side of that split to the other without anyone asking.
			spent, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
			defer cancel()

			ul, err := NewFilesystemBackend(GinkgoT().TempDir()).AcquireSameHostLock(spent, "crl")
			Expect(err).NotTo(HaveOccurred())
			Expect(ul.Unlock()).To(Succeed())
		})

		It("gives up at once when the lock is held and the deadline has gone", func() {
			// The other half: waiting is what ctx bounds, and a spent deadline
			// buys no wait at all.
			dir := GinkgoT().TempDir()
			held, err := NewFilesystemBackend(dir).AcquireSameHostLock(ctx, "crl")
			Expect(err).NotTo(HaveOccurred())
			// Released explicitly below rather than in a cleanup: Unlocker's
			// contract is exactly-once, and a second call unlocks an unlocked
			// mutex, which is fatal rather than merely wrong.

			cancelled, cancel := context.WithCancel(ctx)
			cancel()

			waiter := NewFilesystemBackend(dir)
			start := time.Now()
			_, err = waiter.AcquireSameHostLock(cancelled, "crl")
			Expect(err).To(MatchError(context.Canceled))
			Expect(time.Since(start)).To(BeNumerically("<", contendedTimeout))

			Expect(held.Unlock()).To(Succeed())
			expectRetryable(waiter, "crl")
		})

		It("announces a wait once, naming the lock file", func() {
			// docs/storage-backends.md promises operators this line, and it is
			// the only thing that distinguishes an `openvox-ca-ctl migrate`
			// waiting on a lock — with no deadline at all — from one that has
			// hung. Nothing else asserts it exists, so a refactor could drop it
			// silently and leave that command mute.
			dir := GinkgoT().TempDir()
			holder, waiter := NewFilesystemBackend(dir), NewFilesystemBackend(dir)

			held, err := holder.AcquireSameHostLock(ctx, "crl")
			Expect(err).NotTo(HaveOccurred())

			var buf bytes.Buffer
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
			defer slog.SetDefault(orig)

			deadline, cancel := context.WithTimeout(ctx, contendedTimeout)
			defer cancel()
			_, err = waiter.AcquireSameHostLock(deadline, "crl")
			Expect(err).To(HaveOccurred())
			Expect(held.Unlock()).To(Succeed())

			// Once, not once per retry: the wait above runs several attempts.
			Expect(strings.Count(buf.String(), "Waiting for the CA lock")).To(Equal(1))
			Expect(buf.String()).To(ContainSubstring(fileLockFileName("crl")),
				"the line must name the lock file, so the operator can find the holder")
		})

		It("picks up a release promptly however long it has been waiting", func() {
			// The backoff doubles, and without its ceiling a waiter under the
			// production 60s lockTimeout reaches a ~40s sleep: a lock released
			// at 25s would not be noticed until past 40s, so a revocation that
			// should have succeeded fails at its deadline instead. Every other
			// contended spec here gives up well before the doubling saturates,
			// so none of them would notice the ceiling going missing.
			//
			// The hold has to outlast a specific un-ceilinged attempt, not just
			// saturation. Doubling from 5ms puts attempts at 635, 1275, 2555 and
			// 5115ms; releasing at ~2600ms means a waiter without the ceiling
			// would not look again until 5115ms — 2.5s late against the 1s bound
			// below — while the ceilinged path hands off within one 250ms poll.
			// Releasing at 1500ms instead leaves only 55ms between the two, which
			// a loaded -race runner can eat.
			dir := GinkgoT().TempDir()
			holder, waiter := NewFilesystemBackend(dir), NewFilesystemBackend(dir)

			held, err := holder.AcquireSameHostLock(ctx, "crl")
			Expect(err).NotTo(HaveOccurred())

			acquired := make(chan time.Duration, 1)
			go func() {
				defer GinkgoRecover()
				attempt, cancel := context.WithTimeout(ctx, 30*time.Second)
				defer cancel()
				start := time.Now()
				ul, err := waiter.AcquireSameHostLock(attempt, "crl")
				Expect(err).NotTo(HaveOccurred())
				acquired <- time.Since(start)
				Expect(ul.Unlock()).To(Succeed())
			}()

			// Long enough that the backoff has saturated at its ceiling.
			time.Sleep(2600 * time.Millisecond)
			releasedAt := time.Now()
			Expect(held.Unlock()).To(Succeed())

			var waited time.Duration
			Eventually(acquired, 15*time.Second).Should(Receive(&waited))
			// 4x the ceiling, not 2x: the worst legitimate case is a release
			// landing just after a failed attempt (one full interval), plus
			// Eventually's polling granularity and two goroutine wakeups under
			// -race on a loaded runner. The mutation this kills — the ceiling
			// removed — is not noticed until ~1s after the release, so the
			// headroom costs nothing.
			Expect(time.Since(releasedAt)).To(BeNumerically("<", 4*fileLockRetryMax),
				"the waiter must notice the release within a capped poll interval, not after an unbounded doubling")
			Expect(waited).To(BeNumerically(">", 2*time.Second), "sanity: it really did wait")
		})
	})

	Describe("the SQLite backend", func() {
		It("excludes a second connection to the same database file", func() {
			dsn := "file:" + filepath.Join(GinkgoT().TempDir(), "ca.db")
			first, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: dsn})
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = first.Close() })
			second, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: dsn})
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = second.Close() })

			held, err := first.AcquireSameHostLock(ctx, "bootstrap")
			Expect(err).NotTo(HaveOccurred())

			deadline, cancel := context.WithTimeout(ctx, contendedTimeout)
			defer cancel()
			_, err = second.AcquireSameHostLock(deadline, "bootstrap")
			Expect(err).To(MatchError(context.DeadlineExceeded))

			Expect(held.Unlock()).To(Succeed())
		})

		It("puts its lock files beside the database, not inside it", func() {
			dir := GinkgoT().TempDir()
			dbPath := filepath.Join(dir, "ca.db")
			b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: "file:" + dbPath})
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = b.Close() })
			Expect(b.EnsureReady(ctx)).To(Succeed(), "so there is a database file to sit beside")

			ul, err := b.AcquireSameHostLock(ctx, "crl")
			Expect(err).NotTo(HaveOccurred())
			Expect(ul.Unlock()).To(Succeed())

			names := []string{}
			entries, err := os.ReadDir(filepath.Join(dir, ".ca.db.locks"))
			Expect(err).NotTo(HaveOccurred(), "lock directory beside the database file")
			for _, e := range entries {
				names = append(names, e.Name())
			}
			// EnsureReady took the schema-migration lock through the same tier,
			// so its file is here too — which is the point of that path.
			Expect(names).To(ContainElements(
				fileLockFileName("crl"), fileLockFileName(lockNameSQLMigrate)))

			// The database file itself is never the lock: SQLite locks it, and a
			// second scheme over the same file would leave two answers to
			// "is this database busy".
			info, err := os.Stat(dbPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(info.IsDir()).To(BeFalse())
		})

		It("serialises schema migrations across separate backends on one file", func() {
			// The property the change actually adds. sql_migrations_test.go
			// already races four EnsureReady calls on *one* backend, but those
			// share a per-name mutex, so it passed before this change and passes
			// with the same-host tier deleted. Four separate backends over one
			// DSN share no mutex and meet only at the flock — the in-process
			// stand-in for four starting processes — so this is what fails if
			// the lock is not held across the whole migration.
			dsn := "file:" + filepath.Join(GinkgoT().TempDir(), "ca.db")

			// Seed the database first, then rewind the migration ledger. Racing
			// four backends at a file that does not exist yet races their
			// `PRAGMA journal_mode=WAL` instead, which is not what this pins and
			// which fails SQLITE_BUSY about one run in four regardless of
			// busy_timeout, since a journal-mode change needs an exclusive lock.
			// Rewinding leaves every migration pending against a database that
			// is already there and already in WAL, so the four runners meet at
			// the DDL — and at the lock that is supposed to serialise it.
			seed, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: dsn})
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = seed.Close() })
			Expect(seed.EnsureReady(ctx)).To(Succeed())
			_, err = seed.db.ExecContext(ctx, "DELETE FROM bun_migrations")
			Expect(err).NotTo(HaveOccurred())

			const runners = 4
			backends := make([]*SQLBackend, runners)
			for i := range backends {
				b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: dsn})
				Expect(err).NotTo(HaveOccurred())
				backends[i] = b
				DeferCleanup(func() { _ = b.Close() })
			}

			// Bounded for the same reason as the migration below: these four
			// carry the production budget, and a regression in lock release
			// would wedge three of them until it expired. Being the concurrent
			// one, this spec is the likelier of the two to meet that first.
			ready, cancelReady := context.WithTimeout(ctx, specPatience)
			defer cancelReady()

			errs := make([]error, runners)
			var wg sync.WaitGroup
			wg.Add(runners)
			for i := range runners {
				go func() {
					defer GinkgoRecover()
					defer wg.Done()
					errs[i] = backends[i].EnsureReady(ready)
				}()
			}
			wg.Wait()
			for i, err := range errs {
				Expect(err).NotTo(HaveOccurred(), "runner %d", i)
			}

			// One row per migration: two runners that both recorded a version
			// and ran the DDL is exactly the corruption the lock prevents.
			expectOneRowPerMigration(ctx, backends[0])
		})

		It("refuses a schema migration while another holder has the lock", func() {
			// The complement, and the operator-visible half: a startup that
			// cannot get the migration lock must say so rather than proceed.
			// (That the lock is *held* across the migration is the spec above;
			// this one pins that EnsureReady takes it at all, and the message it
			// fails with.)
			dsn := "file:" + filepath.Join(GinkgoT().TempDir(), "ca.db")
			holder, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: dsn})
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = holder.Close() })

			held, err := holder.AcquireSameHostLock(ctx, lockNameSQLMigrate)
			Expect(err).NotTo(HaveOccurred())

			// A short migration budget so the refusal arrives inside the spec
			// rather than after the default ten minutes.
			second, err := NewSQLBackend(SQLConfig{
				Dialect: SQLitePure, DSN: dsn, MigrationTimeout: contendedTimeout,
			})
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = second.Close() })

			// The refusal's own premise, pinned for the same reason as the reset
			// below. Without this the guard is one-directional: moving the reset
			// above this line would put the production budget on the refusal,
			// which waits its budget out -- and ten minutes is also the binary
			// timeout, so the likely surface is the package-wide panic rather
			// than a slow pass. This fails in microseconds instead, and says so.
			Expect(second.migrationTimeout).To(Equal(contendedTimeout),
				"the refusal below must run under the contended budget")

			err = second.EnsureReady(ctx)
			Expect(err).To(HaveOccurred(), "a second starter must not migrate under a held lock")
			Expect(err.Error()).To(ContainSubstring("another process on this host may be migrating"),
				"and the error must say why, since this is a startup failure an operator sees")

			// Released, it proceeds — so the refusal was the lock, not the DSN.
			// It has to be this same backend that proceeds: a fresh one would
			// only show the DSN is migratable, not that what stopped *this* one
			// was the lock. But the budget it still carries was sized for the
			// refusal above, and what follows is a genuine schema migration, so
			// hand it the production budget for that.
			second.migrationTimeout = sqlMigrationTimeout

			Expect(held.Unlock()).To(Succeed())

			// Asserted, not merely assigned. Deleting the line above would put a
			// 750ms deadline back on a migration measured at 1.508s under -race,
			// and the spec would go back to failing on whichever loaded runner
			// picked it up — in test:unit, or in any of the four backend jobs,
			// four of which this SQLite spec has nothing otherwise to do with
			// (#298). Failing here instead costs nothing and names the reason.
			//
			// This is a deletion tripwire, not an invariant of the code under
			// test: nothing in production can move the field between the line
			// above and this one. That is what it is for; the refusal-side
			// assertion above is the one that exercises real plumbing, running
			// SQLConfig through applyDefaults into the field. Timing the
			// migration instead would buy nothing: the ready context below
			// already bounds that same window, so an elapsed-time assertion
			// could only fire where the deadline has already cancelled -- no
			// detection gained, and a clock on the success path is what #298
			// was about.
			Expect(second.migrationTimeout).To(Equal(sqlMigrationTimeout),
				"the migration below must not run under the contended budget")

			// The budget is the production one; how long this spec will wait for
			// it is a different question, so it is asked here rather than by
			// shrinking the budget. EnsureReady derives its deadline from this
			// ctx (context.WithTimeout on the caller's), so the shorter of the
			// two wins and a wedged lock fails here, naming this spec, instead
			// of as an unattributed package timeout ten minutes later.
			ready, cancelReady := context.WithTimeout(ctx, specPatience)
			defer cancelReady()
			Expect(second.EnsureReady(ready)).To(Succeed())
		})

		It("still migrates an in-memory database, which has no same-host lock", func() {
			// EnsureReady's ladder has three arms and this is the one nothing
			// else reaches: the same-host lock reports itself unsupported, and
			// the process-local mutex has to carry it. Folding this arm into the
			// `default:` beside it — they switch on the same error — would make
			// every in-memory start fail outright, and the rest of the suite
			// would stay green, since nothing else calls EnsureReady on a
			// backend without a lock set.
			b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: ":memory:"})
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = b.Close() })

			_, lockErr := b.AcquireSameHostLock(ctx, lockNameSQLMigrate)
			Expect(lockErr).To(MatchError(ErrSameHostLockingUnsupported),
				"precondition: this backend has no same-host lock")

			Expect(b.EnsureReady(ctx)).To(Succeed(),
				"an unavailable same-host lock must degrade to the mutex, not refuse the migration")
		})

		It("reports the lock unsupported for an in-memory database", func() {
			// Nothing outside this process can open it, so there is nothing to
			// exclude and no file to sit beside. WithLock then uses the
			// process-local mutex, which is the whole of the guarantee available.
			for _, dsn := range []string{":memory:", "file::memory:", "file:x?mode=memory&cache=shared"} {
				b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: dsn})
				Expect(err).NotTo(HaveOccurred(), "opening %q", dsn)

				_, err = b.AcquireSameHostLock(ctx, "crl")
				Expect(err).To(MatchError(ErrSameHostLockingUnsupported), "dsn %q", dsn)
				Expect(b.Close()).To(Succeed())
			}
		})

		DescribeTable("derives the database path from a DSN",
			func(dsn, wantPath string, wantOK bool) {
				got, ok := sqliteFilePath(dsn)
				Expect(ok).To(Equal(wantOK), "dsn %q", dsn)
				if wantOK {
					Expect(got).To(Equal(wantPath), "dsn %q", dsn)
				}
			},
			Entry("bare absolute path", "/var/lib/puppet-ca/ca.db", "/var/lib/puppet-ca/ca.db", true),
			Entry("bare relative path", "ca.db", "ca.db", true),
			Entry("bare path with parameters", "/var/lib/ca.db?_txlock=immediate", "/var/lib/ca.db", true),
			Entry("file URI, absolute", "file:/var/lib/ca.db", "/var/lib/ca.db", true),
			Entry("file URI, absolute with empty authority", "file:///var/lib/ca.db", "/var/lib/ca.db", true),
			Entry("file URI, relative", "file:ca.db", "ca.db", true),
			Entry("file URI with parameters", "file:/var/lib/ca.db?_pragma=busy_timeout(5000)", "/var/lib/ca.db", true),
			Entry("in-memory, bare", ":memory:", "", false),
			Entry("in-memory, URI", "file::memory:", "", false),
			Entry("in-memory, mode parameter", "file:anything?mode=memory", "", false),
			Entry("empty", "", "", false),
		)
	})

	Describe("the overlay backend", func() {
		It("delegates the same-host lock to its base", func() {
			// The overlay serves local CA material but the store it protects is
			// the base's, so two servers sharing a cadir must still exclude each
			// other through it.
			dir := GinkgoT().TempDir()
			certFile := filepath.Join(GinkgoT().TempDir(), "ca_crt.pem")
			Expect(os.WriteFile(certFile, []byte("cert"), 0600)).To(Succeed())

			overlayOver := func() *OverlayBackend {
				o, err := NewOverlayBackend(NewFilesystemBackend(dir), map[string]string{KeyCACert: certFile})
				Expect(err).NotTo(HaveOccurred())
				return o
			}
			first, second := overlayOver(), overlayOver()

			held, err := first.AcquireSameHostLock(ctx, "crl")
			Expect(err).NotTo(HaveOccurred())

			deadline, cancel := context.WithTimeout(ctx, contendedTimeout)
			defer cancel()
			_, err = second.AcquireSameHostLock(deadline, "crl")
			Expect(err).To(MatchError(context.DeadlineExceeded))

			Expect(held.Unlock()).To(Succeed())
		})

		It("reports the lock unsupported when the base offers neither tier", func() {
			o, err := NewOverlayBackend(&noLockBackend{}, map[string]string{KeyCACert: "/dev/null"})
			Expect(err).NotTo(HaveOccurred())

			_, err = o.AcquireSameHostLock(ctx, "crl")
			Expect(err).To(MatchError(ErrSameHostLockingUnsupported))
		})
	})

	Describe("WithLock", func() {
		It("takes the same-host lock on the filesystem backend", func() {
			// The tier is reached, not merely implemented: a second service over
			// the same cadir cannot enter the critical section while the first
			// is inside it. Before this change both proceeded at once.
			dir := GinkgoT().TempDir()
			first, second := svc(NewFilesystemBackend(dir)), svc(NewFilesystemBackend(dir))

			inside := make(chan struct{})
			release := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				done <- first.WithLock(ctx, "crl", func() error {
					close(inside)
					<-release
					return nil
				})
			}()
			<-inside

			deadline, cancel := context.WithTimeout(ctx, contendedTimeout)
			defer cancel()
			err := second.WithLock(deadline, "crl", func() error {
				Fail("the second service entered a critical section the first was holding")
				return nil
			})
			Expect(err).To(MatchError(context.DeadlineExceeded))
			Expect(err.Error()).To(ContainSubstring("acquiring same-host lock"))

			close(release)
			Expect(<-done).To(Succeed())
		})

		It("falls back to the process-local mutex when no tier is available", func() {
			// A backend with neither capability must behave exactly as it did
			// before same-host locking existed: fn runs, serialised in-process.
			s := svc(&noLockBackend{})
			Expect(s.WithLock(ctx, "crl", func() error { return nil })).To(Succeed())
		})

		It("releases the same-host lock when fn panics", func() {
			// withlock_test.go pins this for tier 1 only — its stub embeds the
			// Backend interface, so it never reaches tier 2. The consequence
			// here is worse than there: net/http recovers a panicking handler,
			// so a leaked fileUnlocker holds both the per-name mutex and the
			// kernel flock for the life of the process, wedging that lock name
			// for every process on the host rather than just this one.
			dir := GinkgoT().TempDir()
			s := svc(NewFilesystemBackend(dir))

			func() {
				defer func() { Expect(recover()).NotTo(BeNil(), "the panic must propagate") }()
				_ = s.WithLock(ctx, "crl", func() error { panic("boom") })
			}()

			deadline, cancel := context.WithTimeout(ctx, contendedTimeout)
			defer cancel()
			ul, err := NewFilesystemBackend(dir).AcquireSameHostLock(deadline, "crl")
			Expect(err).NotTo(HaveOccurred(),
				"the flock outlived the panic: it is now held for the life of this process")
			Expect(ul.Unlock()).To(Succeed())
		})

		It("prefers the distributed lock when the backend offers both", func() {
			// The tier order is the whole of the "two distinct capabilities"
			// argument: a backend that can coordinate across hosts must be
			// locked that way, not settled for the weaker one.
			//
			// bothLocker embeds the *concrete* filesystem backend rather than
			// the Backend interface, and that is load-bearing. Embedding the
			// interface promotes only the interface's own methods, and
			// AcquireSameHostLock is not among them — so a stub built that way
			// does not satisfy SameHostLocker at all, and this spec would pass
			// with the tiers reversed, or with tier 2 deleted outright.
			dir := GinkgoT().TempDir()
			both := &bothLocker{FilesystemBackend: NewFilesystemBackend(dir)}

			var asSameHost any = both
			_, ok := asSameHost.(SameHostLocker)
			Expect(ok).To(BeTrue(), "precondition: this backend really does offer both tiers")

			Expect(svc(both).WithLock(ctx, "crl", func() error { return nil })).To(Succeed())
			Expect(both.distributedCalls).To(Equal(1), "the distributed lock must be the one taken")

			// And the same-host tier was not reached: it would have left its
			// directory behind.
			_, err := os.Stat(filepath.Join(dir, fsLockDir))
			Expect(errors.Is(err, os.ErrNotExist)).To(BeTrue(),
				"the same-host tier must not run when a distributed lock succeeded")
		})
	})

	Describe("across real processes", func() {
		It("excludes a real second process", func() {
			// Everything above proves flock's open-file-description semantics.
			// This proves the claim the issue actually makes -- that a `ctl`
			// command cannot write behind a running server's back -- by
			// re-executing this test binary as a second process and asking it to
			// hold the lock.
			if !fileLockingSupported {
				Skip("no flock(2) on " + runtime.GOOS)
			}
			dir := GinkgoT().TempDir()

			// startLockHelper registers its own cleanup.
			helper := startLockHelper(dir, "crl")

			deadline, cancel := context.WithTimeout(ctx, contendedTimeout)
			defer cancel()
			err := svc(NewFilesystemBackend(dir)).WithLock(deadline, "crl", func() error {
				Fail("this process took a lock another process was holding")
				return nil
			})
			Expect(err).To(MatchError(context.DeadlineExceeded))
			Expect(err.Error()).To(ContainSubstring("another process on this host holds the CA lock"))

			// And the lock is genuinely released when that process dies, with no
			// cleanup by anyone: SIGKILL, so the helper never reaches its own
			// Unlock and the kernel is the only thing that can drop it. Stopping
			// it politely instead would prove nothing here — the orderly release
			// would explain the result just as well — and this is the property
			// the whole flock-over-lockfile choice rests on.
			helper.kill()
			Eventually(func() error {
				attempt, cancel := context.WithTimeout(ctx, contendedTimeout)
				defer cancel()
				return svc(NewFilesystemBackend(dir)).WithLock(attempt, "crl", func() error { return nil })
			}, 5*time.Second, 50*time.Millisecond).Should(Succeed())
		})
	})
})

// noLockBackend implements neither Locker nor SameHostLocker, standing in for a
// backend that can only be serialised in-process. The embedded nil Backend is
// never called: every spec using it stops at the capability probe.
type noLockBackend struct{ Backend }

// bothLocker offers both locking capabilities: a working same-host lock from the
// embedded concrete filesystem backend, and a distributed one of its own. It
// exists to pin WithLock's tier order, which no real backend can currently
// exercise — the two that implement SameHostLocker are precisely the two that
// have no distributed lock.
//
// The concrete type is embedded deliberately. An embedded *interface* promotes
// only that interface's method set, so a stub built over Backend would silently
// fail to satisfy SameHostLocker and make the ordering assertion vacuous.
type bothLocker struct {
	*FilesystemBackend
	distributedCalls int
}

func (b *bothLocker) AcquireLock(context.Context, string) (Unlocker, error) {
	b.distributedCalls++
	return noopUnlocker{}, nil
}

// noopUnlocker now lives in instancelock.go, where StorageService.AcquireInstanceLock
// returns one for every case in which the single-instance rule does not apply.
