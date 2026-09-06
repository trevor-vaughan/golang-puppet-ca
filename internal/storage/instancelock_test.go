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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The single-instance rule: a backend with distributed locking may run several
// instances, every other backend exactly one.
//
// As in filelock_test.go, two backend values over one store stand in for two
// processes, and for the same reason — flock(2) is held by an open file
// description, so two independent os.OpenFile calls exclude each other whether
// or not a fork separates them. One spec below uses a real second process
// anyway, because the holder's identity is the thing being asserted and a
// same-process stand-in would report the pid of the test itself.

var _ = Describe("Store instance lock", func() {
	var ctx context.Context

	BeforeEach(func() { ctx = context.Background() })

	svc := func(b Backend) *StorageService {
		return NewWithBackend(b, filepath.Join(GinkgoT().TempDir(), "private"))
	}

	// countLockFiles reports how many lock files exist under dir, which is how
	// the "no distributed locking" specs tell "took no lock" from "took one".
	countLockFiles := func(dir string) int {
		entries, err := os.ReadDir(dir)
		if errors.Is(err, os.ErrNotExist) {
			return 0
		}
		Expect(err).NotTo(HaveOccurred())
		n := 0
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".lock") {
				n++
			}
		}
		return n
	}

	Describe("a backend with no distributed locking", func() {
		It("admits the first instance and refuses the second", func() {
			cadir := GinkgoT().TempDir()

			first, err := svc(NewFilesystemBackend(cadir)).AcquireInstanceLock(ctx)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = first.Unlock() })

			_, err = svc(NewFilesystemBackend(cadir)).AcquireInstanceLock(ctx)
			Expect(err).To(HaveOccurred(), "a second instance must not be admitted")

			var locked *StoreLockedError
			Expect(errors.As(err, &locked)).To(BeTrue(),
				"the refusal must be a StoreLockedError, so callers can tell it from a lock that could not be taken")
		})

		It("admits a new instance once the first has released the store", func() {
			cadir := GinkgoT().TempDir()

			first, err := svc(NewFilesystemBackend(cadir)).AcquireInstanceLock(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(first.Unlock()).To(Succeed())

			second, err := svc(NewFilesystemBackend(cadir)).AcquireInstanceLock(ctx)
			Expect(err).NotTo(HaveOccurred(), "the store must not stay locked after the holder released it")
			Expect(second.Unlock()).To(Succeed())
		})

		It("names the process holding the store, rather than timing out", func() {
			cadir := GinkgoT().TempDir()
			helper := startLockHelper(cadir, instanceLockName)

			_, err := svc(NewFilesystemBackend(cadir)).AcquireInstanceLock(ctx)
			Expect(err).To(HaveOccurred())

			var locked *StoreLockedError
			Expect(errors.As(err, &locked)).To(BeTrue())

			// The identity, which is the half a lock timeout cannot give an
			// operator. Asserting the holder's real pid — and that it is not
			// this process's — is what distinguishes a recorded holder from a
			// message that merely looks like one.
			helperPID := helper.cmd.Process.Pid
			Expect(helperPID).NotTo(Equal(os.Getpid()), "precondition: the holder is a different process")
			Expect(locked.Holder).To(ContainSubstring("pid " + strconv.Itoa(helperPID)))
			Expect(locked.Error()).To(ContainSubstring("pid " + strconv.Itoa(helperPID)))
			Expect(locked.Path).To(BeARegularFile())

			// And the reason, so an operator is not left to infer it.
			Expect(locked.Error()).To(ContainSubstring("exactly one instance"))

			helper.stop()

			// The kernel drops the flock when the holder exits, so the store is
			// free with nothing to clean up.
			after, err := svc(NewFilesystemBackend(cadir)).AcquireInstanceLock(ctx)
			Expect(err).NotTo(HaveOccurred(), "the store must be free once the holding process has gone")
			Expect(after.Unlock()).To(Succeed())
		})

		It("refuses a second acquisition inside one process without deadlocking", func() {
			// flock(2) is per open file description, so without the TryLock in
			// acquireInstance this process would refuse itself and report its
			// own pid as the holder — true, and baffling.
			cadir := GinkgoT().TempDir()
			b := NewFilesystemBackend(cadir)

			first, err := svc(b).AcquireInstanceLock(ctx)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = first.Unlock() })

			_, err = b.AcquireInstanceLock()
			Expect(err).To(MatchError(ContainSubstring("this process already holds")))

			var locked *StoreLockedError
			Expect(errors.As(err, &locked)).To(BeFalse(),
				"our own second acquisition is a programming error, not another instance")
		})

		It("locks the SQLite store through the directory beside the database", func() {
			dsn := "file:" + filepath.Join(GinkgoT().TempDir(), "ca.db")
			open := func() *SQLBackend {
				b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: dsn})
				Expect(err).NotTo(HaveOccurred())
				DeferCleanup(func() { _ = b.Close() })
				return b
			}

			first, err := svc(open()).AcquireInstanceLock(ctx)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = first.Unlock() })

			// A second value over the same DSN is a second process, as above.
			second := open()

			_, err = svc(second).AcquireInstanceLock(ctx)
			var locked *StoreLockedError
			Expect(errors.As(err, &locked)).To(BeTrue(), "SQLite permits exactly one running instance")
		})

		It("locks the base store through an overlay", func() {
			// Without OverlayBackend.AcquireInstanceLock the type assertion in
			// AcquireInstanceLock finds no InstanceLocker and silently permits
			// the second instance — a wrong answer that looks like a working
			// one, since the call still succeeds.
			ov, cadir, _, _ := overlayTestSetup()

			first, err := svc(ov).AcquireInstanceLock(ctx)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = first.Unlock() })

			_, err = svc(NewFilesystemBackend(cadir)).AcquireInstanceLock(ctx)
			var locked *StoreLockedError
			Expect(errors.As(err, &locked)).To(BeTrue(),
				"an overlay must exclude a second instance on the store it wraps")
		})
	})

	Describe("a backend with distributed locking", func() {
		It("permits several instances and takes no store lock at all", func() {
			// The exemption this rule turns on. Multiple instances are a
			// designed-for configuration on the HA backends, so enforcement
			// must not merely tolerate them — it must not run.
			cadir := GinkgoT().TempDir()
			lockDir := filepath.Join(cadir, fsLockDir)

			// bothLocker embeds the concrete filesystem backend, so it also
			// promotes AcquireInstanceLock: this backend *could* take the
			// store-wide flock. If the capability gate were dropped it would,
			// and the second acquisition below would be refused.
			backend := func() Backend {
				return &bothLocker{FilesystemBackend: NewFilesystemBackend(cadir)}
			}

			first, err := svc(backend()).AcquireInstanceLock(ctx)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = first.Unlock() })

			second, err := svc(backend()).AcquireInstanceLock(ctx)
			Expect(err).NotTo(HaveOccurred(), "a backend that coordinates across processes may run many instances")
			DeferCleanup(func() { _ = second.Unlock() })

			Expect(countLockFiles(lockDir)).To(BeZero(),
				"a backend with distributed locking must not have a store-wide flock taken on it")
		})
	})

	Describe("when the rule cannot be enforced", func() {
		It("permits the instance when the capability probe fails", func() {
			// A probe error means a backend that does have distributed locking
			// is momentarily unreachable — the single-node backends answer
			// (false, nil) and never reach here. Refusing to start would be a
			// restriction on exactly the deployments this rule exempts.
			probeErr := errors.New("cluster unreachable")
			s := svc(&stubLocker{Backend: NewFilesystemBackend(GinkgoT().TempDir()), err: probeErr})

			_, err := s.SupportsDistributedLocking(ctx)
			Expect(err).To(MatchError(probeErr), "precondition: the probe fails for this backend")

			ul, err := s.AcquireInstanceLock(ctx)
			Expect(err).NotTo(HaveOccurred(), "an unreachable HA backend must not be refused startup")
			Expect(ul.Unlock()).To(Succeed())
		})

		It("permits the instance when the backend implements no InstanceLocker", func() {
			// A backend with neither distributed locking nor a store-wide lock
			// to offer. It is not broken -- it is one where the rule has to rest
			// on the operator -- so it must be permitted rather than refused,
			// and the caller must not read the nil error as "the lock was
			// taken".
			b := &plainBackend{Backend: NewFilesystemBackend(GinkgoT().TempDir())}

			var asInstanceLocker any = b
			_, isInstanceLocker := asInstanceLocker.(InstanceLocker)
			Expect(isInstanceLocker).To(BeFalse(), "precondition: this backend offers no store-wide lock")
			distributed, err := svc(b).SupportsDistributedLocking(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(distributed).To(BeFalse(), "precondition: and no distributed locking either")

			ul, err := svc(b).AcquireInstanceLock(ctx)
			Expect(err).NotTo(HaveOccurred(), "a backend that cannot offer the lock must not be refused startup")
			Expect(ul.Unlock()).To(Succeed())
		})

		It("permits the instance when the backend offers no store lock", func() {
			// An in-memory SQLite database is private to the process that
			// opened it, so there is no second instance for a lock to exclude
			// and nothing to lock beside.
			b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: ":memory:"})
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = b.Close() })

			_, err = b.AcquireInstanceLock()
			Expect(err).To(MatchError(ErrSameHostLockingUnsupported),
				"precondition: an in-memory database has no lock set")

			ul, err := svc(b).AcquireInstanceLock(ctx)
			Expect(err).NotTo(HaveOccurred(), "an unavailable lock must not be reported as a held one")
			Expect(ul.Unlock()).To(Succeed())
		})
	})

	Describe("the holder record", func() {
		It("describes this process without quoting its arguments", func() {
			record := instanceHolderRecord()

			Expect(record).To(ContainSubstring(fmt.Sprintf("pid %d", os.Getpid())))
			host, err := os.Hostname()
			Expect(err).NotTo(HaveOccurred())
			Expect(record).To(ContainSubstring(host))

			// A command line can carry a passphrase file path or another
			// operational detail, and this record is printed back in an error.
			for _, arg := range os.Args[1:] {
				if arg == "" {
					continue
				}
				Expect(record).NotTo(ContainSubstring(arg),
					"the record must name the binary only, never its arguments")
			}
			Expect(record).To(HaveLen(len(strings.TrimSpace(record))), "a record is one line")
		})

		It("replaces the previous holder's record rather than accumulating one per instance", func() {
			// The lock file outlives every process that holds it — fileUnlocker
			// deliberately never unlinks one — so an appended record would leave
			// a reader unable to tell which line is current.
			cadir := GinkgoT().TempDir()
			path := filepath.Join(cadir, fsLockDir, fileLockFileName(instanceLockName))

			for range 3 {
				ul, err := svc(NewFilesystemBackend(cadir)).AcquireInstanceLock(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(ul.Unlock()).To(Succeed())
			}

			body, err := os.ReadFile(path)
			Expect(err).NotTo(HaveOccurred())
			Expect(strings.TrimSpace(string(body))).NotTo(ContainSubstring("\n"))
			Expect(strings.Count(string(body), "pid ")).To(Equal(1))
		})

		It("still refuses when the holder's record is unreadable", func() {
			// A holder that was killed between taking the flock and writing its
			// record leaves an empty file. The refusal is what matters; the name
			// is what improves it.
			cadir := GinkgoT().TempDir()
			locks := newFileLocks(filepath.Join(cadir, fsLockDir))

			ul, err := locks.acquireInstance()
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = ul.Unlock() })

			path := filepath.Join(cadir, fsLockDir, fileLockFileName(instanceLockName))
			Expect(os.Truncate(path, 0)).To(Succeed())

			_, err = svc(NewFilesystemBackend(cadir)).AcquireInstanceLock(ctx)
			var locked *StoreLockedError
			Expect(errors.As(err, &locked)).To(BeTrue())
			Expect(locked.Holder).To(BeEmpty())
			Expect(locked.Error()).To(ContainSubstring("unidentified process"))
		})
	})

	Describe("a hostile holder record", func() {
		It("strips control characters and terminal escapes before reporting it", func() {
			// The record is read back out of a file and interpolated into an
			// error a terminal renders. The writer is another instance of this
			// program, but the file is only as trustworthy as the directory it
			// sits in -- and a store on a shared or misowned path is exactly the
			// case the permission handling in filelock.go exists for. An escape
			// sequence surviving to the terminal could rewrite what the operator
			// sees around it.
			cadir := GinkgoT().TempDir()
			locks := newFileLocks(filepath.Join(cadir, fsLockDir))

			ul, err := locks.acquireInstance()
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = ul.Unlock() })

			path := filepath.Join(cadir, fsLockDir, fileLockFileName(instanceLockName))
			hostile := "openvox-ca (pid 1)\x1b[2J\x1b[1;31m ALL CERTIFICATES REVOKED\x00\x07" +
				"\u202e detrever setacifitrec lla \u2066spoofed\u2069\u200b" +
				"\nnot-the-current-holder (pid 2)\n"
			Expect(os.WriteFile(path, []byte(hostile), FilePermPrivate)).To(Succeed())

			_, err = svc(NewFilesystemBackend(cadir)).AcquireInstanceLock(ctx)
			var locked *StoreLockedError
			Expect(errors.As(err, &locked)).To(BeTrue())

			Expect(locked.Holder).NotTo(BeEmpty(), "a sanitised record is still a record")
			Expect(locked.Holder).NotTo(ContainSubstring("\x1b"), "no terminal escapes")
			// Format characters reorder what a terminal draws around them
			// without being control characters, so a C0-and-DEL filter lets them
			// straight through.
			for _, bidi := range []string{"\u202e", "\u202d", "\u2066", "\u2067", "\u2068", "\u2069", "\u200b"} {
				Expect(locked.Holder).NotTo(ContainSubstring(bidi),
					"a Unicode format character survived the sanitiser")
			}
			Expect(locked.Holder).NotTo(ContainSubstring("\x00"), "no NUL")
			Expect(locked.Holder).NotTo(ContainSubstring("\x07"), "no BEL")
			for _, r := range locked.Holder {
				Expect(r).To(BeNumerically(">=", 0x20), "control character %q survived", r)
				Expect(r).NotTo(Equal(rune(0x7f)), "DEL survived")
			}

			// Only the first line, so a record cannot forge extra lines of
			// output around itself.
			Expect(locked.Holder).NotTo(ContainSubstring("not-the-current-holder"))
			Expect(locked.Error()).NotTo(ContainSubstring("\n"))
		})

		It("caps how much of the file it will report", func() {
			cadir := GinkgoT().TempDir()
			locks := newFileLocks(filepath.Join(cadir, fsLockDir))

			ul, err := locks.acquireInstance()
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = ul.Unlock() })

			path := filepath.Join(cadir, fsLockDir, fileLockFileName(instanceLockName))
			Expect(os.WriteFile(path, []byte(strings.Repeat("A", 64*1024)), FilePermPrivate)).To(Succeed())

			_, err = svc(NewFilesystemBackend(cadir)).AcquireInstanceLock(ctx)
			var locked *StoreLockedError
			Expect(errors.As(err, &locked)).To(BeTrue())
			Expect(len(locked.Holder)).To(BeNumerically("<=", instanceHolderLimit),
				"a lock file is not a licence to print 64KB into an operator's terminal")
		})
	})

	Describe("the capability probe's bound", func() {
		It("does not hang startup when the probe never answers", func() {
			// The bound lives inside AcquireInstanceLock rather than at its
			// callers precisely so no caller can forget it. Untested it is a
			// claim; this is the property: a backend whose AcquireLock blocks
			// for ever must cost the configured bound and then be permitted, not
			// hang the server that is starting.
			original := instanceProbeTimeout
			instanceProbeTimeout = 100 * time.Millisecond
			DeferCleanup(func() { instanceProbeTimeout = original })

			s := svc(&blockingLocker{Backend: NewFilesystemBackend(GinkgoT().TempDir())})

			done := make(chan error, 1)
			start := time.Now()
			go func() {
				ul, err := s.AcquireInstanceLock(context.Background())
				if err == nil {
					_ = ul.Unlock()
				}
				done <- err
			}()

			var err error
			Eventually(done, "5s").Should(Receive(&err),
				"an unbounded probe hangs startup; that is the outage this bound exists to prevent")
			Expect(err).NotTo(HaveOccurred(), "a probe that timed out must permit, not refuse")
			Expect(time.Since(start)).To(BeNumerically(">=", 100*time.Millisecond),
				"it must actually have waited on the probe rather than skipped it")
		})
	})

	Describe("a caller that already knows the capability", func() {
		It("skips the probe when told, and probes when not", func() {
			// The probe acquires and releases a real lock, so on a cluster
			// backend it is a round trip. `openvox-ca generate` was paying for
			// two: one for the capability report it prints and one for this.
			cadir := GinkgoT().TempDir()

			probed := &countingLocker{FilesystemBackend: NewFilesystemBackend(cadir)}
			told, err := svc(probed).AcquireInstanceLock(ctx, WithKnownDistributedLocking(true))
			Expect(err).NotTo(HaveOccurred())
			Expect(probed.calls()).To(BeZero(), "a supplied answer must not be bought again")
			Expect(told.Unlock()).To(Succeed())

			unprompted := &countingLocker{FilesystemBackend: NewFilesystemBackend(cadir)}
			ul, err := svc(unprompted).AcquireInstanceLock(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(unprompted.calls()).To(Equal(1),
				"knowing nothing must still get a correct answer; the hint is optional")
			Expect(ul.Unlock()).To(Succeed())
		})

		It("honours a hint of false by enforcing the rule", func() {
			// The hint must decide the outcome, not merely save a call. Told
			// "not distributed", it has to take the store-wide lock and refuse
			// the second instance.
			cadir := GinkgoT().TempDir()

			first, err := svc(&countingLocker{FilesystemBackend: NewFilesystemBackend(cadir)}).
				AcquireInstanceLock(ctx, WithKnownDistributedLocking(false))
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = first.Unlock() })

			_, err = svc(NewFilesystemBackend(cadir)).AcquireInstanceLock(ctx)
			var locked *StoreLockedError
			Expect(errors.As(err, &locked)).To(BeTrue(), "a hint of false must still enforce")
		})

		It("honours a hint of true by exempting the store", func() {
			// And the other way: told the backend coordinates, it must take no
			// store lock, exactly as if it had probed and been told so.
			cadir := GinkgoT().TempDir()
			lockDir := filepath.Join(cadir, fsLockDir)

			first, err := svc(NewFilesystemBackend(cadir)).
				AcquireInstanceLock(ctx, WithKnownDistributedLocking(true))
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = first.Unlock() })

			second, err := svc(NewFilesystemBackend(cadir)).
				AcquireInstanceLock(ctx, WithKnownDistributedLocking(true))
			Expect(err).NotTo(HaveOccurred(), "a hint of true must exempt the store")
			DeferCleanup(func() { _ = second.Unlock() })

			Expect(countLockFiles(lockDir)).To(BeZero())
		})
	})

	Describe("when the holder record cannot be written", func() {
		It("keeps the lock rather than surrendering it over a cosmetic failure", func() {
			// The record exists so a refusal can name the holder. Failing to
			// write it loses a name in somebody else's error message; failing to
			// keep the lock would let a second instance run. The branch has to
			// prefer the lock, and it is short enough to look obviously right
			// while being wrong.
			cadir := GinkgoT().TempDir()

			original := writeHolder
			writeHolder = func(*os.File) error { return errors.New("no space left on device") }
			DeferCleanup(func() { writeHolder = original })

			first, err := svc(NewFilesystemBackend(cadir)).AcquireInstanceLock(ctx)
			Expect(err).NotTo(HaveOccurred(), "a failed record must not cost us the lock")
			DeferCleanup(func() { _ = first.Unlock() })

			// And the lock is real, not merely returned: the exclusion is the
			// part that would be silently lost.
			writeHolder = original
			_, err = svc(NewFilesystemBackend(cadir)).AcquireInstanceLock(ctx)
			var locked *StoreLockedError
			Expect(errors.As(err, &locked)).To(BeTrue(), "the lock must still exclude a second instance")
			Expect(locked.Holder).To(BeEmpty(), "there is no record, so there is no name to report")
			Expect(locked.Error()).To(ContainSubstring("unidentified process"))
		})
	})

	Describe("the reserved lock name", func() {
		It("cannot collide with a lock a running instance takes", func() {
			// The store-wide lock is held for the whole life of the process, so
			// a collision with any name real work uses would deadlock the
			// instance against itself on its first operation.
			Expect(instanceLockName).NotTo(Equal(lockProbeName))
			Expect(instanceLockName).NotTo(Equal("bootstrap"))
			Expect(instanceLockName).NotTo(Equal("crl"))
			Expect(instanceLockName).NotTo(HavePrefix("subject:"))
		})
	})
})

// plainBackend hides every optional locking interface its embedded backend
// implements, standing in for a backend that offers neither distributed nor
// store-wide locking. The embedded field is an interface deliberately: an
// embedded concrete type would promote AcquireInstanceLock and make the spec
// assert the opposite of what it says.
type plainBackend struct {
	Backend
}

// blockingLocker advertises distributed locking and never grants it, which is
// an unreachable cluster backend as AcquireInstanceLock meets one.
type blockingLocker struct {
	Backend
}

func (b *blockingLocker) AcquireLock(ctx context.Context, _ string) (Unlocker, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// countingLocker counts the capability probes made against it. The embedded
// concrete backend is deliberate, as in bothLocker: an embedded interface would
// not promote AcquireInstanceLock, and the specs that assert a lock was or was
// not taken would be measuring the stub rather than the store.
type countingLocker struct {
	*FilesystemBackend

	mu sync.Mutex
	n  int
}

func (c *countingLocker) AcquireLock(context.Context, string) (Unlocker, error) {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return noopUnlocker{}, nil
}

func (c *countingLocker) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

var _ = Describe("LockIsEnforced", func() {
	// The predicate is the sole input to rebuild-inventory-hmac's refusal, and
	// it must fail closed: an Unlocker it does not recognise has to read as
	// unenforced, because the cost of the other direction is proceeding on a
	// store nothing proved was quiet.
	It("is false for the no-op AcquireInstanceLock hands back", func() {
		Expect(LockIsEnforced(noopUnlocker{})).To(BeFalse())
	})

	It("is false for an unrecognised Unlocker rather than assuming enforcement", func() {
		Expect(LockIsEnforced(strangeUnlocker{})).To(BeFalse(),
			"an Unlocker this predicate has not been told about must not read as a real lock")
	})

	It("is true for the file lock, which really does exclude another process", func() {
		Expect(LockIsEnforced(&fileUnlocker{})).To(BeTrue())
	})
})

// strangeUnlocker is an Unlocker from outside this package's knowledge — a
// wrapper, or a no-op variant added later.
type strangeUnlocker struct{}

func (strangeUnlocker) Unlock() error { return nil }
