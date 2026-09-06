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

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// The single-instance rule as the commands see it: on a backend with no
// distributed locking, one process may be running against the store and the
// rest are refused by name.
//
// A separate StorageService over the same cadir stands in for the process
// already running. The substitution is exact — flock(2) is held by an open file
// description, so a second one excludes the first whether or not a fork
// separates them, and each service builds its own.

var _ = Describe("the store instance lock", func() {
	var ctx context.Context

	BeforeEach(func() { ctx = context.Background() })

	// The specs below drive real root commands, which resolve PUPPET_CA_CONFIG
	// and the PUPPET_CA_* environment. Without a pin, an exported
	// PUPPET_CA_STORAGE_BACKEND (or a host /etc/puppet-ca/config.yaml) sends
	// them at a store the holdStore flock does not cover. It covers every
	// command-driving spec in this file, not only the newest: the hazard is the
	// same for csr and import-ca-cert, and counting them here would go stale
	// the next time one is added.
	BeforeEach(func() {
		pinned := filepath.Join(GinkgoT().TempDir(), "pinned.yaml")
		Expect(os.WriteFile(pinned, []byte("ca_key_algo: ecdsa\nca_key_size: 256\n"), 0o644)).To(Succeed())
		setEnv("PUPPET_CA_CONFIG", pinned)
		clearServerEnv()
	})

	// holdStore takes the store's instance lock the way a running server does,
	// and releases it when the spec ends.
	holdStore := func(cadir string) {
		GinkgoHelper()
		ul, err := storage.New(cadir).AcquireInstanceLock(ctx)
		Expect(err).NotTo(HaveOccurred(), "the store must be free before the spec holds it")
		DeferCleanup(func() { _ = ul.Unlock() })
	}

	Describe("offline generate", func() {
		It("refuses while another process holds the store, and names it", func() {
			caDir := GinkgoT().TempDir()
			outDir := GinkgoT().TempDir()
			bootstrapCAInDir(caDir, "puppet.example.com")
			holdStore(caDir)

			_, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "1h", "--key-out", filepath.Join(outDir, "web01.key"))

			Expect(err).To(HaveOccurred(), "minting beside a running server is not supported")
			Expect(err).To(MatchError(ContainSubstring("already running against this store")))
			// The holder, which is the thing an operator needs and a lock
			// timeout cannot give them.
			Expect(err).To(MatchError(ContainSubstring("pid " + strconv.Itoa(os.Getpid()))))
			Expect(err).To(MatchError(ContainSubstring("stop the running one first")))
		})

		It("mints once the store has been released", func() {
			// The other half of the assertion above: the refusal must come from
			// the lock being held, not from the lock existing at all.
			caDir := GinkgoT().TempDir()
			outDir := GinkgoT().TempDir()
			bootstrapCAInDir(caDir, "puppet.example.com")

			ul, err := storage.New(caDir).AcquireInstanceLock(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(ul.Unlock()).To(Succeed())

			_, _, err = runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "1h", "--key-out", filepath.Join(outDir, "web01.key"))
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("lockStoreInstance", func() {
		It("keeps the store locked after the runtime it opened has been closed", func() {
			// The claim the launcher rests on. It opens the store for no reason
			// but this lock and closes it again at once, so a lock that died
			// with the backend handle would leave the server unprotected while
			// appearing to work.
			caDir := GinkgoT().TempDir()
			cfg := &serverConfig{CADir: caDir}

			ul, err := lockStoreInstance(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = ul.Unlock() })

			_, err = storage.New(caDir).AcquireInstanceLock(ctx)
			var locked *storage.StoreLockedError
			Expect(errors.As(err, &locked)).To(BeTrue(),
				"the flock must outlive the backend handle lockStoreInstance opened to take it")
		})

		It("refuses a second instance and admits one after the first releases", func() {
			caDir := GinkgoT().TempDir()
			cfg := &serverConfig{CADir: caDir}

			first, err := lockStoreInstance(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())

			_, err = storage.New(caDir).AcquireInstanceLock(ctx)
			Expect(err).To(HaveOccurred(), "a second instance must be refused")

			Expect(first.Unlock()).To(Succeed())

			second, err := storage.New(caDir).AcquireInstanceLock(ctx)
			Expect(err).NotTo(HaveOccurred(), "the store must be free once the instance has released it")
			Expect(second.Unlock()).To(Succeed())
		})

		It("permits every instance on a backend that coordinates across processes", func() {
			// The exemption. Multiple instances on the HA backends are a
			// designed-for configuration, and a gate that caught them would
			// take out an HA deployment rather than a single-node one. An
			// unreachable backend answers the same way, deliberately: see
			// StorageService.AcquireInstanceLock.
			caDir := GinkgoT().TempDir()
			// An endpoint nothing is listening on, with the dial bounded so the
			// spec costs a second rather than the probe's own ceiling. What it
			// exercises end to end is that neither answer -- "distributed" nor
			// "could not tell" -- refuses the instance.
			cfg := &serverConfig{
				CADir:                 caDir,
				StorageBackend:        "etcd",
				EtcdEndpoints:         []string{"127.0.0.1:1"},
				EtcdDialTimeoutSec:    1,
				EtcdRequestTimeoutSec: 1,
			}

			first, err := lockStoreInstance(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = first.Unlock() })

			second, err := lockStoreInstance(ctx, cfg)
			Expect(err).NotTo(HaveOccurred(), "an etcd-backed CA may run as many instances as it likes")
			DeferCleanup(func() { _ = second.Unlock() })
		})
	})

	Describe("holdInstanceLock", func() {
		// The helper the offline subcommands share. It exists to carry an
		// ordering invariant that a hand-written defer pair gets backwards, and
		// until now nothing pinned the helper itself -- only the callers that
		// happened to use it.
		newRuntime := func(rec *testutil.RecordingBackend) *caRuntime {
			rt := &caRuntime{Store: storage.NewWithBackend(rec, filepath.Join(GinkgoT().TempDir(), "private"))}
			// resolveRuntime registers the backend's Close first, so Close runs
			// it last. Reproduced here, because the invariant is about where the
			// release lands relative to it.
			rt.closers = append(rt.closers, rec.Close)
			return rt
		}

		It("releases the lock only after the backend it protects is closed", func() {
			// Close runs closers in reverse, so the release has to be inserted at
			// the FRONT to run last. Append it instead and the store is given up
			// while this process still holds an open handle to it -- on SQLite, a
			// pooled connection to the database file the lock exists to keep to
			// one writer.
			rec := testutil.NewRecordingBackend(GinkgoT().TempDir())
			rt := newRuntime(rec)

			Expect(func() error { _, e := holdInstanceLock(ctx, rt); return e }()).To(Succeed())
			Expect(rec.Events()).To(BeEmpty(), "nothing is given back before Close")

			Expect(rt.Close()).To(Succeed())
			Expect(rec.Events()).To(Equal([]string{"close", "unlock"}),
				"the lock must outlive the backend handle it protects")
		})

		It("refuses when another instance holds the store, and leaves rt closable", func() {
			cadir := GinkgoT().TempDir()
			holdStore(cadir)

			rec := testutil.NewRecordingBackend(cadir)
			rt := newRuntime(rec)

			_, err := holdInstanceLock(ctx, rt)
			var locked *storage.StoreLockedError
			Expect(errors.As(err, &locked)).To(BeTrue())

			// No release was registered, so Close must still close the backend
			// exactly once and must not try to unlock a lock never taken.
			Expect(rt.Close()).To(Succeed())
			Expect(rec.Events()).To(Equal([]string{"close"}))
		})
	})

	Describe("the offline subcommands that share holdInstanceLock", func() {
		// generate is covered above. These are the other call sites, which
		// exercised no lock behaviour at all.
		It("refuses csr while another instance holds the store", func() {
			caDir := GinkgoT().TempDir()
			bootstrapCAInDir(caDir, "puppet.example.com")
			holdStore(caDir)

			_, _, err := runCSRStreams("--cadir", caDir,
				"--out", filepath.Join(GinkgoT().TempDir(), "ca-request.pem"))

			Expect(err).To(MatchError(ContainSubstring("already running against this store")))
			Expect(err).To(MatchError(ContainSubstring("pid " + strconv.Itoa(os.Getpid()))))
		})

		It("refuses import-ca-cert while another instance holds the store", func() {
			caDir := GinkgoT().TempDir()
			bootstrapCAInDir(caDir, "puppet.example.com")
			holdStore(caDir)

			_, err := runImport("--cadir", caDir,
				"--cert-bundle", filepath.Join(caDir, "ca_crt.pem"))

			Expect(err).To(MatchError(ContainSubstring("already running against this store")))
			Expect(err).To(MatchError(ContainSubstring("pid " + strconv.Itoa(os.Getpid()))))
		})

		It("still reports rebuild-inventory-hmac while another instance holds the store", func() {
			// The other half of the documented promise, and the half nothing
			// pinned: reporting takes no instance lock, so a CA can be inspected
			// while it runs. The guarantee rests entirely on holdInstanceLock
			// sitting below the --yes-re-bless gate; moving that one line up
			// would break it silently.
			caDir := GinkgoT().TempDir()
			bootstrapCAInDir(caDir, "puppet.example.com")
			breakInventoryIntegrity(caDir)
			holdStore(caDir)

			stdout, _, err := runRebuild("--cadir", caDir)

			Expect(err).To(MatchError(ContainSubstring("--yes-re-bless")),
				"reporting must refuse for want of confirmation, not for the lock")
			Expect(err).NotTo(MatchError(ContainSubstring("already running against this store")))
			Expect(stdout).To(ContainSubstring("verifies:      NO"),
				"and it must still have produced the report the operator came for")
		})

		It("refuses rebuild-inventory-hmac while another instance holds the store", func() {
			caDir := GinkgoT().TempDir()
			bootstrapCAInDir(caDir, "puppet.example.com")

			// The integrity value must actually be broken, or the command
			// reports "nothing to do" and returns before it reaches the lock at
			// all -- it is taken only when a write is about to happen, so that a
			// command which declines to act leaves no locks/ directory behind.
			// A spec that skipped this would pass while asserting nothing.
			breakInventoryIntegrity(caDir)
			holdStore(caDir)

			_, _, err := runRebuild("--cadir", caDir, "--yes-re-bless")

			Expect(err).To(MatchError(ContainSubstring("already running against this store")))
			Expect(err).To(MatchError(ContainSubstring("pid " + strconv.Itoa(os.Getpid()))))
		})
	})

	Describe("the server's own startup", func() {
		It("refuses to start, through the command an operator actually runs", func() {
			// Every other spec here drives the mechanism. This one drives the top
			// level: the refusal has to survive flag parsing, config resolution
			// and role dispatch to reach the operator as a non-zero exit.
			caDir := GinkgoT().TempDir()
			bootstrapCAInDir(caDir, "puppet.example.com")
			holdStore(caDir)

			cmd := newRootCmd()
			cmd.SetOut(GinkgoWriter)
			cmd.SetErr(GinkgoWriter)
			cmd.SetArgs([]string{"--cadir", caDir, "--host", "127.0.0.1", "--port", "0"})

			// Bounded rather than called directly, because of what sits
			// immediately after the check: if enforcement regressed, the next
			// thing this command does is fork the launcher and supervise it for
			// ever. A spec that hangs on regression is worse than one that
			// fails, and a plain Execute() here does exactly that -- confirmed
			// by mutating the guard away, which hung the run rather than
			// reporting anything.
			done := make(chan error, 1)
			go func() { done <- cmd.Execute() }()

			var err error
			Eventually(done, "30s").Should(Receive(&err),
				"the refusal must come before the launcher forks; a hang here means it does not")
			Expect(err).To(MatchError(ContainSubstring("already running against this store")),
				"a second server must be refused before it forks anything")
			Expect(err).To(MatchError(ContainSubstring("stop the running one first")))
		})

		It("refuses under --daemon instead of reporting success", func() {
			// --daemon discards the child's stdout and stderr, so a refusal
			// raised there reaches nobody: the operator is told the CA started,
			// gets exit 0, and the child dies in silence. The one deployment
			// shape most likely to hit this conflict must not be the one that
			// hides it.
			caDir := GinkgoT().TempDir()
			bootstrapCAInDir(caDir, "puppet.example.com")
			holdStore(caDir)

			cmd := newRootCmd()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(GinkgoWriter)
			cmd.SetArgs([]string{"--cadir", caDir, "--host", "127.0.0.1", "--port", "0", "--daemon"})

			err := cmd.Execute()
			Expect(err).To(MatchError(ContainSubstring("already running against this store")))
			Expect(out.String()).NotTo(ContainSubstring("started in background"),
				"reporting a background start for a process that was refused is the failure")
		})
	})

	Describe("the capability hint generate passes on", func() {
		// The hint saves a probe. Its dangerous branch is the one where the
		// probe *failed*: an error is a third answer, and coercing it into
		// "false" would apply the single-instance rule to an HA backend having
		// a bad moment -- refusing a deployment entitled to run many, which is
		// the one restriction #275 forbids.
		It("reports the capability as unknown when the probe fails, and hints nothing", func() {
			probeErr := errors.New("cluster unreachable")
			store := storage.NewWithBackend(
				testutil.NewUnreachableLockBackend(GinkgoT().TempDir(), probeErr),
				filepath.Join(GinkgoT().TempDir(), "private"))

			var out bytes.Buffer
			distributed, known := reportBackendCapabilities(ctx, &out, store)

			Expect(known).To(BeFalse(), "a failed probe is not an answer to pass on")
			Expect(distributed).To(BeFalse())
			Expect(out.String()).To(ContainSubstring("could not determine"),
				"the operator is told it is unknown, not told it is absent")
		})

		It("does not enforce the rule on a backend whose capability could not be determined", func() {
			// The end the wiring exists to protect. Omitting the hint sends
			// AcquireInstanceLock back to its own probe, which fails the same
			// way and applies warn-and-permit -- so no store lock is taken and
			// an HA backend is not refused. Passing a hint of false here
			// instead would take the lock and enforce.
			cadir := GinkgoT().TempDir()
			store := storage.NewWithBackend(
				testutil.NewUnreachableLockBackend(cadir, errors.New("cluster unreachable")),
				filepath.Join(GinkgoT().TempDir(), "private"))

			var out bytes.Buffer
			distributed, known := reportBackendCapabilities(ctx, &out, store)
			Expect(known).To(BeFalse(), "precondition: the probe failed")

			var opts []storage.InstanceLockOption
			if known {
				opts = append(opts, storage.WithKnownDistributedLocking(distributed))
			}

			first, err := store.AcquireInstanceLock(ctx, opts...)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = first.Unlock() })

			second, err := storage.New(cadir).AcquireInstanceLock(ctx)
			Expect(err).NotTo(HaveOccurred(),
				"an undetermined capability must not be enforced as though it were absent")
			Expect(second.Unlock()).To(Succeed())
		})
	})

	Describe("the isolated child roles", func() {
		// The reason the lock is taken before the role dispatch and not in
		// resolveRuntime. With PUPPET_CA_ROLE unset the process is either the
		// launcher, which forks a signer and a frontend that open the store for
		// themselves, or the single-process server. If a child took the lock
		// too, the default topology on the default backend would deadlock
		// against itself at startup -- and every single-process test would go
		// on passing.
		DescribeTable("do not take the store lock",
			func(role string) {
				caDir := GinkgoT().TempDir()
				bootstrapCAInDir(caDir, "puppet.example.com")
				holdStore(caDir)

				GinkgoT().Setenv("PUPPET_CA_ROLE", role)

				cmd := newRootCmd()
				cmd.SetOut(GinkgoWriter)
				cmd.SetErr(GinkgoWriter)
				cmd.SetArgs([]string{"--cadir", caDir, "--host", "127.0.0.1", "--port", "0"})

				// A child fails for its own reasons -- there is no launcher to
				// hand it a signer socket -- so this asserts the reason rather
				// than success. Anything mentioning the store lock means a child
				// tried to take a lock its own parent already holds.
				err := cmd.Execute()
				Expect(err).To(HaveOccurred(), "a role child cannot run without its launcher")
				Expect(err).NotTo(MatchError(ContainSubstring("already running against this store")),
					"a launcher child must never contend for the instance lock its instance holds")
			},
			Entry("signer", "signer"),
			Entry("frontend", "frontend"),
		)
	})
})
