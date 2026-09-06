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
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// distributedLockBackend is a real filesystem store that also answers the
// capability probe successfully, which is what etcd, Redis and the server SQL
// dialects look like from here. Everything else is the genuine backend, so a
// bootstrapped cadir behaves normally underneath it.
type distributedLockBackend struct {
	storage.Backend
}

func (distributedLockBackend) AcquireLock(context.Context, string) (storage.Unlocker, error) {
	return probeUnlocker{}, nil
}

type probeUnlocker struct{}

func (probeUnlocker) Unlock() error { return nil }

// droppingHMACBackend accepts the integrity-head write and silently discards
// it, which is what the re-read guard exists to catch: a rebuild that reported
// success while the store still held the old value.
type droppingHMACBackend struct {
	storage.Backend
}

func (b droppingHMACBackend) Put(ctx context.Context, key string, data []byte, kind storage.BlobKind) error {
	if key == storage.KeyInventoryHMAC {
		return nil
	}
	return b.Backend.Put(ctx, key, data, kind)
}

// opaqueBackend is a real filesystem store whose InstanceLocker is not visible.
// Embedding the Backend interface promotes only Backend's methods, so
// AcquireInstanceLock finds no store-wide lock and returns a working no-op --
// the state a platform without flock(2) or a read-only mount produces.
type opaqueBackend struct {
	storage.Backend
}

// writeLoggingConfig points the next command at a config naming a logfile that
// exists, and returns its path. Asserting through the configured logfile rather
// than a captured handler also pins the applySubcommandLogging wiring the audit
// records depend on -- without it a record exists only in the terminal that ran
// the command.
func writeLoggingConfig() string {
	GinkgoHelper()
	logFile := filepath.Join(GinkgoT().TempDir(), "ca.log")
	// applySubcommandLogging declines to create the file, so it has to exist.
	// That is the deployment shape too: the server owns the logfile.
	Expect(os.WriteFile(logFile, nil, 0o640)).To(Succeed())
	cfg := filepath.Join(GinkgoT().TempDir(), "logging.yaml")
	Expect(os.WriteFile(cfg,
		[]byte("ca_key_algo: ecdsa\nca_key_size: 256\nlogfile: "+logFile+"\n"), 0o644)).To(Succeed())
	setEnv("PUPPET_CA_CONFIG", cfg)
	return logFile
}

// atomicNoLockBackend has a structured inventory and no distributed locking,
// which is SQLite's shape and the only combination that renders the capability
// report's "atomic inventory append" as true.
type atomicNoLockBackend struct {
	atomicCapBackend
}

func (atomicNoLockBackend) AcquireLock(context.Context, string) (storage.Unlocker, error) {
	return nil, storage.ErrDistributedLockingUnsupported
}

// legacyStructuredBackend is an InventoryStore whose decomposed rows do not
// exist yet, over a real filesystem cadir whose inventory blob does. That is an
// etcd or Redis CA upgraded from a pre-decomposition release and not yet
// started: asInventoryStore is true by static type, but Entries reads rows that
// EnsureReady has not created.
type legacyStructuredBackend struct {
	storage.Backend
}

func (legacyStructuredBackend) Entries(context.Context) ([]storage.InventoryEntry, error) {
	return nil, nil
}

func (legacyStructuredBackend) AppendEntry(context.Context, storage.CertRecord, func([]byte) []byte) error {
	return nil
}

func (legacyStructuredBackend) LatestSerialForSubject(context.Context, string) (string, error) {
	return "", nil
}

func (legacyStructuredBackend) PruneEntries(context.Context, func(storage.InventoryEntry) bool,
	func([]byte, storage.InventoryEntry) []byte,
) ([]storage.InventoryEntry, error) {
	return nil, nil
}

// failHMACPutBackend fails the integrity write outright, where
// droppingHMACBackend silently succeeds. The difference matters: this reaches
// RebuildInventoryHMAC's own error return, which is a mutating path in the
// wrong-length-key state because the key has already been replaced by then.
type failHMACPutBackend struct {
	storage.Backend
}

func (b failHMACPutBackend) Put(ctx context.Context, key string, data []byte, kind storage.BlobKind) error {
	if key == storage.KeyInventoryHMAC {
		return errors.New("simulated integrity write failure")
	}
	return b.Backend.Put(ctx, key, data, kind)
}

// runRebuildOver drives the subcommand against an explicitly supplied store,
// through the injection seam, so the capability branches can be reached without
// a real cluster.
func runRebuildOver(store *storage.StorageService, args ...string) (stdout string, err error) {
	cmd := newRebuildInventoryHMACCmdWith(func(context.Context, *serverConfig) (*caRuntime, error) {
		return &caRuntime{Store: store}, nil
	})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(args)
	err = cmd.Execute()
	return out.String(), err
}

// storeOver builds a StorageService over a bootstrapped cadir with the given
// backend wrapper, keeping the real private-key directory New would use.
func storeOver(caDir string, wrap func(storage.Backend) storage.Backend) *storage.StorageService {
	return storage.NewWithBackend(wrap(storage.NewFilesystemBackend(caDir)),
		filepath.Join(caDir, "private"))
}

// runRebuild drives the subcommand through the root command, as an operator
// reaches it: flag parsing and config resolution included.
func runRebuild(args ...string) (stdout, stderr string, err error) {
	root := newRootCmd()
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(append([]string{"rebuild-inventory-hmac"}, args...))
	err = root.Execute()
	return out.String(), errOut.String(), err
}

// startCA is what the command exists to restore: a CA.Init against the same
// cadir, which is the operation that fails while the integrity value does not
// verify and must succeed once it does.
func startCA(dir string) error {
	myCA := ca.New(storage.New(dir), ca.AutosignConfig{Mode: "off"}, "puppet.example.com")
	myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
	return myCA.Init(context.Background())
}

// issueInDir signs a certificate so the inventory holds a genuine entry before
// anything is broken. A fixture whose only entry is the injected one is weaker
// than it looks: several wrong rebuilds produce an inventory containing exactly
// that entry too.
func issueInDir(dir, subject string) {
	GinkgoHelper()
	myCA := ca.New(storage.New(dir), ca.AutosignConfig{Mode: "off"}, "puppet.example.com")
	myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
	myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
	Expect(myCA.Init(context.Background())).To(Succeed())
	_, err := myCA.Generate(context.Background(), subject, nil)
	Expect(err).NotTo(HaveOccurred())
}

// breakInventoryIntegrity appends an inventory line out of band, which is what
// a lost append race leaves behind: a real entry the stored HMAC does not
// cover. It is deliberately not a corruption of the HMAC file itself -- that
// would test a different and easier failure, and the entry-shaped one is what
// #188 is about.
func breakInventoryIntegrity(dir string) {
	GinkgoHelper()
	inv := filepath.Join(dir, "inventory.txt")
	before, err := os.ReadFile(inv)
	Expect(err).NotTo(HaveOccurred(), "the bootstrapped CA must have an inventory to break")

	line := "0x0999 2026-01-01T00:00:00UTC 2036-01-01T00:00:00UTC /CN=ghost.example.com\n"
	Expect(os.WriteFile(inv, append(before, []byte(line)...), 0o640)).To(Succeed())
}

var _ = Describe("openvox-ca rebuild-inventory-hmac", func() {
	var caDir string

	BeforeEach(func() {
		caDir = GinkgoT().TempDir()
		bootstrapCAInDir(caDir, "puppet.example.com")

		// Pin the configuration these specs resolve, as csr_test.go,
		// importcacert_test.go and generate_test.go each do. Every spec here
		// drives the real root command, so without this an exported
		// PUPPET_CA_SQL_DSN, or a host /etc/puppet-ca/config.yaml, silently
		// points them at a real store instead of --cadir. Most would then fail
		// loudly, but "refuses when no HMAC key is stored" would not: it deletes
		// the local key and asserts only an error string, so against a
		// redirected store that happens to have no key it goes green while the
		// deletion it rests on did nothing at all.
		pinnedCfg := filepath.Join(GinkgoT().TempDir(), "pinned.yaml")
		Expect(os.WriteFile(pinnedCfg, []byte("ca_key_algo: ecdsa\nca_key_size: 256\n"), 0o644)).To(Succeed())
		setEnv("PUPPET_CA_CONFIG", pinnedCfg)
		clearServerEnv()

		// Every spec here drives a command that calls applySubcommandLogging ->
		// setupLogger -> slog.SetDefault. The closer it returns only closes the
		// file; it never puts the previous default back. generate_test.go, which
		// this BeforeEach is otherwise modelled on, restores it for exactly this
		// reason and the guard was not carried over with the rest.
		origLogger := slog.Default()
		DeferCleanup(func() { slog.SetDefault(origLogger) })
	})

	Describe("the property the command exists for", func() {
		It("restores a CA that will not start, having first confirmed it would not", func() {
			// The premise, asserted rather than assumed. Without this the spec
			// could pass against a CA that was never broken, which is the shape
			// of a test that goes green for a reason unrelated to the defect.
			Expect(startCA(caDir)).To(Succeed(), "the CA must start before anything is broken")

			breakInventoryIntegrity(caDir)

			Expect(startCA(caDir)).To(MatchError(storage.ErrInventoryTampered),
				"the premise of this spec is a CA that will not start; if this passes, nothing below is meaningful")

			stdout, _, err := runRebuild("--cadir", caDir, "--yes-re-bless")
			Expect(err).NotTo(HaveOccurred(), "stdout: %s", stdout)

			// The property: not that the command ran, but that the CA starts.
			Expect(startCA(caDir)).To(Succeed(), "the CA must start once integrity has been re-asserted")

			// The summary is the operator's only account of what was signed
			// over, and every refusal message is pinned while this was not.
			// "1 entry" also pins pluralEntries' singular branch.
			Expect(stdout).To(ContainSubstring("covers 1 entry"))
			Expect(stdout).To(ContainSubstring("Integrity has been re-asserted, not verified"))
		})

		It("covers the entry that was appended out of band, rather than dropping it", func() {
			// Re-blessing must sign over the inventory as it stands. A rebuild
			// that quietly excluded the unknown entry would also produce a
			// startable CA, so "it starts" alone does not pin this.
			issueInDir(caDir, "web01.example.com")
			breakInventoryIntegrity(caDir)

			_, _, err := runRebuild("--cadir", caDir, "--yes-re-bless")
			Expect(err).NotTo(HaveOccurred())

			entries, err := storage.New(caDir).InventoryEntries(context.Background())
			Expect(err).NotTo(HaveOccurred(), "the rebuilt value must let the inventory be read")
			Expect(entries).To(ContainElement(HaveField("Subject", "CN=ghost.example.com")),
				"the out-of-band entry must still be there and now be covered")
			Expect(entries).To(ContainElement(HaveField("Subject", "web01.example.com")),
				"and the entry that was already there must survive the rebuild")
		})
	})

	Describe("the durable audit record", func() {
		It("writes what was signed over to the configured logfile", func() {
			logFile := writeLoggingConfig()
			issueInDir(caDir, "web01.example.com")
			breakInventoryIntegrity(caDir)

			headBefore, readBefore := os.ReadFile(filepath.Join(caDir, ".inventory.hmac"))
			Expect(readBefore).NotTo(HaveOccurred())

			stdout, _, err := runRebuild("--cadir", caDir, "--yes-re-bless")
			Expect(err).NotTo(HaveOccurred())

			// The plural branch of pluralEntries, reachable only here: this
			// fixture rebuilds two entries where the flagship spec rebuilds one.
			Expect(stdout).To(ContainSubstring("covers 2 entries"))

			headAfter, readAfter := os.ReadFile(filepath.Join(caDir, ".inventory.hmac"))
			Expect(readAfter).NotTo(HaveOccurred())

			logged, readErr := os.ReadFile(logFile)
			Expect(readErr).NotTo(HaveOccurred())

			// Per record, not over the whole file. Both records carry a
			// `previous` field, so a ContainSubstring over the file passes when
			// only one of them is wrong -- found by mutating the first record's
			// `previous` to the computed head, which the file-wide assertion
			// missed because the second record still held the right value.
			reAsserted := logRecord(logged, "Inventory integrity re-asserted by rebuild-inventory-hmac; "+
				"the inventory as it stood is now treated as authentic")
			verified := logRecord(logged, "Inventory integrity rebuild verified")

			// By value, not by shape: both heads are 64 hex characters, so a
			// regex is satisfied by either. What matters is that `previous` is
			// the head captured BEFORE the write -- recording the new head there
			// would answer "what was signed over" with the value that replaced
			// it, and pass every shape assertion.
			Expect(reAsserted).To(HaveKeyWithValue("previous", hex.EncodeToString(headBefore)),
				"previous must be the head that was replaced, not the one that replaced it")
			Expect(reAsserted).To(HaveKeyWithValue("level", "WARN"),
				"an operator must find this without knowing to look for it")
			Expect(reAsserted).To(HaveKeyWithValue("replicas_stopped_asserted", false))
			Expect(reAsserted).To(HaveKeyWithValue("entries", float64(2)))
			Expect(reAsserted).To(HaveKeyWithValue("key_state", "usable"))

			Expect(verified).To(HaveKeyWithValue("previous", hex.EncodeToString(headBefore)))
			Expect(verified).To(HaveKeyWithValue("new", hex.EncodeToString(headAfter)),
				"and the new head must be what the store actually now holds")
		})

		It("records the mutation even when the rebuilt value does not verify", func() {
			// The store has already been rewritten by the time that failure is
			// detected, and its own message says something is writing to the
			// store. A record emitted only on success would lose exactly the
			// case an auditor most needs.
			logFile := writeLoggingConfig()
			breakInventoryIntegrity(caDir)
			headBefore, readBefore := os.ReadFile(filepath.Join(caDir, ".inventory.hmac"))
			Expect(readBefore).NotTo(HaveOccurred())

			store := storeOver(caDir, func(b storage.Backend) storage.Backend {
				return droppingHMACBackend{b}
			})

			_, err := runRebuildOver(store, "--yes-re-bless", "--replicas-stopped")
			Expect(err).To(MatchError(ContainSubstring("still does not verify")))

			logged, readErr := os.ReadFile(logFile)
			Expect(readErr).NotTo(HaveOccurred())
			// Per record, as its sibling is: this logfile also holds the
			// instance-lock no-op warning, and file-wide matching is what let a
			// wrong field in one record be satisfied by another.
			rec := logRecord(logged, "Inventory integrity re-asserted by rebuild-inventory-hmac; "+
				"the inventory as it stood is now treated as authentic")
			Expect(rec).To(HaveKeyWithValue("replicas_stopped_asserted", true))
			Expect(rec).To(HaveKeyWithValue("previous", hex.EncodeToString(headBefore)),
				"the head that was replaced must be on record even when the outcome was bad")
			Expect(string(logged)).NotTo(ContainSubstring("rebuild verified"),
				"but it must not claim the rebuild verified")
		})

		It("records the unverified baseline the next start will establish", func() {
			// The third audit record, and the only one outside this Describe
			// until now: deleting it, or demoting it to Info, passed the suite.
			logFile := writeLoggingConfig()
			issueInDir(caDir, "web01.example.com")
			Expect(os.Remove(filepath.Join(caDir, ".inventory.hmac"))).To(Succeed())

			stdout, _, err := runRebuild("--cadir", caDir, "--yes-re-bless")
			Expect(err).NotTo(HaveOccurred())
			Expect(stdout).To(ContainSubstring("nothing to rebuild"))

			logged, readErr := os.ReadFile(logFile)
			Expect(readErr).NotTo(HaveOccurred())
			rec := logRecord(logged,
				"No inventory integrity value is stored; the next start will baseline the inventory as it stands")
			Expect(rec).To(HaveKeyWithValue("level", "WARN"),
				"an operator must find this without knowing to look for it")
			Expect(rec).To(HaveKeyWithValue("key_state", "usable"))
			Expect(rec).To(HaveKeyWithValue("entries", float64(1)))
			// By value, as its siblings are: this record exists to say what the
			// next start will baseline, so a record naming the wrong head must
			// fail rather than merely having the key.
			expected, repErr := storage.New(caDir).InventoryIntegrityReport(context.Background())
			Expect(repErr).NotTo(HaveOccurred())
			Expect(rec).To(HaveKeyWithValue("computed", hex.EncodeToString(expected.ComputedHead)))
		})
	})

	Describe("what it refuses to do", func() {
		It("refuses without --yes-re-bless, and changes nothing", func() {
			breakInventoryIntegrity(caDir)

			hmacFile := filepath.Join(caDir, ".inventory.hmac")
			before, err := os.ReadFile(hmacFile)
			Expect(err).NotTo(HaveOccurred())

			stdout, _, err := runRebuild("--cadir", caDir)

			Expect(err).To(MatchError(ContainSubstring("--yes-re-bless")))
			Expect(err).To(MatchError(ContainSubstring("rather than verifying it")),
				"the refusal must say what the flag would authorise, not merely name it")

			after, readErr := os.ReadFile(hmacFile)
			Expect(readErr).NotTo(HaveOccurred())
			Expect(after).To(Equal(before), "a refusal must not write")
			Expect(startCA(caDir)).To(MatchError(storage.ErrInventoryTampered),
				"and must leave the CA exactly as broken as it found it")

			// Reporting is the reason to run it without the flag at all.
			Expect(stdout).To(ContainSubstring("Inventory integrity"))
			Expect(stdout).To(ContainSubstring("verifies:      NO"))
		})

		It("distinguishes a zero-length stored value from no stored value", func() {
			// A torn write leaves a present-but-empty value. Get returns it with
			// a nil error, so it IS stored, and the command routes it to the
			// ordinary mismatch refusal -- rendering it "(none stored)" put "no
			// value is stored" directly above "verifies: NO". Found by mutation:
			// collapsing the two renderings passed the whole suite.
			Expect(os.WriteFile(filepath.Join(caDir, ".inventory.hmac"), nil, 0o640)).To(Succeed())

			stdout, _, err := runRebuild("--cadir", caDir)

			Expect(stdout).To(ContainSubstring("stored value:  (stored, but empty)"))
			Expect(stdout).NotTo(ContainSubstring("stored value:  (none stored)"))
			Expect(stdout).To(ContainSubstring("verifies:      NO"),
				"and it is a mismatch, not the no-baseline state")
			Expect(err).To(MatchError(ContainSubstring("--yes-re-bless")),
				"so it takes the re-bless path rather than reporting nothing to rebuild")
		})

		It("names blob content the entry count does not describe", func() {
			// The disclosure at the moment of confirmation: those lines are
			// covered by the value --yes-re-bless re-asserts. Every other
			// fixture appends a well-formed entry, so this branch was never
			// entered and deleting it left the suite green.
			inv := filepath.Join(caDir, "inventory.txt")
			before, readErr := os.ReadFile(inv)
			Expect(readErr).NotTo(HaveOccurred())
			Expect(os.WriteFile(inv, append(before, []byte("TORN-WRITE-FRAGMENT\n")...), 0o640)).To(Succeed())

			stdout, _, err := runRebuild("--cadir", caDir)
			Expect(err).To(MatchError(ContainSubstring("--yes-re-bless")))

			Expect(stdout).To(ContainSubstring("unparseable:   1 line(s)"))
			Expect(stdout).To(ContainSubstring("but which the integrity value covers"))
		})

		It("reports the state before it refuses, because that is why an operator runs it", func() {
			breakInventoryIntegrity(caDir)

			stdout, _, err := runRebuild("--cadir", caDir)
			Expect(err).To(HaveOccurred())

			Expect(stdout).To(ContainSubstring("scheme:        whole-blob-hmac"))
			Expect(stdout).To(ContainSubstring("HMAC key:      usable"))
			// The fixture's count is known, so assert it rather than "some
			// digits": %d over a len() renders digits unconditionally.
			// The capability branch every filesystem-backed spec prints, and the
			// one nothing asserted: rewriting it to carry generate's green-light
			// reassurance passed the whole suite.
			Expect(stdout).To(ContainSubstring("Backend does not coordinate locks across hosts"))
			Expect(stdout).To(ContainSubstring("atomic inventory append: false"),
				"the interpolated capability, not just the prefix before it")
			Expect(stdout).To(ContainSubstring("reporting never takes it"))
			// The record parameter threaded through applySubcommandLogging: the
			// only prior assertion matched "terminal-only", which passes for any
			// value including the other caller's.
			Expect(stdout).To(ContainSubstring("the audit record for this rebuild is terminal-only"))
			Expect(stdout).NotTo(ContainSubstring("safe to run alongside a live server"))

			Expect(stdout).To(ContainSubstring("entries:       1"))
			Expect(stdout).To(MatchRegexp(`stored value:  [0-9a-f]{16}…`),
				"the column must carry a fingerprint, not just a label")
			Expect(stdout).To(MatchRegexp(`computed:      [0-9a-f]{16}…`))
		})

		It("does nothing when the value already verifies", func() {
			hmacFile := filepath.Join(caDir, ".inventory.hmac")
			before, err := os.ReadFile(hmacFile)
			Expect(err).NotTo(HaveOccurred())

			stdout, _, err := runRebuild("--cadir", caDir, "--yes-re-bless")
			Expect(err).NotTo(HaveOccurred())
			Expect(stdout).To(ContainSubstring("verifies:      yes"))
			Expect(stdout).To(ContainSubstring("Nothing to do"))

			after, err := os.ReadFile(hmacFile)
			Expect(err).NotTo(HaveOccurred())
			Expect(after).To(Equal(before), "a verifying store must not be rewritten")
		})

		Describe("where the single-instance rule cannot be enforced", func() {
			// holdInstanceLock is real on filesystem and SQLite, but
			// AcquireInstanceLock deliberately returns a no-op on backends with
			// distributed locking: those support many replicas, so there is
			// nothing to refuse. That leaves the rebuild with no way to know
			// whether a replica is appending right now -- which is exactly when
			// it writes a fresh incorrect value, because the head is computed
			// from a snapshot. These specs pin the assertion that stands in for
			// the enforcement that cannot happen.

			It("refuses on a backend that coordinates across hosts, without --replicas-stopped", func() {
				breakInventoryIntegrity(caDir)
				store := storeOver(caDir, func(b storage.Backend) storage.Backend {
					return distributedLockBackend{b}
				})

				_, err := runRebuildOver(store, "--yes-re-bless")

				Expect(err).To(MatchError(ContainSubstring("--replicas-stopped")))
				Expect(err).To(MatchError(ContainSubstring("coordinates locks across hosts")))
				Expect(err).To(MatchError(ContainSubstring("cannot detect one")),
					"the refusal must say why it cannot check, not merely that it will not")

				Expect(startCA(caDir)).To(MatchError(storage.ErrInventoryTampered),
					"a refusal must leave the store untouched")
			})

			It("proceeds on that backend once --replicas-stopped is given", func() {
				breakInventoryIntegrity(caDir)
				store := storeOver(caDir, func(b storage.Backend) storage.Backend {
					return distributedLockBackend{b}
				})

				// Premise: without it, a fixture that was never broken satisfies
				// every assertion below -- the command would return "Nothing to
				// do" with a nil error, never reaching the gate this spec names,
				// and the CA would start because nothing was ever wrong.
				Expect(startCA(caDir)).To(MatchError(storage.ErrInventoryTampered),
					"premise: the CA must be broken, or this spec proves nothing about the gate")

				stdout, err := runRebuildOver(store, "--yes-re-bless", "--replicas-stopped")
				Expect(err).NotTo(HaveOccurred())

				Expect(stdout).To(ContainSubstring("Rebuilt."),
					"the rebuild path must actually have run, not the nothing-to-do path")
				Expect(stdout).NotTo(ContainSubstring("Nothing to do"))
				Expect(startCA(caDir)).To(Succeed(),
					"the assertion is the operator's to make, and having made it the repair must happen")
			})

			It("reports an atomic inventory append where the backend has one", func() {
				// The %t verb was only ever observed as false, because every
				// fixture reaching this branch is a FilesystemBackend. A
				// structured backend without distributed locking -- SQLite's
				// shape -- is the combination that renders it true.
				var out bytes.Buffer
				store := storage.NewWithBackend(
					atomicNoLockBackend{}, GinkgoT().TempDir())

				distributed, known := reportRebuildCapabilities(context.Background(), &out, store)

				Expect(distributed).To(BeFalse(), "premise: no distributed locking")
				Expect(known).To(BeTrue())
				Expect(out.String()).To(ContainSubstring("atomic inventory append: true"))
			})

			It("says nothing generate's reporter would say, on a backend with both capabilities", func() {
				// The end-to-end spec below cannot pin this: its double wraps a
				// FilesystemBackend, which is not an InventoryStore, so
				// SupportsAtomicInventory is false and generate's green branch
				// is unreachable there -- its negative assertions would hold
				// whichever reporter ran. atomicCapBackend has both
				// capabilities, which is the state etcd, redis and the SQL
				// dialects are actually in, and the only state where the two
				// reporters visibly disagree.
				lockOK := func(context.Context, string) (storage.Unlocker, error) {
					return probeUnlocker{}, nil
				}
				store := storage.NewWithBackend(
					atomicCapBackend{capBackend{acquire: lockOK}}, GinkgoT().TempDir())

				var shared, mine bytes.Buffer
				sharedDist, sharedKnown := reportBackendCapabilities(context.Background(), &shared, store)
				mineDist, mineKnown := reportRebuildCapabilities(context.Background(), &mine, store)

				Expect(sharedDist).To(BeTrue(), "premise: this double is a distributed backend")
				Expect(sharedKnown).To(BeTrue())
				Expect(shared.String()).To(ContainSubstring("safe to run alongside a live server"),
					"premise: generate's reporter really does say this here")

				Expect(mineDist).To(Equal(sharedDist), "the capability answer must not differ")
				Expect(mineKnown).To(Equal(sharedKnown))
				Expect(mine.String()).NotTo(ContainSubstring("safe to run alongside a live server"),
					"this command refuses on exactly these backends; calling them safe argues the operator past it")
				Expect(mine.String()).NotTo(ContainSubstring("OCSP"),
					"generate's certificate-minting notes describe nothing this command does")
				Expect(mine.String()).To(ContainSubstring("supports many replicas"))
				Expect(mine.String()).To(ContainSubstring("every replica must be stopped first"))
			})

			It("refuses on a distributed backend end to end, with no false reassurance", func() {
				// reportBackendCapabilities says exactly that, and this command
				// refuses on precisely those backends. Printing it here would
				// argue the operator past --replicas-stopped, which is a bare
				// assertion with nothing enforcing it.
				breakInventoryIntegrity(caDir)
				store := storeOver(caDir, func(b storage.Backend) storage.Backend {
					return distributedLockBackend{b}
				})

				stdout, err := runRebuildOver(store, "--yes-re-bless")
				Expect(err).To(HaveOccurred())

				// Deliberately no NotTo assertions on generate's green-branch
				// strings here: this fixture is not an InventoryStore, so
				// atomicInventory is false and generate's reporter would not
				// emit them whichever reporter ran. The spec above, over a
				// double with BOTH capabilities, is the one that pins the
				// reporter choice; these positives pin the wording.
				Expect(stdout).To(ContainSubstring("supports many replicas"))
				Expect(stdout).To(ContainSubstring("every replica must be stopped first"))
			})

			It("refuses when the store offers no lock that would exclude anyone", func() {
				// AcquireInstanceLock returns a working no-op whenever it has
				// nothing to enforce, and says so only through slog -- which by
				// then points at the server's logfile, not this terminal. The
				// command must not report a refusal it did not perform.
				breakInventoryIntegrity(caDir)
				store := storeOver(caDir, func(b storage.Backend) storage.Backend {
					return opaqueBackend{b}
				})

				_, err := runRebuildOver(store, "--yes-re-bless")

				Expect(err).To(MatchError(ContainSubstring("offers no lock that would exclude a second instance")))
				Expect(err).To(MatchError(ContainSubstring("--replicas-stopped")))
				Expect(startCA(caDir)).To(MatchError(storage.ErrInventoryTampered),
					"a refusal must leave the store untouched")
			})

			It("proceeds on such a store once --replicas-stopped is given", func() {
				breakInventoryIntegrity(caDir)
				store := storeOver(caDir, func(b storage.Backend) storage.Backend {
					return opaqueBackend{b}
				})

				// The same two guards its distributed sibling carries: without
				// them a fixture that stopped breaking integrity would take the
				// "Nothing to do" branch, never reach the gate, and pass.
				Expect(startCA(caDir)).To(MatchError(storage.ErrInventoryTampered),
					"premise: the CA must be broken, or this proves nothing about the gate")

				stdout, err := runRebuildOver(store, "--yes-re-bless", "--replicas-stopped")
				Expect(err).NotTo(HaveOccurred())
				Expect(stdout).To(ContainSubstring("Rebuilt."))
				Expect(stdout).NotTo(ContainSubstring("Nothing to do"))
				Expect(startCA(caDir)).To(Succeed())
			})

			It("proceeds on an undetermined capability once --replicas-stopped is given", func() {
				// The third reachable combination of the gate, and the one that
				// matters most: the operator has asserted the thing the command
				// cannot verify, on a backend whose safety could not be
				// established either. A regression that required
				// capabilityKnown before honouring --replicas-stopped would
				// silently close the documented escape hatch, and the refusal
				// specs cannot see it because they never pass the flag.
				breakInventoryIntegrity(caDir)
				store := storage.NewWithBackend(
					testutil.NewUnreachableLockBackend(caDir, errors.New("cluster unreachable")),
					filepath.Join(caDir, "private"))

				Expect(startCA(caDir)).To(MatchError(storage.ErrInventoryTampered),
					"premise: the CA must be broken, or a nothing-to-do run would satisfy this too")

				stdout, err := runRebuildOver(store, "--yes-re-bless", "--replicas-stopped")
				Expect(err).NotTo(HaveOccurred())

				Expect(stdout).To(ContainSubstring("Rebuilt."))
				Expect(stdout).NotTo(ContainSubstring("Nothing to do"))
				Expect(startCA(caDir)).To(Succeed())
			})

			It("refuses when the capability could not be determined at all", func() {
				// A failed probe is a third answer, not a "no". The instance
				// lock will not enforce in this state either, so the honest
				// reading is that this command does not know the store is quiet.
				breakInventoryIntegrity(caDir)
				store := storage.NewWithBackend(
					testutil.NewUnreachableLockBackend(caDir, errors.New("cluster unreachable")),
					filepath.Join(caDir, "private"))

				stdout, err := runRebuildOver(store, "--yes-re-bless")

				Expect(stdout).To(ContainSubstring("could not determine whether this backend coordinates locks"),
					"the printed warning, which is separate from the error below")
				Expect(err).To(MatchError(ContainSubstring("--replicas-stopped")))
				Expect(err).To(MatchError(ContainSubstring("could not be determined")),
					"an undetermined capability must not be reported as a known one")
			})
		})

		It("mints a new key on a wrong-length one, having said so first", func() {
			// The only state in which this command touches key material.
			// EnsureHMACKey regenerates a stored key that is not hmacKeyLen
			// bytes, so --yes-re-bless here destroys the ability to reproduce
			// any existing MAC -- and that is the one consequence the report
			// must state before the operator confirms.
			keyFile := filepath.Join(caDir, "private/.inventory_hmac_key")
			truncated := []byte("far too short")
			Expect(os.WriteFile(keyFile, truncated, 0o600)).To(Succeed())

			// Deliberately NOT asserted by starting the CA first: CA.Init
			// reaches EnsureHMACKey, which mints a replacement over a
			// wrong-length blob, so a premise check written that way destroys
			// the state under test and the command then sees a usable key.
			// Assert the fixture on disk instead.
			onDisk, readErr := os.ReadFile(keyFile)
			Expect(readErr).NotTo(HaveOccurred())
			Expect(onDisk).To(Equal(truncated), "premise: the stored key is the truncated blob")

			stdout, _, err := runRebuild("--cadir", caDir, "--yes-re-bless")
			Expect(err).NotTo(HaveOccurred(), "stdout: %s", stdout)

			Expect(stdout).To(ContainSubstring("HMAC key:      wrong-length"))
			Expect(stdout).To(ContainSubstring("mint a new key as well as a new value"),
				"the operator must be told the key is being replaced, not just the value")

			after, readErr := os.ReadFile(keyFile)
			Expect(readErr).NotTo(HaveOccurred())
			Expect(after).NotTo(Equal(truncated), "a fresh key must have been minted")
			Expect(after).To(HaveLen(32))

			Expect(startCA(caDir)).To(Succeed(), "and the CA must start afterwards")
		})

		It("reports rather than rebuilds when the wrong-length key is only inspected", func() {
			keyFile := filepath.Join(caDir, "private/.inventory_hmac_key")
			truncated := []byte("far too short")
			Expect(os.WriteFile(keyFile, truncated, 0o600)).To(Succeed())

			stdout, _, err := runRebuild("--cadir", caDir)
			Expect(err).To(MatchError(ContainSubstring("--yes-re-bless")))
			Expect(stdout).To(ContainSubstring("HMAC key:      wrong-length"))

			// The two columns must not say the same thing about nil. Nothing
			// pinned this, so collapsing them back into one marker -- the exact
			// regression headFingerprint's second parameter exists to prevent --
			// passed every spec.
			Expect(stdout).To(ContainSubstring("computed:      (not computed)"),
				"a value that was never computed is not a value missing from storage")
			Expect(stdout).To(MatchRegexp(`stored value:  [0-9a-f]{16}…`),
				"and the stored column still holds a real value in this state")

			after, readErr := os.ReadFile(keyFile)
			Expect(readErr).NotTo(HaveOccurred())
			Expect(after).To(Equal(truncated), "inspecting must never mint a key")
		})

		It("refuses to report success when the rebuilt value did not persist", func() {
			// Without the post-rebuild re-read this reports a repair that did
			// not happen, and sends an operator away from a CA that still will
			// not start.
			breakInventoryIntegrity(caDir)
			store := storeOver(caDir, func(b storage.Backend) storage.Backend {
				return droppingHMACBackend{b}
			})

			_, err := runRebuildOver(store, "--yes-re-bless", "--replicas-stopped")

			Expect(err).To(MatchError(ContainSubstring("still does not verify after rebuilding")))
			Expect(err).To(MatchError(ContainSubstring("did not persist")))
		})

		It("treats a missing baseline as nothing to rebuild, not as tampering", func() {
			// Deleting the stored value is a documented way to acknowledge a
			// lost baseline, and the server establishes a new one on start. An
			// operator who has just done that must not be answered with a
			// warning about tampering being signed over.
			Expect(os.Remove(filepath.Join(caDir, ".inventory.hmac"))).To(Succeed())

			stdout, _, err := runRebuild("--cadir", caDir, "--yes-re-bless")
			Expect(err).NotTo(HaveOccurred(), "a missing baseline is not a failure")

			Expect(stdout).To(ContainSubstring("no baseline stored yet, which is not a mismatch"))
			Expect(stdout).To(ContainSubstring("nothing to rebuild"))
			Expect(stdout).To(ContainSubstring("stored value:  (none stored)"))
			Expect(stdout).NotTo(ContainSubstring("tampering"),
				"a healthy CA must not be warned about tampering")
		})

		It("does not advise starting the server when a head survives the lost key", func() {
			// Key gone, value retained. Telling the operator to start the server
			// loops them: it mints a key, disagrees with the retained head, and
			// refuses with a tampering error for something the CA itself did.
			Expect(os.Remove(filepath.Join(caDir, "private/.inventory_hmac_key"))).To(Succeed())

			stdout, _, err := runRebuild("--cadir", caDir, "--yes-re-bless")

			Expect(stdout).To(ContainSubstring("verifies:      no key stored, so nothing can be computed"),
				"without this branch the operator sees a bare NO, which reads as tampering")
			Expect(err).To(MatchError(ContainSubstring("but an integrity value is")))
			Expect(err).To(MatchError(ContainSubstring("removing the stored integrity value")),
				"the refusal must name the gesture that actually resolves this")
			Expect(err).NotTo(MatchError(ContainSubstring("never initialised inventory integrity")),
				"that advice belongs to the no-value case, and is false here")
			Expect(stdout).To(ContainSubstring("HMAC key:      absent"))
		})

		It("refuses on an undecomposed legacy inventory rather than blessing an empty one", func() {
			// The rows do not exist yet, so the report would describe an empty
			// inventory for a store holding a full one, and a rebuild would put
			// an empty chain head over the whole-blob value that is the only
			// thing able to validate it. Destruction, not repair.
			issueInDir(caDir, "web01.example.com")
			before, readErr := os.ReadFile(filepath.Join(caDir, ".inventory.hmac"))
			Expect(readErr).NotTo(HaveOccurred())

			store := storeOver(caDir, func(b storage.Backend) storage.Backend {
				return legacyStructuredBackend{b}
			})

			_, err := runRebuildOver(store, "--yes-re-bless", "--replicas-stopped")

			Expect(err).To(MatchError(ContainSubstring("undecomposed legacy inventory")))
			Expect(err).To(MatchError(ContainSubstring("cannot repair a pre-decomposition inventory")))
			// Not "start the server and re-run": decomposition verifies the
			// legacy blob first and refuses on a mismatch, so that advice is
			// circular for the operator whose integrity check is already
			// failing. The refusal must describe both outcomes of starting.
			Expect(err).To(MatchError(ContainSubstring("If it does not, the server refuses")))

			after, readAfter := os.ReadFile(filepath.Join(caDir, ".inventory.hmac"))
			Expect(readAfter).NotTo(HaveOccurred())
			Expect(after).To(Equal(before),
				"the legacy baseline must survive: overwriting it is the harm this refusal prevents")
		})

		It("records the mutation when the rebuild itself fails mid-write", func() {
			// The wrong-length-key state makes RebuildInventoryHMAC two writes:
			// the key is replaced, then the head. A failure between them is a
			// mutating path, and the operator needs to know a key may already
			// have been minted.
			logFile := writeLoggingConfig()
			Expect(os.WriteFile(filepath.Join(caDir, "private/.inventory_hmac_key"),
				[]byte("far too short"), 0o600)).To(Succeed())

			store := storeOver(caDir, func(b storage.Backend) storage.Backend {
				return failHMACPutBackend{b}
			})

			_, err := runRebuildOver(store, "--yes-re-bless", "--replicas-stopped")

			Expect(err).To(MatchError(ContainSubstring("completes the repair")),
				"the operator must be told a key may already have been minted")

			logged, readErr := os.ReadFile(logFile)
			Expect(readErr).NotTo(HaveOccurred())
			rec := logRecord(logged, "Inventory integrity rebuild failed; the store may already have been changed")
			Expect(rec).To(HaveKeyWithValue("level", "WARN"))
			Expect(rec).To(HaveKeyWithValue("key_state", "wrong-length"))
		})

		It("records a mid-write failure under a usable key, without the minted-key advice", func() {
			// The sibling spec always truncates the key first, so only the
			// wrong-length branch was driven. This is the ordinary case -- a
			// transient write failure with a perfectly good key -- where the
			// extra sentence about a possibly-reminted key would be false.
			logFile := writeLoggingConfig()
			breakInventoryIntegrity(caDir)

			store := storeOver(caDir, func(b storage.Backend) storage.Backend {
				return failHMACPutBackend{b}
			})

			_, err := runRebuildOver(store, "--yes-re-bless", "--replicas-stopped")

			Expect(err).To(MatchError(ContainSubstring("rebuilding the inventory integrity value")))
			Expect(err).NotTo(MatchError(ContainSubstring("completes the repair")),
				"no key was minted here, so that advice must not appear")

			logged, readErr := os.ReadFile(logFile)
			Expect(readErr).NotTo(HaveOccurred())
			rec := logRecord(logged, "Inventory integrity rebuild failed; the store may already have been changed")
			Expect(rec).To(HaveKeyWithValue("key_state", "usable"))
		})

		It("refuses when neither a key nor a value is stored, and says a start will fix it", func() {
			// RebuildInventoryHMAC is a no-op with no key. Reporting success
			// would send the operator away believing they had a fix.
			// Both removed: with a value still stored the advice below is false,
			// and that case is the spec above.
			Expect(os.Remove(filepath.Join(caDir, "private/.inventory_hmac_key"))).To(Succeed())
			Expect(os.Remove(filepath.Join(caDir, ".inventory.hmac"))).To(Succeed())

			_, _, err := runRebuild("--cadir", caDir, "--yes-re-bless")
			Expect(err).To(MatchError(ContainSubstring("no inventory HMAC key is stored")))
			Expect(err).To(MatchError(ContainSubstring("starting the server will establish a baseline")))
		})
	})
})
