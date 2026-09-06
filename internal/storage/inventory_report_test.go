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
	"log/slog"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// failEntriesBackend is a structured backend whose row read fails.
type failEntriesBackend struct {
	Backend
	err error
}

func (b failEntriesBackend) Entries(context.Context) ([]InventoryEntry, error) {
	return nil, b.err
}

func (b failEntriesBackend) AppendEntry(context.Context, CertRecord, func([]byte) []byte) error {
	return nil
}

func (b failEntriesBackend) LatestSerialForSubject(context.Context, string) (string, error) {
	return "", nil
}

func (b failEntriesBackend) PruneEntries(context.Context, func(InventoryEntry) bool,
	func([]byte, InventoryEntry) []byte,
) ([]InventoryEntry, error) {
	return nil, nil
}

// emptyEntriesBackend answers as a structured backend with no decomposed rows,
// over whatever blob the embedded backend still holds.
type emptyEntriesBackend struct {
	Backend
}

func (emptyEntriesBackend) Entries(context.Context) ([]InventoryEntry, error) { return nil, nil }

func (emptyEntriesBackend) AppendEntry(context.Context, CertRecord, func([]byte) []byte) error {
	return nil
}

func (emptyEntriesBackend) LatestSerialForSubject(context.Context, string) (string, error) {
	return "", nil
}

func (emptyEntriesBackend) PruneEntries(context.Context, func(InventoryEntry) bool,
	func([]byte, InventoryEntry) []byte,
) ([]InventoryEntry, error) {
	return nil, nil
}

// failGetBackend fails reads of one key with a non-ErrNotExist error, which is
// what an unreadable store looks like as distinct from an absent value.
type failGetBackend struct {
	Backend
	key string
	err error
}

func (b failGetBackend) Get(ctx context.Context, key string) ([]byte, error) {
	if key == b.key {
		return nil, b.err
	}
	return b.Backend.Get(ctx, key)
}

var _ = Describe("InventoryIntegrityReport", func() {
	ctx := context.Background()

	Describe("on a blob backend", func() {
		It("reports a healthy inventory as verifying, and names the scheme", func() {
			svc := newFilesystemInventoryService()

			rep, err := svc.InventoryIntegrityReport(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(rep.Scheme).To(Equal("whole-blob-hmac"))
			Expect(rep.KeyState).To(Equal(HMACKeyUsable))
			Expect(rep.Entries).To(Equal(len(sampleInventoryLines)))
			Expect(rep.Verifies).To(BeTrue())
			Expect(rep.StoredHead).To(Equal(rep.ComputedHead))
		})

		It("reports a mismatch without returning ErrInventoryTampered", func() {
			// The whole reason this method exists: every ordinary read path is
			// fail-closed, so an operator diagnosing a CA that will not start
			// cannot use them. If this ever starts erroring, the command built
			// on it can no longer report anything.
			svc := newFilesystemInventoryService()

			// An entry the stored value does not cover, written straight to the
			// backend so nothing updates the head.
			blob, err := svc.readInventoryForHMAC(ctx)
			Expect(err).NotTo(HaveOccurred())
			extra := append(blob, []byte("0x0999 2026-01-01T00:00:00UTC 2036-01-01T00:00:00UTC /CN=ghost\n")...)
			Expect(svc.backend.Put(ctx, KeyInventory, extra, BlobPrivate)).To(Succeed())

			rep, err := svc.InventoryIntegrityReport(ctx)
			Expect(err).NotTo(HaveOccurred(), "reporting must not fail closed the way reading does")

			Expect(rep.Verifies).To(BeFalse())
			Expect(rep.Entries).To(Equal(len(sampleInventoryLines)+1),
				"the count must describe the inventory as it stands, which is what a rebuild would cover")
			Expect(rep.StoredHead).NotTo(BeEmpty())
			Expect(rep.ComputedHead).NotTo(BeEmpty())
			Expect(rep.StoredHead).NotTo(Equal(rep.ComputedHead))

			// And the ordinary path really is fail-closed, so the contrast
			// above is a real one rather than an assumption about it.
			_, readErr := svc.ReadInventory(ctx)
			Expect(readErr).To(MatchError(ErrInventoryTampered))
		})
	})

	Describe("on a structured backend", func() {
		It("names the hash-chain scheme", func() {
			svc, _ := newInventoryService()

			rep, err := svc.InventoryIntegrityReport(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(rep.Scheme).To(Equal("hash-chain"))
			Expect(rep.Entries).To(Equal(len(sampleInventoryLines)))
			Expect(rep.Verifies).To(BeTrue())
			Expect(rep.StoredHead).NotTo(BeEmpty())
			Expect(rep.StoredHead).To(Equal(rep.ComputedHead))
		})

		It("reports a mismatch on the path the failure is most likely to occur on", func() {
			// etcd, redis and the SQL dialects take this branch, and the
			// command's own documentation says the failure this repairs is most
			// likely there. Without a mismatch case, a report that returned nil
			// heads or folded the chain over the wrong entry set would satisfy
			// every assertion above.
			svc, backend := newInventoryService()

			// A row the persisted head does not cover: the same shape as an
			// append that lost its race.
			_, err := backend.db.NewInsert().
				Model(&sqlInventoryRow{
					Serial:    "0999",
					Subject:   "ghost.example.com",
					NotBefore: "2026-01-01T00:00:00UTC",
					NotAfter:  "2036-01-01T00:00:00UTC",
					State:     "valid",
				}).Exec(ctx)
			Expect(err).NotTo(HaveOccurred())

			rep, err := svc.InventoryIntegrityReport(ctx)
			Expect(err).NotTo(HaveOccurred(), "reporting must not fail closed the way reading does")

			Expect(rep.Scheme).To(Equal("hash-chain"))
			Expect(rep.Verifies).To(BeFalse())
			Expect(rep.Entries).To(Equal(len(sampleInventoryLines)+1),
				"the count must describe the inventory as it stands")
			Expect(rep.StoredHead).NotTo(BeEmpty())
			Expect(rep.ComputedHead).NotTo(BeEmpty())
			Expect(rep.StoredHead).NotTo(Equal(rep.ComputedHead))

			_, readErr := svc.InventoryEntries(ctx)
			Expect(readErr).To(MatchError(ErrInventoryTampered),
				"and the ordinary path really is fail-closed, so the contrast is real")
		})
	})

	Describe("when no baseline has been stored", func() {
		It("does not call an empty structured inventory with no baseline verified", func() {
			// Found by mutation: dropping the StoredHead != nil guard survives
			// every other spec, because hmac.Equal(nil, non-empty) is already
			// false. It differs in exactly one state -- both heads nil, where
			// hmac.Equal(nil, nil) is TRUE and a store that never wrote a
			// baseline would report as verifying.
			//
			// It has to be a STRUCTURED backend: computeInventoryHMAC folds the
			// chain from `var head []byte` and returns nil over an empty one,
			// whereas a blob backend returns HMAC-of-empty, which is 32 bytes
			// and not nil. A first attempt at this spec used a filesystem store
			// and passed without ever reaching the case it names.
			b := newSQLiteBackend()
			svc := NewWithBackend(b, "")
			Expect(svc.TouchInventory(ctx)).To(Succeed())
			_, err := svc.EnsureHMACKey(ctx)
			Expect(err).NotTo(HaveOccurred())

			rep, err := svc.InventoryIntegrityReport(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(rep.Entries).To(BeZero(), "premise: the inventory is empty")
			Expect(rep.StoredHead).To(BeNil(), "premise: no baseline was ever written")
			Expect(rep.ComputedHead).To(BeNil(),
				"premise: an empty chain folds to nil, which is what makes this case distinct")
			Expect(rep.KeyState).To(Equal(HMACKeyUsable))
			Expect(rep.Verifies).To(BeFalse(),
				"an absent baseline is not a match, even when there is nothing to cover")
		})

		It("separates a missing value from a mismatch", func() {
			// The caller distinguishes these two: one is a healthy CA that has
			// never run the verification path, the other is tampering. Nothing
			// pinned the difference, and the Verifies expression guards on
			// StoredHead != nil.
			svc := newFilesystemInventoryService()
			Expect(svc.backend.Delete(ctx, KeyInventoryHMAC)).To(Succeed())

			rep, err := svc.InventoryIntegrityReport(ctx)
			Expect(err).NotTo(HaveOccurred(), "an absent baseline is not an error")

			Expect(rep.StoredHead).To(BeNil())
			Expect(rep.ComputedHead).NotTo(BeEmpty(), "the key is usable, so a value is still computable")
			Expect(rep.KeyState).To(Equal(HMACKeyUsable))
			Expect(rep.Verifies).To(BeFalse())
		})
	})

	Describe("content the entry count does not describe", func() {
		It("counts lines the blob holds that are not entries", func() {
			// The blob scheme MACs the whole blob, so a torn write or an
			// injected fragment is covered by the value a rebuild re-asserts
			// while being invisible in Entries -- the operator's only
			// quantitative view of what they are about to sign over.
			svc := newFilesystemInventoryService()
			blob, err := svc.readInventoryForHMAC(ctx)
			Expect(err).NotTo(HaveOccurred())
			// Fewer than four fields: parseInventoryEntry's actual rejection
			// rule. A longer sentence would be *accepted* as an entry, which is
			// its own hazard but not the one this spec is about.
			junk := append(blob, []byte("TORN-WRITE-FRAGMENT\n\n")...)
			Expect(svc.backend.Put(ctx, KeyInventory, junk, BlobPrivate)).To(Succeed())

			rep, err := svc.InventoryIntegrityReport(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(rep.Entries).To(Equal(len(sampleInventoryLines)),
				"the junk line is not an entry")
			Expect(rep.UnparseableLines).To(Equal(1),
				"but it is in the blob the integrity value covers, so it must be reported")
		})

		It("reports none on a structured backend, whose entries are rows", func() {
			svc, _ := newInventoryService()
			rep, err := svc.InventoryIntegrityReport(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(rep.UnparseableLines).To(BeZero())
		})
	})

	Describe("when a structured backend cannot be read", func() {
		It("errors rather than reporting an empty inventory", func() {
			// The arm etcd, redis and the SQL dialects take, and the path the
			// command's own docs call the most likely site of this failure. An
			// Entries() failure folded into "no entries" would report an empty
			// inventory for a store that could not be read at all -- which is
			// the same shape as the legacy hazard below, arrived at by a
			// different route.
			svc, _ := newInventoryService()
			boom := errors.New("cluster unreachable")
			svc.backend = failEntriesBackend{Backend: svc.backend, err: boom}

			_, err := svc.InventoryIntegrityReport(ctx)

			Expect(err).To(MatchError(boom))
			Expect(err.Error()).To(ContainSubstring("reading inventory entries"))
		})
	})

	Describe("an undecomposed legacy inventory", func() {
		It("is detected from the data rather than the backend type", func() {
			// The detection added for the destruction-presented-as-repair
			// finding, and until now exercised only through the CLI. A
			// regression here would be caught by one integration spec and by
			// nothing in this package, which owns the method that computes it.
			svc := newFilesystemInventoryService()
			blob, err := svc.readInventoryForHMAC(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(blob).NotTo(BeEmpty(), "premise: the blob holds a real inventory")

			// Structured by type, with no decomposed rows, over a store whose
			// blob still holds everything: an etcd or Redis CA upgraded from a
			// pre-decomposition release and not yet started.
			svc.backend = emptyEntriesBackend{Backend: svc.backend}

			rep, err := svc.InventoryIntegrityReport(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(rep.Scheme).To(Equal("hash-chain"), "premise: it answers as a structured backend")
			Expect(rep.Entries).To(BeZero(), "premise: no decomposed rows exist yet")
			Expect(rep.LegacyUndecomposed).To(BeTrue(),
				"the blob holds parseable entries, so this store is not empty -- it is undecomposed")
		})

		It("is not claimed for a genuinely empty structured inventory", func() {
			// The other side, or the detection would refuse every new CA.
			b := newSQLiteBackend()
			svc := NewWithBackend(b, "")
			Expect(svc.TouchInventory(ctx)).To(Succeed())

			rep, err := svc.InventoryIntegrityReport(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(rep.Entries).To(BeZero())
			Expect(rep.LegacyUndecomposed).To(BeFalse(),
				"an empty structured inventory has no blob to be undecomposed from")
		})
	})

	Describe("when the store cannot be read", func() {
		It("errors rather than reporting an absent baseline", func() {
			// The ErrNotExist arm deliberately leaves StoredHead nil, and the
			// command renders that as "nothing to rebuild" and exits 0. If a
			// genuine read failure took the same arm, an operator whose store is
			// unreadable would be told their CA is fine.
			svc := newFilesystemInventoryService()
			boom := errors.New("backend unreachable")
			svc.backend = failGetBackend{Backend: svc.backend, key: KeyInventoryHMAC, err: boom}

			_, err := svc.InventoryIntegrityReport(ctx)

			Expect(err).To(HaveOccurred(), "an unreadable store is not an absent baseline")
			Expect(err).To(MatchError(boom))
			Expect(err.Error()).To(ContainSubstring("reading inventory HMAC"))
		})
	})

	DescribeTable("errors rather than reporting a state it never read",
		// Three of the four failure arms had no spec. Each must surface the
		// wrapped cause AND its own prefix, so an operator can tell which read
		// failed rather than being told their CA is fine.
		func(key, prefix string) {
			svc := newFilesystemInventoryService()
			boom := errors.New("backend unreachable")
			svc.backend = failGetBackend{Backend: svc.backend, key: key, err: boom}

			rep, err := svc.InventoryIntegrityReport(ctx)

			Expect(err).To(MatchError(boom))
			Expect(err.Error()).To(ContainSubstring(prefix))
			Expect(rep.KeyState).To(Equal(HMACKeyUnknown),
				"a report returned alongside an error must not assert a key state it never read")
		},
		// The blob arm's prefix is a substring of the other two, so it must be
		// asserted with its punctuation to discriminate at all.
		Entry("reading the inventory", KeyInventory, "reading inventory: "),
		Entry("reading the HMAC key", KeyHMACKey, "reading inventory HMAC key: "),
	)

	Describe("the stored HMAC key", func() {
		It("reports a wrong-length key without regenerating it", func() {
			// EnsureHMACKey regenerates a wrong-length key, and doing so is one
			// of the ways an inventory stops verifying in the first place. A
			// report that reached for it would perform the very act it exists
			// to describe, and would do it to an operator who had asked only to
			// look.
			svc := newFilesystemInventoryService()
			truncated := []byte("far too short")
			Expect(svc.backend.Put(ctx, KeyHMACKey, truncated, BlobPrivate)).To(Succeed())

			rep, err := svc.InventoryIntegrityReport(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(rep.KeyState).To(Equal(HMACKeyWrongLength))
			Expect(rep.ComputedHead).To(BeNil(), "nothing can be computed under an unusable key")
			Expect(rep.Verifies).To(BeFalse())

			after, err := svc.backend.Get(ctx, KeyHMACKey)
			Expect(err).NotTo(HaveOccurred())
			Expect(after).To(Equal(truncated), "the report must not have minted a new key")
		})

		It("reports an absent key as absent", func() {
			svc := newFilesystemInventoryService()
			Expect(svc.backend.Delete(ctx, KeyHMACKey)).To(Succeed())

			rep, err := svc.InventoryIntegrityReport(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(rep.KeyState).To(Equal(HMACKeyAbsent))
			Expect(rep.ComputedHead).To(BeNil())
			Expect(rep.Verifies).To(BeFalse())
		})
	})
})

var _ = Describe("the integrity-mismatch warning", func() {
	ctx := context.Background()

	It("names the supported repair on both mismatch sites", func() {
		// inventoryRepairHint exists as one constant so the two warnings cannot
		// drift, and it names a flag defined in another package. Nothing
		// asserted it, so dropping it from one site — the exact drift the single
		// definition prevents — was invisible.
		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		DeferCleanup(func() { slog.SetDefault(orig) })

		svc := newFilesystemInventoryService()
		blob, err := svc.readInventoryForHMAC(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(svc.backend.Put(ctx, KeyInventory,
			append(blob, []byte("0x0999 2026-01-01T00:00:00UTC 2036-01-01T00:00:00UTC /CN=ghost\n")...),
			BlobPrivate)).To(Succeed())

		// Each site driven separately, with the buffer reset between them.
		// Counting occurrences across one combined capture does not pin "both
		// sites carry it": one site emitting twice satisfies the same count,
		// which is how dropping the hint from compareInventoryMACLocked
		// survived this spec until the mutation exposed it.
		expectHint := func(what string, act func()) {
			GinkgoHelper()
			buf.Reset()
			act()
			out := buf.String()
			Expect(out).To(ContainSubstring(`"repair":`),
				"%s must name the supported repair", what)
			Expect(out).To(ContainSubstring("openvox-ca rebuild-inventory-hmac"), what)
			Expect(out).To(ContainSubstring("--yes-re-bless"), what)
		}

		// InventoryEntries, not ReadInventory: compareInventoryMACLocked is
		// reached from the entries path only, and driving the wrong call left
		// this half of the assertion exercising the other site.
		expectHint("the entries path's mismatch warning", func() {
			_, entErr := svc.InventoryEntries(ctx)
			Expect(entErr).To(MatchError(ErrInventoryTampered))
		})
		expectHint("the startup verification's mismatch warning", func() {
			Expect(svc.InitHMAC(ctx)).To(MatchError(ErrInventoryTampered))
		})
	})
})
