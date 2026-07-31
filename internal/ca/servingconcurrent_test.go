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

package ca_test

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// sharedLockBackend wraps a Backend with a lock table shared by every
// StorageService built on top of it.
//
// This exists because the filesystem backend implements no Locker, so
// StorageService.WithLock silently falls back to a *process-local* mutex keyed
// per service. Two CA instances built on separate services therefore take
// different mutexes, and a convergence assertion between them holds whether or
// not the lock coordinates anything — which is exactly the vacuous test the
// design warned about. Sharing one table models what etcd, Redis and SQL
// actually provide: mutual exclusion between processes.
type sharedLockBackend struct {
	storage.Backend
	mu       sync.Mutex
	locks    map[string]*sync.Mutex
	acquired []string
}

func newSharedLockBackend(base storage.Backend) *sharedLockBackend {
	return &sharedLockBackend{Backend: base, locks: map[string]*sync.Mutex{}}
}

func (b *sharedLockBackend) AcquireLock(_ context.Context, name string) (storage.Unlocker, error) {
	b.mu.Lock()
	m, ok := b.locks[name]
	if !ok {
		m = &sync.Mutex{}
		b.locks[name] = m
	}
	b.acquired = append(b.acquired, name)
	b.mu.Unlock()

	m.Lock()
	return &sharedUnlocker{m: m}, nil
}

// acquiredLocks returns the lock names taken so far, oldest first.
func (b *sharedLockBackend) acquiredLocks() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.acquired...)
}

// lockIndex is the position of a lock name in an acquisition record, or -1.
// Order matters as much as presence: the two paths must take the pair the same
// way round or they deadlock against each other.
func lockIndex(acquired []string, name string) int {
	for i, got := range acquired {
		if got == name {
			return i
		}
	}
	return -1
}

// resetLocks forgets the record, so a spec can scope its assertion to one call.
func (b *sharedLockBackend) resetLocks() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.acquired = nil
}

type sharedUnlocker struct {
	m    *sync.Mutex
	once sync.Once
}

func (u *sharedUnlocker) Unlock() error {
	u.once.Do(u.m.Unlock)
	return nil
}

var _ = Describe("Serving certificate across replicas", func() {
	const subject = "puppet.example.com"

	var (
		ctx     context.Context
		backend *sharedLockBackend
		dir     string
	)

	// newReplica builds an independent CA over the shared backend, as a
	// separate pod would: its own StorageService, its own in-memory state.
	newReplica := func() *ca.CA {
		GinkgoHelper()
		store := storage.NewWithBackend(backend, dir)
		replica := ca.New(store, ca.AutosignConfig{Mode: "off"}, subject)
		replica.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		replica.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(replica.Init(ctx)).To(Succeed())
		return replica
	}

	BeforeEach(func() {
		ctx = context.Background()
		dir = GinkgoT().TempDir()
		backend = newSharedLockBackend(storage.NewFilesystemBackend(dir))

		// Bootstrap the CA once so every replica loads the same CA material.
		bootstrap := storage.NewWithBackend(backend, dir)
		seed := ca.New(bootstrap, ca.AutosignConfig{Mode: "off"}, subject)
		seed.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(seed.Init(ctx)).To(Succeed())
	})

	It("issues exactly one certificate when replicas start simultaneously", func() {
		// The property the subject lock exists to guarantee. Without it both
		// replicas find no stored certificate, both mint, and the loser's
		// certificate is the one clients get while the winner serves another —
		// two live serving certificates for one name, only one of them stored.
		const replicas = 4
		cfg := ca.ServingConfig{Subject: subject}

		instances := make([]*ca.CA, replicas)
		for i := range instances {
			instances[i] = newReplica()
		}

		var (
			wg      sync.WaitGroup
			mu      sync.Mutex
			serials []string
		)
		start := make(chan struct{})
		for _, replica := range instances {
			wg.Add(1)
			go func(r *ca.CA) {
				defer GinkgoRecover()
				defer wg.Done()
				<-start
				got, err := r.EnsureServingCert(ctx, cfg)
				Expect(err).NotTo(HaveOccurred())
				mu.Lock()
				serials = append(serials, got.Leaf.SerialNumber.String())
				mu.Unlock()
			}(replica)
		}
		close(start)
		wg.Wait()

		Expect(serials).To(HaveLen(replicas))
		for _, s := range serials {
			Expect(s).To(Equal(serials[0]), "every replica must converge on one serial")
		}

		var issued uint64
		for _, r := range instances {
			issued += r.ServingCertIssued()
		}
		Expect(issued).To(Equal(uint64(1)), "exactly one replica may mint")
	})

	It("converges when replicas disagree about the configured names", func() {
		// Incomparable configurations -- a rename, where each side has a name
		// the other lacks -- which is what an ingress hostname change plus one
		// pod left on a stale ConfigMap produces. Neither list contains the
		// other, so a rule that mints only its own configured names has no
		// fixed point: the two replicas trade places on every maintenance pass
		// forever, each one adding an inventory row, a supersession entry and
		// eventually a permanent CRL entry that every agent downloads.
		//
		// Alternating passes rather than goroutines: the question is whether
		// the sequence terminates, not whether the lock serialises it.
		a := newReplica()
		b := newReplica()
		cfgA := ca.ServingConfig{Subject: subject, ExtraNames: []string{"a.example.com"}}
		cfgB := ca.ServingConfig{Subject: subject, ExtraNames: []string{"b.example.com"}}

		for i := 0; i < 6; i++ {
			Expect(a.EnsureServingCert(ctx, cfgA)).Error().NotTo(HaveOccurred())
			Expect(b.EnsureServingCert(ctx, cfgB)).Error().NotTo(HaveOccurred())
		}

		Expect(a.ServingCertIssued()+b.ServingCertIssued()).To(BeNumerically("<=", uint64(3)),
			"incomparable name lists must converge, not mint on every pass")

		final, err := a.EnsureServingCert(ctx, cfgA)
		Expect(err).NotTo(HaveOccurred())
		Expect(final.Issued).To(BeFalse(), "the fleet must reach a fixed point")
		Expect(final.Leaf.DNSNames).To(ContainElements("a.example.com", "b.example.com"),
			"the fixed point is the union, which satisfies both configurations")
	})

	It("sweeps the pending list under the same lock the mint path appends beneath", func() {
		// The sweep read-modify-writes the pending list; so does the mint path,
		// under the subject lock. Serialising them on different locks lets a
		// sweep write a list computed before a concurrent mint appended to it,
		// dropping that entry — and the superseded certificate then stays valid
		// for its full remaining life with nothing recording that it should not.
		//
		// This asserts the serialisation point rather than reproducing the
		// interleaving. The window is a few hundred microseconds wide, so a
		// timing-based spec would pass almost always whether or not the lock is
		// taken, which is worse than not testing it: the two paths take the same
		// lock or they do not, and that is a property the lock table can answer
		// deterministically.
		minter := newReplica()
		base := ca.ServingConfig{Subject: subject, RevokeAfter: time.Hour}

		// Something must be due, because the sweep only writes when it has
		// something to prune — the write that can erase a concurrent append.
		_, err := minter.EnsureServingCert(ctx, base)
		Expect(err).NotTo(HaveOccurred())
		dueNow := base
		dueNow.ExtraNames = []string{"alt1.example.com"}
		dueNow.RevokeAfter = time.Nanosecond
		_, err = minter.EnsureServingCert(ctx, dueNow)
		Expect(err).NotTo(HaveOccurred())

		backend.resetLocks()
		Expect(newReplica().ReconcileSuperseded(ctx, base)).To(Succeed())

		acquired := backend.acquiredLocks()
		Expect(acquired).To(ContainElements("serving", "subject:"+subject),
			"the sweep must serialise on both locks the mint path takes")
		Expect(lockIndex(acquired, "serving")).To(
			BeNumerically("<", lockIndex(acquired, "subject:"+subject)),
			"serving outside subject, or this deadlocks against a mint holding them the other way")
	})

	It("takes a fixed serving lock outside the per-subject one on both paths", func() {
		// The lock that actually makes the read-modify-write mutual between
		// replicas, and the one nothing else in the suite would miss. The
		// per-subject lock cannot do this job: it is derived from each
		// replica's own hostname, and replicas are explicitly allowed to
		// disagree about that, so two of them take different subject locks and
		// exclude each other from nothing. Both multi-replica specs above give
		// every replica the same subject, so they pass either way -- which is
		// why the guarantee is asserted here by name rather than inferred from
		// them.
		//
		// Both paths, because the guarantee is mutual exclusion *between* them:
		// the mint appends to the pending list and the sweep rewrites it, and
		// one of them holding a lock the other does not take serialises nothing.
		cfg := ca.ServingConfig{Subject: subject, RevokeAfter: time.Hour}

		backend.resetLocks()
		_, err := newReplica().EnsureServingCert(ctx, cfg)
		Expect(err).NotTo(HaveOccurred())
		minted := backend.acquiredLocks()

		backend.resetLocks()
		Expect(newReplica().ReconcileSuperseded(ctx, cfg)).To(Succeed())
		swept := backend.acquiredLocks()

		for _, acquired := range []struct {
			path  string
			locks []string
		}{{"the mint", minted}, {"the sweep", swept}} {
			Expect(acquired.locks).To(ContainElements("serving", "subject:"+subject),
				acquired.path+" must take the fixed serving lock as well as the subject one")
			Expect(lockIndex(acquired.locks, "serving")).To(
				BeNumerically("<", lockIndex(acquired.locks, "subject:"+subject)),
				acquired.path+" must take them serving-first, or the two paths deadlock")
		}
	})

	It("prunes what is due and keeps what is not", func() {
		// The partial-prune branch: with a 24h default, any second reissue
		// inside that window leaves one entry due and one pending. Writing nil
		// instead of the survivors would discard the second, and every spec
		// that records a single entry would still pass.
		minter := newReplica()
		base := ca.ServingConfig{Subject: subject, RevokeAfter: time.Hour}
		// Each reissue is forced by widening the name set, which the stored
		// certificate then does not cover. An over-large renew-before would not
		// work: servingRenewBefore clamps it, precisely so a window at or beyond
		// the lifetime cannot make every certificate permanently due.
		names := 0
		forced := func(cfg ca.ServingConfig) ca.ServingConfig {
			names++
			cfg.ExtraNames = append(append([]string{}, cfg.ExtraNames...),
				fmt.Sprintf("alt%d.example.com", names))
			return cfg
		}

		_, err := minter.EnsureServingCert(ctx, base)
		Expect(err).NotTo(HaveOccurred())

		// First supersession is due immediately, second is an hour out.
		dueNow := forced(base)
		dueNow.RevokeAfter = time.Nanosecond
		second, err := minter.EnsureServingCert(ctx, dueNow)
		Expect(err).NotTo(HaveOccurred())
		_, err = minter.EnsureServingCert(ctx, forced(base))
		Expect(err).NotTo(HaveOccurred())

		Expect(minter.ReconcileSuperseded(ctx, base)).To(Succeed())

		raw, err := storage.NewWithBackend(backend, dir).GetServingSuperseded(ctx)
		Expect(err).NotTo(HaveOccurred())
		var pending []struct {
			Serial string `json:"serial"`
		}
		Expect(json.Unmarshal(raw, &pending)).To(Succeed())
		Expect(pending).To(HaveLen(1), "the not-yet-due entry must survive the prune")
		Expect(pending[0].Serial).To(Equal(fmt.Sprintf("%X", second.Leaf.SerialNumber)))
	})
})
