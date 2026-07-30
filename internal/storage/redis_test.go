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
	"fmt"
	"io/fs"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// newMiniredis starts an in-process fake Redis and returns a go-redis client
// wired to it plus a teardown.
func newMiniredis() (*miniredis.Miniredis, *redis.Client, func()) {
	mr, err := miniredis.Run()
	Expect(err).NotTo(HaveOccurred())
	cli := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return mr, cli, func() {
		_ = cli.Close()
		mr.Close()
	}
}

func newRedisBackend(cli redis.UniversalClient, prefix string) *RedisBackend {
	b := NewRedisBackendFromClient(cli, prefix, 5*time.Second, 5*time.Second)
	Expect(b.EnsureReady(context.Background())).NotTo(HaveOccurred())
	return b
}

var _ = Describe("RedisBackend", func() {
	It("supports Put/Get/Delete round-trips", func() {
		_, cli, stop := newMiniredis()
		defer stop()
		b := newRedisBackend(cli, "test1")

		_, err := b.Get(context.Background(), KeyCACert)
		Expect(err).To(MatchError(fs.ErrNotExist))
		ok, err := b.Exists(context.Background(), KeyCACert)
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeFalse())

		payload := []byte("-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n")
		Expect(b.Put(context.Background(), KeyCACert, payload, BlobPublic)).NotTo(HaveOccurred())
		got, err := b.Get(context.Background(), KeyCACert)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(payload))
		ok, err = b.Exists(context.Background(), KeyCACert)
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeTrue())

		Expect(b.Delete(context.Background(), KeyCACert)).NotTo(HaveOccurred())
		err = b.Delete(context.Background(), KeyCACert)
		Expect(err).To(MatchError(fs.ErrNotExist))
	})

	It("records a ModTime on write", func() {
		_, cli, stop := newMiniredis()
		defer stop()
		b := newRedisBackend(cli, "test-modtime")

		_, err := b.ModTime(context.Background(), KeyCRL)
		Expect(err).To(MatchError(fs.ErrNotExist))

		before := time.Now().Add(-time.Second)
		Expect(b.Put(context.Background(), KeyCRL, []byte("crl-data"), BlobPublic)).NotTo(HaveOccurred())
		mt, err := b.ModTime(context.Background(), KeyCRL)
		Expect(err).NotTo(HaveOccurred())
		Expect(mt.Before(before)).To(BeFalse(), "ModTime = %v, expected near now", mt)
		Expect(mt.After(time.Now().Add(time.Second))).To(BeFalse(), "ModTime = %v, expected near now", mt)
	})

	It("lists keys by prefix", func() {
		_, cli, stop := newMiniredis()
		defer stop()
		b := newRedisBackend(cli, "test-list")

		subjects := []string{"alpha.example.com", "beta.example.com", "gamma.example.com"}
		for _, s := range subjects {
			Expect(b.Put(context.Background(), CSRKey(s), []byte("csr:"+s), BlobPublic)).NotTo(HaveOccurred())
		}
		Expect(b.Put(context.Background(), CertKey("alpha.example.com"), []byte("cert"), BlobPublic)).NotTo(HaveOccurred())

		csrs, err := b.List(context.Background(), csrPrefix)
		Expect(err).NotTo(HaveOccurred())
		sort.Strings(csrs)
		want := []string{
			CSRKey("alpha.example.com"),
			CSRKey("beta.example.com"),
			CSRKey("gamma.example.com"),
		}
		Expect(fmt.Sprint(csrs)).To(Equal(fmt.Sprint(want)))

		certs, err := b.List(context.Background(), certPrefix)
		Expect(err).NotTo(HaveOccurred())
		Expect(len(certs) == 1 && certs[0] == CertKey("alpha.example.com")).To(BeTrue(), "List cert = %v, want [%s]", certs, CertKey("alpha.example.com"))

		_, err = b.List(context.Background(), "bogus/")
		Expect(err).To(HaveOccurred())
	})

	// TestRedisBackendHonoursCallerContext is the negative case for the ctx
	// propagation contract: an already-cancelled caller context must reach
	// the backend and short-circuit the operation. Without ctx propagation
	// the call would proceed until b.timeout fired (5s in this fixture).
	It("honours an already-cancelled caller context", func() {
		_, cli, stop := newMiniredis()
		defer stop()
		b := newRedisBackend(cli, "test-ctx")

		cancelled, cancel := context.WithCancel(context.Background())
		cancel()

		deadline := time.Now().Add(500 * time.Millisecond)
		_, err := b.Get(cancelled, KeyCACert)
		Expect(err).To(MatchError(context.Canceled))
		Expect(time.Now().After(deadline)).To(BeFalse(), "Get took longer than 500ms; ctx cancellation did not short-circuit")

		// Positive: a fresh non-cancelled ctx still completes normally.
		_, err = b.Get(context.Background(), KeyCACert)
		Expect(err).To(MatchError(fs.ErrNotExist))
	})

	// TestFilesystemBackendHonoursCallerContext mirrors the negative case for
	// the filesystem backend, which honours ctx only at operation start since
	// individual syscalls cannot be interrupted.
	It("honours an already-cancelled caller context on the filesystem backend", func() {
		dir := GinkgoT().TempDir()
		b := NewFilesystemBackend(dir)
		Expect(b.EnsureReady(context.Background())).NotTo(HaveOccurred())

		cancelled, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := b.Get(cancelled, KeyCACert)
		Expect(err).To(MatchError(context.Canceled))
		err = b.Put(cancelled, KeyCACert, []byte("x"), BlobPublic)
		Expect(err).To(MatchError(context.Canceled))

		// Positive: live ctx still works.
		Expect(b.Put(context.Background(), KeyCACert, []byte("ok"), BlobPublic)).NotTo(HaveOccurred())
	})

	// TestRedisBackendListMultiPage verifies that List correctly walks every
	// SCAN page when the result set is larger than the per-page COUNT (100).
	// Before each page got its own deadline, a single fixed-deadline ctx for
	// the whole loop could expire mid-walk on slow links and silently truncate
	// the listing.
	It("walks every SCAN page for large result sets", func() {
		_, cli, stop := newMiniredis()
		defer stop()
		b := newRedisBackend(cli, "test-multipage")

		const totalCSRs = 275 // > 2x the SCAN COUNT of 100 → at least 3 pages
		for i := range totalCSRs {
			subj := fmt.Sprintf("node-%03d.example.com", i)
			Expect(b.Put(context.Background(), CSRKey(subj), []byte("csr-payload"), BlobPublic)).NotTo(HaveOccurred())
		}

		got, err := b.List(context.Background(), csrPrefix)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(HaveLen(totalCSRs))

		// Confirm uniqueness — duplicate cursor handling must not double-list
		// a single key across pages.
		seen := make(map[string]bool, len(got))
		for _, k := range got {
			Expect(seen[k]).To(BeFalse(), "duplicate key %q in multi-page List output", k)
			seen[k] = true
		}
	})

	// TestRedisBackendAcquireLockBackoffSurvivesManyRetries exercises sustained
	// lock contention so the contended caller traverses the full backoff
	// schedule (50 → 100 → 200 → 400 → 500ms) several times. The test
	// guards two properties:
	//   - the loop terminates and acquires the lock once the holder releases
	//     (positive path);
	//   - goroutine population during the wait stays bounded (smoke check
	//     that the backoff loop is not spawning per-iteration goroutines).
	It("survives many backoff retries under sustained contention", func() {
		_, cli, stop := newMiniredis()
		defer stop()
		a := newRedisBackend(cli, "test-backoff")
		b := newRedisBackend(cli, "test-backoff")
		defer a.Close()
		defer b.Close()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		holder, err := a.AcquireLock(ctx, "crl")
		Expect(err).NotTo(HaveOccurred())

		baseline := runtime.NumGoroutine()

		bDone := make(chan struct{})
		bAcquired := make(chan struct{})
		go func() {
			defer close(bDone)
			bCtx, bCancel := context.WithTimeout(ctx, 5*time.Second)
			defer bCancel()
			ul, err := b.AcquireLock(bCtx, "crl")
			if err != nil {
				return
			}
			close(bAcquired)
			_ = ul.Unlock()
		}()

		// While B traverses multiple backoff iterations (holder still owns the
		// lock), the goroutine population must stay bounded: a backoff loop that
		// spawned a goroutine per retry would blow past this ceiling. Poll
		// instead of fixed-sleeping so a loaded runner doesn't flake, and assert
		// the bound holds for the whole contention window rather than at one
		// instant.
		Consistently(func() int { return runtime.NumGoroutine() - baseline }, 2*time.Second, 50*time.Millisecond).
			Should(BeNumerically("<=", 5), "goroutine count grew during contention (baseline=%d)", baseline)

		Expect(holder.Unlock()).NotTo(HaveOccurred())
		select {
		case <-bAcquired:
		case <-time.After(2 * time.Second):
			Fail("B never acquired the lock after A unlocked")
		}
		<-bDone
	})

	// TestRedisBackendAcquireLockCancelDuringBackoff verifies the negative
	// path: if the caller cancels mid-retry, AcquireLock returns promptly
	// with the context error rather than spinning until a holder releases.
	It("returns promptly when the caller cancels during backoff", func() {
		_, cli, stop := newMiniredis()
		defer stop()
		a := newRedisBackend(cli, "test-cancel")
		b := newRedisBackend(cli, "test-cancel")
		defer a.Close()
		defer b.Close()

		holder, err := a.AcquireLock(context.Background(), "crl")
		Expect(err).NotTo(HaveOccurred())
		defer holder.Unlock()

		bCtx, bCancel := context.WithCancel(context.Background())
		errCh := make(chan error, 1)
		go func() {
			_, err := b.AcquireLock(bCtx, "crl")
			errCh <- err
		}()

		// Let B enter the retry loop, then cancel.
		time.Sleep(120 * time.Millisecond)
		bCancel()

		select {
		case err := <-errCh:
			Expect(err).To(MatchError(context.Canceled))
		case <-time.After(2 * time.Second):
			Fail("AcquireLock did not honour ctx cancellation in the backoff loop")
		}
	})

	// TestRedisBackendAppendLineConcurrent hammers AppendLine from several
	// goroutines across two backends (simulating two replicas on one Redis) and
	// asserts no lines are lost — the Lua append script is atomic server-side.
	It("loses no lines under concurrent AppendLine", func() {
		_, cli, stop := newMiniredis()
		defer stop()
		a := newRedisBackend(cli, "test-append")
		b := newRedisBackend(cli, "test-append")

		const writers = 4
		const perWriter = 25
		var wg sync.WaitGroup
		wg.Add(writers)
		for w := range writers {
			backend := a
			if w%2 == 1 {
				backend = b
			}
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				for i := range perWriter {
					line := fmt.Sprintf("w%d-i%d\n", w, i)
					Expect(backend.AppendLine(context.Background(), KeyInventory, []byte(line), BlobPrivate)).NotTo(HaveOccurred())
				}
			}()
		}
		wg.Wait()

		data, err := a.Get(context.Background(), KeyInventory)
		Expect(err).NotTo(HaveOccurred())
		lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte{'\n'})
		Expect(lines).To(HaveLen(writers*perWriter), "got %d lines, want %d (no lines were lost?)", len(lines), writers*perWriter)
	})

	It("round-trips end to end via the StorageService", func() {
		_, cli, stop := newMiniredis()
		defer stop()
		backend := newRedisBackend(cli, "test-service")
		svc := NewWithBackend(backend, filepath.Join(GinkgoT().TempDir(), "private"))

		Expect(svc.EnsureDirs(context.Background())).NotTo(HaveOccurred())
		Expect(svc.SaveCACert(context.Background(), []byte("ca-cert-pem"))).NotTo(HaveOccurred())
		ok, _ := svc.HasCACert(context.Background())
		Expect(ok).To(BeTrue(), "HasCACert = false after SaveCACert")
		Expect(svc.WriteSerial(context.Background(), "0001")).NotTo(HaveOccurred())
		got, err := svc.GetSerial(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(string(got)).To(Equal("0001"))
		Expect(svc.InitHMAC(context.Background())).NotTo(HaveOccurred())
		const line1 = "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1"
		const line2 = "0002 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node2"
		Expect(svc.AppendInventory(context.Background(), line1)).NotTo(HaveOccurred())
		Expect(svc.AppendInventory(context.Background(), line2)).NotTo(HaveOccurred())
		inv, err := svc.ReadInventory(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(string(inv)).To(Equal(line1 + "\n" + line2 + "\n"))

		// Re-appending line1's serial (0001) under a different subject must be
		// rejected by the blob-path duplicate scan, and must leave the inventory
		// untouched.
		dup := "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node3"
		Expect(svc.AppendInventory(context.Background(), dup)).To(MatchError(ErrDuplicateSerial))
		inv, err = svc.ReadInventory(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(string(inv)).To(Equal(line1 + "\n" + line2 + "\n"))

		Expect(svc.SaveCSR(context.Background(), "node1", []byte("csr-pem"))).NotTo(HaveOccurred())
		Expect(svc.SaveCert(context.Background(), "node1", []byte("cert-pem"))).NotTo(HaveOccurred())
		csrs, err := svc.ListCSRs(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(len(csrs) == 1 && csrs[0] == "node1").To(BeTrue(), "ListCSRs = %v, want [node1]", csrs)
		certs, err := svc.ListCerts(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(len(certs) == 1 && certs[0] == "node1").To(BeTrue(), "ListCerts = %v, want [node1]", certs)
	})

	// TestRedisBackendAcquireLockMutualExclusion asserts two replicas sharing a
	// Redis cannot both hold the same lock at once.
	It("enforces mutual exclusion across replicas", func() {
		_, cli, stop := newMiniredis()
		defer stop()
		a := newRedisBackend(cli, "test-lock-mutex")
		b := newRedisBackend(cli, "test-lock-mutex")
		defer a.Close()
		defer b.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		ulA, err := a.AcquireLock(ctx, "crl")
		Expect(err).NotTo(HaveOccurred())

		type result struct {
			got time.Time
			err error
		}
		ch := make(chan result, 1)
		startB := time.Now()
		go func() {
			ul, err := b.AcquireLock(ctx, "crl")
			res := result{got: time.Now(), err: err}
			if err == nil {
				_ = ul.Unlock()
			}
			ch <- res
		}()

		// Give B time to attempt and block on the SET NX retry loop.
		time.Sleep(200 * time.Millisecond)
		Expect(ulA.Unlock()).NotTo(HaveOccurred())

		select {
		case res := <-ch:
			Expect(res.err).NotTo(HaveOccurred())
			waited := res.got.Sub(startB)
			Expect(waited).To(BeNumerically(">=", 150*time.Millisecond), "B acquired after %v; expected to wait ~200ms while A held the lock", waited)
		case <-time.After(5 * time.Second):
			Fail("B never acquired the lock")
		}
	})

	// TestRedisBackendAcquireLockDistinctNames asserts distinct lock names do
	// not contend.
	It("does not contend on distinct lock names", func() {
		_, cli, stop := newMiniredis()
		defer stop()
		b := newRedisBackend(cli, "test-lock-distinct")
		defer b.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		ul1, err := b.AcquireLock(ctx, "subject:alpha")
		Expect(err).NotTo(HaveOccurred())
		ul2, err := b.AcquireLock(ctx, "subject:beta")
		Expect(err).NotTo(HaveOccurred())
		Expect(ul1.Unlock()).NotTo(HaveOccurred())
		Expect(ul2.Unlock()).NotTo(HaveOccurred())
	})

	// TestRedisBackendAcquireLockSerialisesConcurrentCallers asserts that many
	// callers across two backends enter the critical section one-at-a-time.
	It("serialises many concurrent callers", func() {
		_, cli, stop := newMiniredis()
		defer stop()
		a := newRedisBackend(cli, "test-lock-serial")
		b := newRedisBackend(cli, "test-lock-serial")
		defer a.Close()
		defer b.Close()

		const workers = 6
		var inCritical atomic.Int32
		var maxConcurrent atomic.Int32
		var wg sync.WaitGroup
		wg.Add(workers)
		for i := range workers {
			backend := a
			if i%2 == 1 {
				backend = b
			}
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				ul, err := backend.AcquireLock(ctx, "crl")
				Expect(err).NotTo(HaveOccurred())
				cur := inCritical.Add(1)
				for {
					m := maxConcurrent.Load()
					if cur <= m || maxConcurrent.CompareAndSwap(m, cur) {
						break
					}
				}
				time.Sleep(20 * time.Millisecond)
				inCritical.Add(-1)
				Expect(ul.Unlock()).NotTo(HaveOccurred())
			}()
		}
		wg.Wait()
		Expect(maxConcurrent.Load()).To(Equal(int32(1)), "lock did not serialise writers")
	})

	// TestRedisBackendWithLockCrossBackend asserts StorageService.WithLock
	// coordinates across two StorageService instances sharing a Redis.
	It("coordinates WithLock across backends sharing a Redis", func() {
		_, cli, stop := newMiniredis()
		defer stop()
		a := newRedisBackend(cli, "test-withlock")
		b := newRedisBackend(cli, "test-withlock")
		svcA := NewWithBackend(a, filepath.Join(GinkgoT().TempDir(), "a"))
		svcB := NewWithBackend(b, filepath.Join(GinkgoT().TempDir(), "b"))

		var counter atomic.Int32
		var maxSeen atomic.Int32
		var wg sync.WaitGroup
		wg.Add(4)
		for i := range 4 {
			svc := svcA
			if i%2 == 1 {
				svc = svcB
			}
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				err := svc.WithLock(ctx, "crl", func() error {
					cur := counter.Add(1)
					for {
						m := maxSeen.Load()
						if cur <= m || maxSeen.CompareAndSwap(m, cur) {
							break
						}
					}
					time.Sleep(20 * time.Millisecond)
					counter.Add(-1)
					return nil
				})
				Expect(err).NotTo(HaveOccurred())
			}()
		}
		wg.Wait()
		Expect(maxSeen.Load()).To(Equal(int32(1)))
	})

	// RedisConfigDefaults pins the preserved backward-compatibility contract:
	// a zero RedisConfig must default its key prefix to "puppet-ca" (mirrors
	// EtcdConfigDefaults). Renaming this default would silently orphan every
	// existing deployment's keyspace.
	It("defaults the key prefix to puppet-ca on a zero config", func() {
		cfg := RedisConfig{}
		cfg.applyDefaults()
		Expect(cfg.DialTimeout).To(Equal(5*time.Second), "DialTimeout = %v, want 5s", cfg.DialTimeout)
		Expect(cfg.RequestTimeout).To(Equal(5*time.Second), "RequestTimeout = %v, want 5s", cfg.RequestTimeout)
		Expect(cfg.LockTTL).To(Equal(30*time.Second), "LockTTL = %v, want 30s", cfg.LockTTL)
		Expect(cfg.KeyPrefix).To(Equal("puppet-ca"), "KeyPrefix = %q, want puppet-ca", cfg.KeyPrefix)
	})

	It("strips a trailing colon from KeyPrefix", func() {
		cfg := RedisConfig{KeyPrefix: "custom:"}
		cfg.applyDefaults()
		Expect(cfg.KeyPrefix).To(Equal("custom"), "KeyPrefix trailing colon not stripped: %q", cfg.KeyPrefix)
	})

	// RedisPhysicalKey pins the logical→physical key layout (mirrors
	// EtcdPhysicalKey) and the "../empty-segment rejection contract. The
	// prefix uses ":" as the Redis separator.
	Describe("RedisPhysicalKey", func() {
		b := &RedisBackend{prefix: "puppet-ca"}
		DescribeTable("maps logical keys to physical keys",
			func(logical, want string, wantErr bool) {
				got, err := b.physicalKey(logical)
				if wantErr {
					Expect(err).To(HaveOccurred(), "physicalKey(%q): err = %v, wantErr = %v", logical, err, wantErr)
				} else {
					Expect(err).NotTo(HaveOccurred(), "physicalKey(%q): err = %v, wantErr = %v", logical, err, wantErr)
					Expect(got).To(Equal(want), "physicalKey(%q) = %q, want %q", logical, got, want)
				}
			},
			Entry(nil, KeyCACert, "puppet-ca:ca:cert", false),
			Entry(nil, KeyCAKey, "puppet-ca:ca:key", false),
			Entry(nil, KeyCAPubKey, "puppet-ca:ca:pubkey", false),
			Entry(nil, KeyCRL, "puppet-ca:ca:crl", false),
			Entry(nil, KeySerial, "puppet-ca:serial", false),
			Entry(nil, KeyInventory, "puppet-ca:inventory:data", false),
			Entry(nil, KeyInventoryHMAC, "puppet-ca:inventory:hmac", false),
			Entry(nil, KeyHMACKey, "puppet-ca:private:hmac_key", false),
			// See the etcd table: an omission here is invisible until runtime.
			Entry(nil, KeyServingCert, "puppet-ca:serving:cert", false),
			Entry(nil, KeyServingKey, "puppet-ca:private:serving_key", false),
			Entry(nil, KeyServingSuperseded, "puppet-ca:serving:superseded", false),
			Entry(nil, CSRKey("node1.example.com"), "puppet-ca:requests:node1.example.com", false),
			Entry(nil, CertKey("node1.example.com"), "puppet-ca:signed:node1.example.com", false),
			Entry(nil, "", "", true),
			Entry(nil, "unknown", "", true),
			Entry(nil, "../evil", "", true),
			Entry(nil, CSRKey("../evil"), "", true),
		)
	})

	// TestRedisBackendUnlockIdempotentOnExpiry verifies that Unlock after lock
	// TTL has elapsed does not error and does not interfere with a subsequent
	// AcquireLock holder — i.e. the unlock script's token check protects us.
	It("makes Unlock idempotent after the lock TTL expires", func() {
		mr, cli, stop := newMiniredis()
		defer stop()
		// Short TTL so we can simulate expiry via miniredis's time control.
		a := NewRedisBackendFromClient(cli, "test-expiry", 5*time.Second, 100*time.Millisecond)
		Expect(a.EnsureReady(context.Background())).NotTo(HaveOccurred())
		defer a.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		ul, err := a.AcquireLock(ctx, "crl")
		Expect(err).NotTo(HaveOccurred())

		// Fast-forward past the lock TTL in miniredis; the key is now gone.
		mr.FastForward(5 * time.Second)

		// A different holder can now acquire.
		b := NewRedisBackendFromClient(cli, "test-expiry", 5*time.Second, 100*time.Millisecond)
		ul2, err := b.AcquireLock(ctx, "crl")
		Expect(err).NotTo(HaveOccurred())

		// Unlocking the original holder must not delete B's new lock (token mismatch).
		Expect(ul.Unlock()).NotTo(HaveOccurred())

		// B's unlock should still succeed.
		Expect(ul2.Unlock()).NotTo(HaveOccurred())
	})
})
