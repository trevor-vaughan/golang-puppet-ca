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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// dialServing completes one TLS handshake against a listener configured exactly
// as the server configures its own, and returns the certificate presented.
//
// A real handshake rather than an inspection of tls.Config: the property under
// test is that a client receives the self-provisioned certificate, and the two
// are only the same thing if GetCertificate is wired up correctly.
func dialServing(holder *servingCertHolder, roots *x509.CertPool, serverName string) *x509.Certificate {
	GinkgoHelper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(func() { _ = ln.Close() })

	tlsLn := tls.NewListener(ln, &tls.Config{
		GetCertificate: holder.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	})
	go func() {
		defer GinkgoRecover()
		conn, err := tlsLn.Accept()
		if err != nil {
			return
		}
		_ = conn.(*tls.Conn).HandshakeContext(context.Background())
		_ = conn.Close()
	}()

	client, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		RootCAs:    roots,
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	})
	Expect(err).NotTo(HaveOccurred())
	defer func() { _ = client.Close() }()

	state := client.ConnectionState()
	Expect(state.PeerCertificates).NotTo(BeEmpty())
	return state.PeerCertificates[0]
}

var _ = Describe("self-provisioned serving certificate", func() {
	const hostname = "puppet.example.com"

	var (
		ctx    context.Context
		store  *storage.StorageService
		myCA   *ca.CA
		cfg    *serverConfig
		roots  *x509.CertPool
		holder *servingCertHolder
	)

	BeforeEach(func() {
		ctx = context.Background()
		store = storage.New(GinkgoT().TempDir())
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, hostname)
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())

		roots = x509.NewCertPool()
		roots.AddCert(myCA.CACert)

		cfg = &serverConfig{TLSSelfProvision: true, Hostname: hostname}
		holder = &servingCertHolder{}
	})

	It("serves a certificate a client verifies against the CA", func() {
		Expect(ensureServingCert(ctx, myCA, cfg, holder)).To(Succeed())

		presented := dialServing(holder, roots, hostname)
		Expect(presented.Subject.CommonName).To(Equal(hostname))
	})

	It("serves under a configured extra name", func() {
		cfg.TLSSelfProvisionNames = []string{"openvox-ca.puppet.svc.cluster.local"}
		Expect(ensureServingCert(ctx, myCA, cfg, holder)).To(Succeed())

		presented := dialServing(holder, roots, "openvox-ca.puppet.svc.cluster.local")
		Expect(presented.Subject.CommonName).To(Equal(hostname))
	})

	It("presents the renewed certificate on the next handshake, with no restart", func() {
		// GetCertificate is consulted per handshake, which is the whole reason
		// the holder exists: rotation must not need a listener rebuild.
		Expect(ensureServingCert(ctx, myCA, cfg, holder)).To(Succeed())
		before := dialServing(holder, roots, hostname)

		// Force the next pass to reissue by adding a name the stored
		// certificate does not cover. An over-large renew-before is clamped, so
		// it cannot be used to force one.
		cfg.TLSSelfProvisionNames = []string{"alt.example.com"}
		Expect(ensureServingCert(ctx, myCA, cfg, holder)).To(Succeed())

		after := dialServing(holder, roots, hostname)
		Expect(after.SerialNumber).NotTo(Equal(before.SerialNumber))
	})

	It("is rejected by a client that does not trust the CA", func() {
		// Confirms the handshake above is actually verifying, rather than
		// succeeding because verification was never attempted.
		Expect(ensureServingCert(ctx, myCA, cfg, holder)).To(Succeed())

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = ln.Close() }()
		tlsLn := tls.NewListener(ln, &tls.Config{
			GetCertificate: holder.GetCertificate,
			MinVersion:     tls.VersionTLS12,
		})
		go func() {
			defer GinkgoRecover()
			if conn, err := tlsLn.Accept(); err == nil {
				_ = conn.(*tls.Conn).HandshakeContext(context.Background())
				_ = conn.Close()
			}
		}()

		_, err = tls.Dial("tcp", ln.Addr().String(), &tls.Config{
			RootCAs:    x509.NewCertPool(),
			ServerName: hostname,
			MinVersion: tls.VersionTLS12,
		})
		Expect(err).To(HaveOccurred())
	})

	It("counts an issuance and leaves the failure counter alone", func() {
		Expect(ensureServingCert(ctx, myCA, cfg, holder)).To(Succeed())
		Expect(myCA.ServingCertIssued()).To(Equal(uint64(1)))
		Expect(myCA.ServingRenewalFailureCount()).To(BeZero())

		// A reuse must not count as an issuance, or the churn signal is noise.
		Expect(ensureServingCert(ctx, myCA, cfg, holder)).To(Succeed())
		Expect(myCA.ServingCertIssued()).To(Equal(uint64(1)))
	})

	It("stores the certificate where a restart will find it", func() {
		Expect(ensureServingCert(ctx, myCA, cfg, holder)).To(Succeed())

		certPEM, err := store.GetServingCert(ctx)
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(certPEM)
		Expect(block).NotTo(BeNil())
		Expect(block.Type).To(Equal("CERTIFICATE"))

		keyPEM, err := store.GetServingKey(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(keyPEM).NotTo(BeEmpty())
	})
})

var _ = Describe("runMaintenance", func() {
	It("returns immediately when no task is registered", func() {
		// The loop is started only if something registered, so this is the
		// belt to that braces: no goroutine spins on an empty task list.
		runMaintenance(context.Background(), time.Millisecond, nil)
	})

	It("runs every task once before the first tick and stops on cancellation", func() {
		ctx, cancel := context.WithCancel(context.Background())
		ran := make(chan string, 2)
		tasks := []maintenanceTask{
			{name: "a", run: func(context.Context) { ran <- "a" }},
			{name: "b", run: func(context.Context) { ran <- "b" }},
		}

		done := make(chan struct{})
		go func() {
			defer close(done)
			runMaintenance(ctx, time.Hour, tasks)
		}()

		Eventually(ran).Should(Receive(Equal("a")))
		Eventually(ran).Should(Receive(Equal("b")))
		cancel()
		Eventually(done).Should(BeClosed())
	})

	It("repeats every task on each tick", func() {
		// Each tenant is independently gated but they share one loop, so a
		// second pass has to run all of them, not just the one that had work.
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var a, b atomic.Int64
		tasks := []maintenanceTask{
			{name: "a", run: func(context.Context) { a.Add(1) }},
			{name: "b", run: func(context.Context) { b.Add(1) }},
		}
		go runMaintenance(ctx, 10*time.Millisecond, tasks)

		Eventually(a.Load).Should(BeNumerically(">=", 3))
		Expect(b.Load()).To(BeNumerically("~", a.Load(), 1),
			"both tasks run on every pass, not one per tick")
	})
})

var _ = Describe("serving certificate encrypted at rest", func() {
	const hostname = "puppet.example.com"

	var (
		ctx    context.Context
		store  *storage.StorageService
		myCA   *ca.CA
		cfg    *serverConfig
		roots  *x509.CertPool
		holder *servingCertHolder
	)

	BeforeEach(func() {
		ctx = context.Background()
		store = storage.New(GinkgoT().TempDir())
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, hostname)
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())

		roots = x509.NewCertPool()
		roots.AddCert(myCA.CACert)

		cfg = &serverConfig{
			TLSSelfProvision:           true,
			Hostname:                   hostname,
			TLSSelfProvisionEncryptKey: true,
		}
		holder = &servingCertHolder{}
	})

	It("serves normally when the stored key is encrypted", func() {
		// tls.X509KeyPair accepts any PEM block whose type ends " PRIVATE KEY",
		// so an "ENCRYPTED PRIVATE KEY" block passes its type check and then
		// fails to parse — taking the whole server down at startup, since a
		// serving-certificate failure there is fatal. The certificate must be
		// assembled from the decrypted signer, not from the stored blob.
		Expect(ensureServingCert(ctx, myCA, cfg, holder)).To(Succeed())

		presented := dialServing(holder, roots, hostname)
		Expect(presented.Subject.CommonName).To(Equal(hostname))
	})

	It("stores the key encrypted rather than in plaintext", func() {
		// Guards the other direction: a change that fixed the boot failure by
		// quietly storing plaintext would pass the spec above.
		Expect(ensureServingCert(ctx, myCA, cfg, holder)).To(Succeed())

		keyPEM, err := store.GetServingKey(ctx)
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(keyPEM)
		Expect(block).NotTo(BeNil())
		Expect(block.Type).To(Equal("ENCRYPTED PRIVATE KEY"))
	})

	It("recovers on restart, reading the encrypted key back", func() {
		// The stored blob is what a restarted process reads, and parseServingKey
		// keys on the block type rather than on config — so this is the path
		// that stays broken if only the mint path is fixed.
		Expect(ensureServingCert(ctx, myCA, cfg, holder)).To(Succeed())
		first := dialServing(holder, roots, hostname)

		restarted := ca.New(store, ca.AutosignConfig{Mode: "off"}, hostname)
		restarted.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		restarted.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(restarted.Init(ctx)).To(Succeed())

		freshHolder := &servingCertHolder{}
		Expect(ensureServingCert(ctx, restarted, cfg, freshHolder)).To(Succeed())

		after := dialServing(freshHolder, roots, hostname)
		Expect(after.SerialNumber).To(Equal(first.SerialNumber), "the certificate must be reused, not reminted")
	})
})

// failReadBackend fails Get for one key, so a storage read failure can be
// driven from this layer. The CA package has its own copy; the two cannot be
// shared because both are test-only.
type failReadBackend struct {
	storage.Backend
	failKey string
}

func (b *failReadBackend) Get(ctx context.Context, key string) ([]byte, error) {
	if key == b.failKey {
		return nil, errors.New("backend unavailable")
	}
	return b.Backend.Get(ctx, key)
}

var _ = Describe("maintenance tasks", func() {
	const hostname = "puppet.example.com"

	var (
		ctx    context.Context
		store  *storage.StorageService
		myCA   *ca.CA
		cfg    *serverConfig
		holder *servingCertHolder
	)

	BeforeEach(func() {
		ctx = context.Background()
		store = storage.New(GinkgoT().TempDir())
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, hostname)
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())

		cfg = &serverConfig{TLSSelfProvision: true, Hostname: hostname}
		holder = &servingCertHolder{}
	})

	Describe("servingRenewalTask", func() {
		It("installs the certificate it resolves", func() {
			task := servingRenewalTask(myCA, cfg, holder)
			Expect(task.name).To(Equal("serving-cert-renewal"))

			task.run(ctx)

			pair, err := holder.GetCertificate(nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(pair.Leaf.Subject.CommonName).To(Equal(hostname))
			Expect(myCA.ServingRenewalFailureCount()).To(Equal(uint64(0)))
		})

		It("counts a failure and keeps the certificate already installed", func() {
			// The counter is what the mixin alerts on, and the docs single it
			// out; without a spec the failure branch is dead to the suite while
			// the bound on how long a superseded certificate stays valid rests
			// on renewals succeeding.
			servingRenewalTask(myCA, cfg, holder).run(ctx)
			before, err := holder.GetCertificate(nil)
			Expect(err).NotTo(HaveOccurred())

			// An invalid subject fails inside EnsureServingCert, after the
			// holder already holds a certificate.
			broken := &serverConfig{TLSSelfProvision: true, Hostname: "../etc/passwd"}
			servingRenewalTask(myCA, broken, holder).run(ctx)

			Expect(myCA.ServingRenewalFailureCount()).To(Equal(uint64(1)))
			after, err := holder.GetCertificate(nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(after.Leaf.SerialNumber).To(Equal(before.Leaf.SerialNumber),
				"a failed renewal must leave the working certificate in place")
		})
	})

	Describe("servingMaintenanceTasks", func() {
		It("registers both tasks when self-provisioning is on", func() {
			// The feature's two standing promises -- renew before expiry, revoke
			// what was superseded. Both constructors are well specced, but
			// nothing pinned that either is ever registered, and a task that
			// never runs never fails, so neither counter would signal its
			// absence.
			tasks := servingMaintenanceTasks(myCA, cfg, holder)
			names := make([]string, 0, len(tasks))
			for _, t := range tasks {
				names = append(names, t.name)
			}
			Expect(names).To(ConsistOf(
				"serving-cert-renewal", "serving-cert-superseded-revocation"))
		})

		It("registers nothing when self-provisioning is off", func() {
			Expect(servingMaintenanceTasks(myCA, &serverConfig{Hostname: hostname}, holder)).To(BeEmpty())
		})
	})

	Describe("servingConfigFrom", func() {
		It("carries the configured renewal window through to the CA", func() {
			// The sibling of the RevokeAfter assertion below, and the half that
			// was missing: dropping the RenewBefore line from servingConfigFrom
			// left the suite green, so an operator's configured window was
			// silently replaced by the lifetime/3 default -- reissuing up to
			// years earlier or later than they asked for, in either direction,
			// with validateTLS still accepting the value.
			Expect(ensureServingCert(ctx, myCA, cfg, holder)).To(Succeed())
			first, err := holder.GetCertificate(nil)
			Expect(err).NotTo(HaveOccurred())

			// Just inside the window, by the same arithmetic the CA-layer spec
			// uses: a fresh certificate is backdated 24h, so a window an hour
			// under the lifetime already contains it.
			lifetime := first.Leaf.NotAfter.Sub(first.Leaf.NotBefore)
			cfg.TLSSelfProvisionRenewBeforeSec = int(lifetime.Seconds()) - 3600

			Expect(ensureServingCert(ctx, myCA, cfg, holder)).To(Succeed())
			second, err := holder.GetCertificate(nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(second.Leaf.SerialNumber.Cmp(first.Leaf.SerialNumber)).NotTo(BeZero(),
				"a configured renewal window that contains the certificate must force a reissue")
		})
	})

	Describe("reconcileAtStartup", func() {
		It("counts a startup sweep that could not run", func() {
			// The arm with no next pass: with tls_self_provision off no periodic
			// task is registered, so this call is the only sweep the process
			// runs. It lived inside RunE, which no spec can execute, so its
			// increment was dead -- and this is the one arm the shipped runbook
			// singles out as needing manual action.
			dir := GinkgoT().TempDir()
			seed := ca.New(storage.New(dir), ca.AutosignConfig{Mode: "off"}, hostname)
			seed.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
			seed.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
			Expect(seed.Init(ctx)).To(Succeed())

			blind := ca.New(storage.NewWithBackend(&failReadBackend{
				Backend: storage.NewFilesystemBackend(dir),
				failKey: storage.KeyServingSuperseded,
			}, dir), ca.AutosignConfig{Mode: "off"}, hostname)
			blind.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
			blind.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
			Expect(blind.Init(ctx)).To(Succeed())

			// Deliberately with the feature off: this call is ungated, which is
			// the whole reason it counts.
			reconcileAtStartup(ctx, blind, &serverConfig{Hostname: hostname})

			Expect(blind.ServingRevocationFailureCount()).To(Equal(uint64(1)))
		})

		It("does nothing at all without a hostname", func() {
			// ReconcileSuperseded rejects an empty subject, so without this
			// guard every deployment that never enabled the feature would warn
			// and count on every boot -- which is how operators learn to stop
			// reading boot logs, and how an alert becomes noise.
			reconcileAtStartup(ctx, myCA, &serverConfig{Hostname: ""})
			Expect(myCA.ServingRevocationFailureCount()).To(BeZero())
		})
	})

	Describe("supersededRevocationTask", func() {
		It("passes a zero delay through, discarding the list without revoking", func() {
			// Registered even when the delay is zero, so entries a previously
			// non-zero setting recorded are discarded rather than stranded.
			// Asserting the drain, not merely that it does not panic: this is
			// the only place the resolved duration reaches the CA layer, so
			// transposing RevokeAfter and RenewBefore in servingConfigFrom
			// would otherwise leave the suite green.
			// Recorded under a non-zero delay -- nothing is recorded at all
			// when the delay is off -- then drained by a task configured with
			// zero, which is exactly the "previously non-zero setting" the
			// comment describes.
			cfg.TLSSelfProvisionRevokeAfterSec = 7200
			Expect(ensureServingCert(ctx, myCA, cfg, holder)).To(Succeed())
			first, err := holder.GetCertificate(nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(myCA.Storage.SaveServingKey(ctx, []byte("not a key\n"))).To(Succeed())
			Expect(ensureServingCert(ctx, myCA, cfg, holder)).To(Succeed())
			pending, err := myCA.Storage.GetServingSuperseded(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(pending)).NotTo(Equal("[]"))

			off := &serverConfig{TLSSelfProvision: true, Hostname: hostname, TLSSelfProvisionRevokeAfterSec: 0}
			task := supersededRevocationTask(myCA, off)
			Expect(task.name).To(Equal("serving-cert-superseded-revocation"))
			task.run(ctx)

			drained, err := myCA.Storage.GetServingSuperseded(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(drained)).To(Equal("[]"), "a zero delay discards the list")
			revoked, err := myCA.IsRevokedSerial(ctx, first.Leaf.SerialNumber)
			Expect(err).NotTo(HaveOccurred())
			Expect(revoked).To(BeFalse(), "discarding must not revoke")
		})

		It("counts a sweep that could not run at all", func() {
			// Distinct from the malformed-entry spec below: that one increments
			// inside ReconcileSuperseded and the call returns nil, so it never
			// reaches this task's own error branch. Nothing did -- deleting the
			// increment here left the suite green, and with it gone a sweep that
			// fails every pass moves no counter, so the alert whose runbook
			// routes on this exact log line never fires.
			dir := GinkgoT().TempDir()
			seed := ca.New(storage.New(dir), ca.AutosignConfig{Mode: "off"}, hostname)
			seed.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
			seed.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
			Expect(seed.Init(ctx)).To(Succeed())

			blind := ca.New(storage.NewWithBackend(&failReadBackend{
				Backend: storage.NewFilesystemBackend(dir),
				failKey: storage.KeyServingSuperseded,
			}, dir), ca.AutosignConfig{Mode: "off"}, hostname)
			blind.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
			blind.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
			Expect(blind.Init(ctx)).To(Succeed())

			cfg.TLSSelfProvisionRevokeAfterSec = 7200
			supersededRevocationTask(blind, cfg).run(ctx)

			Expect(blind.ServingRevocationFailureCount()).To(Equal(uint64(1)))
		})

		It("counts a failure and discards an entry that can never be revoked", func() {
			// The sibling of the renewal-failure spec above, and for the same
			// reason: this counter is what bounds how long a superseded
			// certificate stays a valid credential, and without a spec its
			// branch is dead to the suite.
			//
			// A malformed serial fails inside the sweep rather than before it
			// -- an empty hostname would return before touching storage,
			// leaving any assertion here trivially true. It is discarded rather
			// than carried, because retrying it forever would latch this
			// counter's alert with nothing an operator could do about it. The
			// carry-forward path is for transient failures and is covered at
			// the CA layer.
			cfg.TLSSelfProvisionRevokeAfterSec = 7200
			Expect(myCA.Storage.SaveServingSuperseded(ctx,
				[]byte(`[{"serial":"zz","revoke_at":"2020-01-01T00:00:00Z"}]`))).To(Succeed())

			supersededRevocationTask(myCA, cfg).run(ctx)

			Expect(myCA.ServingRevocationFailureCount()).To(Equal(uint64(1)))
			after, err := myCA.Storage.GetServingSuperseded(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(after)).NotTo(ContainSubstring("zz"),
				"an entry that can never be revoked must not be retried forever")
		})
	})
})
