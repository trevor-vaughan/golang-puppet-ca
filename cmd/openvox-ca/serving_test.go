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

	It("stores the certificate where the exporter and a restart will find it", func() {
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
