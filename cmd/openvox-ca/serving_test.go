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

		// Force the next pass to reissue by putting any certificate inside the
		// renewal window.
		cfg.TLSSelfProvisionRenewBeforeSec = int((100 * 365 * 24 * time.Hour).Seconds())
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
