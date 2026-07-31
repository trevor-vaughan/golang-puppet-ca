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
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/k8sexport"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// runK8sExporter is the wiring that connects the CA's CRL-update notifications
// to the exporter's reconcile. It must export once at startup, re-export on
// every CRL update, and return promptly on context cancellation.
var _ = Describe("runK8sExporter", func() {
	It("exports at startup, re-exports on CRL update, and returns on cancel", func() {
		c, store := newRefresherTestCA()

		client := fake.NewClientset()
		var applies atomic.Int32
		// Count server-side applies (a patch) but let the fake tracker handle
		// them so the objects are still created/updated.
		client.PrependReactor("patch", "secrets",
			func(ktesting.Action) (bool, runtime.Object, error) {
				applies.Add(1)
				return false, nil, nil
			})

		cfg := k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust", Namespace: "ns1"}, CRL: true,
		}}}
		Expect(cfg.Validate()).To(Succeed())

		// store (*storage.StorageService) satisfies k8sexport.MaterialSource.
		exporter := k8sexport.New(client, cfg, store, "", nil)

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			runK8sExporter(ctx, c, exporter)
			close(done)
		}()

		// (1) The startup export applies the target.
		Eventually(applies.Load).WithTimeout(2*time.Second).
			Should(BeNumerically(">=", 1), "startup export did not apply within 2s")
		startupCount := applies.Load()

		// (2) A CRL update wakes the loop and triggers a re-export.
		Expect(c.ReissueCRL(ctx)).To(Succeed())
		Eventually(applies.Load).WithTimeout(2*time.Second).
			Should(BeNumerically(">", startupCount), "CRL update did not trigger a re-export within 2s")

		// (3) Cancelling the context stops the loop.
		cancel()
		Eventually(done).WithTimeout(2*time.Second).Should(BeClosed(),
			"runK8sExporter did not return after context cancellation")
	})
})

var _ = Describe("runK8sExporter serving-certificate wake-up", func() {
	It("re-exports when the serving certificate rotates, with no CRL change", func() {
		// The reason the loop selects on two channels. A rotation does not touch
		// the CRL, so with only the CRL case the rotated certificate would sit
		// unexported until the periodic reconcile came round.
		c, store := newRefresherTestCA()
		c.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}

		client := fake.NewClientset()
		var applies atomic.Int32
		client.PrependReactor("patch", "secrets",
			func(ktesting.Action) (bool, runtime.Object, error) {
				applies.Add(1)
				return false, nil, nil
			})

		cfg := k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust", Namespace: "ns1"}, CRL: true,
		}}}
		Expect(cfg.Validate()).To(Succeed())
		exporter := k8sexport.New(client, cfg, store, "", nil)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan struct{})
		go func() {
			runK8sExporter(ctx, c, exporter)
			close(done)
		}()

		Eventually(applies.Load).WithTimeout(2 * time.Second).Should(BeNumerically(">=", 1))
		startupCount := applies.Load()

		// Announce a rotation. The signal is sent by whoever installs the new
		// pair -- ensureServingCert -- not by the mint, so this stands in for
		// that caller. The CRL is untouched.
		c.NotifyServingCertUpdated()

		Eventually(applies.Load).WithTimeout(2*time.Second).
			Should(BeNumerically(">", startupCount),
				"a serving-certificate rotation did not wake the export loop")

		cancel()
		Eventually(done).WithTimeout(2 * time.Second).Should(BeClosed())
	})
})

// The end-to-end ordering property the whole rotation mechanism turns on: after
// a rotation, what the Secret holds is the certificate the CA is now serving.
//
// The wake-up used to be sent from inside the mint, several frames and a
// storage round trip before the holder was installed, so the exporter woke, won
// the race to an atomic load, and published the certificate being *replaced* --
// successfully, so no alert fired and no retry was armed, and the depth-1
// channel was drained before the new pair arrived.
//
// What this spec adds is the assertion nobody made: that the bytes applied are
// the certificate now being served. It does NOT pin the ordering, and cannot be
// made to -- with RevokeAfter unset recordSuperseded returns immediately and the
// filesystem backend's WithLock is a process-local mutex, so there is no I/O in
// the window at all and the test goroutine wins it essentially always.
//
// The ordering is pinned structurally instead: servingCertHolder.Set stores
// before it calls notify, so "announce before install" cannot be written. See
// "stores the pair before it announces it" below, and "stays silent until the
// caller announces an installed certificate" in internal/ca/serving_test.go for
// the half that keeps the mint out of it. Do not rewrite either as a timing
// test here.
var _ = Describe("serving-certificate rotation, end to end", func() {
	It("publishes the certificate the CA is now serving, not the one it replaced", func() {
		c, store := newRefresherTestCA()
		c.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}

		// Capture what each apply actually carries, rather than counting them.
		var (
			mu      sync.Mutex
			lastCrt []byte
		)
		client := fake.NewClientset()
		client.PrependReactor("patch", "secrets",
			func(action ktesting.Action) (bool, runtime.Object, error) {
				patch, ok := action.(ktesting.PatchAction)
				if !ok {
					return false, nil, nil
				}
				var applied corev1.Secret
				if err := json.Unmarshal(patch.GetPatch(), &applied); err == nil {
					mu.Lock()
					lastCrt = applied.Data["tls.crt"]
					mu.Unlock()
				}
				return false, nil, nil
			})

		cfg := k8sexport.Config{Targets: []k8sexport.Target{{
			Kind:        "Secret",
			Metadata:    k8sexport.Metadata{Name: "serving", Namespace: "ns1"},
			Type:        "kubernetes.io/tls",
			ServingCert: true,
			ServingKey:  true,
		}}}
		Expect(cfg.Validate()).To(Succeed())

		holder := newServingCertHolder(c.NotifyServingCertUpdated)
		exporter := k8sexport.New(client, cfg, store, "", nil).WithServingSource(holder)

		srvCfg := &serverConfig{TLSSelfProvision: true, Hostname: "puppet.test"}
		Expect(ensureServingCert(context.Background(), c, srvCfg, holder)).To(Succeed())
		first, err := holder.GetCertificate(nil)
		Expect(err).NotTo(HaveOccurred())

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan struct{})
		go func() {
			runK8sExporter(ctx, c, exporter)
			close(done)
		}()

		crtOf := func() []byte {
			mu.Lock()
			defer mu.Unlock()
			return lastCrt
		}
		firstPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: first.Leaf.Raw})
		Eventually(crtOf).WithTimeout(2 * time.Second).Should(Equal(firstPEM))

		// Rotate. Widening the name set forces a reissue without faking a clock.
		srvCfg.TLSSelfProvisionNames = []string{"alt.example.test"}
		Expect(ensureServingCert(ctx, c, srvCfg, holder)).To(Succeed())
		second, err := holder.GetCertificate(nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(second.Leaf.SerialNumber.Cmp(first.Leaf.SerialNumber)).NotTo(BeZero(),
			"the spec needs a real rotation to mean anything")

		secondPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: second.Leaf.Raw})
		Eventually(crtOf).WithTimeout(2*time.Second).Should(Equal(secondPEM),
			"the export woken by the rotation must carry the new certificate")

		cancel()
		Eventually(done).WithTimeout(2 * time.Second).Should(BeClosed())
	})
})

var _ = Describe("servingCertHolder.ServingMaterial", func() {
	// The only code in the tree that turns the CA's private key into bytes for
	// publication, and it had no spec of any kind: every export spec drives a
	// stub. `return keyPEM, certPEM, nil` -- publishing the private key as
	// tls.crt -- passed the whole suite, as did emitting PKCS#8 bytes under a
	// PKCS#1 label, which fails at every consumer's first handshake.
	var holder *servingCertHolder

	BeforeEach(func() {
		c, _ := newRefresherTestCA()
		c.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		holder = &servingCertHolder{}
		Expect(ensureServingCert(context.Background(), c,
			&serverConfig{TLSSelfProvision: true, Hostname: "puppet.test"}, holder)).To(Succeed())
	})

	It("returns a pair a TLS consumer can actually load", func() {
		certPEM, keyPEM, err := holder.ServingMaterial(context.Background())
		Expect(err).NotTo(HaveOccurred())

		// Catches the transposition: X509KeyPair parses the certificate and the
		// key and checks the public keys match, so returning them the wrong way
		// round fails here. It does NOT catch a wrong PEM label -- Go accepts
		// any block whose type ends "PRIVATE KEY" and tries PKCS#1, PKCS#8 and
		// SEC1 regardless -- so the label is pinned by the sibling spec below,
		// which asserts block.Type directly. Neither pins atomicity.
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		Expect(err).NotTo(HaveOccurred(),
			"the exported pair must load as a kubernetes.io/tls Secret's consumer would load it")

		served, err := holder.GetCertificate(nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(pair.Certificate[0]).To(Equal(served.Certificate[0]),
			"the exported certificate must be the one the listener presents")
	})

	It("emits the key unencrypted even when the stored key is encrypted", func() {
		// The contract that settled the "do not publish the key" question: a
		// kubernetes.io/tls Secret holding an encrypted PEM looks correct and
		// fails at the first handshake. Encryption at rest must not reach here.
		c, _ := newRefresherTestCA()
		c.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		pf := filepath.Join(GinkgoT().TempDir(), "pass")
		Expect(os.WriteFile(pf, []byte("hunter2\n"), 0o600)).To(Succeed())
		c.KeyPassphrase = ca.KeyPassphraseConfig{PassphraseFile: pf}
		encrypted := &servingCertHolder{}
		Expect(ensureServingCert(context.Background(), c, &serverConfig{
			TLSSelfProvision: true, Hostname: "puppet.test", TLSSelfProvisionEncryptKey: true,
		}, encrypted)).To(Succeed())

		_, keyPEM, err := encrypted.ServingMaterial(context.Background())
		Expect(err).NotTo(HaveOccurred())

		block, _ := pem.Decode(keyPEM)
		Expect(block).NotTo(BeNil())
		Expect(block.Type).To(Equal("PRIVATE KEY"))
		Expect(block.Headers).To(BeEmpty(), "an encrypted PEM carries headers; this must not")
		Expect(x509.ParsePKCS8PrivateKey(block.Bytes)).Error().NotTo(HaveOccurred())
	})

	It("returns an error rather than a half pair when nothing is installed", func() {
		certPEM, keyPEM, err := (&servingCertHolder{}).ServingMaterial(context.Background())
		Expect(err).To(HaveOccurred())
		Expect(certPEM).To(BeNil())
		Expect(keyPEM).To(BeNil())
	})
})

var _ = Describe("serving export wiring", func() {
	// Three decisions that lived inline in RunE, which no spec can execute --
	// the same reason reconcileAtStartup was extracted in #165.
	const host = "puppet.test"

	target := func(t k8sexport.Target) *serverConfig {
		return &serverConfig{
			TLSSelfProvision: true, Hostname: host,
			KubernetesExport: k8sexport.Config{Targets: []k8sexport.Target{t}},
		}
	}

	It("refuses a serving target when self-provisioning is off", func() {
		// Otherwise every cycle fails for the life of the process, and whatever
		// was last published -- a plaintext CA-chained private key -- stays in
		// the Secret with nothing to refresh or remove it.
		cfg := target(k8sexport.Target{Kind: "Secret", ServingKey: true})
		cfg.TLSSelfProvision = false
		Expect(validateServingExport(cfg)).To(MatchError(ContainSubstring("tls_self_provision is off")))

		cfg.TLSSelfProvision = true
		Expect(validateServingExport(cfg)).To(Succeed())
	})

	It("refuses a serving_cert-only target for the same reason", func() {
		cfg := target(k8sexport.Target{Kind: "Secret", ServingCert: true})
		cfg.TLSSelfProvision = false
		Expect(validateServingExport(cfg)).To(HaveOccurred())
	})

	It("does not refuse a cert/CRL target", func() {
		cfg := target(k8sexport.Target{Kind: "Secret", Cert: true, CRL: true})
		cfg.TLSSelfProvision = false
		Expect(validateServingExport(cfg)).To(Succeed())
	})

	It("warns about the plaintext key only when one is actually published", func() {
		Expect(servingExportWarnings(target(k8sexport.Target{Kind: "Secret", ServingKey: true}))).
			To(HaveLen(1))
		Expect(servingExportWarnings(target(k8sexport.Target{Kind: "Secret", ServingCert: true}))).
			To(BeEmpty(), "the certificate is public; only the key warrants a warning")

		off := target(k8sexport.Target{Kind: "Secret", ServingKey: true})
		off.TLSSelfProvision = false
		Expect(servingExportWarnings(off)).To(BeEmpty(),
			"no key is published without self-provisioning, so warning about one is noise")
	})

	It("attaches the holder the listener presents, and only under self-provisioning", func() {
		cfg := target(k8sexport.Target{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "s", Namespace: "ns"},
			Type: "kubernetes.io/tls", ServingCert: true, ServingKey: true,
		})
		c, store := newRefresherTestCA()
		c.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		holder := &servingCertHolder{}
		Expect(ensureServingCert(context.Background(), c, cfg, holder)).To(Succeed())

		// A fresh exporter per case: WithServingSource mutates its receiver, so
		// reusing one would leave the source attached and prove nothing.
		newExporter := func() *k8sexport.Exporter {
			return k8sexport.New(fake.NewClientset(), cfg.KubernetesExport, store, "ns", nil)
		}
		Expect(attachServingSource(newExporter(), cfg, holder, store).ExportAll(context.Background())).
			To(Succeed(), "with the holder attached the serving materials resolve")

		cfg.TLSSelfProvision = false
		Expect(attachServingSource(newExporter(), cfg, holder, store).ExportAll(context.Background())).
			To(MatchError(ContainSubstring("tls_self_provision")),
				"without it the source must stay nil, so the failure names the cause")
	})
})

var _ = Describe("nextExportInterval", func() {
	It("keeps the retry inside the alert's debounce", func() {
		// exportRetryInterval's whole justification is that a transient failure
		// is corrected before PuppetCAKubernetesExportFailing pages. That
		// coupling is to k8sExportFailingFor in mixin/config.libsonnet, which no
		// Go code reads -- so it is asserted here or nowhere, and raising the
		// interval past it would otherwise be invisible.
		Expect(exportRetryInterval).To(BeNumerically("<", 15*time.Minute),
			"must stay inside k8sExportFailingFor (15m) so a retry lands before the page")
	})

	It("retries sooner after a failure than it resyncs after a success", func() {
		// The timer is always armed. A failed cycle needs to be retried inside
		// the alert's debounce; a successful one still needs a floor, because a
		// replica that did not mint can apply a stale pair successfully and
		// nothing else would ever correct it.
		Expect(nextExportInterval(false)).To(Equal(exportRetryInterval))
		Expect(nextExportInterval(true)).To(Equal(exportResyncInterval))
		Expect(exportRetryInterval).To(BeNumerically("<", exportResyncInterval))
	})
})

var _ = Describe("runK8sExporter periodic reconcile", func() {
	// The timer is the only thing that corrects a Secret nothing will wake the
	// exporter about: both signals are edge-triggered, and a replica that did
	// not mint never sees a rotation at all. Deleting either retry.Reset leaves
	// nextExportInterval's own spec green, so the arming has to be observed.
	BeforeEach(func() {
		retry, resync := exportRetryInterval, exportResyncInterval
		DeferCleanup(func() { exportRetryInterval, exportResyncInterval = retry, resync })
		// Distinct, so a cycle driven by the resync arm cannot be mistaken for
		// one driven by the retry arm: the reconcile spec below succeeds every
		// time, so only the resync value can produce its repeats.
		exportRetryInterval = 5 * time.Second
		exportResyncInterval = 20 * time.Millisecond
	})

	It("keeps reconciling with no CRL change and no rotation", func() {
		c, store := newRefresherTestCA()

		client := fake.NewClientset()
		var applies atomic.Int32
		client.PrependReactor("patch", "configmaps",
			func(ktesting.Action) (bool, runtime.Object, error) {
				applies.Add(1)
				return false, nil, nil
			})

		cfg := k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "ConfigMap", Metadata: k8sexport.Metadata{Name: "trust", Namespace: "ns1"}, CRL: true,
		}}}
		Expect(cfg.Validate()).To(Succeed())

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan struct{})
		go func() {
			runK8sExporter(ctx, c, k8sexport.New(client, cfg, store, "", nil))
			close(done)
		}()

		// Several cycles with nothing signalling: only the timer can produce them.
		Eventually(applies.Load).WithTimeout(2 * time.Second).Should(BeNumerically(">=", 3))

		cancel()
		Eventually(done).WithTimeout(2 * time.Second).Should(BeClosed())
	})
})

var _ = Describe("servingCertHolder.Set", func() {
	// The ordering the whole rotation mechanism turns on, pinned without any
	// timing: a consumer woken by the announcement immediately reads the holder,
	// so announcing before storing publishes the certificate being replaced.
	//
	// Round 1 moved the announcement out of the mint and into ensureServingCert,
	// which narrowed the window to two adjacent statements but left it open --
	// swapping them kept the whole suite green. Making the announcement a side
	// effect of Set removes the class: there is no longer a place to write the
	// wrong order. The callback runs synchronously on the setter's goroutine, so
	// what it observes is exactly what a woken consumer would.
	It("stores the pair before it announces it", func() {
		h := &servingCertHolder{}
		pair := &tls.Certificate{Certificate: [][]byte{{0x01}}}

		var seen *tls.Certificate
		h.notify = func() { seen, _ = h.GetCertificate(nil) }
		h.Set(pair)

		Expect(seen).To(BeIdenticalTo(pair),
			"the announcement must not precede the installation")
	})

	It("is usable without an announcement, for the file route", func() {
		h := newServingCertHolder(nil)
		Expect(func() { h.Set(&tls.Certificate{Certificate: [][]byte{{0x01}}}) }).NotTo(Panic())
	})
})

var _ = Describe("currentOnly", func() {
	// The first spec on this branch that builds two replicas. Every cross-replica
	// claim before it was pinned by a single *ca.CA -- so a fence that consulted
	// this process's own state looked correct, shipped, and could not work for
	// the replica it was written for.
	//
	// Two CAs over one storage service is the shape internal/ca already uses for
	// exactly this reason.
	var (
		ctx    context.Context
		minter *ca.CA
		lagger *ca.CA
		store  *storage.StorageService
		held   *servingCertHolder
	)

	const host = "puppet.test"

	BeforeEach(func() {
		ctx = context.Background()
		minter, store = newRefresherTestCA()
		minter.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}

		// A second process over the same backend, as a second pod would be.
		lagger = ca.New(store, ca.AutosignConfig{Mode: "off"}, host)
		lagger.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		lagger.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(lagger.Init(ctx)).To(Succeed())

		held = newServingCertHolder(nil)
		Expect(ensureServingCert(ctx, minter,
			&serverConfig{TLSSelfProvision: true, Hostname: host}, held)).To(Succeed())
	})

	It("publishes while what this replica holds is what storage holds", func() {
		certPEM, keyPEM, err := currentOnly{inner: held, store: store}.ServingMaterial(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(certPEM).NotTo(BeEmpty())
		Expect(keyPEM).NotTo(BeEmpty())
	})

	It("declines once another replica has rotated underneath it", func() {
		// The property four mechanisms were written for and none could observe:
		// the minting replica moves storage on, and this replica -- still
		// holding the previous pair until its own maintenance pass -- must not
		// write it back over the new one.
		fresh := newServingCertHolder(nil)
		Expect(ensureServingCert(ctx, minter, &serverConfig{
			TLSSelfProvision: true, Hostname: host,
			TLSSelfProvisionNames: []string{"alt.example.test"},
		}, fresh)).To(Succeed())

		_, _, err := currentOnly{inner: held, store: store}.ServingMaterial(ctx)
		Expect(err).To(MatchError(k8sexport.ErrServingStale))
	})

	It("declines a pair another replica revoked and replaced", func() {
		// Subsumes the revocation fence this replaces, and does it by reading
		// shared state: the earlier version asked this process's cached CRL,
		// which a replica that did not perform the revoke never updates -- so it
		// answered "not revoked" for exactly the replica it existed to stop.
		Expect(lagger.Revoke(ctx, host)).To(Succeed())
		Expect(ensureServingCert(ctx, lagger,
			&serverConfig{TLSSelfProvision: true, Hostname: host}, newServingCertHolder(nil))).To(Succeed())

		// The fact that makes this a two-replica spec rather than a one-replica
		// one: minter never saw lagger's revoke, so anything consulting its own
		// CRL cache -- as the fence this replaced did -- answers "not revoked".
		heldSerial, parseErr := leafSerialOf(mustServingCert(ctx, held))
		Expect(parseErr).NotTo(HaveOccurred())
		serial, ok := new(big.Int).SetString(heldSerial, 16)
		Expect(ok).To(BeTrue())
		Expect(minter.IsRevokedSerial(ctx, serial)).To(BeFalse(),
			"minter's cached CRL cannot see lagger's revoke; the comparison must not depend on it")

		_, _, err := currentOnly{inner: held, store: store}.ServingMaterial(ctx)
		Expect(err).To(MatchError(k8sexport.ErrServingStale),
			"a replica must not republish what the fleet has retired, whatever its own CRL cache says")
	})

	It("is what the production wiring installs", func() {
		// The fence is attached at one line, and replacing it with the bare
		// holder compiles and left the whole suite green -- restoring the
		// defect four rounds chased. Driven through attachServingSource with a
		// stale holder, so the wiring is asserted rather than read.
		Expect(ensureServingCert(ctx, minter, &serverConfig{
			TLSSelfProvision: true, Hostname: host,
			TLSSelfProvisionNames: []string{"alt.example.test"},
		}, newServingCertHolder(nil))).To(Succeed())

		cfg := &serverConfig{TLSSelfProvision: true, Hostname: host}
		client := fake.NewClientset()
		exportCfg := k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "serving", Namespace: "ns1"},
			Type: "kubernetes.io/tls", ServingCert: true, ServingKey: true,
		}}}
		Expect(exportCfg.Validate()).To(Succeed())

		e := attachServingSource(k8sexport.New(client, exportCfg, store, "ns1", nil), cfg, held, store)
		Expect(e.ExportAll(ctx)).To(Succeed(), "being behind is not an export failure")

		_, err := client.CoreV1().Secrets("ns1").Get(ctx, "serving", metav1.GetOptions{})
		Expect(err).To(HaveOccurred(),
			"an unfenced source would have republished the superseded pair here")
	})

	It("passes the holder's own failure through as a failure, not staleness", func() {
		// The opposite direction, and the one that would be silent: labelled as
		// staleness, a replica whose holder never populates skips forever --
		// no applies_total, no last_error, so neither arm of the export alert
		// can fire and the only trace is a debug line.
		_, _, err := currentOnly{inner: newServingCertHolder(nil), store: store}.ServingMaterial(ctx)
		Expect(err).To(HaveOccurred())
		Expect(err).NotTo(MatchError(k8sexport.ErrServingStale))
	})

	It("reports a read failure as a failure, not as staleness", func() {
		// Opposite handling: nobody can publish, so it belongs in the metrics
		// the alert watches rather than being skipped quietly.
		dir := GinkgoT().TempDir()
		blind := storage.NewWithBackend(
			&failReadBackend{Backend: storage.NewFilesystemBackend(dir), failKey: storage.KeyServingCert}, dir)
		_, _, err := currentOnly{inner: held, store: blind}.ServingMaterial(ctx)
		Expect(err).To(HaveOccurred())
		Expect(err).NotTo(MatchError(k8sexport.ErrServingStale))
	})
})

var _ = Describe("fatalExportStartupError", func() {
	// A configuration mistake must stop startup; an environmental one must not.
	// Collapsing the two disabled the export permanently and silently -- no
	// series written, so the alert that owns it could not fire either.
	It("stops startup for a configuration mistake", func() {
		err := fmt.Errorf("%w: targets 0 and 1 both resolve to Secret", k8sexport.ErrInvalidConfig)
		Expect(fatalExportStartupError(err)).To(HaveOccurred())
	})

	It("lets the CA serve on when the client will not initialise", func() {
		Expect(fatalExportStartupError(errors.New("no ServiceAccount token"))).To(BeNil())
		Expect(fatalExportStartupError(nil)).To(BeNil())
	})
})

// mustServingCert returns the certificate PEM a holder is presenting.
func mustServingCert(ctx context.Context, h *servingCertHolder) []byte {
	GinkgoHelper()
	certPEM, _, err := h.ServingMaterial(ctx)
	Expect(err).NotTo(HaveOccurred())
	return certPEM
}

var _ = Describe("leafSerialOf", func() {
	// The two call sites wrap its error differently, and those strings are the
	// only way an operator tells "my holder is broken" from "storage is
	// corrupt" -- one means restart this pod, the other means the fleet is
	// about to re-mint. Transposing them left the suite green.
	It("reads the serial of a real certificate", func() {
		c, _ := newRefresherTestCA()
		c.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		h := newServingCertHolder(nil)
		Expect(ensureServingCert(context.Background(), c,
			&serverConfig{TLSSelfProvision: true, Hostname: "puppet.test"}, h)).To(Succeed())

		served, err := h.GetCertificate(nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(leafSerialOf(mustServingCert(context.Background(), h))).
			To(Equal(served.Leaf.SerialNumber.Text(16)))
	})

	DescribeTable("refuses what it cannot read",
		func(in []byte, want string) {
			_, err := leafSerialOf(in)
			Expect(err).To(MatchError(ContainSubstring(want)))
		},
		Entry("not PEM at all", []byte("nonsense\n"), "not PEM"),
		Entry("a PEM block that is not a certificate",
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not DER")}), "parsing"),
	)
})

var _ = Describe("exportResyncInterval", func() {
	It("is the ten minutes the documentation states", func() {
		// docs/kubernetes-export.md and docs/metrics.md both name this figure,
		// and neither is checked by anything. It has been wrong three times.
		Expect(exportResyncInterval).To(Equal(10 * time.Minute))
	})
})
