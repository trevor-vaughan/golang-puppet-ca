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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// passphraseFile writes secret to a fresh temp file and returns its path.
func passphraseFile(secret string) string {
	GinkgoHelper()
	path := filepath.Join(GinkgoT().TempDir(), "passphrase")
	Expect(os.WriteFile(path, []byte(secret+"\n"), 0o600)).To(Succeed())
	return path
}

var _ = Describe("Serving certificate", func() {
	const subject = "puppet.example.com"

	var (
		ctx   context.Context
		store *storage.StorageService
		myCA  *ca.CA
		cfg   ca.ServingConfig
	)

	BeforeEach(func() {
		ctx = context.Background()
		store = storage.New(GinkgoT().TempDir())
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, subject)
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())
		cfg = ca.ServingConfig{Subject: subject}
	})

	Describe("EnsureServingCert", func() {
		It("mints a certificate chained to the CA on first call", func() {
			got, err := myCA.EnsureServingCert(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(got.Issued).To(BeTrue())
			Expect(got.Leaf.Subject.CommonName).To(Equal(subject))
			Expect(got.Leaf.DNSNames).To(ContainElement(subject))
			Expect(got.Leaf.CheckSignatureFrom(myCA.CACert)).To(Succeed())
		})

		It("leaves ordinary issuance at serverAuth + clientAuth", func() {
			// The other arm of the same override. This changeset turned a
			// hard-coded literal into a variadic parameter with a defaulting
			// helper; the override arm is pinned by the spec below, and without
			// this one, dropping clientAuth from the default would leave the
			// suite green and break agent authentication across the fleet.
			res, err := myCA.Generate(ctx, "agent1.example.com", nil)
			Expect(err).NotTo(HaveOccurred())
			block, _ := pem.Decode(res.CertificatePEM)
			Expect(block).NotTo(BeNil())
			leaf, err := x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(leaf.ExtKeyUsage).To(Equal([]x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth,
			}))
		})

		It("rejects a subject that is not a valid certificate name", func() {
			bad := cfg
			bad.Subject = "../etc/passwd"
			_, err := myCA.EnsureServingCert(ctx, bad)
			Expect(err).To(MatchError(ContainSubstring("serving certificate subject")))
		})

		It("issues serverAuth only, never clientAuth", func() {
			// The common name is the CA's own hostname. Where that hostname also
			// appears in puppet_server, a clientAuth certificate sitting in the
			// storage backend would be a usable admin credential.
			got, err := myCA.EnsureServingCert(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(got.Leaf.ExtKeyUsage).To(Equal([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}))
		})

		It("reuses the stored certificate on a second call", func() {
			first, err := myCA.EnsureServingCert(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())

			second, err := myCA.EnsureServingCert(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(second.Issued).To(BeFalse())
			Expect(second.Leaf.SerialNumber).To(Equal(first.Leaf.SerialNumber))
		})

		It("gives a second CA instance the same certificate, as a restart would", func() {
			// The property that makes an ephemeral cadir over a shared backend
			// work: the certificate survives the process, not the filesystem.
			first, err := myCA.EnsureServingCert(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())

			restarted := ca.New(store, ca.AutosignConfig{Mode: "off"}, subject)
			restarted.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
			Expect(restarted.Init(ctx)).To(Succeed())

			second, err := restarted.EnsureServingCert(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(second.Issued).To(BeFalse())
			Expect(second.Leaf.SerialNumber).To(Equal(first.Leaf.SerialNumber))
		})

		It("covers every configured extra name", func() {
			cfg.ExtraNames = []string{"openvox-ca.puppet.svc.cluster.local", "puppet.example.com"}
			got, err := myCA.EnsureServingCert(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(got.Leaf.DNSNames).To(Equal([]string{
				subject, "openvox-ca.puppet.svc.cluster.local",
			}), "the subject leads and duplicates are dropped")
		})

		It("reissues when a name is added to the configuration", func() {
			first, err := myCA.EnsureServingCert(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())

			cfg.ExtraNames = []string{"ingress.example.com"}
			second, err := myCA.EnsureServingCert(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(second.Issued).To(BeTrue())
			Expect(second.Leaf.SerialNumber).NotTo(Equal(first.Leaf.SerialNumber))
			Expect(second.Leaf.DNSNames).To(ContainElement("ingress.example.com"))
		})

		It("reissues once inside the renewal window", func() {
			first, err := myCA.EnsureServingCert(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())

			// Adding a name the stored certificate does not cover forces a
			// reissue without waiting or faking a clock. A renew-before longer
			// than the lifetime would not: servingRenewBefore clamps it, because
			// a window at or beyond the lifetime makes every certificate
			// immediately due and the CA would reissue forever.
			cfg.ExtraNames = []string{"alt.example.com"}
			second, err := myCA.EnsureServingCert(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(second.Issued).To(BeTrue())
			Expect(second.Leaf.SerialNumber).NotTo(Equal(first.Leaf.SerialNumber))
		})

		It("does not reissue on every pass when the renewal window exceeds the lifetime", func() {
			// The loop this guards against: issueLeafLocked caps every
			// certificate at the CA certificate's *remaining* life, so a window
			// that was comfortably inside the configured lifetime becomes larger
			// than the real one as the CA certificate ages. Every fresh
			// certificate is then immediately due, and each pass signs one,
			// appends to the inventory, and schedules a revocation that grows
			// and re-signs the CRL.
			cfg.RenewBefore = 100 * 365 * 24 * time.Hour

			first, err := myCA.EnsureServingCert(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(first.Issued).To(BeTrue())

			for i := 0; i < 3; i++ {
				again, err := myCA.EnsureServingCert(ctx, cfg)
				Expect(err).NotTo(HaveOccurred())
				Expect(again.Issued).To(BeFalse(), "pass %d reissued a certificate that is not due", i+2)
				Expect(again.Leaf.SerialNumber).To(Equal(first.Leaf.SerialNumber))
			}
			Expect(myCA.ServingCertIssued()).To(Equal(uint64(1)))
		})

		It("reissues when the stored certificate has been revoked", func() {
			// The documented recovery route for a compromised serving key:
			// revoke the CA's own hostname and let the next pass reissue.
			first, err := myCA.EnsureServingCert(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(myCA.Revoke(ctx, subject)).To(Succeed())

			second, err := myCA.EnsureServingCert(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(second.Issued).To(BeTrue())
			Expect(second.Leaf.SerialNumber).NotTo(Equal(first.Leaf.SerialNumber))
		})

		It("reissues when the stored key does not match the stored certificate", func() {
			// A torn write between the two Puts. Recoverable, not fatal: the
			// alternative is every replica crash-looping with no route out but
			// deleting rows by hand.
			_, err := myCA.EnsureServingCert(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())

			other := ca.New(storage.New(GinkgoT().TempDir()), ca.AutosignConfig{Mode: "off"}, subject)
			other.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
			Expect(other.Init(ctx)).To(Succeed())
			foreign, err := other.EnsureServingCert(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(store.SaveServingKey(ctx, foreign.KeyPEM)).To(Succeed())

			got, err := myCA.EnsureServingCert(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(got.Issued).To(BeTrue())
		})

		It("reissues when the stored key is unreadable", func() {
			_, err := myCA.EnsureServingCert(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(store.SaveServingKey(ctx, []byte("not a key\n"))).To(Succeed())

			got, err := myCA.EnsureServingCert(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(got.Issued).To(BeTrue())
		})

		It("reissues a certificate issued by a different CA certificate", func() {
			// Checking the AuthorityKeyId would not catch this: the SKI is
			// derived from the public key, so a CA certificate re-signed over
			// the same key keeps its SKI and a stale serving certificate would
			// be retained silently.
			other := ca.New(storage.New(GinkgoT().TempDir()), ca.AutosignConfig{Mode: "off"}, subject)
			other.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
			Expect(other.Init(ctx)).To(Succeed())
			foreign, err := other.EnsureServingCert(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())

			Expect(store.SaveServingCert(ctx, foreign.CertPEM)).To(Succeed())
			Expect(store.SaveServingKey(ctx, foreign.KeyPEM)).To(Succeed())

			got, err := myCA.EnsureServingCert(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(got.Issued).To(BeTrue())
			Expect(got.Leaf.CheckSignatureFrom(myCA.CACert)).To(Succeed())
		})

		It("requires a subject", func() {
			_, err := myCA.EnsureServingCert(ctx, ca.ServingConfig{})
			Expect(err).To(MatchError(ContainSubstring("subject is required")))
		})

		It("does not deadlock when called twice in the same goroutine", func() {
			// The subject lock is not reentrant and neither is c.mu; the two
			// hazards this function's lock discipline exists to avoid both
			// present as a hang with no deadline to break it. Ginkgo's spec
			// timeout is what fails this if the discipline regresses.
			_, err := myCA.EnsureServingCert(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.EnsureServingCert(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())
		})

		It("leaves the CA able to sign for other subjects afterwards", func() {
			// Proves the subject lock and c.mu were both released.
			_, err := myCA.EnsureServingCert(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())
			res, err := myCA.Generate(ctx, "node1.example.com", nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.CertificatePEM).NotTo(BeEmpty())
		})

		It("records the certificate in the inventory, so it is revocable", func() {
			got, err := myCA.EnsureServingCert(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())

			// Revoking by subject finds it, which is what makes the compromise
			// recovery route above work at all.
			Expect(myCA.Revoke(ctx, subject)).To(Succeed())
			revoked, err := myCA.IsRevokedSerial(ctx, got.Leaf.SerialNumber)
			Expect(err).NotTo(HaveOccurred())
			Expect(revoked).To(BeTrue())
		})
	})

	Describe("encryption at rest", func() {
		It("stores an encrypted key when configured and reads it back", func() {
			myCA.KeyPassphrase = ca.KeyPassphraseConfig{PassphraseFile: passphraseFile("hunter2")}
			cfg.EncryptKey = true

			first, err := myCA.EnsureServingCert(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())

			stored, err := store.GetServingKey(ctx)
			Expect(err).NotTo(HaveOccurred())
			block, _ := pem.Decode(stored)
			Expect(block).NotTo(BeNil())
			Expect(block.Type).To(Equal("ENCRYPTED PRIVATE KEY"))

			// And it is reusable, not merely written.
			second, err := myCA.EnsureServingCert(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(second.Issued).To(BeFalse())
			Expect(second.Leaf.SerialNumber).To(Equal(first.Leaf.SerialNumber))
		})

		It("reissues rather than failing when the passphrase no longer decrypts", func() {
			// A rotated passphrase must not be unrecoverable: the material is
			// derived, so minting again is always available.
			myCA.KeyPassphrase = ca.KeyPassphraseConfig{PassphraseFile: passphraseFile("hunter2")}
			cfg.EncryptKey = true
			_, err := myCA.EnsureServingCert(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())

			myCA.KeyPassphrase = ca.KeyPassphraseConfig{PassphraseFile: passphraseFile("different")}
			got, err := myCA.EnsureServingCert(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(got.Issued).To(BeTrue())
		})

		It("reads a plaintext key back after encryption is switched on", func() {
			// Keying on the stored block rather than on configuration means
			// flipping the setting is not a hard failure.
			first, err := myCA.EnsureServingCert(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())

			myCA.KeyPassphrase = ca.KeyPassphraseConfig{PassphraseFile: passphraseFile("hunter2")}
			cfg.EncryptKey = true
			second, err := myCA.EnsureServingCert(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(second.Issued).To(BeFalse(), "an existing plaintext key is still usable")
			Expect(second.Leaf.SerialNumber).To(Equal(first.Leaf.SerialNumber))
		})
	})
})

var _ = Describe("Superseded serving certificates", func() {
	const subject = "puppet.example.com"

	var (
		ctx   context.Context
		store *storage.StorageService
		myCA  *ca.CA
		cfg   ca.ServingConfig
	)

	// reissue forces a mint by putting any stored certificate inside the
	// renewal window, and returns the certificate it replaced.
	//
	// reissueCount is reset per spec in the BeforeEach below: the Describe body
	// runs once at tree construction, so leaving it here would make each spec's
	// forced SAN depend on how many siblings ran first.
	reissueCount := 0
	reissue := func() *x509.Certificate {
		GinkgoHelper()
		before, err := myCA.EnsureServingCert(ctx, cfg)
		Expect(err).NotTo(HaveOccurred())

		// A name the stored certificate does not cover forces the reissue; see
		// the note in "reissues once inside the renewal window" for why an
		// over-large renew-before does not.
		widened := cfg
		widened.ExtraNames = append(append([]string{}, cfg.ExtraNames...),
			fmt.Sprintf("alt%d.example.com", reissueCount))
		reissueCount++
		after, err := myCA.EnsureServingCert(ctx, widened)
		Expect(err).NotTo(HaveOccurred())
		Expect(after.Issued).To(BeTrue())
		Expect(after.Leaf.SerialNumber).NotTo(Equal(before.Leaf.SerialNumber))
		return before.Leaf
	}

	BeforeEach(func() {
		reissueCount = 0
		ctx = context.Background()
		store = storage.New(GinkgoT().TempDir())
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, subject)
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())
		cfg = ca.ServingConfig{Subject: subject, RevokeAfter: time.Hour}
	})

	It("does not revoke the replaced certificate before its delay elapses", func() {
		// The swap is per-process: a sibling replica may still be serving the
		// old certificate, and revoking immediately breaks every client doing
		// revocation checking.
		old := reissue()
		Expect(myCA.ReconcileSuperseded(ctx, revokeCfg(subject, time.Hour))).To(Succeed())

		revoked, err := myCA.IsRevokedSerial(ctx, old.SerialNumber)
		Expect(err).NotTo(HaveOccurred())
		Expect(revoked).To(BeFalse())
	})

	It("revokes the replaced certificate once the delay has elapsed", func() {
		// revoke_at is stamped at mint time, so a tiny delay there is what
		// makes the entry due — the reconcile argument only says whether
		// revocation is enabled at all.
		cfg.RevokeAfter = time.Nanosecond
		old := reissue()

		Expect(myCA.ReconcileSuperseded(ctx, revokeCfg(subject, time.Hour))).To(Succeed())

		revoked, err := myCA.IsRevokedSerial(ctx, old.SerialNumber)
		Expect(err).NotTo(HaveOccurred())
		Expect(revoked).To(BeTrue())
	})

	It("leaves the live certificate valid when revoking its predecessor", func() {
		// The trap this guards: CA.Revoke resolves subject to the *current*
		// certificate, so revoking by subject here would revoke the one being
		// served. The sweep must revoke the recorded serial and nothing else.
		cfg.RevokeAfter = time.Nanosecond
		old := reissue()
		live, err := myCA.EnsureServingCert(ctx, cfg)
		Expect(err).NotTo(HaveOccurred())

		Expect(myCA.ReconcileSuperseded(ctx, revokeCfg(subject, time.Hour))).To(Succeed())

		oldRevoked, err := myCA.IsRevokedSerial(ctx, old.SerialNumber)
		Expect(err).NotTo(HaveOccurred())
		Expect(oldRevoked).To(BeTrue())

		liveRevoked, err := myCA.IsRevokedSerial(ctx, live.Leaf.SerialNumber)
		Expect(err).NotTo(HaveOccurred())
		Expect(liveRevoked).To(BeFalse(), "the certificate being served must stay valid")
	})

	It("prunes the list, so a second pass revokes nothing new", func() {
		cfg.RevokeAfter = time.Nanosecond
		reissue()
		Expect(myCA.ReconcileSuperseded(ctx, revokeCfg(subject, time.Hour))).To(Succeed())

		stored, err := store.GetServingSuperseded(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(stored)).To(Equal("[]"))
	})

	It("discards the list without revoking when the delay is switched off", func() {
		// Otherwise an entry recorded under a non-zero delay would sit there
		// indefinitely and fire much later if the delay were re-enabled.
		old := reissue()
		Expect(myCA.ReconcileSuperseded(ctx, revokeCfg(subject, 0))).To(Succeed())

		revoked, err := myCA.IsRevokedSerial(ctx, old.SerialNumber)
		Expect(err).NotTo(HaveOccurred())
		Expect(revoked).To(BeFalse())

		stored, err := store.GetServingSuperseded(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(stored)).To(Equal("[]"))
	})

	It("records nothing when revocation is disabled at mint time", func() {
		cfg.RevokeAfter = 0
		reissue()

		_, err := store.GetServingSuperseded(ctx)
		Expect(err).To(HaveOccurred(), "nothing should have been written")
	})

	It("is completed by another replica, since the list is shared", func() {
		// The minting replica may die before the delay elapses; any replica
		// must be able to finish the job.
		cfg.RevokeAfter = time.Nanosecond
		old := reissue()

		other := ca.New(store, ca.AutosignConfig{Mode: "off"}, subject)
		other.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(other.Init(ctx)).To(Succeed())
		Expect(other.ReconcileSuperseded(ctx, revokeCfg(subject, time.Hour))).To(Succeed())

		// Asserted through the replica that did the work: each process holds
		// its own in-memory CRL cache, and myCA has not refreshed since.
		revoked, err := other.IsRevokedSerial(ctx, old.SerialNumber)
		Expect(err).NotTo(HaveOccurred())
		Expect(revoked).To(BeTrue())
	})

	It("is a no-op with nothing pending", func() {
		Expect(myCA.ReconcileSuperseded(ctx, revokeCfg(subject, time.Hour))).To(Succeed())
	})

	It("survives an unparseable list rather than refusing to serve", func() {
		// Worst case is a superseded certificate staying valid until it
		// expires; failing closed would take the listener down instead.
		Expect(store.SaveServingSuperseded(ctx, []byte("{not json"))).To(Succeed())
		Expect(myCA.ReconcileSuperseded(ctx, revokeCfg(subject, time.Hour))).To(Succeed())
	})
})

// revokeCfg is the minimal ServingConfig ReconcileSuperseded needs: the subject
// names the lock it serialises on, the delay decides what is due.
func revokeCfg(subject string, revokeAfter time.Duration) ca.ServingConfig {
	return ca.ServingConfig{Subject: subject, RevokeAfter: revokeAfter}
}

// failReadBackend fails Get for one key with a non-fs.ErrNotExist error, so a
// read failure can be told apart from absent material. Everything else passes
// through to the real backend.
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

var _ = Describe("Renewing a node that has taken the CA's hostname", func() {
	// validateTLS refuses this configuration when it can see it -- a
	// puppet_server CN -- but it cannot see an ordinary agent that takes the
	// name. Without the guard in Renew, that agent's renewal revokes the
	// certificate the listener is serving, immediately, with none of the delay
	// tls_self_provision_revoke_after_sec exists to give.
	const hostname = "openvox-ca.example.com"

	var (
		ctx   context.Context
		store *storage.StorageService
		myCA  *ca.CA
	)

	BeforeEach(func() {
		ctx = context.Background()
		store = storage.New(GinkgoT().TempDir())
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, hostname)
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())
	})

	csrFor := func(cn string) []byte {
		GinkgoHelper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		der, err := x509.CreateCertificateRequest(rand.Reader,
			&x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
		Expect(err).NotTo(HaveOccurred())
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	}

	It("does not revoke the live serving certificate", func() {
		serving, err := myCA.EnsureServingCert(ctx, ca.ServingConfig{Subject: hostname})
		Expect(err).NotTo(HaveOccurred())

		// A node renews under the CA's own name. LatestSerialForSubject
		// resolves to the serving certificate, because it was issued last.
		_, err = myCA.Renew(ctx, hostname, csrFor(hostname))
		Expect(err).NotTo(HaveOccurred())

		revoked, err := myCA.IsRevokedSerial(ctx, serving.Leaf.SerialNumber)
		Expect(err).NotTo(HaveOccurred())
		Expect(revoked).To(BeFalse(),
			"renewing under the CA's hostname must not revoke the certificate it is serving")

		// And the comparison must be a comparison: a second renewal replaces
		// the node's own certificate, whose serial is not the serving one, so
		// that predecessor must still be revoked. Widening the guard to "a
		// serving certificate exists" would leave it valid indefinitely.
		latest, err := myCA.Storage.LatestSerialForSubject(ctx, hostname)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.Renew(ctx, hostname, csrFor(hostname))
		Expect(err).NotTo(HaveOccurred())

		want := new(big.Int)
		_, ok := want.SetString(latest, 16)
		Expect(ok).To(BeTrue())
		revoked, err = myCA.IsRevokedSerial(ctx, want)
		Expect(err).NotTo(HaveOccurred())
		Expect(revoked).To(BeTrue(),
			"a replaced certificate that is not the serving one must still be revoked")
	})

	It("skips the revocation when the serving certificate cannot be read", func() {
		// The arm round 3 added, and the one that had no spec: reverting it to
		// `return false` restores the fail-open a reviewer blocked on, with the
		// whole suite otherwise green. A read failure is not an answer, so the
		// revoke must not proceed on it.
		dir := GinkgoT().TempDir()
		seed := ca.New(storage.New(dir), ca.AutosignConfig{Mode: "off"}, hostname)
		seed.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		seed.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(seed.Init(ctx)).To(Succeed())
		serving, err := seed.EnsureServingCert(ctx, ca.ServingConfig{Subject: hostname})
		Expect(err).NotTo(HaveOccurred())

		base := storage.NewFilesystemBackend(dir)
		blind := ca.New(storage.NewWithBackend(
			&failReadBackend{Backend: base, failKey: storage.KeyServingCert}, dir),
			ca.AutosignConfig{Mode: "off"}, hostname)
		blind.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		blind.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(blind.Init(ctx)).To(Succeed())

		_, err = blind.Renew(ctx, hostname, csrFor(hostname))
		Expect(err).NotTo(HaveOccurred())

		// The serial Renew resolves is the serving certificate's -- it was
		// issued last -- so that is the one that must survive.
		revoked, err := blind.IsRevokedSerial(ctx, serving.Leaf.SerialNumber)
		Expect(err).NotTo(HaveOccurred())
		Expect(revoked).To(BeFalse(),
			"an unreadable serving certificate must not let the revocation through")
	})

	It("revokes normally when no serving certificate is stored", func() {
		// The precision half, and the fs.ErrNotExist arm. Without it the guard
		// could be reduced to `subject == c.Hostname` and still pass, which
		// would silently end revoke-on-renew for the CA's hostname -- and with
		// tls_self_provision off that is an ordinary node certname.
		//
		// Note the collision cannot be built the other way round: while a
		// serving certificate is stored, Generate and SaveRequest refuse a
		// certificate for the same subject (ErrCertExists), so a node can only
		// take the name if it held it first or the serving one was revoked.
		first, err := myCA.Generate(ctx, hostname, nil)
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(first.CertificatePEM)
		Expect(block).NotTo(BeNil())
		firstCrt, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())

		_, err = myCA.Renew(ctx, hostname, csrFor(hostname))
		Expect(err).NotTo(HaveOccurred())

		revoked, err := myCA.IsRevokedSerial(ctx, firstCrt.SerialNumber)
		Expect(err).NotTo(HaveOccurred())
		Expect(revoked).To(BeTrue())
	})
})

var _ = Describe("Serving certificate read failures", func() {
	// The rule under test: a read failure is not evidence the stored material
	// is unusable. Minting on it would let a degraded backend rotate the
	// certificate every replica serves and schedule the good one for
	// revocation. Without these specs the guard can be deleted and the whole
	// suite stays green.
	const subject = "puppet.example.com"

	var (
		ctx  context.Context
		dir  string
		base storage.Backend
	)

	BeforeEach(func() {
		ctx = context.Background()
		dir = GinkgoT().TempDir()
		base = storage.NewFilesystemBackend(dir)

		// Seed a good certificate through a normal service first.
		seed := ca.New(storage.New(dir), ca.AutosignConfig{Mode: "off"}, subject)
		seed.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		seed.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(seed.Init(ctx)).To(Succeed())
		Expect(seed.EnsureServingCert(ctx, ca.ServingConfig{Subject: subject})).Error().NotTo(HaveOccurred())
	})

	withFailingRead := func(failKey string) *ca.CA {
		GinkgoHelper()
		store := storage.NewWithBackend(&failReadBackend{Backend: base, failKey: failKey}, dir)
		blind := ca.New(store, ca.AutosignConfig{Mode: "off"}, subject)
		blind.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		blind.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(blind.Init(ctx)).To(Succeed())
		return blind
	}

	It("counts a revocation failure when it cannot read what it is replacing", func() {
		// The supersession-record path, not the reuse path: the mint is already
		// under way and storedServingLeaf cannot read the certificate being
		// replaced, so nothing is scheduled for revocation and the only signal
		// that happened is this counter.
		store := storage.NewWithBackend(&failReadBackend{Backend: base, failKey: storage.KeyServingCert}, dir)
		blind := ca.New(store, ca.AutosignConfig{Mode: "off"}, subject)
		blind.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		blind.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(blind.Init(ctx)).To(Succeed())

		Expect(blind.ServingRevocationFailureCount()).To(BeZero())
		blind.StoredServingLeafForTest(ctx)
		Expect(blind.ServingRevocationFailureCount()).To(Equal(uint64(1)))
	})

	It("does not count a revocation failure for bytes that do not parse", func() {
		// Those are not a credential in circulation, so counting them would
		// fire an alert telling the operator a replaced certificate is still
		// valid when none exists.
		good := ca.New(storage.New(dir), ca.AutosignConfig{Mode: "off"}, subject)
		good.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		good.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(good.Init(ctx)).To(Succeed())
		Expect(storage.New(dir).SaveServingCert(ctx, []byte("not a certificate\n"))).To(Succeed())

		good.StoredServingLeafForTest(ctx)
		Expect(good.ServingRevocationFailureCount()).To(BeZero())
	})

	DescribeTable("surfaces the failure instead of minting over the stored certificate",
		func(failKey, wantReason string) {
			blind := withFailingRead(failKey)
			before := blind.ServingCertIssued()

			code, detail := blind.ServingReuseReasonForTest(ctx, ca.ServingConfig{Subject: subject})
			Expect(code).To(Equal(wantReason))
			Expect(detail).To(BeEmpty(), "backend error text must not reach the reason")

			_, err := blind.EnsureServingCert(ctx, ca.ServingConfig{Subject: subject})
			Expect(err).To(HaveOccurred(), "a read failure must not be treated as unusable material")
			Expect(blind.ServingCertIssued()).To(Equal(before),
				"nothing may be minted over a certificate we merely could not read")
		},
		Entry("certificate", storage.KeyServingCert, "certificate-unreadable"),
		Entry("key", storage.KeyServingKey, "key-unreadable"),
	)
})

var _ = Describe("Serving certificate reuse reasons", func() {
	const subject = "puppet.example.com"

	var (
		ctx   context.Context
		store *storage.StorageService
		myCA  *ca.CA
		cfg   ca.ServingConfig
	)

	BeforeEach(func() {
		ctx = context.Background()
		store = storage.New(GinkgoT().TempDir())
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, subject)
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())
		cfg = ca.ServingConfig{Subject: subject}
	})

	reasonFor := func() (string, string) {
		GinkgoHelper()
		return myCA.ServingReuseReasonForTest(ctx, cfg)
	}

	It("is empty when the stored certificate is usable", func() {
		Expect(myCA.EnsureServingCert(ctx, cfg)).Error().NotTo(HaveOccurred())
		code, detail := reasonFor()
		Expect(code).To(BeEmpty())
		Expect(detail).To(BeEmpty())
	})

	It("mints again when the key never landed, and says so distinctly", func() {
		// The torn-write case the code documents: certificate stored, key
		// absent. Genuinely unusable material, so it must mint -- and it must
		// be distinguishable from a key that could not be *read*, which is I/O
		// and must not mint over a certificate that may be fine.
		Expect(myCA.EnsureServingCert(ctx, cfg)).Error().NotTo(HaveOccurred())
		Expect(store.Backend().Delete(ctx, storage.KeyServingKey)).To(Succeed())

		code, detail := reasonFor()
		Expect(code).To(Equal("key-missing"))
		Expect(detail).To(BeEmpty())
		Expect(myCA.EnsureServingCert(ctx, cfg)).Error().NotTo(HaveOccurred())
	})

	It("mints again when the stored certificate is not PEM", func() {
		// The certificate side of the unusable-material policy; every other
		// spec here corrupts the key.
		Expect(myCA.EnsureServingCert(ctx, cfg)).Error().NotTo(HaveOccurred())
		Expect(store.SaveServingCert(ctx, []byte("not a certificate\n"))).To(Succeed())

		code, _ := reasonFor()
		Expect(code).To(Equal("certificate-not-pem"))
		Expect(myCA.EnsureServingCert(ctx, cfg)).Error().NotTo(HaveOccurred())
	})

	It("reports a stable code with no detail when nothing is stored", func() {
		code, detail := reasonFor()
		Expect(code).To(Equal("no-stored-certificate"))
		Expect(detail).To(BeEmpty())
	})

	It("withholds the error text when the stored key cannot be read", func() {
		// SECURITY: this reason is logged at Info on every reissue. The error
		// comes from the storage backend, and a SQL driver's connection error
		// can carry the DSN — which carries a password. The code says what
		// happened; the detail stays empty.
		Expect(myCA.EnsureServingCert(ctx, cfg)).Error().NotTo(HaveOccurred())
		Expect(store.SaveServingKey(ctx, []byte("not a key\n"))).To(Succeed())

		code, detail := reasonFor()
		Expect(code).To(Equal("key-unusable"))
		Expect(detail).To(BeEmpty())
	})

	It("withholds the passphrase file path when the key cannot be decrypted", func() {
		// The path is not a secret, but it reaches this string through
		// resolvePassphrase's error and has no business in a routine rotation
		// log line. This is the flow CodeQL traced.
		myCA.KeyPassphrase = ca.KeyPassphraseConfig{PassphraseFile: passphraseFile("hunter2")}
		cfg.EncryptKey = true
		Expect(myCA.EnsureServingCert(ctx, cfg)).Error().NotTo(HaveOccurred())

		secret := passphraseFile("different")
		myCA.KeyPassphrase = ca.KeyPassphraseConfig{PassphraseFile: secret}

		code, detail := reasonFor()
		Expect(code).To(Equal("key-unusable"))
		Expect(detail).To(BeEmpty())
		Expect(detail).NotTo(ContainSubstring(secret), "the configured path must not reach the log")
	})

	It("carries only operator-supplied detail for a missing name", func() {
		Expect(myCA.EnsureServingCert(ctx, cfg)).Error().NotTo(HaveOccurred())
		cfg.ExtraNames = []string{"ingress.example.com"}

		code, detail := reasonFor()
		Expect(code).To(Equal("missing-configured-name"))
		Expect(detail).To(Equal("ingress.example.com"))
	})

	It("keeps a withdrawn name until the certificate is reissued for another reason", func() {
		// Not an oversight: a subset test is what makes a mixed-configuration
		// fleet converge. Set equality would leave replicas whose name lists
		// differ minting over each other forever. See missingNames.
		cfg.ExtraNames = []string{"ingress.example.com"}
		Expect(myCA.EnsureServingCert(ctx, cfg)).Error().NotTo(HaveOccurred())

		cfg.ExtraNames = nil
		code, _ := reasonFor()
		Expect(code).To(BeEmpty(), "a withdrawn name alone must not force a reissue")

		reused, err := myCA.EnsureServingCert(ctx, cfg)
		Expect(err).NotTo(HaveOccurred())
		Expect(reused.Issued).To(BeFalse())
		Expect(reused.Leaf.DNSNames).To(ContainElement("ingress.example.com"))
	})

	It("drops a withdrawn name once the serving certificate is revoked", func() {
		// The remedy the missingNames comment points at, and the reason the
		// subset rule is acceptable: revocation is shared state, so every
		// replica agrees, and the reissue picks up the current configuration.
		cfg.ExtraNames = []string{"ingress.example.com"}
		Expect(myCA.EnsureServingCert(ctx, cfg)).Error().NotTo(HaveOccurred())

		cfg.ExtraNames = nil
		Expect(myCA.Revoke(ctx, subject)).To(Succeed())

		reissued, err := myCA.EnsureServingCert(ctx, cfg)
		Expect(err).NotTo(HaveOccurred())
		Expect(reissued.Issued).To(BeTrue())
		Expect(reissued.Leaf.DNSNames).NotTo(ContainElement("ingress.example.com"))
	})

	It("carries only clock arithmetic as detail in the renewal window", func() {
		issued, err := myCA.EnsureServingCert(ctx, cfg)
		Expect(err).NotTo(HaveOccurred())

		// Derived from the certificate actually issued: a window at or beyond
		// the lifetime is clamped, so it would not put this inside the window.
		lifetime := issued.Leaf.NotAfter.Sub(issued.Leaf.NotBefore)
		cfg.RenewBefore = lifetime - time.Hour

		code, detail := reasonFor()
		Expect(code).To(Equal("within-renewal-window"))
		Expect(detail).To(HaveSuffix("remaining"))
	})

	It("reports revocation with no detail", func() {
		Expect(myCA.EnsureServingCert(ctx, cfg)).Error().NotTo(HaveOccurred())
		Expect(myCA.Revoke(ctx, subject)).To(Succeed())

		code, detail := reasonFor()
		Expect(code).To(Equal("certificate-revoked"))
		Expect(detail).To(BeEmpty())
	})
})
