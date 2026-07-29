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
	"crypto/x509"
	"encoding/pem"
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

			// A renew-before longer than the whole lifetime puts any certificate
			// inside the window, without waiting or faking a clock.
			cfg.RenewBefore = 100 * 365 * 24 * time.Hour
			second, err := myCA.EnsureServingCert(ctx, cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(second.Issued).To(BeTrue())
			Expect(second.Leaf.SerialNumber).NotTo(Equal(first.Leaf.SerialNumber))
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
	reissue := func() *x509.Certificate {
		GinkgoHelper()
		before, err := myCA.EnsureServingCert(ctx, cfg)
		Expect(err).NotTo(HaveOccurred())

		widened := cfg
		widened.RenewBefore = 100 * 365 * 24 * time.Hour
		after, err := myCA.EnsureServingCert(ctx, widened)
		Expect(err).NotTo(HaveOccurred())
		Expect(after.Issued).To(BeTrue())
		Expect(after.Leaf.SerialNumber).NotTo(Equal(before.Leaf.SerialNumber))
		return before.Leaf
	}

	BeforeEach(func() {
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
		Expect(myCA.ReconcileSuperseded(ctx, time.Hour)).To(Succeed())

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

		Expect(myCA.ReconcileSuperseded(ctx, time.Hour)).To(Succeed())

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

		Expect(myCA.ReconcileSuperseded(ctx, time.Hour)).To(Succeed())

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
		Expect(myCA.ReconcileSuperseded(ctx, time.Hour)).To(Succeed())

		stored, err := store.GetServingSuperseded(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(stored)).To(Equal("[]"))
	})

	It("discards the list without revoking when the delay is switched off", func() {
		// Otherwise an entry recorded under a non-zero delay would sit there
		// indefinitely and fire much later if the delay were re-enabled.
		old := reissue()
		Expect(myCA.ReconcileSuperseded(ctx, 0)).To(Succeed())

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
		Expect(other.ReconcileSuperseded(ctx, time.Hour)).To(Succeed())

		// Asserted through the replica that did the work: each process holds
		// its own in-memory CRL cache, and myCA has not refreshed since.
		revoked, err := other.IsRevokedSerial(ctx, old.SerialNumber)
		Expect(err).NotTo(HaveOccurred())
		Expect(revoked).To(BeTrue())
	})

	It("is a no-op with nothing pending", func() {
		Expect(myCA.ReconcileSuperseded(ctx, time.Hour)).To(Succeed())
	})

	It("survives an unparseable list rather than refusing to serve", func() {
		// Worst case is a superseded certificate staying valid until it
		// expires; failing closed would take the listener down instead.
		Expect(store.SaveServingSuperseded(ctx, []byte("{not json"))).To(Succeed())
		Expect(myCA.ReconcileSuperseded(ctx, time.Hour)).To(Succeed())
	})
})
