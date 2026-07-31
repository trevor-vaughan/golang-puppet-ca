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

	It("keeps the entries a corrupt list still yields", func() {
		// encoding/json fills the slice as it decodes, so a blob with one bad
		// field still names real, revocable serials before it. Discarding them
		// and writing nil made those permanently unrevokable -- and hand-editing
		// this blob is a realistic thing to do precisely because there is no
		// by-serial revoke.
		issued, err := myCA.EnsureServingCert(ctx, cfg)
		Expect(err).NotTo(HaveOccurred())
		good := fmt.Sprintf("%X", issued.Leaf.SerialNumber)

		partial := fmt.Sprintf(
			`[{"serial":%q,"revoke_at":"2020-01-01T00:00:00Z"},`+
				`{"serial":"CD","revoke_at":"soon"}]`, good)
		Expect(store.SaveServingSuperseded(ctx, []byte(partial))).To(Succeed())

		Expect(myCA.ReconcileSuperseded(ctx, revokeCfg(subject, time.Hour))).To(Succeed())

		revoked, err := myCA.IsRevokedSerial(ctx, issued.Leaf.SerialNumber)
		Expect(err).NotTo(HaveOccurred())
		Expect(revoked).To(BeTrue(),
			"a serial that decoded before the corruption is still revocable")
	})

	It("schedules a revocation even when the pending list is corrupt", func() {
		// The mint path's half: recordSuperseded discards the corrupt flag on
		// purpose, because appending to what decoded and writing is the
		// overwrite those bytes need. Refusing instead would leave the
		// certificate it just replaced with nothing scheduling its revocation,
		// on top of whatever the corrupt bytes already lost.
		Expect(store.SaveServingSuperseded(ctx, []byte("{not json"))).To(Succeed())

		first, err := myCA.EnsureServingCert(ctx, cfg)
		Expect(err).NotTo(HaveOccurred())
		cfg.ExtraNames = []string{"alt.example.com"}
		Expect(myCA.EnsureServingCert(ctx, cfg)).Error().NotTo(HaveOccurred())

		pending, err := store.GetServingSuperseded(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(pending)).To(ContainSubstring(fmt.Sprintf("%X", first.Leaf.SerialNumber)),
			"the replaced certificate must still be scheduled for revocation")
	})

	It("requires a subject", func() {
		// The twin of EnsureServingCert's own guard. Without it an empty subject
		// takes the lock named "subject:", finds nothing pending and returns
		// nil -- so the caller-side guard in reconcileAtStartup would be the
		// only thing standing between a misconfiguration and a silent no-op.
		Expect(myCA.ReconcileSuperseded(ctx, ca.ServingConfig{})).To(
			MatchError(ContainSubstring("subject is required")))
	})

	It("survives an unparseable list rather than refusing to serve", func() {
		// Worst case is a superseded certificate staying valid until it
		// expires; failing closed would take the listener down instead.
		//
		// But it is a loss, and the least recoverable one on this path: nothing
		// can rediscover what those bytes named. So it must be counted like the
		// other unrecoverable arms, and the bytes must actually be overwritten
		// -- treating them as merely "empty" took the early return below, left
		// them in place, and re-warned on every pass forever while the one
		// counter that bounds the exposure stayed at zero.
		Expect(store.SaveServingSuperseded(ctx, []byte("{not json"))).To(Succeed())
		Expect(myCA.ReconcileSuperseded(ctx, revokeCfg(subject, time.Hour))).To(Succeed())

		Expect(myCA.ServingRevocationFailureCount()).To(Equal(uint64(1)))
		after, err := store.GetServingSuperseded(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(after)).To(Equal("[]"),
			"bytes that will never parse must be cleared, not re-read every pass")
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
		return nil, errors.New(backendErrText)
	}
	return b.Backend.Get(ctx, key)
}

// backendErrText stands in for what a real backend error carries. The specs
// that assert it does not reach the caller are checking a security property:
// on a SQL backend this text is the driver's, and a driver's connection error
// carries the DSN, which carries a password.
const backendErrText = "backend unavailable dsn=postgres://user:hunter2@db/ca"

// failWriteBackend fails Put for one key. The twin of failReadBackend, and the
// reason every write-failure branch on this path went unexercised until it
// existed.
type failWriteBackend struct {
	storage.Backend
	failKey string
}

func (b *failWriteBackend) Put(ctx context.Context, key string, data []byte, kind storage.BlobKind) error {
	if key == b.failKey {
		return errors.New(backendErrText)
	}
	return b.Backend.Put(ctx, key, data, kind)
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

	// caOver builds a second CA over an existing directory, as a replica or a
	// restarted process would.
	caOver := func(store *storage.StorageService) *ca.CA {
		GinkgoHelper()
		other := ca.New(store, ca.AutosignConfig{Mode: "off"}, hostname)
		other.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		other.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(other.Init(ctx)).To(Succeed())
		return other
	}

	DescribeTable("skips the revocation whenever it cannot tell what is being served",
		// Every state in which servingSerialMatches cannot answer must answer
		// alike, because the listener holds its certificate in memory: corrupt
		// or unreadable storage does not put the credential out of circulation,
		// and the serial being compared comes from the inventory, not from
		// these bytes. Reverting any one arm to `return false` re-opens the
		// fail-open round 3 blocked on. Only the read arm had a spec.
		func(blindOver func(dir string) *ca.CA) {
			dir := GinkgoT().TempDir()
			seed := caOver(storage.New(dir))
			serving, err := seed.EnsureServingCert(ctx, ca.ServingConfig{Subject: hostname})
			Expect(err).NotTo(HaveOccurred())

			blind := blindOver(dir)
			_, err = blind.Renew(ctx, hostname, csrFor(hostname))
			Expect(err).NotTo(HaveOccurred())

			// The serial Renew resolves is the serving certificate's -- it was
			// issued last -- so that is the one that must survive.
			revoked, err := blind.IsRevokedSerial(ctx, serving.Leaf.SerialNumber)
			Expect(err).NotTo(HaveOccurred())
			Expect(revoked).To(BeFalse(),
				"a serving certificate it cannot read must not let the revocation through")
		},
		Entry("the read fails", func(dir string) *ca.CA {
			return caOver(storage.NewWithBackend(&failReadBackend{
				Backend: storage.NewFilesystemBackend(dir),
				failKey: storage.KeyServingCert,
			}, dir))
		}),
		Entry("the stored bytes are not PEM", func(dir string) *ca.CA {
			Expect(storage.New(dir).SaveServingCert(
				context.Background(), []byte("not a certificate\n"))).To(Succeed())
			return caOver(storage.New(dir))
		}),
		Entry("the PEM block is not a certificate", func(dir string) *ca.CA {
			Expect(storage.New(dir).SaveServingCert(context.Background(),
				pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: []byte("this is not DER"),
				}))).To(Succeed())
			return caOver(storage.New(dir))
		}),
	)

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

var _ = Describe("Reconciling superseded serving certificates", func() {
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
		cfg = ca.ServingConfig{Subject: subject, RevokeAfter: time.Hour}
	})

	It("keeps an entry whose revocation failed for a reason that may pass", func() {
		// The carry-forward arm, distinct from the discard beside it: a
		// well-formed serial that could not be revoked *this* pass must stay on
		// the list, or it becomes a valid credential for its full remaining
		// life with nothing recording that it should not be. A corrupt CRL is
		// the transient shape -- revokeSerialLocked must read the CRL before it
		// can add to it -- and it is what round 6 stopped covering when the
		// malformed serial it had used became a discard instead.
		issued, err := myCA.EnsureServingCert(ctx, cfg)
		Expect(err).NotTo(HaveOccurred())
		serial := fmt.Sprintf("%X", issued.Leaf.SerialNumber)

		due := fmt.Sprintf(`[{"serial":%q,"revoke_at":"2020-01-01T00:00:00Z"}]`, serial)
		Expect(store.SaveServingSuperseded(ctx, []byte(due))).To(Succeed())
		Expect(store.UpdateCRL(ctx, []byte("not a CRL"))).To(Succeed())

		// The pass itself succeeds: one entry failing must not fail the sweep,
		// which would strand every other entry behind it.
		Expect(myCA.ReconcileSuperseded(ctx, cfg)).To(Succeed())

		left, err := store.GetServingSuperseded(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(left)).To(ContainSubstring(serial),
			"a failed revocation must be retried, not dropped")
		Expect(myCA.ServingRevocationFailureCount()).To(Equal(uint64(1)))
	})

	It("revokes the entries it can and discards one it never could", func() {
		// The property the per-entry loop exists for: partial progress across a
		// mixed due list. Aborting on the first failure -- the previous
		// behaviour -- would leave the good serial unrevoked and every
		// certificate behind it a valid credential indefinitely.
		//
		// A single-entry list cannot tell the two implementations apart, which
		// is why this one has both.
		first, err := myCA.EnsureServingCert(ctx, cfg)
		Expect(err).NotTo(HaveOccurred())
		cfg.ExtraNames = []string{"alt.example.com"}
		second, err := myCA.EnsureServingCert(ctx, cfg)
		Expect(err).NotTo(HaveOccurred())
		Expect(second.Leaf.SerialNumber.Cmp(first.Leaf.SerialNumber)).NotTo(BeZero())

		// The malformed entry sits *between* the two good ones. With it last,
		// abandoning the loop at the first bad entry still revoked everything
		// and the spec could not tell the two implementations apart.
		due := fmt.Sprintf(
			`[{"serial":%q,"revoke_at":"2020-01-01T00:00:00Z"},`+
				`{"serial":"zz","revoke_at":"2020-01-01T00:00:00Z"},`+
				`{"serial":%q,"revoke_at":"2020-01-01T00:00:00Z"}]`,
			fmt.Sprintf("%X", first.Leaf.SerialNumber),
			fmt.Sprintf("%X", second.Leaf.SerialNumber))
		Expect(store.SaveServingSuperseded(ctx, []byte(due))).To(Succeed())

		Expect(myCA.ReconcileSuperseded(ctx, cfg)).To(Succeed())

		for _, leaf := range []*x509.Certificate{first.Leaf, second.Leaf} {
			revoked, err := myCA.IsRevokedSerial(ctx, leaf.SerialNumber)
			Expect(err).NotTo(HaveOccurred())
			Expect(revoked).To(BeTrue(), "a failing entry must not block the ones beside it")
		}

		// The malformed entry is dropped, not carried: it can never succeed, and
		// retrying it forever would latch an alert with no way to clear it.
		left, err := store.GetServingSuperseded(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(left)).NotTo(ContainSubstring("zz"))
		Expect(myCA.ServingRevocationFailureCount()).To(Equal(uint64(1)))
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

	It("counts a revocation failure when it cannot record the supersession", func() {
		// The sibling of the arm above, and the other unrecoverable one: the
		// mint has already overwritten what named the old serial, so no later
		// sweep can rediscover it. The counter is the only signal it happened.
		store := storage.NewWithBackend(
			&failReadBackend{Backend: base, failKey: storage.KeyServingSuperseded}, dir)
		blind := ca.New(store, ca.AutosignConfig{Mode: "off"}, subject)
		blind.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		blind.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(blind.Init(ctx)).To(Succeed())

		cfg := ca.ServingConfig{Subject: subject, RevokeAfter: time.Hour}
		Expect(blind.EnsureServingCert(ctx, cfg)).Error().NotTo(HaveOccurred())
		Expect(blind.ServingRevocationFailureCount()).To(BeZero(),
			"the seeded certificate is still usable, and the reuse path reads no pending list")

		cfg.ExtraNames = []string{"alt.example.com"}
		reissued, err := blind.EnsureServingCert(ctx, cfg)
		Expect(err).NotTo(HaveOccurred())
		Expect(reissued.Issued).To(BeTrue(),
			"failing to schedule the revocation must not stop the CA serving")
		Expect(blind.ServingRevocationFailureCount()).To(Equal(uint64(1)))
	})

	It("writes the serving private key readable only by its owner", func() {
		// BlobPrivate is the only thing selecting 0600 here, and flipping it to
		// BlobPublic left the whole suite green -- the migration spec that does
		// assert FilePermPrivate takes its mode from migratableSingletons, a
		// separate list, so it does not cover the mint. A world-readable private
		// key in a shared cadir volume is the deployment shape this feature
		// targets, and docs/development/storage-internals.md states 0600.
		fresh := GinkgoT().TempDir()
		minter := ca.New(storage.New(fresh), ca.AutosignConfig{Mode: "off"}, subject)
		minter.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		minter.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(minter.Init(ctx)).To(Succeed())
		Expect(minter.EnsureServingCert(ctx, ca.ServingConfig{Subject: subject})).
			Error().NotTo(HaveOccurred())

		info, err := os.Stat(filepath.Join(fresh, "private", "serving_key.pem"))
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o600)))
	})

	It("counts a revocation failure when it cannot persist the supersession", func() {
		// The write-side twin of the arm above, and the one no double could
		// reach: returning nil from writeSuperseded instead of the error made
		// recordSuperseded report success on a write that never landed, so the
		// mint path counted nothing and the superseded certificate stayed a
		// valid credential for its full remaining life.
		store := storage.NewWithBackend(
			&failWriteBackend{Backend: base, failKey: storage.KeyServingSuperseded}, dir)
		blind := ca.New(store, ca.AutosignConfig{Mode: "off"}, subject)
		blind.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		blind.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(blind.Init(ctx)).To(Succeed())

		cfg := ca.ServingConfig{Subject: subject, RevokeAfter: time.Hour, ExtraNames: []string{"alt.example.com"}}
		reissued, err := blind.EnsureServingCert(ctx, cfg)
		Expect(err).NotTo(HaveOccurred())
		Expect(reissued.Issued).To(BeTrue(),
			"failing to schedule the revocation must not stop the CA serving")
		Expect(blind.ServingRevocationFailureCount()).To(Equal(uint64(1)))
	})

	DescribeTable("refuses to report a mint whose material it could not store",
		// Discarding either error left EnsureServingCert returning Issued: true
		// for a certificate whose key or body was never persisted -- so the
		// process serves normally, every restart mints again, and the only
		// symptom is a rising issuance counter.
		func(failKey string) {
			blind := ca.New(storage.NewWithBackend(
				&failWriteBackend{Backend: base, failKey: failKey}, dir),
				ca.AutosignConfig{Mode: "off"}, subject)
			blind.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
			blind.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
			Expect(blind.Init(ctx)).To(Succeed())

			before := blind.ServingCertIssued()
			_, err := blind.EnsureServingCert(ctx,
				ca.ServingConfig{Subject: subject, ExtraNames: []string{"alt.example.com"}})
			Expect(err).To(HaveOccurred())
			Expect(blind.ServingCertIssued()).To(Equal(before),
				"a mint that could not be stored must not be counted as issued")
		},
		Entry("the key", storage.KeyServingKey),
		Entry("the certificate", storage.KeyServingCert),
	)

	DescribeTable("keeps the backend's error text out of the supersession errors",
		// A security property, and the one round 7 fixed with nothing behind
		// it: reverting either arm to fmt.Errorf("...: %w", err) puts the text
		// into a Warn on the mint path and an Error on the sweep path. On a SQL
		// backend that text is the driver's, and carries the DSN.
		func(newStore func() *storage.StorageService) {
			blind := ca.New(newStore(), ca.AutosignConfig{Mode: "off"}, subject)
			blind.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
			blind.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
			Expect(blind.Init(ctx)).To(Succeed())

			// Something must be pending, or the sweep returns before it writes.
			Expect(storage.New(dir).SaveServingSuperseded(ctx,
				[]byte(`[{"serial":"AB","revoke_at":"2020-01-01T00:00:00Z"}]`))).To(Succeed())

			err := blind.ReconcileSuperseded(ctx, revokeCfg(subject, time.Hour))
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).NotTo(ContainSubstring("hunter2"),
				"the backend's error text must not reach the caller, or the log")
			Expect(err.Error()).NotTo(ContainSubstring("dsn="))
		},
		Entry("on the read", func() *storage.StorageService {
			return storage.NewWithBackend(
				&failReadBackend{Backend: base, failKey: storage.KeyServingSuperseded}, dir)
		}),
		Entry("on the write-back", func() *storage.StorageService {
			return storage.NewWithBackend(
				&failWriteBackend{Backend: base, failKey: storage.KeyServingSuperseded}, dir)
		}),
	)

	DescribeTable("does not count a revocation failure for bytes that do not parse",
		// Those are not a credential in circulation, so counting them would
		// fire an alert telling the operator a replaced certificate is still
		// valid when none exists. The policy comment covers both parse arms;
		// only the first had a spec, so adding the increment to the second
		// passed.
		func(stored []byte) {
			good := ca.New(storage.New(dir), ca.AutosignConfig{Mode: "off"}, subject)
			good.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
			good.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
			Expect(good.Init(ctx)).To(Succeed())
			Expect(storage.New(dir).SaveServingCert(ctx, stored)).To(Succeed())

			good.StoredServingLeafForTest(ctx)
			Expect(good.ServingRevocationFailureCount()).To(BeZero())
		},
		Entry("not PEM at all", []byte("not a certificate\n")),
		Entry("a PEM block that is not a certificate",
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("this is not DER")})),
	)

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
		Expect(detail).To(BeEmpty(),
			"empty is the only safe answer: this is the flow CodeQL traced, and the "+
				"configured passphrase path must not reach the log through it")
	})

	It("carries only operator-supplied detail for a missing name", func() {
		Expect(myCA.EnsureServingCert(ctx, cfg)).Error().NotTo(HaveOccurred())
		cfg.ExtraNames = []string{"ingress.example.com"}

		code, detail := reasonFor()
		Expect(code).To(Equal("missing-configured-name"))
		Expect(detail).To(Equal("ingress.example.com"))
	})

	It("keeps a withdrawn name until the certificate is reissued for another reason", func() {
		// Not an oversight. What makes a mixed-configuration fleet converge is
		// the union carried on the missing-name path (see missingNames, and the
		// convergence spec in servingconcurrent_test.go); the check itself
		// stays one-directional, so a withdrawal needs the revoke below.
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

	It("lets revocation win when a name is also missing", func() {
		// A rename: withdraw one name and add another, then revoke to apply it.
		// Both conditions hold at once, and only reasonMissingName carries the
		// stored names forward -- so if the name check ran first the union
		// would put the withdrawn name straight back and swallow the
		// revocation, leaving the operator with a fresh certificate still
		// asserting the name they revoked to remove.
		cfg.ExtraNames = []string{"old.example.com"}
		Expect(myCA.EnsureServingCert(ctx, cfg)).Error().NotTo(HaveOccurred())

		cfg.ExtraNames = []string{"new.example.com"}
		Expect(myCA.Revoke(ctx, subject)).To(Succeed())

		reissued, err := myCA.EnsureServingCert(ctx, cfg)
		Expect(err).NotTo(HaveOccurred())
		Expect(reissued.Issued).To(BeTrue())
		Expect(reissued.Leaf.DNSNames).To(ContainElement("new.example.com"))
		Expect(reissued.Leaf.DNSNames).NotTo(ContainElement("old.example.com"),
			"a revocation must mint from the configured names alone")
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

	It("reissues once the stored certificate is inside the renewal window", func() {
		// The branch the feature exists for, end to end rather than as far as
		// the reason code: reasonRenewalWindow must be mint-worthy, not an
		// error. The arithmetic needs no clock faking -- a fresh certificate is
		// backdated 24h, so a window just under the lifetime already contains
		// it, and a window at or beyond the lifetime would be clamped.
		issued, err := myCA.EnsureServingCert(ctx, cfg)
		Expect(err).NotTo(HaveOccurred())

		lifetime := issued.Leaf.NotAfter.Sub(issued.Leaf.NotBefore)
		cfg.RenewBefore = lifetime - time.Hour

		reissued, err := myCA.EnsureServingCert(ctx, cfg)
		Expect(err).NotTo(HaveOccurred())
		Expect(reissued.Issued).To(BeTrue(),
			"a certificate inside its renewal window must be replaced, not served to expiry")
		Expect(reissued.Leaf.SerialNumber.Cmp(issued.Leaf.SerialNumber)).NotTo(BeZero())
	})

	It("reports revocation with no detail", func() {
		Expect(myCA.EnsureServingCert(ctx, cfg)).Error().NotTo(HaveOccurred())
		Expect(myCA.Revoke(ctx, subject)).To(Succeed())

		code, detail := reasonFor()
		Expect(code).To(Equal("certificate-revoked"))
		Expect(detail).To(BeEmpty())
	})
})
