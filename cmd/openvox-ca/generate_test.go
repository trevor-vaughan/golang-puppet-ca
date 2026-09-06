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
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

func runGenerate(args ...string) (stdout, stderr string, err error) {
	root := newRootCmd()
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(append([]string{"generate"}, args...))
	err = root.Execute()
	return out.String(), errOut.String(), err
}

// runGenerateStdout is runGenerate with the caller's own stdout writer, so a
// spec can drive the failure of the default output path. The certificate goes
// to stdout unless --cert-out is given, and that is the form every documented
// invocation uses.
func runGenerateStdout(stdout io.Writer, args ...string) (stderr string, err error) {
	root := newRootCmd()
	var errOut bytes.Buffer
	root.SetOut(stdout)
	root.SetErr(&errOut)
	root.SetArgs(append([]string{"generate"}, args...))
	err = root.Execute()
	return errOut.String(), err
}

// failingWriter refuses every write, standing in for a closed pipe or a full
// filesystem behind stdout.
type failingWriter struct{ err error }

func (f failingWriter) Write([]byte) (int, error) { return 0, f.err }

// logRecord decodes the JSON log record carrying msg, so a spec can assert on
// its fields. A configured logfile receives every record the run emits, and the
// one under test is not the first: Init logs "Loaded existing CA" ahead of it.
func logRecord(data []byte, msg string) map[string]any {
	GinkgoHelper()
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var entry map[string]any
		Expect(json.Unmarshal(line, &entry)).To(Succeed(),
			"a configured logfile receives JSON, one record per line")
		if entry["msg"] == msg {
			return entry
		}
	}
	Fail(fmt.Sprintf("no log record with msg %q in:\n%s", msg, data))
	return nil
}

// hashTree fingerprints every file under dir, so a spec can assert that a
// refusal changed nothing at all rather than only that one file survived.
func hashTree(dir string) map[string]string {
	GinkgoHelper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			return relErr
		}
		if d.IsDir() {
			// Recorded too: Init calls EnsureDirs before it reaches the
			// bootstrap decision, so a guard that moved below it would create
			// directories and a file-only fingerprint would not notice.
			out[rel+"/"] = ""
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		sum := sha256.Sum256(data)
		out[rel] = string(sum[:])
		return nil
	})
	// An absent directory is a legitimate "nothing here" fingerprint; any other
	// walk error must fail the spec rather than silently yield a partial map.
	if err != nil && !os.IsNotExist(err) {
		Expect(err).NotTo(HaveOccurred())
	}
	return out
}

func certFromPEM(pemBytes string) *x509.Certificate {
	GinkgoHelper()
	block, _ := pem.Decode([]byte(pemBytes))
	Expect(block).NotTo(BeNil())
	cert, err := x509.ParseCertificate(block.Bytes)
	Expect(err).NotTo(HaveOccurred())
	return cert
}

var _ = Describe("openvox-ca generate", func() {
	var (
		caDir  string
		outDir string
	)

	BeforeEach(func() {
		caDir = GinkgoT().TempDir()
		outDir = GinkgoT().TempDir()

		// ECDSA P-256 rather than the RSA defaults: these specs mint a CA and a
		// leaf on nearly every It, and RSA at the default sizes dominates the
		// suite's runtime for no assertion value.
		pinnedCfg := "ca_key_algo: ecdsa\nca_key_size: 256\nleaf_key_algo: ecdsa\nleaf_key_size: 256\n"
		cfgPath := filepath.Join(GinkgoT().TempDir(), "pinned.yaml")
		Expect(os.WriteFile(cfgPath, []byte(pinnedCfg), 0o644)).To(Succeed())
		setEnv("PUPPET_CA_CONFIG", cfgPath)
		clearServerEnv()

		// The command calls setupLogger, which rebinds the process-wide default
		// logger. Restore it so it cannot leak into sibling specs.
		orig := slog.Default()
		DeferCleanup(func() { slog.SetDefault(orig) })
	})

	keyPath := func(name string) string { return filepath.Join(outDir, name+".key") }

	Describe("refusing to act on storage that holds no usable CA", func() {
		It("will not bootstrap a CA when none exists", func() {
			before := hashTree(caDir)

			_, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "1h", "--key-out", keyPath("web01"))
			Expect(err).To(MatchError(ContainSubstring("refusing to create one")))

			// Init writes -- EnsureDirs, InitHMAC, CRL seeding -- before it
			// reaches the bootstrap decision, so asserting only that ca_crt.pem
			// is absent would pass with the guard in the wrong place.
			Expect(hashTree(caDir)).To(Equal(before), "a refusal must leave the cadir untouched")
		})

		It("will not issue when the CA certificate is present but the key is gone", func() {
			// Init refuses this case too, so this passes with the command's own
			// guard removed -- it is defence in depth against a regression in
			// either layer, not a pin on this command alone. What it does pin
			// here is that the refusal happens before Init's side effects, so
			// the cadir is left byte-identical rather than merely un-bootstrapped.
			bootstrapCAInDir(caDir, "puppet.example.com")
			Expect(os.Remove(filepath.Join(caDir, "private", "ca_key.pem"))).To(Succeed())
			before := hashTree(caDir)

			_, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "1h", "--key-out", keyPath("web01"))
			Expect(err).To(MatchError(ContainSubstring("its key is missing")))
			Expect(hashTree(caDir)).To(Equal(before))
		})

		It("will not issue when the CA key is present but its certificate is gone", func() {
			// The state openvox-ca csr --create-key leaves behind while an
			// external root's signature is outstanding. The remedy is
			// import-ca-cert, and telling the operator to "start the server once
			// to bootstrap" instead would be the one action that must not be
			// taken here.
			bootstrapCAInDir(caDir, "puppet.example.com")
			Expect(os.Remove(filepath.Join(caDir, "ca_crt.pem"))).To(Succeed())
			before := hashTree(caDir)

			_, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "1h", "--key-out", keyPath("web01"))
			Expect(err).To(MatchError(ContainSubstring("its certificate is missing")))
			Expect(err).To(MatchError(ContainSubstring("import-ca-cert")))
			Expect(hashTree(caDir)).To(Equal(before))
		})

		It("refuses on the frontend role, which cannot reach the CA key", func() {
			// The role is an environment variable the launcher sets into its
			// children, not a config key. roleMayReachCAKey is role !=
			// "frontend", so the predicate is easy to invert -- hence both
			// directions below.
			bootstrapCAInDir(caDir, "puppet.example.com")
			setEnv("PUPPET_CA_ROLE", "frontend")

			_, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "1h", "--key-out", keyPath("web01"))
			Expect(err).To(MatchError(ContainSubstring("frontend")))
		})

		It("proceeds on the signer role, which does hold the key", func() {
			bootstrapCAInDir(caDir, "puppet.example.com")
			setEnv("PUPPET_CA_ROLE", "signer")

			_, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "1h", "--key-out", keyPath("web01"))
			Expect(err).NotTo(HaveOccurred())
			// A nil error is not the claim; the claim is that it issued. The
			// refusing direction is pinned by its sibling above, so without
			// this the predicate could be inverted to refuse nothing at all.
			Expect(storage.New(caDir).HasCert(context.Background(), "web01")).To(BeTrue())
		})
	})

	Describe("minting against an existing CA", func() {
		BeforeEach(func() { bootstrapCAInDir(caDir, "puppet.example.com") })

		It("requires a ttl rather than defaulting to five years", func() {
			_, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--key-out", keyPath("web01"))
			Expect(err).To(MatchError(ContainSubstring(`"ttl" not set`)))
		})

		// MarkFlagRequired only asserts the flag was given. Without an explicit
		// check, --ttl 0 reaches issueLeafLocked and inherits the multi-year
		// built-in -- the exact silent default this command requires --ttl in
		// order to prevent.
		//
		// One Entry per spelling rather than a loop: a loop stops at the first
		// failed Expect, so a regression reaching only "-1h" would stay hidden
		// behind "0" until that was fixed and the suite re-run.
		DescribeTable("refuses a zero or negative ttl",
			func(bad string) {
				_, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
					"--ttl", bad, "--key-out", keyPath("web01"))
				Expect(err).To(MatchError(ContainSubstring("--ttl must be a positive duration")))
				Expect(storage.New(caDir).HasCert(context.Background(), "web01")).To(BeFalse())
			},
			Entry("bare zero", "0"),
			Entry("zero seconds", "0s"),
			Entry("negative", "-1h"),
		)

		It("refuses --key-out and --cert-out pointing at one path", func() {
			// The key is written first and the certificate second, so a shared
			// path ends with a live inventoried certificate whose key was
			// overwritten and exists nowhere.
			shared := filepath.Join(outDir, "both.pem")
			_, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--key-out", shared, "--cert-out", shared)
			Expect(err).To(MatchError(ContainSubstring("same path")))
			Expect(storage.New(caDir).HasCert(context.Background(), "web01")).To(BeFalse())
		})

		It("refuses two spellings of one path, not just two identical strings", func() {
			// The guard compares what prepareOutputPath returns, which is
			// cleaned and absolute -- not the raw flag values. Passing the same
			// string twice cannot tell those apart: compare the raw flags
			// instead and the spec above still passes, while this spelling
			// walks straight into the outcome the guard exists to prevent, a
			// live inventoried certificate whose key was overwritten by it.
			// Built by concatenation, not filepath.Join: Join cleans its result,
			// so a Join-built "equivalent" would be the identical string and
			// this spec would be the one above again.
			shared := filepath.Join(outDir, "both.pem")
			viaDot := outDir + "/sub/../both.pem"
			Expect(viaDot).NotTo(Equal(shared), "the two spellings must differ as strings")
			Expect(filepath.Clean(viaDot)).To(Equal(shared), "but must name the same file")

			_, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--key-out", shared, "--cert-out", viaDot)
			Expect(err).To(MatchError(ContainSubstring("same path")))
			Expect(storage.New(caDir).HasCert(context.Background(), "web01")).To(BeFalse())
		})

		It("refuses when the output path's parent is a file, not a directory", func() {
			notADir := filepath.Join(outDir, "regular-file")
			Expect(os.WriteFile(notADir, []byte("x"), 0o600)).To(Succeed())

			_, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--key-out", filepath.Join(notADir, "web01.key"))
			// Both of prepareOutputPath's branches for this case say "not a
			// directory" -- the explicit one, and the wrapped ENOTDIR that
			// os.Stat actually produces on Unix -- so this holds whichever
			// fires, without pinning which. A bare HaveOccurred() would pass
			// just as well if the refusal came from somewhere else entirely.
			Expect(err).To(MatchError(ContainSubstring("not a directory")))
			Expect(err).To(MatchError(ContainSubstring("web01.key")))
			Expect(storage.New(caDir).HasCert(context.Background(), "web01")).To(BeFalse())
		})

		It("reports the serial and expiry of what it issued", func() {
			stdout, stderr, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--key-out", keyPath("web01"))
			Expect(err).NotTo(HaveOccurred())

			cert := certFromPEM(stdout)
			Expect(stderr).To(ContainSubstring(fmt.Sprintf("%X", cert.SerialNumber)),
				"the operator needs the serial to revoke this later")
			Expect(stderr).To(ContainSubstring(cert.NotAfter.Format(time.RFC3339)))
		})

		It("emits a certificate signed by the CA on stdout", func() {
			stdout, _, err := runGenerate("--cadir", caDir, "--certname", "web01.example.com",
				"--ttl", "8760h", "--key-out", keyPath("web01"))
			Expect(err).NotTo(HaveOccurred())

			cert := certFromPEM(stdout)
			Expect(cert.Subject.CommonName).To(Equal("web01.example.com"))
			Expect(cert.DNSNames).To(ConsistOf("web01.example.com"), "the CN is promoted to a SAN")

			caPEM, err := os.ReadFile(filepath.Join(caDir, "ca_crt.pem"))
			Expect(err).NotTo(HaveOccurred())
			Expect(cert.CheckSignatureFrom(certFromPEM(string(caPEM)))).To(Succeed())
		})

		It("writes the private key at 0600 and leaves none in the cadir", func() {
			stdout, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--key-out", keyPath("web01"))
			Expect(err).NotTo(HaveOccurred())

			info, err := os.Stat(keyPath("web01"))
			Expect(err).NotTo(HaveOccurred())
			Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o600)))

			// The key must match the certificate, or the operator has a
			// credential they cannot use.
			keyPEM, err := os.ReadFile(keyPath("web01"))
			Expect(err).NotTo(HaveOccurred())
			block, _ := pem.Decode(keyPEM)
			Expect(block).NotTo(BeNil())
			key, err := x509.ParseECPrivateKey(block.Bytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(key.PublicKey.Equal(certFromPEM(stdout).PublicKey)).To(BeTrue())

			_, statErr := os.Stat(storage.New(caDir).PrivateKeyPath("web01"))
			Expect(os.IsNotExist(statErr)).To(BeTrue(),
				"nothing should be left in the cadir when --key-out was given")
		})

		It("falls back to the cadir and says what that costs", func() {
			_, stderr, err := runGenerate("--cadir", caDir, "--certname", "web01", "--ttl", "8760h")
			Expect(err).NotTo(HaveOccurred())

			Expect(storage.New(caDir).PrivateKeyPath("web01")).To(BeAnExistingFile())
			Expect(stderr).To(ContainSubstring("persists there until"))
			Expect(stderr).To(ContainSubstring("ephemeral cadir"))
		})

		It("applies dns alt names and an explicit ttl", func() {
			stdout, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "1h", "--dns", "a.example.com,b.example.com",
				"--key-out", keyPath("web01"))
			Expect(err).NotTo(HaveOccurred())

			cert := certFromPEM(stdout)
			Expect(cert.DNSNames).To(ConsistOf("a.example.com", "b.example.com"))
			Expect(cert.NotAfter.Sub(cert.NotBefore)).To(BeNumerically("<", 26*60*60*1e9),
				"a 1h ttl plus the 24h backdate, not the multi-year default")
		})

		It("writes the certificate to --cert-out at 0644, leaving stdout empty", func() {
			certOut := filepath.Join(outDir, "web01.crt")
			stdout, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--key-out", keyPath("web01"), "--cert-out", certOut)
			Expect(err).NotTo(HaveOccurred())
			Expect(stdout).To(BeEmpty())

			info, err := os.Stat(certOut)
			Expect(err).NotTo(HaveOccurred())
			Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o644)))

			// The mode alone would stay green if the file were handed the key
			// PEM, or nothing at all.
			written, err := os.ReadFile(certOut)
			Expect(err).NotTo(HaveOccurred())
			Expect(certFromPEM(string(written)).Subject.CommonName).To(Equal("web01"))
		})

		It("says what was issued when the --cert-out write fails afterwards", func() {
			// The one place the command can fail with the certificate already
			// committed: it holds a serial, it is in the inventory, and under
			// --force its predecessor is on the CRL. Returning the bare write
			// error would leave the operator believing nothing was issued, and
			// their re-run would hit ErrCertExists on a name they thought was
			// free. Every other spec here fails before issuance, so nothing
			// else exercises the reportSuccess-then-error shape.
			if os.Geteuid() == 0 {
				Skip("root ignores directory permissions")
			}
			roDir := filepath.Join(outDir, "readonly")
			Expect(os.Mkdir(roDir, 0o755)).To(Succeed())
			// After prepareOutputPath's checks, which only stat: 0500 still
			// permits the lookup that finds the target absent and the parent a
			// directory, and denies the CreateTemp that comes later.
			Expect(os.Chmod(roDir, 0o500)).To(Succeed())
			DeferCleanup(func() { _ = os.Chmod(roDir, 0o755) })

			_, stderr, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--key-out", keyPath("web01"),
				"--cert-out", filepath.Join(roDir, "web01.crt"))

			Expect(err).To(MatchError(ContainSubstring("issued and recorded, but writing it to")))
			// The remedy has to name a route that works. 'openvox-ca-ctl list'
			// does not: it reports name and state only, never the PEM, and it
			// needs the running server this command exists to work without.
			Expect(err).To(MatchError(ContainSubstring("Do not re-run")))
			Expect(err).To(MatchError(ContainSubstring("signed/")))
			Expect(err).NotTo(MatchError(ContainSubstring("openvox-ca-ctl list")))

			store := storage.New(caDir)
			Expect(store.HasCert(context.Background(), "web01")).To(BeTrue(),
				"the error must not imply the certificate can be minted again")
			certPEM, readErr := store.GetCert(context.Background(), "web01")
			Expect(readErr).NotTo(HaveOccurred())
			Expect(stderr).To(ContainSubstring(fmt.Sprintf("%X", certFromPEM(string(certPEM)).SerialNumber)),
				"the serial is how the operator finds what they now own")

			// The key belongs to a live certificate, so the unused-key cleanup
			// that runs on an issuance failure must not have reached it.
			Expect(keyPath("web01")).To(BeAnExistingFile())
		})

		It("says what was issued when the stdout write fails afterwards", func() {
			// The --cert-out twin above is the rarer path. Stdout is the
			// default, and the form every documented invocation uses
			// ('openvox-ca generate ... > web01.crt'), so a closed pipe or a
			// full filesystem lands here -- with the certificate already
			// committed, exactly as in the sibling spec.
			stderr, err := runGenerateStdout(failingWriter{err: errors.New("broken pipe")},
				"--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--key-out", keyPath("web01"))

			Expect(err).To(MatchError(ContainSubstring("could not be written to stdout")))
			Expect(err).To(MatchError(ContainSubstring("broken pipe")))
			// The same remedy the --cert-out branch gives. Telling the operator
			// what failed without telling them where the certificate is, and
			// not to re-run, is the half that sends them into ErrCertExists on
			// a name they think is free.
			Expect(err).To(MatchError(ContainSubstring("Do not re-run")))
			Expect(err).To(MatchError(ContainSubstring("signed/")))

			store := storage.New(caDir)
			Expect(store.HasCert(context.Background(), "web01")).To(BeTrue())
			certPEM, readErr := store.GetCert(context.Background(), "web01")
			Expect(readErr).NotTo(HaveOccurred())
			Expect(stderr).To(ContainSubstring(fmt.Sprintf("%X", certFromPEM(string(certPEM)).SerialNumber)),
				"stderr is the only place left to tell the operator what they now own")
		})

		It("reports the configuration and backend capabilities before acting", func() {
			_, stderr, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--key-out", keyPath("web01"))
			Expect(err).NotTo(HaveOccurred())

			Expect(stderr).To(ContainSubstring("Storage backend: filesystem"))
			// The pinned config sets neither URL, so this is also the "(none)"
			// rendering. Asserting the label alone would stay green with the
			// whole payload dropped -- and the payload is the point: a
			// flag-configured server is invisible to this command, so an
			// absent crl_url here means a certificate about to be minted
			// without a distribution point the server's own issuance carries.
			Expect(stderr).To(ContainSubstring(
				"Issuance settings: crl_url: (none); ocsp_url: (none); promote_cn_to_san: true"))
			// The filesystem backend provides neither capability, so the
			// stop-the-server warning is the correct output here.
			Expect(stderr).To(ContainSubstring("Stop the server before running this"))

			// "Before acting" is the whole value of the warning, and presence
			// alone does not pin it: move reportBackendCapabilities below
			// reportSuccess and every assertion above still holds, while the
			// operator learns their backend cannot coordinate writes only
			// after the mint it was meant to stop.
			Expect(strings.Index(stderr, "Stop the server before running this")).
				To(BeNumerically("<", strings.Index(stderr, "Issued web01")),
					"the pre-flight report must precede the issuance it guards")
		})

		It("reports the issuance settings it actually resolved", func() {
			cfgPath := filepath.Join(GinkgoT().TempDir(), "urls.yaml")
			Expect(os.WriteFile(cfgPath, []byte(
				"ca_key_algo: ecdsa\nca_key_size: 256\nleaf_key_algo: ecdsa\nleaf_key_size: 256\n"+
					"crl_url: http://ca.example.com/crl\nocsp_url: http://ca.example.com/ocsp\n"+
					// false, because true is the default and would not
					// distinguish a resolved value from an ignored one.
					"promote_cn_to_san: false\n"), 0o644)).To(Succeed())
			setEnv("PUPPET_CA_CONFIG", cfgPath)

			_, stderr, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--key-out", keyPath("web01"))
			Expect(err).NotTo(HaveOccurred())

			Expect(stderr).To(ContainSubstring(
				"Issuance settings: crl_url: http://ca.example.com/crl; " +
					"ocsp_url: http://ca.example.com/ocsp; promote_cn_to_san: false"))
		})

		It("bypasses autosign policy, which is not consulted at all", func() {
			// Deliberate: this is an operator action, not a request, and must
			// work when there is no policy and no server to evaluate one.
			//
			// This cannot fail today, and that is the point of writing it down:
			// generate hardcodes AutosignConfig{Mode: "off"}, and
			// GenerateWithOptions never reaches CheckAutosign at all -- its one
			// non-test caller is SaveRequest, on the CSR path. What this guards
			// is a future change that starts consulting policy here, which with
			// a deny-everything config would then fail. The config below is set
			// through the file rather than the environment so it really is
			// loaded into serverConfig, rather than being inert twice over.
			cfgPath := filepath.Join(GinkgoT().TempDir(), "denyall.yaml")
			Expect(os.WriteFile(cfgPath, []byte(
				"ca_key_algo: ecdsa\nca_key_size: 256\nautosign_config: \"false\"\n"), 0o644)).To(Succeed())
			setEnv("PUPPET_CA_CONFIG", cfgPath)

			_, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--key-out", keyPath("web01"))
			Expect(err).NotTo(HaveOccurred())
			// The whole claim is that a certificate is minted despite a
			// deny-everything policy, so a nil error alone does not make it.
			Expect(storage.New(caDir).HasCert(context.Background(), "web01")).To(BeTrue())
		})

	})

	Describe("output pre-flight", func() {
		BeforeEach(func() { bootstrapCAInDir(caDir, "puppet.example.com") })

		It("refuses to overwrite an existing key, issuing nothing", func() {
			existing := keyPath("web01")
			Expect(os.WriteFile(existing, []byte("original"), 0o600)).To(Succeed())

			_, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--key-out", existing)
			Expect(err).To(MatchError(ContainSubstring("refusing to overwrite")))

			data, readErr := os.ReadFile(existing)
			Expect(readErr).NotTo(HaveOccurred())
			Expect(string(data)).To(Equal("original"))

			// The point of checking before issuing: the certificate would
			// otherwise have consumed a serial and be in the inventory.
			Expect(storage.New(caDir).HasCert(context.Background(), "web01")).To(BeFalse())
		})

		It("refuses when the key's directory does not exist", func() {
			_, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--key-out", filepath.Join(outDir, "nope", "web01.key"))
			Expect(err).To(MatchError(ContainSubstring("does not exist")))
			// Same invariant as the sibling above: the refusal has to happen
			// before issuance, or a serial is consumed and an inventory row
			// written for a mint that then reports failure.
			Expect(storage.New(caDir).HasCert(context.Background(), "web01")).To(BeFalse())
		})

		It("refuses to overwrite an existing certificate file", func() {
			certOut := filepath.Join(outDir, "web01.crt")
			Expect(os.WriteFile(certOut, []byte("original"), 0o644)).To(Succeed())

			_, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--key-out", keyPath("web01"), "--cert-out", certOut)
			Expect(err).To(MatchError(ContainSubstring("refusing to overwrite")))
			Expect(storage.New(caDir).HasCert(context.Background(), "web01")).To(BeFalse())
		})
	})

	Describe("administrator credentials", func() {
		BeforeEach(func() { bootstrapCAInDir(caDir, "puppet.example.com") })

		It("stamps pp_cli_auth only when asked", func() {
			stdout, _, err := runGenerate("--cadir", caDir, "--certname", "node",
				"--ttl", "8760h", "--key-out", keyPath("node"))
			Expect(err).NotTo(HaveOccurred())
			for _, ext := range certFromPEM(stdout).Extensions {
				Expect(ca.IsAuthOID(ext.Id)).To(BeFalse())
			}

			stdout, _, err = runGenerate("--cadir", caDir, "--certname", "admin",
				"--ttl", "8760h", "--pp-cli-auth", "--key-out", keyPath("admin"))
			Expect(err).NotTo(HaveOccurred())

			var found bool
			for _, ext := range certFromPEM(stdout).Extensions {
				if ext.Id.Equal(ca.OIDPpCliAuth) {
					found = true
					Expect(ext.Value).To(Equal([]byte{0x0c, 0x04, 't', 'r', 'u', 'e'}))
				}
			}
			Expect(found).To(BeTrue())
		})

		It("requires --key-out, so the key cannot land somewhere ephemeral", func() {
			_, _, err := runGenerate("--cadir", caDir, "--certname", "admin",
				"--ttl", "8760h", "--pp-cli-auth")
			Expect(err).To(MatchError(ContainSubstring("--key-out is required with --pp-cli-auth")))

			Expect(storage.New(caDir).HasCert(context.Background(), "admin")).To(BeFalse())
		})

		It("states what the credential grants and how to withdraw it", func() {
			_, stderr, err := runGenerate("--cadir", caDir, "--certname", "admin",
				"--ttl", "8760h", "--pp-cli-auth", "--key-out", keyPath("admin"))
			Expect(err).NotTo(HaveOccurred())

			Expect(stderr).To(ContainSubstring("administrator credential"))
			// The withdrawal procedure is the part an operator cannot infer,
			// and all three steps matter: revoking alone does not take effect
			// on a running server, and a superseded serial may not be
			// revocable at all.
			Expect(stderr).To(ContainSubstring("openvox-ca-ctl revoke --certname admin"))
			Expect(stderr).To(ContainSubstring("restart every replica"))
			Expect(stderr).To(ContainSubstring("other live serials"))

			// Every configuration key this procedure names must be one the
			// operator can look up. docs/operator-cli.md transcribes these
			// steps, so the two drift apart silently: correcting the doc alone
			// once left this string naming a crl_validity key that does not
			// exist, in the withdrawal instructions for the most privileged
			// credential the CA issues.
			Expect(stderr).To(ContainSubstring("crl_validity_days"))
			Expect(stderr).To(ContainSubstring("revoke_on_auto_renew"))
		})

		It("refuses when the CA is configured to ignore pp_cli_auth", func() {
			cfgPath := filepath.Join(GinkgoT().TempDir(), "nopp.yaml")
			Expect(os.WriteFile(cfgPath, []byte(
				"ca_key_algo: ecdsa\nca_key_size: 256\nno_pp_cli_auth: true\n"), 0o644)).To(Succeed())
			setEnv("PUPPET_CA_CONFIG", cfgPath)

			_, _, err := runGenerate("--cadir", caDir, "--certname", "admin",
				"--ttl", "8760h", "--pp-cli-auth", "--key-out", keyPath("admin"))
			Expect(err).To(MatchError(ContainSubstring("no_pp_cli_auth")))
		})
	})

	Describe("replacing an existing certificate", func() {
		BeforeEach(func() { bootstrapCAInDir(caDir, "puppet.example.com") })

		It("names both remedies when a certificate already exists", func() {
			_, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--key-out", keyPath("web01"))
			Expect(err).NotTo(HaveOccurred())

			_, _, err = runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--key-out", keyPath("web01-again"))
			Expect(err).To(MatchError(ca.ErrCertExists),
				"the sentinel is what callers discriminate on; a substring is not")
			Expect(err.Error()).To(ContainSubstring("--force"))
			Expect(err.Error()).To(ContainSubstring("openvox-ca-ctl clean"))

			// EmitKey writes the key before the CA commits to anything, so a
			// failed mint leaves one on disk. It must be cleaned up: a private
			// key with no certificate, at a path the operator will not think to
			// revisit, is a leaked credential.
			Expect(keyPath("web01-again")).NotTo(BeAnExistingFile())
		})

		It("replaces with --force and reports the revocation", func() {
			first, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--key-out", keyPath("web01"))
			Expect(err).NotTo(HaveOccurred())
			oldSerial := certFromPEM(first).SerialNumber

			second, stderr, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--force", "--key-out", keyPath("web01-new"))
			Expect(err).NotTo(HaveOccurred())

			Expect(certFromPEM(second).SerialNumber.Cmp(oldSerial)).NotTo(Equal(0))
			Expect(stderr).To(ContainSubstring("was revoked"))
			Expect(stderr).To(ContainSubstring("until it reloads the CRL"))
		})

		It("requires --key-out, because a failed key write after the revoke is unrecoverable", func() {
			_, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--force")
			Expect(err).To(MatchError(ContainSubstring("--key-out is required with --force")))
		})

		It("does not claim a revocation when --force had nothing to replace", func() {
			// reportSuccess used to key off the flag rather than the outcome, so
			// this printed "the previous certificate was revoked" for a name
			// that never had one -- and, for the CA's own hostname, told the
			// operator to restart a server over a revocation that never
			// happened.
			_, stderr, err := runGenerate("--cadir", caDir, "--certname", "brand-new",
				"--ttl", "8760h", "--force", "--key-out", keyPath("brand-new"))
			Expect(err).NotTo(HaveOccurred())
			Expect(stderr).NotTo(ContainSubstring("was revoked"))
		})

		It("issues again once an existing certificate has been revoked", func() {
			revokeInDir(caDir, "web01")

			_, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--key-out", keyPath("web01"))
			Expect(err).NotTo(HaveOccurred(), "a revoked certificate must be evictable without --force")
		})

		It("warns when replacing the CA's own serving name", func() {
			cfgPath := filepath.Join(GinkgoT().TempDir(), "host.yaml")
			Expect(os.WriteFile(cfgPath, []byte(
				"ca_key_algo: ecdsa\nca_key_size: 256\nhostname: puppet.example.com\n"), 0o644)).To(Succeed())
			setEnv("PUPPET_CA_CONFIG", cfgPath)

			_, _, err := runGenerate("--cadir", caDir, "--certname", "puppet.example.com",
				"--ttl", "8760h", "--key-out", keyPath("serving"))
			Expect(err).NotTo(HaveOccurred())

			_, stderr, err := runGenerate("--cadir", caDir, "--certname", "puppet.example.com",
				"--ttl", "8760h", "--force", "--key-out", keyPath("serving-new"))
			Expect(err).NotTo(HaveOccurred())
			Expect(stderr).To(ContainSubstring("this CA's own hostname"))
		})
	})

	Describe("audit logging", func() {
		BeforeEach(func() { bootstrapCAInDir(caDir, "puppet.example.com") })

		It("writes the grant to a configured logfile", func() {
			logPath := filepath.Join(outDir, "ca.log")
			Expect(os.WriteFile(logPath, nil, 0o600)).To(Succeed())

			cfgPath := filepath.Join(GinkgoT().TempDir(), "log.yaml")
			Expect(os.WriteFile(cfgPath, []byte(
				"ca_key_algo: ecdsa\nca_key_size: 256\nlogfile: "+logPath+"\n"), 0o644)).To(Succeed())
			setEnv("PUPPET_CA_CONFIG", cfgPath)

			_, _, err := runGenerate("--cadir", caDir, "--certname", "admin",
				"--ttl", "8760h", "--pp-cli-auth", "--key-out", keyPath("admin"))
			Expect(err).NotTo(HaveOccurred())

			logged, err := os.ReadFile(logPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(logged)).To(ContainSubstring("pp_cli_auth=true"))
			Expect(string(logged)).To(ContainSubstring("admin"))

			// The encoding, not just the content. setupLogger installs a JSON
			// handler for a logfile and a text handler for stderr, so the two
			// sinks do not look alike -- and docs/operator-cli.md publishes
			// both forms for operators to build aggregator rules from. A
			// ContainSubstring on the value alone holds under either encoding,
			// so it would not notice the handler changing underneath the docs.
			entry := logRecord(logged, "Issued certificate carrying a Puppet authorisation extension")
			Expect(entry).To(HaveKeyWithValue("grant", "pp_cli_auth=true"))
			Expect(entry).To(HaveKeyWithValue("subject", "admin"))
			Expect(entry).To(HaveKeyWithValue("level", "WARN"))
		})

		It("does not create a missing logfile, and mints anyway", func() {
			// Creating it would be actively harmful: run as root before the
			// server has ever started, the file would end up owned by root and
			// the server -- running unprivileged -- would fail to open it and
			// exit at startup.
			logPath := filepath.Join(outDir, "absent.log")
			cfgPath := filepath.Join(GinkgoT().TempDir(), "log.yaml")
			Expect(os.WriteFile(cfgPath, []byte(
				"ca_key_algo: ecdsa\nca_key_size: 256\nlogfile: "+logPath+"\n"), 0o644)).To(Succeed())
			setEnv("PUPPET_CA_CONFIG", cfgPath)

			_, stderr, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--key-out", keyPath("web01"))
			Expect(err).NotTo(HaveOccurred(), "a logging problem must not stop an operator issuing")
			Expect(stderr).To(ContainSubstring("will not be created"))
			Expect(logPath).NotTo(BeAnExistingFile())
		})

		It("says the record is terminal-only when no logfile is configured", func() {
			// SECURITY: the flagship case. Minting before the first server
			// start is exactly when no logfile exists, and the grant line is
			// the only record distinguishing an administrator credential from
			// a node one -- docs/operator-cli.md tells the operator to capture
			// stderr because of this notice. Lose it silently and a
			// pp_cli_auth mint leaves no trace and no warning that it did not.
			// The pinned config in the outer BeforeEach sets no logfile.
			_, stderr, err := runGenerate("--cadir", caDir, "--certname", "admin",
				"--ttl", "8760h", "--pp-cli-auth", "--key-out", keyPath("admin"))
			Expect(err).NotTo(HaveOccurred())
			Expect(stderr).To(ContainSubstring("the audit record for this mint is terminal-only"))
		})

		It("falls back to stderr when the configured logfile cannot be opened", func() {
			// Present, so it survives the not-present check above, and still
			// unopenable. The command must degrade rather than abort: an
			// interactive mint failing because a log file is unwritable would
			// be the wrong trade, and the root command's own behaviour here
			// (return the error) is the one precedent not to follow.
			if os.Geteuid() == 0 {
				Skip("root ignores file permissions")
			}
			logPath := filepath.Join(outDir, "unwritable.log")
			Expect(os.WriteFile(logPath, nil, 0o400)).To(Succeed())

			cfgPath := filepath.Join(GinkgoT().TempDir(), "log.yaml")
			Expect(os.WriteFile(cfgPath, []byte(
				"ca_key_algo: ecdsa\nca_key_size: 256\nlogfile: "+logPath+"\n"), 0o644)).To(Succeed())
			setEnv("PUPPET_CA_CONFIG", cfgPath)

			_, stderr, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--key-out", keyPath("web01"))
			Expect(err).NotTo(HaveOccurred(), "a logging problem must not stop an operator issuing")
			Expect(stderr).To(ContainSubstring("could not open"))
			Expect(stderr).To(ContainSubstring("logging to stderr instead"))
			Expect(storage.New(caDir).HasCert(context.Background(), "web01")).To(BeTrue())
		})
	})
})

// capBackend is a Backend that answers only the capability probe. The embedded
// nil interface panics on anything else, which is the point: it fails loudly if
// reportBackendCapabilities ever starts touching storage.
type capBackend struct {
	storage.Backend
	acquire func(ctx context.Context, name string) (storage.Unlocker, error)
}

func (b capBackend) AcquireLock(ctx context.Context, name string) (storage.Unlocker, error) {
	return b.acquire(ctx, name)
}

// noopUnlocker satisfies the probe's release step.
type noopUnlocker struct{}

func (noopUnlocker) Unlock() error { return nil }

// atomicCapBackend additionally claims a structured inventory, so the two
// capabilities can be varied independently.
type atomicCapBackend struct {
	capBackend
}

func (atomicCapBackend) AppendEntry(context.Context, storage.CertRecord, func([]byte) []byte) error {
	return nil
}
func (atomicCapBackend) Entries(context.Context) ([]storage.InventoryEntry, error) { return nil, nil }
func (atomicCapBackend) LatestSerialForSubject(context.Context, string) (string, error) {
	return "", nil
}
func (atomicCapBackend) PruneEntries(context.Context, func(storage.InventoryEntry) bool,
	func([]byte, storage.InventoryEntry) []byte,
) ([]storage.InventoryEntry, error) {
	return nil, nil
}

// Satisfying InventoryStore is the whole point of this double: SupportsAtomicInventory
// type-asserts for it, so a signature that drifts out of step stops satisfying it
// silently and the two specs above run the warning branch they exist to tell apart
// from the clear one. That is how it drifted the first time -- #154 changed
// PruneEntries' second callback from the survivors to (prev, entry) and nothing
// here complained until the specs failed for a reason that looked unrelated.
// Compile-time assertion so the next change is a build error instead.
var _ storage.InventoryStore = atomicCapBackend{}

var _ = Describe("reportBackendCapabilities", func() {
	// The command-level specs above run on the filesystem backend, which
	// provides neither capability, so they only ever reach the warning branch.
	// The other two answers are what an operator on Postgres or etcd sees, and
	// getting either wrong sends them to stop a server for no reason -- or,
	// worse, tells them it is safe not to.
	var buf bytes.Buffer

	BeforeEach(func() { buf.Reset() })

	report := func(b storage.Backend) string {
		reportBackendCapabilities(context.Background(), &buf,
			storage.NewWithBackend(b, GinkgoT().TempDir()))
		return buf.String()
	}

	lockOK := func(context.Context, string) (storage.Unlocker, error) { return noopUnlocker{}, nil }

	It("clears the backend when both capabilities are present", func() {
		out := report(atomicCapBackend{capBackend{acquire: lockOK}})
		Expect(out).To(ContainSubstring("safe to run alongside a live server"))
		Expect(out).NotTo(ContainSubstring("Warning"))

		// The green light is qualified, and the qualification is the part that
		// costs an operator something if it goes missing: writes coordinate,
		// but the running server's serialIndex is built at Init, so it answers
		// OCSP "unknown" for this serial until it restarts. A verifier set to
		// hard-fail on unknown then rejects a correctly issued certificate,
		// with nothing in this output pointing at the restart that fixes it.
		Expect(out).To(ContainSubstring("OCSP 'unknown'"))
		Expect(out).To(ContainSubstring("until it restarts"))
	})

	It("reports an unreachable lock service as unknown, not as absent", func() {
		// SupportsDistributedLocking returns (bool, error) precisely so this
		// case is distinguishable. Collapsing it to false would tell an
		// operator whose etcd is briefly unreachable that their backend lacks
		// cross-process locking, which is not true and not the problem.
		out := report(atomicCapBackend{capBackend{
			acquire: func(context.Context, string) (storage.Unlocker, error) {
				return nil, errors.New("etcd: context deadline exceeded")
			},
		}})
		Expect(out).To(ContainSubstring("could not determine"))
		Expect(out).To(ContainSubstring("etcd: context deadline exceeded"))
		Expect(out).To(ContainSubstring("cross-process locking: unknown"))
		Expect(out).NotTo(ContainSubstring("cross-process locking: no"))
		Expect(out).NotTo(ContainSubstring("safe to run alongside"))
	})

	It("does not wait forever on a backend that never answers", func() {
		// The bound, not just its consequence. The spec above pins that an
		// AcquireLock *error* becomes "unknown", but a backend that simply
		// never returns produces no error to map: pg_advisory_lock blocks
		// until granted or the context is cancelled, and cmd.Execute() runs on
		// context.Background(). Drop the WithTimeout in
		// reportBackendCapabilities and every other spec here still passes
		// while the command hangs before printing anything.
		orig := lockProbeTimeout
		lockProbeTimeout = 50 * time.Millisecond
		DeferCleanup(func() { lockProbeTimeout = orig })

		// A local buffer and a channel carrying the result, deliberately: on
		// the Fail branch below this goroutine is abandoned while still
		// running. Writing to the container-scoped buf, which the next spec's
		// BeforeEach resets, or assigning to a captured variable, would race a
		// sibling spec under -race and bury the real diagnosis under unrelated
		// race reports. Reading lockProbeTimeout is the same hazard against
		// the DeferCleanup above; nothing can be done about that from here,
		// which is another reason not to add a second one.
		done := make(chan string, 1)
		go func() {
			defer GinkgoRecover()
			var local bytes.Buffer
			reportBackendCapabilities(context.Background(), &local,
				storage.NewWithBackend(atomicCapBackend{capBackend{
					acquire: func(ctx context.Context, _ string) (storage.Unlocker, error) {
						<-ctx.Done()
						return nil, ctx.Err()
					},
				}}, GinkgoT().TempDir()))
			done <- local.String()
		}()

		var reached string
		select {
		case reached = <-done:
		case <-time.After(30 * time.Second):
			Fail("the capability probe never returned: it is running on an unbounded context")
		}
		Expect(reached).To(ContainSubstring("cross-process locking: unknown"))
		Expect(reached).NotTo(ContainSubstring("safe to run alongside"))
	})

	It("still warns when locking is real but the inventory append is not", func() {
		// etcd and Redis: the subject lock coordinates, but AppendInventory
		// recomputes a whole-blob HMAC from a snapshot, so a concurrent
		// appender can still leave a record the server refuses to start on.
		out := report(capBackend{acquire: lockOK})
		Expect(out).To(ContainSubstring("cross-process locking: yes"))
		Expect(out).To(ContainSubstring("atomic inventory append: false"))
		Expect(out).To(ContainSubstring("Stop the server"))
		Expect(out).NotTo(ContainSubstring("safe to run alongside"))
	})

	It("still warns when the inventory append is atomic but locking is not", func() {
		// SQLite: a shipped backend, classified no/yes by
		// docs/operator-cli.md and pinned at the storage layer by
		// internal/storage/capability_test.go. It is the fourth quadrant of the
		// green-light guard and the one the other specs leave open -- drop the
		// `locking` conjunct from that guard and every one of them still
		// passes, while a SQLite operator is told it is safe to mint alongside
		// a live server on a backend with no cross-process lock at all. This
		// also gives the "no" rendering its only positive assertion.
		out := report(atomicCapBackend{capBackend{
			acquire: func(context.Context, string) (storage.Unlocker, error) {
				return nil, storage.ErrDistributedLockingUnsupported
			},
		}})
		Expect(out).To(ContainSubstring("cross-process locking: no"))
		Expect(out).To(ContainSubstring("atomic inventory append: true"))
		Expect(out).To(ContainSubstring("Stop the server"))
		Expect(out).NotTo(ContainSubstring("safe to run alongside"))
	})
})

var _ = Describe("generate's output-path handling", func() {
	It("reports a removal it could not perform after a failed mint", func() {
		// The other half of the post-failure cleanup. Its happy path is
		// covered by the ErrCertExists spec, which asserts the leftover key is
		// gone; nothing exercised the branch that reports a removal that
		// failed. Called directly because within one run the atomic write and
		// os.Remove need the same directory permission, so no end-to-end spec
		// can have the first succeed and the second fail.
		if os.Geteuid() == 0 {
			Skip("root ignores directory permissions")
		}
		dir := GinkgoT().TempDir()
		keyPath := filepath.Join(dir, "orphan_key.pem")
		Expect(os.WriteFile(keyPath, []byte("key"), 0o600)).To(Succeed())
		Expect(os.Chmod(dir, 0o500)).To(Succeed())
		DeferCleanup(func() { _ = os.Chmod(dir, 0o700) })

		var out bytes.Buffer
		removeUnusedKey(&out, keyPath)

		Expect(out.String()).To(ContainSubstring("could not remove the unused private key"))
		Expect(out.String()).To(ContainSubstring(keyPath))
		Expect(keyPath).To(BeAnExistingFile(), "the key is still there; that is what the warning is for")
	})

	It("says nothing when there is no key to remove", func() {
		// --key-out was not given, or the key was never written. An empty path
		// must not produce a warning about failing to remove nothing.
		var out bytes.Buffer
		removeUnusedKey(&out, "")
		Expect(out.String()).To(BeEmpty())

		removeUnusedKey(&out, filepath.Join(GinkgoT().TempDir(), "never-written.pem"))
		Expect(out.String()).To(BeEmpty(), "an absent key is the normal case, not a warning")
	})

	It("distinguishes an unreadable path from an absent one", func() {
		// prepareOutputPath's third stat outcome. "Does not exist" is the path
		// it proceeds past, so collapsing any stat failure into it would have
		// the command carry on and mint against a path it cannot actually
		// write, discovering that only after the certificate is committed.
		if os.Geteuid() == 0 {
			Skip("root ignores directory permissions")
		}
		locked := filepath.Join(GinkgoT().TempDir(), "locked")
		Expect(os.Mkdir(locked, 0o700)).To(Succeed())
		Expect(os.Chmod(locked, 0o000)).To(Succeed())
		DeferCleanup(func() { _ = os.Chmod(locked, 0o700) })

		_, err := prepareOutputPath(filepath.Join(locked, "sub", "key.pem"))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("checking "),
			"an unsearchable parent must not be reported as 'already exists' or silently accepted")
	})
})
