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
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/voxpupuli/openvox-ca/internal/ca"
)

// newImportCACertCmd builds the "import-ca-cert" subcommand, which installs a
// CA certificate chain signed by an external parent — the other half of
// "openvox-ca csr".
//
// It is distinct from "openvox-ca-ctl import", which takes a certificate *and*
// its private key and can only address a local filesystem directory. This one
// takes no key: the key already exists, wherever ca_key_provider says, and the
// command proves the certificate matches it rather than being handed it.
func newImportCACertCmd() *cobra.Command {
	var (
		configFile string
		caDir      string
		bundleFile string
		outFile    string
		force      bool
	)

	cmd := &cobra.Command{
		Use:   "import-ca-cert",
		Short: "Install a CA certificate chain signed by an external parent",
		Long: `Install a CA certificate chain signed by an external parent CA, completing the
process started by "openvox-ca csr".

The bundle must be a complete chain, ordered nearest-first: this CA's own
certificate, each issuer after it, ending with a self-signed root. No key
material need be supplied: the command proves the certificate binds whatever key
ca_key_provider holds, before writing anything. With the default file provider
that means reading the stored key (and decrypting it, if encrypt_ca_key is set);
with OpenBao Transit the key never leaves the vault and only its public
component is compared.

With --out the bundle is validated and written to a file instead of storage,
for deployments where the CA certificate is mounted read-only from outside
(a Kubernetes Secret, for example).`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if outFile != "" && force {
				// --force's obligation is to re-sign the stored CRL, which is a
				// storage write --out by definition does not perform. Doing it
				// anyway would move the CRL to the new issuer while the
				// certificate sat in a file the operator had not yet installed,
				// leaving the CA serving a CRL that does not match its own
				// certificate.
				return fmt.Errorf("--out cannot be combined with --force: replacing an in-use CA certificate " +
					"requires re-signing the stored CRL, which --out does not write. Install the validated " +
					"bundle, restart every replica, then run 'openvox-ca-ctl reissue-crl'")
			}

			bundlePEM, err := os.ReadFile(bundleFile)
			if err != nil {
				return fmt.Errorf("reading --cert-bundle: %w", err)
			}

			resolvedCfgFile := resolveConfigFile(configFile, "PUPPET_CA_CONFIG", "/etc/puppet-ca/config.yaml")
			cfg, err := loadServerConfig(resolvedCfgFile)
			if err != nil {
				return err
			}
			if cmd.Flags().Changed("cadir") {
				cfg.CADir = caDir
			}

			// Before resolveRuntime, not after: every failure in there —
			// "cadir is required", an invalid provider, a backend that will not
			// open — is a symptom of the misresolved configuration this line
			// exists to expose, and none of those messages names the file that
			// was read. csr reports in the same order for the same reason.
			reportResolvedConfig(cmd.ErrOrStderr(), resolvedCfgFile, cfg)

			rt, err := resolveRuntime(cmd.Context(), cfg, true)
			if err != nil {
				return err
			}
			defer func() { _ = rt.Close() }()

			// Refuse while a server holds the store: this replaces the CA
			// certificate and may revoke through the CRL, and one instance is
			// all a backend without distributed locking supports.
			if _, err := holdInstanceLock(cmd.Context(), rt); err != nil {
				return err
			}

			myCA := ca.New(rt.Store, ca.AutosignConfig{Mode: "off"}, cfg.Hostname)
			if err := applyCAConfig(myCA, cfg); err != nil {
				return err
			}
			myCA.KeyProvider = rt.KeyProvider

			// Validate before touching anything, so --out and a real import
			// apply exactly the same checks. The key-binding proof is part of
			// that: --out exists for read-only Secret mounts, where a bundle
			// that does not bind this CA's key is otherwise discovered only
			// after it has rolled out to every replica.
			certs, err := ca.ParseCABundle(bundlePEM)
			if err != nil {
				return fmt.Errorf("--cert-bundle: %w", err)
			}
			if err := ca.ValidateCABundleOrder(certs); err != nil {
				return fmt.Errorf("--cert-bundle: %w", err)
			}

			signer, err := myCA.LoadOrCreateCAKey(cmd.Context(), false)
			if err != nil {
				if errors.Is(err, ca.ErrKeyProviderKeyNotFound) {
					return fmt.Errorf("no CA key exists to match this certificate against: run "+
						"'openvox-ca csr --create-key' first, or provision the key out of band: %w", err)
				}
				return err
			}
			if err := ca.AssertSignerMatchesCert(certs[0], signer); err != nil {
				return err
			}

			if outFile != "" {
				return writeValidatedBundle(cmd, outFile, certs)
			}

			replaced, err := ca.ImportCACertificate(cmd.Context(), rt.Store, bundlePEM, signer,
				myCA.CRLValidityDuration(), force)
			if err != nil {
				return annotateOverlayWriteError(err, cfg)
			}

			msg := fmt.Sprintf("Imported CA certificate %q (%d certificates in chain)\n",
				certs[0].Subject.CommonName, len(certs))
			if replaced {
				// The CA certificate is read once at startup, so a running
				// replica keeps serving under the certificate it replaced.
				msg += "The previous CA certificate was replaced: restart every replica before it issues again.\n"
			}
			// Best-effort, and deliberately not returned: the import has
			// committed, and under --force the previous certificate is already
			// gone. An EPIPE from a closed pipe in a wrapper script would
			// otherwise make tooling read an irreversible, successful
			// replacement as a failure — and the natural response to that is a
			// retry or a rollback, neither of which is what storage now needs.
			// The exit code reports the state of storage, not of stderr.
			_, _ = fmt.Fprint(cmd.ErrOrStderr(), msg)
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&configFile, "config", "", "Path to YAML config file (default: /etc/puppet-ca/config.yaml if it exists)")
	f.StringVar(&caDir, "cadir", "", "CA storage directory (overrides the config file)")
	f.StringVar(&bundleFile, "cert-bundle", "", "Path to the signed CA certificate chain, nearest first")
	f.StringVar(&outFile, "out", "", "Validate and write the bundle to this file instead of to storage")
	f.BoolVar(&force, "force", false, "Replace an existing CA certificate, re-signing the stored CRL")
	_ = cmd.MarkFlagRequired("cert-bundle")

	return cmd
}

// writeValidatedBundle writes an already-validated chain to path.
//
// The chain is re-encoded rather than the operator's file copied through, so
// what lands in the Secret is exactly what was validated — same DER, no PEM
// commentary and nothing that was skipped on the way in.
func writeValidatedBundle(cmd *cobra.Command, path string, certs []*x509.Certificate) error {
	if err := writePublicFile(path, ca.EncodeCABundle(certs)); err != nil {
		return err
	}
	_, err := fmt.Fprintf(cmd.ErrOrStderr(),
		"Validated CA certificate %q written to %s (not installed; load it into the configured ca_cert_file)\n",
		certs[0].Subject.CommonName, path)
	return err
}

// annotateOverlayWriteError appends guidance when writing the CA certificate
// failed and that certificate is overlaid onto a local path.
//
// It keys on ErrCACertWrite, not on any import failure: the remedy it names —
// re-run with --out and load the result out of band — is right only for a
// certificate blob that could not be written, and is actively misleading for a
// key mismatch or a bad CRL, neither of which --out would fix.
//
// Writability itself is never guessed at. An overlay onto a writable path is a
// supported configuration and must not be pre-emptively refused, so the write
// is attempted and only its failure is annotated.
func annotateOverlayWriteError(err error, cfg *serverConfig) error {
	if err == nil || cfg.CACertFile == "" || !errors.Is(err, ca.ErrCACertWrite) {
		return err
	}
	return fmt.Errorf("%w\n\nThe CA certificate is overlaid onto %s. If that path is read-only "+
		"(a mounted Kubernetes Secret, for example), re-run with --out to write a validated bundle "+
		"to a file and load it into the Secret out of band", err, cfg.CACertFile)
}
