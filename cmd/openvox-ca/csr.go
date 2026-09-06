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
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/voxpupuli/openvox-ca/internal/ca"
)

// newCSRCmd builds the "csr" subcommand, which emits a PKCS#10 certificate
// signing request for this CA's own key so an external parent can sign it and
// make this an intermediate CA.
//
// It lives on the server binary rather than openvox-ca-ctl because it must
// reach the configured storage backend and key provider, and openvox-ca-ctl can
// address only a local filesystem directory through a different configuration
// schema. Driving it from the server's own config file is also what makes it
// work identically for every ca_key_provider without special-casing.
func newCSRCmd() *cobra.Command {
	return newCSRCmdWith(func(ctx context.Context, cfg *serverConfig) (*caRuntime, error) {
		return resolveRuntime(ctx, cfg, true)
	})
}

// newCSRCmdWith is newCSRCmd with runtime resolution injected.
//
// The seam exists for one path a test cannot otherwise reach: a key provider
// that creates a key and then refuses to sign with it. That is not a contrived
// failure — under Transit the create and the signature are two separate grants,
// so a policy scoped one endpoint short produces exactly it, and the operator
// guidance the command prints in response ("a CA key now exists with no
// certificate") is the only thing standing between them and a crash-looping
// Deployment with no explanation.
func newCSRCmdWith(resolve runtimeResolver) *cobra.Command {
	var (
		configFile string
		caDir      string
		hostname   string
		outFile    string
		createKey  bool
	)

	cmd := &cobra.Command{
		Use:   "csr",
		Short: "Emit a certificate signing request for this CA's own key",
		Long: `Emit a PKCS#10 certificate signing request for this CA's own key, for an
external parent CA to sign.

The request carries the same subject this CA would otherwise self-sign, so the
certificate that comes back is a drop-in replacement. Sign it with the parent,
then load the resulting chain with "openvox-ca import-ca-cert".

The CA key is reached through the configured ca_key_provider, so this works
identically whether the key is a local PEM file or lives in OpenBao Transit.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedCfgFile := resolveConfigFile(configFile, "PUPPET_CA_CONFIG", "/etc/puppet-ca/config.yaml")
			cfg, err := loadServerConfig(resolvedCfgFile)
			if err != nil {
				return err
			}
			if cmd.Flags().Changed("cadir") {
				cfg.CADir = caDir
			}
			if cmd.Flags().Changed("hostname") {
				cfg.Hostname = hostname
			}

			reportResolvedConfig(cmd.ErrOrStderr(), resolvedCfgFile, cfg)

			rt, err := resolve(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			defer func() { _ = rt.Close() }()

			// Refuse while a server holds the store. --create-key writes the CA
			// key, and a backend without distributed locking supports exactly
			// one running process against it.
			if _, err := holdInstanceLock(cmd.Context(), rt); err != nil {
				return err
			}

			myCA := ca.New(rt.Store, ca.AutosignConfig{Mode: "off"}, cfg.Hostname)
			if err := applyCAConfig(myCA, cfg); err != nil {
				return err
			}
			myCA.KeyProvider = rt.KeyProvider

			// Checked before BuildCSR, which may create the key: with no
			// certificate the server refuses to start until import-ca-cert
			// installs the signed chain, and creating the key is what opens
			// that window. An operator who is not told walks into a
			// crash-looping Deployment with no idea which step caused it.
			hadCert, err := rt.Store.HasCACert(cmd.Context())
			if err != nil {
				return fmt.Errorf("checking for an existing CA certificate: %w", err)
			}

			csrPEM, err := myCA.BuildCSR(cmd.Context(), cfg.Hostname, createKey)
			if err != nil {
				if errors.Is(err, ca.ErrKeyProviderKeyNotFound) {
					return fmt.Errorf("no CA key exists yet: pass --create-key to create one, "+
						"or provision it out of band first: %w", err)
				}
				// BuildCSR creates the key and then signs with it, so a failure
				// here may already have committed a key. Under Transit those are
				// two different grants — transit/keys for the create,
				// transit/sign for the request — so a policy scoped one endpoint
				// short lands exactly here, with a key in the vault and no
				// certificate. Say so: it is the same obligation the import side
				// discharges with incompleteImportError, and the state is the
				// one Init refuses to start from.
				if createKey && !hadCert {
					if nowHasKey, keyErr := myCA.HasCAKey(cmd.Context()); keyErr == nil && nowHasKey {
						return fmt.Errorf("%w\n\nA CA key now exists with no certificate, so the server "+
							"will refuse to start. Fix the cause and re-run 'openvox-ca csr' (without "+
							"--create-key, which is no longer needed), then install the signed chain "+
							"with 'openvox-ca import-ca-cert'", err)
					}
				}
				return err
			}

			if !hadCert {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
					"This CA has a key but no certificate, so the server will refuse to start until "+
						"'openvox-ca import-ca-cert' installs the chain the parent signs.\n")
			}

			if outFile == "" {
				_, err := cmd.OutOrStdout().Write(csrPEM)
				return err
			}
			if err := writePublicFile(outFile, csrPEM); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.ErrOrStderr(), "Certificate signing request written to %s\n", outFile)
			return err
		},
	}

	f := cmd.Flags()
	f.StringVar(&configFile, "config", "", "Path to YAML config file (default: /etc/puppet-ca/config.yaml if it exists)")
	f.StringVar(&caDir, "cadir", "", "CA storage directory (overrides the config file)")
	f.StringVar(&hostname, "hostname", "", "Hostname for the CA subject, when no CA certificate exists yet")
	f.StringVar(&outFile, "out", "", "Write the request to this file instead of stdout")
	f.BoolVar(&createKey, "create-key", false, "Create the CA key if it does not exist yet")

	return cmd
}
