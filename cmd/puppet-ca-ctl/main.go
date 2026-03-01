// Copyright (C) 2026 Trevor Vaughan
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

// puppet-ca-ctl is an operator management CLI for the puppet-ca server.
//
// Usage:
//
//	puppet-ca-ctl [global-flags] <subcommand> [subcommand-flags]
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/tvaughan/puppet-ca/internal/ca"
	"github.com/tvaughan/puppet-ca/internal/storage"
)

// ---------- global state (set by persistent flags / config) ----------

var (
	globalServerURL  string
	globalCACert     string
	globalClientCert string
	globalClientKey  string
	globalVerbose    bool
	globalConfigFile string
)

// ---------- HTTP client ----------

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

func newClient() (*Client, error) {
	transport := &http.Transport{}

	tlsCfg := &tls.Config{}

	if globalCACert != "" {
		caCertPEM, err := os.ReadFile(globalCACert)
		if err != nil {
			return nil, fmt.Errorf("reading --ca-cert %s: %w", globalCACert, err)
		}
		pool := x509.NewCertPool()
		block, _ := pem.Decode(caCertPEM)
		if block != nil {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parsing --ca-cert: %w", err)
			}
			pool.AddCert(cert)
		}
		tlsCfg.RootCAs = pool
	} else {
		// No CA cert provided: skip TLS verification (useful for self-signed dev certs).
		tlsCfg.InsecureSkipVerify = true //nolint:gosec
	}

	if globalClientCert != "" && globalClientKey != "" {
		cert, err := tls.LoadX509KeyPair(globalClientCert, globalClientKey)
		if err != nil {
			return nil, fmt.Errorf("loading --client-cert/--client-key: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	transport.TLSClientConfig = tlsCfg

	return &Client{
		BaseURL: strings.TrimRight(globalServerURL, "/"),
		HTTPClient: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
	}, nil
}

func (c *Client) do(method, path string, body []byte) (int, []byte, error) {
	url := c.BaseURL + path
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody, err
}

func (c *Client) get(path string) (int, []byte, error) {
	return c.do("GET", path, nil)
}

func (c *Client) put(path string, body []byte) (int, []byte, error) {
	return c.do("PUT", path, body)
}

func (c *Client) delete(path string) (int, []byte, error) {
	return c.do("DELETE", path, nil)
}

func (c *Client) post(path string, body []byte) (int, []byte, error) {
	return c.do("POST", path, body)
}

// ---------- helpers ----------

func checkHTTP(code int, body []byte, method, path string) error {
	if code >= 200 && code < 300 {
		return nil
	}
	return fmt.Errorf("HTTP %d on %s %s: %s", code, method, path, strings.TrimSpace(string(body)))
}

func printTable(rows [][2]string) {
	w := 0
	for _, r := range rows {
		if len(r[0]) > w {
			w = len(r[0])
		}
	}
	for _, r := range rows {
		fmt.Printf("%-*s  %s\n", w, r[0], r[1])
	}
}

// ---------- subcommand constructors ----------

func newListCmd() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:          "list",
		Short:        "List pending (or all) certificate requests",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}

			path := "/puppet-ca/v1/certificate_statuses/all"
			if !all {
				path += "?state=requested"
			}

			code, body, err := c.get(path)
			if err != nil {
				return err
			}
			if err := checkHTTP(code, body, "GET", path); err != nil {
				return err
			}

			var statuses []struct {
				Name  string `json:"name"`
				State string `json:"state"`
			}
			if err := json.Unmarshal(body, &statuses); err != nil {
				return fmt.Errorf("could not parse response: %w", err)
			}

			if len(statuses) == 0 {
				fmt.Println("(no certificates)")
				return nil
			}
			rows := make([][2]string, len(statuses))
			for i, s := range statuses {
				rows[i] = [2]string{s.Name, s.State}
			}
			printTable(rows)
			return nil
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "List all certs (default: only pending CSRs)")
	return cmd
}

func newSignCmd() *cobra.Command {
	var certname string
	var all bool
	cmd := &cobra.Command{
		Use:          "sign",
		Short:        "Sign a pending CSR (or --all)",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}

			if all {
				code, body, err := c.post("/puppet-ca/v1/sign/all", nil)
				if err != nil {
					return err
				}
				if err := checkHTTP(code, body, "POST", "/puppet-ca/v1/sign/all"); err != nil {
					return err
				}
				var result struct {
					Signed []string `json:"signed"`
				}
				if err := json.Unmarshal(body, &result); err != nil {
					return fmt.Errorf("parse error: %w", err)
				}
				if len(result.Signed) == 0 {
					fmt.Println("Signed: (none)")
				} else {
					fmt.Printf("Signed: %s\n", strings.Join(result.Signed, ", "))
				}
				return nil
			}

			if certname == "" {
				return fmt.Errorf("--certname or --all is required")
			}

			path := "/puppet-ca/v1/certificate_status/" + certname
			body, _ := json.Marshal(map[string]string{"desired_state": "signed"})
			code, respBody, err := c.put(path, body)
			if err != nil {
				return err
			}
			if err := checkHTTP(code, respBody, "PUT", path); err != nil {
				return err
			}
			fmt.Printf("Signed %s\n", certname)
			return nil
		},
	}
	cmd.Flags().StringVar(&certname, "certname", "", "Subject name to sign")
	cmd.Flags().BoolVar(&all, "all", false, "Sign all pending CSRs")
	return cmd
}

func newRevokeCmd() *cobra.Command {
	var certname string
	cmd := &cobra.Command{
		Use:          "revoke",
		Short:        "Revoke a certificate",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}

			path := "/puppet-ca/v1/certificate_status/" + certname
			body, _ := json.Marshal(map[string]string{"desired_state": "revoked"})
			code, respBody, err := c.put(path, body)
			if err != nil {
				return err
			}
			if err := checkHTTP(code, respBody, "PUT", path); err != nil {
				return err
			}
			fmt.Printf("Revoked %s\n", certname)
			return nil
		},
	}
	cmd.Flags().StringVar(&certname, "certname", "", "Subject name to revoke")
	_ = cmd.MarkFlagRequired("certname")
	return cmd
}

func newCleanCmd() *cobra.Command {
	var certname string
	cmd := &cobra.Command{
		Use:          "clean",
		Short:        "Revoke and delete a certificate/CSR",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}

			path := "/puppet-ca/v1/certificate_status/" + certname
			code, respBody, err := c.delete(path)
			if err != nil {
				return err
			}
			if err := checkHTTP(code, respBody, "DELETE", path); err != nil {
				return err
			}
			fmt.Printf("Cleaned %s\n", certname)
			return nil
		},
	}
	cmd.Flags().StringVar(&certname, "certname", "", "Subject name to clean")
	_ = cmd.MarkFlagRequired("certname")
	return cmd
}

func newGenerateCmd() *cobra.Command {
	var certname, outDir, dns string
	cmd := &cobra.Command{
		Use:          "generate",
		Short:        "Generate a server-side key+cert pair",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}

			path := "/puppet-ca/v1/generate/" + certname
			if dns != "" {
				path += "?dns=" + strings.ReplaceAll(dns, ",", "&dns=")
			}

			code, body, err := c.post(path, nil)
			if err != nil {
				return err
			}
			if err := checkHTTP(code, body, "POST", path); err != nil {
				return err
			}

			var result struct {
				PrivateKey  string `json:"private_key"`
				Certificate string `json:"certificate"`
			}
			if err := json.Unmarshal(body, &result); err != nil {
				return fmt.Errorf("could not parse response: %w", err)
			}

			keyPath := filepath.Join(outDir, certname+"_key.pem")
			if err := os.WriteFile(keyPath, []byte(result.PrivateKey), 0640); err != nil {
				return fmt.Errorf("failed to save private key to %s: %w", keyPath, err)
			}
			fmt.Fprintf(os.Stderr, "Private key saved to %s\n", keyPath)
			fmt.Print(result.Certificate)
			return nil
		},
	}
	cmd.Flags().StringVar(&certname, "certname", "", "Subject name to generate")
	cmd.Flags().StringVar(&outDir, "out-dir", ".", "Directory to save the private key file")
	cmd.Flags().StringVar(&dns, "dns", "", "Comma-separated DNS alt names")
	_ = cmd.MarkFlagRequired("certname")
	return cmd
}

func newSetupCmd() *cobra.Command {
	var caDir, hostname string
	cmd := &cobra.Command{
		Use:          "setup",
		Short:        "Initialise a new CA (offline)",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			absDir, err := filepath.Abs(caDir)
			if err != nil {
				return fmt.Errorf("invalid --cadir: %w", err)
			}

			store := storage.New(absDir)
			myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, hostname)
			if err := myCA.Init(); err != nil {
				return err
			}
			fmt.Printf("CA initialized in %s (CN: Puppet CA: %s)\n", absDir, hostname)
			return nil
		},
	}
	cmd.Flags().StringVar(&caDir, "cadir", "", "Directory to initialise CA in")
	cmd.Flags().StringVar(&hostname, "hostname", "puppet", "Hostname for the CA certificate CN")
	_ = cmd.MarkFlagRequired("cadir")
	return cmd
}

func newImportCmd() *cobra.Command {
	var caDir, certBundle, privateKey, crlChain string
	cmd := &cobra.Command{
		Use:          "import",
		Short:        "Import an external CA cert/key (offline)",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			absDir, err := filepath.Abs(caDir)
			if err != nil {
				return fmt.Errorf("invalid --cadir: %w", err)
			}

			certPEM, err := os.ReadFile(certBundle)
			if err != nil {
				return fmt.Errorf("reading --cert-bundle: %w", err)
			}
			keyPEM, err := os.ReadFile(privateKey)
			if err != nil {
				return fmt.Errorf("reading --private-key: %w", err)
			}
			var crlPEM []byte
			if crlChain != "" {
				crlPEM, err = os.ReadFile(crlChain)
				if err != nil {
					return fmt.Errorf("reading --crl-chain: %w", err)
				}
			}

			store := storage.New(absDir)
			if err := ca.ImportCA(store, certPEM, keyPEM, crlPEM); err != nil {
				return err
			}
			fmt.Printf("CA imported into %s\n", absDir)
			return nil
		},
	}
	cmd.Flags().StringVar(&caDir, "cadir", "", "CA storage directory")
	cmd.Flags().StringVar(&certBundle, "cert-bundle", "", "Path to CA certificate PEM")
	cmd.Flags().StringVar(&privateKey, "private-key", "", "Path to CA private key PEM")
	cmd.Flags().StringVar(&crlChain, "crl-chain", "", "Path to CRL PEM (optional; one will be generated if absent)")
	_ = cmd.MarkFlagRequired("cadir")
	_ = cmd.MarkFlagRequired("cert-bundle")
	_ = cmd.MarkFlagRequired("private-key")
	return cmd
}

// ---------- main ----------

func main() {
	rootCmd := &cobra.Command{
		Use:   "puppet-ca-ctl",
		Short: "Operator management CLI for puppet-ca",
		Long: `puppet-ca-ctl manages certificates on a running puppet-ca server.

Global flags must be specified before the subcommand.`,
		SilenceUsage: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			resolved := resolveConfigFile(globalConfigFile, "PUPPET_CA_CTL_CONFIG", "/etc/puppet-ca/ctl.yaml")
			cfg, err := loadCtlConfig(resolved)
			if err != nil {
				return err
			}

			// Apply explicitly-set CLI flags (highest precedence).
			pf := cmd.Root().PersistentFlags()
			if pf.Changed("server-url") {
				cfg.ServerURL = globalServerURL
			}
			if pf.Changed("ca-cert") {
				cfg.CACert = globalCACert
			}
			if pf.Changed("client-cert") {
				cfg.ClientCert = globalClientCert
			}
			if pf.Changed("client-key") {
				cfg.ClientKey = globalClientKey
			}
			if pf.Changed("verbose") {
				cfg.Verbose = globalVerbose
			}

			// Assign resolved values back to globals used by subcommands.
			globalServerURL = cfg.ServerURL
			globalCACert = cfg.CACert
			globalClientCert = cfg.ClientCert
			globalClientKey = cfg.ClientKey
			globalVerbose = cfg.Verbose

			if globalVerbose {
				slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
			}
			return nil
		},
	}

	pf := rootCmd.PersistentFlags()
	pf.StringVar(&globalConfigFile, "config", "", "Path to YAML config file (default: /etc/puppet-ca/ctl.yaml if it exists)")
	pf.StringVar(&globalServerURL, "server-url", "https://localhost:8140", "puppet-ca server URL")
	pf.StringVar(&globalCACert, "ca-cert", "", "Path to CA cert PEM for TLS verification (omit to skip verify)")
	pf.StringVar(&globalClientCert, "client-cert", "", "Path to client certificate PEM for mTLS")
	pf.StringVar(&globalClientKey, "client-key", "", "Path to client private key PEM for mTLS")
	pf.BoolVar(&globalVerbose, "verbose", false, "Enable verbose logging")

	rootCmd.AddCommand(
		newListCmd(),
		newSignCmd(),
		newRevokeCmd(),
		newCleanCmd(),
		newGenerateCmd(),
		newSetupCmd(),
		newImportCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
