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
// It mirrors the subcommands of tvaughan-server-ca:
//
//	list, sign, revoke, clean, generate, setup, import
//
// Global flags must appear before the subcommand.
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
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tvaughan/puppet-ca/internal/ca"
	"github.com/tvaughan/puppet-ca/internal/storage"
)

// ---------- global state ----------

var (
	globalServerURL  string
	globalCACert     string
	globalClientCert string
	globalClientKey  string
	globalVerbose    bool
)

// ---------- HTTP client ----------

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

func newClient() *Client {
	transport := &http.Transport{}

	tlsCfg := &tls.Config{}
	needTLS := false

	if globalCACert != "" {
		caCertPEM, err := os.ReadFile(globalCACert)
		if err != nil {
			fatalf("Error reading --ca-cert %s: %v", globalCACert, err)
		}
		pool := x509.NewCertPool()
		block, _ := pem.Decode(caCertPEM)
		if block != nil {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				fatalf("Error parsing --ca-cert: %v", err)
			}
			pool.AddCert(cert)
		}
		tlsCfg.RootCAs = pool
		needTLS = true
	} else {
		// No CA cert provided: skip TLS verification (useful for self-signed dev certs).
		tlsCfg.InsecureSkipVerify = true //nolint:gosec
		needTLS = true
	}

	if globalClientCert != "" && globalClientKey != "" {
		cert, err := tls.LoadX509KeyPair(globalClientCert, globalClientKey)
		if err != nil {
			fatalf("Error loading --client-cert/--client-key: %v", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
		needTLS = true
	}

	if needTLS {
		transport.TLSClientConfig = tlsCfg
	}

	return &Client{
		BaseURL: strings.TrimRight(globalServerURL, "/"),
		HTTPClient: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
	}
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

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	os.Exit(1)
}

func checkHTTP(code int, body []byte, method, path string) {
	if code >= 200 && code < 300 {
		return
	}
	fatalf("HTTP %d on %s %s: %s", code, method, path, strings.TrimSpace(string(body)))
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

// ---------- subcommand: list ----------

func cmdList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	all := fs.Bool("all", false, "List all certs (default: only pending CSRs)")
	if err := fs.Parse(args); err != nil {
		fatalf("list: %v", err)
	}

	c := newClient()
	path := "/puppet-ca/v1/certificate_statuses/all"
	if !*all {
		path += "?state=requested"
	}

	code, body, err := c.get(path)
	if err != nil {
		fatalf("list: %v", err)
	}
	checkHTTP(code, body, "GET", path)

	var statuses []struct {
		Name  string `json:"name"`
		State string `json:"state"`
	}
	if err := json.Unmarshal(body, &statuses); err != nil {
		fatalf("list: could not parse response: %v", err)
	}

	if len(statuses) == 0 {
		fmt.Println("(no certificates)")
		return
	}
	rows := make([][2]string, len(statuses))
	for i, s := range statuses {
		rows[i] = [2]string{s.Name, s.State}
	}
	printTable(rows)
}

// ---------- subcommand: sign ----------

func cmdSign(args []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	certname := fs.String("certname", "", "Subject name to sign")
	all := fs.Bool("all", false, "Sign all pending CSRs")
	if err := fs.Parse(args); err != nil {
		fatalf("sign: %v", err)
	}

	c := newClient()

	if *all {
		code, body, err := c.post("/puppet-ca/v1/sign/all", nil)
		if err != nil {
			fatalf("sign --all: %v", err)
		}
		checkHTTP(code, body, "POST", "/puppet-ca/v1/sign/all")
		var result struct {
			Signed []string `json:"signed"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			fatalf("sign --all: parse error: %v", err)
		}
		if len(result.Signed) == 0 {
			fmt.Println("Signed: (none)")
		} else {
			fmt.Printf("Signed: %s\n", strings.Join(result.Signed, ", "))
		}
		return
	}

	if *certname == "" {
		fatalf("sign: --certname or --all is required")
	}

	path := "/puppet-ca/v1/certificate_status/" + *certname
	body, _ := json.Marshal(map[string]string{"desired_state": "signed"})
	code, respBody, err := c.put(path, body)
	if err != nil {
		fatalf("sign: %v", err)
	}
	checkHTTP(code, respBody, "PUT", path)
	fmt.Printf("Signed %s\n", *certname)
}

// ---------- subcommand: revoke ----------

func cmdRevoke(args []string) {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	certname := fs.String("certname", "", "Subject name to revoke (required)")
	if err := fs.Parse(args); err != nil {
		fatalf("revoke: %v", err)
	}
	if *certname == "" {
		fatalf("revoke: --certname is required")
	}

	c := newClient()
	path := "/puppet-ca/v1/certificate_status/" + *certname
	body, _ := json.Marshal(map[string]string{"desired_state": "revoked"})
	code, respBody, err := c.put(path, body)
	if err != nil {
		fatalf("revoke: %v", err)
	}
	checkHTTP(code, respBody, "PUT", path)
	fmt.Printf("Revoked %s\n", *certname)
}

// ---------- subcommand: clean ----------

func cmdClean(args []string) {
	fs := flag.NewFlagSet("clean", flag.ExitOnError)
	certname := fs.String("certname", "", "Subject name to clean (required)")
	if err := fs.Parse(args); err != nil {
		fatalf("clean: %v", err)
	}
	if *certname == "" {
		fatalf("clean: --certname is required")
	}

	c := newClient()
	path := "/puppet-ca/v1/certificate_status/" + *certname
	code, respBody, err := c.delete(path)
	if err != nil {
		fatalf("clean: %v", err)
	}
	checkHTTP(code, respBody, "DELETE", path)
	fmt.Printf("Cleaned %s\n", *certname)
}

// ---------- subcommand: generate ----------

func cmdGenerate(args []string) {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	certname := fs.String("certname", "", "Subject name to generate (required)")
	outDir := fs.String("out-dir", ".", "Directory to save the private key file")
	dns := fs.String("dns", "", "Comma-separated DNS alt names")
	if err := fs.Parse(args); err != nil {
		fatalf("generate: %v", err)
	}
	if *certname == "" {
		fatalf("generate: --certname is required")
	}

	path := "/puppet-ca/v1/generate/" + *certname
	if *dns != "" {
		path += "?dns=" + strings.ReplaceAll(*dns, ",", "&dns=")
	}

	c := newClient()
	code, body, err := c.post(path, nil)
	if err != nil {
		fatalf("generate: %v", err)
	}
	checkHTTP(code, body, "POST", path)

	var result struct {
		PrivateKey  string `json:"private_key"`
		Certificate string `json:"certificate"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		fatalf("generate: could not parse response: %v", err)
	}

	// Save private key.
	keyPath := filepath.Join(*outDir, *certname+"_key.pem")
	if err := os.WriteFile(keyPath, []byte(result.PrivateKey), 0640); err != nil {
		fatalf("generate: failed to save private key to %s: %v", keyPath, err)
	}
	fmt.Fprintf(os.Stderr, "Private key saved to %s\n", keyPath)

	// Print certificate to stdout.
	fmt.Print(result.Certificate)
}

// ---------- subcommand: setup ----------

func cmdSetup(args []string) {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	caDir := fs.String("cadir", "", "Directory to initialise CA in (required)")
	hostname := fs.String("hostname", "puppet", "Hostname for the CA certificate CN")
	if err := fs.Parse(args); err != nil {
		fatalf("setup: %v", err)
	}
	if *caDir == "" {
		fatalf("setup: --cadir is required")
	}

	absDir, err := filepath.Abs(*caDir)
	if err != nil {
		fatalf("setup: invalid --cadir: %v", err)
	}

	store := storage.New(absDir)
	myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, *hostname)
	if err := myCA.Init(); err != nil {
		fatalf("setup: %v", err)
	}
	fmt.Printf("CA initialized in %s (CN: Puppet CA: %s)\n", absDir, *hostname)
}

// ---------- subcommand: import ----------

func cmdImport(args []string) {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	caDir := fs.String("cadir", "", "CA storage directory (required)")
	certBundle := fs.String("cert-bundle", "", "Path to CA certificate PEM (required)")
	privateKey := fs.String("private-key", "", "Path to CA private key PEM (required)")
	crlChain := fs.String("crl-chain", "", "Path to CRL PEM (optional; one will be generated if absent)")
	if err := fs.Parse(args); err != nil {
		fatalf("import: %v", err)
	}
	if *caDir == "" {
		fatalf("import: --cadir is required")
	}
	if *certBundle == "" {
		fatalf("import: --cert-bundle is required")
	}
	if *privateKey == "" {
		fatalf("import: --private-key is required")
	}

	absDir, err := filepath.Abs(*caDir)
	if err != nil {
		fatalf("import: invalid --cadir: %v", err)
	}
	certPEM, err := os.ReadFile(*certBundle)
	if err != nil {
		fatalf("import: reading --cert-bundle: %v", err)
	}
	keyPEM, err := os.ReadFile(*privateKey)
	if err != nil {
		fatalf("import: reading --private-key: %v", err)
	}
	var crlPEM []byte
	if *crlChain != "" {
		crlPEM, err = os.ReadFile(*crlChain)
		if err != nil {
			fatalf("import: reading --crl-chain: %v", err)
		}
	}

	store := storage.New(absDir)
	if err := ca.ImportCA(store, certPEM, keyPEM, crlPEM); err != nil {
		fatalf("import: %v", err)
	}
	fmt.Printf("CA imported into %s\n", absDir)
}

// ---------- main ----------

func main() {
	// Parse global flags before the subcommand.
	flag.StringVar(&globalServerURL, "server-url", "https://localhost:8140", "puppet-ca server URL")
	flag.StringVar(&globalCACert, "ca-cert", "", "Path to CA cert PEM for TLS verification (omit to skip verify)")
	flag.StringVar(&globalClientCert, "client-cert", "", "Path to client certificate PEM for mTLS")
	flag.StringVar(&globalClientKey, "client-key", "", "Path to client private key PEM for mTLS")
	flag.BoolVar(&globalVerbose, "verbose", false, "Enable verbose logging")
	flag.Parse()

	if globalVerbose {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}

	subcmdArgs := flag.Args()
	if len(subcmdArgs) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: puppet-ca-ctl [global-flags] <subcommand> [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Subcommands:\n")
		fmt.Fprintf(os.Stderr, "  list      List pending (or all) certificate requests\n")
		fmt.Fprintf(os.Stderr, "  sign      Sign a pending CSR (or --all)\n")
		fmt.Fprintf(os.Stderr, "  revoke    Revoke a certificate\n")
		fmt.Fprintf(os.Stderr, "  clean     Revoke and delete a certificate/CSR\n")
		fmt.Fprintf(os.Stderr, "  generate  Generate a server-side key+cert pair\n")
		fmt.Fprintf(os.Stderr, "  setup     Initialise a new CA (offline)\n")
		fmt.Fprintf(os.Stderr, "  import    Import an external CA cert/key (offline)\n")
		os.Exit(1)
	}

	subcmd := subcmdArgs[0]
	rest := subcmdArgs[1:]

	switch subcmd {
	case "list":
		cmdList(rest)
	case "sign":
		cmdSign(rest)
	case "revoke":
		cmdRevoke(rest)
	case "clean":
		cmdClean(rest)
	case "generate":
		cmdGenerate(rest)
	case "setup":
		cmdSetup(rest)
	case "import":
		cmdImport(rest)
	default:
		fatalf("unknown subcommand %q (run without arguments for help)", subcmd)
	}
}

// Ensure errors package is used (it's imported for future extensions).
var _ = errors.New
