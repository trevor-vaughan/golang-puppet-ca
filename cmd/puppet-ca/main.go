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

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/tvaughan/puppet-ca/internal/api"
	"github.com/tvaughan/puppet-ca/internal/ca"
	"github.com/tvaughan/puppet-ca/internal/storage"
)

// isLoopback reports whether host is a loopback address (127.x.x.x, ::1, or
// "localhost"). Plain HTTP is only safe when the server cannot be reached from
// outside the local process.
func isLoopback(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return host == "localhost"
}

func main() {
	var (
		caDir         string
		autosignVal   string
		host          string
		port          int
		hostname      string
		daemon        bool
		verbosity     int
		logFile       string
		tlsCert       string
		tlsKey        string
		puppetServers string
		noTLSRequired bool
		ocspURL       string
	)

	cmd := &cobra.Command{
		Use:          "puppet-ca",
		Short:        "Puppet-compatible certificate authority server",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			absCADir, err := filepath.Abs(caDir)
			if err != nil {
				return fmt.Errorf("resolving --cadir: %w", err)
			}

			// Daemonise only when explicitly requested AND we aren't already the daemon child.
			if daemon && os.Getenv("PUPPET_CA_DAEMON") != "1" {
				exe, err := os.Executable()
				if err != nil {
					return fmt.Errorf("failed to determine executable: %w", err)
				}
				c := exec.Command(exe, os.Args[1:]...)
				c.Env = append(os.Environ(), "PUPPET_CA_DAEMON=1")
				c.Stdin = nil
				c.Stdout = nil
				c.Stderr = nil
				if err := c.Start(); err != nil {
					return fmt.Errorf("failed to start daemon: %w", err)
				}
				fmt.Printf("Puppet CA started in background (PID: %d)\n", c.Process.Pid)
				return nil
			}

			// --- Logging setup ---
			var logLevel slog.Level
			switch verbosity {
			case 0:
				logLevel = slog.LevelInfo
			case 1:
				logLevel = slog.LevelDebug
			default:
				logLevel = slog.Level(-8) // Trace
			}

			opts := &slog.HandlerOptions{Level: logLevel}
			var logHandler slog.Handler

			if logFile != "" {
				f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
				if err != nil {
					return fmt.Errorf("failed to open log file %s: %w", logFile, err)
				}
				logHandler = slog.NewJSONHandler(f, opts)
			} else {
				logHandler = slog.NewTextHandler(os.Stderr, opts)
			}

			logger := slog.New(logHandler)
			slog.SetDefault(logger)

			slog.Info("Starting Puppet CA",
				"cadir", absCADir,
				"host", host,
				"port", port,
				"verbosity", verbosity,
			)

			// --- TLS enforcement ---
			// Plain HTTP over a non-loopback interface lets any on-path host
			// inject forged certificates. Refuse to start unless:
			//   (a) TLS is configured (--tls-cert + --tls-key), or
			//   (b) the bind address is loopback-only, or
			//   (c) the operator explicitly opts out with --no-tls-required.
			tlsConfigured := tlsCert != "" && tlsKey != ""
			if !tlsConfigured {
				if !isLoopback(host) && !noTLSRequired {
					slog.Error("Refusing to start: plain HTTP on a non-loopback address is " +
						"vulnerable to certificate injection attacks. " +
						"Enable TLS (--tls-cert / --tls-key), " +
						"restrict to loopback (--host 127.0.0.1), " +
						"or explicitly opt out with --no-tls-required.")
					os.Exit(1)
				}
				if noTLSRequired && !isLoopback(host) {
					slog.Warn("TLS is not configured on a non-loopback address; " +
						"certificate injection is possible. " +
						"Only use --no-tls-required behind a trusted TLS proxy or in test environments.")
				}
			}

			// --- Storage & Directories ---
			store := storage.New(absCADir)
			if err := store.EnsureDirs(); err != nil {
				slog.Error("Failed to create CA directories", "error", err)
				os.Exit(1)
			}

			// --- Autosign ---
			asCfg := ca.AutosignConfig{Mode: "off"}
			switch autosignVal {
			case "", "false":
				// leave as off
			case "true":
				asCfg.Mode = "true"
			default:
				info, err := os.Stat(autosignVal)
				if err != nil {
					slog.Error("Autosign config invalid", "path", autosignVal, "error", err)
					os.Exit(1)
				}
				if info.Mode().IsRegular() {
					if info.Mode().Perm()&0111 != 0 {
						asCfg.Mode = "executable"
					} else {
						asCfg.Mode = "file"
					}
					asCfg.FileOrPath = autosignVal
				}
			}
			slog.Debug("Autosign config", "mode", asCfg.Mode, "path", asCfg.FileOrPath)

			// --- CA Initialisation ---
			myCA := ca.New(store, asCfg, hostname)
			if ocspURL != "" {
				myCA.OCSPURLs = []string{ocspURL}
			}
			if err := myCA.Init(); err != nil {
				slog.Error("Failed to initialise CA", "error", err)
				os.Exit(1)
			}

			// --- HTTP(S) Server ---
			srv := api.New(myCA)

			// Wire mTLS auth middleware when TLS is configured.
			if tlsCert != "" && tlsKey != "" {
				allowList := map[string]bool{}
				if puppetServers != "" {
					for _, cn := range strings.Split(puppetServers, ",") {
						cn = strings.TrimSpace(cn)
						if cn != "" {
							allowList[cn] = true
						}
					}
				}
				srv.AuthConfig = &api.AuthConfig{
					CACert:    myCA.CACert,
					AllowList: allowList,
				}
			}

			addr := fmt.Sprintf("%s:%d", host, port)
			slog.Info("Listening", "address", addr)

			server := &http.Server{
				Addr:              addr,
				Handler:           srv.Routes(),
				ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout:       30 * time.Second,
				WriteTimeout:      60 * time.Second,
				IdleTimeout:       120 * time.Second,
				MaxHeaderBytes:    1 << 20,
			}

			if tlsCert != "" && tlsKey != "" {
				serverCert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
				if err != nil {
					slog.Error("Failed to load TLS cert/key", "cert", tlsCert, "key", tlsKey, "error", err)
					os.Exit(1)
				}

				caCertPEM, err := os.ReadFile(myCA.Storage.CACertPath())
				if err != nil {
					slog.Error("Failed to read CA cert for TLS", "error", err)
					os.Exit(1)
				}
				caPool := x509.NewCertPool()
				block, _ := pem.Decode(caCertPEM)
				if block != nil {
					if caCert, err := x509.ParseCertificate(block.Bytes); err == nil {
						caPool.AddCert(caCert)
					}
				}

				server.TLSConfig = &tls.Config{
					Certificates: []tls.Certificate{serverCert},
					ClientCAs:    caPool,
					ClientAuth:   tls.RequestClientCert,
					MinVersion:   tls.VersionTLS12,
				}

				slog.Info("TLS enabled", "cert", tlsCert)
				if err := server.ListenAndServeTLS("", ""); err != nil {
					slog.Error("Server failed", "error", err)
					os.Exit(1)
				}
			} else {
				if err := server.ListenAndServe(); err != nil {
					slog.Error("Server failed", "error", err)
					os.Exit(1)
				}
			}

			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&caDir, "cadir", "", "Directory for CA storage (required)")
	f.StringVar(&autosignVal, "autosign-config", "", "Autosign configuration: 'true', 'false', or path to file/executable")
	f.StringVar(&host, "host", "0.0.0.0", "Address to listen on")
	f.IntVar(&port, "port", 8140, "Port to listen on")
	f.StringVar(&hostname, "hostname", "", "Hostname for the CA certificate CN (e.g. puppet.example.com)")
	f.BoolVar(&daemon, "daemon", false, "Run in background as a daemon (not recommended in containers)")
	f.IntVarP(&verbosity, "verbosity", "v", 0, "Verbosity: 0=Info 1=Debug 2=Trace")
	f.StringVar(&logFile, "logfile", "", "Log to file instead of stderr (implies daemon log destination)")
	f.StringVar(&tlsCert, "tls-cert", "", "Path to TLS server certificate PEM (enables HTTPS)")
	f.StringVar(&tlsKey, "tls-key", "", "Path to TLS server private key PEM (enables HTTPS)")
	f.StringVar(&puppetServers, "puppet-server", "", "Comma-separated list of puppet-server CNs allowed admin access")
	f.BoolVar(&noTLSRequired, "no-tls-required", false, "Allow plain HTTP on non-loopback addresses (use only behind a trusted TLS proxy or in test environments)")
	f.StringVar(&ocspURL, "ocsp-url", "", "OCSP responder URL to embed in issued certificates (e.g. http://puppet-ca:8140/ocsp)")
	_ = cmd.MarkFlagRequired("cadir")

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
