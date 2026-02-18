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
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/tvaughan/puppet-ca/internal/api"
	"github.com/tvaughan/puppet-ca/internal/ca"
	"github.com/tvaughan/puppet-ca/internal/storage"
)

func main() {
	caDir := flag.String("cadir", "", "Directory for CA storage (required)")
	autosignVal := flag.String("autosign-config", "", "Autosign configuration: 'true', 'false', or path to file/executable")
	host := flag.String("host", "0.0.0.0", "Address to listen on")
	port := flag.Int("port", 8140, "Port to listen on")
	hostname := flag.String("hostname", "", "Hostname for the CA certificate CN (e.g. puppet.example.com)")
	daemon := flag.Bool("daemon", false, "Run in background as a daemon (not recommended in containers)")
	verbosity := flag.Int("v", 0, "Verbosity: 0=Info 1=Debug 2=Trace")
	logFile := flag.String("logfile", "", "Log to file instead of stderr (implies daemon log destination)")
	tlsCert := flag.String("tls-cert", "", "Path to TLS server certificate PEM (enables HTTPS)")
	tlsKey := flag.String("tls-key", "", "Path to TLS server private key PEM (enables HTTPS)")
	puppetServers := flag.String("puppet-server", "", "Comma-separated list of puppet-server CNs allowed admin access")
	flag.Parse()

	if *caDir == "" {
		fmt.Fprintln(os.Stderr, "Error: --cadir is required")
		os.Exit(1)
	}

	absCADir, err := filepath.Abs(*caDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving cadir: %v\n", err)
		os.Exit(1)
	}

	// Daemonise only when explicitly requested AND we aren't already the daemon child.
	if *daemon && os.Getenv("PUPPET_CA_DAEMON") != "1" {
		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to determine executable: %v\n", err)
			os.Exit(1)
		}
		cmd := exec.Command(exe, os.Args[1:]...)
		cmd.Env = append(os.Environ(), "PUPPET_CA_DAEMON=1")
		cmd.Stdin = nil
		cmd.Stdout = nil
		cmd.Stderr = nil
		if err := cmd.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to start daemon: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Puppet CA started in background (PID: %d)\n", cmd.Process.Pid)
		os.Exit(0)
	}

	// --- Logging setup ---
	var logLevel slog.Level
	switch *verbosity {
	case 0:
		logLevel = slog.LevelInfo
	case 1:
		logLevel = slog.LevelDebug
	default:
		logLevel = slog.Level(-8) // Trace
	}

	opts := &slog.HandlerOptions{Level: logLevel}
	var logHandler slog.Handler

	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open log file %s: %v\n", *logFile, err)
			os.Exit(1)
		}
		logHandler = slog.NewJSONHandler(f, opts)
	} else {
		logHandler = slog.NewTextHandler(os.Stderr, opts)
	}

	logger := slog.New(logHandler)
	slog.SetDefault(logger)

	slog.Info("Starting Puppet CA",
		"cadir", absCADir,
		"host", *host,
		"port", *port,
		"verbosity", *verbosity,
	)

	// --- Storage & Directories ---
	store := storage.New(absCADir)
	if err := store.EnsureDirs(); err != nil {
		slog.Error("Failed to create CA directories", "error", err)
		os.Exit(1)
	}

	// --- Autosign ---
	asCfg := ca.AutosignConfig{Mode: "off"}
	switch *autosignVal {
	case "", "false":
		// leave as off
	case "true":
		asCfg.Mode = "true"
	default:
		info, err := os.Stat(*autosignVal)
		if err != nil {
			slog.Error("Autosign config invalid", "path", *autosignVal, "error", err)
			os.Exit(1)
		}
		if info.Mode().IsRegular() {
			if info.Mode().Perm()&0111 != 0 {
				asCfg.Mode = "executable"
			} else {
				asCfg.Mode = "file"
			}
			asCfg.FileOrPath = *autosignVal
		}
	}
	slog.Debug("Autosign config", "mode", asCfg.Mode, "path", asCfg.FileOrPath)

	// --- CA Initialisation ---
	myCA := ca.New(store, asCfg, *hostname)
	if err := myCA.Init(); err != nil {
		slog.Error("Failed to initialise CA", "error", err)
		os.Exit(1)
	}

	// --- HTTP(S) Server ---
	srv := api.New(myCA)

	// Wire mTLS auth middleware when TLS is configured.
	if *tlsCert != "" && *tlsKey != "" {
		allowList := map[string]bool{}
		if *puppetServers != "" {
			for _, cn := range strings.Split(*puppetServers, ",") {
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

	addr := fmt.Sprintf("%s:%d", *host, *port)
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

	if *tlsCert != "" && *tlsKey != "" {
		// Load server TLS cert/key.
		serverCert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if err != nil {
			slog.Error("Failed to load TLS cert/key", "cert", *tlsCert, "key", *tlsKey, "error", err)
			os.Exit(1)
		}

		// Build a CA pool from the on-disk CA cert for client cert verification.
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

		slog.Info("TLS enabled", "cert", *tlsCert)
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
}
