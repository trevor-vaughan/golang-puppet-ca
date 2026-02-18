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

package ca

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type AutosignConfig struct {
	Mode       string // "true", "file", "executable" (or "off" implicitly)
	FileOrPath string // Path to autosign.conf or executable
}

func CheckAutosign(cfg AutosignConfig, csr *x509.CertificateRequest, csrPEM []byte) (bool, error) {
	switch cfg.Mode {
	case "true":
		return true, nil
	case "file":
		return checkAutosignFile(cfg.FileOrPath, csr.Subject.CommonName)
	case "executable":
		return checkAutosignExecutable(cfg.FileOrPath, csr.Subject.CommonName, csrPEM)
	default:
		return false, nil
	}
}

func checkAutosignFile(path, commonName string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Simple glob matching
		matched, err := filepath.Match(line, commonName)
		if err != nil {
			// If pattern is bad, just ignore or log? Standard Match doesn't handle some complex globs
			// but Puppet's autosign usually uses standard shell globs.
			continue
		}
		if matched {
			return true, nil
		}
	}
	return false, scanner.Err()
}

func checkAutosignExecutable(path, commonName string, csrPEM []byte) (bool, error) {
	cmd := exec.Command(path, commonName)

	// Set Env
	cmd.Env = os.Environ()
	// Ensure RUBYLIB and GEM_PATH are preserved (they are in Environ, but let's be explicit if needed)
	// Actually os.Environ() includes them.

	cmd.Stdin = bytes.NewReader(csrPEM)

	if err := cmd.Run(); err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			// Non-zero exit code means deny
			return false, nil
		}
		return false, err
	}

	return true, nil
}
