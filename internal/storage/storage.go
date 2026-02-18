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

package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	FilePermPrivate = 0640
	FilePermPublic  = 0644
	DirPerm         = 0750
)

type StorageService struct {
	baseDir     string
	serialMu    sync.Mutex
	inventoryMu sync.RWMutex
	crlMu       sync.RWMutex
	fileMu      sync.RWMutex // General file system lock for certs/csrs
}

func New(baseDir string) *StorageService {
	return &StorageService{
		baseDir: baseDir,
	}
}

func (s *StorageService) EnsureDirs() error {
	dirs := []string{
		s.baseDir,
		filepath.Join(s.baseDir, "signed"),
		filepath.Join(s.baseDir, "requests"),
		filepath.Join(s.baseDir, "private"), // For CA key
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, DirPerm); err != nil {
			return err
		}
	}
	return nil
}

// IncrementSerial reads the serial file, returns the current value, and increments it in the file.
func (s *StorageService) IncrementSerial() (string, error) {
	s.serialMu.Lock()
	defer s.serialMu.Unlock()

	path := filepath.Join(s.baseDir, "serial")

	// Read current
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Initialize if missing (Plan says Init handles this, but good to be safe)
			return "", fmt.Errorf("serial file not found: %w", err)
		}
		return "", err
	}

	// Parse
	val := new(int64)
	n, err := fmt.Sscanf(string(content), "%x", val)
	if err != nil || n != 1 {
		return "", fmt.Errorf("invalid serial file at %s", path)
	}

	// Prepare return value (padded)
	ret := fmt.Sprintf("%04X", *val)

	// Increment
	nextVal := *val + 1
	nextHex := fmt.Sprintf("%04X", nextVal)

	// Write back
	if err := os.WriteFile(path, []byte(nextHex), FilePermPublic); err != nil {
		return "", err
	}

	return ret, nil
}

func (s *StorageService) WriteSerial(val string) error {
	s.serialMu.Lock()
	defer s.serialMu.Unlock()
	return os.WriteFile(filepath.Join(s.baseDir, "serial"), []byte(val), FilePermPublic)
}

func (s *StorageService) AppendInventory(entry string) error {
	s.inventoryMu.Lock()
	defer s.inventoryMu.Unlock()

	f, err := os.OpenFile(filepath.Join(s.baseDir, "inventory.txt"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, FilePermPublic)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.WriteString(entry + "\n"); err != nil {
		return err
	}
	return nil
}

func (s *StorageService) ReadInventory() ([]byte, error) {
	s.inventoryMu.RLock()
	defer s.inventoryMu.RUnlock()
	return os.ReadFile(s.InventoryPath())
}

func (s *StorageService) CRLPath() string {
	return filepath.Join(s.baseDir, "ca_crl.pem")
}

func (s *StorageService) UpdateCRL(pemData []byte) error {
	s.crlMu.Lock()
	defer s.crlMu.Unlock()
	return os.WriteFile(s.CRLPath(), pemData, FilePermPublic)
}

func (s *StorageService) GetCRL() ([]byte, error) {
	s.crlMu.RLock()
	defer s.crlMu.RUnlock()
	return os.ReadFile(s.CRLPath())
}

func (s *StorageService) CADir() string {
	return s.baseDir
}

func (s *StorageService) CAKeyPath() string {
	return filepath.Join(s.baseDir, "private", "ca_key.pem")
}

func (s *StorageService) CACertPath() string {
	return filepath.Join(s.baseDir, "ca_crt.pem")
}

func (s *StorageService) CAPubKeyPath() string {
	return filepath.Join(s.baseDir, "ca_pub.pem")
}

// Helpers for paths — subject is pre-validated as ^[a-z0-9._-]+$ by the CA layer.
func (s *StorageService) reqPath(subject string) string {
	return filepath.Join(s.baseDir, "requests", subject+".pem")
}

func (s *StorageService) signedPath(subject string) string {
	return filepath.Join(s.baseDir, "signed", subject+".pem")
}

// CSRDir returns the directory where pending CSRs are stored.
func (s *StorageService) CSRDir() string {
	return filepath.Join(s.baseDir, "requests")
}

// SignedDir returns the directory where signed certificates are stored.
func (s *StorageService) SignedDir() string {
	return filepath.Join(s.baseDir, "signed")
}

func (s *StorageService) SaveCSR(subject string, pemData []byte) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	return os.WriteFile(s.reqPath(subject), pemData, FilePermPublic)
}

func (s *StorageService) GetCSR(subject string) ([]byte, error) {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	return os.ReadFile(s.reqPath(subject))
}

func (s *StorageService) SaveCert(subject string, pemData []byte) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	return os.WriteFile(s.signedPath(subject), pemData, FilePermPublic)
}

func (s *StorageService) GetCert(subject string) ([]byte, error) {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	return os.ReadFile(s.signedPath(subject))
}

func (s *StorageService) DeleteCSR(subject string) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	return os.Remove(s.reqPath(subject))
}

func (s *StorageService) DeleteCert(subject string) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	return os.Remove(s.signedPath(subject))
}

// HasCert reports whether a signed certificate exists for subject.
func (s *StorageService) HasCert(subject string) bool {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	_, err := os.Stat(s.signedPath(subject))
	return err == nil
}

// HasCSR reports whether a pending CSR exists for subject.
func (s *StorageService) HasCSR(subject string) bool {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	_, err := os.Stat(s.reqPath(subject))
	return err == nil
}

func (s *StorageService) InventoryPath() string {
	return filepath.Join(s.baseDir, "inventory.txt")
}

func (s *StorageService) SerialPath() string {
	return filepath.Join(s.baseDir, "serial")
}

func (s *StorageService) PrivateKeyPath(subject string) string {
	return filepath.Join(s.baseDir, "private", subject+"_key.pem")
}

func (s *StorageService) SavePrivateKey(subject string, pemData []byte) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	return os.WriteFile(s.PrivateKeyPath(subject), pemData, FilePermPrivate)
}

// ListCSRs returns the subject names of all pending certificate requests.
func (s *StorageService) ListCSRs() ([]string, error) {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	return listSubjectsInDir(s.CSRDir())
}

// ListCerts returns the subject names of all signed certificates.
func (s *StorageService) ListCerts() ([]string, error) {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	return listSubjectsInDir(s.SignedDir())
}

func listSubjectsInDir(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	subjects := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".pem" {
			continue
		}
		subjects = append(subjects, strings.TrimSuffix(e.Name(), ".pem"))
	}
	return subjects, nil
}
