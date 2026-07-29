// Copyright (C) 2026 Chris Boot
// Copyright (C) 2026 Trevor Vaughan
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

package storage

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// File permissions used by the filesystem backend. Exposed because callers
// that still reach directly into the filesystem (tests, migration helpers)
// need to match them.
const (
	FilePermPrivate = 0600
	FilePermPublic  = 0644
	DirPerm         = 0750
)

// fsLayout maps logical keys to paths relative to the backend's baseDir.
// Keys of the form "csr/<subject>" and "cert/<subject>" are handled
// explicitly in pathFor.
var fsLayout = map[string]string{
	KeyCACert:        "ca_crt.pem",
	KeyCAPubKey:      "ca_pub.pem",
	KeyCAKey:         "private/ca_key.pem",
	KeyCRL:           "ca_crl.pem",
	KeySerial:        "serial",
	KeyInventory:     "inventory.txt",
	KeyInventoryHMAC: ".inventory.hmac",
	KeyHMACKey:       "private/.inventory_hmac_key",

	KeyServingCert:       "serving_cert.pem",
	KeyServingKey:        "private/serving_key.pem",
	KeyServingSuperseded: "serving_superseded.json",
}

// FilesystemBackend stores blobs as files under a single base directory.
// It is the default Backend implementation and preserves the exact on-disk
// layout used by earlier versions of openvox-ca.
type FilesystemBackend struct {
	baseDir  string
	appendMu sync.Mutex // serialises AppendLine across the backend
}

// NewFilesystemBackend constructs a FilesystemBackend rooted at baseDir.
func NewFilesystemBackend(baseDir string) *FilesystemBackend {
	return &FilesystemBackend{baseDir: baseDir}
}

// BaseDir returns the filesystem root.
func (b *FilesystemBackend) BaseDir() string { return b.baseDir }

// Path returns the filesystem path for key, or empty if key is unknown.
// Used for diagnostic messages and by StorageService's legacy *Path methods.
func (b *FilesystemBackend) Path(key string) string {
	p, err := b.pathFor(key)
	if err != nil {
		return ""
	}
	return p
}

func (b *FilesystemBackend) pathFor(key string) (string, error) {
	if err := validateKey(key); err != nil {
		return "", err
	}
	if rel, ok := fsLayout[key]; ok {
		return filepath.Join(b.baseDir, rel), nil
	}
	switch {
	case strings.HasPrefix(key, csrPrefix):
		subj := strings.TrimPrefix(key, csrPrefix)
		return filepath.Join(b.baseDir, "requests", subj+".pem"), nil
	case strings.HasPrefix(key, certPrefix):
		subj := strings.TrimPrefix(key, certPrefix)
		return filepath.Join(b.baseDir, "signed", subj+".pem"), nil
	}
	return "", fmt.Errorf("unknown key %q", key)
}

// The filesystem backend's syscalls cannot be interrupted mid-flight, so
// ctx is honoured only at the start of each operation. ctxErr returns the
// caller's cancellation error if ctx is already done; otherwise nil.
func ctxErr(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func (b *FilesystemBackend) EnsureReady(ctx context.Context) error {
	if err := ctxErr(ctx); err != nil {
		return err
	}
	for _, d := range []string{
		b.baseDir,
		filepath.Join(b.baseDir, "signed"),
		filepath.Join(b.baseDir, "requests"),
		filepath.Join(b.baseDir, "private"),
	} {
		if err := os.MkdirAll(d, DirPerm); err != nil {
			return err
		}
	}
	return nil
}

func (b *FilesystemBackend) Get(ctx context.Context, key string) ([]byte, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	p, err := b.pathFor(key)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(p)
}

func (b *FilesystemBackend) Put(ctx context.Context, key string, data []byte, kind BlobKind) error {
	if err := ctxErr(ctx); err != nil {
		return err
	}
	p, err := b.pathFor(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), DirPerm); err != nil {
		return err
	}
	return atomicWriteFile(p, data, permFor(kind))
}

func (b *FilesystemBackend) Delete(ctx context.Context, key string) error {
	if err := ctxErr(ctx); err != nil {
		return err
	}
	p, err := b.pathFor(key)
	if err != nil {
		return err
	}
	return os.Remove(p)
}

func (b *FilesystemBackend) Exists(ctx context.Context, key string) (bool, error) {
	if err := ctxErr(ctx); err != nil {
		return false, err
	}
	p, err := b.pathFor(key)
	if err != nil {
		return false, err
	}
	_, err = os.Stat(p)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func (b *FilesystemBackend) List(ctx context.Context, prefix string) ([]string, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	var dir, outPrefix string
	switch prefix {
	case csrPrefix:
		dir = filepath.Join(b.baseDir, "requests")
		outPrefix = csrPrefix
	case certPrefix:
		dir = filepath.Join(b.baseDir, "signed")
		outPrefix = certPrefix
	default:
		return nil, fmt.Errorf("unsupported list prefix %q", prefix)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return []string{}, nil
		}
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".pem" {
			continue
		}
		out = append(out, outPrefix+strings.TrimSuffix(e.Name(), ".pem"))
	}
	return out, nil
}

func (b *FilesystemBackend) AppendLine(ctx context.Context, key string, data []byte, kind BlobKind) error {
	if err := ctxErr(ctx); err != nil {
		return err
	}
	b.appendMu.Lock()
	defer b.appendMu.Unlock()
	p, err := b.pathFor(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), DirPerm); err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, permFor(kind))
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	// Flush the appended bytes to stable storage so a crash cannot lose a
	// just-written inventory or CRL line.
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func (b *FilesystemBackend) ModTime(ctx context.Context, key string) (time.Time, error) {
	if err := ctxErr(ctx); err != nil {
		return time.Time{}, err
	}
	p, err := b.pathFor(key)
	if err != nil {
		return time.Time{}, err
	}
	info, err := os.Stat(p)
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

func (b *FilesystemBackend) Close() error { return nil }

func permFor(kind BlobKind) os.FileMode {
	if kind == BlobPrivate {
		return FilePermPrivate
	}
	return FilePermPublic
}

// atomicWriteFile writes data to a temporary file in the same directory as
// target, then renames it into place. This prevents partial writes from
// leaving a corrupt file on disk (e.g. during a crash or power loss).
func atomicWriteFile(target string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	// Flush the data to stable storage before the rename. Without this the
	// rename can be reordered ahead of the data on a crash, leaving a
	// zero-length or stale file in place of a CA key, cert, or CRL.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("syncing temp file %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, target); err != nil {
		return err
	}
	// fsync the parent directory so the rename itself survives a crash. The
	// data is already on disk and renamed, so a failure here is best-effort.
	if dirF, err := os.Open(dir); err != nil {
		slog.Warn("Failed to open parent directory for fsync after rename", "dir", dir, "error", err)
	} else {
		if err := dirF.Sync(); err != nil {
			slog.Warn("Failed to fsync parent directory after rename", "dir", dir, "error", err)
		}
		_ = dirF.Close()
	}
	return nil
}
