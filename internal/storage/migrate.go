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

package storage

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
)

// migratableSingleton pairs a fixed (non-enumerable) blob key with the
// visibility it is normally written with, so the destination backend can
// reproduce the correct permissions (e.g. 0600 vs 0644 on the filesystem).
type migratableSingleton struct {
	Key  string
	Kind BlobKind
}

// migratableSingletons lists every fixed blob a CA may hold, in a stable copy
// order (CA material first, then operational state). The kinds mirror how
// StorageService writes each blob. Per-subject CSRs and signed certs are
// enumerated separately via List; per-subject generated private keys are
// intentionally excluded — they always live on local disk
// (StorageService.localPrivateKeyDir) and are never stored in a backend.
var migratableSingletons = []migratableSingleton{
	{KeyCACert, BlobPublic},
	{KeyCAPubKey, BlobPublic},
	{KeyCAKey, BlobPrivate},
	{KeyCRL, BlobPrivate},
	{KeySerial, BlobPublic},
	{KeyInventory, BlobPrivate},
	{KeyInventoryHMAC, BlobPrivate},
	{KeyHMACKey, BlobPrivate},
	{KeyServingCert, BlobPublic},
	{KeyServingKey, BlobPrivate},
	{KeyServingSuperseded, BlobPrivate},
}

// MigrateOptions tunes a Migrate run.
type MigrateOptions struct {
	// Force permits writing into a destination that already holds CA material.
	// When false, Migrate aborts with ErrDestinationNotEmpty if the destination
	// already has a CA certificate, to avoid clobbering a live CA.
	Force bool

	// Logf, when non-nil, receives one human-readable line per copied blob.
	Logf func(format string, args ...any)
}

// MigrateReport summarises what a Migrate run copied.
type MigrateReport struct {
	Singletons int // fixed CA/operational blobs copied
	CSRs       int // pending certificate requests copied
	Certs      int // signed certificates copied
}

// Total returns the total number of blobs copied.
func (r MigrateReport) Total() int { return r.Singletons + r.CSRs + r.Certs }

// ErrDestinationNotEmpty is returned by Migrate when the destination backend
// already holds a CA certificate and MigrateOptions.Force is false.
var ErrDestinationNotEmpty = errors.New("destination backend already contains a CA certificate (use --force to overwrite)")

// migrateLockName is the distributed-lock name MigrateService holds on both
// backends for the duration of a copy. It deliberately matches the CA
// bootstrap lock (internal/ca uses "bootstrap") so a migration and a server
// bootstrapping or re-initialising the same backend are mutually exclusive,
// and so two migrations cannot run against the same backend at once.
//
// Per-subject signing uses different lock names and is therefore not held off;
// operators should still stop the server during a migration. Backends without
// distributed locking fall back to a process-local mutex (no cross-process
// effect), which is why MigrateService is best-effort for those.
const migrateLockName = "bootstrap"

// MigrateService copies src to dst exactly like Migrate, but holds each
// backend's distributed lock (when the backend supports one) for the whole
// copy, guarding against a concurrent migration or a CA bootstrap racing on
// either backend. Locks are acquired source-first, then destination, and
// released in reverse on return. Backends that cannot provide a distributed
// lock fall back to a process-local mutex via StorageService.WithLock.
//
// Note: pointing both src and dst at the same distributed backend would have
// the two lock acquisitions (from separate sessions) deadlock; migrating a
// store onto itself is not a supported operation.
func MigrateService(ctx context.Context, src, dst *StorageService, opts MigrateOptions) (MigrateReport, error) {
	var report MigrateReport
	err := src.WithLock(ctx, migrateLockName, func() error {
		return dst.WithLock(ctx, migrateLockName, func() error {
			r, e := Migrate(ctx, src.Backend(), dst.Backend(), opts)
			report = r
			if e != nil {
				return e
			}
			// The destination's integrity scheme may differ from the source's
			// (a structured backend uses a hash chain, a blob backend hashes the
			// whole inventory), so the copied inventory_hmac is not meaningful
			// for the destination. Recompute it from the copied inventory.
			return dst.RebuildInventoryHMAC(ctx)
		})
	})
	return report, err
}

// Migrate copies every blob held by src into dst, preserving each blob's
// visibility (public/private). It is backend-agnostic: any pair of Backend
// implementations may be combined, enabling filesystem→database,
// database→database and database→filesystem migrations.
//
// Per-subject generated private keys are not copied: they always live on the
// local filesystem outside any backend.
//
// Migrate is not transactional. On error it returns the blobs copied so far in
// the report. Re-running is safe: copies overwrite matching keys idempotently.
func Migrate(ctx context.Context, src, dst Backend, opts MigrateOptions) (MigrateReport, error) {
	var report MigrateReport

	if err := dst.EnsureReady(ctx); err != nil {
		return report, fmt.Errorf("preparing destination: %w", err)
	}

	if !opts.Force {
		exists, err := dst.Exists(ctx, KeyCACert)
		if err != nil {
			return report, fmt.Errorf("checking destination for existing CA: %w", err)
		}
		if exists {
			return report, ErrDestinationNotEmpty
		}
	}

	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}

	// copyKey copies one blob; a key absent in the source is skipped (not an
	// error) so partially-populated CAs migrate cleanly.
	copyKey := func(key string, kind BlobKind) (bool, error) {
		data, err := src.Get(ctx, key)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return false, nil
			}
			return false, fmt.Errorf("reading %q from source: %w", key, err)
		}
		if err := dst.Put(ctx, key, data, kind); err != nil {
			return false, fmt.Errorf("writing %q to destination: %w", key, err)
		}
		logf("copied %s (%d bytes)", key, len(data))
		return true, nil
	}

	for _, s := range migratableSingletons {
		copied, err := copyKey(s.Key, s.Kind)
		if err != nil {
			return report, err
		}
		if copied {
			report.Singletons++
		}
	}

	csrKeys, err := src.List(ctx, csrPrefix)
	if err != nil {
		return report, fmt.Errorf("listing CSRs in source: %w", err)
	}
	for _, key := range csrKeys {
		copied, err := copyKey(key, BlobPublic)
		if err != nil {
			return report, err
		}
		if copied {
			report.CSRs++
		}
	}

	certKeys, err := src.List(ctx, certPrefix)
	if err != nil {
		return report, fmt.Errorf("listing signed certificates in source: %w", err)
	}
	for _, key := range certKeys {
		copied, err := copyKey(key, BlobPublic)
		if err != nil {
			return report, err
		}
		if copied {
			report.Certs++
		}
	}

	return report, nil
}
