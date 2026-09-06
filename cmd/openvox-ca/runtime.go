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
	"fmt"
	"io"
	"path/filepath"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// caRuntime is the storage and key-provider pair described by a resolved
// server configuration: everything an operation needs to reach this CA's
// material, short of running an HTTP listener.
//
// It exists so that offline subcommands reach the configured backend and key
// provider through exactly the same code the server uses. The alternative —
// each subcommand assembling its own storage and provider — is how a CLI ends
// up quietly supporting a different subset of backends from the daemon, which
// is the failure mode openvox-ca-ctl already has (it can only ever address a
// local filesystem directory).
type caRuntime struct {
	// Store is the storage service for the configured backend.
	Store *storage.StorageService
	// KeyProvider is non-nil only when ca_key_provider names one. A nil
	// provider means the CA key is a local PEM blob reached through Store.
	KeyProvider ca.KeyProvider

	closers []func() error
}

// Close releases everything resolveRuntime opened, in reverse order. Safe to
// call on a partially-constructed runtime.
func (r *caRuntime) Close() error {
	var firstErr error
	for i := len(r.closers) - 1; i >= 0; i-- {
		if err := r.closers[i](); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// runtimeResolver resolves the storage and key provider a subcommand operates
// on. Subcommands take one rather than calling resolveRuntime directly so a
// test can substitute a provider that fails as only a real backend would.
type runtimeResolver func(ctx context.Context, cfg *serverConfig) (*caRuntime, error)

// resolveRuntime builds the storage service and, when one is configured, the CA
// key provider, from an already-resolved server configuration.
//
// Configuration *loading* is deliberately not part of this: the server and each
// subcommand expose different flag sets, so they resolve cfg themselves and
// hand the result here. What this owns is the part that must not vary —
// backend-spec construction and provider wiring.
//
// withKeyProvider is explicit at every call site rather than inferred, because
// the distinction is security-relevant: the frontend role must not reach the CA
// key, and a caller that silently got a provider it should not have would open
// an authenticated session to the key backend without anything failing.
//
// The caller must Close the returned runtime.
func resolveRuntime(ctx context.Context, cfg *serverConfig, withKeyProvider bool) (*caRuntime, error) {
	if cfg.CADir == "" {
		return nil, fmt.Errorf("cadir is required (set --cadir, PUPPET_CA_CADIR, or cadir in the config file)")
	}
	absCADir, err := filepath.Abs(cfg.CADir)
	if err != nil {
		return nil, fmt.Errorf("resolving cadir: %w", err)
	}

	if err := cfg.CAKeyProviderConfig.Validate(); err != nil {
		return nil, err
	}

	rt := &caRuntime{}

	backendSpec, err := buildBackendSpec(cfg, absCADir)
	if err != nil {
		return nil, fmt.Errorf("invalid storage backend config: %w", err)
	}
	store, err := storage.NewServiceFromSpec(backendSpec)
	if err != nil {
		return nil, fmt.Errorf("failed to initialise storage backend: %w", err)
	}
	rt.Store = store
	rt.closers = append(rt.closers, store.Backend().Close)

	if withKeyProvider && cfg.UsesOpenBao() {
		tm, provider, err := newOpenBaoKeyProvider(ctx, cfg)
		if err != nil {
			_ = rt.Close()
			return nil, fmt.Errorf("initialising OpenBao key provider: %w", err)
		}
		rt.KeyProvider = provider
		rt.closers = append(rt.closers, tm.Close)
	}

	return rt, nil
}

// lockStoreInstance takes the store-wide lock permitting one running instance,
// opening the configured store for no other purpose and closing it again at
// once.
//
// Used by the two entry points that have no runtime of their own to hang the
// lock on: the launcher, which forks children that open the store themselves,
// and the single-process server, which opens it moments later. Closing the
// store here is deliberate and safe — the lock is an flock(2) on a descriptor
// the Unlocker owns outright, so it outlives the backend handle that led us to
// it. That is what keeps a cluster backend from carrying a connection it has no
// use for: the probe dials, answers "distributed", and everything opened for it
// is released before the server proper starts.
//
// The caller must Unlock for as long as it intends to be the running instance.
func lockStoreInstance(ctx context.Context, cfg *serverConfig) (storage.Unlocker, error) {
	rt, err := resolveRuntime(ctx, cfg, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rt.Close() }()
	return rt.Store.AcquireInstanceLock(ctx)
}

// preflightInstanceLock reports whether another instance already holds the
// store, without keeping the lock.
//
// For the one caller that is about to hand startup to a process whose
// diagnostics nobody will read: `--daemon` discards the child's stderr, so a
// refusal raised there reaches no one. Taking the lock and immediately
// releasing it answers the question while there is still somewhere to print the
// answer. It is a check, not a guarantee -- the child takes the real lock, and
// the gap between the two belongs to whoever wants it.
func preflightInstanceLock(ctx context.Context, cfg *serverConfig) error {
	ul, err := lockStoreInstance(ctx, cfg)
	if err != nil {
		return err
	}
	return ul.Unlock()
}

// holdInstanceLock takes the store's instance lock and ties its release to rt,
// for callers that already hold a runtime.
//
// The release is inserted at the front of the closer list rather than appended,
// because Close runs closers in reverse and the lock must outlive the backend
// handle it protects. Why that ordering matters, and why openvox-ca-ctl reaches
// it by a different route, is stated once on StorageService.AcquireInstanceLock.
//
// enforced reports whether the lock actually excludes a second instance.
// AcquireInstanceLock returns a working no-op — nil error, usable Unlocker —
// on every backend it has nothing to enforce for: one that coordinates across
// hosts (many replicas are expected), one offering no store-wide lock at all,
// and one whose lock set is unavailable.
//
// Three of the four callers discard it today, and the reason differs per
// caller rather than following a rule: csr and import-ca-cert displace a writer
// rather than compute over a snapshot, so a lost race is a conflict they would
// notice; generate has the same snapshot exposure the rebuild does — its own
// pre-flight says a concurrent append can leave an HMAC covering a blob that
// never existed — but warns rather than refusing, and changing that is out of
// scope for #188. Only rebuild-inventory-hmac acts on the answer. A fifth
// caller should decide deliberately rather than copy whichever neighbour it
// read first.
func holdInstanceLock(ctx context.Context, rt *caRuntime, opts ...storage.InstanceLockOption) (enforced bool, err error) {
	ul, err := rt.Store.AcquireInstanceLock(ctx, opts...)
	if err != nil {
		return false, err
	}
	rt.closers = append([]func() error{ul.Unlock}, rt.closers...)
	return storage.LockIsEnforced(ul), nil
}

// resolveRuntimeForRole resolves the runtime a process running as role should
// operate on, deciding key-provider access from the role itself.
//
// The composition lives here rather than inline at the server's single call
// site so it can be driven directly by a test. The security property is not
// resolveRuntime honouring its boolean, nor roleMayReachCAKey's mapping — both
// are covered on their own — but that the two are wired together the right way
// round. An inverted or hardcoded argument would pass every test of the parts
// while handing the frontend an authenticated session to the key backend.
func resolveRuntimeForRole(ctx context.Context, cfg *serverConfig, role string) (*caRuntime, error) {
	return resolveRuntime(ctx, cfg, roleMayReachCAKey(role))
}

// roleMayReachCAKey reports whether a process running as role is permitted to
// construct a CA key provider of its own.
//
// Only the frontend is not. It proxies every signature to the isolated signer
// process, so opening its own authenticated session to the key backend would
// give it reach over a key it is specifically not allowed to use. Every other
// role — the signer, and the empty single-process role — needs the key.
//
// A named function rather than an inline `role != "frontend"` so the predicate
// can be tested directly. The half that can regress is the mapping, not
// resolveRuntime's handling of the boolean, and an inverted or mistyped
// comparison at the call site would silently hand the frontend the key.
func roleMayReachCAKey(role string) bool {
	return role != "frontend"
}

// reportResolvedConfig prints the configuration the offline subcommands actually
// resolved, before they act on it.
//
// These subcommands read the config file and PUPPET_CA_* environment, and
// nothing else: the server's storage and key-provider flags are local to the
// root command, so a server configured entirely by flags — as the shipped
// container image's own CMD is, and as the systemd examples are — is invisible
// here. The failure is silent and expensive rather than loud: `csr --create-key`
// would resolve ca_key_provider: file, mint a *local* CA key, and emit a request
// bound to a key the Transit-backed server will never use, so the parent signs
// the wrong key. Naming what was resolved is what makes that visible while it is
// still cheap to fix.
func reportResolvedConfig(w io.Writer, resolvedFile string, cfg *serverConfig) {
	from := resolvedFile
	if from == "" {
		from = "none found (defaults, plus any PUPPET_CA_* environment)"
	}
	provider := cfg.CAKeyProvider
	if provider == "" {
		provider = "file"
	}
	backend := cfg.StorageBackend
	if backend == "" {
		backend = "filesystem"
	}
	_, _ = fmt.Fprintf(w, "Using config file: %s\n", from)
	_, _ = fmt.Fprintf(w, "Storage backend: %s; CA key provider: %s; cadir: %s\n",
		backend, provider, cfg.CADir)
}
