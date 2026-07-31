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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/k8sexport"
)

// runK8sExporter publishes the CA certificate, CRL and serving material into
// the configured Kubernetes Secrets/ConfigMaps. It exports once at startup
// (reconciling state after restarts, config changes, or a CA import) and then
// re-exports on either wake-up signal: a CRL update (revoke, reissue,
// background refresh, or expired-cert cleanup), or a serving-certificate
// rotation.
//
// Both signals are needed. A serving-certificate rotation does not touch the
// CRL, so waiting only on CRLUpdated would leave a rotated certificate
// unexported until the periodic reconcile below came round. What the signal buys
// is promptness — the Secret follows the rotation within a cycle rather than
// within a reconcile interval — not rescue from an unbounded stall, which is
// what the floor is for. Earlier versions of this comment claimed "months" and
// then "~24 hours / ~20 days"; both predate the floor.
//
// It runs in the frontend process, reading the cert/CRL through the storage
// service. Export failures are logged and swallowed: the export is auxiliary
// and must never take down the CA. It returns when ctx is cancelled. Retries are
// on a fixed interval, not a backoff -- see exportRetryInterval.
//
// The timer is always armed, at one of two intervals, because both wake-ups are
// edge-triggered and neither covers everything:
//
//   - after a failure, exportRetryInterval, so a target that failed once is not
//     stale until something unrelated moves the CRL;
//   - after a success, exportResyncInterval, because a *successful* apply can
//     still have published stale material. servingNotify is per-process, so a
//     replica that did not mint never learns of a rotation until its own hourly
//     maintenance pass refreshes its holder — and any CRL event in that window
//     has it republish its old pair over the correct one, successfully, with
//     nothing to alert on. Server-side apply makes the extra cycles idempotent.
func runK8sExporter(ctx context.Context, c *ca.CA, exporter *k8sexport.Exporter, resync time.Duration) {
	slog.Info("Starting Kubernetes export job")

	retry := time.NewTimer(exportRetryInterval)
	defer retry.Stop()
	stopTimer(retry)
	retry.Reset(nextExportInterval(exportK8sOnce(ctx, exporter), resync))

	for {
		var reason string
		select {
		case <-ctx.Done():
			slog.Debug("Kubernetes export job stopping")
			return
		case <-c.CRLUpdated():
			reason = "CRL updated"
		case <-c.ServingCertUpdated():
			reason = "serving certificate rotated"
		case <-retry.C:
			reason = "periodic reconcile"
		}

		slog.Debug("Re-exporting to Kubernetes", "reason", reason)
		stopTimer(retry)
		retry.Reset(nextExportInterval(exportK8sOnce(ctx, exporter), resync))
	}
}

// nextExportInterval picks how long to wait before the next unprompted cycle.
func nextExportInterval(ok bool, resync time.Duration) time.Duration {
	if ok {
		return resync
	}
	return exportRetryInterval
}

// exportRetryInterval is how long to wait before retrying a cycle that had
// failures. Comfortably inside the alert's 15-minute debounce, so a transient
// failure is corrected before it pages.
//
// A fixed interval rather than a backoff: the failures this sees are API-server
// or RBAC problems that an operator fixes, the work is one apply per target, and
// a predictable retry is easier to reason about against that debounce. Both are
// vars rather than consts so a spec can shorten them.
var exportRetryInterval = 2 * time.Minute

// exportResyncInterval is the floor for cycles that had no failures — the
// periodic reconcile every controller needs, since an apply can succeed while
// publishing material this replica has not yet caught up with.
//
// Ten minutes suits cert and CRL material, where every replica reads the same
// storage and a resync only repairs drift. It is the wrong figure on its own for
// serving material: a replica that did not mint holds the previous pair until
// its own maintenance pass, so resyncing more often than that interval does not
// converge any sooner and simply republishes the stale pair more times. See
// servingResyncInterval.
var exportResyncInterval = 10 * time.Minute

// servingResyncInterval is the floor to use when a target publishes serving
// material, given how often this process refreshes its own holder.
//
// Convergence is gated by the maintenance interval, not by the resync, so
// resyncing faster than that buys nothing and costs one stale republish per
// cycle -- which a Gateway or Ingress watching the Secret hot-reloads on.
func servingResyncInterval(maintenance time.Duration) time.Duration {
	if maintenance > exportResyncInterval {
		return maintenance
	}
	return exportResyncInterval
}

// stopTimer drains t so a later Reset cannot fire immediately on a stale value.
func stopTimer(t *time.Timer) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
}

// exportK8sOnce runs a single reconcile, logging the outcome and reporting
// whether it fully succeeded. Per-target errors are already logged by ExportAll;
// here we log only that the cycle had failures.
func exportK8sOnce(ctx context.Context, exporter *k8sexport.Exporter) bool {
	if err := exporter.ExportAll(ctx); err != nil {
		slog.Warn("Kubernetes export cycle completed with errors", "error", err)
		return false
	}
	slog.Debug("Kubernetes export cycle complete")
	return true
}

// validateServingExport refuses a serving export that can never succeed.
//
// serving_cert and serving_key come from the holder the listener presents, and
// that holder is only ever populated under tls_self_provision. Without it every
// cycle fails for the life of the process — and, worse, quietly leaves whatever
// was last published in place: a plaintext CA-chained private key sitting in a
// Secret that nothing will now refresh or remove.
//
// Refused at startup rather than reported per cycle, matching validateTLS: the
// operator has asked for something the configuration cannot deliver, and the
// remedy is a config change, not a retry.
func validateServingExport(cfg *serverConfig) error {
	if cfg.TLSSelfProvision || !cfg.KubernetesExport.WantsServingMaterial() {
		return nil
	}
	return fmt.Errorf("a kubernetes_export target requests serving_cert or serving_key, but " +
		"tls_self_provision is off: the serving certificate and key only exist when the CA " +
		"issues them itself, so every export cycle would fail. Enable tls_self_provision, or " +
		"remove the serving material from the target -- and delete the Secret it was publishing " +
		"to, which still holds the key in plaintext")
}

// servingExportWarnings returns what an operator should be told at startup about
// a serving export, or nothing when none is configured.
//
// Split out of the serve command so a spec can reach it, and gated on
// tls_self_provision so it cannot warn about publishing a key that this
// configuration never publishes.
func servingExportWarnings(cfg *serverConfig) []string {
	if !cfg.TLSSelfProvision || !cfg.KubernetesExport.WantsServingKey() {
		return nil
	}
	// SECURITY: the exported key is always plaintext, because a
	// kubernetes.io/tls Secret holding an encrypted PEM is useless to every
	// consumer of one. Say so plainly: with tls_self_provision_encrypt_key on,
	// the operator has asked for encryption at rest and is nonetheless
	// publishing the key in the clear to etcd.
	return []string{
		"A kubernetes_export target publishes the serving private key. " +
			"It is written to the Secret in plaintext even when " +
			"tls_self_provision_encrypt_key is set, because TLS consumers cannot use " +
			"an encrypted key. Restrict who can read that Secret.",
	}
}

// attachServingSource points the exporter at the holder the listener presents,
// when there is one to point at.
//
// Separated from the serve command so that "the exporter reads the same pair the
// listener serves" is a proposition a spec can check: inline, pointing it at a
// different or empty holder compiled and passed.
func attachServingSource(e *k8sexport.Exporter, cfg *serverConfig, holder *servingCertHolder, c *ca.CA) *k8sexport.Exporter {
	if !cfg.TLSSelfProvision {
		return e
	}
	return e.WithServingSource(revocationFenced{inner: holder, ca: c})
}

// revocationFenced refuses to publish a serving pair the CA has revoked.
//
// A replica that did not mint holds the previous pair until its own maintenance
// pass, and the periodic reconcile republishes whatever it holds. That is
// merely stale for an ordinary rotation, but it is a live exposure for the
// documented remedy after a key compromise: the operator revokes, one replica
// re-mints, and every other replica goes on writing the compromised pair back
// into the Secret until it catches up.
//
// Revocation is shared state that every replica agrees about, so it is the one
// freshness signal available here without a storage read per cycle. Refusing
// turns "quietly republishes a revoked key" into a failed target, which records
// an error and fires the export alert.
type revocationFenced struct {
	inner k8sexport.ServingSource
	ca    *ca.CA
}

func (f revocationFenced) ServingMaterial(ctx context.Context) (certPEM, keyPEM []byte, err error) {
	certPEM, keyPEM, err = f.inner.ServingMaterial(ctx)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("the serving certificate to export is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing the serving certificate to export: %w", err)
	}
	revoked, err := f.ca.IsRevokedSerial(ctx, leaf.SerialNumber)
	if err != nil {
		return nil, nil, fmt.Errorf("checking whether the serving certificate is revoked: %w", err)
	}
	if revoked {
		return nil, nil, fmt.Errorf("refusing to publish serving certificate %s: it is revoked, so this "+
			"replica has not yet picked up the replacement", leaf.SerialNumber.Text(16))
	}
	return certPEM, keyPEM, nil
}

// fatalExportStartupError reports which constructor failures must stop startup.
//
// The two kinds are handled oppositely and the distinction is easy to lose: a
// client that will not initialise is environmental and the CA carries on
// serving without export, but a configuration mistake belongs with every other
// one, at startup. Routing both to a log line disabled the export for the life
// of the process while writing no metric series at all -- so the alert that owns
// it could not fire, and the only trace was one boot line blaming the client.
//
// Split out of the serve command because RunE cannot be reached from a spec,
// and this is the decision worth pinning rather than the plumbing around it.
func fatalExportStartupError(err error) error {
	if errors.Is(err, k8sexport.ErrInvalidConfig) {
		return err
	}
	return nil
}
