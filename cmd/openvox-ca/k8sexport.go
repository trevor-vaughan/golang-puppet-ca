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
	"github.com/voxpupuli/openvox-ca/internal/storage"
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
//   - after a success, exportResyncInterval, so an object edited or deleted out
//     from under the exporter is repaired. Server-side apply makes an unchanged
//     re-apply a genuine no-op, so the extra cycles cost nothing.
func runK8sExporter(ctx context.Context, c *ca.CA, exporter *k8sexport.Exporter) {
	slog.Info("Starting Kubernetes export job")

	retry := time.NewTimer(exportRetryInterval)
	defer retry.Stop()
	stopTimer(retry)
	retry.Reset(nextExportInterval(exportK8sOnce(ctx, exporter)))

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
		retry.Reset(nextExportInterval(exportK8sOnce(ctx, exporter)))
	}
}

// nextExportInterval picks how long to wait before the next unprompted cycle.
func nextExportInterval(ok bool) time.Duration {
	if ok {
		return exportResyncInterval
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
// periodic reconcile every controller needs.
//
// It repairs drift -- an object edited or deleted out from under the exporter,
// and a Secret left holding the pair a lost cross-replica apply race put there.
// A replica that is behind publishes nothing at all, so this interval no longer
// has to be reasoned about against the maintenance interval.
//
// docs/kubernetes-export.md and docs/metrics.md both state this figure; a spec
// pins it, because it has been wrong three times.
var exportResyncInterval = 10 * time.Minute

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
func attachServingSource(e *k8sexport.Exporter, cfg *serverConfig, holder *servingCertHolder, store *storage.StorageService) *k8sexport.Exporter {
	if !cfg.TLSSelfProvision {
		return e
	}
	return e.WithServingSource(currentOnly{inner: holder, store: store})
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

// stopTimer drains t so a later Reset cannot fire immediately on a stale value.
func stopTimer(t *time.Timer) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
}

// currentOnly refuses to publish a serving pair this replica knows is not the
// current one.
//
// Freshness cannot be answered from anything a single replica holds. Only the
// replica that minted has the new pair; the others carry the previous one until
// their own maintenance pass, and a periodic reconcile would otherwise write it
// back over the correct one -- successfully, so nothing alerts. Three earlier
// attempts bounded that with per-replica state (announcement ordering, a
// reconcile floor, a revocation check) and each was wrong for the lagging
// replica, because a replica cannot know from local state whether what it holds
// is current.
//
// So it asks storage, which is the shared referent every replica agrees about.
// The stored serving *certificate* is public material: no lock and no
// decryption, unlike reading the pair itself, and the same call storedServingLeaf
// already makes. Comparing its serial with the holder's answers the question
// exactly, and it subsumes the revocation case -- a revoked pair has been
// replaced in storage, so its serial no longer matches.
//
// A mismatch is a skip rather than a failure. It is normal, transient, and
// another replica is publishing the right bytes meanwhile.
type currentOnly struct {
	inner k8sexport.ServingSource
	store *storage.StorageService
}

func (c currentOnly) ServingMaterial(ctx context.Context) (certPEM, keyPEM []byte, err error) {
	certPEM, keyPEM, err = c.inner.ServingMaterial(ctx)
	if err != nil {
		return nil, nil, err
	}
	held, err := leafSerialOf(certPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("reading the serving certificate this replica holds: %w", err)
	}
	storedPEM, err := c.store.GetServingCert(ctx)
	if err != nil {
		// Without the backend's error text, for the reason internal/ca gives at
		// this same call: a SQL driver's connection error can carry the DSN, and
		// this reaches a Warn line every retry interval for as long as the
		// backend is unhappy.
		return nil, nil, errors.New("reading the stored serving certificate to compare against")
	}
	current, err := leafSerialOf(storedPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("reading the stored serving certificate: %w", err)
	}
	if held != current {
		return nil, nil, fmt.Errorf("%w: holding %s, storage has %s",
			k8sexport.ErrServingStale, held, current)
	}
	return certPEM, keyPEM, nil
}

// leafSerialOf returns the serial of a PEM-encoded certificate, normalised so
// two encodings of the same serial compare equal.
func leafSerialOf(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parsing: %w", err)
	}
	return leaf.SerialNumber.Text(16), nil
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
