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
// unexported until something else moved the CRL. How long that is depends on
// configuration and is worth stating accurately rather than dramatically: with
// the default tls_self_provision_revoke_after_sec, the rotation itself produces
// a CRL update roughly a day later, so the fallback is ~24 hours. With
// revocation disabled it is the CRL refresh interval — about 20 days on a
// low-churn CA. Neither is "months", which is what the design said and what an
// earlier version of this comment repeated.
//
// It runs in the frontend process, reading the cert/CRL through the storage
// service. Export failures are logged and swallowed: the export is auxiliary
// and must never take down the CA. A failed cycle is retried on a bounded
// backoff rather than waiting for the next wake-up, because the wake-ups are
// edge-triggered: without a retry, a target that failed once stays stale until
// something unrelated moves the CRL. It returns when ctx is cancelled.
func runK8sExporter(ctx context.Context, c *ca.CA, exporter *k8sexport.Exporter) {
	slog.Info("Starting Kubernetes export job")

	retry := time.NewTimer(exportRetryInterval)
	defer retry.Stop()
	if !exportK8sOnce(ctx, exporter) {
		retry.Reset(exportRetryInterval)
	} else {
		stopTimer(retry)
	}

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
			reason = "retrying a failed export"
		}

		slog.Debug("Re-exporting to Kubernetes", "reason", reason)
		stopTimer(retry)
		if !exportK8sOnce(ctx, exporter) {
			// Both wake-ups are edge-triggered, so without this a target that
			// failed once stays stale until something unrelated moves the CRL.
			// A fixed interval rather than a backoff: the failures this sees are
			// API-server or RBAC problems that an operator fixes, the work is
			// one apply per target, and a predictable retry is easier to reason
			// about against the alert's own debounce.
			retry.Reset(exportRetryInterval)
		}
	}
}

// exportRetryInterval is how long to wait before retrying a cycle that had
// failures. Comfortably inside the alert's 15-minute debounce, so a transient
// failure is corrected before it pages.
const exportRetryInterval = 2 * time.Minute

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
