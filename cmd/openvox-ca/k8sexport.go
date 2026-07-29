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
// unexported until the next revocation — potentially months.
//
// It runs in the frontend process, reading the cert/CRL through the storage
// service. Export failures are logged and swallowed: the export is auxiliary
// and must never take down the CA. A subsequent CRL update — or a restart —
// retries. It returns when ctx is cancelled (i.e. on shutdown).
func runK8sExporter(ctx context.Context, c *ca.CA, exporter *k8sexport.Exporter) {
	slog.Info("Starting Kubernetes export job")

	exportK8sOnce(ctx, exporter)

	for {
		select {
		case <-ctx.Done():
			slog.Debug("Kubernetes export job stopping")
			return
		case <-c.CRLUpdated():
			slog.Debug("CRL updated, re-exporting to Kubernetes")
			exportK8sOnce(ctx, exporter)
		case <-c.ServingCertUpdated():
			slog.Debug("Serving certificate rotated, re-exporting to Kubernetes")
			exportK8sOnce(ctx, exporter)
		}
	}
}

// exportK8sOnce runs a single reconcile, logging the outcome. Per-target errors
// are already logged by ExportAll; here we log only that the cycle had failures.
func exportK8sOnce(ctx context.Context, exporter *k8sexport.Exporter) {
	if err := exporter.ExportAll(ctx); err != nil {
		slog.Warn("Kubernetes export cycle completed with errors", "error", err)
		return
	}
	slog.Debug("Kubernetes export cycle complete")
}
