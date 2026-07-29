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
	"crypto/tls"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/ca"
)

// servingCertHolder owns the certificate the TLS stack presents, and swaps it
// atomically when the CA issues a replacement.
//
// tls.Config.GetCertificate is consulted per handshake, so a swap takes effect
// on the next connection with no restart and no listener churn. Established
// connections keep the certificate they negotiated with, which is why revoking
// a superseded certificate has to be delayed rather than immediate.
type servingCertHolder struct {
	current atomic.Pointer[tls.Certificate]
}

// Set installs cert as the certificate served from the next handshake onward.
func (h *servingCertHolder) Set(cert *tls.Certificate) {
	h.current.Store(cert)
}

// GetCertificate satisfies tls.Config.GetCertificate.
func (h *servingCertHolder) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := h.current.Load()
	if cert == nil {
		// Unreachable in practice: ensureServingCert runs to completion before
		// the listener is constructed, and a failure there is fatal. Returning
		// an error rather than nil, nil because nil, nil makes crypto/tls
		// report a confusing internal error to the client.
		return nil, fmt.Errorf("no serving certificate available")
	}
	return cert, nil
}

// servingConfigFrom derives the CA-layer serving configuration from the server
// configuration.
func servingConfigFrom(cfg *serverConfig) ca.ServingConfig {
	return ca.ServingConfig{
		Subject:     cfg.Hostname,
		ExtraNames:  cfg.TLSSelfProvisionNames,
		RenewBefore: time.Duration(cfg.TLSSelfProvisionRenewBeforeSec) * time.Second,
		EncryptKey:  cfg.TLSSelfProvisionEncryptKey,
		RevokeAfter: cfg.servingRevokeAfter(),
	}
}

// toTLSCertificate assembles a tls.Certificate from issued material.
func toTLSCertificate(sc *ca.ServingCertificate) (*tls.Certificate, error) {
	pair, err := tls.X509KeyPair(sc.CertPEM, sc.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("assembling serving certificate for TLS: %w", err)
	}
	pair.Leaf = sc.Leaf
	return &pair, nil
}

// ensureServingCert resolves the serving certificate and installs it in holder.
//
// At startup a failure here is fatal: a server with no serving certificate
// cannot serve, and failing fast beats a listener that never comes up. On the
// maintenance cycle it is not — see runMaintenance.
func ensureServingCert(ctx context.Context, myCA *ca.CA, cfg *serverConfig, holder *servingCertHolder) error {
	sc, err := myCA.EnsureServingCert(ctx, servingConfigFrom(cfg))
	if err != nil {
		return fmt.Errorf("resolving serving certificate: %w", err)
	}
	pair, err := toTLSCertificate(sc)
	if err != nil {
		return err
	}
	holder.Set(pair)
	if sc.Issued {
		slog.Info("Serving certificate issued",
			"subject", sc.Leaf.Subject.CommonName,
			"serial", sc.Leaf.SerialNumber.Text(16),
			"not_after", sc.Leaf.NotAfter.Format(time.RFC3339),
			"dns_names", sc.Leaf.DNSNames)
	} else {
		slog.Info("Serving certificate loaded",
			"subject", sc.Leaf.Subject.CommonName,
			"serial", sc.Leaf.SerialNumber.Text(16),
			"not_after", sc.Leaf.NotAfter.Format(time.RFC3339))
	}
	return nil
}
