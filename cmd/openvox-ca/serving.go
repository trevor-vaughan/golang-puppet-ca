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
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/api"
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

	// notify, when set, is called after -- never before -- the new pair is
	// reachable through current.
	//
	// It exists to make the ordering unrepresentable rather than commented. A
	// consumer woken by the announcement immediately reads this holder, so
	// announcing first publishes the certificate being replaced; that was the
	// original defect, and moving the send from the mint to the caller only
	// narrowed the window rather than closing it. Set is the one place that can
	// get this right, so it is the only place that does it.
	notify func()
}

// newServingCertHolder builds a holder that announces each installed pair.
//
// A constructor rather than a struct literal so there is one place the two are
// tied together: a holder built without its announcement is a holder whose
// rotations no consumer hears about.
func newServingCertHolder(notify func()) *servingCertHolder {
	return &servingCertHolder{notify: notify}
}

// Set installs cert as the certificate served from the next handshake onward,
// then announces it.
func (h *servingCertHolder) Set(cert *tls.Certificate) {
	h.current.Store(cert)
	if h.notify != nil {
		h.notify()
	}
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

// ServingMaterial returns the certificate and key the listener is currently
// presenting, as PEM, satisfying k8sexport.ServingSource.
//
// Served from the holder rather than from storage, and that is the whole point.
// Two storage reads can straddle a rotation and yield a certificate and a key
// from different keypairs — a kubernetes.io/tls Secret that is well-formed and
// fails every handshake made against it. The holder swaps the pair as one
// atomic pointer, so a reader gets a matched pair or nothing.
//
// It also removes the need to decrypt on the export path: the key here is the
// signer the CA already decrypted when it validated the stored material, so
// tls_self_provision_encrypt_key costs the exporter nothing.
//
// The residual window is between replicas, not inside one: two exporters can
// still order their applies against each other, so a replica that fetched
// before a rotation can land after another's corrective apply. Nothing notices
// at the time -- both applies succeed -- and the losing write is corrected by
// the next periodic reconcile, which is the only thing that repairs it. See
// currentOnly and exportResyncInterval in k8sexport.go.
func (h *servingCertHolder) ServingMaterial(context.Context) (certPEM, keyPEM []byte, err error) {
	pair := h.current.Load()
	if pair == nil || len(pair.Certificate) == 0 {
		return nil, nil, fmt.Errorf("no serving certificate available")
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]})

	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("the serving key is not a signer")
	}
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, nil, fmt.Errorf("marshalling the serving key for export: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return certPEM, keyPEM, nil
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
//
// It builds from the parsed leaf and the decrypted signer rather than from the
// stored PEM. tls.X509KeyPair would be the obvious call and is wrong here:
// crypto/tls accepts any PEM block whose type ends " PRIVATE KEY", so an
// "ENCRYPTED PRIVATE KEY" block passes its type check and then fails to parse —
// and because a serving-certificate failure at startup is fatal, enabling
// tls_self_provision_encrypt_key would stop the server booting. Worse, the
// encrypted blob is persisted before this runs, so turning the flag back off
// would not recover it.
//
// ServingCertificate.Key is the key the CA already decrypted while validating
// the stored material, so using it costs nothing and cannot disagree with the
// certificate: EnsureServingCert has checked they match.
func toTLSCertificate(sc *ca.ServingCertificate) (*tls.Certificate, error) {
	if sc.Key == nil {
		return nil, fmt.Errorf("assembling serving certificate for TLS: no private key resolved")
	}
	if sc.Leaf == nil {
		return nil, fmt.Errorf("assembling serving certificate for TLS: no certificate resolved")
	}
	return &tls.Certificate{
		Certificate: [][]byte{sc.Leaf.Raw},
		PrivateKey:  sc.Key,
		Leaf:        sc.Leaf,
	}, nil
}

// serverAuthConfig returns the mTLS authorisation configuration for the server,
// or nil when TLS is off.
//
// A nil AuthConfig disables the authorisation middleware for every route, so
// this must answer "configured" for exactly the topologies that terminate TLS
// -- including tls_self_provision, where no tls_cert/tls_key pair is set. That
// is what cfg.tlsEnabled() already decides, and routing the decision through
// here keeps it a single expression: a second condition at the call site is how
// a listener ends up on TLS with every endpoint unauthenticated.
func serverAuthConfig(cfg *serverConfig, myCA *ca.CA) (*api.AuthConfig, error) {
	if !cfg.tlsEnabled() {
		return nil, nil
	}
	return buildAuthConfig(cfg, myCA)
}

// servingMaintenanceTasks returns the background tasks tls_self_provision
// needs, and none at all when it is off.
//
// Collected here rather than appended inside the serve command so that "the
// feature is on, therefore these tasks run" is a proposition a spec can check.
// Both tasks are the feature's standing promises -- renew before expiry, revoke
// what was superseded -- and a task that is never registered never fails, so
// neither counter would signal its absence.
func servingMaintenanceTasks(myCA *ca.CA, cfg *serverConfig, holder *servingCertHolder) []maintenanceTask {
	if !cfg.TLSSelfProvision {
		return nil
	}
	return []maintenanceTask{
		servingRenewalTask(myCA, cfg, holder),
		supersededRevocationTask(myCA, cfg),
	}
}

// reconcileAtStartup drains any pending serving-certificate revocations before
// the listener opens, and deliberately without regard to whether
// tls_self_provision is on.
//
// Startup is the only moment a process reliably observes a configuration
// change, and with self-provisioning switched off no periodic task runs at all
// — so entries a previous configuration recorded would otherwise sit in storage
// indefinitely and fire much later if the delay were re-enabled. A failure is
// logged and not fatal: it is bookkeeping, and the CA can still serve.
//
// Skipped only when there is no hostname to reconcile under.
// ReconcileSuperseded rejects an empty subject, and hostname is optional
// whenever self-provisioning is off — so without this guard every such
// deployment warns on every boot about a feature it has never used, which is
// how operators learn to stop reading boot logs.
//
// Split out of the serve command rather than inlined there so a spec can reach
// it: RunE is not reachable from one, and the increment below was dead to the
// suite for exactly that reason.
func reconcileAtStartup(ctx context.Context, myCA *ca.CA, cfg *serverConfig) {
	if cfg.Hostname == "" {
		return
	}
	if err := myCA.ReconcileSuperseded(ctx, servingConfigFrom(cfg)); err != nil {
		// Counted as well as logged, matching supersededRevocationTask. With
		// tls_self_provision off this call is the only sweep the process ever
		// runs, so there is no next pass to clear it and nothing else would
		// move the alert's counter.
		myCA.IncServingRevocationFailures()
		slog.Warn("Could not reconcile superseded serving certificates at startup", "error", err)
	}
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
