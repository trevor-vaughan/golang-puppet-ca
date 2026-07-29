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

package k8sexport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// applyTimeout bounds a single server-side apply. The exporter runs on the
// process-lifetime context, and the in-cluster clientset carries no request
// timeout, so without this a black-holed API-server connection could block the
// single exporter goroutine (and thus re-export of every target) for as long as
// the OS transport takes to give up. A per-apply deadline surfaces a stuck call
// as a counted, logged error and lets the loop proceed to the next wake-up; the
// next CRL update or a restart re-reconciles.
const applyTimeout = 30 * time.Second

// MaterialSource provides the current CA certificate and CRL in PEM form. It is
// satisfied by *storage.StorageService, but kept as a narrow interface so this
// package does not depend on the storage layer and is easy to fake in tests.
type MaterialSource interface {
	GetCACert(ctx context.Context) ([]byte, error)
	GetCRL(ctx context.Context) ([]byte, error)
}

// ServingSource additionally provides the self-provisioned serving certificate
// and its private key. It is separate from MaterialSource because the key must
// be handed over *decrypted* — a kubernetes.io/tls Secret holding an encrypted
// PEM is useless to every consumer of one. The storage service satisfies
// MaterialSource alone, so a deployment that exports no serving material needs
// no extra wiring.
//
// One method returning both, deliberately, rather than two. Reading them
// separately means two round trips with a rotation possible in between, which
// publishes a tls.crt and a tls.key from different keypairs — a Secret that
// looks well-formed and fails every handshake against it. The implementation
// serves both from the pair the listener itself is using, which is swapped
// atomically, so there is no window to lose.
type ServingSource interface {
	ServingMaterial(ctx context.Context) (certPEM, keyPEM []byte, err error)
}

// Exporter reconciles the configured Secret/ConfigMap targets with the current
// CA certificate and CRL using server-side apply.
type Exporter struct {
	client    kubernetes.Interface
	cfg       Config
	src       MaterialSource
	serving   ServingSource // nil unless serving material is exported
	defaultNS string        // resolved pod namespace; used for targets without one
	metrics   *Metrics      // may be nil (metrics disabled)
}

// WithServingSource attaches the source for serving certificate and key
// material. Required when any target sets serving_cert or serving_key.
func (e *Exporter) WithServingSource(s ServingSource) *Exporter {
	e.serving = s
	return e
}

// New constructs an Exporter from an existing clientset. cfg must already have
// been validated (Config.Validate). defaultNS is the namespace used for targets
// that do not set their own; it may be empty if every target sets a namespace.
// m may be nil to disable instrumentation.
func New(client kubernetes.Interface, cfg Config, src MaterialSource, defaultNS string, m *Metrics) *Exporter {
	return &Exporter{client: client, cfg: cfg, src: src, defaultNS: defaultNS, metrics: m}
}

// NewInCluster builds an Exporter using in-cluster ServiceAccount credentials,
// resolving the default namespace from the pod's ServiceAccount mount. cfg must
// already have been validated. m may be nil to disable instrumentation.
func NewInCluster(cfg Config, src MaterialSource, m *Metrics) (*Exporter, error) {
	client, err := newInClusterClientset()
	if err != nil {
		return nil, err
	}
	// Only resolve the pod namespace if some target relies on it; otherwise a
	// missing namespace file should not block export.
	var defaultNS string
	if cfg.needsDefaultNamespace() {
		ns, err := podNamespace()
		if err != nil {
			return nil, fmt.Errorf("resolving default namespace for a target without an explicit namespace: %w", err)
		}
		defaultNS = ns
	}
	return New(client, cfg, src, defaultNS, m), nil
}

// needsDefaultNamespace reports whether any target omits its namespace and so
// depends on the pod's own namespace being resolvable.
func (c *Config) needsDefaultNamespace() bool {
	for i := range c.Targets {
		if c.Targets[i].Metadata.Namespace == "" {
			return true
		}
	}
	return false
}

// ExportAll reconciles every configured target with the current cert/CRL. It
// reads each material at most once. A failure applying one target is logged and
// collected but does not prevent the others from being applied; the joined error
// (or nil) is returned.
//
// A material that cannot be read fails only the targets that asked for it. The
// obvious alternative — return early from the whole cycle — is what this used to
// do, and it is worse in a way that is hard to see: recordApply never runs, so
// no per-target series is written, and both arms of the shipped alert put
// last_error on the left-hand side. A single transient read leaves every target
// stale with nothing firing, and because cycles are edge-triggered on CRL and
// serving-certificate changes, the next one may be a long time coming.
func (e *Exporter) ExportAll(ctx context.Context) error {
	m, matErrs := e.fetchMaterials(ctx)

	var errs []error
	for i := range e.cfg.Targets {
		t := &e.cfg.Targets[i]
		err := matErrs.forTarget(t)
		if err == nil {
			err = e.applyTarget(ctx, t, m)
		}
		e.metrics.recordApply(t, e.namespaceFor(t), err)
		if err != nil {
			slog.Warn("Kubernetes export failed for target",
				"kind", t.Kind, "name", t.Metadata.Name, "namespace", e.namespaceFor(t), "error", err)
			errs = append(errs, fmt.Errorf("%s/%s: %w", t.Kind, t.Metadata.Name, err))
			continue
		}
		slog.Debug("Kubernetes export applied",
			"kind", t.Kind, "name", t.Metadata.Name, "namespace", e.namespaceFor(t))
	}
	return errors.Join(errs...)
}

// materials is the set of PEM blobs one export cycle publishes. Passed as a
// struct rather than as positional byte slices so that adding a material does
// not mean editing every signature between here and the apply, and so that a
// caller cannot transpose two of them.
type materials struct {
	cert        []byte
	crl         []byte
	servingCert []byte
	servingKey  []byte
}

// materialErrors records, per material, why it could not be read. A target is
// failed only by the materials it actually requests, so one unreadable blob
// does not silence the targets that never needed it.
type materialErrors struct {
	cert        error
	crl         error
	servingCert error
	servingKey  error
}

// forTarget returns the first read failure affecting t, or nil.
func (me materialErrors) forTarget(t *Target) error {
	switch {
	case t.Cert && me.cert != nil:
		return me.cert
	case t.CRL && me.crl != nil:
		return me.crl
	case t.ServingCert && me.servingCert != nil:
		return me.servingCert
	case t.ServingKey && me.servingKey != nil:
		return me.servingKey
	}
	return nil
}

// fetchMaterials reads each material only if some target requires it.
//
// Read failures are returned alongside whatever succeeded rather than aborting,
// so ExportAll can still apply the targets that do not depend on the missing
// material — and, more importantly, can record a per-target failure for the ones
// that do. See ExportAll for why that matters to the alert.
func (e *Exporter) fetchMaterials(ctx context.Context) (materials, materialErrors) {
	var m materials
	var errs materialErrors
	var wantCert, wantCRL, wantServingCert, wantServingKey bool
	for i := range e.cfg.Targets {
		wantCert = wantCert || e.cfg.Targets[i].Cert
		wantCRL = wantCRL || e.cfg.Targets[i].CRL
		wantServingCert = wantServingCert || e.cfg.Targets[i].ServingCert
		wantServingKey = wantServingKey || e.cfg.Targets[i].ServingKey
	}
	if wantCert {
		certPEM, err := e.src.GetCACert(ctx)
		if err != nil {
			errs.cert = fmt.Errorf("reading CA certificate for export: %w", err)
		}
		m.cert = certPEM
	}
	if wantCRL {
		crlPEM, err := e.src.GetCRL(ctx)
		if err != nil {
			errs.crl = fmt.Errorf("reading CRL for export: %w", err)
		}
		m.crl = crlPEM
	}
	if wantServingCert || wantServingKey {
		if e.serving == nil {
			err := fmt.Errorf("a target requests serving material but no serving source is configured; " +
				"serving_cert and serving_key require tls_self_provision")
			errs.servingCert, errs.servingKey = err, err
			return m, errs
		}
		certPEM, keyPEM, err := e.serving.ServingMaterial(ctx)
		if err != nil {
			err = fmt.Errorf("reading serving material for export: %w", err)
			errs.servingCert, errs.servingKey = err, err
			return m, errs
		}
		if wantServingCert {
			m.servingCert = certPEM
		}
		if wantServingKey {
			m.servingKey = keyPEM
		}
	}
	return m, errs
}

// namespaceFor returns the namespace a target should be applied to: its own, or
// the resolved default.
func (e *Exporter) namespaceFor(t *Target) string {
	if t.Metadata.Namespace != "" {
		return t.Metadata.Namespace
	}
	return e.defaultNS
}

// applyTarget server-side applies a single target. Force is set so the exporter
// reclaims any of its fields that drifted (e.g. were edited by another manager).
func (e *Exporter) applyTarget(ctx context.Context, t *Target, m materials) error {
	ns := e.namespaceFor(t)
	if ns == "" {
		return fmt.Errorf("no namespace resolved")
	}
	// Never publish an empty material: applying an empty value would clobber a
	// previously-good cert/CRL in the target object. A requested-but-empty
	// material means the CA is in an unexpected state, so fail this target (it is
	// counted and logged) and leave the existing object untouched.
	if t.Cert && len(m.cert) == 0 {
		return fmt.Errorf("refusing to export an empty CA certificate")
	}
	if t.CRL && len(m.crl) == 0 {
		return fmt.Errorf("refusing to export an empty CRL")
	}
	if t.ServingCert && len(m.servingCert) == 0 {
		return fmt.Errorf("refusing to export an empty serving certificate")
	}
	if t.ServingKey && len(m.servingKey) == 0 {
		return fmt.Errorf("refusing to export an empty serving key")
	}
	opts := metav1.ApplyOptions{FieldManager: e.cfg.FieldManager, Force: true}

	ctx, cancel := context.WithTimeout(ctx, applyTimeout)
	defer cancel()

	switch t.Kind {
	case KindSecret:
		_, err := e.client.CoreV1().Secrets(ns).Apply(ctx, t.buildSecretApply(ns, m), opts)
		return err
	case KindConfigMap:
		_, err := e.client.CoreV1().ConfigMaps(ns).Apply(ctx, t.buildConfigMapApply(ns, m), opts)
		return err
	default:
		// Unreachable after Validate, but fail loudly rather than silently skip.
		return fmt.Errorf("unsupported kind %q", t.Kind)
	}
}
