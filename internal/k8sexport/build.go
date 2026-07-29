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
	corev1 "k8s.io/api/core/v1"
	accorev1 "k8s.io/client-go/applyconfigurations/core/v1"
)

// The managed-by label marks every object this exporter maintains so operators
// can identify and select resources owned by openvox-ca. It is always present
// and takes precedence over any operator-supplied value for the same key.
const (
	managedByLabelKey   = "app.kubernetes.io/managed-by"
	managedByLabelValue = "openvox-ca"
)

// labelsFor merges the target's configured labels with the mandatory
// managed-by label. The managed-by label always wins so ownership cannot be
// accidentally masked by configuration.
func (t *Target) labelsFor() map[string]string {
	labels := make(map[string]string, len(t.Metadata.Labels)+1)
	for k, v := range t.Metadata.Labels {
		labels[k] = v
	}
	labels[managedByLabelKey] = managedByLabelValue
	return labels
}

// secretDataFor returns the Secret data entries for a target. Only the
// materials the target requested are included, so a cert-only target never
// carries the CRL and vice versa. Secret data is applied as raw bytes under the
// object's data field (the client base64-encodes it in the request); using data
// rather than the write-only stringData keeps server-side apply idempotent — a
// re-apply of unchanged material is a genuine no-op instead of rewriting the
// object each time.
func (t *Target) secretDataFor(m materials) map[string][]byte {
	data := make(map[string][]byte, 2)
	for key, value := range t.entries(m) {
		data[key] = value
	}
	return data
}

// configMapDataFor returns the ConfigMap data entries for a target. ConfigMap
// data is plain text, and PEM is text, so the values are kept as strings.
func (t *Target) configMapDataFor(m materials) map[string]string {
	data := make(map[string]string, 2)
	for key, value := range t.entries(m) {
		data[key] = string(value)
	}
	return data
}

// entries maps each requested material to the data key it is published under.
// One definition so a Secret and a ConfigMap can never disagree about which
// keys a target carries.
func (t *Target) entries(m materials) map[string][]byte {
	out := make(map[string][]byte, 2)
	if t.Cert {
		out[t.CertKey] = m.cert
	}
	if t.CRL {
		out[t.CRLKey] = m.crl
	}
	return out
}

// buildSecretApply constructs the server-side apply configuration for a Secret
// target. The namespace must already be resolved (non-empty).
func (t *Target) buildSecretApply(namespace string, m materials) *accorev1.SecretApplyConfiguration {
	ac := accorev1.Secret(t.Metadata.Name, namespace).
		WithLabels(t.labelsFor()).
		WithData(t.secretDataFor(m))
	// Only own the type field when one is configured, so openvox-ca can
	// co-maintain a Secret whose type (e.g. kubernetes.io/tls) is owned by
	// another manager. An unset type leaves it to the API server default on
	// creation and untouched on an existing object.
	if t.Type != "" {
		ac = ac.WithType(corev1.SecretType(t.Type))
	}
	if len(t.Metadata.Annotations) > 0 {
		ac = ac.WithAnnotations(t.Metadata.Annotations)
	}
	return ac
}

// buildConfigMapApply constructs the server-side apply configuration for a
// ConfigMap target. The namespace must already be resolved (non-empty).
func (t *Target) buildConfigMapApply(namespace string, m materials) *accorev1.ConfigMapApplyConfiguration {
	ac := accorev1.ConfigMap(t.Metadata.Name, namespace).
		WithLabels(t.labelsFor()).
		WithData(t.configMapDataFor(m))
	if len(t.Metadata.Annotations) > 0 {
		ac = ac.WithAnnotations(t.Metadata.Annotations)
	}
	return ac
}
