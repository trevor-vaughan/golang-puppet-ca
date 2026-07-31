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

// Package k8sexport publishes the CA certificate and/or CRL into Kubernetes
// Secrets and ConfigMaps. It is an optional feature: when no targets are
// configured nothing in this package runs. Objects are reconciled with
// server-side apply so each export is an idempotent create-or-update.
//
// The exporter authenticates with the pod's in-cluster ServiceAccount, so it is
// only available when openvox-ca itself runs inside a Kubernetes cluster.
package k8sexport

import (
	"fmt"
	"strings"
)

// Kind enumerates the Kubernetes object kinds an export target may be. The
// canonical spellings match Kubernetes; configuration accepts any case and is
// normalised to these values.
const (
	KindSecret    = "Secret"
	KindConfigMap = "ConfigMap"
)

const (
	// defaultFieldManager is the server-side apply field manager used when the
	// operator does not set one. It scopes ownership of the fields this exporter
	// writes so other managers (e.g. kubectl) can co-own unrelated fields.
	defaultFieldManager = "openvox-ca"
	// defaultCertKey / defaultCRLKey are the data keys used when a target does
	// not override them. They follow common Kubernetes trust-bundle conventions.
	defaultCertKey = "ca.crt"
	defaultCRLKey  = "ca.crl"
	// secretTypeTLS is the Kubernetes Secret type whose contract requires both
	// tls.crt and tls.key. G101: a well-known API constant, not a credential.
	secretTypeTLS = "kubernetes.io/tls" //nolint:gosec // G101: Kubernetes Secret type name

	// defaultServingCertKey / defaultServingKeyKey follow the kubernetes.io/tls
	// convention instead, because that is what an Ingress or Gateway reading
	// the Secret expects to find.
	defaultServingCertKey = "tls.crt"
	defaultServingKeyKey  = "tls.key"
)

// Config is the top-level kubernetes_export configuration block. The feature is
// considered enabled when Targets is non-empty.
type Config struct {
	// FieldManager is the server-side apply field manager name. Empty selects
	// defaultFieldManager.
	FieldManager string `yaml:"field_manager"`
	// Targets is the set of Secrets/ConfigMaps to maintain.
	Targets []Target `yaml:"targets"`
}

// Metadata mirrors the shape of a Kubernetes object's metadata block, so a
// target reads like the manifest it produces.
type Metadata struct {
	// Name is the object's metadata.name (required).
	Name string `yaml:"name"`
	// Namespace is the object's namespace. Empty resolves at runtime to the
	// pod's own ServiceAccount namespace.
	Namespace string `yaml:"namespace"`
	// Labels and Annotations are applied to the object's metadata.
	Labels      map[string]string `yaml:"labels"`
	Annotations map[string]string `yaml:"annotations"`
}

// Target describes a single Secret or ConfigMap to maintain.
type Target struct {
	// Kind is "Secret" or "ConfigMap" (case-insensitive; normalised by
	// Validate to the canonical Kubernetes spelling).
	Kind string `yaml:"kind"`
	// Metadata carries the object's name, namespace, labels and annotations.
	Metadata Metadata `yaml:"metadata"`
	// Type sets a Secret's type field (e.g. "Opaque"). Only valid for Secrets.
	// When empty the exporter does not manage the type field at all, so it can
	// co-maintain a Secret whose type is owned by another manager (e.g. a
	// kubernetes.io/tls Secret created by Flux): the API server defaults a new
	// Secret to Opaque, and an existing Secret's type is left untouched.
	Type string `yaml:"type"`
	// Cert and CRL select which materials to include. At least one of the four
	// material flags must be true.
	Cert bool `yaml:"cert"`
	CRL  bool `yaml:"crl"`
	// ServingCert and ServingKey publish the self-provisioned serving
	// certificate and its private key, for an Ingress or Gateway that
	// terminates TLS in front of the CA. Only meaningful with
	// tls_self_provision enabled.
	ServingCert bool `yaml:"serving_cert"`
	ServingKey  bool `yaml:"serving_key"`
	// CertKey and CRLKey name the data entries for the cert and CRL. Empty
	// selects defaultCertKey / defaultCRLKey.
	CertKey string `yaml:"cert_key"`
	CRLKey  string `yaml:"crl_key"`
	// ServingCertKey and ServingKeyKey name the data entries for the serving
	// material. Empty selects defaultServingCertKey / defaultServingKeyKey.
	ServingCertKey string `yaml:"serving_cert_key"`
	ServingKeyKey  string `yaml:"serving_key_key"`
}

// WantsServingKey reports whether any target publishes the serving private key.
// Used at startup to warn that it reaches the Secret in plaintext.
func (c *Config) WantsServingKey() bool {
	if c == nil {
		return false
	}
	for i := range c.Targets {
		if c.Targets[i].ServingKey {
			return true
		}
	}
	return false
}

// WantsServingMaterial reports whether any target publishes either half of the
// serving pair. Both halves come from the holder the listener presents, so both
// require tls_self_provision.
func (c *Config) WantsServingMaterial() bool {
	if c == nil {
		return false
	}
	for i := range c.Targets {
		if c.Targets[i].ServingCert || c.Targets[i].ServingKey {
			return true
		}
	}
	return false
}

// Enabled reports whether any export target is configured.
func (c *Config) Enabled() bool {
	return c != nil && len(c.Targets) > 0
}

// Validate normalises the config in place (canonicalising kinds, applying
// defaults) and returns an error describing the first invalid target. It is
// safe to call once at startup before constructing an Exporter.
func (c *Config) Validate() error {
	if c.FieldManager == "" {
		c.FieldManager = defaultFieldManager
	}
	seen := map[string]int{}
	for i := range c.Targets {
		if err := c.Targets[i].validate(); err != nil {
			return fmt.Errorf("kubernetes_export target %d: %w", i, err)
		}

		// Two targets naming the same object do not merge: each apply sends the
		// full set of fields this field manager owns, so the second overwrites
		// the first's data every cycle and the pair flap against each other. It
		// is an easy mistake to make from the "use two targets" advice for
		// keeping the private key out of a widely-read Secret — that advice
		// means two *different* Secrets.
		// Keyed on the namespace as written. An omitted namespace resolves at
		// runtime to the pod's own, which Validate cannot see -- so this catches
		// only collisions that are already textually identical, and
		// CheckDistinctObjects repeats it against the resolved namespace once
		// the exporter knows it. Both are needed: this one fails at startup with
		// a config-file line number, that one covers the case where "" and an
		// explicit namespace name the same object.
		t := &c.Targets[i]
		id := t.Kind + "/" + t.Metadata.Namespace + "/" + t.Metadata.Name
		if first, dup := seen[id]; dup {
			return fmt.Errorf("kubernetes_export targets %d and %d both name %s %q in namespace %q: "+
				"each apply replaces the other's data, so they would overwrite each other on every "+
				"export. Merge them into one target, or give them different names",
				first, i, t.Kind, t.Metadata.Name, t.Metadata.Namespace)
		}
		seen[id] = i
	}
	return nil
}

// CheckDistinctObjects repeats the duplicate-target check against the namespace
// each target actually resolves to.
//
// Validate runs before the pod's namespace is known, so it compares namespaces
// as written: a target with no namespace and one naming the pod's own namespace
// explicitly look different there and collide here. Both applies then succeed
// and record success, so nothing alerts -- the object simply loses whichever
// fields the other target does not set, on every cycle. A trust bundle sharing
// an object with a serving-key target that way would carry the private key to
// every workload mounting it, which is what the per-target refusals exist to
// stop.
func (c *Config) CheckDistinctObjects(defaultNS string) error {
	seen := map[string]int{}
	for i := range c.Targets {
		t := &c.Targets[i]
		ns := t.Metadata.Namespace
		if ns == "" {
			ns = defaultNS
		}
		id := t.Kind + "/" + ns + "/" + t.Metadata.Name
		if first, dup := seen[id]; dup {
			return fmt.Errorf("kubernetes_export targets %d and %d both resolve to %s %q in "+
				"namespace %q: each apply replaces the other's data, so they would overwrite each "+
				"other on every export. Merge them into one target, or give them different names",
				first, i, t.Kind, t.Metadata.Name, ns)
		}
		seen[id] = i
	}
	return nil
}

func (t *Target) validate() error {
	t.Kind = strings.TrimSpace(t.Kind)
	switch {
	case strings.EqualFold(t.Kind, KindSecret):
		t.Kind = KindSecret
	case strings.EqualFold(t.Kind, KindConfigMap):
		t.Kind = KindConfigMap
	case t.Kind == "":
		return fmt.Errorf("kind is required (%q or %q)", KindSecret, KindConfigMap)
	default:
		return fmt.Errorf("invalid kind %q (must be %q or %q)", t.Kind, KindSecret, KindConfigMap)
	}

	if strings.TrimSpace(t.Metadata.Name) == "" {
		return fmt.Errorf("metadata.name is required")
	}
	if !t.Cert && !t.CRL && !t.ServingCert && !t.ServingKey {
		return fmt.Errorf("at least one of cert, crl, serving_cert or serving_key must be true")
	}
	if t.Type != "" && t.Kind != KindSecret {
		return fmt.Errorf("type is only valid for Secret targets")
	}

	// A ConfigMap is world-readable to anything that can get it and is not
	// encrypted at rest. A private key does not belong in one.
	if t.ServingKey && t.Kind != KindSecret {
		return fmt.Errorf("serving_key is only valid for Secret targets, not a %s", t.Kind)
	}

	// SECURITY: a Secret holding ca.crt is routinely mounted widely — it is
	// public trust material and workloads across the cluster read it. Letting
	// it quietly acquire a tls.key entry would extend the serving key's reach
	// to every one of them. Two targets cost nothing.
	if t.ServingKey && (t.Cert || t.CRL) {
		return fmt.Errorf("serving_key cannot be combined with cert or crl in one target: " +
			"a Secret carrying public trust material is mounted far more widely than " +
			"one carrying a private key. Use two targets, with different names")
	}

	// Freshness, not blast radius, separates this one. A replica that is behind
	// skips every target carrying serving material, because server-side apply
	// with Force would delete the keys it omitted rather than leave them. That
	// is right for the serving pair and wrong for a trust bundle: sharing an
	// object would take ca.crt and ca.crl dark for as long as that replica is
	// behind -- up to one maintenance interval -- and leave a stale
	// PuppetCAKubernetesExportFailing with no way to clear it. Separate targets
	// keep each material on its own freshness clock.
	if t.ServingCert && (t.Cert || t.CRL) {
		return fmt.Errorf("serving_cert cannot be combined with cert or crl in one target: " +
			"a replica that has not yet caught up with a rotation skips its serving targets, " +
			"which would take the trust material with them. Use two targets, with different names")
	}

	// type: kubernetes.io/tls is validated by the API server, which requires
	// both tls.crt and tls.key to be present. Half a pair is accepted here and
	// then rejected on every apply for the life of the deployment, which shows
	// up as a permanently failing export rather than as the configuration error
	// it is.
	if strings.EqualFold(t.Type, secretTypeTLS) && (!t.ServingCert || !t.ServingKey) {
		return fmt.Errorf("type %s requires both serving_cert and serving_key: "+
			"the API server rejects a %s Secret that is missing tls.crt or tls.key, so this "+
			"would fail on every export", secretTypeTLS, secretTypeTLS)
	}

	if t.Cert && t.CertKey == "" {
		t.CertKey = defaultCertKey
	}
	if t.CRL && t.CRLKey == "" {
		t.CRLKey = defaultCRLKey
	}
	if t.ServingCert && t.ServingCertKey == "" {
		t.ServingCertKey = defaultServingCertKey
	}
	if t.ServingKey && t.ServingKeyKey == "" {
		t.ServingKeyKey = defaultServingKeyKey
	}

	// A single object cannot store two materials under the same key. Checked
	// across every requested pair rather than just cert/crl, because the
	// defaults now come from two different conventions and an operator
	// overriding one could collide with any of the others.
	if err := t.checkDistinctKeys(); err != nil {
		return err
	}
	return nil
}

// checkDistinctKeys reports the first data key claimed by two materials.
func (t *Target) checkDistinctKeys() error {
	seen := make(map[string]string, 4)
	for _, e := range []struct {
		want bool
		name string
		key  string
	}{
		{t.Cert, "cert_key", t.CertKey},
		{t.CRL, "crl_key", t.CRLKey},
		{t.ServingCert, "serving_cert_key", t.ServingCertKey},
		{t.ServingKey, "serving_key_key", t.ServingKeyKey},
	} {
		if !e.want {
			continue
		}
		if prev, ok := seen[e.key]; ok {
			return fmt.Errorf("%s and %s must differ (both %q)", prev, e.name, e.key)
		}
		seen[e.key] = e.name
	}
	return nil
}
