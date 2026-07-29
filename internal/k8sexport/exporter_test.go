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

package k8sexport_test

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/voxpupuli/openvox-ca/internal/k8sexport"
)

// metricValue gathers reg and returns the value of the counter or gauge series
// matching name and labels, or false when no such series exists.
func metricValue(reg *prometheus.Registry, name string, labels map[string]string) (float64, bool) {
	GinkgoHelper()
	mfs, err := reg.Gather()
	Expect(err).NotTo(HaveOccurred())
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			have := make(map[string]string, len(m.GetLabel()))
			for _, lp := range m.GetLabel() {
				have[lp.GetName()] = lp.GetValue()
			}
			matched := true
			for k, v := range labels {
				if have[k] != v {
					matched = false
					break
				}
			}
			if !matched {
				continue
			}
			if c := m.GetCounter(); c != nil {
				return c.GetValue(), true
			}
			return m.GetGauge().GetValue(), true
		}
	}
	return 0, false
}

// stubSource is a MaterialSource returning fixed PEM bytes.
type stubSource struct {
	cert, crl []byte
	certErr   error
	crlErr    error
}

func (s stubSource) GetCACert(context.Context) ([]byte, error) { return s.cert, s.certErr }
func (s stubSource) GetCRL(context.Context) ([]byte, error)    { return s.crl, s.crlErr }

// stubServing is a ServingSource returning fixed PEM bytes. It stands in for
// the CA, which is the real implementation because the private key must be
// decrypted before publication and only the CA holds the passphrase.
type stubServing struct {
	cert, key []byte
	certErr   error
	keyErr    error
}

func (s stubServing) ServingCertPEM(context.Context) ([]byte, error) { return s.cert, s.certErr }
func (s stubServing) ServingKeyPEM(context.Context) ([]byte, error)  { return s.key, s.keyErr }

var _ = Describe("Exporter", func() {
	var (
		ctx    context.Context
		client *fake.Clientset
		src    stubSource
	)

	BeforeEach(func() {
		ctx = context.Background()
		client = fake.NewClientset()
		src = stubSource{cert: []byte("CERT-PEM"), crl: []byte("CRL-PEM")}
	})

	mustValidate := func(cfg *k8sexport.Config) {
		GinkgoHelper()
		Expect(cfg.Validate()).To(Succeed())
	}

	It("applies a Secret with both materials, keys, type and managed-by label", func() {
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret",
			Metadata: k8sexport.Metadata{
				Name: "trust", Namespace: "ns1",
				Labels: map[string]string{"app": "demo"},
			},
			Type: "Opaque",
			Cert: true, CRL: true,
		}}}
		mustValidate(cfg)

		exp := k8sexport.New(client, *cfg, src, "", nil)
		Expect(exp.ExportAll(ctx)).To(Succeed())

		sec, err := client.CoreV1().Secrets("ns1").Get(ctx, "trust", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(sec.Data).To(HaveKeyWithValue("ca.crt", []byte("CERT-PEM")))
		Expect(sec.Data).To(HaveKeyWithValue("ca.crl", []byte("CRL-PEM")))
		Expect(string(sec.Type)).To(Equal("Opaque"))
		Expect(sec.Labels).To(HaveKeyWithValue("app", "demo"))
		Expect(sec.Labels).To(HaveKeyWithValue("app.kubernetes.io/managed-by", "openvox-ca"))
	})

	It("does not set the type when none is configured, so it is not owned", func() {
		// A CRL-only target with no type: openvox-ca co-maintains the CRL inside
		// a Secret whose type (e.g. kubernetes.io/tls) is owned by another
		// manager, without claiming the type field itself.
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust", Namespace: "ns1"}, CRL: true,
		}}}
		mustValidate(cfg)

		exp := k8sexport.New(client, *cfg, src, "", nil)
		Expect(exp.ExportAll(ctx)).To(Succeed())

		sec, err := client.CoreV1().Secrets("ns1").Get(ctx, "trust", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(sec.Data).To(HaveKeyWithValue("ca.crl", []byte("CRL-PEM")))
		Expect(sec.Type).To(BeEmpty()) // exporter left the type field unset
	})

	It("applies a ConfigMap with only the CRL under a custom key", func() {
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
			Kind:     "ConfigMap",
			Metadata: k8sexport.Metadata{Name: "crl-cm", Namespace: "ns1"},
			CRL:      true, CRLKey: "openvox.crl",
		}}}
		mustValidate(cfg)

		exp := k8sexport.New(client, *cfg, src, "", nil)
		Expect(exp.ExportAll(ctx)).To(Succeed())

		cm, err := client.CoreV1().ConfigMaps("ns1").Get(ctx, "crl-cm", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(cm.Data).To(HaveKeyWithValue("openvox.crl", "CRL-PEM"))
		Expect(cm.Data).NotTo(HaveKey("ca.crt"))
		Expect(cm.Labels).To(HaveKeyWithValue("app.kubernetes.io/managed-by", "openvox-ca"))
	})

	It("uses the default namespace for targets without one", func() {
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust"}, Cert: true,
		}}}
		mustValidate(cfg)

		exp := k8sexport.New(client, *cfg, src, "default-ns", nil)
		Expect(exp.ExportAll(ctx)).To(Succeed())

		_, err := client.CoreV1().Secrets("default-ns").Get(ctx, "trust", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	It("re-exports an updated CRL on a subsequent call", func() {
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust", Namespace: "ns1"}, CRL: true,
		}}}
		mustValidate(cfg)

		src.crl = []byte("CRL-V1")
		exp := k8sexport.New(client, *cfg, src, "", nil)
		Expect(exp.ExportAll(ctx)).To(Succeed())

		// Update the source CRL and a fresh exporter (same config) re-applies it.
		src.crl = []byte("CRL-V2")
		exp = k8sexport.New(client, *cfg, src, "", nil)
		Expect(exp.ExportAll(ctx)).To(Succeed())

		sec, err := client.CoreV1().Secrets("ns1").Get(ctx, "trust", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(sec.Data).To(HaveKeyWithValue("ca.crl", []byte("CRL-V2")))
	})

	It("returns an error and applies nothing when the CRL cannot be read", func() {
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust", Namespace: "ns1"}, CRL: true,
		}}}
		mustValidate(cfg)

		src.crlErr = context.DeadlineExceeded
		exp := k8sexport.New(client, *cfg, src, "", nil)
		Expect(exp.ExportAll(ctx)).To(MatchError(ContainSubstring("reading CRL")))

		_, err := client.CoreV1().Secrets("ns1").Get(ctx, "trust", metav1.GetOptions{})
		Expect(err).To(HaveOccurred()) // never created
	})

	It("refuses to publish an empty material, leaving any existing object untouched", func() {
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust", Namespace: "ns1"}, CRL: true,
		}}}
		mustValidate(cfg)

		// The source returns no error but an empty CRL (e.g. an unexpected CA
		// state): the target must fail rather than clobber the object.
		src.crl = nil
		exp := k8sexport.New(client, *cfg, src, "", nil)
		Expect(exp.ExportAll(ctx)).To(MatchError(ContainSubstring("empty CRL")))

		_, err := client.CoreV1().Secrets("ns1").Get(ctx, "trust", metav1.GetOptions{})
		Expect(err).To(HaveOccurred()) // never created
	})

	It("records apply metrics per target and result", func() {
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{
			{Kind: "Secret", Metadata: k8sexport.Metadata{Name: "good", Namespace: "ns1"}, CRL: true},
			{Kind: "ConfigMap", Metadata: k8sexport.Metadata{Name: "bad", Namespace: "ns1"}, CRL: true},
		}}
		mustValidate(cfg)

		// Fail every ConfigMap apply so the second target records an error.
		client.PrependReactor("patch", "configmaps",
			func(ktesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("boom")
			})

		reg := prometheus.NewRegistry()
		exp := k8sexport.New(client, *cfg, src, "", k8sexport.NewMetrics(reg))
		Expect(exp.ExportAll(ctx)).To(MatchError(ContainSubstring("ConfigMap/bad")))

		v, found := metricValue(reg, "puppetca_k8s_export_applies_total", map[string]string{
			"kind": "Secret", "namespace": "ns1", "name": "good", "result": "success",
		})
		Expect(found).To(BeTrue())
		Expect(v).To(Equal(1.0))

		v, found = metricValue(reg, "puppetca_k8s_export_applies_total", map[string]string{
			"kind": "ConfigMap", "namespace": "ns1", "name": "bad", "result": "error",
		})
		Expect(found).To(BeTrue())
		Expect(v).To(Equal(1.0))

		// Only the successful target gets a last-success timestamp, and only
		// the failing target gets a last-error timestamp.
		v, found = metricValue(reg, "puppetca_k8s_export_last_success_timestamp_seconds",
			map[string]string{"kind": "Secret", "namespace": "ns1", "name": "good"})
		Expect(found).To(BeTrue())
		Expect(v).To(BeNumerically(">", 0))

		_, found = metricValue(reg, "puppetca_k8s_export_last_success_timestamp_seconds",
			map[string]string{"kind": "ConfigMap", "namespace": "ns1", "name": "bad"})
		Expect(found).To(BeFalse())

		v, found = metricValue(reg, "puppetca_k8s_export_last_error_timestamp_seconds",
			map[string]string{"kind": "ConfigMap", "namespace": "ns1", "name": "bad"})
		Expect(found).To(BeTrue())
		Expect(v).To(BeNumerically(">", 0))

		_, found = metricValue(reg, "puppetca_k8s_export_last_error_timestamp_seconds",
			map[string]string{"kind": "Secret", "namespace": "ns1", "name": "good"})
		Expect(found).To(BeFalse())
	})

	It("still applies later targets when an earlier target fails", func() {
		// Failure isolation: a failing target must not stop the ones after it.
		// The failing target is first so a regress-to-early-return (return
		// instead of continue) would leave the second target uncreated.
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{
			{Kind: "Secret", Metadata: k8sexport.Metadata{Name: "bad", Namespace: "ns1"}, CRL: true},
			{Kind: "ConfigMap", Metadata: k8sexport.Metadata{Name: "good", Namespace: "ns1"}, CRL: true},
		}}
		mustValidate(cfg)

		// Fail every Secret apply so the first (earlier) target errors.
		client.PrependReactor("patch", "secrets",
			func(ktesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("boom")
			})

		exp := k8sexport.New(client, *cfg, src, "", nil)
		Expect(exp.ExportAll(ctx)).To(MatchError(ContainSubstring("Secret/bad")))

		// The later ConfigMap must still have been applied.
		cm, err := client.CoreV1().ConfigMaps("ns1").Get(ctx, "good", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(cm.Data).To(HaveKeyWithValue("ca.crl", "CRL-PEM"))
	})

	It("does not read the cert when no target requests it", func() {
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust", Namespace: "ns1"}, CRL: true,
		}}}
		mustValidate(cfg)

		// A cert read would error, but a CRL-only export must not touch it.
		src.certErr = context.DeadlineExceeded
		exp := k8sexport.New(client, *cfg, src, "", nil)
		Expect(exp.ExportAll(ctx)).To(Succeed())
	})

	It("keeps the managed-by label even when a target tries to override it", func() {
		// The managed-by label always wins so ownership cannot be masked by
		// configuration: an operator setting it to another value is overridden.
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret",
			Metadata: k8sexport.Metadata{
				Name: "trust", Namespace: "ns1",
				Labels: map[string]string{"app.kubernetes.io/managed-by": "intruder"},
			},
			Cert: true,
		}}}
		mustValidate(cfg)

		exp := k8sexport.New(client, *cfg, src, "", nil)
		Expect(exp.ExportAll(ctx)).To(Succeed())

		sec, err := client.CoreV1().Secrets("ns1").Get(ctx, "trust", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(sec.Labels).To(HaveKeyWithValue("app.kubernetes.io/managed-by", "openvox-ca"))
	})

	It("propagates configured annotations onto applied objects", func() {
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{
			{
				Kind: "Secret",
				Metadata: k8sexport.Metadata{
					Name: "trust-sec", Namespace: "ns1",
					Annotations: map[string]string{"owner": "platform"},
				},
				Cert: true,
			},
			{
				Kind: "ConfigMap",
				Metadata: k8sexport.Metadata{
					Name: "trust-cm", Namespace: "ns1",
					Annotations: map[string]string{"owner": "platform"},
				},
				CRL: true,
			},
		}}
		mustValidate(cfg)

		exp := k8sexport.New(client, *cfg, src, "", nil)
		Expect(exp.ExportAll(ctx)).To(Succeed())

		sec, err := client.CoreV1().Secrets("ns1").Get(ctx, "trust-sec", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(sec.Annotations).To(HaveKeyWithValue("owner", "platform"))

		cm, err := client.CoreV1().ConfigMaps("ns1").Get(ctx, "trust-cm", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(cm.Annotations).To(HaveKeyWithValue("owner", "platform"))
	})

	It("returns an error and applies nothing when the cert cannot be read", func() {
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust", Namespace: "ns1"}, Cert: true,
		}}}
		mustValidate(cfg)

		src.certErr = context.DeadlineExceeded
		exp := k8sexport.New(client, *cfg, src, "", nil)
		Expect(exp.ExportAll(ctx)).To(MatchError(ContainSubstring("reading CA certificate")))

		_, err := client.CoreV1().Secrets("ns1").Get(ctx, "trust", metav1.GetOptions{})
		Expect(err).To(HaveOccurred()) // never created
	})

	It("refuses to publish an empty cert, leaving any existing object untouched", func() {
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust", Namespace: "ns1"}, Cert: true,
		}}}
		mustValidate(cfg)

		// The source returns no error but an empty cert: the target must fail
		// rather than clobber the object.
		src.cert = nil
		exp := k8sexport.New(client, *cfg, src, "", nil)
		Expect(exp.ExportAll(ctx)).To(MatchError(ContainSubstring("empty CA certificate")))

		_, err := client.CoreV1().Secrets("ns1").Get(ctx, "trust", metav1.GetOptions{})
		Expect(err).To(HaveOccurred()) // never created
	})

	It("errors when a target has no namespace and no default is resolved", func() {
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust"}, Cert: true,
		}}}
		mustValidate(cfg)

		// No per-target namespace and an empty default: apply must fail rather
		// than write into the empty-string namespace.
		exp := k8sexport.New(client, *cfg, src, "", nil)
		Expect(exp.ExportAll(ctx)).To(MatchError(ContainSubstring("no namespace resolved")))

		_, err := client.CoreV1().Secrets("").Get(ctx, "trust", metav1.GetOptions{})
		Expect(err).To(HaveOccurred()) // never created
	})
})

var _ = Describe("Exporter with serving material", func() {
	var (
		ctx     context.Context
		client  *fake.Clientset
		src     stubSource
		serving stubServing
	)

	BeforeEach(func() {
		ctx = context.Background()
		client = fake.NewClientset()
		src = stubSource{cert: []byte("CERT-PEM"), crl: []byte("CRL-PEM")}
		serving = stubServing{cert: []byte("SERVING-CERT-PEM"), key: []byte("SERVING-KEY-PEM")}
	})

	servingTarget := func() *k8sexport.Config {
		GinkgoHelper()
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
			Kind:        "Secret",
			Metadata:    k8sexport.Metadata{Name: "serving", Namespace: "ns1"},
			Type:        "kubernetes.io/tls",
			ServingCert: true, ServingKey: true,
		}}}
		Expect(cfg.Validate()).To(Succeed())
		return cfg
	}

	It("publishes the serving pair under the kubernetes.io/tls keys", func() {
		exp := k8sexport.New(client, *servingTarget(), src, "", nil).WithServingSource(serving)
		Expect(exp.ExportAll(ctx)).To(Succeed())

		sec, err := client.CoreV1().Secrets("ns1").Get(ctx, "serving", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(sec.Data).To(HaveKeyWithValue("tls.crt", []byte("SERVING-CERT-PEM")))
		Expect(sec.Data).To(HaveKeyWithValue("tls.key", []byte("SERVING-KEY-PEM")))
		Expect(sec.Type).To(Equal(corev1.SecretTypeTLS))
	})

	It("carries no trust material into the serving Secret", func() {
		// The separation rule is enforced at validation; this asserts the data
		// actually written matches it.
		exp := k8sexport.New(client, *servingTarget(), src, "", nil).WithServingSource(serving)
		Expect(exp.ExportAll(ctx)).To(Succeed())

		sec, err := client.CoreV1().Secrets("ns1").Get(ctx, "serving", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(sec.Data).To(HaveLen(2))
		Expect(sec.Data).NotTo(HaveKey("ca.crt"))
	})

	It("fails the cycle when no serving source is attached", func() {
		// Rather than publishing an empty tls.key, which would look like a
		// working Secret and fail at the first handshake.
		exp := k8sexport.New(client, *servingTarget(), src, "", nil)
		err := exp.ExportAll(ctx)
		Expect(err).To(HaveOccurred())

		_, getErr := client.CoreV1().Secrets("ns1").Get(ctx, "serving", metav1.GetOptions{})
		Expect(getErr).To(HaveOccurred(), "nothing should have been applied")
	})

	It("refuses to publish an empty serving key", func() {
		serving.key = nil
		exp := k8sexport.New(client, *servingTarget(), src, "", nil).WithServingSource(serving)
		Expect(exp.ExportAll(ctx)).To(HaveOccurred())

		_, err := client.CoreV1().Secrets("ns1").Get(ctx, "serving", metav1.GetOptions{})
		Expect(err).To(HaveOccurred(), "an empty key must not clobber a good one")
	})

	It("publishes the serving certificate alone without needing the key", func() {
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
			Kind:        "ConfigMap",
			Metadata:    k8sexport.Metadata{Name: "serving-cert", Namespace: "ns1"},
			ServingCert: true,
		}}}
		Expect(cfg.Validate()).To(Succeed())

		exp := k8sexport.New(client, *cfg, src, "", nil).WithServingSource(stubServing{
			cert:   []byte("SERVING-CERT-PEM"),
			keyErr: errors.New("must not be called"),
		})
		Expect(exp.ExportAll(ctx)).To(Succeed())

		cm, err := client.CoreV1().ConfigMaps("ns1").Get(ctx, "serving-cert", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(cm.Data).To(HaveKeyWithValue("tls.crt", "SERVING-CERT-PEM"))
	})
})
