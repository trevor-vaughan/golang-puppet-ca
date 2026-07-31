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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/k8sexport"
)

var _ = Describe("Config", func() {
	Describe("Enabled", func() {
		It("is false for an empty config", func() {
			cfg := &k8sexport.Config{}
			Expect(cfg.Enabled()).To(BeFalse())
		})

		It("is true once a target is configured", func() {
			cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
				Kind: "Secret", Metadata: k8sexport.Metadata{Name: "x"}, CRL: true,
			}}}
			Expect(cfg.Enabled()).To(BeTrue())
		})
	})

	Describe("Validate", func() {
		Context("with valid targets", func() {
			It("applies defaults for a Secret target", func() {
				cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
					Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust"}, Cert: true, CRL: true,
				}}}
				Expect(cfg.Validate()).To(Succeed())

				Expect(cfg.FieldManager).To(Equal("openvox-ca"))
				t := cfg.Targets[0]
				Expect(t.Kind).To(Equal("Secret"))
				// type is left empty so the exporter does not own the field.
				Expect(t.Type).To(BeEmpty())
				Expect(t.CertKey).To(Equal("ca.crt"))
				Expect(t.CRLKey).To(Equal("ca.crl"))
			})

			DescribeTable("normalises kind case-insensitively",
				func(kind, want string) {
					cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
						Kind: kind, Metadata: k8sexport.Metadata{Name: "trust"}, CRL: true,
					}}}
					Expect(cfg.Validate()).To(Succeed())
					Expect(cfg.Targets[0].Kind).To(Equal(want))
				},
				Entry("lowercase secret", "secret", "Secret"),
				Entry("canonical Secret", "Secret", "Secret"),
				Entry("lowercase configmap", "configmap", "ConfigMap"),
				Entry("canonical ConfigMap", "ConfigMap", "ConfigMap"),
				Entry("mixed-case CONFIGMAP", "CONFIGMAP", "ConfigMap"),
			)

			It("does not default a type for ConfigMap targets", func() {
				cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
					Kind: "ConfigMap", Metadata: k8sexport.Metadata{Name: "trust"}, CRL: true,
				}}}
				Expect(cfg.Validate()).To(Succeed())
				Expect(cfg.Targets[0].Type).To(BeEmpty())
				Expect(cfg.Targets[0].CRLKey).To(Equal("ca.crl"))
			})

			It("preserves an explicit field manager and keys", func() {
				cfg := &k8sexport.Config{
					FieldManager: "my-mgr",
					Targets: []k8sexport.Target{{
						Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust"}, Cert: true,
						CertKey: "tls.crt", Type: "Opaque",
					}},
				}
				Expect(cfg.Validate()).To(Succeed())
				Expect(cfg.FieldManager).To(Equal("my-mgr"))
				Expect(cfg.Targets[0].CertKey).To(Equal("tls.crt"))
				Expect(cfg.Targets[0].Type).To(Equal("Opaque"))
			})
		})

		Context("with invalid targets", func() {
			DescribeTable("rejects",
				func(t k8sexport.Target, msg string) {
					cfg := &k8sexport.Config{Targets: []k8sexport.Target{t}}
					err := cfg.Validate()
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring(msg))
				},
				Entry("missing kind", k8sexport.Target{Metadata: k8sexport.Metadata{Name: "x"}, CRL: true}, "kind is required"),
				Entry("invalid kind", k8sexport.Target{Kind: "Deployment", Metadata: k8sexport.Metadata{Name: "x"}, CRL: true}, "invalid kind"),
				Entry("missing name", k8sexport.Target{Kind: "Secret", CRL: true}, "metadata.name is required"),
				Entry("neither cert nor crl", k8sexport.Target{Kind: "Secret", Metadata: k8sexport.Metadata{Name: "x"}}, "at least one of cert, crl, serving_cert or serving_key"),
				Entry("type on ConfigMap", k8sexport.Target{Kind: "ConfigMap", Metadata: k8sexport.Metadata{Name: "x"}, CRL: true, Type: "Opaque"}, "type is only valid for Secret"),
				Entry("colliding keys", k8sexport.Target{Kind: "Secret", Metadata: k8sexport.Metadata{Name: "x"}, Cert: true, CRL: true, CertKey: "ca.pem", CRLKey: "ca.pem"}, "must differ"),
				Entry("serving_key in a ConfigMap", k8sexport.Target{Kind: "ConfigMap", Metadata: k8sexport.Metadata{Name: "x"}, ServingKey: true}, "only valid for Secret targets"),
				Entry("serving_key with cert", k8sexport.Target{Kind: "Secret", Metadata: k8sexport.Metadata{Name: "x"}, ServingKey: true, Cert: true}, "cannot be combined with cert or crl"),
				Entry("serving_key with crl", k8sexport.Target{Kind: "Secret", Metadata: k8sexport.Metadata{Name: "x"}, ServingKey: true, CRL: true}, "cannot be combined with cert or crl"),
				Entry("serving certificate colliding with the serving key", k8sexport.Target{Kind: "Secret", Metadata: k8sexport.Metadata{Name: "x"}, ServingCert: true, ServingKey: true, ServingCertKey: "tls.key"}, "must differ"),
				// The API server requires both tls.crt and tls.key in a
				// kubernetes.io/tls Secret, so half a pair is accepted here and
				// then rejected on every apply for the life of the deployment.
				Entry("kubernetes.io/tls with only the certificate", k8sexport.Target{Kind: "Secret", Metadata: k8sexport.Metadata{Name: "x"}, Type: "kubernetes.io/tls", ServingCert: true}, "requires both serving_cert and serving_key"),
				Entry("kubernetes.io/tls with only the key", k8sexport.Target{Kind: "Secret", Metadata: k8sexport.Metadata{Name: "x"}, Type: "kubernetes.io/tls", ServingKey: true}, "requires both serving_cert and serving_key"),
			)

			It("accepts kubernetes.io/tls with the whole pair", func() {
				cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
					Kind: "Secret", Metadata: k8sexport.Metadata{Name: "serving"},
					Type: "kubernetes.io/tls", ServingCert: true, ServingKey: true,
				}}}
				Expect(cfg.Validate()).To(Succeed())
			})

			It("rejects two targets naming the same object", func() {
				// They do not merge: each apply sends the full field set this
				// manager owns, so the second replaces the first's data every
				// cycle and the two flap against each other. Easy to reach from
				// the "use two targets" advice for keeping the key out of a
				// widely-read Secret — which means two different Secrets.
				cfg := &k8sexport.Config{Targets: []k8sexport.Target{
					{Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust", Namespace: "ns1"}, Cert: true},
					{Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust", Namespace: "ns1"}, ServingKey: true},
				}}
				Expect(cfg.Validate()).To(MatchError(ContainSubstring("overwrite each other")))
			})

			It("allows the same name in different namespaces", func() {
				cfg := &k8sexport.Config{Targets: []k8sexport.Target{
					{Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust", Namespace: "ns1"}, Cert: true},
					{Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust", Namespace: "ns2"}, Cert: true},
				}}
				Expect(cfg.Validate()).To(Succeed())
			})
		})

		Context("with serving material", func() {
			It("defaults to the kubernetes.io/tls data keys", func() {
				// Not the trust-bundle convention: an Ingress or Gateway reading
				// this Secret expects tls.crt and tls.key.
				cfg := &k8sexport.Config{Targets: []k8sexport.Target{
					{Kind: "Secret", Metadata: k8sexport.Metadata{Name: "serving"}, ServingCert: true, ServingKey: true},
				}}
				Expect(cfg.Validate()).To(Succeed())
				Expect(cfg.Targets[0].ServingCertKey).To(Equal("tls.crt"))
				Expect(cfg.Targets[0].ServingKeyKey).To(Equal("tls.key"))
			})

			It("separates the serving certificate from public trust material", func() {
				// Not for blast radius -- the certificate is public -- but for
				// freshness. A replica that has not caught up with a rotation
				// skips every target carrying serving material, and server-side
				// apply cannot omit just those keys without deleting them, so a
				// shared object would take ca.crt and ca.crl dark with it.
				cfg := &k8sexport.Config{Targets: []k8sexport.Target{
					{Kind: "Secret", Metadata: k8sexport.Metadata{Name: "x"}, Cert: true, ServingCert: true},
				}}
				Expect(cfg.Validate()).To(MatchError(ContainSubstring("serving_cert cannot be combined")))
			})

			It("allows each on its own target", func() {
				cfg := &k8sexport.Config{Targets: []k8sexport.Target{
					{Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust"}, Cert: true, CRL: true},
					{Kind: "Secret", Metadata: k8sexport.Metadata{Name: "serving"}, Type: "kubernetes.io/tls",
						ServingCert: true, ServingKey: true},
				}}
				Expect(cfg.Validate()).To(Succeed())
			})

			It("reports whether any target wants the private key", func() {
				withKey := &k8sexport.Config{Targets: []k8sexport.Target{
					{Kind: "Secret", Metadata: k8sexport.Metadata{Name: "x"}, ServingKey: true},
				}}
				Expect(withKey.Validate()).To(Succeed())
				Expect(withKey.WantsServingKey()).To(BeTrue())

				withoutKey := &k8sexport.Config{Targets: []k8sexport.Target{
					{Kind: "Secret", Metadata: k8sexport.Metadata{Name: "x"}, ServingCert: true},
				}}
				Expect(withoutKey.Validate()).To(Succeed())
				Expect(withoutKey.WantsServingKey()).To(BeFalse())
			})
		})

		It("reports the offending target index", func() {
			cfg := &k8sexport.Config{Targets: []k8sexport.Target{
				{Kind: "Secret", Metadata: k8sexport.Metadata{Name: "ok"}, CRL: true},
				{Kind: "bogus", Metadata: k8sexport.Metadata{Name: "bad"}, CRL: true},
			}}
			err := cfg.Validate()
			Expect(err).To(MatchError(ContainSubstring("target 1")))
		})
	})
})

var _ = Describe("Target key collisions", func() {
	// The serving_key_key row of checkDistinctKeys had no case: deleting it left
	// the suite green while serving_key_key: tls.crt put the private key under
	// tls.crt, overwriting the certificate. With type kubernetes.io/tls the API
	// server then rejects every apply forever; without it the apply succeeds and
	// the Secret quietly carries the key where consumers expect the certificate.
	It("refuses a serving pair that collides on one data key", func() {
		cfg := k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "serving", Namespace: "ns1"},
			ServingCert: true, ServingKey: true, ServingKeyKey: "tls.crt",
		}}}
		Expect(cfg.Validate()).To(MatchError(ContainSubstring("must differ")))
	})
})

var _ = Describe("Config.CheckDistinctObjects", func() {
	// Validate cannot see this collision: it runs before the pod's namespace is
	// known, so it compares namespaces as written. A target with none and one
	// naming the pod's own namespace explicitly look different there and resolve
	// to the same object at runtime -- and both applies then *succeed*, so
	// nothing alerts while the object loses whatever fields the other target
	// does not set, every cycle.
	sameName := func(nsA, nsB string) k8sexport.Config {
		return k8sexport.Config{Targets: []k8sexport.Target{
			{
				Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust", Namespace: nsA},
				Cert: true,
			},
			{
				Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust", Namespace: nsB},
				CRL: true,
			},
		}}
	}

	It("refuses an omitted namespace that resolves onto an explicit one", func() {
		cfg := sameName("", "ns1")
		Expect(cfg.Validate()).To(Succeed(), "Validate cannot know what the empty one resolves to")
		Expect(cfg.CheckDistinctObjects("ns1")).To(MatchError(ContainSubstring("both resolve to")))
	})

	It("refuses it in the other order too", func() {
		cfg := sameName("ns1", "")
		Expect(cfg.CheckDistinctObjects("ns1")).To(HaveOccurred())
	})

	It("allows the same name when the namespaces genuinely differ", func() {
		a := sameName("", "ns2")
		Expect(a.CheckDistinctObjects("ns1")).To(Succeed())
		b := sameName("ns1", "ns2")
		Expect(b.CheckDistinctObjects("ns1")).To(Succeed())
	})
})
