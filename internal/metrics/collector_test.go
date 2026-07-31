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

package metrics_test

import (
	"context"

	dto "github.com/prometheus/client_model/go"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/metrics"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// gathered indexes a Prometheus gather result by metric family name.
type gathered map[string]*dto.MetricFamily

func gather(c prometheus.Collector) gathered {
	reg := prometheus.NewRegistry()
	ExpectWithOffset(1, reg.Register(c)).To(Succeed())
	mfs, err := reg.Gather()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	out := make(gathered, len(mfs))
	for _, mf := range mfs {
		out[mf.GetName()] = mf
	}
	return out
}

// labelsOf flattens a metric's label pairs into a map for easy assertions.
func labelsOf(m *dto.Metric) map[string]string {
	out := make(map[string]string, len(m.GetLabel()))
	for _, lp := range m.GetLabel() {
		out[lp.GetName()] = lp.GetValue()
	}
	return out
}

// findByLabels returns the first metric in family whose labels match every
// key/value in want, or nil when none match.
func (g gathered) findByLabels(name string, want map[string]string) *dto.Metric {
	mf := g[name]
	if mf == nil {
		return nil
	}
	for _, m := range mf.GetMetric() {
		got := labelsOf(m)
		match := true
		for k, v := range want {
			if got[k] != v {
				match = false
				break
			}
		}
		if match {
			return m
		}
	}
	return nil
}

func gaugeValue(m *dto.Metric) float64 { return m.GetGauge().GetValue() }

func counterValue(m *dto.Metric) float64 { return m.GetCounter().GetValue() }

var _ = Describe("Collector", func() {
	var (
		ctx   context.Context
		myCA  *ca.CA
		store *storage.StorageService
	)

	BeforeEach(func() {
		ctx = context.Background()
		store = storage.New(GinkgoT().TempDir())
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(myCA.Init(ctx)).To(Succeed())
	})

	signCert := func(subject string) {
		csrPEM, err := testutil.GenerateCSR(subject)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(ctx, subject, csrPEM)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.Sign(ctx, subject)
		Expect(err).NotTo(HaveOccurred())
	}

	requestCert := func(subject string) {
		csrPEM, err := testutil.GenerateCSR(subject)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(ctx, subject, csrPEM)
		Expect(err).NotTo(HaveOccurred())
	}

	It("reports CA certificate and CRL metrics", func() {
		g := gather(metrics.NewCollector(myCA))

		Expect(gaugeValue(g.findByLabels("puppetca_collector_scrape_success", nil))).To(Equal(1.0))
		Expect(gaugeValue(g.findByLabels("puppetca_ca_ready", nil))).To(Equal(1.0))

		caInfo := g.findByLabels("puppetca_ca_certificate_info", nil)
		Expect(caInfo).NotTo(BeNil())
		Expect(labelsOf(caInfo)).To(HaveKeyWithValue("common_name", ContainSubstring("Puppet CA")))
		Expect(gaugeValue(caInfo)).To(Equal(1.0))

		notAfter := g.findByLabels("puppetca_ca_certificate_not_after_timestamp_seconds", nil)
		Expect(notAfter).NotTo(BeNil())
		Expect(gaugeValue(notAfter)).To(BeNumerically(">", gaugeValue(
			g.findByLabels("puppetca_ca_certificate_not_before_timestamp_seconds", nil))))

		// A freshly bootstrapped CA has published an (empty) CRL.
		Expect(g.findByLabels("puppetca_crl_next_update_timestamp_seconds", nil)).NotTo(BeNil())
		Expect(gaugeValue(g.findByLabels("puppetca_crl_revoked_certificates", nil))).To(Equal(0.0))

		// The CRL-update failure counter is always exported, starting at zero
		// on a CA that has performed no failed CRL amendments.
		crlUpdateFailures := g.findByLabels("puppetca_crl_update_failures_total", nil)
		Expect(crlUpdateFailures).NotTo(BeNil())
		Expect(counterValue(crlUpdateFailures)).To(Equal(0.0))

		// The serving-certificate counters are exported unconditionally too, so
		// a dashboard or alert can select them whether or not the feature is on.
		// Pinned by name: the mixin's PuppetCAServingCertRenewalFailing selects
		// the second one, and a rename would silently stop it firing.
		servingIssued := g.findByLabels("puppetca_serving_cert_issued_total", nil)
		Expect(servingIssued).NotTo(BeNil())
		Expect(counterValue(servingIssued)).To(Equal(0.0))

		servingRenewalFailures := g.findByLabels("puppetca_serving_cert_renewal_failures_total", nil)
		Expect(servingRenewalFailures).NotTo(BeNil())
		Expect(counterValue(servingRenewalFailures)).To(Equal(0.0))

		servingRevocationFailures := g.findByLabels("puppetca_serving_cert_revocation_failures_total", nil)
		Expect(servingRevocationFailures).NotTo(BeNil())
		Expect(counterValue(servingRevocationFailures)).To(Equal(0.0))
	})

	It("keeps the three serving counters distinct", func() {
		// Zero on every one of them means the spec above pins their names but
		// not which value each carries: transposing two of the collector's
		// MustNewConstMetric lines passes it, and stops the mixin's
		// PuppetCAServingCertRenewalFailing firing exactly as a rename would.
		Expect(myCA.EnsureServingCert(ctx, ca.ServingConfig{Subject: "puppet.test"})).
			Error().NotTo(HaveOccurred())
		myCA.IncServingRenewalFailures()
		myCA.IncServingRenewalFailures()
		for range 3 {
			myCA.IncServingRevocationFailures()
		}

		g := gather(metrics.NewCollector(myCA))
		Expect(counterValue(g.findByLabels("puppetca_serving_cert_issued_total", nil))).
			To(Equal(1.0))
		Expect(counterValue(g.findByLabels("puppetca_serving_cert_renewal_failures_total", nil))).
			To(Equal(2.0))
		Expect(counterValue(g.findByLabels("puppetca_serving_cert_revocation_failures_total", nil))).
			To(Equal(3.0))
	})

	It("reports per-leaf metrics with issuance state", func() {
		signCert("signed-node")
		signCert("revoked-node")
		requestCert("pending-node")
		Expect(myCA.Revoke(ctx, "revoked-node")).To(Succeed())

		g := gather(metrics.NewCollector(myCA))

		signed := g.findByLabels("puppetca_leaf_certificate_info", map[string]string{"subject": "signed-node"})
		Expect(signed).NotTo(BeNil())
		Expect(labelsOf(signed)).To(HaveKeyWithValue("state", "signed"))
		Expect(labelsOf(signed)["serial"]).NotTo(BeEmpty())

		revoked := g.findByLabels("puppetca_leaf_certificate_info", map[string]string{"subject": "revoked-node"})
		Expect(revoked).NotTo(BeNil())
		Expect(labelsOf(revoked)).To(HaveKeyWithValue("state", "revoked"))

		pending := g.findByLabels("puppetca_leaf_certificate_info", map[string]string{"subject": "pending-node"})
		Expect(pending).NotTo(BeNil())
		Expect(labelsOf(pending)).To(HaveKeyWithValue("state", "requested"))
		Expect(labelsOf(pending)["serial"]).To(BeEmpty())

		// Pending requests carry no issued certificate, so they have no expiry series.
		Expect(g.findByLabels("puppetca_leaf_certificate_not_after_timestamp_seconds",
			map[string]string{"subject": "pending-node"})).To(BeNil())
		// Signed certs do.
		Expect(g.findByLabels("puppetca_leaf_certificate_not_after_timestamp_seconds",
			map[string]string{"subject": "signed-node"})).NotTo(BeNil())

		// The CRL now lists exactly the one revoked serial.
		Expect(gaugeValue(g.findByLabels("puppetca_crl_revoked_certificates", nil))).To(Equal(1.0))

		// Aggregate per-state counts.
		Expect(gaugeValue(g.findByLabels("puppetca_leaf_certificates",
			map[string]string{"state": "signed"}))).To(Equal(1.0))
		Expect(gaugeValue(g.findByLabels("puppetca_leaf_certificates",
			map[string]string{"state": "revoked"}))).To(Equal(1.0))
		Expect(gaugeValue(g.findByLabels("puppetca_leaf_certificates",
			map[string]string{"state": "requested"}))).To(Equal(1.0))
	})

	It("excludes cleaned (deleted) certificates from the live set", func() {
		signCert("keep-node")
		signCert("clean-node")
		Expect(myCA.Clean(ctx, "clean-node")).To(Succeed())

		g := gather(metrics.NewCollector(myCA))

		Expect(g.findByLabels("puppetca_leaf_certificate_info",
			map[string]string{"subject": "keep-node"})).NotTo(BeNil())
		Expect(g.findByLabels("puppetca_leaf_certificate_info",
			map[string]string{"subject": "clean-node"})).To(BeNil())
	})

	It("exposes Go and process collectors plus HTTP request metrics via the exporter", func() {
		exp := metrics.NewExporter(myCA)
		mfs, err := exp.Registry().Gather()
		Expect(err).NotTo(HaveOccurred())

		names := map[string]bool{}
		for _, mf := range mfs {
			names[mf.GetName()] = true
		}
		Expect(names).To(HaveKey("go_goroutines"))
		Expect(names).To(HaveKey("puppetca_ca_certificate_info"))
		Expect(names).To(HaveKey("puppetca_http_requests_in_flight"))
	})
})
