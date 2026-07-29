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

// Package metrics exposes a Prometheus exporter for the Puppet CA. In addition
// to the standard Go runtime / process collectors and HTTP request metrics
// (wired up in metrics.go), it provides a custom collector that, on every
// scrape, reports the state of the CA certificate, its CRL, and every known
// (non-deleted) leaf certificate — including issue/expiry timestamps and
// issuance status — so operators can alert on impending expiry and pending
// requests.
package metrics

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/voxpupuli/openvox-ca/internal/ca"
)

// namespace is the common Prometheus metric prefix for every CA-specific
// series. It is deliberately distinct from the Go/process collectors so that
// puppetca_* groups the exporter's domain metrics together.
const namespace = "puppetca"

// Leaf certificate issuance states reported via the `state` label. "expired" is
// intentionally not a state: expiry is derived by alerting rules from the
// not_after timestamp metric, which keeps a single source of truth and lets the
// same certificate be both signed/revoked and expired.
const (
	stateRequested = "requested" // a pending CSR with no issued certificate yet
	stateSigned    = "signed"    // an issued certificate not present in the CRL
	stateRevoked   = "revoked"   // an issued certificate listed in the CRL
)

// defaultGatherTimeout bounds a single scrape's storage access. prometheus
// Collect has no context of its own, so the collector imposes its own deadline
// to avoid a slow/unavailable backend wedging the scrape indefinitely.
const defaultGatherTimeout = 10 * time.Second

// Collector implements prometheus.Collector, translating the CA's live state
// into metrics on each scrape. It reads through the CA's StorageService, so it
// observes whichever backend (filesystem, etcd, redis, SQL) the CA is using.
type Collector struct {
	ca      *ca.CA
	timeout time.Duration

	// Descriptors, built once in NewCollector and reused on every scrape.
	scrapeSuccess  *prometheus.Desc
	scrapeDuration *prometheus.Desc
	caReady        *prometheus.Desc

	crlUpdateFailures *prometheus.Desc

	servingCertIssued      *prometheus.Desc
	servingRenewalFailures *prometheus.Desc

	caInfo      *prometheus.Desc
	caNotBefore *prometheus.Desc
	caNotAfter  *prometheus.Desc

	crlNumber     *prometheus.Desc
	crlThisUpdate *prometheus.Desc
	crlNextUpdate *prometheus.Desc
	crlRevoked    *prometheus.Desc

	leafInfo       *prometheus.Desc
	leafNotBefore  *prometheus.Desc
	leafNotAfter   *prometheus.Desc
	leafStateCount *prometheus.Desc
}

// NewCollector returns a Collector for the given CA. The CA need not be fully
// initialised yet: until it is, the exporter reports puppetca_ca_ready 0 and
// omits the CA/CRL/leaf series rather than failing the scrape.
func NewCollector(c *ca.CA) *Collector {
	return &Collector{
		ca:      c,
		timeout: defaultGatherTimeout,
		scrapeSuccess: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "collector", "scrape_success"),
			"1 if the most recent CA metrics scrape succeeded, 0 otherwise.",
			nil, nil),
		scrapeDuration: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "collector", "scrape_duration_seconds"),
			"Time taken to gather the CA, CRL and leaf certificate metrics.",
			nil, nil),
		caReady: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "ca_ready"),
			"1 when the CA has finished initialising and can serve requests, 0 otherwise.",
			nil, nil),
		crlUpdateFailures: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "crl", "update_failures_total"),
			"Total failures to amend the CRL — a revocation that could not be recorded, or a CRL "+
				"that could not be re-signed or written (across revoke, cleanup, reissue and refresh). "+
				"A rising value means the CRL is not being maintained; for revocations it means a "+
				"superseded certificate may still be a valid credential.",
			nil, nil),
		servingCertIssued: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "serving_cert", "issued_total"),
			"Total serving certificates this process has issued to itself (tls_self_provision). "+
				"A sustained rate rather than an occasional increment means replicas disagree about "+
				"which CA certificate is current, each reissuing over the other; a fleet restart resolves it.",
			nil, nil),
		servingRenewalFailures: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "serving_cert", "renewal_failures_total"),
			"Total maintenance passes that failed to renew the serving certificate. The existing "+
				"certificate stays in place and the next cycle retries, so alert on a persistent rise: "+
				"it is invisible until the certificate expires, and it breaks the bound that "+
				"tls_self_provision_revoke_after_sec relies on.",
			nil, nil),
		caInfo: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "ca_certificate", "info"),
			"Static information about the CA certificate; constant value 1.",
			[]string{"common_name", "serial", "issuer"}, nil),
		caNotBefore: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "ca_certificate", "not_before_timestamp_seconds"),
			"NotBefore (issue) time of the CA certificate, in seconds since the Unix epoch.",
			nil, nil),
		caNotAfter: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "ca_certificate", "not_after_timestamp_seconds"),
			"NotAfter (expiry) time of the CA certificate, in seconds since the Unix epoch.",
			nil, nil),
		crlNumber: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "crl", "number"),
			"Monotonically increasing CRL sequence number (X.509 cRLNumber extension).",
			nil, nil),
		crlThisUpdate: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "crl", "this_update_timestamp_seconds"),
			"ThisUpdate time of the current CRL, in seconds since the Unix epoch.",
			nil, nil),
		crlNextUpdate: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "crl", "next_update_timestamp_seconds"),
			"NextUpdate (expiry) time of the current CRL, in seconds since the Unix epoch.",
			nil, nil),
		crlRevoked: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "crl", "revoked_certificates"),
			"Number of certificates currently listed in the CRL.",
			nil, nil),
		leafInfo: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "leaf_certificate", "info"),
			"One series per known (non-deleted) leaf certificate or pending request; constant value 1. "+
				"For pending requests the serial label is empty.",
			[]string{"subject", "serial", "state"}, nil),
		leafNotBefore: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "leaf_certificate", "not_before_timestamp_seconds"),
			"NotBefore (issue) time of a leaf certificate, in seconds since the Unix epoch. "+
				"Not emitted for pending requests, which have no issued certificate.",
			[]string{"subject", "serial", "state"}, nil),
		leafNotAfter: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "leaf_certificate", "not_after_timestamp_seconds"),
			"NotAfter (expiry) time of a leaf certificate, in seconds since the Unix epoch. "+
				"Not emitted for pending requests, which have no issued certificate.",
			[]string{"subject", "serial", "state"}, nil),
		leafStateCount: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "leaf_certificates"),
			"Number of known (non-deleted) leaf certificates by issuance state.",
			[]string{"state"}, nil),
	}
}

// Describe implements prometheus.Collector. The exporter uses an unchecked
// collector model (it emits dynamic, per-certificate label sets each scrape),
// but advertising the descriptors still lets the registry detect duplicate
// metric names at registration time.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.scrapeSuccess
	ch <- c.scrapeDuration
	ch <- c.caReady
	ch <- c.crlUpdateFailures
	ch <- c.servingCertIssued
	ch <- c.servingRenewalFailures
	ch <- c.caInfo
	ch <- c.caNotBefore
	ch <- c.caNotAfter
	ch <- c.crlNumber
	ch <- c.crlThisUpdate
	ch <- c.crlNextUpdate
	ch <- c.crlRevoked
	ch <- c.leafInfo
	ch <- c.leafNotBefore
	ch <- c.leafNotAfter
	ch <- c.leafStateCount
}

// Collect implements prometheus.Collector. It gathers a fresh snapshot of CA
// state under its own deadline and emits the corresponding metrics. A gather
// failure is reported via puppetca_collector_scrape_success rather than
// aborting the whole /metrics response, so the Go/process/HTTP metrics still
// scrape even when storage is momentarily unavailable.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	start := time.Now()
	snap, err := c.gather(ctx)
	duration := time.Since(start)

	ch <- prometheus.MustNewConstMetric(c.scrapeDuration, prometheus.GaugeValue, duration.Seconds())

	// This counter is an in-process event tally, independent of the storage
	// gather, so emit it even when the gather below fails — an unreadable
	// backend must not blind operators to CRL-maintenance failures.
	ch <- prometheus.MustNewConstMetric(c.crlUpdateFailures, prometheus.CounterValue,
		float64(c.ca.CRLUpdateFailures()))
	ch <- prometheus.MustNewConstMetric(c.servingCertIssued, prometheus.CounterValue,
		float64(c.ca.ServingCertIssued()))
	ch <- prometheus.MustNewConstMetric(c.servingRenewalFailures, prometheus.CounterValue,
		float64(c.ca.ServingRenewalFailureCount()))

	if err != nil {
		slog.Warn("Prometheus CA metrics scrape failed", "error", err)
		ch <- prometheus.MustNewConstMetric(c.scrapeSuccess, prometheus.GaugeValue, 0)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.scrapeSuccess, prometheus.GaugeValue, 1)

	ch <- prometheus.MustNewConstMetric(c.caReady, prometheus.GaugeValue, boolToFloat(snap.caReady))

	if snap.haveCA {
		ch <- prometheus.MustNewConstMetric(c.caInfo, prometheus.GaugeValue, 1,
			snap.caCommonName, snap.caSerial, snap.caIssuer)
		ch <- prometheus.MustNewConstMetric(c.caNotBefore, prometheus.GaugeValue, timestamp(snap.caNotBefore))
		ch <- prometheus.MustNewConstMetric(c.caNotAfter, prometheus.GaugeValue, timestamp(snap.caNotAfter))
	}

	if snap.haveCRL {
		ch <- prometheus.MustNewConstMetric(c.crlNumber, prometheus.GaugeValue, snap.crlNumber)
		ch <- prometheus.MustNewConstMetric(c.crlThisUpdate, prometheus.GaugeValue, timestamp(snap.crlThisUpdate))
		ch <- prometheus.MustNewConstMetric(c.crlNextUpdate, prometheus.GaugeValue, timestamp(snap.crlNextUpdate))
		ch <- prometheus.MustNewConstMetric(c.crlRevoked, prometheus.GaugeValue, float64(snap.crlRevokedCount))
	}

	stateCounts := map[string]int{stateRequested: 0, stateSigned: 0, stateRevoked: 0}
	for _, leaf := range snap.leaves {
		stateCounts[leaf.state]++
		ch <- prometheus.MustNewConstMetric(c.leafInfo, prometheus.GaugeValue, 1,
			leaf.subject, leaf.serial, leaf.state)
		if leaf.hasCert {
			ch <- prometheus.MustNewConstMetric(c.leafNotBefore, prometheus.GaugeValue,
				timestamp(leaf.notBefore), leaf.subject, leaf.serial, leaf.state)
			ch <- prometheus.MustNewConstMetric(c.leafNotAfter, prometheus.GaugeValue,
				timestamp(leaf.notAfter), leaf.subject, leaf.serial, leaf.state)
		}
	}
	for state, count := range stateCounts {
		ch <- prometheus.MustNewConstMetric(c.leafStateCount, prometheus.GaugeValue, float64(count), state)
	}
}

// leafCert is one row of the per-certificate snapshot.
type leafCert struct {
	subject   string
	serial    string
	state     string
	notBefore time.Time
	notAfter  time.Time
	hasCert   bool // false for pending requests (no issued certificate)
}

// snapshot is the immutable view of CA state captured by a single scrape.
type snapshot struct {
	caReady bool

	haveCA       bool
	caCommonName string
	caSerial     string
	caIssuer     string
	caNotBefore  time.Time
	caNotAfter   time.Time

	haveCRL         bool
	crlNumber       float64
	crlThisUpdate   time.Time
	crlNextUpdate   time.Time
	crlRevokedCount int

	leaves []leafCert
}

// gather reads the CA certificate, CRL and every known leaf certificate from
// storage and returns them as a snapshot. It returns an error only for failures
// that prevent enumerating certificates at all (e.g. the signed-cert listing
// fails); a missing or unparseable CRL is tolerated and simply omits the CRL
// metrics, since a freshly bootstrapped CA may not have published one yet.
func (c *Collector) gather(ctx context.Context) (snapshot, error) {
	var snap snapshot

	snap.caReady = c.ca.IsReady()
	// CACert is written once during Init and not mutated afterwards, so reading
	// it after IsReady reports true is safe without holding the CA lock.
	if snap.caReady && c.ca.CACert != nil {
		cert := c.ca.CACert
		snap.haveCA = true
		snap.caCommonName = cert.Subject.CommonName
		snap.caSerial = serialHex(cert.SerialNumber)
		snap.caIssuer = cert.Issuer.CommonName
		snap.caNotBefore = cert.NotBefore
		snap.caNotAfter = cert.NotAfter
	}

	// Parse the CRL once. The set of revoked serials drives leaf state below, so
	// we avoid CA.IsRevoked (which re-reads and re-parses each cert from storage).
	revoked := map[string]bool{}
	if crlPEM, err := c.ca.Storage.GetCRL(ctx); err == nil {
		if crl, perr := parseCRL(crlPEM); perr == nil {
			snap.haveCRL = true
			if crl.Number != nil {
				// CRL numbers can exceed float64's exact-integer range in theory;
				// in practice they are small counters, so float64 is fine and
				// keeps the metric a plain gauge.
				snap.crlNumber, _ = new(big.Float).SetInt(crl.Number).Float64()
			}
			snap.crlThisUpdate = crl.ThisUpdate
			snap.crlNextUpdate = crl.NextUpdate
			snap.crlRevokedCount = len(crl.RevokedCertificateEntries)
			for _, entry := range crl.RevokedCertificateEntries {
				revoked[serialHex(entry.SerialNumber)] = true
			}
		} else {
			slog.Warn("Prometheus exporter: failed to parse CRL", "error", perr)
		}
	}

	// Signed certificates: enumerate the live (non-deleted) signed set. A cleaned
	// certificate is removed from this listing even though its inventory line
	// persists, which is exactly the "known (non-deleted)" set the operator wants.
	signed, err := c.ca.Storage.ListCerts(ctx)
	if err != nil {
		return snapshot{}, fmt.Errorf("listing signed certificates: %w", err)
	}
	seen := make(map[string]bool, len(signed))
	for _, subject := range signed {
		seen[subject] = true
		certPEM, err := c.ca.Storage.GetCert(ctx, subject)
		if err != nil {
			// The cert was deleted between listing and reading, or is briefly
			// unreadable; skip it rather than failing the whole scrape.
			slog.Debug("Prometheus exporter: skipping unreadable certificate", "subject", subject, "error", err)
			continue
		}
		cert, err := parseCert(certPEM)
		if err != nil {
			slog.Warn("Prometheus exporter: skipping unparseable certificate", "subject", subject, "error", err)
			continue
		}
		serial := serialHex(cert.SerialNumber)
		state := stateSigned
		if revoked[serial] {
			state = stateRevoked
		}
		snap.leaves = append(snap.leaves, leafCert{
			subject:   subject,
			serial:    serial,
			state:     state,
			notBefore: cert.NotBefore,
			notAfter:  cert.NotAfter,
			hasCert:   true,
		})
	}

	// Pending requests: CSRs without a corresponding signed certificate. These
	// carry no issued cert, so only the info/count series describe them.
	pending, err := c.ca.Storage.ListCSRs(ctx)
	if err != nil {
		return snapshot{}, fmt.Errorf("listing certificate requests: %w", err)
	}
	for _, subject := range pending {
		if seen[subject] {
			continue
		}
		snap.leaves = append(snap.leaves, leafCert{
			subject: subject,
			state:   stateRequested,
		})
	}

	return snap, nil
}

// parseCert decodes a PEM-encoded X.509 certificate.
func parseCert(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

// parseCRL decodes a PEM-encoded X.509 CRL.
func parseCRL(pemData []byte) (*x509.RevocationList, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseRevocationList(block.Bytes)
}

// serialHex formats a serial number as uppercase hexadecimal without leading
// zeros, matching the representation used in the CA's inventory file and CRL so
// that labels line up with the operator's other tooling.
func serialHex(n *big.Int) string {
	return fmt.Sprintf("%X", n)
}

// timestamp renders t as fractional seconds since the Unix epoch, the
// convention for Prometheus *_timestamp_seconds gauges. A zero time yields 0.
func timestamp(t time.Time) float64 {
	if t.IsZero() {
		return 0
	}
	return float64(t.UnixNano()) / 1e9
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
