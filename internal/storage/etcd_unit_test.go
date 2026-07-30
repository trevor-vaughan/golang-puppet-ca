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

package storage

import (
	"bytes"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// These tests exercise pure helpers of the etcd backend without requiring a
// running cluster. Integration tests that spin up an embedded etcd live in
// etcd_integration_test.go behind a build tag.

var _ = Describe("EncodeDecodeBlobRoundTrip", func() {
	DescribeTable("round-trips data through encode/decode",
		func(data []byte) {
			// Truncate to nanosecond precision to match encode/decode semantics.
			when := time.Unix(0, time.Now().UnixNano())
			enc := encodeBlob(when, data)
			Expect(len(enc)).To(Equal(8+len(data)), "encoded length = %d, want %d", len(enc), 8+len(data))
			gotTime, gotData, err := decodeBlob(enc)
			Expect(err).NotTo(HaveOccurred(), "decodeBlob: %v", err)
			Expect(gotTime.Equal(when)).To(BeTrue(), "time = %v, want %v", gotTime, when)
			Expect(bytes.Equal(gotData, data)).To(BeTrue(), "data = %q, want %q", gotData, data)
		},
		Entry("nil", []byte(nil)),
		Entry("empty", []byte{}),
		Entry("hello", []byte("hello")),
		Entry("4096 bytes", bytes.Repeat([]byte{0xAB}, 4096)),
	)
})

var _ = Describe("DecodeBlobRejectsShortInput", func() {
	DescribeTable("rejects inputs shorter than the timestamp header",
		func(n int) {
			_, _, err := decodeBlob(make([]byte, n))
			Expect(err).To(HaveOccurred(), "decodeBlob(len=%d) = nil error, want error", n)
		},
		Entry("0", 0),
		Entry("1", 1),
		Entry("7", 7),
	)
})

// DecodeBlobReturnsIndependentBuffer verifies that the returned data slice
// does not alias the input buffer. The etcd and redis Get paths return this
// slice straight to callers; if it shared the client's response buffer, a
// caller modifying the slice would corrupt the client's internal state, and
// a future read of the same buffer would observe stale or torn bytes.
var _ = Describe("DecodeBlobReturnsIndependentBuffer", func() {
	It("returns a buffer that does not alias the input", func() {
		when := time.Unix(0, time.Now().UnixNano())
		original := []byte("payload-bytes")
		enc := encodeBlob(when, original)

		_, decoded, err := decodeBlob(enc)
		Expect(err).NotTo(HaveOccurred(), "decodeBlob: %v", err)

		// Mutate the source buffer; the decoded slice must not see the change.
		for i := 8; i < len(enc); i++ {
			enc[i] = 0xFF
		}
		Expect(bytes.Equal(decoded, original)).To(BeTrue(), "decoded data aliases input buffer: got %q, want %q", decoded, original)
	})
})

var _ = Describe("EtcdPhysicalKey", func() {
	b := &EtcdBackend{prefix: "/puppet-ca"}
	DescribeTable("maps logical keys to physical keys",
		func(logical, want string, wantErr bool) {
			got, err := b.physicalKey(logical)
			if wantErr {
				Expect(err).To(HaveOccurred(), "physicalKey(%q): err = %v, wantErr = %v", logical, err, wantErr)
			} else {
				Expect(err).NotTo(HaveOccurred(), "physicalKey(%q): err = %v, wantErr = %v", logical, err, wantErr)
				Expect(got).To(Equal(want), "physicalKey(%q) = %q, want %q", logical, got, want)
			}
		},
		Entry(nil, KeyCACert, "/puppet-ca/ca/cert", false),
		Entry(nil, KeyCAKey, "/puppet-ca/ca/key", false),
		Entry(nil, KeyCAPubKey, "/puppet-ca/ca/pubkey", false),
		Entry(nil, KeyCRL, "/puppet-ca/ca/crl", false),
		Entry(nil, KeySerial, "/puppet-ca/serial", false),
		Entry(nil, KeyInventory, "/puppet-ca/inventory/data", false),
		Entry(nil, KeyInventoryHMAC, "/puppet-ca/inventory/hmac", false),
		Entry(nil, KeyHMACKey, "/puppet-ca/private/hmac_key", false),
		// physicalKey fails closed on an unmapped key, so an omission from
		// etcdLayout makes the serving certificate unstorable at runtime -- on
		// exactly the backends this feature exists for -- while the unit suite
		// stays green.
		Entry(nil, KeyServingCert, "/puppet-ca/serving/cert", false),
		Entry(nil, KeyServingKey, "/puppet-ca/private/serving_key", false),
		Entry(nil, KeyServingSuperseded, "/puppet-ca/serving/superseded", false),
		Entry(nil, CSRKey("node1.example.com"), "/puppet-ca/requests/node1.example.com", false),
		Entry(nil, CertKey("node1.example.com"), "/puppet-ca/signed/node1.example.com", false),
		Entry(nil, "", "", true),
		Entry(nil, "unknown", "", true),
		Entry(nil, "../evil", "", true),
		Entry(nil, CSRKey("../evil"), "", true),
	)
})

var _ = Describe("EtcdConfigDefaults", func() {
	It("applies defaults to a zero config", func() {
		cfg := EtcdConfig{}
		cfg.applyDefaults()
		Expect(cfg.DialTimeout).To(Equal(5*time.Second), "DialTimeout = %v, want 5s", cfg.DialTimeout)
		Expect(cfg.RequestTimeout).To(Equal(5*time.Second), "RequestTimeout = %v, want 5s", cfg.RequestTimeout)
		Expect(cfg.KeyPrefix).To(Equal("/puppet-ca"), "KeyPrefix = %q, want /puppet-ca", cfg.KeyPrefix)
	})

	It("strips a trailing slash from KeyPrefix", func() {
		cfg2 := EtcdConfig{KeyPrefix: "/custom/"}
		cfg2.applyDefaults()
		Expect(cfg2.KeyPrefix).To(Equal("/custom"), "KeyPrefix trailing slash not stripped: %q", cfg2.KeyPrefix)
	})
})

var _ = Describe("EtcdBackendImplementsBackend", func() {
	It("implements Backend", func() {
		// Compile-time check via the interface.
		var _ Backend = (*EtcdBackend)(nil)
	})
})
