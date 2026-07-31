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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Config.needsDefaultNamespace", func() {
	It("is false when every target sets its own namespace", func() {
		cfg := Config{Targets: []Target{
			{Metadata: Metadata{Name: "a", Namespace: "ns1"}},
			{Metadata: Metadata{Name: "b", Namespace: "ns2"}},
		}}
		Expect(cfg.needsDefaultNamespace()).To(BeFalse())
	})

	It("is true when any target omits its namespace", func() {
		cfg := Config{Targets: []Target{
			{Metadata: Metadata{Name: "a", Namespace: "ns1"}},
			{Metadata: Metadata{Name: "b"}},
		}}
		Expect(cfg.needsDefaultNamespace()).To(BeTrue())
	})
})

var _ = Describe("newChecked", func() {
	// The wiring, as distinct from the check itself: NewInCluster needs a real
	// ServiceAccount mount, so this is the deepest a spec can reach. Dropping
	// the CheckDistinctObjects call leaves the check's own specs green while the
	// collision it exists for sails through to runtime.
	It("refuses a collision only visible once the namespace resolves", func() {
		cfg := Config{Targets: []Target{
			{Kind: "Secret", Metadata: Metadata{Name: "trust"}, Cert: true},
			{Kind: "Secret", Metadata: Metadata{Name: "trust", Namespace: "ns1"}, CRL: true},
		}}
		Expect(cfg.Validate()).To(Succeed())

		_, err := newChecked(nil, cfg, nil, "ns1", nil)
		Expect(err).To(MatchError(ContainSubstring("both resolve to")))

		// Marked as a configuration error, not an environmental one: the caller
		// routes on that, and without the marking a collision is logged as a
		// client-init failure and the whole export is silently disabled for the
		// life of the process, writing no series for the alert to fire on.
		Expect(err).To(MatchError(ErrInvalidConfig))
	})

	It("builds an exporter when the objects are genuinely distinct", func() {
		cfg := Config{Targets: []Target{
			{Kind: "Secret", Metadata: Metadata{Name: "trust"}, Cert: true},
			{Kind: "Secret", Metadata: Metadata{Name: "serving", Namespace: "ns1"}, CRL: true},
		}}
		Expect(cfg.Validate()).To(Succeed())
		Expect(newChecked(nil, cfg, nil, "ns1", nil)).Error().NotTo(HaveOccurred())
	})
})
