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

package ca

import (
	"context"
	"crypto/x509"
)

// ServingReuseReasonForTest reports why the stored serving certificate would be
// replaced: the stable code and the detail, separately.
//
// In an _test.go file so it is compiled only for tests and never becomes part
// of the shipped API. The reason codes are what an operator greps and alerts
// on, and what keeps arbitrary error text out of a routine log line, so they
// are worth asserting directly rather than by scraping the log.
func (c *CA) ServingReuseReasonForTest(ctx context.Context, cfg ServingConfig) (code, detail string) {
	_, reason := c.loadUsableServingCert(ctx, cfg)
	return reason.Code, reason.Detail
}

// StoredServingLeafForTest exposes storedServingLeaf so its counter policy can
// be pinned: a read failure counts a revocation failure, unparseable bytes do
// not. Both directions were changed in review and neither had a spec.
func (c *CA) StoredServingLeafForTest(ctx context.Context) *x509.Certificate {
	return c.storedServingLeaf(ctx)
}
