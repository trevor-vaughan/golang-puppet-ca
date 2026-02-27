// Copyright (C) 2026 Trevor Vaughan
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

import "encoding/asn1"

var (
	// OIDAIA is the Authority Information Access extension (RFC 5280 §4.2.2.1).
	OIDAIA = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}

	// OIDAdOCSP is the id-ad-ocsp access method OID (RFC 5280 §4.2.2.1 / RFC 6960)
	// used in Authority Information Access extensions to point at an OCSP responder.
	// Not to be confused with id-kp-OCSPSigning (1.3.6.1.5.5.7.3.9), which is the
	// extended key usage for delegated OCSP signing certificates.
	OIDAdOCSP = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}

	// Puppet OID Arc: 1.3.6.1.4.1.34380.1
	PuppetOIDArc = []int{1, 3, 6, 1, 4, 1, 34380, 1}

	// PuppetAuthOIDArc is the sub-arc for authorization extensions: 1.3.6.1.4.1.34380.1.3
	PuppetAuthOIDArc = []int{1, 3, 6, 1, 4, 1, 34380, 1, 3}

	// Netscape Comment OID
	OIDNetscapeComment = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 13}
)

// IsPuppetOID returns true if the OID belongs to the Puppet arc.
func IsPuppetOID(oid asn1.ObjectIdentifier) bool {
	return hasPrefix(oid, PuppetOIDArc)
}

// IsAuthOID returns true if the OID is in the Puppet authorization extension arc.
func IsAuthOID(oid asn1.ObjectIdentifier) bool {
	return hasPrefix(oid, PuppetAuthOIDArc)
}

func hasPrefix(oid asn1.ObjectIdentifier, prefix []int) bool {
	if len(oid) < len(prefix) {
		return false
	}
	for i, v := range prefix {
		if oid[i] != v {
			return false
		}
	}
	return true
}

// PuppetShortNames maps well-known Puppet OID strings to their short names.
// Covers both the regular node attribute arc (1.3.6.1.4.1.34380.1.1.*) and
// the authorization arc (1.3.6.1.4.1.34380.1.3.*).
var PuppetShortNames = map[string]string{
	// Node attributes
	"1.3.6.1.4.1.34380.1.1.1":  "pp_uuid",
	"1.3.6.1.4.1.34380.1.1.2":  "pp_instance_id",
	"1.3.6.1.4.1.34380.1.1.3":  "pp_image_name",
	"1.3.6.1.4.1.34380.1.1.4":  "pp_preshared_key",
	"1.3.6.1.4.1.34380.1.1.5":  "pp_cost_center",
	"1.3.6.1.4.1.34380.1.1.6":  "pp_product",
	"1.3.6.1.4.1.34380.1.1.7":  "pp_project",
	"1.3.6.1.4.1.34380.1.1.8":  "pp_application",
	"1.3.6.1.4.1.34380.1.1.9":  "pp_service",
	"1.3.6.1.4.1.34380.1.1.10": "pp_employee",
	"1.3.6.1.4.1.34380.1.1.11": "pp_created_by",
	"1.3.6.1.4.1.34380.1.1.12": "pp_environment",
	"1.3.6.1.4.1.34380.1.1.13": "pp_role",
	"1.3.6.1.4.1.34380.1.1.14": "pp_software_version",
	"1.3.6.1.4.1.34380.1.1.15": "pp_department",
	"1.3.6.1.4.1.34380.1.1.16": "pp_cluster",
	"1.3.6.1.4.1.34380.1.1.17": "pp_provisioner",
	"1.3.6.1.4.1.34380.1.1.18": "pp_region",
	"1.3.6.1.4.1.34380.1.1.19": "pp_datacenter",
	"1.3.6.1.4.1.34380.1.1.20": "pp_zone",
	"1.3.6.1.4.1.34380.1.1.21": "pp_network",
	"1.3.6.1.4.1.34380.1.1.22": "pp_securitypolicy",
	"1.3.6.1.4.1.34380.1.1.23": "pp_cloudplatform",
	"1.3.6.1.4.1.34380.1.1.24": "pp_apptier",
	"1.3.6.1.4.1.34380.1.1.25": "pp_hostname",
	"1.3.6.1.4.1.34380.1.1.26": "pp_owner",
	// Authorization extensions
	"1.3.6.1.4.1.34380.1.3.1":  "pp_authorization",
	"1.3.6.1.4.1.34380.1.3.2":  "pp_auth_auto_renew",
	"1.3.6.1.4.1.34380.1.3.13": "pp_auth_role",
}

// OIDKey returns the display name for an OID: its Puppet short name if known,
// otherwise the raw dotted OID string.
func OIDKey(oid asn1.ObjectIdentifier) string {
	s := oid.String()
	if short, ok := PuppetShortNames[s]; ok {
		return short
	}
	return s
}
