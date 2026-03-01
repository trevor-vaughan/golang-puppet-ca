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

import (
	"crypto/rsa"
	"crypto/x509"
	"sync"

	"github.com/tvaughan/puppet-ca/internal/storage"
)

type CA struct {
	Storage        *storage.StorageService
	CACert         *x509.Certificate
	CAKey          *rsa.PrivateKey
	AutosignConfig AutosignConfig
	Hostname       string
	// OCSPURLs, when non-nil, causes newly issued certs to embed an AIA extension
	// pointing at the OCSP responder. Set before calling Init().
	OCSPURLs    []string
	serialIndex map[string]string         // padded uppercase hex serial → subject; protected by mu
	ocspCache   map[string]ocspCacheEntry // same key; protected by mu
	mu          sync.RWMutex
}

func New(s *storage.StorageService, autosignCfg AutosignConfig, hostname string) *CA {
	return &CA{
		Storage:        s,
		AutosignConfig: autosignCfg,
		Hostname:       hostname,
		serialIndex:    make(map[string]string),
		ocspCache:      make(map[string]ocspCacheEntry),
	}
}

// IsReady reports whether the CA has been fully initialized and can serve requests.
func (c *CA) IsReady() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.CACert != nil && c.CAKey != nil
}
