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

package main

import (
	"fmt"
	"os"
	"strconv"

	"go.yaml.in/yaml/v3"
)

// ctlConfig holds all configuration for puppet-ca-ctl.
// Fields are populated from (lowest → highest priority):
//
//	built-in defaults → config file → env vars → CLI flags
type ctlConfig struct {
	ServerURL  string `yaml:"server_url"`
	CACert     string `yaml:"ca_cert"`
	ClientCert string `yaml:"client_cert"`
	ClientKey  string `yaml:"client_key"`
	Verbose    bool   `yaml:"verbose"`
}

// loadCtlConfig applies built-in defaults, optionally loads a YAML config
// file, then overlays environment variables. configFile may be "" to skip file
// loading.
func loadCtlConfig(configFile string) (*ctlConfig, error) {
	cfg := &ctlConfig{
		ServerURL: "https://localhost:8140",
	}

	if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err != nil {
			return nil, fmt.Errorf("reading config file %s: %w", configFile, err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parsing config file %s: %w", configFile, err)
		}
	}

	applyCtlEnv(cfg)
	return cfg, nil
}

// applyCtlEnv overlays PUPPET_CA_CTL_* environment variables onto cfg.
func applyCtlEnv(cfg *ctlConfig) {
	if v := os.Getenv("PUPPET_CA_CTL_SERVER_URL"); v != "" {
		cfg.ServerURL = v
	}
	if v := os.Getenv("PUPPET_CA_CTL_CA_CERT"); v != "" {
		cfg.CACert = v
	}
	if v := os.Getenv("PUPPET_CA_CTL_CLIENT_CERT"); v != "" {
		cfg.ClientCert = v
	}
	if v := os.Getenv("PUPPET_CA_CTL_CLIENT_KEY"); v != "" {
		cfg.ClientKey = v
	}
	if v := os.Getenv("PUPPET_CA_CTL_VERBOSE"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Verbose = b
		}
	}
}

// resolveConfigFile returns the config file path to use:
// cliFlag → envVar → defaultPath (if it exists) → "".
func resolveConfigFile(cliFlag, envVar, defaultPath string) string {
	if cliFlag != "" {
		return cliFlag
	}
	if v := os.Getenv(envVar); v != "" {
		return v
	}
	if _, err := os.Stat(defaultPath); err == nil {
		return defaultPath
	}
	return ""
}
