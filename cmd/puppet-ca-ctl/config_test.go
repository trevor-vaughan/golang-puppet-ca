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
	"os"
	"path/filepath"
	"testing"
)

// ctlEnvVars is the full list of env vars read by applyCtlEnv.
var ctlEnvVars = []string{
	"PUPPET_CA_CTL_SERVER_URL",
	"PUPPET_CA_CTL_CA_CERT",
	"PUPPET_CA_CTL_CLIENT_CERT",
	"PUPPET_CA_CTL_CLIENT_KEY",
	"PUPPET_CA_CTL_VERBOSE",
}

// clearCtlEnv unsets all PUPPET_CA_CTL_* vars and restores them after the test.
func clearCtlEnv(t *testing.T) {
	t.Helper()
	for _, key := range ctlEnvVars {
		t.Setenv(key, "") // t.Setenv restores; empty string is treated as unset by applyCtlEnv
	}
}

// --- resolveConfigFile ---

func TestResolveConfigFile(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "exists.yaml")
	if err := os.WriteFile(existing, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing.yaml")

	const envKey = "PUPPET_CA_CTL_CONFIG_TEST_RESOLVE"

	tests := []struct {
		name        string
		cliFlag     string
		envVal      string
		defaultPath string
		want        string
	}{
		{
			name:        "cli flag wins over env and default",
			cliFlag:     "/cli/path.yaml",
			envVal:      "/env/path.yaml",
			defaultPath: existing,
			want:        "/cli/path.yaml",
		},
		{
			name:        "env var used when no cli flag",
			envVal:      "/env/path.yaml",
			defaultPath: existing,
			want:        "/env/path.yaml",
		},
		{
			name:        "default path used when it exists",
			defaultPath: existing,
			want:        existing,
		},
		{
			name:        "empty when default does not exist",
			defaultPath: missing,
			want:        "",
		},
		{
			name: "empty when nothing provided",
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envKey, tc.envVal)
			got := resolveConfigFile(tc.cliFlag, envKey, tc.defaultPath)
			if got != tc.want {
				t.Errorf("resolveConfigFile(%q, %q, %q) = %q; want %q",
					tc.cliFlag, envKey, tc.defaultPath, got, tc.want)
			}
		})
	}
}

// --- loadCtlConfig: built-in defaults ---

func TestLoadCtlConfigDefaults(t *testing.T) {
	clearCtlEnv(t)

	cfg, err := loadCtlConfig("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ServerURL != "https://localhost:8140" {
		t.Errorf("ServerURL = %q; want https://localhost:8140", cfg.ServerURL)
	}
	if cfg.CACert != "" {
		t.Errorf("CACert = %q; want empty", cfg.CACert)
	}
	if cfg.ClientCert != "" {
		t.Errorf("ClientCert = %q; want empty", cfg.ClientCert)
	}
	if cfg.ClientKey != "" {
		t.Errorf("ClientKey = %q; want empty", cfg.ClientKey)
	}
	if cfg.Verbose {
		t.Error("Verbose = true; want false")
	}
}

// --- loadCtlConfig: YAML file ---

func TestLoadCtlConfigYAML(t *testing.T) {
	clearCtlEnv(t)

	content := `
server_url: https://puppet-ca:8140
ca_cert: /etc/ssl/ca.pem
client_cert: /etc/ssl/client.pem
client_key: /etc/ssl/client_key.pem
verbose: true
`
	cfgFile := writeTempCtlConfig(t, content)

	cfg, err := loadCtlConfig(cfgFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	checks := []struct {
		field string
		got   interface{}
		want  interface{}
	}{
		{"ServerURL", cfg.ServerURL, "https://puppet-ca:8140"},
		{"CACert", cfg.CACert, "/etc/ssl/ca.pem"},
		{"ClientCert", cfg.ClientCert, "/etc/ssl/client.pem"},
		{"ClientKey", cfg.ClientKey, "/etc/ssl/client_key.pem"},
		{"Verbose", cfg.Verbose, true},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v; want %v", c.field, c.got, c.want)
		}
	}
}

// TestLoadCtlConfigYAMLPartial verifies that unset YAML keys keep built-in defaults.
func TestLoadCtlConfigYAMLPartial(t *testing.T) {
	clearCtlEnv(t)

	cfgFile := writeTempCtlConfig(t, "server_url: https://myserver:9000\n")
	cfg, err := loadCtlConfig(cfgFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ServerURL != "https://myserver:9000" {
		t.Errorf("ServerURL = %q; want https://myserver:9000", cfg.ServerURL)
	}
	if cfg.Verbose {
		t.Error("Verbose = true; want default false")
	}
}

// --- loadCtlConfig: env vars override YAML ---

func TestLoadCtlConfigEnvOverridesYAML(t *testing.T) {
	clearCtlEnv(t)

	cfgFile := writeTempCtlConfig(t, "server_url: https://from-file:8140\n")
	t.Setenv("PUPPET_CA_CTL_SERVER_URL", "https://from-env:9999")

	cfg, err := loadCtlConfig(cfgFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ServerURL != "https://from-env:9999" {
		t.Errorf("ServerURL = %q; want env value https://from-env:9999", cfg.ServerURL)
	}
}

// --- loadCtlConfig: error cases ---

func TestLoadCtlConfigMissingFile(t *testing.T) {
	_, err := loadCtlConfig("/nonexistent/path/ctl.yaml")
	if err == nil {
		t.Error("expected error for missing config file, got nil")
	}
}

func TestLoadCtlConfigInvalidYAML(t *testing.T) {
	cfgFile := writeTempCtlConfig(t, "server_url: [unclosed\n")
	_, err := loadCtlConfig(cfgFile)
	if err == nil {
		t.Error("expected error for invalid YAML, got nil")
	}
}

// --- applyCtlEnv: each variable ---

func TestApplyCtlEnvEachVar(t *testing.T) {
	tests := []struct {
		name   string
		envKey string
		envVal string
		check  func(*ctlConfig) bool
		desc   string
	}{
		{
			name: "SERVER_URL", envKey: "PUPPET_CA_CTL_SERVER_URL", envVal: "https://myhost:8140",
			check: func(c *ctlConfig) bool { return c.ServerURL == "https://myhost:8140" },
			desc:  "ServerURL",
		},
		{
			name: "CA_CERT", envKey: "PUPPET_CA_CTL_CA_CERT", envVal: "/etc/ssl/ca.pem",
			check: func(c *ctlConfig) bool { return c.CACert == "/etc/ssl/ca.pem" },
			desc:  "CACert",
		},
		{
			name: "CLIENT_CERT", envKey: "PUPPET_CA_CTL_CLIENT_CERT", envVal: "/etc/ssl/cert.pem",
			check: func(c *ctlConfig) bool { return c.ClientCert == "/etc/ssl/cert.pem" },
			desc:  "ClientCert",
		},
		{
			name: "CLIENT_KEY", envKey: "PUPPET_CA_CTL_CLIENT_KEY", envVal: "/etc/ssl/key.pem",
			check: func(c *ctlConfig) bool { return c.ClientKey == "/etc/ssl/key.pem" },
			desc:  "ClientKey",
		},
		{
			name: "VERBOSE_true", envKey: "PUPPET_CA_CTL_VERBOSE", envVal: "true",
			check: func(c *ctlConfig) bool { return c.Verbose },
			desc:  "Verbose=true",
		},
		{
			name: "VERBOSE_1", envKey: "PUPPET_CA_CTL_VERBOSE", envVal: "1",
			check: func(c *ctlConfig) bool { return c.Verbose },
			desc:  "Verbose=1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clearCtlEnv(t)
			t.Setenv(tc.envKey, tc.envVal)
			cfg := &ctlConfig{}
			applyCtlEnv(cfg)
			if !tc.check(cfg) {
				t.Errorf("%s not applied from %s=%s", tc.desc, tc.envKey, tc.envVal)
			}
		})
	}
}

// TestApplyCtlEnvInvalidValues verifies that a malformed VERBOSE value is silently ignored.
func TestApplyCtlEnvInvalidValues(t *testing.T) {
	clearCtlEnv(t)
	t.Setenv("PUPPET_CA_CTL_VERBOSE", "maybe")

	cfg := &ctlConfig{}
	applyCtlEnv(cfg)

	if cfg.Verbose {
		t.Error("Verbose changed on bad input: want false")
	}
}

// --- helper ---

func writeTempCtlConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ctl.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}
