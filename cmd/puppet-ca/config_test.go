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

// serverEnvVars is the full list of env vars read by applyServerEnv.
var serverEnvVars = []string{
	"PUPPET_CA_CADIR",
	"PUPPET_CA_AUTOSIGN_CONFIG",
	"PUPPET_CA_HOST",
	"PUPPET_CA_PORT",
	"PUPPET_CA_HOSTNAME",
	"PUPPET_CA_VERBOSITY",
	"PUPPET_CA_LOGFILE",
	"PUPPET_CA_TLS_CERT",
	"PUPPET_CA_TLS_KEY",
	"PUPPET_CA_PUPPET_SERVER",
	"PUPPET_CA_NO_TLS_REQUIRED",
	"PUPPET_CA_OCSP_URL",
}

// clearServerEnv unsets all PUPPET_CA_* vars and restores them after the test.
func clearServerEnv(t *testing.T) {
	t.Helper()
	for _, key := range serverEnvVars {
		t.Setenv(key, "") // t.Setenv restores; empty string is treated as unset by applyServerEnv
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

	const envKey = "PUPPET_CA_CONFIG_TEST_RESOLVE"

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

// --- loadServerConfig: built-in defaults ---

func TestLoadServerConfigDefaults(t *testing.T) {
	clearServerEnv(t)

	cfg, err := loadServerConfig("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Host != "0.0.0.0" {
		t.Errorf("Host = %q; want 0.0.0.0", cfg.Host)
	}
	if cfg.Port != 8140 {
		t.Errorf("Port = %d; want 8140", cfg.Port)
	}
	if cfg.CADir != "" {
		t.Errorf("CADir = %q; want empty", cfg.CADir)
	}
	if cfg.NoTLSRequired {
		t.Error("NoTLSRequired = true; want false")
	}
	if cfg.Verbosity != 0 {
		t.Errorf("Verbosity = %d; want 0", cfg.Verbosity)
	}
}

// --- loadServerConfig: YAML file ---

func TestLoadServerConfigYAML(t *testing.T) {
	clearServerEnv(t)

	content := `
cadir: /tmp/myca
host: 127.0.0.1
port: 9090
hostname: myhost
no_tls_required: true
tls_cert: /etc/ssl/cert.pem
tls_key: /etc/ssl/key.pem
puppet_server: puppet-master
autosign_config: "true"
logfile: /var/log/puppet-ca.log
verbosity: 1
ocsp_url: http://ocsp.example.com/ocsp
`
	cfgFile := writeTempConfig(t, content)

	cfg, err := loadServerConfig(cfgFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	checks := []struct {
		field string
		got   interface{}
		want  interface{}
	}{
		{"CADir", cfg.CADir, "/tmp/myca"},
		{"Host", cfg.Host, "127.0.0.1"},
		{"Port", cfg.Port, 9090},
		{"Hostname", cfg.Hostname, "myhost"},
		{"NoTLSRequired", cfg.NoTLSRequired, true},
		{"TLSCert", cfg.TLSCert, "/etc/ssl/cert.pem"},
		{"TLSKey", cfg.TLSKey, "/etc/ssl/key.pem"},
		{"PuppetServer", cfg.PuppetServer, "puppet-master"},
		{"AutosignConfig", cfg.AutosignConfig, "true"},
		{"LogFile", cfg.LogFile, "/var/log/puppet-ca.log"},
		{"Verbosity", cfg.Verbosity, 1},
		{"OCSPUrl", cfg.OCSPUrl, "http://ocsp.example.com/ocsp"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v; want %v", c.field, c.got, c.want)
		}
	}
}

// TestLoadServerConfigYAMLPartial verifies that unset YAML keys keep built-in defaults.
func TestLoadServerConfigYAMLPartial(t *testing.T) {
	clearServerEnv(t)

	cfgFile := writeTempConfig(t, "cadir: /tmp/partial\n")
	cfg, err := loadServerConfig(cfgFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Host != "0.0.0.0" {
		t.Errorf("Host = %q; want default 0.0.0.0", cfg.Host)
	}
	if cfg.Port != 8140 {
		t.Errorf("Port = %d; want default 8140", cfg.Port)
	}
	if cfg.CADir != "/tmp/partial" {
		t.Errorf("CADir = %q; want /tmp/partial", cfg.CADir)
	}
}

// --- loadServerConfig: env vars override YAML ---

func TestLoadServerConfigEnvOverridesYAML(t *testing.T) {
	clearServerEnv(t)

	cfgFile := writeTempConfig(t, "host: 10.0.0.1\nport: 9090\n")
	t.Setenv("PUPPET_CA_HOST", "192.168.1.1")
	t.Setenv("PUPPET_CA_PORT", "7777")

	cfg, err := loadServerConfig(cfgFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Host != "192.168.1.1" {
		t.Errorf("Host = %q; want env value 192.168.1.1", cfg.Host)
	}
	if cfg.Port != 7777 {
		t.Errorf("Port = %d; want env value 7777", cfg.Port)
	}
}

// --- loadServerConfig: error cases ---

func TestLoadServerConfigMissingFile(t *testing.T) {
	_, err := loadServerConfig("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("expected error for missing config file, got nil")
	}
}

func TestLoadServerConfigInvalidYAML(t *testing.T) {
	cfgFile := writeTempConfig(t, "host: [unclosed\n")
	_, err := loadServerConfig(cfgFile)
	if err == nil {
		t.Error("expected error for invalid YAML, got nil")
	}
}

// --- applyServerEnv: each variable ---

func TestApplyServerEnvEachVar(t *testing.T) {
	tests := []struct {
		name   string
		envKey string
		envVal string
		check  func(*serverConfig) bool
		desc   string
	}{
		{
			name: "CADIR", envKey: "PUPPET_CA_CADIR", envVal: "/some/dir",
			check: func(c *serverConfig) bool { return c.CADir == "/some/dir" },
			desc:  "CADir",
		},
		{
			name: "AUTOSIGN_CONFIG", envKey: "PUPPET_CA_AUTOSIGN_CONFIG", envVal: "true",
			check: func(c *serverConfig) bool { return c.AutosignConfig == "true" },
			desc:  "AutosignConfig",
		},
		{
			name: "HOST", envKey: "PUPPET_CA_HOST", envVal: "1.2.3.4",
			check: func(c *serverConfig) bool { return c.Host == "1.2.3.4" },
			desc:  "Host",
		},
		{
			name: "PORT", envKey: "PUPPET_CA_PORT", envVal: "9999",
			check: func(c *serverConfig) bool { return c.Port == 9999 },
			desc:  "Port",
		},
		{
			name: "HOSTNAME", envKey: "PUPPET_CA_HOSTNAME", envVal: "puppet.test",
			check: func(c *serverConfig) bool { return c.Hostname == "puppet.test" },
			desc:  "Hostname",
		},
		{
			name: "VERBOSITY", envKey: "PUPPET_CA_VERBOSITY", envVal: "2",
			check: func(c *serverConfig) bool { return c.Verbosity == 2 },
			desc:  "Verbosity",
		},
		{
			name: "LOGFILE", envKey: "PUPPET_CA_LOGFILE", envVal: "/var/log/puppet.log",
			check: func(c *serverConfig) bool { return c.LogFile == "/var/log/puppet.log" },
			desc:  "LogFile",
		},
		{
			name: "TLS_CERT", envKey: "PUPPET_CA_TLS_CERT", envVal: "/etc/tls/cert.pem",
			check: func(c *serverConfig) bool { return c.TLSCert == "/etc/tls/cert.pem" },
			desc:  "TLSCert",
		},
		{
			name: "TLS_KEY", envKey: "PUPPET_CA_TLS_KEY", envVal: "/etc/tls/key.pem",
			check: func(c *serverConfig) bool { return c.TLSKey == "/etc/tls/key.pem" },
			desc:  "TLSKey",
		},
		{
			name: "PUPPET_SERVER", envKey: "PUPPET_CA_PUPPET_SERVER", envVal: "puppet-master",
			check: func(c *serverConfig) bool { return c.PuppetServer == "puppet-master" },
			desc:  "PuppetServer",
		},
		{
			name: "NO_TLS_REQUIRED_true", envKey: "PUPPET_CA_NO_TLS_REQUIRED", envVal: "true",
			check: func(c *serverConfig) bool { return c.NoTLSRequired },
			desc:  "NoTLSRequired=true",
		},
		{
			name: "NO_TLS_REQUIRED_1", envKey: "PUPPET_CA_NO_TLS_REQUIRED", envVal: "1",
			check: func(c *serverConfig) bool { return c.NoTLSRequired },
			desc:  "NoTLSRequired=1",
		},
		{
			name: "OCSP_URL", envKey: "PUPPET_CA_OCSP_URL", envVal: "http://ocsp.example.com",
			check: func(c *serverConfig) bool { return c.OCSPUrl == "http://ocsp.example.com" },
			desc:  "OCSPUrl",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clearServerEnv(t)
			t.Setenv(tc.envKey, tc.envVal)
			cfg := &serverConfig{}
			applyServerEnv(cfg)
			if !tc.check(cfg) {
				t.Errorf("%s not applied from %s=%s", tc.desc, tc.envKey, tc.envVal)
			}
		})
	}
}

// TestApplyServerEnvInvalidValues verifies that malformed values are silently ignored.
func TestApplyServerEnvInvalidValues(t *testing.T) {
	clearServerEnv(t)
	t.Setenv("PUPPET_CA_PORT", "not-a-number")
	t.Setenv("PUPPET_CA_VERBOSITY", "bad")
	t.Setenv("PUPPET_CA_NO_TLS_REQUIRED", "maybe")

	cfg := &serverConfig{Port: 8140, Verbosity: 0}
	applyServerEnv(cfg)

	if cfg.Port != 8140 {
		t.Errorf("Port changed on bad input: got %d, want 8140", cfg.Port)
	}
	if cfg.Verbosity != 0 {
		t.Errorf("Verbosity changed on bad input: got %d, want 0", cfg.Verbosity)
	}
	if cfg.NoTLSRequired {
		t.Error("NoTLSRequired changed on bad input: want false")
	}
}

// --- helper ---

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}
