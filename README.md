# puppet-ca

---

> 🤖 LLM/AI WARNING 🤖
>
> This project was largely written by [Claude](https://claude.ai/) using Sonnet
> 4.5. It has been reviewed and tested, but use in production at your own
> discretion.
>
> 🤖 LLM/AI WARNING 🤖

---

A drop-in replacement for Puppet Server's built-in CA, written in Go. It implements the same HTTP API that Puppet agents and `puppet cert` / `puppetserver ca` tooling use, backed by a flat-file certificate store compatible with existing Puppet CA directories.

## Features

- **Full Puppet CA API compatibility** — all 13 endpoints used by agents and puppet-server
- **Flat-file storage** — reads/writes the same directory layout as Puppet Server
- **Autosigning** — `true`, glob-pattern file, or executable plugin modes
- **mTLS support** — optional HTTPS with per-endpoint tier-based client certificate authorization
- **CA import** — replace a bootstrapped CA with an external cert/key pair offline
- **Server-side key generation** — issue cert+key pairs without a node-submitted CSR
- **FIPS-compatible** — standard library only (`crypto/x509`, `net/http`); no CGO by default
- **`puppet-ca-ctl`** — operator CLI matching `tvaughan-server-ca` subcommands

## Building

Requirements: Go 1.25+, [Mage](https://magefile.org/)

```bash
git clone https://github.com/tvaughan/puppet-ca.git
cd puppet-ca

# Build both binaries to bin/
mage build:all

# Or with plain Go
go build -o bin/puppet-ca     ./cmd/puppet-ca
go build -o bin/puppet-ca-ctl ./cmd/puppet-ca-ctl
```

### FIPS build (Linux/amd64)

```bash
mage build:fips   # → bin/puppet-ca-fips  (GOEXPERIMENT=boringcrypto)
```

## puppet-ca — the server

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `""` | Path to YAML config file (auto-detected at `/etc/puppet-ca/config.yaml`) |
| `--cadir` | `""` | CA storage directory (keys, certs, CSRs, CRL) — required via flag, env, or config |
| `--host` | `0.0.0.0` | Listen address |
| `--port` | `8140` | Listen port |
| `--hostname` | `puppet` | CN suffix for a bootstrapped CA (`Puppet CA: <hostname>`) |
| `--autosign-config` | `""` | Autosign mode: `true`, `false`, or path to a file/executable |
| `--tls-cert` | `""` | Server TLS certificate PEM (enables HTTPS when set with `--tls-key`) |
| `--tls-key` | `""` | Server TLS private key PEM |
| `--puppet-server` | `""` | Comma-separated CNs granted admin API access (mTLS only) |
| `--no-tls-required` | `false` | Allow plain HTTP on non-loopback addresses; use only behind a trusted TLS proxy or in test environments |
| `--daemon` | `false` | Fork to background (not recommended in containers) |
| `--logfile` | `""` | Write JSON logs to this file instead of stderr |
| `--verbosity` / `-v` | `0` | Verbosity: `0`=Info, `1`=Debug, `2`=Trace |

### Configuration

All flags can be set via a YAML config file or environment variables. Precedence
(highest → lowest): **CLI flag** → **environment variable** → **config file** → **built-in default**.

The config file is located by checking, in order:
1. `--config /path/to/config.yaml` (explicit flag)
2. `PUPPET_CA_CONFIG` environment variable
3. `/etc/puppet-ca/config.yaml` (auto-detected if the file exists)

**Example `/etc/puppet-ca/config.yaml`:**

```yaml
cadir: /etc/puppetlabs/puppet/ssl/ca
host: 0.0.0.0
port: 8140
hostname: puppet.example.com
tls_cert: /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem
tls_key:  /etc/puppetlabs/puppet/ssl/ca/ca_key.pem
puppet_server: puppet.example.com
no_tls_required: false
autosign_config: ""
logfile: ""
verbosity: 0
ocsp_url: ""
```

**Environment variables:**

| Flag | Environment variable |
|------|---------------------|
| `--cadir` | `PUPPET_CA_CADIR` |
| `--autosign-config` | `PUPPET_CA_AUTOSIGN_CONFIG` |
| `--host` | `PUPPET_CA_HOST` |
| `--port` | `PUPPET_CA_PORT` |
| `--hostname` | `PUPPET_CA_HOSTNAME` |
| `--verbosity` | `PUPPET_CA_VERBOSITY` |
| `--logfile` | `PUPPET_CA_LOGFILE` |
| `--tls-cert` | `PUPPET_CA_TLS_CERT` |
| `--tls-key` | `PUPPET_CA_TLS_KEY` |
| `--puppet-server` | `PUPPET_CA_PUPPET_SERVER` |
| `--no-tls-required` | `PUPPET_CA_NO_TLS_REQUIRED` |
| `--ocsp-url` | `PUPPET_CA_OCSP_URL` |

> **Note:** `--daemon` is intentionally excluded from config file and environment
> variable support because `PUPPET_CA_DAEMON` is used internally as the daemon fork
> signal.

Boolean env vars accept any value accepted by `strconv.ParseBool`: `1`, `t`, `true`,
`yes`, `on` (case-insensitive) to enable; `0`, `f`, `false`, `no`, `off` to disable.

### Quick start (plain HTTP, auto-bootstrap CA)

```bash
./bin/puppet-ca --cadir /etc/puppetlabs/puppet/ssl --hostname puppet.example.com
```

On first run the server bootstraps a new CA under `--cadir` and begins serving on port 8140.

### HTTPS with mTLS

```bash
./bin/puppet-ca \
  --cadir /etc/puppetlabs/puppet/ssl \
  --tls-cert /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem \
  --tls-key  /etc/puppetlabs/puppet/ssl/ca/ca_key.pem \
  --puppet-server puppet.example.com
```

When `--tls-cert` and `--tls-key` are both set, the server:
1. Presents those certs to connecting clients
2. Requests (but does not require) a client certificate from every connection
3. Enforces endpoint-level authorization (see [Authorization tiers](#authorization-tiers) below)

## Autosigning

The `--autosign-config` flag controls automatic CSR signing:

| Value | Behavior |
|-------|----------|
| `false` / `""` | Manual signing only (default) |
| `true` | Sign every incoming CSR immediately |
| `/path/to/file` (not executable) | Glob-pattern allowlist (one pattern per line, `#` comments ignored) |
| `/path/to/script` (executable) | Custom plugin: called with `argv[1]=CN`, CSR PEM on stdin; exit 0 = sign, non-zero = hold |

Allowlist example:

```
# autosign.conf
*.agent.example.com
compile-*.internal
```

Executable plugin example:

```bash
#!/bin/bash
subject="$1"
csr_pem=$(cat)
# approve only nodes whose name starts with "web-"
[[ "$subject" == web-* ]] && exit 0 || exit 1
```

## Directory layout

```
<cadir>/
  ca_crt.pem          CA certificate
  ca_pub.pem          CA public key
  ca_crl.pem          Certificate Revocation List
  serial              Next serial number (hex)
  inventory.txt       Signed certificate log
  signed/             Issued certificates
  requests/           Pending CSRs
  private/
    ca_key.pem        CA private key  (mode 0640)
    {subject}_key.pem Server-side generated private keys (mode 0640)
```

## API reference

All endpoints are served under both the bare path and `/puppet-ca/v1/<path>`, so the server can be used directly by agents or placed behind a proxy that strips the prefix.

### Certificate status

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/certificate_status/{subject}` | Get status: `signed`, `requested`, or `revoked` |
| `PUT` | `/certificate_status/{subject}` | Change state (`signed` or `revoked`); supports `cert_ttl` (seconds) |
| `DELETE` | `/certificate_status/{subject}` | Revoke + delete cert and CSR (`puppet cert clean`) |

`PUT` body:

```json
{ "desired_state": "signed", "cert_ttl": 86400 }
```

`GET` response:

```json
{
  "name": "agent.example.com",
  "state": "signed",
  "fingerprint": "AA:BB:...",
  "fingerprints": { "SHA256": "AA:BB:...", "default": "AA:BB:..." },
  "dns_alt_names": ["agent.example.com"],
  "subject_alt_names": ["agent.example.com"],
  "authorization_extensions": {},
  "serial_number": 4,
  "not_before": "2025-01-01T00:00:00Z",
  "not_after": "2030-01-01T00:00:00Z"
}
```

### Certificate statuses (list)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/certificate_statuses/{any}` | List all certificates; filter with `?state=requested\|signed\|revoked` |

### CSR management

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/certificate_request/{subject}` | Retrieve a pending CSR PEM |
| `PUT` | `/certificate_request/{subject}` | Submit a new CSR (body: raw PEM) |
| `DELETE` | `/certificate_request/{subject}` | Delete a pending CSR |

### Certificate retrieval

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/certificate/{subject}` | Retrieve a signed certificate PEM (`ca` returns the CA cert) |

### Bulk signing

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/sign` | Sign one or more CSRs; body: `{"certnames":["a","b"]}` |
| `POST` | `/sign/all` | Sign every pending CSR |

### CRL

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/certificate_revocation_list/ca` | Download the current CRL PEM |

### Expirations

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/expirations` | CA cert and CRL expiry dates |

### Server-side key generation

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/generate/{subject}` | Generate RSA key + cert server-side; optional `?dns=alt.name` |

Response:

```json
{ "private_key": "-----BEGIN RSA PRIVATE KEY-----\n...", "certificate": "-----BEGIN CERTIFICATE-----\n..." }
```

## Authorization tiers

When mTLS is enabled (both `--tls-cert` and `--tls-key` set), each endpoint requires a minimum client certificate tier:

| Tier | Required client cert | Endpoints |
|------|---------------------|-----------|
| **Public** | None | `GET /certificate/ca`, `GET /certificate/{subject}`, `GET /certificate_revocation_list/ca`, `PUT /certificate_request/{subject}` |
| **Self or admin** | Cert CN matches path subject, OR CN is in `--puppet-server` list | `GET /certificate_status/{subject}`, `GET /certificate_request/{subject}` |
| **Admin** | CN in `--puppet-server` list | All other endpoints |

In plain HTTP mode (no TLS), all endpoints are accessible without authentication.

## puppet-ca-ctl — the operator CLI

`puppet-ca-ctl` mirrors the `tvaughan-server-ca` / `puppetserver ca` subcommands and communicates with a running `puppet-ca` server over HTTP(S).

### Global flags

```
--config       ""                       Path to YAML config file (auto-detected at /etc/puppet-ca/ctl.yaml)
--server-url   https://localhost:8140   puppet-ca server URL
--ca-cert      ""                       CA cert PEM for TLS verification (omit to skip verify)
--client-cert  ""                       Client certificate PEM for mTLS
--client-key   ""                       Client private key PEM for mTLS
--verbose                               Enable debug logging
```

Global flags may be placed before or after the subcommand name.

### Configuration

All global flags can be set via a YAML config file or environment variables. Precedence
(highest → lowest): **CLI flag** → **environment variable** → **config file** → **built-in default**.

The config file is located by checking, in order:
1. `--config /path/to/ctl.yaml` (explicit flag)
2. `PUPPET_CA_CTL_CONFIG` environment variable
3. `/etc/puppet-ca/ctl.yaml` (auto-detected if the file exists)

**Example `/etc/puppet-ca/ctl.yaml`:**

```yaml
server_url:  https://puppet-ca.example.com:8140
ca_cert:     /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem
client_cert: /etc/puppetlabs/puppet/ssl/certs/puppet-master.pem
client_key:  /etc/puppetlabs/puppet/ssl/private_keys/puppet-master.pem
verbose:     false
```

**Environment variables:**

| Flag | Environment variable |
|------|---------------------|
| `--server-url` | `PUPPET_CA_CTL_SERVER_URL` |
| `--ca-cert` | `PUPPET_CA_CTL_CA_CERT` |
| `--client-cert` | `PUPPET_CA_CTL_CLIENT_CERT` |
| `--client-key` | `PUPPET_CA_CTL_CLIENT_KEY` |
| `--verbose` | `PUPPET_CA_CTL_VERBOSE` |

### Subcommands

```bash
# List pending CSRs
puppet-ca-ctl list

# List all certificates (signed, revoked, requested)
puppet-ca-ctl list --all

# Sign a pending CSR
puppet-ca-ctl sign --certname agent.example.com

# Sign all pending CSRs
puppet-ca-ctl sign --all

# Revoke a certificate
puppet-ca-ctl revoke --certname agent.example.com

# Revoke + delete cert and CSR
puppet-ca-ctl clean --certname agent.example.com

# Generate a server-side key+cert pair (key saved to ./agent.example.com_key.pem)
puppet-ca-ctl generate --certname agent.example.com
puppet-ca-ctl generate --certname agent.example.com --dns alt.example.com --out-dir /etc/ssl

# Bootstrap a new CA offline (no server required)
puppet-ca-ctl setup --cadir /etc/puppetlabs/puppet/ssl --hostname puppet.example.com

# Import an external CA cert/key offline
puppet-ca-ctl import \
  --cadir      /etc/puppetlabs/puppet/ssl \
  --cert-bundle ca_cert.pem \
  --private-key ca_key.pem \
  --crl-chain   ca_crl.pem     # optional; a new CRL is generated if omitted
```

`setup` and `import` operate **directly on the filesystem** — no running server is needed.

## Container / Compose

A `Dockerfile` and `compose.yml` are provided for development and integration testing.

```bash
# Build images and run the full integration test suite
mage test:integCompose

# integCompose + concurrency/correctness tests (DO_LOAD=true)
mage test:loadCompose

# k6 load test suite: correctness, throughput benchmarks, saturation ramp
mage test:bench

# Build binary + container image, run integration + load tests (single container)
mage test:load

# Full Puppet stack: CA (TLS) + WEBrick master + OpenVoxDB + agent
mage test:puppet
```

`test:integCompose` and `test:loadCompose` use `compose.yml` (autosign=false, TAP-format functional tests).
`test:bench` uses `compose-bench.yml` (autosign=true, k6 load runner).
`test:puppet` uses `compose-puppet.yml` — a five-service stack that validates end-to-end catalog compilation, PuppetDB reporting, exported resources, and CRL revocation using a real OpenVox 8 agent and WEBrick puppet master. The CA runs with genuine TLS (a cert with CN=puppet-ca signed by the CA itself); all inter-service traffic verifies it.

The k6 script (`test/load.js`) runs two concurrent scenarios:
- **reads** — hammers GET /certificate/ca, CRL, and expirations; ramps to 200 VUs
- **workflow** — POST /generate → GET status → GET cert → DELETE; ramps to 50 VUs (CPU-bound on RSA key generation)

Thresholds that fail the run: error rate ≥ 1%, read p95 ≥ 500 ms, workflow p95 ≥ 5 s.

`mage test:stress` uses `compose-stress.yml` and `test/stress.js`. It uses the `ramping-arrival-rate` executor to fix request rate and ramp it up until the server saturates — reads ramp to 500 req/s, writes (POST /generate) ramp to 50 req/s. There are no thresholds; the run always exits 0. Watch the k6 summary for `dropped_iterations` and p95/p99 latency inflection points to identify the ceiling.

> **Warning:** `mage test:stress` will deliberately push the server past its limits. Do not run against a shared or production instance.

## Development

```bash
# Run all unit tests
mage test:unit

# Format, vet, and tidy modules
mage dev:check

# Run integration tests (builds binary + container, starts container, tears down)
mage test:integ

# Run integration tests using the compose stack
mage test:integCompose

# Run the full Puppet stack (CA TLS + WEBrick master + OpenVoxDB + agent)
mage test:puppet

# Run k6 load tests (correctness + throughput + saturation) via compose
mage test:bench

# Find the upper-limit saturation ceiling (always exits 0 — observational)
mage test:stress
```

### File permissions

| Content | Mode |
|---------|------|
| Directories | `0750` |
| Private keys | `0640` |
| Public data (certs, CSRs, CRL, inventory) | `0644` |

The user running `puppet-ca` must own (or have write access to) `--cadir`.
