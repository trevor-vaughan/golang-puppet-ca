# openvox-ca

---

> 🤖 LLM/AI WARNING 🤖
>
> This project was largely written by [Claude](https://claude.ai/)
> It has been reviewed and tested, but use in production at your own discretion.
>
> 🤖 LLM/AI WARNING 🤖

---

**openvox-ca** is a drop-in replacement for the certificate authority built into
[OpenVox Server](https://voxpupuli.org/openvox/) (and its upstream, Puppet
Server), written in Go. It speaks the same HTTP API that OpenVox and Puppet
agents — and the `puppetserver ca` / `puppet ssl` tooling — already use, and
reads and writes a certificate store compatible with the existing Puppet CA
directory layout. Existing agents keep working without reconfiguration.

Run it instead of OpenVox Server's built-in (Clojure) CA when you want a small,
self-contained CA process that scales out across replicas, keeps its key in
OpenBao, exports to Kubernetes, or exposes Prometheus metrics — while remaining
wire-compatible with your existing Puppet/OpenVox fleet.

> **Migrating from OpenVox Server or Puppet Server?** See the
> [migration guide](docs/migrating-from-puppet-server.md) for step-by-step
> instructions, directory layout mapping, and CLI command translation.

## Features

- **Full Puppet CA API compatibility:** all 13 endpoints used by agents and OpenVox Server. See the [HTTP API reference](docs/api.md)
- **Pluggable storage:** filesystem (default; drop-in compatible with the OpenVox/Puppet Server CA layout), SQLite (single database file), or PostgreSQL / MySQL (MariaDB) / etcd / Redis (Valkey) for HA clusters; CA cert/key can be pinned to local files independently. See the [storage backends guide](docs/storage-backends.md)
- **Pluggable CA key custody:** keep the CA private key as a local file (default) or delegate it entirely to an OpenBao Transit secrets engine key, which never leaves OpenBao — works identically on a VM (AppRole/token) or in Kubernetes (native ServiceAccount auth, no sidecar). See [OpenBao Transit-engine CA key](docs/openbao-transit.md)
- **Autosigning:** `true`, glob-pattern file, or executable plugin modes
- **mTLS support:** optional HTTPS with per-endpoint tier-based client certificate authorization
- **CA import:** replace a bootstrapped CA with an external cert/key pair offline
- **Server-side key generation:** issue cert+key pairs without a node-submitted CSR; configurable RSA (2048/3072/4096) or ECDSA (P-256/P-384/P-521)
- **Configurable key algorithms:** CA and leaf certificates can use RSA or ECDSA; ECDSA support for both bootstrapped CAs and generated leaf certs
- **Random serial numbers:** every issued leaf certificate gets a cryptographically random 128-bit serial (CA/Browser Forum guidance)
- **CRL Distribution Points:** optionally embed a CRL URL in every issued certificate (`--crl-url`) so verifiers can automatically fetch the CRL
- **Configurable CRL validity:** control how long each published CRL is valid (`crl_validity_days`)
- **Automatic CRL refresh:** a background job re-signs the CRL before its validity lapses, so a low-churn CA never serves an expired CRL; safe across replicas (serialised on the shared CRL lock) and tunable or disablable. Operators can also force a refresh on demand via `openvox-ca-ctl reissue-crl`
- **Expired-certificate cleanup (opt-in):** a background job removes certificates that expired more than a configurable grace period ago from the inventory and the CRL (and deletes their stored signed certificate), keeping both from growing without bound as nodes are decommissioned; safe across replicas (serialised on the shared CRL lock)
- **OCSP responder:** built-in RFC 6960 OCSP responder; AIA extension embedded in issued certs when `--ocsp-url` is set; in-memory cache with nonce bypass
- **Health probes:** `/healthz/live`, `/healthz/ready`, and `/healthz/startup` endpoints for Kubernetes-style liveness/readiness checks
- **Prometheus exporter:** optional `/metrics` listener (`--metrics-listen`) exposing Go runtime/process and HTTP metrics plus CA certificate, CRL, and per–leaf-certificate expiry and issuance-status series; ships with a [Jsonnet alerting mixin](mixin/). See [metrics & monitoring](docs/metrics.md)
- **Kubernetes export (opt-in):** publish the CA certificate and/or CRL into any number of Kubernetes Secrets and ConfigMaps via in-cluster server-side apply, with configurable names, namespaces, data keys, labels, annotations, and Secret `type`; CRL-bearing objects are refreshed whenever the CRL changes. See [Kubernetes export](docs/kubernetes-export.md)
- **Helm chart:** an OCI-published chart, versioned in lockstep with the server, covering dual-stack Services, TLS-passthrough Ingress and Gateway API routes, an opt-in ServiceMonitor and network policies; the server's own settings pass straight through to its config file, so the whole configuration reference is reachable. See [deploying with Helm](docs/helm-chart.md)
- **Graceful shutdown:** `SIGTERM`/`SIGINT` drains in-flight requests with a configurable window (25s default) before exiting; deferred storage and signer cleanup always runs
- **FIPS-compatible:** the core CA uses the standard library only (`crypto/x509`, `net/http`); no CGO by default; FIPS build available via `GOEXPERIMENT=boringcrypto` (the optional Kubernetes export adds the `client-go` dependency)
- **`openvox-ca-ctl`:** operator CLI matching `puppetserver ca` subcommands. See the [operator CLI reference](docs/operator-cli.md)

## Installation

### Container images (recommended)

Prebuilt, multi-arch images are published to the GitHub Container Registry for
every release:

```console
$ docker pull ghcr.io/voxpupuli/openvox-ca:latest
```

See [container images](docs/container-images.md) for the available tags and a
`docker run` example.

### Kubernetes (Helm)

A chart is published as an OCI artefact for every release, versioned in lockstep
with the server:

```console
$ helm install openvox-ca \
    oci://ghcr.io/voxpupuli/openvox-ca-charts/openvox-ca \
    --version 0.9.0 \
    --namespace puppet --create-namespace
```

See [deploying with Helm](docs/helm-chart.md) for the guide and the
[chart README](charts/openvox-ca/README.md) for the values reference.

### Building from source

Requires Go 1.25+ and [Mage](https://magefile.org/):

```bash
git clone https://github.com/voxpupuli/openvox-ca.git
cd openvox-ca
mage build:all      # → bin/openvox-ca and bin/openvox-ca-ctl
```

Full build instructions (including the FIPS build) are in
[`CONTRIBUTING.md`](CONTRIBUTING.md#building).

## Quick start

### Plain HTTP, auto-bootstrap CA

```bash
./bin/openvox-ca --cadir /etc/puppetlabs/puppet/ssl --hostname puppet.example.com
```

On first run the server bootstraps a new CA under `--cadir` and begins serving on port 8140.

### HTTPS with mTLS

```bash
./bin/openvox-ca \
  --cadir /etc/puppetlabs/puppet/ssl \
  --tls-cert /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem \
  --tls-key  /etc/puppetlabs/puppet/ssl/ca/ca_key.pem \
  --puppet-server puppet.example.com
```

When `--tls-cert` and `--tls-key` are both set, the server:

1. Presents those certs to connecting clients
2. Requests (but does not require) a client certificate from every connection
3. Enforces endpoint-level authorization (see [Authorization tiers](docs/api.md#authorization-tiers))

Alternatively, let the CA issue and renew its own serving certificate — useful
where an external issuer cannot help, such as when the CA key is held in OpenBao
and cert-manager therefore cannot act as a CA issuer:

```bash
./bin/openvox-ca \
  --cadir /etc/puppetlabs/puppet/ssl \
  --hostname openvox-ca.example.com \
  --tls-self-provision \
  --puppet-server puppet.example.com
```

The CA's `--hostname` must be a name of its own, not one a node also holds. The
serving certificate is an ordinary node certificate issued under that name, so
sharing it with the OpenVox Server would put two certificates in one
per-subject slot. The CA refuses to start when that name is also a
`--puppet-server` CN, but it cannot detect an ordinary agent sharing it — see
[the caveat in the configuration guide](docs/configuration.md#self-provisioned-serving-certificate).

It enables HTTPS on the same terms, renews in the background, and is mutually
exclusive with `--tls-cert`/`--tls-key`. See
[self-provisioned serving certificate](docs/configuration.md#self-provisioned-serving-certificate).

The complete flag, environment-variable, and config-file reference is in
[configuring the server](docs/configuration.md).

## Documentation

| Guide | What it covers |
| --- | --- |
| [Configuring the server](docs/configuration.md) | Every flag, environment variable, config-file key; autosigning; directory layout; graceful shutdown |
| [HTTP API reference](docs/api.md) | All endpoints, authorization tiers, and admin credential resolution |
| [Operator CLI (`openvox-ca-ctl`)](docs/operator-cli.md) | The `openvox-ca-ctl` command reference |
| [Storage backends](docs/storage-backends.md) | filesystem, SQLite, PostgreSQL, MySQL, etcd, Redis/Valkey; migrating between them |
| [CA key security](docs/ca-key-security.md) | Key encryption at rest, key-custody options, PKCS#11 plans, destructive-op monitoring |
| [OpenBao Transit-engine CA key](docs/openbao-transit.md) | Delegating CA key custody to OpenBao |
| [Deploying with Helm](docs/helm-chart.md) | The `openvox-ca` chart: installation, TLS passthrough, ingress and Gateway API, monitoring |
| [Kubernetes export](docs/kubernetes-export.md) | Publishing the CA cert/CRL into Secrets and ConfigMaps |
| [Metrics & monitoring](docs/metrics.md) | The Prometheus exporter and the alerting [mixin](mixin/) |
| [Container images](docs/container-images.md) | Pulling and running the published images |
| [Migration guide](docs/migrating-from-puppet-server.md) | Replacing an OpenVox/Puppet Server built-in CA |

## Contributing

Contributions are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for how to
build, test, and submit changes, [`AGENTS.md`](AGENTS.md) for the repository
conventions, and the [development documentation](docs/development/) for internal
design notes and the test suites.

## License

See [LICENSE](LICENSE).
