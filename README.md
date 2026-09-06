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
> instructions, directory layout mapping, and CLI command translation, and
> [authorisation behaviour worth knowing](#authorisation-behaviour-worth-knowing)
> for the two rules that differ from a relaxed `auth.conf`.

## Features

- **Full Puppet CA API compatibility:** all 13 endpoints used by agents and OpenVox Server. See the [HTTP API reference](docs/api.md)
- **Pluggable storage:** filesystem (default; drop-in compatible with the OpenVox/Puppet Server CA layout), SQLite (single database file), or PostgreSQL / MySQL (MariaDB) / etcd / Redis (Valkey) for HA clusters; CA cert/key can be pinned to local files independently. See the [storage backends guide](docs/storage-backends.md)
- **Pluggable CA key custody:** keep the CA private key as a local file (default) or delegate it entirely to an OpenBao Transit secrets engine key, which never leaves OpenBao — works identically on a VM (AppRole/token) or in Kubernetes (native ServiceAccount auth, no sidecar). See [OpenBao Transit-engine CA key](docs/openbao-transit.md)
- **Autosigning:** `true`, glob-pattern file, or executable plugin modes
- **mTLS support:** optional HTTPS with per-endpoint tier-based client certificate authorization
- **CA import:** replace a bootstrapped CA with an external cert/key pair offline
- **Intermediate CA:** run under an external root, with `openvox-ca csr` emitting a signing request for a parent CA and `openvox-ca import-ca-cert` installing the signed chain. No key material is ever supplied on the command line, so it works identically for every `ca_key_provider` including an OpenBao Transit key that never leaves the vault. See the [operator CLI reference](docs/operator-cli.md)
- **Server-side key generation:** issue cert+key pairs without a node-submitted CSR; configurable RSA (2048/3072/4096) or ECDSA (P-256/P-384/P-521)
- **Offline certificate minting:** `openvox-ca generate` issues a certificate directly against storage with no running server and no API — the only way to mint a *new* `pp_cli_auth` administrator credential, and the way to mint before a server exists
- **Configurable key algorithms:** CA and leaf certificates can use RSA or ECDSA; ECDSA support for both bootstrapped CAs and generated leaf certs
- **Random serial numbers:** every issued leaf certificate gets a cryptographically random 128-bit serial (CA/Browser Forum guidance)
- **CRL Distribution Points:** optionally embed a CRL URL in every issued certificate (`--crl-url`) so verifiers can automatically fetch the CRL
- **Configurable CRL validity:** control how long each published CRL is valid (`crl_validity_days`)
- **Automatic CRL refresh:** a background job re-signs this CA's own CRL before its validity lapses, so a low-churn CA never serves an expired CRL; safe across replicas (serialised on the shared CRL lock) and tunable or disablable. Operators can also force a refresh on demand via `openvox-ca-ctl reissue-crl`. Imported ancestor CRLs are preserved but cannot be re-signed here, so keeping them current is `crl_chain_file`'s job (below) or, failing that, a re-import before they expire
- **Revocation that propagates:** on the HA backends every replica reloads the stored CRL on a short timer (`crl_sync_interval_sec`, 60s by default), so a certificate revoked on one replica stops being accepted by the others within that window rather than whenever they next happen to re-sign. Renewal re-reads the CRL from storage, so a revoked certificate cannot renew itself into a fresh one on a replica that has yet to catch up. See [Revocation across replicas](docs/configuration.md#revocation-across-replicas)
- **Upstream CRL chain (opt-in):** point `crl_chain_file` at a PEM bundle of *ancestor* CRLs and openvox-ca re-reads it on a timer and republishes it alongside its own, so a sub-CA's ancestors stay current without anyone remembering to re-import before each `nextUpdate`. An ancestor's CRL can never move backwards. On every storage backend except `filesystem`, and under `encrypt_ca_key` or `ca_key_provider: openbao`, this is the only mechanism that does not require stopping the CA. See [configuration](docs/configuration.md#publishing-an-upstream-crl-chain)
- **Client trust domains (opt-in):** by default the CA trusts exactly one issuer for client authentication — itself. `client_ca` adds others, each entry with its own admin allow list, its own `allow_pp_cli_auth` setting, and its own CRLs — per *entry*, so give each issuer its own entry where the grants should differ; a foreign client is checked against *its own issuer's* CRLs, chain-wide. Grants default to off, and `client_revocation_policy` defaults to `require`, which refuses a client whose issuer has no currently valid CRL. See [trusting client certificates from another CA](docs/configuration.md#trusting-client-certificates-from-another-ca)
- **Expired-certificate cleanup (opt-in):** a background job removes certificates that expired more than a configurable grace period ago from the inventory and the CRL (and deletes their stored signed certificate), keeping both from growing without bound as nodes are decommissioned; safe across replicas (serialised on the shared CRL lock)
- **Delayed supersession:** a renewal records the certificate it replaced rather than revoking it inside the call, and a background job revokes it once an overlap window elapses (`superseded_cert_revoke_after_sec`, 24h by default) — the overlap a certificate other parties are actively verifying needs in order to be replaced without a gap. The window is a deliberate weakening, so it is bounded at both ends: a superseded certificate cannot renew itself into a fresh one, and revoking a subject retires anything of its own still inside a window. Set `0` to revoke inside the renewal as earlier releases did. Safe across replicas (serialised on the shared CRL lock). See [delayed supersession](docs/configuration.md#delayed-supersession)
- **OCSP responder:** built-in RFC 6960 OCSP responder; AIA extension embedded in issued certs when `--ocsp-url` is set; in-memory cache with nonce bypass. On the HA backends each replica reloads the set of serials it recognises on a timer (`ocsp_index_sync_interval_sec`, 5m by default), so a certificate signed on one replica is not reported `unknown` by the others. See [OCSP status across replicas](docs/configuration.md#ocsp-status-across-replicas)
- **Health probes:** `/healthz/live`, `/healthz/ready`, and `/healthz/startup` endpoints for Kubernetes-style liveness/readiness checks
- **Prometheus exporter:** optional `/metrics` listener (`--metrics-listen`) exposing Go runtime/process and HTTP metrics plus CA certificate, CRL, and per–leaf-certificate expiry and issuance-status series; ships with a [Jsonnet alerting mixin](mixin/). See [metrics & monitoring](docs/metrics.md)
- **Kubernetes export (opt-in):** publish the CA certificate and/or CRL into any number of Kubernetes Secrets and ConfigMaps via in-cluster server-side apply, with configurable names, namespaces, data keys, labels, annotations, Secret `type`, and how much of the chain to publish (`cert_scope`/`crl_scope`, which publish the whole stored chain by default — set them to `self` on a target whose consumer wants this CA's block alone); CRL-bearing objects are refreshed whenever the CRL changes. See [Kubernetes export](docs/kubernetes-export.md)
- **Helm chart:** an OCI-published chart, versioned in lockstep with the server, covering dual-stack Services, TLS-passthrough Ingress and Gateway API routes, an opt-in ServiceMonitor and network policies; the server's own settings pass straight through to its config file, so the whole configuration reference is reachable. See [deploying with Helm](docs/helm-chart.md)
- **Graceful shutdown:** `SIGTERM`/`SIGINT` drains in-flight requests with a configurable window (25s default) before exiting; deferred storage and signer cleanup always runs
- **Configuration reload:** `SIGHUP` (or `systemctl reload`) re-reads the TLS keypair and the admin allow list without dropping connections, so renewing the CA's server certificate or decommissioning a compile server needs no restart. See [reloading configuration](docs/configuration.md#reloading-configuration)
- **systemd integration:** `Type=notify` readiness (`systemctl start` returns once the listener is actually accepting), a live status line covering the listener, CA expiry and CRL freshness, watchdog keep-alives, and `systemctl reload` for TLS certificate renewal and admin allow-list changes; ships a hardened [unit file](packaging/systemd/openvox-ca.service). See [running under systemd](docs/systemd.md)
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
`docker run` example, or use the [compose.yml](compose.yml) at the repository
root for a Docker/Podman Compose deployment.

### Release tarballs

Each release publishes four tarballs — `linux_amd64` and `linux_arm64`, each in a standard and a
FIPS (`_fips`) build — plus an SBOM pair per tarball, `checksums.txt`, and a signed provenance
bundle (see [verifying what you downloaded](#verifying-what-you-downloaded)). Every archive
contains both binaries (`openvox-ca`, `openvox-ca-ctl`) and the systemd unit
`openvox-ca.service`. Asset names carry the release version, so set `VERSION` to the release you
want (the newest is on the
[releases page](https://github.com/voxpupuli/openvox-ca/releases/latest)) and download by tag:

```console
$ VERSION=0.9.0
$ curl -fLO https://github.com/voxpupuli/openvox-ca/releases/download/v${VERSION}/openvox-ca_${VERSION}_linux_amd64.tar.gz
$ curl -fLO https://github.com/voxpupuli/openvox-ca/releases/download/v${VERSION}/checksums.txt
$ sha256sum --ignore-missing -c checksums.txt
$ tar xzf openvox-ca_${VERSION}_linux_amd64.tar.gz
```

See [running under systemd](docs/systemd.md) for the rest of a VM install.

### Verifying what you downloaded

`checksums.txt` establishes that a download arrived intact. Provenance establishes
where it came from: every tarball, container image and chart published from a
release tag carries a [SLSA v1.0](https://slsa.dev/spec/v1.0/provenance) build
provenance attestation, signed through [Sigstore](https://www.sigstore.dev/) with a
short-lived certificate — there is no long-lived signing key to trust or rotate.

With the GitHub CLI, verification is one command per artefact:

```console
$ gh attestation verify openvox-ca_${VERSION}_linux_amd64.tar.gz \
    --repo voxpupuli/openvox-ca \
    --signer-workflow voxpupuli/openvox-ca/.github/workflows/release.yml \
    --source-ref refs/tags/v${VERSION}
```

All three flags matter, and they do different jobs. `--repo` on its own accepts any
attestation this repository produced — and the container image workflow signs
pull-request builds too, so repository-scoped verification is weaker than it
looks. `--signer-workflow` pins *which* workflow signed; it has no ref
component, so it does not on its own separate a release from a pull request.
`--source-ref` is what pins the ref. The cosign commands below get all three
properties from one certificate identity — `--certificate-identity` where the
exact URL is known, `--certificate-identity-regexp` where the version is not
fixed in advance — because the identity URL carries repository, workflow path
and ref together.

The provenance bundle is also published as a release asset, so verification needs
nothing but `cosign` and `curl` — no GitHub API call, and it works air-gapped.
It is a Sigstore-format bundle, so it wants cosign v3 or newer (on cosign v2.4
and later, add `--new-bundle-format`; earlier v2 releases cannot read it):

```console
$ curl -fLO https://github.com/voxpupuli/openvox-ca/releases/download/v${VERSION}/provenance.sigstore.json
$ cosign verify-blob-attestation openvox-ca_${VERSION}_linux_amd64.tar.gz \
    --bundle provenance.sigstore.json \
    --type slsaprovenance1 \
    --certificate-identity https://github.com/voxpupuli/openvox-ca/.github/workflows/release.yml@refs/tags/v${VERSION} \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The bundle covers every file listed in `checksums.txt` — each tarball and each SBOM —
so the same bundle verifies any of them.

Container images and the Helm chart are both attested and signed. Because images are
also built for pull requests, whose certificates name `refs/pull/N/merge`, pin the
identity to the release shape rather than accepting any identity from this repository:

```console
$ cosign verify ghcr.io/voxpupuli/openvox-ca:${VERSION} \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity-regexp '^https://github\.com/voxpupuli/openvox-ca/\.github/workflows/container-images\.yml@refs/tags/v'
```

**SBOMs.** Each tarball ships an SBOM in both SPDX-JSON (`.spdx.json`, ISO/IEC 5962)
and CycloneDX-JSON (`.cdx.json`, ECMA-424), generated from the built binaries rather
than from `go.mod`, so they record what actually linked.

Container images carry the equivalent pair as registry attestations, catalogued from
the image so the base-layer packages are included too. These are attached to each
**per-architecture** image rather than to the multi-arch index, because that is where
they differ — so resolve a child digest first; a tag resolves to the index, which
carries provenance only:

```console
$ digest="$(docker buildx imagetools inspect ghcr.io/voxpupuli/openvox-ca:${VERSION} \
    --format '{{range .Manifest.Manifests}}{{if eq .Platform.Architecture "amd64"}}{{.Digest}}{{end}}{{end}}')"
$ gh attestation verify oci://ghcr.io/voxpupuli/openvox-ca@${digest} \
    --repo voxpupuli/openvox-ca \
    --signer-workflow voxpupuli/openvox-ca/.github/workflows/container-images.yml \
    --source-ref refs/tags/v${VERSION} \
    --predicate-type https://spdx.dev/Document/v2.3
```

Select the child by architecture rather than by position — the order the index
lists them in is not meaningful, so `index … 0` would verify whichever image
happened to sort first. Substitute `arm64` for the other architecture, and
`--predicate-type https://cyclonedx.org/bom` for the CycloneDX document.

The SPDX predicate type carries the document's own SPDX version, so it moves if
the generator's output version does: check the `spdxVersion` field of the
published `.spdx.json` if `v2.3` stops matching. CycloneDX's is unversioned.
The Helm chart carries provenance and a signature but no SBOM: it declares no
dependencies, so there would be nothing to catalogue.

### Kubernetes (Helm)

A chart is published as an OCI artefact for every release, versioned in lockstep
with the server:

```console
$ helm install openvox-ca \
    oci://ghcr.io/voxpupuli/openvox-ca-charts/openvox-ca \
    --namespace puppet --create-namespace \
    --set tls.existingSecret=openvox-ca-server-tls
```

See [deploying with Helm](docs/helm-chart.md) for the guide and the
[chart README](charts/openvox-ca/README.md) for the values reference. The chart is
signed and attested like the images:

```console
$ cosign verify ghcr.io/voxpupuli/openvox-ca-charts/openvox-ca:${VERSION} \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity-regexp '^https://github\.com/voxpupuli/openvox-ca/\.github/workflows/helm-chart\.yml@refs/tags/v'
```

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

### Local demo: plain HTTP on loopback, auto-bootstrap CA

```bash
./bin/openvox-ca --cadir /etc/puppetlabs/puppet/ssl/ca --host 127.0.0.1 --hostname puppet.example.com
```

On first run the server bootstraps a new CA under `--cadir` and begins serving
plain HTTP on port 8140. The server refuses plain HTTP on a non-loopback
address unless `--no-tls-required` is set — only do that behind a trusted
TLS-terminating proxy or in test environments. For anything reachable from the
network, serve HTTPS as below.

### HTTPS with mTLS

```bash
./bin/openvox-ca \
  --cadir /etc/puppetlabs/puppet/ssl/ca \
  --tls-cert /etc/puppetlabs/puppet/ssl/ca/signed/puppet.example.com.pem \
  --tls-key  /etc/puppetlabs/puppet/ssl/ca/private/puppet.example.com_key.pem \
  --puppet-server puppet.example.com
```

`--tls-cert` needs a serving certificate the CA has issued to itself. The CA's
own `ca_crt.pem` is not one — its `keyUsage` is `certSign, cRLSign` and it
carries no `subjectAltName`, so a server presenting it completes the handshake
and is then rejected by every agent, and the server says so at startup. Issue
one by starting the CA on loopback with TLS off and asking it for a
certificate:

```bash
# Stop any CA already listening on 8140 first, or this one cannot bind.
./bin/openvox-ca --tls-cert= --tls-key= \
  --cadir /etc/puppetlabs/puppet/ssl/ca --host 127.0.0.1 --hostname puppet.example.com &
PCA_PID=$!

# Wait for it to serve: a cold cadir generates an RSA-4096 key first.
for _ in $(seq 1 300); do
  curl -sf http://127.0.0.1:8140/puppet-ca/v1/certificate/ca >/dev/null && break; sleep 1
done

./bin/openvox-ca-ctl generate \
  --server-url http://127.0.0.1:8140 \
  --certname   puppet.example.com \
  --dns        puppet.example.com \
  --out-dir    /etc/puppetlabs/puppet/ssl/ca/private

kill $PCA_PID; wait $PCA_PID 2>/dev/null
```

**While that server is up its whole admin API is unauthenticated** — the
authorisation middleware is only installed when `tls_cert` and `tls_key` are
both set, and that includes `POST /generate/<subject>`, which hands back a
signed certificate and its private key. `--host 127.0.0.1` is required rather
than advisable, and the `kill` above is part of the procedure, not tidying.

`--server-url` is needed because it defaults to HTTPS while that server speaks
plain HTTP, and the empty `--tls-cert=`/`--tls-key=` keep the start from
picking up a `tls_cert` in `/etc/puppet-ca/config.yaml` — which would name the
file this step is about to create. `--out-dir` points at the directory the CA
writes the key to anyway, so no second copy of it is left lying around; omit it
and one lands in the current directory. The certificate is printed on stdout,
and with the default filesystem backend the CA also writes both halves under
`cadir`, at the two paths `--tls-cert`/`--tls-key` point at above, so once the
temporary server is stopped you can start again with the TLS flags. [Serving
certificate](docs/configuration.md#serving-certificate) has the full procedure,
including the other storage backends and running it under systemd.

When `--tls-cert` and `--tls-key` are both set, the server:

1. Presents those certs to connecting clients
2. Requests (but does not require) a client certificate from every connection,
   and does not verify it at the TLS layer
3. Enforces endpoint-level authorization, which is where a presented
   certificate is verified against this CA and checked against the CRL (see
   [Authorization tiers](docs/api.md#authorization-tiers))

The complete flag, environment-variable, and config-file reference is in
[configuring the server](docs/configuration.md).

## Documentation

| Guide | What it covers |
| --- | --- |
| [Configuring the server](docs/configuration.md) | Every flag, environment variable, config-file key; the serving certificate; autosigning; directory layout; graceful shutdown; reloading configuration; trusting client certificates from another CA |
| [HTTP API reference](docs/api.md) | All endpoints, authorization tiers, and admin credential resolution |
| [Operator CLI (`openvox-ca-ctl`)](docs/operator-cli.md) | The `openvox-ca-ctl` command reference, and the offline `openvox-ca` subcommands (`csr`, `import-ca-cert`, `generate`) that run against the server's own configuration |
| [Storage backends](docs/storage-backends.md) | filesystem, SQLite, PostgreSQL, MySQL, etcd, Redis/Valkey; migrating between them |
| [CA key security](docs/ca-key-security.md) | Process isolation and the signer handshake, key encryption at rest, key-custody options, PKCS#11 plans, destructive-op monitoring, and where the inventory-integrity key lives |
| [OpenBao Transit-engine CA key](docs/openbao-transit.md) | Delegating CA key custody to OpenBao |
| [Deploying with Helm](docs/helm-chart.md) | The `openvox-ca` chart: installation, TLS passthrough, ingress and Gateway API, monitoring |
| [Kubernetes export](docs/kubernetes-export.md) | Publishing the CA cert/CRL into Secrets and ConfigMaps |
| [Metrics & monitoring](docs/metrics.md) | The Prometheus exporter and the alerting [mixin](mixin/) |
| [Running under systemd](docs/systemd.md) | The `Type=notify` unit, status text, `systemctl reload`, watchdog, and hardening |
| [Container images](docs/container-images.md) | Pulling and running the published images |
| [Migration guide](docs/migrating-from-puppet-server.md) | Replacing an OpenVox/Puppet Server built-in CA |

## Authorisation behaviour worth knowing

Two rules catch operators out, neither of which changes a stock deployment.

`GET /certificate_status/{subject}` is admin-only. That matches OpenVox/Puppet
Server's shipped `auth.conf`, so only a configuration that had been relaxed to
let ordinary agent certificates read statuses loses that access. It can be
granted back two ways, both of which confer the whole admin tier — signing and
revocation included — plus an escape hatch that makes the route public rather
than authenticated. Denials are logged, with the string to grep for, in
[authorisation parity](docs/migrating-from-puppet-server.md#authorisation-parity).

`POST /certificate_renewal` accepts only certificates this CA issued and has not
revoked. In the default single-issuer topology nothing reaches that check that
the authorisation middleware had not already refused with `403 access denied`
(TLS requests but does not verify a client certificate — see [HTTPS with
mTLS](#https-with-mtls)). The gate becomes load-bearing once a second issuer can
be trusted for client authentication. There is no opt-out: an agent holding a
certificate from a replaced CA must re-enrol. See [renewal
eligibility](docs/migrating-from-puppet-server.md#renewal-eligibility).

## Contributing

Contributions are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for how to
build, test, and submit changes, [`AGENTS.md`](AGENTS.md) for the repository
conventions, and the [development documentation](docs/development/) for internal
design notes and the test suites.

## License

See [LICENSE](LICENSE).
