# Container images

Prebuilt, multi-arch container images are published to the GitHub Container
Registry (GHCR) for every release and every push to `main`. Two variants are
built, differing only in base image:

| Variant | Base image | Tag suffix |
| --- | --- | --- |
| CentOS Stream | `quay.io/centos/centos` | *(none)* |
| Alpine | `alpine` | `-alpine` |

Both variants are built for `linux/amd64` and `linux/arm64` and published as a
single multi-arch manifest per variant, so `docker`/`podman` pulls the right
architecture automatically. The images are published as
`ghcr.io/voxpupuli/openvox-ca`.

## Pulling

```console
$ docker pull ghcr.io/voxpupuli/openvox-ca:latest          # CentOS Stream
$ docker pull ghcr.io/voxpupuli/openvox-ca:latest-alpine   # Alpine
```

## Available tags

| Tag | Points at |
| --- | --- |
| `latest` / `latest-alpine` | The most recent release |
| `1.2.3`, `1.2`, `1` (+ `-alpine`) | A specific release and its semver aliases; the major-only tag (`1`) is published for v1+ releases only, so `0.x` releases have no `0` tag |
| `edge` / `edge-alpine` | The latest build from the default branch (`main`) |
| `main` / `main-alpine` | Same as `edge`; the head of `main` |

Pin to a specific semver tag (e.g. `1.2.3`) for reproducible deployments;
`edge` tracks unreleased changes and can break at any time.

## Verifying an image

Every published image is signed and carries SLSA v1.0 build provenance, through
Sigstore — there is no long-lived signing key involved. Pin the identity to the
release shape rather than accepting anything this repository signed, because
pull-request builds are signed too:

```console
$ cosign verify ghcr.io/voxpupuli/openvox-ca:1.2.3 \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity-regexp '^https://github\.com/voxpupuli/openvox-ca/\.github/workflows/container-images\.yml@refs/tags/v'
```

Each per-architecture image also carries an SBOM in both SPDX-JSON and
CycloneDX-JSON, catalogued from the image itself so the base-layer packages are
included as well as the Go modules. Those are attached to the architecture
digests, not to the multi-arch index a tag resolves to; see [verifying what you
downloaded](../README.md#verifying-what-you-downloaded) for the two-step form,
and [verifying a release](development/releasing.md#verifying-a-release) for what
each check does and does not prove.

## Running

The image's entrypoint is `openvox-ca`; any arguments you pass are appended to
it, exactly like running the binary. Mount a volume for the CA directory so the
CA survives container restarts, and publish port 8140:

```console
$ docker run -d --name openvox-ca \
    -p 8140:8140 \
    -v openvox-ca-data:/data \
    ghcr.io/voxpupuli/openvox-ca:latest \
    --cadir=/data --hostname=puppet.example.com \
    --tls-cert=/data/ca_crt.pem --tls-key=/data/private/ca_key.pem
```

On first run this bootstraps a new CA under `/data` and serves HTTPS on port
8140, using the CA's own certificate as the TLS server certificate. (The
server refuses plain HTTP on a non-loopback address unless `--no-tls-required`
is set — only do that behind a trusted TLS-terminating proxy or in test
environments.)

That last part makes the command self-contained, and nothing else: the CA
certificate's `keyUsage` is `certSign, cRLSign` and it has no
`subjectAltName`, so no agent will accept the connection. The server warns
about this at startup; see [serving
certificate](configuration.md#serving-certificate). Before any agent talks to
this CA, issue it a serving certificate with `openvox-ca-ctl generate` and
point `--tls-cert`/`--tls-key` at that. The same goes for the rest of a
production deployment — mTLS, an alternative storage backend, autosigning: pass the
relevant flags, or mount a config file and set `--config`. See [configuring the
server](configuration.md) for the full reference, and the [HTTP API
reference](api.md) for the endpoints agents use.

### Memory limits

If you set a memory limit — `--memory`, podman's `-m`, or a compose `mem_limit`
— the launcher reads it from the container's **cgroup v2** ceiling and divides
it across the three processes it runs (a supervisor, an isolated signer and the
frontend), rather than letting each apply the whole of it. On a cgroup v1 host
nothing is derived; set `GOMEMLIMIT` on the container instead. `GOMEMLIMIT` set
on the container likewise names the budget for the whole tree, not for one
process. See [memory budget](configuration.md#memory-budget).

### Runtime user

Both variants run as the non-root user `puppet`, uid/gid **1000**, declared
numerically so that a host which cannot read the image's `/etc/passwd` can
still tell who the process runs as. Under Kubernetes, a container whose image
only names its user fails to start when the pod sets `runAsNonRoot` without
also setting `runAsUser` — the kubelet cannot verify that a name is non-root,
and the container stops at `CreateContainerConfigError`.

A named volume like the one above is created with the right ownership
automatically. A bind mount is not, so `chown 1000:1000` the host directory
before starting the container, or the CA cannot write its state. Under
rootless Podman the container's uid 1000 maps to a subordinate uid on the
host, so a plain `chown` leaves the directory unwritable — use `podman
unshare chown 1000:1000 <dir>`, or mount with the `:U` suffix. Under
Kubernetes, `fsGroup: 1000` on the pod covers PersistentVolumeClaims and
`emptyDir`, but the kubelet does not apply it to a `hostPath`, which needs
the same treatment as a bind mount.

### Compose

The [`compose.yml`](../compose.yml) at the repository root is the equivalent
Docker/Podman Compose deployment: edit `--hostname`, then `docker compose up
-d` (or `podman-compose up -d`). The `test/compose*.yml` files, by contrast,
are the integration-test topologies — they build throwaway images from the
working tree and are not deployment examples.

> **Autosigning is off by default.** Only set `--autosign-config=true` in
> dev/test environments: it lets any CSR submitter obtain a signed certificate
> without operator review.

## Publishing

How these images are built and published (the GitHub Actions workflow, the tag
matrix, and the one-time repository setup a maintainer performs) is documented
in [publishing container images](development/publishing-images.md).
