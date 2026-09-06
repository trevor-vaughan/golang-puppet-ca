# OpenBao Transit-engine CA key

By default `openvox-ca` holds the CA private key itself: as a local PEM file
(optionally encrypted at rest, see [CA key security](ca-key-security.md#ca-key-encryption-at-rest)),
or — in the isolated-signer deployment — inside a separate, isolated `openvox-ca
[signer]` child process.

Setting `--ca-key-provider openbao` changes where the key itself lives: it
never exists inside any `openvox-ca` process at all. Instead it lives in an
[OpenBao](https://openbao.org/) **Transit secrets engine**, and `openvox-ca`
only ever sends OpenBao a digest to sign, getting a signature back. It plugs
into the same key-custody seam the isolated signer uses and the
[PKCS#11/HSM plans](ca-key-security.md#planned-pkcs11--hsm-support) target;
OpenBao is simply the first concrete backend for it.

Every other storage backend — filesystem, etcd, redis/valkey, sqlite,
postgres, mysql — keeps working exactly as documented in
[storage backends](storage-backends.md). OpenBao only ever supplants **key
custody**: the CA certificate, CSRs, issued certificates, the CRL, and the
inventory are still read and written through whichever storage backend you
have configured. Set `openbao.key_name` and the rest of the `openbao.*`
settings below alongside your existing `storage_backend` config; nothing
about it needs to change.

## Vault compatibility

This integration is built against and tested with **OpenBao** specifically,
against current OpenBao releases. It should also work against **HashiCorp
Vault** — OpenBao is a fork of Vault and remains wire-compatible with its
Transit engine, AppRole/Kubernetes auth methods, and Go client API — but
Vault is not part of the test matrix, so this has not been actively
verified. Compatibility bug reports (and fixes) for Vault are welcome.

## Provisioning the Transit key

**Recommended:** create (or import) the Transit key directly in OpenBao, out
of band, before pointing `openvox-ca` at it, and scope a dedicated policy to
just that key rather than granting broader Transit access.

### Create the key

```bash
bao secrets enable transit   # if not already enabled
bao write -f transit/keys/openvox-ca \
  type=rsa-4096 \
  exportable=false \
  allow_plaintext_backup=false
```

`exportable` and `allow_plaintext_backup` already default to `false`; setting
them explicitly is a reminder that the whole point of this integration is
that the key never leaves OpenBao — don't turn either of these on.

To bring existing CA key material into OpenBao instead of generating a fresh
key, see `bao write transit/keys/<name>/import` (BYOK) in OpenBao's own
documentation — that's an OpenBao-side operation, not an openvox-ca one.

> **Disaster recovery — read before you rely on this in production.** With
> `exportable=false` and `allow_plaintext_backup=false` (recommended above), a
> freshly generated key exists **only** inside OpenBao and cannot be exported
> or plaintext-backed-up by design. That means OpenBao's own snapshot/HA
> becomes the sole recovery path for your CA private key: if OpenBao's storage
> is lost and not restored from an OpenBao snapshot, the CA key is
> **permanently unrecoverable** and every agent must be re-bootstrapped against
> a new CA. Treat OpenBao's own backups and high availability as a hard
> requirement here, not an optional extra. If you would rather retain an independent
> recovery copy of the CA key, generate it outside OpenBao and bring it in via
> BYOK/import (above) instead of letting OpenBao generate it — accepting that
> the key then existed outside OpenBao at import time.

### Create a policy scoped to that key

```bash
bao policy write openvox-ca - <<'EOF'
path "transit/sign/openvox-ca" {
  capabilities = ["update"]
}

path "transit/keys/openvox-ca" {
  capabilities = ["read"]
}
EOF
```

This is the minimum `openvox-ca` needs at steady state: sign with the key,
and read its public component. It deliberately excludes `create`, so this
policy alone cannot be used to provision the key — see "Convenience" below
if you want that instead.

### Bind the policy to a Kubernetes role

This assumes the `kubernetes` auth method is already enabled and configured
with your cluster's API address and CA certificate; that part is generic
OpenBao/Kubernetes setup, not specific to this integration, so see OpenBao's
own Kubernetes auth documentation for it.

```bash
bao write auth/kubernetes/role/openvox-ca \
  bound_service_account_names=openvox-ca \
  bound_service_account_namespaces=openvox-ca \
  token_policies=openvox-ca \
  token_ttl=1h \
  token_max_ttl=4h
```

Change `bound_service_account_names` and `bound_service_account_namespaces`
to match the ServiceAccount name and namespace `openvox-ca` actually runs as.

### Bind the policy to an AppRole role

This assumes the `approle` auth method is already enabled; see OpenBao's own
AppRole documentation for that part.

```bash
bao write auth/approle/role/openvox-ca \
  token_policies=openvox-ca \
  token_ttl=1h \
  token_max_ttl=4h

bao read auth/approle/role/openvox-ca/role-id
bao write -f auth/approle/role/openvox-ca/secret-id
```

Write the `secret_id` value from that last command into the file
`openbao.approle_secret_id_file` points at (and the `role_id` into
`openbao.approle_role_id_file`, if you use the file form rather than the
inline `openbao.approle_role_id`), owned by the user `openvox-ca` runs as and
mode `0600`:

```bash
install -o openvox-ca -g openvox-ca -m 0600 /dev/null /etc/puppet-ca/openbao-secret-id
bao write -f -field=secret_id auth/approle/role/openvox-ca/secret-id \
  > /etc/puppet-ca/openbao-secret-id
```

`openvox-ca` re-reads this file on every login, so rotating the `secret_id`
is just a matter of rewriting the file — no restart needed.

Set `secret_id_ttl` and `secret_id_num_uses` on the role to match your own
secret_id rotation practice; there's no single default that's right for
every environment, so they're left unset (unlimited) above rather than
copied blindly.

Then configure `openvox-ca` with `openbao.key_name: openvox-ca` (and the
matching `ca_key_algo`/`ca_key_size` if you want `openvox-ca-ctl setup`'s
offline bootstrap to describe the same algorithm — the key's actual type is
whatever you created in OpenBao). This keeps the running server's OpenBao
policy scoped to `sign` and `read` on that one key — it never needs
`create`/`import` rights.

**Convenience:** if the named key does not exist yet, `openvox-ca` creates
it itself on first boot (mirroring today's local-key bootstrap behaviour),
using `ca_key_algo`/`ca_key_size` to pick the Transit key type. This requires
the server's OpenBao policy to also grant key creation — a stronger
permission than steady-state signing ever needs again afterwards, so the
manual route above is preferred for production.

## Configuration

Every OpenBao-specific setting lives under a top-level `openbao:` YAML key
(flags and environment variables use an `--openbao-*` / `PUPPET_CA_OPENBAO_*`
prefix instead, since there's no flat-file nesting for those).

| Config key | Environment variable | CLI flag | Description |
| --- | --- | --- | --- |
| `ca_key_provider` | `PUPPET_CA_CA_KEY_PROVIDER` | `--ca-key-provider` | `file` (default) or `openbao` |
| `openbao.addr` | `PUPPET_CA_OPENBAO_ADDR` | `--openbao-addr` | OpenBao server address as a full URI, including scheme and port, e.g. `https://openbao.example.com:8200`. `http://` is also accepted for a plain-HTTP listener in development only — never against a non-loopback or production OpenBao, because the client token and all signing traffic then cross the network in cleartext |
| `openbao.transit_mount` | `PUPPET_CA_OPENBAO_TRANSIT_MOUNT` | `--openbao-transit-mount` | Transit engine mount path (default `transit`) |
| `openbao.key_name` | `PUPPET_CA_OPENBAO_KEY_NAME` | `--openbao-key-name` | Name of the Transit key backing the CA's private key |
| `openbao.tls_ca_file` | `PUPPET_CA_OPENBAO_TLS_CA_FILE` | `--openbao-tls-ca-file` | PEM CA bundle to verify OpenBao's server certificate |
| `openbao.tls_cert_file` | `PUPPET_CA_OPENBAO_TLS_CERT_FILE` | `--openbao-tls-cert-file` | Client certificate PEM for mTLS to OpenBao |
| `openbao.tls_key_file` | `PUPPET_CA_OPENBAO_TLS_KEY_FILE` | `--openbao-tls-key-file` | Client private key PEM for mTLS to OpenBao |
| `openbao.auth_method` | `PUPPET_CA_OPENBAO_AUTH_METHOD` | `--openbao-auth-method` | `approle`, `token`, or `kubernetes` |

### AppRole auth (VM / systemd deployments)

> Running as a systemd service? See [running under systemd](systemd.md) for the shipped unit; the `role_id` and `secret_id` files below are re-read on every login, so rotating them needs neither a reload nor a restart.

| Config key | Environment variable | CLI flag | Description |
| --- | --- | --- | --- |
| `openbao.approle_mount` | `PUPPET_CA_OPENBAO_APPROLE_MOUNT` | `--openbao-approle-mount` | AppRole mount path (default `approle`) |
| `openbao.approle_role_id` | `PUPPET_CA_OPENBAO_APPROLE_ROLE_ID` | `--openbao-approle-role-id` | AppRole `role_id` |
| `openbao.approle_role_id_file` | `PUPPET_CA_OPENBAO_APPROLE_ROLE_ID_FILE` | `--openbao-approle-role-id-file` | Path to a file containing `role_id`, read fresh on every login |
| `openbao.approle_secret_id_file` | `PUPPET_CA_OPENBAO_APPROLE_SECRET_ID_FILE` | `--openbao-approle-secret-id-file` | Path to a file containing `secret_id`, read fresh on every login |

```yaml
ca_key_provider: openbao
openbao:
  addr: https://openbao.example.com:8200
  key_name: openvox-ca
  auth_method: approle
  approle_role_id: 11111111-2222-3333-4444-555555555555
  approle_secret_id_file: /etc/puppet-ca/openbao-secret-id
```

### Static token file (VM / systemd deployments)

| Config key | Environment variable | CLI flag | Description |
| --- | --- | --- | --- |
| `openbao.token_file` | `PUPPET_CA_OPENBAO_TOKEN_FILE` | `--openbao-token-file` | Path to a file containing a pre-issued OpenBao token |

This file holds a bearer credential that can sign arbitrary certificates as
the CA, so — like the AppRole `secret_id` file and the encryption passphrase
file — it must be owned by the user `openvox-ca` runs as and mode `0600`.

Simplest to set up, at the cost of needing something else to keep that
token's underlying credential rotated/renewed at the source (a periodic
`bao token create` against a role, a secrets-management pipeline, etc.).
`openvox-ca` itself still renews the token's lease proactively and re-reads
the file if it ever needs to fully re-authenticate — see
[token lifecycle](#token-lifecycle) below — but it cannot mint a *new*
underlying credential out of thin air if the one in the file is permanently
revoked.

### Kubernetes auth (native, no sidecar)

| Config key | Environment variable | CLI flag | Description |
| --- | --- | --- | --- |
| `openbao.kubernetes_mount` | `PUPPET_CA_OPENBAO_KUBERNETES_MOUNT` | `--openbao-kubernetes-mount` | Kubernetes auth mount path (default `kubernetes`) |
| `openbao.kubernetes_role` | `PUPPET_CA_OPENBAO_KUBERNETES_ROLE` | `--openbao-kubernetes-role` | OpenBao Kubernetes auth role name |
| `openbao.kubernetes_jwt_file` | `PUPPET_CA_OPENBAO_KUBERNETES_JWT_FILE` | `--openbao-kubernetes-jwt-file` | Path to the projected ServiceAccount token (default: the standard in-cluster path) |

```yaml
ca_key_provider: openbao
openbao:
  addr: https://openbao.default.svc:8200
  key_name: openvox-ca
  auth_method: kubernetes
  kubernetes_role: openvox-ca
```

No Vault/OpenBao Agent sidecar, injector, or init container is required — the
pod only needs its own ServiceAccount bound to an OpenBao Kubernetes auth
role; `openvox-ca` logs in and maintains its own token for as long as the
process runs.

## Running under an external root CA

By default openvox-ca generates a self-signed root and issues everything from
it. It can instead be an *intermediate* CA, with its certificate signed by an
external root — an OpenBao PKI mount, an offline root, or any other CA — while
its private key stays in Transit and is never exportable.

Two subcommands on the `openvox-ca` binary do this. They read the server's own
configuration, so they reach the Transit key and the configured storage backend
exactly as the running server does.

### 1. Create the key and request a certificate

```console
$ openvox-ca csr --hostname puppet.example.com --create-key --out ca-request.pem
Using config file: /etc/puppet-ca/config.yaml
Storage backend: postgres; CA key provider: openbao; cadir: /etc/puppetlabs/puppet/ssl/ca
This CA has a key but no certificate, so the server will refuse to start until
'openvox-ca import-ca-cert' installs the chain the parent signs.
Certificate signing request written to ca-request.pem
```

`--create-key` creates `transit/keys/<openbao.key_name>` when it does not exist.
Omit it if you provisioned the key out of band, which is the recommended path —
see [Provisioning the Transit key](#provisioning-the-transit-key). It never
replaces a key that already exists.

The request carries the same subject openvox-ca would otherwise self-sign, built
from `hostname` and any `ca_subject_*` settings. If a CA certificate already
exists its encoded subject is reused byte for byte instead, so re-issuance
reproduces the established name exactly.

### 2. Sign it with the parent

Whatever your root is. With an OpenBao PKI mount:

```console
$ bao write -format=json pki-root/root/sign-intermediate \
    csr=@ca-request.pem \
    format=pem_bundle \
    ttl=43800h | jq -r '.data.certificate' > signed.pem
$ bao read -format=json pki-root/cert/ca | jq -r '.data.certificate' > root.pem
$ cat signed.pem root.pem > signed-chain.pem
```

The bundle must be **nearest first**: openvox-ca's certificate, then each issuer,
ending with the self-signed root. A partial chain is rejected — without the root
nothing can verify the root's CRL, which is what agents need for full-chain
revocation checking.

### 3. Install the chain

```console
$ openvox-ca import-ca-cert --cert-bundle signed-chain.pem
Imported CA certificate "Puppet CA: puppet.example.com" (2 certificates in chain)
```

The key material never leaves Transit. Instead the command proves the
certificate binds the key Transit holds, refusing the import otherwise — a
certificate this CA could not sign under would leave every issuance failing.

The bundle must contain only certificates. One carrying a private key is
rejected outright: the CA certificate is stored world-readable and served
unauthenticated at `GET /certificate/ca`, so anything in that file is published.
`bao write pki/intermediate/generate/exported ... format=pem_bundle` produces
exactly that shape, which is why the check exists.

#### Transit will not hold the CA certificate alongside its key

`transit/keys/<openbao.key_name>/set-certificate` looks like the way to record
which certificate belongs to the key OpenBao is holding — the more so because
its sibling `transit/keys/<openbao.key_name>/csr` does exactly what you would
expect. It will not take a CA certificate, and the error does not explain
itself:

```text
certificate in the first element is not a valid leaf certificate
```

The endpoint exists for end-entity certificates. It rejects any chain whose
first element carries `basicConstraints` with `CA:TRUE` — which every CA
certificate does, including the one your parent has just signed. There is no
parameter that relaxes it.

The consequence is worth stating plainly, because nothing surfaces it: **a
Transit-backed CA has no record inside OpenBao of which certificate its key
belongs to.** Transit holds the key, openvox-ca's storage backend holds the
certificate, and the only thing tying them together is whatever you wrote down.
Keep `signed-chain.pem` somewhere durable and off the cluster. `import-ca-cert`
will reinstall it, and proves the binding when it does — but only if you still
have the file.

### The server will not start between steps 1 and 3

This is by design and is worth expecting. After `csr --create-key` the key
exists but storage has no CA certificate, and `Init` refuses to bootstrap over
that state: doing so would replace the key your parent CA is in the middle of
signing, and the chain that came back could then never be imported. The
Deployment will crash-loop with

```
a CA key already exists at the configured key provider but the CA certificate is missing
```

until `import-ca-cert` completes. Run the two steps together, or scale the
Deployment to zero while you do.

This applies to every `ca_key_provider`, not only Transit — with the default
`file` provider the message names storage instead.

**Running the two commands in Kubernetes.** Scaling the Deployment to zero
removes the very thing the commands authenticate with: under
`auth_method: kubernetes` the credential is the pod's own projected
ServiceAccount token, and the configuration comes from the pod's mounts. Run
them from a one-shot Job carrying the same ServiceAccount, image and mounts as
the Deployment.

Three details are easy to get wrong. The config must land where the command
looks for it — `/etc/puppet-ca/config.yaml`, unless you pass `--config` or set
`PUPPET_CA_CONFIG`. Setting `args:` replaces the image's `CMD`, so any `--cadir`
it supplied is gone and the config file (or a flag) has to provide it. And the
request has to outlive the pod, so write it somewhere that survives: a
PersistentVolumeClaim, or stdout, which `kubectl logs` can retrieve after the
Job completes.

Pin the Job to the version the Deployment was actually running rather than to
its tag; [reading the version back off a floating tag](operator-cli.md#reading-the-version-back-off-a-floating-tag)
has how to recover it, and warns that it is much harder once the Deployment has
already been scaled down.

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: openvox-ca-csr
spec:
  template:
    spec:
      restartPolicy: Never
      serviceAccountName: openvox-ca        # the same one the Deployment uses
      containers:
        - name: csr
          image: ghcr.io/voxpupuli/openvox-ca:1.2.3   # the version it was running, not its tag
          # No --out: the request goes to stdout, so it survives the pod. Logs
          # go to stderr and kubectl merges the two streams, so extract the
          # block rather than redirecting wholesale:
          #   kubectl logs job/openvox-ca-csr \
          #     | sed -n '/BEGIN CERTIFICATE REQUEST/,/END CERTIFICATE REQUEST/p'
          # logfile does not apply here: these subcommands write their progress
          # messages to stderr unconditionally, so extract the block rather than
          # relying on a quiet stream.
          # No --create-key: this assumes the Transit key was provisioned out
          # of band, the recommended path, and the Job runs under the
          # Deployment's own ServiceAccount, whose policy deliberately excludes
          # create on transit/keys. Add the flag only if you must create the
          # key here, and grant create for the duration of the Job alone --
          # leaving it on the steady-state policy widens the running CA's
          # credential to key creation for good.
          args: ["csr"]
          volumeMounts:
            - { name: config, mountPath: /etc/puppet-ca }
            # Only needed on the filesystem backend, which keeps the CA
            # certificate in the cadir: csr reads it from there to reproduce an
            # established subject. It must be the same volume the Deployment
            # uses, or the Job reads an empty ephemeral layer instead of the CA.
            # The key is not in play here -- under ca_key_provider: openbao it
            # lives in Transit, and only the default file provider would put it
            # in the cadir.
            - { name: cadir, mountPath: /etc/puppetlabs/puppet/ssl/ca }
      volumes:
        - { name: config, configMap: { name: openvox-ca-config } }   # key: config.yaml
        - { name: cadir, persistentVolumeClaim: { claimName: openvox-ca } }
```

The image runs as uid/gid 1000, so the `cadir` PVC has to be writable by that
uid for the `import-ca-cert` step below, which a freshly provisioned PVC is
not: most CSI drivers hand it over owned by `root:root`. Set
`securityContext.fsGroup: 1000` on this Job's pod spec, and on the Deployment
that shares the claim. See [the runtime
user](container-images.md#runtime-user) for the full contract.

The second step is the same Job with the signed chain mounted in and
`args: ["import-ca-cert", "--cert-bundle", "/in/signed-chain.pem"]`, the chain
supplied as a Secret or ConfigMap mounted read-only at `/in`.

Anywhere with equivalent OpenBao credentials and the same configuration works
just as well; the Job is only the most direct way to get them.

### Re-issuing the CA certificate later

The procedure below re-issues the CA certificate: a new certificate, under a new
parent or a longer validity, **bound to the same key**. It does not rotate the
key. Neither `csr` nor `csr --create-key` can: both return the existing key
untouched, and the Transit provider refuses to generate over a populated key
slot. Rotating the CA key means provisioning a new key out of band and treating
the result as a new CA, with every issued certificate reissued under it.

Re-issuance needs an ordered procedure, because `--force` re-signs the stored
CRL and every replica caches the CA certificate for its process lifetime.

> **Stop the CA first, on any backend.** `--force` is a read-modify-write
> spanning the certificate and the CRL, and it takes the bootstrap and CRL locks
> to keep a concurrent revocation from being lost. On `filesystem` and `sqlite`
> this is not advice you can weigh up: those backends support one running
> instance, so the command is refused outright while a server holds the store,
> naming the process that holds it. On the backends that do coordinate across
> nodes the command can run, but the import is a read-modify-write over the
> certificate and CRL that no lock covers end to end, so one racing issuance can
> still interleave with it. Stopping the CA is a one-line step; the import is not the
> place to economise. See [running a second process against a live
> store](storage-backends.md#running-a-second-process-against-a-live-store).

1. Keep a copy of the bundle you are about to replace:
   `curl -sk https://<ca>/puppet-ca/v1/certificate/ca > ca-bundle.backup.pem`.
   `--force` overwrites it in storage and openvox-ca retains no copy, so this is
   the only rollback you will have. A bundle that passes every check can still
   be the wrong one — wrong parent, wrong validity — and rolling back is then
   `import-ca-cert --cert-bundle ca-bundle.backup.pem --force` plus a restart.
2. `openvox-ca csr --out ca-request.pem`, and have the parent sign it.
3. `openvox-ca import-ca-cert --cert-bundle signed-chain.pem --force`.
4. Restart every replica. The CA certificate is read once at startup, so an
   unrestarted replica will keep using the old one.

When `ca_cert_file` mounts the certificate read-only — a Kubernetes Secret, for
example — storage cannot be written directly. Use `--out` to validate the bundle
and write it to a file, load that into the Secret, restart, then run
`openvox-ca-ctl reissue-crl` to bring the CRL under the new certificate.
`--out` and `--force` are mutually exclusive for that reason: `--out` writes no
CRL, and moving the CRL to a certificate that is not yet installed would leave
the CA serving a CRL that does not match itself.

## Token lifecycle

`openvox-ca` proactively renews its OpenBao token before it expires, and
re-authenticates from source credentials — re-reading the AppRole
`secret_id` file, the token file, or the projected ServiceAccount JWT —
whenever renewal itself fails (the token hit its `max_ttl`, was revoked
out-of-band, or OpenBao restarted and lost the lease). A Transit `sign`
request that hits a `403` triggers the same re-authentication immediately,
rather than waiting for the background renewal check, so a revoked token is
recovered from within a single retried request.

The projected ServiceAccount JWT is read from disk on every login attempt
rather than cached across the process lifetime: Kubernetes bound
ServiceAccount tokens are short-lived (default 1 hour) and kubelet rewrites
the token file in place before it expires, so each re-authentication picks
up the current token.

## Performance and outage behaviour

Choosing `ca_key_provider: openbao` moves every CA signing operation from a
local in-memory key to a network round trip to OpenBao, and puts OpenBao's
availability directly on the CA's critical path. This changes the CA's
failure and throughput profile; plan for it:

- **OpenBao must be reachable at startup.** If OpenBao is down when
  `openvox-ca` boots, the initial login fails and the process exits rather
  than starting a CA it cannot sign with. In the isolated-signer deployment
  this is the signer child failing to come up.
- **Signing fails while OpenBao is unreachable.** An in-flight issuance whose
  Transit `sign` call cannot reach OpenBao returns an error to the requesting
  agent; the background loop keeps trying to re-authenticate on roughly a
  5-second cadence, so the CA recovers on its own once OpenBao comes back,
  without a restart. Nothing is queued or retried on the agent's behalf.
- **Throughput serialises at roughly one OpenBao round trip per certificate.**
  Issuance holds the CA's process-wide lock across the signing call, so under
  a large Puppet check-in burst certificates are signed one OpenBao round trip
  at a time rather than in parallel. For most fleets this is fine; if you
  issue at very high rates, keep OpenBao close (network-wise) and sized for the
  request rate.
- **OCSP signs against the same backend, and it does not serialise.** The
  serialisation above is a property of *issuance*, not of every signature. The
  OCSP responder signs outside the CA's process-wide lock
  ([#197](https://github.com/voxpupuli/openvox-ca/issues/197)), so concurrent
  OCSP requests produce concurrent Transit `sign` calls against the same
  backend that issuance uses. Two consequences worth planning for:

  - `/ocsp` is **unauthenticated**, and the only rate limiter in the server
    applies to CSR submission, so the request rate is not something the CA
    bounds for you. A response that misses the cache signs, and an RFC 8954
    nonced request misses on every request.
  - OCSP load and issuance load land on one OpenBao, so a burst of the first
    can consume capacity the second needs. Size and place OpenBao for the sum,
    and if `/ocsp` is exposed to untrusted clients consider fronting it with a
    cache or a proxy-level rate limit.

  `ca_signing_concurrency` is that aggregate bound
  ([#274](https://github.com/voxpupuli/openvox-ca/issues/274)); the bullet
  below says why you should set it explicitly here rather than take its
  default.
- **A stalled backend cannot pin the CA indefinitely.** Each signing round
  trip is bounded by `openbao` login/renew timeout (`LoginTimeout`, default
  10s), so a hung Transit backend fails that request and releases the lock
  rather than wedging all issuance forever. Raising that timeout for a slow or
  distant OpenBao correspondingly raises the worst-case time the lock can be
  held.
- **Set `ca_signing_concurrency` explicitly.** The bound on concurrent CA-key
  signatures defaults to `max(4, GOMAXPROCS)`, derived from *this host's* CPU
  count — a number with no relationship to what your Transit key can sustain,
  especially where other consumers share it. Set it to that key's capacity. The
  bound is per process, so N replicas permit N × the limit against one shared
  key; size it against your replica count too. Leaving it unset here logs a
  warning at startup naming the derived value, because a CPU-derived ceiling is
  the wrong shape for a signer reached over the network — it is not an error,
  but it is almost certainly not the number you want. See
  [bounding CA-key signing](configuration.md#bounding-ca-key-signing).

  This matters most on `/ocsp`, which is unauthenticated and signs on a cache
  miss: it is the one path where a caller you did not authorise decides how many
  Transit requests you make. Requests over the limit are refused with RFC 6960
  `tryLater` and counted in `puppetca_ca_signing_shed_total`.

In short, `ca_key_provider: openbao` makes OpenBao's availability and HA a
hard dependency of CA availability. This is the intended trade-off — the key
never touching the CA host — but it is a real operational change from
local-key custody, where the CA can sign with no external dependency at all.

## Troubleshooting and monitoring

- **CA won't start, logs "initial OpenBao login failed".** OpenBao is
  unreachable, the credential is wrong/expired, or the auth role/policy
  doesn't grant `read` on `transit/keys/<key_name>`. Check connectivity to
  `openbao.addr`, that the `secret_id`/token/JWT file is present and current,
  and that the bound role maps to the scoped policy above.
- **Startup fails with "does not match" / key-rotation errors.** The Transit
  key's public component no longer matches the stored CA certificate — see
  [Key rotation detection](#key-rotation-detection). Point at the correct
  `key_name`, or reissue the CA certificate to match by following
  [Re-issuing the CA certificate later](#re-issuing-the-ca-certificate-later).
- **Issuance intermittently fails with `403`.** The token was revoked or hit
  its `max_ttl`; `openvox-ca` re-authenticates and retries automatically, so
  transient `403`s that recover are expected. Persistent `403`s point at a
  policy/role problem or a `secret_id`/token that can no longer be renewed at
  the source.
- **What to monitor.** Because OpenBao availability is now on the CA's
  critical path, alert on OpenBao reachability/health from the CA hosts and on
  certificate-issuance error rates. Watch OCSP request rates too, if `/ocsp` is
  reachable by untrusted clients: those signatures hit the same backend and are
  not serialised, so they can crowd out issuance without issuance itself
  looking abnormal until it starts failing. Three CA-side metrics cover exactly
  this: `puppetca_ca_signing_in_flight` against `puppetca_ca_signing_limit`
  shows how close the shared bound is to saturation, and
  `puppetca_ca_signing_shed_total` rising means OCSP requests are being refused
  at it. Sustained shedding while Transit has capacity to spare means
  `ca_signing_concurrency` is set below what this deployment needs. Watch the
  OpenBao side too — the CA metrics show contention for the bound, not the
  health of the backend behind it. Also watch for repeated
  "re-authentication failed" warnings in the `openvox-ca` logs — a steady
  stream of those means the source credential can no longer authenticate and
  needs operator attention before the current token lease runs out.

## Key rotation detection

The CA certificate's public key and the Transit key's public key have to
match — if they diverge, certificates signed going forward will not verify
against the CA certificate clients already trust. `openvox-ca` checks for
this in two places:

- **At startup**, when the CA certificate and the Transit key are both
  loaded: if they don't match, `openvox-ca` refuses to start rather than
  silently signing with a key that doesn't correspond to the trusted CA
  certificate.
- **On every certificate issuance**, signing re-verifies the signature the
  Transit key returned against the CA certificate's public key before the
  certificate is persisted or returned. If someone rotates the key directly
  at OpenBao (`bao write -f transit/keys/<name>/rotate`) while `openvox-ca`
  is already running, the next issuance signs with the new key, that
  signature no longer verifies against the trusted CA certificate, and the
  request fails with an error instead of returning a certificate that would
  silently fail verification later. The check adds no extra OpenBao round trip
  — it reuses the signature from the signing request itself.

This works the same way whether or not key isolation (the isolated
`openvox-ca [signer]` process) is in use — the check happens wherever the
certificate is assembled from the Transit signature.

If you do intend to rotate the Transit key, reissue the CA certificate to match
afterwards — see [Re-issuing the CA certificate
later](#re-issuing-the-ca-certificate-later) — rather than rotating it in place
underneath a running CA. Note that `openvox-ca-ctl import` cannot do this job
under Transit: it requires a `--private-key` a Transit-held key can never yield,
and refuses with a message naming `openvox-ca import-ca-cert` instead.

## Process isolation

The isolated-signer deployment (the default; see the
[OpenBao Transit-engine key custody](ca-key-security.md#openbao-transit-engine-key-custody)
discussion) keeps working unchanged in OpenBao
mode: the OpenBao client and its token live inside the isolated
`openvox-ca [signer]` child process, exactly where a local private key lives
today. An OpenBao token scoped to `sign`+`read` on one Transit key is still a
credential capable of signing arbitrary certificates on the CA's behalf, so
it gets the same process isolation a local key would. The frontend process
is unaffected either way — it talks to the signer the same way whether the
signer holds a local key or an OpenBao client.

`--single-process` disables that isolation (as it does for local keys):
the one process authenticates to OpenBao and holds the resulting token
itself.

The launcher passes each child its socketpair end on **fd 3** and the read end of
a pre-shared-key pipe on **fd 4**, so a wrapper script, systemd unit or process
supervisor must not leave an inherited descriptor open at either number — see
[process isolation](ca-key-security.md#process-isolation). This is unchanged by
OpenBao mode.
