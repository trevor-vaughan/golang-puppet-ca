# Operator CLI (`openvox-ca-ctl`)

`openvox-ca-ctl` mirrors the `puppet cert` / `puppetserver ca` subcommands and communicates with a running `openvox-ca` server over HTTP(S). The `setup`, `import` and `migrate` subcommands operate directly on storage and need no running server.

## Global flags

```text
--config       ""                       Path to YAML config file (auto-detected at /etc/puppet-ca/ctl.yaml)
--server-url   https://localhost:8140   openvox-ca server URL
--ca-cert      ""                       CA cert PEM for TLS verification (omit to use system trust store)
--client-cert  ""                       Client certificate PEM for mTLS
--client-key   ""                       Client private key PEM for mTLS
--insecure                              Skip TLS server certificate verification (vulnerable to MITM; use only for testing)
--verbose, -v                           Enable debug logging
```

Global flags may be placed before or after the subcommand name.

`--ca-cert` takes precedence over `--insecure`: if both are given, the server
certificate is still verified, against the supplied CA certificate, and a `NOTE:`
on stderr says `--insecure` was ignored. To override a `ca_cert` set in the config
file or environment and reach `--insecure`, pass an empty `--ca-cert=""`
alongside it.

The file *replaces* the system trust store rather than adding to it, so a server
whose certificate chains to a public CA stops verifying once `--ca-cert` is
given. It may hold a bundle: every certificate in it that parses is loaded, so a
root plus its intermediates can be passed as one file. A file holding no usable
certificate (a DER export, a truncated download, the wrong file) is rejected
before the connection is attempted rather than failing later in the handshake.

`--insecure` disables verification of the **server** and nothing else. The
client certificate is still sent, and the server still verifies it in full:
chain back to this CA, the client-authentication extended key usage, and the
serial against the CRL. None of that is influenced by a flag on the client. So
`--insecure` widens what *you* will talk to; it does not widen what the server
will accept from you.

That distinction is worth having in advance, because the `WARNING:` line says
`vulnerable to MITM` and an operator part-way through a key ceremony may
reasonably decline on those grounds — see [The first credential on a new
CA](#the-first-credential-on-a-new-ca), where it is the flag that unblocks the
one route available.

`--client-cert` and `--client-key` must be supplied together; giving only one is
an error.

Subcommands that contact the server write at most one advisory line to
**stderr**, not stdout: a `WARNING:` about MITM exposure when `--insecure` is in
effect, a `NOTE:` when no `--ca-cert` is supplied, the override `NOTE:` above when
both are, and nothing at all when only `--ca-cert` is. These are expected output,
not failures. `setup`, `import` and `migrate` build no client, so they write no
advisory line and never check `--ca-cert`.

`openvox-ca-ctl --version` prints the version (including commit metadata when
built from a git checkout) and exits. Unlike the global flags above,
`--version` is accepted only on the root command, not after a subcommand.

## Configuration

All global flags can be set via a YAML config file or environment variables. Precedence
(highest → lowest): **CLI flag** → **environment variable** → **config file** → **built-in default**.

The config file is located by checking, in order:

1. `--config /path/to/ctl.yaml` (explicit flag)
2. `PUPPET_CA_CTL_CONFIG` environment variable
3. `/etc/puppet-ca/ctl.yaml` (auto-detected if the file exists)

**Example `/etc/puppet-ca/ctl.yaml`:**

```yaml
server_url:  https://openvox-ca.example.com:8140
ca_cert:     /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem
client_cert: /etc/puppetlabs/puppet/ssl/certs/puppet-master.pem
client_key:  /etc/puppetlabs/puppet/ssl/private_keys/puppet-master.pem
insecure:    false
verbose:     false
```

**Environment variables:**

| Flag | Environment variable |
| --- | --- |
| `--server-url` | `PUPPET_CA_CTL_SERVER_URL` |
| `--ca-cert` | `PUPPET_CA_CTL_CA_CERT` |
| `--client-cert` | `PUPPET_CA_CTL_CLIENT_CERT` |
| `--client-key` | `PUPPET_CA_CTL_CLIENT_KEY` |
| `--insecure` | `PUPPET_CA_CTL_INSECURE` |
| `--verbose` | `PUPPET_CA_CTL_VERBOSE` |

## Subcommands

```bash
# List pending CSRs
openvox-ca-ctl list

# List all certificates (signed, revoked, requested)
openvox-ca-ctl list --all

# Sign a pending CSR
openvox-ca-ctl sign --certname agent.example.com

# Sign all pending CSRs
openvox-ca-ctl sign --all

# Revoke a certificate (the most recent one issued for that name)
openvox-ca-ctl revoke --certname agent.example.com

# Revoke one exact certificate by serial. Use this when a replacement has
# already been issued for the same name and the one it displaced was never
# retired: --certname would now revoke the live replacement and leave the
# superseded certificate valid. Serials are hexadecimal, in any case, and are
# what `openssl x509 -noout -serial` prints.
#
# With superseded_cert_revoke_after_sec set, --certname does reach a predecessor
# still inside its overlap window, so this is for the two cases it cannot: a
# supersession that was never recorded (puppetca_supersede_failures_total is
# what tells you one exists), and cutting an active window short for a
# certificate you now believe is compromised. Revoking a serial the sweep still
# has queued is safe -- re-revoking a listed serial is a no-op.
openvox-ca-ctl revoke --serial 472C95FAA0DAE424BD7E911E26066010

# A serial that is still the certificate stored for its subject is refused,
# because --certname already covers that and a mistyped digit would otherwise
# take a working node offline. --force revokes it anyway.
openvox-ca-ctl revoke --serial 472C95FAA0DAE424BD7E911E26066010 --force

# Revoke + delete cert and CSR. The delete happens even if the revocation
# fails, so check the server log: a certificate that could not be revoked
# stays a valid credential until it expires, and it is no longer in storage
# to clean again. See docs/api.md for the state that causes it. To recover, fix
# that state and revoke the certificate that was deleted but not revoked: the
# inventory row outlives the delete, so `revoke --certname` still reaches it
# while no replacement has been issued for that name, and `revoke --serial
# <hex>` (above) is what is needed once one has. The WARN line names the serial
# only when the revocation got as far as the CRL; otherwise take it from the
# inventory. See docs/api.md for which is which.
openvox-ca-ctl clean --certname agent.example.com

# Re-sign the CRL with a fresh validity window (preserves all revocations)
openvox-ca-ctl reissue-crl

# Generate a server-side key+cert pair (key saved to ./agent.example.com_key.pem)
openvox-ca-ctl generate --certname agent.example.com
openvox-ca-ctl generate --certname agent.example.com --dns alt.example.com --out-dir /etc/ssl

# Import a certificate issued outside this CA's normal flow (e.g. migrated
# from a legacy CA sharing this CA's key)
openvox-ca-ctl import-cert --certname legacy-node.example.com --cert-file legacy-node_cert.pem

# Bootstrap a new CA offline (no server required)
openvox-ca-ctl setup --cadir /etc/puppetlabs/puppet/ssl --hostname puppet.example.com

# Import an external CA cert/key offline
openvox-ca-ctl import \
  --cadir      /etc/puppetlabs/puppet/ssl \
  --cert-bundle ca_cert.pem \
  --private-key ca_key.pem \
  --crl-chain   ca_crl.pem     # optional; omitting it leaves the stored CRL
                               # chain alone. One is generated if none is
                               # stored, and the import is refused if nothing
                               # stored was signed by the certificate being
                               # imported -- pass --crl-chain to replace it.
                               # --crl-chain may hold several concatenated
                               # CRLs in any order. This CA's own is identified
                               # by signature and moved to the front; the rest
                               # are kept and served so agents can do full-chain
                               # revocation checking. Every X509 CRL block must
                               # parse; other PEM block types are ignored and
                               # not stored.
                               #
                               # With crl_chain_file configured on the server,
                               # that file is authoritative instead: ancestors
                               # imported here but absent from it are dropped
                               # on the next CRL amendment. See "Publishing an
                               # upstream CRL chain" in the configuration
                               # guide.
# The bundle must be a complete chain, nearest first, ending at a self-signed
# root, and every certificate in it must be within its validity window. If the
# CA's key is held by a provider rather than a file, there is no --private-key
# to pass: use `openvox-ca import-ca-cert` instead (below).
#
# --crl-chain must contain only X509 CRL blocks. Every one is parsed, and only
# the parsed CRLs are stored -- so a file with a certificate or a key
# concatenated into it is refused, for the same reason the certificate bundle
# rejects keys: the result is world-readable and served to every agent.

# Migrate an entire CA between storage backends offline (any pair of backends:
# filesystem, sqlite, postgres, mysql, etcd, redis/valkey). Each backend is
# described by a normal openvox-ca config file. Refuses a non-empty destination
# unless --force.
openvox-ca-ctl migrate \
  --source-config /etc/puppet-ca/filesystem.yaml \
  --dest-config   /etc/puppet-ca/postgres.yaml
```

`setup`, `import` and `migrate` operate directly on storage, and each requires
the server to be **stopped** on a backend that supports one running instance
(`filesystem`, `sqlite`). Run one beside a live server and it is refused, naming
the process holding the store — not left waiting for a lock it was never going
to get. Because they reach storage directly they take the same locks a running
server takes, so run them as the user the server runs as rather than under
`sudo` (see the link below for why). See [running a second process against a
live store](storage-backends.md#running-a-second-process-against-a-live-store).
See [storage backends](storage-backends.md#migrating-between-backends) for migration details.

## Offline subcommands on the server binary

Three subcommands live on `openvox-ca` rather than `openvox-ca-ctl`, because they
must reach the storage backend and CA key provider named in the *server's*
configuration. `openvox-ca-ctl` reads a different configuration file and can
only address a local filesystem directory, so it cannot serve a CA whose state
is in PostgreSQL or whose key is in OpenBao Transit.

None of them needs a running server, and on a backend that supports one running
instance none of them will run beside one: each is refused, naming the process
holding the store. Stop the server first. Within an instance they take the CA's
locks while they work — `csr --create-key` and `import-ca-cert` take
`bootstrap`, `import-ca-cert` the CRL lock too, and `generate` takes
`subject:<name>` for the name it is minting, plus the CRL lock when `--force`
revokes the certificate it replaces. See [running a second process against a
live store](storage-backends.md#running-a-second-process-against-a-live-store).

All three read the **server's** configuration, not `openvox-ca-ctl`'s: `--config`, or
`PUPPET_CA_CONFIG`, defaulting to `/etc/puppet-ca/config.yaml`. A working
`ctl.yaml` has no effect on them. `--cadir` overrides the configured storage
directory for a one-off run.

```bash
# Emit a certificate signing request for the CA's own key, for an external
# parent CA to sign. Works for every ca_key_provider.
openvox-ca csr --out ca-request.pem

# ... and create the key first, if it does not exist yet
openvox-ca csr --hostname puppet.example.com --create-key --out ca-request.pem

# Install the chain the parent signed, completing the round trip
openvox-ca import-ca-cert --cert-bundle signed-chain.pem

# Mint a certificate with no running server and no API
openvox-ca generate --certname web01.example.com --ttl 8760h \
  --key-out web01_key.pem > web01.crt

# ... and make it a CA administrator credential
openvox-ca generate --certname admin-cli --ttl 8760h --pp-cli-auth \
  --key-out admin-cli_key.pem > admin-cli.crt
```

`csr` reuses an existing CA certificate's subject verbatim — the encoded DN is
carried across byte for byte, so re-issuance reproduces the established name
exactly, including attributes the `ca_subject_*` settings cannot express. When
no certificate exists yet it builds the name from `hostname` and those settings —
the same name a self-signed bootstrap would use — and refuses if `hostname` is
unset rather than guessing, because the request is about to be signed by a third
party.

`--create-key` creates the CA key when it does not exist, and never replaces one
that does. Between `csr --create-key` and `import-ca-cert` the CA has a key but
no certificate, and **the server will refuse to start** in that window rather
than bootstrap over the key your parent CA is in the middle of signing. This
holds for every `ca_key_provider`, including the default. Run the two steps
together, or stop the service while you do.

> **These subcommands read the config file and `PUPPET_CA_*` environment only.**
> The server's storage and key-provider flags (`--storage-backend`, `--sql-dsn`,
> `--ca-key-provider`, `--openbao-*`, `--encrypt-ca-key`, …) belong to the server
> command itself and are not available here, so a server configured entirely by
> flags — including the container image's own `CMD` — is invisible to them. That
> matters: with no config file, `csr --create-key` would resolve
> `ca_key_provider: file`, mint a **local** CA key, and emit a request bound to a
> key a Transit-backed server will never use, so the parent would sign the wrong
> key. All three commands therefore print the config file, storage backend and
> key provider they resolved before doing anything — check those lines match the
> server. If your server is configured by flags, mirror the storage and
> key-provider settings into the config file or `PUPPET_CA_*` environment for
> these commands.
>
> `generate` extends this to the settings that shape or record what it issues:
> `crl_url`, `ocsp_url` and `logfile`. A flag-configured server would otherwise
> leave it minting certificates with no CRL distribution point while the
> server's own issuance carries one, and with no durable record that an
> administrator credential was created. Mirror those too.
>
> `promote_cn_to_san` needs no mirroring: it has no flag, so the config file and
> `PUPPET_CA_*` are its only sources — the same two this command reads, and it
> cannot diverge from the server. It is still printed in the pre-flight, because
> it decides what a run without `--dns` produces.

`import-ca-cert` requires a **complete chain, nearest first**: this CA's own
certificate, each issuer after it, ending with a self-signed root. Supply only
certificates; a bundle carrying a private key is rejected, because this file is
stored world-readable and served to every agent.

> [!IMPORTANT]
> **This bundle is what every agent trusts.** It is served by
> `GET /certificate/ca`, so each certificate in it is a CA the fleet accepts —
> and ending at a root admits every sibling sub-CA beneath that root, present
> and future, not only this CA's own ancestors.
>
> That is the price of Puppet's default `certificate_revocation = chain`, not
> something to design around: under it a shorter bundle does not check less, it
> stops agents connecting. Tested on a reconstructed `root → intermediate →
> leaf` PKI with OpenSSL 3.6.3, where it fails twice over — path building will
> not end at a non-self-signed anchor without `PARTIAL_CHAIN`, which Puppet does
> not set, and with that forced, `-crl_check_all` then demands a CRL for the
> anchor itself:
>
> ```bash
> openssl verify -CAfile intermediate.pem -crl_check_all -CRLfile crls.pem leaf.pem
> ```
>
> `certificate_revocation = leaf` permits a narrow bundle, at the cost of no
> revocation checking above the leaf's issuer.

**Ancestor CRLs are part of the same decision.** Whatever issuers this bundle
carries, their CRLs must be published too or agents running `chain` fail
verification — and a CRL for an issuer *not* in the bundle is discarded and
alerts, because nothing here can verify it. `openvox-ca-ctl import --crl-chain`
seeds them where the key is a file; where the key is held by a provider there is
no `--private-key` to pass, so use `crl_chain_file` in the server configuration
instead, which re-reads the ancestors on a timer and needs no key at all. See
[Publishing an upstream CRL chain](configuration.md#publishing-an-upstream-crl-chain).

Two further rules, both checked before anything is written, and both worth
knowing before you ask the parent to sign rather than after:

- **The leading certificate must carry a CA profile.** If a KeyUsage extension
  is present it must include `keyCertSign` and `cRLSign`; without them the
  certificate installs cleanly and then cannot issue certificates or publish a
  CRL. A parent signing through a narrowed role — an OpenBao PKI role with a
  restricted `key_usage`, say — is the usual cause. An absent KeyUsage extension
  is unconstrained by RFC 5280 and is accepted. `pathlen:0` is correct for this
  CA, not a fault: it permits end-entity certificates and forbids further CAs,
  which is exactly what openvox-ca issues.
- **Every certificate in the chain must be within its validity window.** Not
  just the leading one: an expired root or issuer further up is refused here
  rather than discovered as chain-verification failures across the fleet, after
  the bundle has been written and served.

The command never needs the private key *material*: it proves the certificate
binds the key the configured `ca_key_provider` holds, which is what makes
importing without a key file safe. With the default `file` provider that means
reading the key from storage (and decrypting it, if `encrypt_ca_key` is set);
with OpenBao Transit the key never leaves the vault and only its public
component is compared.

Use `--force` to replace an existing CA certificate — it re-signs the stored
CRL, which the replacement would otherwise invalidate, and reminds you to
restart every replica afterwards.

When the CA certificate is mounted read-only from outside (`ca_cert_file`
pointing at a Kubernetes Secret, say), `--out` validates the bundle — including
the key-binding proof — and writes it to a file instead of to storage, for
loading into the Secret out of band.

See [running under an external root CA](openbao-transit.md#running-under-an-external-root-ca)
— written against OpenBao Transit, but the procedure is identical for every
`ca_key_provider`, including the default file provider —
for the end-to-end procedure.

### `generate`: minting a certificate offline

`generate` issues a certificate directly against the configured storage backend
and CA key provider. No running server, no API, and no admin client certificate.

**Use the API for ordinary node certificates.** `POST /generate/{subject}`, or
an agent submitting a CSR, needs no outage and no shell on the CA host. This
command exists for the two cases the API cannot serve:

- a `pp_cli_auth` administrator credential, which the API refuses to issue by
  construction (see [Auth-arc OID stripping](migrating-from-puppet-server.md#auth-arc-oid-stripping));
- minting before a server exists. `openvox-ca-ctl generate` can only reach that
  by starting the CA temporarily on loopback with TLS disabled, where every
  endpoint is unauthenticated — which is exactly the dance the migration guide
  used to prescribe, and what this command exists to make unnecessary.
  [The first credential on a new CA](#the-first-credential-on-a-new-ca) walks
  through that case: it is a deadlock rather than an inconvenience, and it is
  the one an operator meets first.

`--dns` adds subject alternative names, repeatable or comma-separated. Supplying
it **suppresses CN promotion**: with no `--dns`, the certname is added as a DNS
SAN automatically (RFC 2818 clients match SANs, not the CN) — unless
`promote_cn_to_san: false` is set, in which case a run with no `--dns` mints a
certificate with **no SANs at all**, which is the same unusable outcome by
configuration rather than by flag. Check the value the pre-flight prints. As
soon as you supply any `--dns`, the list is taken verbatim. So a serving certificate that must answer
to both its own name and an alias has to list both:

```bash
openvox-ca generate --certname ca.example.com --ttl 8760h \
  --dns ca.example.com,puppet.example.com --key-out ca_key.pem > ca.crt
```

Omitting the certname there yields a certificate no client will accept for it.

`--ttl` is required. There is deliberately no default: a certificate minted this
way is usually long-lived and privileged, and inheriting a multi-year built-in
silently is the wrong failure. One year is `8760h`.

What you get is a certificate the CA can see. It takes a serial from the CA's
own generator, is written to the inventory, appears in `openvox-ca-ctl list
--all`, is swept by the expiry job, and can be revoked by name — none of which
is true of a certificate signed out of band with `openssl`.

**Autosign policy is not consulted.** This is an operator action rather than a
request, and it has to work when there is no policy configured and no server
running to evaluate one.

**It refuses rather than bootstrapping.** If the configured storage holds no CA
certificate and no key, the command stops. A mistyped `--cadir` would otherwise
mint a brand-new CA and issue under it, leaving you with certificates nothing in
your fleet trusts and no obvious sign of why.

#### Where the private key goes

`--key-out` writes the key to a path you choose, at mode 0600, and keeps no copy.

Without it the key goes to the cadir's `private/` directory, which has two
properties worth knowing. Nothing sweeps that directory, so the key persists
there until you remove it. And it is written to the **local filesystem whatever
the storage backend**, so on an ephemeral cadir — a container with no persistent
volume — it is lost at the next restart while its certificate stays live in the
shared inventory.

`--key-out` is therefore **required** with `--pp-cli-auth` (an administrator
credential whose key evaporates is the worst version of that problem) and with
`--force` (see below).

Both `--key-out` and `--cert-out` refuse a path that already exists rather than
overwriting it, and they refuse before anything is issued — a mint cannot be
undone, so a path collision has to be caught first. There is no `--overwrite`:
move the previous file aside, which re-minting for a name you already hold will
require you to do.

#### Running alongside a live server

The command prints whether the resolved backend can coordinate writes with other
processes, and warns when it cannot.

Two independent capabilities matter, and the command reports safe to run
alongside a live server only when a backend has **both**:

| Backend | Cross-node locking | Atomic inventory append | Verdict |
| --- | --- | --- | --- |
| `postgres`, `mysql` | yes | yes | safe |
| `etcd` | yes | yes | safe |
| `redis` | yes | yes | safe |
| `sqlite` | no (single-node) | yes | refused while the server runs |
| `filesystem` (default) | no (single-node) | no | refused while the server runs |

The last two rows are not advice. A backend without cross-node locking supports
one running instance, so the server holds the store while it runs and `generate`
is refused outright, naming the process holding it — see [running a second
process against a live
store](storage-backends.md#running-a-second-process-against-a-live-store).
`redis` coordinates across nodes and appends atomically — its Lua append
advances the integrity head in the same script — so several instances are
supported and this command is safe beside them.

Note which lock the first column measures: the **cross-node** one, which is what
`SupportsDistributedLocking` probes and the only one that helps when the other
writer is on another host. `filesystem` and `sqlite` also take an `flock(2)`
between processes on one host, but that is a different and weaker guarantee —
the probe deliberately does not report it as this one, and it is what the
single-instance rule is enforced with rather than a substitute for it.

What each missing capability costs is different. Without cross-node locking, two
writers on different hosts can each decide a subject has no certificate and both
issue one. Without an atomic inventory append — `filesystem` alone — the
integrity record is recomputed from a snapshot, so an interleaved append leaves
an HMAC covering a state that never existed, after which the server refuses to
start. Recovery is a cutover: `migrate` rebuilds the integrity value on the
destination, so it needs a second store, and a supported in-place rebuild is
still open ([#188](https://github.com/voxpupuli/openvox-ca/issues/188)). That
second failure is the reason to take this seriously. It does not apply to
`sqlite`, which is single-node but appends atomically, nor to `etcd` and
`redis`, whose inventories are decomposed into per-entry keys and fields and
whose appends commit the entry and the integrity head together. The threat model
is in
[inventory-store.md](development/inventory-store.md#inventory-integrity-threat-model-and-rationale).

On a fresh install this costs nothing, because there is no server running yet.
It is re-minting on an established CA that forces a real outage.

In containers, pass `--cadir` explicitly: the shipped image sets it in the
image's `CMD` rather than in a config file, so the bare command cannot find it.
Where the backend does coordinate, `podman exec` or `kubectl exec` into the
running CA is fine. Where it does not, stop the service and run a one-shot
container against the same volume, mounting somewhere for `--key-out` to land
that outlives the container:

```bash
mkdir -p ca-admin-out
podman unshare chown 1000:1000 ca-admin-out
podman run --rm \
  -v ca-data:/data \
  -v "$PWD/ca-admin-out":/out:Z \
  ghcr.io/voxpupuli/openvox-ca:1.2.3 \
  generate --cadir /data --certname admin-cli --ttl 8760h \
  --pp-cli-auth --key-out /out/admin-cli_key.pem > admin-cli.crt

# Take the key back: it lands 0600 owned by the container's user.
podman unshare chown 0:0 ca-admin-out/admin-cli_key.pem
```

Five details that are easy to get wrong. **Pin the image to the version the
stopped server was running**, as shown, rather than taking `:latest`: this
container writes on-disk state that the server wrote and will read again when it
restarts, the inventory and its integrity record among it, so a version
difference here is between two writers of the same data rather than between a
client and a server. The image must be fully qualified — an unqualified name
will not resolve without registry search configured. The images run as
uid 1000 (the `puppet` user), so under rootless podman a bind mount owned by your host user is
not writable inside the container — the mint then fails at the key write,
cleanly but confusingly. Hence the `podman unshare chown`: it sets the
directory's owner to whatever container uid 1000 maps to on the host, which is
what `puppet` runs as.

That mapping has to be undone afterwards, which is the last line of the recipe.
The key is written `0600` as `puppet`, so on the host it belongs to a subuid you
are not, and reading it back as yourself gives `Permission denied` — a key you
cannot open is the same as no key at all, which is the standard this section
already sets for the Kubernetes path. Inside `podman unshare` you *are* uid 0,
so `chown 0:0` hands it back; do not reach for `$(id -u)`, which the shell
expands outside the namespace and would hand the file to a different subuid
again.

Resist fixing that with `--userns` instead. A remap applies to every path the
container touches, `ca-data` included, so mapping yourself onto uid 1000 shifts
the CA files the server left behind out from under it — and the failure moves
from the key write to the CA directory, which is a worse place to discover it.
The images create `puppet` with no explicit id, so it takes the distro's first
regular uid; confirm yours with
`podman run --rm --entrypoint id ghcr.io/voxpupuli/openvox-ca:<tag>`. The
`--entrypoint` is needed because the images set one — which is also why the
recipe above appends `generate ...` rather than a shell command. And the mount
is a dedicated directory with `:Z` rather than `$PWD` with `:z`, because `:Z`
relabels its target private to the container — pointing that at a whole project
or home directory would relabel unrelated files with it.

On Kubernetes the equivalent is scaling the Deployment to zero and running a Job
that mounts the same PVC, pinned for the reason above to the digest the
Deployment was running — the subsection below has how to read that back — and
with a retrieval step for the key: a `--key-out` path inside a Job pod that is
then reaped is the same as having no key at all.

One more asymmetry to expect: a running server answers OCSP `unknown` for a
certificate minted this way until it restarts, because its serial index is built
at startup. The CRL and the inventory are correct immediately.

##### Reading the version back off a floating tag

Pin the *version*, not whatever tag the deployment names. `compose.yml` ships
`:latest` deliberately, so copying the tag from a deployment that floats would
reintroduce exactly the skew this avoids.

Take the digest off the **running container, before you stop it**. Inspecting
the tag instead would resolve to whatever `:latest` points at now, which is the
one thing it may no longer be:

```bash
podman inspect --format '{{index .RepoDigests 0}}' \
  "$(podman inspect --format '{{.Image}}' openvox-ca)"
```

`openvox-ca` is the container name — `compose.yml` sets none, so under compose
it is named for the project and service; `podman ps` will tell you. The command
prints `ghcr.io/voxpupuli/openvox-ca@sha256:…`, which goes into the `podman run`
above in place of the tag. Prefer that digest to the
`org.opencontainers.image.version` label: the label is stamped from the git ref,
so on a release it reads `v1.2.3` while the published tag is `1.2.3`, and
pasting it back gives `manifest unknown` at the point you have already stopped
the CA.

An image built locally rather than pulled has no repo digest, and the command
errors rather than printing one. Pin such a build by the image id the inner
command prints, which `podman run` also accepts — not by the tag you gave it,
which the next `podman build -t` moves.

On Kubernetes take the resolved digest from the running pod, again before
scaling the Deployment down:

```bash
kubectl get pod -l app=openvox-ca \
  -o jsonpath='{.items[0].status.containerStatuses[0].imageID}'
```

`app=openvox-ca` is only an example — this project ships no manifests, so use
whatever selector your own Deployment carries; the Deployment you are about to
scale down will tell you
(`kubectl get deploy <name> -o jsonpath='{.spec.selector.matchLabels}'`). An
empty result means the selector matched nothing, not that there is no digest.
Expect `ghcr.io/voxpupuli/openvox-ca@sha256:…`, usable as the Job's `image:`
verbatim; some runtimes report a bare `sha256:…` config id instead, which is not
pullable. Resolve it registry-side in that case, with the tag the pod is still
running (`kubectl get pod <name> -o jsonpath='{.spec.containers[0].image}'`):

```bash
skopeo inspect --format '{{.Digest}}' \
  docker://ghcr.io/voxpupuli/openvox-ca:<tag>
```

Two caveats. This asks the registry what the tag means *now*, which is the very
thing the top of this subsection says not to trust: it is the running image only
if nothing has re-pointed the tag since the pod started, and from a bare config
id that is awkward to confirm — these are multi-arch tags, so `--raw` returns an
image index with no `config` object to compare against, and getting one means
selecting the platform entry and inspecting that digest in turn. If you are in
this branch, treat the result as a best effort and take the digest properly next
time. Second, without `--raw` skopeo resolves the index for your workstation's
platform, so an arm64 laptop returns an arm64 digest for an amd64 cluster; pass
`--override-os`/`--override-arch` to match the nodes. Once the pod is gone the
tag is all there is — which is the whole reason to take the digest before
scaling down.

#### Replacing a certificate

By default a live certificate for the name blocks re-issuance with `certificate
already exists`. A name whose certificate was previously cleaned or revoked
re-issues freely — the block is on a live certificate, not on a name that
appears in the inventory.

`--force` revokes the existing certificate and issues a replacement. The old
serial goes on the CRL, but **a running server honours it until that server
reloads the CRL**, which can be a substantial fraction of `crl_validity_days` away.
Restart it if that matters. If the name is the CA's own hostname, the command
says so: you may be revoking the certificate the server is currently serving.

`--force` revokes the serial of the certificate in storage, which is not
necessarily every live serial for the name — see the withdrawal note below.

#### Administrator credentials

`--pp-cli-auth` stamps the `pp_cli_auth` extension, which grants the holder the
entire admin tier: signing any request, signing all of them, generating for any
name, revoking, cleaning, importing, and replacing the CRL. See
[authorization tiers](api.md#authorization-tiers).

The command prints a warning naming all of that before it issues, and requires
`--key-out`.

**Withdrawing the grant is not one step**, and this is the part that is easy to
get wrong:

1. `openvox-ca-ctl revoke --certname <name>` — revokes the newest serial.
2. **Restart every replica.** Each holds its own CRL cache, so a revocation made
   elsewhere is not honoured until the process reloads it; waiting for that can
   take roughly two-thirds of `crl_validity_days`, and even afterwards a pre-signed
   OCSP response can vouch for the revoked serial for up to another four hours.
3. **Check the inventory for other live serials for that name.** With
   `revoke_on_auto_renew: false`, or after a renewal whose best-effort revoke
   failed, more than one can be valid. Step 1 retires only the newest; retire
   each of the others with `openvox-ca-ctl revoke --serial <serial>`, which
   needs `--force` where the serial is still the certificate stored for its
   subject. Step 2 applies to each of them: a revocation is not honoured by a
   replica until it reloads.

Choose `--ttl` with that in mind even so. Every extra live serial is another
round of the three steps above, and the operator retiring the credential has to
find them all — a short lifetime bounds the damage of missing one.

`no_pp_cli_auth: true` makes the extension grant nothing, and the command
refuses rather than minting an inert certificate. Treat that as a convenience
check rather than a security boundary: it reads the configuration *this command*
resolved, so it cannot see `--no-pp-cli-auth` passed as a server flag, and it
can refuse when a shared config file sets it but the running server does not.

Note also what is *not* recorded. The inventory line is the Puppet-compatible
format — serial, dates, subject — with nothing about the grant, so the log
message this command emits is the only record distinguishing an administrator
credential from a node one. It is written by whoever ran the command, and it
only lands somewhere durable if `logfile` is configured in a file this command
can read **and that file already exists**. `generate` deliberately never creates
it: run before the server has ever started, and as root, it would leave a
root-owned logfile the unprivileged server then cannot open, and the service
would fail to start. In the flagship case — minting before the first start —
that means the record is terminal-only unless you create the file first with the
server's runtime ownership, or capture stderr.

The line to alert on is `Issued certificate carrying a Puppet authorisation
extension`, with attributes `subject` and `grant`. `--force` emits a second one
for the certificate it retired: `Revoked a certificate to make room for its
replacement`, at `INFO`, with `subject` and `serial`.

Match on the message string and the attribute names, not on a copied line: the
two sinks use different encodings. With no `logfile`, logging goes to stderr as
logfmt —

```text
level=WARN msg="Issued certificate carrying a Puppet authorisation extension" subject=openvox-admin grant="pp_cli_auth=true"
```

— while a configured `logfile`, which is what reaches a log aggregator, gets
JSON:

```json
{"level":"WARN","msg":"Issued certificate carrying a Puppet authorisation extension","subject":"openvox-admin","grant":"pp_cli_auth=true"}
```

Both are worth a rule wherever these logs are aggregated; see
[Monitoring destructive operations](ca-key-security.md#monitoring-destructive-operations).

**Who can do this.** The `openssl` recipe this replaces required the raw CA key
file. This requires the ability to run the binary with the server's
configuration — which under `ca_key_provider: openbao` means Transit sign
permission plus write access to the cadir, rather than the key itself. That is a
deliberate widening, and the reason the feature is possible at all, but it is
worth knowing when deciding who gets a shell on the CA host.

Where the caller has a stable CN, `--puppet-server` remains the lower-privilege
alternative: an allow-list entry is withdrawn by editing a file and restarting,
with none of the above.

#### The first credential on a new CA

A CA that has just been stood up — self-signed, or a Transit-backed sub-CA whose
chain has only now been imported — has a deadlock in it. It is easy to walk into
and hard to reason about from inside, so it is worth meeting on paper first:

- signing a pending request is an admin-tier operation;
- admin membership is the `--puppet-server` allow list, or `pp_cli_auth`;
- client certificates are verified against **this** CA and no other.

The allow list is a list of names, and it survives the change perfectly well.
What does not survive is the certificates behind those names: they were issued
by the CA you have just replaced, so they no longer verify, and an allow-listed
name whose certificate does not verify never reaches the tier check. The first
agent to check in leaves a pending CSR that nothing in existence can sign.

Nothing is broken at that point. There is simply no credential yet that this CA
will accept, and no way to create one through an API that requires one.

`generate` is the way out, because it never touches the API:

```bash
# 1. Mint the first administrator credential, offline, against the new CA.
openvox-ca generate --certname openvox-admin --ttl 8760h --pp-cli-auth \
  --key-out openvox-admin_key.pem > openvox-admin.crt

# 2. Start the server. It indexes the new serial as it comes up.

# 3. Sign the waiting request, using the credential from step 1.
openvox-ca-ctl sign --certname agent01.example.com \
  --client-cert openvox-admin.crt --client-key openvox-admin_key.pem \
  --insecure
```

Minting **before** the first start, rather than after, is also what keeps step 1
in the case that needs no coordination: no server is running, so none of
[Running alongside a live server](#running-alongside-a-live-server) applies. If
the server is already up, read that section first — the answer depends on your
storage backend.

Two details in that sequence cost time if you meet them cold.

**`--ttl` has no default and step 1 fails without it.** That is deliberate, for
the reason given above, and it fails before doing anything — but a bare `required
flag(s) "ttl" not set` part-way through a ceremony reads as the command being
broken rather than as an argument you have not supplied yet.

**Step 3 needs `--insecure`, and that is less alarming than it sounds.** The
serving certificate names the CA's public hostname; you are connecting to
`localhost`, the default `--server-url`, so the name check fails. `--insecure`
turns off verification of the *server* only. The credential you just minted is
still verified in full at the other end — chain, extended key usage and
revocation — so this weakens what you will talk to, not what the CA will accept
from you.

If you would rather not pass it at all, the alternative is to reach the server
by a name on its certificate, arranging resolution locally and passing
`--server-url https://puppet.example.com:8140`. That is the same trust decision
made in a different place, not a stronger one; the flag is not the thing to
avoid here.
