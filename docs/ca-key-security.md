# CA key security

This page covers how the CA private key is protected while the CA is running and
at rest, the options for moving key custody off the CA host entirely, the
detective control that watches for anomalous destructive operations, and where
inventory integrity's own key lives.

## Process isolation

By default `openvox-ca` runs as three processes, and **only one of them ever
loads the CA private key**:

| Process | Holds the key | Listens on the network |
| --- | --- | --- |
| launcher | no | no |
| `openvox-ca [signer]` | yes | no |
| `openvox-ca [frontend]` | no | yes |

The frontend serves every API request and never has the key in its address
space; when it needs a signature it sends the digest to the signer over a
pre-connected Unix socketpair and gets the signature back. So a memory-disclosure
bug in the HTTP layer — the part exposed to agents — cannot leak the key, because
the key is not there to leak. `--single-process` collapses all three into one and
gives that up; it exists for containers and debugging.

The two children inherit two file descriptors from the launcher:

| Descriptor | Contents |
| --- | --- |
| fd 3 | this child's end of the socketpair |
| fd 4 | read end of a pipe holding a per-start pre-shared key |

Before the first signing call the two ends run a **mutual** challenge-response
over that pre-shared key: each proves knowledge of it to the other, with distinct
domain-separation labels per direction. A process that somehow obtained a leaked
socketpair descriptor can impersonate neither side, and a child whose fd 4 is not
the launcher's pipe refuses to start rather than proceeding unauthenticated.

> **The pre-shared key travels over a pipe, not the environment.** A process's
> exec-time environment stays readable at `/proc/<pid>/environ` for its whole
> lifetime — `os.Unsetenv` only mutates the process's own copy — and is captured
> verbatim by crash-dump tooling such as `systemd-coredump`. A pipe is consumed
> once and leaves no such residue.
>
> **Do not run a role process by hand with a descriptor open at fd 3 or fd 4.**
> The launcher replaces both numbers in the children it spawns, so a descriptor
> your supervisor or wrapper script leaks is harmless in the default topology. It
> matters when you set `PUPPET_CA_ROLE` yourself: `execve` preserves every
> descriptor not marked close-on-exec, so whatever your shell left at fd 4 is what
> the process finds there. A descriptor that is not a pipe is refused immediately.
> A *pipe* cannot be told from the launcher's by inspection, so it gets ten
> seconds to produce a valid pre-shared key before the process gives up and says
> so — and fails at once if it is already at end-of-file or carries anything else.

The same isolation is why the shipped systemd unit sets `LimitCORE=0` and
withholds `$NOTIFY_SOCKET` from the signer — see
[running under systemd](systemd.md).

### The signer is a shared resource, and how it is bounded

Every signature the CA makes crosses the socketpair to this one process:
certificate issuance, CRL re-signing, **and OCSP responses**. Isolation decides
*where* the key lives; on its own it does nothing to limit how much work
reaches it.

**OCSP signing does not serialise, and `/ocsp` is unauthenticated.** Issuance
holds the CA's process-wide lock across its signing call, so it proceeds at
roughly one round trip at a time. The OCSP responder does not
([#197](https://github.com/voxpupuli/openvox-ca/issues/197)) — that was the
point of the change — so concurrent OCSP requests become concurrent signer
round trips. The endpoint is public by design (verifiers query it before they
hold a client certificate), the only rate limiter in the server applies to CSR
submission, and a response that misses the cache signs. An RFC 8954 nonced
request misses on every request.

**`ca_signing_concurrency` is the aggregate cap**
([#274](https://github.com/voxpupuli/openvox-ca/issues/274)). It bounds all
three paths together, because they share one key, and it defaults to
`max(4, GOMAXPROCS)` — sized for exactly this topology, since signing is
CPU-bound inside the signer child and beyond the CPU count extra concurrency
buys latency and memory rather than throughput. Issuance and CRL re-signing
queue for a slot; the OCSP responder is refused with RFC 6960 `tryLater`, which
costs no key work because a non-success OCSP response carries no signature. See
[bounding CA-key signing](configuration.md#bounding-ca-key-signing).

**`RemoteSigner.Sign` waits at most two minutes.** The OpenBao Transit path
bounds every call by its login timeout; the isolated signer's RPC used to bound
nothing at all, so a signer child that stopped answering blocked its caller
indefinitely. It now gives up and returns an error, which is what lets a
signing slot come back.

That deadline is a backstop, not a tuning, and it bounds *this caller's wait
rather than the signer's work*: the RPC layer has no cancellation, so an
abandoned call leaves the child still signing and its reply is discarded. If
you have raised OpenBao's login timeout substantially, note that the signer
child's own call is bounded at roughly twice it — well inside two minutes at
the 10s default, but worth knowing the ceiling exists.

An abandoned call also leaves a small entry in the RPC client's pending table,
which is only reclaimed if a reply eventually arrives. Against a signer that is
wedged rather than dead none ever does, so during such an incident the frontend
accumulates roughly a megabyte a day — bounded at `ca_signing_concurrency`
entries per two minutes, because every signature passes through that bound
first. It is a deliberate trade: without the deadline the frontend instead
accumulated stuck goroutines and never got its signing slots back. Nothing
needs doing about it beyond fixing the signer; the frontend cannot re-dial,
since the socketpair is inherited once at spawn, so restarting the service is
what clears it.

Fronting `/ocsp` with a cache or a proxy-level rate limit remains worthwhile
where it is reachable by untrusted clients: the cap stops CA-key work growing
without limit, but it does not stop the connections, handshakes and goroutines
that carry the requests.

Watch `puppetca_ca_signing_shed_total` and `puppetca_ca_signing_in_flight`
against `puppetca_ca_signing_limit` — sustained shedding while the signer has
capacity to spare means the limit is too low. A rise in issuance latency with
no rise in issuance *rate* is still the signal that OCSP is crowding issuance
out. See [metrics.md](metrics.md).

The equivalent note for the OpenBao Transit backend is in
[the OpenBao Transit guide](openbao-transit.md) under "Performance and outage
behaviour".

## CA key encryption at rest

By default, the CA private key is stored as unencrypted PEM at `<cadir>/private/ca_key.pem`.
Enable `--encrypt-ca-key` to encrypt the key at rest using AES-256-GCM with an Argon2id-derived key.

### How it works

- The private key is marshalled to PKCS#8 DER, then encrypted with AES-256-GCM.
- The encryption key is derived from a passphrase using Argon2id (time=3, memory=64 MiB, threads=4).
- The encrypted key is stored as a PEM block with type `ENCRYPTED PRIVATE KEY`.
- On startup, the key is decrypted into memory and used for all signing operations.

### Passphrase resolution order

1. **`--ca-key-passphrase-file`:** reads the first line of the specified file.
2. **`PUPPET_CA_KEY_PASSPHRASE`** environment variable: avoids CLI `/proc/cmdline` exposure.
3. **Auto-generated:** if no passphrase source is configured, a cryptographically random
   passphrase is generated and saved to `<cadir>/private/.ca_key_passphrase` (mode `0600`).
   The path is logged at startup so operators know where it is.

### Example usage

```bash
# Bootstrap with encryption (auto-generated passphrase):
openvox-ca --cadir /var/lib/puppet-ca --encrypt-ca-key

# Bootstrap with an explicit passphrase file:
echo "my-secret-passphrase" > /etc/puppet-ca/key-passphrase
chmod 600 /etc/puppet-ca/key-passphrase
openvox-ca --cadir /var/lib/puppet-ca --encrypt-ca-key \
  --ca-key-passphrase-file /etc/puppet-ca/key-passphrase

# Or via environment variable:
export PUPPET_CA_KEY_PASSPHRASE="my-secret-passphrase"
openvox-ca --cadir /var/lib/puppet-ca --encrypt-ca-key

# openvox-ca-ctl setup also supports encryption:
openvox-ca-ctl setup --cadir /var/lib/puppet-ca --encrypt-ca-key
```

### Backward compatibility

Existing CAs with unencrypted keys continue to work without changes. The `--encrypt-ca-key`
flag only affects new CA bootstraps. Loading transparently handles both encrypted and
unencrypted PEM files.

### Security considerations

Encrypting the CA key at rest protects against **offline exfiltration**. If an attacker
obtains the key file from a backup, disk image, or volume snapshot, the key is unusable
without the passphrase. It does **not** protect against a live host compromise where the
attacker can read the passphrase source or dump the process memory.

For stronger protection, either delegate key custody to OpenBao entirely (available
today; see [OpenBao Transit-engine key custody](#openbao-transit-engine-key-custody)
below) or consider a hardware security module (HSM) via PKCS#11 (planned; see
[Planned: PKCS#11 / HSM support](#planned-pkcs11--hsm-support) below).

## OpenBao Transit-engine key custody

`--ca-key-provider openbao` delegates the CA private key entirely to an
[OpenBao](https://openbao.org/) Transit secrets engine key: the key never exists inside
any `openvox-ca` process at all, on disk or in memory — only a digest crosses the wire
to be signed. This works identically whether `openvox-ca` runs as a plain systemd
service (AppRole or a static token file) or as a Kubernetes pod authenticating via its
own ServiceAccount (Kubernetes auth) — with no Vault/OpenBao Agent sidecar required:
`openvox-ca` maintains its own OpenBao token lifecycle, proactively renewing it and
re-authenticating from source credentials whenever renewal fails.

Every existing storage backend keeps working unmodified in this mode — OpenBao only
ever supplants key custody, never CSR/certificate/CRL/inventory storage. See
[OpenBao Transit-engine CA key](openbao-transit.md) for full configuration
reference and setup instructions.

Whatever holds the key, the CA can run as an intermediate under an external root
rather than as its own root: `openvox-ca csr` emits a signing request bound to
the key the configured provider holds, and `openvox-ca import-ca-cert` installs
the chain the parent signs. No key material is passed on the command line at any
point, which is what lets the same procedure work for a Transit key that never
leaves the vault. See [offline subcommands on the server
binary](operator-cli.md#offline-subcommands-on-the-server-binary).

This integration is built and tested against OpenBao specifically, against current
OpenBao releases. It should also work against HashiCorp Vault, since Vault's Transit
engine, AppRole/Kubernetes auth methods, and Go client API are what OpenBao forked from
and remains wire-compatible with — but Vault is not part of the test matrix, so this is
currently unverified. Compatibility bug reports (and fixes) for Vault are welcome.

## Planned: PKCS#11 / HSM support

A future enhancement will add PKCS#11 support so the CA private key can be held in a
hardware security module (HSM), TPM, or software token (e.g. SoftHSM2). The key would
never leave the token; only signing operations would be delegated via the PKCS#11 API.
It would slot in as a third `--ca-key-provider` value, alongside `file` (default) and
`openbao`.

**Planned design:**

- `--ca-key-provider pkcs11`: a PKCS#11 module URI or library path, slot/token label, and PIN
  (via file or env var, same pattern as `--ca-key-passphrase-file`)
- Integration with **p11-kit** for module discovery, allowing operators to configure the
  PKCS#11 backend (SoftHSM2, TPM2 PKCS#11, cloud KMS bridges, Nitrokey, YubiHSM, etc.)
  via the system p11-kit configuration rather than hardcoding library paths
- CGo dependency for the PKCS#11 C bindings (build-time opt-in)

This is tracked as a separate feature. Contributions welcome.

## Monitoring destructive operations

The server tracks the rate of destructive operations (certificate revocation and
deletion) per authenticated client. When a single client exceeds **5 destructive
operations per minute**, a warning is emitted to the structured log:

```text
level=WARN msg="High rate of destructive operations detected" client.cn=admin.example.com client.domain="this CA" operation=revoke
```

A client is identified by its common name *and* the trust domain that vouched for
it. With [`client_ca`](configuration.md#trusting-client-certificates-from-another-ca)
configured, an `ops-admin` issued by a partner CA is therefore counted separately
from an `ops-admin` this CA issued: they are different principals, so neither can
spend the other's allowance or raise an alert against it.

> **Upgrading: the `client` log field has changed shape.** It used to be a flat
> string holding the common name — `client=admin.example.com`. It is now a group,
> rendering as the two fields shown above, `client.cn` and `client.domain`
> (`client` becomes an object under the JSON handler). Every log line in the API
> that names a client changed with it, not only this one, and three lines that
> previously used a bare `cn` key now use the same group.
>
> **This breaks queries keyed on the old field.** A SIEM rule, log-based alert,
> Loki selector or `grep` matching `client=<value>` will stop matching after the
> upgrade — and it fails quietly, because the line is still emitted and still
> carries the name. Update such queries to `client.cn` before upgrading. The
> message text is unchanged, so alerts keyed on the message alone are unaffected.
>
> The reason for the change is that a common name is not an identity once more
> than one issuer is trusted: two CAs may each have an `ops-admin`, and a record
> naming only the name cannot say which of them acted.
>
> **`client.domain` takes one of three shapes.** `this CA` for a certificate we
> issued; `client_ca "<name>"` — quoted — for one attributed to a configured
> entry; and **`unattributed`** where the request never passed through the
> authorisation middleware, so nothing vouched for the name. The last is not an
> error and is the normal value on a deployment with no mTLS configured, but on
> one that does have it, an `unattributed` record is a request that reached a
> handler without being attributed, and is worth looking at.

This is a detective control, not a preventive one. It does not block the operation, but alerts
operators to potentially anomalous administrative activity. Operators should:

- Forward `openvox-ca` logs to a centralized log aggregator (e.g. Loki,
  Elasticsearch, Splunk)
- Create alerts on `"High rate of destructive operations"` log messages
- Create alerts on `"Issued certificate carrying a Puppet authorisation
  extension"` too. That one is emitted by `openvox-ca generate --pp-cli-auth`
  (see [operator-cli.md](operator-cli.md#administrator-credentials)) and marks
  the minting of a CA administrator credential — the only record that
  distinguishes one from an ordinary node certificate, since the inventory line
  keeps the Puppet-compatible format and says nothing about the grant. It is
  the counterpart to the alert above: this one fires when the privilege is
  handed out, that one when it is used destructively
- Investigate any alerts promptly. A burst of revocations may indicate a
  compromised admin certificate or an operational error
- Consider whether the allow list that granted the client should be tightened
  if unexpected clients appear in these warnings. Read `client.domain` first: it
  names which one. `this CA` means `--puppet-server` or `--puppet-server-file`;
  `client_ca "<name>"` means that entry's own `admin_cns`, or its
  `allow_pp_cli_auth` if the certificate carries the extension — tightening the
  wrong one changes nothing and leaves the grant in place

The threshold (5 ops/minute) is a sensible default for environments where
bulk revocation is uncommon. Future versions may make this configurable.

## Inventory integrity, and the key that protects it

The certificate inventory has its own integrity control — an HMAC-SHA256 over
the inventory, or a hash chain on backends that store it as rows — keyed by
`hmac_key`. It is documented, with its threat model, in
[inventory-store.md](development/inventory-store.md#inventory-integrity-threat-model-and-rationale).

It is mentioned here because it is a **key-custody** question as much as an
integrity one, and the custody choice is the opposite of the one this page makes
for the CA private key. `hmac_key` lives in the same storage backend as the
inventory it protects, behind the same permissions. An attacker who can write
the inventory can usually also read the key and recompute a valid MAC, so the
control is aimed at accidental corruption and at tampering that cannot reach the
key — not at an adversary with write access to the store. Unlike the CA private
key, there is at present no option to move `hmac_key` outside that boundary.

Whether that should change is an open question, and moving the key would close
only part of the gap: the cheaper bypass needs no key at all. The trade-offs are
set out in the threat model linked above.
