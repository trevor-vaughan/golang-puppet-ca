# Migrating from OpenVox Server (or Puppet Server) to openvox-ca

This guide walks through replacing the certificate authority built into OpenVox
Server (or Puppet Server) with `openvox-ca`. The Go CA uses the same HTTP API
and a compatible flat-file layout, so existing agents continue to work without
reconfiguration, provided the CA hostname and port stay the same.

OpenVox Server is the Vox Pupuli fork of Puppet Server and keeps the same
`/etc/puppetlabs` paths and `puppetserver` command, so the steps below apply to
both; where a path or command is shown, it is identical on each.

## Prerequisites

- `openvox-ca` and `openvox-ca-ctl` binaries built and installed
- Access to the existing OpenVox/Puppet Server CA directory
  (typically `/etc/puppetlabs/puppet/ssl` or `/etc/puppetlabs/puppetserver/ca`)
- Maintenance window: agents cannot sign new certs during migration

## Quick overview

```
1. Back up the existing CA directory
2. Import the CA cert, key, and CRL into a new openvox-ca directory
3. Copy signed certificates and inventory
4. Disable the built-in CA in OpenVox Server
5. Start openvox-ca
6. Verify agent connectivity
```

## Step 1: Back up the existing CA

```bash
PUPPET_SSL=/etc/puppetlabs/puppet/ssl
BACKUP_DIR=/root/openvox-ca-backup-$(date +%Y%m%d)

cp -a "$PUPPET_SSL" "$BACKUP_DIR"
echo "Backed up to $BACKUP_DIR"
```

## Step 2: Identify your CA files

OpenVox Server (and Puppet Server) store CA material in one of two locations
depending on version:

| Version | CA directory |
| --- | --- |
| OpenVox / Puppet Server 6+ (monolithic) | `/etc/puppetlabs/puppet/ssl/ca/` |
| OpenVox / Puppet Server 6+ (external CA) | `/etc/puppetlabs/puppetserver/ca/` |
| Older Puppet | `/var/lib/puppet/ssl/ca/` |

Find your CA cert and key:

```bash
# Typical locations -- adjust for your installation
CA_CERT="$PUPPET_SSL/ca/ca_crt.pem"
CA_KEY="$PUPPET_SSL/ca/ca_key.pem"
CA_CRL="$PUPPET_SSL/ca/ca_crl.pem"

# Verify they exist and the key matches the cert
openssl x509 -noout -modulus -in "$CA_CERT" | md5sum
openssl rsa  -noout -modulus -in "$CA_KEY"  | md5sum
# Both MD5 sums must match
```

## Step 3: Import the CA

```bash
NEW_CADIR=/etc/puppet-ca/ssl

openvox-ca-ctl import \
  --cadir       "$NEW_CADIR" \
  --cert-bundle "$CA_CERT" \
  --private-key "$CA_KEY" \
  --crl-chain   "$CA_CRL"   # only X509 CRL blocks; anything else is refused

echo "CA imported into $NEW_CADIR"
```

This creates the directory structure, writes the CA cert/key/CRL, and
initialises `inventory.txt` and `serial` (the serial file is written for compatibility but is not used at runtime; openvox-ca generates random serial numbers).

`--cert-bundle` must be a **complete chain, ordered nearest first**: the CA's own
certificate, each issuer after it, ending with a self-signed root. A self-signed
Puppet Server CA already is exactly that — one certificate, which is its own
root — so the common case needs nothing extra.

If your Puppet Server ran under an external root, its `ca_crt.pem` may hold only
its own intermediate certificate. Assemble the full chain before importing:

```bash
# ca_crt.pem first, then each issuer, then the root
cat "$PUPPET_SSL/ca/ca_crt.pem" intermediate.pem root.pem > ca_chain.pem
CA_CERT=ca_chain.pem   # re-run the import above with this
```

Certificates only: a bundle containing the private key is rejected, because this
file is stored world-readable and served to every agent. Every certificate in
the chain must also be within its validity window — an expired root is refused
at import rather than surfacing as verification failures across the fleet.

`--crl-chain` accepts a multi-CRL bundle in any order. Every `X509 CRL` block must
parse, or the whole import is refused; PEM blocks of other types are ignored and
are not stored, because the blob is served
to every agent and Puppet's default `certificate_revocation = chain` makes an
agent parse all of it.

This CA's own CRL is moved to the front, since every reader takes the first
block as ours, and every other CRL is preserved through subsequent re-signing —
so `certificate_revocation = chain` keeps working after a revocation or a CRL
refresh. Which CRL is "ours" is decided by verifying the signature against this
CA's certificate, not by comparing issuer names or key identifiers: a CRL from
`openssl ca -gencrl` carries no Authority Key Identifier under the stock
`openssl.cnf`, and a shared root can issue two sub-CAs with the same name. If
the bundle contains no CRL signed by this CA, the one already in storage is kept
at the front, and only if there is none is an empty CRL generated. Re-running
the import with a newer ancestor bundle therefore refreshes the ancestor CRLs,
without exporting and concatenating your own first.

Ancestor CRLs cannot be re-signed by this CA, so they have to be replaced before
they lapse. There are two ways. Re-importing is one, and its limits are worth
reading before you rely on it: see [Refreshing ancestor
CRLs](#refreshing-ancestor-crls) below. The other is
[`crl_chain_file`](configuration.md#publishing-an-upstream-crl-chain), which has
openvox-ca re-read a PEM bundle on a timer and republish it, so the ancestors
stay current without an operator remembering to act before each `nextUpdate`.
Either way, watch `puppetca_crl_chain_next_update_timestamp_seconds{issuer}` —
the shipped mixin alerts on it.

Re-import is also not signalled to consumers: the Kubernetes exporter republishes
on CRL notifications, which the import path deliberately does not send. After a
live ancestor refresh, run `openvox-ca-ctl reissue-crl` or restart to republish
the exported copies.

The `import` command creates the directory structure, writes the CA cert/key/CRL, and
initialises `inventory.txt` and `serial` (the serial file is written for compatibility but is not used at runtime; openvox-ca generates random serial numbers).

## Step 4: Copy signed certificates

The `import` command only brings in the CA material. Existing signed
certificates must be copied separately so agents can fetch their certs
from the new CA.

```bash
# Puppet Server stores signed certs in ca/signed/ or certs/
# openvox-ca stores them in <cadir>/signed/
OLD_SIGNED="$PUPPET_SSL/ca/signed"

if [ -d "$OLD_SIGNED" ]; then
    cp "$OLD_SIGNED"/*.pem "$NEW_CADIR/signed/"
    echo "Copied $(ls "$NEW_CADIR/signed/" | wc -l) signed certificates"
fi
```

## Step 5: Rebuild the inventory

openvox-ca tracks signed certificates in `inventory.txt`. After copying
certs, rebuild it from the signed certificate files:

```bash
> "$NEW_CADIR/inventory.txt"  # truncate

for cert in "$NEW_CADIR/signed/"*.pem; do
    [ -f "$cert" ] || continue
    subject=$(basename "$cert" .pem)
    serial=$(openssl x509 -noout -serial -in "$cert" | cut -d= -f2)
    not_before=$(openssl x509 -noout -startdate -in "$cert" \
        | sed 's/notBefore=//' \
        | date -f- -u +%Y-%m-%dT%H:%M:%SUTC 2>/dev/null || echo "unknown")
    not_after=$(openssl x509 -noout -enddate -in "$cert" \
        | sed 's/notAfter=//' \
        | date -f- -u +%Y-%m-%dT%H:%M:%SUTC 2>/dev/null || echo "unknown")
    echo "$serial $not_before $not_after /$subject" >> "$NEW_CADIR/inventory.txt"
done

echo "Inventory rebuilt with $(wc -l < "$NEW_CADIR/inventory.txt") entries"
```

## Step 6: Disable the built-in CA

In OpenVox Server's (or Puppet Server's) service configuration, replace the CA
service with the disabled stub:

```bash
# OpenVox / Puppet Server 7+ uses services.d/ca.cfg
CA_CFG=/etc/puppetlabs/puppetserver/services.d/ca.cfg
[ -f "$CA_CFG" ] || CA_CFG=/etc/puppetlabs/puppetserver/bootstrap.cfg

sed -i \
  's|certificate-authority-service/certificate-authority-service|certificate-authority-disabled-service/certificate-authority-disabled-service|g' \
  "$CA_CFG"
```

Configure `puppet.conf` to point to the external CA:

```ini
[main]
ca_server = openvox-ca.example.com
ca_port   = 8140
```

## Step 7: Start openvox-ca

First, generate a TLS server certificate for openvox-ca itself:

```bash
openvox-ca generate \
  --cadir    "$NEW_CADIR" \
  --certname openvox-ca.example.com \
  --ttl      8760h \
  --key-out  "$NEW_CADIR/private/openvox-ca.example.com_key.pem" \
  >/dev/null

# Or, if you prefer a DNS SAN for the old puppet-master hostname:
openvox-ca generate \
  --cadir    "$NEW_CADIR" \
  --certname openvox-ca.example.com \
  --ttl      8760h \
  --dns      openvox-ca.example.com,puppet-master.example.com \
  --key-out  "$NEW_CADIR/private/openvox-ca.example.com_key.pem" \
  >/dev/null
```

This runs before the server starts, against the cadir `openvox-ca-ctl import`
populated in the previous step. Earlier versions of this guide had to start the
CA temporarily on loopback without TLS to mint this certificate through the API,
then restart it with TLS; that is no longer necessary.

Two details worth copying exactly. `--cadir` is required here because this guide
configures everything by flag and never writes a config file — without it the
command exits with `cadir is required`. And the certificate is **not** captured
by redirecting stdout: `generate` already writes it to
`$NEW_CADIR/signed/openvox-ca.example.com.pem` through the storage layer, which
is the path the server is pointed at below. Redirecting into that path would
make the shell truncate it before the command runs, and the CA would then refuse
to issue because a (zero-length, undecodable) certificate already exists for
that name. If you want a second copy elsewhere, use `--cert-out` with a path
outside the cadir.

```bash
# Production start with TLS
openvox-ca \
  --cadir    "$NEW_CADIR" \
  --hostname openvox-ca.example.com \
  --tls-cert "$NEW_CADIR/signed/openvox-ca.example.com.pem" \
  --tls-key  "$NEW_CADIR/private/openvox-ca.example.com_key.pem" \
  --puppet-server puppet-master.example.com
```

If migrating in-place (same hostname and port), agents will connect to the
new CA without any reconfiguration.

For a permanent installation, run it as a service rather than from a shell —
see [running under systemd](systemd.md), which ships a hardened unit. One thing
to watch for a migrated CA: `cadir` here is under `/etc/puppetlabs`, and the
unit's `ProtectSystem=strict` makes that read-only until you uncomment its
`ReadWritePaths=` line and point it at your `cadir`.

## Step 8: Verify

```bash
# Check the CA is serving
curl -sfk https://openvox-ca.example.com:8140/puppet-ca/v1/certificate/ca | head -1

# List all certificates
openvox-ca-ctl \
  --server-url https://openvox-ca.example.com:8140 \
  --ca-cert "$NEW_CADIR/ca_crt.pem" \
  list --all

# Run a puppet agent to verify connectivity
puppet agent --test --noop
```

## Refreshing ancestor CRLs

Some limits worth knowing before you rely on re-import as a refresh mechanism.

> **The bundle replaces the stored ancestor set wholesale.** Only *this CA's own*
> CRL is recovered from storage; ancestors are taken solely from what you supply.
> So a refresh bundle must contain **every** ancestor CRL, not just the one that
> changed — supplying a new root CRL alone drops the intermediate's, which is
> exactly the loss this preservation exists to prevent. (Re-*signing* preserves
> ancestors; importing replaces them. The two paths differ deliberately: the file
> you hand to `import` is authoritative.)
>
> **Ancestor CRLs age in place.** This CA cannot re-sign another CA's list, so
> whatever was imported stays until something replaces it, and it must be replaced
> before its own `nextUpdate` lapses.
> `puppetca_crl_chain_next_update_timestamp_seconds{issuer}` reports each
> ancestor's deadline and the shipped mixin alerts on it — see
> [the metrics reference](metrics.md#upstream-crl-chain). Configuring
> [`crl_chain_file`](configuration.md#publishing-an-upstream-crl-chain) is what
> keeps them current without an operator acting before each lapse.
>
> `import` is the one place it is detectable, so read its output. It warns when a
> supplied ancestor is already past its `nextUpdate`, and when the chain carries
> more than one CRL for the same ancestor:
>
> ```text
> level=WARN msg="Ancestor CRL has already expired; agents doing full-chain revocation checking will reject the published chain" issuer="CN=Root CA" next_update=2026-01-01T00:00:00Z
> ```
>
> Running `import` with no `--crl-chain` writes nothing and still performs both
> checks, so it is a safe way to ask whether the chain you are serving is sound.
>
> **`import` writes to a local filesystem directory only.** It takes `--cadir` and
> constructs filesystem storage directly; unlike `migrate` it has no
> `--source-config`/`--dest-config`. If your CA runs on **sqlite, postgres, mysql,
> etcd or redis**, re-importing writes to a directory the server never reads,
> prints `CA imported into <dir>`, and changes nothing — the live chain expires
> anyway. (SQLite is in that list: it keeps the CRL in its database file, so a
> cadir-based import misses it exactly as a networked backend does. See
> [storage backends](storage-backends.md).)

On those backends the refresh is a round trip with the CA stopped, and the
return leg needs `--force` because the destination still holds a CA
certificate. **Back up the destination first** — `migrate` is not
transactional, and the write-back covers the cert, key, inventory, inventory
HMAC and every signed certificate in order to refresh one PEM blob:

`scratch.yaml` must describe a **filesystem** backend whose `cadir` is the same
directory the middle step passes to `--cadir`. `migrate` resolves its destination
from that file; `import` resolves its own from the flag. If the two disagree,
all three commands exit 0 and print success while the middle step writes
somewhere the third never reads — the same silent no-op described above,
reintroduced inside the workaround for it. Use a **fresh, empty** scratch directory
every time — `mktemp -d` — because `migrate` copies and never deletes: anything
left from a previous run is pushed back into the live backend on the return leg,
including signed certificates that have since been cleaned, which reappear with
no inventory row and are then invisible to the expiry cleanup. Remove the
directory afterwards; it holds a plaintext copy of the CA key.

```bash
# A fresh, empty directory every time, as above. Write its path into
# scratch.yaml as `cadir:` (with storage_backend: filesystem) so migrate's
# destination and import's --cadir are the same directory.
SCRATCH=$(mktemp -d)

openvox-ca-ctl migrate --source-config live.yaml --dest-config scratch.yaml

# --cert-bundle and --private-key are the copies the first leg just wrote there.
openvox-ca-ctl import --cadir "$SCRATCH" \
  --cert-bundle "$SCRATCH/ca_crt.pem" \
  --private-key "$SCRATCH/private/ca_key.pem" \
  --crl-chain refreshed-chain.pem

# Back up the live backend before the return leg: --force overwrites a CA that
# is already there, and migrate is not transactional. backup.yaml must describe
# a filesystem backend whose cadir is a fresh, empty directory, for the same
# reason scratch.yaml must -- migrate refuses a destination that already holds a
# CA certificate, so a reused backup directory fails this leg *after* the import
# above has run, and reusing it with --force would overwrite the previous backup
# with the state you are about to replace.
BACKUP=$(mktemp -d)   # write this path into backup.yaml as cadir:
openvox-ca-ctl migrate --source-config live.yaml --dest-config backup.yaml

openvox-ca-ctl migrate --source-config scratch.yaml --dest-config live.yaml --force

# The scratch copy holds the CA key in plaintext.
rm -rf "$SCRATCH"
```

On the **filesystem** backend `import` does write where the server reads, and
the CA must be stopped: that backend supports one running instance, so `import`
is refused while a server holds the store and tells you which process does. This
is not a limitation of `import` but the shape of the backend — nothing
reconciles what two processes would each hold in memory (see
[running a second process against a live store](storage-backends.md#running-a-second-process-against-a-live-store)).

> **Re-import rewrites the CA key, so two custody modes cannot use it.** `import`
> writes whatever `--private-key` holds, and offers no encryption flags. Under
> `encrypt_ca_key` the stored key is an `ENCRYPTED PRIVATE KEY` block that
> `import` cannot parse, so feeding it back fails — and feeding the original
> plaintext key instead succeeds while silently replacing the encrypted at-rest
> key with a plaintext one, because key loading accepts both forms and nothing
> warns. Under `ca_key_provider: openbao` there is no exportable key at all, so
> re-import is unavailable outright. For both,
> [`crl_chain_file`](configuration.md#publishing-an-upstream-crl-chain) is not an
> alternative to re-import but the only ancestor-refresh mechanism there is: it
> reads a PEM bundle and republishes it, touching neither the CA key nor the
> import path.
>
> **An older replica still flattens the chain.** A build from before this change
> rewrites the stored blob as a single block, so one un-upgraded replica handling
> one revocation drops the ancestors for everyone. Complete the rollout before
> importing a chain.

Re-import is also not signalled to consumers: the Kubernetes exporter republishes
on CRL notifications, which the import path deliberately does not send. After a
live ancestor refresh, run `openvox-ca-ctl reissue-crl` or restart to republish
the exported copies.

## Directory layout mapping

| OpenVox / Puppet Server | openvox-ca | Notes |
| --- | --- | --- |
| `ssl/ca/ca_crt.pem` | `<cadir>/ca_crt.pem` | Same filename |
| `ssl/ca/ca_key.pem` | `<cadir>/private/ca_key.pem` | Moved into `private/` |
| `ssl/ca/ca_crl.pem` | `<cadir>/ca_crl.pem` | Same filename |
| `ssl/ca/signed/*.pem` | `<cadir>/signed/*.pem` | Same structure |
| `ssl/ca/inventory.txt` | `<cadir>/inventory.txt` | Same format |
| `ssl/ca/serial` | (not used) | openvox-ca uses random 128-bit serials |
| `ssl/certificate_requests/*.pem` | `<cadir>/requests/*.pem` | Directory renamed |
| `ssl/certs/ca.pem` | (not needed) | Symlink; agents fetch CA cert via API |
| `ssl/crl.pem` | (not needed) | Symlink; agents fetch CRL via API |

## Authorisation parity

`GET /certificate_status/{certname}` is **admin-only**, matching Puppet Server's
shipped `auth.conf`, which grants `certificate_status` and
`certificate_statuses` to holders of the `pp_cli_auth` extension and to nothing
else. An existing `auth.conf` expectation therefore carries over unchanged: the
CA CLI's certificate keeps working, and an ordinary agent certificate does not
read statuses.

**The symptom, if tooling of yours read statuses with an agent certificate:** the
request now returns `403 access denied` where it previously returned the status
JSON. The server logs the refusal with the client CN, the path and the reason. Look
for a `reason` field of `route requires admin access` — rendered
`reason="route requires admin access"` on stderr, and
`"reason":"route requires admin access"` when `logfile` is set, since that
selects the JSON handler. The message is `Request denied by authorisation
middleware` and the client is in `client.cn`, beside the `client.domain` that
vouched for the name.

First, be clear what restoring it costs. Admin is a single boolean
(`isAdmin`), not a per-route grant, so both of the options that preserve
authentication give the caller the *entire* admin tier — `POST /sign`,
`POST /sign/all`, `POST /generate/{subject}`, `PUT /clean`,
`DELETE /certificate_status/{subject}`, `PUT /certificate/{subject}` and CRL
replacement, as listed under [Authorization tiers](api.md#authorization-tiers).
There is no read-only status grant today. A monitoring host given option 1 or 2
to fix a status poll can also sign and revoke certificates.

If the caller only needs to observe state, `GET /certificate/{subject}` and the
CRL are both public and need no grant at all.

**First check which trust domain the caller was attributed to**, because it
decides whether either remedy below can work at all. Both are scoped to
certificates **this CA issued**. If the caller holds a certificate from a
[`client_ca`](configuration.md#trusting-client-certificates-from-another-ca)
issuer — the usual shape when the servers and operators administering this CA
sit under a sibling intermediate — then neither `--puppet-server` nor
`pp_cli_auth` reaches them: their admin grant is that entry's `admin_cns` and
`allow_pp_cli_auth`. The denial log line carries a `client.domain` field naming the
domain the certificate was attributed to, beside `client.cn` and `reason`.

For a caller this CA issued, two ways to restore authenticated access, in order
of preference:

1. **Add the caller's CN to the admin allow list** — `--puppet-server`, or
   `--puppet-server-file` for one CN per line. Authentication is preserved and
   the grant is explicit. `--puppet-server` is frozen at startup, so changing it
   needs a restart; `--puppet-server-file` is re-read on `SIGHUP` — see
   [reloading configuration](configuration.md#reloading-configuration) — which
   is the reason to prefer the file where the set will change. Grants full
   admin, as above.
2. **Give the caller a certificate carrying `pp_cli_auth`**, which is how
   OpenVox Server's own CLI authenticates. It is the *more* invasive of the
   two, not the less: authorisation-arc OIDs are stripped from submitted CSRs (see
   [Auth-arc OID stripping](#auth-arc-oid-stripping)), so such a certificate
   cannot be obtained through the API at all. Mint it offline with
   [`openvox-ca generate --pp-cli-auth`](operator-cli.md#administrator-credentials),
   which needs no access to the raw CA key and so works under
   `ca_key_provider: openbao` and `encrypt_ca_key` as well as with a key file.
   The reason to prefer option 1 is not availability but withdrawal: an
   allow-list entry is taken back by editing a file and restarting, whereas this
   grant is baked into a certificate and comes back only by revoking every live
   serial for that subject *and* restarting the server. It also has no effect if
   `--no-pp-cli-auth` / `no_pp_cli_auth: true` is set. Grants full admin.

Separately, **`allow_public_status: true`** exists if agents must poll status
before they hold a client certificate. It is listed apart from the two above
because it does not restore *authenticated* access: it makes the route fully
unauthenticated rather than relaxing it to any client. It is the bootstrapping
escape hatch, not the way to restore agent access.

### Renewal eligibility

`POST /certificate_renewal` additionally requires that the presented
certificate is one this CA issued, has not revoked, and is for the subject being
renewed. The revocation requirement bites in ordinary operation: renewal
re-reads the CRL from storage rather than trusting the copy the mTLS layer
holds, so on a replica that has not yet synced a revoked certificate gets past
the middleware and is refused here instead — `403 access denied` either way.
That is deliberate, and it is why revoking cannot be outrun by renewing.

The issuer requirement is reachable once a `client_ca` entry is configured: the
middleware then trusts a second issuer for authentication, while renewal stays
scoped to this CA's own namespace. A foreign certificate authenticates, may be
an administrator of its own domain, and is still answered `403 certificate not
eligible for renewal` — renewal reissues under our authority using the presented
certificate's subject, which is only safe for names we assigned. With no
`client_ca` configured there is one trust domain and the requirement is
unreachable, exactly as before.

The third is a defence-in-depth invariant on the internal API rather than
something a request can trip: the HTTP handler derives the subject from the
presented certificate, so the two always agree. It guards against a future
caller that passes them separately, and a second trust anchor does not make it
reachable.

Renewal reissues under
this CA's authority using the presented certificate's own subject, so it is
only meaningful for names this CA assigned. (Extensions differ by path, and on both
paths only Puppet OID extensions are carried at all: the empty-body form
carries the presented certificate's SANs and Puppet OIDs forward unchanged,
while the CSR form takes Puppet OIDs from the CSR and strips authorization-arc
ones.)

In the default topology every certificate an agent holds was issued by this CA,
so nothing changes. A certificate issued by a *previous* CA whose material was
replaced without re-issuing agent certificates cannot be renewed — but note
that such a certificate already fails the middleware's own chain check, so it
was locked out of every mTLS route before this change too, not just renewal.
Those agents must re-enrol.

**There is no opt-out**, and none is planned: the gate is what stops this CA
reissuing under its own authority for a name it never assigned, so re-enrolment
is the resolution. When the CA's own refusal is reached — which takes a second
trusted issuer, as above — it logs `Renewal rejected: certificate not eligible`,
or `Auto-renewal rejected: certificate not eligible` for the empty-body form,
each with the `subject` and the reason in `error`.

## CLI command mapping

| Puppet / puppetserver ca | openvox-ca-ctl | Notes |
| --- | --- | --- |
| `puppet cert list` | `openvox-ca-ctl list` | Pending CSRs |
| `puppet cert list --all` | `openvox-ca-ctl list --all` | All certs |
| `puppet cert sign <name>` | `openvox-ca-ctl sign --certname <name>` | |
| `puppet cert sign --all` | `openvox-ca-ctl sign --all` | |
| `puppet cert revoke <name>` | `openvox-ca-ctl revoke --certname <name>` | |
| `puppet cert clean <name>` | `openvox-ca-ctl clean --certname <name>` | Revoke + delete |
| `puppetserver ca setup` | `openvox-ca-ctl setup --cadir <path>` | |
| `puppetserver ca import` | `openvox-ca-ctl import --cadir <path> ...` | |
| `puppetserver ca generate` | `openvox-ca-ctl generate --certname <name>` | Needs a running server. Use `openvox-ca generate --certname <name> --ttl <duration>` to mint offline, which is also the only way to mint a *new* `pp_cli_auth` certificate |

## Differences to be aware of

### Serial numbers

openvox-ca uses cryptographically random 128-bit serial numbers instead of
sequential integers. This is a security improvement (CA/Browser Forum
guidance) but means serial numbers will look different from what you're
used to. The `serial` file from old Puppet CAs is ignored.

### Subject alternative names requested by a CSR

Parity, and worth checking before you cut over: `allow_subject_alt_names`
defaults to `false`, as OpenVox Server's `allow-subject-alt-names` does. A CSR
asking for any SAN beyond a DNS entry equal to its own certname is refused at
signing time rather than trimmed or honoured.

If your agents request alt names — a `dns_alt_names` setting in their
`puppet.conf`, or a load-balanced service answering to several hostnames — those
nodes will fail to sign until you set:

```yaml
allow_subject_alt_names: true
```

Certificates you have already imported keep renewing whatever the setting says:
the gate judges a renewal against the certificate being renewed, so a name it
already holds is never refused and only a request for a *new* name is. What the
setting does not fix is which names survive onto the replacement — the
empty-body auto-renewal path carries all four SAN types forward, while a
CSR-body renewal is issued with DNS names only, as every CSR-signed certificate
is today (see [#241](https://github.com/voxpupuli/openvox-ca/issues/241)). An
imported certificate holding IP, email or URI SANs keeps them through
auto-renewal and loses them through a re-key. The generate paths are not filtered either
— `openvox-ca generate --dns` on the CA host and the admin-only
`POST /generate/{subject}?dns=` — because their names come from an administrator
rather than from an agent's CSR.

The refusal names no entries back to the requester; look in the CA's log at
`WARN` for which ones were refused.

### Auth-arc OID stripping

openvox-ca strips Puppet authorization-arc OIDs (`1.3.6.1.4.1.34380.1.3.*`)
from CSRs during signing as a security measure to prevent privilege
escalation. This means you cannot create admin certificates (with
`pp_cli_auth`) by submitting a CSR through the API. That is deliberate and
unchanged: a request that could ask for `pp_cli_auth` would let any agent ask
for CA admin.

Mint one offline instead:

```bash
openvox-ca generate --cadir "$NEW_CADIR" --certname admin-cli \
  --ttl 8760h --pp-cli-auth --key-out admin-cli_key.pem > admin-cli.crt
```

Run it on the CA host, against the server's own configuration. No running
server, no admin certificate, and no API — and on the filesystem backend this
guide configures, **stop the CA first if it is already running**: `generate`
cannot coordinate with it, and a concurrent write can corrupt the inventory
integrity record (see
[running alongside a live server](operator-cli.md#running-alongside-a-live-server)).
During the migration itself this costs nothing, because the new CA has not been
started yet. `--cadir` is spelled out because this
guide configures the server entirely by flag and never writes
`/etc/puppet-ca/config.yaml`; where that file does exist, the command reads the
cadir from it and the flag can be dropped.

This is not merely a shorter recipe than signing with `openssl` by hand. It
needs no access to the raw CA key, so it works under `ca_key_provider: openbao`
— where the key never leaves the vault — and under `encrypt_ca_key`, neither of
which can be fed to `openssl x509 -req` at all. And the certificate it produces
is one the CA can see: it takes a serial from the CA's own generator, is written
to the inventory, appears in `openvox-ca-ctl list --all`, is swept by the expiry
job, and can be revoked by name.

`pp_cli_auth` grants the entire admin tier — signing, revoking, cleaning,
importing, replacing the CRL. Withdrawing it takes three steps rather than one,
and `--pp-cli-auth` has other requirements and caveats worth reading before you
use it: see [`generate`](operator-cli.md#administrator-credentials).

It has no effect where `no_pp_cli_auth: true` is set; the command refuses rather
than issuing a certificate that would grant nothing.

Alternatively, use the `--puppet-server` flag to grant admin access by CN
without needing the `pp_cli_auth` extension at all. Prefer it where the caller
has a stable CN: an allow-list entry is withdrawn by editing a file and
restarting, whereas this grant is withdrawn only by revoking the certificate and
restarting every replica.

#### Certificates you already minted with openssl

Earlier versions of this guide told you to sign admin certificates directly with
the CA key. Those certificates have no inventory row, which means
`openvox-ca-ctl revoke --certname` cannot find them and `--force` cannot replace
them: they were never in the CA's storage. They are nonetheless valid,
CA-signed, admin-granting credentials until they expire.

To retire one, register it first so the CA can see it, then revoke it:

```bash
# 1. With the server running, authenticated by the very certificate you are
#    retiring (it is still an admin credential until you revoke it).
openvox-ca-ctl import-cert --certname admin-tool --cert-file admin.crt

# 2. It is now in the inventory and revocable by name.
openvox-ca-ctl revoke --certname admin-tool

# 3. Restart every replica so the revocation is honoured.
#
# 4. Stop the CA before re-minting. On the filesystem backend this guide
#    configures, generate does not coordinate with a running server, and a
#    concurrent write can corrupt the inventory integrity record so the server
#    will not restart. See docs/operator-cli.md#running-alongside-a-live-server.
systemctl stop openvox-ca

openvox-ca generate --cadir "$NEW_CADIR" --certname admin-tool \
  --ttl 8760h --pp-cli-auth --key-out admin-tool_key.pem > admin-tool.crt

systemctl start openvox-ca
```

Note that step 1 is an admin-authenticated API call and needs a running server —
importing is a prerequisite for revoking here, not an alternative to it.

### No `puppet cert` compatibility shim

openvox-ca does not accept `puppet cert` command syntax directly. Use
`openvox-ca-ctl` instead (see the CLI command mapping table above). The HTTP
API is fully compatible; only the CLI tool name and flag syntax differ.

### Agent configuration

If openvox-ca runs on the same hostname and port as the old CA, agents need
no configuration changes. If the hostname changes, update `ca_server` in
each agent's `puppet.conf`:

```ini
[main]
ca_server = new-ca-hostname.example.com
```

## Rollback

If something goes wrong, restore from backup:

```bash
# Stop openvox-ca
systemctl stop openvox-ca  # or kill the process

# Restore the old CA directory
cp -a "$BACKUP_DIR" "$PUPPET_SSL"

# Re-enable the built-in CA in OpenVox Server (or Puppet Server)
sed -i \
  's|certificate-authority-disabled-service/certificate-authority-disabled-service|certificate-authority-service/certificate-authority-service|g' \
  /etc/puppetlabs/puppetserver/services.d/ca.cfg

# Restart the server
systemctl restart puppetserver
```
