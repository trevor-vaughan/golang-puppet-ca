# Storage backends

`openvox-ca` keeps its CA state — the CA certificate, private key, CRL,
certificate inventory, pending CSRs and issued certificates — in a pluggable
storage backend. Pick the one that matches how you want to run the CA:

| Kind | Status | Best for |
| --- | --- | --- |
| `filesystem` | default | single-node installs; drop-in compatibility with the OpenVox/Puppet Server CA layout |
| `etcd` | stable | HA clusters where multiple `openvox-ca` replicas share a single CA |
| `redis` (incl. Valkey) | stable | clusters that already run Redis/Valkey (direct or Sentinel-managed) |
| `sqlite` | stable | single-node installs that prefer a single database file over a cadir tree |
| `postgres` | stable | HA clusters that already run PostgreSQL; shared CA across replicas |
| `mysql` (incl. MariaDB) | stable | HA clusters that already run MySQL/MariaDB; shared CA across replicas |

`sqlite`, `postgres` and `mysql` share one SQL implementation and differ only in
driver. All drivers are pure Go, so the default `CGO_ENABLED=0` and FIPS
(`GOEXPERIMENT=boringcrypto`) builds work with every backend.

Two things are true regardless of backend:

- **Server-generated per-subject private keys always live on local disk** (under
  `cadir`). They are issued once, handed back to the requester, and kept locally
  for operator convenience only; they are never written to a remote store.
- The **CA certificate and/or CA private key can be pinned to a local file**
  (e.g. a mounted secret volume) independent of the chosen backend — see
  [CA cert/key as local files](#ca-certkey-as-local-files).

In the HA backends (`etcd`, `redis`, `postgres`, `mysql`), any replica can sign,
revoke, or refresh the CRL, and everything it writes lands in shared storage and
is immediately visible to the others; `openvox-ca` coordinates the replicas and
recovers automatically if one crashes. You don't need to configure any of that.
The CRL an agent downloads is served straight from storage, so it is current on
whichever replica answers.

What is not instant is a replica's *own* revocation verdicts — both the client
certificates it will accept and the OCSP responses it signs. Those are answered
from a CRL it holds in memory and reloads on a timer, so a certificate revoked
on one replica stops working against the others within `crl_sync_interval_sec`
(60s by default) rather than at once. See
[Revocation across replicas](configuration.md#revocation-across-replicas).

The responder keeps a second such copy: the set of serials this CA has issued,
which decides whether it will speak about a certificate at all. On the shared
backends it is reloaded on its own timer, so a certificate signed on one replica
stops being reported `unknown` by the others within `ocsp_index_sync_interval_sec`
(5m by default). `filesystem` and `sqlite` do not run that job — they
support a single running instance, so nothing else should be writing
certificates there — so on those two the set is what it was at startup. See [OCSP status across
replicas](configuration.md#ocsp-status-across-replicas).

---

## Running a second process against a live store

**Running more than one `openvox-ca` against a `filesystem` or `sqlite` store is
not supported.** Those two have no distributed locking, and a backend without it
permits exactly one running instance. Stop the server before running any command
that reaches storage directly.

This is a property of the backend's locking rather than of its name. The HA
backends — `etcd`, `redis`, `postgres` and `mysql` — coordinate writers across
processes *and* hosts, so on those you may run as many instances as you like, on
as many machines as you like, and none of this section applies to them. A future
backend inherits whichever behaviour its locking earns it.

### Why only one

Not because of what lands on disk, but because of what does not. Each running CA
answers from state held in its own memory and reconciled through shared storage:
the index of serials it has issued, its OCSP cache, and the CRL its revocation
checks read. On a backend with distributed locking, storage is what the replicas
reconcile that state through. `filesystem` and `sqlite` have no such mechanism,
by design — so a second instance issues certificates the first never hears of,
and **a certificate revoked on one goes on being accepted by the other**. No
amount of finer-grained locking fixes that; only running one instance does.

### What the server does about it

At startup the server takes an exclusive `flock(2)` on the store and holds it
until it exits — under `<cadir>/locks/` for `filesystem`, and in the hidden
directory beside the database file for `sqlite`. So:

- **A second `openvox-ca` fails to start**, naming the process that holds the
  store: `another openvox-ca process is already running against this store:
  openvox-ca (pid 1234) on ca1.example.com since …`. It is a refusal rather than
  a wait, because waiting would only postpone the same answer.
- **`openvox-ca-ctl setup`, `import` and `migrate` are refused the same way**,
  as are the offline `openvox-ca` subcommands (`csr`, `generate`,
  `import-ca-cert`, and `rebuild-inventory-hmac` on its `--yes-re-bless` path;
  reporting takes no store-wide instance lock). Those are the commands that
  reach storage directly.
  Every other `openvox-ca-ctl` subcommand works through the admin API over HTTP
  instead, never opens the store, and is unaffected — asking a running CA to
  sign, revoke or list remains an ordinary thing to do.
- **`migrate` no longer hangs when both ends are the same store.** That was
  never supported, and it used to wait for ever on a lock it had already taken
  itself; it now fails immediately.
- **Nothing to clean up after a crash.** The kernel releases an `flock` when the
  holding process dies, however it dies. There is no stale lock to remove and no
  lock file that needs deleting — see the note on `locks/` under
  [the filesystem backend](#filesystem-backend-default).
- **Under `--daemon` the refusal comes before the fork.** That flag re-execs the
  server and discards the child's output, so a refusal raised there would reach
  nobody: you would be told the CA had started, get a zero exit, and have the
  child die in silence. The check therefore runs in the process you started,
  which fails with a non-zero exit and names the holder. It is a pre-flight — it
  takes the lock and releases it again, and the child takes the real one — so a
  third process that wins the moment between them still produces the silent
  failure. A server that is already running does not, which is the case this
  exists for.

Under the default isolated-process topology the lock is held by the supervisor
process, once, on behalf of the signer and frontend children it starts. One
instance means one `openvox-ca` service, not one operating-system process.

### What the lock cannot do, and why the rule matters more than it does

The lock is a backstop, not a licence. It reduces the damage when the
unsupported thing is attempted on one host. It cannot do more than that:

- **`flock(2)` says nothing useful over NFS**, so a cadir or SQLite file shared
  between hosts is not protected at all, and sharing one was never supported.
- **A second process on another host cannot be excluded**, by this or by
  anything else we could build.
- **Both processes must be on a release that has this.** The exclusion works
  only if each side takes the lock, so a new `openvox-ca-ctl` beside an older
  running server — or the reverse, during a staged upgrade where the package is
  updated but the service has not been restarted — silently gets the old
  behaviour: no coordination at all. Upgrade and restart the server before
  relying on any of it.
- **Absolute paths matter.** Two processes exclude each other only if they
  resolve the same lock directory, so `cadir` and `sql_dsn` should be absolute.
  A relative path used from two different working directories, or one store
  reached through two different symlinks, gives two independent locks and no
  mutual exclusion.
- **Where the store cannot be locked at all** — a filesystem without `flock(2)`,
  a read-only mount — the server logs a warning and starts anyway, because
  refusing over a lock that is unavailable rather than held would take down a CA
  that worked before. The rule still holds; only the enforcement is missing.

So the rule is not "the lock will stop you". It is that these backends support
one instance, and the lock catches the case it can.

### Running `openvox-ca-ctl` as the service user

- **Run `openvox-ca-ctl` as the user the server runs as**, not under `sudo`.
  The lock files are `0600` and the directory `0750`, so a command run as root
  leaves a root-owned lock file in a store the service account owns, and the
  server's next acquisition of that name fails — deliberately and loudly, with
  an error naming the file, its owner and `chown -R`, because the alternative is
  it quietly giving up on locking while the root process believes it holds an
  exclusive one. Under systemd that means `sudo -u puppet-ca openvox-ca-ctl …`
  (or `runuser -u puppet-ca --`), matching the `User=` in the unit. It applies
  even to commands that only read, such as `migrate` from a live source, since
  taking the lock is what creates the file.

Within a single instance the per-lock-name `flock(2)` coordination added for
`filesystem` and `sqlite` still applies: a command that is not refused outright
waits for the named lock it needs and then fails if it cannot get it, logging
`Waiting for the CA lock: another process on this host holds it` the first time
it is refused, so a command that pauses is distinguishable from one that has
hung.

### If you run two anyway

The damage is not limited to the stale caches above. `SameHostLocker` excludes
another process per lock *name*, and the inventory append takes no cluster lock
of its own — it is serialised by a process-local mutex. Two processes issuing
for **different** subjects therefore hold different `subject:<name>` locks, and
can still interleave an append with its integrity update, leaving an integrity
value covering an inventory that never existed — which the *next* start rejects.

That is not a tracked defect, because it describes a configuration that is not
supported rather than a bug in one that is. Note *why* it is not one, because
the distinction decides whether this paragraph is still worth reading: it is
closed by **scope**, not by mechanism. Nothing makes the interleave impossible —
the same-host locking work did not close it and was never going to — so the
rule, and the store lock that holds operators to it, are the whole of the
protection. Stop the server before issuing certificates from a second process.

A deployment that genuinely needs concurrent writers wants a structured backend,
where the entry and its integrity head are written in one step: SQL in one
transaction, redis in one atomic script, etcd in one transaction. On those
backends concurrent writers are the supported case, and this whole section is
moot.

---

## Filesystem backend (default)

All CA state lives under `--cadir`. The on-disk layout matches the OpenVox/Puppet
Server CA, so you can swap in `openvox-ca` without reorganising your SSL tree:

```text
<cadir>/
├── ca_crt.pem              CA certificate
├── ca_pub.pem              CA public key
├── ca_crl.pem              Certificate Revocation List (see note)
├── inventory.txt           Issued/revoked certificate log
├── superseded.json         Certificates awaiting delayed
│                           revocation (see note)              0600
├── private/
│   ├── ca_key.pem          CA private key                    0600
│   └── <subject>_key.pem   server-generated private keys     0600
├── requests/
│   └── <subject>.pem       pending CSRs
├── signed/
│   └── <subject>.pem       issued certificates
└── locks/
    └── <hash>.lock         same-host lock files              0600
```

> **`superseded.json` is absent until the first supersession.** It appears only
> where [`superseded_cert_revoke_after_sec`](configuration.md#delayed-supersession)
> grants renewals an overlap window, and it holds the serials — with their
> subjects and due times — of certificates that have been replaced but not yet
> revoked. Deleting it does not revoke anything; it strands every certificate it
> named, each of which stays valid until it expires. If you must remove it, take
> the serials first and retire them with `openvox-ca-ctl revoke --serial <hex>`.
>
> **`ca_crl.pem` may hold more than one CRL.** Once a chain has been imported
> with `--crl-chain`, the blob is this CA's own CRL followed by its ancestors', so
> agents can do full-chain revocation checking. Every backend stores it as one
> logical value — a single file here, a single key elsewhere — so nothing below
> changes; only the number of PEM blocks inside it does. See
> [storage internals](development/storage-internals.md).

(The directory also holds small internal integrity files; leave them in place.)
File permissions are fixed: `0600` for anything under `private/` and for the
lock files under `locks/`, `0644` for everything else. `openvox-ca` warns at startup about any `*_key.pem` in
`private/` whose permissions are looser than `0600` and leaves them for you to
fix.

`locks/` holds lock files, not CA state — named after a hash of the lock rather
than anything readable. They are how a second process on the same host is kept
from writing behind a running server's back; see [Running a second process
against a live store](#running-a-second-process-against-a-live-store).

Two things to expect of them. There is one per distinct lock name, and that
**includes one per subject**, so on a large fleet the directory holds roughly as
many files as `signed/` and never shrinks — retiring a node with
`openvox-ca-ctl clean` removes its certificate, not its lock file.

And with one exception their contents tell you nothing: the per-name lock files
are empty whether the lock is held or not, and whether one is held is visible
only to `fuser`/`lsof`. The exception is the store-wide instance lock, which
records the process holding it — binary name, pid, host and the time it started
— so that a refused second instance can name it. A non-empty lock file is
therefore normal and is **not** a sign of corruption; the record may equally
well name a process that has since exited, because the file outlives every
holder and the kernel releases the lock without erasing it.

Do not delete them while anything may be using the store — see the deletion
hazard in [locking and concurrency](development/locking.md). Sweeping them while
everything is stopped is safe, and backing them up is harmless.

### Configuration

Default. Nothing to set.

```yaml
# /etc/puppet-ca/config.yaml
storage_backend: filesystem   # optional; this is the default
cadir: /etc/puppetlabs/puppet/ssl/ca
```

---

## etcd backend

Stores the CA in an etcd v3 cluster. Multiple `openvox-ca` replicas can point at
the same cluster (and the same `etcd_key_prefix`) to share one CA. `cadir` is
still required for per-subject generated keys and ancillary local state.

### Configuration

```yaml
# /etc/puppet-ca/config.yaml
storage_backend: etcd
cadir: /var/lib/puppet-ca                # still needed for per-subject keys
                                         # and ancillary local state

etcd_endpoints:
  - https://etcd-0.example.com:2379
  - https://etcd-1.example.com:2379
  - https://etcd-2.example.com:2379
etcd_key_prefix: /puppet-ca               # default shown; override to
                                         # share a cluster between CAs
etcd_dial_timeout_sec: 5
etcd_request_timeout_sec: 5

# Optional authentication.
etcd_username: openvox-ca
etcd_password: "..."                     # prefer PUPPET_CA_ETCD_PASSWORD

# Optional mTLS to the etcd cluster.
etcd_tls_ca_file:   /etc/puppet-ca/etcd-ca.pem
etcd_tls_cert_file: /etc/puppet-ca/etcd-client.pem
etcd_tls_key_file:  /etc/puppet-ca/etcd-client-key.pem
```

### CLI flags

```text
--storage-backend etcd
--etcd-endpoints  https://etcd-0:2379,https://etcd-1:2379,https://etcd-2:2379
--etcd-key-prefix /puppet-ca
```

### Environment variables

| Config key | Env var |
| --- | --- |
| `storage_backend` | `PUPPET_CA_STORAGE_BACKEND` |
| `etcd_endpoints` | `PUPPET_CA_ETCD_ENDPOINTS` (comma-separated) |
| `etcd_key_prefix` | `PUPPET_CA_ETCD_KEY_PREFIX` |
| `etcd_username` | `PUPPET_CA_ETCD_USERNAME` |
| `etcd_password` | `PUPPET_CA_ETCD_PASSWORD` |
| `etcd_dial_timeout_sec` | `PUPPET_CA_ETCD_DIAL_TIMEOUT_SEC` |
| `etcd_request_timeout_sec` | `PUPPET_CA_ETCD_REQUEST_TIMEOUT_SEC` |
| `etcd_tls_ca_file` | `PUPPET_CA_ETCD_TLS_CA_FILE` |
| `etcd_tls_cert_file` | `PUPPET_CA_ETCD_TLS_CERT_FILE` |
| `etcd_tls_key_file` | `PUPPET_CA_ETCD_TLS_KEY_FILE` |

### Operational notes

- **The CA private key lives in etcd by default.** That lets a new replica join
  without copying the key out of band, but it makes the etcd cluster part of the
  CA key's blast radius. Restrict etcd ACLs to the `openvox-ca` identity, enable
  [CA key encryption at rest](ca-key-security.md) (`encrypt_ca_key: true`), or
  pin the key to a local file with `ca_key_file` (see
  [CA cert/key as local files](#ca-certkey-as-local-files)).
- **`openvox-ca-ctl setup` / `import` work on the local filesystem only.** To
  import a CA into an etcd-backed cluster, run them against a scratch directory
  first, then point `openvox-ca` at a cadir containing the output.
- **The certificate inventory is stored as one etcd key per issued
  certificate**, not as a single ever-growing text blob, so signing cost does
  not grow with the size of the inventory and duplicate serial numbers are
  rejected atomically across all replicas (see
  [the inventory internals](development/inventory-store.md)). On first start
  after upgrading from a version that stored the inventory as a blob, the
  backend converts it in place automatically: the blob is first verified
  against its stored HMAC (a mismatch fails startup, exactly as it would have
  before the upgrade), and after the conversion the integrity value is
  re-established over the converted entries — the conversion window itself is
  the one moment tamper detection does not cover. An interrupted conversion
  resumes safely on the next start. **Upgrade all replicas together**: a
  not-yet-upgraded replica writing the old blob format while an upgraded one
  serves the converted inventory is not supported and is refused with an
  explicit error when detected.
- **The conversion is one-way; take a snapshot before the first upgraded
  start.** Downgrading to a release that predates it is not supported, and
  fails quietly rather than loudly: the old binary reads `inventory/data`,
  finds the empty marker the conversion left, and reports an *empty* inventory
  rather than an error — so it prunes nothing, and starts appending new
  issuances to the legacy blob. Upgrading again is then refused, because the
  blob and the decomposed entries no longer agree. Recovery is a restore from
  an etcd snapshot taken before the upgrade, so take one.
- **The etcd backend also maintains the certificate index**: `GET
  /certificate_statuses` (`puppetserver ca list`) is answered from the
  decomposed inventory entries instead of reading and parsing every stored
  certificate, with the same rebuildable-projection semantics as the SQL
  backends — after migrating from another backend the display fields are
  backfilled automatically on the next server start. Note the first start
  after an upgrade or migration therefore performs both the inventory
  conversion and a per-certificate projection backfill before serving; on a
  large fleet expect it to take a while (progress is logged).
- **Bulk inventory rewrites are batched.** Imports and prunes larger than one
  etcd transaction are split into multiple transactions; batch sizes stay
  well under etcd's default `--max-txn-ops` (128), so no cluster tuning is
  needed. Every *prune* transaction leaves the inventory and its integrity
  head consistent, and a single expired-certificate cleanup pass removes at
  most 900 entries so a large backlog drains over several runs rather than
  stalling signing. At the default daily cleanup interval that is 900
  entries/day: enabling cleanup for the first time on a large backlog, or
  running a fleet whose expiry churn exceeds it, calls for a shorter
  `expired_cert_cleanup_interval_sec` — the server logs every deferral, and
  escalates to a warning once the deferred backlog exceeds what a whole pass
  can remove, which is the point at which the backlog is growing rather than
  draining. An in-progress *conversion* is instead covered by the
  blob-stays-authoritative resume behaviour described above.
- **Legacy inventories with duplicate serial numbers** (possible, because the
  pre-conversion blob had no cluster-wide uniqueness guarantee) are imported
  verbatim with a startup warning naming the serials. The certificate index
  cannot track per-serial state for them, so their status in
  `certificate_statuses` output is derived from the signed CRL on each
  request (always correct, slightly slower) and their display fields come
  from the stored certificate. This resolves itself once the affected
  certificates expire and are cleaned up, or when they are revoked and
  reissued under fresh serials.

---

## Redis / Valkey backend

Stores the CA in a Redis instance, a Valkey instance (a wire-compatible fork of
Redis), or a Sentinel-managed primary. Multiple `openvox-ca` replicas can share
one instance (and the same `redis_key_prefix`). `redis` and `valkey` are
accepted as aliases. `cadir` is still required for per-subject keys and
ancillary local state.

Redis replication under Sentinel is asynchronous, so an in-flight failover
leaves a narrow window during which cross-replica coordination is weaker than
etcd's. For `openvox-ca`'s workloads that window is small and self-healing;
operators who need the strictest cross-node consistency should prefer `etcd`.

### Configuration — direct connection

```yaml
# /etc/puppet-ca/config.yaml
storage_backend: redis                   # or "valkey"
cadir: /var/lib/puppet-ca                # still needed for per-subject keys
                                         # and ancillary local state

redis_addrs:
  - redis-0.example.com:6379             # first address is used in direct mode

redis_key_prefix: puppet-ca               # default shown; override to share
                                         # an instance between CAs
redis_db: 0                              # logical database (default 0)

redis_dial_timeout_sec: 5
redis_request_timeout_sec: 5
redis_lock_ttl_sec: 30

# Optional auth (ACL user + password; use PUPPET_CA_REDIS_PASSWORD for secrets).
redis_username: openvox-ca
redis_password: "..."

# Optional TLS to the Redis primary.
redis_tls_ca_file:   /etc/puppet-ca/redis-ca.pem
redis_tls_cert_file: /etc/puppet-ca/redis-client.pem
redis_tls_key_file:  /etc/puppet-ca/redis-client-key.pem
```

### Configuration — Sentinel-managed failover

Set `redis_sentinel_master_name` (and leave `redis_addrs` empty) to route
through Sentinels. The client discovers the current primary and follows
failovers automatically.

```yaml
storage_backend: redis
cadir: /var/lib/puppet-ca

redis_sentinel_master_name: mymaster
redis_sentinel_addrs:
  - sentinel-0.example.com:26379
  - sentinel-1.example.com:26379
  - sentinel-2.example.com:26379

# Optional auth against the Sentinels themselves (distinct from Redis auth).
redis_sentinel_username: openvox-ca
redis_sentinel_password: "..."

# Auth / TLS against the primary — same fields as direct mode.
redis_username: openvox-ca
redis_password: "..."
redis_tls_ca_file:   /etc/puppet-ca/redis-ca.pem
redis_tls_cert_file: /etc/puppet-ca/redis-client.pem
redis_tls_key_file:  /etc/puppet-ca/redis-client-key.pem
```

### CLI flags

```text
--storage-backend           redis
--redis-addrs               redis-0:6379,redis-1:6379
--redis-sentinel-master-name mymaster
--redis-sentinel-addrs      sentinel-0:26379,sentinel-1:26379
--redis-key-prefix          puppet-ca
```

### Environment variables

| Config key | Env var |
| --- | --- |
| `storage_backend` | `PUPPET_CA_STORAGE_BACKEND` |
| `redis_addrs` | `PUPPET_CA_REDIS_ADDRS` (comma-separated) |
| `redis_sentinel_master_name` | `PUPPET_CA_REDIS_SENTINEL_MASTER_NAME` |
| `redis_sentinel_addrs` | `PUPPET_CA_REDIS_SENTINEL_ADDRS` (comma-separated) |
| `redis_sentinel_username` | `PUPPET_CA_REDIS_SENTINEL_USERNAME` |
| `redis_sentinel_password` | `PUPPET_CA_REDIS_SENTINEL_PASSWORD` |
| `redis_db` | `PUPPET_CA_REDIS_DB` |
| `redis_username` | `PUPPET_CA_REDIS_USERNAME` |
| `redis_password` | `PUPPET_CA_REDIS_PASSWORD` |
| `redis_key_prefix` | `PUPPET_CA_REDIS_KEY_PREFIX` |
| `redis_dial_timeout_sec` | `PUPPET_CA_REDIS_DIAL_TIMEOUT_SEC` |
| `redis_request_timeout_sec` | `PUPPET_CA_REDIS_REQUEST_TIMEOUT_SEC` |
| `redis_lock_ttl_sec` | `PUPPET_CA_REDIS_LOCK_TTL_SEC` |
| `redis_tls_ca_file` | `PUPPET_CA_REDIS_TLS_CA_FILE` |
| `redis_tls_cert_file` | `PUPPET_CA_REDIS_TLS_CERT_FILE` |
| `redis_tls_key_file` | `PUPPET_CA_REDIS_TLS_KEY_FILE` |

### Operational notes

- **Persistence.** Make sure the instance is durable enough for CA state (RDB
  snapshots and/or AOF). A pure in-memory instance with no persistence loses the
  CA on restart.
- **The CA private key lives in Redis by default.** Restrict ACLs, enable
  `encrypt_ca_key`, or pin the key to a local file with `ca_key_file` (see
  [CA cert/key as local files](#ca-certkey-as-local-files)).
- **`openvox-ca-ctl setup` / `import` work on the local filesystem only.**
  Bootstrap/import against a scratch directory, then point `openvox-ca` at a
  cadir containing the output.
- **The certificate inventory is stored as one hash field per issued
  certificate**, not as a single ever-growing text value, so signing cost does
  not grow with the size of the inventory and duplicate serial numbers are
  rejected atomically across all replicas (see
  [the inventory internals](development/inventory-store.md)). On first start
  after upgrading from a version that stored the inventory as a blob, the
  backend converts it in place automatically: the blob is first verified
  against its stored HMAC (a mismatch fails startup, exactly as it would have
  before the upgrade), and after the conversion the integrity value is
  re-established over the converted entries — the conversion window itself is
  the one moment tamper detection does not cover. An interrupted conversion
  resumes safely on the next start. **Upgrade all replicas together**: a
  not-yet-upgraded replica writing the old blob format while an upgraded one
  serves the converted inventory is not supported and is refused with an
  explicit error when detected.
- **The conversion is one-way; take a snapshot before the first upgraded
  start.** Downgrading to a release that predates it is not supported, and
  fails quietly rather than loudly: the old binary reads `inventory:data`,
  finds the bare marker the conversion left, and reports an *empty* inventory
  rather than an error — so it prunes nothing, and starts appending new
  issuances to the legacy blob. Upgrading again is then refused, because the
  blob and the entries hash no longer agree. Recovery is a restore from a
  Redis snapshot (RDB/AOF) taken before the upgrade, so take one.
- **The Redis backend also maintains the certificate index**: `GET
  /certificate_statuses` (`puppetserver ca list`) is answered from the
  decomposed inventory entries instead of reading and parsing every stored
  certificate, with the same rebuildable-projection semantics as the SQL
  backends — after migrating from another backend the display fields are
  backfilled automatically on the next server start. Note the first start
  after an upgrade or migration therefore performs both the inventory
  conversion and a per-certificate projection backfill before serving; on a
  large fleet expect it to take a while (progress is logged).
- **Bulk inventory rewrites are bounded.** Redis executes a Lua script
  atomically, blocking every other client for its duration, so an inventory
  conversion is split into scripts of 512 records and a single
  expired-certificate cleanup pass removes at most 5000 entries. Each pass is
  atomic — the inventory and its integrity head are never observably out of
  step — and a large backlog simply drains over several runs rather than
  stalling signing. At the default daily cleanup interval that is 5000
  entries/day: enabling cleanup for the first time on a large backlog, or
  running a fleet whose expiry churn exceeds it, calls for a shorter
  `expired_cert_cleanup_interval_sec` — the server logs every deferral, and
  escalates to a warning once the deferred backlog exceeds what a whole pass
  can remove, which is the point at which the backlog is growing rather than
  draining.
- **Legacy inventories with duplicate serial numbers** (possible, because the
  pre-conversion blob had no cluster-wide uniqueness guarantee) are imported
  verbatim with a startup warning naming the serials. The certificate index
  cannot track per-serial state for them, so their status in
  `certificate_statuses` output is derived from the signed CRL on each
  request (always correct, slightly slower) and their display fields come
  from the stored certificate. This resolves itself once the affected
  certificates expire and are cleaned up, or when they are revoked and
  reissued under fresh serials.
- **Redis Cluster is not supported.** The backend dials a single primary,
  directly or through Sentinel. The inventory scripts span several keys, which
  Cluster would require to share a hash slot.

---

## SQL backends

The `sqlite`, `postgres` and `mysql` backends share one SQL implementation. The
backend creates and upgrades its own tables automatically on startup, so
multiple replicas can start against the same database safely. `cadir` is still
required for per-subject keys and ancillary local state.

> **Upgrading a PostgreSQL or MySQL deployment across this release.** The
> advisory-lock key derivation changed, so a server running either side of the
> change does not exclude one running the other side — for as long as both are
> up, nothing serialises CRL rewrites or bootstrap across the two generations.
> **Stop the old process before starting the new one** for this one upgrade:
> with the Helm chart set `strategy: {type: Recreate}` (an external-backend
> deployment otherwise derives `RollingUpdate`), or scale to zero and back. If
> you set the strategy, clear it again afterwards — a pin left in place keeps
> costing you a Recreate outage on every later upgrade.
>
> **One replica is not enough to be safe.** The derived `RollingUpdate` sets
> `maxUnavailable: 0`, so the new pod must become Ready before the old one is
> terminated, and the two overlap even at `replicaCount: 1`. What does exempt
> you is already being on `Recreate` (which `persistence.enabled: true`
> derives), or running a single process you stop and restart yourself. SQLite
> and the filesystem backend are unaffected either way: their same-host lock
> derives from `sha256(name).lock` and is unchanged. Background: rule 11 of
> [locking](development/locking.md).

SQL backends additionally maintain a certificate index (as do
[etcd](#etcd-backend) and [Redis](#redis--valkey-backend)): `GET
/certificate_statuses` (`puppetserver ca list`)
is answered from indexed columns instead of reading and parsing every stored
certificate, which matters for large fleets. The index is a rebuildable
projection of the stored certificates and the CRL — after migrating from
another backend it is backfilled automatically on the next server start.

### SQLite backend

Stores the entire CA in one SQLite database file — a convenient, dependency-free
alternative to the filesystem backend (one file to back up instead of a
directory tree). `sqlite` and `sqlite3` are accepted as aliases. It is
single-node, not a clustering option.

```yaml
# /etc/puppet-ca/config.yaml
storage_backend: sqlite
cadir: /var/lib/puppet-ca                # still needed for per-subject keys
sql_dsn: "file:/var/lib/puppet-ca/ca.db" # SQLite database file path / URI

sql_request_timeout_sec: 10              # per-operation timeout (default 10)
sql_migration_timeout_sec: 600           # whole schema-migration run (default 600)
```

`openvox-ca` adds safe SQLite defaults to the DSN (WAL journal, immediate write
locking, a busy timeout) unless you set them yourself, so writers wait rather
than failing under contention.

```text
--storage-backend sqlite
--sql-dsn         file:/var/lib/puppet-ca/ca.db
```

**Operational notes.** The database file *is* the CA — back it up (with its WAL
sidecar) the way you would a cadir tree. The CA private key lives in the
database by default; enable `encrypt_ca_key` or pin it to a local file with
`ca_key_file`. `openvox-ca-ctl setup` / `import` work on the local filesystem
only; bootstrap against a scratch directory, then point a SQLite-backed
`openvox-ca` at a fresh database.

Alongside the database, `openvox-ca` keeps a hidden `.<database>.locks/`
directory — `.ca.db.locks/` for the DSN above — holding the lock files that stop
a second process on the host writing behind a running server's back, and the
store-wide lock that refuses a second instance outright. They are empty but for
that last one, which records its holder; see the note under [the filesystem
backend](#filesystem-backend-default).
The database file itself is never locked this way; SQLite locks that. See
[Running a second process against a live
store](#running-a-second-process-against-a-live-store).

### PostgreSQL backend

Stores the entire CA in a PostgreSQL database; multiple `openvox-ca` replicas
can share it. `postgres`, `postgresql` and `pg` are accepted as aliases.

```yaml
# /etc/puppet-ca/config.yaml
storage_backend: postgres
cadir: /var/lib/puppet-ca                # still needed for per-subject keys
sql_dsn: "postgres://puppetca:secret@db.example.com:5432/puppetca?sslmode=require"

sql_request_timeout_sec: 10              # per-operation timeout (default 10)
sql_migration_timeout_sec: 600           # whole schema-migration run (default 600)
sql_max_open_conns: 0                    # 0 = database/sql default; min 4 when set
sql_max_idle_conns: 0                    # 0 = database/sql default

# Optional mTLS to PostgreSQL (alternative to sslmode/ssl params in the DSN).
sql_tls_ca_file:   /etc/puppet-ca/pg-ca.pem
sql_tls_cert_file: /etc/puppet-ca/pg-client.pem
sql_tls_key_file:  /etc/puppet-ca/pg-client-key.pem
```

TLS is driven either by the DSN (`sslmode=require`, etc.) or by the
`sql_tls_*_file` options.

```text
--storage-backend postgres
--sql-dsn         postgres://puppetca:secret@db.example.com:5432/puppetca?sslmode=require
```

**Operational notes.** Back the database up with your normal PostgreSQL tooling.
The CA private key lives in the database by default; enable `encrypt_ca_key` or
pin it to a local file with `ca_key_file`. Grant the configured role rights to
create tables on first run (or pre-create the schema and grant DML).
`openvox-ca-ctl setup` / `import` work on the local filesystem only.

### MySQL / MariaDB backend

Stores the entire CA in a MySQL or MariaDB database; multiple `openvox-ca`
replicas can share it. `mysql` and `mariadb` are accepted as aliases.

```yaml
# /etc/puppet-ca/config.yaml
storage_backend: mysql                   # or "mariadb"
cadir: /var/lib/puppet-ca                # still needed for per-subject keys
sql_dsn: "puppetca:secret@tcp(db.example.com:3306)/puppetca"

sql_request_timeout_sec: 10              # per-operation timeout (default 10)
sql_migration_timeout_sec: 600           # whole schema-migration run (default 600)

# Optional TLS to the server (registered with the driver automatically;
# no need to add tls= to the DSN).
sql_tls_ca_file:   /etc/puppet-ca/mysql-ca.pem
sql_tls_cert_file: /etc/puppet-ca/mysql-client.pem
sql_tls_key_file:  /etc/puppet-ca/mysql-client-key.pem
```

The DSN is the [go-sql-driver/mysql](https://github.com/go-sql-driver/mysql)
form (`user:pass@tcp(host:3306)/dbname`).

```text
--storage-backend mysql
--sql-dsn         puppetca:secret@tcp(db.example.com:3306)/puppetca
```

**Operational notes.** The CA private key lives in the database by default;
enable `encrypt_ca_key` or pin it to a local file with `ca_key_file`.
`openvox-ca-ctl setup` / `import` work on the local filesystem only.

Do not point two independent `openvox-ca` deployments at one MySQL server, even
with separate databases. `GET_LOCK` names are scoped to the server instance
rather than to a schema, so both deployments take the same lock names and
serialise against each other. (Multiple replicas of *one* deployment sharing a
database is the supported arrangement and is exactly what those locks are for.)
PostgreSQL advisory locks are database-scoped, so the equivalent there is not to
share a *database* with another application that uses `pg_advisory_lock`.

### SQL environment variables

The SQL backends share one set of config keys and environment variables:

| Config key | Env var |
| --- | --- |
| `storage_backend` | `PUPPET_CA_STORAGE_BACKEND` |
| `sql_dsn` | `PUPPET_CA_SQL_DSN` |
| `sql_request_timeout_sec` | `PUPPET_CA_SQL_REQUEST_TIMEOUT_SEC` |
| `sql_max_open_conns` | `PUPPET_CA_SQL_MAX_OPEN_CONNS` |
| `sql_max_idle_conns` | `PUPPET_CA_SQL_MAX_IDLE_CONNS` |
| `sql_migration_timeout_sec` | `PUPPET_CA_SQL_MIGRATION_TIMEOUT_SEC` |
| `sql_tls_ca_file` | `PUPPET_CA_SQL_TLS_CA_FILE` |
| `sql_tls_cert_file` | `PUPPET_CA_SQL_TLS_CERT_FILE` |
| `sql_tls_key_file` | `PUPPET_CA_SQL_TLS_KEY_FILE` |

The pool-tuning and TLS settings apply only to the networked SQL dialects;
SQLite ignores them.

`sql_max_open_conns`, when set to a non-zero value below 4, is raised to 4 and
the effective value is logged at startup. The distributed locks are
session-scoped (PostgreSQL advisory locks and MySQL `GET_LOCK` both bind to
their connection), so each lock held occupies a connection for its lifetime
while the work under it needs another. A `migrate` run nests three deep — the
bootstrap lock, the migration lock inside it, and the migration's own
statements. A smaller pool would not merely be slow, it would deadlock, so the
floor is not negotiable. Leave the setting at 0 unless you have measured a
reason to cap it.

That floor covers `migrate`; it does not size a busy server. The requests that
retire a certificate — `Revoke`, `Clean`, and the renewal paths when they retire
the certificate they replaced — take `subject:<name>` and then, inside it, the
cluster-wide `crl` lock, so each one in flight wants three connections at once:
one per held lock, plus one for its own reads and writes. A plain sign or CSR
submission takes only `subject:<name>` and wants two.

Revocation joined that set in this release, and the cost shows up when
revocations overlap — several admin clients or an orchestration tool issuing
`PUT`/`DELETE /certificate_status/{subject}` for *distinct* subjects at once.
Throughput is unchanged, because they still queue one at a time on the single
`crl` lock; what changed is that each one now holds its own `subject:<name>`
connection for the whole of that wait instead of queueing without one. Size the
pool for the retirements you expect to overlap rather than for a single request.
Note that `PUT /clean` is not that case: it processes its certnames
sequentially, so a bulk clean holds one subject lock at a time and has always
paid this cost. See rule 8 in the
[locking notes](development/locking.md#rules-for-new-or-changed-code) for the
invariant behind this.

---

## CA cert/key as local files

Sometimes you want the benefits of a shared backend (agents, CSRs, signed
certs, CRL) without exposing the CA cert or private key in that backend.
Common scenarios:

- **Secret volume / HSM-adjacent.** The key is mounted from a Kubernetes
  secret, an encrypted tmpfs, or a path an HSM driver populates.
- **Operator-supplied cert.** The CA cert came from an offline ceremony and
  should never be rewritten by the server.

Set either or both of these options and the named asset is read/written
against the given local path instead of the selected backend. Everything
else (CSRs, signed certs, CRL, inventory, serial) still flows through the
configured backend.

### Configuration

```yaml
storage_backend: etcd
cadir: /var/lib/puppet-ca
etcd_endpoints: [https://etcd:2379]

# Keep the CA cert and key out of etcd; mount them from the host.
ca_cert_file: /etc/puppet-ca/secrets/ca_crt.pem
ca_key_file:  /etc/puppet-ca/secrets/ca_key.pem
```

### CLI flags

```text
--ca-cert-file /etc/puppet-ca/secrets/ca_crt.pem
--ca-key-file  /etc/puppet-ca/secrets/ca_key.pem
```

### Environment variables

| Config key | Env var |
| --- | --- |
| `ca_cert_file` | `PUPPET_CA_CA_CERT_FILE` |
| `ca_key_file` | `PUPPET_CA_CA_KEY_FILE` |

### Behaviour

- On **first start** with no existing CA, `openvox-ca` bootstraps a new CA
  and writes the cert/key to the configured local paths (not the backend).
- A populated `ca_key_file` with **no** CA certificate is refused rather than
  bootstrapped over. That state is what `openvox-ca csr --create-key` leaves
  behind while a parent signs the request, and also what a partial restore or an
  interrupted bootstrap looks like; overwriting the key would orphan every
  certificate issued under it, and would destroy the key an outstanding signing
  request is bound to. The startup error names the three ways out: install the
  signed chain with `openvox-ca import-ca-cert`, restore the certificate, or
  remove the orphaned key. See
  [offline subcommands on the server binary](operator-cli.md#offline-subcommands-on-the-server-binary),
  and [removing an orphaned CA key](#removing-an-orphaned-ca-key) below for how
  to do the last of those on each backend.
- On subsequent starts, the cert and key are loaded from the local paths.
- `openvox-ca` writes the cert at mode `0644` and the key at mode `0600`
  atomically (temp-file + rename). If you supply pre-existing files, they are
  read as-is and never overwritten unless the server rotates the CA.
- Existing protections still apply: `encrypt_ca_key` encrypts the key PEM
  before writing, and `ca_key_passphrase_file` overrides the auto-generated
  passphrase file.

This override also works with the filesystem backend, e.g. to pull the CA
key out of the cadir tree and onto a separately-mounted volume.

---

### Removing an orphaned CA key

A CA key with no CA certificate makes the server refuse to start, deliberately —
see [Behaviour](#behaviour) above. If the key really is orphaned (no signing
request is outstanding and no certificate is coming), removing it lets the CA
bootstrap afresh. **This retires the CA:** every certificate already issued
stops verifying, and every agent must be re-enrolled. There is no
`openvox-ca-ctl` command for it precisely because it is not an operation to
perform casually. Take a backup and stop the CA first.

Where the key lives depends on the backend. Note the physical names differ from
the logical key `ca_key`:

| Backend | Where the key is | How to remove it |
| --- | --- | --- |
| `filesystem` (default) | `private/ca_key.pem` under the cadir | `rm` the file |
| `ca_key_file` overlay | the configured path | `rm` the file |
| `sqlite`, `postgres`, `mysql` | table `puppet_ca_blobs`, column `blob_key`, value `ca_key` | `DELETE FROM puppet_ca_blobs WHERE blob_key = 'ca_key';` |
| `etcd` | `<prefix>/ca/key` | `etcdctl del <prefix>/ca/key` |
| `redis` / `valkey` | `<prefix>:ca:key` | `redis-cli DEL <prefix>:ca:key` |

The column is `blob_key` rather than `key` because `KEY` is reserved in
MySQL/MariaDB. The etcd and Redis paths are `ca/key` and `ca:key`, not `ca_key` —
and both `etcdctl del` and `redis-cli DEL` exit successfully having deleted
nothing when the name is wrong, so check the reported count. A zero means you
have the wrong name, not that the problem is solved. Do not reach for
`del --prefix` to compensate: that removes the whole CA.

#### With the CA key at a provider

`ca_key_provider: openbao` puts the key in a Transit engine rather than a
storage backend, and `HasCAKey` asks the provider directly — so a populated
Transit slot counts as present however empty the backend is. Three routes exist
for abandoning a half-finished sub-CA, and only the first two are cheap:

1. **Finish the round trip.** Have the parent sign the outstanding request and
   install it with `openvox-ca import-ca-cert`. This is the intended path and
   costs nothing.
2. **Have any CA you control sign the outstanding request.** `openvox-ca csr`
   emits a PKCS#10 request bound to the Transit key; a throwaway root made with
   `openssl` or `bao pki` can sign it, and `import-ca-cert` accepts the result
   (a lone self-signed CA is a valid bundle). This satisfies the startup check
   without touching the key. Note that *self*-signing a certificate for a
   non-exportable Transit key is not one of the options: it would mean signing a
   TBSCertificate with the Transit key and assembling the DER by hand, and
   neither `openvox-ca` nor `openvox-ca-ctl` will do that.
3. **Delete the Transit key**, which requires `deletion_allowed` on it, and let
   the CA bootstrap afresh. Irreversible, and it retires the CA as above.

Deleting the *CA certificate* and keeping the key is **not** a route: that is
exactly the state the startup refusal exists for, so the server will not
bootstrap over it. It leaves you with less to recover from and no closer to a
working CA.

## Migrating between backends

`openvox-ca-ctl migrate` copies an entire CA from one backend to another. Any
pair can be combined:

- import an existing filesystem CA into a database (`filesystem` → `postgres`),
- move between databases or stores (`redis`/`valkey` → `postgres`, `etcd` →
  `sqlite`, …),
- export a database back to a plain directory of files (`postgres` →
  `filesystem`), e.g. for an offline backup or to revert to a single-node setup.

Both ends are described by ordinary `openvox-ca` config files — the same YAML the
server reads. `--source-config` is read from; `--dest-config` is written to.

```bash
# Import a filesystem CA into PostgreSQL.
openvox-ca-ctl migrate \
  --source-config /etc/puppet-ca/filesystem.yaml \
  --dest-config   /etc/puppet-ca/postgres.yaml

# Export it back out to a directory of files.
openvox-ca-ctl migrate \
  --source-config /etc/puppet-ca/postgres.yaml \
  --dest-config   /etc/puppet-ca/filesystem.yaml
```

Each config file needs only the storage fields (plus `cadir`); for example a
minimal SQLite target:

```yaml
# sqlite.yaml
storage_backend: sqlite
cadir: /var/lib/puppet-ca
sql_dsn: file:/var/lib/puppet-ca/ca.db
```

The migration copies the whole CA — certificate, keys, CRL, serial, the
inventory (with its tamper-detection preserved), every pending CSR and every
signed certificate. Per-subject generated private keys are **not** copied: they
always live on the local filesystem under `cadir`, so on a remote backend they
stay put across a migration. The `ca_cert_file` / `ca_key_file` overrides are
honoured on both ends.

Notes:

- **Stop the server first**, on both ends. Run `migrate` while no `openvox-ca`
  is serving either backend, so the copy sees a consistent snapshot. It does not
  race one that is, and it no longer waits for one either: on a backend that
  supports a single running instance it is refused at once, naming the process
  holding the store, for the source as well as the destination — reading a live
  store still copies an inventory the server is appending to. Pointing
  `--source-config` and `--dest-config` at the same store is refused for the
  same reason, rather than waiting for ever on a lock it has already taken
  itself. See [running a second process against a live
  store](#running-a-second-process-against-a-live-store).
- **Overwrite protection.** `migrate` refuses to write into a destination that
  already holds a CA certificate. Pass `--force` to overwrite it.
- **Re-runnable.** The copy is idempotent per item; an interrupted run can be
  repeated (with `--force` if a partial CA already landed).
- Use `--verbose` to log each item as it is copied.

---

## Choosing a backend

| | `filesystem` | `sqlite` | `postgres` / `mysql` | `etcd` | `redis` / `valkey` |
| --- | --- | --- | --- | --- | --- |
| Replicas | one active | one active | many (active/active) | many (active/active) | many (active/active) |
| Operational dependencies | none | none (single file) | SQL server | healthy etcd cluster | Redis/Valkey primary (+ Sentinel) |
| CA key exposure | local file | in DB unless `ca_key_file` set | in DB unless `ca_key_file` set | in etcd unless `ca_key_file` set | in Redis unless `ca_key_file` set |
| Backup/restore | tar `<cadir>/` | copy `.db` (+ WAL) + local dirs | DB dump + local dirs | etcd snapshot + local dirs | RDB/AOF + local dirs |
| Cross-node consistency | single node | single node | strong | strongest | strong (narrow failover window) |
| Second instance, same store | refused (`flock`) | refused (`flock`) | supported | supported | supported |
| Drop-in for OpenVox/Puppet Server CA | yes | no (key paths change) | no (key paths change) | no (key paths change) | no (key paths change) |

> **If you publish an upstream CRL chain**, note that `openvox-ca-ctl import`
> writes to a local filesystem directory only. On every backend except
> `filesystem` — and on any backend under `encrypt_ca_key` or
> `ca_key_provider: openbao` —
> [`crl_chain_file`](configuration.md#publishing-an-upstream-crl-chain) is not
> merely the better way to keep ancestor CRLs current, it is the only one that
> does not require stopping the CA. On a non-`filesystem` backend there is a
> `migrate` round trip if you cannot deliver a file to the pod — see
> [re-importing a chain](migrating-from-puppet-server.md#step-3-import-the-ca)
> for it, and for the limits. Under `encrypt_ca_key` or
> `ca_key_provider: openbao` there is **no** fallback: `import` cannot parse an
> encrypted key, feeding it the plaintext one silently replaces your encrypted
> key with a plaintext one, and under OpenBao there is no exportable key at all.

Use `filesystem` for single-node installs or migrating from an OpenVox/Puppet
Server CA. Use `sqlite` for a single-node install that prefers one database file
over a cadir tree (e.g. simpler backups). Use `postgres` or `mysql` when you
want multiple `openvox-ca` replicas backed by a database you already operate.
Use `etcd` when you need multiple replicas and want the strongest cross-node
guarantees. Use `redis`/`valkey` when you already run Redis/Valkey and are
willing to accept the narrower failover window in exchange for reusing existing
infrastructure.

---

## Internals

The on-disk / in-store key layout for each backend, the cross-node coordination
mechanisms, the SQL schema, and the inventory integrity design are documented in
[storage internals](development/storage-internals.md) and
[the inventory store](development/inventory-store.md) — reference material for
contributors, not needed to deploy.
