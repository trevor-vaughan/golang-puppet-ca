# Storage backend internals

Reference material for contributors working on the storage layer. Deploying
`openvox-ca` needs none of this — see the user-facing
[storage backends](../storage-backends.md) guide instead. The inventory
integrity design has its own document, [the inventory store](inventory-store.md).

## Backend contract

`openvox-ca` abstracts its persistent state behind a pluggable **Backend**
interface. Every backend serves the following logical keys:

| Logical key | Purpose | Writer |
| --- | --- | --- |
| `ca_cert` | CA certificate (PEM) | bootstrap / import |
| `ca_pubkey` | CA public key (PEM, PKIX in a `PUBLIC KEY` block, companion to `ca_cert`) | bootstrap / import / seed |
| `ca_key` | CA private key (PEM, optionally AES-256-GCM encrypted) | bootstrap / import |
| `crl` | Certificate Revocation List (PEM). May hold several concatenated CRLs when a chain has been imported: this CA's own first, ancestors after it. The re-sign path (`readStoredCRL`) and every reader that parses a single CRL (`loadCRLCache`, `/expirations`) take block 0; the whole-blob consumers are `GET`/`PUT /certificate_revocation_list/ca`, the Kubernetes exporter, `storedCRLChain` on the import path, `publishedUpstream` and `RefreshCRLChainFile` (the `crl_chain_file` job), the metrics collector's per-issuer freshness series (`UpstreamCRLStatuses`, alongside its block-0 reads), and `crlChainLocked` on the re-sign path — which preserves the stored ancestor blocks only when `crl_chain_file` is unset; with it set the file is authoritative and the stored ancestors are replaced by what it names. Revocation questions are answered from `cachedCRL`, which `loadCRLCache` fills with the block this CA signed — the newest block it signed, wherever it sits, so a stale copy of ours at block 0 is passed over as readily as an ancestor's | bootstrap, revoke, rotate, import, seed |
| `serial` | Next leaf certificate serial counter | sign / seed |
| `inventory` | Append-only log of issued/revoked certificates | sign / revoke / seed |
| `inventory_hmac` | Inventory integrity head (blob HMAC, or hash chain on the structured backends: SQL, etcd, redis) | sign / revoke |
| `hmac_key` | Integrity key for `inventory_hmac` | first run |
| `superseded` | JSON list of certificates a renewal has replaced and that are awaiting delayed revocation: `{serial, subject, revoke_at}` per entry. Absent until the first supersession, which needs `superseded_cert_revoke_after_sec` set. Read-modify-written whole, under the cluster `crl` lock so an append and the sweep's rewrite exclude each other | renew / auto-renew / revoke / supersession sweep |
| `csr/<subject>` | Pending certificate signing request (PEM), per subject | CSR submission |
| `cert/<subject>` | Issued certificate (PEM), per subject | sign |

`inventory` is the only key that supports atomic append semantics; all other
keys are whole-blob read/write/delete.

*seed* above is `seedSupportingState` (`internal/ca/init.go`): a start that
finds a certificate and key but not the supporting state writes it then, rather
than at bootstrap. It covers a CA mounted into an empty backend via an overlay,
and a bootstrap that failed partway — including one that failed on `ca_pubkey`
itself, which nothing else would write again.

## Filesystem layout (full)

```text
<cadir>/
├── ca_crt.pem                      (KeyCACert)
├── ca_pub.pem                      (KeyCAPubKey)
├── ca_crl.pem                      (KeyCRL)
├── serial                          (KeySerial)
├── inventory.txt                   (KeyInventory)
├── .inventory.hmac                 (KeyInventoryHMAC)
├── superseded.json                 (KeySuperseded)     0600
├── private/
│   ├── ca_key.pem                  (KeyCAKey)          0600
│   ├── .inventory_hmac_key         (KeyHMACKey)        0600
│   └── <subject>_key.pem           server-gen keys     0600
├── requests/
│   └── <subject>.pem               (csr/<subject>)
├── signed/
│   └── <subject>.pem               (cert/<subject>)
└── locks/
    └── <sha256(name)>.lock         not a logical key   0600
```

`locks/` is the exception to the mapping above: its files are not blobs and have
no logical key, so `Get`/`Put`/`List`/`Migrate` never touch them. They are the
same-host `flock(2)` targets described under
[cross-node coordination](#cross-node-coordination) below.

## etcd backend

### Key layout

With the default prefix `/puppet-ca`:

| Logical key | etcd key |
| --- | --- |
| `ca_cert` | `/puppet-ca/ca/cert` |
| `ca_pubkey` | `/puppet-ca/ca/pubkey` |
| `ca_key` | `/puppet-ca/ca/key` |
| `crl` | `/puppet-ca/ca/crl` |
| `serial` | `/puppet-ca/serial` |
| `inventory` | `/puppet-ca/inventory/data` (presence marker only; see below) |
| `inventory_hmac` | `/puppet-ca/inventory/hmac` |
| `hmac_key` | `/puppet-ca/private/hmac_key` |
| `superseded` | `/puppet-ca/superseded` |
| `csr/<subject>` | `/puppet-ca/requests/<subject>` |
| `cert/<subject>` | `/puppet-ca/signed/<subject>` |

Stored values carry an 8-byte big-endian `time.UnixNano` mtime prefix so
`GET /puppet-ca/v1/certificate_revocation_list/ca` still answers
`If-Modified-Since` without a second round-trip.

The certificate inventory is not stored at `inventory/data` — that key is only
a presence marker (and the location pre-decomposition versions kept the blob).
The inventory itself is decomposed into one key per issued certificate under
`inventory/entries/<seq>`, with `inventory/seq` acting as sequence allocator
and mutation fence and `inventory/by-serial/<serial>` /
`inventory/by-subject/<subject>` as index keys. Appends are transactions
guarded on the fence's `ModRevision` with bounded retry, so concurrent
appends across replicas lose nothing and duplicate serials are rejected
cluster-wide. See
[the inventory store](inventory-store.md#the-etcd-decomposition) for the full
key family and the rules that keep it coherent. When two replicas race to
bootstrap, etcd's compare-and-swap semantics prevent double-writes of
`ca/cert` and `ca/key`; the loser observes the winner's cert and continues.

### Cross-node coordination

Operations that perform a read-modify-write against shared state — CA
bootstrap, CRL rotation during revocation, CSR-then-autosign sequencing — are
serialised across replicas by distributed locks implemented on top of etcd's
`concurrency.Mutex`. The backend keeps a lease-backed session (30s TTL) and
grabs per-name mutexes under `<prefix>/locks/<name>`. This section owns the
per-backend *mechanism*; the lock *names*, every operation that holds each one,
and the ordering invariant are documented in
[locking and concurrency](locking.md) — that table is authoritative for those,
so they are not duplicated here (its own backend table is only a summary of the
mechanism detail below).

If a replica holding a lock crashes without calling Unlock, the etcd lease
expires after 30s and the lock is released automatically. For the filesystem
backend (single-node), the same call path falls through to a same-host lock: an
exclusive `flock(2)` on `<cadir>/locks/<sha256 of the name>.lock`, taken behind
a per-name process-local `sync.Mutex` and released when the descriptor closes.
That excludes another process on the host and nothing beyond it — see
[locking and concurrency](locking.md) for why the two capabilities are separate
interfaces.

## Redis / Valkey backend

### Key layout

With the default prefix `puppet-ca` (Redis convention uses `:` as a
separator):

| Logical key | Redis key |
| --- | --- |
| `ca_cert` | `puppet-ca:ca:cert` |
| `ca_pubkey` | `puppet-ca:ca:pubkey` |
| `ca_key` | `puppet-ca:ca:key` |
| `crl` | `puppet-ca:ca:crl` |
| `serial` | `puppet-ca:serial` |
| `inventory` | `puppet-ca:inventory:data` (presence marker only; see below) |
| `inventory_hmac` | `puppet-ca:inventory:hmac` |
| `hmac_key` | `puppet-ca:private:hmac_key` |
| `superseded` | `puppet-ca:superseded` |
| `csr/<subject>` | `puppet-ca:requests:<subject>` |
| `cert/<subject>` | `puppet-ca:signed:<subject>` |

Stored values carry an 8-byte big-endian `time.UnixNano` mtime prefix so
`ModTime` is answered from the same round-trip as the value.

The certificate inventory is not stored at `inventory:data` — that key is only
a presence marker (and the location pre-decomposition versions kept the blob).
The inventory itself is decomposed into one hash field per issued certificate
in `inventory:entries`, with `inventory:seq` acting as sequence allocator and
mutation fence and `inventory:by-serial` / `inventory:by-subject` as index
hashes. Every mutation is one server-side Lua script — atomic by construction,
so an append either applies whole or not at all, and duplicate serials are
rejected cluster-wide. That atomicity is the primary's: unlike etcd's
consensus-backed writes above, Redis replication under Sentinel is
asynchronous, so a failover can still lose an entry the primary had
acknowledged but not yet replicated. Decomposition does not change that — it
is the same caveat `AcquireLock` documents for locks. See
[the inventory store](inventory-store.md#the-redis-decomposition) for the full
key family and the rules that keep it coherent.

### Cross-node coordination

Cross-replica locks are implemented with `SET NX PX` using a per-acquisition
random token. A background heartbeat extends the TTL (default 30s) while the
lock is held; `Unlock` runs a Lua script that deletes the key only when the
stored value still matches the caller's token. Lock names and their holders
are shared across every backend and documented in
[locking and concurrency](locking.md). If a replica holding a lock
crashes, the lock releases automatically when the TTL elapses.

Redis replication under Sentinel is asynchronous, so an in-flight failover
could in theory hand a lock to a new holder while the old primary briefly keeps
the prior entry. The resulting window is narrow and bounded by the lock TTL;
operators who need strict cross-node linearizability should prefer the etcd
backend.

## SQL backends

A single shared backend stores every logical key (except the local private-key
directory) as one row in a key-value table, with the certificate inventory
broken out into its own structured table. The same implementation drives every
dialect; only the driver, a few SQL clauses, and the cross-node lock mechanism
differ. SQLite uses [`modernc.org/sqlite`](https://pkg.go.dev/modernc.org/sqlite)
(a pure-Go translation, no CGO), so the default `CGO_ENABLED=0` and
`GOEXPERIMENT=boringcrypto` (FIPS) builds are unaffected.

### Schema and migrations

Most logical keys live in a key-value table, `puppet_ca_blobs`:

| Column | Purpose |
| --- | --- |
| `blob_key` | logical key (primary key) — e.g. `ca_cert`, `cert/<subject>` |
| `data` | blob payload |
| `kind` | visibility hint (public/private); recorded, not enforced |
| `modified_at` | last-write timestamp, used to answer `ModTime` |

Migrations are managed by [bun](https://bun.uptrace.dev/)'s migrator. On every
start the backend runs any pending migrations and records applied versions in
its own `bun_migrations` table. Migrations are defined as Go functions, so one
definition emits dialect-correct DDL across SQLite, PostgreSQL, and
MySQL/MariaDB.

bun does **not** serialise concurrent migration runners on its own. It creates a
`bun_migration_locks` table and exposes `Migrator.Lock`/`Unlock`, but `Migrate`
never calls them, and it records a migration as applied *before* running it. Two
processes starting together — separate replicas, or the signer and frontend of
one replica — will therefore both see a version as unapplied, both record it,
and both run its DDL; the loser fails on work the winner already did, and the
version stays recorded and is never retried. `EnsureReady` closes that hole with
four measures:

- It holds the backend's own distributed lock (`sql-schema-migrate`) across the
  whole run, taken before any migration state is read.
- It passes `WithMarkAppliedOnSuccess`, so a failed migration is retried on the
  next start rather than remembered as done.
- Each migration's DDL runs in a transaction where the dialect has transactional
  DDL (PostgreSQL and SQLite), and every statement is idempotent, so MySQL —
  which commits implicitly on each DDL statement — recovers by re-running.
- The run gets its own timeout rather than the per-statement request timeout, so
  a slow index build cannot be cut off part-way.

SQLite has no distributed lock, so `EnsureReady` walks the same tiers
`WithLock` does — by hand, since the migration budget and the "waiting for the
lock" announcement belong to it — and takes the same-host `flock` instead. Two
processes sharing one file therefore no longer race here. Where even that is
unavailable (an in-memory database, a platform without `flock(2)`) the fallback
is the process-local mutex, and the transactional, idempotent migrations mean a
loser fails cleanly and succeeds on its next start rather than leaving the
schema half-changed.

#### Recovering a half-migrated schema

A database migrated by a build without those measures can hold a version in
`bun_migrations` whose DDL only partly ran — typically visible as a startup
failure naming a column that does not exist, reported as an inventory integrity
failure because the integrity check is the first thing to read the table.
Confirm it by listing the table's columns and the recorded versions:

```sql
SELECT column_name FROM information_schema.columns
 WHERE table_name = 'puppet_ca_inventory' ORDER BY ordinal_position;
SELECT id, name, group_id, migrated_at FROM bun_migrations ORDER BY id;
```

SQLite has no `information_schema`; list the columns there with the pragma
form instead (the `bun_migrations` query works unchanged), mirroring the
dialect split `columnExists` implements in code:

```sql
SELECT name FROM pragma_table_info('puppet_ca_inventory');
```

Two rows for one version, recorded milliseconds apart, are the fingerprint of
two runners having raced. To recover, stop every replica, delete the duplicate
rows for the affected version, and start one replica: migrations are idempotent,
so the run completes the missing DDL and leaves the already-applied statements
alone. Applying the remaining DDL by hand and leaving the rows in place works
equally well and is the safer choice on a large table, where the missing
statement may be a long index build you would rather schedule.

On MySQL/MariaDB, the first-run migration widens the `data` column to `LONGBLOB`
(MySQL's default `BLOB` caps at 64 KiB, too small for large blobs such as the
CRL).

### Structured inventory

The SQL backends do not store the inventory as one growing `inventory` blob.
Each issued certificate is a row in a dedicated `puppet_ca_inventory` table,
indexed by subject:

| Column | Purpose |
| --- | --- |
| `id` | autoincrement key; also defines issuance order |
| `serial` | certificate serial (unique) |
| `subject` | certificate subject (indexed) |
| `not_before` / `not_after` | validity window, stored as the inventory.txt strings |
| `fingerprint_sha256` | SHA-256 fingerprint; `NULL` means "no projection, read the PEM" |
| `dns_alt_names` | subject alternative names, JSON array; `NULL` when empty |
| `auth_extensions` | Puppet auth extensions, JSON object; `NULL` when empty |
| `state` | `signed` or `revoked`, projected from the signed CRL (indexed) |
| `revoked_at` | revocation time; `NULL` unless revoked |

The last five columns make the table double as the certificate index; see
[the inventory store](inventory-store.md) for what reads them and how a missing
projection falls back to the stored PEM. `not_after` is indexed alongside
`state` for consumers that have not landed yet (see the migration's own note).

This turns appends and revocation lookups (`LatestSerialForSubject`) into
single-row operations instead of scanning the whole inventory. Integrity uses a
**hash chain** rather than a whole-blob HMAC. See
[the inventory store](inventory-store.md) for the full design.

### Cross-node coordination

Lock names, holders, and ordering are documented in
[locking and concurrency](locking.md); only the per-dialect mechanism differs:

- **SQLite** is single-node: `AcquireLock` reports
  `ErrDistributedLockingUnsupported` and `WithLock` falls through to the
  same-host `flock`, exactly as the filesystem backend does. The lock files live
  in a hidden `.<database>.locks/` directory beside the database, alongside the
  `-wal` and `-shm` files SQLite maintains itself; the database file is never
  flocked, because SQLite locks that. A lock *table* was rejected rather than
  merely not chosen: the pool is pinned to one connection, so a `BEGIN
  IMMEDIATE` held for the duration of the critical section would own the only
  connection the work inside it needs. The backend also appends
  `_txlock=immediate`, `busy_timeout`, and `journal_mode=WAL` to the DSN unless
  already set.
- **PostgreSQL** uses session-level advisory locks. The lock name is mapped to
  the `bigint` key `pg_advisory_lock` requires through a *partitioned* key
  space, not a uniform hash: a reserved singleton name (`bootstrap`, `crl`,
  `sql-schema-migrate`) takes a namespaced base plus its hand-assigned ordinal,
  with bit 63 clear, and every other name — every `subject:<name>` — takes the
  leading 64 bits of SHA-256 over the domain-separated name with bit 63 set. The
  two halves cannot meet, so no subject name can reach a singleton's key; see
  rule 11 of [locking](locking.md) for why. The lock is taken on a dedicated
  connection
  and released with `pg_advisory_unlock` on that same connection. A crashed
  replica's session ends and the lock releases automatically. A process-local
  mutex serialises in-process callers first so they don't each tie up a blocked
  connection.
- **MySQL/MariaDB** uses named locks via `GET_LOCK` / `RELEASE_LOCK` on a
  dedicated connection. The lock name is mapped to a stable identifier within
  MySQL's 64-character `GET_LOCK` limit, partitioned on the same principle:
  `openvox-ca:0:<name>` for a reserved singleton, `openvox-ca:1:<128-bit hex>`
  for everything else; acquisition polls with a one-second
  server-side wait so caller-context cancellation is honoured. Concurrent
  inventory appends serialise on a `FOR UPDATE` transaction; an InnoDB deadlock
  (the expected outcome when two replicas race to create the same not-yet-
  existing row) is retried transparently.

## Upgrading a pre-fix `ca_key_file` / `ca_cert_file` + database deployment

Builds from before the InventoryStore-unwrap fix computed the inventory
integrity value under the whole-blob HMAC scheme when a local cert/key override
wrapped a SQL backend, instead of that backend's hash chain. The first start
after upgrading such a deployment reports `ErrInventoryTampered` even though
nothing was tampered with — only the *scheme* changed, not the data. The
inventory rows are intact, so recompute the integrity head by running
`openvox-ca-ctl migrate` from the affected backend into a fresh destination (the
migration rewrites the head under the correct scheme; a store cannot be migrated
onto itself) and then serve from that destination. This affects pre-release
builds only; deployments created after the fix are unaffected.

## Optional capabilities

Two properties vary by backend and are not visible from the `Backend` interface
alone. `StorageService` answers both, because callers that need to know cannot
determine them for themselves — `openvox-ca generate` uses them to decide
whether it is safe to write to storage a live server is also using.

| Backend | `SupportsDistributedLocking` | `SupportsAtomicInventory` |
| --- | --- | --- |
| `postgres`, `mysql` | yes | yes |
| `sqlite` | no | yes |
| `etcd`, `redis` | yes | yes |
| `filesystem` | no | no |

**"Atomic" here covers the line append *and* the integrity-head update
together**, which is narrower than the word's use in the backend sections above.
Only the filesystem backend now answers `false`: it reads the whole inventory,
appends, and writes a recomputed whole-blob HMAC as a separate step, and it is
that pair being non-atomic which lets a concurrent appender leave an integrity
value covering a state that never existed. etcd and Redis once answered `false`
for the same reason; their decompositions closed it, advancing the chain head
inside the CAS append and the Lua script respectively.

`SupportsAtomicInventory` wraps `asInventoryStore`, so it is true exactly for
backends implementing `InventoryStore` — the SQL backends including SQLite, plus
etcd and Redis.
It is a method rather than a caller-side type assertion because
`asInventoryStore` unwraps `OverlayBackend`, and a caller asserting on the
wrapper would answer "no" for a SQL backend that happens to be overlaid by
`ca_cert_file`.

`SupportsDistributedLocking` deliberately does **not** answer
`_, ok := backend.(Locker)`. That assertion is true for two backends that
provide no cross-process lock at all: `SQLBackend` implements `Locker` but
returns `ErrDistributedLockingUnsupported` for SQLite, and `OverlayBackend`
implements it but delegates to a base that may not. A caller using the
assertion to decide whether a second process is safe would be told the opposite
of the truth in exactly the configurations where it matters. So the method
reproduces `WithLock`'s decision instead — same `AcquireLock` call, same
classification of the result, lock released immediately.

It returns three outcomes, not two. A non-sentinel `AcquireLock` failure means
the lock service is unreachable, which `WithLock` treats as fatal; reporting
that as `false` would tell an operator their backend does not do distributed
locking when the truth is that it is temporarily unavailable.

The probe cannot be folded into `WithLock` — that would add a lock round trip
to every `Sign` — so the two necessarily duplicate the classification. A
`DescribeTable` in
[internal/storage/capability_test.go](../../internal/storage/capability_test.go)
runs the backends constructible without a live service — `filesystem`, `sqlite`
and a stub `Locker` — through both and asserts they agree. That spec is what
keeps the probe and `WithLock` from drifting, not the type system.

That agreement table covers the *locking* column only: `postgres`, `mysql`,
`etcd` and `redis` are classified there by the code above rather than by a spec,
because the probe needs a live service to answer. `SupportsAtomicInventory` has
no such constraint — it is a pure type probe, so the same file covers `etcd` and
`redis` in-process alongside `filesystem`. **Add a new backend to whichever of
the two tables can construct it in-process**, and otherwise state its
classification here.

## Extending

The `Backend` interface is defined in
[internal/storage/backend.go](../../internal/storage/backend.go). To add a new
backend, implement the interface, declare its optional capabilities (see above,
including the `capability_test.go` table **and the operator-facing table in
[operator-cli.md](../operator-cli.md#running-alongside-a-live-server)**, which
tells operators whether it is safe to mint against a running server), register
it in
[internal/storage/spec.go](../../internal/storage/spec.go)'s
`NewServiceFromSpec`, and add any backend-specific config fields to
[internal/config/storage.go](../../internal/config/storage.go)'s `StorageConfig`
(shared by the server and `openvox-ca-ctl migrate`, and mapped to a
`BackendSpec` by `ToBackendSpec`). The `OverlayBackend` wrapper (overlay.go)
shows how to compose a backend with local-file overrides. A new backend is
automatically migratable — `openvox-ca-ctl migrate` works against any `Backend`
implementation with no extra code.

## Tests

Backend integration suites are gated behind Go build tags. See
[testing](testing.md) for the `mage test:backends*` targets, and
[`AGENTS.md`](../../AGENTS.md) for the build-tag conventions. The opt-in
environment variables for pointing a suite at a real service:

```bash
# etcd (embedded, no external service needed)
go test -tags=etcd_integration ./internal/storage/...

# Redis / Valkey
PUPPET_CA_TEST_REDIS_ADDR=127.0.0.1:6379 \
    go test -tags=redis_integration ./internal/storage/...

# PostgreSQL
PUPPET_CA_TEST_POSTGRES_DSN="postgres://user:pass@127.0.0.1:5432/db?sslmode=disable" \
    go test -tags=postgres_integration ./internal/storage/...

# MySQL / MariaDB
PUPPET_CA_TEST_MYSQL_DSN="user:pass@tcp(127.0.0.1:3306)/db" \
    go test -tags=mysql_integration ./internal/storage/...
```
