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
| `ca_pubkey` | CA public key (PEM, companion to `ca_cert`) | bootstrap |
| `ca_key` | CA private key (PEM, optionally AES-256-GCM encrypted) | bootstrap / import |
| `crl` | Current Certificate Revocation List (PEM) | bootstrap, revoke, rotate |
| `serial` | Next leaf certificate serial counter | sign |
| `inventory` | Append-only log of issued/revoked certificates | sign / revoke |
| `inventory_hmac` | Inventory integrity head (blob HMAC or hash chain on SQL) | sign / revoke |
| `hmac_key` | Integrity key for `inventory_hmac` | first run |
| `serving_cert` | Serving certificate the API listener presents (PEM) | `tls_self_provision` |
| `serving_key` | Serving private key (PEM, optionally AES-256-GCM encrypted) | `tls_self_provision` |
| `serving_superseded` | Pending revocations for replaced serving certificates (JSON) | `tls_self_provision` |
| `csr/<subject>` | Pending certificate signing request (PEM), per subject | CSR submission |
| `cert/<subject>` | Issued certificate (PEM), per subject | sign |

`inventory` is the only key that supports atomic append semantics; all other
keys are whole-blob read/write/delete.

## Filesystem layout (full)

```text
<cadir>/
├── ca_crt.pem                      (KeyCACert)
├── ca_pub.pem                      (KeyCAPubKey)
├── ca_crl.pem                      (KeyCRL)
├── serial                          (KeySerial)
├── inventory.txt                   (KeyInventory)
├── .inventory.hmac                 (KeyInventoryHMAC)
├── serving_cert.pem                (KeyServingCert)
├── serving_superseded.json         (KeyServingSuperseded)
├── private/
│   ├── ca_key.pem                  (KeyCAKey)          0600
│   ├── serving_key.pem             (KeyServingKey)     0600
│   ├── .inventory_hmac_key         (KeyHMACKey)        0600
│   └── <subject>_key.pem           server-gen keys     0600
├── requests/
│   └── <subject>.pem               (csr/<subject>)
└── signed/
    └── <subject>.pem               (cert/<subject>)
```

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
| `inventory` | `/puppet-ca/inventory/data` |
| `inventory_hmac` | `/puppet-ca/inventory/hmac` |
| `hmac_key` | `/puppet-ca/private/hmac_key` |
| `serving_cert` | `/puppet-ca/serving/cert` |
| `serving_key` | `/puppet-ca/private/serving_key` |
| `serving_superseded` | `/puppet-ca/serving/superseded` |
| `csr/<subject>` | `/puppet-ca/requests/<subject>` |
| `cert/<subject>` | `/puppet-ca/signed/<subject>` |

Stored values carry an 8-byte big-endian `time.UnixNano` mtime prefix so
`GET /puppet-ca/v1/certificate_revocation_list/ca` still answers
`If-Modified-Since` without a second round-trip.

Inventory appends use an etcd transaction guarded on the key's `ModRevision`
with bounded retry, so concurrent appends across replicas don't lose lines.
When two replicas race to bootstrap, etcd's compare-and-swap semantics prevent
double-writes of `ca/cert` and `ca/key`; the loser observes the winner's cert
and continues.

### Cross-node coordination

Operations that perform a read-modify-write against shared state — CA
bootstrap, CRL rotation during revocation, CSR-then-autosign sequencing — are
serialised across replicas by distributed locks implemented on top of etcd's
`concurrency.Mutex`. The backend keeps a lease-backed session (30s TTL) and
grabs per-name mutexes under `<prefix>/locks/<name>`:

| Lock name | Held during |
| --- | --- |
| `bootstrap` | First-run CA generation (winner writes, loser loads) |
| `crl` | `Revoke` (read CRL, append entry, write CRL) |
| `subject:<subject>` | `SaveRequest` and `Sign` for that one subject |

If a replica holding a lock crashes without calling Unlock, the etcd lease
expires after 30s and the lock is released automatically. For the filesystem
backend (single-node), the same call path falls back to a process-local
`sync.Mutex` per lock name.

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
| `inventory` | `puppet-ca:inventory:data` |
| `inventory_hmac` | `puppet-ca:inventory:hmac` |
| `hmac_key` | `puppet-ca:private:hmac_key` |
| `serving_cert` | `puppet-ca:serving:cert` |
| `serving_key` | `puppet-ca:private:serving_key` |
| `serving_superseded` | `puppet-ca:serving:superseded` |
| `csr/<subject>` | `puppet-ca:requests:<subject>` |
| `cert/<subject>` | `puppet-ca:signed:<subject>` |

Stored values carry an 8-byte big-endian `time.UnixNano` mtime prefix so
`ModTime` is answered from the same round-trip as the value. Inventory appends
are performed by a Lua script on the server, making a read-modify-write
single-step atomic across all replicas.

### Cross-node coordination

Cross-replica locks are implemented with `SET NX PX` using a per-acquisition
random token. A background heartbeat extends the TTL (default 30s) while the
lock is held; `Unlock` runs a Lua script that deletes the key only when the
stored value still matches the caller's token. Lock names mirror the etcd
backend (`bootstrap`, `crl`, `subject:<subject>`). If a replica holding a lock
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
its own `bun_migrations` table; a `bun_migration_locks` table serialises
concurrent runners so multiple replicas can start against the same database
safely. Migrations are defined as Go functions, so one definition emits
dialect-correct DDL across SQLite, PostgreSQL, and MySQL/MariaDB.

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

This turns appends and revocation lookups (`LatestSerialForSubject`) into
single-row operations instead of scanning the whole inventory. Integrity uses a
**hash chain** rather than a whole-blob HMAC. See
[the inventory store](inventory-store.md) for the full design.

### Cross-node coordination

- **SQLite** is single-node: `WithLock` falls back to a process-local
  `sync.Mutex` per lock name, exactly as the filesystem backend does. The
  backend appends `_txlock=immediate`, `busy_timeout`, and `journal_mode=WAL`
  to the DSN unless already set, and pins the pool to a single connection.
- **PostgreSQL** uses session-level advisory locks: the lock name is hashed to
  the `bigint` key `pg_advisory_lock` requires, taken on a dedicated connection
  and released with `pg_advisory_unlock` on that same connection. A crashed
  replica's session ends and the lock releases automatically. A process-local
  mutex serialises in-process callers first so they don't each tie up a blocked
  connection.
- **MySQL/MariaDB** uses named locks via `GET_LOCK` / `RELEASE_LOCK` on a
  dedicated connection. The lock name is hashed to a stable identifier within
  MySQL's 64-character `GET_LOCK` limit; acquisition polls with a one-second
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

## Extending

The `Backend` interface is defined in
[internal/storage/backend.go](../../internal/storage/backend.go). To add a new
backend, implement the interface, register it in
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
