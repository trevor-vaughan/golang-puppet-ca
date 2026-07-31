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
revoke, or refresh the CRL and the others see the change immediately;
`openvox-ca` coordinates the replicas and recovers automatically if one crashes.
You don't need to configure any of that.

---

## Filesystem backend (default)

All CA state lives under `--cadir`. The on-disk layout matches the OpenVox/Puppet
Server CA, so you can swap in `openvox-ca` without reorganising your SSL tree:

```text
<cadir>/
├── ca_crt.pem              CA certificate
├── ca_pub.pem              CA public key
├── ca_crl.pem              Certificate Revocation List
├── inventory.txt           Issued/revoked certificate log
├── private/
│   ├── ca_key.pem          CA private key                    0600
│   └── <subject>_key.pem   server-generated private keys     0600
├── requests/
│   └── <subject>.pem       pending CSRs
└── signed/
    └── <subject>.pem       issued certificates
```

(The directory also holds small internal integrity files; leave them in place.)
File permissions are fixed: `0600` for anything under `private/`, `0644` for
everything else. `openvox-ca` warns at startup about any `*_key.pem` in
`private/` whose permissions are looser than `0600` and leaves them for you to
fix.

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

  > **`tls_self_provision` adds a second private key.** The serving key is stored the same way, and `ca_key_file` does **not** pin it — only `tls_self_provision_encrypt_key` protects it at rest. If you hold the CA key at a provider or in a local file, this is the only private key in the backend. See [CA key security](ca-key-security.md).
- **`openvox-ca-ctl setup` / `import` work on the local filesystem only.** To
  import a CA into an etcd-backed cluster, run them against a scratch directory
  first, then point `openvox-ca` at a cadir containing the output.

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

  > **`tls_self_provision` adds a second private key.** The serving key is stored the same way, and `ca_key_file` does **not** pin it — only `tls_self_provision_encrypt_key` protects it at rest. If you hold the CA key at a provider or in a local file, this is the only private key in the backend. See [CA key security](ca-key-security.md).
- **`openvox-ca-ctl setup` / `import` work on the local filesystem only.**
  Bootstrap/import against a scratch directory, then point `openvox-ca` at a
  cadir containing the output.

---

## SQL backends

The `sqlite`, `postgres` and `mysql` backends share one SQL implementation. The
backend creates and upgrades its own tables automatically on startup, so
multiple replicas can start against the same database safely. `cadir` is still
required for per-subject keys and ancillary local state.

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
`ca_key_file`.

> **`tls_self_provision` adds a second private key.** The serving key is stored the same way, and `ca_key_file` does **not** pin it — only `tls_self_provision_encrypt_key` protects it at rest. If you hold the CA key at a provider or in a local file, this is the only private key in the backend. See [CA key security](ca-key-security.md).

`openvox-ca-ctl setup` / `import` work on the local filesystem
only; bootstrap against a scratch directory, then point a SQLite-backed
`openvox-ca` at a fresh database.

### PostgreSQL backend

Stores the entire CA in a PostgreSQL database; multiple `openvox-ca` replicas
can share it. `postgres`, `postgresql` and `pg` are accepted as aliases.

```yaml
# /etc/puppet-ca/config.yaml
storage_backend: postgres
cadir: /var/lib/puppet-ca                # still needed for per-subject keys
sql_dsn: "postgres://puppetca:secret@db.example.com:5432/puppetca?sslmode=require"

sql_request_timeout_sec: 10              # per-operation timeout (default 10)
sql_max_open_conns: 0                    # 0 = database/sql default
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
pin it to a local file with `ca_key_file`.

> **`tls_self_provision` adds a second private key.** The serving key is stored the same way, and `ca_key_file` does **not** pin it — only `tls_self_provision_encrypt_key` protects it at rest. If you hold the CA key at a provider or in a local file, this is the only private key in the backend. See [CA key security](ca-key-security.md).

Grant the configured role rights to
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

> **`tls_self_provision` adds a second private key.** The serving key is stored the same way, and `ca_key_file` does **not** pin it — only `tls_self_provision_encrypt_key` protects it at rest. If you hold the CA key at a provider or in a local file, this is the only private key in the backend. See [CA key security](ca-key-security.md).

`openvox-ca-ctl setup` / `import` work on the local filesystem only.

### SQL environment variables

The SQL backends share one set of config keys and environment variables:

| Config key | Env var |
| --- | --- |
| `storage_backend` | `PUPPET_CA_STORAGE_BACKEND` |
| `sql_dsn` | `PUPPET_CA_SQL_DSN` |
| `sql_request_timeout_sec` | `PUPPET_CA_SQL_REQUEST_TIMEOUT_SEC` |
| `sql_max_open_conns` | `PUPPET_CA_SQL_MAX_OPEN_CONNS` |
| `sql_max_idle_conns` | `PUPPET_CA_SQL_MAX_IDLE_CONNS` |
| `sql_tls_ca_file` | `PUPPET_CA_SQL_TLS_CA_FILE` |
| `sql_tls_cert_file` | `PUPPET_CA_SQL_TLS_CERT_FILE` |
| `sql_tls_key_file` | `PUPPET_CA_SQL_TLS_KEY_FILE` |

The pool-tuning and TLS settings apply only to the networked SQL dialects;
SQLite ignores them.

> **`sql_max_open_conns` has a floor.** On PostgreSQL and MySQL each held
> distributed lock pins one pooled connection for its whole critical section,
> because both dialects scope their locks to a session. The CA nests locks: a
> renewal or a clean holds two (subject, then CRL) and needs a third for the
> work inside, and with `tls_self_provision` on the superseded-certificate sweep
> holds three (serving, subject, CRL) and needs a fourth. Setting
> `sql_max_open_conns` below **three** — or below **four** with
> `tls_self_provision` — stalls the pool until the 60-second lock timeout
> expires, on every pass.
>
> Those are floors for **one operation in isolation**, and the pool is
> process-wide. A CA serving traffic runs the maintenance sweep, agent
> renewals, the CRL refresher and the metrics collector concurrently, each
> needing its own connections and none able to release a lock-pinned one until
> its work completes — so a working setting is the floor multiplied by the
> operations you expect in flight. `0` (the default) means no limit; leave it
> there unless the database forces otherwise, and size any explicit value with
> plenty of headroom.
> SQLite is unaffected: it has no distributed locking and falls back to
> process-local mutexes, which hold no connection.

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
- On subsequent starts, the cert and key are loaded from the local paths.
- `openvox-ca` writes the cert at mode `0644` and the key at mode `0600`
  atomically (temp-file + rename). If you supply pre-existing files, they are
  read as-is and never overwritten unless the server rotates the CA.
- Existing protections still apply: `encrypt_ca_key` encrypts the key PEM
  before writing, and `ca_key_passphrase_file` overrides the auto-generated
  passphrase file.
- **This override covers the CA cert and key only.** The
  `tls_self_provision` serving key has no local-file equivalent and stays in the
  backend; use `tls_self_provision_encrypt_key` to protect it there.

This override also works with the filesystem backend, e.g. to pull the CA
key out of the cadir tree and onto a separately-mounted volume.

---

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

- **Stop the server first.** Run `migrate` while no `openvox-ca` is serving
  either backend, so the copy sees a consistent snapshot.
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
| Drop-in for OpenVox/Puppet Server CA | yes | no (key paths change) | no (key paths change) | no (key paths change) | no (key paths change) |

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
