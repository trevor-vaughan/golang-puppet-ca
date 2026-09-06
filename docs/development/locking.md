# Locking and concurrency

Reference for contributors (human or AI) touching any code path that reads or
mutates shared CA state. Deploying `openvox-ca` needs none of this. Companion
documents: [storage internals](storage-internals.md) for the backend contract
and [the inventory store](inventory-store.md) for inventory integrity.

The one-paragraph version: **mutations serialise on cluster-wide named locks
taken through `StorageService.WithLock`; read-only paths never take a
distributed lock** — they use in-memory caches and process-local read locks
only. When you add a code path, decide which side of that line it is on first,
and everything else follows.

## The three tiers

Locking happens at three distinct levels. They are not interchangeable — each
protects against a different class of interleaving.

| Tier | Mechanism | Protects against | Defined in |
| --- | --- | --- | --- |
| Cluster-wide named locks | `StorageService.WithLock(ctx, name, fn)` | Concurrent mutations from **other replicas** sharing the same backend, or failing that from **other processes on this host** | [storage.go](../../internal/storage/storage.go) |
| Storage-service mutexes | `serialMu`, `inventoryMu` (RW), `crlMu` (RW), `fileMu` (RW) | Interleaved compound storage operations **within this process** | [storage.go](../../internal/storage/storage.go) |
| CA in-memory state | `ca.CA.mu` (RW) | Torn reads/writes of the CA's **in-memory caches** | [ca.go](../../internal/ca/ca.go) |

### Tier 1: cluster-wide named locks (`WithLock`)

`StorageService.WithLock` runs `fn` while holding a named lock, taking the
strongest lock the backend offers. Three sub-tiers, tried in order:

1. **`Locker`** — coordinated across every replica sharing the backend (etcd,
   Redis, PostgreSQL, MySQL).
2. **`SameHostLocker`** — coordinated across every process on this host, and
   across no more than that. An exclusive `flock(2)` on a file per lock name,
   provided by the two single-node backends (filesystem, SQLite).
3. A process-local named `sync.Mutex`, for a backend offering neither.

The two capabilities are deliberately separate interfaces rather than one with
a quality setting. A caller deciding whether it is safe to start a second
*replica* must not be told "yes" because a second *process* is handled, so the
filesystem backend implements `SameHostLocker` and still implements no
`Locker`, and SQLite still answers `ErrDistributedLockingUnsupported`. Nothing
that probes for cross-node coordination changed its answer when same-host
locking landed.

What sub-tier 2 buys is the case an operator actually meets: an
`openvox-ca-ctl` command, or a second server, run against the same store on the
same host as a live one. Before it, both wrote with no coordination at all —
two issuers could each pass `evictRevokedLocked` and produce two certificates
for one subject. Now the second process waits, and then fails with "another
process on this host holds the CA lock" if it waits past its deadline.

Read that as scoped to the lock names, because it is. Two processes contending
for the *same* name — the same subject, the CRL, bootstrap, a migration — now
exclude each other. Two processes issuing for **different** subjects hold
different `subject:<name>` locks and are not serialised against each other at
all, so the inventory-HMAC corruption in the motivating issue is *not* fully
closed by this tier: `AppendInventory` is guarded by `inventoryMu` and no
cluster lock, so its append and integrity rewrite can still interleave and
leave an HMAC covering a blob that never existed, which fails `InitHMAC` at the
*next* start. That is [#204](https://github.com/voxpupuli/openvox-ca/issues/204)
in the known gaps below, and the fix for it inherits cross-process coverage on
these backends from this tier.

What it does not buy is clustering. `flock(2)` is not a sound basis for
coordination across hosts — over NFS it depends on the server, the mount
options and the client's `lockd`, none of which this code can see — so shared
storage across hosts stays unsupported for both backends, exactly as
[storage backends](../storage-backends.md) scopes them.

The lock names are part of the cross-replica protocol: every replica must agree
on them, so they are **stable across releases**. Names taken through
`WithLock` by the CA layer are defined in
[init.go](../../internal/ca/init.go) — with one mirror: `migrateLockName` in
[migrate.go](../../internal/storage/migrate.go) redefines `"bootstrap"`
independently (the `internal/storage` package cannot import `internal/ca`), so
the two are coupled only by the string literal and must be renamed together.
Storage-layer and backend-internal locks live beside the code that takes them,
for the same import-direction reason: `lockNameHMACKey` (`"hmac-key"`) in
[storage.go](../../internal/storage/storage.go) and `etcdDecomposeLockName`
(`"inventory-decompose"`) in
[etcd_inventory.go](../../internal/storage/etcd_inventory.go), which
`redisDecomposeLockName` in
[redis_inventory.go](../../internal/storage/redis_inventory.go) deliberately
aliases — a deployment only ever has one backend, so the two can never
contend. They are no less protocol for it.

One name in `internal/storage` is not a lock in that sense at all:
`lockProbeName` in [storage.go](../../internal/storage/storage.go) defines
`capability-probe`, which `SupportsDistributedLocking` acquires and releases
purely to find out whether the backend coordinates across processes. It sits
outside every namespace above so it can never contend with an operation in
flight — see its row below.

| Lock name | Serialises | Taken by |
| --- | --- | --- |
| `bootstrap` | First-run CA generation; seeding supporting state (CRL/inventory/serial) for a mounted cert+key; whole-store migration | `CA.Init`, `CA.seedSupportingState`, `storage.MigrateService` (which reuses the name deliberately so a migration and a bootstrapping server exclude each other) |
| `crl` | Every CRL read-modify-write (read entries → re-sign → write), **and** the pending-supersession list's read-modify-write, which has to be mutual with the revocations it schedules | `Revoke`, `RevokeSerial`, `ReissueCRL`, `RefreshCRLIfDue`, `CleanupExpiredCerts`, `RefreshCRLChainFile` (the `crl_chain_file` job, on every replica on a timer), `ImportCA`, `ReconcileSuperseded`, the revoke step inside `Clean` and `GenerateWithOptions`, and the retire step inside `Renew`, `AutoRenew` — "retire" because only those two can defer it to the list; `Clean` and `GenerateWithOptions` always revoke inline |
| `subject:<name>` | The whole lifecycle of one subject: evict/save CSR/sign/delete CSR/renew/import/clean/revoke/generate | `SaveRequest`, `Sign`, `SignWithTTL`, `DeleteRequest`, `Renew`, `AutoRenew`, `Clean`, `ImportCertificate`, `Revoke`, `Generate`/`GenerateWithOptions` |
| `hmac-key` | Generating and persisting the inventory HMAC key when none is usable — a cold start, or a stored blob of the wrong length | `StorageService.EnsureHMACKey`, reached from `CA.Init` → `InitHMAC`, from `MigrateService` → `RebuildInventoryHMAC`, and from the offline `openvox-ca rebuild-inventory-hmac` → `RebuildInventoryHMAC` (only where it has to mint a key, i.e. a stored blob of the wrong length). Deliberately **not** `bootstrap`: the migration already holds that name across the rebuild, and `WithLock` is not reentrant |
| `sql-schema-migrate` | One schema-migration run, so two replicas starting at once do not migrate concurrently (SQL backends only) | `SQLBackend.EnsureReady` |
| `inventory-decompose` | One-time legacy inventory blob conversion (etcd and redis backends) on the first start after upgrading | `EtcdBackend.decomposeLegacyInventory` and `RedisBackend.decomposeLegacyInventory`, from `EnsureReady` |
| `capability-probe` | Nothing. Acquired and released immediately by `StorageService.SupportsDistributedLocking` to find out whether this backend coordinates locks across processes at all | The offline `openvox-ca generate` and `rebuild-inventory-hmac` pre-flights. The name sits deliberately outside every namespace above so a probe can never contend with an operation in flight |
| `store-instance` | The store as a whole, for as long as a process is running against it. Taken **outside `WithLock`**, through `StorageService.AcquireInstanceLock` → `InstanceLocker`, so it never reaches a cross-node lock and needs no ordinal: it applies only where `SupportsDistributedLocking` is false, and those backends have no SQL advisory lock to reach. Acquired without waiting, and refused with the holder's identity rather than a timeout | The server (the launcher, or a single-process server — never the signer or frontend children, which are inside an instance that already holds it), `openvox-ca-ctl setup`/`import`/`migrate`, and the offline `csr`/`generate`/`import-ca-cert`/`rebuild-inventory-hmac` (which takes it only on its `--yes-re-bless` path, never to report). Like `capability-probe` the name sits outside every namespace above, so the lock proving an instance is alone can never contend with that instance's own work |

How each backend provides the distributed lock (a summary — the full per-backend
mechanism, key layouts and transaction/retry detail lives in
[storage internals](storage-internals.md), which owns it):

| Backend | Mechanism | Crash recovery |
| --- | --- | --- |
| etcd | `concurrency.Mutex` under `<prefix>/locks/<name>` on a lease-backed session (30 s TTL) | Lease expires within the TTL, lock releases |
| Redis/Valkey | `SET NX PX` with a per-acquisition random token; a heartbeat goroutine extends the TTL while held; unlock is a Lua compare-token-and-delete | Key expires within the TTL, lock releases |
| PostgreSQL | `pg_advisory_lock` (session-level) on a dedicated pooled connection | Only when the server reaps the session — no TTL (see below) |
| MySQL/MariaDB | `GET_LOCK` on a dedicated connection, polled with a 1 s server-side wait so context cancellation is honoured | Only when the server reaps the session — no TTL (see below) |
| SQLite, filesystem | No cross-node lock — `ErrDistributedLockingUnsupported` / no `Locker`. Same-host only: an exclusive `flock(2)` per lock name, under `<cadir>/locks/` or a `.<db>.locks/` directory beside the SQLite file. These are also the backends the store-wide `store-instance` lock applies to, in the same directories, since they are the ones that support a single running instance | Kernel releases the lock when the descriptor closes or the holder dies — no stale lock, no TTL |
| Overlay | Delegates to the base backend's `Locker`, then to its `SameHostLocker`; reports unsupported when the base has neither | as base |

The same-host lock is the one entry in that table with nothing to recover.
`flock(2)` is held by an open file description, so the kernel drops it when the
descriptor closes or the process dies, however it dies — which is why it was
chosen over an `O_EXCL` lockfile, whose stale-lock cleanup and PID-liveness
guessing are the maintenance burden that makes lockfiles a poor fit for a
service operators restart and kill. Consequences worth knowing:

- **Lock files are never removed, and deleting one on a live store is
  unsafe** — not merely useless. Unlinking a file another process is blocked on
  lets a third create a fresh inode at that name and take a lock the blocked one
  is still waiting for, so both then believe they hold it. Empty 0600 files are
  the cheaper side of that trade. They can be swept while nothing is using the
  store; while anything is, sweeping them silently defeats the exclusion.
- **The directory grows with the fleet.** One file per distinct lock name means
  `bootstrap`, `crl` — and one per subject, since `subject:<name>` is a lock
  name. It is roughly an inode per node the CA has ever locked, it never
  shrinks (`Clean` retires a node's certificate, not its lock file), and it
  rides along in any `tar <cadir>/` backup.
- **The lock identity is the path, not the inode.** Two processes exclude each
  other only if they resolve the same lock directory. The path is made
  absolute, so differently spelled configuration for one store still agrees,
  but a *relative* `cadir` or `sql_dsn` resolved from two different working
  directories will not, and neither will one store reached through two
  different symlinks. Configure absolute paths.
- **A wait announces itself once.** The first refused attempt logs `Waiting for
  the CA lock`, naming the lock and the file. Without it an `openvox-ca-ctl
  migrate` — which inherits a context with no deadline — would print nothing and
  never return, and a lock wait would be indistinguishable from a hang.
- **A store nobody can write disables the tier; a lock path this process
  cannot write does not.** Three outcomes, and which one you get depends on the
  errno and the call site:
  - *Cannot create the lock directory* (`EROFS` or `EACCES`) — the capability
    reports itself absent and `WithLock` drops to the mutex. On both backends
    that directory sits where the store's own writes go, so failing to create it
    really does mean the store cannot be written, and a store with no writer has
    nothing to exclude. `openvox-ca-ctl migrate` takes `bootstrap` on a source it
    only reads, and that source may be a read-only snapshot.
  - *Cannot open a lock file in a directory that already exists*, with
    `EACCES` — a **hard error**. `os.MkdirAll` returns nil for an existing
    directory without checking writability, so this says nothing about the
    store: it means the lock directory or the lock file belongs to another user,
    typically because a `ctl` command was run under sudo against a cadir the
    server owns. Downgrading would silently return the server to its pre-#187
    behaviour for the rest of its life while the root process went on taking
    flocks it believed were exclusive — both sides think they are safe, which is
    worse than neither being. The error names whichever of the file and the
    directory is actually foreign, and its uid, because a sudo `ctl` leaves a
    root-owned *file* inside a server-owned directory as often as it creates the
    directory itself.
  - *`EROFS` at either site, a filesystem that rejects BSD locks*
    (`EOPNOTSUPP`, `ENOSYS`), or a kernel out of lock records (`ENOLCK`) —
    absent again, not fatal. `EROFS` says nothing about ownership, and a store
    nobody can lock is the runtime form of a platform without `flock(2)`;
    failing hard there would take down a CA that worked before this tier
    existed. The three are grouped by what they cost, not by what they mean:
    the first two are properties of the mount and the third is transient
    pressure, so read the errno in the log line rather than the message.

Crash recovery is not uniform across the distributed backends. etcd and Redis self-heal
within the lock TTL (30 s): a crashed holder's lease or key expires and the lock
frees itself, which is what the 60 s `lockTimeout` below is sized to ride out.
The SQL advisory locks have **no TTL** — `pg_advisory_lock` and `GET_LOCK`
persist until the database tears the holder's session down, and after a hard
host loss or network partition that is governed by the server's own keepalive
settings (PostgreSQL `tcp_keepalives_idle`, MySQL `wait_timeout`), whose
defaults are measured in hours. A crashed replica can therefore hold `crl` or
`subject:<name>` far beyond `lockTimeout` while every surviving replica's
revoke/sign fails at that timeout; the recovery action is to terminate the
orphaned backend session (`pg_terminate_backend` / `KILL`) or to lower those
server-side keepalives for HA deployments.

Every implementation of either capability first takes a **per-name
process-local mutex** before touching the network or the filesystem. This is
load-bearing, not an optimisation: etcd's `concurrency.Mutex` is not safe for
re-entry on one session, on the SQL backends it stops N in-process callers each
pinning a pooled connection just to queue on the same lock, and for the
same-host lock it keeps in-process contention a mutex wait rather than N
goroutines each running their own `flock` retry loop. It is also what preserves
the existing re-entrancy behaviour: `flock(2)` is per open file description, so
without the mutex a second acquisition in this same process would block in the
kernel rather than on the mutex it blocks on today.

CA request paths bound lock acquisition *and* the critical section together
with `lockTimeout` (60 s, [init.go](../../internal/ca/init.go)) via
`context.WithTimeout` — long enough to ride out a brief leader election, short
enough that a crashed replica's stale lease doesn't hang requests forever. Three
things that timeout does *not* cover. First, it bounds only the
*other-process* half: the process-local mutexes (both the fallback path and the
per-name gate in front of every distributed and same-host implementation) are
plain `sync.Mutex` and do not honour context cancellation, so same-process
waiters queue unboundedly. Second, the offline `openvox-ca-ctl migrate` path
applies no timeout at all — `MigrateService` inherits the caller's context,
which is signal-cancellable but carries no deadline — so a migration waits
indefinitely on a contended `bootstrap` lock; interrupt it and stop the server
rather than waiting. Since same-host locking landed that applies to the
filesystem and SQLite backends too, where the wait used to be no wait at all.

Third, and specific to the same-host tier: the deadline bounds *waiting* for
another process, not the acquisition itself. An **uncontended** same-host lock
is granted even to a caller whose deadline has already gone, matching the
process-local mutex it replaces — that caller then fails on its own first
storage read. The distinction is visible in metrics: `Revoke` counts a failure
that reached the CRL work and does not count one refused at lock acquisition
(see [metrics](../metrics.md)), so the single-node backends stay on the
"counted" side for a spent deadline exactly as they were. A *contended*
same-host acquisition that outlasts the deadline does fail at acquisition, and
so is not counted — the one place where the split moved.

### Tier 2: storage-service mutexes

`StorageService` guards each family of logical keys with its own process-local
mutex so a compound operation (read blob → transform → write blob) can't
interleave with another goroutine's within the process. Three are
`sync.RWMutex`; `serialMu` is a plain `sync.Mutex`, since the serial counter
has no read-only fast path:

| Mutex | Guards | Why compound |
| --- | --- | --- |
| `inventoryMu` | `inventory` + `inventory_hmac` | An append must scan for duplicate serials and advance the integrity head as one unit |
| `crlMu` | `crl` | Plain read/write pairs |
| `fileMu` | `ca_cert`, `ca_pubkey`, `ca_key`, `csr/<subject>`, `cert/<subject>`, per-subject private keys | One mutex spans all subjects; simple and sufficient at current scale |
| `serialMu` | `serial` | Plain read/write pairs |

One shared-state key is absent from this table for a reason worth stating:
`hmac_key` is guarded a tier *up*, not here. Its initialisation
(`EnsureHMACKey`) is a read-modify-write, and the replicas that can fork the key
are in different processes, so a process-local mutex would never have been the
answer — the generating path takes the Tier 1 `hmac-key` lock and reads the key
again after winning it. The read-only path — a key already present *and* of the
expected length, which is every start after the first — takes no lock at all; a
present-but-wrong-length blob regenerates, and so locks. That was
[#202](https://github.com/voxpupuli/openvox-ca/issues/202); how far the
guarantee reaches is `WithLock`'s tiers and nothing more, so see the known gaps
below for the one configuration where two processes can still fork it.

These are **internal to `StorageService`** — callers never touch them, and no
`StorageService` method calls another locked method while holding one (they are
non-reentrant; doing so self-deadlocks). Methods that require a caller-held
mutex generally carry the `...Locked` suffix and always say which lock in
their doc comment. The doc comment is authoritative — a couple of helpers
(`readInventoryForHMAC`, `computeInventoryHMAC`) require `inventoryMu`
without carrying the suffix.

### Tier 3: CA in-memory state (`c.mu`)

`ca.CA.mu` protects the fields that make the hot read paths fast:
`CACert`/`CAKey` (readiness), `serialIndex` (OCSP subject lookup), `ocspCache`
(pre-signed responses), and `cachedCRL` (revocation checks for authentication
without a storage round-trip).

Mutating operations hold `c.mu` (write) across the storage mutation *and* the
cache update, so within a process the caches can never be observed out of step
with what the same process just wrote. Read paths take `c.mu.RLock` only.

`DeleteRequest` is the one mutation that takes no `c.mu` at all: a pending CSR
backs none of these caches, so there is nothing to keep in step with the write.
That costs nothing in ordering: a rejection and a `Generate` for the same name
serialise on `subject:<name>`, which both take, in every process rather than
merely within one. `c.mu` was never what stood between them.

`c.mu` is held across the signing call itself **on the issuance paths**. Every
one of them (`Sign`, `SignWithTTL`, `SaveRequest`'s autosign, `Renew`,
`AutoRenew`, `ImportCertificate`, `Generate`) calls `issueLeafLocked` with
`c.mu` held, and `x509.CreateCertificate` runs inside it — so with an external
key provider (`ca_key_provider: openbao`, or the isolated signer) `c.mu`, not
the per-subject cluster lock, is the process-wide issuance serialiser, and it
spans a network/IPC round trip. Issuance therefore proceeds at roughly one
signing round trip at a time within a process, and a stalled signer backend
pins the mutex and stalls all issuance — see the "Performance and outage
behaviour" section of [the OpenBao Transit guide](../openbao-transit.md). This
is the one deliberate exception to rule 3 (keep expensive work outside the
lock): the signature is inside the lock because the cache update it guards must
be atomic with the issuance.

**The OCSP responder is not in that set, and the difference is worth stating
because it used to be.** `AnswerOCSP` reads what it needs under `c.mu.RLock` —
whether the serial is in `serialIndex`, the `cachedCRL` pointer, `CACert` and
`CAKey` — releases, and signs holding no CA lock at all; it re-takes the write
lock only to store the finished response, and only when there is one to store —
a nonced or `unknown` answer is never cached, so those take no write lock at
all. It can do this and issuance cannot because the two guard different
things. An issuance *mutates* storage, so its
cache update has to be atomic with the write. A response is *derived* from
state the responder only reads, so the equivalent obligation is weaker: not
"nothing may change while I sign", but "do not cache an answer that stopped
being true while I signed". `AnswerOCSP` discharges that by re-deciding the
status under the write lock and dropping the cache write if it moved — see
[#197](#known-gaps). A revocation landing mid-signature therefore costs a
re-sign on the next request, and the response it overtook is emitted with
`MaxAge` zero so no shared cache stores it.

What that does *not* undo is the `NextUpdate` already inside the signed
response: it says four hours, and it cannot be changed without re-signing. A
verifier that keeps the response for its stated validity may therefore hold a
`good` that was true when signed and is not now. That residue is not new — the
pre-#197 arrangement produced the identical artefact whenever a revocation sat
waiting on `c.mu` behind a response being signed — and the window is the
signature rather than the whole request. It is the reason the CRL, not OCSP
response lifetime, is what a revocation is ultimately enforced by.

`c.mu` is non-reentrant. The same `...Locked` suffix convention applies: e.g.
`revokeLocked` requires the cluster `crl` lock **and** `c.mu`; each `...Locked`
function's comment states exactly which locks its caller must hold.

`RevokeSerial` takes the `crl` lock and then `c.mu`, in that order. It does
**not** take a subject lock, which `Revoke` acquires outside both: a revocation
by serial has no subject to lock, the serial being the identifier precisely
because the name now resolves to a different certificate. It does take the `crl`
lock through `withCRLLockCounted`, as `Revoke` does, so a lock it cannot take
moves `crl_update_failures`. Its checks run inside the locks for the reason
rule 3 exists: the subject a serial belongs
to, and whether that subject's stored certificate still carries it, are what
justify the CRL write, so resolving either outside the lock would let the answer
go stale before the mutation. That puts an inventory read — on blob backends an
HMAC verification over the whole blob — inside the `crl` lock, which is why the
operation is documented as operator-initiated rather than something to call in a
loop.

## Lock ordering

Nested acquisition follows a fixed order. The request paths share one chain, and
there is a second, narrower nesting on the CA-import path:

```text
subject:<name>  →  crl  →  c.mu  →  (StorageService internal mutexes)
bootstrap       →  crl                    (ImportCACertificate only)
```

Both are one-way. `bootstrap` and `subject:<name>` are never held together at
all, so the two lines do not compose into a single chain — which is why they are
written as two.

- The pending-supersession list deliberately has **no lock name of its own**.
  Its read-modify-write must exclude the sweep that rewrites it — an append
  landing between the sweep's read and its write would be erased, leaving a
  superseded certificate valid with nothing recording that it should not be —
  and the per-subject lock cannot provide that, because two renewals for
  different subjects hold different subject locks. `crl` can, and reusing it
  costs nothing: the renewal path already took that lock to revoke, so nesting
  depth (and therefore the SQL pool floor below) is unchanged, and the sweep
  needs one acquisition to cover both the list rewrite and the revocations it
  drives. See [supersede.go](../../internal/ca/supersede.go).
- `Revoke`, `Clean`, `Renew`, `AutoRenew` and `GenerateWithOptions` (the last
  on its `ReplaceExisting` path only) are the paths that take all three. For
  the four issuance paths it is the subject lock around the whole operation,
  then the `crl` lock + `c.mu` for the revocation step; note they release and
  re-acquire `c.mu` between the signing and revocation steps — `c.mu` is not
  held across a `WithLock` acquisition. `Revoke` has the same nesting for a
  different reason: the `crl` lock + `c.mu` cover the revocation that is the
  whole operation, and the subject lock is there only to serialise it against
  an issuance already under way for that subject.
- No code path acquires `subject:<name>` while holding `crl`, and none acquires
  either while holding `c.mu`. Keep it that way; the comments in
  [signing.go](../../internal/ca/signing.go) and
  [revoke.go](../../internal/ca/revoke.go) record this invariant at each
  nesting site.
- Two *different* subject locks are never held at once (bulk operations like
  `SignMultiple` loop, taking one at a time).
- The **CA-key signing bound** (`signSlots`, see
  [signbound.go](../../internal/ca/signbound.go)) is not one of the three tiers
  and does not appear in the chain above, but it is acquired *inside* `c.mu` on
  the issuance and CRL paths and so belongs here. The one-way rule is
  `c.mu` → signing slot: a slot is never held while acquiring `c.mu`, and
  nothing acquires a second slot while holding one.

  That nesting is only safe because slot occupancy is bounded. The OCSP
  responder refuses rather than queues, so it cannot build a line an issuance
  under `c.mu` would have to join; and both acquisitions honour `ctx`, so a
  caller that has gone away stops waiting rather than holding `c.mu` on nobody's
  behalf. Let the OCSP path queue here, or drop the `ctx`, and an
  unauthenticated flood stalls every `c.mu` reader — the same process-wide stall
  [#197](https://github.com/voxpupuli/openvox-ca/issues/197) removed, reached
  by a different queue.
- `CA.Init` inverts the order (it holds `c.mu` while acquiring **two**
  distributed locks in turn: `hmac-key`, via `InitHMAC` → `EnsureHMACKey` on a
  cold start, and then `bootstrap`). They are sequential, never nested. The
  inversion itself is safe only because `Init` runs to completion before
  the server starts serving, so nothing else can be holding a distributed lock
  while waiting on `c.mu`; do not copy this pattern into anything that runs
  while serving. Init also *had* a separate hazard on the same lock — its slow
  path re-entered `bootstrap` and deadlocked startup
  ([#201](https://github.com/voxpupuli/openvox-ca/issues/201)). Fixed; the rule
  that produced it is not, because `WithLock` is still not reentrant at any
  tier. See known gaps.
- `bootstrap` → `hmac-key` is the first nesting in which a name owned by
  `StorageService` sits inside one owned by the CA layer, and the only one taken
  entirely within `internal/storage`. It is not the only nesting of two
  different `WithLock` names — `subject:<name>` → `crl` above is one, and so is
  `bootstrap` → `crl` on the import path — and it is deliberately **absent from
  `allowedLockNesting`** rather than missing from it: that table keys pairs by
  lock *name* and not by (store, name), so a path holding `bootstrap` over two
  different stores is outside its scope by construction. This prose is where the
  pair is recorded, and the table must not gain it. `MigrateService` holds
  `bootstrap` on the destination across `RebuildInventoryHMAC`, which reaches
  `EnsureHMACKey`; if the copied `hmac_key` is the wrong length, that takes
  `hmac-key` inside it. An *absent* key does not: `RebuildInventoryHMAC`
  short-circuits on an `Exists` check before it calls `EnsureHMACKey`, so
  corruption is the only route to this nesting.
  This order is one-way and must stay so — nothing may acquire `bootstrap` from
  inside an `hmac-key` critical section, and `WithLock` is not reentrant at any
  tier, so the two names must also never be made equal.
- `ImportCACertificate` holds `bootstrap` across the CRL rewrite inside
  `importCAMaterial`, so **`bootstrap` → `crl`** is a second permitted nesting
  ([caImport.go](../../internal/ca/caImport.go)). One-way, like the first:
  nothing takes `crl` and then `bootstrap`, and nothing may start. This matters
  more than an import-only path sounds like it should — the documented import
  procedure restarts replicas *after* the import, so the server is serving
  throughout, and a future path acquiring `crl` before `bootstrap` would
  deadlock against a live import rather than fail.
- This section has a machine-readable counterpart: `allowedLockNesting` in
  [lockorder_test.go](../../internal/ca/lockorder_test.go) lists the
  simultaneously-held pairs the CA layer is permitted to take, and a spec fails
  on any pair that is not there — an inverted one *and* a newly introduced one.
  Adding a nesting therefore means editing both, together. See the Tests
  section below for what that does and does not reach.
- `MigrateService` holds two `bootstrap` locks (source backend, then
  destination). Pointing both at the same store deadlocks on **every** backend
  now, not only the distributed ones: on filesystem and SQLite the two are
  separate backend values with separate per-name mutexes, so the second
  acquisition blocks on the `flock` and spins in its backoff loop — a live poll
  rather than a parked goroutine, which is what a stack dump will show. Since
  `MigrateService` applies no deadline it waits forever, announcing itself once.
  Migrating a store onto itself is unsupported.
  That is the behaviour of `MigrateService` called directly. `openvox-ca-ctl
  migrate` no longer reaches it: since #275 the command takes the store-wide
  instance lock on both ends first, so a store pointed at itself is refused
  immediately rather than deadlocking, and so is either end held by a running
  server.

## Read paths take no distributed locks — by design

Read-only operations must stay cheap and must keep working while another
replica holds a lock. The pattern:

- **Authentication revocation checks** (`IsRevokedSerial`) and **OCSP**
  (`AnswerOCSP`) answer from `cachedCRL`/`ocspCache`/`serialIndex` under
  `c.mu.RLock`. A *cacheable* miss — no nonce, and a definite status — is not
  wholly a read path: it ends by taking the write lock to re-check and store.
  It still takes its snapshot under the same `RLock` and signs outside it, so
  what it holds these readers off across is **a CRL scan plus a map write**,
  rather than a signer round trip. The scan is `decideOCSPStatus` re-deciding
  the status before the entry is stored — the check that makes the race guard
  sound — and it is linear in the number of revoked certificates, so it is the
  part of that window which grows with the CRL. Naming only the map write would
  understate it by leaving out the one term that scales. Go's `RWMutex` gives
  that waiting writer priority, so the store does briefly stall new `RLock`
  acquisitions.

  That window is not a cost #197 added: the pre-#197 code ran the same scan
  under the same exclusive lock, and a signature besides. What changed is that
  the signer round trip left it, which is the whole of the improvement — but
  the remaining window is a scan and a map write, not a map write. The
  guarantee is about the signature, not about never blocking.

  A nonced miss and an `unknown` are never cached, so they take no write lock at
  all — which matters, because the nonced request is the motivating case: it
  misses on every request.
- **HTTP GETs** (certificate, CRL, status listings) read straight through
  `StorageService` getters, which take only the relevant tier-2 read lock.
- `ReadInventory` verifies the integrity HMAC under `inventoryMu.RLock` but
  takes no cluster lock.

The costs of this choice are deliberate and documented:

- A replica's in-memory caches learn about other replicas' activity only when
  this process next writes them: `cachedCRL` staleness for authentication is
  [#171](https://github.com/voxpupuli/openvox-ca/issues/171) (being fixed by
  [PR #182](https://github.com/voxpupuli/openvox-ca/pull/182)'s background
  sync), and `serialIndex`/`ocspCache` staleness for OCSP was
  [#183](https://github.com/voxpupuli/openvox-ca/issues/183), now reconciled by
  `SyncSerialIndex` on `ocsp_index_sync_interval_sec` — see the entry below for
  the lock discipline that pass uses, which is not this section's.
- A read racing a mutation sees either the old or the new state, never a torn
  one — every backend's `Put` is atomic with respect to readers (see the
  `Backend` contract in [backend.go](../../internal/storage/backend.go)).

When you add a read-only endpoint or check, follow this pattern. Do not
"defensively" wrap a read in `WithLock`: it adds a cluster round-trip per
request, serialises hot paths behind slow mutations, and — on the fallback
path — still provides no cross-replica guarantee anyway.

## Rules for new or changed code

1. **Classify the operation first.** Pure read → tier-2/3 read locks only,
   never `WithLock`. Any read-modify-write of shared backend state → the
   narrowest applicable cluster lock (`subject:<name>` where the unit of
   contention is one subject; `crl` for the CRL; `bootstrap` only for
   whole-store lifecycle).
2. **Hold the lock across the whole decision, not just the write.** The
   check that justifies a mutation (duplicate cert? already revoked? CRL still
   fresh?) must run *inside* the same `WithLock` as the mutation, or it is a
   TOCTOU bug. `RefreshCRLIfDue` (check-then-re-sign under one lock) and
   `SaveRequest` (evict-then-save-then-autosign under one lock) are the
   patterns to copy. [#173](https://github.com/voxpupuli/openvox-ca/issues/173)
   / [PR #186](https://github.com/voxpupuli/openvox-ca/pull/186) exist because
   a renewal once did such a re-check outside the lock.
3. **Keep expensive, shared-state-free work outside the lock.** Key
   generation in `Generate` runs before any lock is taken (it no longer
   assembles a CSR at all — that round trip through the signing path was
   removed); parsing and validation in `Renew`/`SaveRequest` likewise. Only the
   storage-touching tail belongs inside. The deliberate exception is the CA
   signature *on the issuance paths*: `x509.CreateCertificate` runs under
   `c.mu` (see Tier 3), because the cache update it guards must be atomic with
   the issuance. The OCSP responder's signature is not an exception — it signs
   outside the lock and re-checks before caching, which is the shape to copy
   for anything else that signs from state it only reads.
4. **Respect the ordering** (`subject` → `crl` → `c.mu`, and `bootstrap` →
   `crl` on the CA-import path), never acquire the same lock reentrantly, and
   release `c.mu` before entering another `WithLock`. Use the
   closure-with-defer shape from `Renew`/`AutoRenew` so a
   panic can't wedge a mutex.
5. **Calling convention:** public CA methods take their own locks and say so
   ("The caller must NOT hold c.mu"); internal `...Locked` helpers document
   which locks the caller must already hold. Preserve both halves when
   refactoring, and never call a public locking method from inside a locked
   region.
6. **A distributed lock is a serialiser, not a guarantee.** All the
   implementations are lease/session-based with no fencing tokens: a process
   paused longer than the TTL (GC pause, VM freeze, network partition) can
   lose the lock while still inside `fn`, and Redis failover can hand the lock
   over early (see the note on `RedisBackend.AcquireLock`). Where corruption
   would be the consequence, back the lock with a storage-level invariant that
   holds even without it — and check the invariant's own scope.
   `AppendInventory`'s duplicate-serial check (`ErrDuplicateSerial`) is the
   worked example: it is a cluster-wide guarantee on the structured backends —
   SQL via the database's unique index, etcd via the `by-serial` key's
   `CreateRevision == 0` guard inside the append transaction, redis via the
   `by-serial` hash field the append script refuses to overwrite — but on the
   filesystem backend, the only remaining blob one, the scan runs under the
   process-local `inventoryMu` only (the doc comment on `ErrDuplicateSerial`
   in [storage.go](../../internal/storage/storage.go) spells this out, and
   the remaining gap is tracked as
   [#204](https://github.com/voxpupuli/openvox-ca/issues/204)).
7. **New lock names are protocol.** There are three homes, one per layer that
   takes a lock. Define CA-layer names as constants in
   [init.go](../../internal/ca/init.go) (keeping `migrateLockName` in
   [migrate.go](../../internal/storage/migrate.go) in sync — it redefines
   `"bootstrap"` independently); storage-layer names, taken through
   `StorageService.WithLock` by `StorageService` itself, as constants beside
   the code that takes them (e.g. `lockNameHMACKey` in
   [storage.go](../../internal/storage/storage.go)); and backend-internal
   names, taken directly via `Backend.AcquireLock`, as constants in the owning
   backend package (e.g. `etcdDecomposeLockName` in
   [etcd_inventory.go](../../internal/storage/etcd_inventory.go)); keep them
   all stable across releases, and document them in the table above. All
   callers using a name contend on one lock, so
   never derive a name from unvalidated input (subject names pass
   `ValidateSubject` first). **A new singleton name that can reach a SQL
   backend must also be reserved** in `reservedLockOrdinals` in
   [sql.go](../../internal/storage/sql.go), which is how those backends keep
   singleton locks out of the hashed key space — see rule 11. "Can reach a SQL
   backend" is the test, not "is a singleton": `inventory-decompose` is a
   singleton that only the etcd backend takes, so reserving it would claim a
   key nothing uses.

   For a name declared in `internal/storage` this is **enforced**, not just
   asked for: `SQLLockNameConstantsAreRegistered` walks the package source for
   lock-name constants and fails unless each is reserved or listed as
   deliberately exempt. A name declared in `internal/ca` is not reachable by
   that check — `internal/storage` cannot import `internal/ca` — so for those
   this rule is the only thing standing.
8. **SQL pool sizing:** on PostgreSQL/MySQL every *held* distributed lock pins
   one pooled connection. A single in-flight `Revoke`/`Clean`/`Renew`/`AutoRenew`
   needs at least three connections at once — one for the `subject:<name>` lock,
   a second for the nested `crl` lock, and a third for the reads/writes inside
   the revocation step — so `sql_max_open_conns` must be at least 3 per
   concurrently mutating request. `Revoke` joined that list when it took the
   subject lock: revoking many *distinct* subjects at once used to queue on the
   single `crl` gate and hold one lock connection between them, whereas each
   concurrent revocation now pins its own `subject:<name>` connection while it
   waits for `crl`. Set below that and a single request
   hard-stalls (not only under load), bounded only by the 60 s `lockTimeout`.
   See the `sql_max_open_conns` knob in
   [storage backends](../storage-backends.md).
9. **Offline `openvox-ca-ctl` commands** (import, migrate) assume the server
   is stopped. `MigrateService` holds `bootstrap` on both stores, which
   excludes a booting server but deliberately not per-subject signing. That
   exclusion is now genuinely cross-process on every backend — the same-host
   lock covers filesystem and SQLite, where the fallback mutex used to have no
   cross-process effect at all — but the scope is unchanged: a migration and a
   concurrent `Sign` still take different names and do not exclude each other,
   so stop the server. `MigrateService` also inherits the caller's context with
   no `lockTimeout`, so it waits indefinitely on a contended `bootstrap` lock
   (see Tier 1). Reaching that wait through `openvox-ca-ctl migrate` is no
   longer possible on a backend that supports a single running instance: the
   command takes the store-wide instance lock on both ends before any of this
   and is refused, by name, if a server holds either.
10. **A lock name is now also a filename.** On the single-node backends each
    name maps to `sha256(name).lock` in the store's lock directory. The mapping
    is protocol for the same reason the names are: a server and a `ctl` command
    exclude each other only by deriving the same file, so neither the hash nor
    the directory layout may change without a compatibility story. Hashing is
    also what keeps a name from addressing a path — nothing about a new lock
    name needs to be filesystem-safe.
11. **A lock name is also a hashed key on the SQL backends, so the key space is
    partitioned.** `pg_advisory_lock` takes a `bigint`, so a name has to be
    reduced to 64 bits and distinct names can in principle share one. That is
    tolerable between two subject locks — they cost each other contention — and
    was not tolerable between a subject lock and `crl` or `bootstrap`, where it
    is a repeatable denial of revocation
    ([#203](https://github.com/voxpupuli/openvox-ca/issues/203)). So
    `advisoryLockKey` splits the key space on bit 63 instead of hashing every
    name alike: a name in `reservedLockOrdinals` gets a namespaced base plus its
    hand-assigned ordinal, with bit 63 clear, and every other name gets the
    leading 64 bits of SHA-256 over the domain-separated name, with bit 63 set.
    Nothing a caller supplies crosses that line, so the aliasing is
    structurally impossible and `ValidateSubject` is no longer load-bearing
    for it. `mysqlLockName` partitions the same way,
    on a class tag in the `GET_LOCK` name (`openvox-ca:0:<name>` reserved,
    `openvox-ca:1:<128-bit hex>` derived); it has 64 characters to spend rather
    than 64 bits, so its derived form puts collisions between two derived names
    out of reach too.

    The base is namespaced rather than starting the ordinals at 1 because
    `pg_advisory_lock` keys are scoped to the *database*, not to the
    application: every client of that database shares one key space, and 1 and
    2 are exactly what a co-tenant's migration tool would pick. The old FNV-1a
    keys had that property by accident, being pseudorandom; the partition has
    to ask for it.

    The ordinals and the derivation are protocol, exactly as rule 10 says of
    the lock filename: replicas exclude one another only by deriving the same
    key. Never renumber or reuse an ordinal. Changing the derivation is a
    breaking change for a *running* cluster — during a rolling upgrade, nodes
    on either side of it derive different keys and do not exclude one another
    for the length of the rollout, so it needs a full restart rather than a
    rolling one.

12. **A new nesting is protocol too, not only a new name.** Rule 7 covers
    defining and documenting a lock *name*; this covers holding two of them at
    once. Any pair of **two different** named locks that the **CA layer** can
    hold simultaneously through `StorageService.WithLock` must appear both in
    the **Lock ordering** section above and in `allowedLockNesting` in
    [lockorder_test.go](../../internal/ca/lockorder_test.go), added together —
    a pair in only one is drift. **The obligation is unconditional; the
    automated detection is not.** A pair missing from the table fails that spec
    only when a spec drives the caller that takes it, and the specs drive a
    minority of the call sites (see "What the observer does not see" in the
    Tests section). Do not read a green suite as confirmation that you had
    nothing to add. The
    order within a pair is the protocol: one path taking it the other way is
    what deadlocks, and it deadlocks rather than timing out because the
    per-name gate ignores the context.

    The qualifiers are load-bearing, and each excludes a real pair the table
    deliberately does not carry. They are exclusions, not an inventory: pairs
    that *are* in scope go in the table whether or not a spec drives them —
    `bootstrap` → `crl` is listed on exactly that basis. **Two different**: `MigrateService` holds
    `bootstrap` over the source store and then over the destination, which the
    Lock ordering section documents and the table cannot express, because pairs
    are keyed by name and `("bootstrap", "bootstrap")` would read as a
    self-nesting it is not. **CA layer, through `WithLock`**: `bootstrap` →
    `sql-schema-migrate` is a live nesting reached from `MigrateService`, but
    `EnsureReady` takes that name through `Backend.AcquireLock`, so no
    `WithLock`-level observer can see it; it stays governed by rules 7 and 9.
    Do not add either pair to satisfy this rule — adding them would make the
    table claim coverage it does not have.

## Known gaps

Concurrency limitations that are understood and tracked. This list reflects the
state when the document was last updated and is not guaranteed exhaustive.

- ~~[#197](https://github.com/voxpupuli/openvox-ca/issues/197) — OCSP's slow
  path signs responses while holding `c.mu` exclusively, so nonced requests
  (which always miss the cache) serialise process-wide behind the signing
  round trip.~~ Fixed. `AnswerOCSP` now snapshots the decision inputs under
  `c.mu.RLock`, signs holding no CA lock, and re-takes the write lock only to
  store the result — and only when there is a result to store, since a nonced
  or `unknown` answer is never cached and so takes no write lock at all.
  Concurrent responses sign in parallel, and neither they nor the `c.mu.RLock`
  readers on the authentication path queue behind **the responder's** signer
  round trip.

  That qualifier is not decoration. **Issuance still holds `c.mu` exclusively
  across its signature** — deliberately, see Tier 3 — so an authentication-path
  `IsRevokedSerial` can still queue behind a signer round trip; it is just an
  issuance's rather than a responder's. Do not assume that wait is short:
  under `ca_key_provider: openbao` it is bounded by roughly *twice* the
  configured login timeout, not once — `openbao.Signer.Sign` records why, the
  403 path's `Reauth` taking a mutex that does not honour a context — and under
  the isolated signer `RemoteSigner.Sign` issues a `net/rpc` call carrying no
  deadline at all, so it is not bounded. An unnonced OCSP request can likewise
  block on `c.mu.Lock()` for its optional cache write while an issuance holds
  the lock. Anyone diagnosing a stalled authentication
  path should still look at the signer.

  **What the restructure had to add, and why anything else narrowing a lock
  around a cache needs the same.** Signing outside `c.mu` opens a window the
  serialised version did not have: a revocation can land between the status
  snapshot and the cache write. Storing unconditionally would put a pre-signed
  `good` back *after* `installCachedCRLLocked` evicted it, where it would be
  served for `OCSPValidity` — reintroducing, by a different door, exactly the
  staleness the #183 entry below closed. `AnswerOCSP` therefore re-decides the
  status under the write lock (`decideOCSPStatus`, the same function the response
  was built from) and skips the cache write if the answer moved, emitting the
  response with `MaxAge` zero so nothing downstream stores it either. Evicting
  locally while still handing a shared proxy a four-hour licence would only be
  half a guard — the same argument `AnswerOCSP` already makes about `unknown`.
  The response already signed is still returned, since an OCSP response is a
  statement about its `ThisUpdate`/`NextUpdate` window and the pre-fix code
  returned an equally stale one whenever a revocation was waiting behind the
  lock.

  The predicate is re-run rather than a generation counter compared. Both work;
  re-running settles the question a later reader of the cache actually has, and
  survives a third eviction path being added. `serialIndexEpoch` is the counter
  shape, and the #183 entry below says why the index sync has to use it —
  that path cannot re-check its own predicate, and this one can.

- ~~[#274](https://github.com/voxpupuli/openvox-ca/issues/274) — unbounded
  concurrent signing on `/ocsp`, opened by the #197 fix above. Recorded here
  because closing one gap opened another, and a known-gaps list that only
  records what was closed is misleading.~~ Fixed: `ca_signing_concurrency` caps
  concurrent CA-key signatures across all three signing paths together, since
  they share one key. The two halves behave differently under it, and that
  asymmetry is the fix rather than an implementation detail. Issuance and CRL
  re-signing **queue** for a slot; the OCSP responder **sheds**, answering RFC
  6960 `tryLater` after a bounded wait.

  Shedding on the public path is not a preference. Letting `/ocsp` queue would
  have converted unbounded signing into unbounded queueing — and worse, it
  would have reinstated the very stall #197 removed, by a different route:
  `issueLeafLocked` and `signCRLLocked` acquire their slot *while holding
  `c.mu`*, so an anonymous flood owning every slot would block a `c.mu` holder
  and stall every reader behind it, including the revocation check on the
  authentication path. Both acquisitions also honour `ctx`. Remove either
  property and the stall returns; the invariant is recorded under **Lock
  ordering** above.

  The default is `max(4, GOMAXPROCS)` and is a **safe ceiling, not a tuning** —
  its only job is to make the number finite. The reasoning below for why #197
  declined to pick one still holds: the right size is a property of the
  deployment's signer, so an operator with a remote signer is told to lower it
  to that signer's capacity, which openvox-ca cannot discover.

  The metric gap named below is closed with it: `puppetca_ca_signing_in_flight`,
  `puppetca_ca_signing_limit` and `puppetca_ca_signing_shed_total`.

  What that does **not** reach: the bound is per process, so N replicas permit
  N × the limit against one shared signer; it caps CA-key work and not the
  connections, handshakes and goroutines carrying the requests; and
  `RemoteSigner.Sign`'s new two-minute deadline bounds *the caller's wait, not
  the signer's work* — the RPC layer has no cancellation, so an abandoned call
  leaves the child still signing. That deadline is what lets a slot come back
  from a wedged signer, which is what makes the cap a limit rather than an
  outage; it does not reduce the load on the signer itself. The coalescing
  sub-bullet at the end of this entry is also still open.

  **The rest of this entry is retained as the reasoning, and is now history in
  two places**: "The missing half is a cap on concurrent signing … deliberately
  not attempted" describes what #197 left rather than what is missing today,
  and "No metric covers either of these" is no longer true of concurrent
  signing (it remains true of the raced cache write).

  Before #197, `c.mu` capped CA-key use at **one signature in flight
  process-wide**: every `CAKey.Sign` call site — `issueLeafLocked`,
  `signCRLLocked` and the OCSP responder — held it. Signing outside the lock
  removes that bound for OCSP, and nothing replaces it. `/ocsp` is
  unauthenticated by design (`tierPublic` in
  [auth.go](../../internal/api/auth.go)), the package's only rate limiter is
  CSR-only, and a cache *miss* signs — so an unauthenticated caller can drive
  as many concurrent CA-key signatures as it can open connections.

  **This relocates a denial of service rather than creating one.** The same
  flood previously stalled openvox-ca itself by queueing on the mutex, which is
  the bug #197 exists to fix. What is new is where it lands: against
  `ca_key_provider: openbao` or an isolated signer, N in-flight requests are N
  concurrent operations on the CA key with no aggregate cap, and that signer is
  shared with issuance and CRL re-signing. A mutex queue drains; a saturated
  signing backend serving other consumers does not, and it takes issuance down
  with it. `openbao.Signer.Sign` bounds each call — by roughly twice the login
  timeout, as the #197 entry above sets out — but nothing bounds how many run at
  once, and under the isolated signer `RemoteSigner.Sign` carries no per-call
  deadline either.

  The missing half is a cap on concurrent signing — a semaphore around the
  signature sized to the signer's capacity — which is deliberately not attempted
  in the #197 change: the right size is a property of the deployment's signer,
  so it is configuration and a design decision rather than a lock-scope fix. A
  rate limit in front of `/ocsp` would address the same exposure from the other
  end; extending the existing CSR limiter to that route was raised in review and
  declined for the same reason, since throttling a public revocation-status
  endpoint changes what verifiers see and is a decision in its own right.

  What #197 *did* take is the cheap half that needs no size: `AnswerOCSP` checks
  `ctx.Err()` immediately before signing, so a request whose client has already
  disconnected — or whose server deadline has expired — does not spend a signer
  round trip on an answer nobody can receive. That sheds load; it does not bound
  it, and it is not offered as a substitute.

  **No metric covers either of these.** The raced cache write logs, and nothing
  counts it; concurrent signing has no gauge at all. An operator cannot tell
  "this never happens" from "this happens throughout every CRL update", and the
  same is true of a caller saturating the signer. Raised in review and left out
  of #197 as scope — this repository ships a Prometheus mixin and adding series
  to it is its own change — but it belongs with whatever closes the gap above,
  because a bound nobody can observe being approached is only half an answer.

  Two smaller consequences of the same restructure, both deliberate:

  - **Concurrent misses for one serial no longer coalesce.** The pre-#197 code
    re-checked the cache after taking the write lock, so N goroutines racing on
    one uncached serial cost one signature and N-1 cache hits. They now cost N
    signatures. #197 sanctions this outright ("tolerating the benign race where
    two goroutines both sign the same serial and one result wins"), and the
    attacker case was never bounded by it since varying the serial is free. The
    case worth knowing is legitimate: the first burst after a restart, or after
    an eviction of a serial many verifiers poll, stampedes rather than
    coalescing. A `singleflight` around the signature would close it, at the
    cost of promoting `golang.org/x/sync` to a direct dependency.
  - **A signing failure is now a routine degradation path**, not a rarity, so it
    is reported as RFC 6960 `internalError` rather than `malformedRequest` —
    the latter tells a verifier not to retry and logs an outage as a client
    error.
- ~~[#201](https://github.com/voxpupuli/openvox-ca/issues/201) — `CA.Init`'s slow
  path can re-enter the `bootstrap` lock (via `finishLoadExisting` →
  `seedSupportingState`) and deadlock startup, because `WithLock` is not
  reentrant and its process-local gate ignores the context. Reachable when a
  replica loads a CA bootstrapped elsewhere but then finds the CRL absent.~~
  Fixed: the seeding is split into `seedSupportingStateLocked`, which does the
  work, and `seedSupportingState`, which acquires `bootstrap` around it.
  `finishLoadExisting` takes the variant to use from its caller, so the choice
  is made where the lock state is known — the fast path holds nothing and
  passes the acquiring one, the slow path is already inside the lock and passes
  the other. What is **not** fixed is the property underneath: `WithLock` is
  still not reentrant at any tier and its per-name gate is still a plain
  `sync.Mutex` that ignores the context, so a second acquisition on one
  goroutine still hangs rather than failing at the lock timeout. This closed one
  call site, not a mechanism.
  [initreentrancy_test.go](../../internal/ca/initreentrancy_test.go) pins both
  halves. The slow path is driven against a backend that refuses the first
  CA-certificate read, and the spec fails on a bounded wait for `Init` to
  return — neither of the two shapes the Tests section below describes, because
  a re-entrant acquisition never returns to be counted and waits on nobody else
  to be parked behind. The fast path is the before/after acquisition count that
  section does describe, and it is there because moving *both* call sites onto
  the `...Locked` variant would cure the hang and leave two replicas racing to
  seed — which the first spec alone cannot tell from a fix.
- ~~[#202](https://github.com/voxpupuli/openvox-ca/issues/202) — `hmac_key`
  initialisation (`EnsureHMACKey`, called by `InitHMAC` *before* the
  `bootstrap` lock) is an unlocked read-modify-write, so two replicas
  cold-starting against a fresh shared backend can generate divergent keys and
  one then fails inventory-HMAC verification.~~ Fixed: `EnsureHMACKey` now runs
  its generating path under the `hmac-key` lock and re-reads the key after
  winning it, so the replica that loses adopts the winner's key rather than
  writing over it. The re-read is the load-bearing half — a lock alone would
  only have ordered two overwrites. `InitHMAC` still runs *before* the
  `bootstrap` lock, deliberately: `InitHMAC` runs on every start, and the fast
  path immediately below it loads an already-bootstrapped CA *without* a
  distributed lock. Moving it inside `bootstrap` would make every replica's
  every start contend for that lock, and would enlarge the `bootstrap` critical
  section that
  [#201](https://github.com/voxpupuli/openvox-ca/issues/201)'s re-entrancy was
  found inside. That gap is fixed above; the contention argument stands on its
  own. A separate reason, and a separate claim, is why
  the new name is not *called* `bootstrap`: `MigrateService` reaches
  `EnsureHMACKey` from inside that lock and `WithLock` is not reentrant, so a
  shared name would turn a migration that met a corrupt key into a hang —
  #201's failure mode arrived at from the storage side. What is left open is
  the reach of the lock itself, which is exactly `WithLock`'s: cross-replica on
  etcd, Redis and the server SQL dialects; cross-process on filesystem and
  SQLite; process-local for an in-memory SQLite database or a platform without
  `flock(2)`. Read that last tier as single-*process*, not single-node: an
  in-memory database is private to its process, but two `openvox-ca` processes
  over one `cadir` on a platform with no `flock(2)` (Windows, AIX, Solaris,
  js/wasm) can still fork the key. That is the residue. Across hosts the
  question does not arise, since shared storage is unsupported for those
  backends for the reason `flock(2)` gives above.
- ~~[#203](https://github.com/voxpupuli/openvox-ca/issues/203) — on the SQL
  backends the distributed-lock identity is a 64-bit FNV-1a hash of the name,
  so distinct names can alias; a crafted subject that passes `ValidateSubject`
  could collide with the `crl`/`bootstrap` key and deny revocation.~~ Fixed:
  the key space is now partitioned so a hashed name and a reserved singleton
  can never share a key (rule 11). What that does *not* remove is aliasing
  *within* the hashed half — two subject locks still share a `pg_advisory_lock`
  key with probability 2^-63, which the `bigint` key makes a floor rather than
  a choice (the partition spends one of the 64 bits on the class tag). The
  cost of landing on it is contention between two subjects, not a stalled
  CRL, and finding such a pair deliberately is now a search against
  SHA-256 rather than against FNV-1a, whose invertible per-byte step made a
  chosen target reachable by meet-in-the-middle. MySQL has no such floor: its
  `GET_LOCK` name carries a 128-bit digest.
- ~~[#187](https://github.com/voxpupuli/openvox-ca/issues/187) — filesystem and
  SQLite backends have no same-host, cross-**process** locking.~~ Fixed: both
  now implement `SameHostLocker`, so every name taken through `WithLock`
  excludes another process on the host. What that does *not* reach is the
  inventory append, which is guarded by `inventoryMu` and no cluster lock: two
  processes issuing for **different** subjects hold different `subject:<name>`
  locks and can still interleave an `AppendInventory` and its HMAC rewrite.
  That is the blob-backend gap below, and closing it closes the filesystem case
  with it.
- ~~[#204](https://github.com/voxpupuli/openvox-ca/issues/204) — nothing wraps
  `AppendInventory` in a cluster lock, so on a blob backend its
  duplicate-serial check is not cross-writer and the whole-blob HMAC rewrite
  can cover a blob that never existed.~~ Fixed: #204's scope is the
  *distributed* blob backends, and both halves are closed by their decomposed
  inventories' atomic `by-serial` guards
  ([#138](https://github.com/voxpupuli/openvox-ca/issues/138) for etcd,
  [#139](https://github.com/voxpupuli/openvox-ca/issues/139) for Redis); the
  Redis half also removed the read-compute-write whole-blob HMAC update that
  made it a live CI flake rather than a theoretical gap. The filesystem backend
  still takes no cluster lock around the append — `SameHostLocker` excludes per
  lock *name*, and two processes issuing for different subjects hold different
  `subject:<name>` locks — but that is outside #204's scope and is not a
  tracked defect: two processes writing one filesystem store is an unsupported
  configuration. That is now **enforced** rather than merely stated:
  [#275](https://github.com/voxpupuli/openvox-ca/issues/275) added the
  store-wide `store-instance` lock, held for the life of the process, so a
  second instance is refused at startup and an `openvox-ca-ctl` or offline
  command run beside a live server is told which process holds the store. The
  enforcement is best-effort by design — `flock(2)` says nothing useful over
  NFS, and a process on another host cannot be excluded at all — so the rule,
  not the lock, remains the guarantee. See
  [storage backends](../storage-backends.md).
  The offline `generate` still reports both capabilities in its pre-flight, via
  `SupportsDistributedLocking`/`SupportsAtomicInventory`, and still tells the
  operator to stop the server: neither is made true by the same-host tier, and
  the inventory append above is why.
- [#171](https://github.com/voxpupuli/openvox-ca/issues/171) — `cachedCRL` is
  per-replica, so authentication and renewal keep accepting a certificate
  revoked elsewhere until this process re-signs the CRL.
  [PR #182](https://github.com/voxpupuli/openvox-ca/pull/182) fixes it with a
  background poll (monotonic in the CRL number, deliberately lock-free).
- ~~[#183](https://github.com/voxpupuli/openvox-ca/issues/183) — OCSP's
  `serialIndex` is built once at startup, so certificates issued on another
  replica answer `unknown`; the `ocspCache` half can even keep serving a
  pre-signed `good` for a certificate revoked elsewhere.~~ Fixed, in two
  halves. `CA.SyncSerialIndex` reconciles the index from the inventory on
  `ocsp_index_sync_interval_sec`, and every write of `c.cachedCRL` now goes
  through `installCachedCRLLocked`, which drops the cached responses the
  incoming CRL contradicts — previously only `SyncCRLCache` and
  `revokeSerialLocked` did, so whichever path installed a peer's revocation
  first decided whether a stale `good` survived.

  **The sync's lock discipline is a deliberate exception to tier 3.** The rule
  above is that a mutation holds `c.mu` across the storage access and the cache
  update together. `SyncSerialIndex` does not: it samples `serialIndexEpoch`
  under `RLock`, reads the inventory holding no `c.mu` at all, then takes the
  write lock to reconcile. Holding `c.mu` across a whole-inventory read would
  block every OCSP answer and every issuance on this replica for the duration,
  once per interval — the cost tier 3 exists to avoid. The epoch counter is
  what makes the gap safe: an issuance landing inside it moves the counter, and
  a pass that sees it moved applies its additions but stands its removals down,
  because it cannot then tell "pruned elsewhere" from "signed here, after I
  read". Additions are always safe, removals never are.

  The exception is bounded rather than free. The reconciliation still holds the
  write lock for O(n) map *reads* over the inventory, so a very large fleet
  pays a brief pause on the admission path once per interval; it writes only
  where storage and the index disagree, so the steady-state pass — the
  overwhelmingly common one — stores nothing. `SyncCRLCache` takes
  the same shape for the same reason and is ordered instead by CRL number.

  `InventoryEntries` exists for this path: `ReadInventory` verifies and then
  fetches, and its verification recomputes from storage, so every call
  materialises the whole inventory twice — on both backend families — and a job
  on a timer should not pay that. It fetches once and folds the integrity value
  over the rows it already holds.

  **It verifies on every backend**, which is where it parts company with
  `SubjectForSerial`. That method skips the check on `InventoryStore` backends
  because doing so "would cost a second full fetch of every row"; here it costs
  no fetch at all, so the reason to skip does not apply. The distinction matters
  for this caller in particular, because it drives *removals*: a row deleted out
  of band takes a serial out of the index, and an index miss downgrades the
  responder's answer for that serial from `revoked` to `unknown` before the CRL
  is consulted. Tampering has to fail closed here.
- ~~[#196](https://github.com/voxpupuli/openvox-ca/issues/196) —
  `DELETE /certificate_request/{subject}` deleted the CSR directly through
  `StorageService`, bypassing the subject lock.~~ Fixed: the handler now goes
  through `CA.DeleteRequest`, which takes `subject:<name>` for the delete, so a
  rejection orders against an in-flight sign instead of racing it. The HTTP
  layer also stopped reporting a failed deletion as `404`, which had told the
  operator the request was gone at the moment it was still queued; it answers
  `503` now.
- ~~[#173](https://github.com/voxpupuli/openvox-ca/issues/173) — renewal
  re-checked revocation before acquiring the subject lock.~~ Fixed: both
  renewal paths now call `refuseIfRevoked` again as the first statement inside
  the subject lock, and `Revoke` takes `subject:<name>` → `crl` so nothing can
  revoke in the gap between that answer and the issuance it guards. `Generate`
  takes `subject:<name>` as well, so a revocation orders against it like any
  other issuance. It remains the one issuance path with no `refuseIfRevoked`
  gate, and deliberately so: it issues *for* a subject rather than renewing a
  certificate someone presented, so a revoked certificate for that name is
  evicted and replaced rather than refused.
- On the filesystem backend, an inventory append and its HMAC update are two
  writes to two files (`inventory.txt` and `.inventory.hmac`). `Put` is already
  atomic per file — write to a temporary and `rename(2)` — but no POSIX
  primitive makes a *pair* of renames atomic, so a crash between them leaves the
  digest covering the previous state. This is a structural consequence of
  keeping the Puppet-compatible on-disk layout, not a defect awaiting a fix:
  one file would break that format, and reordering fails either way round —
  HMAC-first covers content that does not exist yet, inventory-first leaves a
  digest covering the previous state.
  `openvox-ca rebuild-inventory-hmac` is the mitigation, a supported way to
  rebuild the HMAC after the fact; it does not close the window. The
  structured inventory is the durable answer — SQL and etcd commit the entry and
  its integrity head in one transaction, redis in one Lua script. See
  [the inventory store](inventory-store.md).

## Tests

`WithLock`'s fallback semantics, its overlay/unsupported delegation, and its
unlock-error handling are covered in
[withlock_test.go](../../internal/storage/withlock_test.go); each distributed
implementation's mutual exclusion is exercised in its backend integration
suite (build-tagged; see [testing](testing.md)).

The same-host tier is covered in
[filelock_test.go](../../internal/storage/filelock_test.go), which runs in the
ordinary unit suite because it needs nothing but a temporary directory. Most of
it uses two backend values over one store, which is an exact substitution
rather than a convenient one — `flock(2)` is held by an open file description,
so two `os.OpenFile` calls exclude each other whether or not a fork separates
them. One spec does not settle for that: it re-executes the test binary (via a
`TestMain` guard in
[filelock_helper_test.go](../../internal/storage/filelock_helper_test.go)) so a
real second process holds the lock, and asserts both that this process is
refused and that the lock frees itself when that process is **SIGKILLed** — no
orderly release, so the kernel dropping the descriptor is the only thing that
can explain it. That is the property the whole flock-over-lockfile choice rests
on, and it is asserted rather than assumed.

The opposite property — that a lock is *not* held — is automated in
[ocsplockscope_test.go](../../internal/ca/ocsplockscope_test.go), which is what
rule 3 points at when it calls the OCSP responder "the shape to copy". It parks
a wrapped `crypto.Signer` inside `Sign` so a signature can be held open, and
splits into two pairs.

Two specs pin the **scope**: an unrelated `c.mu.RLock` reader
(`IsRevokedSerial`) must complete while a signature is parked, and two
responses must sign concurrently rather than queueing — asserted as a parked
peak of two. Both assert the other work finished *while* the signature was
still in flight, since an end-state assertion is equally satisfied by a late
unblock. Both were run against the pre-#197 arrangement and fail there.

Two more pin the **guard**, and they cannot fail against pre-#197 code because
there the racing operation simply waits for the lock, making the interleave
unreachable. One lands a revocation mid-signature; the other an index-sync
prune, which reaches `decideOCSPStatus`'s `!known` early return rather than the
CRL scan, and so resurrects an entry `dropSerialLocked` removed rather than one
a CRL install evicted. Each requires an operation needing the *write* lock to
complete while the signature is parked, which is what makes the claim "no CA
lock" rather than "no read lock". Their mutations are the guard itself, and
there are two: dropping the re-validation before the cache write, and
decoupling `MaxAge` from whether the response was actually cached. Each fails
both guard specs on its own assertion and leaves the two scope specs green.

That a given path takes its lock *at all* is automated for five of them, all in
the same shape: park the operation on a held `subject:<name>` and require it to
wait, since one that stopped taking the lock returns immediately instead.
[renewrace_test.go](../../internal/ca/renewrace_test.go) does this for `Revoke`,
`Clean`, `Renew` and `AutoRenew` alongside the ordering assertions described
below, and
[deleterequest_test.go](../../internal/ca/deleterequest_test.go) for
`DeleteRequest`. That last one also pins the far side — it parks a delete on
the inventory append inside an autosigning `SaveRequest`'s issuance, so it
observes the lock being held from that append until `SaveRequest` returns, not
across the evict/save prefix ahead of it. Dropping `SaveRequest`'s `WithLock`
still fails it, which is what makes `SaveRequest` pinned too.

`Sign` is pinned as well, but in a second shape rather than this one:
[lockorder_test.go](../../internal/ca/lockorder_test.go)'s rule-9 spec compares
the count of `subject:<name>` acquisitions before and after a `Sign`, so
dropping its `WithLock` fails on the delta rather than on a lock wait. The
`c.mu` spec's expected-acquisition total counts it too. `SignWithTTL` and
`ImportCertificate` are the ones now left with no spec at all: for those the
lock-name table above is the only record, and dropping the lock fails no
assertion. Either shape is worth copying when closing one of the gaps above —
park-on-a-held-lock proves the operation *waits*, a before/after count proves it
*acquires*, and the second is much cheaper when the operation is not otherwise
concurrent.

The nested lock-ordering invariant *is* now automated, in
[renewrace_test.go](../../internal/ca/renewrace_test.go): for each caller that
holds both locks — `Revoke`, `Clean`, `Renew`, `AutoRenew` — it parks the
operation on a held subject lock and requires `crl` to still be grantable while
it waits. An inverted nesting therefore fails on an assertion rather than
deadlocking the suite to its timeout, which is how an inversion otherwise
presents: every backend serialises same-process callers on a mutex that ignores
the context deadline. These run under the race detector on every unit
run: `mage test:unit` passes `-race` over every unit package, `internal/ca`
included. Of the backend suites, `backendsEtcd`, `backendsPostgres`,
`backendsMySQL` and `backendsRedisGo` run under it too.

That is only the suites this document cares about. For the exhaustive list of
every `go test` the repository invokes and whether each is raced — including the
two outside storage locking — see
[testing](testing.md#which-suites-run-under--race); enumerating it in two places
is how the two came to disagree before.

That per-caller coverage is not the whole graph, and cannot be: it is a
hand-maintained list of callers — three `Entry` lines plus the standalone
`Revoke` spec beside them — so a further caller that nests two locks, or a
first caller that nests two *different* names, is protected by nothing until
somebody extends it.
[lockorder_test.go](../../internal/ca/lockorder_test.go) covers the graph
itself instead. It wraps the backend in an observer that records every
`(outer, inner)` pair the CA layer actually takes through
`StorageService.WithLock`, and asserts the observed set against
`allowedLockNesting` — the machine-readable form of the **Lock ordering**
section above. An inversion fails because the reversed pair is absent from that
table; a **new** nesting fails because the new pair is absent too, which is
deliberate. A new pair of simultaneously-held lock names is protocol in the same
sense rule 7 makes a new lock *name* protocol — rule 7 governs names, not pairs,
so the pair obligation is its own rule ("A new nesting is protocol too") in
**Rules for new or changed code** above — and it should cost a line in
`allowedLockNesting` and a line in the **Lock ordering** section above, added
together. The failure message names the offending pair.

Three things that file pins which nothing else does:

- **Rule 4's "release `c.mu` before entering another `WithLock`".** `c.mu` is
  unexported, so no spec outside `internal/ca` can probe it, and the per-caller
  table checks only that the *CRL* lock stays grantable. The observer instead
  tries `c.mu` at each acquisition and records a violation if it is held.
  `CA.Init` is excluded explicitly rather than by accident — it holds `c.mu`
  while taking `bootstrap`, which this document sanctions above — so the probe
  is armed after `Init` returns.
- **Completion under concurrency.** Competing issuance, renewal, revocation and
  clean paths run at once against a bounded context and must all finish, with
  two of them racing for one subject through different callers — the only shape
  that can close an ordering cycle, since goroutines on disjoint subjects
  serialise instead of deadlocking whatever order they take. Be clear which
  assertion is the detector: the **edge table** catches an inversion
  deterministically and in a fraction of a second, and the timeout is a *bound*
  that keeps an interleaving which does reach a real cycle legible rather than
  hanging the suite, because the per-name gate ignores the deadline.
- **Rule 9's documented *non*-edge.** A migration holding `bootstrap` must not
  exclude per-subject signing — that is precisely why operators are told to
  stop the server rather than rely on the lock. A well-meant widening of the
  migration lock would look like a safety improvement while converting a
  documented "stop the server" into a silent stall bounded only by
  `lockTimeout`.

What the observer does **not** see, stated because a check that never reaches a
class of acquisition reports a clean graph exactly as a check that reached it
would:

- **Tiers 2 and 3.** They are not named locks, so no backend wrapper can observe
  them; the tail of the order (`… → c.mu → internal mutexes`) is covered by the
  `c.mu` probe above rather than by the edge table.
- **Any caller the specs do not drive.** The observer is passive — it records
  what the operations a spec calls actually do, so it sees a minority of the
  `WithLock` call sites in `internal/ca`, and an inversion in one it does not
  reach would fail nothing. The driven and untouched sets are listed once, in
  [lockorder_test.go](../../internal/ca/lockorder_test.go)'s top-of-file comment,
  and deliberately not restated here — the same reason the `-race` roster lives
  only in [testing](testing.md#which-suites-run-under--race): a list kept in two
  places is a list that will disagree with itself. To check the ratio at any
  commit, count
  `c.Storage.WithLock` in non-test `internal/ca` plus the sites in
  [caImport.go](../../internal/ca/caImport.go) that lock through a passed-in
  store — deliberately a rule rather than a number, because which operations take
  which locks is under active change and a literal here would go stale in a merge
  that conflicts with nothing and fails no spec. What the edge table removes is
  the hand-maintained list of *pairs*, not the list of callers: driving one more
  operation checks every pair that operation takes.
- **Names taken outside `WithLock`.** `sql-schema-migrate`
  ([sql.go](../../internal/storage/sql.go)) and `inventory-decompose`
  ([etcd_inventory.go](../../internal/storage/etcd_inventory.go)) are acquired
  through `Backend.AcquireLock` directly, so a `WithLock`-level observer cannot
  see them at all.
- **`MigrateService`.** It nests the *same* name over two different stores
  (`bootstrap` source, then destination), and pairs are keyed by lock name
  rather than by store, so driving it would record a self-nesting that is not
  one. Out of scope here rather than misrepresented; rule 9's operator-visible
  half is pinned by the spec above.

`GenerateWithOptions` is a fifth holder of both locks, on its `ReplaceExisting`
path. Neither mechanism above reaches it: it is not in the per-caller fixture,
and the edge observer does not drive it either — that spec's setup calls
`Generate`, which takes `subject:<name>` alone and so records no pair. It is a
worked instance of the "any caller the specs do not drive" bullet above, and its
`subject:<name>` → `crl` pair is already sanctioned by `allowedLockNesting`, so
nothing there fails; the pair is simply never observed. Two things are pinned
for it separately, in
[generate_test.go](../../internal/ca/generate_test.go):

- **The subject → CRL ordering**, asserted directly rather than raced, for the
  same reason `renewrace_test.go` parks rather than races: nothing forces the
  hazardous interleaving reliably.
- **The cross-replica outcome** — two `CA` values over one `StorageService`-shared
  backend that implements `Locker`, racing the same subject, exactly one
  certificate. This is the outcome the per-subject lock exists for, as opposed
  to the per-backend mechanism the integration suites cover. Note what the
  fixture has to do to be a test at all: the two callers rendezvous at the
  existence check, because an unsynchronised race is decided by whichever
  goroutine writes first and detects a missing lock only by luck. Its doc
  comment records the measurements.
