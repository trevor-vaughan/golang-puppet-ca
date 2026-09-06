# Decomposing the inventory: the `InventoryStore` capability

## Background

Historically the certificate inventory is a single append-only text blob, the
Puppet-style `inventory.txt`, with one line per issued certificate:

```
SERIAL NOT_BEFORE NOT_AFTER /SUBJECT
```

It is addressed by the logical key `inventory` and manipulated through a handful
of `StorageService` methods (`AppendInventory`, `ReadInventory`,
`TouchInventory`, `HasInventory`). Integrity is provided by an HMAC-SHA256 over
the **entire blob**, stored under `inventory_hmac` and keyed by `hmac_key`
(see [storage-backends.md](../storage-backends.md)).

Despite being a blob, the inventory is only ever used four ways:

1. **Append one entry** when a certificate is signed.
2. **Find the latest serial for a subject** during revocation — a full scan.
3. **Build a serial → subject index** at startup for OCSP — a full scan, then
   held in memory and updated incrementally on each signing.
4. **Find the subject holding a given serial** during a by-serial revocation
   (`StorageService.SubjectForSerial`) — a full scan on **every** backend,
   including `InventoryStore` ones. The unique index on `serial` cannot serve
   it: that index is an exact match over the stored text, while this lookup
   matches on the normalised value, because an inventory written by an older
   version — or migrated from Puppet Server — carries zero-padded sequential
   serials. An indexed exact match would miss exactly the historical
   certificates most likely to need retiring. A canonical-first fast path with
   fallback to the scan would be sound and is noted as future work in
   `SubjectForSerial`'s own comment.

The inventory is never served over the API; the `inventory.txt` text format is
an internal and on-disk-compatibility concern only.

### Costs of the blob model

- Every append re-hashes the whole inventory (O(n) per append) and every
  verifying read re-verifies it — not every read, as the threat model below
  sets out. Fine while inventories are small; wasteful as they grow.
- Lookups (revocation) scan the whole blob. Implementing `InventoryStore` for a
  backend fixes uses 1–3 but not use 4: the by-serial lookup stays a scan there
  too, for the normalisation reason above.
- A SQL backend stores the entire history as one ever-growing row.

## Goal

Let backends that can do better store the inventory as **structured records**
(e.g. a SQL table, one etcd key per entry, one Redis hash field per entry)
while preserving exact behaviour for backends that keep the blob (filesystem).
This is opt-in per backend.

## Design

### Optional capability interface

Following the existing `Locker` pattern — an optional interface probed by
`StorageService` via a type assertion, with a clean fallback — we add:

```go
// InventoryEntry is one issued-certificate record. NotBefore/NotAfter are
// stored verbatim as the formatted strings the signing path produces, so that
// rendering rows back to inventory.txt is byte-identical to the legacy blob.
type InventoryEntry struct {
    Serial    string
    NotBefore string
    NotAfter  string
    Subject   string
}

// InventoryStore is an optional Backend capability for structured inventory
// storage. Backends that implement it let StorageService skip the
// render → scan → reparse round-trip. Backends that do not implement it keep
// using the KeyInventory blob via AppendLine/Get.
type InventoryStore interface {
    // AppendEntry inserts rec and advances the integrity head atomically.
    // newHead computes the chained head MAC from the previous head (nil when
    // the inventory is empty); the backend MUST invoke it inside the same
    // transaction/lock that serialises appends so the chain cannot fork under
    // concurrent appenders. rec is a CertRecord (see "The certificate index"
    // below); only its canonical InventoryEntry fields feed the chain.
    AppendEntry(ctx context.Context, rec CertRecord, newHead func(prev []byte) []byte) error

    // Entries returns every entry in issuance order, for the OCSP index build
    // and for chain verification.
    Entries(ctx context.Context) ([]InventoryEntry, error)

    // LatestSerialForSubject returns the most recently issued serial for
    // subject, wrapping fs.ErrNotExist when the subject has no entry.
    LatestSerialForSubject(ctx context.Context, subject string) (string, error)

    // PruneEntries removes every entry for which keep returns false and
    // rewrites the integrity head over the survivors; advanceHead advances
    // the chain by one entry (nil disables integrity). Entries and head must
    // never be observable out of sync, but a prune may commit in several
    // transactions, be bounded per call, and partially complete — whatever
    // happens, the returned slice contains every entry actually removed,
    // even alongside an error. See backend.go for the full contract.
    PruneEntries(ctx context.Context, keep func(InventoryEntry) bool, advanceHead func(prev []byte, e InventoryEntry) []byte) ([]InventoryEntry, error)
}
```

`StorageService` probes `backend.(InventoryStore)`:

- **`AppendInventory`** → structured: build the `newHead` closure and call
  `AppendEntry`; blob: today's `AppendLine` + whole-blob HMAC recompute.
- **`LatestSerialForSubject`** (new) → structured: backend query; blob: scan the
  bytes from `ReadInventory` (the logic moved out of `ca.findSerialForSubject`).
- **`computeInventoryHMAC`** → structured: fold the chain over `Entries`; blob:
  HMAC over the blob bytes (unchanged).
- **`ReadInventory` / `TouchInventory` / `HasInventory`** keep using the blob
  path; for structured backends they are served by the render/parse shim
  (below), which keeps migration and the OCSP index build working unchanged.

### Integrity: a hash chain

Re-hashing the whole inventory on every append defeats the point of moving to a
table, so structured backends use a **hash chain** instead of a blob HMAC:

```
mac_i = HMAC-SHA256(key, mac_{i-1} ‖ canonical(entry_i))      mac_{-1} = ∅
head  = mac_n
```

- `canonical(entry)` is the exact `SERIAL NB NA /SUBJECT\n` line the signing
  path already writes, so the chain is trivially reproducible and independent of
  any backend's row encoding.
- The **head** (`mac_n`) is stored under the existing `inventory_hmac` blob row
  — no new logical key, and `VerifyInventoryHMAC`/`UpdateInventoryHMAC` keep
  their shape. The key still lives in `StorageService` (`s.hmacKey`); the
  `newHead` closure captures it, so no key handling leaks into backends.
- **Append is O(1)**: read the current head, hash one entry onto it, store the
  new head — all inside the backend's append transaction so the chain cannot
  fork across replicas.
- **Verification** is an O(n) fold over all rows at startup (same cost profile
  as the existing OCSP index build), compared against the stored head; a
  mismatch returns `ErrInventoryTampered`, exactly as today.

This detects modification, insertion, deletion, and truncation of the entry set
— the same tamper-evidence guarantee the blob HMAC provides, with the same
locally-held key threat model.

### Migration

`Migrate` copies blobs opaquely via `Backend.Get`/`Put` keyed by logical key. To
keep filesystem ⇄ SQL migrations working without teaching the migrator about
inventory internals, a structured backend serves the `inventory` logical key
through a **render/parse shim**:

- `Get(KeyInventory)` renders the rows back to byte-identical `inventory.txt`.
- `Put(KeyInventory, data)` parses the text and replaces the table contents
  (also covers the empty `Put` from `TouchInventory`).
- `Exists(KeyInventory)` reports whether the inventory has been seeded.

A chain head is **not** byte-portable across a backend-type change (a filesystem
blob HMAC ≠ a chain head over the same entries). So after the copy,
`MigrateService` — which holds both `StorageService`s and the destination key —
recomputes the destination's integrity head from its entries
(`RebuildInventoryHMAC`). This resolves the otherwise-spurious
`ErrInventoryTampered` that copying a foreign `inventory_hmac` would cause.

### The certificate index (`CertIndex`)

The inventory table doubles as a **certificate index**: alongside the four
canonical columns, each row carries a denormalised display projection
(`fingerprint_sha256`, `dns_alt_names`, `auth_extensions`, filled at signing or
import — see `issueLeafLocked` and `ImportCertificate`)
and the one mutable fact, revocation (`state`, `revoked_at`). Backends owning
the rows may advertise a second optional capability:

```go
type CertIndex interface {
    // One record per subject with a stored certificate (latest issuance),
    // optionally filtered by state ("signed"/"revoked").
    Statuses(ctx context.Context, stateFilter string) ([]CertRecord, error)
    SetRevoked(ctx context.Context, serial string, at time.Time) error
    ClearRevoked(ctx context.Context, serial string) error
    SetProjection(ctx context.Context, serial string, proj CertProjection) error
}
```

As with `InventoryStore`, the `StorageService` wrapper and the capability use
different names — the wrapper's are qualified because they sit beside the blob
methods, the interface's are not because the receiver already says `CertIndex`:

- `CertStatuses` → structured: `Statuses`; blob: falls back to the list-and-parse
  scan
- `MarkCertRevoked` → structured: `SetRevoked`; blob: no-op, since revocation
  there is read from the CRL at display time
- `ClearCertRevoked` → structured: `ClearRevoked`; blob: no-op
- `SetCertProjection` → structured: `SetProjection`; blob: no-op
- `AppendInventoryRecord` → structured: `AppendEntry` with the projection; blob:
  `AppendInventory`, projection ignored

`GET /certificate_statuses` probes it (via `StorageService.CertStatuses`,
mirroring `asInventoryStore`) and collapses from an O(N) *list-certs →
read-PEM → parse → CRL-check* scan to indexed queries; blob backends keep the
scan path verbatim. Pending CSRs are not issued certificates and stay on the
`csr/` list-and-parse path.

Design rules that keep the index honest:

- **The PEM and the signed CRL stay authoritative.** The projection columns
  are immutable copies of fields fixed at signing (so they cannot drift); the
  revocation columns are written by the revoke path right after the CRL is
  re-signed. Every column is rebuildable from the artefacts.
- **The hash chain covers only the canonical columns.** Chaining the
  projection would add nothing: each projected field is independently
  verifiable against a signed artefact.
- **Blob-imported rows carry no projection** (`fingerprint_sha256` NULL). The
  CA runs an index repair pass at startup (`rebuildCertIndex`) that backfills
  projections from the stored PEMs and reconciles `state` against the CRL —
  this is what makes a `storage migrate` from a blob backend converge. Until
  repair runs, the statuses handler falls back to the PEM per projection-less
  record.
- **Statuses is gated on blob existence.** Historical rows survive cleaning
  (that is the inventory's job), so the index reports only subjects whose
  `cert/<subject>` blob still exists, and only their latest issuance —
  matching what the scan path would have listed.

### The etcd decomposition

The etcd backend implements both capabilities too (issue #138), with a key
layout that plays to etcd's strengths — a sorted keyspace and multi-key
compare-then-op transactions:

```text
<prefix>/inventory/entries/<seq>       one JSON CertRecord per issuance;
                                       <seq> is zero-padded so a range scan
                                       returns issuance order
<prefix>/inventory/seq                 last allocated sequence number; doubles
                                       as the mutation fence (below)
<prefix>/inventory/by-serial/<serial>  serial → seq; existence is the atomic
                                       duplicate-serial guard
<prefix>/inventory/by-subject/<subj>   subject → latest serial (O(1) lookup)
<prefix>/inventory/data                presence marker for the KeyInventory
                                       logical key (empty payload)
<prefix>/inventory/hmac                chain head, unchanged logical key
```

Rules that keep the decomposed structure coherent:

- **One fence, guarded everywhere.** etcd transactions cannot read-compute-
  write, so `chainInventoryMAC` runs in Go between a read and a guarded
  commit. Every mutating transaction — append, prune batch, import batch —
  both *guards on* and *re-puts* `inventory/seq`, so any interleaved writer
  (same or another replica) invalidates the guard and forces a re-read. This
  is the same optimistic ModRevision-retry shape the blob append already used.
- **Appends are O(1)** — six puts guarded on the fence plus
  `CreateRevision(by-serial/<serial>) == 0`, which makes duplicate-serial
  rejection atomic cluster-wide (previously a SQL-only guarantee).
- **Bulk rewrites are batched; prune commits are individually consistent.**
  Prunes and imports larger than one transaction (bounded well under etcd's
  default `--max-txn-ops` of 128) are split into batches. Each *prune* batch
  writes a head covering exactly the entries that remain after it, so a
  concurrent verifier never sees entries and head out of sync and a crash
  mid-prune leaves a valid, partially-pruned inventory rather than a spurious
  tamper alarm. *Import* batches carry no head at all — the head is left for
  `RebuildInventoryHMAC` (migration) or dropped in the final commit (legacy
  conversion) — which is exactly why the legacy blob stays authoritative
  until the import's final commit and why the marker-guard/resume machinery
  exists. Because a batched prune can partially complete, `PruneEntries`
  returns every entry actually removed — accumulated across batches and
  retries, even alongside an error — so `CleanupExpiredCerts` can always
  finish the CRL and blob cleanup for what was deleted (see the contract in
  `backend.go`). Prune batches run newest-first, which keeps the intermediate
  heads cheap (each is a cached prefix fold over the untouched older entries
  resumed across the survivor tail), and one call removes at most a bounded
  number of batches so a huge backlog cannot blow the caller's lock budget —
  deferred matches stay present and consistent for later runs.
- **Legacy blobs are decomposed in place.** `EnsureReady` detects a non-empty
  pre-decomposition `inventory/data` blob, takes a distributed lock
  (`inventory-decompose`), verifies the blob against its stored whole-blob
  HMAC (the key is a backend blob, so it is available), imports the lines
  into entry keys, and empties the marker only in the final commit.
  Verification is fail-closed: a mismatch — or a stored HMAC that cannot be
  verified because the key is missing or malformed — fails startup with
  `ErrInventoryTampered`, exactly as the pre-decomposition code would have;
  the operator acknowledges a lost baseline by deleting the stored
  `inventory/hmac` key. The verified HMAC is deleted in the same import — it
  is not a chain head, so it cannot carry over — and the next verification
  re-baselines from the imported entries; only the import window itself is
  uncovered. A CA upgraded while its inventory is *empty* has no import to
  drop the head as part of, so `EnsureReady` handles that case separately:
  when zero entries exist and the stored head verifies as the whole-blob MAC
  of an empty inventory, it is deleted so the first verification re-baselines
  cleanly (any other head over zero entries is left for verification to
  flag). Because the blob stays authoritative until the import's final
  commit, an interrupted import is detected on the next start (the partial
  entries are the import-written prefix of the blob) and redone from the
  intact blob; entries that are *not* such a prefix mean a mixed-version
  cluster wrote both forms, which is refused with an explicit error rather
  than guessed at. Duplicate serials in the legacy blob — possible, since
  blob backends never had a cluster-wide uniqueness guarantee — are imported
  verbatim with a warning; their by-serial keys carry an ambiguity sentinel
  that keeps the serial reserved against reissue but makes certificate-index
  writes for it explicit no-ops, since a one-to-one index cannot say which
  bearer such a write is meant for. `Statuses` reports those records with
  `CertStateUnknown` — driven by the sentinel itself, not a live duplicate
  count — the statuses handler derives their real state from the signed CRL,
  and the startup repair pass skips them (they can never converge). The
  sentinel outlives partial prunes: a prune releases a by-serial key only
  when the last record bearing that serial is removed, so a lone surviving
  bearer stays reserved and unknown until the serial is fully released. All
  replicas must still upgrade together:
  an old-version writer appending to the blob mid-import is detected via the
  marker guard and the import restarts, but the race only closes once the old
  writers are gone.
- **Certificate-index writes stay off the chain.** `SetRevoked` /
  `ClearRevoked` / `SetProjection` rewrite a single entry key guarded on its
  own ModRevision (the mutable fields are not chain input), so index repair
  cannot fork the integrity head.

### The Redis decomposition

The Redis/Valkey backend implements both capabilities too (issue #139), with a
layout that mirrors etcd's but plays to a different strength — Lua scripts that
execute atomically:

```text
<prefix>:inventory:entries     HASH seq → JSON CertRecord, one field per
                               issuance
<prefix>:inventory:seq         last allocated sequence number, allocated by
                               INCR and doubling as the mutation fence
<prefix>:inventory:by-serial   HASH serial → seq; the field the append script
                               refuses to overwrite is the duplicate-serial
                               guard
<prefix>:inventory:by-subject  HASH subject → latest serial (O(1) lookup)
<prefix>:inventory:data        presence marker for the KeyInventory logical
                               key (empty payload)
<prefix>:inventory:hmac        chain head, unchanged logical key
```

Rules that keep the decomposed structure coherent:

- **Every mutation is one script, and a script is atomic.** Nothing else runs
  on the server while it does, so unlike etcd — which can only compare-then-op,
  and so needs individually-consistent batches — an append, a prune, or an
  import batch either happens whole or not at all. There is no window in which
  entries and head are out of sync, and no partial-completion case for callers
  to handle.
- **The one thing the server cannot do is the chain.** `chainInventoryMAC` is
  HMAC-SHA256 and the Lua sandbox has no HMAC primitive (only
  `redis.sha1hex`), so the new head is computed in Go from the head that was
  read and both are handed to the script, which aborts if the stored head has
  moved. Note the HMAC key is itself a backend blob
  (`<prefix>:private:hmac_key`), so it shares the instance with the entries it
  covers: the chain detects accidental corruption, a lost or reordered write
  and a racing writer, not an attacker who owns the Redis instance. That
  optimistic check is the only reason anything here retries. With integrity
  disabled there is no head and no check, so the sequence counter — which an
  append advances and a prune only reads — is the fence that catches an
  interleaved append instead.
  Both are checked: without the fence, a prune could repoint a subject's index
  at a serial its own stale snapshot chose, silently undoing a newer issuance.
- **Appends are O(1)** — a handful of hash writes, where the blob path read and
  rewrote the entire inventory per certificate issued. The by-serial field the
  script refuses to overwrite makes duplicate-serial rejection atomic
  cluster-wide, and writing the entry and the head in the same script closes
  the Redis half of
  [#204](https://github.com/voxpupuli/openvox-ca/issues/204): the blob path
  computed its whole-blob HMAC from the bytes it read *before* its own append,
  so two replicas interleaving left the stored HMAC covering a blob that never
  existed and the next verifying read failed with
  `ErrInventoryTampered`.
- **Bulk rewrites are bounded, not batched-for-consistency.** A prune commits
  its whole removal in one script, so `PruneEntries` here only ever reports a
  completed removal — the strongest form of a contract etcd satisfies more
  weakly. What is bounded is *size*: a script blocks the single-threaded server
  for its duration, so one prune call removes at most 5000 entries (oldest
  first) and an import is split into scripts of 512 records. Deferred prune
  matches stay present and consistent for later calls, and the server logs what
  it deferred.
- **Legacy blobs are decomposed in place**, under the same
  `inventory-decompose` lock etcd takes, with the same fail-closed rules:
  `EnsureReady` verifies the pre-decomposition blob against its stored
  whole-blob HMAC before trusting it (a mismatch, or a stored HMAC that cannot
  be verified because the key is missing or malformed, fails startup with
  `ErrInventoryTampered`; the operator acknowledges a lost baseline by deleting
  the `inventory:hmac` key), imports the lines into hash fields, and empties
  the marker only in the final script. The verified HMAC is deleted in the same
  import — it is not a chain head — and the next verification re-baselines from
  the imported entries; a CA upgraded while its inventory was *empty* has no
  import to drop it as part of, so `EnsureReady` handles that separately, on
  exactly the same terms as etcd. Because the blob stays authoritative until
  the final script, an interrupted import is detected on the next start (the
  partial entries are the import-written prefix of the blob) and redone from
  the intact blob; entries that are *not* such a prefix mean a mixed-version
  deployment wrote both forms, which is refused rather than guessed at. A
  not-yet-upgraded replica writing the blob mid-import is caught by a guard on
  the marker's stored mtime prefix and length — every writer stamps a fresh
  mtime, so an unchanged prefix means nothing has touched it — and the import
  restarts from the new blob. Duplicate serials are imported verbatim with a
  warning and carry the same ambiguity sentinel, with the same consequences:
  the serial stays reserved against reissue, certificate-index writes for it
  are explicit no-ops, `Statuses` reports its bearers as `CertStateUnknown` so
  readers derive their state from the signed CRL, the repair pass skips them,
  and a prune releases the sentinel only when the last bearer goes.
- **Certificate-index writes stay off the chain.** `SetRevoked` /
  `ClearRevoked` / `SetProjection` rewrite a single entry field, guarded on the
  stored value still being the one that was decoded (the mutable fields are not
  chain input), so index repair cannot fork the integrity head.

## Scope

- **SQL backend** (sqlite/postgres/mysql) implements `InventoryStore` with a
  dedicated `puppet_ca_inventory` table indexed on `subject` (and a unique index
  on `serial`, since serials never repeat), plus the render/parse shim. This is
  where decomposition pays off.
- **etcd** implements `InventoryStore` and `CertIndex` with per-entry keys —
  see [The etcd decomposition](#the-etcd-decomposition) above.
- **redis/valkey** implements `InventoryStore` and `CertIndex` with per-entry
  hash fields — see [The Redis decomposition](#the-redis-decomposition) above.
- **The filesystem backend keeps the blob.** It does not implement the
  interface; the type assertion fails and it behaves exactly as before. It is
  single-node, so the cost the decomposition removes (and the cross-replica
  guarantee it adds) does not arise there in the same way.
- **Wrapper backends unwrap to their base.** The probe is `asInventoryStore`,
  not a bare `s.backend.(InventoryStore)`: it sees through wrappers such as
  `OverlayBackend` (the `ca_cert_file`/`ca_key_file` local-override wrapper) via
  their `Unwrap()` method, so a SQL backend underneath keeps its hash-chain
  scheme rather than being downgraded to the whole-blob HMAC. Overriding only
  the cert/key blobs never touches the inventory, so consulting the base is
  always correct.
- **OCSP is untouched**: the in-memory serial index is still built at startup
  and updated on signing.

## Implementation phases

Each phase is a separate commit.

1. **Interface + routing.** Define `InventoryEntry` / `InventoryStore`; fork the
   `StorageService` inventory methods; move the subject-scan into
   `LatestSerialForSubject`; point `ca.findSerialForSubject` at it. No backend
   implements the interface yet, so behaviour is unchanged everywhere.
2. **SQL backend.** New bun migration creating `puppet_ca_inventory`; implement
   `AppendEntry`/`Entries`/`LatestSerialForSubject`; add the render/parse shim
   for the `inventory` logical key.
3. **Migration integrity rebuild.** Add `RebuildInventoryHMAC` and call it from
   `MigrateService` after the copy.
4. **Tests.** Exercise the inventory contract against both blob and structured
   backends: latest-wins lookups, chain tamper detection (modify / insert /
   delete), byte-identical render, and a filesystem ⇄ sqlite migration
   round-trip that verifies integrity on both sides.
5. **Certificate index** (issue #137, a later extension). Extend the SQL
   inventory table with the projection/state columns, define `CertIndex`,
   serve `certificate_statuses` from it, and add the startup repair pass.
6. **etcd decomposition** (issue #138, a later extension). Implement
   `InventoryStore` and `CertIndex` on the etcd backend with per-entry keys,
   including the in-place legacy blob conversion described above.
7. **Redis decomposition** (issue #139, a later extension). The same for the
   Redis/Valkey backend with per-entry hash fields, resolving the chain's one
   unavoidable read-compute-write optimistically because Lua cannot compute a
   keyed hash server-side.

## Inventory integrity: threat model and rationale

The sections above describe what the integrity mechanism *computes*. This one
states what it is *for*: which threats it is meant to address, which it is not,
and why the chosen shape meets the first set. A threat model that overstates
what a control provides is worse than none, because it stops people looking; so
the limitations below are stated as plainly as the guarantees.

**The reasoning behind the original remediation item is not recorded in this
repository.** The whole-blob HMAC arrived with the CA-key process isolation work
as remediation item `[012]`, which references a design document
(`PUPPET-CA-20260318-055744`) that is not in the repo. What follows is derived
from the code as it stands, not from the original intent. Where the two could
differ this section says so rather than reconstructing a rationale that would
read as authoritative — see [Open questions](#open-questions).

For context, upstream Puppet Server's CA does none of this: its `inventory.txt`
is a plain append-only text file with no integrity checking. This is an
openvox-ca addition, which is why its purpose has to be argued rather than
inherited.

### What the control is

Exactly one integrity value is persisted for the whole inventory, under the
`inventory_hmac` logical key, keyed by `hmac_key`. Two schemes compute it:

- **Whole-blob HMAC** — `HMAC-SHA256(key, blob)`, used by backends that keep the
  inventory as a blob.
- **Hash chain** — the fold described in
  [Integrity: a hash chain](#integrity-a-hash-chain), used by `InventoryStore`
  backends, which persists only the final head.

Both detect modification, insertion, deletion and truncation of the entry set.
Neither persists a per-entry value, so **a mismatch establishes that the
inventory diverged from its recorded state, never where it diverged.** Recovery
is therefore a rebuild, not a repair.

Verification runs at startup from `CA.Init`, on `ReadInventory` and
`InventoryEntries`, on `SubjectForSerial` on the blob path, and in
`PruneInventory` on every backend. **How often it runs after startup
depends on the backend, and the difference cuts against the weaker scheme.** The
OCSP serial-index resync tick re-checks the inventory through
`InventoryEntries` once per `ocsp_index_sync_interval_sec` (default five
minutes), but that job starts only for the shared backends:
`sharedStorageBackend` excludes `filesystem` and `sqlite`, and on those the
server logs `OCSP serial index sync not started` and no tick runs.

So on postgres, mysql, etcd and redis an established CA re-checks its inventory
continuously. The two without a tick do not, and they differ from each other.
On the default filesystem backend — also the only whole-blob backend —
verification after `CA.Init` happens only when something drives a verifying
read: both revocation entry points, the CSR-based renewal path, and the opt-in
expired-certificate cleanup. **Auto-renewal is not one of them.** `AutoRenew` —
the empty-body flow real agents use by default — takes the predecessor serial
from the presented certificate rather than the inventory, so a fleet doing
nothing but routine renewal never drives a verifying read at all.

SQLite gets a smaller set still: the by-subject and by-serial lookups skip
verification on `InventoryStore` backends, so no revocation carries it there,
and `ReadInventory` is reachable only from the blob branch SQLite never takes.
That leaves startup and, if the opt-in cleanup is enabled, the prune. Startup
itself verifies twice — `InitHMAC`, which fails the start, and the serial-index
build, whose failure is only logged — so with cleanup off, those two passes are
the whole of it.

So the gap between the two is narrower than it looks: on a filesystem CA whose
agents only auto-renew, verification is also just the startup pair. The backend
with the weaker integrity scheme is among those whose value is checked least
often.

What a mismatch then does depends on the caller. At `CA.Init` it returns
`ErrInventoryTampered` and startup fails. On the periodic path it does **not**
fail closed: `SyncSerialIndex` counts the failure into
`puppetca_ocsp_index_sync_failures_total`, `syncOCSPIndexOnce` logs `OCSP serial
index sync failed; continuing with the index already in memory` at `Warn`, and
the CA keeps answering from the index it already holds.

The signal to alert on is the mismatch warning itself — `inventory HMAC
mismatch; integrity check failed`, at `Warn`, carrying a `scheme` attribute of
`whole-blob-hmac` or `hash-chain`. That is the only integrity-specific,
backend-identifying record the system emits. The counter is the weaker
secondary: `puppetca_ocsp_index_sync_failures_total` counts *every* failed
inventory read on that path, an unreachable backend included, so a rise in it
means "this replica is not refreshing its serial index" and only the log line
says why.

No metric is *specific* to the mismatch, so only the log line identifies it as
one. What a mismatch moves depends on which path met it, and that differs by
backend. On the shared backends the tick counts into
`puppetca_ocsp_index_sync_failures_total`, raising `PuppetCAOCSPIndexSyncFailing`.
On filesystem the tick does not run, but a revocation that meets the mismatch
does count: both revoke paths read through a verifying call there, so the failure
lands in `puppetca_crl_update_failures_total` and can raise
`PuppetCACRLUpdateFailing` — an alert that fires for a tamper signal while naming
it a CRL problem. SQLite is the one backend where neither happens: no tick, and
the by-subject and by-serial lookups verify nothing, so no metric moves for a
mismatch at all and the signals are the log line and a failed start. A refused
start aborts before the metrics listener binds, so it shows up as
`PuppetCAExporterDown` (or a bare `absent(up)`) rather than `PuppetCANotReady` —
mislabelled in the same way, and on SQLite it is the only alert a mismatch
produces.

Several read paths do not verify at all. `SerialExists` reads through
`inventoryEntriesLocked`, which checks nothing on any backend.
`SubjectForSerial` and `LatestSerialForSubject` verify on the blob path but not
on `InventoryStore` backends — deliberately, because re-verifying would cost a
second full fetch of every row, as `SubjectForSerial`'s comment sets out at
length. `CertStatuses`, which answers the certificate-status listing, reads the
index without checking it. And the append path does not verify before it writes;
no comment records whether that is intentional, and it matters more — see
out-of-scope item 1.

### In scope

1. **Accidental corruption, truncation and partial writes.** A half-written
   append, a truncation after a full disk or an unclean shutdown, or bit-rot in
   the stored bytes all change the covered input and are caught with
   overwhelming probability. This is the strongest justification for the
   control and the one least sensitive to where the key lives: corruption does
   not recompute a MAC. Detection is bounded by how often verification runs,
   though, which on the default filesystem backend is at startup, on revocation
   and CSR-based renewal, and on the opt-in cleanup — not on auto-renewal, and
   not continuously.

2. **Tampering that reaches the inventory but not the key.** A tampered or
   mismatched backup, or an exposure path that reaches the inventory without
   reaching `hmac_key`. Genuine, but narrow: it depends on the inventory being
   separable from **both** `hmac_key` and `inventory_hmac`, since reaching
   either of those defeats the control, and by default the same permissions
   reach all three.

3. **Defence in depth.** The control raises the cost of a silent edit — an
   attacker must additionally reach the key or the integrity blob, rather than
   appending a line to a text file and stopping.

### Out of scope

These are properties of the design, not defects to be fixed quietly. They are
recorded so the control is not credited with more than it does.

1. **An adversary with write access to the storage backend.** This is the
   central limitation. `hmac_key` lives in the same backend as the inventory it
   protects, behind the same permissions, so an attacker who can write the
   inventory can usually also read the key and recompute a valid MAC.

   The bypass is in fact cheaper than that. `VerifyInventoryHMAC` treats an
   **absent** `inventory_hmac` as a first run: it logs `No inventory HMAC found;
   initializing integrity baseline` at `Info` level and computes a fresh value
   over whatever the inventory currently contains. Tampering with the inventory
   and unlinking one blob is therefore sufficient — the key need not be read at
   all, and no restart is strictly needed. Absence is indistinguishable from a
   first run, so the control's own initialisation path is the bypass.

   Which verifier gets there first matters. `verifyInventoryHMACLocked` — reached
   from `CA.Init`, `ReadInventory`, `SubjectForSerial` and the prune path — is
   the one that re-baselines. `compareInventoryMACLocked`, which
   `InventoryEntries` and therefore the resync tick use, instead logs `No
   inventory HMAC stored; skipping the integrity check for this read` at `Warn`
   and writes nothing; its comment says the divergence is deliberate, because a
   read path that writes, from every replica at once on a timer, is not worth
   leaving available. On a hash-chain backend an append that lands before any
   re-baseline makes things worse for the attacker rather than better: the new
   head chains onto the absent predecessor while verification folds over every
   row, leaving a mismatch that no later check clears.

   A second and quieter path reaches the same place on blob backends without
   deleting anything: the append path does not verify before it writes.
   `AppendInventoryRecord` reads the current blob, appends the new line and
   stores an HMAC over the result, so if the blob had already been tampered
   with, the next issued certificate re-blesses it. **The hash chain does not
   launder tampering this way** — a new head is chained onto its stored
   predecessor while verification folds over the rows themselves, so an altered
   row keeps failing every subsequent check.

   A third path is a supported operator command rather than an attack.
   `MigrateService` copies through the raw backend without verifying the source,
   then calls `RebuildInventoryHMAC` on the destination unconditionally, so
   `openvox-ca-ctl migrate` recomputes the integrity value over whatever was
   copied. That clears a mismatch on **either** scheme — it is the rebuild the
   opening of this section says recovery requires, and it cannot tell a repair
   from a laundering. It is a cutover rather than an in-place repair: the
   destination must be a different store (a store cannot be migrated onto
   itself), one that already holds a CA is refused without `--force`, and the CA
   must then be served from the destination. Because it only ever reads the
   source, the mismatched pair survives in the store you migrated away from, so
   a cutover does not destroy the evidence — decommissioning or re-forcing into
   that store afterwards is what does. Note that migrating into a scratch
   destination preserves nothing: the rebuild overwrites the copied value
   there. An operator with no second store has only one in-field move — delete
   the stored value and let the next verifier re-baseline — and that is the same
   path described above as the attacker's cheap bypass. It is silent and
   irreversible, so copy the inventory and its integrity value aside first: the
   mismatch is the only evidence that there was one.

   **Against an adversary with storage write access, this control should not be
   relied upon.**

2. **Interleaved appends from a second writer, where one can reach the store.**
   Locks do not prevent this on a blob backend, but the single-instance rule
   mostly does, and the distinction decides how an operator should read a
   mismatch.

   Neither lock helps. Issuance serialises on a per-subject lock
   (`subjectLockName(subject)`), a different name per subject, and there is no
   global inventory lock. `AppendInventoryRecord` does hold
   `StorageService.inventoryMu` across the whole read-append-rewrite sequence, so
   two appends inside one process cannot interleave — but `inventoryMu` is a
   plain `sync.RWMutex` and orders nothing between processes.

   What excludes a second writer is the single-instance rule, and — as
   [storage-backends.md](../storage-backends.md) and
   [locking.md](locking.md) both put it — that case is closed by **scope**, not
   by mechanism: nothing makes the interleave impossible, so the rule is the
   guarantee and the store-wide lock is what holds operators to it. On the
   filesystem backend `AcquireInstanceLock` takes that lock and refuses a second
   instance. The no-op branch, where it returns without locking because the
   backend has distributed locking, is reached only by etcd, Redis, PostgreSQL
   and MySQL — all of them hash-chain backends that advance the head atomically.
   It cannot fire on a whole-blob backend at all. SQLite is a hash-chain backend
   that takes the store-wide lock too, like filesystem, because its `Locker`
   reports `ErrDistributedLockingUnsupported`.

   The lock is best-effort by design, and the residual paths matter more than
   the rule. A platform where it is unavailable
   (`ErrSameHostLockingUnsupported`), and the two branches where the capability
   probe fails or the backend offers no store-wide lock, each log a warning
   naming the reason. **A cadir on a network filesystem that accepts `flock(2)`
   logs nothing at all** — the lock is taken and reported as held while
   excluding nothing across hosts, and no code detects the case. One that
   rejects it (`EOPNOTSUPP`, `ENOSYS`) falls into the unavailable branch above
   and does warn. So a clean log is not evidence that a
   second writer was excluded; an operator has to know from their own deployment
   whether the cadir is local. The derivation behind all this lives in
   [locking.md](locking.md); only the conclusion belongs here.

   Where it does happen, two concurrent appenders leave an integrity value
   covering a blob that **never existed** — not one that has since changed.

3. **Rollback to an earlier consistent state.** The stored value covers contents,
   not freshness. Replacing both the inventory and its integrity value with an
   older, self-consistent pair verifies successfully. This is what lets a whole
   backup be restored, and equally what makes such a rollback undetectable here.

4. **The denormalised projection.** The chain input is `canonicalInventoryLine`
   — serial, notBefore, notAfter, subject — and `InventoryEntry` carries exactly
   those fields, so the projection columns added for the certificate index,
   including the mutable revocation state, are not integrity-covered and cannot
   be by construction. This is deliberate (see
   [The certificate index](#the-certificate-index-certindex)): revocation truth
   rests on the signed CRL, not on this control.

5. **The append/prune ordering gap on blob backends.** The line is durably
   appended before the integrity value is updated, so a crash between the two
   leaves them inconsistent. `PruneInventory` has the identical shape: it
   rewrites the whole inventory and only then recomputes the value, and on the
   default backend it is reachable through the opt-in expired-certificate
   cleanup. Both report the failure rather than hiding it, and the code explains
   why it does not try to make either pair atomic, but the window is real. The
   structured backends have neither gap: rows and head move together.

### What a mismatch does and does not prove

This differs by scheme. The mismatch warning carries a `scheme` attribute
naming which one it computed under; the `ErrInventoryTampered` text that
surfaces a refused startup does not, so the label is in the log rather than in
the error an operator first meets.

- **Whole-blob HMAC** (the filesystem backend) — a mismatch means only that the
  stored value does not match the blob. Tampering is one cause. A torn append is
  another, and it needs no second writer: the line is durably appended before the
  integrity value is updated, so a crash between the two produces exactly this
  (out-of-scope item 5), and so is an interrupted prune, which has the same
  shape. An interleaved append from a second writer is a third, but only in the
  configurations named in out-of-scope item 2, where the instance lock did not
  hold. **A mismatch is not by itself evidence of tampering** — though on a
  single-node deployment whose instance lock was in force, the benign
  explanations narrow to the torn append, and the signal is correspondingly
  stronger than the general case.
- **Hash chain** (`InventoryStore` backends) — the head advances atomically with
  the row inside the append transaction, so neither the torn-append nor the
  interleaved-append cause applies, and a mismatch is a stronger signal. It is
  not conclusive either: a first start after upgrading a
  `ca_key_file`/`ca_cert_file` deployment over a structured backend can fail
  here with no tampering, because the stored value was written under the
  whole-blob scheme and is now read as a chain. That affects pre-release builds
  only — deployments created after the unwrap fix are unaffected — and
  [storage-internals.md](storage-internals.md#upgrading-a-pre-fix-ca_key_file--ca_cert_file--database-deployment)
  carries the recovery. It is precisely why the warning names the scheme it
  computed under.

### Why the mechanism meets the in-scope set

- A keyed MAC over the covered input catches any change to it, truncation at any
  offset included, which is what in-scope item 1 requires.
- **Keying the hash is what buys in-scope item 2.** An unkeyed checksum stored
  beside the data could be recomputed by anyone able to write it, so it would detect
  corruption but no tampering at all. The key is what makes the control
  adversarial in the cases where the attacker cannot reach it.
- The **hash chain** exists so appends stay O(1) on structured backends while
  preserving the same detection properties, and — as a side effect that matters
  more than the performance — it removes out-of-scope item 2 by advancing the
  head inside the append transaction.
- Storing **one head** rather than per-entry values is a deliberate trade: it is
  cheap and makes a forked chain impossible, at the cost of localising damage.

The honest summary is that the control is well matched to accidental corruption,
and to tampering that reaches the inventory but neither `hmac_key` nor
`inventory_hmac`. It provides little against an adversary who can write the
store.

Three properties compound on one backend. The only whole-blob backend is the
default one; it is the only family where an append can re-bless already-tampered
contents; and it is one of the two that get no periodic verification.
**The control is weakest on the backend a deployment gets if it chooses
nothing.** (SQLite is the one where no metric moves for a mismatch at all, so
it is worst served for detection even though its scheme is the stronger one.)

That is a claim about the control, not about where the threat is worst — the
section does not argue the latter, and for at least one threat it points the
other way, since a networked store is reachable from more places than a local
cadir of `0600` files under `0750` directories. Whether this distribution of strength is the intended goal is
the first of the open questions below.

### Open questions

These need a decision or the original author's input; they are recorded here
rather than resolved, and this document does not change the mechanism.

1. **The reasoning behind `[012]` and `PUPPET-CA-20260318-055744`.** Not
   recorded in this repository; asked in
   [#136](https://github.com/voxpupuli/openvox-ca/issues/136). The remediation
   arrived with commit `18ff78be08ec`, which is where the author is recorded.
2. **Compliance mapping.** The codebase cites NIST 800-53 controls at many
   sites, but `internal/storage` cites none, so the inventory HMAC has no
   recorded control mapping. If `[012]` was written against a specific integrity
   control, naming it would settle whether the current shape satisfies it.
3. **Is the co-located key an accepted limitation or a gap to close?** Moving
   `hmac_key` outside the storage boundary — environment, a separate secret
   store, or transit/HSM custody — closes only the key-recovery half of
   out-of-scope item 1. The cheaper bypass needs no key at all, so relocating
   the key leaves it untouched; bringing item 1 fully into scope also requires
   the absent-value path to fail closed, which is question 5. Both are larger
   changes and worth making only if the adversarial case is agreed to be in
   scope.
4. **The ordering gap** (out-of-scope item 5) is fixable on its own, independently
   of the above.
5. **The absent-integrity-blob path** cannot distinguish "never had one" from
   "had one and it is now missing", which on an established CA means a partial
   restore, a deletion, or the absent-value bypass in out-of-scope item 1. The two verifiers
   report it differently: `verifyInventoryHMACLocked` re-baselines and logs at
   `Info`, while `compareInventoryMACLocked` logs at `Warn` and writes nothing.
   So on a shared backend, where the resync tick runs, a deleted integrity blob
   produces a repeating warning worth alerting on. The two backends without a
   tick then diverge in opposite directions: on filesystem, if an issuance
   reaches the store before any verifying read, the append silently rewrites the
   value and there is no record at all, not even the `Info` line; on SQLite the
   same issuance chains onto the absent predecessor and leaves the permanent
   mismatch described in out-of-scope item 1. That one fails the next start and
   logs the `inventory HMAC mismatch; integrity check failed` warning with
   `scheme=hash-chain` before it does, so a deletion surfaces there as a
   suspected-tampering signal rather than as the absent-value notice that
   produced it.
6. **Some of this is pinned by a spec and some is not**, and the split is worth
   knowing before relying on any of it. Asserted: both arms of the absent-value
   behaviour — the re-baseline by `storage_test.go`'s "initializes HMAC baseline
   when no HMAC file exists yet", the non-writing compare by
   `sql_inventory_test.go`'s "accepts a missing stored value without writing
   one" — the backend gate on the resync tick, the periodic path's not failing
   closed, both halves of the ordering gap reporting their failure rather than
   hiding it, and detection of a modified, inserted or deleted row on all three
   `InventoryStore` implementations (SQL, etcd, redis — PostgreSQL and MySQL
   carry no tamper spec of their own and inherit the SQLite one through the
   shared SQL path). The by-serial half of the CRL-counter claim above is
   asserted too. Only the prune half additionally pins the aftermath —
   that the rewrite is durable, the head lags it, and the next read reports
   `ErrInventoryTampered`.

   Not asserted, and load-bearing for this section's argument: **the blob/chain
   asymmetry on either side**. The tamper suites verify immediately after
   tampering and never append in between, which is the step the asymmetry is
   about — so nothing pins that a blob append re-blesses, and nothing pins that a
   chain append does not. A refactor making `AppendEntry` recompute over all rows
   would launder tampering exactly as the blob path does and every existing spec
   would still pass. Nor is the append half's aftermath pinned: its spec asserts
   only that an error is returned, so rolling the line back on failure, or
   writing the value first, would leave it green and this item's first sentence
   false. Nor is the by-subject half of the CRL-counter claim: nothing pins
   that `LatestSerialForSubject` verifies on a blob backend, so a refactor
   giving it an unverified fast path would leave that paragraph half wrong.
   Also unasserted: the migration laundering above, the
   `Info`/`Warn` levels of the quoted messages, and the `scheme` attribute on the
   mismatch warning. A change to any of these would leave this section quietly
   wrong rather than failing a build.
