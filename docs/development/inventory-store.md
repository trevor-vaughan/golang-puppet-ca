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

- Every append re-hashes the whole inventory (O(n) per append) and every read
  re-verifies it. Fine while inventories are small; wasteful as they grow.
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

`RebuildInventoryHMAC` is no longer reached only from a migration: the offline
[`openvox-ca rebuild-inventory-hmac`](../operator-cli.md#rebuild-inventory-hmac-re-asserting-inventory-integrity)
calls it too, as the supported repair for a CA whose stored integrity value has
stopped verifying. Note what that command
re-asserts rather than verifies, and why it cannot say *which* entry diverged —
one head is persisted, not one per entry.

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
  so two replicas interleaving left the stored HMAC covering a blob that no
  longer existed and the next verifying read failed with
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
