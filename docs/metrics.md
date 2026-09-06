# Metrics & monitoring

The openvox-ca server ships with an optional [Prometheus](https://prometheus.io/)
exporter. When enabled it serves the standard Go runtime/process metrics and
HTTP request metrics expected of a Go web service, plus CA-specific series
describing the **CA certificate**, its **CRL**, and every known (non-deleted)
**leaf certificate** — including issue/expiry timestamps and issuance status.

A ready-to-import [Jsonnet alerting mixin](../mixin/) is included; see
[Alerting](#alerting) for what it covers.

## Enabling the exporter

The exporter is **disabled by default**. Enable it by setting a listen address:

| Flag | Env | Config (YAML) |
| --- | --- | --- |
| `--metrics-listen 127.0.0.1:9140` | `PUPPET_CA_METRICS_LISTEN=127.0.0.1:9140` | `metrics_listen: 127.0.0.1:9140` |

```sh
openvox-ca --cadir /var/lib/puppet-ca --metrics-listen 127.0.0.1:9140
```

The exporter runs on a **separate listener** from the Puppet API and always
serves plain HTTP at `/metrics`, regardless of the API's TLS configuration. In
the default isolated-process mode it runs inside the frontend process (the
signer process has no network exposure).

> **Security:** the leaf-certificate metrics expose node hostnames (certificate
> subjects) as label values. Bind the exporter to loopback or a trusted
> management network — e.g. `127.0.0.1:9140` scraped via a node exporter sidecar,
> or a dedicated interface protected by a network policy — rather than a public
> address.

### Prometheus scrape config

```yaml
scrape_configs:
  - job_name: openvox-ca
    static_configs:
      - targets: ['openvox-ca.internal:9140']
```

The `job_name` is referenced by the alerting mixin's selector (default
`job="openvox-ca"`).

## Metric reference

All CA-specific metrics use the `puppetca_` prefix. Timestamps are seconds since
the Unix epoch, the Prometheus convention for `*_timestamp_seconds` gauges.

### Standard Go / web-application metrics

| Metric | Description |
| --- | --- |
| `go_*` | Go runtime metrics (goroutines, GC, memory) from the standard Go collector. |
| `process_*` | Process metrics (CPU, resident memory, open FDs) where supported by the platform. |
| `puppetca_http_requests_total{method,code}` | Total CA API requests, by HTTP method and response code. |
| `puppetca_http_request_duration_seconds{method,code}` | CA API request latency histogram. |
| `puppetca_http_requests_in_flight` | CA API requests currently being served. |

> HTTP request metrics are intentionally **not** labelled by URL path: the CA's
> API paths embed per-node subjects (e.g. `/certificate_status/<hostname>`),
> which would otherwise explode metric cardinality.

### Exporter health

| Metric | Description |
| --- | --- |
| `puppetca_ca_ready` | `1` when the CA has finished initialising, else `0`. |
| `puppetca_collector_scrape_success` | `1` if the last CA-state gather succeeded, else `0` (e.g. storage unavailable). |
| `puppetca_collector_scrape_duration_seconds` | Time taken to gather the CA, CRL and leaf metrics. |

### CA certificate

| Metric | Labels | Description |
| --- | --- | --- |
| `puppetca_ca_certificate_info` | `common_name`, `serial`, `issuer` | Constant `1`; carries CA identity in labels. |
| `puppetca_ca_certificate_not_before_timestamp_seconds` | — | CA certificate issue time. |
| `puppetca_ca_certificate_not_after_timestamp_seconds` | — | CA certificate expiry time. |

### CRL

| Metric | Description |
| --- | --- |
| `puppetca_crl_number` | Monotonic CRL sequence number (`cRLNumber`). Expect it to advance without any revocation having happened: a re-sign bumps it, and with [`crl_chain_file`](configuration.md#publishing-an-upstream-crl-chain) configured, so does a change to the upstream chain. The number need only increase, so this is harmless — but do not treat a rise as evidence that something was revoked. |
| `puppetca_crl_this_update_timestamp_seconds` | CRL `ThisUpdate` time. |
| `puppetca_crl_next_update_timestamp_seconds` | CRL `NextUpdate` (expiry) time. |
| `puppetca_crl_revoked_certificates` | Number of certificates currently listed in the CRL. |
| `puppetca_crl_update_failures_total` | Counter of failures to amend the CRL. A lower bound — see the note below. Resets to `0` on process restart. |
| `puppetca_crl_cached_number` | CRL number of the copy **this replica** is answering revocation checks from. `number`, `this_update`, `next_update` and `revoked_certificates` above are read from storage and so are identical on every replica; this one and both `*_failures_total` counters are per-process and have to be checked on each. |
| `puppetca_crl_sync_failures_total` | Counter of failures to reload the stored CRL into that in-memory copy — an unreadable or unparseable CRL, or one this CA did not sign. While it rises the replica keeps enforcing whichever CRL it already held. Resets to `0` on process restart. |

Each replica decides revocation from `puppetca_crl_cached_number` and reloads it
from storage every `crl_sync_interval_sec` (60s by default), so after a
revocation it briefly trails `puppetca_crl_number`. A gap that persists is a
replica still admitting certificates the rest of the fleet has revoked — see
[watching revocation propagate](#watching-revocation-propagate) below for the
query, and `puppetca_crl_sync_failures_total` for why it is stuck.
> **What the failure counter does and does not see.** It counts a CRL that
> could not be re-signed or written, *or read*, on any of the five paths that
> write one (revoke by subject, revoke by serial, CRL reissue, background
> refresh, expired-cert cleanup).
> The read half is `readStoredCRL`'s doing: it increments before returning, on
> every path that calls it, which is what makes this counter cover all five
> rather than only the one that noticed. On the revoke paths alone it also counts
> a malformed serial, or an inventory read that failed while resolving the
> subject's serial — which on the filesystem backend includes an **integrity
> MAC that no longer verifies**, since both revoke paths verify there, so this
> counter is the one a tamper signal reaches on the default backend (see the
> [inventory integrity threat
> model](development/inventory-store.md#inventory-integrity-threat-model-and-rationale)).
> That last one
> includes a revocation whose wait for the per-subject lock spent the 60-second
> budget behind another goroutine *in this process* on the single-node backends,
> which reach the read with the deadline already gone; see
> [revocation cost](api.md#certificate-status). So a queued revocation is a
> benign cause of this alert on filesystem and SQLite. A wait for another
> *process* on the host is refused at acquisition instead and never reaches the
> read, so it does not move this counter — see the uncounted list below. The
> revoke path is the shared revoke-by-serial code, so it also covers
> `DELETE /certificate_status` (`puppet cert clean`) and the best-effort
> revocation of a superseded certificate on renewal, which on a busy fleet is
> the likeliest source of a rising count: grep for `Renew:` /
> `AutoRenew: failed to retire replaced certificate` alongside the `Clean:`
> warnings. Both *renewal* warnings name the serial, and the certificate they
> left valid is one revoking by subject cannot reach: the replacement is what
> makes it a renewal, so `revoke --certname` would retire that instead. That is
> specific to a failure on the *immediate* path — nothing recorded the
> predecessor, so nothing but its serial addresses it. Where
> [`superseded_cert_revoke_after_sec`](configuration.md#delayed-supersession)
> grants a window, which is the default, a predecessor is on the pending list
> and revoking the subject does retire it. Retire an unrecorded one with
> `openvox-ca-ctl revoke --serial <hex>`; see
> [revocation by serial](api.md#revocation-by-serial). The `Clean:` warnings are
> qualified differently: they name the serial only once the revocation reached
> the CRL, and the certificate they leave behind is still reachable by subject
> until a replacement is issued.
>
> Counted since the CRL lock gained its own accounting: a write path that could
> not take the lock at all, on the five writers that go through
> `withCRLLockCounted` — revoke by subject, revoke by serial, reissue, refresh
> and cleanup. The closure never runs in that case, so nothing beneath it could
> count anything, and the error used to reach a log line only. The
> `crl_chain_file` refresh counts a lock it could not take on this same counter
> itself rather than through the helper (a failure there is not the file's
> fault, so it does not touch `puppetca_crl_chain_refresh_failures_total`). The
> revoke step inside `Clean` and `GenerateWithOptions`, the retire step inside
> `Renew` and `AutoRenew` — whether it revokes inline or defers to the superseded
> sweep — the sweep itself (`ReconcileSuperseded`), and `ImportCA`, are not
> counted on that arm at all.
>
> The line between the two is whether the revocation is one an operator asked
> for. A contended lock during `Clean`'s best-effort revoke is not a revocation
> that did not happen — the operation the caller asked for succeeded — whereas
> `openvox-ca-ctl revoke --serial` failing on the lock is exactly that, and it is
> the only way to retire a superseded certificate. Revoke by serial was left out
> of the counted set when the rest were converted, and a review caught it; the
> enumeration above is now every writer, with nothing falling into an unnamed
> remainder.
>
> The read half of that is `readStoredCRL`'s doing: it increments before
> returning, on every path that calls it.
>
> Uncounted, and logged only: a revocation refused at the **subject** lock,
> which `Revoke` takes outside the CRL lock and which therefore fails ahead of
> any CRL work (this is the `409` a spent lock budget produces on PostgreSQL,
> MySQL, etcd and Redis; the single-node backends take the subject lock and fail
> at the CRL lock beneath it, which *is* counted, by the rule above — *unless*
> another process on the same host was holding it, the one case where they too
> refuse at acquisition), a revocation whose subject or serial was simply **not
> present** in the inventory — a read that *failed* is counted, per above (though `PUT
> /certificate_status` also answers its caller `409` in both cases), and a
> malformed serial met by the cleanup job.
>
> A CRL the *exporter* cannot read is a different matter, and is invisible here
> — as it is to `puppetca_collector_scrape_success`: the exporter drops the
> CRL gauges and still reports a successful scrape. It does not show up as an
> expiring CRL either, because the gauge is *absent* rather than stale — the
> shipped `PuppetCACRLExpiringSoon` and `PuppetCACRLExpired` rules compare
> `puppetca_crl_next_update_timestamp_seconds` against `time()` and match
> nothing when the series is missing. Pair them with a per-instance presence
> check, e.g. `puppetca_ca_ready == 1 unless on(instance)
> puppetca_crl_next_update_timestamp_seconds`; bare `absent()` will not fire
> while any other replica still reports the series.

The four CRL gauges above describe the **first block of the stored blob**, which
is normally this CA's own CRL and not always: a hand-assembled blob can lead with
an ancestor's, and the CA then answers revocation from its own block found later
in the chain (see [storage internals](development/storage-internals.md)) while
these series still describe block 0. Startup warns loudly in that state, and every
write path refuses it, so it is a condition to fix rather than to monitor. When a CRL chain has been imported, the ancestor CRLs that follow it
are not covered: this CA cannot re-sign them, so their expiry is not something a
re-sign can fix and not something these series track. The series below cover
those instead.

### Upstream CRL chain

| Metric | Description |
| --- | --- |
| `puppetca_crl_chain_next_update_timestamp_seconds` | NextUpdate of each **upstream** CRL in the stored blob — every block this CA did not issue — labelled by `issuer`. Deliberately a separate series from the unlabelled CRL metrics above: an expiring upstream CRL is fixed at the parent CA, not here, so it has its own alert and runbook. |
| `puppetca_crl_chain_last_read_timestamp_seconds` | When `crl_chain_file` was last read successfully, or `0` if it never has been. Exported **only where `crl_chain_file` is configured**, so `absent()` means the feature is off and `== 0` means it is on but the file has never been opened — a wrong path, or a mount that never landed. That case moves no counter and would otherwise look healthy; `PuppetCAUpstreamCRLNeverRead` alerts on it. It does **not** detect a `subPath` mount: that reads successfully forever, so this advances exactly as it does on a healthy file. See [the `subPath` note](configuration.md#publishing-an-upstream-crl-chain) for what does. |
| `puppetca_crl_chain_refresh_failures_total` | Counter of failed `crl_chain_file` reads — unreadable, unparseable, not ending on a PEM block boundary, or too large. Counted where the file is read, so it moves on every CRL amendment as well as on each refresh pass; the visible symptom is that **revocation fails** until the file is fixed, as well as ancestor CRLs ageing. A failure of the refresh pass for some *other* reason — a lock it could not take, storage it could not read — deliberately moves `puppetca_crl_update_failures_total` instead, so this counter's runbook stays "check the file". The chain already published is left in place either way. Zero and static without `crl_chain_file`. Resets to `0` on process restart. |
| `puppetca_crl_chain_discarded_total` | Counter of discards: one per CRL dropped from `crl_chain_file`, each time the file is evaluated, because no certificate in the stored CA bundle signed it. The file is evaluated on every CRL amendment as well as on each refresh pass, so with a static bad file the value tracks revocation rate rather than the number of bad CRLs — alert on `increase(...) > 0`, not on the value. **Alert on this** — the shipped mixin does. It is the only signal that the published chain is *smaller* than the file says: a discarded CRL has no series of its own to go missing from. The remedy is to complete the CA bundle; a CRL passed over for being *stale* is counted separately, below. Zero and static without `crl_chain_file`. Resets to `0` on process restart. |
| `puppetca_crl_chain_removed_total` | Counter of ancestors `crl_chain_file` has stopped listing while their CRL was published. The removal is honoured — the file is authoritative — but it cannot be undone here, because this CA cannot re-sign another CA's list, and the ancestor's own `..._next_update_timestamp_seconds` series simply stops existing, which no alert can fire on. A deliberate removal increments this on the pass that applies it; a `cat` glob that matched one file fewer increments it identically, which is why it is worth alerting on. It also counts a second cause with the same outcome: a published ancestor whose certificate has left the stored CA bundle, so nothing signs its CRL any more and it can no longer be published. Its remedy is to re-import the bundle with that certificate — not to touch the file — and the log line names which cause fired. An incomplete bundle can therefore move this counter and `..._discarded_total` together: discarded for the copy the file carries, removed for the copy already published. Counted once per *ancestor* on both arms, not once per CRL: the first deduplicates by signing certificate, the second by issuer distinguished name, since there is no signer left to key on. Two published CRLs from one ancestor removed together therefore count once. Once per *removal*, too, rather than per evaluation: a rewriting pass reads the file twice — once to decide a rewrite is needed, once to build what it publishes — and only the pass that publishes counts, so one lost ancestor adds exactly 1. That is the difference between this counter and `..._discarded_total` / `..._regressed_total`, which describe what the file currently holds and so re-count on every evaluation while the condition stands. Zero and static without `crl_chain_file`. Resets to `0` on process restart. |
| `puppetca_crl_chain_regressed_total` | Counter of CRLs in `crl_chain_file` passed over because the published chain already carried a newer one from the same ancestor. The published CRL is kept, so revocation is unaffected — this is not a failure, and deliberately does not block CRL amendment the way an unreadable file does. A rising value means the file is stale, rolled back or being replayed; the remedy is whatever refreshes the file, **not** the CA bundle, which must already be complete or the CRL would have failed its signature check. Counted per CRL per evaluation, like the discard counter, so alert on `increase(...) > 0`. Zero and static without `crl_chain_file`. Resets to `0` on process restart. |

The gauge appears whenever the stored blob holds a CRL this CA did not issue —
which includes a chain brought in by `openvox-ca-ctl import --crl-chain` on a
deployment that has never set `crl_chain_file`. That is deliberate: an ancestor
CRL ages the same way whether or not anything is refreshing it, and it is
precisely the import-only deployment where nothing is. The remedy differs,
though, and the alert text names `crl_chain_file` because that is the standing
fix. On an import-only deployment, read
`PuppetCAUpstreamCRLExpiringSoon`/`Expired` as "re-import the chain with a
current one, or configure [`crl_chain_file`](configuration.md#publishing-an-upstream-crl-chain)
so it stays current by itself".

> **No series tracks the chain's length either, so watch the log during a rolling
> upgrade.** A replica running a build from before chain preservation re-signs the
> CRL by writing one block, dropping every ancestor — and nothing detects it,
> because the next re-sign on an upgraded replica then reads one block and writes
> one block while `puppetca_crl_number` keeps climbing. Upgrade every replica
> before importing a chain, and keep the imported bundle so it can be re-imported
> if this does happen. A re-sign that *can* see a difference says so, at `WARN`:
>
> ```text
> level=WARN msg="Stored CRL chain length changed while re-signing" blocks_read=2 blocks_written=1
> ```
>
> On a healthy CA that line never appears: every block that is not ours is carried
> across, and import discards duplicates of our own. Treat one as a chain to
> inspect.

### CA-key signing bound

| Metric | Description |
| --- | --- |
| `puppetca_ca_signing_in_flight` | CA-key signatures in flight right now, across certificate issuance, CRL re-signing and the OCSP responder together — they share one bound because they share one key. Always `0` when signing is unbounded. |
| `puppetca_ca_signing_limit` | The configured ceiling (`ca_signing_concurrency`). `0` means unbounded. |
| `puppetca_ca_signing_shed_total` | Counter of OCSP responses refused with RFC 6960 `tryLater` because the bound was full. Resets to `0` on process restart. |

Read the first two together: in-flight alone cannot say whether 8 concurrent
signatures is comfortable or is the ceiling. Headroom is the quantity worth
graphing.

```promql
puppetca_ca_signing_in_flight / puppetca_ca_signing_limit > 0.8
```

`puppetca_ca_signing_shed_total` rising is **not by itself a fault** — it is the
bound doing the job it exists for, and on an unauthenticated `/ocsp` flood it is
the protection working. What it asks is whether the limit matches the
deployment's signer, and the two answers look different:

- Shedding while `puppetca_ca_signing_in_flight` sits at the limit and the
  signer has capacity to spare → the limit is too low. Raise it.
- Shedding in bursts that correlate with request volume rather than with
  issuance → something is driving `/ocsp` harder than this responder is sized
  for. That is either growth to provision for or a caller to rate-limit
  upstream.

`puppetca_ca_signing_limit` is worth an alert of its own where an operator
intends signing to be bounded, because `0` is a legitimate configured value and
is indistinguishable at a glance from a bound that is simply working:

```promql
puppetca_ca_signing_limit == 0
```

All three are per-process. The bound itself is per-process too, so N replicas
against one shared OpenBao Transit key permit N × the limit against that key —
sum the series across the job to see what the signer actually faces.

### OCSP responder

| Metric | Description |
| --- | --- |
| `puppetca_ocsp_index_serials` | Number of certificate serials **this replica's** responder recognises. A serial it does not hold is answered `unknown`, before the CRL is consulted. |
| `puppetca_ocsp_index_sync_failures_total` | Counter of failures to reload the inventory into that index — an unreadable inventory, or one whose integrity MAC no longer verifies. While it rises the replica keeps whatever index it already held. Resets to `0` on process restart. |

Both are per-process, like the two CRL series above, and that is the point:
every replica sharing a backend should converge on the same
`puppetca_ocsp_index_serials` within one `ocsp_index_sync_interval_sec` (5m by
default). One persistently below the others is reporting valid certificates as
unrecognised — see
[OCSP status across replicas](configuration.md#ocsp-status-across-replicas).

```promql
# Replicas whose OCSP index has fallen behind the fleet
scalar(max(puppetca_ocsp_index_serials{job="openvox-ca"}))
  - puppetca_ocsp_index_serials{job="openvox-ca"} > 0
```

Both parts are load-bearing. The selector scopes the comparison to one CA: a
bare `max(...)` folds in every `puppetca_ocsp_index_serials` the Prometheus
scrapes, so a second, smaller CA — a staging instance, or an unrelated PKI —
would show every one of its replicas permanently "behind the fleet". Widen it
with `max by (job)` and an explicit `on(job)` match if you want one rule
covering several CAs.

And `scalar()` is load-bearing. A bare `max(...)` returns one sample with no labels
at all, and binary arithmetic between two instant vectors matches on the full
label set — so `max(x) - x` never matches anything carrying `job`/`instance`
and is silently always empty. The CRL query below can subtract two vectors
directly only because both sides carry identical labels, which is not the case
here.

Expect this to be briefly non-empty after each issuance and to clear on the next
sync. A replica that stays in it is answering `unknown` for certificates its
peers have signed; `puppetca_ocsp_index_sync_failures_total` usually says why.
Unlike the CRL gap this is not a security lag — `unknown` is not `good` — but a
verifier that hard-fails on `unknown` will reject against that replica alone.
A replica reading *above* the others is not a fault: a pass that overlaps a
local issuance defers its removals, so pruned serials linger an interval or two.

`puppetca_ocsp_index_sync_failures_total` has a shipped alert
(`PuppetCAOCSPIndexSyncFailing`); the fleet-relative gauge comparison above does
not, and has to be added by hand if you want it.

### Delayed supersession

Present on every CA, and live on any CA that renews certificates, since
[`superseded_cert_revoke_after_sec`](configuration.md#delayed-supersession)
defaults to 24 hours. Only where it is set to `0` is nothing ever recorded — a
renewal then revokes its predecessor inside the call, and a failure there is a
CRL failure counted above instead — so there the gauge sits at zero and the
counter stays flat.

Even there, one exception, and it is the one an operator who set `0` will
actually hit: three code paths read the pending list whatever the setting says —
the sweep, every renewal, and every subject revocation — and each counts a list
it could not read. A store that cannot serve the `superseded` key therefore
raises the counter, and fires `PuppetCASupersedeFailing`, even with the window
closed. The log line says which path: `Superseded-certificate revocation sweep
failed`, `cannot determine supersession status`, or `Revoke: could not read
pending supersessions`.

| Metric | Description |
| --- | --- |
| `puppetca_supersede_pending` | Certificates a renewal has replaced that are still inside their overlap window and not yet revoked. Read from storage, so identical on every replica. **Absent, not zero**, when the list could not be read — zero is what a drained list reports, so an unreadable one must not report it too. |
| `puppetca_supersede_failures_total` | Counter of failures to schedule or carry out one of those revocations. Per-process, and resets to `0` on process restart. |

`puppetca_supersede_pending` is the live measure of the exposure the window
buys: each of those certificates is a credential the CA still accepts even
though something newer has taken its place. It rises as renewals happen and
falls as the sweep drains the list, so a value that does not fall means the
sweep is not completing — check the failure counter.

> **What the failure counter sees.** A supersession the renewal path could not
> record (the certificate was replaced but nothing scheduled its revocation —
> the `failed to retire replaced certificate` warning names the serial); a
> pending list that could not be *read*, on the renewal path, in the sweep, or
> while revoking a subject; one that could not be *parsed*, in the sweep or
> while revoking a subject — a parse failure met on the renewal path refuses
> that renewal but is left for the sweep to count, so one corrupt blob cannot
> become a counter storm on a busy CA; a sweep pass that could not take the CRL
> lock or write the list back; a predecessor a subject revocation could not
> retire; and each pass that left an entry unrevoked or discarded one whose
> serial it could never revoke. A pass counts
> once however many entries it failed on, so this is a count of bad passes
> rather than of lost certificates.
>
> The cases differ in what you have to do about them, and the log line is what
> tells them apart. `Could not revoke superseded certificates` retries on the
> next pass by itself. `failed to retire replaced certificate` and `Discarding`
> are both gone for good — nothing will rediscover them, and the certificate
> stays valid for its full remaining life. Retire those by serial with
> `openvox-ca-ctl revoke --serial <hex>`; see
> [revocation by serial](api.md#revocation-by-serial). Revoking by subject does
> reach a predecessor the CA still has *recorded* — that is what makes
> `revoke --certname` containment during a window — but not one whose record was
> lost, which is exactly what a rising count here means.
>
> A sweep that cannot read the list at all counts once per pass and omits
> `puppetca_supersede_pending` rather than reporting zero, so the two signals
> cannot both read clean while the list stops draining. A sweep that *can* read
> it but cannot amend the CRL counts once per pass too, not once per entry: the
> re-sign covers the whole pass, so every certificate that pass attempted stays
> on the list and is retried together. A pending gauge that does not fall while
> this counter rises is a sweep failing outright rather than one falling behind
> — the sweep no longer paces itself, so there is no longer a backlog it
> declines to attempt.

### Client trust domains

| Metric | Description |
| --- | --- |
| `puppetca_client_crl_usable` | 1 when a `client_ca` trust domain holds any currently valid CRL, 0 when it holds none, labelled by `client_ca`. Present only where `client_ca` is configured **and the policy is `require`** — `crl_file` is optional under `check` and `skip`, so a domain without CRLs is correct there and a 0 would alert on a healthy server. **Alert on 0**: the domain has nothing to check against. It does **not** report partial coverage — whether an uncovered anchor matters depends on chains that have not arrived, so a domain can read 1 while clients of one of its anchors are refused. `puppetca_client_crl_refusals_total` is the signal for that. |
| `puppetca_client_crl_last_reload_timestamp_seconds` | When this `client_ca` entry's `crl_file` was last applied, labelled by `client_ca`. A reload that fails, that would cover fewer anchors than the set in use, that would drop an enforced partial CRL, or that would move an anchor backwards to an older CRL, or that cannot be shown to be newer at all (this server will not date the CRLs it holds for that anchor, and neither side publishes a `cRLNumber`), deliberately keeps the previous set — right for availability, and invisible on every other series, because the retained CRLs are still current and clients are still served. What has stopped is the file being applied, so revocations published since are not honoured. **Alert on it going stale** relative to `client_crl_refresh_interval_sec`. |
| `puppetca_client_crl_refusals_total` | Counter of clients refused **because revocation information was missing**, labelled by `client_ca`. Not incremented when a CRL was found and said the client is revoked — that is the feature working, and counting it made this alert driveable at will by the holder of a revoked certificate. Published under every policy, and zero-initialised so `increase()` can see the first refusal. Unlike the gauge this is not an estimate: it counts requests actually turned away, so it sees a partially covered entry — one anchor's CRL missing while another's is fine — which no load-time check can distinguish from a healthy one. **Alert on `increase(...) > 0`.** Resets to `0` on process restart. |

Emitted only when [`client_ca`](configuration.md#trusting-client-certificates-from-another-ca) is
configured. A foreign issuer's CRLs are not the chain above: they come from that
issuer's own `crl_file`, and this CA neither issues nor republishes them.

### Leaf certificates

One series per known (non-deleted) leaf certificate or pending request. Cleaned
(`puppet cert clean`) certificates drop out of these series even though their
inventory line persists. The `state` label is one of `requested` (a pending CSR
with no issued certificate), `signed`, or `revoked`.

| Metric | Labels | Description |
| --- | --- | --- |
| `puppetca_leaf_certificate_info` | `subject`, `serial`, `state` | Constant `1`. For `requested`, `serial` is empty. |
| `puppetca_leaf_certificate_not_before_timestamp_seconds` | `subject`, `serial`, `state` | Issue time. Not emitted for `requested`. |
| `puppetca_leaf_certificate_not_after_timestamp_seconds` | `subject`, `serial`, `state` | Expiry time. Not emitted for `requested`. |
| `puppetca_leaf_certificates` | `state` | Count of leaf certificates per state. |

> Expiry is **not** a `state`: it is derived from the `not_after` timestamp by
> alerting rules, so a certificate can be both `signed`/`revoked` and expired.
> To alert on expiry while ignoring revoked certs, filter on `state!="revoked"`,
> as the mixin does.

### Kubernetes export

Only present when [Kubernetes export](kubernetes-export.md) targets are
configured. Export failures are logged but never stop the CA, so these series
are the way to alert on a target that persistently fails. Two `applies_total`
series per configured target, plus up to one of each timestamp gauge;
cardinality is bounded by the configuration.

| Metric | Labels | Description |
| --- | --- | --- |
| `puppetca_k8s_export_applies_total` | `kind`, `namespace`, `name`, `result` | Apply attempts per target; `result` is `success` or `error`. |
| `puppetca_k8s_export_last_success_timestamp_seconds` | `kind`, `namespace`, `name` | Time of the last successful apply for each target. |
| `puppetca_k8s_export_last_error_timestamp_seconds` | `kind`, `namespace`, `name` | Time of the last failed apply for each target. |

> Exports are event-driven (startup, CRL updates, and a retry a couple of
> minutes after a failed cycle) and can be days apart on a quiet CA, so alert by
> comparing `last_error` against `last_success` (the mixin's
> `PuppetCAKubernetesExportFailing` does this) rather than with rate windows or
> staleness thresholds, which misbehave between sparse attempts.

Every configured target gets a result recorded on every cycle, including one
where the CA certificate or CRL could not be read from storage: such a read
fails the targets that asked for that material and leaves the rest alone. This
matters for alerting, because `PuppetCAKubernetesExportFailing` has
`last_error` on the left of both its arms and so can only speak about targets
that have a series at all.

The two `applies_total` children of each target are published at zero before
the first cycle runs — and also when the export fails to start at all, so a
Kubernetes client that cannot be built is reported rather than merely logged.
Without that, a configured-but-never-attempted target would be an absent
series, indistinguishable from a target that is not configured, and no
threshold can match an absence. The mixin's
`PuppetCAKubernetesExportNotRunning` alerts on that zero.

The timestamp gauges are deliberately *not* published this way. A `last_success`
of zero is not a neutral placeholder: it asserts that the last successful export
happened in 1970, which poisons any `time() - last_success` staleness query or
dashboard panel written against a gauge whose help text promises the time of the
last successful apply. (Alert coverage would survive it — a never-succeeded
target still trips the `last_error > last_success` arm against a zero — but the
`unless` arm would become dead code and every derived query would lie.)

## Example queries

```promql
# CA certificate days until expiry
(puppetca_ca_certificate_not_after_timestamp_seconds - time()) / 86400

# Non-revoked leaf certificates expiring within 7 days
puppetca_leaf_certificate_not_after_timestamp_seconds{state!="revoked"} - time() < 7 * 86400

# Pending certificate requests
puppetca_leaf_certificate_info{state="requested"} == 1

# CA API error rate
sum(rate(puppetca_http_requests_total{code=~"5.."}[5m]))

# Kubernetes export targets whose most recent apply failed
puppetca_k8s_export_last_error_timestamp_seconds
  > puppetca_k8s_export_last_success_timestamp_seconds
or
puppetca_k8s_export_last_error_timestamp_seconds
  unless puppetca_k8s_export_last_success_timestamp_seconds

# Kubernetes export targets configured but never attempted
sum without (result) (
  puppetca_k8s_export_applies_total
) == 0

# Export targets that keep needing a retry to succeed. No shipped alert covers
# this: the CA retries a failed cycle after two minutes, well inside the
# fifteen-minute debounce on PuppetCAKubernetesExportFailing, so a target that
# fails first and succeeds second every cycle never pages.
increase(puppetca_k8s_export_applies_total{result="error"}[6h]) > 0

# Replicas enforcing a CRL behind the stored one (see below)
puppetca_crl_number - puppetca_crl_cached_number > 0
or
(puppetca_crl_cached_number unless puppetca_crl_number)
  and on(instance) puppetca_collector_scrape_success == 1
```

### Watching revocation propagate

The query above is how you confirm a revocation has reached the whole fleet. It
is normally empty, and briefly non-empty after each revocation while replicas
pick the new CRL up on their `crl_sync_interval_sec` timer. A replica that stays
in it is still admitting certificates the rest of the fleet has revoked.

The second arm matters as much as the first: a replica whose stored CRL cannot
be read or parsed publishes no `puppetca_crl_number` at all, so the subtraction
alone would go quiet in exactly the case worth paging on. It is qualified on a
successful scrape so that arm covers only the CRL being unreadable — a storage
outage drops the same series and is already paged by `PuppetCAScrapeFailing`.
This is the expression the mixin's `PuppetCACRLStale` rule uses, modulo its
target selector.

`puppetca_crl_sync_failures_total` usually says why a replica is stuck. If it is
flat, the reads are succeeding and the stored CRL genuinely has not advanced.

Restarting the replica reloads the CRL, selecting the newest block this CA
signed the same way the sync does. If the stored chain carries none, startup
warns loudly and keeps serving from whatever block 0 holds — an availability
trade rather than a fail-closed refusal — while the re-sign paths refuse that
blob outright. The sync then replaces the foreign copy as soon as a CRL of ours
is stored. See
[Revocation across replicas](configuration.md#revocation-across-replicas).

## Alerting

See the [`mixin/`](../mixin/) directory for the Jsonnet monitoring mixin and
instructions for rendering or importing it. It alerts on exporter availability,
CA/CRL/leaf expiry, pending requests, CRL update failures
(`puppetca_crl_update_failures_total`), a replica whose CRL has fallen behind
the stored one (`puppetca_crl_cached_number`,
`puppetca_crl_sync_failures_total`), a replica that cannot reload its OCSP
serial index (`puppetca_ocsp_index_sync_failures_total`), delayed revocations
that were lost or could not be carried out
(`puppetca_supersede_failures_total`), the [upstream CRL
chain](#upstream-crl-chain) (an ancestor nearing or past its `NextUpdate`, and
the four ways `crl_chain_file` goes wrong — unreadable, a CRL discarded, one
rolled back, one removed — plus a file that has never been read at all),
[client trust domains](#client-trust-domains) whose revocation material has gone
unusable or stale (`PuppetCAClientCRLUnusable`, `PuppetCAClientCRLRefusals` and
`PuppetCAClientCRLStale`, and only where `client_ca` is configured), and
Kubernetes export failures, with all thresholds configurable. It does **not**
alert on the fleet-relative `puppetca_ocsp_index_serials` comparison — that one
is left to the operator, since it needs a `by (job)` aggregation to avoid
fanning in across unrelated CAs and the condition it catches is not fail-open.
