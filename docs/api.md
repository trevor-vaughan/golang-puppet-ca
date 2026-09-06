# HTTP API reference

`openvox-ca` implements the same HTTP API that OpenVox and Puppet agents, and
the `puppetserver ca` / `puppet ssl` tooling, already use — the Puppet CA API.

All endpoints are served under both the bare path and `/puppet-ca/v1/<path>`, so the server can be used directly by agents or placed behind a proxy that strips the prefix.

## Certificate status

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/certificate_status/{subject}` | Get status: `signed`, `requested`, or `revoked` |
| `PUT` | `/certificate_status/{subject}` | Change state (`signed` or `revoked`); supports `cert_ttl` (seconds). `revoked` returns `409 Conflict` when the stored CRL was not signed by the CA certificate this process loaded — see the note below. `signed` returns `409 Conflict` when the queued CSR requests subject alternative names policy refuses ([`allow_subject_alt_names`](configuration.md#subject-alternative-names-requested-by-a-csr)) or extensions that disallow signing; both carry a body naming the cause |
| `DELETE` | `/certificate_status/{subject}` | Revoke + delete cert and CSR (`puppet cert clean`). The delete happens even if the revocation fails, as does the deletion of any pending request — see the note below and [Authorization tiers](#authorization-tiers) |
| `PUT` | `/certificate_status_by_serial/{serial}` | Revoke one specific serial, rather than whatever is newest for a subject — see [Revocation by serial](#revocation-by-serial); admin-only |

`PUT` body:

```json
{ "desired_state": "signed", "cert_ttl": 86400 }
```

A revocation takes the per-subject lock that signing and [renewal](#certificate-renewal) take, so it waits for an issuance already under way for that subject instead of overlapping it. That leaves two orderings, and both are answers rather than races: the revocation commits first and the renewal's under-lock re-check refuses it, or the renewal completes and the revocation then retires the serial it has just issued. Note what the second ordering does *not* promise. A revocation retires the subject's latest serial and no other, so it leaves the agent nothing usable only where the renewal retired the certificate it replaced — the default, but not a guarantee: `revoke_on_auto_renew: false` keeps the predecessor deliberately, and on both paths that revoke is best-effort and only warns when it fails. [`superseded_cert_revoke_after_sec`](configuration.md#delayed-supersession) does *not* belong on that list, and the difference matters when you are containing an agent: a predecessor inside its overlap window is recorded, so revoking the subject retires it too, in the same call. What the setting does change is the failure mode above — a predecessor whose supersession was never recorded is not on the pending list either, so nothing but `revoke --serial` reaches it, and `puppetca_supersede_failures_total` is what tells you one exists. A predecessor left behind stays valid for its own key, and still authenticates, because admission tests the serial presented rather than whatever certificate is on disk. Three further consequences worth knowing. The wait is not short, and it is not bounded the way you would expect. A renewal holds that lock across its own wait for the CRL lock, so a busy CA can keep a revocation queued; and the server's 60-second `lockTimeout` bounds only a wait for *another replica*, because every backend serialises callers within one process on a lock that ignores the deadline. A revocation queued behind an issuance on the same replica therefore waits as long as that issuance takes — `SaveRequest` holds the subject lock across an autosign signature, which has no bound of its own. Once that wait passes 60 seconds the revocation fails on every backend — never as a late success — but it fails in two different places, and the difference is visible in your monitoring. On PostgreSQL, MySQL, etcd and Redis it reaches its cross-node acquisition with the deadline already spent and is rejected there, before any CRL work: nothing is written and no counter moves. On SQLite and the filesystem — the default — there is no *cross-node* acquisition to reject it, so a wait behind another goroutine in this same process proceeds into the CRL work still carrying the spent deadline and fails on its first storage read instead. Nothing is written there either, but that failure *is* counted into `puppetca_crl_update_failures_total`, so on a single-node deployment a revocation that merely queued too long can fire `PuppetCACRLUpdateFailing`. The one exception is a wait for a *different process on the same host* — an `openvox-ca-ctl` command, a second server — which SQLite and the filesystem do now reject at acquisition like the others, uncounted, with an error naming the lock; see [running a second process against a live store](storage-backends.md#running-a-second-process-against-a-live-store). `openvox-ca-ctl` gives up after 30 seconds regardless, so treat a client-side timeout as *unknown* rather than failed. To settle it, ask the replica that served the request — `GET /certificate_status/{subject}` answers from the CRL the revocation would have amended — or simply repeat the revocation, which is a no-op if the first one landed. The logs settle only the failure direction (`Revoke failed`, a warning); a revocation that commits is logged at debug level, so it is silent at the default verbosity. Either way the answer is a bare `409 Conflict` with body `conflict`, which is **not** the CRL-provenance `409` described below and carries none of its remedy; retrying is always safe, because revoking a serial already on the CRL is a no-op. `POST /generate/{subject}` takes that same per-subject lock, so a revocation waits for a server-side key generation exactly as it waits for a signature, on every replica rather than only within one process. Close off issuance before revoking when you are containing an agent.

> **Note:** revoking amends this CA's own CRL, so it fails with `409 Conflict`
> when the stored CRL was not signed by the CA certificate this process loaded —
> re-signing it would destroy a list this CA cannot reproduce. The usual cause is
> a CA certificate replaced under a running process, since it is read once at
> startup; the response body names the cause and the remedy, which is to restart
> the replica holding the stale certificate. `PUT /certificate_revocation_list/ca`
> refuses the same state for the same reason.
>
> **`clean` is not symmetric with `revoke` here.** Clean's job is to remove the
> certificate, so a revocation that fails does not stop it: `DELETE
> /certificate_status/{subject}` and `PUT /clean` return success, delete the
> certificate, and leave it unrevoked and usable as a credential until it expires.
> In the `409` state above that means the whole revoke family does *not* fail
> closed — the `PUT` refuses, the `DELETE` succeeds. The revoke failure is logged
> at `WARN` ("stays a valid credential until it expires") and counted in
> `puppetca_crl_update_failures_total`, so
> [`PuppetCACRLUpdateFailing`](metrics.md#crl) fires. Recovering means restarting
> the stale replica and then revoking the certificate that was deleted but not
> revoked — `clean` cannot be repeated, because the certificate is no longer in
> storage. The inventory row outlives the delete, so
> `PUT /certificate_status/{subject}` still resolves to that serial and is enough
> on its own; [revocation by serial](#revocation-by-serial) is needed only once a
> replacement has been issued for the same name, which makes the by-subject
> lookup resolve to the replacement instead. That is common after a clean, since
> the agent re-enrols.
>
> In this state the `WARN` line names the serial. A revocation that failed
> *before* the CRL was reached — a lock it could not take, or a subject the
> inventory could not resolve — does not, and the serial has to come from the
> inventory instead.

`GET` response:

```json
{
  "name": "agent.example.com",
  "state": "signed",
  "fingerprint": "AA:BB:...",
  "fingerprints": { "SHA256": "AA:BB:...", "default": "AA:BB:..." },
  "dns_alt_names": ["agent.example.com"],
  "subject_alt_names": ["agent.example.com"],
  "authorization_extensions": {},
  "serial_number": 7329847239485029341,
  "not_before": "2025-01-01T00:00:00Z",
  "not_after": "2030-01-01T00:00:00Z"
}
```

> **Note:** `serial_number` is the low 64 bits of the certificate's cryptographically random 128-bit serial, returned as a signed int64 for API compatibility. It is omitted for certificates in the `requested` state.

### Revocation by serial

`PUT /certificate_status/{subject}` with `desired_state: revoked` revokes
whichever serial is *newest* for that subject. That is what an operator almost
always wants, but it leaves one state unreachable: a certificate that a later
issuance for the same subject displaced without retiring, and *without the CA
recording that it owes it a revocation*. Asking for the subject then revokes the
live replacement and leaves the superseded certificate valid — worse than doing
nothing.

A predecessor inside an overlap window is not in that state: it is on the
pending-supersession list, and revoking the subject retires everything of that
subject's the list names, in the same call. What stays unreachable is a
predecessor whose retirement was never recorded at all — an immediate-path
revoke that failed, or a supersession the CA could not write down.
`puppetca_supersede_failures_total` is what tells you one exists. `PUT /certificate_status_by_serial/{serial}` names the
certificate instead of the subject, so it can reach that one.

The serial is hexadecimal, in any case and with or without leading zeros; it is
matched against the inventory in canonical form — uppercase and unpadded, which
is how `openvox-ca` logs it. `openssl x509 -noout -serial` prints the same digits
zero-padded to whole bytes, a rendering this route accepts unchanged.

`PUT` body:

```json
{ "desired_state": "revoked", "force": false }
```

`desired_state` must be `revoked` — there is no by-serial signing operation, and
any other value is a `400` rather than a revocation. Responses:

| Status | Meaning |
| --- | --- |
| `204 No Content` | Revoked, or already revoked (repeating the call is a no-op) |
| `400 Bad Request` | The serial is not hexadecimal, or `desired_state` was not `revoked` |
| `404 Not Found` | No inventory entry carries that serial |
| `409 Conflict` | The serial is the certificate currently stored for its subject; the stored certificate could not be read, so that could not be determined; or the stored CRL was not signed by this process's CA certificate (see the note above). Each returns a body naming which, and what to do about it |
| `503 Service Unavailable` | The CA could not service the request — an inventory read (including an integrity failure), a CRL read/sign/write, or a lock it could not take. The cause is in the server log, not the response, because the message can name storage paths |

A `409` always carries a descriptive body. `"force": true` is the documented way
past the first two causes and **only** those two — not the foreign CRL, and not a
`503`; re-running with it would revoke without the live-certificate guard having
run.

Two refusals are deliberate:

- **A serial this CA has no record of issuing is refused, and `force` does not
  override it.** `CleanupExpiredCerts` drops CRL entries only for serials it
  finds in the inventory, so an entry admitted for an unknown serial could never
  be removed again — permanent growth in a document served to every agent.
- **The serial of the certificate currently stored for its subject is refused
  unless `force` is set.** That case is exactly what `PUT
  /certificate_status/{subject}` is for, so reaching it by serial is more likely
  a mistyped digit than an intent, and the cost of being wrong is a working node
  losing its credential. The `409` body names the subject and the by-name
  command. Set `"force": true` to revoke it anyway — the legitimate case is a
  compromise where the serial, not the name, is what you have.

  If the stored certificate cannot be read at all (corrupt, or an I/O failure),
  the request is refused for the same reason: the CA cannot show that the serial
  is *not* in circulation. That is a distinct `409` whose body says so and names
  the subject — the guard did not fire, it could not run, and the first thing to
  try is the request again once storage is healthy. `force` overrides this too,
  revoking with the guard never having run, and logs that it did.

## Certificate statuses (list)

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/certificate_statuses/{any}` | List all certificates; filter with `?state=requested\|signed\|revoked` |

## CSR management

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/certificate_request/{subject}` | Retrieve a pending CSR PEM |
| `PUT` | `/certificate_request/{subject}` | Submit a new CSR (body: raw PEM) |
| `DELETE` | `/certificate_request/{subject}` | Delete a pending CSR |

`PUT /certificate_request/{subject}` answers `200 OK` when the CSR is accepted —
whether it was autosigned immediately or queued for manual signing, and also
when a signed certificate already exists for the subject, which is a `200` so
that an agent continues its poll loop and collects the certificate by `GET`
rather than treating the submission as fatal. It answers `400 Bad Request` for a
CSR that cannot be decoded or parsed, whose signature does not verify, or whose
Common Name does not match the subject in the path. Those three are refused
whatever the autosign policy, because they are decided before it. A fourth is
not: a CSR requesting subject alternative names it may not have, which
[`allow_subject_alt_names`](configuration.md#subject-alternative-names-requested-by-a-csr)
governs, is refused here with `400` **only when the submission is autosigned**,
since that is the only case in which this endpoint signs anything. With manual
signing the CSR is accepted (`200`) and queued as usual, and the refusal
surfaces later — at `PUT /certificate_status` as a `409`, or in `POST /sign`'s
signing-errors list. An operator testing the setting with autosign off should
expect the `200`. That last refusal is deliberately generic — it names no entries, so a
caller on this unauthenticated endpoint cannot use it to discover which names
the CA would issue; the refused entries go to the CA's log at `WARN`. Anything
else is a `500`, whose message is withheld for the same reason — except a submission
refused by [`csr_rate_limit`](configuration.md), which answers `429 Too Many Requests` before the CSR is read at all.

`DELETE /certificate_request/{subject}` is an operator rejecting a request
rather than signing it, and it takes the same per-subject lock that `POST
/sign`, `PUT /certificate_request`'s autosign and [renewal](#certificate-renewal)
take. The rejection therefore orders against those issuances rather than racing
them, and both orderings are answers. Win the lock and the pending CSR is gone
before the sign looks for it, so the sign fails with nothing to sign. Lose it
and the CSR has usually been consumed already — signing removes it once the
certificate is stored — so the delete answers `404` with the certificate
issued. That removal is best-effort and only warns when it fails, so on a
storage fault there the delete removes the CSR instead and answers `204` for a
subject that already has a certificate. What the lock rules out is the case
that made this a bug: a `204` telling the operator the request was rejected
while a certificate was being issued for it.

The endpoint answers `400 Bad Request` for a subject that fails validation,
`404 Not Found` when there is no pending CSR for the subject, and `503 Service
Unavailable` when the deletion could not be carried out — a storage fault, or a
lock it could not take. The `404` and the `503` are deliberately different
answers: a `404` says the request is no longer queued, so reporting a failed
deletion as one would tell an operator their rejection had landed while the CSR
was still there and still signable. Nothing is deleted in any of the `503`
cases, so retrying is always safe.

The wait for that lock is bounded the way a revocation's is, which is to say
not uniformly.
The server's 60-second `lockTimeout` bounds only a wait for *another replica*,
because every backend serialises callers within one process on a lock that
ignores the deadline — so a delete queued behind an issuance on the same
replica waits as long as that issuance takes, and an autosigning `SaveRequest`
holds the subject lock across a signature that has no bound of its own. Note
too that the server's `WriteTimeout` is itself 60 seconds: a wait that exhausts
the lock budget reaches the response write with the connection's deadline
already spent, so expect a dropped connection rather than the `503` above. The
`DeleteRequest failed` line in the serving replica's log is the authoritative
record. To settle it from the outside, repeat the `DELETE` — it is a safe
retry, and its three answers distinguish all three outcomes. Do not reach for
`GET /certificate_request/{subject}`: that route reports a storage failure as
`404` as well, so it cannot tell "no longer queued" from "could not tell you",
which is the conflation this endpoint just stopped making.

## Certificate retrieval

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/certificate/{subject}` | Retrieve a signed certificate PEM (`ca` returns the CA cert) |

## Certificate renewal

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/certificate_renewal` | Renew an existing certificate; body: raw CSR PEM, or empty; returns new certificate PEM. Restricted to certificates this CA issued — see [renewal eligibility](#renewal-eligibility) |

Requires a valid CA-signed client certificate. The new certificate is issued immediately without entering the pending-CSR queue or autosign evaluation, and the certificate it replaces is retired once the new one is safely stored (see `revoke_on_auto_renew` below for the auto-renewal case). "Retired" means revoked before the response is returned, unless [`superseded_cert_revoke_after_sec`](configuration.md#delayed-supersession) grants an overlap window, in which case the replaced serial is recorded and a sweep revokes it once the window elapses — so both certificates verify for the length of the window, on this path including the replaced private key.

- **CSR body (re-key):** the CSR Common Name must match the authenticated client CN — an agent can only renew its own certificate, not another's. Issues a certificate for the new key in the CSR. Puppet OID extensions are copied from the CSR **except** authorization-arc OIDs (`1.3.6.1.4.1.34380.1.3.*`, such as `pp_cli_auth`), which are stripped so a submitted CSR cannot request elevated privileges.
- **Empty body (wire-compatible auto-renewal):** matches the request real OpenVox/Puppet agents send by default (`hostcert_renewal_interval`, and the `puppet ssl renew_cert` CLI action). Identity and key possession come solely from the mTLS-presented client certificate; the same public key is reissued with a fresh serial and validity, carrying forward the original certificate's SANs and Puppet OID extensions unchanged. Unlike the CSR path, this **preserves authorization-arc OIDs** (e.g. `pp_cli_auth`): they were already vetted when the presented certificate was issued, so a cert that legitimately holds them keeps them across renewal.

If the CA has not finished initialising, the request returns `503 Service Unavailable` (retry once it is ready).

If the presented certificate's (or CSR's) key falls below the CA key-strength policy — for example an RSA-1024 key imported from a legacy CA — the request is rejected with `422 Unprocessable Entity` rather than renewed; the agent must re-key via the CSR path with a compliant key.

A CSR-body renewal requesting a subject alternative name the presented certificate does not already carry is rejected with `400 Bad Request`, governed by [`allow_subject_alt_names`](configuration.md#subject-alternative-names-requested-by-a-csr). A renewal may keep the names its own certificate already holds — that is what stops the setting stranding the nodes it was enabled for — but it may not introduce new ones, so this is `400` rather than a server error: the request can never succeed as submitted and the agent should stop rather than retry. The refusal names no entries; they go to the CA's log at `WARN`. The empty-body path cannot reach this refusal at all, since it carries the presented certificate's SANs forward rather than reading any from a request.

If the presented certificate has been revoked, both paths reject the request with `403 Forbidden`. That check re-reads the CRL from storage rather than trusting the in-memory copy the mTLS layer uses, so it holds even on a replica that has not yet picked up a revocation performed elsewhere — renewal does not become a way out of a lockout during the propagation window.

It is also asked *again* once the per-subject lock is held, immediately before the replacement is issued. Acquiring that lock can wait behind an issuance already under way for the subject, and a revocation landing inside that window would otherwise be outrun: the first answer has already been given, and nothing between it and the signing looks again. Revoking takes the same lock, so a revocation cannot slip into the gap between the second answer and the issuance either — see [Certificate status](#certificate-status).

The re-read is best-effort in one direction: if the storage read itself fails, the check falls back to the CRL already in memory rather than refusing every renewal in the fleet over a storage blip. A renewal in that window is then bounded by the same propagation window as everything else, not by the stronger guarantee above. `puppetca_crl_sync_failures_total` counts those failures — see [metrics](metrics.md#crl). See also [Revocation across replicas](configuration.md#revocation-across-replicas).

`revoke_on_auto_renew` (env `PUPPET_CA_REVOKE_ON_AUTO_RENEW`, default `true`) controls whether the certificate replaced by an auto-renewal (empty body) is revoked. The default keeps only the newest serial per subject valid. Set to `false` to match OpenVox Server's own (Clojure) CA exactly, which leaves the replaced certificate valid — for the same key — until it naturally expires. This setting has no effect on the CSR-body (re-key) path, which always retires the certificate it replaces. It is a *whether*, not a *when*: [`superseded_cert_revoke_after_sec`](configuration.md#delayed-supersession) decides how long the replaced certificate stays valid first, on both paths, and with `revoke_on_auto_renew: false` the auto-renewal path records nothing at all rather than deferring anything.

> **CRL growth:** with the default `true`, every auto-renewal appends the retired serial to the CRL, and the entry stays there until the certificate expires. Entries are only pruned by the expired-certificate cleanup job, which is off by default — enable `enable_expired_cert_cleanup` to bound CRL size on busy CAs, and watch `puppetca_crl_revoked_certificates` to keep an eye on it. Revocation is best-effort (a failure never fails the renewal), and which counter sees a failure depends on which path retired the certificate. Retiring it *immediately* — the default, with no overlap window configured — puts a CRL that could not be read, re-signed or written into `puppetca_crl_update_failures_total`, so that counter catches most, but not all, of them: a CRL lock the renewal could not take is logged only. Retiring it *later*, with [`superseded_cert_revoke_after_sec`](configuration.md#delayed-supersession) set, puts every failure to record the supersession into `puppetca_supersede_failures_total` instead — the lock acquisition included, because a supersession that was never recorded is lost outright rather than merely missing from the CRL. See [delayed supersession](metrics.md#delayed-supersession). A superseded certificate left valid this way is reachable only by [revocation by serial](#revocation-by-serial): asking for its subject would revoke the replacement instead. See [Authorization tiers](#authorization-tiers) for the same distinction on the clean path.

### Renewal eligibility

The presented client certificate must be one **this CA** issued, must not be revoked, must not be one a previous renewal already superseded, and must be the certificate for the subject being renewed.

The revocation condition is reached in ordinary operation: the CA re-reads the CRL from storage before renewing, so a replica whose in-memory copy has not yet caught up — up to `crl_sync_interval_sec`, see [revocation across replicas](configuration.md#revocation-across-replicas) — admits the certificate at the middleware and then refuses it here, with `403 access denied`. That is what stops renewal being a way out of a lockout during the propagation window.

The supersession condition can only *refuse* where an overlap window is configured — nothing is ever recorded without one — and it is what keeps that window a grace period for relying parties rather than a reprieve for the credential. A superseded certificate is deliberately absent from the CRL, so the revocation check above cannot see it — and a renewal mints a fresh full-lifetime certificate. Without this condition the replaced credential could renew itself out of the window entirely, which on the re-key path means the *previous private key* doing it. A match, and an unparseable list, both answer `403 access denied`, like the revocation condition. A list that cannot be *read* fails closed too, but answers `500 internal server error`: the CA cannot determine the certificate's status, which is not an authorisation decision, and the same is true of the revocation check when its storage read fails. Note that this check runs on every renewal whatever `superseded_cert_revoke_after_sec` says — a store that cannot serve the pending-supersession key refuses renewals on a CA that never enabled a window, and raises `puppetca_supersede_failures_total`.

The issuer condition is reachable as soon as a `client_ca` entry is configured — see [trusting client certificates from another CA](configuration.md#trusting-client-certificates-from-another-ca). Renewal is scoped to domain zero, this CA's own: a foreign certificate authenticates and may hold admin authority in its own domain, but it has no standing to renew, because renewal reissues under our authority using the presented certificate's own subject, which is only safe for names we assigned. It is answered `403 certificate not eligible for renewal`. With no `client_ca` configured there is one trust domain and the condition stays unreachable, as it always was.

The subject condition cannot be reached from HTTP at all, because the handler derives the subject from the presented certificate; it guards future callers of the internal API.

## Bulk signing

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/sign` | Sign one or more CSRs; body: `{"certnames":["a","b"]}` |
| `POST` | `/sign/all` | Sign every pending CSR |

## Bulk clean

| Method | Path | Description |
| --- | --- | --- |
| `PUT` | `/clean` | Revoke + delete multiple certificates in bulk; body: `{"certnames":["a","b"]}` |

Response:

```json
{ "cleaned": ["a.example.com"], "not-found": ["missing.example.com"], "clean-errors": [] }
```

Each subject goes through the same path as `DELETE
/certificate_status/{subject}`, with the same best-effort revoke and deletes, so
`clean-errors` does not capture any of them: a subject whose revocation or
deletion failed is reported under `cleaned`. The CRL is the authority for what
was actually revoked — see [Authorization tiers](#authorization-tiers).

## CRL

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/certificate_revocation_list/ca` | Download the stored CRL PEM verbatim. When a CRL **chain** was imported (see `--crl-chain`) the response is that whole chain, this CA's own CRL first, so agents can perform full-chain revocation checking (Puppet's default `certificate_revocation = chain`). Ancestor CRLs are preserved across re-signing. This CA never *issues* them — it cannot re-sign another CA's list — but it will republish newer copies if [`crl_chain_file`](configuration.md#publishing-an-upstream-crl-chain) is configured; without it they stay as current as what was imported |
| `PUT` | `/certificate_revocation_list/ca` | Re-sign **this CA's own** CRL with a fresh validity window (preserves all revocations, and every ancestor block unless `crl_chain_file` is set — with it, that file decides which ancestors are published); admin-only. Returns the whole stored chain, this CA's own CRL first. Returns `409 Conflict` when the stored CRL was not signed by the CA certificate this process loaded — the usual cause is a replaced CA certificate on an unrestarted replica, and the response body names the remedy |

## Expirations

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/expirations` | CA cert and CRL expiry dates. The CRL date is **this CA's own CRL (block 0) only** — imported ancestor CRLs are not reflected, so an ancestor can be past its `nextUpdate` while this reports a comfortable date. See [metrics](metrics.md#crl) |

## Server-side key generation

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/generate/{subject}` | Generate key + cert server-side; optional `?dns=alt.name`. Key algorithm follows `--leaf-key-algo` / `--leaf-key-size` (default: RSA 2048) |

Response:

```json
{ "private_key": "-----BEGIN RSA PRIVATE KEY-----\n...", "certificate": "-----BEGIN CERTIFICATE-----\n..." }
```

This route serialises on the same per-subject lock as signing, so it can block
while another replica holds that lock.

It cannot issue a certificate carrying `pp_cli_auth` — see
[authorization tiers](#authorization-tiers) — and it needs a running server.
Neither is true of [`openvox-ca generate`](operator-cli.md#generate-minting-a-certificate-offline),
which mints against storage directly.

## Certificate import

| Method | Path | Description |
| --- | --- | --- |
| `PUT` | `/certificate/{subject}` | Import a certificate issued outside this CA's normal signing flow into the inventory; admin-only |

Shares its path with `GET /certificate/{subject}` (certificate retrieval, above) but is a distinct, admin-only operation. Request body: raw certificate PEM. `{subject}` must match the certificate's CN or one of its DNS Subject Alternative Names — this lets an operator import under a specific identity even when the certificate's SANs list several names.

This is for certificates that were signed by this CA's key but never went through `Sign`/`Generate` — most commonly certificates migrated from a legacy CA installation that shared this CA's key material. The certificate's signature must verify against this CA's certificate (a pure cryptographic check, so an already-expired certificate is still accepted for record-keeping); CA certificates (`IsCA: true`) are rejected — use `openvox-ca-ctl import` for CA bundle import instead (or `openvox-ca import-ca-cert` when the CA key is held by a provider, which `openvox-ca-ctl import` cannot reach — see [offline subcommands on the server binary](operator-cli.md#offline-subcommands-on-the-server-binary)).

Once imported, the certificate is tracked exactly like a normally-issued one: it appears in listings and status lookups, is cleaned up by the normal expiry sweep, and can be revoked via the usual `PUT /certificate_status/{subject}` (`desired_state: "revoked"`) mechanism.

Conflict handling, in priority order:

1. If the exact same certificate (same serial, byte-identical) is already the tracked certificate for the subject, the request succeeds as a no-op (`"imported": false` in the response).
2. Otherwise, if the certificate's serial number is already tracked anywhere in the inventory (under this subject or another), the request is rejected with `409 Conflict`.
3. Otherwise, if the subject already has an active (non-revoked) certificate, the request is rejected with `409 Conflict`. If the subject's existing certificate is revoked, it is evicted and the import proceeds.

Invalid certificates — malformed or multi-block PEM, a signature that does not chain to this CA, a CA certificate (`IsCA: true`), a subject that matches neither the CN nor any DNS SAN, a non-positive serial, or a bad validity window — are rejected with `400 Bad Request`. If the CA has not finished initialising, the request returns `503 Service Unavailable` (retry once it is ready).

Response:

```json
{ "subject": "legacy-node.example.com", "serial": "1A2B3C4D5E6F", "not_before": "2020-01-01T00:00:00Z", "not_after": "2025-01-01T00:00:00Z", "imported": true }
```

`serial` is uppercase hex (matching the inventory/CRL/OCSP convention), unlike the decimal `serial_number` field in certificate status responses (which is decimal only to preserve the full 128-bit value without int64 truncation — a constraint that doesn't apply to this string field).

## OCSP

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/ocsp` | RFC 6960 OCSP request; body is DER-encoded `OCSPRequest` |
| `GET` | `/ocsp/{request}` | RFC 6960 GET form; `{request}` is standard or URL-safe base64-encoded DER |

Both paths are also served under `/puppet-ca/v1/`. Responses are signed by the CA key directly (`Content-Type: application/ocsp-response`). The AIA extension is embedded in issued certificates when `--ocsp-url` is set; the endpoint answers either way.

A GET carries `Cache-Control: max-age=…, public` for a `good` or `revoked` answer to a nonce-free request, and `Cache-Control: no-store` otherwise. Two cases get `no-store`: a request carrying a nonce, since an RFC 8954 response answers that request and no other and so also bypasses the pre-signed cache; and an `unknown`, which additionally carries no `NextUpdate`, because a later inventory read can overturn it — see [OCSP status across replicas](configuration.md#ocsp-status-across-replicas). A POST carries no `Cache-Control` at all.

## Health probes

These endpoints are served at bare paths only (no `/puppet-ca/v1` prefix) and require no client certificate.

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/healthz/live` | Liveness probe: always `200` while the process is running |
| `GET` | `/healthz/ready` | Readiness probe: `200` once the CA is initialised, `503` before |
| `GET` | `/healthz/startup` | Startup probe: delegates to the readiness check |

Response body: `{"status":"ok"}` (200) or `{"status":"not_ready"}` (503).

## Authorization tiers

When mTLS is enabled (both `--tls-cert` and `--tls-key` set), each endpoint requires a minimum client certificate tier:

| Tier | Required client cert | Endpoints |
| --- | --- | --- |
| **Public** | None | `GET /healthz/*`, `GET /certificate/{subject}`, `GET /certificate_revocation_list/ca`, `PUT /certificate_request/{subject}`, `GET /expirations`, `POST /ocsp`, `GET /ocsp/{request}` |
| **Own client** | A cert **this CA** issued, with `clientAuth` EKU | `POST /certificate_renewal` — restricted to certificates this CA issued (see [renewal eligibility](#renewal-eligibility)); renewal reissues under our authority using that certificate's own subject, which is only safe for names we assigned. The empty-body path also carries that certificate's SANs and Puppet OID extensions forward unchanged; the CSR path takes Puppet OID extensions from the CSR and strips authorization-arc OIDs (see [Certificate renewal](#certificate-renewal)) |
| **Self or admin** | Cert CN matches path subject **and was issued by this CA**, OR cert is admin | `GET /certificate_request/{subject}` |
| **Admin** | Cert is admin (see below) | `GET /certificate_status/{subject}` (public with `--allow-public-status`), `PUT /certificate_status/{subject}`, `DELETE /certificate_status/{subject}`, `DELETE /certificate_request/{subject}`, `GET /certificate_statuses/*`, `POST /sign`, `POST /sign/all`, `POST /generate/{subject}`, `PUT /clean`, `PUT /certificate_revocation_list/ca`, `PUT /certificate/{subject}`, `PUT /certificate_status_by_serial/{serial}` |

Above the public tier, a presented certificate must also be **currently valid,
not revoked, and carry the `clientAuth` extended key usage**: an expired
certificate, one listed in the CRL, or one issued for `serverAuth` only is
refused at every tier above public — including `POST /certificate_renewal`, so
revoking an agent's certificate cuts off its access to every *authenticated*
endpoint, not merely its next renewal.

That is unconditional for certificates **this CA issued**. For a client from a
configured [`client_ca`](configuration.md#trusting-client-certificates-from-another-ca) domain, the
revocation half is governed by `client_revocation_policy`: the default
`require` refuses a client whose issuer has no currently valid CRL, `check`
consults whatever CRLs are loaded and admits the client when there are none, and
`skip` does not check at all. Under `skip` — and under `check` for an issuer
publishing no CRL — a foreign certificate its own issuer has revoked **is**
admitted above the public tier, including where its CN grants it admin.

The public tier is unaffected, because it examines no client certificate at
all. A revoked agent can still fetch the CA certificate and the CRL, read
`/expirations`, query OCSP, and submit a CSR to
`PUT /certificate_request/{subject}`.

**Neither form of revocation prevents re-enrolment under the same subject.**
Submitting a CSR evicts a revoked certificate for that subject (see
[Certificate import](#certificate-import) for the same rule on the import
path), so the difference between the two verbs is only *when* the stored
certificate goes away:

- `PUT /certificate_status/{subject}` with `{"desired_state":"revoked"}` adds
  the serial to the CRL and leaves the certificate in storage until a later CSR
  displaces it. Eviction reads the same per-process CRL cache as the admission
  check described below, so on the HA backends a peer that has not yet synced
  answers `200 OK` and silently discards the CSR instead — for at most
  `crl_sync_interval_sec`, see below.
- `DELETE /certificate_status/{subject}` revokes, then deletes the certificate
  and any pending request, all against shared storage, so no step depends on a
  replica's cache. All three are best-effort: each failure is logged and the
  handler carries on, and the endpoint answers `204` regardless — so a `204`
  records that the subject existed, not that it was revoked or removed. Since
  admission reads the CRL rather than storage, the dangerous combination is a
  delete whose revocation failed: the file is gone and the certificate still
  works. Confirm the serial in `GET /certificate_revocation_list/ca`; one that is
  missing there can still be retired. The inventory row outlives the delete, so
  `PUT /certificate_status/{subject}` still resolves to it and is enough on its
  own — unless a replacement has since been issued for the same subject, which
  makes it resolve to the replacement instead and leaves
  [revocation by serial](#revocation-by-serial) the only way back to the
  original. The
  server's `Clean: revoke failed`, `Clean: delete cert failed` and
  `Clean: delete CSR failed` warnings are the complete signal;
  `puppetca_crl_update_failures_total` covers most of the first — a CRL that
  could not be read, signed or written all count, as does an inventory read that
  *failed* while resolving the subject's serial — but not a revocation refused
  at a cross-node lock acquisition, which never reaches the CRL work, not a
  subject that was simply never issued, and not a failed delete at all.

Otherwise the next CSR is accepted: with autosign enabled it is signed at once
and the agent is back with a fresh, unrevoked certificate; with autosign off it
queues for manual signing. The CRL entry for the old serial persists in both
cases, so the old certificate stays refused — but that is not the same as
locking the *agent* out.

When containing a compromised agent, apply the levers that hold, in this order:

1. Close off issuance: disable autosign, or use an autosign policy that
   excludes the subject, and block the agent at the network layer.
2. Revoke the certificate.
3. Wait one sync interval, or force it. Each replica re-reads the stored CRL
   every `crl_sync_interval_sec` (60s by default) and installs it once it has
   advanced, so that interval is the worst case for a replica that did not
   perform the revocation — see [revocation across
   replicas](configuration.md#revocation-across-replicas). To not wait, force a
   re-sign against a replica's own address (`openvox-ca-ctl reissue-crl`, or
   `PUT /certificate_revocation_list/ca`); each call refreshes only the replica
   that serves it, so through a load balancer it refreshes whichever one the
   VIP picked.

   To confirm a given replica, ask that address. `GET
   /certificate_status/{subject}` reports `revoked` from the very cache the
   admission check reads, and an `/ocsp` query carrying a nonce (`openssl ocsp`
   sends one unless you pass `-no_nonce`) resolves status from it too; the
   `puppetca_crl_cached_number` gauge is the same answer as a number. Each is
   reliable only while issuance stays closed off, per step 1, since the status
   answer describes whatever certificate is in storage for that subject now.
   The status probe also needs that certificate to still be there, so it suits
   the `PUT` route: after a `DELETE` — what `openvox-ca-ctl clean` sends — every
   replica answers `404` and it distinguishes nothing, so record the serial
   beforehand and use OCSP or the gauge. OCSP answers `Unknown` — not
   `revoked` — for a serial a peer issued that this replica has not yet indexed,
   which the index sync bounds at `ocsp_index_sync_interval_sec` (5 minutes by
   default); see [OCSP status across
   replicas](configuration.md#ocsp-status-across-replicas). Send the nonce
   (`openssl ocsp` does unless you pass `-no_nonce`), because a nonce-free query
   may be answered from a response pre-signed up to four hours ago. That cache
   cannot contradict this replica's own CRL — every install of a new CRL drops
   the responses it revokes — but for a probe, a freshly signed answer is the
   one worth having. What cannot answer it at all is anything reading shared
   storage: `GET /certificate_revocation_list/ca`, `puppetca_crl_number` and
   `puppetca_crl_revoked_certificates` all read the same on a stale replica as
   on a fresh one.

The order matters. Step 3 is also what makes a stale replica willing to evict
the revoked certificate and issue a replacement, so letting the sync land while
autosign is still open hands whoever holds the compromised key a fresh, valid
certificate.

> **Revocation is not enforced cluster-wide instantly.** Every admission
> decision reads an in-memory copy of the CRL, not storage: the hot path of an
> authenticated request cannot afford a storage round trip. A revocation reaches
> shared storage at once and `GET /certificate_revocation_list/ca` serves it
> from there immediately, but the replica that performed it is the only one that
> rewrites its own copy on the spot. The rest pick it up on the
> `crl_sync_interval_sec` poll, which is what bounds the window — 60 seconds by
> default. Two things it does not cover: OCSP responses already handed out
> (signed with four hours of validity, and a client's cache cannot be recalled),
> and other live certificates the same subject already holds. Both are set out
> under [revocation across
> replicas](configuration.md#revocation-across-replicas).

In plain HTTP mode (no TLS), all endpoints are accessible without authentication:
the authorisation middleware is only installed when `--tls-cert`/`--tls-key`
(`tls_cert`/`tls_key` in the config file) are both set.

> **Note:** `GET /certificate_status/{subject}` is **admin-only**, matching Puppet Server's shipped `auth.conf`, which grants `certificate_status` and `certificate_statuses` to `pp_cli_auth` only. An ordinary agent certificate is refused with 403. Use `--allow-public-status` to make it public instead, for environments where bootstrapping agents need to poll status before obtaining a client certificate — note that this removes authentication from the route entirely rather than relaxing it to any client. The response exposes state, fingerprint, serial number, and authorization extensions. If tooling of yours read statuses with an agent certificate, see [Authorisation parity](migrating-from-puppet-server.md#authorisation-parity) for the ways to restore it and what each one grants.

### Admin credential resolution

A client certificate is considered an admin credential if **either** condition is met:

1. **CN allow list:** the certificate's Common Name appears in the `--puppet-server` comma-separated list or in the file pointed to by `--puppet-server-file` (one CN per line; `#` comments and blank lines ignored). Both sources can be used simultaneously; their CNs are merged.
2. **`pp_cli_auth` extension:** the certificate carries the Puppet authorization extension OID `1.3.6.1.4.1.34380.1.3.39` with the UTF8String value `"true"`. OpenVox Server embeds this extension in its own certificate by default, so the `puppetserver ca` CLI can authenticate without being listed by CN.

The `pp_cli_auth` check is enabled by default. Disable it with `--no-pp-cli-auth` (or `no_pp_cli_auth: true` in the config file) if you prefer strict CN-only authorization.

Both conditions are scoped to the **issuer** that signed the certificate. A CN means something only within the namespace of the CA that signed it, so `--puppet-server` and `pp_cli_auth` grant admin to certificates **this CA issued**. Certificates from another issuer are granted admin by **that entry's** `admin_cns` and `allow_pp_cli_auth` — *entry*, not certificate: where an entry's `file` bundles more than one anchor the grant spans all of them, which the server warns about at startup, so give each issuer its own entry — see [trusting client certificates from another CA](configuration.md#trusting-client-certificates-from-another-ca). With no `client_ca` configured there is one issuer and this distinction has no effect.

The CN allow list is not fixed for the life of the process: `SIGHUP` (or `systemctl reload`) rebuilds it from the current contents of `--puppet-server-file`, merged with the `--puppet-server` value the process started with, so CN-based admin access can be granted or withdrawn without a restart. The swap is atomic with respect to in-flight requests, and the CNs added or removed are named in the log. See [reloading configuration](configuration.md#reloading-configuration).

Two limits are worth knowing before relying on that to decommission a host. `--puppet-server` itself is frozen at startup — only the file is re-read — and condition 2 is untouched by a reload: a certificate carrying `pp_cli_auth=true`, which OpenVox Server issues to itself by default, remains an admin credential until it is revoked or the server is restarted with `--no-pp-cli-auth`. Revoking the certificate (`openvox-ca-ctl revoke`, or `PUT /certificate_status/{subject}` with `desired_state: revoked`) is the step that actually removes admin authority.

No *new* `pp_cli_auth` grant can be requested through this API: authorization-arc OIDs are stripped from submitted CSRs so that no request can ask for elevated privileges. Mint one offline with [`openvox-ca generate --pp-cli-auth`](operator-cli.md#administrator-credentials), which also documents what the grant covers and the three steps needed to withdraw it.

An existing holder can still obtain a *fresh certificate* carrying the grant, because empty-body auto-renewal preserves authorization-arc OIDs deliberately (see [Certificate renewal](#certificate-renewal) above). That is not an escalation — it requires already holding one — but it does mean a compromised admin credential can renew itself into a new serial and a new validity window, which is why withdrawing one is not simply a matter of waiting for it to expire.

> **OID source:** [`lib/puppet/ssl/oids.rb`](https://github.com/puppetlabs/puppet/blob/main/lib/puppet/ssl/oids.rb)
