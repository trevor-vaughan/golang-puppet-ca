# Running under systemd

`openvox-ca` speaks the systemd notification protocol ([`sd_notify(3)`](https://www.freedesktop.org/software/systemd/man/sd_notify.html)), so a unit can be `Type=notify` rather than `Type=simple`. That gives you four things:

- **`systemctl start` blocks until the CA is actually serving** — storage reachable, CA loaded (bootstrapped on a first run), listener accepting. Units ordered `After=openvox-ca.service` no longer race a cold start.
- **`systemctl status` says what the CA is doing**, both during startup and while it runs.
- **`systemctl reload` re-reads the TLS keypair and the admin allow list** without dropping connections.
- **An optional watchdog** restarts a CA that has stopped making progress.

None of it needs configuration. The protocol is driven entirely by `$NOTIFY_SOCKET`, which systemd sets; without it every notification is a no-op, so the same binary behaves normally under a shell, another supervisor, or in a container.

## Installing the unit

A ready-to-use unit ships in [`packaging/systemd/openvox-ca.service`](../packaging/systemd/openvox-ca.service) and in every [release tarball](../README.md#release-tarballs), alongside the two binaries. Download, verify and extract one as the README describes, then, from the extracted directory:

```console
$ sudo useradd --system --home-dir /var/lib/puppet-ca --shell /usr/sbin/nologin puppet-ca
$ sudo install -m 0755 openvox-ca openvox-ca-ctl /usr/local/bin/
$ sudo install -m 0644 openvox-ca.service /etc/systemd/system/
$ sudo install -d -m 0755 /etc/puppet-ca
$ sudoedit /etc/puppet-ca/config.yaml   # your own file; see configuration.md
$ sudo chown root:puppet-ca /etc/puppet-ca/config.yaml && sudo chmod 0640 /etc/puppet-ca/config.yaml
$ sudo systemctl daemon-reload
$ sudo systemctl enable --now openvox-ca.service
```

Building from source instead? `mage build:all` puts the binaries in `bin/` and the unit stays at `packaging/systemd/openvox-ca.service`; install from there.

The configuration file is yours to write — it is not in the tarball — and [configuring the server](configuration.md#config-file) has a worked example. Make it **0640 root:puppet-ca**, because it can hold credentials — `etcd_password`, or an inline OpenBao `role_id` — and the service only needs to read it. The server auto-detects that path, so the unit passes no `--config` and `PUPPET_CA_CONFIG` still works in a drop-in.

The unit expects the binary at `/usr/local/bin/openvox-ca` and its configuration at `/etc/puppet-ca/config.yaml`. See [configuring the server](configuration.md).

**Set `cadir` to `/var/lib/puppet-ca`** (the `StateDirectory=` the unit creates), or the CA will not be able to write: `ProtectSystem=strict` makes the rest of the filesystem read-only. To keep an existing directory instead — a CA migrated from OpenVox/Puppet Server usually lives in `/etc/puppetlabs/puppet/ssl/ca` — uncomment the `ReadWritePaths=` line in the unit and point it there.

### The two settings you must not drop

```ini
Type=notify
NotifyAccess=all
```

`NotifyAccess=all` is required, not optional hardening slack. In the default deployment `openvox-ca` runs as three processes — a launcher supervising an isolated signer that holds the CA key, and a frontend that serves the API (`--single-process` collapses them; see [CA key security](ca-key-security.md#process-isolation)) — and readiness is reported by the **frontend child**, because only it knows when the listener is accepting. systemd's default (`NotifyAccess=main`) accepts notifications only from the launcher, silently discards the frontend's, and the start job then fails on `TimeoutStartSec`.

The notification socket is withheld from the signer process, so it never notifies in normal operation. Treat that as hygiene rather than as an access control: `NotifyAccess=all` authorises every process in the unit's cgroup, and the socket path is well known, so the isolation is defence in depth — the residual cost of the multi-process design.

Running with `--single-process` collapses this to one process and `NotifyAccess=main` is then sufficient — but the shipped unit keeps `all` so it works either way.

### `--daemon` is for something else

Do not add `--daemon` to `ExecStart`. It forks and exits, which under `Type=notify` looks exactly like the service dying the moment it started. The CA logs a warning if you try. Running in the foreground is what a service manager wants; journald captures stderr.

## What the status text shows

During startup, each phase reports what it is waiting on — which is usually all you need to diagnose a start that hangs:

```console
$ systemctl status openvox-ca
     Active: activating (start) since Sat 2026-08-01 21:02:38 BST; 3s ago
     Status: "Waiting for the signer process to initialise the CA"
```

Once serving, the status summarises the listener, the CA certificate and the CRL:

```text
Status: "Serving HTTPS on 0.0.0.0:8140 | CA \"Puppet CA: puppet.example.com\" expires in 1824d | CRL #7 (3 revoked) expires in 29d"
```

It is refreshed on a timer, so the countdowns stay true. An elapsed deadline is spelled in capitals, so an expired CA certificate or a lapsed CRL is visible at a glance:

```text
Status: "Serving HTTPS on 0.0.0.0:8140 | CA \"Puppet CA: puppet.example.com\" expires in 1824d | CRL #7 (3 revoked) EXPIRED 2d ago"
```

Everything in the line is read from memory. Certificate counts are deliberately absent: that means listing the inventory in the storage backend, which is scrape-weight work and belongs in the [Prometheus exporter](metrics.md), not in a status line refreshed on a timer (every minute with no watchdog, or half `WatchdogSec=` when one is set — 45 seconds for the shipped unit).

## Reloading

`systemctl reload openvox-ca` re-reads the two file-backed inputs that can be swapped safely under live traffic:

| Input | Why it changes |
| --- | --- |
| `--tls-cert` / `--tls-key` | The CA's own server certificate expires like any other and has to be renewed |
| `--puppet-server-file` | A compile server is added, or a decommissioned one must stop being an admin |

`--puppet-server` itself is frozen at startup — reload re-reads only the file — and a certificate carrying `pp_cli_auth` stays an admin whatever the allow list says, so decommissioning a host means revoking its certificate too. See [admin credential resolution](api.md#admin-credential-resolution).

Connections in flight keep the certificate they negotiated with; the next TLS handshake picks up the new one. The allow list is swapped atomically with respect to in-flight requests: each request sees either the whole old list or the whole new one, and any CN that gained or lost admin rights is named in the log so the change is auditable.

Everything else — the listen address, the storage backend, CA key custody, CA properties, and which autosign configuration is in use — needs a restart. Those are bound to state established at startup, and re-reading them behind your back would be worse than telling you to restart. (The autosign allowlist or script, and the OpenBao AppRole credential files, are read live on every use and need neither a reload nor a restart.)

A reload that fails (a half-written certificate, a deleted allow-list file) leaves the previous configuration in place and the CA serving. The failure is logged and stays in the status text until a reload succeeds:

```text
Status: "Serving HTTPS on 0.0.0.0:8140 | ... | last reload FAILED, see the logs"
```

Check for that line after rotating a certificate. `systemctl reload` itself reports success either way — the notification protocol has no way to fail a reload without hanging the job.

### systemd 253 and later

The shipped unit uses `ExecReload=/bin/kill -HUP $MAINPID`, which works everywhere. On systemd 253+ you can instead drop `ExecReload` and use:

```ini
Type=notify-reload
```

systemd then sends `SIGHUP` itself and — because the CA stamps its reload acknowledgement with `MONOTONIC_USEC` — waits for the new configuration to be in effect before `systemctl reload` returns.

## Watchdog

```ini
WatchdogSec=90s
Restart=on-failure
```

The shipped unit uses 90 seconds, not 60: composing the status text takes the CA's read lock, and a storage operation holding the write lock is bounded by a 60-second cluster-lock timeout. An equal budget would leave no headroom between a slow backend and a kill.

The keep-alive is sent by the frontend process on a timer at half the configured interval — not by the launcher, which would only ever prove the supervisor was alive.

Be clear about what this does and does not catch. It stops arriving if the frontend dies outright, if the Go runtime deadlocks, or if the heartbeat goroutine itself stalls — which includes a storage operation wedged while holding the CA's write lock, since composing the status text takes the matching read lock. It keeps arriving quite happily if the API is unresponsive for a reason that leaves that goroutine scheduling normally, such as request handlers blocked on a read-only backend call. For genuine end-to-end liveness, point a probe at `/healthz/ready` as well; the watchdog is a backstop, not a health check.

Remove `WatchdogSec=` to disable it. Note that a watchdog restart is a hard kill: it does not drain in-flight requests, and a `WatchdogSec=` under 200ms is logged as too short to feed reliably. It is still fed at half the deadline down to 20ms. Below that the CA stops shortening the ticker at 10ms, which first costs the twice-per-interval margin `sd_watchdog_enabled(3)` recommends and, below about 10ms, stops beating the deadline at all — at which point the service manager kills the CA. That is the deliberate trade against spinning on a value nobody sets on purpose.

## Shutdown

On `SIGTERM` the CA reports `STOPPING=1` before draining, so a graceful shutdown is not mistaken for a crash, and the status names the budget:

```text
Status: "Shutting down: draining connections (up to 25s)"
```

`TimeoutStopSec` must exceed the drain budget (`shutdown_timeout_sec`, 25 seconds by default) plus the supervisor's 3-second headroom, or systemd will `SIGKILL` the CA part-way through the drain it asked for. The shipped unit uses 35 seconds. If you raise `shutdown_timeout_sec`, raise `TimeoutStopSec` with it — see [graceful shutdown](configuration.md#graceful-shutdown).

## Memory budget

`openvox-ca` runs as three processes under this unit, and `GOMEMLIMIT` is a
per-process knob, so the launcher treats one budget as belonging to the **whole
tree** and divides it between itself, the isolated signer and the frontend. A
`GOMEMLIMIT` set in the unit environment therefore caps the tree, not each
process.

With no `GOMEMLIMIT`, the launcher reads this unit's own cgroup v2 memory
ceiling, so a `MemoryMax=` in a drop-in is honoured:

```ini
[Service]
MemoryMax=512M
```

It claims 90% of that by default (`memory_budget_percent`), leaving headroom for
the memory the Go runtime does not account for. The shipped unit sets no
`MemoryMax=`, so out of the box nothing is derived and the runtimes are
unlimited, which is the right default for a host that is not memory-constrained.

The launcher and signer take fixed shares (`memory_reserve_launcher`,
`memory_reserve_signer`) and the frontend takes the remainder. The signer's share
does not grow with the ceiling, and it carries the Go runtime's own footprint
before any inventory, so a fleet beyond roughly 40,000 certificates should raise
`memory_reserve_signer` — raising `MemoryMax=` alone will not reach it. A
`MemoryMax=` set on a parent slice rather than on this unit is not derived
either, and `MemoryHigh=` is not read at all — only `memory.max` is consulted.
Set `MemoryMax=` on the unit itself, or set `GOMEMLIMIT` explicitly.

See [configuration](configuration.md#memory-budget).

## Hardening

The shipped unit runs the CA as a dedicated `puppet-ca` user with `ProtectSystem=strict`, an empty capability set (the API's port 8140 and the exporter's 9140 are both unprivileged), and a `@system-service` syscall filter. `RestrictAddressFamilies` includes `AF_UNIX`, which is needed for both the notification socket and the launcher's socketpair to the isolated signer.

`LimitCORE=0` is deliberate and worth keeping: the signer holds the decrypted CA private key in memory for its whole life, so a core dump would write that key to `/var/lib/systemd/coredump` — undoing [key encryption at rest](ca-key-security.md) for anything that ships crash dumps off the host.

`ProtectSystem=strict` is the directive most likely to bite: see [installing the unit](#installing-the-unit) for the `cadir` / `ReadWritePaths=` choice it forces. The same applies to `--logfile`, though logging to stderr and letting journald handle it is simpler.

Check your changes with:

```console
$ systemd-analyze security openvox-ca.service
```

## Verifying

```console
$ systemctl show openvox-ca -p Type,NotifyAccess,StatusText,WatchdogUSec,NRestarts
```

`StatusText` empty while the service is `active (running)` means notifications are not arriving — nearly always `NotifyAccess` left at its default. systemd logs a warning in that case:

```text
Got notification message from PID 1234, but reception only permitted for main PID
```
