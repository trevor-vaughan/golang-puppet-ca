# Running under systemd

`openvox-ca` speaks the systemd notification protocol ([`sd_notify(3)`](https://www.freedesktop.org/software/systemd/man/sd_notify.html)), so a unit can be `Type=notify` rather than `Type=simple`. That gives you four things:

- **`systemctl start` blocks until the CA is actually serving** — storage reachable, CA loaded (bootstrapped on a first run), listener accepting. Units ordered `After=openvox-ca.service` no longer race a cold start.
- **`systemctl status` says what the CA is doing**, both during startup and while it runs.
- **`systemctl reload` re-reads the TLS keypair and the admin allow list** without dropping connections.
- **An optional watchdog** restarts a CA that has stopped making progress.

None of it needs configuration. The protocol is driven entirely by `$NOTIFY_SOCKET`, which systemd sets; without it every notification is a no-op, so the same binary behaves normally under a shell, another supervisor, or in a container.

## Installing the unit

A ready-to-use unit ships in every [release tarball](../README.md#release-tarballs), alongside the two binaries.

The copy in the repository, [`packaging/systemd/openvox-ca.service`](../packaging/systemd/openvox-ca.service), is a **template** rather than an installable file: its `ExecStart` carries a placeholder that is substituted per channel, because a tarball is extracted by hand into `/usr/local` and a package owns `/usr/bin`. Building from source? `mage build:unit /usr/local/bin` renders it to `dist/openvox-ca.service`; `mage build:all` still puts the binaries in `bin/`.

Download, verify and extract a tarball as the README describes, then, from the extracted directory:

```console
$ sudo groupadd --system puppet
$ sudo useradd --system --gid puppet --home-dir /etc/puppetlabs/puppet --shell /usr/sbin/nologin puppet
$ sudo install -m 0755 openvox-ca openvox-ca-ctl /usr/local/bin/
$ sudo install -m 0644 openvox-ca.service /etc/systemd/system/
$ sudo install -d -m 0755 /etc/puppet-ca
$ sudoedit /etc/puppet-ca/config.yaml   # your own file; see configuration.md
$ sudo chown root:puppet /etc/puppet-ca/config.yaml && sudo chmod 0640 /etc/puppet-ca/config.yaml
$ sudo install -d -o puppet -g puppet -m 0770 /etc/puppetlabs/puppet/ssl/ca
$ sudo systemctl daemon-reload
$ sudo systemctl enable --now openvox-ca.service
```

The configuration file is yours to write — it is not in the tarball — and [configuring the server](configuration.md#config-file) has a worked example. Make it **0640 root:puppet**, because it can hold credentials — `etcd_password`, or an inline OpenBao `role_id` — and the service only needs to read it. The server auto-detects that path, so the unit passes no `--config` and `PUPPET_CA_CONFIG` still works in a drop-in.

The unit as rendered for a tarball expects the binary at `/usr/local/bin/openvox-ca` (the packages' copy names `/usr/bin`) and its configuration at `/etc/puppet-ca/config.yaml`. See [configuring the server](configuration.md).

**Set `cadir` to `/etc/puppetlabs/puppet/ssl/ca`**, which is the one writable path the unit grants (`ReadWritePaths=`), or the CA will not be able to write: `ProtectSystem=strict` makes the rest of the filesystem read-only, and a filesystem-backend CA has to write a signed certificate, a serial and a CRL. It is also the Clojure CA's own layout, so a CA migrated from OpenVox/Puppet Server is already there. To use a different directory, change `ReadWritePaths=` to match — the two must always name the same place.

### Why `puppet` and not a private account

OpenVox Server creates `puppet:puppet` in its own `preinst` and chowns `/etc/puppetlabs/puppet/ssl` to it, so the tree openvox-ca needs to write is already expected to be owned by that account: running as it fits rather than intrudes. openvox-agent creates no account at all and runs as root.

openvox-ca does not assume either is installed. The packages create the account themselves, and the recipe above does it by hand, because the CA has to work on a host running neither. Divergence is tolerable in one direction only: Server's `preinst` runs `usermod` over an account it finds, so installing Server afterwards repairs the home directory and shell to its own values rather than creating a second account.

**What sharing the account costs, stated plainly.** On a host that also runs OpenVox Server, the CA's private key is now readable by Server's own uid — the two are the same account. Anything running as `puppet` can read the key that signs every certificate in the estate, so a compromise of Server is a compromise of the CA on that host, without a privilege boundary in between.

It runs the other way too, and less obviously: **installing the package gives `/etc/puppetlabs/puppet/ssl` and `ssl/ca` to `puppet:puppet` even where an agent created that tree as root.** Write permission on a directory is what governs unlink and rename of the entries in it, so on such a host anything running as `puppet` — a compromised OpenVox Server included — can replace `crl.pem` or move `certs/` aside and substitute its own, and those are the trust anchors a root-running agent reads.

That is the price of fitting the layout Server already establishes, and it is worth knowing rather than discovering. Two things reduce it. [Encrypting the CA key at rest](ca-key-security.md) means the file alone is not enough. Better, a CA that matters should not share a host with the server it issues for — a dedicated CA host has no `puppet` account but its own, and the question does not arise.

A private `puppet-ca` account was the alternative and was rejected deliberately: it leaves `/etc/puppetlabs/puppet/ssl` owned by one account and written by another, which is a permissions problem an operator has to solve on every upgrade of either package.

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

## Hardening

The shipped unit runs the CA as the `puppet` user with `ProtectSystem=strict`, an empty capability set (the API's port 8140 and the exporter's 9140 are both unprivileged), and a `@system-service` syscall filter. `RestrictAddressFamilies` includes `AF_UNIX`, which is needed for both the notification socket and the launcher's socketpair to the isolated signer.

`LimitCORE=0` is deliberate and worth keeping: the signer holds the decrypted CA private key in memory for its whole life, so a core dump would write that key to `/var/lib/systemd/coredump` — undoing [key encryption at rest](ca-key-security.md) for anything that ships crash dumps off the host.

`ProtectSystem=strict` is the directive most likely to bite: see [installing the unit](#installing-the-unit) for the `cadir` / `ReadWritePaths=` choice it forces. The same applies to `--logfile`, though logging to stderr and letting journald handle it is simpler.

Check your changes with:

```console
$ systemd-analyze security openvox-ca.service
```

## Installing from a package

**Where the packages come from, first.** They are not published as release assets yet — `release.yml` has no packaging job, and adding one is [#266](https://github.com/voxpupuli/openvox-ca/pull/266). Until it lands, build them from a checkout:

```console
$ mage build:dist          # or build:distVariant per architecture
$ mage build:packages      # reads those tarballs; builds no binaries
```

They land in `dist/`, one `.deb` and one `.rpm` per non-FIPS architecture. A FIPS deployment uses the `_fips` tarball and the unit it ships; the packages carry the pure-Go build only.

Then install and start:

```console
$ sudo apt install ./openvox-ca_<version>_amd64.deb     # Debian, Ubuntu
$ sudo dnf install ./openvox-ca-<version>-1.x86_64.rpm  # RHEL, Rocky, Fedora
$ sudo systemctl enable --now openvox-ca
```

**`enable --now`, not `start`.** The package deliberately leaves `openvox-ca.service` disabled — an install is not consent to create a certificate authority — so `start` alone gives you a running CA that does not come back after a reboot. Enabling is the step that says yes.

The `.deb` and `.rpm` install the same unit, rendered for `/usr/bin`, and add a second one: `openvox-ca-first-boot.service`, a `Type=oneshot` that provisions the CA the first time you start the service.

It is pulled in by `openvox-ca.service` and runs nowhere else. There is no `WantedBy=multi-user.target` on it, so installing the package provisions nothing and neither does the next reboot — a CA is created the first time you run `systemctl start openvox-ca`. It is ordered `Before=openvox-ca.service` and is required by it, so provisioning that fails stops the service rather than letting it start against a half-provisioned directory.

**You do not have to write a configuration file first.** The package ships `/etc/puppet-ca/config.yaml` already set up: the CA directory, the serving certificate and key, and the port. Review it if you like — it is marked as a configuration file, so your edits survive upgrades — but a default install needs no edit to start.

Every step it takes is guarded on absence, so it **adopts rather than replaces**: nothing already on disk is overwritten, moved or re-signed. Running it twice does nothing the second time, and on a host that already has a CA it leaves that CA alone — but it does still fill in whatever is missing around it, which is what makes such an install produce a service that starts:

1. Create the `certs/`, `private_keys/` and `public_keys/` directories under `/etc/puppetlabs/puppet/ssl` if they are absent.
2. Bootstrap a CA in `/etc/puppetlabs/puppet/ssl/ca` unless one is already there.
3. Adopt this host's node certificate if `certs/$NAME.pem` and `private_keys/$NAME.pem` both exist; otherwise mint one.
4. Create `certs/ca.pem` and `crl.pem` in the ssl tree as symlinks pointing into the CA directory (`../ca/ca_crt.pem` and `ca/ca_crl.pem`), as Puppet's own layout does, if nothing is there already.
5. Link the serving credential the shipped configuration names — `certs/openvox-ca-server.pem` and `private_keys/openvox-ca-server.pem` — to the certificate step 3 produced.

Step 5 is what makes the service able to start at all: it binds `0.0.0.0` and refuses plain HTTP on a non-loopback address, so it needs `tls_cert` and `tls_key`. Those name fixed paths because a file shipped in a package cannot know this host's certificate name, and provisioning points them at the credential it just adopted or minted. Re-minting under a corrected name is then a matter of replacing those two links rather than editing configuration. Like every other step it is guarded on absence, so pointing `tls_cert` at your own certificate keeps it.

**Step 2 stops rather than bootstrap if it finds a CA at `/var/lib/puppet-ca`.**
That path is where an `openvox-ca` CA commonly lives — it is the Helm chart's
`persistence.mountPath` default, and a common choice for a hand-built install —
so provisioning checks it before creating anything. Finding a CA there and none
in `/etc/puppetlabs/puppet/ssl/ca`, it stops and says so, rather than
bootstrapping a second CA that every agent already enrolled against the first
would distrust. The message gives both ways out: point `cadir` and
`ReadWritePaths=` at the existing directory, or move the CA to the shipped one.
Which is right depends on what you set `cadir` to, and moving a CA is not a
copy — it takes the private key, the inventory and the CRL, and the service may
be running against it, which is why provisioning refuses rather than attempting
the move itself.

Step 3 is the one that can stop rather than warn, and it does so in two cases. If **one half of a credential** is present — a certificate with no key, or the reverse — it refuses to guess and says which file to move aside. If the binary has **no `generate` subcommand** it stops too, because a build that cannot mint leaves the service with no certificate to serve and `openvox-ca` refuses to start without TLS on a non-loopback address; failing here names the cause, where failing at the service would only report that TLS is not configured. In both cases the CA itself is bootstrapped and intact, and the message says so.

`$NAME` is resolved first-usable-wins: `OPENVOX_CA_CERTNAME` from a systemd drop-in, then `certname` from `/etc/puppetlabs/puppet/puppet.conf`, then `hostname -f` if it is dotted and not a localhost form, then the short hostname, then `localhost`. Every source is also checked against an allow-list of characters that cannot express a path, because the name is joined to one.

**Two names are reserved and provisioning refuses them: `ca` and `openvox-ca-server`.** Both are basenames this script maintains as aliases under `certs/` — `certs/ca.pem` is where every agent on this host looks for the CA certificate — so a node certificate written under either would take the alias's place and hold the wrong thing, with nothing to say so. `ca` is worth knowing about because it is not contrived: it is what the short-hostname tier yields for a host called `ca.example.com`. If this host is genuinely named that, set an explicit `certname` — the fully qualified name is the right answer where there is one. **The last two resolution tiers — the short hostname and `localhost` — are failure states that still produce a running CA**; both warn, naming what will not work and how to re-mint. (The two reserved names above are not among them: those stop provisioning outright, and because the oneshot is required by the service, the service does not start.) The `localhost` case also writes `/etc/puppetlabs/puppet/ssl/openvox-ca-certname-unresolved`, because a CA nothing can reach still looks healthy in `systemctl status` — but only when that run created the CA. On a takeover the marker would be describing a CA this run did not issue, and its recovery steps begin by deleting one.

A oneshot rather than a maintainer script because it runs under the same hardening directives as the service — apart from `ReadWritePaths=`, which covers the whole ssl tree rather than the CA directory alone, because it links `certs/ca.pem` and `crl.pem` above the CA directory — and because it fails visibly in `systemctl status` rather than in package-manager output nobody keeps.

It re-runs after the CA directory is wiped **on the next boot, or on an explicit `systemctl restart openvox-ca-first-boot`** — not on a restart of `openvox-ca` alone. `RemainAfterExit=yes` leaves it active once it has succeeded, and a requirement on an already-active unit does nothing.

**That `Requires=` edge runs both ways.** Stopping or restarting the oneshot stops or restarts `openvox-ca` with it, so `systemctl stop openvox-ca-first-boot` on a unit that has visibly finished its job takes the CA down.

**The mint step prints a warning, and on a first boot it is expected.** `openvox-ca generate` reports that the `filesystem` backend coordinates no writes across processes and says to stop the server before running it. That is the right warning in general and it is why this unit is ordered `Before=openvox-ca.service`: at the moment it runs there is no server to stop. Seeing it in `journalctl -u openvox-ca-first-boot` after a first boot is not a fault. Seeing it after starting the oneshot by hand on a **running** CA is — stop the service first.

**Installing also takes ownership of two directories.** The postinstall gives `/etc/puppetlabs/puppet/ssl` and `/etc/puppetlabs/puppet/ssl/ca` to `puppet:puppet` — not recursively, so their contents are left alone, and not following symlinks. On a host where openvox-agent created that tree as root, those two directories change owner when this package is installed. See [why `puppet`](#why-puppet-and-not-a-private-account) for what sharing the account costs.

### The packages listen on 8141

The binary's own default is 8140, and the packages ship `/etc/puppet-ca/config.yaml` setting `port: 8141`. The reason is collision, not preference: 8140 is right for a release tarball, a container and a host running nothing but the CA, but a *package* is what gets installed alongside OpenVox Server, and Server binds 8140 itself. So agents talking to a packaged CA are configured with `ca_port = 8141`.

The release tarballs are unaffected and stay on 8140 — they ship no configuration file at all.

It is set in the configuration file rather than as `--port` in the unit or `PUPPET_CA_PORT` in the environment, and that is deliberate: the server resolves the port as **file, then environment, then flag**, so a value in either of those would outrank the file and silently ignore an operator who edited it. A default has to sit at the layer an operator can override. Edit the file, and neither `apt upgrade` nor `dnf update` will overwrite you — it is marked as a configuration file in both formats.

### What removing the package does not do

Neither `apt remove` nor `dnf remove` deletes **the CA private key, anything else under `/etc/puppetlabs/puppet/ssl`, or the `puppet` account.** The service is stopped and disabled and the shipped files go; the CA's material stays exactly where it was.

That is deliberate. `/etc/puppetlabs/puppet/ssl` holds the key that signs every certificate in the estate, and the account may be shared with openvox-agent or OpenVox Server, so removing either could take an estate's trust root — or another product's account — with it on what an operator meant as an uninstall. `apt purge` does not change this: the tree is not registered as configuration.

The consequence worth knowing is the other one: **removing the package does not decommission the CA.** Reinstalling adopts the existing directory rather than provisioning a new one, and the key remains on disk and readable by anything running as `puppet` until someone deletes it. To actually retire a CA, remove `/etc/puppetlabs/puppet/ssl/ca` yourself, having first understood that every certificate it issued stops being verifiable.

The one file an upgrade will not overwrite is `/etc/puppet-ca/config.yaml`: it is marked as a configuration file in both formats, so your edits survive and a changed default arrives beside it as `.dpkg-dist` or `.rpmnew`.

### One instance per CA directory

The packages configure the `filesystem` storage backend, which coordinates no writes between hosts and cannot append to its inventory atomically. **Exactly one `openvox-ca` may run against a given CA directory.** Running two — on one host or two — can leave an integrity record covering a state that never existed, after which the server refuses to start.

That is also why provisioning is ordered before the service rather than beside it: the oneshot writes to storage directly, and doing so while a server is running would make it the second writer. Only a backend that reports distributed locking may run more than one instance; see [configuring the server](configuration.md).

## Verifying

```console
$ systemctl show openvox-ca -p Type,NotifyAccess,StatusText,WatchdogUSec,NRestarts
```

`StatusText` empty while the service is `active (running)` means notifications are not arriving — nearly always `NotifyAccess` left at its default. systemd logs a warning in that case:

```text
Got notification message from PID 1234, but reception only permitted for main PID
```
