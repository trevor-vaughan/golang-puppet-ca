# Configuring the server

This is the full configuration reference for the `openvox-ca` server. For the
operator CLI, see [operator CLI (`openvox-ca-ctl`)](operator-cli.md), which also
covers the offline subcommands that run on the `openvox-ca` binary itself
against this configuration — `csr` and `import-ca-cert`, for running under an
external root CA with any `ca_key_provider`, and `generate`, for minting a
certificate with no running server.

## Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--config` | `""` | Path to YAML config file (auto-detected at `/etc/puppet-ca/config.yaml`) |
| `--cadir` | `""` | CA storage directory (keys, certs, CSRs, CRL); required via flag, env, or config |
| `--host` | `0.0.0.0` | Listen address |
| `--port` | `8140` | Listen port |
| `--hostname` | `""` | CN suffix for a bootstrapped CA (`Puppet CA: <hostname>`); defaults to `puppet` when empty |
| `--autosign-config` | `""` | Autosign mode: `true`, `false`, or path to a file/executable |
| `--tls-cert` | `""` | Server TLS certificate PEM (enables HTTPS when set with `--tls-key`) |
| `--tls-key` | `""` | Server TLS private key PEM |
| `--puppet-server` | `""` | Comma-separated CNs granted admin API access (mTLS only) |
| `--puppet-server-file` | `""` | Path to a file of CNs granted admin API access (one per line; `#` comments and blank lines ignored) |
| `--client-revocation-policy` | `require` | Revocation checking for `client_ca` domains: `require`, `check` or `skip`. Scoped to foreign issuers; this CA always checks its own CRL. See [trusting client certificates from another CA](#trusting-client-certificates-from-another-ca). |
| `--no-pp-cli-auth` | `false` | Disable `pp_cli_auth` extension as an admin credential **for certificates this CA issued**; require CN allow list only. It does not reach `client_ca` entries, which each carry their own `allow_pp_cli_auth` and default to off — see [trusting client certificates from another CA](#trusting-client-certificates-from-another-ca) |
| `--no-tls-required` | `false` | Allow plain HTTP on non-loopback addresses; use only behind a trusted TLS proxy or in test environments |
| `--allow-public-status` | `false` | Allow unauthenticated `GET /certificate_status`; by default this endpoint is admin-only, matching Puppet Server's shipped `auth.conf`. "Admin" means an admin CN of the trust domain that verified the client, or `pp_cli_auth` where that domain honours it — see [trusting client certificates from another CA](#trusting-client-certificates-from-another-ca) |
| `--ocsp-url` | `""` | OCSP responder URL to embed in issued certificates |
| `--crl-url` | `""` | CRL distribution point URL to embed in issued certificates |
| `--metrics-listen` | `""` | Address for the Prometheus exporter (e.g. `127.0.0.1:9140`); empty disables it. See [metrics & monitoring](metrics.md) |
| `--encrypt-ca-key` | `false` | Encrypt the CA private key at rest (AES-256-GCM + Argon2id). See [CA key security](ca-key-security.md) |
| `--ca-key-passphrase-file` | `""` | Path to file containing the CA key passphrase (first line used) |
| `--csr-rate-limit` | `60` | Max CSR submissions per IP per minute on the public `PUT /certificate_request` endpoint (0 disables) |
| `--ca-signing-concurrency` | `max(4, GOMAXPROCS)` | Max concurrent CA-key signatures across issuance, CRL re-signing and the OCSP responder (0 disables the bound) |
| `--single-process` | `false` | Disable CA key isolation (run signer and frontend in a single process) |
| `--storage-backend` | `filesystem` | Storage backend for CA state: `filesystem`, `sqlite`, `postgres`, `mysql`, `etcd`, or `redis`. See [storage backends](storage-backends.md) |
| `--etcd-endpoints` | `""` | Comma-separated etcd endpoints (used when `--storage-backend etcd`) |
| `--etcd-key-prefix` | `/puppet-ca` | etcd key namespace for this CA |
| `--ca-cert-file` | `""` | Keep the CA certificate at this local path regardless of backend |
| `--ca-key-file` | `""` | Keep the CA private key at this local path regardless of backend |
| `--ca-key-provider` | `file` | CA private key custody: `file` (default) or `openbao` (OpenBao Transit key). See [OpenBao Transit-engine CA key](openbao-transit.md) for the full `--openbao-*` flag reference |
| `--daemon` | `false` | Fork to background (not recommended in containers; incompatible with the `Type=notify` systemd unit — see [running under systemd](systemd.md)). The single-instance check runs *before* the fork, so starting a second instance against a `filesystem` or `sqlite` store fails here with a non-zero exit rather than in a child whose output is discarded |
| `--logfile` | `""` | Write JSON logs to this file instead of stderr |
| `--verbosity` / `-v` | `0` | Verbosity: `0`=Info, `1`=Debug, `2`=Trace |
| `--version` | | Print the version and exit; includes commit metadata when built from a git checkout |

## Precedence

All flags can be set via a YAML config file or environment variables. Precedence
(highest → lowest): **CLI flag** → **environment variable** → **config file** → **built-in default**.

Key generation and CA subject options are intentionally **not** exposed as CLI flags. They are one-time bootstrap decisions that belong in a config file or environment variable. Use the config file or `PUPPET_CA_CA_KEY_ALGO` / `PUPPET_CA_CA_SUBJECT_*` env vars to set them.

The config file is located by checking, in order:

1. `--config /path/to/config.yaml` (explicit flag)
2. `PUPPET_CA_CONFIG` environment variable
3. `/etc/puppet-ca/config.yaml` (auto-detected if the file exists)

## Config file

**Example `/etc/puppet-ca/config.yaml`:**

```yaml
cadir: /etc/puppetlabs/puppet/ssl/ca
host: 0.0.0.0
port: 8140
hostname: puppet.example.com
# A serving certificate issued by this CA — not the CA's own ca_crt.pem and
# ca_key.pem, which cannot serve TLS. See "Serving certificate" below.
tls_cert: /etc/puppetlabs/puppet/ssl/ca/signed/puppet.example.com.pem
tls_key:  /etc/puppetlabs/puppet/ssl/ca/private/puppet.example.com_key.pem
puppet_server: puppet.example.com
puppet_server_file: ""
no_pp_cli_auth: false
no_tls_required: false
allow_public_status: false  # set true to allow unauthenticated GET /certificate_status
                            # (otherwise admin-only: an admin CN of the matched
                            # trust domain, or pp_cli_auth where that domain
                            # honours it)
client_ca: []               # additional client issuers; see "Trusting client certificates from another CA"
client_revocation_policy: require   # require | check | skip (client_ca entries only)
client_crl_refresh_interval_sec: 0  # how often each entry's crl_file is re-read; 0 = built-in default (1h)
autosign_config: ""
logfile: ""
verbosity: 0
ocsp_url: ""
crl_url: ""
shutdown_timeout_sec: 0  # graceful HTTP-drain budget on SIGTERM; 0 = built-in default (25s)
# Key generation options (applied only when bootstrapping a new CA or generating leaf certs).
ca_key_algo: ""       # "rsa" (default) or "ecdsa"
ca_key_size: 0        # RSA: 2048/3072/4096 (default 4096); ECDSA: 256/384/521 (default 256)
leaf_key_algo: ""     # "rsa" (default) or "ecdsa"
leaf_key_size: 0      # RSA: 2048/3072/4096 (default 2048); ECDSA: 256/384/521 (default 256)
# CA certificate subject fields (applied only when bootstrapping a new CA).
ca_subject_org: ""
ca_subject_ou: ""
ca_subject_country: ""
ca_subject_locality: ""
ca_subject_province: ""
# Validity and path length.
# ca_* apply only when bootstrapping a new CA.
# leaf_validity_days and crl_validity_days apply on every signing / revocation operation.
ca_path_length: -1    # -1 = unconstrained, 0 = leaf certs only, N = N levels of intermediates
ca_validity_days: 0   # 0 = built-in default (~5 years); positive integer overrides
leaf_validity_days: 0 # 0 = built-in default (~5 years); positive integer overrides
promote_cn_to_san: true # add the CN as a DNS SAN when a CSR carries none (RFC 2818)
allow_subject_alt_names: false # let a CSR request SANs of its own; see "Subject alternative names requested by a CSR"
crl_validity_days: 0  # 0 = built-in default (30 days); positive integer overrides
csr_rate_limit: 60    # max CSR submissions per IP per minute; 0 = disable rate limiting
# Caps concurrent CA-key signatures across issuance, CRL re-signing and the OCSP
# responder together. Unset uses max(4, GOMAXPROCS); 0 disables the bound.
# Lower it to a remote signer's capacity — see "Bounding CA-key signing" below.
ca_signing_concurrency: -1     # -1/unset = max(4, GOMAXPROCS); 0 = unbounded
# Background CRL refresh keeps the CRL's NextUpdate from lapsing on a low-churn CA.
# Safe to run on every replica (serialised on the shared CRL lock).
disable_crl_refresh: false     # true = never auto-refresh the CRL
crl_refresh_interval_sec: 0    # how often to check; 0 = built-in default (1h)
crl_refresh_before_sec: 0      # re-sign when remaining validity < this; 0 = crl_validity/3
# Background CRL sync reloads the stored CRL into the copy this replica's
# revocation checks read, so a revocation performed on another replica takes
# effect here. Read-only, runs on every replica, and is not covered by
# disable_crl_refresh. See "Revocation across replicas" below.
crl_sync_interval_sec: 0       # how often to reload; 0 = built-in default (60s)
# A PEM bundle of upstream CRLs published alongside this CA's own, for agents
# doing full-chain revocation checking. Verified against the stored CA bundle,
# and re-read by the crl-chain-refresh background job.
crl_chain_file: ""
crl_chain_refresh_interval_sec: 0  # how often to re-read it; 0 = built-in default (1h)
# Background OCSP index sync reloads the inventory into the serial index this
# replica's OCSP responder answers from, so a certificate signed on another
# replica stops being reported as "unknown". Read-only; runs on the shared
# backends only, since nothing else can be writing certificates on filesystem
# or sqlite. See "OCSP status across replicas" below.
ocsp_index_sync_interval_sec: 0  # how often to reload; 0 = built-in default (5m)
# Background expired-certificate cleanup (opt-in). When enabled, a job removes
# certificates that expired more than the retention grace period ago from the
# inventory and the CRL, and deletes their stored signed certificate. Safe to run
# on every replica (serialised on the shared CRL lock).
enable_expired_cert_cleanup: false       # true = run the cleanup job
expired_cert_retention_sec: 0            # grace period after a cert's NotAfter before removal; 0 = built-in default (30d)
expired_cert_cleanup_interval_sec: 0     # how often to run; 0 = built-in default (24h)
# CA key encryption at rest.
encrypt_ca_key: false           # encrypt the CA private key (AES-256-GCM + Argon2id)
ca_key_passphrase_file: ""      # path to passphrase file; auto-generated if omitted
# Date/time format in JSON responses.
puppet_datetime_format: false   # use Puppet CA style "2006-01-02T15:04:05MST" instead of RFC 3339
# Certificate auto-renewal (empty-body POST /certificate_renewal).
revoke_on_auto_renew: true      # false matches OpenVox Server's Clojure CA (no revocation on auto-renewal)
# Delayed supersession. A renewal records the certificate it replaced and a sweep
# revokes it once the overlap window elapses, so both verify in the meantime and
# relying parties can pick up the replacement without a gap. The window is a
# deliberate weakening and it is on by default — read "Delayed supersession"
# below, and set 0 for the earlier behaviour of revoking inside the call.
superseded_cert_revoke_after_sec: -1   # overlap window; 0 = revoke inside the renewal; -1/unset = 24h
superseded_cert_sweep_interval_sec: 0  # how often the sweep runs; 0 = built-in default (15m)
```

## Environment variables

Environment variables mirror the CLI flags:

| Flag | Environment variable |
| --- | --- |
| `--cadir` | `PUPPET_CA_CADIR` |
| `--autosign-config` | `PUPPET_CA_AUTOSIGN_CONFIG` |
| `--host` | `PUPPET_CA_HOST` |
| `--port` | `PUPPET_CA_PORT` |
| `--hostname` | `PUPPET_CA_HOSTNAME` |
| `--verbosity` | `PUPPET_CA_VERBOSITY` |
| `--logfile` | `PUPPET_CA_LOGFILE` |
| `--tls-cert` | `PUPPET_CA_TLS_CERT` |
| `--tls-key` | `PUPPET_CA_TLS_KEY` |
| `--puppet-server` | `PUPPET_CA_PUPPET_SERVER` |
| `--puppet-server-file` | `PUPPET_CA_PUPPET_SERVER_FILE` |
| `--client-revocation-policy` | `PUPPET_CA_CLIENT_REVOCATION_POLICY` |
| `--no-pp-cli-auth` | `PUPPET_CA_NO_PP_CLI_AUTH` |
| `--no-tls-required` | `PUPPET_CA_NO_TLS_REQUIRED` |
| `--allow-public-status` | `PUPPET_CA_ALLOW_PUBLIC_STATUS` |
| `--ocsp-url` | `PUPPET_CA_OCSP_URL` |
| `--crl-url` | `PUPPET_CA_CRL_URL` |
| `--metrics-listen` | `PUPPET_CA_METRICS_LISTEN` |
| `--csr-rate-limit` | `PUPPET_CA_CSR_RATE_LIMIT` |
| `--ca-signing-concurrency` | `PUPPET_CA_SIGNING_CONCURRENCY` |
| `--encrypt-ca-key` | `PUPPET_CA_ENCRYPT_CA_KEY` |
| `--ca-key-passphrase-file` | `PUPPET_CA_KEY_PASSPHRASE_FILE` |
| `--storage-backend` | `PUPPET_CA_STORAGE_BACKEND` |
| `--etcd-endpoints` | `PUPPET_CA_ETCD_ENDPOINTS` |
| `--etcd-key-prefix` | `PUPPET_CA_ETCD_KEY_PREFIX` |
| `--ca-cert-file` | `PUPPET_CA_CA_CERT_FILE` |
| `--ca-key-file` | `PUPPET_CA_CA_KEY_FILE` |
| `--ca-key-provider` | `PUPPET_CA_CA_KEY_PROVIDER` |
| `--openbao-addr` | `PUPPET_CA_OPENBAO_ADDR` |
| `--openbao-transit-mount` | `PUPPET_CA_OPENBAO_TRANSIT_MOUNT` |
| `--openbao-key-name` | `PUPPET_CA_OPENBAO_KEY_NAME` |
| `--openbao-auth-method` | `PUPPET_CA_OPENBAO_AUTH_METHOD` |

The full `--openbao-*` flag/environment-variable reference (TLS, AppRole, token-file, and
Kubernetes auth settings) is in [OpenBao Transit-engine CA key](openbao-transit.md#configuration).
Storage-backend environment variables are documented per backend in
[storage backends](storage-backends.md).

The CA key passphrase can also be provided via `PUPPET_CA_KEY_PASSPHRASE` (env var only, no CLI flag to avoid `/proc/cmdline` exposure).

**Config file / env var only, no CLI flag:**

| Config key | Environment variable |
| --- | --- |
| `client_crl_refresh_interval_sec` | `PUPPET_CA_CLIENT_CRL_REFRESH_INTERVAL_SEC` |
| `ca_key_algo` | `PUPPET_CA_CA_KEY_ALGO` |
| `ca_key_size` | `PUPPET_CA_CA_KEY_SIZE` |
| `leaf_key_algo` | `PUPPET_CA_LEAF_KEY_ALGO` |
| `leaf_key_size` | `PUPPET_CA_LEAF_KEY_SIZE` |
| `ca_subject_org` | `PUPPET_CA_CA_SUBJECT_ORG` |
| `ca_subject_ou` | `PUPPET_CA_CA_SUBJECT_OU` |
| `ca_subject_country` | `PUPPET_CA_CA_SUBJECT_COUNTRY` |
| `ca_subject_locality` | `PUPPET_CA_CA_SUBJECT_LOCALITY` |
| `ca_subject_province` | `PUPPET_CA_CA_SUBJECT_PROVINCE` |
| `ca_path_length` | `PUPPET_CA_CA_PATH_LENGTH` |
| `ca_validity_days` | `PUPPET_CA_CA_VALIDITY_DAYS` |
| `leaf_validity_days` | `PUPPET_CA_LEAF_VALIDITY_DAYS` |
| `promote_cn_to_san` | `PUPPET_CA_PROMOTE_CN_TO_SAN` |
| `allow_subject_alt_names` | `PUPPET_CA_ALLOW_SUBJECT_ALT_NAMES` |
| `crl_validity_days` | `PUPPET_CA_CRL_VALIDITY_DAYS` |
| `disable_crl_refresh` | `PUPPET_CA_DISABLE_CRL_REFRESH` |
| `crl_refresh_interval_sec` | `PUPPET_CA_CRL_REFRESH_INTERVAL_SEC` |
| `crl_refresh_before_sec` | `PUPPET_CA_CRL_REFRESH_BEFORE_SEC` |
| `crl_sync_interval_sec` | `PUPPET_CA_CRL_SYNC_INTERVAL_SEC` |
| `crl_chain_file` | `PUPPET_CA_CRL_CHAIN_FILE` |
| `crl_chain_refresh_interval_sec` | `PUPPET_CA_CRL_CHAIN_REFRESH_INTERVAL_SEC` |
| `ocsp_index_sync_interval_sec` | `PUPPET_CA_OCSP_INDEX_SYNC_INTERVAL_SEC` |
| `enable_expired_cert_cleanup` | `PUPPET_CA_ENABLE_EXPIRED_CERT_CLEANUP` |
| `expired_cert_retention_sec` | `PUPPET_CA_EXPIRED_CERT_RETENTION_SEC` |
| `expired_cert_cleanup_interval_sec` | `PUPPET_CA_EXPIRED_CERT_CLEANUP_INTERVAL_SEC` |
| `shutdown_timeout_sec` | `PUPPET_CA_SHUTDOWN_TIMEOUT_SEC` |
| `etcd_username` | `PUPPET_CA_ETCD_USERNAME` |
| `etcd_password` | `PUPPET_CA_ETCD_PASSWORD` |
| `etcd_dial_timeout_sec` | `PUPPET_CA_ETCD_DIAL_TIMEOUT_SEC` |
| `etcd_request_timeout_sec` | `PUPPET_CA_ETCD_REQUEST_TIMEOUT_SEC` |
| `etcd_tls_ca_file` | `PUPPET_CA_ETCD_TLS_CA_FILE` |
| `etcd_tls_cert_file` | `PUPPET_CA_ETCD_TLS_CERT_FILE` |
| `etcd_tls_key_file` | `PUPPET_CA_ETCD_TLS_KEY_FILE` |
| `puppet_datetime_format` | `PUPPET_CA_PUPPET_DATETIME_FORMAT` |
| `revoke_on_auto_renew` | `PUPPET_CA_REVOKE_ON_AUTO_RENEW` |
| `superseded_cert_revoke_after_sec` | `PUPPET_CA_SUPERSEDED_CERT_REVOKE_AFTER_SEC` |
| `superseded_cert_sweep_interval_sec` | `PUPPET_CA_SUPERSEDED_CERT_SWEEP_INTERVAL_SEC` |

> **Note:** `--daemon` is intentionally excluded from config file and environment
> variable support because `PUPPET_CA_DAEMON` is used internally as the daemon fork
> signal.

Boolean env vars accept any value accepted by `strconv.ParseBool`: `1`, `t`, `true`,
`yes`, `on` (case-insensitive) to enable; `0`, `f`, `false`, `no`, `off` to disable.

## Serving certificate

`tls_cert` and `tls_key` name a **serving certificate issued by this CA**, not
the CA's own `ca_crt.pem` and `ca_key.pem`. The CA certificate exists to sign
other certificates, not to identify a server: its `keyUsage` is
`certSign, cRLSign` — neither of the two bits a TLS server needs — and it has
no `subjectAltName`. Pointed at it, the CA starts, logs `TLS enabled`, and
completes the handshake, and then every client that verifies the certificate
rejects it:

```console
$ openssl s_client -connect puppet.example.com:8140 -CAfile ca_crt.pem -verify_hostname puppet.example.com
verify error:num=26:unsuitable certificate purpose
verify error:num=62:hostname mismatch
```

`hostname` does not repair this. It only names a CA at bootstrap, so on a CA
that already exists it changes nothing at all, and even at bootstrap it sets
the subject and adds no SAN — and clients have matched SANs rather than the
common name for years.

### Issuing one

`generate` needs a running server, so the first serving certificate is issued
against this CA started temporarily on loopback with TLS switched off. Stop the
service first if one is already running on port 8140, then:

```bash
# Your configured cadir. The CA writes the serving key under it, and pointing
# --out-dir at the same place keeps a second copy from being left elsewhere.
# The systemd unit's default is /var/lib/puppet-ca, not the path below.
CADIR=/etc/puppetlabs/puppet/ssl/ca

openvox-ca --tls-cert= --tls-key= --host 127.0.0.1 --port 8140 &
PCA_PID=$!

# Poll rather than sleep: bootstrapping a cold cadir generates an RSA-4096 key
# first, which is not a fixed-length wait on a slow or entropy-starved machine.
# 300s matches the TimeoutStartSec the shipped systemd unit allows for it.
for _ in $(seq 1 300); do
  curl -sf http://127.0.0.1:8140/puppet-ca/v1/certificate/ca >/dev/null && break
  sleep 1
done
curl -sf http://127.0.0.1:8140/puppet-ca/v1/certificate/ca >/dev/null || {
  echo "the CA did not become ready" >&2; kill $PCA_PID; exit 1; }

openvox-ca-ctl generate \
  --server-url http://127.0.0.1:8140 \
  --certname   puppet.example.com \
  --dns        puppet.example.com \
  --out-dir    "$CADIR/private"

kill $PCA_PID; wait $PCA_PID 2>/dev/null
```

Empty `--tls-cert=` and `--tls-key=` override the config file for this one
start, and switching TLS off is all they do — every other setting stays in
force, which matters more than it looks.

> **Warning:** do not reach for `--config /dev/null` here. It switches TLS off
> too, but it discards `storage_backend`, `sql_dsn` and `ca_key_provider` along
> with everything else. On any backend other than `filesystem` the temporary CA
> then finds nothing under `cadir` and **bootstraps a second CA**, with the same
> subject as the real one and no warning that it has done so. The serving
> certificate would be issued by that impostor, every agent would reject it, and
> a stray signing key would be left in `cadir`.

If you are not using a config file at all, pass `--cadir` (and, on a cold
`cadir`, `--hostname` — it is the CN *suffix* a CA is bootstrapped with, once
and permanently, giving `CN=Puppet CA: <hostname>` and defaulting to `puppet`)
plus whatever storage flags the deployment uses. `--dns` is passed explicitly
so the result does not depend on `promote_cn_to_san`, which promotes the CN to
a SAN and is on by default but can be turned off.

### After it is issued

The CA writes the private key to `<cadir>/private/puppet.example.com_key.pem`
on **every** backend: server-generated per-subject keys always go to local disk
and never to the configured store (see [storage
backends](storage-backends.md)), so a CA on Postgres or etcd still keeps a copy
of its serving key on its own filesystem — worth knowing when deciding what to
back up and what to protect. `openvox-ca-ctl` saves its own copy into
`--out-dir`, which is why the command above points that at the same directory:
it lands on the file the CA just wrote, with the same contents, instead of
leaving a second private key somewhere else. That is also why `CADIR` has to
match the `cadir` the server is actually using — `openvox-ca-ctl` does not
create the directory, and it writes the key only after the certificate has been
issued, so a wrong path fails late and needs `clean --certname` before a retry.
Left at its default, `--out-dir` writes into the current working directory.

Only the certificate depends on the backend. It is printed on stdout, and with
the **filesystem** backend the CA also keeps it at
`<cadir>/signed/puppet.example.com.pem` — so there both paths in the example
config already exist, and `tls_cert`/`tls_key` can be set and the service
started. On any other backend the certificate is in the store rather than on
disk, so capture what `generate` prints, put it somewhere the service can read,
and point `tls_cert` at that before starting.

> **Note:** capture it somewhere other than `<cadir>/signed/`. A shell
> redirection creates the file before the request is made, the CA reads that
> as a certificate already issued for the name, and `generate` fails with
> `certificate already exists` — which is also what a second run for the same
> name gets. Use `openvox-ca-ctl clean --certname` first to reissue.

While TLS is off, the whole admin API is unauthenticated: the authorisation
middleware is only installed when `tls_cert` and `tls_key` are both set. So
`--host 127.0.0.1` is not decoration — treat it as required, and keep the
window short. On an ordinary configuration the server would refuse to serve
plain HTTP off loopback anyway, so forgetting it fails safe. On one carrying
`no_tls_required: true` — the documented setup behind a TLS-terminating proxy —
that refusal is already switched off, and so is the block on handing a private
key over plain HTTP. There, the loopback bind is the only thing standing
between an unauthenticated `POST /generate/<subject>` and every interface on
the host.

[Migrating from Puppet
Server](migrating-from-puppet-server.md#step-7-start-openvox-ca) mints a
serving certificate for the CA at Step 7 as well, in a context where no
configuration file exists yet — so it passes `--cadir` explicitly rather than
relying on one.

The block above assumes a shell that owns the CA process, which is not how the
two production deployments in these docs work:

- Under [systemd](systemd.md) the unit is already bound to 8140, so stop it
  first. It also runs as a dedicated user, so run both commands as that user
  rather than under plain `sudo` — `sudo -u puppet-ca openvox-ca --tls-cert=
  ...`. Anything created as `root` is left behind for a service that is not
  root: directories most of all, since they are created `0750` and the service
  then cannot write in them at all, and the private key, which is written
  directly at `0600` and would simply be unreadable. Note that running the CA
  by hand this way gets none of the unit's hardening — including the `LimitCORE=0`
  that keeps a crash from writing the decrypted CA key into a core dump — so
  keep it to the length of this procedure.
- Under Kubernetes it does not apply: the chart takes the serving certificate
  from a Secret — see [Helm chart](helm-chart.md).

### When the certificate cannot serve

A serving certificate is not checked by the TLS stack that presents it, so a
wrong one is silent on this side and fatal on the other. The server therefore
inspects the keypair itself, at startup and on every reload, and warns rather
than refusing — a CA that will not start is worse than one agents distrust,
since the CRL and the public endpoints keep working either way:

```text
level=WARN msg="The TLS certificate just loaded cannot serve TLS to a client that verifies it; issue a serving certificate with `openvox-ca-ctl generate` and point tls_cert/tls_key at that" cert=/etc/puppetlabs/puppet/ssl/ca/ca_crt.pem subject="Puppet CA: puppet.example.com" problems="it has no subjectAltName, and clients match the hostname against SANs only; its keyUsage allows neither digitalSignature nor keyEncipherment"
```

A second, separate line covers a certificate that *can* serve TLS but should
not be the one doing it — a CA certificate has a signing key attached, and
serving from it puts that key on the network-facing listener:

```text
level=WARN msg="The TLS certificate just loaded is a CA certificate; serving from it puts a signing key on the network-facing listener. Issue an end-entity certificate with `openvox-ca-ctl generate` and point tls_cert/tls_key at that" cert=/etc/puppetlabs/puppet/ssl/ca/ca_crt.pem subject="Puppet CA: puppet.example.com"
```

Pointing `tls_cert` at `ca_crt.pem` produces both. Two ways of being rejected
by agents still pass every check here, because neither is visible from the
server: a certificate issued by some other CA, and one whose SANs name a host
other than the one agents dial — the `hostname mismatch` above.

## Revocation across replicas

The CA answers "is this certificate revoked?" from a copy of the CRL it holds in
memory, not from storage — the check is on the hot path of every authenticated
request, and it also backs the OCSP responses this replica signs. The copy is
loaded at startup and rewritten whenever *that* process re-signs the CRL, which
on a single node is the whole story.

On the shared backends (`etcd`, `redis`, `postgres`, `mysql`) it is not: only
the replica that handled the revocation re-signs, so every other
replica would go on accepting the certificate until it happened to re-sign on
its own. `crl_sync_interval_sec` closes that. Each replica re-reads the stored
CRL on the interval and installs it if it has advanced, which makes the interval
the worst-case window in which a revoked certificate still works against a
replica that did not revoke it. The default is 60 seconds.

Three things the window does not cover, all worth knowing before you rely on it:

- **OCSP responses already handed out.** The responder signs each response with
  four hours of validity and clients cache it, so a verifier that asked before
  the revocation can keep treating the certificate as valid for that long. The
  replica drops its own cached responses for a serial whenever it installs a
  CRL revoking it — by any route, not only the sync — but answers already in a
  client's or proxy's cache cannot be recalled. This applies whether or not you
  set `--ocsp-url`: that flag decides whether issued certificates advertise the
  responder, not whether `/ocsp` answers. An `unknown` is treated differently
  and is not subject to this — see
  [OCSP status across replicas](#ocsp-status-across-replicas).
- **Certificates issued to the agent before it was locked out.** Revoking one
  serial does not revoke another the same subject already holds. Renewal is not
  a way out — `POST /certificate_renewal` re-reads the CRL from storage rather
  than trusting the cached copy, so a revoked certificate is refused there even
  on a replica that has not synced — but if you are locking out a compromised
  node rather than retiring one certificate, check the inventory for other live
  serials for that subject and retire each one with
  `openvox-ca-ctl revoke --serial <hex>` — see
  [revocation by serial](api.md#revocation-by-serial). `openvox-ca-ctl clean` is
  not a substitute: it revokes the most recently issued serial for the subject
  and removes the stored certificate, leaving the subject's other serials valid.
- **A renewal that coincides with a storage read failure.** That re-read is
  best-effort: if it fails, the check falls back to the CRL already in memory
  rather than refusing every renewal in the fleet over a transient backend
  error. Such a renewal is bounded by the ordinary propagation window instead of
  by the read-through check. `puppetca_crl_sync_failures_total` is what tells
  you it happened.

The read is one small blob, takes no cluster lock, and writes nothing, so it
costs the same on every backend and needs no leader. Lengthening the interval
trades that cost against the window; there is no switch to turn it off, and
`disable_crl_refresh` does not — that setting governs whether this deployment
*re-signs* the CRL on a timer, which is a separate question from whether
revocations reach it.

`filesystem` and `sqlite` are single-node, so the sync has nothing to find and
the setting does not matter there.

To confirm propagation, compare `puppetca_crl_cached_number` (per replica)
against `puppetca_crl_number` (from storage) — see
[metrics](metrics.md#watching-revocation-propagate).

Restarting a replica also reloads its CRL. The sync installs only a CRL this CA
signed, picking out the newest such block wherever it sits in the stored chain —
the same selection the startup loader and the re-sign paths make. A stored chain
carrying nothing of ours leaves the replica on the CRL it already holds and
raises `puppetca_crl_sync_failures_total`; startup warns about the same
condition and the re-sign paths refuse it outright. See
[storage backends](storage-backends.md) for how that state is reached and
repaired.

## Publishing an upstream CRL chain

When openvox-ca runs as an intermediate, agents doing full-chain revocation
checking — Puppet's default `certificate_revocation = chain` — need the
ancestors' CRLs as well as this CA's own. `crl_chain_file` is how they get
there:

```yaml
crl_chain_file: /etc/puppet-ca/upstream-crls.pem
```

It is a PEM bundle of upstream CRLs, re-read by the `crl-chain-refresh`
background job (`crl_chain_refresh_interval_sec`, 1 hour by default) and on
every CRL amendment, and
published alongside this CA's own CRL at
`GET /puppet-ca/v1/certificate_revocation_list/ca`. The file is **declarative**:
whatever it contains is what gets published, so a CRL removed from it disappears
from the served chain. Refresh it by whatever mechanism you already have — a
mounted Secret, a sidecar, a CronJob — and openvox-ca picks the change up.
Getting the file there in the *first* place carries an ordering requirement,
which is what the next section is about.

### Order the writer before the server

**Whatever populates `crl_chain_file` must be ordered before the server starts,
not merely started alongside it.**

The refresh job runs a pass immediately rather than waiting out its first tick,
so a file already in place is picked up at startup. A file that is not there
*yet* is not an error — an absent file is no statement, as below — so the CA
starts, publishes its own CRL alone, and does not look again until
`crl_chain_refresh_interval_sec` elapses. For that whole interval every agent on
the default `certificate_revocation = chain` rejects the CRL it is served.

This is the ordinary shape of the deployment rather than an unusual one: where
the thing that writes the file starts concurrently with the server — a sidecar,
a config-management run, a job fetching a CDP — the server generally wins the
race, having nothing to fetch.

Nothing rescues that window:

- **No counter moves.** An absent file is not a failure, so
  `puppetca_crl_chain_refresh_failures_total` stays flat. The one signal is
  `puppetca_crl_chain_last_read_timestamp_seconds` reading `0`, which
  `PuppetCAUpstreamCRLNeverRead` alerts on — after the shipped mixin's
  `for: 15m`. At the default hourly interval that is a quarter of an hour of
  failing agents before anything fires; at a fifteen-minute interval the outage
  ends about when the alert would have. Neither arrives in time to be a warning.
- **The other trigger does not fire.** The file is re-read on every CRL
  amendment too, but amendments come from revoking or cleaning a certificate —
  operator activity, not something a fleet of agents failing verification
  produces. Nor does the scheduled re-sign of this CA's own CRL, which runs only
  as that CRL nears expiry, and a CA that has just started has just signed one.

So gate the server on the file rather than leaving it to the timer. In
Kubernetes that is a native sidecar: run whatever writes the file as an
`initContainer` with `restartPolicy: Always`, and give *that container* a
`startupProbe` which does not succeed until the file is non-empty. A native
sidecar's startup probe gates the containers after it, so the server cannot
start before the chain exists. Under systemd the equivalent is an ordering
dependency — `Before=` on the unit that writes the file, or an `ExecStartPre=`
that waits for it — rather than two units started together.

The published chart has no dedicated support for this: it exposes
`initContainers`, `extraContainers`, `extraVolumes` and `extraVolumeMounts` as
generic escape hatches, and the sidecar above is assembled from those rather
than configured by a value of its own — see [trust and revocation across
CAs](helm-chart.md#trust-and-revocation-across-cas), which works the sidecar
above through as chart values.

Probe for a **non-empty** file, not merely an existing one: a zero-byte file is
a deliberate statement here (see the table below), so a probe testing only for
existence passes on exactly the case that publishes no ancestors at all.

### What each failure to read the file does

Being declarative cuts both ways, so these distinctions matter more than they
look:

| The file is | What gets published | Why |
| --- | --- | --- |
| **absent** | the chain already published, unchanged | An absent file is *no statement*, not a statement that the chain should be empty. It has to be: this path runs on every CRL amendment, so a single revocation on a replica whose Secret has not mounted yet would otherwise truncate the chain for the whole fleet — permanently, because this CA cannot re-sign another CA's list. |
| **empty**, or nothing but whitespace | this CA's own CRL only | An empty file *is* a statement. This is how you say "publish nothing extra". It is also what a failed `cat >` leaves behind, so it is logged at `ERROR` — see the note on atomic writes below. |
| **unparseable** | the chain already published, unchanged | The refresh fails and is counted. Note this also blocks **revocation** until the file is fixed: refusing to publish half a chain is deliberate, but it does couple CRL amendment to a file refreshed outside openvox-ca. |
| **truncated, or not a CRL bundle** | the chain already published, unchanged | Refused, not read as an empty declaration. A file that does not end on a PEM block boundary, or that decodes to no CRL at all — a block cut mid-write, DER, a certificate bundle, an HTML error page — is a read that failed, not the operator asking for an empty chain. Only an empty file means that. Leading and interleaved commentary is fine; see below. |
| **carrying a CRL older than the one published** | the newer, already-published CRL for that ancestor; everything else from the file | Not a failure and **not** a block on revocation: the published chain is correct, so the older CRL is simply passed over and counted by `puppetca_crl_chain_regressed_total`. |
| **present but unreadable** (permissions, or a directory mounted at the path) | the chain already published, unchanged | The refresh fails and is counted, and revocation is blocked as for **unparseable**. A Secret projected `0400` root-owned against an unprivileged container is the usual cause. |
| **larger than 4 MiB** | the chain already published, unchanged | Refused rather than truncated: a half-read PEM blob would silently drop CRLs. A real chain is a handful of CRLs. |
| **holding more than 64 CRLs** | the chain already published, unchanged | Refused. The byte bound does not cover this: one ancestor with a long revocation list is legitimately large, while many small CRLs are what cost, since each one's signer is resolved by trial verification against the whole CA bundle while the CRL lock is held. A chain is one CRL per ancestor, so more than a couple of dozen means a directory concatenated by accident or a file appended to instead of replaced. |

> **The one revocation this does not block is auto-renewal's.** When an agent
> renews, the CA revokes the certificate it just replaced (`revoke_on_auto_renew`,
> on by default) on a best-effort basis: a failure there is logged
> (`AutoRenew: failed to revoke replaced certificate`) and the renewal is allowed
> to stand, with no retry. So a chain file that is unreadable at that moment does
> not block the renewal — it skips that one revocation permanently, and the
> superseded certificate stays valid until it expires. `puppetca_crl_update_failures_total`
> counts it, but nothing records which serial now needs revoking by hand. Grep
> for that message alongside a rising
> `puppetca_crl_chain_refresh_failures_total`, and revoke by subject afterwards
> if the window mattered.

**Write the file atomically** — write to a temporary path, then rename. A read
that catches a `cat >` mid-write sees a file that does not end on a PEM block
boundary, which is refused rather than acted on: revocations fail until the next
complete write lands, and that is deliberate. Treating a truncated read as "the
operator says publish nothing" would delete the ancestor CRLs permanently, since
this CA cannot re-sign them.

The file may carry non-PEM commentary — `openssl crl -text` output is a bundle
of exactly this shape, since its human-readable dump *precedes* each block and
everything before a `-----BEGIN` line is skipped. What is refused is trailing
text after the last block, because that is indistinguishable from a write cut
short. One truncation is inherently undetectable: a write severed exactly on a
block boundary yields a valid, shorter file, and since the file is authoritative
a missing ancestor is a legitimate thing for it to say. Writing atomically is
what closes that case; nothing in the file's content can.

Atomicity does not, however, cover an **empty** write. `cat upstream/*.pem >
bundle.pem` with an empty or unmounted source directory produces a zero-byte
file — and that is the deliberate way to say "publish nothing extra", so it is
honoured, and every ancestor CRL is dropped permanently. A file of nothing but
whitespace counts the same. There is no way to tell that apart from intent, so
it is logged at `ERROR` naming how many CRLs are being dropped. If you generate
the file from a script, have the script refuse to write an empty one.

In Kubernetes, mount the file from **its own volume, not with `subPath`**. A
`subPath`-mounted ConfigMap or Secret never receives updates, so the file reads
successfully forever and never changes — the feature becomes a silent no-op.
No metric distinguishes that from a healthy file:
`puppetca_crl_chain_last_read_timestamp_seconds` advances on every read either
way, because the read genuinely succeeds — it is the content that is frozen.
What catches it is the consequence — `PuppetCAUpstreamCRLExpiringSoon` firing on a CA that
*has* `crl_chain_file` configured is the `subPath` signature.
`puppetca_crl_chain_last_read_timestamp_seconds` does detect the different case
of a file never opened at all: it reads `0`, and `PuppetCAUpstreamCRLNeverRead`
alerts on it.

If one ancestor appears more than once — which is what a CronJob that appends
rather than replaces produces — only the newest of its CRLs is published, by CRL
number, or by `thisUpdate` for a CRL carrying no `cRLNumber` (`openssl ca
-gencrl` omits it unless `crl_extensions` is configured). Publishing both would
let a client that stops at the first match be handed the older list, un-revoking
a certificate. Ancestors are told apart by which certificate signed their CRL,
not by issuer name, so a shared root that issued two sub-CAs with the same
distinguished name still gets both their CRLs published.

**An ancestor that disappears from the file is dropped**, and counted by
`puppetca_crl_chain_removed_total`. The file is authoritative, so this is the
documented way to stop publishing an ancestor — but it is also what a `cat`
glob that matched one file fewer produces, and it cannot be undone here. The
same counter covers a second way an ancestor disappears: its certificate leaving
the CA bundle, so nothing signs its published CRL any more. That one is fixed by
re-importing the bundle rather than by touching the file. Every case is logged
at `ERROR` naming the issuer, and the message says which happened.

**An ancestor's CRL can never move backwards.** A CRL in the file that is older
than the one already published for the same ancestor is passed over and the
published one kept, counted by `puppetca_crl_chain_regressed_total`. Ancestors
are matched by which certificate signed their CRL, and ordered by CRL number, or
by `thisUpdate` where there is none.

There is one legitimate way to trip this: an ancestor CA rebuilt from backup that
resumes numbering from a low value while still signing with the same key. To
adopt it, drop that ancestor from the file for one publish cycle and then add the
new CRL back — with nothing published to compare against, it is accepted. (An
ancestor that *re-keys* needs nothing special: a different signing certificate is
a different ancestor to this comparison.) Publishing
it would un-revoke, fleet-wide, every certificate that ancestor revoked in
between, and there is no legitimate cause for it: a stale copy, a rolled-back
mirror, or a replay. Unlike a corrupt file this does *not* block revocation —
the published chain is already correct, so failing would let anyone who can
write the file deny revocation instead.

**Every CRL in the file is signature-verified** against a certificate in the
stored CA bundle before it is served, and discarded with a warning otherwise.
This content goes to every agent, so an unverified file would be a way to inject
arbitrary bytes into every agent's CRL store. Whether the check can succeed for
a given CRL depends on the stored bundle holding that issuer's certificate:
importing the *complete* chain, up to and including the root, is what makes the
root's own CRL publishable. `openvox-ca-ctl import` does not currently enforce
completeness — a partial chain is accepted, and the CRLs whose issuers are
missing from it are then discarded on every refresh. That is visible rather than
silent: `puppetca_crl_chain_discarded_total` counts it and the shipped mixin
alerts on it as `PuppetCAUpstreamCRLDiscarded`.

A CRL this CA issued is ignored if found in the file — its own is always rebuilt
from the inventory, and a stale copy must not be able to supersede live
revocations.

Refreshing the chain re-signs this CA's own CRL, so its number advances even
when no certificate was revoked. That is harmless (the number need only
increase) and is the price of having one write path rather than a second,
subtler one.

Per-issuer freshness is reported as
`puppetca_crl_chain_next_update_timestamp_seconds{issuer}`, deliberately
separate from `puppetca_crl_next_update_timestamp_seconds`, which continues to
mean *this CA's own* CRL. An expiring upstream CRL is fixed at the parent CA,
not here, so it gets its own alert with its own runbook — see the
[mixin](../mixin/). Four counters cover what would otherwise be one warning per
cycle in the log, and they are separate because their remedies are:
`puppetca_crl_chain_refresh_failures_total` for a file that could not be read or
parsed (fix the file or its mount); `puppetca_crl_chain_discarded_total` for a
CRL dropped because nothing in the bundle signed it (complete the CA bundle) —
the one case where the published chain silently *shrinks*;
`puppetca_crl_chain_regressed_total` for a CRL older than the one already
published (fix whatever refreshes the file); and
`puppetca_crl_chain_removed_total` for an ancestor that has disappeared from the
file altogether (restore it, or accept the removal) — or whose certificate has
left the CA bundle, so its published CRL can no longer be attributed to anyone
(re-import the bundle). A fifth series,
`puppetca_crl_chain_last_read_timestamp_seconds`, reads `0` where the file is
configured but has never been opened.

> **Rolling upgrades.** A replica running a build from before chain preservation
> re-signs the CRL as a single block and silently drops the chain, so one old
> replica handling one revocation undoes it for everyone. Make sure every
> replica is running a build with chain preservation *before* configuring
> `crl_chain_file`. Preservation is a no-op on a single-CRL deployment, so that
> ordering costs nothing.

## OCSP status across replicas

The responder answers from a second per-process copy of shared state: an index
of every serial this CA has issued, built from the inventory. A serial the index
does not hold is answered `unknown` — before the CRL is consulted at all — so
the index decides whether the responder will speak about a certificate, and the
CRL decides what it says.

Like the CRL cache, that index was loaded once at startup and afterwards only
recorded this process's own issuances. On the shared backends that meant a
replica answered `unknown` for every certificate one of its peers had signed,
indefinitely: the certificate is valid, the inventory row is in shared storage,
and only a restart made the replica see it. `ocsp_index_sync_interval_sec`
closes that. Each replica re-reads the inventory on the interval and adds what
it does not already hold, so the interval is the worst-case window in which a
newly issued certificate is reported as unrecognised elsewhere in the fleet.
The default is five minutes — longer than the CRL sync's minute because the
inventory is much larger than the CRL and because `unknown` is not fail-open.

What that window does and does not mean:

- **It is not a revocation bypass.** `unknown` is not `good`, and the mTLS
  admission path reads the CRL rather than this index. What the window costs is
  a peer's ability to say `revoked` at all: an index miss answers before the CRL
  lookup, so during it the responder is silent about a certificate's revocation
  rather than wrong about it.
- **Whether a client notices depends on its soft-fail policy.** A verifier that
  treats `unknown` as a failure sees one replica reject a certificate the others
  accept, which is an unpleasant split to diagnose; one that soft-fails sees
  nothing.
- **An `unknown` is not cached anywhere, by anyone.** A `good` or a `revoked`
  is pre-signed and held for four hours, here and in the verifier. An `unknown`
  is not: this replica does not keep one, and the response carries no
  `NextUpdate` and (on the GET form) `Cache-Control: no-store`, so no verifier
  or proxy keeps one either. That is what makes the window above the whole
  story rather than the window plus four hours — an index refresh changes the
  answer on the very next request that reaches this replica.
- **The pass also removes.** A serial another replica's expired-certificate
  cleanup has pruned leaves this index on the next pass, taking its cached
  response with it, so `puppetca_ocsp_index_serials` tracks the inventory
  downward as well as upward.
- **`filesystem` and `sqlite` are single-node**, so the job has nothing to find
  there; it costs one local inventory read per interval.

The read takes no cluster lock and does not re-sign anything, but it is not
free: it is the whole inventory, so unlike the CRL sync its cost grows with the
number of certificates ever issued — one read of the whole thing, as a blob or
as a row fetch depending on how the backend stores it, plus the small integrity
value either way. That is what the five-minute default is buying
back. Lengthening the interval trades cost against the window; there is no
switch to turn it off, for the same reason the CRL sync has none — a deployment
cannot opt out of `/ocsp` answering, so it should not be able to opt out of
answering correctly.

Note what the cost scales with: certificates **ever issued**, not certificates
currently valid, because the inventory keeps a row per issuance for the life of
the CA. On a long-lived or high-churn fleet that grows without bound, and the
knob that bounds it is `enable_expired_cert_cleanup`, which is off by default —
it prunes rows for certificates that expired more than
`expired_cert_retention_sec` ago, and so caps what this job (and the startup
index build) has to read. Worth turning on before the inventory is large rather
than after.

Watch `puppetca_ocsp_index_serials` across replicas to confirm they agree, and
`puppetca_ocsp_index_sync_failures_total` for a replica that cannot catch up. A
replica reading *above* its peers is not a fault: a pass that overlaps a local
issuance defers its removals to the next one, so a busy replica can hold pruned
serials a little longer.

## Bounding CA-key signing

`ca_signing_concurrency` caps how many CA-key signatures may be in flight at
once. The cap is shared across certificate issuance, CRL re-signing and the
OCSP responder, because they share one key: what needs bounding is the load on
whatever holds that key, not the load on any one endpoint.

```yaml
ca_signing_concurrency: -1   # -1/unset = max(4, GOMAXPROCS); 0 = unbounded
```

### Why there is a bound at all

`/ocsp` is unauthenticated, the rate limiter in front of the API covers CSR
submissions only, and an OCSP cache miss signs. Without a cap, an anonymous
caller can drive as many concurrent signatures as it can open connections,
against the same key and the same signer that issuance uses.

### Issuance waits; OCSP is refused

The two halves behave differently, and the asymmetry is deliberate:

- **Issuance and CRL re-signing queue** for a slot. They are authenticated, and
  refusing a certificate a client asked for in order to protect an
  unauthenticated responder would be the wrong way round.
- **The OCSP responder sheds**, answering RFC 6960 `tryLater` over HTTP 503
  after a short wait. Letting it queue would convert unbounded signing into
  unbounded queueing and bound nothing.

Shedding is cheap here in a way that is specific to OCSP: a non-success OCSP
response carries no signature, so a refused request costs no CA-key work.

Verifiers see `tryLater` as "ask again", not as "this certificate is bad". A
verifier configured to hard-fail on an unavailable responder will still treat
sustained shedding as a revocation-checking outage, so the limit wants to be
above your steady-state verifier traffic, not merely above your issuance rate.

### Choosing a value

The right number is a property of your signer, which openvox-ca cannot
discover:

| Deployment | Guidance |
| --- | --- |
| Isolated signer (the default) | The built-in default is sized for this: signing is CPU-bound in the signer child, so past `GOMAXPROCS` extra concurrency buys latency and memory rather than throughput. |
| `ca_key_provider: openbao` | **Set this explicitly.** Every signature is a network round trip to a Transit key that other consumers may share, and the default — derived from this host's CPU count — has no relationship to what that key can sustain. The server logs a warning at startup if you leave it unset here, naming the value it derived. |
| Single-process software key | The default is fine. |

The shipped default is a *ceiling*, not a tuning. Its only job is to keep the
number finite; it is not a claim about what your signer can take.

Note the bound is per process. Running N replicas against one shared OpenBao
Transit key permits N × `ca_signing_concurrency` concurrent operations against
that key, so size it against your replica count.

### Watching it

Three metrics (see [metrics.md](metrics.md)):

- `puppetca_ca_signing_in_flight` — signatures in flight now.
- `puppetca_ca_signing_limit` — the configured ceiling; `0` means unbounded.
- `puppetca_ca_signing_shed_total` — OCSP responses refused with `tryLater`.

Sustained shedding while the signer has capacity to spare means the limit is
too low. Shedding under an unauthenticated flood is the bound doing its job.

## Delayed supersession

A renewal replaces a certificate. What happens to the one it replaced is
`superseded_cert_revoke_after_sec`, and the default is **24 hours**: the
predecessor is recorded and stays valid for that long, and a sweep revokes it
once the window elapses. Both certificates verify in the meantime.

The window exists because a certificate other parties are actively verifying
cannot be replaced without a gap unless the predecessor outlives the moment the
replacement is published — the verifiers do not all learn about it at once. An
agent renewing its own credential does not need it: it holds both and simply
stops presenting the old one. The default is set for the harder case.

24 hours is chosen to comfortably exceed the interval on which a fleet notices a
renewal, while staying short enough that a replaced credential is not a standing
one. The same window is what the CA's own serving-certificate work settled on
for the same question asked about a different subject; that work is not in this
release, so there is no companion setting to compare against yet.

> **Upgrading.** This changes behaviour without any config change. Before this
> setting existed, every renewal revoked its predecessor before returning; now
> the predecessor stays valid for 24 hours by default. If you need the old
> behaviour — because your threat model does not tolerate a replaced credential
> outliving its replacement at all — set `superseded_cert_revoke_after_sec: 0`,
> which is an explicit choice and not the same as leaving it unset. You will
> also see a new `superseded.json` in the cadir, a
> `Starting superseded-certificate revocation sweep` line in the logs at
> startup, and `puppetca_supersede_pending` rising and falling.

**The window is a deliberate weakening, and because it is the default it is one
you inherit rather than choose.** For its whole length the replaced certificate
is still a credential this CA accepts, and on the CSR-body (re-key) renewal path
the replaced *private key* is too, since that path issues against a new key and
the old one keeps working until its certificate is revoked. Everything a
compromised predecessor could do, it can still do until the sweep catches up.

Two things bound that, and they are why the default is defensible:

- **A superseded certificate cannot renew itself.** The renewal paths check the
  pending list as well as the CRL, so the credential the window keeps alive
  cannot mint a fresh full-lifetime successor and leave the window behind. That
  check is what makes the window bound the exposure rather than end it, and it
  runs for every deployment because the window now does.
- **Revoking the subject retires it.** `revoke --certname` reaches a recorded
  predecessor in the same call, so containment is not weakened by the window.

If you are replacing a certificate *because* it was compromised, still do not
rely on the window: revoke the serial directly with
`openvox-ca-ctl revoke --serial <hex>`, or set the window to 0 for that
deployment.

Two settings, two questions:

| Setting | Question |
| --- | --- |
| `revoke_on_auto_renew` | *Whether* an auto-renewal retires its predecessor at all. `false` keeps it valid until it naturally expires and records nothing. |
| `superseded_cert_revoke_after_sec` | *When*, on both renewal paths. `0` means inside the renewal call; unset means 24 hours later. |

They compose as you would expect: with `revoke_on_auto_renew: false` the
auto-renewal path records nothing, whatever the delay says, and the CSR-body
path — which always retires what it replaces — still honours the delay.

Some things worth knowing before you rely on it:

- **Each entry keeps the window it was given.** The due time is fixed when the
  supersession is recorded. Shortening the setting later changes what future
  renewals record; it does not retroactively expire a window a fleet may be
  mid-way through relying on, and lengthening it does not extend one.
- **The sweep runs whatever the setting says, including zero.** It is the only
  thing that drains the list, so gating it on the delay would strand every entry
  recorded under an earlier configuration — including one recorded before an
  operator set the window to 0. On a CA that has never recorded a supersession
  each pass is a single absent-key read taking no cluster lock: the sweep rules
  the work out before acquiring one.
- **A pass costs one CRL re-sign, whatever the backlog.** The sweep collects
  every due entry and amends the CRL once — one read, one signature, one write —
  however many certificates come due together, and holds the shared CRL lock
  that every revocation on every replica needs for that single amendment rather
  than for one per entry. Under
  [`ca_key_provider: openbao`](openbao-transit.md) it is likewise one remote
  Transit round trip rather than one per entry. That matters most in the case
  the sweep used to handle worst: a large backlog coming due at once, after a
  fleet-wide outage or a passphrase rotation. A pass that cannot amend the CRL
  fails as a whole — it leaves every entry it attempted on the list, raises
  `puppetca_supersede_failures_total`, and the next pass retries them
  together.
- **Revoking a subject retires its pending predecessor too.** `revoke --certname`
  and `DELETE /certificate_status` retire the subject's current certificate
  *and* anything of that subject's still inside its window, in the same call —
  otherwise containing a compromised node would leave a second working
  credential for it in circulation. A predecessor whose supersession was never
  recorded is not reachable that way; see the failure counter below.
- **A superseded certificate cannot renew itself.** It is absent from the CRL
  for the length of its window, so the renewal paths check the pending list as
  well; without that, the credential the window keeps alive could mint a fresh
  full-lifetime successor and leave the window behind. If the list cannot be
  read, renewals are refused rather than admitted — and that check runs whatever
  the window setting says, so a store that cannot serve the
  `superseded` key refuses renewals even on a CA that never enabled one.
- **The sweep interval is added to the window in the worst case.** A certificate
  due at 12:00 is revoked on the first pass after that, so keep
  `superseded_cert_sweep_interval_sec` (15 minutes by default) well below the
  window. The server warns at startup when it is not shorter than the window,
  naming the worst-case effective window — with the default interval, any window
  of 15 minutes or less trips it.
- **Safe on every replica.** The list rewrite and the revocations it drives run
  under the shared cluster CRL lock, so only the first replica to take it
  revokes and the others find the list already drained. No leader election.
- **Watch `puppetca_supersede_pending`** for how many certificates are inside
  their window right now, and `puppetca_supersede_failures_total` for
  supersessions that were lost or could not be carried out — see
  [metrics](metrics.md#delayed-supersession). A pending count that does not fall
  means the sweep is not completing.

## Trusting client certificates from another CA

By default openvox-ca authenticates exactly one set of clients: the ones it
issued. `client_ca` adds others.

This is for the topology where the servers and operators administering this CA
hold certificates from a *different* CA — typically a sibling intermediate under
a shared root, one issuing agent certificates and one issuing server
certificates. Without it, those administrators cannot authenticate at all.

**Nothing below applies unless `client_ca` is set.** With it absent there is one
trust domain, it is ours, and admin is `puppet_server` plus `pp_cli_auth`
exactly as it has always been.

```yaml
client_ca:
  - name: server-ca
    file: /etc/openvox-ca/server-ca.pem          # anchors for THIS entry only
    crl_file: /etc/openvox-ca/server-ca-crls.pem # CRLs for THIS entry only
    admin_cns:
      - openvox-server.example.com
    allow_pp_cli_auth: false
client_revocation_policy: require                # require | check | skip
client_crl_refresh_interval_sec: 0               # re-read every crl_file this often;
                                                 # 0 = built-in default (1h)
```

### Anchor on the issuing CA, not the root

`file` should contain the **issuing** CA, not the root above it.

A trust anchor need not be self-signed. Anchoring on an intermediate accepts
what that intermediate issued and nothing else — so two sibling CAs under a
shared root stay separate, even when a client presents the shared root and the
sibling CA in its own chain. Putting the root there instead silently extends
this entry's authority, **including its `admin_cns`**, to every intermediate
that root has issued or ever will.

openvox-ca warns at startup when an entry's anchor is self-signed, naming the
entry and the certificate. It warns rather than refuses, because anchoring on a
root is legitimate when the root really is the intended boundary — but it is the
natural mistake, since "the CA bundle" usually means the whole chain.

Each entry's **`name` is required and must be unique**; startup refuses a
duplicate. It is not decorative: it is the `client_ca` label on every metric
series for the entry — `puppetca_client_crl_usable`,
`puppetca_client_crl_refusals_total` and
`puppetca_client_crl_last_reload_timestamp_seconds` — and the `client_ca` field
on every log line about it. Two entries sharing a name would make both
ambiguous, which is why it is refused rather than warned about. Choose something
an operator will recognise in an alert.

### A name means something only within its issuer's namespace

Every CA has its own namespace of names it has signed, and a name means nothing
outside the one it was issued in. So:

| Grant | Our own CA | A `client_ca` entry |
| --- | --- | --- |
| Admin CNs | `puppet_server` / `puppet_server_file` — unchanged | that entry's `admin_cns` |
| `pp_cli_auth` | honoured unless `no_pp_cli_auth` — unchanged | honoured only if that entry sets `allow_pp_cli_auth: true` |

Both foreign grants default to off, so adding an entry authenticates an issuer
without granting it anything.

`allow_pp_cli_auth` **delegates admin admission to that CA**: every certificate
it chooses to stamp with the extension is an administrator here. For a Server CA
under the same operator's control that is correct, and is how the Puppet CA CLI
authenticates upstream. For a CA you do not control it is a full delegation.
Enabling it emits a startup warning naming the issuer.

Two operations remain **own-CA only** regardless of any entry, because they act
on this CA's own namespace: renewing a certificate (`POST /certificate_renewal`)
and the self-match on `GET /certificate_request/{subject}`. A foreign
certificate named `agent1.example.com` is not our `agent1.example.com`.

> **The unit of scoping is the entry, not the anchor** — and the sentence
> heading this section is what makes that worth spelling out, because read
> literally it promises more than an entry can deliver. `admin_cns` and
> `allow_pp_cli_auth` belong to the `client_ca` entry, while its `file` may hold
> any number of anchors. Bundle two issuers into one entry and they share one
> admin list: a name you meant for one of them is honoured from the other, and
> the namespace separation this section describes stops at the entry boundary.
>
> **Split the bundle, one `client_ca` entry per issuer**, wherever the grants are
> meant to differ. Entries are cheap, and per-issuer scoping is exactly what
> having more than one buys you. An entry whose `file` holds several anchors and
> which grants anything warns at startup, naming the entry and every anchor in
> it.
>
> This is a different warning from the [anchor on the issuing CA, not the
> root](#anchor-on-the-issuing-ca-not-the-root) one, though the consequence
> rhymes. That fires on a self-signed anchor and is about an anchor admitting
> intermediates it will issue in future; this fires on a multi-anchor file and is
> about issuers already in it. A single-anchor entry on a root trips the first
> and not the second.

### Revocation

`client_revocation_policy` governs foreign issuers only; our own clients are
always checked against our own CRL.

| Policy | Behaviour |
| --- | --- |
| `require` (default) | A client whose issuer has no currently valid CRL is rejected |
| `check` | Verify against whatever CRLs are loaded; allow where an issuer has none |
| `skip` | No revocation checking for foreign issuers. **Unsafe** |

Checking covers the **whole verified chain**, not just the leaf: a sibling CA
revoked by the shared root must not go on authenticating its leaves.

Under the default `require` policy, **`crl_file` is mandatory** for every entry:
configuration validation rejects a block without one. Separately, and under
*every* policy, the server refuses to start if a `crl_file` that is set cannot
be read or holds a CRL that does not parse — so a stale path left behind on
`skip` stops the server rather than being ignored. That is deliberate — the
anchor bundle beside it already fails closed, and a server that starts here
would reject every client of the domain while its readiness probe reported
healthy. The check runs where the trust set is assembled, which is when TLS is
configured; with no `tls_cert` and `tls_key` there is no client authentication
to set up and `client_ca` is not consulted at all.

Every CRL in `crl_file` is signature-verified against an anchor in the same
entry before it is used, and each is bound to the anchor whose key signed it.
The CRL's own Authority Key Identifier is not consulted at all. RFC 5280 §5.2.1
requires a conforming CRL issuer to include it, but not every issuer conforms,
and there is no reason to refuse a CRL whose signature verifies over a field
this CA does not use — so an issuer that omits it is fully supported. Without verification, a writable `crl_file` would be a way to
*clear* revocations, not merely add them.

**`client_crl_refresh_interval_sec`** is how often each entry's `crl_file` is
re-read, defaulting to an hour. The file is refreshed by whatever mechanism
already delivers it — a mounted Secret, a config-management run, a job fetching
the issuer's CDP — and this only notices; nothing in openvox-ca writes it. A
reload is refused, keeping the previous set, when it fails outright, when it
would cover fewer anchors than the set already in use, when it would drop a partial CRL whose
serials are enforced while that issuer's full CRL stays where it was, or when it
would move any anchor *backwards* — an older CRL from the same issuer, or one
that cannot be shown to be newer at all, which is the case when this server
will not date what it already holds for that anchor and neither side publishes
a `cRLNumber`.

Refusing a backwards move is what stops a replayed file: it verifies, it is
current, and it covers everything the installed set covers, so nothing else on
the path would notice — while re-admitting every serial revoked since it was
signed. Each anchor carries two high-water marks for the purpose — the highest
`cRLNumber` seen for it, and the latest `thisUpdate` — and a candidate that is
behind on **either** is refused.

Either, rather than both, because an attacker who can write `crl_file` cannot
forge a signature: they can only replay CRLs the issuer really published, at a
time of their choosing. A replay is behind on at least one mark, and requiring
both to regress would let them replay using whichever mark their target issuer
keeps badly. `cRLNumber` is compared only where both sides publish one, so an
issuer that never publishes it, or stops, is ordered by date alone rather than
pinned.

Two marks rather than one "newest CRL" because a bundle can hold numbered and
unnumbered CRLs for the same anchor, and a comparison that switches axis
depending on whether both sides carry a number is intransitive across such a
mixture — which would leave the outcome depending on the order the CRLs happen
to appear in the file. Taking each maximum separately is order-independent.

The practical cost is that an issuer whose `thisUpdate` moves backwards while
its numbers rise — two signers with a clock skew between them is the usual way —
has reloads refused until it publishes something that is not behind on either
mark — which here means a `thisUpdate` at or after the highest already seen,
the number axis being ahead already. That normally resolves within a
publication interval.

A CRL whose `thisUpdate` is more than five minutes ahead of this server's clock
is treated as **not yet issued**, the same way a certificate's `notBefore` is.
It cannot make an issuer **current**, and cannot move that anchor's
`thisUpdate` high-water mark — so neither a forward-skewed signer nor a
replayed CRL can pin an anchor against every later one.

It does still count as revocation material the entry *holds*, and it does still
raise the `cRLNumber` mark. Both are deliberate. What the server holds is a fact
about the file rather than about its clock, and the guard that refuses a
narrowing reload rests on it — suppressing it once emptied that guard's view of
the installed set and let an empty file install unchallenged. And `cRLNumber`
sits inside the signed CRL, so only the issuer can mint one and its numbering
runs forwards; a date this server will not believe is no reason to disbelieve a
number, which leaves one ordering intact exactly when the other is suppressed. Five minutes because the signer and
this server keep separate clocks and neither is authoritative; a small forward
difference is ordinary rather than suspicious.

The serials such a CRL names **are** still enforced. Whether a CRL is current is
a claim about the issuer's timeline, which this server cannot verify; whether it
revokes a serial is a claim its signature already backs. Discarding the second
would let a clock difference re-admit revoked clients, which is the outcome the
whole setting exists to prevent.

If the difference is larger than the tolerance the effect is loud rather than
silent: that issuer loses coverage, `puppetca_client_crl_usable` goes to 0 for
the entry, and under `require` its clients are rejected while their revocations
go on being honoured. Fix the clock on whichever side is wrong — that is a
genuine fault, not something to tune the tolerance around.

The marks are held in memory and not persisted, so this is a ratchet for the
life of the process rather than tamper-evidence across restarts. Restarting is
**not** a way out of a refusal, though: startup rebuilds the marks from the same
`crl_file`, so whatever that file contains still decides. The way out is to fix
the file.

A refusal costs freshness at once, and availability if it persists: the
installed CRLs go on being served, but once they pass their own `nextUpdate`
they stop counting as current, and under `require` every client of that issuer
is then rejected. So a refusal that does not clear by the next publication is
an incident, not a nuisance — which is what
`puppetca_client_crl_last_reload_timestamp_seconds` going stale is for.

Every refusal is logged with the `client_ca` entry; the three that compare
against the installed set also name the anchors concerned, while a read failure
has no parsed issuer to name and logs the error instead.

A **delta CRL** or one scoped to an **issuing distribution point** does not
count as coverage for its issuer, and is logged when one is seen. Either lists a
fraction of what its issuer has revoked, and this CA is handed a file rather
than fetching distribution points, so it has no way to obtain the rest; treating
a partial list as a full one would report a domain fully covered while
consulting a list missing most of its revocations.

The serials such a CRL *does* name are still enforced. Refusing to let it answer
"is this issuer covered" is not a reason to stop believing it about the clients
it revokes — a file holding a base CRL beside its delta is what concatenating an
issuer's CDP and freshestCRL output gives you, and discarding the delta would
re-admit everything revoked since the base was signed. So a partial CRL can deny
a client and can never, on its own, satisfy `require`. If every CRL in an entry's file is partial, the
result is a set covering nothing — and what happens next depends on when it
arrives. At **startup** that is the entry's only set, so under `require` the
domain refuses its clients and `puppetca_client_crl_usable` is 0 for it. On a
**reload** it is refused like any other narrowing candidate, the previous CRLs
stay in use, and the visible signal is instead
`puppetca_client_crl_last_reload_timestamp_seconds` going stale while the log
records the discard and the refusal.

The anchors themselves deliberately do not reload: re-reading them would mean
re-parsing what a domain trusts while requests are being decided against it, and
adding or removing an issuer is a restart-shaped change. `admin_cns` on a
`client_ca` entry are startup configuration for the same reason. Only domain
zero's admin allow list is reloadable, through `SIGHUP` — see [reloading
configuration](#reloading-configuration).

A client certificate that is *itself* one of your anchors is rejected under
`require`: the chain is one element long, so there is nothing above it to attest
to its revocation status, and a trust anchor is trusted by configuration rather
than by anything it presents. If you meant that certificate to authenticate as a
client, issue it a leaf from the anchor instead.

> **Anchoring on a shared root and using `require` locks everyone out.** The
> walk needs a CRL for every issuer in the chain, **the anchor included** — what
> is never checked is the anchor as a *subject*, which is a different question.
> An intermediate's own CRL is signed by that intermediate — not by the root — so
> it fails the verification above and is discarded, leaving the
> `(leaf, intermediate)` pair with no CRL. Every client of the entry is then
> rejected.
>
> The server warns at startup when any anchor has no currently valid CRL, but it
> **cannot** warn about this case: the root is an anchor and its own CRL does
> verify and is kept, so the entry looks covered from the outside. Nor can
> `puppetca_client_crl_usable` see it — that gauge only reports whether the entry
> holds *anything* current, which it does. What reports it is
> `puppetca_client_crl_refusals_total`, which counts clients actually turned
> away for want of a CRL, because by then the missing issuer is a fact rather
> than a guess. Anchor on the issuing CA
> and the problem does not arise: the chain is then `[leaf, anchor]` and the only
> CRL `crl_file` needs is the one the anchor itself issued.
>
> The fix is to anchor on the issuing CA, which is what scopes the entry anyway.
> **Do not reach for `client_revocation_policy: check`**: it restores service by
> disabling leaf revocation checking for that domain entirely, and nothing
> afterwards says so.

An expired CRL is treated differently by the two policies, and deliberately.
A CRL carrying **no `nextUpdate` at all** is treated as expired, and for the
same reason. The field is `OPTIONAL` in the `TBSCertList` ASN.1, which is why
Go's parser leaves it zero, but RFC 5280 §5.1.2.5 requires a conforming CRL
issuer to include it and declines to specify what a client should do when it is
absent — so treating such a CRL as expired is a conforming choice, and the safe
one: reading its absence as "never expires" would satisfy `require` forever
from a snapshot that says nothing about revocations since. The fix is at the
issuing CA — give it a next-update interval — not here.

Under `require` an expired CRL counts as absent, so the policy does not quietly decay into
`skip`. Under `check` it is still consulted — it is loaded, and the serials it
names are still revoked — because `check` means "tolerate an issuer with no
CRLs", not "stop reading the ones you were given".

> **`crl_file` does not cover the CA named in the same block.** The trust anchor
> is never revocation-checked — it is trusted by configuration, not by anything
> it presents. Revoking a trusted domain is an operator action: remove or
> replace the `client_ca` entry. `crl_file` covers what that CA *issued*.

`crl_file` is re-read on the interval set by `client_crl_refresh_interval_sec`,
and a reload that cannot be trusted is refused rather than applied — see
[Revocation](#revocation) above for which reloads those
are. **`file` is not**: anchors are
read once at startup, because a half-applied anchor reload locks out every
client of a domain, where a half-applied CRL reload costs at most a stale
revocation. To rotate an anchor, add the new one as a second `client_ca` entry,
roll the fleet, then remove the old entry and roll again.

`puppetca_client_crl_usable{client_ca}` reports whether a domain holds any
currently valid revocation material, and is published **only under `require`** —
`crl_file` is optional under `check` and `skip`, so a domain without CRLs is
correct there and a 0 would alert on a healthy server. It does not report
partial coverage; `puppetca_client_crl_refusals_total{client_ca}` counts clients
actually refused for want of a CRL, and
`puppetca_client_crl_last_reload_timestamp_seconds{client_ca}` goes stale when
`crl_file` has stopped being applied. **Alert on all three**: under `require` a `0` rejects every client
of that issuer, and the first symptom is otherwise an agent-side 403.

> Not to be confused with a CRL this CA *publishes*: those carry its own and its
> ancestors' revocations and are served to agents. `client_ca[].crl_file` is
> inbound, used only by the
> authorisation middleware, and never served.

Under Kubernetes the anchor and its CRL are a mounted Secret and the entry is
`config.client_ca`, with the same rule against `subPath` that `crl_chain_file`
carries, and one further consequence: anchors are read only at startup, so
editing that Secret in place changes nothing until the pods roll. See [trust and
revocation across CAs](helm-chart.md#trust-and-revocation-across-cas).

## Autosigning

The `--autosign-config` flag controls automatic CSR signing:

| Value | Behaviour |
| --- | --- |
| `false` / `""` | Manual signing only (default) |
| `true` | Sign every incoming CSR immediately |
| `/path/to/file` (not executable) | Glob-pattern allowlist (one pattern per line, `#` comments ignored) |
| `/path/to/script` (executable) | Custom plugin: called with `argv[1]=CN`, CSR PEM on stdin; exit 0 = sign, non-zero = hold |

Allowlist example:

```text
# autosign.conf
*.agent.example.com
compile-*.internal
```

Executable plugin example:

```bash
#!/bin/bash
subject="$1"
csr_pem=$(cat)
# approve only nodes whose name starts with "web-"
[[ "$subject" == web-* ]] && exit 0 || exit 1
```

### Subject alternative names requested by a CSR

`allow_subject_alt_names` decides whether a submitted CSR may ask for Subject
Alternative Names of its own. It is **off by default**, matching OpenVox
Server's `allow-subject-alt-names`.

> **What you will see if your agents request alt names.** Any node whose CSR
> asks for a name beyond its own certname — a `dns_alt_names` setting in its
> `puppet.conf`, or a service enrolling under several hostnames — cannot enrol
> or re-key while this is off. The CA logs a `WARN` naming
> `allow_subject_alt_names`, and the client gets a `400` (autosigned) or a `409`
> (manual signing). Set `allow_subject_alt_names: true` if that is what your
> fleet needs. Certificates that already hold SANs keep renewing either way:
> renewal carries their existing names forward, so only new registrations and
> re-keys are affected.

It matters most with autosigning. TLS peers match the name they dialled against
a certificate's SAN set, not its Common Name, so a CSR that may name anything is
a CSR that may ask to *be* anything: a node autosigned as `web01` could request
`DNS:puppet.example.com` and be handed a certificate that impersonates this CA's
own server to everything trusting this PKI. With the setting off, that request is
refused at signing time.

A CSR whose only SAN is a DNS entry equal to its own certname is always allowed,
whatever the setting: agents send that to comply with RFC 2818, and it asks for
nothing the certname does not already grant. That is distinct from
`promote_cn_to_san`, which *adds* that entry when a CSR carries none.

Turn it on when nodes legitimately need extra names — a load-balanced service
answering to several hostnames, say — and prefer a narrow autosign policy
alongside it:

```yaml
allow_subject_alt_names: true
```

Note what turning it on does *not* yet buy. Only DNS names are carried onto an
issued certificate today, so a CSR requesting an IP, email or URI SAN is signed
with the setting on and that entry is silently dropped — the certificate comes
back without it, and the mismatch surfaces later as a failed TLS verification
rather than as a refusal at signing time. With the setting off the same request
is refused outright, which is the louder of the two failures.
[#241](https://github.com/voxpupuli/openvox-ca/issues/241) adds the
carry-through; this caveat goes when it lands.

The refusal is deliberately terse to the requester: it names no entries, so a
client cannot use it to discover which names the CA would issue. The specifics
are in the CA's log, at `WARN`:

```text
level=WARN msg="Refusing CSR: requested subject alternative names are not allowed"
  subject=web01 disallowed="[DNS:puppet.example.com]" disallowed_count=1
  renewal=false setting=allow_subject_alt_names
```

The gate covers names carried on a *submitted CSR*. Three paths are treated
differently, all deliberately:

- **Renewal** is judged against the certificate being renewed rather than against
  policy, so a certificate that already carries SANs stays renewable after the
  setting is turned off — otherwise enabling the gate would strand exactly the
  nodes it was enabled for. The gate does still run: a renewal may keep the names
  its own certificate already has, and may not introduce new ones.
- **`openvox-ca generate --dns`** mints offline from names an operator typed on
  the CA host, and is not filtered.
- **`POST /generate/{subject}?dns=`** is the same minting path reached over HTTP,
  and is likewise not filtered. It *is* a request, but an admin-only one —
  `lookupTier` classifies it `tierAdminOnly` — so its names come from an
  administrator who could already mint anything, not from an enrolling agent.
  That is the distinction the exemption rests on: who supplies the names, not
  whether the path is offline.

## Directory layout (filesystem backend)

```text
<cadir>/
  ca_crt.pem          CA certificate
  ca_pub.pem          CA public key
  ca_crl.pem          Certificate Revocation List
  inventory.txt       Signed certificate log (hex serial, dates, subject per line)
  superseded.json     Certificates awaiting delayed revocation (mode 0600; absent until
                      the first supersession) — see "Delayed supersession" above
  signed/             Issued certificates
  requests/           Pending CSRs
  locks/              Same-host lock files (mode 0600; empty but for the store-wide
                      instance lock, which records its holder) — see below
  private/
    ca_key.pem              CA private key (mode 0600; encrypted PEM when --encrypt-ca-key)
    .ca_key_passphrase      Auto-generated passphrase file (mode 0600; only when --encrypt-ca-key
                            is used without an explicit passphrase source)
    {subject}_key.pem       Server-side generated private keys (mode 0600)
```

> **Note:** Serial numbers are cryptographically random (128-bit). The `serial`
> file used by older Puppet CAs for sequential serial tracking is no longer
> written or read by this server.

The full on-disk layout, including the inventory HMAC files, is documented in
[storage backends](storage-backends.md#filesystem-backend-default). Other backends
store the same logical state elsewhere.

### File permissions

| Content | Mode |
| --- | --- |
| Directories | `0750` |
| Private keys | `0600` |
| CRL file | `0600` |
| Pending-supersession list | `0600` |
| Lock files under `locks/` | `0600` |
| Public data (certs, CSRs, inventory) | `0644` |

The user running `openvox-ca` must own (or have write access to) `--cadir` —
and so must anything else that touches the store. `openvox-ca-ctl` and the
offline `openvox-ca` subcommands take the same locks the server does, so run
them as that user rather than under `sudo`: a root-owned lock file left in
`locks/` will fail the server's next acquisition of that name. They also require
the server to be stopped, because the filesystem backend supports a single
running instance. See [running a second process against a live
store](storage-backends.md#running-a-second-process-against-a-live-store).

## Graceful shutdown

On `SIGTERM` or `SIGINT`, the frontend HTTP server calls `http.Server.Shutdown()` with a drain context (wired via `signal.NotifyContext`) so in-flight requests (signing, CRL, OCSP) drain cleanly before the process exits. The request context is cancelled on signal, and the command returns normally rather than calling `os.Exit` on its error paths, so deferred storage and signer cleanup always runs after all connections are done.

The drain budget defaults to **25 seconds** and is configurable via `shutdown_timeout_sec` (config file) or `PUPPET_CA_SHUTDOWN_TIMEOUT_SEC` (environment); a non-positive value falls back to the default.

In the default isolated-process deployment, the supervisor gives its child processes the drain budget **plus a 3-second headroom** (28 seconds by default) before force-killing anything that has not exited, so the drain is never truncated.

This is particularly important for **Kubernetes rolling updates**: pods receive `SIGTERM` with a configurable grace period (`terminationGracePeriodSeconds`, default 30 seconds). The defaults (25s drain, 28s supervisor) nest under that 30-second grace so the server drains and exits cleanly before the platform `SIGKILL`s the pod. If you raise `shutdown_timeout_sec`, raise `terminationGracePeriodSeconds` to at least the drain budget plus 3 seconds. Under systemd, raise `TimeoutStopSec` instead — see [running under systemd](systemd.md).

## Reloading configuration

`SIGHUP` re-reads the two file-backed inputs that can be swapped safely while the server is running:

| Input | Effect |
| --- | --- |
| `--tls-cert` / `--tls-key` | The renewed keypair is served to new TLS handshakes; connections in flight keep the certificate they negotiated with |
| `--puppet-server-file` | The admin allow list is rebuilt from the current file contents, merged with the `--puppet-server` value the process started with, and swapped atomically with respect to in-flight requests |

A `client_ca` entry's `crl_file` is re-read too, but **on its own timer rather than on `SIGHUP`** — every `client_crl_refresh_interval_sec`, by the `client-crl-refresh` job. It needs no signal and is not listed above because nothing an operator does triggers it. The entry's *anchors* are not re-read at all: changing `file` needs a restart, deliberately, since a trust anchor changing under a running server is not a reload but a different trust configuration.

`--puppet-server` (config key `puppet_server`) itself is frozen at startup: a CN removed from it stays an admin until the server restarts. Reload only re-reads the *file*.

Withdrawing admin access has a second caveat: a certificate carrying the `pp_cli_auth` extension is an admin regardless of the allow list (see [admin credential resolution](api.md#admin-credential-resolution)). Revoke that certificate, or run with `--no-pp-cli-auth`, if the reload is meant to decommission a host.

Everything else — the listen address, the storage backend, CA key custody, CA properties, which autosign configuration is in use, and every `client_ca` field except `crl_file` — requires a restart.

Two file-backed inputs are consulted live, with no signal needed at all: the autosign allowlist or executable is read on every CSR, and the OpenBao AppRole `role_id`/`secret_id` files are read on every login (see [OpenBao Transit-engine CA key](openbao-transit.md)). Editing those takes effect on the next request; only the settings naming them are fixed at startup.

A reload that fails (an unreadable keypair, a missing allow-list file) is logged and leaves the previous configuration in place; the server keeps serving. Each input is applied independently, so a broken allow list does not block a certificate rotation.

In the default isolated-process deployment, send `SIGHUP` to the supervisor (the process you started); it forwards the signal to the frontend. Under systemd this is `systemctl reload openvox-ca` — see [running under systemd](systemd.md#reloading).

Under `--daemon` the process you started has already forked and exited, so there is nothing left to signal by job control; find the supervisor with `pgrep -f openvox-ca` (the parent of the two child processes) and send `SIGHUP` to that. Running in the foreground under a service manager avoids the question entirely.
