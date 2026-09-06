# Deploying with Helm

The `openvox-ca` Helm chart deploys the CA on Kubernetes. It is maintained in
this repository under [`charts/openvox-ca`](../charts/openvox-ca) and released
in lockstep with the server: the chart's `version` and `appVersion` are always
the release version, so chart `0.9.0` deploys openvox-ca `0.9.0` and defaults
to that release's image.

This is the narrative guide. The exhaustive values table is the
[chart's own README](../charts/openvox-ca/README.md); the settings you place in
`config` are documented in [configuring the server](configuration.md).

## Installing

The chart is distributed as an **OCI artefact only** — there is no HTTP chart
repository and no `helm repo add` step. The commands below omit `--version`, so
helm resolves the newest published chart; add `--version X.Y.Z` to pin one (the
chart version is the openvox-ca version):

```console
$ helm install openvox-ca \
    oci://ghcr.io/voxpupuli/openvox-ca-charts/openvox-ca \
    --namespace puppet --create-namespace \
    --values my-values.yaml
```

Inspect it before installing:

```console
$ helm show values oci://ghcr.io/voxpupuli/openvox-ca-charts/openvox-ca
$ helm template openvox-ca oci://ghcr.io/voxpupuli/openvox-ca-charts/openvox-ca \
    --values my-values.yaml
```

The chart lives in a GHCR package of its own, separate from the container
images, because one package cannot hold both:

| Artefact | Reference |
| --- | --- |
| Container images | `ghcr.io/voxpupuli/openvox-ca` |
| Helm chart | `ghcr.io/voxpupuli/openvox-ca-charts/openvox-ca` |

Alongside each release, every push to `main` republishes a **rolling
development chart** at the in-development version (e.g. `0.9.0-dev`). That tag
is mutable — each push overwrites it — and its `appVersion` resolves to the
rolling `edge-alpine` image, so the two stay consistent. Use it to try
unreleased changes; never pin production to it.

## Verifying the chart

The chart is signed and carries SLSA v1.0 build provenance, like the images.
Pin the identity to the release shape rather than accepting anything this
repository signed:

```console
$ cosign verify ghcr.io/voxpupuli/openvox-ca-charts/openvox-ca:X.Y.Z \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity-regexp '^https://github\.com/voxpupuli/openvox-ca/\.github/workflows/helm-chart\.yml@refs/tags/v'
```

The rolling development chart is signed too, but from `main` rather than from a
tag, so its certificate identity ends `@refs/heads/main` and the pattern above
will not match it. Substitute that suffix if you are deliberately verifying a
development chart.

There is no `.prov` file, so `helm verify` has nothing to check — Helm's own
provenance mechanism is PGP and wants a long-lived keyring, which is what
Sigstore's short-lived certificates exist to avoid. The chart carries no SBOM
either: it declares no dependencies, so there would be nothing to catalogue. The
software it installs is the container image, which carries its own — see
[verifying an image](container-images.md#verifying-an-image).

## How the chart is configured

openvox-ca has a large configuration surface, and the chart deliberately does
**not** mirror it key by key. Instead:

- **`config`** is written verbatim to `/etc/puppet-ca/config.yaml`, which the
  server auto-detects and the chart passes explicitly via `--config`. Every key
  in [configuring the server](configuration.md) is valid there, including the
  nested `kubernetes_export` and `openbao` blocks.
- **Convenience blocks** — `tls`, `ca`, `caKeyPassphrase`, `puppetServers`,
  `autosign`, `metrics`, `kubernetesExport`, `persistence` — do the Kubernetes
  half of a feature (mount the Secret, open the port, create the RBAC) *and*
  set the config keys pointing at whatever they mounted.
- **`config` always wins**, with three exceptions. The two are deep-merged with
  your `config` on top — except `port`, `cadir` and `metrics_listen`, which also
  shape a Kubernetes object (the container port and Service, the volume mount,
  the exporter's port and any ServiceMonitor). Overriding one of those in `config`
  alone would move the server and leave the object behind, so the chart refuses
  the install and names the value to set instead.
  This is why `verbosity` is written into the config file rather than passed as
  `--verbosity`: a flag would outrank the file unconditionally, leaving
  `config.verbosity` silently ineffective. The only argument the chart passes is
  `--config`.

So this:

```yaml
tls:
  existingSecret: openvox-ca-tls
```

mounts that Secret read-only and produces `tls_cert: /run/secrets/openvox-ca-tls/tls.crt`
and the matching `tls_key`. If you would rather point them somewhere else, set
`config.tls_cert` and `config.tls_key` and they take precedence.

Run `helm template` to see exactly what the merge produced — the rendered
`config.yaml` is right there in the ConfigMap.

Settings that must come from a Secret at runtime, such as a database DSN, go
through the environment instead:

```yaml
extraEnv:
  - name: POSTGRES_PASSWORD
    valueFrom:
      secretKeyRef:
        name: openvox-ca-db
        key: password
  - name: PUPPET_CA_SQL_DSN
    value: postgres://openvox-ca:$(POSTGRES_PASSWORD)@db-rw:5432/openvox-ca?sslmode=require
```

Environment variables take precedence over the config file, which is what makes
this work.

## Choosing an image

The chart defaults to the **Alpine** image variant. With `image.tag` empty it
resolves to `<appVersion>-alpine`, e.g. `ghcr.io/voxpupuli/openvox-ca:0.9.0-alpine`.

An explicit tag is used verbatim — the chart never appends a suffix to it — so
the CentOS Stream variant, whose tags carry no suffix, is simply:

```yaml
image:
  tag: "0.9.0"
```

To pin by digest (which is what you want if you are reconciling with Flux or
Argo CD and letting an image automation update it):

```yaml
image:
  digest: sha256:78f5a09763…
```

The digest wins over the tag, and the reference becomes
`repository@sha256:…`.

## TLS: the chart's most important setting

Puppet agents speak HTTPS, and openvox-ca authenticates administrative
operations by **client certificate**. Serving plain HTTP on a non-loopback
address would let an on-path host inject forged certificates, so the server
does not offer it as a fallback: it **refuses to start**.

The chart therefore refuses to render an install that would hit that, rather
than handing you a pod that crash-loops. `helm install` with no TLS
configuration fails immediately, naming the ways out. The usual one is to point
`tls.existingSecret` at a `kubernetes.io/tls` Secret — cert-manager produces one
readily:

```yaml
tls:
  existingSecret: openvox-ca-server-tls
```

The alternatives, in the same message:

| Setting | When |
| --- | --- |
| `config.tls_cert` / `config.tls_key` | A certificate you mount yourself, via `extraVolumes` |
| `env` / `extraEnv` — `PUPPET_CA_TLS_CERT` and `PUPPET_CA_TLS_KEY` | The paths come from a Secret at runtime. Environment variables outrank the config file, and the chart counts them |
| `config.no_tls_required: true` | Only behind a proxy that terminates TLS and re-originates it to the pod. Client certificates do not survive that, so mTLS-authenticated endpoints become unreachable |
| `listen.host: 127.0.0.1` or `localhost` | A sidecar-only deployment. Those two spellings and nothing else: the server tests `net.ParseIP(host).IsLoopback()`, which rejects the bracketed `[::1]`, and it builds its listen address as `host + ":" + port`, which turns a bare `::1` into the unparseable `::1:8140` |

With `no_tls_required` the chart also switches the health probes to HTTP, since
the kubelet has to speak whatever the server speaks. Set `httpGet.scheme` on a
probe explicitly to override that.

**The check only runs when the chart can see the whole configuration.**
`existingConfigMap`, `args`, `envFrom` and a `--config` in `extraArgs` each put
settings somewhere the chart does not read — someone else's ConfigMap, a replaced
argv, a Secret, a config file it never rendered — so it stops asserting rather
than refusing an install it cannot judge. In those modes
the probes assume HTTPS, and it is on you to set `httpGet.scheme` if the server
is actually serving cleartext.

**A renewed certificate needs a signal or a restart — nothing sends one.**
openvox-ca re-reads the keypair on `SIGHUP` and serves it to new handshakes
without dropping connections in flight (see
[reloading configuration](configuration.md#reloading-configuration)), and the
chart mounts `tls.existingSecret` as an ordinary Secret volume with no
`subPath`, so the kubelet refreshes the files in place when cert-manager rotates
them. What nothing does is signal the pod, so the running process keeps serving
the old certificate until something acts. The probes talk to that same listener,
so readiness stays green right up to expiry, at which point every agent fails at
once.

Three ways to act, cheapest first:

- `kubectl exec <pod> -- kill -HUP 1` — PID 1 is the supervisor, which forwards
  the signal to the frontend. No restart, no dropped connections.
- `kubectl rollout restart deployment/<release>-openvox-ca`.
- Let a controller restart it: `ci/postgres-ha-values.yaml` sets
  `reloader.stakater.com/auto: "true"` under `podAnnotations`, which has
  [Reloader](https://github.com/stakater/Reloader) watch every Secret and
  ConfigMap the pod mounts. Note that Reloader restarts the pod; neither it nor
  the chart sends `SIGHUP`.

Two further consequences follow from the CA terminating its own TLS:

- **Ingress must pass TLS through**, not terminate it (see below).
- **The pod's `fsGroup` must match its `runAsGroup`.** Mounted Secrets are
  written mode `0600` owned by `root:fsGroup`; the kubelet grants group access
  when `fsGroup` is set, which is how the container user reads them. The chart's
  default `podSecurityContext` already does this — if you replace it wholesale,
  keep `fsGroup` aligned with `runAsUser`/`runAsGroup`.

## Storage and replicas

The default is the **filesystem** backend on a PersistentVolumeClaim. That is
the simplest correct deployment, and the one restriction is that it does not
scale out: the CA's private key and inventory live on that volume.

```yaml
persistence:
  enabled: true
  storageClass: fast-ssd
  size: 2Gi
```

The PVC carries `helm.sh/resource-policy: keep`, so `helm uninstall` does not
take the CA's private key with it. Set `persistence.retain: false` if you
genuinely want it removed with the release.

To run more than one replica, move the state into a shared backend — see
[storage backends](storage-backends.md) — and turn persistence off, because
`cadir` then holds nothing durable. Worth knowing before you scale out: a
revocation reaches the other replicas within `crl_sync_interval_sec` (60s by
default) rather than instantly, since each answers revocation checks from its own
copy of the CRL — see
[revocation across replicas](configuration.md#revocation-across-replicas).
A certificate signed on one replica is likewise reported `unknown` by the
others until they reload the inventory into the index their OCSP responder
answers from, within `ocsp_index_sync_interval_sec` (5m by default) — see
[OCSP status across replicas](configuration.md#ocsp-status-across-replicas).

```yaml
replicaCount: 2

persistence:
  enabled: false
emptyDir:
  medium: Memory

strategy:
  type: RollingUpdate
  rollingUpdate:
    maxUnavailable: 0
    maxSurge: 1

config:
  storage_backend: postgres
```

The `strategy` block above is redundant, and shown only to be explicit: an
unset `strategy` already follows `persistence.enabled`, so turning persistence
off selects RollingUpdate on its own. Recreate applies while the cadir is a
ReadWriteOnce PVC that a surging replacement pod could not mount; once the
state is external there is nothing left to serialise on. `podDisruptionBudget` and
`autoscaling` become meaningful at that point too.

### Sizing

The default memory limit is 128Mi, and it is a hard cap. The server's footprint
grows with the size of the fleet: it keeps a serial index and a cache of
pre-signed OCSP responses, one entry per known certificate, pruned only on
revocation or expired-certificate cleanup. Crossing the limit is an OOMKill, and
with the Recreate strategy that persistence-enabled installs default to, that
is CA downtime. Raise `resources.limits.memory` before a growing inventory
reaches it.

You do not normally need to set `GOMEMLIMIT`. The server runs as three
processes — a launcher supervising an isolated signer and the frontend, see
[CA key security](ca-key-security.md#process-isolation) — and the launcher reads
the pod's **cgroup v2** memory ceiling and divides it between them, so the Go
runtimes collect harder instead of hitting the cgroup wall with no configuration
at all. On a cgroup v1 node nothing is derived and the pre-change behaviour
stands; set `GOMEMLIMIT` explicitly there.

It does not claim the whole ceiling. `GOMEMLIMIT` bounds Go runtime memory only,
while the binary's resident text, kernel memory charged to the cgroup and a
memory-backed cadir all count against the same limit from outside it, so the
launcher claims `config.memory_budget_percent` of the ceiling (default 90%) and leaves
the rest as headroom. **With `persistence.enabled: false` and the default
`emptyDir.medium: Memory` the cadir tmpfs shares that headroom**, and tmpfs pages
cannot be reclaimed without swap; on a small limit with a busy cadir, lower
`config.memory_budget_percent` or set `GOMEMLIMIT` explicitly.

If you do set it, **`GOMEMLIMIT` names the budget for the whole process tree**,
not for one process. An explicit value takes precedence over the cgroup ceiling
and is taken at face value — no headroom is withheld, because naming a number is
choosing your own — so set it at or just under `resources.limits.memory`, never
above it and never to a per-process share:

```yaml
resources:
  limits:
    memory: 256Mi
env:
  GOMEMLIMIT: 240MiB
```

The launcher and signer take fixed shares (`config.memory_reserve_launcher`,
`config.memory_reserve_signer`) and the frontend takes the remainder. The
signer's share is the one you can outgrow: its startup peak is
fleet-proportional at roughly 420 bytes per certificate, and **raising
`resources.limits.memory` does not reach it**. The share also carries the Go
runtime's own footprint, so the usable headroom in the 24MiB default is nearer
16MiB: past roughly 40,000 certificates raise `config.memory_reserve_signer` as
well:

```yaml
resources:
  limits:
    memory: 256Mi
config:
  memory_reserve_signer: 128Mi
```

The raised limit is not optional. The ceiling has to leave the frontend at least
**24Mi** after both reservations, and a derived ceiling is scaled to 90% first,
so a 128Mi signer reserve needs roughly 178Mi before anything divides at all —
at the shipped 128Mi limit this setting alone would switch the whole mechanism
off.

A budget too small to leave the frontend a workable share is left undivided
rather than split into shares that would cause continuous GC. That case is
logged as a warning; a host that states no ceiling at all is logged at debug
level, since there is nothing to act on. `--single-process`
divides nothing either, because there is no tree to divide. A `GOMEMLIMIT` the Go
runtime cannot parse is not one of these cases: the runtime rejects it during
startup, before any of this runs, and the process dies with `fatal error:
malformed GOMEMLIMIT`.

**63Mi** is the smallest whole MiB that divides under the default reservations
(the exact floor is 65244729 bytes). Below it `resources.limits.memory` is left
undivided — and then no process gets a limit at all, so the cliff is back.

At the shipped 128Mi default the tree budget is 115.2Mi and the frontend's share
is **83.2Mi**, the launcher's 8Mi and the signer's 24Mi; the startup log line
reports all four. If that is tighter than your fleet needs, raise
`resources.limits.memory` — every byte above the two fixed reservations goes to
the frontend.

These three keys go under `config`; see
[memory budget](configuration.md#memory-budget) for their grammar and defaults.

### Shutdown and drain

The 30-second default `terminationGracePeriodSeconds` nests the server's
25-second drain plus the supervisor's 3-second headroom. If you raise
`shutdown_timeout_sec`, raise the grace period to at least that plus three —
see [graceful shutdown](configuration.md#graceful-shutdown).

## Exposing the CA

### Service

```yaml
service:
  type: ClusterIP
  port: 443
```

For dual stack, set both the Service policy and the listen address — a
dual-stack Service in front of a pod listening only on `0.0.0.0` gets you an
IPv6 address that refuses connections:

```yaml
service:
  ipFamilyPolicy: RequireDualStack

listen:
  host: "[::]"

metrics:
  host: "[::]"
```

`ipFamilies` pins the families and their order (the first is primary), so
`[IPv6, IPv4]` gives an IPv6-primary Service. Leave both unset to inherit the
cluster default.

### Ingress

**The controller must pass TLS through.** A controller that terminates TLS
strips the client certificate, and every administrative endpoint stops
authenticating.

```yaml
ingress:
  enabled: true
  className: haproxy
  annotations:
    ingress.kubernetes.io/ssl-passthrough: "true"
  hosts:
    - host: ca.example.com
      paths:
        - path: /
          pathType: Prefix
```

The annotation is controller-specific: HAProxy uses
`ingress.kubernetes.io/ssl-passthrough`, ingress-nginx uses
`nginx.ingress.kubernetes.io/ssl-passthrough` (and needs the controller started
with `--enable-ssl-passthrough`). Note that `ingress.tls` is *not* how you
serve TLS here — the serving certificate openvox-ca presents does that, from
the `tls` Secret or from `config.tls_cert`/`config.tls_key`. Only set it if
your controller needs a certificate for SNI routing.

If you deliberately terminate TLS at the edge, set `config.no_tls_required:
true` and accept that mTLS-authenticated endpoints are unreachable.

### Gateway API

Use a **TLSRoute** — the Gateway API equivalent of ssl-passthrough. It forwards
the TLS connection without terminating it, so client certificates arrive
intact:

```yaml
gateway:
  tlsRoute:
    enabled: true
    parentRefs:
      - name: external
        namespace: gateway-system
        sectionName: tls-passthrough
    hostnames:
      - ca.example.com
```

The Gateway listener it attaches to needs `tls.mode: Passthrough`. TLSRoute is
in the Gateway API **experimental** channel (`v1alpha2`), so the CRD must be
installed from that channel; `gateway.tlsRoute.apiVersion` is available if your
implementation serves it elsewhere.

An **HTTPRoute** (`gateway.httpRoute`) is also available, but it makes the
Gateway terminate TLS. Reserve it for the anonymous endpoints — CRL
distribution, OCSP, health — where no client certificate is involved:

```yaml
gateway:
  httpRoute:
    enabled: true
    parentRefs:
      - name: internal
        namespace: gateway-system
    hostnames:
      - crl.example.com
    rules:
      - matches:
          - path:
              type: PathPrefix
              value: /puppet-ca/v1/certificate_revocation_list
        backendRefs:
          - name: openvox-ca
            port: 443
```

Both may be enabled at once if you want passthrough for agents and a plain-HTTP
CRL endpoint for verifiers.

## Admin access

Compilers that need to sign, revoke, or list certificates must be named:

```yaml
puppetServers:
  - openvoxserver.example.com
  - compile-1.example.com
```

The chart renders these into the config ConfigMap and sets
`puppet_server_file`. Without them no CN has admin access, and the chart says
so on install.

By default a client certificate carrying the `pp_cli_auth` extension is also
accepted as an admin credential. Set `config.no_pp_cli_auth: true` to require
the CN allow list alone.

## Autosigning

Off by default, which is the right default: autosigning lets any CSR submitter
obtain a signed certificate without operator review.

A glob allowlist is rendered into the config ConfigMap for you:

```yaml
autosign:
  patterns:
    - "*.agent.example.com"
    - "compile-*.internal"
```

`autosign.mode` takes the raw setting instead — `"true"` (sign everything;
development only, and the chart warns), or a path to an executable policy
plugin you have mounted via `extraVolumes`.

## Monitoring

The Prometheus exporter is off by default. Enabling it opens a second,
plain-HTTP listener and adds the port to the pod and the Service:

```yaml
metrics:
  enabled: true
  serviceMonitor:
    enabled: true
    labels:
      release: kube-prometheus-stack
```

The `ServiceMonitor` is opt-in on top of that, because it needs the Prometheus
Operator CRDs; the chart refuses the combination of a ServiceMonitor with the
exporter disabled rather than creating a monitor for a port that does not
exist. Its `labels` usually need whatever label your Prometheus selects
monitors on.

**Leaf-certificate metrics carry node hostnames as label values.** Restrict who
can scrape them:

```yaml
networkPolicy:
  enabled: true
  metricsNamespaces:
    - monitoring
```

A [Jsonnet alerting mixin](../mixin/) ships with the project for the expiry and
export-failure alerts. Its selector is a fixed `job="openvox-ca"`, and the
chart leaves `metrics.serviceMonitor.jobLabel` empty so the Prometheus Operator
derives `job` from the Service name.

Those two only line up when the Service is named `openvox-ca`. **Set the
mixin's `puppetCASelector` to match your deployment** rather than reaching for
`jobLabel` to force the job name: `job` has to stay distinct per release,
because two releases of this chart may run side by side while a fleet migrates
from one CA to another, and an alert that cannot say which one is failing is
worth little. Pointing `jobLabel` at `app.kubernetes.io/name` in particular
would give every release of the chart the same job, since that label carries the
chart name rather than the release name.

## Network policy

Disabled by default. When enabled, the API port admits the whole cluster —
Puppet agents live in any namespace — and the metrics port only the namespaces
you list:

```yaml
networkPolicy:
  enabled: true
  apiAccess: any          # or "namespace", or "none" to define it yourself
  metricsNamespaces:
    - monitoring
  egress:
    enabled: true
    rules:
      - to:
          - podSelector:
              matchLabels:
                cnpg.io/cluster: openvox-ca-cnpg
        ports:
          - port: 5432
            protocol: TCP
```

Turning egress on means you must enumerate everything the CA talks to — its
storage backend, OpenBao, the Kubernetes API. DNS is always allowed.

## Kubernetes export

Publishing the CA certificate and CRL into Secrets and ConfigMaps for other
workloads (see [Kubernetes export](kubernetes-export.md)) needs three things,
all of which the chart handles from one block: the config, the RBAC, and a
mounted ServiceAccount token.

```yaml
kubernetesExport:
  enabled: true
  targets:
    - kind: Secret
      metadata:
        name: openvox-ca-trust
      cert: true
      crl: true
    - kind: ConfigMap
      metadata:
        name: openvox-ca-crl
        namespace: monitoring
      crl: true
      crl_key: ca_crl.pem
  rbac:
    namespaces:
      - monitoring
```

`rbac.namespaces` lists the *extra* namespaces to bind the Role into; the
release namespace is always included. Every namespace you export into needs a
binding. `rbac.scope: ClusterRole` grants it cluster-wide instead, which is
worth it only if you export into many namespaces.

The chart mounts the ServiceAccount token automatically when this (or OpenBao's
Kubernetes auth) is enabled, and leaves it unmounted otherwise. These are the
inputs it counts as enabled — some because it can see the setting, the rest
because it cannot see far enough to rule it out:

| Input | Why it mounts |
| --- | --- |
| `kubernetesExport.enabled`, or `config.kubernetes_export.targets` | Export is configured, so the exporter needs the API |
| `config.openbao.auth_method: kubernetes` | The key provider authenticates with the pod's own token |
| `PUPPET_CA_OPENBAO_AUTH_METHOD: kubernetes` in `env` or `extraEnv` | Environment variables outrank the config file, so the chart reads those two values too. An empty value is ignored, as the server ignores it |
| `--openbao-auth-method=kubernetes` in `extraArgs` | Arguments outrank both, and `extraArgs` is appended to the argv the chart builds, so it is readable |
| An `extraEnv` entry for that variable fed by `valueFrom` | The chart cannot read which method the Secret names, so it assumes the one needing a token |
| A bare `--openbao-auth-method` in `extraArgs`, with the value in the next element | The chart does not reassemble the separated form, so it assumes the same |
| `existingConfigMap`, `args` or `envFrom` | Each can configure either feature somewhere the chart does not read at all |
| A `--config` in `extraArgs` | The chart renders its own `--config` and appends `extraArgs` after it, so a second one wins and the server reads a file the chart never saw |

`automountServiceAccountToken` forces the decision either way.

## Running under an external root

openvox-ca can run as an intermediate CA under a parent root, using the offline
`openvox-ca csr` and `openvox-ca import-ca-cert` subcommands. No chart value
enables it.

**Follow [running under an external root CA](openbao-transit.md#running-under-an-external-root-ca).**
That is the canonical procedure — the flags, the ordering, the re-issuance case —
and despite living in the OpenBao guide it applies to every `ca_key_provider`,
including the default. It already covers Kubernetes: a one-shot Job carrying the
same ServiceAccount, image and mounts as the Deployment, and the three details
that are easy to get wrong there. Use it rather than improvising from this page.

What that guide cannot know is what this chart names things, and the rest of this
section is only that:

- **Substitute the chart's names into its Job.** Its example mounts
  `configMap: { name: openvox-ca-config }` and puts `cadir` at
  `/etc/puppetlabs/puppet/ssl/ca`; the chart renders the ConfigMap, the
  ServiceAccount and the PVC all as `openvox-ca.fullname` — `<release>-openvox-ca`,
  or just `openvox-ca` when the release name already contains it — and takes
  `cadir` from `persistence.mountPath`, `/var/lib/puppet-ca` by default. The cadir
  one matters most: the Job reads the chart's own `config.yaml`, so a mount at the
  example's path leaves the command looking somewhere else and quietly reproducing
  the wrong CA rather than failing.
- **The server refuses to start between the two steps**, which under a Deployment
  is a crash-loop, so do not begin a rollout inside that window — see
  [the server will not start between steps 1 and 3](openbao-transit.md#the-server-will-not-start-between-steps-1-and-3).
  Scaling to zero is the obvious answer and is wrong under OpenBao Kubernetes auth,
  where the pod's own token is the credential; that guide's Job route exists for
  exactly this.
- **A restart is required, not a signal.** `SIGHUP` covers the TLS keypair and the
  admin allow list; the CA certificate is read at startup, so a signalled process
  carries on issuing under the certificate you just replaced.
- **Re-issuing later needs the CA stopped, on any backend.** The `--force`
  re-issuance is a read-modify-write across the certificate and the CRL, and it
  takes the bootstrap and CRL locks. Those are genuinely cross-process
  everywhere now — `filesystem` and `sqlite`, the chart's default, coordinate two
  processes on one host with `flock(2)` — so a revocation is no longer silently
  discarded, and the import will instead wait and then fail if the CA holds the
  lock. What no lock covers on any backend is the inventory append, so an import
  racing issuance can still leave the inventory's integrity value inconsistent.
  See [running a second process against a live
  store](storage-backends.md#running-a-second-process-against-a-live-store).
- **With `ca.existingSecret` the CA certificate is mounted read-only**, so the
  import cannot write it back. That is the `--out` route in the procedure, which
  cannot be combined with `--force`, and which ends in `openvox-ca-ctl
  reissue-crl` — an admin API call needing a client certificate whose CN is in
  `puppetServers`. The chart neither mounts one nor documents obtaining one, so
  plan that credential before you start.

Everything else about the resulting CA — storage, TLS, export — is unchanged; only
the certificate's issuer differs.

## OpenBao CA key custody

Keeping the CA private key in an OpenBao Transit engine (see
[OpenBao Transit-engine CA key](openbao-transit.md)) is config plus, for the
non-Kubernetes auth methods, a mounted Secret:

```yaml
config:
  ca_key_provider: openbao
  openbao:
    addr: https://openbao.example.com:8200
    transit_mount: transit
    key_name: openvox-ca
    auth_method: kubernetes
    kubernetes_role: openvox-ca
```

If you also pin the CA *certificate* to a Secret, note that the `ca` block sets
both `ca_cert_file` and `ca_key_file`, and under this provider there is no key
file to point at. Clear that one explicitly — the empty string survives the
merge, and the server treats an empty `ca_key_file` as unset:

```yaml
ca:
  existingSecret: openvox-ca-cert   # certificate only
config:
  ca_key_provider: openbao
  ca_key_file: ""
```

With `auth_method: kubernetes` the pod authenticates with its own projected
ServiceAccount token — the chart detects this and mounts the token for you, so
there is nothing else to configure. For `approle` or `token`, mount the
credential files and point at them:

```yaml
extraVolumes:
  - name: openbao-approle
    secret:
      secretName: openvox-ca-openbao
extraVolumeMounts:
  - name: openbao-approle
    mountPath: /run/secrets/openbao
    readOnly: true

config:
  openbao:
    auth_method: approle
    approle_role_id_file: /run/secrets/openbao/role_id
    approle_secret_id_file: /run/secrets/openbao/secret_id
```

## Bringing your own objects

Several escape hatches exist for things the chart does not model:

| Value | Use for |
| --- | --- |
| `existingConfigMap` | A `config.yaml` you generate elsewhere |
| `persistence.existingClaim` | A PVC you provision yourself |
| `serviceAccount.create: false` + `serviceAccount.name` | An account managed outside the release |
| `extraVolumes` / `extraVolumeMounts` | etcd/Redis/SQL client certificates, passphrase files, autosign plugins |
| `initContainers` / `extraContainers` | Waiting on a dependency, sidecars |
| `command` / `args` | Full control of the container's invocation |
| `extraObjects` | Arbitrary manifests rendered with the release |

`extraVolumes`, `initContainers`, `extraContainers`, `extraObjects` and the
ingress and route fields are all run through `tpl`, so they can reference
`.Values` and the chart's helpers:

```yaml
extraObjects:
  - apiVersion: v1
    kind: Secret
    metadata:
      name: '{{ include "openvox-ca.fullname" . }}-extra'
    type: Opaque
    stringData:
      note: templated
```

## Upgrading

Chart and application versions move together, so upgrading the chart upgrades
openvox-ca:

```console
$ helm upgrade openvox-ca \
    oci://ghcr.io/voxpupuli/openvox-ca-charts/openvox-ca \
    --version X.Y.Z --namespace puppet --reset-then-reuse-values
```

`--reset-then-reuse-values` rather than `--reuse-values`: the latter rebuilds
the previous release's values by coalescing your overrides with *the chart
version you installed from*, and lays that over the upgrade, so a default the
new chart changed is masked by the old chart's copy of it and never takes
effect. `--reset-then-reuse-values` starts from the new chart's defaults and
reapplies your overrides on top, which is almost always what an upgrade is for.
Pass `-f values.yaml` instead if you keep your values in a file.

Worth knowing before you upgrade:

- While `persistence.enabled` is true the derived strategy is Recreate, so
  there is a brief outage as the old pod releases the volume. External-backend
  deployments (`persistence.enabled: false`) derive RollingUpdate and roll
  without one. To keep Recreate there, set `strategy: {type: Recreate}`
  explicitly.
- **Upgrading a SQL-backed deployment that is on RollingUpdate, across the
  advisory-lock change**, needs `strategy: {type: Recreate}` for that one
  upgrade, or a scale to zero and back. The PostgreSQL/MySQL lock-key
  derivation changed, so old and new pods do not exclude one another while
  both are running — and because the derived RollingUpdate sets
  `maxUnavailable: 0`, it surges the new pod alongside the old one even at
  `replicaCount: 1`. One replica is not enough to avoid this. If you take the
  `strategy` route, clear it again afterwards — remove the key from your
  values file, or `--set strategy=null` — because
  `--reset-then-reuse-values` reapplies your overrides on every later
  upgrade, so a pin set once keeps costing you the Recreate outage the bullet
  above says you had escaped. Scaling to zero and back leaves no such
  residue. See the note in
  [storage backends](storage-backends.md#sql-backends).
- The pods carry a checksum of the rendered config, so a change to `config`
  restarts them even though the Deployment's pod template is otherwise
  unchanged. Set `configChecksumAnnotation: false` if you would rather manage
  restarts yourself (with Reloader, say).
- **`existingConfigMap` turns that off**, necessarily: the chart cannot
  checksum a ConfigMap it did not render. openvox-ca does not re-read
  `config.yaml`, so editing your own ConfigMap leaves the running pods on the
  old config until you restart them — `kubectl rollout restart`, or an
  annotation-based reloader watching that ConfigMap. There is one exception, and
  it is narrower than it looks: *if your own config.yaml sets
  `puppet_server_file`* at a path in that ConfigMap, that file is re-read on
  `SIGHUP` (see
  [reloading configuration](configuration.md#reloading-configuration)) — the
  chart renders neither the file nor the setting in this mode, so it depends
  entirely on your config. Even then a signal only withdraws CNs that came from
  the file: one listed in `puppet_server` is frozen at startup, and a certificate
  carrying `pp_cli_auth` is an admin regardless of the allow list.

## Uninstalling

```console
$ helm uninstall openvox-ca --namespace puppet
```

The PersistentVolumeClaim **survives** by default, because it holds the CA's
private key. Remove it deliberately:

```console
$ kubectl delete pvc openvox-ca --namespace puppet
```

Objects created by [Kubernetes export](kubernetes-export.md) also survive —
openvox-ca does not delete what it exported. They carry
`app.kubernetes.io/managed-by=openvox-ca` — and *only* that: the exporter sets no
per-release label, so the selector cannot tell one CA's exports from another's.
Find them cluster-wide, but delete by namespace:

```console
$ kubectl get secret,configmap -A -l app.kubernetes.io/managed-by=openvox-ca
$ kubectl delete secret,configmap --namespace puppet \
    -l app.kubernetes.io/managed-by=openvox-ca
```

If you run more than one openvox-ca and export into shared namespaces, add a
label of your own under `kubernetesExport.targets[].metadata.labels` and select
on that as well — otherwise a cluster-wide delete takes the other CA's
certificate and CRL with it.
