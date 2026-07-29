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
repository and no `helm repo add` step:

```console
$ helm install openvox-ca \
    oci://ghcr.io/voxpupuli/openvox-ca-charts/openvox-ca \
    --version 0.9.0 \
    --namespace puppet --create-namespace \
    --values my-values.yaml
```

Inspect it before installing:

```console
$ helm show values oci://ghcr.io/voxpupuli/openvox-ca-charts/openvox-ca --version 0.9.0
$ helm template openvox-ca oci://ghcr.io/voxpupuli/openvox-ca-charts/openvox-ca \
    --version 0.9.0 --values my-values.yaml
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
- **`config` always wins.** The two are deep-merged with your `config` on top.
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
| `config.tls_self_provision: true` | The CA issues and renews its own serving certificate. See below |
| `config.tls_cert` / `config.tls_key` | A certificate you mount yourself, via `extraVolumes` |
| `env` / `extraEnv` — `PUPPET_CA_TLS_CERT` and `PUPPET_CA_TLS_KEY` | The paths come from a Secret at runtime. Environment variables outrank the config file, and the chart counts them |
| `config.no_tls_required: true` | Only behind a proxy that terminates TLS and re-originates it to the pod. Client certificates do not survive that, so mTLS-authenticated endpoints become unreachable |
| `listen.host: 127.0.0.1` or `localhost` | A sidecar-only deployment. Those two spellings and nothing else: the server tests `net.ParseIP(host).IsLoopback()`, which rejects the bracketed `[::1]`, and it builds its listen address as `host + ":" + port`, which turns a bare `::1` into the unparseable `::1:8140` |

With `no_tls_required` the chart also switches the health probes to HTTP, since
the kubelet has to speak whatever the server speaks. Set `httpGet.scheme` on a
probe explicitly to override that.

**The check only runs when the chart can see the whole configuration.**
`existingConfigMap`, `args` and `envFrom` each put settings somewhere the chart
does not read — someone else's ConfigMap, a replaced argv, a Secret — so it
stops asserting rather than refusing an install it cannot judge. In those modes
the probes assume HTTPS, and it is on you to set `httpGet.scheme` if the server
is actually serving cleartext.

### Letting the CA issue its own certificate

Where nothing else can issue it — the CA key is in OpenBao Transit, so
cert-manager cannot act as a CA issuer for it — the CA can issue its own:

```yaml
config:
  hostname: ca.example.com        # required: the certificate's CN and first SAN
  tls_self_provision: true
  tls_self_provision_names:
    - openvox-ca.openvox-ca.svc.cluster.local
```

There are no `tls.selfProvision.*` values, deliberately. The chart's convenience
blocks exist to do Kubernetes *wiring* — volumes, mounts, Secrets — and
self-provisioning needs none: it is a server setting, so you set it as one. The
chart reads it back out of the merged configuration to decide the probe scheme,
and it counts `PUPPET_CA_TLS_SELF_PROVISION` from `env`/`extraEnv` too.

The chart refuses two combinations that the server also refuses:

- `config.tls_self_provision` with no `config.hostname`. The chart does not set
  `hostname` by default, so this is easy to hit; without it the certificate
  carries the fallback subject `puppet`, which no agent validates.
- `config.tls_self_provision` together with `tls.existingSecret` or
  `config.tls_cert`/`tls_key`. One route supplies the certificate in memory, the
  other from disk.

The certificate lives in the storage backend, not in `cadir`, so every replica
serves the same one and an ephemeral `cadir` loses nothing. Publish it to an
Ingress with a [`serving_cert`/`serving_key` export
target](kubernetes-export.md#serving-certificate-and-key), and see
[configuration](configuration.md#self-provisioned-serving-certificate) for
renewal, revocation of superseded certificates, and the
filesystem/SQLite caveat.

Two consequences follow from the CA terminating its own TLS:

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
`cadir` then holds nothing durable:

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

The `strategy` change matters: the chart defaults to `Recreate` because a
surging replacement pod cannot mount the default ReadWriteOnce volume. Once
state is external, a zero-downtime rollout is safe. `podDisruptionBudget` and
`autoscaling` become meaningful at that point too.

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
serve TLS here — the CA's own certificate does that. Only set it if your
controller needs a certificate for SNI routing.

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
export-failure alerts.

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
Kubernetes auth) is enabled, and leaves it unmounted otherwise.
`automountServiceAccountToken` forces the decision either way.

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
    --version 0.10.0 --namespace puppet --reuse-values
```

Two things worth knowing:

- With the default `Recreate` strategy there is a brief outage while the old
  pod releases the volume. External-backend deployments using `RollingUpdate`
  roll without one.
- The pods carry a checksum of the rendered config, so a change to `config`
  restarts them even though the Deployment's pod template is otherwise
  unchanged. Set `configChecksumAnnotation: false` if you would rather manage
  restarts yourself (with Reloader, say).
- **`existingConfigMap` turns that off**, necessarily: the chart cannot
  checksum a ConfigMap it did not render. openvox-ca has no reload path, so
  editing your own ConfigMap leaves the running pods on the old config until
  you restart them — `kubectl rollout restart`, or an annotation-based reloader
  watching that ConfigMap.

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
`app.kubernetes.io/managed-by=openvox-ca`:

```console
$ kubectl delete secret,configmap -A -l app.kubernetes.io/managed-by=openvox-ca
```
