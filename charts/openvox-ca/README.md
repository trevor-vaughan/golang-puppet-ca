# openvox-ca Helm chart

Deploys [openvox-ca](https://github.com/voxpupuli/openvox-ca), a
Puppet-compatible X.509 certificate authority and a drop-in replacement for the
CA built into OpenVox/Puppet Server.

The chart is released in lockstep with openvox-ca itself: its `version` and
`appVersion` are always the release version, so chart `X.Y.Z` deploys
openvox-ca `X.Y.Z`. It is published as an OCI artefact only — there is no HTTP
chart repository to add. Omitting `--version` installs the newest published
chart; pass `--version X.Y.Z` to pin one.

A server TLS certificate is **required**: openvox-ca refuses to serve plain
HTTP on a non-loopback address, so the chart refuses to render an install that
has none rather than handing you a crash-looping pod.

```console
$ helm install openvox-ca \
    oci://ghcr.io/voxpupuli/openvox-ca-charts/openvox-ca \
    --namespace puppet --create-namespace \
    --set tls.existingSecret=openvox-ca-server-tls
```

A narrative guide — TLS termination, storage backends, ingress and Gateway API,
monitoring, Kubernetes export — is in
[docs/helm-chart.md](https://github.com/voxpupuli/openvox-ca/blob/main/docs/helm-chart.md). This file is the values
reference.

## How configuration works

openvox-ca has a large configuration surface (see
[docs/configuration.md](https://github.com/voxpupuli/openvox-ca/blob/main/docs/configuration.md)), and the chart does not
mirror it key by key. Instead:

- **`config`** is written verbatim to `/etc/puppet-ca/config.yaml`, which the
  server reads. Every documented setting — including the nested
  `kubernetes_export` and `openbao` blocks — is valid there.
- **Convenience blocks** (`tls`, `ca`, `caKeyPassphrase`, `puppetServers`,
  `autosign`, `metrics`, `kubernetesExport`, `persistence`) do the Kubernetes
  side of a feature — mount the Secret, open the port, create the RBAC — *and*
  set the config keys that point at what they mounted.
- **`config` always wins.** The two are deep-merged with your `config` on top,
  so you can override anything a convenience block computed — with three
  exceptions the install refuses rather than lets diverge, because they also
  shape a Kubernetes object: `port`, `cadir` and `metrics_listen`. Set those
  through `listen.port`, `persistence.mountPath` and `metrics.port`, or set both
  sides to agree.
- **`env`, `extraEnv` and `envFrom`** are the escape hatch for settings that
  must come from a Secret at runtime, such as a database DSN.

A single `helm template` will show you exactly what the merge produced.

## Requirements

Kubernetes **1.26 or newer** (the `kubeVersion` floor in `Chart.yaml`, checked
against the 1.26 schemas in CI). Two optional values need more:
`podDisruptionBudget.unhealthyPodEvictionPolicy` needs 1.27, and
`service.trafficDistribution` needs 1.31.

Helm 3 or 4. CI validates the chart against one pinned version of each major —
see the chart matrix in
[`.github/workflows/ci.yml`](https://github.com/voxpupuli/openvox-ca/blob/main/.github/workflows/ci.yml).
Renovate moves those pins forward within each major, so treat them as the
tested floor rather than a ceiling; naming them here would go stale on its own.

## Values

### Image

| Key | Default | Description |
| --- | --- | --- |
| `image.registry` | `ghcr.io` | Registry hosting the image |
| `image.repository` | `voxpupuli/openvox-ca` | Image repository |
| `image.tag` | `""` | Empty resolves to `<appVersion>-alpine`. An explicit tag is used verbatim — this is how you select the CentOS Stream variant (`tag: "0.9.0"`) |
| `image.digest` | `""` | `sha256:…` digest; takes precedence over `tag` |
| `image.pullPolicy` | `IfNotPresent` | |
| `imagePullSecrets` | `[]` | |

### Naming and metadata

| Key | Default | Description |
| --- | --- | --- |
| `nameOverride` | `""` | Overrides the chart name in generated names and labels |
| `fullnameOverride` | `""` | Overrides the generated resource name outright |
| `namespaceOverride` | `""` | Deploy into a namespace other than the release namespace |
| `commonLabels` | `{}` | Added to every object the chart creates |
| `commonAnnotations` | `{}` | Added to every object the chart creates |

### Server configuration

| Key | Default | Description |
| --- | --- | --- |
| `config` | `{}` | Written verbatim to `config.yaml`; the full [configuration reference](https://github.com/voxpupuli/openvox-ca/blob/main/docs/configuration.md) applies |
| `existingConfigMap` | `""` | Use a ConfigMap you manage instead of rendering one. The chart cannot checksum what it did not render, so `configChecksumAnnotation` has no effect and editing that ConfigMap will **not** restart the pods. `config.yaml` is fixed at startup, so roll them yourself. Of this ConfigMap's contents a `SIGHUP` re-reads only the allow-list file, and only if your own config sets `puppet_server_file` at a path in it. `config`, `verbosity`, `listen.host`, `puppetServers`, `autosign`, `extraConfigFiles` and `kubernetesExport.targets` stop being written anywhere in this mode — carry the ones you need into your own ConfigMap, `listen.host` included, or a dual-stack Service will front an IPv4-only socket |
| `configMount` | `/etc/puppet-ca` | Where the config ConfigMap is mounted |
| `extraConfigFiles` | `{}` | Extra `filename: contents` entries placed alongside `config.yaml`. Refused when the chart is rendering that file itself, since yours would take its place: `config.yaml` always, `puppet-server` with `puppetServers`, `autosign.conf` with `autosign.patterns` — none of them under `existingConfigMap`, where the chart renders no ConfigMap and these entries go nowhere. Keys must look like ConfigMap keys (letters, digits, `-`, `_`, `.`) |
| `listen.host` | `0.0.0.0` | API listen address; use `[::]` for a dual-stack Service |
| `listen.port` | `8140` | API listen port |
| `verbosity` | `0` | `0`=Info, `1`=Debug, `2`=Trace. Written into `config.yaml`, so `config.verbosity` overrides it |
| `puppetServers` | `[]` | CNs granted admin API access over mTLS; rendered into a file and wired to `puppet_server_file`. One entry per line — an entry containing a newline is refused |
| `autosign.mode` | `""` | `"false"`, `"true"`, or a path inside the container |
| `autosign.patterns` | `[]` | Glob allowlist rendered into the config ConfigMap; sets `autosign_config` |

### TLS and CA material

| Key | Default | Description |
| --- | --- | --- |
| `tls.existingSecret` | `""` | Secret holding the server certificate; sets `tls_cert`/`tls_key`. The server re-reads the keypair on `SIGHUP`, but nothing sends one, so a renewal needs a signal (`kubectl exec <pod> -- kill -HUP 1`) or a restart — see [the guide](https://github.com/voxpupuli/openvox-ca/blob/main/docs/helm-chart.md) |
| `tls.certKey` / `tls.keyKey` | `tls.crt` / `tls.key` | Data keys within that Secret |
| `tls.mountPath` | `/run/secrets/openvox-ca-tls` | |
| `ca.existingSecret` | `""` | Secret holding the CA certificate and key; sets `ca_cert_file`/`ca_key_file`. Under a provider that holds the key (`config.ca_key_provider: openbao`) clear the latter with `config.ca_key_file: ""` |
| `ca.certKey` / `ca.keyKey` | `tls.crt` / `tls.key` | Data keys within that Secret |
| `ca.mountPath` | `/run/secrets/openvox-ca-ca` | |
| `caKeyPassphrase.existingSecret` | `""` | Secret holding the CA key passphrase; sets `encrypt_ca_key` and `ca_key_passphrase_file` |
| `caKeyPassphrase.key` | `passphrase` | Data key within that Secret |
| `caKeyPassphrase.mountPath` | `/run/secrets/openvox-ca-passphrase` | |

### Storage

| Key | Default | Description |
| --- | --- | --- |
| `persistence.enabled` | `true` | Back `cadir` with a PersistentVolumeClaim. **Required** for the filesystem and sqlite backends |
| `persistence.mountPath` | `/var/lib/puppet-ca` | The CA's `cadir` |
| `persistence.existingClaim` | `""` | Use a PVC you created yourself |
| `persistence.storageClass` | `""` | |
| `persistence.accessModes` | `[ReadWriteOnce]` | |
| `persistence.size` | `1Gi` | |
| `persistence.annotations` / `.labels` / `.selector` | `{}` | |
| `persistence.retain` | `true` | Keep the PVC on `helm uninstall` |
| `emptyDir.medium` | `Memory` | emptyDir spec used when `persistence.enabled` is false |
| `emptyDir.sizeLimit` | `""` | |

### Metrics

| Key | Default | Description |
| --- | --- | --- |
| `metrics.enabled` | `false` | Enable the Prometheus exporter and its port |
| `metrics.host` | `0.0.0.0` | Exporter listen address |
| `metrics.port` | `9140` | Exporter listen port |
| `metrics.serviceMonitor.enabled` | `false` | Create a ServiceMonitor (needs the Prometheus Operator CRDs) |
| `metrics.serviceMonitor.namespace` | `""` | Defaults to the release namespace |
| `metrics.serviceMonitor.labels` / `.annotations` | `{}` | |
| `metrics.serviceMonitor.interval` | `60s` | |
| `metrics.serviceMonitor.scrapeTimeout` | `""` | |
| `metrics.serviceMonitor.path` | `/metrics` | |
| `metrics.serviceMonitor.scheme` | `http` | |
| `metrics.serviceMonitor.honorLabels` | `false` | |
| `metrics.serviceMonitor.jobLabel` | `""` | Which Service label supplies the Prometheus `job` value. Empty leaves it to the Operator, which uses the Service name, keeping `job` distinct per release. Do not point it at `app.kubernetes.io/name`: that is the chart name, so concurrent releases would collide. Match the mixin's `puppetCASelector` to your deployment instead |
| `metrics.serviceMonitor.targetLabels` | `[]` | |
| `metrics.serviceMonitor.relabelings` / `.metricRelabelings` | `[]` | |

### Kubernetes export

| Key | Default | Description |
| --- | --- | --- |
| `kubernetesExport.enabled` | `false` | Publish the CA cert and/or CRL into Secrets and ConfigMaps |
| `kubernetesExport.fieldManager` | `""` | Server-side apply field manager |
| `kubernetesExport.targets` | `[]` | Passed through to `kubernetes_export.targets` |
| `kubernetesExport.rbac.create` | `true` | Create the `create`/`patch` Role and binding |
| `kubernetesExport.rbac.scope` | `Role` | `Role` or `ClusterRole` |
| `kubernetesExport.rbac.namespaces` | `[]` | Extra namespaces to bind the Role into |

### Workload

| Key | Default | Description |
| --- | --- | --- |
| `replicaCount` | `1` | More than one requires an external storage backend |
| `strategy` | `{}` | Empty follows `persistence.enabled`: Recreate while the cadir is a ReadWriteOnce PVC, RollingUpdate (maxUnavailable 0, maxSurge 1) once the state is external. Set it explicitly to override either way — a map without `type` is refused, because Kubernetes would read it as RollingUpdate |
| `revisionHistoryLimit` | `10` | |
| `command` | `[]` | Overrides the container entrypoint |
| `args` | `[]` | Overrides the generated argument list outright |
| `extraArgs` | `[]` | Appended to the generated arguments |
| `env` | `{}` | Literal environment variables, as a map |
| `extraEnv` | `[]` | Environment variables in list form, for `valueFrom` |
| `envFrom` | `[]` | `configMapRef`/`secretRef` sources, verbatim |
| `resources` | 10m CPU / 96–128Mi | The memory limit is a hard cap and the footprint grows with the certificate count; raise it before a growing inventory reaches it. The launcher also divides this ceiling across the three server processes, claiming 90% and giving the launcher 8Mi, the signer 24Mi and the frontend the remainder — 83.2Mi at the 128Mi default. 63Mi is the smallest whole MiB that divides: **below it nothing is divided and no process gets a memory limit at all**, so lowering this value past the default disables the mechanism rather than tightening it. See [sizing](https://github.com/voxpupuli/openvox-ca/blob/main/docs/helm-chart.md#sizing) |
| `configChecksumAnnotation` | `true` | Roll the pods when the rendered config changes. Inert when `existingConfigMap` is set |
| `podAnnotations` / `podLabels` | `{}` | |
| `deploymentAnnotations` | `{}` | Annotations on the Deployment rather than the pods |
| `podSecurityContext` | non-root uid/gid 1000, `fsGroup` 1000, `RuntimeDefault` | |
| `securityContext` | no privilege escalation, read-only rootfs, all capabilities dropped | |
| `livenessProbe` / `readinessProbe` / `startupProbe` | probes on `/healthz/*` | Set `enabled: false` to drop one; other keys are the probe spec. `httpGet.scheme` defaults to HTTPS or HTTP to match whether the server has a certificate. `startupProbe.failureThreshold x periodSeconds` is the entire budget `CA.Init` gets, since the probe path is not served until it returns. The default 60s does not cover Init's worst case (two `internal/ca.LockTimeout` waits plus CA key generation); raise it if you run several replicas against a fresh shared backend, where both locks can be contended |
| `lifecycle` | `{}` | |
| `terminationGracePeriodSeconds` | `30` | Must exceed `shutdown_timeout_sec` by ≥ 3s |
| `nodeSelector` / `tolerations` / `affinity` | `{}` / `[]` / `{}` | |
| `topologySpreadConstraints` | one soft constraint per hostname | A constraint with no `labelSelector` gets this release's own selector |
| `priorityClassName` / `runtimeClassName` / `schedulerName` | `""` | |
| `dnsPolicy` / `dnsConfig` / `hostAliases` | `""` / `{}` / `[]` | |
| `enableServiceLinks` | `false` | |
| `automountServiceAccountToken` | `null` | `null` mounts the token when the pod needs the API — Kubernetes export (`kubernetesExport.enabled` or `config.kubernetes_export.targets`), or OpenBao Kubernetes auth (`config.openbao.auth_method`, `PUPPET_CA_OPENBAO_AUTH_METHOD` in `env`/`extraEnv`, or `--openbao-auth-method=kubernetes` in `extraArgs`) — and whenever the chart cannot tell: `existingConfigMap`, `args`, `envFrom`, an `extraEnv` `valueFrom` for that variable, or a bare `--openbao-auth-method` in `extraArgs`. See [the guide](https://github.com/voxpupuli/openvox-ca/blob/main/docs/helm-chart.md) for the full table |
| `initContainers` / `extraContainers` | `[]` | Templated, so they can reference `.Values` |
| `extraVolumes` | `[]` | Templated |
| `extraVolumeMounts` | `[]` | Passed through as written |
| `serviceAccount.create` | `true` | |
| `serviceAccount.name` | `""` | Required when `create` is false and `kubernetesExport.rbac.create` is on — the chart refuses to bind the export Role to the namespace's `default` account |
| `serviceAccount.annotations` / `.labels` | `{}` | |

### Service

| Key | Default | Description |
| --- | --- | --- |
| `service.type` | `ClusterIP` | |
| `service.port` | `443` | Service port mapped to the container's `https` port |
| `service.annotations` / `.labels` | `{}` | |
| `service.ipFamilyPolicy` | `""` | `SingleStack`, `PreferDualStack`, or `RequireDualStack` |
| `service.ipFamilies` | `[]` | e.g. `[IPv6, IPv4]` to make IPv6 primary |
| `service.clusterIP` / `.externalIPs` | `""` / `[]` | |
| `service.externalTrafficPolicy` / `.internalTrafficPolicy` | `""` | |
| `service.trafficDistribution` | `""` | e.g. `PreferClose` (Kubernetes 1.31+) |
| `service.sessionAffinity` / `.sessionAffinityConfig` | `""` / `{}` | |
| `service.publishNotReadyAddresses` | `false` | |
| `service.loadBalancerIP` / `.loadBalancerClass` / `.loadBalancerSourceRanges` | `""` / `""` / `[]` | LoadBalancer only |
| `service.allocateLoadBalancerNodePorts` | `null` | LoadBalancer only |
| `service.nodePort` / `.metricsNodePort` | `""` | NodePort/LoadBalancer only |
| `service.appProtocol` | `""` | |
| `service.extraPorts` | `[]` | |

### Ingress

openvox-ca terminates TLS itself and authenticates agents by client
certificate, so the controller **must** pass TLS through untouched.

| Key | Default | Description |
| --- | --- | --- |
| `ingress.enabled` | `false` | |
| `ingress.className` | `""` | |
| `ingress.annotations` / `.labels` | `{}` | Where the controller's ssl-passthrough annotation goes |
| `ingress.backendPort` | `https` | `https` or `metrics`; `metrics` requires `metrics.enabled` |
| `ingress.hosts` | one example host | `[{host, paths: [{path, pathType}]}]`; `host` is templated |
| `ingress.tls` | `[]` | Templated |

### Gateway API

| Key | Default | Description |
| --- | --- | --- |
| `gateway.tlsRoute.enabled` | `false` | TLS passthrough — preserves client certificates, and the right choice for a CA |
| `gateway.tlsRoute.apiVersion` | `gateway.networking.k8s.io/v1alpha2` | TLSRoute is in the experimental channel |
| `gateway.tlsRoute.parentRefs` / `.hostnames` | `[]` | Templated |
| `gateway.tlsRoute.backendPort` | `https` | `https` or `metrics`; `metrics` requires `metrics.enabled` |
| `gateway.tlsRoute.rules` | `[]` | Replaces the generated rule |
| `gateway.tlsRoute.annotations` / `.labels` | `{}` | |
| `gateway.httpRoute.*` | as above | Terminates TLS at the Gateway, so mTLS endpoints stop authenticating; `apiVersion` defaults to `gateway.networking.k8s.io/v1` |

### Network policy

| Key | Default | Description |
| --- | --- | --- |
| `networkPolicy.enabled` | `false` | |
| `networkPolicy.apiAccess` | `any` | `any` (agents live anywhere), `namespace`, or `none` |
| `networkPolicy.metricsNamespaces` | `[monitoring]` | Namespaces allowed to scrape the exporter |
| `networkPolicy.egress.enabled` | `false` | Adds an Egress policy; DNS is always allowed |
| `networkPolicy.egress.rules` | `[]` | Everything the **pod** reaches, sidecars included: your storage backend, OpenBao if the key lives there, anything `initContainers`/`extraContainers` fetch, and the API server only when `kubernetesExport` is in use (OpenBao's kubernetes auth needs no API egress). DNS is always allowed |
| `networkPolicy.extraIngress` | `[]` | |

### Availability

| Key | Default | Description |
| --- | --- | --- |
| `podDisruptionBudget.enabled` | `false` | |
| `podDisruptionBudget.minAvailable` | `1` | Ignored when `maxUnavailable` is set |
| `podDisruptionBudget.maxUnavailable` | `""` | `0` is honoured (block every voluntary eviction), not treated as unset |
| `podDisruptionBudget.unhealthyPodEvictionPolicy` | `""` | Kubernetes 1.27+ |
| `autoscaling.enabled` | `false` | Requires an external storage backend, and at least one of `targetCPUUtilizationPercentage`, `targetMemoryUtilizationPercentage` or `metrics` — the chart refuses an install with none set |
| `autoscaling.minReplicas` / `.maxReplicas` | `2` / `6` | |
| `autoscaling.targetCPUUtilizationPercentage` | `80` | |
| `autoscaling.targetMemoryUtilizationPercentage` | `""` | |
| `autoscaling.metrics` / `.behavior` | `[]` / `{}` | |

### Extra objects

| Key | Default | Description |
| --- | --- | --- |
| `extraObjects` | `[]` | Arbitrary manifests rendered with the release; each is templated |

## Development

The fixtures in `ci/` are rendered and schema-checked on every pull
request. They are excluded from the packaged chart.

```console
$ mage chart:version    # Chart.yaml tracks internal/version
$ mage chart:lint       # helm lint, once per fixture
$ mage chart:validate   # render everything, check against Kubernetes schemas
$ mage chart:test       # assert what it renders, and that the guards refuse
$ mage chart:package    # write dist/openvox-ca-<version>.tgz
```

`chart:validate` needs `helm` and
[`kubeconform`](https://github.com/yannh/kubeconform) on `PATH`.
