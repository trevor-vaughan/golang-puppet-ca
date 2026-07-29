# openvox-ca Helm chart

Deploys [openvox-ca](https://github.com/voxpupuli/openvox-ca), a
Puppet-compatible X.509 certificate authority and a drop-in replacement for the
CA built into OpenVox/Puppet Server.

The chart is released in lockstep with openvox-ca itself: its `version` and
`appVersion` are always the release version, so chart `0.9.0` deploys
openvox-ca `0.9.0`. It is published as an OCI artefact only — there is no HTTP
chart repository to add.

A server TLS certificate is **required**: openvox-ca refuses to serve plain
HTTP on a non-loopback address, so the chart refuses to render an install that
has none rather than handing you a crash-looping pod.

```console
$ helm install openvox-ca \
    oci://ghcr.io/voxpupuli/openvox-ca-charts/openvox-ca \
    --version 0.9.0 \
    --namespace puppet --create-namespace \
    --set tls.existingSecret=openvox-ca-server-tls
```

There are two routes to a serving certificate. The one above mounts a Secret you
supply. The other lets the CA issue and renew its own, which is the route to use
when nothing else can issue it — with the CA key in OpenBao, cert-manager cannot
act as a CA issuer:

```console
$ helm install openvox-ca \
    oci://ghcr.io/voxpupuli/openvox-ca-charts/openvox-ca \
    --version 0.9.0 \
    --namespace puppet --create-namespace \
    --set config.tls_self_provision=true \
    --set config.hostname=openvox-ca.puppet.svc.cluster.local
```

The two are mutually exclusive, and the chart refuses the combination.

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
  so you can override anything a convenience block computed.
- **`env`, `extraEnv` and `envFrom`** are the escape hatch for settings that
  must come from a Secret at runtime, such as a database DSN.

A single `helm template` will show you exactly what the merge produced.

## Requirements

Kubernetes **1.26 or newer** (the `kubeVersion` floor in `Chart.yaml`, checked
against the 1.26 schemas in CI). Two optional values need more:
`podDisruptionBudget.unhealthyPodEvictionPolicy` needs 1.27, and
`service.trafficDistribution` needs 1.31.

Helm 3.21 or 4.2; both are exercised in CI.

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
| `existingConfigMap` | `""` | Use a ConfigMap you manage instead of rendering one. The chart cannot checksum what it did not render, so `configChecksumAnnotation` has no effect and editing that ConfigMap will **not** restart the pods — the server has no reload path, so roll them yourself |
| `configMount` | `/etc/puppet-ca` | Where the config ConfigMap is mounted |
| `extraConfigFiles` | `{}` | Extra `filename: contents` entries placed alongside `config.yaml` |
| `listen.host` | `0.0.0.0` | API listen address; use `[::]` for a dual-stack Service |
| `listen.port` | `8140` | API listen port |
| `verbosity` | `0` | `0`=Info, `1`=Debug, `2`=Trace. Written into `config.yaml`, so `config.verbosity` overrides it |
| `puppetServers` | `[]` | CNs granted admin API access over mTLS; rendered into a file and wired to `puppet_server_file`. One entry per line — an entry containing a newline is refused |
| `autosign.mode` | `""` | `"false"`, `"true"`, or a path inside the container |
| `autosign.patterns` | `[]` | Glob allowlist rendered into the config ConfigMap; sets `autosign_config` |

### TLS and CA material

| Key | Default | Description |
| --- | --- | --- |
| `tls.existingSecret` | `""` | Secret holding the server certificate; sets `tls_cert`/`tls_key` |
| `tls.certKey` / `tls.keyKey` | `tls.crt` / `tls.key` | Data keys within that Secret |
| `tls.mountPath` | `/run/secrets/openvox-ca-tls` | |
| `ca.existingSecret` | `""` | Secret holding the CA certificate and key; sets `ca_cert_file`/`ca_key_file` |
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
| `metrics.serviceMonitor.jobLabel` / `.targetLabels` | `""` / `[]` | |
| `metrics.serviceMonitor.relabelings` / `.metricRelabelings` | `[]` | |

### Kubernetes export

| Key | Default | Description |
| --- | --- | --- |
| `kubernetesExport.enabled` | `false` | Publish the CA cert, CRL and/or the self-provisioned serving certificate and key into Secrets and ConfigMaps |
| `kubernetesExport.fieldManager` | `""` | Server-side apply field manager |
| `kubernetesExport.targets` | `[]` | Passed through to `kubernetes_export.targets` |
| `kubernetesExport.rbac.create` | `true` | Create the `create`/`patch` Role and binding |
| `kubernetesExport.rbac.scope` | `Role` | `Role` or `ClusterRole` |
| `kubernetesExport.rbac.namespaces` | `[]` | Extra namespaces to bind the Role into |

### Workload

| Key | Default | Description |
| --- | --- | --- |
| `replicaCount` | `1` | More than one requires an external storage backend |
| `strategy` | `{type: Recreate}` | Recreate suits the default ReadWriteOnce volume; switch to RollingUpdate with an external backend |
| `revisionHistoryLimit` | `10` | |
| `command` | `[]` | Overrides the container entrypoint |
| `args` | `[]` | Overrides the generated argument list outright |
| `extraArgs` | `[]` | Appended to the generated arguments |
| `env` | `{}` | Literal environment variables, as a map |
| `extraEnv` | `[]` | Environment variables in list form, for `valueFrom` |
| `envFrom` | `[]` | `configMapRef`/`secretRef` sources, verbatim |
| `resources` | 10m CPU / 48–64Mi | |
| `configChecksumAnnotation` | `true` | Roll the pods when the rendered config changes. Inert when `existingConfigMap` is set |
| `podAnnotations` / `podLabels` | `{}` | |
| `deploymentAnnotations` | `{}` | Annotations on the Deployment rather than the pods |
| `podSecurityContext` | non-root uid/gid 1000, `fsGroup` 1000, `RuntimeDefault` | |
| `securityContext` | no privilege escalation, read-only rootfs, all capabilities dropped | |
| `livenessProbe` / `readinessProbe` / `startupProbe` | probes on `/healthz/*` | Set `enabled: false` to drop one; other keys are the probe spec. `httpGet.scheme` defaults to HTTPS or HTTP to match whether the server has a certificate |
| `lifecycle` | `{}` | |
| `terminationGracePeriodSeconds` | `30` | Must exceed `shutdown_timeout_sec` by ≥ 3s |
| `nodeSelector` / `tolerations` / `affinity` | `{}` / `[]` / `{}` | |
| `topologySpreadConstraints` | one soft constraint per hostname | A constraint with no `labelSelector` gets this release's own selector |
| `priorityClassName` / `runtimeClassName` / `schedulerName` | `""` | |
| `dnsPolicy` / `dnsConfig` / `hostAliases` | `""` / `{}` / `[]` | |
| `enableServiceLinks` | `false` | |
| `automountServiceAccountToken` | `null` | `null` mounts the token only when the pod needs the API (Kubernetes export, OpenBao Kubernetes auth) |
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
| `gateway.tlsRoute.backendPort` | `https` | `https` or `metrics` |
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
| `networkPolicy.egress.rules` | `[]` | Your storage backend, OpenBao, the API server |
| `networkPolicy.extraIngress` | `[]` | |

### Availability

| Key | Default | Description |
| --- | --- | --- |
| `podDisruptionBudget.enabled` | `false` | |
| `podDisruptionBudget.minAvailable` | `1` | Ignored when `maxUnavailable` is set |
| `podDisruptionBudget.maxUnavailable` | `""` | `0` is honoured (block every voluntary eviction), not treated as unset |
| `podDisruptionBudget.unhealthyPodEvictionPolicy` | `""` | Kubernetes 1.27+ |
| `autoscaling.enabled` | `false` | Requires an external storage backend |
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
