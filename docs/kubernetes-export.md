# Kubernetes export

openvox-ca can optionally publish the **CA certificate**, the **CRL**, and the
**serving certificate it issued for itself** into one or more Kubernetes
**Secrets** and **ConfigMaps**, so that other workloads in the cluster can mount
them directly (e.g. as a trust bundle, for CRL distribution, or for an Ingress
to terminate TLS) instead of fetching them over the HTTP API or sharing a
storage volume.

- Any number of targets, each a Secret **or** a ConfigMap.
- Each target may carry the **CA cert**, the **CRL**, the **serving
  certificate**, the **serving key**, or a combination (PEM only for now). The
  serving material requires `tls_self_provision`.
- The data keys, name, namespace, labels, annotations, and a Secret's `type`
  field are all configurable.
- Targets are re-exported whenever the material they carry changes: **the CRL**
  (revoke, reissue, background refresh, expired-cert cleanup) or **a serving
  certificate rotation**. All targets are also reconciled **once at startup**,
  and a cycle with failures is retried on a bounded interval.
- A material that cannot be read fails only the targets that asked for it.

The feature is **disabled by default**; it activates only when at least one
target is configured.

## How it works

The exporter runs inside the openvox-ca pod and talks to the Kubernetes API
using the pod's **in-cluster ServiceAccount** credentials. It is therefore only
available when openvox-ca itself runs inside a Kubernetes cluster.

Objects are reconciled with **server-side apply** (field manager `openvox-ca` by
default), which makes every export an idempotent create-or-update and lets the CA
co-exist with other managers of the same object. Apply uses `force`, so fields
owned by the exporter are reclaimed if something else overwrites them.

Every managed object carries the label `app.kubernetes.io/managed-by:
openvox-ca` so you can find and select the objects openvox-ca owns:

```sh
kubectl get secret,configmap -A -l app.kubernetes.io/managed-by=openvox-ca
```

Each replica runs its own exporter; because writes go through server-side apply,
concurrent exports from multiple replicas are safe.

## Configuration

Kubernetes export is **YAML-file only** — its nested structure (a list of
targets, each with labels and annotations) does not map cleanly onto flags or
environment variables. Add a `kubernetes_export` block to the config file:

```yaml
kubernetes_export:
  # Server-side apply field manager. Optional; default "openvox-ca".
  field_manager: openvox-ca

  targets:
    # A Secret holding both the CA cert and the CRL.
    - kind: Secret              # "Secret" or "ConfigMap" (required; case-insensitive)
      metadata:
        name: openvox-ca-trust  # required
        namespace: puppet       # optional; defaults to the pod's own namespace
        labels:
          app.kubernetes.io/part-of: puppet
        annotations:
          example.com/owner: platform-team
      type: Opaque              # Secret only; optional (see "Secret type" below)
      cert: true                # include the CA certificate (default false)
      crl: true                 # include the CRL (default false)
      cert_key: ca.crt          # data key for the cert; default "ca.crt"
      crl_key: ca.crl           # data key for the CRL; default "ca.crl"

    # A ConfigMap holding only the CRL, in a namespace of its own.
    - kind: ConfigMap
      metadata:
        name: openvox-ca-crl
        namespace: monitoring
      crl: true
      crl_key: ca_crl.pem
```

### Target fields

| Field | Applies to | Default | Notes |
| --- | --- | --- | --- |
| `kind` | both | — | `Secret` or `ConfigMap` (required; matched case-insensitively) |
| `metadata.name` | both | — | Object name (required) |
| `metadata.namespace` | both | pod's namespace | Resolved from the ServiceAccount mount when empty |
| `metadata.labels` | both | — | Merged with the mandatory `managed-by` label |
| `metadata.annotations` | both | — | Applied verbatim |
| `cert` | both | `false` | Include the CA certificate |
| `crl` | both | `false` | Include the CRL |
| `serving_cert` | both | `false` | Include the self-provisioned serving certificate |
| `serving_key` | Secret | `false` | Include the serving private key (see below) |
| `cert_key` | both | `ca.crt` | Data key for the cert |
| `crl_key` | both | `ca.crl` | Data key for the CRL |
| `serving_cert_key` | both | `tls.crt` | Data key for the serving certificate |
| `serving_key_key` | Secret | `tls.key` | Data key for the serving key |
| `type` | Secret | unmanaged | Secret `type` field; unset means the exporter does not own it (see below); rejected on ConfigMaps |

At least one material must be selected, and no two may share a data key.

### Serving certificate and key

With [`tls_self_provision`](configuration.md#self-provisioned-serving-certificate)
the CA issues its own serving certificate. Exporting it produces a
`kubernetes.io/tls` Secret an Ingress or Gateway can terminate against — which
is why these two default to `tls.crt` and `tls.key` rather than the
trust-bundle convention the other materials use.

**Not for the agent-facing hostname.** A controller that terminates TLS strips
the client certificate, so every mTLS endpoint stops authenticating; the CA has
to be reached through a passthrough controller. This pair is for SNI routing at
such a controller, for an edge serving only the anonymous endpoints (CRL, OCSP,
health), or for anything else in the cluster that needs the certificate. See
[Ingress and TLS passthrough](helm-chart.md#ingress).

```yaml
kubernetes_export:
  targets:
    # Public trust material: mounted widely, read by many workloads.
    - kind: Secret
      metadata:
        name: openvox-ca-trust
      cert: true
      crl: true
    # The serving pair, on its own.
    - kind: Secret
      metadata:
        name: openvox-ca-serving
      type: kubernetes.io/tls
      serving_cert: true
      serving_key: true
```

Two rules apply to `serving_key`, both about blast radius:

- **It is rejected on a ConfigMap.** Those are not encrypted at rest and are
  readable by anything that can `get` them.
- **It cannot share a target with `cert` or `crl`.** A Secret holding `ca.crt`
  is public trust material and gets mounted across the cluster; letting it
  quietly acquire a `tls.key` entry would extend the serving key's reach to
  every workload that reads it. Two targets cost nothing — but give them different
*names* as well: two targets naming the same object overwrite each other on
every cycle, and the server refuses that at startup. The serving
  *certificate* is public and may share a target with anything.

**The exported key is always plaintext**, even when
`tls_self_provision_encrypt_key` is set — the exporter publishes the key the
listener is already using, which the CA decrypted when it loaded it. A
`kubernetes.io/tls` Secret holding an encrypted PEM is useless to every
consumer of one: it would look correct and fail at the first handshake. That is a deliberate downgrade: the key is then plaintext in etcd.
The server logs a warning at startup whenever a `serving_key` target is
configured. Restrict who can read that Secret.

**A replica never publishes a serving pair it knows is superseded.** Before
publishing, it compares the certificate it is presenting with the one in
storage; if they differ it is behind — another replica has rotated — and it
publishes nothing that cycle rather than writing its own copy back. That is a
quiet skip, not a failure: it is normal, it clears when that replica's next
maintenance pass catches it up, and the replica that rotated has already
published the new pair. Nothing alerts, and nothing needs to — a replica that
stays behind is one whose maintenance pass is failing, which
`PuppetCAServingCertRenewalFailing` already covers.

That is a bound, not an absolute. The comparison happens when the material is
read, and the apply follows; two replicas can still order their applies against
each other, so a Secret can briefly carry the pair the losing replica read. The
ten-minute reconcile corrects it.

Revoking alone does not stop republication: `openvox-ca-ctl revoke` adds the
serial to the CRL, it does not replace the stored certificate. Republication
stops once some replica notices the revocation and mints the replacement, which
happens on its next maintenance pass. **After a key compromise, restart the
replicas** so a fresh boot mints immediately, and delete or overwrite the
exported Secret rather than waiting for it to be corrected.

### Secret type

When `type` is set, the exporter owns the Secret's `type` field. When it is
**omitted**, the exporter does not manage `type` at all: the API server defaults
a newly-created Secret to `Opaque`, and the type of an existing Secret is left
untouched. This lets openvox-ca **co-maintain** a Secret owned by another tool —
for example a `kubernetes.io/tls` Secret whose `tls.crt`/`tls.key` are pushed by
Flux — by applying only the CRL (or cert) into a data key of its own and leaving
the type, and the other manager's keys, alone. Do not set `type:
kubernetes.io/tls` on a target that only carries the CA cert/CRL: such a Secret
must also contain `tls.crt` and `tls.key`, so the server refuses to start rather
than letting the apply fail.

Secret data is written under `data` (base64-encoded by the client), and
ConfigMap data as plain text under `data`. Using `data` rather than the
write-only `stringData` keeps each server-side apply idempotent, so re-exporting
unchanged material is a genuine no-op.

## RBAC

The pod's ServiceAccount needs permission to create and server-side-apply the
target objects in each target namespace. The exporter only ever creates or
applies objects — it never reads them — so `create` and `patch` are the only
verbs required (server-side apply is a `patch`):

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: openvox-ca-export
  namespace: puppet
rules:
  - apiGroups: [""]
    resources: ["secrets", "configmaps"]
    verbs: ["create"]
  - apiGroups: [""]
    resources: ["secrets", "configmaps"]
    verbs: ["patch"]
    # Named, so this cannot patch any other workload's Secret — which matters
    # more now the CA publishes a private key. The chart does the same.
    # `create` cannot be narrowed this way: at admission the object has no name.
    resourceNames: ["openvox-ca-trust", "openvox-ca-serving"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: openvox-ca-export
  namespace: puppet
subjects:
  - kind: ServiceAccount
    name: openvox-ca           # the SA your CA pod runs as
    namespace: puppet
roleRef:
  kind: Role
  name: openvox-ca-export
  apiGroup: rbac.authorization.k8s.io
```

Create a `Role`/`RoleBinding` pair in **each** namespace you export into, or use
a `ClusterRole` with per-namespace `RoleBinding`s. Restrict the verbs and
resources to the minimum above.

## Behaviour and failure handling

- The export is **auxiliary**: if the Kubernetes client cannot be constructed
  (e.g. openvox-ca is not running in a cluster, or the namespace cannot be
  resolved), the error is logged and the CA continues serving normally.
- A failure applying one target is logged and does not prevent the other targets
  from being applied. A cycle with failures is retried after two minutes, and
  cycles run on a ten-minute floor even when nothing has changed, which repairs
  an object edited or deleted out from under the exporter.
- Configuration is validated at startup; an invalid `kubernetes_export` block
  (bad `kind`, a `type` on a ConfigMap, none of `cert`, `crl`, `serving_cert` or
  `serving_key`, two targets naming the same object, `serving_key` on a
  ConfigMap or sharing a target with `cert`/`crl`, `kubernetes.io/tls` without
  both serving materials, a serving target without `tls_self_provision`,
  colliding
  keys, …) stops the server with a clear error.

## Metrics

When the [Prometheus exporter](metrics.md) is enabled, each apply attempt is
counted in `puppetca_k8s_export_applies_total{kind,namespace,name,result}`, and
per-target `last_success` / `last_error` timestamp gauges record the most
recent outcomes. Because export failures are only logged, alerting on these
series is the recommended way to catch a target that persistently fails; the
[monitoring mixin](../mixin/) ships a `PuppetCAKubernetesExportFailing` alert
that fires while a target's most recent apply attempt failed.

## Limitations

- In-cluster ServiceAccount authentication only (no external kubeconfig).
- PEM encoding only (no DER).
- Objects are not deleted when a target is removed from the config; delete them
  manually (they carry the `app.kubernetes.io/managed-by=openvox-ca` label).
