# OpenVox CA monitoring mixin

A [monitoring mixin](https://monitoring.mixins.dev/) providing Prometheus
alerting rules for the openvox-ca exporter. It alerts on:

- the exporter being down or unable to read CA state, and the CA not being ready;
- the **CA certificate** nearing expiry (warning) or expiring imminently (critical);
- the **CRL** approaching its `NextUpdate` (warning) or having lapsed (critical);
- **leaf certificates** nearing/at expiry — excluding revoked ones — and
  certificate **requests that stay pending** too long;
- **CRL update failures** — the CA failing to amend its CRL (a revocation it
  could not record, or a CRL it could not re-sign or write), which can leave
  revoked or superseded certificates still valid.
- **Serving-certificate failures** — three rules. Two are meaningful only when
  [`tls_self_provision`](../docs/configuration.md#self-provisioned-serving-certificate)
  is in use; *Revocation failing* is live wherever `hostname` is set, because the
  startup sweep runs unconditionally, and that is the case with no retry. *Renewal failing*: the CA cannot renew the certificate its own
  listener presents, which is silent until it expires, at which point every
  agent handshake fails at once. *Revocation failing*: a superseded certificate was
  not revoked, so it stays a valid credential past the bound
  `tls_self_provision_revoke_after_sec` is meant to enforce. The log line
  distinguishes the cases: a failed sweep or a failed single revocation retries,
  so a firing alert means the retries are not clearing it; a mint that could not
  read or write down what it replaced never scheduled that serial at all, and
  since there is no by-serial revoke it cannot be retired — see
  [the metric's notes](../docs/metrics.md#self-provisioned-serving-certificate). *Churning*: replicas reissuing over each other, which grows
  the inventory and the CRL for no reason.
- **Kubernetes export** targets whose applies keep failing (only when the
  [Kubernetes export](../docs/kubernetes-export.md) feature is in use).

All thresholds and the target selector live in [`config.libsonnet`](config.libsonnet)
and can be overridden without editing the rules.

## Enabling the exporter

The alerts assume the openvox-ca Prometheus exporter is enabled and scraped. Start
the server with `--metrics-listen` (or `PUPPET_CA_METRICS_LISTEN` /
`metrics_listen:` in the config file):

```sh
openvox-ca --cadir /var/lib/puppet-ca --metrics-listen 127.0.0.1:9140
```

The exporter serves `/metrics` over plain HTTP on its own listener. It exposes
node hostnames as label values, so bind it to loopback or a trusted management
network and scrape it from there. A matching Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: openvox-ca
    static_configs:
      - targets: ['openvox-ca.internal:9140']
```

The `job_name` must match `puppetCASelector` in the mixin config (default
`job="openvox-ca"`).

## Rendering the alerts standalone

With [`jsonnet`](https://github.com/google/go-jsonnet) installed:

```sh
jsonnet -S -e "std.manifestYamlDoc((import 'mixin.libsonnet').prometheusAlerts)" \
  > puppet_ca_alerts.yaml
promtool check rules puppet_ca_alerts.yaml
```

## Importing into another repo

Vendor the mixin with [jsonnet-bundler](https://github.com/jsonnet-bundler/jsonnet-bundler):

```sh
jb install https://github.com/voxpupuli/openvox-ca/mixin@main
```

Then combine it with your overrides:

```jsonnet
// mixin.jsonnet
local puppetca = (import 'vendor/openvox-ca/mixin.libsonnet') + {
  _config+:: {
    puppetCASelector: 'job="pki/openvox-ca"',
    caExpiryWarningSeconds: 45 * 24 * 3600,
  },
};

{
  'puppet_ca_alerts.yaml': std.manifestYamlDoc(puppetca.prometheusAlerts),
}
```

```sh
jsonnet -J vendor -m . mixin.jsonnet
```

## Configurable thresholds

| Key | Default | Meaning |
| --- | --- | --- |
| `puppetCASelector` | `job="openvox-ca"` | Label selector matching the exporter targets. |
| `alertLabels` | `{}` | Extra labels merged onto every alert (e.g. routing labels). |
| `caExpiryWarningSeconds` | 30 days | CA certificate expiry warning threshold. |
| `caExpiryCriticalSeconds` | 7 days | CA certificate expiry critical threshold. |
| `crlExpiryWarningSeconds` | 3 days | CRL `NextUpdate` warning threshold. |
| `leafExpiryWarningSeconds` | 7 days | Leaf certificate expiry warning threshold. |
| `leafExpiryCriticalSeconds` | 1 day | Leaf certificate expiry critical threshold. |
| `pendingFor` | `1h` | How long a request may stay pending before alerting. |
| `crlUpdateWindow` | `1h` | Window over which CRL-update failures are counted (the metric is a restart-resetting counter). |
| `crlUpdateFor` | `15m` | `for:` debounce for the CRL-update-failure alert. |
| `expiryFor` / `scrapeFor` / `readyFor` / `downFor` / `k8sExportFailingFor` | `1h` / `15m` / `10m` / `5m` / `15m` | `for:` debounce durations. |
| `servingRenewalWindow` | `1h` | Window over which serving-certificate renewal failures are counted. |
| `servingRenewalFor` | `15m` | `for:` debounce for the serving-renewal-failure alert. |
| `servingRevocationWindow` | `1h` | Window over which superseded-revocation failures are counted. |
| `servingRevocationFor` | `15m` | `for:` debounce for the superseded-revocation-failure alert. |
| `servingChurnWindow` | `6h` | Window over which serving-certificate reissues are counted. |
| `servingChurnThreshold` | `4` | Reissues within that window before churn is alerted. One per renewal period is normal. |
| `servingChurnFor` | `15m` | `for:` debounce for the churn alert. |

> **The three `serving*` windows are calibrated to the CA's
> `maintenance_interval_sec` (default 1h), and the churn rule breaks if you
> ignore that.** `servingChurnWindow / maintenance_interval_sec` must exceed
> `servingChurnThreshold` or the rule can never fire: at a 2h interval the
> shipped `6h` window yields at most 3 increments against a threshold of 4, and
> the condition the metric exists to expose becomes permanently invisible. If
> you raise `maintenance_interval_sec`, raise `servingChurnWindow` with it.
