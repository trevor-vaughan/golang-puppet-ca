{
  prometheusAlerts+:: {
    groups+: [
      {
        name: 'openvox-ca-availability',
        rules: [
          {
            alert: 'PuppetCAExporterDown',
            // 'up == 0' only matches an existing series; if the target is absent
            // from service discovery entirely there is no 'up' series to compare,
            // so OR in absent() to catch a wholly-missing exporter too.
            expr: |||
              up{%(selector)s} == 0
              or
              absent(up{%(selector)s})
            ||| % { selector: $._config.puppetCASelector },
            'for': $._config.downFor,
            labels: { severity: 'critical' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA metrics exporter is down.',
              description: 'Prometheus cannot scrape the Puppet CA exporter on {{ $labels.instance }}. Certificate and CRL expiry can no longer be monitored.',
            },
          },
          {
            alert: 'PuppetCAScrapeFailing',
            // The exporter answered but could not read CA state from storage.
            expr: 'puppetca_collector_scrape_success{%(selector)s} == 0' % { selector: $._config.puppetCASelector },
            'for': $._config.scrapeFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA exporter cannot read CA state.',
              description: 'The Puppet CA exporter on {{ $labels.instance }} is failing to gather certificate metrics from storage (puppetca_collector_scrape_success=0).',
            },
          },
          {
            alert: 'PuppetCANotReady',
            expr: 'puppetca_ca_ready{%(selector)s} == 0' % { selector: $._config.puppetCASelector },
            'for': $._config.readyFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA is not ready.',
              description: 'The Puppet CA on {{ $labels.instance }} has been reporting not-ready (puppetca_ca_ready=0) and cannot serve signing requests.',
            },
          },
        ],
      },
      {
        name: 'openvox-ca-certificate-expiry',
        rules: [
          {
            alert: 'PuppetCACertificateExpiringSoon',
            expr: |||
              puppetca_ca_certificate_not_after_timestamp_seconds{%(selector)s} - time() < %(warn)d
              and
              puppetca_ca_certificate_not_after_timestamp_seconds{%(selector)s} - time() >= %(crit)d
            ||| % {
              selector: $._config.puppetCASelector,
              warn: $._config.caExpiryWarningSeconds,
              crit: $._config.caExpiryCriticalSeconds,
            },
            'for': $._config.expiryFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA certificate is approaching expiry.',
              description: 'The CA certificate ({{ $labels.common_name }}) on {{ $labels.instance }} expires in {{ $value | humanizeDuration }}.',
            },
          },
          {
            alert: 'PuppetCACertificateExpiringCritical',
            expr: 'puppetca_ca_certificate_not_after_timestamp_seconds{%(selector)s} - time() < %(crit)d' % {
              selector: $._config.puppetCASelector,
              crit: $._config.caExpiryCriticalSeconds,
            },
            'for': $._config.expiryFor,
            labels: { severity: 'critical' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA certificate expires imminently.',
              description: 'The CA certificate ({{ $labels.common_name }}) on {{ $labels.instance }} expires in {{ $value | humanizeDuration }}. Re-keying the CA is disruptive; act now.',
            },
          },
        ],
      },
      {
        name: 'openvox-ca-crl-expiry',
        rules: [
          {
            alert: 'PuppetCACRLExpiringSoon',
            expr: |||
              puppetca_crl_next_update_timestamp_seconds{%(selector)s} - time() < %(warn)d
              and
              puppetca_crl_next_update_timestamp_seconds{%(selector)s} - time() > 0
            ||| % {
              selector: $._config.puppetCASelector,
              warn: $._config.crlExpiryWarningSeconds,
            },
            'for': $._config.expiryFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA CRL is approaching its NextUpdate.',
              description: 'The CRL on {{ $labels.instance }} reaches NextUpdate in {{ $value | humanizeDuration }}. The CA normally auto-refreshes it; check the CRL refresher.',
            },
          },
          {
            alert: 'PuppetCACRLExpired',
            expr: 'puppetca_crl_next_update_timestamp_seconds{%(selector)s} - time() <= 0' % { selector: $._config.puppetCASelector },
            'for': $._config.expiryFor,
            labels: { severity: 'critical' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA CRL has expired.',
              description: 'The CRL on {{ $labels.instance }} is past its NextUpdate. Relying parties may reject it and fail revocation checks.',
            },
          },
        ],
      },
      {
        name: 'openvox-ca-leaf-certificates',
        rules: [
          {
            alert: 'PuppetCALeafCertificateExpiringSoon',
            // state!="revoked" excludes certificates that have been revoked: a
            // revoked cert nearing expiry is expected and not actionable.
            expr: |||
              puppetca_leaf_certificate_not_after_timestamp_seconds{%(selector)s,state!="revoked"} - time() < %(warn)d
              and
              puppetca_leaf_certificate_not_after_timestamp_seconds{%(selector)s,state!="revoked"} - time() >= %(crit)d
            ||| % {
              selector: $._config.puppetCASelector,
              warn: $._config.leafExpiryWarningSeconds,
              crit: $._config.leafExpiryCriticalSeconds,
            },
            'for': $._config.expiryFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'A leaf certificate is approaching expiry.',
              description: 'Certificate for {{ $labels.subject }} (serial {{ $labels.serial }}) expires in {{ $value | humanizeDuration }}. The node may have stopped renewing.',
            },
          },
          {
            alert: 'PuppetCALeafCertificateExpiringCritical',
            expr: |||
              puppetca_leaf_certificate_not_after_timestamp_seconds{%(selector)s,state!="revoked"} - time() < %(crit)d
              and
              puppetca_leaf_certificate_not_after_timestamp_seconds{%(selector)s,state!="revoked"} - time() > 0
            ||| % {
              selector: $._config.puppetCASelector,
              crit: $._config.leafExpiryCriticalSeconds,
            },
            'for': $._config.expiryFor,
            labels: { severity: 'critical' } + $._config.alertLabels,
            annotations: {
              summary: 'A leaf certificate expires imminently.',
              description: 'Certificate for {{ $labels.subject }} (serial {{ $labels.serial }}) expires in {{ $value | humanizeDuration }}.',
            },
          },
          {
            alert: 'PuppetCALeafCertificateExpired',
            expr: 'puppetca_leaf_certificate_not_after_timestamp_seconds{%(selector)s,state!="revoked"} - time() <= 0' % { selector: $._config.puppetCASelector },
            'for': $._config.expiryFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'A non-revoked leaf certificate has expired.',
              description: 'Certificate for {{ $labels.subject }} (serial {{ $labels.serial }}) on {{ $labels.instance }} has expired but is not revoked.',
            },
          },
          {
            alert: 'PuppetCACertificateRequestPending',
            expr: 'puppetca_leaf_certificate_info{%(selector)s,state="requested"} == 1' % { selector: $._config.puppetCASelector },
            'for': $._config.pendingFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'A certificate request has been pending too long.',
              description: 'The request for {{ $labels.subject }} on {{ $labels.instance }} has been awaiting signing for more than %(pendingFor)s.' % { pendingFor: $._config.pendingFor },
            },
          },
        ],
      },
      {
        name: 'openvox-ca-crl-maintenance',
        rules: [
          {
            alert: 'PuppetCACRLUpdateFailing',
            // The CA failed to amend the CRL — a revocation it could not record,
            // or a CRL it could not re-sign or write (revoke, cleanup, reissue or
            // refresh). Some callers swallow this (e.g. the best-effort revoke of
            // a superseded cert on renewal), so a revoked/superseded certificate
            // may remain valid. The counter resets on restart, so alert on
            // increase() over a window rather than a raw value.
            expr: 'increase(puppetca_crl_update_failures_total{%(selector)s}[%(window)s]) > 0' % {
              selector: $._config.puppetCASelector,
              window: $._config.crlUpdateWindow,
            },
            'for': $._config.crlUpdateFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA is failing to update its CRL.',
              description: 'The Puppet CA on {{ $labels.instance }} could not amend its CRL (puppetca_crl_update_failures_total is rising). Revocations may not have taken effect and superseded certificates may still be valid; check CRL storage and the CA logs.',
            },
          },
        ],
      },
      {
        name: 'openvox-ca-serving-certificate',
        rules: [
          {
            alert: 'PuppetCAServingCertRenewalFailing',
            // The CA could not renew the certificate its own listener presents.
            // Nothing breaks at the moment of failure — the current certificate
            // keeps serving — so this is invisible until it expires and every
            // agent's TLS handshake starts failing at once. It also undermines
            // tls_self_provision_revoke_after_sec, whose exposure bound assumes
            // a superseded certificate is promptly replaced. The counter resets
            // on restart, so alert on increase() over a window.
            expr: 'increase(puppetca_serving_cert_renewal_failures_total{%(selector)s}[%(window)s]) > 0' % {
              selector: $._config.puppetCASelector,
              window: $._config.servingRenewalWindow,
            },
            'for': $._config.servingRenewalFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA is failing to renew its own serving certificate.',
              description: 'The Puppet CA on {{ $labels.instance }} could not renew the certificate its listener presents (puppetca_serving_cert_renewal_failures_total is rising). The current certificate still serves, so this is silent until it expires; check the CA logs and its storage backend.',
            },
          },
          {
            alert: 'PuppetCAServingCertRevocationFailing',
            // The sweep that revokes superseded serving certificates is
            // failing, or a mint could not record what it replaced. Nothing
            // breaks visibly: the CA serves its current certificate
            // throughout. What is lost is the exposure bound
            // tls_self_provision_revoke_after_sec exists to enforce. The sweep
            // retries, so a single failure clears itself -- but this alert only
            // fires on a counter still rising, so a firing instance is a fault
            // the retries are not clearing. A failure to *record* leaves nothing
            // for any sweep to find, and there is no by-serial revoke, so that
            // one cannot be retired at all: see the runbook annotation.
            expr: 'increase(puppetca_serving_cert_revocation_failures_total{%(selector)s}[%(window)s]) > 0' % {
              selector: $._config.puppetCASelector,
              window: $._config.servingRevocationWindow,
            },
            'for': $._config.servingRevocationFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA is failing to revoke superseded serving certificates.',
              description: 'The Puppet CA on {{ $labels.instance }} could not revoke a serving certificate it has replaced (puppetca_serving_cert_revocation_failures_total is rising). That certificate stays a valid credential for the CA hostname past the bound tls_self_provision_revoke_after_sec exists to enforce. This alert fires only while the counter is still rising, so the retries are not clearing it: check the CA logs and its storage backend. Do NOT run "openvox-ca-ctl revoke --certname" against the CA hostname -- it resolves to the certificate the listener is currently serving. The log line names which case it is; see the runbook for what each one needs.',
              runbook_url: '%(servingRevocationRunbook)s' % $._config,
            },
          },
          {
            alert: 'PuppetCAServingCertChurning',
            // Replicas minting over each other. Each pass writes an inventory
            // row, schedules a revocation and re-signs the CRL -- a remote
            // round trip under ca_key_provider: openbao -- and the CRL entries
            // persist for the certificate's full validity. Inferring this from
            // serials would mean noticing an inventory growing for no reason.
            expr: 'increase(puppetca_serving_cert_issued_total{%(selector)s}[%(window)s]) > %(threshold)d' % {
              selector: $._config.puppetCASelector,
              window: $._config.servingChurnWindow,
              threshold: $._config.servingChurnThreshold,
            },
            'for': $._config.servingChurnFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA is reissuing its serving certificate repeatedly.',
              description: 'The Puppet CA on {{ $labels.instance }} has reissued its serving certificate more than %(threshold)d times in %(window)s. Replicas that disagree about which CA certificate is current will mint over each other on every maintenance pass; a fleet restart resolves it.' % {
                threshold: $._config.servingChurnThreshold,
                window: $._config.servingChurnWindow,
              },
            },
          },
        ],
      },
      {
        name: 'openvox-ca-kubernetes-export',
        rules: [
          {
            alert: 'PuppetCAKubernetesExportFailing',
            // The most recent apply attempt for a target failed. Exports are
            // event-driven (startup and CRL updates) and can be days apart on
            // a quiet CA, so this compares last-error/last-success timestamps
            // — a state that persists until a retry succeeds — rather than a
            // rate window, which would silently resolve between attempts. The
            // 'unless' arm catches a target that has never succeeded at all.
            expr: |||
              puppetca_k8s_export_last_error_timestamp_seconds{%(selector)s}
                > puppetca_k8s_export_last_success_timestamp_seconds{%(selector)s}
              or
              puppetca_k8s_export_last_error_timestamp_seconds{%(selector)s}
                unless puppetca_k8s_export_last_success_timestamp_seconds{%(selector)s}
            ||| % {
              selector: $._config.puppetCASelector,
            },
            'for': $._config.k8sExportFailingFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'A Kubernetes export target is failing to apply.',
              description: 'The most recent apply of {{ $labels.kind }}/{{ $labels.name }} in namespace {{ $labels.namespace }} from {{ $labels.instance }} failed; the exported object may hold a stale CA certificate or CRL until the next successful export. Check the CA logs, RBAC, and API server connectivity.',
            },
          },
        ],
      },
    ],
  },
}
