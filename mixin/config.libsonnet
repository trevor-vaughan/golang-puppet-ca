{
  _config+:: {
    // puppetCASelector matches the Prometheus targets that scrape the
    // openvox-ca exporter. Override it to pin the alerts to a specific job,
    // namespace, or instance — e.g. 'job="openvox-ca",namespace="pki"'.
    puppetCASelector: 'job="openvox-ca"',

    // alertLabels are merged onto every alert (e.g. a team or severity routing
    // label). 'severity' is set per-alert below and should not be put here.
    alertLabels: {},

    // --- CA certificate expiry ---
    // Warn well ahead of CA expiry (re-keying a CA is disruptive); page when it
    // becomes urgent. Values are in seconds.
    caExpiryWarningSeconds: 30 * 24 * 3600,  // 30 days
    caExpiryCriticalSeconds: 7 * 24 * 3600,  // 7 days

    // --- CRL expiry ---
    // The CA auto-refreshes its CRL, so an approaching NextUpdate usually means
    // the refresher is wedged. Warn a few days out; page once it has lapsed.
    crlExpiryWarningSeconds: 3 * 24 * 3600,  // 3 days

    // --- Leaf certificate expiry ---
    // Agents normally auto-renew; a leaf nearing expiry indicates a node that
    // has stopped checking in. Revoked certs are excluded by the alert exprs.
    leafExpiryWarningSeconds: 7 * 24 * 3600,  // 7 days
    leafExpiryCriticalSeconds: 24 * 3600,  // 1 day

    // --- Pending requests ---
    // How long a certificate request may sit unsigned before alerting. Set to a
    // larger value (or silence the alert) on CAs that sign manually by policy.
    pendingFor: '1h',

    // --- CRL update failures ---
    // The CA may fail to amend its CRL (a revocation it cannot record, or a CRL
    // it cannot re-sign or write). Some of these are best-effort and swallowed
    // — e.g. revoking the certificate a renewal supersedes — leaving the old
    // certificate valid for its key. The counter resets on restart, so the
    // alert looks at increase() over crlUpdateWindow and debounces with
    // crlUpdateFor.
    crlUpdateWindow: '1h',
    crlUpdateFor: '15m',

    // --- Self-provisioned serving certificate ---
    // The CA could not renew the certificate its own listener presents. The
    // exposure bound behind tls_self_provision_revoke_after_sec assumes renewals
    // succeed, so a replica failing this quietly is how a superseded certificate
    // stays valid past its intended window — and how the live one eventually
    // expires. Like the CRL counter, this resets on restart, so the alert looks
    // at increase() over a window.
    servingRenewalWindow: '1h',
    servingRenewalFor: '15m',

    // --- Kubernetes export ---
    // A target alerts while its most recent apply attempt failed (last-error
    // newer than last-success). Exports are event-driven and can be days apart
    // on a quiet CA, so the alert is stateful and stays firing until a retry
    // succeeds; 'for' only debounces a failure that is corrected moments later.
    k8sExportFailingFor: '15m',

    // 'for' durations applied to the expiry alerts to debounce flapping at the
    // threshold boundary.
    expiryFor: '1h',
    scrapeFor: '15m',
    readyFor: '10m',
    downFor: '5m',
  },
}
