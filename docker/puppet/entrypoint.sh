#!/bin/bash
# Entrypoint for the OpenVox Server container.
#
# 1. Waits for the Go CA (HTTPS) and downloads CA cert + CRL.
# 2. Generates a server key + CSR and gets it signed by the CA.
# 3. Writes puppet.conf, puppetdb.conf, webserver.conf.
# 4. Disables the built-in Puppet CA in services.d/ca.cfg (or bootstrap.cfg).
# 5. Launches a background CRL-refresh daemon.
# 6. Starts `puppetserver foreground`.

set -euo pipefail

export PATH=/opt/puppetlabs/server/bin:/opt/puppetlabs/puppet/bin:$PATH

# ── Configuration ─────────────────────────────────────────────────────────
CA_HOST="${PUPPET_CA_HOST:-puppet-ca}"
CA_PORT="${PUPPET_CA_PORT:-8140}"
CA_URL="https://${CA_HOST}:${CA_PORT}"

# PUPPET_FQDN may be set explicitly (e.g. in compose) to avoid relying on
# `hostname -f` which may differ inside a container.
FQDN="${PUPPET_FQDN:-$(hostname -f 2>/dev/null || hostname)}"

PUPPET_SSL=/etc/puppetlabs/puppet/ssl

echo "=== OpenVox Server Bootstrap ==="
echo "  FQDN   : ${FQDN}"
echo "  CA URL : ${CA_URL}"

# ── SSL directory structure ───────────────────────────────────────────────
mkdir -p \
    "${PUPPET_SSL}/ca" \
    "${PUPPET_SSL}/certs" \
    "${PUPPET_SSL}/private_keys" \
    "${PUPPET_SSL}/certificate_requests" \
    "${PUPPET_SSL}/public_keys"

# ── Wait for Go CA (HTTPS) ────────────────────────────────────────────────
echo "Waiting for Go CA at ${CA_URL}..."
until curl -sfk "${CA_URL}/puppet-ca/v1/certificate/ca" > /dev/null 2>&1; do
    sleep 2
done
echo "Go CA is ready."

# ── Download CA cert (first fetch — skip TLS verify) ─────────────────────
# We do not yet have the CA cert to verify against; skip-verify is safe here
# because we're fetching the CA cert itself (any tampering would be caught
# later when puppet verifies server certs against this CA cert).
curl -sfk "${CA_URL}/puppet-ca/v1/certificate/ca" \
     -o "${PUPPET_SSL}/ca/ca_crt.pem"
echo "CA cert downloaded."

# ── Download CRL (verified against CA cert) ───────────────────────────────
curl -sf "${CA_URL}/puppet-ca/v1/certificate_revocation_list/ca" \
     --cacert "${PUPPET_SSL}/ca/ca_crt.pem" \
     -o "${PUPPET_SSL}/ca/ca_crl.pem"
echo "CRL downloaded."

# ── Generate server key + signed cert (idempotent) ────────────────────────
if [ ! -s "${PUPPET_SSL}/certs/${FQDN}.pem" ]; then
    echo "Generating RSA key for ${FQDN}..."
    openssl genrsa -out "${PUPPET_SSL}/private_keys/${FQDN}.pem" 4096 2>/dev/null
    chmod 640 "${PUPPET_SSL}/private_keys/${FQDN}.pem"

    echo "Creating CSR..."
    openssl req -new \
        -key "${PUPPET_SSL}/private_keys/${FQDN}.pem" \
        -subj "/CN=${FQDN}" \
        -out "/tmp/${FQDN}.csr" 2>/dev/null

    echo "Submitting CSR to Go CA..."
    _csr_status=$(curl -s -o /dev/null -w "%{http_code}" \
        --cacert "${PUPPET_SSL}/ca/ca_crt.pem" \
        -X PUT \
        -H "Content-Type: text/plain" \
        --data-binary "@/tmp/${FQDN}.csr" \
        "${CA_URL}/puppet-ca/v1/certificate_request/${FQDN}")
    echo "CSR submission status: ${_csr_status}"

    echo "Waiting for signed cert..."
    for _i in $(seq 1 30); do
        if curl -sf \
               --cacert "${PUPPET_SSL}/ca/ca_crt.pem" \
               "${CA_URL}/puppet-ca/v1/certificate/${FQDN}" \
               -o "${PUPPET_SSL}/certs/${FQDN}.pem" 2>/dev/null; then
            echo "Server cert obtained for ${FQDN}."
            break
        fi
        sleep 2
    done

    if [ ! -s "${PUPPET_SSL}/certs/${FQDN}.pem" ]; then
        echo "ERROR: Timed out waiting for cert to be signed." >&2
        exit 1
    fi
else
    echo "Server cert already exists — skipping key generation."
fi

# ── File permissions ──────────────────────────────────────────────────────
chown -R puppet:puppet "${PUPPET_SSL}"
chmod 644 \
    "${PUPPET_SSL}/ca/ca_crt.pem" \
    "${PUPPET_SSL}/ca/ca_crl.pem" \
    "${PUPPET_SSL}/certs/${FQDN}.pem"
chmod 640 "${PUPPET_SSL}/private_keys/${FQDN}.pem"

# ── Symlinks required by puppet agent and PuppetDB terminus ───────────────
# puppet agent reads certs/ca.pem; PuppetDB terminus reads crl.pem directly.
ln -sf "${PUPPET_SSL}/ca/ca_crt.pem" "${PUPPET_SSL}/certs/ca.pem"
ln -sf "${PUPPET_SSL}/ca/ca_crl.pem" "${PUPPET_SSL}/crl.pem"

# ── Write puppet.conf ─────────────────────────────────────────────────────
cat > /etc/puppetlabs/puppet/puppet.conf <<EOF
[main]
certname    = ${FQDN}
server      = ${FQDN}
ca_server   = ${CA_HOST}
ca_port     = ${CA_PORT}
ssldir      = ${PUPPET_SSL}
environment = production

[server]
ca = false
EOF
chown puppet:puppet /etc/puppetlabs/puppet/puppet.conf
echo "puppet.conf written."

# ── Configure webserver.conf (TLS) ────────────────────────────────────────
# Tell puppetserver which cert/key to use for TLS and how to validate client
# certificates.  ssl-client-auth: want requests a cert but does not require
# it, allowing unauthenticated requests to be handled by auth rules.
cat > /etc/puppetlabs/puppetserver/conf.d/webserver.conf <<EOF
webserver: {
    ssl-host: 0.0.0.0
    ssl-port: 8140
    ssl-cert: ${PUPPET_SSL}/certs/${FQDN}.pem
    ssl-key: ${PUPPET_SSL}/private_keys/${FQDN}.pem
    ssl-ca-cert: ${PUPPET_SSL}/ca/ca_crt.pem
    ssl-crl-path: ${PUPPET_SSL}/ca/ca_crl.pem
    client-auth: want
}
EOF
echo "webserver.conf written."

# ── Disable built-in Puppet CA ────────────────────────────────────────────
# Replace certificate-authority-service with the disabled stub so puppetserver
# defers all CA operations to the external Go puppet-ca.
# In Puppet Server 7+, the CA service entry is in services.d/ca.cfg.
# Older versions used bootstrap.cfg.
_CA_CFG=/etc/puppetlabs/puppetserver/services.d/ca.cfg
[ -f "$_CA_CFG" ] || _CA_CFG=/etc/puppetlabs/puppetserver/bootstrap.cfg
sed -i \
    's|certificate-authority-service/certificate-authority-service|certificate-authority-disabled-service/certificate-authority-disabled-service|g' \
    "$_CA_CFG"
echo "Built-in CA disabled in ${_CA_CFG}."

# ── PuppetDB configuration (conditional on OPENVOXDB_HOST) ───────────────
if [ -n "${OPENVOXDB_HOST:-}" ]; then
    _DB_PORT="${OPENVOXDB_PORT:-8081}"

    cat > /etc/puppetlabs/puppet/puppetdb.conf <<EOF
[main]
server_urls        = https://${OPENVOXDB_HOST}:${_DB_PORT}
soft_write_failure = false
EOF

    cat > /etc/puppetlabs/puppet/routes.yaml <<EOF
---
master:
  facts:
    terminus: puppetdb
    cache: yaml
EOF

    # Append storeconfigs settings to puppet.conf [server] section.
    cat >> /etc/puppetlabs/puppet/puppet.conf <<EOF
storeconfigs         = true
storeconfigs_backend = puppetdb
reports              = store,puppetdb
EOF

    chown puppet:puppet \
        /etc/puppetlabs/puppet/puppetdb.conf \
        /etc/puppetlabs/puppet/routes.yaml
    echo "PuppetDB configured: https://${OPENVOXDB_HOST}:${_DB_PORT}"
fi

chown puppet:puppet /etc/puppetlabs/puppet/puppet.conf

# ── Background CRL refresh daemon ────────────────────────────────────────
# Refreshes the CRL every 30 minutes.  Puppet Server re-reads the CRL file
# on each SSL handshake so no server restart is needed.
(
    while true; do
        sleep 1800
        _NEW_CRL=$(curl -sf \
            --cacert "${PUPPET_SSL}/ca/ca_crt.pem" \
            "${CA_URL}/puppet-ca/v1/certificate_revocation_list/ca" 2>/dev/null || true)
        if [ -n "${_NEW_CRL}" ]; then
            echo "${_NEW_CRL}" > "${PUPPET_SSL}/ca/ca_crl.pem"
            echo "CRL refreshed at $(date -u +%FT%TZ)"
        fi
    done
) &

# ── Start OpenVox Server ──────────────────────────────────────────────────
echo "Starting puppetserver foreground..."
exec puppetserver foreground
