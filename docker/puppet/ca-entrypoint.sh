#!/bin/bash
# Two-phase entrypoint for puppet-ca in the Puppet stack.
#
# Phase 1: Start CA on loopback (plain HTTP) to bootstrap a TLS cert for the
#           "puppet-ca" service hostname.
# Phase 2: Restart CA on all interfaces with TLS using the generated cert.
#
# This ensures that all inter-service traffic to the CA uses genuine TLS with
# verifiable hostname matching, rather than a self-signed CA cert whose CN
# ("Puppet CA: <hostname>") would not match the service DNS name.

set -euo pipefail

CA_DIR=/data
TLS_CERT="${CA_DIR}/signed/puppet-ca.pem"
TLS_KEY="${CA_DIR}/private/puppet-ca_key.pem"

# Phase 2 passthrough: if the TLS cert was already generated (e.g. container
# restart), skip directly to the real CA startup.
if [ -s "${TLS_CERT}" ] && [ -s "${TLS_KEY}" ]; then
    echo "TLS cert already exists — starting CA with TLS."
    exec /usr/local/bin/puppet-ca \
        --cadir="${CA_DIR}" \
        --hostname=puppet-ca \
        --autosign-config=true \
        --tls-cert="${TLS_CERT}" \
        --tls-key="${TLS_KEY}" \
        --puppet-server=puppet-master \
        "$@"
fi

# ── Phase 1: bootstrap CA on loopback ──────────────────────────────────────
echo "Phase 1: bootstrapping CA on loopback to generate TLS cert..."
/usr/local/bin/puppet-ca \
    --cadir="${CA_DIR}" \
    --hostname=puppet-ca \
    --host=127.0.0.1 \
    --autosign-config=true &
PHASE1_PID=$!

# Wait for the loopback CA to accept connections.
echo "Waiting for loopback CA..."
for _i in $(seq 1 30); do
    if curl -sf http://127.0.0.1:8140/puppet-ca/v1/certificate/ca > /dev/null 2>&1; then
        break
    fi
    sleep 1
done

if ! curl -sf http://127.0.0.1:8140/puppet-ca/v1/certificate/ca > /dev/null 2>&1; then
    echo "ERROR: loopback CA did not start in time." >&2
    kill "${PHASE1_PID}" 2>/dev/null || true
    exit 1
fi
echo "Loopback CA is ready."

# Generate an RSA key + certificate for the "puppet-ca" service hostname.
# The server saves the cert to signed/puppet-ca.pem and the key to
# private/puppet-ca_key.pem; puppet-ca-ctl also writes the key to --out-dir.
echo "Generating TLS cert for puppet-ca service hostname..."
/usr/local/bin/puppet-ca-ctl \
    --server-url http://127.0.0.1:8140 \
    generate \
    --certname puppet-ca \
    --dns puppet-ca \
    --out-dir "${CA_DIR}/private"

# Verify both files were written before proceeding to Phase 2.
if [ ! -s "${TLS_CERT}" ] || [ ! -s "${TLS_KEY}" ]; then
    echo "ERROR: TLS cert (${TLS_CERT}) or key (${TLS_KEY}) missing after generate." >&2
    kill "${PHASE1_PID}" 2>/dev/null || true
    exit 1
fi
chmod 644 "${TLS_CERT}"
chmod 640 "${TLS_KEY}"
echo "TLS cert generated at ${TLS_CERT}"

# Stop the Phase 1 loopback CA gracefully.
kill "${PHASE1_PID}" 2>/dev/null || true
wait "${PHASE1_PID}" 2>/dev/null || true

# ── Phase 2: start CA with TLS on all interfaces ────────────────────────────
echo "Phase 2: starting CA with TLS on all interfaces..."
exec /usr/local/bin/puppet-ca \
    --cadir="${CA_DIR}" \
    --hostname=puppet-ca \
    --autosign-config=true \
    --tls-cert="${TLS_CERT}" \
    --tls-key="${TLS_KEY}" \
    --puppet-server=puppet-master \
    "$@"
