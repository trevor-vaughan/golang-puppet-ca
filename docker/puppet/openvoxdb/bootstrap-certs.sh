#!/bin/bash
# Bootstrap OpenVoxDB TLS certificates from the Go CA via HTTPS.
#
# The stock OpenVoxDB ssl.sh uses openssl s_client to submit CSRs, but
# our Go CA returns HTTP 201 (not 200) for PUT certificate_request.
# ssl.sh only accepts 200, so it loops forever.  This script provisions
# the certs via curl directly against the Go CA's HTTPS port, then ssl.sh
# (20-configure-ssl.sh) sees they already exist and skips.
#
# TLS handling:
#   - First fetch (CA cert download): skip TLS verify (-k) because we do not
#     yet have the CA cert to verify against.
#   - All subsequent fetches: verify against the downloaded CA cert.

set -euo pipefail

CERTNAME="${CERTNAME:-${HOSTNAME}}"
OPENVOXSERVER_HOSTNAME="${OPENVOXSERVER_HOSTNAME:-puppet}"
OPENVOXSERVER_PORT="${OPENVOXSERVER_PORT:-8140}"
SSLDIR="${SSLDIR:-/opt/puppetlabs/server/data/puppetdb/certs}"

# PUPPET_CA_HOST / PUPPET_CA_PORT are set via docker-compose environment.
CA_URL="https://${PUPPET_CA_HOST:-puppet-ca}:${PUPPET_CA_PORT:-8140}"

CERTDIR="${SSLDIR}/certs"
PRIVKEYDIR="${SSLDIR}/private_keys"
CSRDIR="${SSLDIR}/certificate_requests"
CERTFILE="${CERTDIR}/${CERTNAME}.pem"
PRIVKEYFILE="${PRIVKEYDIR}/${CERTNAME}.pem"
CA_CERTFILE="${CERTDIR}/ca.pem"

# If cert already exists, nothing to do.
if [ -s "${CERTFILE}" ]; then
    echo "($0) Cert already exists at ${CERTFILE} — skipping bootstrap."
    exit 0
fi

echo "($0) Bootstrapping TLS certs for ${CERTNAME} from ${CA_URL}"

mkdir -p "${CERTDIR}" "${PRIVKEYDIR}" "${CSRDIR}"

# Wait for Go CA to be reachable.
echo "($0) Waiting for Go CA..."
until curl -sfk "${CA_URL}/puppet-ca/v1/certificate/ca" > /dev/null 2>&1; do
    sleep 2
done

# Download CA cert (first fetch — skip TLS verify).
curl -sfk "${CA_URL}/puppet-ca/v1/certificate/ca" -o "${CA_CERTFILE}"
echo "($0) CA cert downloaded."

# Download CRL (verified against CA cert).
curl -sf \
    --cacert "${CA_CERTFILE}" \
    "${CA_URL}/puppet-ca/v1/certificate_revocation_list/ca" \
    -o "${SSLDIR}/crl.pem"
echo "($0) CRL downloaded."

# Generate key + CSR.
openssl genrsa -out "${PRIVKEYFILE}" 4096 2>/dev/null
openssl req -new \
    -key "${PRIVKEYFILE}" \
    -subj "/CN=${CERTNAME}" \
    -out "${CSRDIR}/${CERTNAME}.pem" 2>/dev/null

# Submit CSR (Go CA returns 201 on success; verified against CA cert).
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    --cacert "${CA_CERTFILE}" \
    -X PUT \
    -H "Content-Type: text/plain" \
    --data-binary "@${CSRDIR}/${CERTNAME}.pem" \
    "${CA_URL}/puppet-ca/v1/certificate_request/${CERTNAME}")
echo "($0) CSR submission HTTP status: ${HTTP_STATUS}"

# Wait for cert to be signed (autosign should be immediate).
echo "($0) Waiting for signed cert..."
for _i in $(seq 1 30); do
    if curl -sf \
           --cacert "${CA_CERTFILE}" \
           "${CA_URL}/puppet-ca/v1/certificate/${CERTNAME}" \
           -o "${CERTFILE}" 2>/dev/null; then
        echo "($0) Signed cert obtained for ${CERTNAME}."
        break
    fi
    sleep 2
done

if [ ! -s "${CERTFILE}" ]; then
    echo "($0) ERROR: Timed out waiting for cert to be signed." >&2
    exit 1
fi

# Create canonical symlinks expected by jetty.ini.
(cd "${CERTDIR}" && ln -sf "${CERTNAME}.pem" server.crt)
(cd "${PRIVKEYDIR}" && ln -sf "${CERTNAME}.pem" server.key)

# Fix permissions (match what ssl.sh does).
find "${SSLDIR}/." -type d -exec chmod u=rwx,g=,o= -- {} +
find "${SSLDIR}/." -type f -exec chmod u=rw,g=,o= -- {} +

# Convert private key to PKCS8 DER for Java (required by OpenVoxDB/Jetty).
openssl pkcs8 -topk8 -nocrypt -inform PEM -outform DER \
    -in "${PRIVKEYFILE}" \
    -out "${PRIVKEYDIR}/server.private_key.pk8"
chmod u=rw,g=,o= "${PRIVKEYDIR}/server.private_key.pk8"

echo "($0) Certificate bootstrap complete."
