#!/bin/bash
# Integration tests for puppet-ca.
#
# Exercises every API endpoint against a live container and (optionally) runs
# a concurrency/load test.
#
# Usage (run from project root):
#   bash test/integration.sh              # test against already-running CA
#   bash test/integration.sh --up         # build image, start container, test, tear down
#   bash test/integration.sh --up --keep  # start, test, leave container running
#   bash test/integration.sh --up --load  # also run concurrency / load tests
#
# Environment variables:
#   CA_URL     Base URL of the CA  (default: http://localhost:8140)
#   CA_IMAGE   Container image tag (default: puppet-ca-integ:latest)
#
# Output follows TAP conventions: "ok N - desc" / "not ok N - desc".
# Exit 0 when all tests pass, exit 1 if any failed.
#
# Prerequisites: curl, openssl

set -uo pipefail

# ── Configuration ──────────────────────────────────────────────────────────────
CA_URL="${CA_URL:-http://localhost:8140}"
CA_IMAGE="${CA_IMAGE:-puppet-ca-integ:latest}"
CA_CONTAINER="puppet-ca-integ"

WORK_DIR=$(mktemp -d /tmp/puppet-ca-integ.XXXXXX)
# Unique per-run suffix so tests never collide with a previous run's CA state.
RUN_ID=$(date +%s)

# ── Argument parsing ────────────────────────────────────────────────────────────
DO_UP=false
DO_KEEP=false
DO_LOAD=false

for arg in "$@"; do
    case "$arg" in
        --up)   DO_UP=true ;;
        --keep) DO_KEEP=true ;;
        --load) DO_LOAD=true ;;
        *) printf 'Unknown argument: %s\n' "$arg" >&2; exit 1 ;;
    esac
done

# ── TAP helpers ─────────────────────────────────────────────────────────────────
T=0
FAILURES=0

pass() {
    T=$(( T + 1 ))
    printf 'ok %d - %s\n' "$T" "$1"
}

fail() {
    T=$(( T + 1 ))
    FAILURES=$(( FAILURES + 1 ))
    printf 'not ok %d - %s\n' "$T" "$1"
    [ -n "${2:-}" ] && printf '  # %s\n' "$2"
}

# assert_http EXPECTED_CODE DESC [curl-opts...]
assert_http() {
    local exp="$1" desc="$2"; shift 2
    local got
    got=$(curl -s -o /dev/null -w '%{http_code}' "$@" 2>/dev/null) || true
    [ "$got" = "$exp" ] \
        && pass "$desc" \
        || fail "$desc" "expected HTTP $exp, got HTTP $got"
}

# assert_contains FIXED_STRING DESC [curl-opts...]
assert_contains() {
    local pat="$1" desc="$2"; shift 2
    local body
    body=$(curl -s "$@" 2>/dev/null) || true
    grep -qF "$pat" <<< "$body" \
        && pass "$desc" \
        || fail "$desc" "pattern not found: $pat"
}

# ── CSR generation ──────────────────────────────────────────────────────────────
# Generate a single test key once; all CSRs reuse it (fast for load tests).
_keygen() {
    if [ ! -f "$WORK_DIR/test.key" ]; then
        openssl genrsa -out "$WORK_DIR/test.key" 2048 2>/dev/null
        chmod 600 "$WORK_DIR/test.key"
    fi
}

# make_csr CN OUTPUT_PATH
make_csr() {
    openssl req -new \
        -key  "$WORK_DIR/test.key" \
        -subj "/CN=$1" \
        -out  "$2" \
        2>/dev/null
}

# ── Container lifecycle ─────────────────────────────────────────────────────────
cleanup() {
    rm -rf "$WORK_DIR"
    if $DO_UP && ! $DO_KEEP; then
        podman rm -f "$CA_CONTAINER" 2>/dev/null || true
    fi
}
trap cleanup EXIT

if $DO_UP; then
    # Verify prerequisites
    if ! command -v podman &>/dev/null; then
        printf 'FATAL: podman not found — required for --up\n' >&2; exit 1
    fi

    podman rm -f "$CA_CONTAINER" 2>/dev/null || true

    printf '# Building container image %s...\n' "$CA_IMAGE"
    podman build -f Dockerfile.run -t "$CA_IMAGE" . 2>&1 | tail -5

    printf '# Starting CA container...\n'
    podman run -d \
        --name "$CA_CONTAINER" \
        -p 8140:8140 \
        "$CA_IMAGE" \
        --cadir=/data \
        --autosign-config=false \
        --no-tls-required \
        -v=1

    printf '# Waiting for CA to become ready'
    for _i in $(seq 1 30); do
        curl -sf "$CA_URL/puppet-ca/v1/certificate/ca" >/dev/null 2>&1 && break
        printf '.'; sleep 1
    done
    printf ' ready\n'
fi

# ── Preflight ───────────────────────────────────────────────────────────────────
if ! command -v openssl &>/dev/null; then
    printf 'FATAL: openssl not found — required for CSR generation\n' >&2; exit 1
fi

printf '\n# Checking CA reachability at %s...\n' "$CA_URL"
if ! curl -sf "$CA_URL/puppet-ca/v1/certificate/ca" -o "$WORK_DIR/ca.pem" 2>/dev/null; then
    printf 'FATAL: CA not reachable at %s — is the server running?\n' "$CA_URL" >&2
    exit 1
fi
printf '# CA cert saved to %s/ca.pem\n' "$WORK_DIR"

_keygen

# ═══════════════════════════════════════════════════════════════════════════════
# Group 1 — Endpoint smoke tests
# ═══════════════════════════════════════════════════════════════════════════════
printf '\n# Group 1 — Endpoint smoke tests\n'

assert_http 200 "GET /certificate/ca returns 200" \
    "$CA_URL/puppet-ca/v1/certificate/ca"

assert_contains "BEGIN CERTIFICATE" "CA cert body contains PEM header" \
    "$CA_URL/puppet-ca/v1/certificate/ca"

assert_http 200 "GET /certificate_revocation_list/ca returns 200" \
    "$CA_URL/puppet-ca/v1/certificate_revocation_list/ca"

assert_contains "BEGIN X509 CRL" "CRL body contains PEM header" \
    "$CA_URL/puppet-ca/v1/certificate_revocation_list/ca"

assert_http 404 "GET /certificate/nonexistent returns 404" \
    "$CA_URL/puppet-ca/v1/certificate/does-not-exist"

assert_http 404 "GET /certificate_status/nonexistent returns 404" \
    "$CA_URL/puppet-ca/v1/certificate_status/does-not-exist"

assert_http 404 "GET /certificate_request/nonexistent returns 404" \
    "$CA_URL/puppet-ca/v1/certificate_request/does-not-exist"

# ═══════════════════════════════════════════════════════════════════════════════
# Group 2 — Full CSR lifecycle
# ═══════════════════════════════════════════════════════════════════════════════
printf '\n# Group 2 — Full CSR lifecycle\n'

_HOST="node-${RUN_ID}.example.com"
make_csr "$_HOST" "$WORK_DIR/node.csr"

# Submit CSR. Puppet CA always returns 200 for PUT /certificate_request.
_csr_st=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT -H "Content-Type: text/plain" \
    --data-binary @"$WORK_DIR/node.csr" \
    "$CA_URL/puppet-ca/v1/certificate_request/${_HOST}") || true
[ "$_csr_st" = "200" ] \
    && pass "PUT /certificate_request returns 200" \
    || fail "PUT /certificate_request returns 200" "got HTTP $_csr_st"

# Sign the CSR via the operator API (autosign=false).
curl -s -o /dev/null \
    -X PUT -H "Content-Type: application/json" \
    -d '{"desired_state":"signed"}' \
    "$CA_URL/puppet-ca/v1/certificate_status/${_HOST}" 2>/dev/null || true

_status_body=$(curl -s "$CA_URL/puppet-ca/v1/certificate_status/${_HOST}" 2>/dev/null) || true
grep -qF '"state":"signed"' <<< "$_status_body" \
    && pass "Signed cert status is 'signed'" \
    || fail "Signed cert status is 'signed'" "got: $_status_body"

grep -qF '"fingerprint"' <<< "$_status_body" \
    && pass "Status response includes fingerprint" \
    || fail "Status response includes fingerprint" "got: $_status_body"

grep -qF '"serial_number"' <<< "$_status_body" \
    && pass "Status response includes serial_number" \
    || fail "Status response includes serial_number" "got: $_status_body"

grep -qF '"authorization_extensions"' <<< "$_status_body" \
    && pass "Status response includes authorization_extensions field" \
    || fail "Status response includes authorization_extensions field" "got: $_status_body"

# Download and verify the signed cert.
assert_http 200 "GET /certificate/{subject} returns 200" \
    "$CA_URL/puppet-ca/v1/certificate/${_HOST}"

curl -sf "$CA_URL/puppet-ca/v1/certificate/${_HOST}" \
    -o "$WORK_DIR/node.crt" 2>/dev/null \
    && pass "Signed cert downloadable" \
    || fail "Signed cert downloadable"

openssl verify -CAfile "$WORK_DIR/ca.pem" "$WORK_DIR/node.crt" >/dev/null 2>&1 \
    && pass "Signed cert verifies against CA" \
    || fail "Signed cert verifies against CA"

# Verify CN in the signed cert matches what was submitted.
openssl x509 -noout -subject -in "$WORK_DIR/node.crt" 2>/dev/null | grep -qF "$_HOST" \
    && pass "Signed cert CN matches submitted subject" \
    || fail "Signed cert CN matches submitted subject"

# CSR should be gone after signing (deleted by sign()).
assert_http 404 "CSR deleted after signing (GET returns 404)" \
    "$CA_URL/puppet-ca/v1/certificate_request/${_HOST}"

# If-Modified-Since: a future timestamp → 304 Not Modified.
assert_http 304 "CRL If-Modified-Since (future) returns 304" \
    -H "If-Modified-Since: Sat, 01 Jan 2050 00:00:00 GMT" \
    "$CA_URL/puppet-ca/v1/certificate_revocation_list/ca"

# If-Modified-Since: a past timestamp → 200 (file is newer).
assert_http 200 "CRL If-Modified-Since (past) returns 200" \
    -H "If-Modified-Since: Thu, 01 Jan 2004 00:00:00 GMT" \
    "$CA_URL/puppet-ca/v1/certificate_revocation_list/ca"

# Revoke the cert.
_rev_st=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT -H "Content-Type: application/json" \
    -d '{"desired_state":"revoked"}' \
    "$CA_URL/puppet-ca/v1/certificate_status/${_HOST}") || true
[[ "$_rev_st" =~ ^2 ]] \
    && pass "PUT /certificate_status revoked returns 2xx" \
    || fail "PUT /certificate_status revoked returns 2xx" "got HTTP $_rev_st"

_rev_body=$(curl -s "$CA_URL/puppet-ca/v1/certificate_status/${_HOST}" 2>/dev/null) || true
grep -qF '"state":"revoked"' <<< "$_rev_body" \
    && pass "Revoked cert status is 'revoked'" \
    || fail "Revoked cert status is 'revoked'" "got: $_rev_body"

# CRL should now contain a revoked entry.
_crl_text=$(curl -sf "$CA_URL/puppet-ca/v1/certificate_revocation_list/ca" 2>/dev/null \
    | openssl crl -text -noout 2>/dev/null) || true
grep -qi "Revoked Certificates" <<< "$_crl_text" \
    && pass "CRL contains revoked certificates section" \
    || fail "CRL contains revoked certificates section"

# Re-register: submitting a new CSR for a revoked subject is permitted.
make_csr "$_HOST" "$WORK_DIR/node2.csr"
_rereg_st=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT -H "Content-Type: text/plain" \
    --data-binary @"$WORK_DIR/node2.csr" \
    "$CA_URL/puppet-ca/v1/certificate_request/${_HOST}") || true
[[ "$_rereg_st" =~ ^2 ]] \
    && pass "Re-registration after revocation returns 2xx" \
    || fail "Re-registration after revocation returns 2xx" "got HTTP $_rereg_st"

# ═══════════════════════════════════════════════════════════════════════════════
# Group 3 — Error cases
# ═══════════════════════════════════════════════════════════════════════════════
printf '\n# Group 3 — Error cases\n'

# Invalid subjects.
assert_http 400 "Invalid subject (uppercase) on GET /certificate_status returns 400" \
    "$CA_URL/puppet-ca/v1/certificate_status/BadNode"

assert_http 400 "Invalid subject (double-dot) on GET /certificate_status returns 400" \
    "$CA_URL/puppet-ca/v1/certificate_status/a..b"

assert_http 400 "Invalid subject on GET /certificate returns 400" \
    "$CA_URL/puppet-ca/v1/certificate/BadNode"

assert_http 400 "Invalid subject on GET /certificate_request returns 400" \
    "$CA_URL/puppet-ca/v1/certificate_request/BadNode"

# Bad PUT /certificate_status body.
assert_http 400 "PUT /certificate_status with invalid desired_state returns 400" \
    -X PUT -H "Content-Type: application/json" \
    -d '{"desired_state":"destroyed"}' \
    "$CA_URL/puppet-ca/v1/certificate_status/valid-node"

assert_http 400 "PUT /certificate_status with malformed JSON returns 400" \
    -X PUT -H "Content-Type: application/json" \
    -d 'not-json' \
    "$CA_URL/puppet-ca/v1/certificate_status/valid-node"

# 409 Conflict: submit a second CSR for an active (signed, non-revoked) cert.
_CONF_HOST="conflict-${RUN_ID}.example.com"
make_csr "$_CONF_HOST" "$WORK_DIR/conflict.csr"
curl -s -o /dev/null \
    -X PUT -H "Content-Type: text/plain" \
    --data-binary @"$WORK_DIR/conflict.csr" \
    "$CA_URL/puppet-ca/v1/certificate_request/${_CONF_HOST}" 2>/dev/null || true
# Sign it so the cert is active before we try the duplicate submission.
curl -s -o /dev/null \
    -X PUT -H "Content-Type: application/json" \
    -d '{"desired_state":"signed"}' \
    "$CA_URL/puppet-ca/v1/certificate_status/${_CONF_HOST}" 2>/dev/null || true

assert_http 409 "Duplicate CSR for active cert returns 409" \
    -X PUT -H "Content-Type: text/plain" \
    --data-binary @"$WORK_DIR/conflict.csr" \
    "$CA_URL/puppet-ca/v1/certificate_request/${_CONF_HOST}"

# 409 CA:TRUE extension in CSR — server must refuse to sign.
# openssl req_extensions embeds BasicConstraints CA:TRUE into the CSR.
cat > "$WORK_DIR/ca_true.cnf" << 'OPENSSLEOF'
[ req ]
distinguished_name  = dn
req_extensions      = v3_req
prompt              = no
[ dn ]
CN = evil-ca-node
[ v3_req ]
basicConstraints = critical, CA:true
OPENSSLEOF

_CA_TRUE_HOST="evil-ca-${RUN_ID}.example.com"
openssl req -new \
    -key "$WORK_DIR/test.key" \
    -config "$WORK_DIR/ca_true.cnf" \
    -subj "/CN=${_CA_TRUE_HOST}" \
    -out "$WORK_DIR/ca_true.csr" 2>/dev/null

curl -s -o /dev/null \
    -X PUT -H "Content-Type: text/plain" \
    --data-binary @"$WORK_DIR/ca_true.csr" \
    "$CA_URL/puppet-ca/v1/certificate_request/${_CA_TRUE_HOST}" 2>/dev/null || true

_catrue_sign_st=$(curl -s -o "$WORK_DIR/catrue_body.txt" -w '%{http_code}' \
    -X PUT -H "Content-Type: application/json" \
    -d '{"desired_state":"signed"}' \
    "$CA_URL/puppet-ca/v1/certificate_status/${_CA_TRUE_HOST}") || true
[ "$_catrue_sign_st" = "409" ] \
    && pass "CSR with BasicConstraints CA:TRUE rejected with 409" \
    || fail "CSR with BasicConstraints CA:TRUE rejected with 409" "got HTTP $_catrue_sign_st"
grep -qF "Found extensions" "$WORK_DIR/catrue_body.txt" 2>/dev/null \
    && pass "CA:TRUE rejection body contains 'Found extensions'" \
    || fail "CA:TRUE rejection body contains 'Found extensions'" \
           "body: $(cat "$WORK_DIR/catrue_body.txt" 2>/dev/null)"
grep -qF "2.5.29.19" "$WORK_DIR/catrue_body.txt" 2>/dev/null \
    && pass "CA:TRUE rejection body contains OID 2.5.29.19" \
    || fail "CA:TRUE rejection body contains OID 2.5.29.19" \
           "body: $(cat "$WORK_DIR/catrue_body.txt" 2>/dev/null)"

# DELETE /certificate_request/{subject} — removes a pending CSR.
_DEL_HOST="del-csr-${RUN_ID}.example.com"
make_csr "$_DEL_HOST" "$WORK_DIR/del.csr"
curl -s -o /dev/null \
    -X PUT -H "Content-Type: text/plain" \
    --data-binary @"$WORK_DIR/del.csr" \
    "$CA_URL/puppet-ca/v1/certificate_request/${_DEL_HOST}" 2>/dev/null || true

assert_http 200 "GET /certificate_request after PUT returns 200" \
    "$CA_URL/puppet-ca/v1/certificate_request/${_DEL_HOST}"

assert_http 204 "DELETE /certificate_request/{subject} returns 204" \
    -X DELETE \
    "$CA_URL/puppet-ca/v1/certificate_request/${_DEL_HOST}"

assert_http 404 "GET /certificate_request after DELETE returns 404" \
    "$CA_URL/puppet-ca/v1/certificate_request/${_DEL_HOST}"

assert_http 404 "DELETE /certificate_request for missing CSR returns 404" \
    -X DELETE \
    "$CA_URL/puppet-ca/v1/certificate_request/nonexistent-node"

# Double-encoded URL: %256c decodes to literal %6c (not 'l').
# The subject would contain a '%', which fails subject validation → 400 or 404.
assert_http 400 "Double-encoded subject (%256c) rejected with 400" \
    "$CA_URL/puppet-ca/v1/certificate_status/%256cocalhost"

# CSR CN mismatch: submit a CSR whose CN is "other-node" but the URL says a
# different subject name.  The server must reject this with 400 to prevent a
# node from inadvertently (or deliberately) obtaining a cert for another name.
_MISMATCH_HOST="cn-mismatch-${RUN_ID}.example.com"
make_csr "other-node-${RUN_ID}" "$WORK_DIR/mismatch.csr"
_mismatch_st=$(curl -s -o "$WORK_DIR/mismatch_body.txt" -w '%{http_code}' \
    -X PUT -H "Content-Type: text/plain" \
    --data-binary @"$WORK_DIR/mismatch.csr" \
    "$CA_URL/puppet-ca/v1/certificate_request/${_MISMATCH_HOST}") || true
[ "$_mismatch_st" = "400" ] \
    && pass "CSR CN mismatch returns 400" \
    || fail "CSR CN mismatch returns 400" "got HTTP $_mismatch_st"
grep -qi "does not match" "$WORK_DIR/mismatch_body.txt" 2>/dev/null \
    && pass "CSR CN mismatch body contains 'does not match'" \
    || fail "CSR CN mismatch body contains 'does not match'" \
           "body: $(cat "$WORK_DIR/mismatch_body.txt" 2>/dev/null)"

# ═══════════════════════════════════════════════════════════════════════════════
# Group 4 — Protocol features
# ═══════════════════════════════════════════════════════════════════════════════
printf '\n# Group 4 — Protocol features\n'

# Bare paths (no /puppet-ca/v1/ prefix) must also work.
assert_http 200 "GET /certificate/ca (bare path) returns 200" \
    "$CA_URL/certificate/ca"

assert_http 200 "GET /certificate_revocation_list/ca (bare path) returns 200" \
    "$CA_URL/certificate_revocation_list/ca"

# Prefixed paths (/puppet-ca/v1/).
assert_http 200 "GET /puppet-ca/v1/certificate/ca returns 200" \
    "$CA_URL/puppet-ca/v1/certificate/ca"

assert_http 200 "GET /puppet-ca/v1/certificate_revocation_list/ca returns 200" \
    "$CA_URL/puppet-ca/v1/certificate_revocation_list/ca"

assert_http 404 "GET /puppet-ca/v1/certificate_status/nonexistent returns 404" \
    "$CA_URL/puppet-ca/v1/certificate_status/does-not-exist"

_PFX_HOST="pfx-${RUN_ID}.example.com"
make_csr "$_PFX_HOST" "$WORK_DIR/pfx.csr"
_pfx_st=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT -H "Content-Type: text/plain" \
    --data-binary @"$WORK_DIR/pfx.csr" \
    "$CA_URL/puppet-ca/v1/certificate_request/${_PFX_HOST}") || true
[[ "$_pfx_st" =~ ^2 ]] \
    && pass "PUT /puppet-ca/v1/certificate_request returns 2xx" \
    || fail "PUT /puppet-ca/v1/certificate_request returns 2xx" "got HTTP $_pfx_st"

assert_http 200 "GET /puppet-ca/v1/certificate_status/{signed-subject} returns 200" \
    "$CA_URL/puppet-ca/v1/certificate_status/${_PFX_HOST}"

# ═══════════════════════════════════════════════════════════════════════════════
# Group 5 — Concurrency / load tests  (opt-in via --load)
# ═══════════════════════════════════════════════════════════════════════════════
if $DO_LOAD; then
    printf '\n# Group 5 — Concurrency / load tests\n'

    # --- 5a: Concurrent CSR submissions ---
    _WRITE_N=20
    printf '# Pre-generating %d CSRs (shared key, unique CNs)...\n' "$_WRITE_N"
    for i in $(seq 1 "$_WRITE_N"); do
        make_csr "load-${RUN_ID}-${i}.example.com" "$WORK_DIR/load-${i}.csr"
    done

    printf '# Submitting %d CSRs concurrently...\n' "$_WRITE_N"
    _w_pids=()
    for i in $(seq 1 "$_WRITE_N"); do
        curl -s -o /dev/null -w '%{http_code}' \
            -X PUT -H "Content-Type: text/plain" \
            --data-binary @"$WORK_DIR/load-${i}.csr" \
            "$CA_URL/puppet-ca/v1/certificate_request/load-${RUN_ID}-${i}.example.com" \
            > "$WORK_DIR/w-result-${i}.txt" 2>/dev/null &
        _w_pids+=($!)
    done
    _w_start=$(date +%s%3N)
    for pid in "${_w_pids[@]}"; do wait "$pid" || true; done
    _w_elapsed=$(( $(date +%s%3N) - _w_start ))

    _w_ok=0
    for i in $(seq 1 "$_WRITE_N"); do
        _code=$(cat "$WORK_DIR/w-result-${i}.txt" 2>/dev/null) || true
        [[ "$_code" =~ ^2 ]] && _w_ok=$(( _w_ok + 1 ))
    done
    [ "$_w_ok" -eq "$_WRITE_N" ] \
        && pass "${_WRITE_N} concurrent CSR submissions all succeeded (${_w_elapsed}ms total)" \
        || fail "${_WRITE_N} concurrent CSR submissions all succeeded" \
               "${_w_ok}/${_WRITE_N} returned 2xx in ${_w_elapsed}ms"

    # Sign all pending CSRs in bulk.
    curl -s -o /dev/null -X POST "$CA_URL/puppet-ca/v1/sign/all" 2>/dev/null || true

    # Verify all are now signed.
    _signed=0
    for i in $(seq 1 "$_WRITE_N"); do
        _body=$(curl -s \
            "$CA_URL/puppet-ca/v1/certificate_status/load-${RUN_ID}-${i}.example.com" \
            2>/dev/null) || true
        grep -qF '"state":"signed"' <<< "$_body" && _signed=$(( _signed + 1 ))
    done
    [ "$_signed" -eq "$_WRITE_N" ] \
        && pass "All ${_WRITE_N} concurrently submitted certs signed and verified" \
        || fail "All ${_WRITE_N} concurrently submitted certs signed and verified" \
               "${_signed}/${_WRITE_N} in 'signed' state"

    # --- 5b: Concurrent reads ---
    _READ_N=50
    printf '# Firing %d concurrent GET /certificate/ca requests...\n' "$_READ_N"
    _r_pids=()
    _r_start=$(date +%s%3N)
    for i in $(seq 1 "$_READ_N"); do
        curl -s -o /dev/null -w '%{http_code}' \
            "$CA_URL/puppet-ca/v1/certificate/ca" \
            > "$WORK_DIR/r-result-${i}.txt" 2>/dev/null &
        _r_pids+=($!)
    done
    for pid in "${_r_pids[@]}"; do wait "$pid" || true; done
    _r_elapsed=$(( $(date +%s%3N) - _r_start ))

    _r_ok=0
    for i in $(seq 1 "$_READ_N"); do
        [ "$(cat "$WORK_DIR/r-result-${i}.txt" 2>/dev/null)" = "200" ] \
            && _r_ok=$(( _r_ok + 1 ))
    done
    [ "$_r_ok" -eq "$_READ_N" ] \
        && pass "${_READ_N} concurrent GET /certificate/ca all returned 200 (${_r_elapsed}ms total)" \
        || fail "${_READ_N} concurrent GET /certificate/ca all returned 200" \
               "${_r_ok}/${_READ_N} returned 200 in ${_r_elapsed}ms"

    # --- 5c: Mixed concurrent reads + writes ---
    _MIX_N=10
    printf '# Mixed: %d concurrent reads + %d concurrent CSR submissions...\n' "$_MIX_N" "$_MIX_N"
    for i in $(seq 1 "$_MIX_N"); do
        make_csr "mixed-${RUN_ID}-${i}.example.com" "$WORK_DIR/mixed-${i}.csr"
    done

    _m_pids=()
    for i in $(seq 1 "$_MIX_N"); do
        curl -s -o /dev/null -w '%{http_code}' \
            "$CA_URL/puppet-ca/v1/certificate/ca" \
            > "$WORK_DIR/mr-${i}.txt" 2>/dev/null &
        _m_pids+=($!)
        curl -s -o /dev/null -w '%{http_code}' \
            -X PUT -H "Content-Type: text/plain" \
            --data-binary @"$WORK_DIR/mixed-${i}.csr" \
            "$CA_URL/puppet-ca/v1/certificate_request/mixed-${RUN_ID}-${i}.example.com" \
            > "$WORK_DIR/mw-${i}.txt" 2>/dev/null &
        _m_pids+=($!)
    done
    for pid in "${_m_pids[@]}"; do wait "$pid" || true; done

    _mr_ok=0; _mw_ok=0
    for i in $(seq 1 "$_MIX_N"); do
        [ "$(cat "$WORK_DIR/mr-${i}.txt" 2>/dev/null)" = "200" ] && _mr_ok=$(( _mr_ok + 1 ))
        [[ "$(cat "$WORK_DIR/mw-${i}.txt" 2>/dev/null)" =~ ^2 ]]  && _mw_ok=$(( _mw_ok + 1 ))
    done
    [ "$_mr_ok" -eq "$_MIX_N" ] && [ "$_mw_ok" -eq "$_MIX_N" ] \
        && pass "Mixed concurrent reads + writes: all ${_MIX_N}+${_MIX_N} requests succeeded" \
        || fail "Mixed concurrent reads + writes: all ${_MIX_N}+${_MIX_N} requests succeeded" \
               "reads: ${_mr_ok}/${_MIX_N}, writes: ${_mw_ok}/${_MIX_N}"

    # --- 5d: Large inventory — sign a cert when inventory already has 500 entries ---
    # Mirrors the Puppet CA integration test certificate-inventory-file-management.
    _INV_HOST="inv-large-${RUN_ID}.example.com"
    printf '# Pre-populating inventory with 500 dummy entries then signing...\n'
    _INV_PREFIX_HOST="inv-bulk-${RUN_ID}"
    _inv_pids=()
    for i in $(seq 1 500); do
        make_csr "${_INV_PREFIX_HOST}-${i}.example.com" "$WORK_DIR/inv-${i}.csr" 2>/dev/null
        curl -s -o /dev/null \
            -X PUT -H "Content-Type: text/plain" \
            --data-binary @"$WORK_DIR/inv-${i}.csr" \
            "$CA_URL/puppet-ca/v1/certificate_request/${_INV_PREFIX_HOST}-${i}.example.com" \
            > "$WORK_DIR/inv-result-${i}.txt" 2>/dev/null &
        _inv_pids+=($!)
        # Submit in batches of 20 to avoid overwhelming the server.
        if (( i % 20 == 0 )); then
            for pid in "${_inv_pids[@]}"; do wait "$pid" || true; done
            _inv_pids=()
        fi
    done
    for pid in "${_inv_pids[@]}"; do wait "$pid" || true; done

    # Now sign one more — inventory append must succeed even with a large file.
    make_csr "$_INV_HOST" "$WORK_DIR/inv-large.csr"
    _inv_sign_st=$(curl -s -o /dev/null -w '%{http_code}' \
        -X PUT -H "Content-Type: text/plain" \
        --data-binary @"$WORK_DIR/inv-large.csr" \
        "$CA_URL/puppet-ca/v1/certificate_request/${_INV_HOST}") || true
    [ "$_inv_sign_st" = "200" ] \
        && pass "CSR submission with 500-entry inventory returns 200" \
        || fail "CSR submission with 500-entry inventory returns 200" "got HTTP $_inv_sign_st"

    # Sign the cert (autosign=false).
    curl -s -o /dev/null \
        -X PUT -H "Content-Type: application/json" \
        -d '{"desired_state":"signed"}' \
        "$CA_URL/puppet-ca/v1/certificate_status/${_INV_HOST}" 2>/dev/null || true

    _inv_status=$(curl -s "$CA_URL/puppet-ca/v1/certificate_status/${_INV_HOST}" 2>/dev/null) || true
    grep -qF '"state":"signed"' <<< "$_inv_status" \
        && pass "Cert signed correctly with large inventory present" \
        || fail "Cert signed correctly with large inventory present" "got: $_inv_status"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Results
# ═══════════════════════════════════════════════════════════════════════════════
printf '\n# Results: %d/%d passed, %d failed\n' \
    $(( T - FAILURES )) "$T" "$FAILURES"

[ "$FAILURES" -eq 0 ]
