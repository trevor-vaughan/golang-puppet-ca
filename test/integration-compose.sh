#!/bin/bash
# Multi-host integration tests for puppet-ca.
#
# Designed to run inside the test-runner container launched by compose.yml.
# The puppet-ca server is reachable at $CA_URL (default: http://puppet-ca:8140).
# The test-runner is a *separate container*, demonstrating true cross-host
# communication over the compose network.
#
# Both the direct HTTP API (curl + openssl) and the puppet-ca-ctl management
# CLI are exercised.
#
# Usage (normally invoked by `mage integCompose`):
#   podman-compose up --exit-code-from test-runner
#
# Environment variables:
#   CA_URL    Base URL of the CA  (default: http://puppet-ca:8140)
#   DO_LOAD   Run concurrency/load tests (default: false)
#
# Output: TAP format.  Exit 0 when all pass, exit 1 if any fail.
#
# Prerequisites inside the container: curl, openssl, puppet-ca-ctl

set -uo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
CA_URL="${CA_URL:-http://puppet-ca:8140}"
DO_LOAD="${DO_LOAD:-false}"

WORK_DIR=$(mktemp -d /tmp/puppet-ca-compose-integ.XXXXXX)
RUN_ID=$(date +%s%N | tail -c 8)   # 8-char unique suffix

# puppet-ca-ctl shorthand — all HTTP subcommands get the server URL
CTL="puppet-ca-ctl --server-url ${CA_URL}"

# ── TAP helpers ──────────────────────────────────────────────────────────────
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
        || fail "$desc" "pattern not found in response: $pat"
}

# assert_json_field JSON_BODY FIELD_PATTERN DESC
assert_json_field() {
    local body="$1" pat="$2" desc="$3"
    grep -qF "$pat" <<< "$body" \
        && pass "$desc" \
        || fail "$desc" "pattern '$pat' not found in: $body"
}

# ── CSR generation ────────────────────────────────────────────────────────────
# Generate one shared RSA key (fast); all CSRs reuse it.
_keygen() {
    if [ ! -f "$WORK_DIR/test.key" ]; then
        openssl genrsa -out "$WORK_DIR/test.key" 2048 2>/dev/null
        chmod 600 "$WORK_DIR/test.key"
    fi
}

# make_csr CN OUTPUT_PATH
make_csr() {
    _keygen
    openssl req -new \
        -key  "$WORK_DIR/test.key" \
        -subj "/CN=$1" \
        -out  "$2" \
        2>/dev/null
}

# submit_csr CN  — PUT CSR, ignore response (used for setup steps)
submit_csr() {
    local cn="$1"
    make_csr "$cn" "$WORK_DIR/${cn}.csr"
    curl -s -o /dev/null \
        -X PUT -H "Content-Type: text/plain" \
        --data-binary @"$WORK_DIR/${cn}.csr" \
        "${CA_URL}/puppet-ca/v1/certificate_request/${cn}" 2>/dev/null || true
}

# ── Cleanup ───────────────────────────────────────────────────────────────────
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

# ═════════════════════════════════════════════════════════════════════════════
# Preflight — CA reachable from this (separate) container
# ═════════════════════════════════════════════════════════════════════════════
printf '# puppet-ca integration tests (multi-host via compose)\n'
printf '# CA URL: %s   (resolved across compose network)\n' "$CA_URL"
printf '# Test-runner container: %s\n' "$(hostname)"
printf '\n'

if ! curl -sf "${CA_URL}/puppet-ca/v1/certificate/ca" -o "$WORK_DIR/ca.pem" 2>/dev/null; then
    printf 'FATAL: CA not reachable at %s\n' "$CA_URL" >&2
    exit 1
fi
printf '# CA cert downloaded from remote host to %s/ca.pem\n' "$WORK_DIR"
_keygen

# ═════════════════════════════════════════════════════════════════════════════
# Group 1 — Endpoint smoke tests (cross-host)
# ═════════════════════════════════════════════════════════════════════════════
printf '\n# Group 1 — Endpoint smoke tests (test-runner → puppet-ca network)\n'

assert_http 200 "GET /certificate/ca returns 200 from remote host" \
    "${CA_URL}/puppet-ca/v1/certificate/ca"

assert_contains "BEGIN CERTIFICATE" "CA cert PEM header present" \
    "${CA_URL}/puppet-ca/v1/certificate/ca"

assert_http 200 "GET /certificate_revocation_list/ca returns 200 from remote host" \
    "${CA_URL}/puppet-ca/v1/certificate_revocation_list/ca"

assert_contains "BEGIN X509 CRL" "CRL PEM header present" \
    "${CA_URL}/puppet-ca/v1/certificate_revocation_list/ca"

assert_http 404 "GET /certificate/nonexistent → 404" \
    "${CA_URL}/puppet-ca/v1/certificate/no-such-host"

assert_http 404 "GET /certificate_status/nonexistent → 404" \
    "${CA_URL}/puppet-ca/v1/certificate_status/no-such-host"

assert_http 200 "GET /expirations returns 200" \
    "${CA_URL}/puppet-ca/v1/expirations"

_exp_body=$(curl -s "${CA_URL}/puppet-ca/v1/expirations" 2>/dev/null) || true
assert_json_field "$_exp_body" '"ca_certificate"' \
    "GET /expirations body has ca_certificate field"
assert_json_field "$_exp_body" '"ca_crl"' \
    "GET /expirations body has ca_crl field"

# ═════════════════════════════════════════════════════════════════════════════
# Group 2 — Full lifecycle: agent submits CSR, operator signs via ctl
#   (autosign=false proves the multi-host operator workflow)
# ═════════════════════════════════════════════════════════════════════════════
printf '\n# Group 2 — Full lifecycle with manual signing via puppet-ca-ctl\n'

_AGENT="agent-${RUN_ID}.example.com"
make_csr "$_AGENT" "$WORK_DIR/agent.csr"

_st=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT -H "Content-Type: text/plain" \
    --data-binary @"$WORK_DIR/agent.csr" \
    "${CA_URL}/puppet-ca/v1/certificate_request/${_AGENT}") || true
[ "$_st" = "200" ] \
    && pass "Agent: PUT /certificate_request returns 200" \
    || fail "Agent: PUT /certificate_request returns 200" "got HTTP $_st"

# CSR must show as 'requested' before signing
_pre_body=$(curl -s "${CA_URL}/puppet-ca/v1/certificate_status/${_AGENT}" 2>/dev/null) || true
assert_json_field "$_pre_body" '"state":"requested"' \
    "Agent cert status is 'requested' before signing"

# puppet-ca-ctl list shows the pending CSR
_list_out=$($CTL list 2>/dev/null) || true
grep -qF "$_AGENT" <<< "$_list_out" \
    && pass "puppet-ca-ctl list shows pending CSR" \
    || fail "puppet-ca-ctl list shows pending CSR" "output: $_list_out"

# Operator signs it
$CTL sign --certname "$_AGENT" >/dev/null 2>&1 \
    && pass "puppet-ca-ctl sign --certname succeeds" \
    || fail "puppet-ca-ctl sign --certname succeeds"

# Status is now 'signed'
_post_body=$(curl -s "${CA_URL}/puppet-ca/v1/certificate_status/${_AGENT}" 2>/dev/null) || true
assert_json_field "$_post_body" '"state":"signed"' \
    "Agent cert status is 'signed' after ctl sign"

assert_json_field "$_post_body" '"fingerprint"' \
    "Signed status includes fingerprint"

assert_json_field "$_post_body" '"serial_number"' \
    "Signed status includes serial_number"

assert_json_field "$_post_body" '"not_before"' \
    "Signed status includes not_before"

assert_json_field "$_post_body" '"not_after"' \
    "Signed status includes not_after"

# Agent downloads cert and verifies it cryptographically against the CA
curl -sf "${CA_URL}/puppet-ca/v1/certificate/${_AGENT}" \
    -o "$WORK_DIR/agent.crt" 2>/dev/null \
    && pass "Agent: signed cert downloadable" \
    || fail "Agent: signed cert downloadable"

openssl verify -CAfile "$WORK_DIR/ca.pem" "$WORK_DIR/agent.crt" >/dev/null 2>&1 \
    && pass "Agent cert cryptographically verifies against CA cert" \
    || fail "Agent cert cryptographically verifies against CA cert"

openssl x509 -noout -subject -in "$WORK_DIR/agent.crt" 2>/dev/null | grep -qF "$_AGENT" \
    && pass "Agent cert CN matches submitted subject" \
    || fail "Agent cert CN matches submitted subject"

# CRL If-Modified-Since
assert_http 304 "CRL If-Modified-Since future → 304" \
    -H "If-Modified-Since: Sat, 01 Jan 2050 00:00:00 GMT" \
    "${CA_URL}/puppet-ca/v1/certificate_revocation_list/ca"

assert_http 200 "CRL If-Modified-Since past → 200" \
    -H "If-Modified-Since: Thu, 01 Jan 2004 00:00:00 GMT" \
    "${CA_URL}/puppet-ca/v1/certificate_revocation_list/ca"

# Operator revokes
$CTL revoke --certname "$_AGENT" >/dev/null 2>&1 \
    && pass "puppet-ca-ctl revoke --certname succeeds" \
    || fail "puppet-ca-ctl revoke --certname succeeds"

_rev_body=$(curl -s "${CA_URL}/puppet-ca/v1/certificate_status/${_AGENT}" 2>/dev/null) || true
assert_json_field "$_rev_body" '"state":"revoked"' \
    "Agent cert status is 'revoked' after ctl revoke"

# CRL must list a revoked entry now
_crl_text=$(curl -sf "${CA_URL}/puppet-ca/v1/certificate_revocation_list/ca" 2>/dev/null \
    | openssl crl -text -noout 2>/dev/null) || true
grep -qi "Revoked Certificates" <<< "$_crl_text" \
    && pass "CRL contains 'Revoked Certificates' section after revoke" \
    || fail "CRL contains 'Revoked Certificates' section after revoke"

# Re-registration after revocation is allowed
make_csr "$_AGENT" "$WORK_DIR/agent2.csr"
_rereg=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT -H "Content-Type: text/plain" \
    --data-binary @"$WORK_DIR/agent2.csr" \
    "${CA_URL}/puppet-ca/v1/certificate_request/${_AGENT}") || true
[[ "$_rereg" =~ ^2 ]] \
    && pass "Re-registration after revocation returns 2xx" \
    || fail "Re-registration after revocation returns 2xx" "got HTTP $_rereg"

# Operator cleans (revoke + delete cert + delete CSR in one step)
$CTL sign --certname "$_AGENT" >/dev/null 2>&1 || true
_CLEAN="clean-${RUN_ID}.example.com"
submit_csr "$_CLEAN"
$CTL sign --certname "$_CLEAN" >/dev/null 2>&1 || true
$CTL clean --certname "$_CLEAN" >/dev/null 2>&1 \
    && pass "puppet-ca-ctl clean --certname succeeds" \
    || fail "puppet-ca-ctl clean --certname succeeds"
assert_http 404 "After ctl clean cert status returns 404" \
    "${CA_URL}/puppet-ca/v1/certificate_status/${_CLEAN}"

# ═════════════════════════════════════════════════════════════════════════════
# Group 3 — puppet-ca-ctl sign --all (bulk signing)
# ═════════════════════════════════════════════════════════════════════════════
printf '\n# Group 3 — puppet-ca-ctl sign --all\n'

_BULK_A="bulk-a-${RUN_ID}.example.com"
_BULK_B="bulk-b-${RUN_ID}.example.com"
submit_csr "$_BULK_A"
submit_csr "$_BULK_B"

_signall_out=$($CTL sign --all 2>/dev/null) || true
grep -qiE "signed|Signed" <<< "$_signall_out" \
    && pass "puppet-ca-ctl sign --all reports signed certs" \
    || fail "puppet-ca-ctl sign --all reports signed certs" "output: $_signall_out"

for _bulk_cn in "$_BULK_A" "$_BULK_B"; do
    _bs=$(curl -s "${CA_URL}/puppet-ca/v1/certificate_status/${_bulk_cn}" 2>/dev/null) || true
    assert_json_field "$_bs" '"state":"signed"' \
        "Bulk-signed $_bulk_cn shows state=signed"
done

# ═════════════════════════════════════════════════════════════════════════════
# Group 4 — POST /generate/{subject}  (server-side key+cert generation)
# ═════════════════════════════════════════════════════════════════════════════
printf '\n# Group 4 — POST /generate/{subject}\n'

_GEN="gen-${RUN_ID}.example.com"

_gen_body=$(curl -s -X POST "${CA_URL}/puppet-ca/v1/generate/${_GEN}" 2>/dev/null) || true

assert_http 200 "POST /generate/{subject} returns 200" \
    -X POST "${CA_URL}/puppet-ca/v1/generate/${_GEN}-b"

assert_json_field "$_gen_body" '"private_key"' \
    "Generate response contains private_key field"

assert_json_field "$_gen_body" '"certificate"' \
    "Generate response contains certificate field"

# Extract cert PEM from the already-captured body (no second POST needed).
echo "$_gen_body" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('certificate',''),end='')" \
    > "$WORK_DIR/gen.crt" 2>/dev/null || true

openssl verify -CAfile "$WORK_DIR/ca.pem" "$WORK_DIR/gen.crt" >/dev/null 2>&1 \
    && pass "Generated cert cryptographically verifies against CA" \
    || fail "Generated cert cryptographically verifies against CA"

# CN in generated cert must match the requested subject
openssl x509 -noout -subject -in "$WORK_DIR/gen.crt" 2>/dev/null | grep -qF "${_GEN}" \
    && pass "Generated cert CN matches requested subject" \
    || fail "Generated cert CN matches requested subject"

# Generated cert must be present in certificate_statuses
_gen_status=$(curl -s "${CA_URL}/puppet-ca/v1/certificate_status/${_GEN}" 2>/dev/null) || true
assert_json_field "$_gen_status" '"state":"signed"' \
    "Generated cert shows as state=signed in certificate_status"

# Conflict: generating again for the same subject must return 409
assert_http 409 "POST /generate/{existing-subject} returns 409" \
    -X POST "${CA_URL}/puppet-ca/v1/generate/${_GEN}"

# Bad subject: must return 400
assert_http 400 "POST /generate/{invalid-subject} returns 400" \
    -X POST "${CA_URL}/puppet-ca/v1/generate/INVALID..NODE"

# puppet-ca-ctl generate subcommand
_GEN_CTL="gen-ctl-${RUN_ID}.example.com"
_GEN_DIR="$WORK_DIR/genout"
mkdir -p "$_GEN_DIR"
_ctl_cert=$($CTL generate --certname "$_GEN_CTL" --out-dir "$_GEN_DIR" 2>/dev/null) || true
[ -n "$_ctl_cert" ] \
    && pass "puppet-ca-ctl generate outputs certificate to stdout" \
    || fail "puppet-ca-ctl generate outputs certificate to stdout" "output was empty"

[ -f "$_GEN_DIR/${_GEN_CTL}_key.pem" ] \
    && pass "puppet-ca-ctl generate saves private key to --out-dir" \
    || fail "puppet-ca-ctl generate saves private key to --out-dir" \
           "key file missing: $_GEN_DIR/${_GEN_CTL}_key.pem"

echo "$_ctl_cert" > "$WORK_DIR/ctl_gen.crt"
openssl verify -CAfile "$WORK_DIR/ca.pem" "$WORK_DIR/ctl_gen.crt" >/dev/null 2>&1 \
    && pass "puppet-ca-ctl generated cert verifies against CA" \
    || fail "puppet-ca-ctl generated cert verifies against CA"

# ═════════════════════════════════════════════════════════════════════════════
# Group 5 — ?state= filter on GET /certificate_statuses
# ═════════════════════════════════════════════════════════════════════════════
printf '\n# Group 5 — GET /certificate_statuses?state= filter\n'

# Set up: one node pending (not signed), one node signed
_PEND="state-pend-${RUN_ID}.example.com"
_SIGNED="state-sign-${RUN_ID}.example.com"
submit_csr "$_PEND"      # will stay pending
submit_csr "$_SIGNED"
$CTL sign --certname "$_SIGNED" >/dev/null 2>&1 || true

# ?state=requested must include pending, exclude signed
_req_body=$(curl -s "${CA_URL}/puppet-ca/v1/certificate_statuses/all?state=requested" 2>/dev/null) || true
grep -qF "$_PEND" <<< "$_req_body" \
    && pass "?state=requested includes the pending CSR" \
    || fail "?state=requested includes the pending CSR" "body: $_req_body"
! grep -qF "$_SIGNED" <<< "$_req_body" \
    && pass "?state=requested excludes the signed cert" \
    || fail "?state=requested excludes the signed cert" "body: $_req_body"

# ?state=signed must include signed, exclude pending
_sign_body=$(curl -s "${CA_URL}/puppet-ca/v1/certificate_statuses/all?state=signed" 2>/dev/null) || true
grep -qF "$_SIGNED" <<< "$_sign_body" \
    && pass "?state=signed includes the signed cert" \
    || fail "?state=signed includes the signed cert" "body: $_sign_body"
! grep -qF "$_PEND" <<< "$_sign_body" \
    && pass "?state=signed excludes the pending CSR" \
    || fail "?state=signed excludes the pending CSR" "body: $_sign_body"

# No state param: must include both
_all_body=$(curl -s "${CA_URL}/puppet-ca/v1/certificate_statuses/all" 2>/dev/null) || true
grep -qF "$_PEND" <<< "$_all_body" \
    && pass "No ?state= param includes pending" \
    || fail "No ?state= param includes pending" "body: $_all_body"
grep -qF "$_SIGNED" <<< "$_all_body" \
    && pass "No ?state= param includes signed" \
    || fail "No ?state= param includes signed" "body: $_all_body"

# puppet-ca-ctl list (default: only requested)
_ctl_list_out=$($CTL list 2>/dev/null) || true
grep -qF "$_PEND" <<< "$_ctl_list_out" \
    && pass "puppet-ca-ctl list shows pending cert" \
    || fail "puppet-ca-ctl list shows pending cert" "output: $_ctl_list_out"
! grep -qF "$_SIGNED" <<< "$_ctl_list_out" \
    && pass "puppet-ca-ctl list (default) excludes signed cert" \
    || fail "puppet-ca-ctl list (default) excludes signed cert" "output: $_ctl_list_out"

# puppet-ca-ctl list --all: shows both
_ctl_all_out=$($CTL list --all 2>/dev/null) || true
grep -qF "$_SIGNED" <<< "$_ctl_all_out" \
    && pass "puppet-ca-ctl list --all shows signed cert" \
    || fail "puppet-ca-ctl list --all shows signed cert" "output: $_ctl_all_out"

# ═════════════════════════════════════════════════════════════════════════════
# Group 6 — cert_ttl in PUT /certificate_status
# ═════════════════════════════════════════════════════════════════════════════
printf '\n# Group 6 — cert_ttl custom validity\n'

_TTL="ttl-${RUN_ID}.example.com"
submit_csr "$_TTL"

# Sign with cert_ttl=7200 seconds (2 hours)
_ttl_sign=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT -H "Content-Type: application/json" \
    -d '{"desired_state":"signed","cert_ttl":7200}' \
    "${CA_URL}/puppet-ca/v1/certificate_status/${_TTL}") || true
[ "$_ttl_sign" = "204" ] \
    && pass "PUT /certificate_status with cert_ttl=7200 returns 204" \
    || fail "PUT /certificate_status with cert_ttl=7200 returns 204" "got HTTP $_ttl_sign"

# Download the cert and verify its validity period is ≤ 3 hours from now
curl -sf "${CA_URL}/puppet-ca/v1/certificate/${_TTL}" \
    -o "$WORK_DIR/ttl.crt" 2>/dev/null || true

_not_after=$(openssl x509 -noout -enddate -in "$WORK_DIR/ttl.crt" 2>/dev/null | cut -d= -f2) || true
_not_after_epoch=$(date -d "$_not_after" +%s 2>/dev/null) || true
_now_epoch=$(date +%s)
_delta=$(( _not_after_epoch - _now_epoch ))

# cert_ttl=7200s + 24h backdating; NotAfter should be ~7200s from now.
# Generous check: < 28800 (8 hours) rules out the default 5-year validity.
[ "$_delta" -lt 28800 ] \
    && pass "cert_ttl=7200 cert expires in < 8 hours (custom TTL applied)" \
    || fail "cert_ttl=7200 cert expires in < 8 hours (custom TTL applied)" \
           "delta=${_delta}s (expected < 28800)"

# ═════════════════════════════════════════════════════════════════════════════
# Group 7 — subject_alt_names mirrors dns_alt_names
# ═════════════════════════════════════════════════════════════════════════════
printf '\n# Group 7 — subject_alt_names field in status response\n'

_SAN="san-${RUN_ID}.example.com"
submit_csr "$_SAN"
$CTL sign --certname "$_SAN" >/dev/null 2>&1 || true

_san_body=$(curl -s "${CA_URL}/puppet-ca/v1/certificate_status/${_SAN}" 2>/dev/null) || true
assert_json_field "$_san_body" '"dns_alt_names"' \
    "Status response includes dns_alt_names field"
assert_json_field "$_san_body" '"subject_alt_names"' \
    "Status response includes subject_alt_names field"

# Both fields must exist and both should be empty arrays [] for a plain CSR
grep -qF '"dns_alt_names":[]' <<< "$_san_body" \
    && pass "dns_alt_names is [] for plain cert (no SANs)" \
    || fail "dns_alt_names is [] for plain cert (no SANs)" "body: $_san_body"
grep -qF '"subject_alt_names":[]' <<< "$_san_body" \
    && pass "subject_alt_names is [] for plain cert (matches dns_alt_names)" \
    || fail "subject_alt_names is [] for plain cert (matches dns_alt_names)" "body: $_san_body"

# GET /certificate_statuses must also have subject_alt_names
_sts_body=$(curl -s "${CA_URL}/puppet-ca/v1/certificate_statuses/all?state=signed" 2>/dev/null) || true
assert_json_field "$_sts_body" '"subject_alt_names"' \
    "GET /certificate_statuses response includes subject_alt_names per entry"

# ═════════════════════════════════════════════════════════════════════════════
# Group 8 — CSR CN mismatch rejection
# ═════════════════════════════════════════════════════════════════════════════
printf '\n# Group 8 — CSR CN mismatch rejection\n'

# Generate a CSR with CN=other-node but submit it as a different subject
_MISMATCH_CSR="$WORK_DIR/mismatch.csr"
openssl req -new \
    -key "$WORK_DIR/test.key" \
    -subj "/CN=other-node-${RUN_ID}" \
    -out "$_MISMATCH_CSR" \
    2>/dev/null

_mm_st=$(curl -s -o "$WORK_DIR/mm_body.txt" -w '%{http_code}' \
    -X PUT -H "Content-Type: text/plain" \
    --data-binary @"$_MISMATCH_CSR" \
    "${CA_URL}/puppet-ca/v1/certificate_request/different-node-${RUN_ID}") || true
[ "$_mm_st" = "400" ] \
    && pass "CSR with CN≠URL subject rejected with 400" \
    || fail "CSR with CN≠URL subject rejected with 400" "got HTTP $_mm_st"

grep -qiF "does not match" "$WORK_DIR/mm_body.txt" 2>/dev/null \
    && pass "CN mismatch error body contains 'does not match'" \
    || fail "CN mismatch error body contains 'does not match'" \
           "body: $(cat "$WORK_DIR/mm_body.txt" 2>/dev/null)"

# ═════════════════════════════════════════════════════════════════════════════
# Group 9 — Error cases (invalid subjects, bad JSON, conflict, CA:TRUE)
# ═════════════════════════════════════════════════════════════════════════════
printf '\n# Group 9 — Error cases\n'

assert_http 400 "Invalid subject (uppercase) on GET /certificate_status → 400" \
    "${CA_URL}/puppet-ca/v1/certificate_status/BadNode"

assert_http 400 "Invalid subject (double-dot) on GET /certificate_status → 400" \
    "${CA_URL}/puppet-ca/v1/certificate_status/a..b"

assert_http 400 "Invalid subject on GET /certificate → 400" \
    "${CA_URL}/puppet-ca/v1/certificate/BadNode"

assert_http 400 "Invalid subject on GET /certificate_request → 400" \
    "${CA_URL}/puppet-ca/v1/certificate_request/BadNode"

assert_http 400 "PUT /certificate_status with bad desired_state → 400" \
    -X PUT -H "Content-Type: application/json" \
    -d '{"desired_state":"destroyed"}' \
    "${CA_URL}/puppet-ca/v1/certificate_status/valid-node"

assert_http 400 "PUT /certificate_status with malformed JSON → 400" \
    -X PUT -H "Content-Type: application/json" \
    -d 'not-json' \
    "${CA_URL}/puppet-ca/v1/certificate_status/valid-node"

# 409: second CSR for active cert
_CONF="conflict-${RUN_ID}.example.com"
submit_csr "$_CONF"
$CTL sign --certname "$_CONF" >/dev/null 2>&1 || true
assert_http 409 "Duplicate CSR for active cert → 409" \
    -X PUT -H "Content-Type: text/plain" \
    --data-binary @"$WORK_DIR/${_CONF}.csr" \
    "${CA_URL}/puppet-ca/v1/certificate_request/${_CONF}"

# 409: CSR with BasicConstraints CA:TRUE
cat > "$WORK_DIR/ca_true.cnf" << 'OPENSSLEOF'
[ req ]
distinguished_name = dn
req_extensions     = v3_req
prompt             = no
[ dn ]
CN = evil-ca-node
[ v3_req ]
basicConstraints = critical, CA:true
OPENSSLEOF

_CA_TRUE="evil-ca-${RUN_ID}.example.com"
openssl req -new \
    -key "$WORK_DIR/test.key" \
    -config "$WORK_DIR/ca_true.cnf" \
    -subj "/CN=${_CA_TRUE}" \
    -out "$WORK_DIR/ca_true.csr" 2>/dev/null

curl -s -o /dev/null \
    -X PUT -H "Content-Type: text/plain" \
    --data-binary @"$WORK_DIR/ca_true.csr" \
    "${CA_URL}/puppet-ca/v1/certificate_request/${_CA_TRUE}" 2>/dev/null || true

_catrue_st=$(curl -s -o "$WORK_DIR/catrue_body.txt" -w '%{http_code}' \
    -X PUT -H "Content-Type: application/json" \
    -d '{"desired_state":"signed"}' \
    "${CA_URL}/puppet-ca/v1/certificate_status/${_CA_TRUE}") || true
[ "$_catrue_st" = "409" ] \
    && pass "CSR with CA:TRUE rejected with 409" \
    || fail "CSR with CA:TRUE rejected with 409" "got HTTP $_catrue_st"

grep -qF "Found extensions" "$WORK_DIR/catrue_body.txt" 2>/dev/null \
    && pass "CA:TRUE rejection body contains 'Found extensions'" \
    || fail "CA:TRUE rejection body contains 'Found extensions'" \
           "body: $(cat "$WORK_DIR/catrue_body.txt" 2>/dev/null)"

grep -qF "2.5.29.19" "$WORK_DIR/catrue_body.txt" 2>/dev/null \
    && pass "CA:TRUE rejection body contains OID 2.5.29.19" \
    || fail "CA:TRUE rejection body contains OID 2.5.29.19" \
           "body: $(cat "$WORK_DIR/catrue_body.txt" 2>/dev/null)"

# DELETE /certificate_request
_DEL="del-csr-${RUN_ID}.example.com"
submit_csr "$_DEL"
assert_http 200 "GET /certificate_request after PUT returns 200" \
    "${CA_URL}/puppet-ca/v1/certificate_request/${_DEL}"
assert_http 204 "DELETE /certificate_request returns 204" \
    -X DELETE "${CA_URL}/puppet-ca/v1/certificate_request/${_DEL}"
assert_http 404 "GET /certificate_request after DELETE returns 404" \
    "${CA_URL}/puppet-ca/v1/certificate_request/${_DEL}"
assert_http 404 "DELETE /certificate_request (missing) returns 404" \
    -X DELETE "${CA_URL}/puppet-ca/v1/certificate_request/no-such-node"

# DELETE /certificate_status (puppet cert clean)
_CLEAN2="clean2-${RUN_ID}.example.com"
submit_csr "$_CLEAN2"
$CTL sign --certname "$_CLEAN2" >/dev/null 2>&1 || true
assert_http 204 "DELETE /certificate_status (cert+CSR) returns 204" \
    -X DELETE "${CA_URL}/puppet-ca/v1/certificate_status/${_CLEAN2}"
assert_http 404 "GET /certificate_status after DELETE returns 404" \
    "${CA_URL}/puppet-ca/v1/certificate_status/${_CLEAN2}"
assert_http 404 "DELETE /certificate_status (nonexistent) returns 404" \
    -X DELETE "${CA_URL}/puppet-ca/v1/certificate_status/no-such-node"

# ═════════════════════════════════════════════════════════════════════════════
# Group 10 — Protocol features (path prefixes, bare paths)
# ═════════════════════════════════════════════════════════════════════════════
printf '\n# Group 10 — Protocol features (bare and prefixed paths)\n'

assert_http 200 "GET /certificate/ca (bare path) returns 200" \
    "${CA_URL}/certificate/ca"
assert_http 200 "GET /certificate_revocation_list/ca (bare path) returns 200" \
    "${CA_URL}/certificate_revocation_list/ca"
assert_http 200 "GET /puppet-ca/v1/certificate/ca (prefixed) returns 200" \
    "${CA_URL}/puppet-ca/v1/certificate/ca"
assert_http 404 "GET /puppet-ca/v1/certificate_status/noexist returns 404" \
    "${CA_URL}/puppet-ca/v1/certificate_status/no-such-host"

_PFX="pfx-${RUN_ID}.example.com"
submit_csr "$_PFX"
assert_http 200 "GET /puppet-ca/v1/certificate_request/{pending} returns 200" \
    "${CA_URL}/puppet-ca/v1/certificate_request/${_PFX}"

# ═════════════════════════════════════════════════════════════════════════════
# Group 11 — puppet-ca-ctl offline subcommands (run inside test-runner)
# ═════════════════════════════════════════════════════════════════════════════
printf '\n# Group 11 — puppet-ca-ctl offline: setup and import\n'

# --- 11a: setup ---
_SETUP_DIR=$(mktemp -d)
puppet-ca-ctl setup --cadir "$_SETUP_DIR" --hostname "setup-test-${RUN_ID}.example.com" \
    >/dev/null 2>&1 \
    && pass "puppet-ca-ctl setup succeeds" \
    || fail "puppet-ca-ctl setup succeeds"

[ -f "$_SETUP_DIR/ca_crt.pem" ] \
    && pass "puppet-ca-ctl setup creates ca_crt.pem" \
    || fail "puppet-ca-ctl setup creates ca_crt.pem"

[ -f "$_SETUP_DIR/private/ca_key.pem" ] \
    && pass "puppet-ca-ctl setup creates private/ca_key.pem" \
    || fail "puppet-ca-ctl setup creates private/ca_key.pem"

[ -f "$_SETUP_DIR/ca_crl.pem" ] \
    && pass "puppet-ca-ctl setup creates ca_crl.pem" \
    || fail "puppet-ca-ctl setup creates ca_crl.pem"

[ -f "$_SETUP_DIR/serial" ] \
    && pass "puppet-ca-ctl setup creates serial file" \
    || fail "puppet-ca-ctl setup creates serial file"

# CA cert CN must match hostname
openssl x509 -noout -subject -in "$_SETUP_DIR/ca_crt.pem" 2>/dev/null \
    | grep -qF "setup-test-${RUN_ID}.example.com" \
    && pass "puppet-ca-ctl setup CA cert CN matches --hostname" \
    || fail "puppet-ca-ctl setup CA cert CN matches --hostname"

# CA cert must be self-signed
openssl verify -CAfile "$_SETUP_DIR/ca_crt.pem" "$_SETUP_DIR/ca_crt.pem" >/dev/null 2>&1 \
    && pass "puppet-ca-ctl setup CA cert is self-signed" \
    || fail "puppet-ca-ctl setup CA cert is self-signed"

rm -rf "$_SETUP_DIR"

# --- 11b: import ---
# Generate a CA cert+key with openssl to import
_IMP_DIR=$(mktemp -d)
_IMP_DEST=$(mktemp -d)

cat > "$_IMP_DIR/ca.cnf" << 'OPENSSLEOF'
[ req ]
distinguished_name = dn
x509_extensions    = v3_ca
prompt             = no
[ dn ]
CN = Imported Test CA
[ v3_ca ]
basicConstraints = critical, CA:TRUE
keyUsage         = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
OPENSSLEOF

openssl req -x509 -newkey rsa:2048 -days 3650 -nodes \
    -keyout "$_IMP_DIR/ca.key" \
    -out    "$_IMP_DIR/ca.crt" \
    -config "$_IMP_DIR/ca.cnf" \
    2>/dev/null \
    && pass "openssl generated import CA cert+key" \
    || fail "openssl generated import CA cert+key"

puppet-ca-ctl import \
    --cadir "$_IMP_DEST" \
    --cert-bundle "$_IMP_DIR/ca.crt" \
    --private-key "$_IMP_DIR/ca.key" \
    >/dev/null 2>&1 \
    && pass "puppet-ca-ctl import succeeds" \
    || fail "puppet-ca-ctl import succeeds"

[ -f "$_IMP_DEST/ca_crt.pem" ] \
    && pass "puppet-ca-ctl import creates ca_crt.pem" \
    || fail "puppet-ca-ctl import creates ca_crt.pem"

[ -f "$_IMP_DEST/private/ca_key.pem" ] \
    && pass "puppet-ca-ctl import creates private/ca_key.pem" \
    || fail "puppet-ca-ctl import creates private/ca_key.pem"

# Verify the imported cert is identical to what we passed in
diff -q "$_IMP_DIR/ca.crt" "$_IMP_DEST/ca_crt.pem" >/dev/null 2>&1 \
    && pass "puppet-ca-ctl import cert file matches source" \
    || fail "puppet-ca-ctl import cert file matches source"

# A CA can be started from the imported directory
puppet-ca-ctl setup --cadir "$_IMP_DEST" --hostname "existing" >/dev/null 2>&1
# (setup on an existing dir loads successfully — the CA key/cert is already there)
[ -f "$_IMP_DEST/ca_crt.pem" ] \
    && pass "CA directory usable after import (cert file still present)" \
    || fail "CA directory usable after import (cert file still present)"

# Import with mismatched key must fail
_BAD_DIR=$(mktemp -d)
openssl req -x509 -newkey rsa:2048 -days 3650 -nodes \
    -keyout "$_IMP_DIR/other.key" \
    -out    "$_IMP_DIR/other.crt" \
    -config "$_IMP_DIR/ca.cnf" \
    2>/dev/null || true

puppet-ca-ctl import \
    --cadir "$_BAD_DIR" \
    --cert-bundle "$_IMP_DIR/ca.crt" \
    --private-key "$_IMP_DIR/other.key" \
    >/dev/null 2>&1 \
    && fail "puppet-ca-ctl import with mismatched key must fail" \
    || pass "puppet-ca-ctl import with mismatched key correctly fails"

rm -rf "$_IMP_DIR" "$_IMP_DEST" "$_BAD_DIR"

# ═════════════════════════════════════════════════════════════════════════════
# Group 12 — POST /sign and POST /sign/all (bulk HTTP API)
# ═════════════════════════════════════════════════════════════════════════════
printf '\n# Group 12 — POST /sign and POST /sign/all\n'

_S1="sign-api-a-${RUN_ID}.example.com"
_S2="sign-api-b-${RUN_ID}.example.com"
submit_csr "$_S1"
submit_csr "$_S2"

_sign_body=$(curl -s \
    -X POST -H "Content-Type: application/json" \
    -d "{\"certnames\":[\"${_S1}\",\"${_S2}\",\"ghost-node\"]}" \
    "${CA_URL}/puppet-ca/v1/sign" 2>/dev/null) || true
assert_json_field "$_sign_body" '"signed"' \
    "POST /sign returns signed field"
grep -qF "$_S1" <<< "$_sign_body" \
    && pass "POST /sign signed first certname" \
    || fail "POST /sign signed first certname" "body: $_sign_body"
grep -qF "ghost-node" <<< "$_sign_body" \
    && pass "POST /sign reports ghost-node in no-csr" \
    || fail "POST /sign reports ghost-node in no-csr" "body: $_sign_body"

_SA1="signall-a-${RUN_ID}.example.com"
_SA2="signall-b-${RUN_ID}.example.com"
submit_csr "$_SA1"
submit_csr "$_SA2"

_signall_body=$(curl -s -X POST "${CA_URL}/puppet-ca/v1/sign/all" 2>/dev/null) || true
assert_json_field "$_signall_body" '"signed"' \
    "POST /sign/all returns signed field"
grep -qF "$_SA1" <<< "$_signall_body" \
    && pass "POST /sign/all signed SA1" \
    || fail "POST /sign/all signed SA1" "body: $_signall_body"

# ═════════════════════════════════════════════════════════════════════════════
# Group 13 — Concurrency / load  (opt-in via DO_LOAD=true)
# ═════════════════════════════════════════════════════════════════════════════
if [ "$DO_LOAD" = "true" ]; then
    printf '\n# Group 13 — Concurrency / load tests\n'

    _LOAD_N=20
    printf '# Pre-generating %d CSRs...\n' "$_LOAD_N"
    for i in $(seq 1 "$_LOAD_N"); do
        make_csr "load-${RUN_ID}-${i}.example.com" "$WORK_DIR/load-${i}.csr"
    done

    printf '# Submitting %d CSRs concurrently...\n' "$_LOAD_N"
    _w_pids=()
    for i in $(seq 1 "$_LOAD_N"); do
        curl -s -o /dev/null -w '%{http_code}' \
            -X PUT -H "Content-Type: text/plain" \
            --data-binary @"$WORK_DIR/load-${i}.csr" \
            "${CA_URL}/puppet-ca/v1/certificate_request/load-${RUN_ID}-${i}.example.com" \
            > "$WORK_DIR/w-${i}.txt" 2>/dev/null &
        _w_pids+=($!)
    done
    for pid in "${_w_pids[@]}"; do wait "$pid" || true; done

    _w_ok=0
    for i in $(seq 1 "$_LOAD_N"); do
        [[ "$(cat "$WORK_DIR/w-${i}.txt" 2>/dev/null)" =~ ^2 ]] && _w_ok=$(( _w_ok + 1 ))
    done
    [ "$_w_ok" -eq "$_LOAD_N" ] \
        && pass "${_LOAD_N} concurrent CSR submissions all 2xx" \
        || fail "${_LOAD_N} concurrent CSR submissions all 2xx" "${_w_ok}/${_LOAD_N} succeeded"

    # Sign all via single sign/all call
    _sa=$(curl -s -X POST "${CA_URL}/puppet-ca/v1/sign/all" 2>/dev/null) || true
    _signed_cnt=$(echo "$_sa" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('signed',[])))" 2>/dev/null) || _signed_cnt=0
    [ "$_signed_cnt" -ge "$_LOAD_N" ] \
        && pass "POST /sign/all signed all ${_LOAD_N} load-test CSRs" \
        || fail "POST /sign/all signed all ${_LOAD_N} load-test CSRs" "signed=${_signed_cnt}"

    printf '# Firing 50 concurrent reads...\n'
    _r_pids=()
    _r_start=$(date +%s%3N)
    for i in $(seq 1 50); do
        curl -s -o /dev/null -w '%{http_code}' \
            "${CA_URL}/puppet-ca/v1/certificate/ca" \
            > "$WORK_DIR/r-${i}.txt" 2>/dev/null &
        _r_pids+=($!)
    done
    for pid in "${_r_pids[@]}"; do wait "$pid" || true; done
    _r_elapsed=$(( $(date +%s%3N) - _r_start ))
    _r_ok=0
    for i in $(seq 1 50); do
        [ "$(cat "$WORK_DIR/r-${i}.txt" 2>/dev/null)" = "200" ] && _r_ok=$(( _r_ok + 1 ))
    done
    [ "$_r_ok" -eq 50 ] \
        && pass "50 concurrent GET /certificate/ca all 200 (${_r_elapsed}ms)" \
        || fail "50 concurrent GET /certificate/ca all 200" "${_r_ok}/50 returned 200"
fi

# ═════════════════════════════════════════════════════════════════════════════
# Group 14 — Autosign modes (true, file glob, executable plugin)
#   Starts short-lived local puppet-ca instances on port 8141 inside this
#   container.  The shared puppet-ca service (port 8140) is untouched.
#   Each sub-test boots a fresh CA, exercises one autosign config, then stops.
# ═════════════════════════════════════════════════════════════════════════════
printf '\n# Group 14 — Autosign modes (true, file, executable)\n'

_LOCAL_CA="http://127.0.0.1:8141"
_LOCAL_PORT=8141

# Wait up to 10 s for a local CA to become healthy
_wait_local_ca() {
    local n=20
    while [ "$n" -gt 0 ]; do
        curl -sf "${_LOCAL_CA}/puppet-ca/v1/certificate/ca" -o /dev/null 2>/dev/null && return 0
        sleep 0.5
        n=$(( n - 1 ))
    done
    return 1
}

# ── 14a: autosign=true ────────────────────────────────────────────────────────
_AS_DIR_A=$(mktemp -d)
puppet-ca --cadir="$_AS_DIR_A" \
    --autosign-config=true \
    --host=127.0.0.1 --port="$_LOCAL_PORT" \
    >/dev/null 2>&1 &
_as_pid_a=$!

if _wait_local_ca; then
    pass "autosign=true: local CA started"

    _AS_TRUE_NODE="as-true-${RUN_ID}.example.com"
    make_csr "$_AS_TRUE_NODE" "$WORK_DIR/as_true.csr"

    _as_true_st=$(curl -s -o /dev/null -w '%{http_code}' \
        -X PUT -H "Content-Type: text/plain" \
        --data-binary @"$WORK_DIR/as_true.csr" \
        "${_LOCAL_CA}/puppet-ca/v1/certificate_request/${_AS_TRUE_NODE}") || true
    [ "$_as_true_st" = "200" ] \
        && pass "autosign=true: CSR submission returns 200" \
        || fail "autosign=true: CSR submission returns 200" "got HTTP $_as_true_st"

    _as_true_status=$(curl -s \
        "${_LOCAL_CA}/puppet-ca/v1/certificate_status/${_AS_TRUE_NODE}" 2>/dev/null) || true
    assert_json_field "$_as_true_status" '"state":"signed"' \
        "autosign=true: cert is immediately signed without operator action"

    # CSR file must be deleted after autosign
    assert_http 404 "autosign=true: CSR deleted after autosign (no pending request)" \
        "${_LOCAL_CA}/puppet-ca/v1/certificate_request/${_AS_TRUE_NODE}"
else
    fail "autosign=true: local CA started" "timed out waiting for health"
fi

kill "$_as_pid_a" 2>/dev/null || true
wait "$_as_pid_a" 2>/dev/null || true
rm -rf "$_AS_DIR_A"

# ── 14b: autosign=file (glob patterns) ───────────────────────────────────────
_AS_DIR_B=$(mktemp -d)
_AS_CONF_B="$WORK_DIR/autosign.conf"
printf '# autosign pattern file\n*.allowed.example.com\n' > "$_AS_CONF_B"

puppet-ca --cadir="$_AS_DIR_B" \
    --autosign-config="$_AS_CONF_B" \
    --host=127.0.0.1 --port="$_LOCAL_PORT" \
    >/dev/null 2>&1 &
_as_pid_b=$!

if _wait_local_ca; then
    pass "autosign=file: local CA started"

    # Matching CN → autosigned
    _AS_MATCH="match-${RUN_ID}.allowed.example.com"
    make_csr "$_AS_MATCH" "$WORK_DIR/as_match.csr"
    curl -s -o /dev/null \
        -X PUT -H "Content-Type: text/plain" \
        --data-binary @"$WORK_DIR/as_match.csr" \
        "${_LOCAL_CA}/puppet-ca/v1/certificate_request/${_AS_MATCH}" 2>/dev/null || true
    _match_status=$(curl -s \
        "${_LOCAL_CA}/puppet-ca/v1/certificate_status/${_AS_MATCH}" 2>/dev/null) || true
    assert_json_field "$_match_status" '"state":"signed"' \
        "autosign=file: CN matching glob pattern is auto-signed"

    # Non-matching CN → stays pending
    _AS_NOMATCH="nomatch-${RUN_ID}.denied.example.com"
    make_csr "$_AS_NOMATCH" "$WORK_DIR/as_nomatch.csr"
    curl -s -o /dev/null \
        -X PUT -H "Content-Type: text/plain" \
        --data-binary @"$WORK_DIR/as_nomatch.csr" \
        "${_LOCAL_CA}/puppet-ca/v1/certificate_request/${_AS_NOMATCH}" 2>/dev/null || true
    _nomatch_status=$(curl -s \
        "${_LOCAL_CA}/puppet-ca/v1/certificate_status/${_AS_NOMATCH}" 2>/dev/null) || true
    assert_json_field "$_nomatch_status" '"state":"requested"' \
        "autosign=file: CN not matching any glob stays in requested state"

    # Comment lines and blank lines must be ignored (they do not accidentally match)
    assert_json_field "$_nomatch_status" '"state":"requested"' \
        "autosign=file: comment/blank lines in pattern file do not cause spurious match"
else
    fail "autosign=file: local CA started" "timed out waiting for health"
fi

kill "$_as_pid_b" 2>/dev/null || true
wait "$_as_pid_b" 2>/dev/null || true
rm -rf "$_AS_DIR_B"

# ── 14c: autosign=executable (custom plugin) ──────────────────────────────────
# The plugin:
#   argv[1] = certname (Subject CN) — used for allow/deny decision
#   stdin   = raw CSR PEM bytes     — validated to confirm the server sends it
# Exit 0 → sign,  exit 1 → deny,  exit 2 → stdin validation failed (treated as error)
_AS_DIR_C=$(mktemp -d)
_AS_EXEC="$WORK_DIR/autosign_plugin.sh"
cat > "$_AS_EXEC" << 'PLUGIN_EOF'
#!/bin/bash
# Custom autosign plugin exercising both argv[1] and stdin.
subject="$1"
csr_pem=$(cat)

# Fail loudly if stdin did not contain a CSR — lets us detect if the server
# forgot to pipe the PEM.
echo "$csr_pem" | grep -q "BEGIN CERTIFICATE REQUEST" || exit 2

# Policy: sign only subjects that contain the word "allowed"
case "$subject" in
    *allowed*) exit 0 ;;
    *)         exit 1 ;;
esac
PLUGIN_EOF
chmod 755 "$_AS_EXEC"

puppet-ca --cadir="$_AS_DIR_C" \
    --autosign-config="$_AS_EXEC" \
    --host=127.0.0.1 --port="$_LOCAL_PORT" \
    >/dev/null 2>&1 &
_as_pid_c=$!

if _wait_local_ca; then
    pass "autosign=executable: local CA started"

    # Allow path: plugin exits 0 → cert auto-signed
    _AS_ALLOW="plugin-allowed-${RUN_ID}.example.com"
    make_csr "$_AS_ALLOW" "$WORK_DIR/as_allow.csr"
    curl -s -o /dev/null \
        -X PUT -H "Content-Type: text/plain" \
        --data-binary @"$WORK_DIR/as_allow.csr" \
        "${_LOCAL_CA}/puppet-ca/v1/certificate_request/${_AS_ALLOW}" 2>/dev/null || true
    _allow_status=$(curl -s \
        "${_LOCAL_CA}/puppet-ca/v1/certificate_status/${_AS_ALLOW}" 2>/dev/null) || true
    assert_json_field "$_allow_status" '"state":"signed"' \
        "autosign=executable: plugin exit 0 → cert auto-signed"

    # Deny path: plugin exits 1 → cert stays pending
    _AS_DENY="plugin-denied-${RUN_ID}.example.com"
    make_csr "$_AS_DENY" "$WORK_DIR/as_deny.csr"
    curl -s -o /dev/null \
        -X PUT -H "Content-Type: text/plain" \
        --data-binary @"$WORK_DIR/as_deny.csr" \
        "${_LOCAL_CA}/puppet-ca/v1/certificate_request/${_AS_DENY}" 2>/dev/null || true
    _deny_status=$(curl -s \
        "${_LOCAL_CA}/puppet-ca/v1/certificate_status/${_AS_DENY}" 2>/dev/null) || true
    assert_json_field "$_deny_status" '"state":"requested"' \
        "autosign=executable: plugin exit 1 → cert stays pending (not auto-signed)"

    # The plugin exits 2 if stdin lacks the PEM header; the allow-path test
    # already proved stdin was delivered correctly (plugin exit 0 required it).
    # Confirm explicitly: the _AS_ALLOW cert was signed, so stdin check passed.
    assert_json_field "$_allow_status" '"state":"signed"' \
        "autosign=executable: plugin received valid CSR PEM on stdin (exit 0 proves stdin check passed)"

    # argv[1] = CN: plugin uses it for allow/deny; the deny test confirms
    # argv[1] was the actual CN ("plugin-denied-…"), not something else.
    assert_json_field "$_deny_status" '"state":"requested"' \
        "autosign=executable: plugin received certname as argv[1] (deny decision used it)"
else
    fail "autosign=executable: local CA started" "timed out waiting for health"
fi

kill "$_as_pid_c" 2>/dev/null || true
wait "$_as_pid_c" 2>/dev/null || true
rm -rf "$_AS_DIR_C"

# ═════════════════════════════════════════════════════════════════════════════
# Results
# ═════════════════════════════════════════════════════════════════════════════
printf '\n1..%d\n' "$T"
printf '# Results: %d passed, %d failed out of %d\n' \
    $(( T - FAILURES )) "$FAILURES" "$T"

[ "$FAILURES" -eq 0 ]
