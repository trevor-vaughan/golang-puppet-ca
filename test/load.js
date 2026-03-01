/**
 * puppet-ca k6 load test
 *
 * Three goals, one script:
 *   1. Correctness  – check assertions fail the run if responses are wrong
 *   2. Performance  – measure throughput and latency percentiles at steady load
 *   3. Saturation   – ramp VUs until error rate or latency thresholds are breached
 *
 * Two concurrent scenarios:
 *   reads    – read-only endpoints; ramps to 200 VUs
 *   workflow – full lifecycle (generate → status → cert → clean); ramps to 50 VUs
 *              (lower ceiling because server-side RSA key generation is CPU-bound)
 *
 * Phases per scenario:
 *   0:00  smoke      –   5 / 2 VUs for 30 s  (correctness)
 *   0:30  load       –  50 /10 VUs for 2 m   (benchmark)
 *   2:30  stress     – 200 /50 VUs for 2 m   (saturation)
 *   4:30  cool-down  –   0 / 0 VUs for 30 s
 *
 * Environment variables:
 *   CA_URL   Base URL of the puppet-ca server (default: http://puppet-ca:8140)
 */

import http from 'k6/http';
import { check } from 'k6';
import { Rate } from 'k6/metrics';

const BASE = (__ENV.CA_URL || 'http://puppet-ca:8140') + '/puppet-ca/v1';

// Custom error-rate metric so thresholds can reference it by name.
const errors = new Rate('errors');

// ── Options ──────────────────────────────────────────────────────────────────

export const options = {
  scenarios: {
    reads: {
      executor: 'ramping-vus',
      exec: 'readScenario',
      startVUs: 0,
      stages: [
        { duration: '30s', target: 5   }, // smoke
        { duration: '2m',  target: 50  }, // sustained load
        { duration: '2m',  target: 200 }, // stress / saturation
        { duration: '30s', target: 0   }, // cool-down
      ],
    },
    workflow: {
      executor: 'ramping-vus',
      exec: 'workflowScenario',
      startVUs: 0,
      stages: [
        { duration: '30s', target: 2  }, // smoke
        { duration: '2m',  target: 10 }, // sustained load
        { duration: '2m',  target: 50 }, // stress / saturation
        { duration: '30s', target: 0  }, // cool-down
      ],
    },
  },
  thresholds: {
    // Overall correctness: fewer than 1% of requests must error.
    errors: ['rate<0.01'],
    // Read endpoints should be fast.
    'http_req_duration{scenario:reads}': ['p(95)<500'],
    // Workflow includes RSA key generation; allow more headroom.
    'http_req_duration{scenario:workflow}': ['p(95)<5000'],
  },
};

// ── Scenario: reads ───────────────────────────────────────────────────────────
// Exercises the three most-hit read-only endpoints:
//   GET /certificate/ca                    – Puppet agents fetch this on every run
//   GET /certificate_revocation_list/ca    – Puppet servers poll this regularly
//   GET /expirations                       – Operator health-check endpoint

export function readScenario() {
  let ok = true;

  const caResp = http.get(`${BASE}/certificate/ca`);
  ok = check(caResp, { 'ca cert: status 200': r => r.status === 200 }) && ok;

  const crlResp = http.get(`${BASE}/certificate_revocation_list/ca`);
  ok = check(crlResp, { 'crl: status 200': r => r.status === 200 }) && ok;

  const expResp = http.get(`${BASE}/expirations`);
  ok = check(expResp, {
    'expirations: status 200':         r => r.status === 200,
    'expirations: has ca_certificate': r => {
      try { return 'ca_certificate' in JSON.parse(r.body); }
      catch (_) { return false; }
    },
  }) && ok;

  errors.add(!ok);
}

// ── Scenario: workflow ────────────────────────────────────────────────────────
// Exercises the full server-side certificate lifecycle:
//   POST /generate/{subject}                 – generate RSA key + sign cert
//   GET  /certificate_status/{subject}       – verify state == "signed"
//   GET  /certificate/{subject}              – download the signed cert
//   DELETE /certificate_status/{subject}     – revoke + delete (cleanup)
//
// Subject names are unique per VU × iteration so parallel VUs never conflict.
// The DELETE at the end ensures the next iteration of the same VU can recycle
// the slot without hitting 409.

// ── End-of-run summary ────────────────────────────────────────────────────────
// Produces a focused report with system context, threshold verdicts, and key
// latency percentiles per scenario.

export function handleSummary(data) {
  const m = data.metrics;

  function fmtMs(v)   { return v == null ? 'n/a' : `${v.toFixed(1)} ms`; }
  function fmtRate(v) { return v == null ? 'n/a' : `${(v * 100).toFixed(2)}%`; }
  function fmtInt(v)  { return v == null ? '0'   : String(Math.round(v)); }

  // Returns 'PASS' / 'FAIL' / 'n/a' for a named metric's thresholds.
  function threshVerdict(name) {
    const metric = m[name];
    if (!metric || !metric.thresholds) return 'n/a';
    const ok = Object.values(metric.thresholds).every(t => t.ok);
    return ok ? 'PASS' : 'FAIL';
  }

  function scenarioBlock(label, tag) {
    const dur  = m[`http_req_duration{scenario:${tag}}`] || {};
    const reqs = m[`http_reqs{scenario:${tag}}`]         || {};
    const fail = m[`http_req_failed{scenario:${tag}}`]   || {};
    const dv   = dur.values  || {};
    const rv   = reqs.values || {};
    const fv   = fail.values || {};
    return [
      `  ${label}`,
      `    requests: ${fmtInt(rv.count)}  (${fmtRate(fv.rate)} failed)`,
      `    p(95):    ${fmtMs(dv['p(95)'])}`,
      `    p(99):    ${fmtMs(dv['p(99)'])}`,
      `    max:      ${fmtMs(dv.max)}`,
    ].join('\n');
  }

  function sysBlock() {
    const mem = __ENV.REPORT_MEM_GB ? `${__ENV.REPORT_MEM_GB} GB` : '(unknown)';
    return [
      '  System',
      `    date:    ${new Date().toISOString()}`,
      `    host:    ${__ENV.REPORT_HOST   || '(unknown)'}`,
      `    cpus:    ${__ENV.REPORT_CPUS   || '(unknown)'}`,
      `    memory:  ${mem}`,
      `    kernel:  ${__ENV.REPORT_KERNEL || '(unknown)'}`,
      `    ca url:  ${__ENV.CA_URL        || 'http://puppet-ca:8140'}`,
    ].join('\n');
  }

  const ms  = data.state.testRunDurationMs;
  const min = Math.floor(ms / 60000);
  const sec = Math.round((ms % 60000) / 1000);

  const report = [
    '',
    '╔══════════════════════════════════════════════════════════╗',
    '║           puppet-ca benchmark test results               ║',
    '╚══════════════════════════════════════════════════════════╝',
    `  duration: ${min}m ${sec}s`,
    '',
    sysBlock(),
    '',
    '  Thresholds',
    `    error rate      (<1%):    ${threshVerdict('errors')}`,
    `    reads p(95)     (<500ms): ${threshVerdict('http_req_duration{scenario:reads}')}`,
    `    workflow p(95)  (<5s):    ${threshVerdict('http_req_duration{scenario:workflow}')}`,
    '',
    scenarioBlock('READ  (GET /certificate/ca + /crl + /expirations)', 'reads'),
    '',
    scenarioBlock('WRITE (POST /generate → status → cert → DELETE)', 'workflow'),
    '',
  ].join('\n');

  return { stdout: report };
}

export function workflowScenario() {
  // Subject must match ^[a-z0-9._-]+$ (puppet-ca validation rule).
  const subject = `bench-vu${__VU}-i${__ITER}.puppet.test`;
  let ok = true;

  // Generate: server creates RSA 2048 key + signs cert.
  const genResp = http.post(`${BASE}/generate/${subject}`);
  if (!check(genResp, { 'generate: status 200': r => r.status === 200 })) {
    errors.add(1);
    return; // No cert to fetch or clean up.
  }

  // Verify the cert was signed (state == "signed").
  const statusResp = http.get(`${BASE}/certificate_status/${subject}`);
  ok = check(statusResp, {
    'status: status 200':  r => r.status === 200,
    'status: state signed': r => {
      try { return JSON.parse(r.body).state === 'signed'; }
      catch (_) { return false; }
    },
  }) && ok;

  // Download the signed certificate PEM.
  const certResp = http.get(`${BASE}/certificate/${subject}`);
  ok = check(certResp, {
    'cert: status 200':       r => r.status === 200,
    'cert: is PEM':           r => r.body.includes('BEGIN CERTIFICATE'),
  }) && ok;

  errors.add(!ok);

  // Clean up: revoke + delete so disk does not fill up during the run.
  http.del(`${BASE}/certificate_status/${subject}`);
}
