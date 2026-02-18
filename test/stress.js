/**
 * puppet-ca upper-limit stress test
 *
 * Goal: find the saturation point — NOT to pass or fail.
 * There are no thresholds. The run always exits 0. Results are printed to
 * stdout as a focused summary at the end of the run.
 *
 * Two independent scenarios use the ramping-arrival-rate executor, which
 * fixes the *request rate* and increases it over time. When the server
 * cannot keep up, k6 reports dropped_iterations and latency goes nonlinear —
 * that inflection point is the saturation ceiling.
 *
 * Scenarios:
 *   read_saturation  — GET /certificate/ca; ramps 10 → 500 req/s
 *                      Exercises the read path and Go's HTTP concurrency.
 *   write_saturation — POST /generate/{subject} + DELETE cleanup;
 *                      ramps 1 → 50 req/s.
 *                      Exercises RSA key generation (CPU-bound).
 *
 * Phases (per scenario):
 *   0:00  warm-up   — low rate for 30 s (let the CA settle)
 *   0:30  ramp      — four 1-minute steps, increasing toward the ceiling
 *   4:30  cool-down — 30 s back to 0
 *
 * Key metrics to watch in the summary:
 *   http_req_duration{scenario:*}   p(90), p(95), p(99) — latency inflection
 *   dropped_iterations              non-zero = server cannot keep up at that rate
 *   errors                          assertion failures (non-200 responses)
 *
 * Environment variables:
 *   CA_URL   Base URL of the puppet-ca server (default: http://puppet-ca:8140)
 */

import http from 'k6/http';
import { check } from 'k6';
import { Rate } from 'k6/metrics';
import exec from 'k6/execution';

const BASE = (__ENV.CA_URL || 'http://puppet-ca:8140') + '/puppet-ca/v1';

const errors = new Rate('errors');

// ── Stage definitions ─────────────────────────────────────────────────────────
// Declared outside options so maxVUs can be derived from the peak target rate.

const READ_STAGES = [
  { duration: '30s', target: 10  }, // warm-up
  { duration: '1m',  target: 50  }, // light load
  { duration: '1m',  target: 150 }, // medium load
  { duration: '1m',  target: 300 }, // heavy load
  { duration: '1m',  target: 500 }, // attempt ceiling
  { duration: '30s', target: 0   }, // cool-down
];

const WRITE_STAGES = [
  { duration: '30s', target: 1  }, // warm-up
  { duration: '1m',  target: 5  }, // light load
  { duration: '1m',  target: 15 }, // medium load
  { duration: '1m',  target: 30 }, // heavy load
  { duration: '1m',  target: 50 }, // attempt ceiling
  { duration: '30s', target: 0  }, // cool-down
];

// maxVUs = peak_rate × worst_case_latency_s
// The latency ceiling is a generous estimate of how long a single request can
// take when the server is fully saturated.  It determines how many requests
// can be simultaneously in-flight, which is the minimum VU pool needed to
// sustain the target arrival rate without k6 running dry before the server
// does.  If the warning "Insufficient VUs" appears, raise the ceiling.
const READ_MAX_LATENCY_S  = 1; // cached PEM reads stay well under 1 s even saturated
const WRITE_MAX_LATENCY_S = 5; // RSA key generation can stall up to ~5 s under load

function peakRate(stages) {
  return Math.max(...stages.map(s => s.target));
}

const READ_MAX_VUS  = Math.ceil(peakRate(READ_STAGES)  * READ_MAX_LATENCY_S);
const WRITE_MAX_VUS = Math.ceil(peakRate(WRITE_STAGES) * WRITE_MAX_LATENCY_S);

// ── Options ──────────────────────────────────────────────────────────────────

export const options = {
  // Thresholds exist solely to materialise the per-scenario sub-metrics in the
  // handleSummary data object — k6 only adds tagged sub-metrics to data.metrics
  // when they are referenced in at least one threshold.  All limits are set far
  // beyond anything this server will produce, so the run always exits 0.
  thresholds: {
    [`http_req_duration{scenario:read_saturation}`]:   ['p(99)<999999'],
    [`http_req_duration{scenario:write_saturation}`]:  ['p(99)<999999'],
    [`http_req_failed{scenario:read_saturation}`]:     ['rate<1.01'],
    [`http_req_failed{scenario:write_saturation}`]:    ['rate<1.01'],
    [`http_reqs{scenario:read_saturation}`]:           ['count<999999999'],
    [`http_reqs{scenario:write_saturation}`]:          ['count<999999999'],
    [`dropped_iterations{scenario:read_saturation}`]:  ['count<999999999'],
    [`dropped_iterations{scenario:write_saturation}`]: ['count<999999999'],
  },
  summaryTrendStats: ['avg', 'p(90)', 'p(95)', 'p(99)', 'max'],
  scenarios: {

    // ── Read saturation ───────────────────────────────────────────────────
    read_saturation: {
      executor: 'ramping-arrival-rate',
      exec: 'readScenario',
      startRate: READ_STAGES[0].target,
      timeUnit: '1s',
      preAllocatedVUs: 50,
      maxVUs: READ_MAX_VUS,
      stages: READ_STAGES,
    },

    // ── Write saturation ──────────────────────────────────────────────────
    write_saturation: {
      executor: 'ramping-arrival-rate',
      exec: 'writeScenario',
      startRate: WRITE_STAGES[0].target,
      timeUnit: '1s',
      preAllocatedVUs: 10,
      maxVUs: WRITE_MAX_VUS,
      stages: WRITE_STAGES,
    },
  },
};

// ── Progress logging ──────────────────────────────────────────────────────────
// exec.scenario.iterationInTest increments atomically across all VUs in the
// scenario, so checking (iter % N === 0) guarantees exactly one VU emits the
// checkpoint — whichever VU happened to get that iteration.  No VU-ID
// filtering is needed, and the spacing is proportional to the current rate
// (more frequent at peak load, which is when saturation data matters most).
//
//   read_saturation:  ~53 k iters over 5 min → LOG_EVERY=3000 ≈ 17 checkpoints
//   write_saturation: ~10 k iters over 5 min → LOG_EVERY=500  ≈ 20 checkpoints
const READ_LOG_EVERY  = 3000;
const WRITE_LOG_EVERY = 500;

function logProgress(tag, every) {
  const iter = exec.scenario.iterationInTest;
  if (iter === 0 || iter % every !== 0) return;
  const pct = Math.round(exec.scenario.progress * 100);
  console.log(`[${tag}] ${new Date().toISOString()}  ${pct}% complete  iter=${iter}`);
}

// ── Scenario: read saturation ─────────────────────────────────────────────────

export function readScenario() {
  logProgress('read ', READ_LOG_EVERY);
  const r = http.get(`${BASE}/certificate/ca`);
  check(r, { 'ca cert 200': r => r.status === 200 }) || errors.add(1);
}

// ── Scenario: write saturation ────────────────────────────────────────────────

export function writeScenario() {
  logProgress('write', WRITE_LOG_EVERY);
  const subject = `stress-vu${__VU}-i${__ITER}.puppet.test`;

  const r = http.post(`${BASE}/generate/${subject}`);
  if (!check(r, { 'generate 200': r => r.status === 200 })) {
    errors.add(1);
    return;
  }

  // Best-effort cleanup; ignore failures (server may be saturated).
  http.del(`${BASE}/certificate_status/${subject}`);
}

// ── End-of-run summary ────────────────────────────────────────────────────────
// Produces a focused report instead of k6's default wall of metrics.
// Only the metrics that matter for saturation analysis are shown.

export function handleSummary(data) {
  const m = data.metrics;

  function fmtMs(v) {
    return v == null ? 'n/a' : `${v.toFixed(1)} ms`;
  }
  function fmtRate(v) {
    return v == null ? 'n/a' : `${(v * 100).toFixed(2)}%`;
  }
  function fmtInt(v) {
    return v == null ? '0' : String(Math.round(v));
  }

  function scenarioBlock(label, tag) {
    const dur   = m[`http_req_duration{scenario:${tag}}`]   || {};
    const fail  = m[`http_req_failed{scenario:${tag}}`]     || {};
    const reqs  = m[`http_reqs{scenario:${tag}}`]           || {};
    const drop  = m[`dropped_iterations{scenario:${tag}}`]  || {};
    const vals  = dur.values  || {};
    const fvals = fail.values || {};
    const rvals = reqs.values || {};
    const dvals = drop.values || {};

    return [
      `  ${label}`,
      `    requests:           ${fmtInt(rvals.count)}  (${fmtRate(fvals.rate)} failed)`,
      `    dropped_iterations: ${fmtInt(dvals.count)}`,
      `    latency avg:        ${fmtMs(vals.avg)}`,
      `    latency p(90):      ${fmtMs(vals['p(90)'])}`,
      `    latency p(95):      ${fmtMs(vals['p(95)'])}`,
      `    latency p(99):      ${fmtMs(vals['p(99)'])}`,
      `    latency max:        ${fmtMs(vals.max)}`,
    ].join('\n');
  }

  const durationMs = data.state.testRunDurationMs;
  const minutes    = Math.floor(durationMs / 60000);
  const seconds    = Math.round((durationMs % 60000) / 1000);

  const report = [
    '',
    '╔══════════════════════════════════════════════════════════╗',
    '║            puppet-ca stress test results                 ║',
    '╚══════════════════════════════════════════════════════════╝',
    `  duration: ${minutes}m ${seconds}s`,
    '',
    scenarioBlock('READ  (GET /certificate/ca,  target 10→500 req/s)', 'read_saturation'),
    '',
    scenarioBlock('WRITE (POST /generate,        target  1→ 50 req/s)', 'write_saturation'),
    '',
    '  Saturation signal: non-zero dropped_iterations or latency spike',
    '  between adjacent stages indicates the server\'s throughput ceiling.',
    '',
  ].join('\n');

  return { stdout: report };
}
