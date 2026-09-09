// Bounded synthetic audit traffic. No Kubernetes API calls, CPU burn or mutations.
import https from 'node:https';
import { readFileSync, realpathSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

const hardLimits = Object.freeze({ durationSeconds: 120, requestsPerSecond: 80, concurrency: 20, maxRequests: 10000, timeoutMs: 3000, preflightMs: 30000, responseBytes: 1024 * 1024 });
const bounded = (value, fallback, maximum, name) => {
  const n = Number(value ?? fallback);
  if (!Number.isSafeInteger(n) || n < 1 || n > maximum) throw Error(`${name} must be an integer in 1..${maximum}`);
  return n;
};
const percentile = (values, fraction) => values.length ? [...values].sort((a, b) => a - b)[Math.max(0, Math.ceil(values.length * fraction) - 1)] : null;
const safeError = error => /^[A-Z][A-Z0-9_]{1,80}$/.test(error?.code || '') ? error.code : 'request_failed';

function getOnce(url, { ca, token, timeoutMs, readiness = false }) {
  return new Promise(resolve => {
    const start = performance.now(); const startedAt = new Date().toISOString(); let done = false; let timer; let request; let status = null; let instance = null; let bytes = 0;
    const finish = result => {
      if (done) return; done = true; clearTimeout(timer);
      resolve({ startedAt, finishedAt: new Date().toISOString(), status, instance, bytes, latencyMs: performance.now() - start, ...result });
    };
    try {
      request = https.request(url, { method: 'GET', ca, rejectUnauthorized: true, agent: false, headers: { connection: 'close', ...(token ? { authorization: `Bearer ${token}` } : {}) } }, response => {
        status = response.statusCode ?? null;
        const claimed = response.headers['x-evidscope-instance'];
        instance = typeof claimed === 'string' && /^[A-Za-z0-9._-]{1,253}$/.test(claimed) ? claimed : null;
        const chunks = [];
        response.on('data', chunk => {
          bytes += chunk.length;
          if (bytes > hardLimits.responseBytes) { finish({ success: false, error: 'response_too_large' }); request.destroy(); }
          else chunks.push(chunk);
        });
        response.on('end', () => {
          let body;
          try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
          catch { finish({ success: false, error: 'invalid_json' }); return; }
          const validBody = readiness ? body?.status === 'ready' : body && typeof body === 'object' && !Array.isArray(body) && body.counts && typeof body.counts === 'object';
          const success = status === 200 && !!validBody;
          finish({ success, ...(success ? {} : { error: status !== 200 ? 'unexpected_status' : 'invalid_response_shape' }) });
        });
        response.on('aborted', () => finish({ success: false, error: 'response_aborted' }));
        response.on('error', error => finish({ success: false, error: safeError(error) }));
      });
      // One total deadline covers DNS, connect, TLS handshake and body receipt.
      timer = setTimeout(() => { finish({ success: false, error: 'request_timeout' }); request.destroy(); }, timeoutMs);
      request.on('error', error => finish({ success: false, error: safeError(error) }));
      request.end();
    } catch (error) { finish({ success: false, error: safeError(error) }); request?.destroy(); }
  });
}

export async function runHpaTraffic(options) {
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') throw Error('TLS verification must not be disabled');
  const origin = new URL(options.auditUrl);
  if (origin.protocol !== 'https:' || origin.username || origin.password || origin.pathname !== '/' || origin.search || origin.hash) throw Error('AUDIT_URL must be an HTTPS origin without credentials, path, query or fragment');
  const principals = options.config?.principals;
  if (!Array.isArray(principals) || !principals.length || principals.length > 100 || principals.some(p => !p || p.role !== 'auditor' || p.hmacSecret !== undefined || typeof p.token !== 'string' || !/^[\x21-\x7e]{32,4096}$/.test(p.token))) throw Error('Only a dedicated synthetic auditor-only config is permitted; source, reviewer, admin and signing credentials are forbidden');
  if (!Buffer.isBuffer(options.ca) || !options.ca.length) throw Error('Explicit readable vault CA is required');
  const settings = {
    durationSeconds: bounded(options.durationSeconds, 120, hardLimits.durationSeconds, 'DURATION_SECONDS'),
    requestsPerSecond: bounded(options.requestsPerSecond, 80, hardLimits.requestsPerSecond, 'REQUESTS_PER_SECOND'),
    concurrency: bounded(options.concurrency, 20, hardLimits.concurrency, 'CONCURRENCY'),
    maxRequests: bounded(options.maxRequests, 10000, hardLimits.maxRequests, 'MAX_REQUESTS'),
    timeoutMs: bounded(options.timeoutMs, 3000, hardLimits.timeoutMs, 'REQUEST_TIMEOUT_MS'),
    preflightMs: bounded(options.preflightMs, 30000, hardLimits.preflightMs, 'PREFLIGHT_TIMEOUT_MS'),
  };
  const report = {
    format: 'evidscope-hpa-audit-traffic-v1', runId: `hpa-traffic-${randomUUID()}`, startedAt: new Date().toISOString(), finishedAt: null,
    target: origin.origin, path: '/api/overview', method: 'GET', settings, hardLimits,
    connectionPolicy: 'One fresh TCP/TLS connection per request; agent:false; explicit CA and hostname verification; no redirects',
    retryPolicy: 'Readiness polling only; every preflight outcome retained. No measurement retries or catch-up bursts.',
    preflight: { path: '/readyz', startedAt: new Date().toISOString(), finishedAt: null, ready: false, attempts: [] },
    measurement: { startedAt: null, dispatchFinishedAt: null, finishedAt: null, attempted: 0, completed: 0, succeeded: 0, failed: 0, peakConcurrency: 0, statusCounts: {}, p95LatencyMs: null, p95SuccessLatencyMs: null, instanceCounts: [], missingInstanceHeaders: 0, errors: [], outcomes: [], backpressure: { concurrencyWaits: 0, concurrencyWaitMs: 0 } },
    hpaVerified: false, limitations: [
      'This traffic report does not establish HPA scaling. Correlate Pod identities, CPU metrics, HPA conditions and replica changes from the same time window.',
      'Instance response headers are server claims. They do not prove independent workload placement or equal balancing.',
      'GET overview load does not measure event ingestion, durable storage or analysis throughput, and cannot establish absence of lost events.',
      'TLS connection setup, rate pacing, concurrency and generator CPU can limit achieved traffic. No response retry hides failures.',
    ],
  };
  const preflightStart = performance.now(); const preflightDeadline = preflightStart + settings.preflightMs;
  while (performance.now() < preflightDeadline) {
    const result = await getOnce(new URL('/readyz', origin), { ca: options.ca, timeoutMs: Math.max(1, Math.min(settings.timeoutMs, Math.floor(preflightDeadline - performance.now()))), readiness: true });
    report.preflight.attempts.push({ attempt: report.preflight.attempts.length + 1, ...result });
    if (result.success) { report.preflight.ready = true; break; }
    const remaining = preflightDeadline - performance.now(); if (remaining > 0) await delay(Math.min(1000, remaining));
  }
  report.preflight.finishedAt = new Date().toISOString(); report.preflight.elapsedMs = performance.now() - preflightStart;
  if (!report.preflight.ready) { report.finishedAt = new Date().toISOString(); report.trafficCompletedWithoutErrors = false; report.terminationReason = 'preflight_not_ready'; return report; }

  const measurement = report.measurement; const intervalMs = 1000 / settings.requestsPerSecond; const start = performance.now(); const deadline = start + settings.durationSeconds * 1000;
  measurement.startedAt = new Date().toISOString(); let nextLaunch = start; const inFlight = new Set();
  while (performance.now() < deadline && measurement.attempted < settings.maxRequests) {
    if (inFlight.size >= settings.concurrency) {
      const waitStart = performance.now(); measurement.backpressure.concurrencyWaits++;
      await Promise.race(inFlight); measurement.backpressure.concurrencyWaitMs += performance.now() - waitStart; continue;
    }
    const remaining = nextLaunch - performance.now();
    if (remaining > 0) { await delay(Math.ceil(Math.min(remaining, Math.max(0, deadline - performance.now())))); continue; }
    if (performance.now() >= deadline) break;
    const index = measurement.attempted++; const principal = principals[index % principals.length];
    nextLaunch = performance.now() + intervalMs; // Never backfill missed slots into a burst.
    const pending = getOnce(new URL('/api/overview', origin), { ca: options.ca, token: principal.token, timeoutMs: settings.timeoutMs }).then(result => { measurement.outcomes.push({ index, ...result }); }).finally(() => inFlight.delete(pending));
    inFlight.add(pending); measurement.peakConcurrency = Math.max(measurement.peakConcurrency, inFlight.size);
  }
  measurement.dispatchFinishedAt = new Date().toISOString(); measurement.dispatchDurationMs = performance.now() - start;
  await Promise.all(inFlight); measurement.finishedAt = new Date().toISOString(); measurement.durationIncludingDrainMs = performance.now() - start;
  measurement.outcomes.sort((a, b) => a.index - b.index); const instances = new Map();
  for (const outcome of measurement.outcomes) {
    measurement.completed++; if (outcome.success) measurement.succeeded++; else measurement.failed++;
    const status = String(outcome.status ?? 'transport_error'); measurement.statusCounts[status] = (measurement.statusCounts[status] || 0) + 1;
    if (!outcome.instance) measurement.missingInstanceHeaders++;
    else {
      if (!instances.has(outcome.instance)) instances.set(outcome.instance, { instance: outcome.instance, responses: 0, succeeded: 0, failed: 0, statusCounts: {}, latencies: [] });
      const item = instances.get(outcome.instance); item.responses++; item.succeeded += Number(outcome.success); item.failed += Number(!outcome.success); item.statusCounts[status] = (item.statusCounts[status] || 0) + 1; item.latencies.push(outcome.latencyMs);
    }
    if (!outcome.success) measurement.errors.push({ index: outcome.index, startedAt: outcome.startedAt, status: outcome.status, instance: outcome.instance, error: outcome.error, latencyMs: outcome.latencyMs });
  }
  measurement.instanceCounts = [...instances.values()].map(({ latencies, ...item }) => ({ ...item, p95LatencyMs: percentile(latencies, 0.95) }));
  measurement.p95LatencyMs = percentile(measurement.outcomes.map(o => o.latencyMs), 0.95);
  measurement.p95SuccessLatencyMs = percentile(measurement.outcomes.filter(o => o.success).map(o => o.latencyMs), 0.95);
  measurement.achievedDispatchRequestsPerSecond = measurement.attempted / (measurement.dispatchDurationMs / 1000);
  measurement.achievedCompletedRequestsPerSecond = measurement.completed / (measurement.durationIncludingDrainMs / 1000);
  report.finishedAt = new Date().toISOString(); report.terminationReason = measurement.attempted >= settings.maxRequests ? 'request_limit_reached' : 'duration_elapsed';
  report.trafficCompletedWithoutErrors = measurement.attempted > 0 && measurement.failed === 0 && measurement.completed === measurement.attempted;
  return report;
}

// ConfigMap mounts resolve through timestamped symlinks; compare real paths.
if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  let report;
  try {
    const env = process.env; let config; let ca;
    try { config = JSON.parse(readFileSync(env.CONFIG_FILE || '', 'utf8')); } catch { throw Error('CONFIG_FILE must be a readable auditor-only JSON file'); }
    try { ca = readFileSync(env.CA_FILE || env.NODE_EXTRA_CA_CERTS || ''); } catch { throw Error('CA_FILE must be a readable vault CA certificate file'); }
    report = await runHpaTraffic({ config, ca, auditUrl: env.AUDIT_URL, durationSeconds: env.DURATION_SECONDS, requestsPerSecond: env.REQUESTS_PER_SECOND, concurrency: env.CONCURRENCY, maxRequests: env.MAX_REQUESTS, timeoutMs: env.REQUEST_TIMEOUT_MS, preflightMs: env.PREFLIGHT_TIMEOUT_MS });
    if (!report.trafficCompletedWithoutErrors) process.exitCode = 1;
  } catch (error) { report = { format: 'evidscope-hpa-audit-traffic-v1', finishedAt: new Date().toISOString(), trafficCompletedWithoutErrors: false, hpaVerified: false, terminationReason: 'configuration_or_runtime_error', error: error.message }; process.exitCode = 1; }
  process.stdout.write(JSON.stringify(report) + '\n');
}
