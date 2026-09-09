// Explicit remote/lab load driver. Never launches a server or selects a cluster.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { createHmac, randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';

const env = process.env;
const number = (key, fallback, max) => { const value = Number(env[key] ?? fallback); if (!Number.isInteger(value) || value < 1 || value > max) throw Error(`${key} must be 1..${max}`); return value; };
const duration = number('DURATION_SECONDS', 30, 1800);
const timeout = number('REQUEST_TIMEOUT_MS', 5000, 60000);
const config = JSON.parse(readFileSync(env.CONFIG_FILE || '', 'utf8'));
if (!Array.isArray(config.principals)) throw Error('CONFIG_FILE requires a principals array');
const auditOnly = env.AUDIT_ONLY === '1';
const base = new URL(auditOnly ? env.AUDIT_URL : env.INGEST_URL);
if (base.protocol !== 'https:' && !(env.ALLOW_LOOPBACK_HTTP === '1' && ['localhost', '127.0.0.1', '[::1]'].includes(base.hostname))) throw Error('HTTPS required; ALLOW_LOOPBACK_HTTP=1 is only for a loopback smoke test');
const runId = `load-${Date.now()}-${randomUUID().slice(0, 8)}`;
const report = { runId, mode: auditOnly ? 'audit-observer' : 'collector', target: base.origin, startedAt: new Date().toISOString(), durationSeconds: duration, claimedClusterVerification: false };
let interrupted = false;
process.once('SIGTERM', () => { interrupted = true; });
process.once('SIGINT', () => { interrupted = true; });

if (auditOnly) {
  if (config.principals.some(p => !['auditor', 'admin', 'reviewer'].includes(p.role))) throw Error('Audit observer config must contain human principals only');
  const principal = config.principals[0];
  if (!principal?.token) throw Error('Audit principal token required');
  report.samples = [];
  const deadline = Date.now() + duration * 1000;
  while (Date.now() < deadline && !interrupted) {
    try {
      const started = performance.now();
      const response = await fetch(new URL('/api/overview', base), { headers: { authorization: `Bearer ${principal.token}` }, signal: AbortSignal.timeout(timeout), redirect: 'error' });
      const text = await response.text();
      report.samples.push({ at: new Date().toISOString(), status: response.status, latencyMs: performance.now() - started, overview: response.ok ? JSON.parse(text) : undefined });
    } catch (error) { report.samples.push({ at: new Date().toISOString(), error: error.name }); }
    if (Date.now() < deadline && !interrupted) await delay(Math.min(1000, deadline - Date.now()));
  }
  report.failures = report.samples.filter(s => s.error || s.status !== 200).length;
} else {
  if (config.principals.some(p => p.role !== 'source')) throw Error('Collector config must contain source principals only; never mount vault config in a collector');
  const sources = config.principals.filter(p => ['agent', 'tool', 'authority', 'safety', 'telemetry'].includes(p.kind));
  const requiredSources = number('SOURCE_COUNT', 3, 100);
  if (sources.length < requiredSources) throw Error(`Need ${requiredSources} source principals; got ${sources.length}`);
  sources.splice(requiredSources);
  if (sources.some(p => !p.token || !p.hmacSecret)) throw Error('Each source needs token and hmacSecret');
  const eps = number('EPS', 20, 10000);
  const concurrency = number('CONCURRENCY', 20, 1000);
  const total = number('TOTAL', eps * duration, 1000000);
  const latencies = [];
  const payloadBytes = [];
  const outcomes = [];
  const started = performance.now();
  let cursor = 0;
  let maxScheduleLagMs = 0;
  Object.assign(report, { requestedEps: eps, concurrency, requestedTotal: total, sources: sources.map(p => ({ id: p.id, tenant: p.tenant, kind: p.kind })), generated: 0, attempted: 0, accepted: 0, duplicates: 0, failed: 0 });
  async function worker() {
    while (!interrupted) {
      const i = cursor++;
      if (i >= total) return;
      const due = started + i * 1000 / eps;
      await delay(Math.max(0, due - performance.now()));
      if (interrupted) return;
      maxScheduleLagMs = Math.max(maxScheduleLagMs, performance.now() - due);
      const source = sources[i % sources.length];
      const now = Date.now();
      const actionId = `${runId}-action-${Math.floor(i / sources.length)}`;
      const event = { id: `${runId}-${i}`, kind: { agent: 'intent', tool: 'execution', authority: 'grant', safety: 'safety_alert', telemetry: 'heartbeat' }[source.kind], actionId, traceId: runId, occurredAt: new Date(now).toISOString(), actor: 'synthetic-agent', tool: 'synthetic-tool', action: 'read', resource: 'synthetic-record', note: 'Synthetic load metadata. ' + 'x'.repeat(700) };
      if (source.kind === 'authority') Object.assign(event, { validFrom: new Date(now - 60000).toISOString(), validUntil: new Date(now + 3600000).toISOString(), policyVersion: 'load-v1', scope: { actor: event.actor, tool: event.tool, action: event.action, resource: event.resource } });
      const body = JSON.stringify(event);
      const timestamp = String(Date.now());
      const nonce = randomUUID();
      const signature = createHmac('sha256', source.hmacSecret).update(`${timestamp}.${nonce}.${body}`).digest('hex');
      report.generated++;
      report.attempted++;
      payloadBytes.push(Buffer.byteLength(body));
      const sentAt = performance.now();
      try {
        const response = await fetch(new URL('/api/ingest', base), { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${source.token}`, 'x-evid-timestamp': timestamp, 'x-evid-nonce': nonce, 'x-evid-signature': signature }, body, signal: AbortSignal.timeout(timeout), redirect: 'error' });
        const responseBody = await response.text();
        const latencyMs = performance.now() - sentAt;
        latencies.push(latencyMs);
        let receipt;
        try { receipt = JSON.parse(responseBody); } catch { receipt = undefined; }
        if (response.ok) { report.accepted++; if (receipt?.duplicate) report.duplicates++; } else report.failed++;
        outcomes.push({ source: source.id, tenant: source.tenant, id: event.id, status: response.status, latencyMs, accepted: response.ok, duplicate: !!receipt?.duplicate });
      } catch (error) {
        const latencyMs = performance.now() - sentAt;
        latencies.push(latencyMs);
        report.failed++;
        outcomes.push({ source: source.id, tenant: source.tenant, id: event.id, latencyMs, accepted: false, error: error.name, ambiguousReceipt: true });
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, total) }, worker));
  latencies.sort((a, b) => a - b);
  const percentile = p => latencies.length ? latencies[Math.min(latencies.length - 1, Math.ceil(latencies.length * p) - 1)] : null;
  const elapsedSeconds = (performance.now() - started) / 1000;
  Object.assign(report, { elapsedSeconds, actualAcceptedEps: report.accepted / elapsedSeconds, maxScheduleLagMs, bytes: { min: payloadBytes.length ? payloadBytes.reduce((a,b) => Math.min(a,b), Infinity) : null, max: payloadBytes.length ? payloadBytes.reduce((a,b) => Math.max(a,b), 0) : null, average: payloadBytes.length ? payloadBytes.reduce((a,b) => a+b, 0) / payloadBytes.length : null }, latencyMs: { p50: percentile(.5), p95: percentile(.95), p99: percentile(.99) }, outcomes, completenessStatus: 'unverified: independently reconcile accepted source/id pairs against audit export; timeout may have committed', retryPolicy: 'no automatic retries; preserve ambiguous outcomes for explicit replay' });
}
report.interrupted = interrupted;
report.finishedAt = new Date().toISOString();
if (env.REPORT_FILE) {
  const path = resolve(env.REPORT_FILE);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(report, null, 2) + '\n');
}
console.log(JSON.stringify(report));
if (interrupted || report.failed || report.failures) process.exitCode = 1;
