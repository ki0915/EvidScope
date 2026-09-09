// Observes response instances over fresh connections. Does not select or mutate a cluster.
import http from 'node:http';
import https from 'node:https';
import { createHmac, randomUUID } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { pathToFileURL } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

const responseLimitBytes = 1024 * 1024;

function bounded(value, fallback, max, name) {
  const n = Number(value ?? fallback);
  if (!Number.isInteger(n) || n < 1 || n > max) throw Error(`${name} must be 1..${max}`);
  return n;
}
function targetOrigin(value, allowLoopbackHttp) {
  let url;
  try { url = new URL(value); } catch { throw Error('Target must be an explicit HTTPS origin'); }
  if (url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw Error('Target must be an origin without credentials, path, query or fragment');
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && allowLoopbackHttp === true && loopback)) throw Error('HTTPS required; explicit loopback HTTP is for local testing only');
  return url;
}
function requestOnce(url, { method, headers, body, timeoutMs, requireJson = true }) {
  return new Promise(resolveResult => {
    const started = performance.now();
    let done = false, timer;
    const finish = result => {
      if (done) return;
      done = true; clearTimeout(timer);
      resolveResult({ ...result, latencyMs: performance.now() - started });
    };
    const request = (url.protocol === 'https:' ? https : http).request(url, {
      method, headers, agent: false, rejectUnauthorized: true,
    }, response => {
      const rawInstance = response.headers['x-evidscope-instance'];
      const instance = typeof rawInstance === 'string' && /^[A-Za-z0-9._-]{1,253}$/.test(rawInstance) ? rawInstance : null;
      let bytes = 0; const chunks = [];
      response.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > responseLimitBytes) { finish({ status: response.statusCode, instance, error: 'response_too_large' }); request.destroy(); }
        else chunks.push(chunk);
      });
      response.on('end', () => {
        if (!requireJson) return finish({ status: response.statusCode, instance });
        let receipt;
        try { receipt = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
        catch { return finish({ status: response.statusCode, instance, error: 'invalid_json' }); }
        finish({ status: response.statusCode, instance, receiptAccepted: receipt?.accepted === true, duplicate: receipt?.duplicate === true });
      });
      response.on('error', () => finish({ status: response.statusCode, instance, error: 'response_interrupted' }));
    });
    // Total deadline also bounds DNS, connect and TLS handshake, not only idle sockets.
    timer = setTimeout(() => { finish({ error: 'request_timeout' }); request.destroy(); }, timeoutMs);
    request.on('error', error => finish({ error: ['ECONNREFUSED', 'ECONNRESET', 'ENOTFOUND', 'EAI_AGAIN', 'CERT_HAS_EXPIRED', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'ERR_TLS_CERT_ALTNAME_INVALID'].includes(error.code) ? error.code : 'request_failed' }));
    request.end(body);
  });
}

export async function runDistribution(options = {}) {
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') throw Error('TLS verification must not be disabled');
  const { config, auditOnly = false, allowLoopbackHttp = false } = options;
  if (typeof auditOnly !== 'boolean' || typeof allowLoopbackHttp !== 'boolean') throw Error('Mode flags must be boolean');
  const total = bounded(options.total, 60, 1000, 'TOTAL');
  const concurrency = bounded(options.concurrency, 6, 50, 'CONCURRENCY');
  const expectedMinInstances = bounded(options.expectedMinInstances, 2, 1000, 'EXPECTED_MIN_INSTANCES');
  const timeoutMs = bounded(options.timeoutMs, 5000, 60000, 'REQUEST_TIMEOUT_MS');
  const preflightTimeoutMs = Number(options.preflightTimeoutMs ?? 0);
  if (!Number.isInteger(preflightTimeoutMs) || preflightTimeoutMs < 0 || preflightTimeoutMs > 30000) throw Error('PREFLIGHT_TIMEOUT_MS must be 0..30000');
  const target = targetOrigin(auditOnly ? options.auditUrl : options.ingestUrl, allowLoopbackHttp);
  if (!Array.isArray(config?.principals) || !config.principals.length) throw Error('CONFIG_FILE requires nonempty principals');
  const principals = config.principals;
  const humanRoles = ['auditor', 'reviewer', 'admin'];
  if (auditOnly && principals.some(p => !p || !humanRoles.includes(p.role))) throw Error('Audit config must contain human principals only');
  if (!auditOnly && principals.some(p => !p || p.role !== 'source')) throw Error('Collector config must contain source principals only');
  const safeId = value => typeof value === 'string' && /^[A-Za-z0-9._:@/-]{1,120}$/.test(value);
  if (principals.some(p => !safeId(p.id) || !safeId(p.tenant) || typeof p.token !== 'string' || !p.token || /[^\x21-\x7e]/.test(p.token))) throw Error('Each principal requires a valid id, tenant and token');
  if (auditOnly && principals.some(p => p.hmacSecret !== undefined)) throw Error('Audit config must not carry source signing credentials');
  if (!auditOnly && principals.some(p => !['agent', 'tool', 'authority', 'safety', 'telemetry'].includes(p.kind) || typeof p.hmacSecret !== 'string' || !p.hmacSecret)) throw Error('Collector needs supported source kinds with signing credentials');

  const runId = `distribution-${Date.now()}-${randomUUID().slice(0, 8)}`;
  const report = { runId, mode: auditOnly ? 'audit-observer' : 'collector', target: target.origin,
    startedAt: new Date().toISOString(), requestedTotal: total, concurrency, expectedMinInstances,
    minSuccessResponses: total, responseLimitBytes, claimedClusterVerification: false, connectionPolicy: 'new connection per request; agent:false; no redirects; TLS verified (NODE_EXTRA_CA_CERTS supported by Node at startup)',
    retryPolicy: 'no measurement retries; optional bounded readiness preflight is reported separately', outcomes: [], measurementStartedAt: null,
    preflight: { enabled: preflightTimeoutMs > 0, timeoutMs: preflightTimeoutMs, intervalMs: 1000, maxAttempts: 30, requestTimeoutLimitMs: 1500, ready: null, attempts: [] } };
  if (preflightTimeoutMs > 0) {
    const deadline = performance.now() + preflightTimeoutMs;
    report.preflight.startedAt = new Date().toISOString();
    report.preflight.ready = false;
    while (report.preflight.attempts.length < 30 && performance.now() < deadline) {
      const at = new Date().toISOString();
      const remaining = Math.max(1, Math.floor(deadline - performance.now()));
      const result = await requestOnce(new URL('/readyz', target), { method: 'GET', headers: { connection: 'close' }, timeoutMs: Math.min(1500, timeoutMs, remaining), requireJson: false });
      const ready = result.status === 200 && !result.error;
      report.preflight.attempts.push({ at, finishedAt: new Date().toISOString(), status: result.status ?? null, instance: result.instance ?? null, latencyMs: result.latencyMs, ready,
        ...(!ready ? { error: result.error || 'unexpected_status' } : {}) });
      if (ready) { report.preflight.ready = true; break; }
      if (report.preflight.attempts.length < 30 && performance.now() < deadline) await delay(Math.min(1000, deadline - performance.now()));
    }
    report.preflight.finishedAt = new Date().toISOString();
    if (!report.preflight.ready) report.preflight.failure = 'readiness_not_confirmed_before_limit';
  }
  let cursor = 0;
  async function worker() {
    while (cursor < total) {
      const index = cursor++, principal = principals[index % principals.length];
      const headers = { authorization: `Bearer ${principal.token}`, connection: 'close' };
      let body, id;
      if (!auditOnly) {
        id = `${runId}-${index}`;
        const now = Date.now();
        const event = { id, actionId: `${runId}-action-${index}`, traceId: runId,
          kind: { agent: 'intent', tool: 'execution', authority: 'grant', safety: 'safety_alert', telemetry: 'heartbeat' }[principal.kind],
          occurredAt: new Date(now).toISOString(), actor: 'synthetic-agent', tool: 'synthetic-tool', action: 'read', resource: 'synthetic-record', note: 'Synthetic distribution probe metadata' };
        if (principal.kind === 'authority') Object.assign(event, { validFrom: new Date(now - 60000).toISOString(), validUntil: new Date(now + 3600000).toISOString(), policyVersion: 'distribution-v1', scope: { actor: event.actor, tool: event.tool, action: event.action, resource: event.resource } });
        body = JSON.stringify(event);
        const timestamp = String(Date.now()), nonce = randomUUID();
        Object.assign(headers, { 'content-type': 'application/json', 'x-evid-timestamp': timestamp, 'x-evid-nonce': nonce,
          'x-evid-signature': createHmac('sha256', principal.hmacSecret).update(`${timestamp}.${nonce}.${body}`).digest('hex') });
      }
      const result = await requestOnce(new URL(auditOnly ? '/api/investigations?limit=1' : '/api/ingest', target), { method: auditOnly ? 'GET' : 'POST', headers, body, timeoutMs });
      const success = !result.error && result.status === (auditOnly ? 200 : 202) && (auditOnly || result.receiptAccepted);
      const outcome = { index, ...(auditOnly ? {} : { source: principal.id, tenant: principal.tenant, id }),
        status: result.status ?? null, instance: result.instance ?? null, latencyMs: result.latencyMs, success,
        ...(auditOnly ? {} : { accepted: success, duplicate: result.duplicate ?? false, ambiguousReceipt: !!result.error }),
        ...(!success ? { error: result.error || (result.status === 202 ? 'invalid_receipt' : 'unexpected_status') } : {}) };
      report.outcomes.push(outcome);
    }
  }
  if (!report.preflight.enabled || report.preflight.ready) {
    report.measurementStartedAt = new Date().toISOString();
    await Promise.all(Array.from({ length: Math.min(total, concurrency) }, worker));
  }
  report.outcomes.sort((a, b) => a.index - b.index);
  const instances = new Map();
  for (const outcome of report.outcomes) {
    if (!outcome.instance) continue;
    if (!instances.has(outcome.instance)) instances.set(outcome.instance, { instance: outcome.instance, count: 0, successful: 0, statuses: {}, latencySamplesMs: [] });
    const instance = instances.get(outcome.instance);
    instance.count++; instance.successful += Number(outcome.success);
    const status = String(outcome.status ?? 'transport_error'); instance.statuses[status] = (instance.statuses[status] || 0) + 1;
    instance.latencySamplesMs.push(outcome.latencyMs);
  }
  const successfulResponses = report.outcomes.filter(o => o.success).length;
  const missingInstances = report.outcomes.filter(o => !o.instance).length;
  Object.assign(report, { finishedAt: new Date().toISOString(), instances: [...instances.values()],
    connectivity: { attempted: report.outcomes.length, notAttempted: total - report.outcomes.length, httpResponses: report.outcomes.filter(o => o.status !== null).length, successfulResponses, failed: report.outcomes.length - successfulResponses },
    distinctInstances: instances.size, missingInstances,
    errors: report.outcomes.filter(o => o.error).map(o => ({ index: o.index, status: o.status, error: o.error })),
    pass: successfulResponses === total && instances.size >= expectedMinInstances && missingInstances === 0,
    completenessStatus: auditOnly ? 'Read request distribution only; does not prove ledger completeness or analysis throughput' : 'Unverified: independently reconcile accepted source/id pairs against audit ledger/export and analysis counts; timeout or interrupted receipt may have committed',
    limitations: ['Instance header is a server claim. Correlate it with actual Kubernetes Pod identities, Service endpoints and environment evidence.', 'Local HTTP tests are not Kubernetes isolation, HPA or multi-replica verification.', 'Distribution observation does not prove equal balancing, capacity, durable storage or absence of missing events.'] });
  return report;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const env = process.env;
    let config;
    try { config = JSON.parse(readFileSync(env.CONFIG_FILE || '', 'utf8')); } catch { throw Error('CONFIG_FILE must identify a readable JSON configuration'); }
    const report = await runDistribution({ config, auditOnly: env.AUDIT_ONLY === '1', allowLoopbackHttp: env.ALLOW_LOOPBACK_HTTP === '1',
      ingestUrl: env.INGEST_URL, auditUrl: env.AUDIT_URL, total: env.TOTAL, concurrency: env.CONCURRENCY,
      expectedMinInstances: env.EXPECTED_MIN_INSTANCES, timeoutMs: env.REQUEST_TIMEOUT_MS, preflightTimeoutMs: env.PREFLIGHT_TIMEOUT_MS });
    if (env.REPORT_FILE) { const path = resolve(env.REPORT_FILE); mkdirSync(dirname(path), { recursive: true }); writeFileSync(path, JSON.stringify(report, null, 2) + '\n'); }
    console.log(JSON.stringify(report));
    if (!report.pass) process.exitCode = 1;
  } catch (error) { console.error(JSON.stringify({ pass: false, error: error.message })); process.exitCode = 1; }
}
