const fixtureHost=process.env.EVIDSCOPE_TEST_HOST==='::1'?'::1':'127.0.0.1';
const fixtureUrlHost=fixtureHost==='::1'?'[::1]':fixtureHost;
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { runDistribution } from '../scripts/k8s-distribution.mjs';
import { validateEvent } from '../src/model.mjs';

const source = { id: 'source-agent', tenant: 'lab', role: 'source', kind: 'agent', token: 'secret-source-token', hmacSecret: 'secret-source-signing' };
const human = { id: 'auditor', tenant: 'lab', role: 'auditor', token: 'secret-human-token' };
async function listen(t, handler) {
  const server = http.createServer(handler);
  await new Promise(resolve => server.listen(0, fixtureHost, resolve));
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
  return { server, url: `http://${fixtureUrlHost}:${server.address().port}` };
}
const options = url => ({ config: { principals: [source] }, ingestUrl: url, allowLoopbackHttp: true, total: 6, concurrency: 3, timeoutMs: 1000 });
const respond = (response, instance, status = 202, body = { accepted: true, duplicate: false }) => {
  response.writeHead(status, { 'content-type': 'application/json', ...(instance ? { 'x-evidscope-instance': instance } : {}) }); response.end(JSON.stringify(body));
};

test('local HTTP fixture observes two backend instances using fresh signed connections; not Kubernetes proof', async t => {
  const requests = [], connections = new Set();
  const sources = ['agent', 'tool', 'authority', 'safety', 'telemetry'].map(kind => ({ ...source, id: `source-${kind}`, kind, token: `${source.token}-${kind}`, hmacSecret: `${source.hmacSecret}-${kind}` }));
  const backend = name => async (req, res) => {
    let body = ''; for await (const chunk of req) body += chunk;
    const timestamp = req.headers['x-evid-timestamp'], nonce = req.headers['x-evid-nonce'];
    const principal = sources.find(p => req.headers.authorization === `Bearer ${p.token}`);
    assert.ok(principal);
    assert.equal(req.headers['x-evid-signature'], createHmac('sha256', principal.hmacSecret).update(`${timestamp}.${nonce}.${body}`).digest('hex'));
    assert.equal(req.method, 'POST'); assert.equal(req.url, '/api/ingest');
    const event = JSON.parse(body);
    assert.doesNotThrow(() => validateEvent(event, principal));
    if (principal.kind === 'authority') {
      assert.equal(event.policyVersion, 'distribution-v1');
      assert.ok(Date.parse(event.validFrom) <= Date.parse(event.occurredAt));
      assert.ok(Date.parse(event.validUntil) > Date.parse(event.occurredAt));
      assert.deepEqual(event.scope, { actor: event.actor, tool: event.tool, action: event.action, resource: event.resource });
    }
    requests.push(event); respond(res, name);
  };
  const one = await listen(t, backend('local-one')), two = await listen(t, backend('local-two'));
  let counter = 0;
  const front = await listen(t, (req, res) => {
    connections.add(req.socket.remotePort);
    const upstream = http.request(new URL(req.url, counter++ % 2 ? one.url : two.url), { method: req.method, headers: req.headers, agent: false }, response => { res.writeHead(response.statusCode, response.headers); response.pipe(res); });
    req.pipe(upstream);
  });
  const report = await runDistribution({ ...options(front.url), config: { principals: sources } });
  assert.equal(report.pass, true); assert.equal(report.distinctInstances, 2); assert.equal(report.missingInstances, 0);
  assert.equal(report.connectivity.successfulResponses, 6); assert.equal(connections.size, 6);
  assert.equal(new Set(requests.map(e => e.id)).size, 6);
  assert.equal(report.outcomes.filter(o => o.accepted).length, 6);
  assert.deepEqual([...new Set(requests.map(e => e.kind))].sort(), ['execution', 'grant', 'heartbeat', 'intent', 'safety_alert']);
  assert.equal(report.claimedClusterVerification, false);
  assert.match(report.completenessStatus, /independently reconcile/);
  const serialized = JSON.stringify(report); assert.ok(!serialized.includes(source.token)); assert.ok(!serialized.includes(source.hmacSecret));
});

test('one observed instance fails minimum two; missing header also fails', async t => {
  const one = await listen(t, (_, res) => respond(res, 'one'));
  const oneReport = await runDistribution({ ...options(one.url), total: 2 });
  assert.equal(oneReport.pass, false); assert.equal(oneReport.distinctInstances, 1); assert.equal(oneReport.connectivity.successfulResponses, 2);
  const missing = await listen(t, (_, res) => respond(res));
  const missingReport = await runDistribution({ ...options(missing.url), total: 2, expectedMinInstances: 1 });
  assert.equal(missingReport.pass, false); assert.equal(missingReport.missingInstances, 2);
});

test('audit uses human credentials and investigation GET only', async t => {
  const service = await listen(t, (req, res) => {
    assert.equal(req.url, '/api/investigations?limit=1'); assert.equal(req.method, 'GET');
    assert.equal(req.headers.authorization, `Bearer ${human.token}`); assert.equal(req.headers['x-evid-signature'], undefined);
    respond(res, 'audit-one', 200, { items: [{ referenceManifest: Array.from({ length: 1000 }, (_, i) => ({ id: `source/event-${i}`, hash: 'f'.repeat(64) })) }] });
  });
  const report = await runDistribution({ config: { principals: [human] }, auditOnly: true, auditUrl: service.url, allowLoopbackHttp: true, total: 2, expectedMinInstances: 1 });
  assert.equal(report.pass, true); assert.equal(report.outcomes[0].accepted, undefined);
  assert.equal(report.responseLimitBytes, 1024 * 1024);
  assert.ok(!JSON.stringify(report).includes(human.token));
});

test('credential separation and unsafe origins refuse before network I/O', async t => {
  let contacted = 0;
  const service = await listen(t, (_, res) => { contacted++; respond(res, 'unexpected'); });
  for (const principals of [[source, human], [human]]) await assert.rejects(runDistribution({ ...options(service.url), config: { principals } }), /source principals only/);
  await assert.rejects(runDistribution({ config: { principals: [source] }, auditOnly: true, auditUrl: service.url, allowLoopbackHttp: true }), /human principals only/);
  await assert.rejects(runDistribution({ config: { principals: [{ ...human, hmacSecret: 'wrong-boundary' }] }, auditOnly: true, auditUrl: service.url, allowLoopbackHttp: true }), /source signing/);
  await assert.rejects(runDistribution({ ...options(service.url), allowLoopbackHttp: false }), /HTTPS/);
  for (const ingestUrl of ['http://127.0.0.2', 'http://localhost.example', 'ftp://127.0.0.1', `${service.url}/not-origin`, `${service.url}/?secret=forbidden`, 'https://user:password@example.invalid']) await assert.rejects(runDistribution({ ...options(service.url), ingestUrl }));
  await assert.rejects(runDistribution({ ...options(service.url), total: 1001 }), /TOTAL/);
  await assert.rejects(runDistribution({ ...options(service.url), concurrency: 51 }), /CONCURRENCY/);
  assert.equal(contacted, 0);
});

test('timeout is ambiguous without retry; redirect and failed receipt stay failures', async t => {
  let requests = 0;
  const timeout = await listen(t, () => { requests++; });
  const report = await runDistribution({ ...options(timeout.url), total: 1, timeoutMs: 40, expectedMinInstances: 1 });
  assert.equal(requests, 1); assert.equal(report.pass, false); assert.equal(report.outcomes[0].error, 'request_timeout'); assert.equal(report.outcomes[0].ambiguousReceipt, true);
  const redirect = await listen(t, (_, res) => { res.writeHead(302, { location: 'http://127.0.0.1:1', 'x-evidscope-instance': 'redirect' }); res.end('{}'); });
  const redirected = await runDistribution({ ...options(redirect.url), total: 1, expectedMinInstances: 1 });
  assert.equal(redirected.pass, false); assert.equal(redirected.outcomes[0].status, 302);
  const deniedReceipt = await listen(t, (_, res) => respond(res, 'reject', 202, { accepted: false }));
  const denied = await runDistribution({ ...options(deniedReceipt.url), total: 1, expectedMinInstances: 1 });
  assert.equal(denied.pass, false); assert.equal(denied.outcomes[0].error, 'invalid_receipt');
});

test('opt-in readiness retains failed preflight then measures only after recovery', async t => {
  let readiness = 0, measured = 0;
  const readinessStarts = [];
  const service = await listen(t, (req, res) => {
    if (req.url === '/readyz') {
      readinessStarts.push(Date.now()); readiness++;
      assert.equal(req.method, 'GET'); assert.equal(req.headers.authorization, undefined); assert.equal(req.headers['x-evid-signature'], undefined);
      if (readiness === 1) { req.socket.destroy(); return; }
      // Readiness does not depend on the health response being JSON or carrying an instance header.
      res.writeHead(200); res.end('ready'); return;
    }
    measured++; respond(res, 'local-ready');
  });
  const report = await runDistribution({ ...options(service.url), total: 2, expectedMinInstances: 1, preflightTimeoutMs: 3000 });
  assert.equal(report.pass, true); assert.equal(report.preflight.ready, true); assert.equal(report.preflight.attempts.length, 2);
  assert.equal(report.preflight.attempts[0].error, 'ECONNRESET'); assert.equal(report.preflight.attempts[0].status, null);
  assert.equal(report.preflight.attempts[1].status, 200); assert.ok(readinessStarts[1] - readinessStarts[0] >= 990);
  assert.ok(Date.parse(report.measurementStartedAt) >= Date.parse(report.preflight.finishedAt));
  assert.equal(measured, 2); assert.equal(report.outcomes.length, 2); assert.equal(report.connectivity.successfulResponses, 2); assert.equal(report.missingInstances, 0);
});

test('permanent preflight failure skips every measurement and preserves readiness failure', async t => {
  let readiness = 0, measured = 0;
  const service = await listen(t, (req, res) => {
    if (req.url === '/readyz') { readiness++; res.writeHead(503); res.end('not ready'); }
    else { measured++; respond(res, 'must-not-measure'); }
  });
  const report = await runDistribution({ ...options(service.url), preflightTimeoutMs: 120 });
  assert.equal(report.pass, false); assert.equal(report.preflight.ready, false); assert.equal(report.preflight.attempts.length, 1);
  assert.equal(report.preflight.attempts[0].status, 503); assert.equal(report.preflight.attempts[0].error, 'unexpected_status');
  assert.equal(report.preflight.failure, 'readiness_not_confirmed_before_limit'); assert.equal(report.measurementStartedAt, null);
  assert.equal(readiness, 1); assert.equal(measured, 0); assert.equal(report.outcomes.length, 0); assert.equal(report.instances.length, 0);
  assert.deepEqual(report.connectivity, { attempted: 0, notAttempted: 6, httpResponses: 0, successfulResponses: 0, failed: 0 });
  await assert.rejects(runDistribution({ ...options(service.url), preflightTimeoutMs: 30001 }), /PREFLIGHT_TIMEOUT_MS/);
});

test('both distribution Jobs opt into the same bounded readiness phase', () => {
  const manifest = JSON.parse(readFileSync(new URL('../deploy/distribution-jobs.json', import.meta.url), 'utf8'));
  const jobs = manifest.items.filter(i => i.kind === 'Job'); assert.equal(jobs.length, 2);
  for (const job of jobs) assert.equal(job.spec.template.spec.containers[0].env.find(e => e.name === 'PREFLIGHT_TIMEOUT_MS').value, '30000');
});
