// Console home API (src/home-service.mjs, docs/feature-guide.md): running agents derived from records in a receivedAt window
// (registered, unregistered, stopped, suspended, retired), the needs-attention summary with role-aware counts, evidence present
// per framework from the period's ledger range, model status, tenant isolation, read-only behaviour and bounded cost.
import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes, randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {join} from 'node:path';
import {initialize} from '../scripts/init.mjs';
import {createService} from '../src/service.mjs';
import {mac} from '../src/crypto.mjs';
import {evaluateJob} from '../src/worker.mjs';
import {ACCESS_BATCH_TYPE} from '../src/access-log.mjs';
import {presence} from '../src/home-service.mjs';
import {NOT_CARRIED, inventory, measure} from '../src/evidence-inventory.mjs';
import {FRAMEWORKS, frameworkMapping} from '../src/evidence-pack-frameworks.mjs';
import {tempDir} from './temp-dir.mjs';

const secret = () => randomBytes(32).toString('base64url');
function open() {
  const dir = tempDir('evidscope-home-'), config = initialize(dir);
  config.principals.push({id: 'alpha-enforcement', tenant: 'alpha', role: 'source', kind: 'enforcement', token: secret(), hmacSecret: secret()},
    {id: 'alpha-agent-2', tenant: 'alpha', role: 'source', kind: 'agent', token: secret(), hmacSecret: secret()},
    {id: 'alpha-reviewer-2', tenant: 'alpha', role: 'reviewer', token: secret()});
  const s = createService({dataDir: join(dir, 'data'), config, key: readFileSync(join(dir, 'signing-private.pem'), 'utf8')});
  const principal = id => config.principals.find(p => p.id === id);
  const as = id => ({authorization: 'Bearer ' + principal(id).token});
  const get = (path, id = 'alpha-auditor') => s.handle('GET', new URL('http://localhost' + path), as(id));
  const post = (path, body, id = 'alpha-reviewer') => s.handle('POST', new URL('http://localhost' + path), as(id), JSON.stringify(body));
  const signed = (path, id, body) => {
    const text = JSON.stringify(body), ts = String(Date.now()), nonce = randomUUID(), p = principal(id);
    return s.handle('POST', new URL('http://localhost' + path), {...as(id), 'x-evid-timestamp': ts, 'x-evid-nonce': nonce,
      'x-evid-signature': mac(p.hmacSecret, ts, nonce, text)}, text);
  };
  const send = (id, event) => signed('/api/ingest', id, {occurredAt: new Date().toISOString(), traceId: event.actionId, ...event});
  // A retained event received at `receivedAt` (an earlier hour), appended and projected like an ingested one.
  const backdated = (sourceId, event, receivedAt) => s.store.transaction(() => {
    const p = principal(sourceId), e = {tenant: p.tenant, source: p.id, sourceKind: p.kind, assurance: 'authenticated_service_record', occurredAt: receivedAt,
      receivedAt, fingerprint: randomUUID().replaceAll('-', ''), traceId: event.actionId, late: false, ...event};
    const record = s.store.append(p.tenant, 'event', e, p.id);s.store.project({...e, seq: record.seq, hash: record.hash});
  });
  async function analyze() {
    for (let i = 0; i < 20; i++) {
      const claim = await s.handle('POST', new URL('http://localhost/internal/claim'), as('analysis-worker'), '{}');
      if (!claim.jobs.length) return;
      for (const job of claim.jobs) await s.handle('POST', new URL('http://localhost/internal/complete'), as('analysis-worker'),
        JSON.stringify({leaseId: job.leaseId, result: evaluateJob(job)}));
    }
  }
  const putVersion = (id, changes) => s.store.transaction(() => {
    const entry = [...s.store.list('alpha', 'agent_registry')].find(v => v.id === id);
    return s.store.put({id: 'alpha-admin', tenant: 'alpha'}, 'agent_registry', id, {...entry, ...changes, version: entry.version + 1,
      effectiveFrom: new Date().toISOString(), change: 'fixture'});
  });
  return {s, config, principal, get, post, signed, send, backdated, analyze, putVersion, close: () => s.store.close()};
}
const ledgerTypes = s => s.store.db.prepare("SELECT body FROM ledger WHERE tenant='alpha' ORDER BY seq").all().map(r => JSON.parse(r.body).type);

test('running agents: registered, unregistered, stopped, suspended and retired activity in a receivedAt window', async t => {
  const f = open();t.after(f.close);
  const entry = (id, extra) => f.post('/api/registry', {id, name: id, owner: 'ops', purpose: 'test', ...extra});
  await entry('mail-agent', {sources: ['alpha-agent'], actors: ['mail-agent']});f.putVersion('mail-agent', {state: 'production'});
  await entry('paused-agent', {actors: ['paused-bot']});f.putVersion('paused-agent', {state: 'production'});
  await entry('old-agent', {actors: ['old-bot']});f.putVersion('old-agent', {state: 'retired'});
  await entry('quiet-agent', {actors: ['quiet-bot']});f.putVersion('quiet-agent', {state: 'production'});
  const stop = await f.post('/api/registry/paused-agent/stop', {reason: 'incident drill'});
  assert.equal(stop.entry.state, 'suspended');
  await f.send('alpha-agent', {id: 'm-1', actionId: 'act-m', kind: 'intent', actor: 'mail-agent', tool: 'mailer', model: 'local-model'});
  await f.send('alpha-tool', {id: 'm-2', actionId: 'act-m', kind: 'execution', actor: 'mail-agent', tool: 'mailer', status: 'success'});
  await f.send('alpha-agent-2', {id: 'r-1', actionId: 'act-r', kind: 'intent', actor: 'rogue', tool: 'shell'});
  await f.send('alpha-tool', {id: 'r-2', actionId: 'act-r', kind: 'execution', actor: 'rogue', tool: 'shell', status: 'success'});
  await f.send('alpha-tool', {id: 's-1', actionId: 'act-s', kind: 'execution', actor: 'shadow-bot', tool: 'db'});
  await f.send('alpha-tool', {id: 'p-1', actionId: 'act-p', kind: 'execution', actor: 'paused-bot', tool: 'payments'});
  await f.send('alpha-tool', {id: 'o-1', actionId: 'act-o', kind: 'execution', actor: 'old-bot', tool: 'db'});
  await f.send('alpha-telemetry', {id: 't-1', actionId: 'act-t', kind: 'heartbeat'});
  await f.send('alpha-enforcement', {id: 'd-1', actionId: 'act-m', kind: 'policy_decision', decision: 'deny', engine: 'opa', actor: 'mail-agent',
    tool: 'mailer', decisionId: 'dec-1', enforcementPointId: 'gw-1'});
  await f.analyze();
  // An event received two hours ago (in beta: written beside the analysis projection, which this read does not need).
  f.backdated('beta-tool', {id: 'stale-1', actionId: 'stale-1', kind: 'execution', actor: 'stale-bot', tool: 'mailer'},
    new Date(Date.now() - 2 * 3600000).toISOString());

  const now = await f.get('/api/home/agents?window=15m');
  assert.equal(now.window.basis, 'receivedAt');assert.match(now.definition, /heartbeat/);
  const by = Object.fromEntries(now.items.map(i => [i.registryId || i.actor, i]));
  assert.deepEqual(Object.keys(by).sort(), ['mail-agent', 'old-agent', 'paused-agent', 'rogue', 'shadow-bot']);
  assert.deepEqual([by['mail-agent'].registered, by['mail-agent'].state, by['mail-agent'].counts], [true, 'production',
    {events: 3, actions: 1, decisions: 1, denies: 1}], 'agent, tool and enforcement records of a registered agent');
  assert.deepEqual(by['mail-agent'].flags, []);
  assert.deepEqual([by.rogue.registered, by.rogue.source, by.rogue.counts.events, by.rogue.flags], [false, 'alpha-agent-2', 2, ['not_registered']],
    'an unregistered agent source and the tool records naming its actor form one group');
  assert.deepEqual([by['shadow-bot'].source, by['shadow-bot'].flags], [null, ['not_registered']]);
  assert.deepEqual([by['paused-agent'].state, by['paused-agent'].stopOrders.active, by['paused-agent'].flags.sort()],
    ['suspended', 1, ['active_after_stop_order', 'active_while_suspended']]);
  assert.deepEqual(by['old-agent'].flags, ['active_after_retirement']);
  assert.ok(by['shadow-bot'].openFindings.total > 0, 'open findings of the window actions');
  assert.equal(now.summary.unattributedEvents, 1, 'telemetry without an actor is counted, not grouped');
  assert.deepEqual(now.quiet.map(q => q.registryId), ['quiet-agent']);
  assert.equal(now.scanned.events, 9);
  assert.ok(!(await f.get('/api/home/agents?window=24h')).items.some(i => i.actor === 'stale-bot'), 'tenant isolation');
  const [betaNow, betaDay] = [await f.get('/api/home/agents?window=1h', 'beta-auditor'), await f.get('/api/home/agents?window=24h', 'beta-auditor')];
  assert.deepEqual([betaNow.total, betaDay.items.map(i => i.actor)], [0, ['stale-bot']], 'activity before the window is not "now"');
  await assert.rejects(f.get('/api/home/agents?window=2d'), e => e.status === 400);
  await assert.rejects(f.get('/api/home/agents', 'alpha-agent'), e => e.status === 403, 'sources do not read the home');

  // Pending approvals are attached to the agent and counted for those who may answer.
  const opened = await f.signed('/api/approvals/requests', 'alpha-enforcement', {decisionId: 'apr-1', actionId: 'act-m', enforcementPointId: 'gw-1',
    target: {actor: 'mail-agent', tool: 'mailer'}, binding_message: 'send mail'});
  assert.ok(opened.auth_req_id);
  assert.equal((await f.get('/api/home/agents')).items.find(i => i.registryId === 'mail-agent').pendingApprovals, 1);
  const home = await f.get('/api/home', 'alpha-reviewer-2'), auditorHome = await f.get('/api/home');
  assert.equal(home.review.approvals.pending, 1);
  assert.equal(home.review.approvals.mayAnswer, 1, 'an independent reviewer may answer');
  assert.equal((await f.get('/api/home', 'alpha-reviewer')).review.approvals.mayAnswer, 0, 'the registrant of the agent may not');
  assert.deepEqual([auditorHome.review.approvals.mayAnswer, auditorHome.viewer.mayDecide], [0, false], 'auditors read, they do not answer');
  assert.equal(home.threats.stopOrders.active, 1);
  assert.equal(home.threats.stopOrders.notPropagated[0].propagation, 'no_enforcement_point');
  assert.ok(home.threats.findings.open > 0 && Object.keys(home.threats.findings.bySeverity).length);
  assert.deepEqual(home.threats.integrity.faults, []);
  assert.equal(home.agents.summary.unregistered, 2);
});

test('needs-attention home: new-since counts, review queues, evidence present per framework, read-only', async t => {
  const f = open();t.after(f.close);
  await f.send('alpha-tool', {id: 'x-1', actionId: 'act-x', kind: 'execution', actor: 'shadow-bot', tool: 'db'});
  await f.analyze();
  const later = new Date(Date.now() + 60000).toISOString();
  const home = await f.get('/api/home?since=' + encodeURIComponent(later)), all = await f.get('/api/home?since=2020-01-01T00:00:00.000Z');
  assert.equal(home.threats.findings.newSince.count, 0);assert.equal(all.threats.findings.newSince.count, all.threats.findings.open);
  const gov = await f.get('/api/home/governance');assert.equal(gov.status, 'ok');
  assert.equal(gov.period.id, '7d');assert.equal((await f.get('/api/home/governance')).reused, true, 'computed summaries are reused for a minute');
  assert.deepEqual(gov.frameworks.map(x => x.id).sort(), ['eu-ai-act-logging', 'isms-p', 'kr-ai-basic-act']);
  const eu = gov.frameworks.find(x => x.id === 'eu-ai-act-logging');
  assert.equal(eu.list.find(i => i.id === 'EU-AIA-12-1').status, 'evidence_present');
  assert.equal(eu.list.find(i => i.id === 'EU-AIA-14-4-E').status, 'no_evidence_recorded');
  assert.equal(eu.items, eu.evidencePresent + eu.noEvidence + eu.notCountedHere);
  assert.match(gov.notice, /준수 판정이 아닙니다/);assert.doesNotMatch(JSON.stringify(gov), /compliant/);
  assert.equal(home.review.cases.open, 0);
  await f.post('/api/cases', {title: 'look', actionId: 'act-x', owner: 'kim'});
  assert.equal((await f.get('/api/home')).review.cases.open, 1);
  await assert.rejects(f.get('/api/home/governance?period=1y'), e => e.status === 400);
  await assert.rejects(f.get('/api/home?since=yesterday'), e => e.status === 400);
  // GETs append no ledger rows of their own (the access log seals in its own batches, under its own type).
  const length = ledgerTypes(f.s).length;
  for (const path of ['/api/home', '/api/home/agents', '/api/home/governance?period=90d', '/api/model-status']) await f.get(path);
  assert.deepEqual(ledgerTypes(f.s).slice(length).filter(type => type !== ACCESS_BATCH_TYPE), []);
});

test('governance support reads only a hash-linked ledger range; an edited row makes the section unavailable', async t => {
  const f = open();t.after(f.close);
  await f.send('alpha-tool', {id: 'g-1', actionId: 'act-g', kind: 'execution', actor: 'a', tool: 'db'});
  const count = f.s.store.checkpoint('alpha').count, range = f.s.store.read(() => f.s.store.ledgerSince('alpha', new Date(Date.now() - 3600000).toISOString()));
  assert.deepEqual([range.first, range.rows.length, range.tooMany], [1, count, false]);
  assert.equal(range.disclosures.length, 1, 'retained events are disclosed from the verified state');
  assert.equal(f.s.store.read(() => f.s.store.ledgerSince('alpha', new Date(Date.now() + 3600000).toISOString())).rows.length, 0);
  // The home's presence test gives the package inventory's answer for every mapped evidence kind.
  const period = {from: '2020-01-01T00:00:00.000Z', to: new Date(Date.now() + 1000).toISOString()};
  const present = presence(range.rows, range.disclosures, period), data = inventory({records: range.rows, disclosures: range.disclosures}, null, {period});
  for (const id of FRAMEWORKS) for (const item of frameworkMapping(id).items) for (const e of item.evidence) {
    if (e.type === 'integrityCheck' || NOT_CARRIED[e.type]) { assert.equal(present(e), null);continue; }
    assert.equal(present(e), measure(e, data, {count: 0}).status === 'present', JSON.stringify(e));
  }
  assert.equal(f.s.store.read(() => f.s.store.ledgerSince('alpha', '2020-01-01T00:00:00.000Z', {maxRows: 1})).tooMany, true);
  const row = f.s.store.db.prepare("SELECT seq,body FROM ledger WHERE tenant='alpha' AND seq=1").get(), body = JSON.parse(row.body);
  f.s.store.db.exec('DROP TRIGGER immutable_update');
  f.s.store.db.prepare("UPDATE ledger SET body=? WHERE tenant='alpha' AND seq=1").run(JSON.stringify({...body, recordedAt: '2020-01-01T00:00:00.000Z'}));
  assert.throws(() => f.s.store.read(() => f.s.store.ledgerSince('alpha', '2020-06-01T00:00:00.000Z')), /digest mismatch|differs from signed evidence/);
  const gov = await f.get('/api/home/governance?period=90d');
  assert.deepEqual([gov.status, gov.httpStatus], ['unavailable', 500]);assert.match(gov.reason, /mismatch|differs/);
});

test('model status: base model as published, no adapter, upgrade shown as such, training records and no automatic promotion', async t => {
  const f = open();t.after(f.close);
  const status = await f.get('/api/model-status');
  assert.equal(status.reviewModel.model, 'fdtn-ai/Foundation-Sec-1.1-8B-Instruct');
  assert.match(status.reviewModel.revision, /^[a-f0-9]{40}$/);
  assert.deepEqual([status.fineTuning.attached, status.fineTuning.summary], [false, 'none_base_model_as_published']);
  assert.equal(status.runtime.enabledByDefault, false);
  assert.equal(status.roles.length, 4);
  // A tenant that never opened the review room still holds the first-shipped version 1; it is shown as an upgrade, not as the model.
  for (const role of status.roles) assert.deepEqual([role.profileVersion, role.upgradePending, role.upgradeTo, role.adapter, role.evalStatus],
    [1, true, 'fdtn-ai/Foundation-Sec-1.1-8B-Instruct', 'none', 'UNREVIEWED']);
  await f.get('/api/assistance/profiles');
  const upgraded = await f.get('/api/model-status');
  for (const role of upgraded.roles) {
    assert.deepEqual([role.profileVersion, role.upgradePending, role.model], [2, false, 'fdtn-ai/Foundation-Sec-1.1-8B-Instruct']);
  }
  assert.equal(status.training.promotionAutomatic, false);assert.equal(status.training.vaultRecords, 'none_signed_by_this_vault');
  const run = status.training.repository.runs[0];
  assert.deepEqual([run.promoted, run.attachedToRuntime, run.evaluation.passed < run.evaluation.alwaysAbstainReference], [false, false, true]);
  const home = await f.get('/api/home');
  assert.deepEqual([home.model.status, home.model.promotionAutomatic, home.model.fineTuning], ['ok', false, 'none_base_model_as_published']);
});

test('lists open on a recent window, newest first, with a cursor for older records; without window parameters they are unchanged', async t => {
  const f = open();t.after(f.close);
  const hour = 3600000, at = ago => new Date(Date.now() - ago).toISOString(), since = encodeURIComponent(at(24 * hour));
  await f.send('alpha-tool', {id: 'x-1', actionId: 'act-x', kind: 'execution', actor: 'shadow-bot', tool: 'db'});
  await f.send('alpha-tool', {id: 'x-2', actionId: 'act-y', kind: 'execution', actor: 'shadow-bot', tool: 'db'});
  await f.analyze();
  const alerts = (await f.get('/api/alerts')).items, recent = await f.get(`/api/alerts?since=${since}&limit=1`);
  assert.equal(recent.windowTotal, alerts.length);assert.equal(recent.items.length, 1);
  let seen = [...recent.items], cursor = recent.nextCursor;
  while (cursor) { const page = await f.get(`/api/alerts?since=${since}&limit=1&cursor=${cursor}`);seen.push(...page.items);cursor = page.nextCursor; }
  assert.deepEqual(seen.map(a => a.id).sort(), alerts.map(a => a.id).sort());
  assert.equal((await f.get(`/api/alerts?since=${encodeURIComponent(at(-hour))}`)).windowTotal, 0);
  const severity = alerts[0].severity, bySeverity = await f.get(`/api/alerts?severity=${severity}&state=open`);
  assert.deepEqual(bySeverity.items.map(a => a.id).sort(), alerts.filter(a => a.severity === severity && a.state === 'open').map(a => a.id).sort());
  await assert.rejects(f.get('/api/alerts?severity=urgent'), e => e.status === 400);
  await f.post('/api/cases', {title: 'one', actionId: 'act-x', owner: 'kim'});
  const c2 = await f.post('/api/cases', {title: 'two', actionId: 'act-y', owner: 'lee'});
  await f.post(`/api/cases/${c2.id}`, {status: 'closed', reason: 'done'}, 'alpha-reviewer-2');
  const cases = await f.get(`/api/cases?since=${since}&status=active`);
  assert.deepEqual([cases.items.map(c => c.title), cases.windowTotal], [['one'], 1]);
  assert.equal((await f.get('/api/cases?since=' + since)).items[0].title, 'two', 'newest change first');
  assert.equal((await f.get('/api/cases')).items.length, 2);
  await assert.rejects(f.get('/api/cases?status=gone'), e => e.status === 400);
  for (const [id, ago] of [['b-1', 30 * hour], ['b-2', 3 * hour], ['b-3', 2 * hour], ['b-4', hour / 2], ['b-5', hour / 4]])
    f.backdated('beta-tool', {id, actionId: 'act-' + id, kind: 'execution', actor: 'bot', tool: id === 'b-4' ? 'needle' : 'db'}, at(ago));
  // Analysis ran first: backdated beta events are written beside the analysis projection, which list reads do not need.
  const get = path => f.get(path, 'beta-auditor');
  const first = await get(`/api/events?since=${since}&limit=2`);
  assert.deepEqual([first.items.map(e => e.id), first.windowTotal, first.hasMore, first.window.order], [['b-5', 'b-4'], 4, true, 'desc']);
  const second = await get(`/api/events?since=${since}&limit=2&cursor=${first.nextCursor}`);
  assert.deepEqual([second.items.map(e => e.id), second.hasMore, second.nextCursor], [['b-3', 'b-2'], false, null]);
  const older = await get(`/api/events?until=${since}&limit=10`);
  assert.deepEqual(older.items.map(e => e.id), ['b-1'], 'older records stay reachable: nothing is deleted');
  assert.deepEqual((await get(`/api/events?since=${since}&q=needle`)).items.map(e => e.id), ['b-4']);
  const plain = await get('/api/events');
  assert.deepEqual([plain.items.map(e => e.id), plain.total, plain.offset], [['b-1', 'b-2', 'b-3', 'b-4', 'b-5'], 5, 0], 'previous order and paging');
  for (const query of ['cursor=x', 'since=yesterday', `since=${since}&until=${since}`, 'order=asc'])
    await assert.rejects(get('/api/events?' + query), e => e.status === 400, query);
});

test('the running-agents read is one index range on events(tenant, received) and does not grow with older history', async t => {
  const f = open();t.after(f.close);
  const plan = f.s.store.db.prepare("EXPLAIN QUERY PLAN SELECT body FROM events WHERE tenant=? AND received>=? ORDER BY received DESC LIMIT ?")
    .all('alpha', new Date().toISOString(), 10).map(r => r.detail).join(' | ');
  assert.match(plan, /USING INDEX event_received \(tenant=\? AND received>\?\)/);assert.doesNotMatch(plan, /TEMP B-TREE|SCAN events/);
  for (let i = 0; i < 300; i++) f.backdated('beta-tool', {id: 'old-' + i, actionId: 'old-' + i, kind: 'execution', actor: 'bot', tool: 'db'},
    new Date(Date.now() - 3 * 86400000 - i * 1000).toISOString());
  f.backdated('beta-tool', {id: 'new-1', actionId: 'new-1', kind: 'execution', actor: 'bot', tool: 'db'}, new Date().toISOString());
  const result = await f.get('/api/home/agents?window=1h', 'beta-auditor');
  assert.deepEqual([result.scanned.events, result.items[0].counts.events], [1, 1]);
});
