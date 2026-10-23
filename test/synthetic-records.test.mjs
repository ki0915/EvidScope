// Synthetic (demo/test) records: an actor a reviewer registers as synthetic (asset synthetic:true, scripts/demo.mjs) keeps its alerts
// apart from real ones in the alerts list (data=real|synthetic) and the overview count; the evaluations and the ledger are unchanged,
// and an action with any real actor's event stays real. Also the windowed retention inventory of the console.
import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes, randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {join} from 'node:path';
import {initialize} from '../scripts/init.mjs';
import {createService} from '../src/service.mjs';
import {mac} from '../src/crypto.mjs';
import {evaluateJob} from '../src/worker.mjs';
import {tempDir} from './temp-dir.mjs';

function open() {
  const dir = tempDir('evidscope-synthetic-'), config = initialize(dir);
  const s = createService({dataDir: join(dir, 'data'), config, key: readFileSync(join(dir, 'signing-private.pem'), 'utf8')});
  const principal = id => config.principals.find(p => p.id === id), as = id => ({authorization: 'Bearer ' + principal(id).token});
  const get = (path, id = 'alpha-auditor') => s.handle('GET', new URL('http://localhost' + path), as(id));
  const post = (path, body, id = 'alpha-reviewer') => s.handle('POST', new URL('http://localhost' + path), as(id), JSON.stringify(body));
  const send = (id, event) => {
    const text = JSON.stringify({occurredAt: new Date().toISOString(), traceId: event.actionId, ...event}), ts = String(Date.now()), nonce = randomUUID();
    return s.handle('POST', new URL('http://localhost/api/ingest'), {...as(id), 'x-evid-timestamp': ts, 'x-evid-nonce': nonce,
      'x-evid-signature': mac(principal(id).hmacSecret, ts, nonce, text)}, text);
  };
  async function analyze() {
    for (let i = 0; i < 20; i++) {
      const claim = await s.handle('POST', new URL('http://localhost/internal/claim'), as('analysis-worker'), '{}');
      if (!claim.jobs.length) return;
      for (const job of claim.jobs) await s.handle('POST', new URL('http://localhost/internal/complete'), as('analysis-worker'),
        JSON.stringify({leaseId: job.leaseId, result: evaluateJob(job)}));
    }
  }
  return {s, get, post, send, analyze, close: () => s.store.close()};
}

test('alerts of synthetic actors are listed apart; real and mixed actions stay real; the ledger is unchanged', async t => {
  const f = open(); t.after(f.close);
  const asset = (actor, synthetic) => f.post('/api/assets', {id: actor, actor, tool: 'crm', owner: 'ops', purpose: 'test', policyVersion: 'p1',
    destinations: ['internal.example'], ...(synthetic === undefined ? {} : {synthetic})});
  assert.equal((await asset('demo-bot', true)).synthetic, true);
  assert.equal('synthetic' in await asset('real-bot', 'yes'), false, 'only true marks an asset');
  // Each action sends to an unlisted destination, so each raises the same alert.
  const write = (id, actionId, actor) => f.send('alpha-tool', {id, actionId, kind: 'execution', actor, tool: 'crm', action: 'write',
    destination: 'external.example', status: 'success', policyVersion: 'p1'});
  await write('d-1', 'demo-action', 'demo-bot');
  await write('r-1', 'real-action', 'real-bot');
  await write('m-1', 'mixed-action', 'demo-bot'); await write('m-2', 'mixed-action', 'real-bot');
  await f.analyze();
  const actions = async data => [...new Set((await f.get(`/api/alerts${data ? '?data=' + data : ''}`)).items.map(a => a.actionId))].sort();
  assert.deepEqual(await actions(), ['demo-action', 'mixed-action', 'real-action']);
  assert.deepEqual(await actions('real'), ['mixed-action', 'real-action']);
  assert.deepEqual(await actions('synthetic'), ['demo-action']);
  const all = (await f.get('/api/alerts')).items;
  assert.ok(all.every(a => a.synthetic === (a.actionId === 'demo-action')));
  const overview = await f.get('/api/overview');
  assert.equal(overview.counts.syntheticAlerts, all.filter(a => a.synthetic).length);
  assert.ok(overview.counts.syntheticAlerts > 0 && overview.counts.alerts === all.length);
  await assert.rejects(f.get('/api/alerts?data=demo'), {status: 400});
  // Unmarking the asset makes the action real again; its evaluation is the same signed record either way.
  const before = f.s.store.db.prepare("SELECT COUNT(*) n FROM ledger WHERE tenant='alpha' AND json_extract(body,'$.type')='evaluation'").get().n;
  await asset('demo-bot');
  assert.deepEqual(await actions('synthetic'), []);
  assert.equal(f.s.store.db.prepare("SELECT COUNT(*) n FROM ledger WHERE tenant='alpha' AND json_extract(body,'$.type')='evaluation'").get().n, before);
});

test('the retention inventory view returns counts of every retained event and a bounded list', async t => {
  const f = open(); t.after(f.close);
  for (let i = 0; i < 5; i++) await f.send('alpha-tool', {id: `e-${i}`, actionId: `a-${i}`, kind: 'execution', actor: 'bot', tool: 'crm'});
  const full = await f.get('/api/retention', 'alpha-reviewer'), two = await f.get('/api/retention?limit=2', 'alpha-reviewer');
  assert.equal(full.counts.items, full.items.length);
  assert.equal(full.itemsTruncated, false);
  assert.equal(two.counts.items, full.counts.items);
  assert.equal(two.items.length, Math.min(2, full.counts.items));
  assert.equal(two.itemsTruncated, full.counts.items > 2);
  assert.deepEqual(two.items, full.items.slice(0, two.items.length), 'the same review order');
  for (const bad of ['0', '5001', 'x']) await assert.rejects(f.get(`/api/retention?limit=${bad}`, 'alpha-reviewer'), {status: 400});
});
