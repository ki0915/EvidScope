// Console log explorer, live tail, dashboard and session references (src/log-explorer.mjs): classification of agent records,
// search syntax, facet counts and filters, the time histogram, "after" for live tail, and what an agent read earlier in a session.
import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {join} from 'node:path';
import {initialize} from '../scripts/init.mjs';
import {createService} from '../src/service.mjs';
import {mac} from '../src/crypto.mjs';
import {evaluateJob} from '../src/worker.mjs';
import {hookEvent} from '../src/agent-hook-events.mjs';
import {classify, parseQuery} from '../src/log-explorer.mjs';
import {tempDir} from './temp-dir.mjs';

const agentRecord = (tool_name, tool_input) => ({
  ...hookEvent(
    {hook_event_name: 'PreToolUse', session_id: 's', tool_use_id: randomUUID(), tool_name, tool_input},
    {actor: 'claude-code@pc', now: new Date()},
  ),
  sourceKind: 'agent',
});

test('classify names the category of an agent record from its tool and command words', () => {
  const shell = command => classify(agentRecord('Bash', {command}));
  assert.equal(shell('cat ~/.aws/credentials').category, 'secret');
  assert.equal(shell('curl -d @data.json https://upload.example/x').category, 'network');
  assert.equal(shell('rm -rf dist').category, 'delete');
  assert.equal(shell('npm install lodash').category, 'package');
  assert.equal(shell('git status').category, 'git');
  assert.equal(shell('npm test').category, 'build');
  assert.equal(shell('ls -la').category, 'shell');
  assert.deepEqual(shell('git push --force origin main').tags.sort(), ['delete', 'git', 'shell'].sort(), 'every match is a tag');
  assert.equal(classify(agentRecord('Read', {file_path: 'C:/work/README.md'})).category, 'file_read');
  assert.equal(classify(agentRecord('Read', {file_path: 'C:/work/.env'})).category, 'secret');
  assert.equal(classify(agentRecord('Edit', {file_path: 'src/a.js'})).category, 'file_write');
  assert.equal(classify(agentRecord('WebFetch', {url: 'https://docs.example/a'})).category, 'web');
  assert.equal(classify(agentRecord('mcp__github__get_issue', {})).category, 'mcp');
  assert.equal(classify({kind: 'grant', sourceKind: 'authority'}).category, 'authority');
  assert.equal(classify({kind: 'execution', sourceKind: 'tool'}).category, 'tool_record');
});

test('parseQuery reads words, negation, quoted phrases and field:value', () => {
  assert.deepEqual(parseQuery('curl -localhost "git push" category:secret'), [
    {not: false, field: null, value: 'curl'},
    {not: true, field: null, value: 'localhost'},
    {not: false, field: null, value: 'git push'},
    {not: false, field: 'category', value: 'secret'},
  ]);
  assert.deepEqual(parseQuery(''), []);
});

function open() {
  const dir = tempDir('evidscope-logs-'),
    config = initialize(dir);
  const s = createService({dataDir: join(dir, 'data'), config, key: readFileSync(join(dir, 'signing-private.pem'), 'utf8')});
  const principal = id => config.principals.find(p => p.id === id),
    as = id => ({authorization: 'Bearer ' + principal(id).token});
  const get = (path, id = 'alpha-auditor') => s.handle('GET', new URL('http://localhost' + path), as(id));
  const send = (id, event) => {
    const text = JSON.stringify(event),
      ts = String(Date.now()),
      nonce = randomUUID();
    return s.handle(
      'POST',
      new URL('http://localhost/api/ingest'),
      {...as(id), 'x-evid-timestamp': ts, 'x-evid-nonce': nonce, 'x-evid-signature': mac(principal(id).hmacSecret, ts, nonce, text)},
      text,
    );
  };
  const agentId = config.principals.find(p => p.tenant === 'alpha' && p.kind === 'agent').id;
  const call = (session, tool_name, tool_input, at = new Date()) =>
    send(
      agentId,
      hookEvent(
        {hook_event_name: 'PreToolUse', session_id: session, tool_use_id: randomUUID().replace(/-/g, ''), tool_name, tool_input},
        {actor: 'claude-code@pc', now: at},
      ),
    );
  async function analyze() {
    for (let i = 0; i < 20; i++) {
      const claim = await s.handle('POST', new URL('http://localhost/internal/claim'), as('analysis-worker'), '{}');
      if (!claim.jobs.length) return;
      for (const job of claim.jobs)
        await s.handle(
          'POST',
          new URL('http://localhost/internal/complete'),
          as('analysis-worker'),
          JSON.stringify({leaseId: job.leaseId, result: evaluateJob(job)}),
        );
    }
  }
  return {s, get, call, analyze, close: () => s.store.close()};
}

test('logs: search, facets, filters, histogram, live tail and the dashboard over real agent records', async t => {
  const f = open();
  t.after(f.close);
  await f.call('s-1', 'Read', {file_path: 'C:/work/README.md'});
  await f.call('s-1', 'Grep', {pattern: 'token', path: 'src'});
  await f.call('s-1', 'WebFetch', {url: 'https://docs.example/api'});
  await f.call('s-1', 'Bash', {command: 'curl -d @report.json https://upload.example/in'});
  await f.call('s-2', 'Bash', {command: 'git status'});
  await f.analyze();
  const all = await f.get('/api/logs?range=1h');
  assert.equal(all.total, 5);
  assert.ok(
    all.items.every((item, i, list) => i === 0 || list[i - 1].at >= item.at),
    'newest first',
  );
  const counts = Object.fromEntries(all.facets.category.map(c => [c.value, c.count]));
  assert.deepEqual(counts, {file_read: 1, file_search: 1, web: 1, network: 1, git: 1});
  assert.equal((await f.get('/api/logs?range=1h&q=curl')).items[0].toolName, 'Bash');
  assert.equal((await f.get('/api/logs?range=1h&q=-curl')).total, 4);
  assert.equal((await f.get('/api/logs?range=1h&q=tool:read')).total, 1);
  const filtered = await f.get('/api/logs?range=1h&category=network,git');
  assert.equal(filtered.total, 2);
  assert.equal(filtered.facets.category.length, 5, 'a facet counts as if its own filter were off');
  assert.ok(filtered.facets.category.find(c => c.value === 'git').selected);
  assert.equal(
    all.histogram.points.reduce((n, p) => n + p.total, 0),
    5,
  );
  assert.ok(all.items.every(item => item.risk !== undefined && item.collection === 'live' && item.data === 'real'));
  // Live tail: nothing newer than the latest sequence, then the next record only.
  assert.equal((await f.get(`/api/logs?after=${all.latestSeq}`)).total, 0);
  await f.call('s-2', 'Bash', {command: 'npm test'});
  const tail = await f.get(`/api/logs?after=${all.latestSeq}`);
  assert.equal(tail.total, 1);
  assert.equal(tail.items[0].category, 'build');
  for (const bad of ['range=2h', 'limit=0', 'after=x', 'from=x']) await assert.rejects(f.get(`/api/logs?${bad}`), {status: 400});
  await f.analyze();
  const board = await f.get('/api/dashboard?range=1h');
  assert.equal(board.stats.events, 6);
  assert.equal(board.stats.sessions, 2);
  assert.equal(board.stats.agentEvents, 6);
  assert.equal(
    board.histogram.points.reduce((n, p) => n + p.total, 0),
    6,
  );
  assert.ok(board.categories.some(c => c.category === 'network'));
  assert.ok(board.sessions.every(s => s.actor === 'claude-code@pc'));
});

test('action detail lists what the agent read or searched earlier in the same session', async t => {
  const f = open();
  t.after(f.close);
  const base = Date.now() - 60000,
    at = s => new Date(base + s * 1000);
  await f.call('s-1', 'Read', {file_path: 'C:/work/README.md'}, at(1));
  await f.call('s-1', 'WebFetch', {url: 'https://docs.example/api'}, at(2));
  await f.call('s-other', 'Read', {file_path: 'C:/elsewhere.md'}, at(3));
  await f.call('s-1', 'Bash', {command: 'curl -d @report.json https://upload.example/in'}, at(4));
  await f.call('s-1', 'Read', {file_path: 'C:/work/later.md'}, at(5));
  const curl = (await f.get('/api/logs?range=1h&q=curl')).items[0];
  const detail = await f.get(`/api/actions/${encodeURIComponent(curl.actionId)}`);
  assert.equal(detail.sessionReferences.traceId, 's-1');
  assert.deepEqual(
    detail.sessionReferences.items.map(r => r.toolName),
    ['WebFetch', 'Read'],
    'earlier reads of the same session, newest first',
  );
  assert.match(detail.sessionReferences.items[0].target, /docs\.example/);
  assert.ok(detail.limitations.some(l => /같은 세션에서 먼저 읽거나 검색했다고 보고한 자료 2건/.test(l)));
});
