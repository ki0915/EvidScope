// Collection continuity (docs/agent-monitoring.md, "수집 연속성"): the hook numbers and links its records, the vault validates the
// chain field, the report finds missing, broken and reused numbers and restarts, and the check records each problem once as a signed
// gap record that becomes a COLLECTION_GAP alert.
import test from 'node:test';
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {promisify} from 'node:util';
import {harness} from './harness.mjs';
import {submit} from '../src/client.mjs';
import {digest} from '../src/crypto.mjs';
import {canonicalJson, hookChain, recordDigest, runHook} from '../src/agent-hook-runner.mjs';
import {createHash} from 'node:crypto';
import {analyzeChains, chainProblems, chainGapEvent, CHAIN_CHECK_PRINCIPAL} from '../src/collection-chain.mjs';
import {validateEvent} from '../src/model.mjs';

const run = promisify(execFile);

test('the hook numbers its records in one stream and links each to the digest the vault stores for the one before', () => {
  const dir = mkdtempSync(join(tmpdir(), 'evid-chain-')), path = join(dir, 'codex-chain.json');
  try {
    const a = [{id: 'a', note: 'é', list: [1, null, {z: 1, a: undefined}]}, {id: 'b'}], b = [{id: 'c'}];
    assert.equal(hookChain(path, a), true);assert.equal(hookChain(path, b), true);
    const [x, y] = a, [z] = b;
    assert.deepEqual([x.chain.seq, y.chain.seq, z.chain.seq], [1, 2, 3]);
    assert.equal(x.chain.prev, 'genesis');
    assert.ok(x.chain.stream === y.chain.stream && y.chain.stream === z.chain.stream);
    assert.equal(y.chain.prev, digest(JSON.parse(JSON.stringify(x))), 'prev is the vault fingerprint of the record as sent');
    assert.equal(z.chain.prev, recordDigest(y));
    assert.equal(canonicalJson({b: [1, 'x'], a: {d: true, c: null}}), '{"a":{"c":null,"d":true},"b":[1,"x"]}');
    const state = JSON.parse(readFileSync(path, 'utf8'));
    assert.deepEqual([state.seq, state.last], [3, recordDigest(z)]);
    writeFileSync(path, 'broken');
    const fresh = [{id: 'd'}];hookChain(path, fresh);
    assert.deepEqual([fresh[0].chain.seq, fresh[0].chain.prev], [1, 'genesis']);
    assert.notEqual(fresh[0].chain.stream, x.chain.stream, 'an unreadable state starts a new stream');
  } finally { rmSync(dir, {recursive: true, force: true}); }
});

test('concurrent hook processes never hand out one number twice', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'evid-chain-')), path = join(dir, 'codex-chain.json');
  const script = `import {hookChain} from ${JSON.stringify(new URL('../src/agent-hook-runner.mjs', import.meta.url).href)};
    const out = [];
    for (let i = 0; i < 25; i++) { const e = [{id: String(i)}]; if (!hookChain(${JSON.stringify(path)}, e)) process.exit(2); out.push(e[0].chain.seq); }
    process.stdout.write(JSON.stringify(out));`;
  try {
    const outs = await Promise.all(Array.from({length: 6}, () => run(process.execPath, ['--input-type=module', '-e', script])));
    const seqs = outs.flatMap(o => JSON.parse(o.stdout)).sort((a, b) => a - b);
    assert.deepEqual(seqs, Array.from({length: 150}, (_, i) => i + 1));
  } finally { rmSync(dir, {recursive: true, force: true}); }
});

test('the chain field is accepted from agent sources only, in its exact shape', () => {
  const agent = {id: 'a', tenant: 't', kind: 'agent'}, telemetry = {id: 'b', tenant: 't', kind: 'telemetry'};
  const base = {id: 'e1', kind: 'intent', occurredAt: new Date().toISOString(), traceId: 't1', actionId: 'a1', actor: 'x'};
  const chain = {stream: '0b8a6c1e-1111-4222-8333-944455556666', seq: 2, prev: 'a'.repeat(64)};
  assert.deepEqual(validateEvent({...base, chain}, agent).chain, chain);
  for (const bad of [{...chain, seq: 0}, {...chain, seq: 1.5}, {...chain, prev: 'xyz'}, {...chain, stream: 'a b'}, {...chain, extra: 1}, []])
    assert.throws(() => validateEvent({...base, chain: bad}, agent), /chain/, JSON.stringify(bad));
  assert.throws(() => validateEvent({...base, kind: 'gap', chain}, telemetry), /chain/);
});

// Stored records as the vault keeps them: fingerprint here is the raw digest itself, compared as is.
const S = 'stream-aaaa-0001', T = 'stream-bbbb-0002', compare = (stored, raw) => stored === raw ? 'same' : 'different';
function stream(stream, seqs, {source = 'agent-1', actor = 'codex@pc', at = '2026-10-18T00:00:00.000Z', tamper = new Set()} = {}) {
  const out = [];let prev = 'genesis';
  for (const seq of Array.from({length: Math.max(...seqs)}, (_, i) => i + 1)) {
    const raw = {id: `${stream}-${seq}`, chain: {stream, seq, prev: tamper.has(seq) ? 'f'.repeat(64) : prev}};
    prev = digest(raw);
    if (seqs.includes(seq)) out.push({...raw, source, actor, tool: 'codex', sourceKind: 'agent', kind: 'intent', fingerprint: digest(raw),
      receivedAt: new Date(Date.parse(at) + seq * 1000).toISOString()});
  }
  return out;
}

test('the report finds holes (pending, then confirmed), broken links, reused numbers, restarts and unchained records', () => {
  const now = Date.parse('2026-10-18T00:30:00.000Z');
  const events = [...stream(S, [1, 2, 3, 6, 7], {tamper: new Set([7])}), ...stream(T, [1, 2], {at: '2026-10-18T00:20:00.000Z'}),
    {id: 'old', source: 'agent-1', actor: 'codex@pc', sourceKind: 'agent', kind: 'intent', receivedAt: '2026-10-17T23:00:00.000Z'},
    {id: 'late', source: 'agent-1', actor: 'codex@pc', sourceKind: 'agent', kind: 'intent', receivedAt: '2026-10-18T00:25:00.000Z'},
    {id: 'tool', source: 'tool-1', sourceKind: 'tool', kind: 'execution', receivedAt: '2026-10-18T00:00:00.000Z'}];
  const reused = {...stream(S, [2])[0], id: 'other', fingerprint: 'c'.repeat(64)};
  const soon = analyzeChains([...events, reused], {compare, now, graceMs: 60 * 60 * 1000});
  const s = soon.streams.find(x => x.stream === S);
  assert.deepEqual(s.missing.map(h => [h.from, h.to, h.status]), [[4, 5, 'pending']], 'a hole waits while a backlog may still come');
  assert.deepEqual(s.broken.map(b => [b.seq, b.reason]), [[7, 'previous_record_differs']]);
  assert.deepEqual(s.reused, [2]);
  assert.deepEqual(soon.restarts.map(r => [r.stream, r.previousStream]), [[T, S]]);
  assert.deepEqual(soon.sources.find(x => x.source === 'agent-1'), {source: 'agent-1', records: 10, chained: 8, unchained: 2, unchainedAfterChain: 1,
    unnumbered: [{id: 'late', actor: 'codex@pc', tool: null, receivedAt: '2026-10-18T00:25:00.000Z'}]});
  assert.equal(soon.counts.agentRecords, 10, 'tool records are not hook records');
  // A restart and an unnumbered record after numbering began are raised too (security review 2026-10-22): both hide removed records.
  const unnumberedId = 'chain.unnumbered.' + createHash('sha256').update('agent-1\u0000late').digest('hex').slice(0, 24);
  assert.deepEqual(chainProblems(soon).map(p => p.id), [`chain.break.${S}.7`, `chain.reuse.${S}.2`, `chain.restart.${T}`, unnumberedId],
    'a pending hole is not raised yet');
  const restart = chainProblems(soon).find(p => p.problem === 'restart'), unnumbered = chainProblems(soon).find(p => p.problem === 'unnumbered');
  assert.match(restart.note, /새 스트림을 시작했습니다\(앞 스트림 stream-aaaa-0001은 7번까지 받음\)/);
  assert.deepEqual([restart.actor, restart.tool, restart.stream, restart.source], ['codex@pc', 'codex', T, 'agent-1']);
  assert.deepEqual([unnumbered.recordId, unnumbered.stream, unnumbered.actor], ['late', null, 'codex@pc']);
  const unnumberedGap = validateEvent(chainGapEvent(unnumbered, new Date(now).toISOString()), {id: CHAIN_CHECK_PRINCIPAL, tenant: 't', kind: 'telemetry'});
  assert.deepEqual([unnumberedGap.kind, unnumberedGap.action, unnumberedGap.actionId.startsWith('chain.unnumbered.'), unnumberedGap.actionId.length <= 120],
    ['gap', 'collection_chain_unnumbered', true, true]);

  const later = analyzeChains(events, {compare, now, graceMs: 0});
  assert.deepEqual(later.counts, {agentRecords: 9, chained: 7, unchained: 2, streams: 2, restarts: 1, missingRecords: 2, confirmedMissingRanges: 1,
    pendingMissingRanges: 0, brokenLinks: 1, unverifiableLinks: 0, reusedNumbers: 0});
  const problems = chainProblems(later);
  assert.deepEqual(problems.map(p => p.id), [`chain.gap.${S}.4-5`, `chain.break.${S}.7`, `chain.restart.${T}`, unnumberedId]);
  const gap = validateEvent(chainGapEvent(problems[0], new Date(now).toISOString()), {id: CHAIN_CHECK_PRINCIPAL, tenant: 't', kind: 'telemetry'});
  assert.deepEqual([gap.kind, gap.actionId, gap.actor, gap.resource], ['gap', `chain.${S}`, 'codex@pc', `chain:${S}`]);

  const erased = analyzeChains(stream(S, [1, 2]), {compare: () => 'unverifiable', now, graceMs: 0});
  assert.deepEqual([erased.counts.brokenLinks, erased.counts.unverifiableLinks, chainProblems(erased).length], [0, 1, 0], 'an erased key is no alarm');
  const head = analyzeChains(stream(S, [5, 6]), {compare, now, graceMs: 0});
  assert.deepEqual([head.streams[0].startsAtOne, head.counts.missingRecords, chainProblems(head).length], [false, 0, 0],
    'records before the first retained one (expired) are not counted missing');
  const badStart = analyzeChains([{...stream(S, [1])[0], chain: {stream: S, seq: 1, prev: 'a'.repeat(64)}}], {compare, now});
  assert.equal(badStart.streams[0].broken[0].reason, 'first_without_genesis');
});

let h;
test.before(async () => { process.env.COLLECTION_CHAIN_GRACE_MS = '0'; h = await harness(); });
test.after(async () => { await h?.close(); delete process.env.COLLECTION_CHAIN_GRACE_MS; });
const call = (path, body, role = 'reviewer') => h.api(path, {body, role});
async function analyzeAll() {for (let i = 0; i < 20; i++) {const r = (await h.analyze()).body;if (!r.backlog && !r.processed) return;}}

test('end to end: a record lost before the vault and a changed link become COLLECTION_GAP alerts, each recorded once', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'evid-chain-e2e-')), configPath = join(dir, 'codex-hook.json'), agent = h.principal('agent');
  writeFileSync(configPath, JSON.stringify({url: h.ingress.url, token: agent.token, hmacSecret: agent.hmacSecret, actor: 'codex@chain-pc',
    policyVersion: 'codex-monitoring-v1'}));
  const env = {EVIDSCOPE_HOOK_CONFIG: configPath, EVIDSCOPE_HOOK_HOME: dir};
  const hook = id => runHook('codex', {env, input: JSON.stringify({hook_event_name: 'PreToolUse', session_id: 'chain-s1', tool_use_id: id,
    tool_name: 'Bash', tool_input: {command: 'ls'}, cwd: dir})});
  try {
    for (const id of ['c1', 'c2', 'c3']) await hook(id);
    let report = (await call('/api/collection/chains', undefined, 'auditor')).body;
    const mine = () => report.streams.find(s => s.actor === 'codex@chain-pc');
    assert.equal(mine().lastSeq, 3, JSON.stringify(report.counts));
    assert.deepEqual([mine().missingRanges, mine().brokenLinks], [0, 0]);
    // A record numbered on the PC and never delivered (a spool line removed), then a record whose link was rewritten on the way.
    hookChain(join(dir, 'codex-chain.json'), [{id: 'lost'}]);
    await hook('c5');
    const sixth = [{id: 'c6', kind: 'intent', status: 'requested', occurredAt: new Date().toISOString(), traceId: 'chain-s1', actionId: 'c6',
      actor: 'codex@chain-pc', tool: 'codex', action: 'shell_exec', resource: 'pwd'}];
    hookChain(join(dir, 'codex-chain.json'), sixth);sixth[0].chain.prev = 'e'.repeat(64);
    assert.equal((await submit(h.ingress.url, agent, sixth[0])).status, 202);
    report = (await call('/api/collection/chains', undefined, 'auditor')).body;
    assert.deepEqual(mine().missing.map(x => [x.from, x.to, x.status]), [[4, 4, 'confirmed']]);
    assert.deepEqual(mine().broken.map(b => b.seq), [6]);

    assert.equal((await call('/api/collection/chains/check', {}, 'auditor')).status, 403, 'only a reviewer runs the check');
    const checked = (await call('/api/collection/chains/check', {})).body;
    assert.deepEqual(checked.recorded.map(r => r.problem).sort(), ['broken', 'missing']);
    assert.deepEqual((await call('/api/collection/chains/check', {})).body.recorded, [], 'a problem is recorded once');
    await analyzeAll();
    const alerts = (await call('/api/alerts', undefined, 'auditor')).body.items.filter(a => a.code === 'COLLECTION_GAP'
      && a.actionId === `chain.${mine().stream}`);
    assert.equal(alerts.length, 2, JSON.stringify(alerts.map(a => [a.actionId, a.code])));
    assert.ok(alerts.every(a => a.severity === 'high'));

    // The state file removed (with whatever the spool still held): the next call starts a new stream, which is an alert, not a note.
    const firstStream = mine().stream;
    rmSync(join(dir, 'codex-chain.json'));
    await hook('c7');
    report = (await call('/api/collection/chains', undefined, 'auditor')).body;
    const restarted = report.streams.find(s => s.actor === 'codex@chain-pc' && s.stream !== firstStream);
    assert.deepEqual([restarted.firstSeq, restarted.lastSeq, report.counts.restarts], [1, 1, 1]);
    assert.deepEqual(report.restarts.map(r => [r.stream, r.previousStream, r.previousLastSeq]), [[restarted.stream, firstStream, 6]]);
    assert.deepEqual((await call('/api/collection/chains/check', {})).body.recorded.map(r => [r.problem, r.stream]), [['restart', restarted.stream]]);
    assert.deepEqual((await call('/api/collection/chains/check', {})).body.recorded, [], 'a restart is recorded once');
    await analyzeAll();
    const restartAlerts = (await call('/api/alerts', undefined, 'auditor')).body.items.filter(a => a.code === 'COLLECTION_GAP'
      && a.actionId === `chain.${restarted.stream}`);
    assert.equal(restartAlerts.length, 1, JSON.stringify(restartAlerts.map(a => [a.actionId, a.code])));
  } finally { rmSync(dir, {recursive: true, force: true}); }
});
