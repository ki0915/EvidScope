// OPA decision-log adapter (src/opa-decision-adapter.mjs, docs/agent-registry.md) on the documented decision log example,
// result mappings, refusals, and the collector script (gzip input, preview and submission to a vault).
import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {gzipSync} from 'node:zlib';
import {adaptOpaDecisions} from '../src/opa-decision-adapter.mjs';
import {harness} from './harness.mjs';

// The example event of https://www.openpolicyagent.org/docs/management-decision-logs, verbatim, plus a canary in input.
const documented = () => ({
  labels: {app: 'my-example-app', id: '1780d507-aea2-45cc-ae50-fa153c8e4a5a', version: 'v1.21.1'},
  decision_id: '4ca636c1-55e4-417a-b1d8-4aceb67960d1',
  bundles: {authz: {revision: 'W3sibCI6InN5cy9jYXRhbG9nIiwicyI6NDA3MX1d'}},
  path: 'http/example/authz/allow',
  input: {method: 'GET', path: '/salary/bob'},
  result: 'true',
  requested_by: '[::1]:59943',
  timestamp: '2018-01-01T00:00:00.000000Z',
});
const collector = (over = {}) => ({id: 'alpha-enforcement', tenant: 'alpha', kind: 'enforcement', enforcementPointId: 'opa-sidecar-1',
  target: {actor: {value: 'salary-agent'}, action: {pointer: '/input/method'}, resource: {pointer: '/input/path'}}, recordedBeforeExecution: true, ...over});

test('the documented OPA decision log event becomes an allowlisted policy_decision record', () => {
  const canary = 'INPUT-BODY-CANARY-민감정보';
  const log = [{...documented(), input: {...documented().input, body: canary}, request_context: {http: {headers: {authorization: 'Bearer secret'}}},
    query: 'data.secret', nd_builtin_cache: {time: {now: canary}}, erased: ['/input/password'], metrics: {timer_server_handler_ns: 2_400_000}}];
  const {events, rejected, assurance} = adaptOpaDecisions(log, collector());
  assert.deepEqual(rejected, []);
  const [e] = events, note = JSON.parse(e.note);
  assert.deepEqual({kind: e.kind, decision: e.decision, decisionId: e.decisionId, occurredAt: e.occurredAt, actor: e.actor, action: e.action,
    resource: e.resource,
    engine: e.engine, engineVersion: e.engineVersion, policyId: e.policyId, policyVersion: e.policyVersion, enforcementPointId: e.enforcementPointId,
    latencyMs: e.latencyMs, recordedBeforeExecution: e.recordedBeforeExecution, actionId: e.actionId},
  {kind: 'policy_decision', decision: 'allow', decisionId: '4ca636c1-55e4-417a-b1d8-4aceb67960d1', occurredAt: '2018-01-01T00:00:00.000Z',
    actor: 'salary-agent', action: 'GET', resource: '/salary/bob', engine: 'opa', engineVersion: 'v1.21.1', policyId: 'http/example/authz/allow',
    policyVersion: 'W3sibCI6InN5cy9jYXRhbG9nIiwicyI6NDA3MX1d', enforcementPointId: 'opa-sidecar-1', latencyMs: 2, recordedBeforeExecution: true,
    actionId: 'opa:4ca636c1-55e4-417a-b1d8-4aceb67960d1'});
  assert.match(e.bundleDigest, /^sha256:[a-f0-9]{64}$/);
  assert.deepEqual([note.erasedFields, note.inputRetained, note.resultRetained], [1, false, false]);
  const text = JSON.stringify({events, assurance});
  for (const leak of [canary, 'Bearer secret', 'data.secret', '59943', 'my-example-app']) assert.ok(!text.includes(leak), leak);
  assert.deepEqual([assurance.signatureVerified, assurance.enforcementVerified, assurance.inputRetained], [false, false, false]);
  assert.equal(adaptOpaDecisions(log, collector()).events[0].id, e.id, 'stable event ids make resubmission idempotent');
});

test('results map to the four decisions through the collector; unmapped or incomplete events are rejected, never guessed', () => {
  const base = documented(), at = new Date().toISOString();
  const mapped = adaptOpaDecisions([
    {...base, decision_id: 'd-false', result: false, timestamp: at},
    {...base, decision_id: 'd-object', result: {allow: false, decision: 'require_approval'}, timestamp: at},
    {...base, decision_id: 'd-custom', result: {outcome: 'needs_review'}, timestamp: at},
    {...base, decision_id: 'd-unmapped', result: {outcome: 'maybe'}, timestamp: at},
  ], collector({decision: {pointer: '/result/decision', values: {needs_review: 'require_approval'}}}));
  assert.deepEqual(mapped.events.map(e => [e.decisionId, e.decision]), [['d-object', 'require_approval']]);
  assert.deepEqual(mapped.rejected.map(r => r.decisionId), ['d-false', 'd-custom', 'd-unmapped']);
  const outcome = adaptOpaDecisions([{...base, result: {outcome: 'needs_review'}, timestamp: at}],
    collector({decision: {pointer: '/result/outcome', values: {needs_review: 'require_approval'}}}));
  assert.equal(outcome.events[0].decision, 'require_approval');
  assert.equal(adaptOpaDecisions([{...base, result: false, timestamp: at}], collector()).events[0].decision, 'deny');
  const linked = adaptOpaDecisions([{...base, input: {...base.input, ctx: {action: 'act-9', tool: 'payroll'}}, trace_id: 'trace-9', timestamp: at}],
    collector({target: {actor: {value: 'salary-agent'}, tool: {pointer: '/input/ctx/tool'}, actionId: {pointer: '/input/ctx/action'}}}));
  assert.deepEqual([linked.events[0].actionId, linked.events[0].traceId, linked.events[0].tool], ['act-9', 'trace-9', 'payroll']);
  const incomplete = adaptOpaDecisions([{...base, timestamp: at}, {...base, decision_id: 'no-time', timestamp: 'yesterday'}],
    collector({target: {actor: {pointer: '/input/subject'}, action: {pointer: '/input/method'}}}));
  assert.equal(incomplete.events.length, 0);assert.match(incomplete.rejected[0].reason, /actor not found/);
  assert.throws(() => adaptOpaDecisions([base], {...collector(), kind: 'authority'}), /enforcement source/);
  assert.throws(() => adaptOpaDecisions([base], collector({target: {actor: {pointer: '/request_context/http/headers'}}})), /may only read/);
  assert.throws(() => adaptOpaDecisions([base], collector({decision: {values: {true: 'block'}}})), /must map/);
  assert.throws(() => adaptOpaDecisions([base], collector({input: true})), /unsupported collector field/);
  assert.throws(() => adaptOpaDecisions([], collector()), /1 to 1000/);
});

test('the collector script previews gzip logs and submits through the enforcement source credential', async t => {
  const enforcement = {id: 'alpha-enforcement', tenant: 'alpha', role: 'source', kind: 'enforcement', token: randomBytes(32).toString('base64url'),
    hmacSecret: randomBytes(32).toString('base64url')};
  const h = await harness({vaultOnly: true, beforeStart: ({dir}) => {
    const file = join(dir, 'config.json'), config = JSON.parse(readFileSync(file, 'utf8'));config.principals.push(enforcement);
    writeFileSync(file, JSON.stringify(config));
  }});
  t.after(() => h.close());
  const dir = mkdtempSync(join(tmpdir(), 'evidscope-opa-'));t.after(() => rmSync(dir, {recursive: true, force: true}));
  const log = join(dir, 'decisions.json.gz'), collectorFile = join(dir, 'collector.json'), at = new Date().toISOString();
  writeFileSync(log, gzipSync(JSON.stringify([{...documented(), timestamp: at}, {...documented(), decision_id: 'd-2', result: false, timestamp: at}])));
  writeFileSync(collectorFile, JSON.stringify(collector()));
  const script = fileURLToPath(new URL('../scripts/collect-opa-decisions.mjs', import.meta.url));
  const run = args => spawnSync(process.execPath, [script, ...args], {encoding: 'utf8', cwd: fileURLToPath(new URL('..', import.meta.url))});
  const preview = run(['--log', log, '--collector', collectorFile]);
  assert.equal(preview.status, 0, preview.stderr);
  assert.deepEqual(JSON.parse(preview.stdout).events.map(e => e.decision), ['allow', 'deny']);
  const sent = run(['--log', log, '--collector', collectorFile, '--send', '--config', join(h.dir, 'config.json'), '--base', h.vault.url + '/']);
  assert.equal(sent.status, 0, sent.stderr);
  assert.deepEqual(JSON.parse(sent.stdout).submissions.map(s => s.duplicate), [false, false]);
  const sendArgs = ['--log', log, '--collector', collectorFile, '--send', '--config', join(h.dir, 'config.json'), '--base', h.vault.url + '/'];
  const again = JSON.parse(run(sendArgs).stdout);
  assert.deepEqual(again.submissions.map(s => s.duplicate), [true, true], 'resubmission is idempotent');
  const stored = (await h.api('/api/events?kind=policy_decision', {role: 'auditor'})).body.items;
  assert.deepEqual(stored.map(e => [e.decision, e.sourceKind, e.assurance]).sort(),
    [['allow', 'enforcement', 'authenticated_service_record'], ['deny', 'enforcement', 'authenticated_service_record']]);
  assert.ok(!JSON.stringify(stored).includes('/salary/bob"}'), 'the input body itself is not stored');
});
