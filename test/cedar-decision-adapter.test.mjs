// Cedar decision adapter (src/cedar-decision-adapter.mjs, docs/agent-registry.md) on the documented Amazon Verified Permissions
// CloudTrail entries and Cedar authorization responses, refusals, the decision rules on its records and the collector script.
import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {gzipSync} from 'node:zlib';
import {adaptCedarDecisions} from '../src/cedar-decision-adapter.mjs';
import {evaluate, validateEvent} from '../src/model.mjs';
import {harness} from './harness.mjs';

// The IsAuthorized and BatchIsAuthorized examples of "Logging Amazon Verified Permissions API calls using AWS CloudTrail",
// verbatim except the {{placeholders}}, plus canaries where a real log carries caller and request data.
const CANARY = 'CONTEXT-CANARY-민감정보';
const isAuthorized = () => ({
  eventVersion: '1.08',
  userIdentity: {type: 'AssumedRole', principalId: 'EXAMPLE_PRINCIPAL_ID', arn: 'arn:aws:iam::123456789012:role/ExampleRole', accountId: '123456789012',
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE'},
  eventTime: '2023-11-20T22:55:03Z', eventSource: 'verifiedpermissions.amazonaws.com', eventName: 'IsAuthorized', awsRegion: 'us-west-2',
  sourceIPAddress: '203.0.113.0',
  userAgent: 'aws-cli/2.11.18 Python/3.11.3 Linux/5.4.241-160.348.amzn2int.x86_64 exe/x86_64.amzn.2 prompt/off command/verifiedpermissions.is-authorized',
  requestParameters: {principal: {entityType: 'PhotoFlash::User', entityId: 'alice'}, action: {actionType: 'PhotoFlash::Action', actionId: 'ViewPhoto'},
    resource: {entityType: 'PhotoFlash::Photo', entityId: 'VacationPhoto94.jpg'}, policyStoreId: 'PSEXAMPLEabcdefg111111'},
  responseElements: null, additionalEventData: {decision: 'ALLOW'}, requestID: '346c4b6a-d12f-46b6-bc06-6c857bd3b28e',
  eventID: '8a4fed32-9605-45dd-a09a-5ebbf0715bbc', readOnly: true,
  resources: [{accountId: '123456789012', type: 'AWS::VerifiedPermissions::PolicyStore',
    ARN: 'arn:aws:verifiedpermissions::123456789012:policy-store/PSEXAMPLEabcdefg111111'}],
  eventType: 'AwsApiCall', managementEvent: false, recipientAccountId: '123456789012', eventCategory: 'Data',
});
const request = (user, action) => ({principal: {entityType: 'PhotoFlash::User', entityId: user}, action: {actionType: 'PhotoFlash::Action', actionId: action},
  resource: {entityType: 'PhotoFlash::Photo', entityId: 'VacationPhoto94.jpg'}});
const batchIsAuthorized = () => ({...isAuthorized(), eventTime: '2023-11-20T23:02:33Z', eventName: 'BatchIsAuthorized',
  requestParameters: {requests: [request('alice', 'ViewPhoto'), request('annalisa', 'DeletePhoto')], policyStoreId: 'PSEXAMPLEabcdefg111111'},
  additionalEventData: {results: [{request: request('alice', 'ViewPhoto'), decision: 'ALLOW'},
    {request: request('annalisa', 'DeletePhoto'), decision: 'DENY'}]},
  requestID: 'a8a5caf3-78bd-4139-924c-7101a8339c3b', eventID: '7d81232f-f3d1-4102-b9c9-15157c70487b'});
const avp = (over = {}) => ({id: 'alpha-enforcement', tenant: 'alpha', kind: 'enforcement', enforcementPointId: 'photo-app', format: 'avp-cloudtrail',
  target: {actor: {pointer: '/principal/entityId'}, action: {pointer: '/action/actionId'}, resource: {pointer: '/resource/entityId'}}, ...over});
// An application log entry embedding the Cedar Agent responses of its README (Allow by admins-policy, Deny with no policy).
const agentEntry = (id, response, over = {}) => ({request_id: id, time: '2026-10-07T09:00:00Z', agent: 'report-agent', tool: 'reports',
  request: {principal: 'User::"admin.1@domain.com"', action: 'Action::"get"', resource: 'Resource::"report"', context: {note: CANARY}}, response, ...over});
const cedar = (over = {}) => ({id: 'alpha-enforcement', tenant: 'alpha', kind: 'enforcement', enforcementPointId: 'cedar-agent-1', format: 'cedar-response',
  record: {id: '/request_id', time: '/time'}, target: {actor: {pointer: '/agent'}, tool: {pointer: '/tool'}}, recordedBeforeExecution: true, ...over});

test('the documented AVP CloudTrail entries become allowlisted policy_decision records; other events are skipped', () => {
  const single = {...isAuthorized(), requestParameters: {...isAuthorized().requestParameters, context: {contextMap: {note: {string: CANARY}}}}};
  const log = {Records: [single, batchIsAuthorized(), {...isAuthorized(), eventSource: 's3.amazonaws.com', eventName: 'GetObject'},
    {...isAuthorized(), eventName: 'CreatePolicy', managementEvent: true}]};
  const {events, rejected, skipped, assurance} = adaptCedarDecisions(log, avp());
  assert.deepEqual(rejected, []);assert.deepEqual(skipped, {GetObject: 1, CreatePolicy: 1});
  assert.deepEqual(events.map(e => [e.decision, e.actor, e.action, e.resource, e.decisionId, e.occurredAt]), [
    ['allow', 'alice', 'ViewPhoto', 'VacationPhoto94.jpg', '346c4b6a-d12f-46b6-bc06-6c857bd3b28e', '2023-11-20T22:55:03.000Z'],
    ['allow', 'alice', 'ViewPhoto', 'VacationPhoto94.jpg', 'a8a5caf3-78bd-4139-924c-7101a8339c3b:0', '2023-11-20T23:02:33.000Z'],
    ['deny', 'annalisa', 'DeletePhoto', 'VacationPhoto94.jpg', 'a8a5caf3-78bd-4139-924c-7101a8339c3b:1', '2023-11-20T23:02:33.000Z']]);
  const [e] = events, note = JSON.parse(e.note);
  assert.deepEqual([e.kind, e.engine, e.enforcementPointId, e.actionId, e.policyId, e.recordedBeforeExecution],
    ['policy_decision', 'amazon-verified-permissions', 'photo-app', 'cedar:346c4b6a-d12f-46b6-bc06-6c857bd3b28e', undefined, undefined]);
  assert.deepEqual([note.policyStoreId, note.eventName, note.determiningPolicies, note.requestRetained], ['PSEXAMPLEabcdefg111111', 'IsAuthorized', 0, false]);
  const text = JSON.stringify({events, assurance});
  for (const leak of [CANARY, 'AKIAIOSFODNN7EXAMPLE', '203.0.113.0', 'ExampleRole', 'aws-cli', '8a4fed32', 'PhotoFlash::User'])
    assert.ok(!text.includes(leak), leak);
  assert.deepEqual([assurance.signatureVerified, assurance.enforcementVerified, assurance.completenessVerified], [false, false, false]);
  assert.deepEqual(adaptCedarDecisions(log, avp()).events.map(x => x.id), events.map(x => x.id), 'stable ids make resubmission idempotent');
  // Determining policies, when the entry carries them (IsAuthorized API field), name the policy; errors are counted only.
  const withPolicies = {...isAuthorized(), additionalEventData: {decision: 'DENY', determiningPolicies: [{policyId: 'SPEXAMPLEabcdefg111111'}],
    errors: [{errorDescription: `evaluation error ${CANARY}`}]}};
  const [denied] = adaptCedarDecisions([withPolicies], avp()).events;
  assert.deepEqual([denied.decision, denied.policyId, JSON.parse(denied.note).errors], ['deny', 'SPEXAMPLEabcdefg111111', 1]);
  assert.ok(!denied.note.includes(CANARY));
  // Only the configured policy store is read.
  assert.deepEqual(adaptCedarDecisions(log, avp({policyStoreId: 'PSother'})).skipped, {IsAuthorized: 1, BatchIsAuthorized: 1, GetObject: 1, CreatePolicy: 1});
});

test('Cedar responses map Allow/Deny with determining policies; failures and unknown values are refused, never guessed', () => {
  const allow = agentEntry('r-1', {decision: 'Allow', diagnostics: {reason: ['admins-policy'], errors: []}});
  const deny = agentEntry('r-2', {decision: 'Deny', diagnostics: {reason: [], errors: []}});
  const ffi = agentEntry('r-3', {type: 'success', response: {decision: 'deny', diagnostics: {reason: ['forbid-b', 'forbid-a'],
    errors: [{policyId: 'policy-err', error: {message: `attribute missing ${CANARY}`}}]}}, warnings: [{message: CANARY}]});
  const failure = agentEntry('r-4', {type: 'failure', errors: [{message: 'parse error'}], warnings: []});
  const maybe = agentEntry('r-5', {decision: 'NotApplicable', diagnostics: {reason: [], errors: []}});
  const noActor = agentEntry('r-6', {decision: 'Allow', diagnostics: {reason: [], errors: []}}, {agent: undefined});
  const {events, rejected} = adaptCedarDecisions([allow, deny, ffi, failure, maybe, noActor], cedar());
  assert.deepEqual(events.map(e => [e.decisionId, e.decision, e.policyId, e.engine, e.actor, e.tool, e.recordedBeforeExecution]), [
    ['r-1', 'allow', 'admins-policy', 'cedar', 'report-agent', 'reports', true], ['r-2', 'deny', undefined, 'cedar', 'report-agent', 'reports', true],
    ['r-3', 'deny', events[2].policyId, 'cedar', 'report-agent', 'reports', true]]);
  assert.match(events[2].policyId, /^cedar-policies:[0-9a-f]{32}$/);
  assert.deepEqual(JSON.parse(events[2].note).policyIds, ['forbid-a', 'forbid-b']);
  assert.deepEqual(JSON.parse(events[2].note).errorPolicyIds, ['policy-err']);
  assert.deepEqual(rejected.map(r => [r.index, /failed|Allow or Deny|actor not found/.test(r.reason)]), [[3, true], [4, true], [5, true]]);
  assert.ok(!JSON.stringify(events).includes(CANARY));
});

test('wrong sources and collector configurations are refused', () => {
  const log = [isAuthorized()];
  assert.throws(() => adaptCedarDecisions(log, avp({kind: 'otlp'})), /enforcement source/);
  assert.throws(() => adaptCedarDecisions(log, avp({target: {actor: {pointer: '/userIdentity/arn'}}})), /may only read/);
  assert.throws(() => adaptCedarDecisions(log, avp({format: 'cedar-agent'})), /format must be/);
  assert.throws(() => adaptCedarDecisions(log, avp({record: {id: '/x', time: '/y'}})), /cedar-response format only/);
  assert.throws(() => adaptCedarDecisions(log, cedar({record: {id: '/request_id'}})), /record.id and record.time/);
  assert.throws(() => adaptCedarDecisions(log, avp({decision: {values: {}}})), /unsupported collector field/);
  assert.throws(() => adaptCedarDecisions([], avp()), /no decision entries/);
  // The records are enforcement-source records: an agent, OTLP or tool credential cannot submit them.
  const [record] = adaptCedarDecisions(log, avp()).events;
  for (const kind of ['agent', 'otlp', 'tool'])
    assert.throws(() => validateEvent(record, {id: `alpha-${kind}`, tenant: 'alpha', role: 'source', kind}), e => [400, 403].includes(e.status), kind);
});

test('the decision rules fire on Cedar records', () => {
  const p = {id: 'alpha-enforcement', tenant: 'alpha', role: 'source', kind: 'enforcement'}, now = Date.now(), at = ms => new Date(now - 600000 + ms);
  const entries = [0, 1, 2].map(i => agentEntry(`deny-${i}`, {decision: 'Deny', diagnostics: {reason: ['forbid-reports'], errors: []}},
    {time: at(i * 1000).toISOString(), action_id: `act-${i}`}));
  const {events} = adaptCedarDecisions(entries, cedar({target: {actor: {pointer: '/agent'}, tool: {pointer: '/tool'}, actionId: {pointer: '/action_id'}},
    clockUncertaintyMs: 1000}));
  const stored = events.map(e => ({...validateEvent(e, p), seq: 1}));
  const execution = {id: 'x-1', tenant: 'alpha', source: 'alpha-tool', sourceKind: 'tool', kind: 'execution', actionId: 'act-0', traceId: 'act-0',
    actor: 'report-agent', tool: 'reports', status: 'success', occurredAt: at(10000).toISOString(), clockUncertaintyMs: 0};
  const codes = evaluate([stored[0], execution], [], [], [], now).findings.map(f => f.code);
  assert.ok(codes.includes('EXECUTION_AFTER_DENY'), codes.join());
  assert.ok(evaluate(stored, [], [], [], now).findings.some(f => f.code === 'REPEATED_DENIES'));
});

test('the collector script previews gzip CloudTrail files and submits through the enforcement source credential', async t => {
  const enforcement = {id: 'alpha-enforcement', tenant: 'alpha', role: 'source', kind: 'enforcement', token: randomBytes(32).toString('base64url'),
    hmacSecret: randomBytes(32).toString('base64url')};
  const h = await harness({vaultOnly: true, beforeStart: ({dir}) => {
    const file = join(dir, 'config.json'), config = JSON.parse(readFileSync(file, 'utf8'));config.principals.push(enforcement);
    writeFileSync(file, JSON.stringify(config));
  }});
  t.after(() => h.close());
  const dir = mkdtempSync(join(tmpdir(), 'evidscope-cedar-'));t.after(() => rmSync(dir, {recursive: true, force: true}));
  const recent = new Date(Date.now() - 60000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const log = join(dir, 'cloudtrail.json.gz'), collectorFile = join(dir, 'collector.json');
  writeFileSync(log, gzipSync(JSON.stringify({Records: [{...isAuthorized(), eventTime: recent}, {...batchIsAuthorized(), eventTime: recent}]})));
  writeFileSync(collectorFile, JSON.stringify(avp()));
  const script = fileURLToPath(new URL('../scripts/collect-cedar-decisions.mjs', import.meta.url));
  const run = args => spawnSync(process.execPath, [script, ...args], {encoding: 'utf8', cwd: fileURLToPath(new URL('..', import.meta.url))});
  const preview = run(['--log', log, '--collector', collectorFile]);
  assert.equal(preview.status, 0, preview.stderr);
  assert.deepEqual(JSON.parse(preview.stdout).events.map(e => e.decision), ['allow', 'allow', 'deny']);
  const sendArgs = ['--log', log, '--collector', collectorFile, '--send', '--config', join(h.dir, 'config.json'), '--base', h.vault.url + '/'];
  const sent = run(sendArgs);
  assert.equal(sent.status, 0, sent.stderr);
  assert.deepEqual(JSON.parse(sent.stdout).submissions.map(s => s.duplicate), [false, false, false]);
  assert.deepEqual(JSON.parse(run(sendArgs).stdout).submissions.map(s => s.duplicate), [true, true, true], 'resubmission is idempotent');
  const stored = (await h.api('/api/events?kind=policy_decision', {role: 'auditor'})).body.items;
  assert.deepEqual(stored.map(e => [e.decision, e.sourceKind, e.engine]).sort(), [['allow', 'enforcement', 'amazon-verified-permissions'],
    ['allow', 'enforcement', 'amazon-verified-permissions'], ['deny', 'enforcement', 'amazon-verified-permissions']]);
  // A collector naming a credential that is not an enforcement source cannot send.
  writeFileSync(collectorFile, JSON.stringify(avp({id: 'alpha-agent'})));
  const wrong = run(sendArgs);
  assert.notEqual(wrong.status, 0);assert.match(wrong.stderr, /Matching enforcement source credential required/);
});
