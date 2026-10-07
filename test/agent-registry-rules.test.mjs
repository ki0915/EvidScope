// Agent registry and policy-decision rules of the evaluation engine (docs/agent-registry.md): point-in-time registry state,
// the four decision rules, the related-deny input, intake validation and the offline lifecycle check. No server.
import test from 'node:test';
import assert from 'node:assert/strict';
import {EVALUATION_ENGINE, EVALUATION_ENGINE_V2, evaluate, evaluationEngine, validateEvent} from '../src/model.mjs';
import {computeRisk, registryAnalysisInput, verifyRegistryHistory} from '../src/agent-registry.mjs';
import {REPEATED_DENIES, relatedDenyInput} from '../src/decision-rules.mjs';

const T0 = Date.parse('2026-09-01T00:00:00.000Z');
const at = minutes => new Date(T0 + minutes * 60000).toISOString();
let serial = 0;
const event = over => ({tenant: 'alpha', actionId: 'a1', traceId: 't1', receivedAt: at(0), late: false, id: `e${++serial}`, ...over});
const intent = (minutes, over = {}) => event({source: 'alpha-agent', sourceKind: 'agent', kind: 'intent', actor: 'agent-x', occurredAt: at(minutes), ...over});
const execution = (minutes, over = {}) => event({source: 'alpha-tool', sourceKind: 'tool', kind: 'execution', actor: 'agent-x', tool: 'mailer', action: 'send',
  resource: 'case-1', occurredAt: at(minutes), ...over});
const decision = (minutes, value, over = {}) => event({source: 'alpha-enforcement', sourceKind: 'enforcement', kind: 'policy_decision', decision: value,
  actor: 'agent-x', tool: 'mailer', decisionId: `d${serial}`, enforcementPointId: 'gw-1', engine: 'opa', occurredAt: at(minutes), ...over});
const version = (n, state, minutes, over = {}) => ({type: 'agent_registry', payload: {id: 'agent-x', version: n, state, effectiveFrom: at(minutes),
  sources: ['alpha-agent'], actors: ['agent-x'], tools: [{name: 'mailer', enforcement: 'not_required'}], ...over}});
const policy = (n, enforcement, minutes) => ({type: 'agent_registry_policy', payload: {id: 'current', version: n, enforcement, effectiveFrom: at(minutes)}});
const codes = (events, context) => evaluate(events, [], [], [], T0, context).findings.map(f => f.code).sort();
const registryCodes = result => result.filter(code => code.startsWith('AGENT_'));

test('engine v2 is named only for snapshots with registry, decision or related-deny input', () => {
  assert.equal(evaluationEngine({events: [intent(1)], assets: []}), EVALUATION_ENGINE);
  assert.equal(evaluationEngine({events: [intent(1)], registry: registryAnalysisInput([version(1, 'draft', 0)])}), EVALUATION_ENGINE_V2);
  assert.equal(evaluationEngine({events: [decision(1, 'allow')]}), EVALUATION_ENGINE_V2);
  assert.equal(evaluationEngine({events: [], relatedDecisions: []}), EVALUATION_ENGINE_V2);
  assert.equal(registryAnalysisInput([]), undefined, 'no registry rows: the snapshot keeps its v1 shape');
  const events = [intent(1), execution(2, {kind: 'result', status: 'failure'})];
  assert.deepEqual(evaluate(events, [], [], [], T0), evaluate(events, [], [], [], T0, {}), 'without v2 input the output is the v1 output');
});

test('registry state is evaluated at the time of the activity, including suspended and retired', () => {
  const registry = registryAnalysisInput([version(1, 'production', 0), version(2, 'suspended', 10), version(3, 'production', 20), version(4, 'retired', 30)]);
  assert.deepEqual(registryCodes(codes([intent(5)], {registry})), []);
  assert.deepEqual(registryCodes(codes([intent(15)], {registry})), ['AGENT_SUSPENDED_ACTIVITY']);
  assert.deepEqual(registryCodes(codes([intent(25)], {registry})), []);
  assert.deepEqual(registryCodes(codes([intent(35)], {registry})), ['AGENT_RETIRED_ACTIVITY']);
  // A tool record is attributed through the actor it names; without an actor it is not attributed.
  assert.deepEqual(registryCodes(codes([execution(15)], {registry})), ['AGENT_SUSPENDED_ACTIVITY']);
  assert.deepEqual(registryCodes(codes([execution(15, {actor: undefined})], {registry})), []);
  // The authenticated source principal also attributes, whatever actor it reports.
  assert.deepEqual(registryCodes(codes([intent(15, {actor: 'renamed'})], {registry})), ['AGENT_SUSPENDED_ACTIVITY']);
  // A suspension inside the clock bound of the event cannot be ordered against it.
  assert.deepEqual(registryCodes(codes([intent(11, {clockUncertaintyMs: 120000})], {registry})), ['AGENT_REGISTRY_STATE_UNCERTAIN']);
  assert.deepEqual(registryCodes(codes([intent(15, {clockUncertaintyMs: 'unknown'})], {registry})), ['AGENT_REGISTRY_STATE_UNCERTAIN']);
  assert.deepEqual(registryCodes(codes([intent(15)], {})), [], 'no registry, no registry findings');
  // Re-registered under a new id after retirement: the live entry applies, the retired one is history.
  const again = registryAnalysisInput([version(1, 'production', 0), version(2, 'retired', 30), version(1, 'production', 40, {id: 'agent-x2'})]);
  assert.deepEqual(registryCodes(codes([intent(35)], {registry: again})), ['AGENT_RETIRED_ACTIVITY']);
  assert.deepEqual(registryCodes(codes([intent(45)], {registry: again})), []);
});

test('unregistered activity is a finding only while enforcement is configured', () => {
  const stranger = intent(5, {source: 'alpha-other', actor: 'nobody'});
  const rows = [version(1, 'production', 0)];
  assert.deepEqual(registryCodes(codes([stranger], {registry: registryAnalysisInput(rows)})), []);
  assert.deepEqual(registryCodes(codes([stranger], {registry: registryAnalysisInput([...rows, policy(1, 'off', 0)])})), []);
  assert.deepEqual(registryCodes(codes([stranger], {registry: registryAnalysisInput([...rows, policy(1, 'unregistered_activity', 0)])})),
    ['AGENT_UNREGISTERED_ACTIVITY']);
  assert.deepEqual(registryCodes(codes([stranger], {registry: registryAnalysisInput([...rows, policy(1, 'unregistered_activity', 6)])})), [],
    'enforcement configured after the activity is not applied to it');
  assert.deepEqual(registryCodes(codes([intent(5)], {registry: registryAnalysisInput([...rows, policy(1, 'unregistered_activity', 0)])})), []);
});

test('execution after a deny, cleared by a later allow, and uncertain order', () => {
  assert.ok(codes([decision(1, 'deny'), execution(2)]).includes('EXECUTION_AFTER_DENY'));
  assert.ok(!codes([decision(1, 'deny'), decision(1.5, 'allow'), execution(2)]).includes('EXECUTION_AFTER_DENY'));
  for (const other of [{source: 'alpha-guardrail'}, {enforcementPointId: 'gw-2'}])
    assert.ok(codes([decision(1, 'deny'), decision(1.5, 'allow', other), execution(2)]).includes('EXECUTION_AFTER_DENY'), 'only the denying point clears');
  assert.ok(!codes([decision(3, 'deny'), execution(2)]).includes('EXECUTION_AFTER_DENY'), 'a deny after the execution is not a bypass');
  assert.ok(!codes([decision(1, 'deny', {tool: 'other-tool'}), execution(2)]).includes('EXECUTION_AFTER_DENY'), 'another target');
  assert.ok(!codes([decision(1, 'deny'), execution(2, {kind: 'result', status: 'failure'})]).includes('EXECUTION_AFTER_DENY'));
  const uncertain = codes([decision(1, 'deny', {clockUncertaintyMs: 'unknown'}), execution(2)]);
  assert.ok(uncertain.includes('DECISION_ORDER_UNCERTAIN') && !uncertain.includes('EXECUTION_AFTER_DENY'));
});

test('a tool the registry marks as enforced needs a decision before its execution', () => {
  const registry = registryAnalysisInput([version(1, 'production', 0, {tools: [{name: 'mailer', enforcement: 'required'}]})]);
  assert.ok(codes([execution(2)], {registry}).includes('ENFORCEMENT_DECISION_MISSING'));
  assert.ok(!codes([decision(1, 'allow'), execution(2)], {registry}).includes('ENFORCEMENT_DECISION_MISSING'));
  assert.ok(codes([execution(2), decision(3, 'allow')], {registry}).includes('ENFORCEMENT_DECISION_MISSING'), 'a decision after the execution');
  assert.ok(!codes([execution(2)], {registry: registryAnalysisInput([version(1, 'production', 0)])}).includes('ENFORCEMENT_DECISION_MISSING'));
  assert.ok(!codes([execution(2)]).includes('ENFORCEMENT_DECISION_MISSING'), 'no registry, no requirement');
  // The requirement is point-in-time: added after the execution, it does not apply.
  const later = registryAnalysisInput([version(1, 'production', 0), version(2, 'production', 5, {tools: [{name: 'mailer', enforcement: 'required'}]})]);
  assert.ok(!codes([execution(2)], {registry: later}).includes('ENFORCEMENT_DECISION_MISSING'));
});

test('require_approval followed by execution needs a matching human approval', () => {
  const run = execution(2, {policyVersion: 'p1'});
  assert.ok(codes([decision(1, 'require_approval'), run]).includes('REQUIRED_APPROVAL_MISSING'));
  const approval = event({source: 'alpha-authority', sourceKind: 'authority', kind: 'human_approval', reviewer: 'person-1', policyVersion: 'p1',
    occurredAt: at(1.5), validFrom: at(1.5), validUntil: at(10), scope: {actor: 'agent-x', tool: 'mailer', action: 'send', resource: 'case-1'}});
  assert.ok(!codes([decision(1, 'require_approval'), approval, run]).join().includes('REQUIRED_APPROVAL'));
  const expired = {...approval, validUntil: at(1.8)};
  assert.ok(codes([decision(1, 'require_approval'), expired, run]).includes('REQUIRED_APPROVAL_MISSING'));
  assert.ok(codes([decision(1, 'require_approval', {clockUncertaintyMs: 'unknown'}), run]).includes('REQUIRED_APPROVAL_TIME_UNCERTAIN'));
});

test('repeated denies for one actor are counted across actions within the window', () => {
  const here = decision(10, 'deny', {actionId: 'a1'});
  const other = (minutes, over = {}) => ({...decision(minutes, 'deny', {actionId: `other-${minutes}`, ...over}), seq: 100 + serial});
  const retained = [here, other(6), other(8), other(30), other(9, {actor: 'someone-else'}), {...here, seq: 1}];
  const related = relatedDenyInput([here], retained);
  assert.deepEqual(related.map(r => r.occurredAt), [at(6), at(8)], 'same actor, other actions, inside the window only');
  assert.deepEqual(Object.keys(related[0]).sort(), ['actionId', 'actor', 'id', 'occurredAt', 'seq', 'source'], 'minimal summaries');
  assert.ok(codes([here], {relatedDecisions: related}).includes('REPEATED_DENIES'));
  assert.ok(!codes([here], {relatedDecisions: related.slice(1)}).includes('REPEATED_DENIES'), `threshold ${REPEATED_DENIES.threshold}`);
  assert.equal(relatedDenyInput([intent(1)], retained), undefined, 'no deny in the action: no related input');
  const many = Array.from({length: 80}, (_, i) => ({...other(9), id: `m${i}`, seq: 1000 + i}));
  assert.equal(relatedDenyInput([here], many).length, REPEATED_DENIES.related);
});

test('decision intake: allowlisted fields, enforcement source only, validated values', () => {
  const enforcement = {id: 'alpha-enforcement', tenant: 'alpha', kind: 'enforcement'}, agent = {id: 'alpha-agent', tenant: 'alpha', kind: 'agent'};
  const raw = {id: 'd-1', actionId: 'a1', traceId: 't1', kind: 'policy_decision', occurredAt: new Date().toISOString(), decision: 'deny', actor: 'agent-x',
    tool: 'mailer', action: 'send', resource: 'r', destination: 'x.example', decisionId: 'opa-1', enforcementPointId: 'gw-1', engine: 'opa',
    engineVersion: '1.4.0',
    policyId: 'http/authz/allow', policyVersion: 'rev-1', bundleDigest: 'sha256:' + 'a'.repeat(64), latencyMs: 3, recordedBeforeExecution: true};
  const accepted = validateEvent(raw, enforcement);
  assert.equal(accepted.decision, 'deny');assert.equal(accepted.latencyMs, 3);assert.equal(accepted.sourceKind, 'enforcement');
  assert.equal(validateEvent({...raw, kind: 'guardrail_decision', decision: 'modify'}, enforcement).kind, 'guardrail_decision');
  const status = (value, principal = enforcement) => {try {validateEvent(value, principal); return 200;} catch (error) {return error.status;}};
  assert.equal(status({...raw, input: {prompt: 'secret'}}), 400, 'unknown field (an input body) is rejected');
  assert.equal(status(raw, agent), 403, 'an agent source cannot report a policy decision');
  assert.equal(status({...raw, kind: 'execution'}), 403, 'an enforcement source reports decisions only');
  assert.equal(status({id: 'i-1', actionId: 'a1', traceId: 't1', kind: 'intent', occurredAt: raw.occurredAt, decision: 'allow'}, agent), 400,
    'decision fields belong to enforcement records only');
  for (const bad of [{decision: 'block'}, {latencyMs: -1}, {latencyMs: 1.5}, {recordedBeforeExecution: 'yes'}, {decisionId: undefined},
    {enforcementPointId: 'bad id'}, {engine: undefined}, {actor: undefined}, {tool: undefined, action: undefined}, {bundleDigest: 'x'}]) {
    assert.equal(status(Object.fromEntries(Object.entries({...raw, ...bad}).filter(([, v]) => v !== undefined))), 400, JSON.stringify(bad));
  }
});

test('risk tiers come from rules over tools, data categories and destinations', () => {
  assert.equal(computeRisk({tools: [{name: 'search'}], dataCategories: ['public'], destinations: ['wiki.corp']}).computed, 'low');
  assert.equal(computeRisk({tools: [{name: 'email_send'}]}).computed, 'medium');
  assert.equal(computeRisk({destinations: ['api.vendor.example']}).computed, 'medium', 'external destination');
  const high = computeRisk({tools: [{name: 'payment_transfer'}, {name: 'search'}], dataCategories: ['personal']});
  assert.equal(high.computed, 'high');
  assert.deepEqual(high.tools, [{name: 'payment_transfer', tier: 'high'}, {name: 'search', tier: 'low'}]);
  assert.deepEqual(high.reasons.map(r => r.rule).sort(), ['data-sensitive', 'tool-payment']);
});

test('offline lifecycle check accepts the API shape and names forged transitions', () => {
  const rows = [];let seq = 0;
  const push = (type, principal, payload) => rows.push({seq: ++seq, type, principal, payload});
  const entry = {id: 'agent-x', registeredBy: 'alice', editedBy: 'alice', sources: [], actors: ['agent-x'], models: [], tools: [], dataCategories: [],
    destinations: [], fingerprint: {}};
  push('agent_registry', 'alice', {...entry, version: 1, state: 'draft', change: 'created'});
  push('agent_transition', 'alice', {id: 't1', agentId: 'agent-x', from: 'draft', to: 'testing', requestedBy: 'alice', registryVersion: 1, status: 'applied'});
  push('agent_registry', 'alice', {...entry, version: 2, state: 'testing', change: 'transition', lastTransition: {id: 't1'}});
  push('agent_transition', 'bob', {id: 't2', agentId: 'agent-x', from: 'testing', to: 'approved', requestedBy: 'bob', registryVersion: 2, status: 'pending'});
  const approved = {id: 't2', agentId: 'agent-x', from: 'testing', to: 'approved', requestedBy: 'bob', registryVersion: 2, status: 'approved',
    reviewedBy: 'carol'};
  push('agent_transition', 'carol', approved);
  push('agent_registry', 'carol', {...entry, version: 3, state: 'approved', change: 'transition', lastTransition: {id: 't2'}});
  assert.deepEqual(verifyRegistryHistory(rows).problems, []);
  const forged = structuredClone(rows);forged[4] = {...forged[4], principal: 'bob', payload: {...approved, reviewedBy: 'bob'}};
  assert.ok(verifyRegistryHistory(forged).problems.some(p => /four-eyes/.test(p.message)), 'requester approving');
  const skipped = structuredClone(rows.slice(0, 1));
  skipped.push({seq: 2, type: 'agent_registry', principal: 'alice', payload: {...entry, version: 2, state: 'production',
    change: 'transition', lastTransition: {id: 'none'}}});
  assert.ok(verifyRegistryHistory(skipped).problems.some(p => /without an applied or approved transition/.test(p.message)));
  const changed = structuredClone(rows);
  changed.push({seq: 7, type: 'agent_registry', principal: 'alice', payload: {...entry, tools: [{name: 'shell'}], version: 4,
    state: 'approved', change: 'updated'}});
  assert.ok(verifyRegistryHistory(changed).problems.some(p => /configuration changed in approved/.test(p.message)));
});
