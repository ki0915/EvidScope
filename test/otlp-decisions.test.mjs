// OTLP decision spans (src/otlp.mjs mapDecisionSpan, src/otlp-ingest.mjs, docs/agent-registry.md): the kube-agentic-networking
// proposal 0033 examples, the allowlist, which credential may store a decision, idempotency and the decision rules on the result.
import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {tmpdir} from 'node:os';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {randomBytes} from 'node:crypto';
import {harness} from './harness.mjs';
import {initialize} from '../scripts/init.mjs';
import {createService} from '../src/service.mjs';
import {submit} from '../src/client.mjs';
import {evaluate, EVALUATION_ENGINE, EVALUATION_ENGINE_V2} from '../src/model.mjs';
import {decodeTraceRequest, mapTraceRequest, otlpDecisionInvariant, OTLP_BATCH_FORMAT, OTLP_MAPPING_VERSION, SPAN_ATTRIBUTE_ALLOWLIST,
  DECISION_ATTRIBUTE_ALLOWLIST, CONTENT_ATTRIBUTE_KEYS} from '../src/otlp.mjs';

const TRACE = 'f5a9d214e6b8c7a9d1e2f3a4b5c6d7e8', GUARD_TRACE = 'c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8';
const CANARIES = ["User role 'support_agent' lacks privileges", 'PII detected', 'arguments.body', 'ssn', 'eyJhbGc', 'sess_agent_2p7k4m', '12345',
  'authorization_failure', 'span name canary'];
const nanos = ms => String(BigInt(ms) * 1000000n);
const value = v => typeof v === 'boolean' ? {boolValue: v} : Array.isArray(v) ? {arrayValue: {values: v.map(x => ({stringValue: x}))}} : {stringValue: v};
const span = (spanId, attributes, {trace = TRACE, start = Date.now() - 60000, ms = 15, parent, error} = {}) => ({traceId: trace, spanId,
  ...(parent ? {parentSpanId: parent} : {}), name: 'span name canary', kind: 1, startTimeUnixNano: nanos(start), endTimeUnixNano: nanos(start + ms),
  attributes: Object.entries(attributes).map(([key, v]) => ({key, value: value(v)})),
  status: error ? {code: 2, message: error} : {code: 1}});
const request = spans => JSON.stringify({resourceSpans: [{resource: {attributes: [{key: 'service.name', value: {stringValue: 'mcp-gateway'}}]},
  scopeSpans: [{scope: {name: 'gateway'}, spans}]}]});
// The "Access policy enforcement" example of proposal 0033 (span ids widened to 16 hex digits). `enrich` adds what the
// authorization span needs to name its target, which the example keeps on the parent request span.
function accessTrace({enrich = false, start = Date.now() - 60000} = {}) {
  return [
    span('5e6f7a8b00000001', {'http.response.status_code': '403', 'gen_ai.operation.name': 'execute_tool', 'gen_ai.tool.name': 'delete_customer_data',
      'mcp.method.name': 'tools/call', 'mcp.session.id': 'sess_agent_2p7k4m', 'error.type': 'PermissionDeniedError'},
    {start, ms: 17, parent: '4e5f6a7b00000001', error: 'Permission denied: customer_id 12345'}),
    span('7a8b9c1d00000001', {'security_rule.ruleset.name': 'crm_data_access_policy', 'event.action': 'deny', 'event.outcome': 'success',
      'error.type': 'PermissionDeniedError', 'error.message': "User role 'support_agent' lacks privileges for customer_data.delete",
      ...(enrich ? {'gen_ai.agent.id': 'claude-agent-prod-001', 'gen_ai.tool.name': 'delete_customer_data'} : {})},
    {start: start + 1, ms: 15, parent: '5e6f7a8b00000001', error: 'Bearer eyJhbGc'}),
    span('2e3f4a5b00000001', {'security_rule.name': 'default-deny', 'security_rule.implicit': true, 'event.action': 'deny', 'event.outcome': 'success'},
      {start: start + 2, ms: 1, parent: '7a8b9c1d00000001'}),
    span('8b9c1d2e00000001', {'audit.event.type': 'authorization_failure', 'audit.event.category': 'security', 'audit.event.outcome': 'failure'},
      {start: start + 16, ms: 2, parent: '5e6f7a8b00000001'}),
  ];
}
// The "Guardrailing" example of proposal 0033, the evaluate span enriched with its target.
const guardTrace = (start = Date.now() - 60000) => [
  span('7a8b9c1d00000002', {'security_rule.ruleset.name': 'pii_detection_policy', 'event.action': 'deny', 'event.outcome': 'success',
    'error.type': 'GuardrailViolationError', 'error.message': 'PII detected: SSN, Credit Card', 'gen_ai.agent.id': 'claude-agent-prod-001',
    'gen_ai.tool.name': 'send_email'}, {trace: GUARD_TRACE, start, ms: 25}),
  span('1d2e3f4a00000002', {'security_rule.name': 'block_sensitive_pii', 'security_rule.match': true, 'event.action': 'deny', 'event.outcome': 'success',
    'guardrail.pii.types_detected': ['ssn', 'credit_card'], 'guardrail.pii.confidence': 'high', 'guardrail.pii.field': 'arguments.body'},
  {trace: GUARD_TRACE, start: start + 1, ms: 2}),
];
const map = spans => mapTraceRequest(decodeTraceRequest(request(spans), 'json'));

test('0033 decision spans become allowlisted candidates; rule, audit and target-less spans are not stored', () => {
  assert.ok(DECISION_ATTRIBUTE_ALLOWLIST.every(k => !CONTENT_ATTRIBUTE_KEYS.includes(k) && !SPAN_ATTRIBUTE_ALLOWLIST.includes(k)));
  const verbatim = map(accessTrace());
  assert.deepEqual(verbatim.decisions, []);
  assert.deepEqual(verbatim.rejected, {decision_target_missing: 1, decision_rule_span: 1, not_genai: 1});
  assert.deepEqual(verbatim.events.map(e => [e.kind, e.action, e.tool]), [['self_report', 'execute_tool', 'delete_customer_data']]);
  const start = Date.parse('2026-10-07T09:00:00.000Z'), {decisions, rejected} = map([...accessTrace({enrich: true, start}), ...guardTrace(start)]);
  assert.deepEqual(rejected, {decision_rule_span: 2, not_genai: 1});
  assert.deepEqual(decisions[0], {id: `otel-decision:${TRACE}:7a8b9c1d00000001`, kind: 'policy_decision', occurredAt: '2026-10-07T09:00:00.016Z',
    traceId: TRACE, actionId: `otel-trace:${TRACE}`, actor: 'claude-agent-prod-001', tool: 'delete_customer_data', decision: 'deny',
    decisionId: `otel:${TRACE}:7a8b9c1d00000001`, status: 'success', policyId: 'crm_data_access_policy', latencyMs: 15});
  assert.deepEqual([decisions[1].policyId, decisions[1].tool, decisions[1].decision], ['pii_detection_policy', 'send_email', 'deny']);
  assert.ok(decisions.every(otlpDecisionInvariant));
  const text = JSON.stringify(decisions);
  for (const canary of CANARIES) assert.ok(!text.includes(canary), canary);
  // Values outside 0033 (allow/deny) are not guessed; the MCP method names the action only when no tool is named.
  const odd = map([span('aa00000000000001', {'event.action': 'block', 'gen_ai.agent.id': 'a'}),
    span('aa00000000000002', {'event.action': 'allow', 'agent.id': 'agent-7', 'mcp.method.name': 'resources/read', 'event.outcome': 'bogus',
      'security_rule.ruleset.name': 'rules with spaces', 'security_rule.version': '3'})]);
  assert.deepEqual(odd.rejected, {unsupported_decision: 1});
  assert.deepEqual([odd.decisions[0].actor, odd.decisions[0].action, odd.decisions[0].status, odd.decisions[0].policyVersion],
    ['agent-7', 'resources/read', undefined, '3']);
  assert.match(odd.decisions[0].policyId, /^otel-ruleset:[0-9a-f]{32}$/);
  // A decision span that is also a GenAI span yields both, the candidate marked as its companion.
  const both = map([span('bb00000000000001', {'gen_ai.operation.name': 'execute_tool', 'gen_ai.tool.name': 'payroll', 'gen_ai.agent.id': 'pay-agent',
    'event.action': 'allow'})]);
  assert.equal(both.events.length, 1); assert.equal(both.decisions[0].companion, true); assert.deepEqual(both.rejected, {});
  for (const [mutate, name] of [[d => { d.note = 'x'; }, 'free text'], [d => { d.enforcementPointId = 'forged'; }, 'point'],
    [d => { d.recordedBeforeExecution = true; }, 'before execution'], [d => { d.action = 'tools/call'; }, 'tool and action'],
    [d => { d.decision = 'modify'; }, 'decision'], [d => { d.actionId = 'pay-1'; }, 'action id'], [d => { d.latencyMs = -1; }, 'latency']]) {
    const copy = structuredClone(decisions[0]); mutate(copy); assert.equal(otlpDecisionInvariant(copy), false, name);
  }
});

test('protobuf and JSON encodings of a decision span map to the same candidate', () => {
  const varint = n => { const out = []; let v = BigInt(n); do { let b = Number(v & 0x7fn); v >>= 7n; if (v) b |= 0x80; out.push(b); } while (v);
    return Buffer.from(out); };
  const ld = (field, payload) => { const b = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, 'utf8');
    return Buffer.concat([varint((field << 3) | 2), varint(b.length), b]); };
  const f64 = (field, n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return Buffer.concat([varint((field << 3) | 1), b]); };
  const start = Date.parse('2026-10-07T09:00:00.000Z'), [json] = accessTrace({enrich: true, start}).slice(1, 2);
  const attrs = json.attributes.map(({key, value: v}) => ld(9, Buffer.concat([ld(1, key), ld(2, ld(1, v.stringValue))])));
  const pb = ld(1, Buffer.concat([ld(1, ld(1, Buffer.concat([ld(1, 'service.name'), ld(2, ld(1, 'mcp-gateway'))]))), ld(2, ld(2, Buffer.concat([
    ld(1, Buffer.from(TRACE, 'hex')), ld(2, Buffer.from(json.spanId, 'hex')), ld(5, 'span name canary'), f64(7, json.startTimeUnixNano),
    f64(8, json.endTimeUnixNano), ...attrs])))]));
  const fromPb = mapTraceRequest(decodeTraceRequest(pb, 'protobuf')).decisions;
  assert.equal(fromPb.length, 1); assert.deepEqual(fromPb, map([json]).decisions);
});

function vault(t, mutate = config => config) {
  mkdirSync('.test-runs', {recursive: true});
  const dir = mkdtempSync(resolve('.test-runs/otlp-decisions-')), config = mutate(initialize(dir));
  const s = createService({dataDir: join(dir, 'data'), config, key: readFileSync(join(dir, 'signing-private.pem'), 'utf8')});
  t.after(() => s.store.close());
  const ingest = (id, body) => s.handle('POST', new URL('http://localhost/api/ingest/otlp'),
    {authorization: `Bearer ${config.principals.find(p => p.id === id).token}`}, body);
  return {s, config, ingest};
}
const gateway = (over = {}) => ({id: 'alpha-gateway', tenant: 'alpha', role: 'source', kind: 'enforcement', token: randomBytes(32).toString('base64url'),
  hmacSecret: randomBytes(32).toString('base64url'), otlpDecisions: {enforcementPointId: 'mcp-gw-1', engine: 'envoy-ext-authz'}, ...over});
const batch = mapped => JSON.stringify({format: OTLP_BATCH_FORMAT, mapping: OTLP_MAPPING_VERSION, events: mapped.events,
  ...(mapped.decisions.length ? {decisions: mapped.decisions} : {})});

test('only an enforcement source that opted in stores decisions; an otlp source cannot forge one', async t => {
  const {s, config, ingest} = vault(t, config => { config.principals.push(gateway(), gateway({id: 'alpha-plain-gateway', otlpDecisions: undefined}));
    return config; });
  const mapped = map([...accessTrace({enrich: true}), span('bb00000000000001', {'gen_ai.operation.name': 'execute_tool', 'gen_ai.tool.name': 'payroll',
    'gen_ai.agent.id': 'pay-agent', 'event.action': 'allow'})]);
  // OTLP source: GenAI events as before; standalone candidates refused, companions silent (their span is the GenAI event).
  const otlp = await ingest('alpha-otlp', batch(mapped));
  assert.deepEqual([otlp.accepted, otlp.reasons], [2, {decision_needs_enforcement_source: 1}]);
  const forged = {...mapped.decisions[0], id: `otel-decision:${TRACE}:7a8b9c1d000000ff`, decisionId: `otel:${TRACE}:7a8b9c1d000000ff`};
  const direct = await ingest('alpha-otlp', JSON.stringify({format: OTLP_BATCH_FORMAT, mapping: OTLP_MAPPING_VERSION, events: [],
    decisions: [forged, {...forged, companion: true}]}));
  assert.deepEqual([direct.accepted, direct.reasons], [0, {decision_needs_enforcement_source: 1}]);
  // Enforcement source without the opt-in: the route stays closed. Agent sources never had it.
  for (const id of ['alpha-plain-gateway', 'alpha-agent']) await assert.rejects(ingest(id, batch(mapped)), e => e.status === 403, id);
  // Opted-in gateway: decisions stored with the configured point and engine; GenAI events of other spans are refused.
  const first = await ingest('alpha-gateway', batch(mapped));
  assert.deepEqual([first.accepted, first.duplicates, first.reasons], [2, 0, {not_decision_span: 1}]);
  const again = await ingest('alpha-gateway', batch(mapped));
  assert.deepEqual([again.accepted, again.duplicates], [0, 2], 'resubmission is idempotent');
  const tampered = structuredClone(mapped); tampered.decisions[0].decision = 'allow';
  assert.deepEqual((await ingest('alpha-gateway', batch(tampered))).reasons, {id_conflict: 1, not_decision_span: 1});
  const smuggled = structuredClone(mapped); Object.assign(smuggled.decisions[0], {note: 'free text', recordedBeforeExecution: true});
  assert.equal((await ingest('alpha-gateway', batch(smuggled))).reasons.invalid_event, 1);
  const auditor = config.principals.find(p => p.role === 'auditor' && p.tenant === 'alpha');
  const stored = (await s.handle('GET', new URL('http://localhost/api/events?kind=policy_decision'), {authorization: `Bearer ${auditor.token}`})).items;
  assert.deepEqual(stored.map(e => [e.source, e.sourceKind, e.enforcementPointId, e.engine, e.decision, e.clockUncertaintyMs, e.recordedBeforeExecution])
    .sort(), [['alpha-gateway', 'enforcement', 'mcp-gw-1', 'envoy-ext-authz', 'allow', 'unknown', undefined],
    ['alpha-gateway', 'enforcement', 'mcp-gw-1', 'envoy-ext-authz', 'deny', 'unknown', undefined]]);
  assert.ok(stored.every(e => JSON.parse(e.note).adapter === 'otel-decision-map-1'));
  for (const canary of CANARIES) assert.ok(!JSON.stringify(stored).includes(canary), canary);
});

test('otlpDecisions is validated at startup and belongs to enforcement sources only', t => {
  for (const [name, over] of [['otlp kind', {kind: 'otlp', hmacSecret: undefined}], ['no point', {otlpDecisions: {}}],
    ['unknown option', {otlpDecisions: {enforcementPointId: 'gw', recordedBeforeExecution: true}}],
    ['bad clock', {otlpDecisions: {enforcementPointId: 'gw', clockUncertaintyMs: 900000}}], ['not an object', {otlpDecisions: true}]])
    assert.throws(() => vault(t, config => { config.principals.push(gateway(over)); return config; }), /Invalid credential configuration/, name);
});

test('decision rules fire on OTLP decisions received through the OTLP/HTTP receiver', async t => {
  const enforcement = gateway({otlpDecisions: {enforcementPointId: 'mcp-gw-1', engine: 'envoy-ext-authz', clockUncertaintyMs: 1000}});
  const unclocked = gateway({id: 'alpha-gateway-2', otlpDecisions: {enforcementPointId: 'mcp-gw-2'}});
  const h = await harness({beforeStart: ({dir}) => {
    const file = join(dir, 'config.json'), config = JSON.parse(readFileSync(file, 'utf8'));config.principals.push(enforcement, unclocked);
    writeFileSync(file, JSON.stringify(config));
  }});
  t.after(() => h.close());
  const send = (token, body) => fetch(`${h.ingress.url}/v1/traces`, {method: 'POST', headers: {'content-type': 'application/json',
    authorization: `Bearer ${token}`}, body}).then(async r => ({status: r.status, body: await r.json()}));
  const start = Date.now() - 120000, trace = accessTrace({enrich: true, start});
  const sent = await send(enforcement.token, request(trace));
  assert.equal(sent.status, 200); assert.equal(sent.body.partialSuccess.rejectedSpans, '3');
  // The tool runs the denied call anyway, 5 s after the decision, recorded under the trace's action id.
  const tool = h.principal('tool'), actionId = `otel-trace:${TRACE}`;
  const execution = {id: 'x-otlp-1', kind: 'execution', actionId, traceId: TRACE, actor: 'claude-agent-prod-001', tool: 'delete_customer_data',
    action: 'tools/call', status: 'success', occurredAt: new Date(start + 5000).toISOString(), clockUncertaintyMs: 500};
  assert.equal((await submit(h.ingress.url + '/', tool, execution)).status, 202);
  // A second gateway without a clock bound: the same deny can only be reported as order-uncertain.
  const other = 'ab'.repeat(16), unordered = accessTrace({enrich: true, start}).map(s => ({...s, traceId: other}));
  assert.equal((await send(unclocked.token, request(unordered))).status, 200);
  assert.equal((await submit(h.ingress.url + '/', tool, {...execution, id: 'x-otlp-2', actionId: `otel-trace:${other}`, traceId: other})).status, 202);
  for (let i = 0; i < 20; i++) { const r = (await h.analyze()).body; if (!r.backlog && !r.processed) break; }
  const codes = async id => (await h.api(`/api/actions/${encodeURIComponent(id)}`, {role: 'auditor'})).body.evaluations[0].findings.map(f => f.code);
  assert.ok((await codes(actionId)).includes('EXECUTION_AFTER_DENY'));
  const uncertain = await codes(`otel-trace:${other}`);
  assert.ok(uncertain.includes('DECISION_ORDER_UNCERTAIN') && !uncertain.includes('EXECUTION_AFTER_DENY'), uncertain.join());
  // Repeated denies across actions, from the stored records themselves.
  const stored = (await h.api('/api/events?kind=policy_decision&limit=50', {role: 'auditor'})).body.items;
  const denies = [0, 1, 2].map(i => ({...stored[0], id: `d${i}`, actionId: `a${i}`, occurredAt: new Date(start + i * 1000).toISOString()}));
  assert.ok(evaluate(denies, [], [], [], Date.now()).findings.some(f => f.code === 'REPEATED_DENIES'));
});

test('an export written before decision spans verifies and replays unchanged; GenAI mapping and span counts are as at 503c185', async t => {
  const fixture = JSON.parse(readFileSync(new URL('./fixtures/pre-decision-sources-export-503c185.json', import.meta.url), 'utf8'));
  const dir = mkdtempSync(join(tmpdir(), 'evidscope-pre-decision-sources-'));t.after(() => rmSync(dir, {recursive: true, force: true}));
  const file = join(dir, 'export.json'), key = join(dir, 'key.pem');
  writeFileSync(file, JSON.stringify(fixture.exportBundle));writeFileSync(key, fixture.publicKeyPem);
  const evaluations = fixture.exportBundle.records.filter(r => r.type === 'evaluation');
  for (const [script, args] of [['evidscope-verify.mjs', ['bundle']], ['verify.mjs', []]]) {
    const r = spawnSync(process.execPath, [fileURLToPath(new URL(`../scripts/${script}`, import.meta.url)), ...args, file, key, '--replay'],
      {encoding: 'utf8'});
    assert.equal(r.status, 0, r.stderr);
    const out = JSON.parse(r.stdout);
    assert.equal(out.replay.valid, true);assert.equal(out.replay.summary.replayed, evaluations.length);
    assert.ok(out.replay.evaluations.every(e => [EVALUATION_ENGINE, EVALUATION_ENGINE_V2].includes(e.engine) && e.inputs.snapshotHash === 'matches_record'));
  }
  assert.ok(evaluations.flatMap(r => r.payload.findings.map(f => f.code)).includes('EXECUTION_AFTER_DENY'));
  // The same OTLP request maps to byte-identical GenAI events; the decision span is still not stored for an otlp source and
  // still counts as one rejected span (now with its reason, at the vault, instead of not_genai at the receiver).
  const mapped = mapTraceRequest(decodeTraceRequest(JSON.stringify(fixture.otlpRequest), 'json'));
  assert.deepEqual(mapped.events, fixture.otlpEvents);
  assert.deepEqual(fixture.otlpRejected, {not_genai: 1});assert.deepEqual(mapped.rejected, {});assert.equal(mapped.decisions.length, 1);
  const {ingest} = vault(t);
  const result = await ingest('alpha-otlp', batch(mapped));
  assert.deepEqual([result.accepted, result.rejected, result.reasons], [fixture.otlpResult.accepted, 1, {decision_needs_enforcement_source: 1}]);
});
