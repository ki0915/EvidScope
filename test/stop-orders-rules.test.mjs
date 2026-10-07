// Stop orders, enforcement bundles and propagation (docs/kill-switch.md) as pure functions: point-in-time findings, the engine
// that names them, the OPA bundle format (parsed here from its own tar.gz with an independent OPA file hash), bundle signing,
// the DSSE deny-list, the activation record allowlist and the offline stop-order history check.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash, generateKeyPairSync, verify as cryptoVerify} from 'node:crypto';
import {gunzipSync} from 'node:zlib';
import {EVALUATION_ENGINE_V2, EVALUATION_ENGINE_V4, boundedEvaluation, evaluate, evaluationEngine, validateEvent} from '../src/model.mjs';
import {contentRevisions, revisionOf, stopOrderAnalysisInput, stopOrderPropagation, verifyStopOrderHistory} from '../src/stop-orders.mjs';
import {DENY_LIST_PAYLOAD_TYPE, bundleSigner, denyList, enforcementState, goCanonical, opaBundle, signDenyList} from '../src/enforcement-bundle.mjs';
import {ed25519Verifier, openEnvelope} from '../src/dsse.mjs';

const T0 = Date.parse('2026-10-07T10:00:00.000Z'), at = s => new Date(T0 + s * 1000).toISOString();
const row = (seq, type, payload, recordedAt = at(0), principal = 'alice') =>
  ({seq, type, payload, recordedAt, principal, hash: createHash('sha256').update(`${seq}:${type}`).digest('hex')});
const entry = {id: 'mail-agent', version: 3, state: 'production', sources: ['alpha-agent'], actors: ['mail-agent'],
  tools: [{name: 'mailer', enforcement: 'required'}]};
const order = (id, extra = {}) => ({id, agentId: 'mail-agent', registryVersion: 3, entryState: 'production', scope: 'agent', tools: [], reason: 'incident',
  evidence: [], target: {sources: ['alpha-agent'], actors: ['mail-agent']}, enforcementPoints: [{id: 'gw', basis: ['policy']}],
  propagation: {windowSeconds: 60, policyVersion: 1, policySource: 'signed'}, issuedBy: 'alice', issuedAt: at(0), status: 'active', version: 1,
  change: 'issued', effectiveFrom: at(0), ...extra});
const rows = [row(1, 'agent_registry', entry, at(-100)), row(2, 'agent_stop_order', order('stop-1'))];
const activation = (seq, source, revision, seconds, extra = {}) => ({seq, id: `act-${seq}`, actionId: `act-${seq}`, source, sourceKind: 'enforcement',
  kind: 'bundle_activation', bundleRevision: revision, enforcementPointId: 'opa-1', occurredAt: at(seconds), receivedAt: at(seconds), ...extra});
const exec = (id, seconds, extra = {}) => ({id, actionId: id, traceId: 't', source: 'alpha-tool', sourceKind: 'tool', kind: 'execution', status: 'success',
  actor: 'mail-agent', tool: 'mailer', occurredAt: at(seconds), receivedAt: at(seconds), tenant: 'alpha', ...extra});
const codes = (events, stopOrders) => evaluate(events, [], [], [], T0 + 3600e3, {stopOrders}).findings.map(f => f.code).filter(c => /^STOP_/.test(c));

test('stop-order findings are judged at the time of each event: not held, missing propagation and uncertain order', () => {
  assert.equal(stopOrderAnalysisInput([rows[0]], []), undefined, 'no stop order: no snapshot key');
  const revision = revisionOf(rows[1]), input = stopOrderAnalysisInput(rows, [activation(3, 'gw', revision, 10), activation(4, 'gw', revision, 30),
    activation(5, 'other-gw', revision, 1), activation(6, 'gw', revisionOf(rows[0]), 0)]);
  assert.deepEqual(input.activations.map(a => [a.seq, a.source]), [[3, 'gw']], 'only the first activation of a covering point and a containing revision');
  assert.deepEqual(codes([exec('before', -30)], input), [], 'before the order');
  assert.deepEqual(codes([exec('early', 5)], input), [], 'after the order, before any activation and inside the window');
  assert.deepEqual(codes([exec('held', 20)], input), ['STOP_ORDER_NOT_HELD']);
  assert.deepEqual(codes([exec('fuzzy', 20, {clockUncertaintyMs: 15000})], input), ['STOP_PROPAGATION_TIME_UNCERTAIN']);
  assert.deepEqual(codes([exec('unknown-clock', 20, {clockUncertaintyMs: 'unknown'})], input), [], 'an unknown clock bound decides nothing');
  const silent = stopOrderAnalysisInput(rows, []);
  const intent = (id, seconds) => ({...exec(id, seconds), source: 'alpha-agent', sourceKind: 'agent', kind: 'intent', status: undefined});
  assert.deepEqual(codes([intent('in-window', 30)], silent), [], 'deadline not passed');
  assert.deepEqual(codes([intent('after-deadline', 120)], silent), ['STOP_PROPAGATION_MISSING']);
  const late = stopOrderAnalysisInput(rows, [activation(3, 'gw', revision, 90)]);
  assert.deepEqual(codes([exec('late', 120)], late), ['STOP_ORDER_NOT_HELD', 'STOP_PROPAGATION_MISSING'], 'activated, but after the window');
  // A claimed activation before its revision was signed is raised to the signing time.
  const claimed = stopOrderAnalysisInput([rows[0], row(2, 'agent_stop_order', order('stop-1'), at(50))], [activation(3, 'gw', revisionOf(row(2, 'x')), -500)]);
  assert.equal(claimed.activations.length, 0, 'a revision this ledger never produced is not an activation');
  const signedLater = [rows[0], row(2, 'agent_stop_order', order('stop-1'), at(50))], laterRevision = revisionOf(row(2, 'agent_stop_order', {}, at(50)));
  const raised = stopOrderAnalysisInput(signedLater, [activation(3, 'gw', laterRevision, -500, {receivedAt: at(60)})]);
  assert.equal(raised.activations[0].activatedAt, at(50));
  // A claimed activation after the vault received the report is lowered to the receipt time.
  const lowered = stopOrderAnalysisInput(signedLater, [activation(3, 'gw', laterRevision, 400, {receivedAt: at(70)})]);
  assert.equal(lowered.activations[0].activatedAt, at(70));
});

test('lifted and tool-scoped orders apply only while active and only to their tools; the engine is v4 only with stop orders', () => {
  const lifted = [...rows, row(3, 'agent_stop_order', {...order('stop-1'), version: 2, status: 'lifted', change: 'lifted', effectiveFrom: at(200)}, at(200))];
  const input = stopOrderAnalysisInput(lifted, []);
  assert.deepEqual(input.orders.map(o => [o.endSeq, o.endedAt]), [[3, at(200)]]);
  assert.deepEqual(codes([exec('during', 120)], input), ['STOP_PROPAGATION_MISSING']);
  assert.deepEqual(codes([exec('after-lift', 300)], input), [], 'after the lift');
  const tools = stopOrderAnalysisInput([rows[0], row(2, 'agent_stop_order', order('stop-t', {scope: 'tools', tools: ['shell']}))], []);
  assert.deepEqual(codes([exec('mail', 120)], tools), [], 'another tool');
  assert.deepEqual(codes([exec('shell', 120, {tool: 'shell'})], tools), ['STOP_PROPAGATION_MISSING']);
  assert.equal(evaluationEngine({events: [], stopOrders: input}), EVALUATION_ENGINE_V4);
  assert.equal(evaluationEngine({events: [], registry: {entries: [], policies: []}}), EVALUATION_ENGINE_V2);
  const limits = {findings: 100, resultBytes: 1024 * 1024};
  const job = {events: [exec('shell', 120, {tool: 'shell'})], assets: [], rules: [], exceptions: [], analysisTime: T0};
  assert.deepEqual(boundedEvaluation({...job}, limits).findings.filter(f => /^STOP_/.test(f.code)), [], 'no stop-order input, no stop findings');
  assert.ok(boundedEvaluation({...job, stopOrders: tools}, limits).findings.some(f => f.code === 'STOP_PROPAGATION_MISSING'));
});

test('propagation view: latency per enforcement point, overdue and not covering points', () => {
  const revision = revisionOf(rows[1]);
  const [view] = stopOrderPropagation(rows, [activation(3, 'gw', revision, 12), activation(4, 'other-gw', revision, 3)], T0 + 600e3);
  assert.deepEqual([view.orderId, view.propagation, view.windowSeconds, view.deadline], ['stop-1', 'activated_in_window', 60, at(60)]);
  assert.deepEqual(view.points.map(p => [p.id, p.covering, p.status, p.firstActivation.latencyMs]),
    [['gw', true, 'activated_in_window', 12000], ['other-gw', false, 'activated_in_window', 3000]]);
  assert.equal(stopOrderPropagation(rows, [], T0 + 30e3)[0].propagation, 'pending');
  assert.equal(stopOrderPropagation(rows, [], T0 + 61e3)[0].propagation, 'overdue');
  const nobody = [rows[0], row(2, 'agent_stop_order', order('stop-1', {enforcementPoints: []}))];
  assert.equal(stopOrderPropagation(nobody, [], T0)[0].propagation, 'no_enforcement_point');
  assert.deepEqual([...contentRevisions(rows).keys()], [revisionOf(rows[0]), revision]);
});

// Independent OPA file hash (v1/bundle/hash.go): parse, walk objects in byte order of keys, Go-encode primitives.
function opaHash(bytes) {
  const walk = v => Array.isArray(v) ? `[${v.map(walk).join(',')}]` : v && typeof v === 'object'
    ? `{${Object.keys(v).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b))).map(k => `${JSON.stringify(k)}:${walk(v[k])}`).join(',')}}`
    : JSON.stringify(v);
  return createHash('sha256').update(walk(JSON.parse(bytes.toString('utf8')))).digest('hex');
}
function untar(gz) {
  const tar = gunzipSync(gz), files = new Map();
  for (let offset = 0; offset + 512 <= tar.length;) {
    const header = tar.subarray(offset, offset + 512);if (header.every(b => b === 0)) break;
    const name = header.subarray(0, 100).toString('utf8').replace(/\0.*$/s, ''), size = parseInt(header.subarray(124, 136).toString('utf8'), 8);
    let sum = 0;for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 32 : header[i];
    assert.equal(parseInt(header.subarray(148, 156).toString('utf8'), 8), sum, `${name} header checksum`);
    assert.equal(header.subarray(257, 263).toString('binary'), 'ustar\0');assert.equal(String.fromCharCode(header[156]), '0');
    files.set(name, tar.subarray(offset + 512, offset + 512 + size));offset += 512 + Math.ceil(size / 512) * 512;
  }
  return files;
}
const state = enforcementState({tenant: 'alpha', revision: '7-0123456789abcdef',
  entries: [entry, {...entry, id: 'old', state: 'retired', actors: ['mail-agent', 'x']}],
  orders: [order('stop-1'), order('stop-t', {scope: 'tools', tools: ['shell']}), {...order('gone'), status: 'lifted'}]});

test('the OPA bundle is a gzip tar with .manifest and data.json under one root, and signs with ES256 or RS256 only', () => {
  assert.deepEqual(state.agents['mail-agent'], {state: 'production', stopped: true, stopped_tools: ['shell'], stop_orders: ['stop-1', 'stop-t'],
    sources: ['alpha-agent'], actors: ['mail-agent'], tools: {mailer: {enforcement: 'required'}}});
  assert.deepEqual([state.actors['mail-agent'], state.actors.x], ['mail-agent', 'old'], 'a live entry answers before a retired one');
  assert.deepEqual(Object.keys(state.stop_orders), ['stop-1', 'stop-t'], 'lifted orders are not distributed');
  const plain = untar(opaBundle(state, {mtime: T0}));
  assert.deepEqual([...plain.keys()], ['/.manifest', '/data.json']);
  const manifest = JSON.parse(plain.get('/.manifest')), data = JSON.parse(plain.get('/data.json'));
  assert.deepEqual(manifest, {revision: '7-0123456789abcdef', roots: ['evidscope'], metadata: {format: 'evidscope-enforcement-bundle-v1', tenant: 'alpha'}});
  assert.deepEqual(Object.keys(data), ['evidscope']);assert.deepEqual(data.evidscope, JSON.parse(JSON.stringify(state)));
  assert.ok(opaBundle(state, {mtime: T0}).equals(opaBundle(state, {mtime: T0})), 'one revision, one byte string');
  for (const options of [{namedCurve: 'P-256', type: 'ec', alg: 'ES256'}, {modulusLength: 2048, type: 'rsa', alg: 'RS256'}]) {
    const {privateKey, publicKey} = generateKeyPairSync(options.type, options);
    const signer = bundleSigner(privateKey.export({format: 'pem', type: 'pkcs8'}), 'kid-1');
    const files = untar(opaBundle(state, {signer})), {signatures} = JSON.parse(files.get('/.signatures.json'));
    assert.equal(signatures.length, 1);
    const [header, payload, signature] = signatures[0].split('.');
    assert.deepEqual(JSON.parse(Buffer.from(header, 'base64url')), {alg: options.alg, kid: 'kid-1', typ: 'JWT'});
    const claims = JSON.parse(Buffer.from(payload, 'base64url'));
    assert.deepEqual(claims.files.map(f => [f.name, f.algorithm, f.hash]), [['.manifest', 'SHA-256', opaHash(files.get('/.manifest'))],
      ['data.json', 'SHA-256', opaHash(files.get('/data.json'))]]);
    assert.equal(claims.keyid, 'kid-1');
    const key = options.type === 'ec' ? {key: publicKey, dsaEncoding: 'ieee-p1363'} : publicKey;
    assert.ok(cryptoVerify('sha256', Buffer.from(`${header}.${payload}`), key, Buffer.from(signature, 'base64url')));
  }
  const ed = generateKeyPairSync('ed25519').privateKey.export({format: 'pem', type: 'pkcs8'});
  assert.throws(() => bundleSigner(ed), /RSA .* or EC P-256/, 'OPA verifies no Ed25519 bundle signature');
  const hmacLike = generateKeyPairSync('ec', {namedCurve: 'P-384'}).privateKey.export({format: 'pem', type: 'pkcs8'});
  assert.throws(() => bundleSigner(hmacLike), /P-256/);
  assert.equal(goCanonical({b: ['é', 1, true, null], a: '<&>'}), '{"a":"<&>","b":["é",1,true,null]}', 'no HTML escaping, byte-ordered keys');
});

test('the deny-list is DSSE-signed with the vault key; tampering and a wrong key are refused', () => {
  const vault = generateKeyPairSync('ed25519'), list = denyList(state);
  assert.deepEqual(list.entries.map(e => [e.agent, e.deny, e.tools]), [['mail-agent', 'all', []], ['old', 'all', []]]);
  const envelope = signDenyList(list, vault.privateKey), verifier = ed25519Verifier(vault.publicKey);
  const opened = openEnvelope(envelope, [verifier], {payloadTypes: [DENY_LIST_PAYLOAD_TYPE]});
  assert.deepEqual(JSON.parse(opened.body), list);
  const tampered = {...envelope, payload: Buffer.from(JSON.stringify({...list, entries: []})).toString('base64')};
  assert.throws(() => openEnvelope(tampered, [verifier], {payloadTypes: [DENY_LIST_PAYLOAD_TYPE]}), /verification failed/);
  assert.throws(() => openEnvelope(envelope, [ed25519Verifier(generateKeyPairSync('ed25519').publicKey)], {payloadTypes: [DENY_LIST_PAYLOAD_TYPE]}),
    /verification failed/);
  assert.throws(() => openEnvelope(envelope, [verifier]), /Unsupported DSSE payload type/, 'not an in-toto statement');
  const toolsOnly = denyList(enforcementState({tenant: 'alpha', revision: '1-0000000000000000', entries: [entry],
    orders: [order('t', {scope: 'tools', tools: ['shell']})]}));
  assert.deepEqual(toolsOnly.entries.map(e => [e.deny, e.tools]), [['tools', ['shell']]]);
});

test('bundle activation records are allowlisted, enforcement-only and name an EvidScope revision', () => {
  const p = {id: 'alpha-gateway', tenant: 'alpha', kind: 'enforcement'}, now = new Date().toISOString();
  const raw = {id: 'a-1', kind: 'bundle_activation', occurredAt: now, actionId: 'a-1', traceId: 'a-1', enforcementPointId: 'opa-1', engine: 'opa',
    bundleName: 'evidscope', bundleRevision: '12-0123456789abcdef'};
  assert.equal(validateEvent(raw, p).bundleRevision, '12-0123456789abcdef');
  assert.throws(() => validateEvent({...raw, labels: {app: 'x'}}, p), /미수집 또는 예약 필드/);
  assert.throws(() => validateEvent({...raw, decision: 'deny'}, p), /결정·대상 필드/);
  assert.throws(() => validateEvent({...raw, actor: 'mail-agent'}, p), /결정·대상 필드/);
  assert.throws(() => validateEvent({...raw, bundleRevision: 'ABC'}, p), /리비전/);
  assert.throws(() => validateEvent({...raw, kind: 'policy_decision'}, p), /묶음 활성화 필드/);
  assert.throws(() => validateEvent(raw, {...p, kind: 'tool'}), /허용되지 않은 이벤트 유형/);
});

test('offline stop-order history accepts the API shape and names forged lifts and suspensions', () => {
  const t = {id: 'tr-1', agentId: 'mail-agent', from: 'production', to: 'suspended', status: 'applied', requestedBy: 'alice', stopOrderId: 'stop-1',
    registryVersion: 3};
  const issued = row(2, 'agent_stop_order', order('stop-1', {suspension: {transitionId: 'tr-1'}}));
  const base = [rows[0], issued, row(3, 'agent_transition', t), row(4, 'agent_registry', {...entry, version: 4, state: 'suspended'})];
  assert.equal(verifyStopOrderHistory(base).valid, true, JSON.stringify(verifyStopOrderHistory(base).problems));
  assert.match(verifyStopOrderHistory([rows[0], issued]).problems[0].message, /suspension transition is missing/);
  const requested = row(5, 'agent_stop_order', {...issued.payload, version: 2, change: 'lift_requested', liftRequest: {by: 'bob', reason: 'x'}}, at(1), 'bob');
  const selfLift = row(6, 'agent_stop_order', {...issued.payload, version: 3, change: 'lifted', status: 'lifted', liftRequest: null,
    lift: {via: 'approval', requestedBy: 'bob', approvedBy: 'bob'}}, at(2), 'bob');
  const problems = verifyStopOrderHistory([...base, requested, selfLift]).problems.map(p => p.message);
  assert.ok(problems.some(m => /four-eyes/.test(m)) && problems.some(m => /resumed only by an approved transition/.test(m)), problems.join('; '));
  const resume = row(7, 'agent_registry', {...entry, version: 5, state: 'production', lastTransition: {id: 'tr-2'}});
  assert.ok(verifyStopOrderHistory([...base, row(6, 'agent_transition', {...t, id: 'tr-2', from: 'suspended', to: 'production', status: 'approved',
    reviewedBy: 'carol'}), resume]).problems.some(p => /without lifting/.test(p.message)));
  const edited = row(5, 'agent_stop_order', {...issued.payload, version: 2, change: 'lift_requested', reason: 'other', liftRequest: {by: 'bob'}}, at(1), 'bob');
  assert.ok(verifyStopOrderHistory([...base, edited]).problems.some(p => /content changed/.test(p.message)));
});
