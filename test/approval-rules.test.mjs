// Approval queue rules (src/approvals.mjs, docs/approval-queue.md): point-in-time findings for executions against in-vault
// approval requests, the require_approval rule satisfied by an in-vault approval, engine selection, and the signed answer a
// gateway verifies offline (DSSE), including tampering.
import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {EVALUATION_ENGINE, EVALUATION_ENGINE_V2, EVALUATION_ENGINE_V3, evaluate, evaluationEngine} from '../src/model.mjs';
import {APPROVAL_LIMITS, answerStatement, approvalAnalysisInput, approvalEligibility, approvalPolicyOf, approvalRequestId, approvalStatus, targetDigest,
  verifyApprovalAnswer} from '../src/approvals.mjs';
import {canonical} from '../src/crypto.mjs';
import {INTOTO_PAYLOAD_TYPE, signEnvelope} from '../src/dsse.mjs';
import {attestationSigner} from '../src/attestation-signer.mjs';

const T0 = Date.parse('2026-10-07T10:00:00.000Z'), at = s => new Date(T0 + s * 1000).toISOString();
const target = {actor: 'pay-agent', tool: 'payment_transfer', resource: 'order-7'};
const base = {tenant: 'alpha', actionId: 'pay-1', traceId: 't-1', receivedAt: at(0), clockUncertaintyMs: 0};
const exec = (s, extra = {}) => ({...base, ...target, id: `x-${s}`, source: 'alpha-tool', sourceKind: 'tool', kind: 'execution', status: 'success',
  occurredAt: at(s), ...extra});
const decision = {...base, ...target, id: 'd-1', source: 'alpha-gateway', sourceKind: 'enforcement', kind: 'policy_decision', decision: 'require_approval',
  engine: 'opa', decisionId: 'dec-1', enforcementPointId: 'gw', occurredAt: at(-60)};
const eligibility = {tier: 'high', approvers: 2, roles: ['reviewer', 'admin'], exclude: ['registrant', 'editor', 'owner'], excluded: ['alpha-registrant']};
function request(status, {decided = 0, window = 300, approvers = ['alpha-r1', 'alpha-r2'], expires = 600, extra = {}} = {}) {
  const v = {id: approvalRequestId('alpha', 'alpha-gateway', 'dec-1'), version: 1, status, decisionId: 'dec-1', actionId: 'pay-1', target,
    targetDigest: targetDigest(target), requestedAt: at(-30), expiresAt: at(expires), eligibility, approvals: [], refusal: null, decidedAt: null,
    executionWindow: null, policyVersion: 'p1'};
  if (status === 'approved') Object.assign(v, {approvals: approvers.map(by => ({by, role: 'reviewer', at: at(decided), reason: 'ok'})), decidedAt: at(decided),
    executionWindow: {notBefore: at(decided), notAfter: at(decided + window)}});
  if (status === 'refused') Object.assign(v, {refusal: {by: 'alpha-r1', role: 'reviewer', at: at(decided), reason: 'no'}, decidedAt: at(decided)});
  return {...v, ...extra};
}
const run = (events, requests, now = T0 + 3600e3) => evaluate(events, [], [], [], now, {approvals: approvalAnalysisInput(requests)});
const codes = result => result.findings.map(f => f.code).filter(c => /APPROVAL/.test(c) && c !== 'APPROVAL_REQUIREMENT_UNKNOWN').sort();

test('an in-vault approval inside its window satisfies require_approval; executions outside it are findings', () => {
  const approved = request('approved', {decided: 0, window: 300});
  assert.deepEqual(codes(run([decision, exec(10)], [approved])), [], 'inside the window');
  assert.deepEqual(codes(evaluate([decision, exec(10)], [], [], [], T0)), ['REQUIRED_APPROVAL_MISSING'], 'the same execution without the queue');
  assert.deepEqual(codes(run([decision, exec(400)], [approved])), ['APPROVAL_WINDOW_EXCEEDED']);
  assert.deepEqual(codes(run([decision, exec(-10)], [approved])), ['EXECUTION_BEFORE_APPROVAL'], 'executed while the request was unanswered');
  assert.deepEqual(codes(run([decision, exec(1, {clockUncertaintyMs: 5000})], [approved])), ['APPROVAL_TIME_UNCERTAIN']);
  assert.deepEqual(codes(run([decision, exec(10, {resource: 'order-8'})], [approved])), ['APPROVAL_TARGET_MISMATCH'], 'a different target is not approved');
});

test('refused and expired requests count as refusal at the time they took effect, whatever the analysis time', () => {
  const refused = request('refused', {decided: 20});
  assert.deepEqual(codes(run([decision, exec(30)], [refused])), ['EXECUTION_AFTER_APPROVAL_REFUSED']);
  assert.deepEqual(codes(run([decision, exec(10)], [refused])), ['EXECUTION_BEFORE_APPROVAL']);
  const pending = request('pending', {expires: 60});
  for (const now of [T0 + 30e3, T0 + 3600e3]) {
    assert.deepEqual(codes(run([decision, exec(90)], [pending], now)), ['EXECUTION_AFTER_APPROVAL_EXPIRED'], 'point in time, not analysis time');
    assert.deepEqual(codes(run([decision, exec(30)], [pending], now)), ['EXECUTION_BEFORE_APPROVAL']);
  }
  assert.equal(approvalStatus(pending, T0 + 59e3), 'pending');assert.equal(approvalStatus(pending, T0 + 60e3), 'expired');
  // Without a decision record the request alone still says approval was required.
  assert.deepEqual(codes(run([exec(30)], [refused])), ['EXECUTION_AFTER_APPROVAL_REFUSED']);
});

test('an approval that breaks its recorded answer rules has no effect and is reported', () => {
  const excluded = request('approved', {approvers: ['alpha-r1', 'alpha-registrant']});
  assert.deepEqual(codes(run([decision, exec(10)], [excluded])), ['APPROVAL_ANSWERER_EXCLUDED']);
  const one = request('approved', {approvers: ['alpha-r1']});
  assert.deepEqual(codes(run([decision, exec(10)], [one])), ['APPROVAL_ANSWERER_EXCLUDED'], 'two distinct approvers were required');
  const twice = request('approved', {approvers: ['alpha-r1', 'alpha-r1']});
  assert.deepEqual(codes(run([decision, exec(10)], [twice])), ['APPROVAL_ANSWERER_EXCLUDED']);
  const auditor = request('approved');auditor.approvals[1].role = 'auditor';
  assert.deepEqual(codes(run([decision, exec(10)], [auditor])), ['APPROVAL_ANSWERER_EXCLUDED']);
});

test('the asset-level human approval is met by an in-vault approval for the same policy version', () => {
  const asset = {id: 'pay', actor: 'pay-agent', tool: 'payment_transfer', policyVersion: 'p1', approvalRequired: true, validFrom: at(-3600)};
  const e = exec(10, {policyVersion: 'p1'}), approved = request('approved');
  const plain = evaluate([e], [asset], [], [], T0).findings.map(f => f.code);
  assert.ok(plain.includes('HUMAN_APPROVAL_MISSING'));
  const queued = evaluate([e], [asset], [], [], T0, {approvals: approvalAnalysisInput([approved])}).findings.map(f => f.code);
  assert.ok(!queued.includes('HUMAN_APPROVAL_MISSING'));
  const other = evaluate([e], [asset], [], [], T0, {approvals: approvalAnalysisInput([{...approved, policyVersion: 'p0'}])}).findings.map(f => f.code);
  assert.ok(other.includes('HUMAN_APPROVAL_MISSING'), 'another policy version does not count');
});

test('engine v3 only when the snapshot holds approval requests; other evaluations are unchanged', () => {
  assert.equal(evaluationEngine({events: [exec(1)]}), EVALUATION_ENGINE);
  assert.equal(evaluationEngine({events: [decision, exec(1)]}), EVALUATION_ENGINE_V2);
  assert.equal(evaluationEngine({events: [exec(1)], approvals: approvalAnalysisInput([request('pending')])}), EVALUATION_ENGINE_V3);
  assert.equal(approvalAnalysisInput([]), undefined, 'no key without requests');
  const events = [decision, exec(10)];
  assert.equal(canonical(evaluate(events, [], [], [], T0)), canonical(evaluate(events, [], [], [], T0, {approvals: undefined})));
  assert.equal(APPROVAL_LIMITS.requestsPerAction, 10);
  // Forged shapes degrade into an input that satisfies nothing, never an exception.
  const forged = approvalAnalysisInput([{id: 7, status: 'approved', target: {actor: 'pay-agent', tool: 'payment_transfer', resource: 'order-7'},
    approvals: 'x', eligibility: null}]);
  assert.deepEqual(codes(evaluate([decision, exec(10)], [], [], [], T0, {approvals: forged})), ['APPROVAL_ANSWERER_EXCLUDED', 'REQUIRED_APPROVAL_MISSING']);
});

test('who may answer is computed from the registry entry and policy data', () => {
  const policy = approvalPolicyOf(null), entry = {id: 'pay-agent', state: 'production', version: 4, registeredBy: 'alpha-reviewer', editedBy: 'alpha-editor',
    owner: 'alpha-owner', actors: ['pay-agent'], tools: [{name: 'payment_transfer'}], dataCategories: [], destinations: []};
  const e = approvalEligibility(entry, policy);
  assert.deepEqual([e.tier, e.approvers, e.excluded], ['high', 2, ['alpha-editor', 'alpha-owner', 'alpha-reviewer']]);
  assert.equal(e.basis.policySource, 'built_in_default');
  const signed = approvalPolicyOf({version: 3, approvals: {...policy.approvals, answer: {...policy.approvals.answer, low: {approvers: 1, roles: ['admin'],
    exclude: []}}}});
  const low = approvalEligibility({...entry, tools: [{name: 'reader'}]}, signed);
  assert.deepEqual([low.tier, low.roles, low.excluded, low.basis.policySource, low.basis.policyVersion], ['low', ['admin'], [], 'signed', 3]);
  assert.deepEqual(approvalEligibility(null, policy).tier, 'high', 'an unregistered actor gets the policy unregisteredTier');
});

test('the signed answer verifies offline with the vault key and refuses tampering, other targets and other windows', async () => {
  const {privateKey, publicKey} = generateKeyPairSync('ed25519'), other = generateKeyPairSync('ed25519').publicKey, signer = attestationSigner(privateKey);
  const approved = {...request('approved', {decided: 0, window: 300}), version: 3, requestedBy: 'alpha-gateway', enforcementPointId: 'gw'};
  const sign = async statement => signEnvelope(INTOTO_PAYLOAD_TYPE, Buffer.from(canonical(statement)), signer);
  const envelope = await sign(answerStatement('alpha', approved, {seq: 42, hash: 'ab'.repeat(32)}));
  const expected = {actionId: 'pay-1', target, auth_req_id: approved.id, tenant: 'alpha', decisionId: 'dec-1'}, now = T0 + 10e3;
  const ok = verifyApprovalAnswer({envelope, publicKey, expected, now});
  assert.deepEqual([ok.valid, ok.approved, ok.answer.ledger.seq, ok.answer.singleUse], [true, true, 42, true]);
  assert.equal(verifyApprovalAnswer({envelope, publicKey, expected: {...expected, target: {...target, resource: 'order-8'}}, now}).approved, false);
  assert.equal(verifyApprovalAnswer({envelope, publicKey, expected: {...expected, actionId: 'pay-2'}, now}).approved, false);
  assert.deepEqual(verifyApprovalAnswer({envelope, publicKey, expected, now: T0 + 400e3}).reasons, ['outside the execution window']);
  assert.throws(() => verifyApprovalAnswer({envelope, publicKey: other, expected, now}), /signature verification failed/);
  assert.throws(() => verifyApprovalAnswer({envelope, publicKey, expected: {target}, now}), /required/, 'the gateway must name what it executes');
  const tampered = structuredClone(envelope), body = JSON.parse(Buffer.from(tampered.payload, 'base64').toString());
  body.predicate.executionWindow.notAfter = at(99999);tampered.payload = Buffer.from(canonical(body)).toString('base64');
  assert.throws(() => verifyApprovalAnswer({envelope: tampered, publicKey, expected, now}), /signature verification failed/);
  const refused = await sign(answerStatement('alpha', {...request('refused', {decided: 5}), requestedBy: 'alpha-gateway', enforcementPointId: 'gw'},
    {seq: 43, hash: 'cd'.repeat(32)}));
  const no = verifyApprovalAnswer({envelope: refused, publicKey, expected, now});
  assert.deepEqual([no.valid, no.approved, no.decision], [true, false, 'refused']);
  // A validly signed statement of another kind (an export attestation) is not an approval.
  const foreign = await sign({_type: 'https://in-toto.io/Statement/v1', subject: [{name: 'x', digest: {sha256: 'ab'.repeat(32)}}], predicateType: 'x',
    predicate: {}});
  assert.throws(() => verifyApprovalAnswer({envelope: foreign, publicKey, expected, now}), /Not an EvidScope approval answer/);
});
