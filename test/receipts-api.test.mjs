// Standard receipts from the vault API (docs/receipts.md): ?attest=intoto on exports and case reports, and per-record
// c2sp.org/tlog-proof receipts with the deployment's c2sp.org/tlog-policy.
import test from 'node:test';
import assert from 'node:assert/strict';
import {sign} from 'node:crypto';
import {canonical} from '../src/crypto.mjs';
import {INTOTO_PAYLOAD_TYPE, pae, sha256Hex} from '../src/dsse.mjs';
import {appendSourceEvent} from '../src/event-ingest.mjs';
import {validateEvent} from '../src/model.mjs';
import * as R from '../src/receipts.mjs';
import * as T from '../src/tlog.mjs';
import {parseTlogPolicy} from '../src/tlog-policy.mjs';
import {BASE, tamper, transparencyFixture} from './support/transparency-fixture.mjs';

const alphaOrigin = T.tenantOrigin(BASE, 'alpha');
const flags = f => ({witnesses: [f.w.vkey], quorum: 1, originBase: BASE, require: true, maxStalenessSeconds: 3600});
const post = (s, path, body, tenant = 'alpha') =>
  s.handle('POST', new URL(path, 'http://local'), {authorization: 'Bearer ' + tenant.repeat(40)}, JSON.stringify(body));
const check = (f, wrapper, options = {}) => R.verifyAttestation({envelope: wrapper.envelope, subject: subjectOf(wrapper), publicKey: f.publicKey, options});
const subjectOf = wrapper => Buffer.from(wrapper.file.content, 'utf8');
// Re-signs a changed statement with the vault key: what a vault bug or a key holder could publish.
function resign(f, wrapper, change) {
  const statement = JSON.parse(Buffer.from(wrapper.envelope.payload, 'base64').toString('utf8'));
  change(statement);
  const body = Buffer.from(canonical(statement), 'utf8');
  return {...wrapper.envelope, payload: body.toString('base64'), signatures: [{keyid: wrapper.envelope.signatures[0].keyid,
    sig: sign(null, pae(INTOTO_PAYLOAD_TYPE, body), f.privateKey).toString('base64')}]};
}
async function caseFor(s, tenant = 'alpha') {
  const src = {id: 'agent-src', tenant, role: 'source', kind: 'agent'}, actionId = 'act-receipt';
  for (const id of ['intent-1', 'claim-1']) {
    const e = validateEvent({id, kind: id.startsWith('intent') ? 'intent' : 'self_report', status: 'success', actionId, traceId: 'trace-1',
      occurredAt: new Date().toISOString(), actor: 'assistant', tool: 'crm', action: 'update', resource: 'case-7'}, src);
    s.store.transaction(() => appendSourceEvent(s.store, src, e));
  }
  return (await post(s, '/api/cases', {title: 'receipt case', owner: 'audit-team', actionId})).id;
}

test('an attested export is the plain export bytes plus a DSSE in-toto statement with tlog-proofs', async t => {
  const f = await transparencyFixture(t, {tenantLogs: true});
  const s = await f.open('enforce');
  f.write(s, 'alpha', 4);
  await s.transparency.pump();
  const wrapper = await f.call(s, '/api/export?attest=intoto');
  assert.equal(wrapper.format, R.ATTESTED_FILE_FORMAT);
  const bundle = JSON.parse(wrapper.file.content);
  assert.equal(wrapper.file.content, JSON.stringify(bundle));
  assert.equal(wrapper.file.sha256, sha256Hex(subjectOf(wrapper)));
  assert.equal(wrapper.file.name, `evidscope-export-${bundle.checkpoint.count}.json`);
  assert.equal(wrapper.envelope.payloadType, 'application/vnd.in-toto+json');
  assert.equal(wrapper.envelope.signatures[0].keyid, sha256Hex(f.publicKey.export({format: 'der', type: 'spki'})));
  // The plain route keeps its shape: no attestation fields appear without the option.
  const plain = await f.call(s, '/api/export');
  assert.deepEqual(Object.keys(plain).sort(), ['checkpoint', 'disclosures', 'format', 'limitations', 'records', 'transparency']);
  const r = check(f, wrapper, {transparency: flags(f), requireWitnessed: true});
  assert.equal(r.predicateType, R.EXPORT_PREDICATE);
  assert.equal(r.witnessed, true);
  const cosigned = T.parseCheckpoint(T.noteText(bundle.transparency.tenantCosigned.checkpoint)).size;
  assert.deepEqual(r.tlogProofs.map(p => [p.seq, p.witnessedCheckpoint, p.quorumMet]), [[cosigned, true, true], [bundle.checkpoint.count, false, false]]);
  assert.equal(r.bundle.transparency.rollbackCheckedAgainst, 'signing_key_holder');
  // A single changed byte of the subject, the payload, or a re-signed predicate that contradicts the subject is refused.
  const changed = Buffer.from(wrapper.file.content.replace('"note"', '"nite"'), 'utf8');
  assert.throws(() => R.verifyAttestation({envelope: wrapper.envelope, subject: changed, publicKey: f.publicKey}), /digest is not the subject/);
  const payload = Buffer.from(wrapper.envelope.payload, 'base64');
  payload[payload.length - 3] ^= 1;
  assert.throws(() => R.verifyAttestation({envelope: {...wrapper.envelope, payload: payload.toString('base64')}, subject: subjectOf(wrapper),
    publicKey: f.publicKey}), /DSSE signature verification failed/);
  const lying = resign(f, wrapper, st => { st.predicate.requirementResults = [{requirementId: 'KR-1', assessment: 'sufficient'}]; });
  assert.throws(() => R.verifyAttestation({envelope: lying, subject: subjectOf(wrapper), publicKey: f.publicKey}), /predicate requirementResults differs/);
  const swapped = resign(f, wrapper, st => { st.predicate.tlogProofs.reverse(); });
  assert.throws(() => R.verifyAttestation({envelope: swapped, subject: subjectOf(wrapper), publicKey: f.publicKey}), /tlog-proof list is malformed/);
  const bent = resign(f, wrapper, st => {
    const p = st.predicate.tlogProofs[1], lines = p.proof.split('\n');
    lines[2] = T.b64(Buffer.alloc(32, 7));
    p.proof = lines.join('\n');
  });
  assert.throws(() => R.verifyAttestation({envelope: bent, subject: subjectOf(wrapper), publicKey: f.publicKey}), /inclusion proof failed/);
  // A policy whose quorum the embedded proofs cannot meet, or another vault key, fails the witnessed requirement or the signature.
  const unwitnessedPolicy = R.tenantTlogPolicy({origin: alphaOrigin, publicKey: f.publicKey});
  assert.throws(() => check(f, wrapper, {transparency: flags(f), requireWitnessed: true, policy: unwitnessedPolicy}), /No embedded tlog-proof/);
  const other = (await import('node:crypto')).generateKeyPairSync('ed25519').publicKey;
  assert.throws(() => R.verifyAttestation({envelope: wrapper.envelope, subject: subjectOf(wrapper), publicKey: other}), /DSSE signature verification failed/);
  assert.equal((await f.call(s, '/api/export?attest=sigstore').catch(e => e)).status, 400);
  assert.equal((await f.call(s, '/api/export?attest=intoto&attest=intoto').catch(e => e)).status, 400);
});

test('an attested case report binds the report bytes, the review result and tlog-proofs of the action records', async t => {
  const f = await transparencyFixture(t, {tenantLogs: true});
  const s = await f.open('enforce');
  const id = await caseFor(s);
  await s.transparency.pump();
  const wrapper = await f.call(s, `/api/cases/${id}/report?attest=intoto`);
  const report = JSON.parse(wrapper.file.content);
  assert.equal(report.format, 'evidscope-case-report-v1');
  assert.match(wrapper.file.name, /^evidscope-case-[A-Za-z0-9._-]+-\d+\.json$/);
  const r = check(f, wrapper, {transparency: flags(f), requireWitnessed: true});
  assert.equal(r.predicateType, R.CASE_REPORT_PREDICATE);
  assert.equal(r.report.caseId, id);
  const events = report.snapshot.action.events.map(e => e.seq);
  assert.deepEqual(r.tlogProofs.map(p => p.seq), [...events, report.snapshot.checkpoint.count]);
  assert.ok(r.tlogProofs.filter(p => events.includes(p.seq)).every(p => p.witnessedCheckpoint && p.quorumMet));
  const statement = JSON.parse(Buffer.from(wrapper.envelope.payload, 'base64').toString('utf8'));
  assert.equal(statement.predicate.requirementResults.review.state, 'unreviewed');
  assert.equal(statement.predicate.issuedAt, report.snapshot.exportedAt);
  const lying = resign(f, wrapper, st => { st.predicate.requirementResults.review.state = 'reviewed'; });
  assert.throws(() => R.verifyAttestation({envelope: lying, subject: subjectOf(wrapper), publicKey: f.publicKey}), /predicate requirementResults differs/);
  // The report itself still verifies with the existing verifier, and the plain route is unchanged.
  const plain = await f.call(s, `/api/cases/${id}/report`);
  assert.equal(plain.format, 'evidscope-case-report-v1');
  assert.equal(plain.envelope, undefined);
});

test('a record receipt is a c2sp.org/tlog-proof under the deployment tlog-policy, witnessed once the quorum cosigned', async t => {
  const f = await transparencyFixture(t, {tenantLogs: true});
  const s = await f.open('enforce');
  f.write(s, 'alpha', 3);
  await s.transparency.pump();
  const receipt = await f.call(s, '/api/receipts/record?seq=2');
  assert.equal(receipt.format, R.RECORD_RECEIPT_FORMAT);
  assert.equal(receipt.witnessed, true);
  assert.equal(receipt.hash, sha256Hex(Buffer.from(receipt.record, 'utf8')));
  const policy = parseTlogPolicy(receipt.policy);
  assert.deepEqual([policy.logs.map(l => l.vkey), policy.witnesses.map(w => w.vkey), policy.quorum],
    [[T.logVkey(alphaOrigin, f.publicKey)], [f.w.vkey], 'witness-1']);
  const ok = R.verifyRecordReceipt({proof: receipt.proof, record: Buffer.from(receipt.record), policy: receipt.policy, publicKey: f.publicKey,
    originBase: BASE});
  assert.deepEqual([ok.seq, ok.quorumMet, ok.witnessed, ok.cosignatures.length], [2, true, true, 1]);
  // Records the witnesses have not cosigned yet come against the vault-signed checkpoint: the policy quorum is then not met.
  f.write(s, 'alpha', 1);
  const head = s.store._tlogRow('alpha').size, late = await f.call(s, `/api/receipts/record?seq=${head}`);
  assert.deepEqual([late.witnessed, late.checkpointSize, late.cosignatures], [false, head, []]);
  assert.throws(() => R.verifyRecordReceipt({proof: late.proof, record: Buffer.from(late.record), policy: late.policy, publicKey: f.publicKey}),
    /quorum witness-1/);
  const unwitnessed = R.verifyRecordReceipt({proof: late.proof, record: Buffer.from(late.record), publicKey: f.publicKey, quorum: 0});
  assert.equal(unwitnessed.witnessed, false);
  // Tampered record, wrong index, other tenant's policy key, and another pinned vault key.
  const record = JSON.parse(receipt.record);
  record.payload.i = 99;
  assert.throws(() => R.verifyRecordReceipt({proof: receipt.proof, record: Buffer.from(canonical(record)), policy: receipt.policy, publicKey: f.publicKey}),
    /inclusion proof failed/);
  assert.throws(() => R.verifyRecordReceipt({proof: receipt.proof, record: Buffer.from(JSON.stringify(JSON.parse(receipt.record), null, 1)),
    policy: receipt.policy}), /exact ledger record body/);
  const shifted = receipt.proof.replace('index 1\n', 'index 0\n');
  assert.throws(() => R.verifyRecordReceipt({proof: shifted, record: Buffer.from(receipt.record), policy: receipt.policy}), /index does not match/);
  const betaPolicy = R.tenantTlogPolicy({origin: T.tenantOrigin(BASE, 'beta'), publicKey: f.publicKey, witnesses: [f.w.vkey], quorum: 1});
  assert.throws(() => R.verifyRecordReceipt({proof: receipt.proof, record: Buffer.from(receipt.record), policy: betaPolicy}),
    /not signed by a policy log for its origin/);
  const other = (await import('node:crypto')).generateKeyPairSync('ed25519').publicKey;
  assert.throws(() => R.verifyRecordReceipt({proof: receipt.proof, record: Buffer.from(receipt.record), policy: receipt.policy, publicKey: other}),
    /not the pinned vault key/);
  assert.throws(() => R.verifyRecordReceipt({proof: receipt.proof, record: Buffer.from(receipt.record), policy: receipt.policy, originBase: 'other.test/x'}),
    /pinned origin base/);
  for (const [q, status] of [['seq=0', 400], ['seq=01', 400], ['seq=abc', 400], ['seq=9999', 404]]) {
    assert.equal((await f.call(s, '/api/receipts/record?' + q).catch(e => e)).status, status, q);
  }
  // A cosignature line rewritten in the database never leaves the vault inside a receipt.
  tamper(f.dataDir, db => db.prepare("UPDATE tlog_cosignatures SET line=replace(line,substr(line,length(line)-8,4),'AAAA') WHERE origin=?").run(alphaOrigin));
  const refused = await f.call(s, '/api/receipts/record?seq=2').catch(e => e);
  assert.equal(refused.status, 409);
  assert.match(refused.message, /영수증을 발급할 수 없습니다/);
});

test('without witnessTenantLogs the tenant policy says quorum none, and with transparency off there is no record receipt', async t => {
  const f = await transparencyFixture(t);
  const s = await f.open('monitor');
  f.write(s, 'alpha', 2);
  await s.transparency.pump();
  const receipt = await f.call(s, '/api/receipts/record?seq=1');
  assert.equal(parseTlogPolicy(receipt.policy).quorum, 'none');
  assert.match(receipt.policy, /do not cosign this tenant log directly/);
  assert.equal(receipt.witnessed, false);
  assert.equal(R.verifyRecordReceipt({proof: receipt.proof, record: Buffer.from(receipt.record), policy: receipt.policy, publicKey: f.publicKey}).valid, true);
  await f.close(s);
  const off = await f.open('off');
  assert.equal((await f.call(off, '/api/receipts/record?seq=1').catch(e => e)).status, 409);
  // Exports and reports are still attested without transparency material: the predicate then has no tlog part.
  const wrapper = await f.call(off, '/api/export?attest=intoto');
  const r = R.verifyAttestation({envelope: wrapper.envelope, subject: subjectOf(wrapper), publicKey: f.publicKey});
  assert.deepEqual([r.tlogProofs, r.witnessed], [[], false]);
});
