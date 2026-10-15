// Evidence packages stage 2 (docs/evidence-pack.md): period-only packages whose records are standard receipts to the signed tenant
// log, receipts bundled for every cited record, signing through the signer process, and mapping versions shipped with the verifier.
import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {generateKeyPairSync} from 'node:crypto';
import {existsSync, mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {attestationSigner} from '../src/attestation-signer.mjs';
import {canonical} from '../src/crypto.mjs';
import {INTOTO_PAYLOAD_TYPE, intotoStatement, pae, sha256Hex, signEnvelope} from '../src/dsse.mjs';
import * as P from '../src/evidence-pack.mjs';
import {buildReceipts, NOT_REPLAYABLE, periodReplay, verifyPeriodEvidence} from '../src/evidence-pack-period.mjs';
import {currentMappingBytes, FRAMEWORKS, MAPPING_VERSION, mappingBytes, shippedMapping} from '../src/evidence-pack-frameworks.mjs';
import {appendSourceEvent} from '../src/event-ingest.mjs';
import {validateEvent} from '../src/model.mjs';
import {replayEvaluations} from '../src/policy-replay.mjs';
import {fileBackend} from '../src/signer-backends.mjs';
import {createSignerClient} from '../src/signer-client.mjs';
import {initSignerState, PACK_STATEMENTS, startSignerServer, verifyAuditLog} from '../src/signer.mjs';
import * as T from '../src/tlog.mjs';
import {main} from '../src/verify-cli.mjs';
import {build} from '../scripts/evidence-pack.mjs';
import {packageVerifier} from '../scripts/package-verifier.mjs';
import {caseFor} from './support/receipt-fixture.mjs';
import {BASE, transparencyFixture} from './support/transparency-fixture.mjs';
import {tempDir} from './temp-dir.mjs';
import {fileURLToPath} from 'node:url';

const pause = ms => new Promise(done => setTimeout(done, ms));
const builder = generateKeyPairSync('ed25519'), signer = attestationSigner(builder.privateKey);
const run = (args, out = []) => main(args, {stdout: {write: s => out.push(s)}, stderr: {write: s => out.push(s)}});
const json = (files, path) => JSON.parse(files.get(path).toString('utf8'));
const put = (files, path, value) => files.set(path, Buffer.from(JSON.stringify(value, null, 1) + '\n'));
const copy = files => new Map([...files].map(([k, v]) => [k, Buffer.from(v)]));
const statementOf = files => JSON.parse(Buffer.from(json(files, P.FILES.envelope).payload, 'base64').toString('utf8'));
// What a dishonest builder holding its own key can publish: changed files, a matching SHA256SUMS and a re-signed statement.
async function resign(files, change = s => s) {
  const out = copy(files), statement = statementOf(files);
  out.delete(P.FILES.envelope);
  out.set(P.FILES.sums, Buffer.from([...out.keys()].filter(p => p !== P.FILES.sums).sort().map(p => `${sha256Hex(out.get(p))}  ${p}\n`).join('')));
  const next = change(intotoStatement([...out.keys()].sort().map(name => ({name, sha256: sha256Hex(out.get(name))})), statement.predicateType,
    statement.predicate));
  put(out, P.FILES.envelope, await signEnvelope(INTOTO_PAYLOAD_TYPE, Buffer.from(canonical(next)), signer));
  return out;
}
function events(s, ids, tenant = 'alpha') {
  const src = {id: 'agent-src', tenant, role: 'source', kind: 'agent'};
  for (const id of ids) {
    const e = validateEvent({id, kind: 'intent', status: 'success', actionId: 'act-' + id, traceId: 'trace-' + id, occurredAt: new Date().toISOString(),
      actor: 'assistant', tool: 'crm', action: 'update', resource: 'case-7'}, src);
    s.store.transaction(() => appendSourceEvent(s.store, src, e));
  }
}
const note = (s, text, tenant = 'alpha') => s.store.transaction(() => s.store.append(tenant, 'note', {text}, 'test'));

// Tenant alpha in three phases a few milliseconds apart: A (a case on two agent events, a witness-cosigned tenant checkpoint after
// it), B (agent events), C (a note that must never reach a period package of A and B). Tenant beta beside it.
async function ledger(t) {
  const f = await transparencyFixture(t, {tenantLogs: true}), s = await f.open('enforce');
  const caseId = await caseFor(s);
  note(s, 'phase A');
  await caseFor(s, 'beta');
  await s.transparency.pump();
  await pause(15);
  events(s, ['b-1', 'b-2', 'b-3']);
  note(s, 'phase B');
  await pause(15);
  note(s, 'SECRET-OF-PHASE-C');
  const exported = await f.call(s, '/api/export'), records = exported.records;
  const report = await f.call(s, `/api/cases/${caseId}/report`), beta = await f.call(s, '/api/export', 'beta');
  const bStart = records.find(r => r.type === 'event' && r.payload.actionId === 'act-b-1'), cStart = records.find(r => r.payload?.text === 'SECRET-OF-PHASE-C');
  const flags = {witness: [f.w.vkey], quorum: '1', 'origin-base': BASE, 'max-staleness': '3600'};
  const cli = ['--witness', f.w.vkey, '--quorum', '1', '--origin-base', BASE, '--max-staleness', '3600'];
  const evidence = (extra = {}) => P.verifyEvidence({exportBytes: Buffer.from(JSON.stringify(exported)), publicKey: f.publicKey, flags, ...extra});
  return {f, s, exported, records, report, beta, flags, cli, evidence, caseId,
    periodAB: {from: records[0].recordedAt, to: cStart.recordedAt}, periodB: {from: bStart.recordedAt, to: cStart.recordedAt}};
}
const periodPack = async (L, period = L.periodAB, extra = {}) =>
  (await P.buildPack({evidence: L.evidence(extra), framework: 'eu-ai-act-logging', period, tenant: 'alpha', signer, periodOnly: true})).files;
const check = (L, files, extra = {}) => P.verifyPack(files, {publicKey: L.f.publicKey, packKey: builder.publicKey, flags: L.flags, ...extra});

test('a period package carries only the period range as receipts to the signed tenant log and verifies offline', async t => {
  const L = await ledger(t), dir = tempDir('evidscope-period-'), vault = join(dir, 'vault.pem'), key = join(dir, 'builder.pem');
  writeFileSync(vault, L.f.publicKey.export({format: 'pem', type: 'spki'}));
  writeFileSync(key, builder.privateKey.export({format: 'pem', type: 'pkcs8'}));
  writeFileSync(join(dir, 'builder-pub.pem'), builder.publicKey.export({format: 'pem', type: 'spki'}));
  writeFileSync(join(dir, 'export.json'), JSON.stringify(L.exported));
  writeFileSync(join(dir, 'report.json'), JSON.stringify(L.report));
  const out = join(dir, 'ab.tar.gz');
  const built = await build(['--framework', 'eu-ai-act-logging', '--tenant', 'alpha', '--key', vault, '--signing-key', key, '--out', out,
    '--export', join(dir, 'export.json'), '--case-report', join(dir, 'report.json'), '--from', L.periodAB.from, '--to', L.periodAB.to, '--period-only',
    ...L.cli]);
  assert.equal(built.packageScope, 'period');
  const files = P.readPack(out), manifest = json(files, P.FILES.period), receipts = json(files, P.FILES.receipts).receipts;
  assert.deepEqual([...files.keys()].sort(), ['SHA256SUMS', 'evidence/case-reports/case-1.json', 'evidence/period.json', 'evidence/receipts.json',
    'index.json', 'mapping.json', 'pack.intoto.json', 'summary.en.md', 'summary.ko.md']);
  // Only the range: no record of phase C, nothing of the whole export, and every record of the range once, in order.
  const cSeq = L.records.find(r => r.payload?.text === 'SECRET-OF-PHASE-C').seq;
  assert.deepEqual(manifest.range, {first: 1, last: cSeq - 1});
  assert.deepEqual(receipts.map(r => r.seq), Array.from({length: cSeq - 1}, (_, i) => i + 1));
  for (const [path, bytes] of files) assert.ok(!bytes.includes('SECRET-OF-PHASE-C'), path);
  // The range spans the witness-cosigned checkpoint and the newest one: both are used, bound by a consistency proof.
  const notes = new Set(receipts.map(r => T.parseTlogProof(r.proof).signedCheckpoint));
  assert.deepEqual([...notes].sort(), [L.exported.transparency.checkpoint, L.exported.transparency.tenantCosigned.checkpoint].sort());
  assert.ok(manifest.transparency.tenantCosigned.consistency.length > 0 && manifest.transparency.heads.consistency.length > 0);
  // The auditor's CLI verifies it with the same trust inputs; the summary states what a period package does not show.
  const log = [];
  assert.equal(run(['pack', out, vault, '--pack-key', join(dir, 'builder-pub.pem'), ...L.cli], log), 0, log.join(''));
  const r = JSON.parse(log.join(''));
  assert.deepEqual([r.packageScope, r.periodRecords.range.first, r.receipts.count, r.mapping.version], ['period', 1, cSeq - 1, MAPPING_VERSION]);
  for (const p of ['PERIOD_RECORDS_INCLUDED_IN_SIGNED_TENANT_LOG', 'RECORD_RECEIPTS_VERIFIED', 'TRANSPARENCY_VERIFIED', 'ROLLBACK_CHECKED',
    'EVALUATION_REPLAY_MATCHED', 'CASE_REPORTS_VERIFIED']) assert.ok(r.properties.includes('EVIDSCOPE_' + p), p);
  const index = json(files, P.FILES.index);
  assert.equal(index.scope.absence, 'not_established_by_a_period_package');
  assert.ok(index.items.every(i => i.status !== 'no_evidence_recorded') && index.items.some(i => i.status === 'no_evidence_in_package'));
  assert.match(files.get(P.FILES.en).toString(), /Absence inside the period/);
  assert.match(files.get(P.FILES.ko).toString(), /부재\)을 증명하지 않습니다/);
  // Each bundled receipt is a standard one: evidscope-verify tlog-proof accepts the record and proof files taken out of it.
  for (const e of [receipts[0], receipts.at(-1)]) {
    writeFileSync(join(dir, 'r.json'), e.record);
    writeFileSync(join(dir, 'r.tlog-proof'), e.proof);
    assert.equal(run(['tlog-proof', join(dir, 'r.tlog-proof'), join(dir, 'r.json'), '--key', vault], log), 0, log.at(-1));
  }
  // Without the witness keys the auditor cannot establish the builder's rollback claim.
  assert.equal(run(['pack', out, vault, '--pack-key', join(dir, 'builder-pub.pem')], log), 1);
  assert.match(log.at(-1), /did not establish: EVIDSCOPE_ROLLBACK_CHECKED/);
  // The separately packaged verifier ships the period code and the mapping versions.
  const v = packageVerifier({out: join(dir, 'release')});
  const packaged = spawnSync(process.execPath, [join(v.directory, 'evidscope-verify.mjs'), 'pack', out, vault, '--pack-key', join(dir, 'builder-pub.pem'),
    ...L.cli], {encoding: 'utf8', cwd: dir});
  assert.equal(packaged.status, 0, packaged.stderr);
});

test('tampering with any proof, receipt, record, link or the manifest of a period package is refused, also when re-signed', async t => {
  const L = await ledger(t), files = await periodPack(L), manifest = json(files, P.FILES.period), receipts = json(files, P.FILES.receipts);
  assert.equal(check(L, await resign(files)).valid, true, 'the builder may re-sign an unchanged package');
  const wrong = async change => { const out = copy(files); change(out); return check(L, await resign(out)); };
  const withReceipts = list => out => put(out, P.FILES.receipts, {...receipts, receipts: list});
  const at = 3, entry = receipts.receipts[at];
  const flipProof = proof => {
    const lines = proof.split('\n'), h = Buffer.from(lines[2], 'base64');
    h[0] ^= 1;
    lines[2] = h.toString('base64');
    return lines.join('\n');
  };
  await assert.rejects(wrong(withReceipts(receipts.receipts.map((e, i) => (i === at ? {...e, proof: flipProof(e.proof)} : e)))), /inclusion proof failed/);
  const record = JSON.parse(entry.record), changed = canonical({...record, payload: {...record.payload, tampered: true}});
  await assert.rejects(wrong(withReceipts(receipts.receipts.map((e, i) => (i === at ? {...e, record: changed} : e)))), /another record, tenant or hash/);
  await assert.rejects(wrong(withReceipts(receipts.receipts.map((e, i) => (i === at ? {...e, record: changed, hash: sha256Hex(changed)} : e)))),
    /inclusion proof failed/);
  await assert.rejects(wrong(withReceipts(receipts.receipts.filter((_, i) => i !== at))), /exactly the receipts/);
  const other = receipts.receipts.map((e, i) => (i === at ? {...e, proof: receipts.receipts[at + 1].proof} : e));
  await assert.rejects(wrong(withReceipts(other)), /proves against another checkpoint|inclusion proof failed/);
  // The manifest: consistency and head inclusion proofs, the range, the checkpoint and the disclosures.
  const tm = manifest.transparency, flip = h => { const b = Buffer.from(h, 'base64'); b[1] ^= 1; return b.toString('base64'); };
  await assert.rejects(wrong(out => put(out, P.FILES.period, {...manifest, transparency: {...tm, tenantCosigned: {...tm.tenantCosigned,
    consistency: tm.tenantCosigned.consistency.map((h, i) => (i ? h : flip(h)))}}})), /inconsistent with the report checkpoint/);
  await assert.rejects(wrong(out => put(out, P.FILES.period, {...manifest, transparency: {...tm, inclusion: tm.inclusion.map(x => ({...x,
    proof: x.proof.map((h, i) => (i ? h : flip(h)))}))}})), /inclusion proof failed/);
  await assert.rejects(wrong(out => put(out, P.FILES.period, {...manifest, range: {...manifest.range, last: manifest.range.last + 1}})),
    /exactly the receipts/);
  await assert.rejects(wrong(out => put(out, P.FILES.period, {...manifest, conclusion: 'all requirements met'})), /unknown field "conclusion"/);
  await assert.rejects(wrong(withReceipts(receipts.receipts.map((e, i) => (i === at ? {...e, note: 'met'} : e)))), /unknown field "note"/);
  const later = {...L.exported.checkpoint, count: L.exported.checkpoint.count + 1};
  await assert.rejects(wrong(out => put(out, P.FILES.period, {...manifest, checkpoint: later})), /Checkpoint signature invalid/);
  await assert.rejects(wrong(out => put(out, P.FILES.period, {...manifest, disclosures: [{seq: 2, event: {tenant: 'alpha'}}]})), /altered retained event/);
  await assert.rejects(wrong(out => put(out, P.FILES.period, {...manifest, disclosures: [...manifest.disclosures, {seq: 1, event: {}}]})),
    /Unexpected (or duplicate )?event disclosure/);
  // A withheld disclosure cannot be told from a later erasure inside a period package: it is counted, and the index differs.
  const withheld = verifyPeriodEvidence({manifestBytes: Buffer.from(JSON.stringify({...manifest, disclosures: []})), receiptsBytes: files.get(P.FILES.receipts),
    publicKey: L.f.publicKey, flags: L.flags});
  assert.deepEqual([withheld.result.undisclosedEvents, withheld.result.disclosedEvents], [manifest.disclosures.length, 0]);
  await assert.rejects(wrong(out => put(out, P.FILES.period, {...manifest, disclosures: []})), /Index differs/);
  // A broken hash link between neighbours (a record of another history with a valid-looking receipt cannot be built without the key).
  assert.throws(() => check(L, files, {checkpoint: {...L.exported.checkpoint, head: '0'.repeat(64)}}), /External checkpoint mismatch/);
  assert.equal(check(L, files, {checkpoint: L.exported.checkpoint}).valid, true);
});

test('records from outside the period or of another tenant, and foreign case reports, are refused', async t => {
  const L = await ledger(t), files = await periodPack(L, L.periodB), manifest = json(files, P.FILES.period), receipts = json(files, P.FILES.receipts);
  assert.equal(check(L, files).valid, true);
  const wrong = async change => { const out = copy(files); change(out); return check(L, await resign(out)); };
  // A valid receipt of the record just before the period, added at the front of the range: the range must start inside the period.
  const first = manifest.range.first, before = JSON.parse(buildReceipts({tenant: 'alpha', records: L.records, material: L.exported.transparency,
    seqs: [first - 1]}).toString()).receipts[0];
  await assert.rejects(wrong(out => {
    put(out, P.FILES.period, {...manifest, range: {...manifest.range, first: first - 1}});
    put(out, P.FILES.receipts, {...receipts, receipts: [before, ...receipts.receipts]});
  }), /begin and end with records inside the period/);
  // A beta record with its own valid receipt (beta's tenant log) in place of the alpha record of the same sequence.
  const betaReceipt = JSON.parse(buildReceipts({tenant: 'beta', records: L.beta.records, material: L.beta.transparency, seqs: [1]}).toString()).receipts[0];
  const swapped = receipts.receipts.map((e, i) => (i === 0 ? {...betaReceipt, seq: e.seq} : e));
  await assert.rejects(wrong(out => put(out, P.FILES.receipts, {...receipts, receipts: swapped})), /another record, tenant or hash|another checkpoint/);
  await assert.rejects(wrong(out => put(out, P.FILES.receipts, {...receipts, tenant: 'beta'})), /not an evidence package receipts file of this tenant/);
  // The case of phase A lies outside a phase B package: its report cannot be shown there.
  await assert.rejects(P.buildPack({evidence: L.evidence({caseReports: [{bytes: Buffer.from(JSON.stringify(L.report))}]}), framework: 'isms-p',
    period: L.periodB, tenant: 'alpha', signer, periodOnly: true}), /not a record of this period package/);
  // A whole export without a tenant log checkpoint, or a period without records, gives no period package.
  const plain = {...L.exported};
  delete plain.transparency;
  const ev = P.verifyEvidence({exportBytes: Buffer.from(JSON.stringify(plain)), publicKey: L.f.publicKey});
  await assert.rejects(P.buildPack({evidence: ev, framework: 'isms-p', period: L.periodB, tenant: 'alpha', signer, periodOnly: true}), /tenant log checkpoint/);
  await assert.rejects(P.buildPack({evidence: L.evidence(), framework: 'isms-p', period: {from: '2001-01-01T00:00:00Z', to: '2001-02-01T00:00:00Z'},
    tenant: 'alpha', signer, periodOnly: true}), /No record of the export lies inside the period/);
});

test('a period package never claims absence, and evaluations needing earlier records are marked not replayable', async t => {
  const L = await ledger(t), files = await periodPack(L, L.periodB), index = json(files, P.FILES.index);
  const none = index.items.find(i => i.status === 'no_evidence_in_package');
  assert.ok(none.evidence.some(e => e.status === 'none_in_package'));
  const claim = {...index, items: index.items.map(i => (i.id === none.id ? {...i, status: 'no_evidence_recorded',
    evidence: i.evidence.map(e => (e.status === 'none_in_package' ? {...e, status: 'none_recorded'} : e))} : i))};
  const out = copy(files);
  put(out, P.FILES.index, claim);
  assert.throws(() => check(L, out), /digest mismatch/);
  await assert.rejects((async () => check(L, await resign(out)))(), /cannot establish/);
  const ev = P.verifyPack(files, {publicKey: L.f.publicKey, packKey: builder.publicKey, flags: L.flags});
  assert.equal(ev.properties.includes('EVIDSCOPE_EVALUATION_REPLAY_MATCHED'), false, 'nothing was replayed from a range after sequence 1');
  await assert.rejects((async () => check(L, await resign(files, s => ({...s, predicate: {...s.predicate,
    properties: [...s.predicate.properties, 'EVIDSCOPE_EVALUATION_REPLAY_MATCHED']}}))))(), /did not establish: EVIDSCOPE_EVALUATION_REPLAY_MATCHED/);
  // Replay from a range: from sequence 1 it is the whole-export replay; from later on, every evaluation is not_replayable with the reason.
  const fixture = JSON.parse(readFileSync(new URL('./fixtures/pack-export-8b3af6c.json', import.meta.url), 'utf8')), b = fixture.exportBundle;
  const full = replayEvaluations(b), from1 = periodReplay(b, 1), evals = b.records.filter(r => r.type === 'evaluation');
  assert.deepEqual(from1.summary, full.summary);
  assert.ok(full.summary.replayed > 0);
  const later = periodReplay({...b, records: b.records.slice(evals[0].seq - 1)}, evals[0].seq);
  assert.deepEqual([later.summary.replayed, later.summary.mismatch, later.summary.notReplayable], [0, 0, evals.length]);
  assert.deepEqual(later.summary.notReplayableReasons, {[NOT_REPLAYABLE]: evals.length});
});

test('whole-ledger packages bundle the receipt of every cited record, regenerated and verified by the verifier', async t => {
  const L = await ledger(t);
  const files = (await P.buildPack({evidence: L.evidence({caseReports: [{bytes: Buffer.from(JSON.stringify(L.report))}]}), framework: 'eu-ai-act-logging',
    tenant: 'alpha', signer})).files;
  const index = json(files, P.FILES.index), receipts = json(files, P.FILES.receipts).receipts, cited = P.citedSeqs(index);
  assert.equal(index.format, P.INDEX_FORMAT_V2);
  assert.ok(cited.length > 3);
  assert.deepEqual(receipts.map(r => r.seq), cited);
  assert.deepEqual([index.evidence.receipts.records, index.evidence.receipts.notCovered], [cited.length, 0]);
  const r = check(L, files);
  assert.deepEqual([r.packageScope, r.receipts.count], ['ledger', cited.length]);
  assert.ok(r.properties.includes('EVIDSCOPE_RECORD_RECEIPTS_VERIFIED'));
  const wrong = async change => { const out = copy(files); change(out); return check(L, await resign(out)); };
  await assert.rejects(wrong(out => put(out, P.FILES.receipts, {...json(files, P.FILES.receipts), receipts: receipts.slice(1)})), /differs from the receipts/);
  await assert.rejects(wrong(out => out.delete(P.FILES.receipts)), /differs from the receipts/);
  // Without tenant log material the export cannot give receipts, and the index says why.
  const plain = {...L.exported};
  delete plain.transparency;
  const bare = await P.buildPack({evidence: P.verifyEvidence({exportBytes: Buffer.from(JSON.stringify(plain)), publicKey: L.f.publicKey}),
    framework: 'eu-ai-act-logging', tenant: 'alpha', signer});
  assert.equal(bare.files.has(P.FILES.receipts), false);
  assert.equal(json(bare.files, P.FILES.index).evidence.receipts.reason, 'export_has_no_tenant_log_checkpoint');
  assert.equal(P.verifyPack(bare.files, {publicKey: L.f.publicKey, packKey: builder.publicKey}).receipts, null);
});

test('packages built by d7413a0 verify unchanged against the mapping version they name; unknown versions stay refused', async () => {
  const dir = fileURLToPath(new URL('./fixtures/pack-d7413a0/', import.meta.url)), key = name => readFileSync(join(dir, name), 'utf8');
  for (const name of ['eu-whole.tar.gz', 'kr-period.tar.gz']) {
    const files = P.readPack(join(dir, name)), r = P.verifyPack(files, {publicKey: key('vault-public.spki.txt'), packKey: key('builder-public.spki.txt')});
    assert.deepEqual([r.valid, r.packageScope, r.mapping.version, r.mapping.source, json(files, P.FILES.index).format], [true, 'ledger', 1, 'verifier',
      P.INDEX_FORMAT]);
    assert.equal(r.receipts, null);
    assert.notEqual(MAPPING_VERSION, 1, 'the current mapping is not the one these packages name');
  }
  // Every shipped version is intact, and the builder writes exactly the current one.
  for (const id of FRAMEWORKS) {
    assert.ok(shippedMapping(id, MAPPING_VERSION).equals(currentMappingBytes(id)), id);
    assert.equal(JSON.parse(shippedMapping(id, 1).toString()).version, undefined);
  }
  assert.equal(shippedMapping('isms-p', 99), null);
  // A package naming a version this verifier does not ship is refused, unless the auditor accepts the package's own mapping.
  const fixture = JSON.parse(readFileSync(new URL('./fixtures/pack-export-8b3af6c.json', import.meta.url), 'utf8'));
  const evidence = P.verifyEvidence({exportBytes: Buffer.from(JSON.stringify(fixture.exportBundle)), publicKey: fixture.publicKeyPem});
  const files = (await P.buildPack({evidence, framework: 'kr-ai-basic-act', tenant: 'alpha', signer})).files;
  const future = {...json(files, P.FILES.mapping), version: 99}, futureBytes = mappingBytes(future);
  const out = copy(files);
  out.set(P.FILES.mapping, futureBytes);
  put(out, P.FILES.index, {...json(files, P.FILES.index), framework: {...json(files, P.FILES.index).framework, mappingVersion: 99}});
  for (const lang of ['ko', 'en']) out.set(P.FILES[lang], P.renderSummary(json(out, P.FILES.index), lang));
  const resigned = await resign(out, s => ({...s, predicate: {...s.predicate, verifier: {...s.predicate.verifier,
    policies: [{...s.predicate.verifier.policies[0], digest: {sha256: sha256Hex(futureBytes)}}]}}}));
  const opts = {publicKey: fixture.publicKeyPem, packKey: builder.publicKey};
  assert.throws(() => P.verifyPack(resigned, opts), /mapping version 99, which this verifier does not ship/);
  const accepted = P.verifyPack(resigned, {...opts, mappingFromPack: true});
  assert.deepEqual([accepted.mapping.version, accepted.mapping.source], [99, 'package']);
  // Version 1 bytes under the current index are refused: the index names the version it was computed with.
  const v1 = copy(files);
  v1.set(P.FILES.mapping, shippedMapping('kr-ai-basic-act', 1));
  const v1signed = await resign(v1, s => ({...s, predicate: {...s.predicate, verifier: {...s.predicate.verifier,
    policies: [{...s.predicate.verifier.policies[0], digest: {sha256: sha256Hex(shippedMapping('kr-ai-basic-act', 1))}}]}}}));
  assert.throws(() => P.verifyPack(v1signed, opts), /Index differs/);
});

test('a package is signed through the signer process, which signs evidence package statements only', async t => {
  const dir = tempDir('evidscope-pack-signer-'), keys = generateKeyPairSync('ed25519'), keyFile = join(dir, 'signer-key.pem');
  mkdirSync(join(dir, 'run'), {mode: 0o700});
  writeFileSync(keyFile, keys.privateKey.export({format: 'pem', type: 'pkcs8'}), {mode: 0o600});
  writeFileSync(join(dir, 'signer-public.pem'), keys.publicKey.export({format: 'pem', type: 'spki'}));
  const start = async (name, statements) => {
    initSignerState(join(dir, 'state-' + name), keys.publicKey);
    const server = await startSignerServer({stateDir: join(dir, 'state-' + name), backend: fileBackend({keyFile}),
      listen: {socket: join(dir, 'run', name + '.sock')}, statements, log: () => {}});
    t.after(() => server.close());
    return server;
  };
  const packSigner = await start('pack', PACK_STATEMENTS), headsOnly = await start('heads', null);
  const fixture = JSON.parse(readFileSync(new URL('./fixtures/pack-export-8b3af6c.json', import.meta.url), 'utf8'));
  writeFileSync(join(dir, 'vault.pem'), fixture.publicKeyPem);
  writeFileSync(join(dir, 'export.json'), JSON.stringify(fixture.exportBundle));
  const args = (out, socket, publicKey = join(dir, 'signer-public.pem')) => ['--framework', 'isms-p', '--tenant', 'alpha', '--key', join(dir, 'vault.pem'),
    '--export', join(dir, 'export.json'), '--out', join(dir, out), '--signer-socket', socket, '--signer-public-key', publicKey];
  const built = await build(args('pack', packSigner.address));
  assert.equal(built.signedBy, 'signer_process');
  const log = [];
  assert.equal(run(['pack', join(dir, 'pack'), join(dir, 'vault.pem'), '--pack-key', join(dir, 'signer-public.pem')], log), 0, log.join(''));
  const audit = join(dir, 'state-pack', 'audit.log');
  assert.ok(readFileSync(audit, 'utf8').includes('"event":"statement_signed"'));
  assert.ok(verifyAuditLog(audit).lines > 0);
  // Refusals: a signer serving heads checkpoints only, another pinned key, a statement of another kind, raw bytes and checkpoints.
  await assert.rejects(build(args('no-statements', headsOnly.address)), /refused the statement \(HTTP 404, not_found\)/);
  writeFileSync(join(dir, 'other.pem'), generateKeyPairSync('ed25519').publicKey.export({format: 'pem', type: 'spki'}));
  await assert.rejects(build(args('other-key', packSigner.address, join(dir, 'other.pem'))), /does not verify with the pinned signer public key/);
  assert.equal(existsSync(join(dir, 'no-statements')) || existsSync(join(dir, 'other-key')), false, 'nothing is written when signing is refused');
  await assert.rejects(build(args('both', packSigner.address).concat(['--signing-key', keyFile])), /exactly one of --signing-key/);
  const client = createSignerClient({socket: packSigner.address});
  const sign = body => client.signStatement(pae(INTOTO_PAYLOAD_TYPE, Buffer.from(body)));
  const statement = (predicateType, id) => canonical(intotoStatement([{name: 'x', sha256: 'a'.repeat(64)}], predicateType, {verifier: {id}}));
  const ok = await sign(statement(P.SVR_PREDICATE, P.BUILDER_ID));
  assert.deepEqual([ok.httpStatus, ok.body.status], [200, 'signed']);
  for (const [body, reason] of [[statement('https://slsa.dev/provenance/v1', P.BUILDER_ID), 'not_allowed'],
    [statement(P.SVR_PREDICATE, 'https://example.com/other-builder'), 'not_allowed'],
    [JSON.stringify(JSON.parse(statement(P.SVR_PREDICATE, P.BUILDER_ID)), null, 1), 'not_allowed']]) {
    const r = await sign(body);
    assert.deepEqual([r.httpStatus, r.body.reason], [422, reason], body.slice(0, 60));
  }
  const checkpointText = T.formatCheckpoint({origin: BASE + '/heads', size: 1, root: Buffer.alloc(32)});
  for (const message of [Buffer.from(checkpointText), pae('text/plain', Buffer.from('anything'))]) {
    const r = await client.signStatement(message);
    assert.equal(r.body.status, 'refused');
  }
  assert.deepEqual(PACK_STATEMENTS.predicateTypes, [P.SVR_PREDICATE]);
  assert.deepEqual(PACK_STATEMENTS.verifierIds, [P.BUILDER_ID]);
});
