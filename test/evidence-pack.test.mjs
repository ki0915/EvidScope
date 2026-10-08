// Auditor evidence packages (docs/evidence-pack.md): built only from verified evidence, re-verified offline by evidscope-verify
// pack, which recomputes the index and summaries and refuses any changed, added or missing file, also when the builder re-signs.
import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {generateKeyPairSync} from 'node:crypto';
import {existsSync, mkdirSync, readFileSync, symlinkSync, writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {attestationSigner} from '../src/attestation-signer.mjs';
import {canonical} from '../src/crypto.mjs';
import {INTOTO_PAYLOAD_TYPE, intotoStatement, sha256Hex, signEnvelope} from '../src/dsse.mjs';
import * as P from '../src/evidence-pack.mjs';
import {FRAMEWORKS} from '../src/evidence-pack-frameworks.mjs';
import {main} from '../src/verify-cli.mjs';
import {build} from '../scripts/evidence-pack.mjs';
import {packageVerifier, tarGz} from '../scripts/package-verifier.mjs';
import {caseFor} from './support/receipt-fixture.mjs';
import {BASE, transparencyFixture} from './support/transparency-fixture.mjs';
import {tempDir} from './temp-dir.mjs';

const repo = new URL('..', import.meta.url).pathname;
// Written by commit 8b3af6c, before evidence packages existed (test/fixtures/make-pack-export-fixture.mjs).
const fixture = JSON.parse(readFileSync(new URL('./fixtures/pack-export-8b3af6c.json', import.meta.url), 'utf8'));
const vaultKey = fixture.publicKeyPem, exportBytes = Buffer.from(JSON.stringify(fixture.exportBundle));
const reportBytes = Buffer.from(JSON.stringify(fixture.caseReports[0]));
const builder = generateKeyPairSync('ed25519'), signer = attestationSigner(builder.privateKey);
const evidence = (extra = {}) => P.verifyEvidence({exportBytes, caseReports: [{bytes: reportBytes}], publicKey: vaultKey, ...extra});
const pack = async (framework = 'eu-ai-act-logging', period = null) =>
  (await P.buildPack({evidence: evidence(), framework, period, tenant: 'alpha', signer})).files;
const check = (files, extra = {}) => P.verifyPack(files, {publicKey: vaultKey, packKey: builder.publicKey, ...extra});
const copy = files => new Map([...files].map(([k, v]) => [k, Buffer.from(v)]));
const json = (files, path) => JSON.parse(files.get(path).toString('utf8'));
const put = (files, path, value) => files.set(path, Buffer.from(JSON.stringify(value, null, 1) + '\n'));
// What a dishonest builder holding its own key can publish: changed files, a matching SHA256SUMS and a re-signed statement.
async function resign(files, key = builder.privateKey) {
  const out = copy(files), statement = JSON.parse(Buffer.from(json(files, P.FILES.envelope).payload, 'base64').toString('utf8'));
  out.delete(P.FILES.envelope);
  out.set(P.FILES.sums, Buffer.from([...out.keys()].filter(p => p !== P.FILES.sums).sort().map(p => `${sha256Hex(out.get(p))}  ${p}\n`).join('')));
  const subjects = [...out.keys()].sort().map(name => ({name, sha256: sha256Hex(out.get(name))}));
  const next = intotoStatement(subjects, statement.predicateType, statement.predicate);
  put(out, P.FILES.envelope, await signEnvelope(INTOTO_PAYLOAD_TYPE, Buffer.from(canonical(next)), attestationSigner(key)));
  return out;
}
function writeDir(dir, files) {
  for (const [path, bytes] of files) { mkdirSync(join(dir, path, '..'), {recursive: true}); writeFileSync(join(dir, path), bytes); }
  return dir;
}
const run = (args, out = []) => main(args, {stdout: {write: s => out.push(s)}, stderr: {write: s => out.push(s)}});
const keys = dir => {
  writeFileSync(join(dir, 'vault.pem'), vaultKey);
  writeFileSync(join(dir, 'builder.pem'), builder.privateKey.export({format: 'pem', type: 'pkcs8'}));
  writeFileSync(join(dir, 'builder-pub.pem'), builder.publicKey.export({format: 'pem', type: 'spki'}));
  return {vault: join(dir, 'vault.pem'), builder: join(dir, 'builder.pem'), builderPub: join(dir, 'builder-pub.pem')};
};

test('an 8b3af6c-era export builds and verifies a package for each framework, with evidence present never phrased as met', async () => {
  for (const framework of FRAMEWORKS) {
    const files = await pack(framework), r = check(files), index = json(files, P.FILES.index);
    assert.equal(r.valid, true, framework);
    assert.equal(r.framework, framework);
    assert.deepEqual([r.tenant, r.export.count, r.mapping.source, r.packSigner.key], ['alpha', fixture.exportBundle.records.length, 'verifier', 'pack_key']);
    assert.deepEqual([...files.keys()].sort(), ['SHA256SUMS', 'evidence/case-reports/case-1.json', 'evidence/export.json', 'index.json', 'mapping.json',
      'pack.intoto.json', 'summary.en.md', 'summary.ko.md']);
    assert.ok(files.get(P.FILES.export).equals(exportBytes) && files.get('evidence/case-reports/case-1.json').equals(reportBytes));
    // In-toto Statement v1 with the Simple Verification Result predicate naming every other file.
    const statement = JSON.parse(Buffer.from(json(files, P.FILES.envelope).payload, 'base64').toString('utf8'));
    assert.equal(statement.predicateType, 'https://in-toto.io/attestation/svr/v0.2');
    assert.deepEqual(statement.subject.map(s => s.name), [...files.keys()].filter(p => p !== P.FILES.envelope).sort());
    assert.ok(statement.predicate.properties.includes('EVIDSCOPE_STOP_ORDER_HISTORY_VERIFIED'));
    for (const lang of ['ko', 'en']) {
      const text = files.get(P.FILES[lang]).toString();
      assert.doesNotMatch(text, /complian|compliant|준수함|적합함/i, `${framework} ${lang}`);
      assert.equal(text.split('\n').filter(l => l.startsWith('- [')).length, index.items.length);
    }
    // Every present evidence entry names verified sequences of the right record type.
    for (const item of index.items) {
      for (const e of item.evidence.filter(x => x.status === 'present')) {
        for (const seq of e.seqs) assert.equal(fixture.exportBundle.records[seq - 1].seq, seq);
      }
    }
  }
  const eu = json(await pack('eu-ai-act-logging'), P.FILES.index), item = id => eu.items.find(i => i.id === id);
  const stops = fixture.exportBundle.records.filter(r => r.type === 'agent_stop_order').map(r => r.seq);
  assert.deepEqual(item('EU-AIA-14-4-E').evidence.find(e => e.name === 'agent_stop_order').seqs, stops);
  assert.deepEqual(item('EU-AIA-14-4-D').evidence.find(e => e.name === 'case_decision').caseReports, ['evidence/case-reports/case-1.json']);
  assert.equal(item('EU-AIA-12-1').humanJudgement, null);
  const kr = json(await pack('kr-ai-basic-act'), P.FILES.index), oversight = kr.items.find(i => i.id === 'KR-34-OVERSIGHT');
  assert.equal(oversight.status, 'evidence_present');
  assert.deepEqual(oversight.humanJudgement.map(j => [j.requirementId, j.assessment, j.legalReviewRecord?.decision !== undefined]),
    [['KR-34-OVERSIGHT', 'insufficient', true]]);
  assert.equal(kr.items.find(i => i.id === 'KR-31-1').status, 'no_evidence_recorded');
});

test('every file kind, the index, the summaries and the statement are refused when changed, added or removed', async () => {
  const files = await pack('kr-ai-basic-act');
  const flip = (path, at = 40) => { const out = copy(files), b = out.get(path); b[at] ^= 1; return out; };
  for (const path of [...files.keys()].filter(p => p !== P.FILES.envelope)) {
    assert.throws(() => check(flip(path)), /digest mismatch|differs from the package files/, path);
  }
  assert.throws(() => check(flip(P.FILES.envelope, 60)), /not JSON|base64|signature/);
  const extra = copy(files).set('evidence/extra.json', Buffer.from('{}'));
  assert.throws(() => check(extra), /not named by the statement: evidence\/extra.json/);
  const missing = copy(files);
  missing.delete(P.FILES.ko);
  assert.throws(() => check(missing), /named by the statement is missing: summary.ko.md/);
  const noStatement = copy(files);
  noStatement.delete(P.FILES.envelope);
  assert.throws(() => check(noStatement), /no pack.intoto.json/);
  // Another key, or the vault key by default, does not verify the builder's statement.
  assert.throws(() => P.verifyPack(files, {publicKey: vaultKey}), /does not verify with the vault key; pass --pack-key/);
  assert.throws(() => check(files, {packKey: generateKeyPairSync('ed25519').publicKey}), /does not verify with the builder key/);
});

test('a re-signed package whose index, summary, mapping or evidence claims more than the evidence shows is refused', async () => {
  const files = await pack('eu-ai-act-logging');
  const index = json(files, P.FILES.index), wrong = async change => { const out = copy(files); change(out); return check(await resign(out)); };
  // The builder's own re-signature is accepted for an unchanged package: refusals below come from the content.
  assert.equal(check(await resign(files)).valid, true);
  await assert.rejects(wrong(out => put(out, P.FILES.index, {...index, items: index.items.map(i => i.id === 'EU-AIA-12-2-B'
    ? {...i, evidence: i.evidence.map(e => e.name === 'gap' ? {...e, status: 'present', count: 3, seqs: [1, 2, 3]} : e)} : i)})), /claims evidence|differs/);
  await assert.rejects(wrong(out => put(out, P.FILES.index, {...index, scope: {...index.scope, period: null, recordsInPeriod: 1}})), /Index differs/);
  const summary = files.get(P.FILES.en).toString();
  await assert.rejects(wrong(out => out.set(P.FILES.en, Buffer.from(summary.replace('## Items\n\n', '## Items\n\n- Logging duties are met.\n')))),
    /not traced to one index item/);
  await assert.rejects(wrong(out => out.set(P.FILES.ko, Buffer.from(files.get(P.FILES.ko).toString().replace('증거 있음**', '기록된 증거 없음**')))),
    /claims "기록된 증거 없음"/);
  await assert.rejects(wrong(out => out.set(P.FILES.en, Buffer.from(summary.replace('What this package does not prove', 'What this package proves')))),
    /Summary \(en\) differs/);
  const mapping = json(files, P.FILES.mapping);
  await assert.rejects(wrong(out => put(out, P.FILES.mapping, {...mapping, items: mapping.items.slice(1)})), /mapping differs from this verifier/);
  // Accepting the package's mapping (--mapping-from-pack) still requires the statement policy to name it and the index to follow from it.
  const shrunk = copy(files);
  put(shrunk, P.FILES.mapping, {...mapping, items: mapping.items.slice(1)});
  assert.throws(() => check(shrunk, {mappingFromPack: true}), /digest mismatch: mapping.json/);
  const resigned = await resign(shrunk);
  assert.throws(() => check(resigned, {mappingFromPack: true}), /policy does not name the package mapping/);
  const statementOf = f => JSON.parse(Buffer.from(json(f, P.FILES.envelope).payload, 'base64').toString('utf8'));
  const claimed = copy(files);
  const s = statementOf(files);
  s.predicate.properties.push('EVIDSCOPE_ROLLBACK_CHECKED');
  put(claimed, P.FILES.envelope, await signEnvelope(INTOTO_PAYLOAD_TYPE, Buffer.from(canonical(s)), signer));
  assert.throws(() => check(claimed), /did not establish: EVIDSCOPE_ROLLBACK_CHECKED/);
  // A file the statement names but no verifier step reads (here an unattached attestation) has no place in a package.
  await assert.rejects(wrong(out => out.set('evidence/case-reports/case-9.json.intoto.json', Buffer.from('{}'))), /has no place/);
  await assert.rejects(wrong(out => out.delete(P.FILES.mapping)), /Package has no mapping.json/);
  // A case report or export swapped for another valid one of the same vault no longer matches the index.
  const report = JSON.parse(reportBytes.toString());
  await assert.rejects(wrong(out => out.set('evidence/case-reports/case-1.json', Buffer.from(JSON.stringify(report, null, 2)))), /Index differs/);
  await assert.rejects(wrong(out => out.set(P.FILES.export, Buffer.from(JSON.stringify(fixture.exportBundle, null, 2)))), /Index differs/);
  const shorter = {...fixture.exportBundle, records: fixture.exportBundle.records.slice(0, -1)};
  await assert.rejects(wrong(out => out.set(P.FILES.export, Buffer.from(JSON.stringify(shorter)))), /Truncated or inconsistent export/);
});

test('summary claims and index entries without verified evidence are refused at build time', async () => {
  const files = await pack('isms-p'), index = json(files, P.FILES.index), ev = evidence();
  const ko = files.get(P.FILES.ko).toString();
  assert.throws(() => P.assertSummaryTraced(Buffer.from(ko.replace('## 항목\n\n', '## 항목\n\n- 모든 항목을 충족합니다.\n')), index, 'ko'),
    /not traced to one index item/);
  const first = ko.split('\n').find(l => l.startsWith('- ['));
  assert.throws(() => P.assertSummaryTraced(Buffer.from(ko.replace(first, first + '\n' + first)), index, 'ko'), /not traced/);
  assert.throws(() => P.assertSummaryTraced(Buffer.from(ko.replace(first + '\n', '')), index, 'ko'), /leaves out index items/);
  const none = index.items.find(i => i.status === 'no_evidence_recorded');
  assert.throws(() => P.assertIndexBacked({...index, items: [{...none, status: 'evidence_present'}]}, ev), /claims evidence_present without matching/);
  const present = index.items.find(i => i.evidence.some(e => e.status === 'present')), at = present.evidence.findIndex(e => e.status === 'present');
  const forged = (change) => ({...index, items: [{...present, evidence: present.evidence.map((e, i) => (i === at ? change(e) : e))}]});
  assert.throws(() => P.assertIndexBacked(forged(e => ({...e, seqs: [fixture.exportBundle.records.length + 5]})), ev), /not a verified/);
  assert.throws(() => P.assertIndexBacked(forged(e => ({...e, seqs: [1]})), ev), /not a verified|without matching/);
  assert.throws(() => P.assertIndexBacked(forged(e => ({...e, seqs: []})), ev), /without matching locators/);
  assert.throws(() => P.assertIndexBacked({...index, items: [{...present, humanJudgement: [{seq: 1, recordHash: 'x'}]}]}, ev), /unverified judgement/);
});

test('the builder refuses unverified exports, other tenants and foreign case reports before writing anything', async t => {
  const dir = tempDir('evidscope-pack-refuse-'), k = keys(dir), out = join(dir, 'out');
  const save = (name, value) => { writeFileSync(join(dir, name), typeof value === 'string' ? value : JSON.stringify(value)); return join(dir, name); };
  const args = (exportPath, extra = []) => ['--framework', 'isms-p', '--tenant', 'alpha', '--key', k.vault, '--signing-key', k.builder, '--out', out,
    '--export', exportPath, ...extra];
  const records = fixture.exportBundle.records, altered = structuredClone(fixture.exportBundle);
  altered.records[5].payload.note = 'changed';
  await assert.rejects(build(args(save('altered.json', altered))), /Record digest mismatch/);
  await assert.rejects(build(args(save('short.json', {...fixture.exportBundle, records: records.slice(0, -1)}))), /Truncated or inconsistent/);
  const otherKey = generateKeyPairSync('ed25519').publicKey.export({format: 'pem', type: 'spki'});
  await assert.rejects(build([...args(save('ok.json', fixture.exportBundle)).map(a => (a === k.vault ? save('other.pem', otherKey) : a))]),
    /signature|Checkpoint/i);
  await assert.rejects(build(args(join(dir, 'ok.json')).map(a => (a === 'alpha' ? 'beta' : a))), /not the requested tenant beta/);
  // A case report of another ledger (here: a later report of the same case, past this export) is refused.
  const later = structuredClone(fixture.caseReports[0]);
  later.snapshot.checkpoint.count += 1;
  await assert.rejects(build(args(join(dir, 'ok.json'), ['--case-report', save('later.json', later)])), /signature invalid|not a snapshot/);
  await assert.rejects(build(args(join(dir, 'ok.json'), ['--from', '2026-01-01T00:00:00Z'])), /--from and --to together/);
  await assert.rejects(build(args(join(dir, 'ok.json'), ['--from', '2026-02-01T00:00:00Z', '--to', '2026-01-01T00:00:00Z'])), /from before to/);
  assert.equal(existsSync(out), false, 'nothing is written when the build is refused');
  const built = await build(args(join(dir, 'ok.json'), ['--case-report', save('report.json', fixture.caseReports[0])]));
  assert.equal(built.built.directory, out);
  await assert.rejects(build(args(join(dir, 'ok.json'))), /Refusing to overwrite/);
  // The verifier CLI (and scripts/verify.mjs pack) accepts the written directory; a tenant pin of another tenant fails.
  const log = [];
  assert.equal(run(['pack', out, k.vault, '--pack-key', k.builderPub], log), 0, log.join(''));
  assert.equal(run(['pack', out, k.vault, '--pack-key', k.builderPub, '--tenant', 'beta'], log), 1);
  assert.match(log.at(-1), /tenant alpha is not beta/);
  const script = spawnSync(process.execPath, [join(repo, 'scripts', 'verify.mjs'), 'pack', out, k.vault, '--pack-key', k.builderPub], {encoding: 'utf8'});
  assert.equal(script.status, 0, script.stderr);
  assert.equal(JSON.parse(script.stdout).valid, true);
  // A symbolic link inside a package directory is refused rather than followed.
  symlinkSync(k.vault, join(out, 'evidence', 'link.pem'));
  assert.equal(run(['pack', out, k.vault, '--pack-key', k.builderPub], log), 1);
  assert.match(log.at(-1), /not a regular file/);
});

test('the period filter counts only records signed inside it, and the verifier holds the builder to that period', async () => {
  const records = fixture.exportBundle.records, caseSeq = records.find(r => r.type === 'case').seq;
  // Phase 1 only: from the first record up to (excluding) the system registration that opens phase 2 of the fixture.
  const cut = records.find(r => r.type === 'system').recordedAt, period = {from: records[0].recordedAt, to: cut};
  const files = await pack('eu-ai-act-logging', period), index = json(files, P.FILES.index), r = check(files);
  assert.deepEqual(r.period, period);
  const inside = records.filter(x => Date.parse(x.recordedAt) < Date.parse(cut)).length;
  assert.deepEqual([index.scope.recordsInPeriod, index.scope.recordsTotal], [inside, records.length]);
  const item = id => index.items.find(i => i.id === id);
  assert.equal(item('EU-AIA-14-4-E').status, 'no_evidence_recorded', 'the stop order of phase 3 is outside the period');
  assert.equal(item('EU-AIA-14-4-A').status, 'no_evidence_recorded', 'the case of phase 2 is outside the period');
  for (const e of index.items.flatMap(i => i.evidence)) {
    for (const seq of e.seqs || []) assert.ok(seq < caseSeq && Date.parse(records[seq - 1].recordedAt) < Date.parse(cut));
  }
  const kr = json(await pack('kr-ai-basic-act', period), P.FILES.index);
  assert.deepEqual(kr.items.find(i => i.id === 'KR-34-OVERSIGHT').humanJudgement, [], 'the assessment of phase 2 is outside the period');
  // The whole ledger is still verified, and a widened period in a re-signed index is refused.
  assert.equal(r.export.count, records.length);
  const widened = copy(files);
  put(widened, P.FILES.index, {...index, scope: {...index.scope, period: {...period, to: '2099-01-01T00:00:00Z'}}});
  const resigned = await resign(widened);
  assert.throws(() => check(resigned), /Index differs/);
  assert.throws(() => P.checkPeriod({from: '2026-01-01', to: '2026-02-01'}), /ISO 8601 UTC/);
});

test('with a period, the whole-ledger check alone is no evidence of that period: no log-keeping claim without a record in it', async () => {
  const records = fixture.exportBundle.records, at = type => records.find(r => r.type === type).recordedAt;
  // Nothing signed in the period; then only the registration of a system (no event, receipt or retention record).
  for (const period of [{from: '2001-01-01T00:00:00Z', to: '2001-02-01T00:00:00Z'}, {from: at('system'), to: at('assessment')}]) {
    for (const framework of FRAMEWORKS) {
      const files = await pack(framework, period), index = json(files, P.FILES.index);
      for (const item of index.items) {
        const others = item.evidence.filter(e => e.type !== 'integrityCheck' && e.status === 'present');
        assert.equal(item.status === 'evidence_present', others.length > 0, `${framework} ${item.id} in ${period.from}`);
      }
      assert.ok(!files.get(P.FILES.en).toString('utf8').includes('signed\\_ledger'), 'the ledger check is not listed as evidence of the period');
      check(files);
    }
  }
  // d7413a0 claimed evidence for Article 12(1), 19(1) and 26(6) here on the strength of records outside the period; such an index is refused.
  const period = {from: at('system'), to: at('assessment')}, files = await pack('eu-ai-act-logging', period), index = json(files, P.FILES.index);
  assert.deepEqual(index.items.filter(i => i.status === 'evidence_present').map(i => i.id), []);
  const claimed = copy(files);
  put(claimed, P.FILES.index, {...index, items: index.items.map(i => (i.id === 'EU-AIA-12-1' ? {...i, status: 'evidence_present'} : i))});
  await assert.rejects(async () => check(await resign(claimed)), /Index differs/);
  assert.throws(() => P.assertIndexBacked(json(claimed, P.FILES.index), evidence()), /claims evidence_present without matching evidence/);
  // Without a period nothing changes: the verified ledger is evidence of the log-keeping items.
  assert.equal(json(await pack('eu-ai-act-logging'), P.FILES.index).items.find(i => i.id === 'EU-AIA-19-1').status, 'evidence_present');
});

test('a package built from the vault API with witnesses carries the attestation and needs the same trust inputs to verify', async t => {
  const f = await transparencyFixture(t, {tenantLogs: true}), s = await f.open('enforce'), caseId = await caseFor(s);
  const betaCase = await caseFor(s, 'beta');
  f.write(s, 'alpha', 2);
  await s.transparency.pump();
  const dir = tempDir('evidscope-pack-api-');
  writeFileSync(join(dir, 'vault.pem'), f.publicKey.export({format: 'pem', type: 'spki'}));
  writeFileSync(join(dir, 'builder.pem'), builder.privateKey.export({format: 'pem', type: 'pkcs8'}));
  writeFileSync(join(dir, 'token'), 'alpha'.repeat(40) + '\n');
  const seen = [];
  const fetchImpl = async (url, init) => {
    seen.push([url.href, init.headers.authorization.slice(0, 12), init.redirect]);
    try {
      const body = await s.handle('GET', new URL(url.pathname + url.search, 'http://local'), {authorization: init.headers.authorization}, '');
      return {ok: true, status: 200, arrayBuffer: async () => Buffer.from(JSON.stringify(body))};
    } catch (error) { return {ok: false, status: error.status ?? 500, arrayBuffer: async () => Buffer.alloc(0)}; }
  };
  const flags = ['--witness', f.w.vkey, '--quorum', '1', '--origin-base', BASE, '--max-staleness', '3600'];
  const args = (out, extra = []) => ['--framework', 'eu-ai-act-logging', '--tenant', 'alpha', '--key', join(dir, 'vault.pem'),
    '--signing-key', join(dir, 'builder.pem'), '--out', join(dir, out), '--api', 'https://vault.example', '--token-file', join(dir, 'token'), ...extra];
  const built = await build(args('pack.tar.gz', ['--case', caseId, ...flags]), {fetchImpl});
  assert.deepEqual(seen.map(x => x[0]), ['https://vault.example/api/export?attest=intoto', `https://vault.example/api/cases/${caseId}/report?attest=intoto`]);
  assert.deepEqual(seen[0].slice(1), ['Bearer alpha', 'error']);
  const paths = built.files.map(x => x.path);
  assert.ok(paths.includes('evidence/export.json.intoto.json') && paths.includes('evidence/case-reports/case-1.json.intoto.json'));
  const files = P.readPack(built.built.file), r = check(files, {flags: {witness: [f.w.vkey], quorum: '1', 'origin-base': BASE, 'max-staleness': '3600'},
    publicKey: f.publicKey});
  for (const p of ['TRANSPARENCY_VERIFIED', 'ROLLBACK_CHECKED', 'EXPORT_ATTESTATION_VERIFIED', 'CASE_REPORTS_VERIFIED'].map(x => 'EVIDSCOPE_' + x)) {
    assert.ok(r.properties.includes(p), p);
  }
  // Without the witness keys the auditor cannot establish what the builder claimed, and the package is not accepted.
  assert.throws(() => check(files, {publicKey: f.publicKey}), /did not establish: EVIDSCOPE_ROLLBACK_CHECKED/);
  // The tarball is a plain ustar .tar.gz under evidence-pack/; links and paths outside it are refused.
  assert.throws(() => P.readTarGz(tarGz([['evidence-pack/', null], ['evidence-pack/../x', Buffer.from('x')]])), /Unsafe/);
  assert.throws(() => P.readTarGz(tarGz([['other/a.json', Buffer.from('x')]])), /outside evidence-pack/);
  // Tenant isolation: the alpha token reads no beta case, and a beta report given as a file is refused for an alpha package.
  await assert.rejects(build(args('beta-case', ['--case', betaCase]), {fetchImpl}), /answered 404/);
  const betaReport = await s.handle('GET', new URL(`/api/cases/${betaCase}/report`, 'http://local'), {authorization: 'Bearer ' + 'beta'.repeat(40)}, '');
  writeFileSync(join(dir, 'beta-report.json'), JSON.stringify(betaReport));
  await assert.rejects(build(args('mixed', ['--case-report', join(dir, 'beta-report.json')]), {fetchImpl}), /Unexpected report tenant/);
  await assert.rejects(build(args('plain', []).map(a => (a === 'https://vault.example' ? 'http://vault.example' : a)), {fetchImpl}), /must be https/);
});

test('the separately packaged verifier verifies a package offline', async t => {
  const dir = tempDir('evidscope-pack-packaged-'), k = keys(dir), files = await pack('isms-p');
  const packDir = writeDir(join(dir, 'pack'), files);
  const v = packageVerifier({out: join(dir, 'release')});
  const verify = args => spawnSync(process.execPath, [join(v.directory, 'evidscope-verify.mjs'), ...args], {encoding: 'utf8', cwd: dir});
  const ok = verify(['pack', packDir, k.vault, '--pack-key', k.builderPub]);
  assert.equal(ok.status, 0, ok.stderr);
  assert.deepEqual([JSON.parse(ok.stdout).valid, JSON.parse(ok.stdout).mapping.source], [true, 'verifier']);
  writeFileSync(join(packDir, P.FILES.en), files.get(P.FILES.en).toString().replace('evidence present', 'all requirements met'));
  const bad = verify(['pack', packDir, k.vault, '--pack-key', k.builderPub]);
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /digest mismatch: summary.en.md/);
});
