import test from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createPrivateKey, generateKeyPairSync} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {harness} from './harness.mjs';
import {tempDir} from './temp-dir.mjs';
import {demo} from '../scripts/demo.mjs';
import {digest, makeCheckpoint} from '../src/crypto.mjs';
import {NOTICE, REPORT_FORMAT, buildReport, renderMarkdown} from '../scripts/isms-p-report.mjs';

// The ISMS-P evidence report must verify the export with the existing verifier before it counts anything, refuse a
// tampered or wrongly keyed export, and say in every output that present evidence is not a finding that a criterion is met.
const alignment = JSON.parse(readFileSync(new URL('../data/isms-p-alignment.json', import.meta.url), 'utf8'));
const titles = new Map(alignment.officialItems.map(i => [i.number, i.title]));
const clone = value => JSON.parse(JSON.stringify(value));
const run = (bundle, keyFile, extra = []) => {
  const dir = tempDir('evidscope-isms-p-'), file = join(dir, 'export.json');
  writeFileSync(file, JSON.stringify(bundle));
  try {
    const options = {encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe']};
    const stdout = execFileSync(process.execPath, ['scripts/isms-p-report.mjs', file, keyFile, ...extra], options);
    return {status: 0, stdout, stderr: ''};
  } catch (error) {
    return {status: error.status, stdout: error.stdout, stderr: error.stderr};
  }
};
// Re-hash the chain and re-sign the checkpoint with the vault's own key, as a holder of that key could.
function resign(bundle, privateKey) {
  let previous = '0'.repeat(64);
  for (const row of bundle.records) {
    row.previous = previous;
    const {hash, ...record} = row;
    row.hash = digest(record);
    previous = row.hash;
  }
  bundle.checkpoint = makeCheckpoint(bundle.checkpoint.tenant, bundle.records.length, previous, privateKey);
  return bundle;
}
async function analyzeAll(h) {
  for (let i = 0; i < 10; i++) {
    const result = (await h.analyze()).body;
    if (!result.backlog && !result.processed) return;
  }
}
const entries = report => report.items.flatMap(i => i.supports.flatMap(s => s.evidence.map(e => ({...e, item: i.item}))));

test('ISMS-P evidence report verifies a demo export, counts named evidence and never assesses a criterion', async t => {
  const h = await harness(); t.after(() => h.close());
  await demo({config: h.config, ingress: h.ingress.url, audit: h.audit.url});
  await analyzeAll(h);
  const bundle = (await h.api('/api/export')).body, anchor = join(h.dir, 'trust-anchor.pem');

  const plain = run(bundle, anchor);
  assert.equal(plain.status, 0, plain.stderr);
  const report = JSON.parse(plain.stdout);
  assert.equal(report.format, REPORT_FORMAT);
  assert.equal(report.notice, NOTICE);
  assert.match(report.notice, /충족했다는 판정이 아닙니다/);
  assert.equal(report.certificationClaim, false);
  assert.equal(report.criterionAssessment, 'not_performed');
  assert.equal(report.alignment.mappingStatus, 'draft_requires_human_review');
  assert.deepEqual(report.items.map(i => i.item), alignment.alignments.map(a => a.item));
  for (const item of report.items) {
    assert.equal(item.criterionAssessment, 'not_performed', item.item);
    assert.equal(item.title, titles.get(item.item));
    assert.ok(item.manual.length, item.item);
  }
  assert.equal(report.notAligned.count, alignment.notAligned.length);
  assert.deepEqual([report.verification.valid, report.verification.count, report.verification.head], [true, bundle.records.length, bundle.checkpoint.head]);
  assert.equal(report.verification.rollbackChecked, false, 'no external checkpoint was pinned');
  assert.equal(report.verification.replay, 'not_requested');

  const all = entries(report);
  assert.equal(all.length, alignment.alignments.flatMap(a => a.supports.flatMap(s => s.evidence)).length);
  for (const e of all.filter(e => e.type === 'api' || e.type === 'file')) assert.equal(e.status, 'not_in_export', `${e.item} ${e.path}`);
  for (const e of all.filter(e => e.type === 'integrityCheck')) {
    if (e.name === 'signed_ledger') assert.deepEqual([e.status, e.count], ['verified_by_this_report', bundle.records.length]);
    else assert.equal(e.status, 'not_in_export');
  }
  for (const e of all.filter(e => e.type === 'record')) {
    const rows = bundle.records.filter(r => r.type === e.name);
    assert.equal(e.count, rows.length, e.name);
    assert.equal(e.status, rows.length ? 'present' : 'none_recorded', e.name);
    if (rows.length) assert.deepEqual(e.recordedAt, {from: rows[0].recordedAt, to: rows.at(-1).recordedAt}, e.name);
  }
  const events = bundle.disclosures.map(d => d.event);
  const approval = all.find(e => e.type === 'eventKind' && e.name === 'human_approval');
  const approvals = events.filter(e => e.kind === 'human_approval' && e.sourceKind === 'authority').length;
  assert.ok(approvals > 0);
  assert.deepEqual([approval.status, approval.count, approval.sourceKinds.authority, approval.disclosureVerified],
    ['present', approvals, approvals, approvals]);
  const notice = all.find(e => e.type === 'eventKind' && e.name === 'notice');
  assert.equal(notice.count, events.filter(e => e.kind === 'notice' && ['otlp', 'telemetry'].includes(e.sourceKind)).length);
  assert.ok(notice.sourceKinds.otlp > 0 && notice.sourceKinds.telemetry > 0, 'OTLP and telemetry notices are both counted');
  const latest = new Map(bundle.records.filter(r => r.type === 'evaluation').map(r => [r.payload.actionId, r.payload]));
  const findingCount = code => [...latest.values()].flatMap(v => v.findings).filter(f => f.code === code).length;
  for (const e of all.filter(e => e.type === 'finding')) assert.equal(e.count, findingCount(e.code), e.code);
  assert.ok(all.some(e => e.type === 'finding' && e.count > 0), 'the demo raises at least one named finding');
  assert.ok(all.some(e => e.status === 'none_recorded'), 'kinds the demo never records are reported as none_recorded');

  // A pinned external checkpoint and --replay feed the same verifier and replay as scripts/verify.mjs.
  const dir = tempDir('evidscope-isms-p-cp-'), pinned = join(dir, 'checkpoint.json');
  writeFileSync(pinned, JSON.stringify(bundle.checkpoint));
  const replayed = run(bundle, anchor, [pinned, '--replay']);
  assert.equal(replayed.status, 0, replayed.stderr);
  const checked = JSON.parse(replayed.stdout);
  assert.equal(checked.verification.rollbackChecked, true);
  assert.equal(checked.verification.replay.mismatch, 0);
  assert.ok(checked.verification.replay.replayed > 0);
  for (const e of entries(checked).filter(e => e.type === 'finding' && e.count)) assert.equal(e.replay.replayed + e.replay.notReplayable, e.actions, e.code);

  const markdown = run(bundle, anchor, ['--markdown']);
  assert.equal(markdown.status, 0, markdown.stderr);
  assert.ok(markdown.stdout.startsWith('# ISMS-P 항목별 증거 목록\n'));
  assert.ok(markdown.stdout.includes(`**${NOTICE}**`));
  assert.ok(markdown.stdout.includes('criterionAssessment: not_performed'));
  assert.ok(markdown.stdout.includes('확인하지 않음: 외부 체크포인트·위트니스 없이 검증했습니다'));
  for (const a of alignment.alignments) assert.ok(markdown.stdout.includes(`### ${a.item} ${titles.get(a.item)}\n`), a.item);
  for (const text of ['내보내기에 없음(not_in_export)', '기록 없음(none_recorded)', '이 보고서의 오프라인 검증으로 확인', '## 한계']) {
    assert.ok(markdown.stdout.includes(text), text);
  }
  assert.doesNotMatch(markdown.stdout, /충족(한다|함|합니다)|준수(한다|함|합니다)/);

  // Refusals: nothing reaches stdout when verification or replay fails.
  const altered = clone(bundle), asset = altered.records.find(r => r.type === 'asset');
  asset.payload.owner = 'someone-else';
  const tampered = run(altered, anchor);
  assert.deepEqual([tampered.status, tampered.stdout], [1, '']);
  assert.match(tampered.stderr, /Record digest mismatch/);

  const forged = clone(bundle), disclosure = forged.disclosures.find(d => d.event.kind === 'human_approval');
  disclosure.event.reviewer = 'forged-reviewer';
  const disclosed = run(forged, anchor);
  assert.deepEqual([disclosed.status, disclosed.stdout], [1, '']);
  assert.match(disclosed.stderr, /Missing or altered retained event disclosure/);

  const extra = clone(bundle);
  extra.records.push({...extra.records.at(-1), seq: extra.records.length + 1});
  const appended = run(extra, anchor);
  assert.deepEqual([appended.status, appended.stdout], [1, '']);

  const other = join(dir, 'other.pem');
  writeFileSync(other, generateKeyPairSync('ed25519').publicKey.export({type: 'spki', format: 'pem'}));
  const wrongKey = run(bundle, other);
  assert.deepEqual([wrongKey.status, wrongKey.stdout], [1, '']);

  const rollback = run(bundle, anchor, [pinned]);
  assert.equal(rollback.status, 0, rollback.stderr);
  const older = clone(bundle);
  older.records.pop();
  const truncated = run(resign(older, createPrivateKey(readFileSync(join(h.dir, 'signing-private.pem')))), anchor, [pinned]);
  assert.deepEqual([truncated.status, truncated.stdout], [1, '']);
  assert.match(truncated.stderr, /External checkpoint mismatch/);

  // A holder of the vault key can re-sign an altered finding; the signature then verifies, so only --replay notices it.
  const resigned = clone(bundle), evaluation = resigned.records.findLast(r => r.type === 'evaluation' && r.payload.findings.length);
  evaluation.payload.findings = evaluation.payload.findings.slice(1);
  resign(resigned, createPrivateKey(readFileSync(join(h.dir, 'signing-private.pem'))));
  assert.equal(run(resigned, anchor).status, 0);
  const mismatch = run(resigned, anchor, ['--replay']);
  assert.deepEqual([mismatch.status, mismatch.stdout], [1, '']);
  assert.match(mismatch.stderr, /Policy replay mismatch in \d+ evaluation\(s\); no report produced/);

  const usage = run(bundle, anchor, [pinned, 'extra-positional']);
  assert.deepEqual([usage.status, usage.stdout], [1, '']);
  assert.match(usage.stderr, /^Usage: /);
});

test('the Markdown rendering escapes bundle-derived text and labels missing kinds without guessing', () => {
  const bundle = {checkpoint: {head: 'a'.repeat(64)}, records: [
    {seq: 1, type: 'event', recordedAt: '2026-10-07T00:00:00.000Z', payload: {kind: 'intent', sourceKind: 'agent', occurredAt: 'not-a-time'}},
    {seq: 2, type: 'asset', recordedAt: '2026-10-07T00:00:01.000Z', payload: {id: 'a'}},
    {seq: 3, type: 'event', recordedAt: '2026-10-07T00:00:02.000Z', payload: {format: 'evidscope-encrypted-event-v1', keyId: 'erased', kind: 'intent'}},
  ], disclosures: []};
  const verification = {valid: true, tenant: 'alpha|<b>x</b>\n# injected', count: 2, rollbackChecked: false, disclosedEvents: 0, erasedEvents: 3,
    scope: 'test'};
  const report = buildReport(bundle, alignment, verification, null), all = entries(report);
  const intent = all.find(e => e.type === 'eventKind' && e.name === 'intent');
  assert.deepEqual([intent.count, intent.disclosureVerified, intent.sourceClaimedOccurredAt], [1, 0, null], 'a sealed event without disclosure is not read');
  assert.equal(all.find(e => e.type === 'record' && e.name === 'retention_disposition').status, 'none_recorded');
  assert.equal(all.find(e => e.type === 'finding').status, 'none_recorded', 'no evaluation means no finding is counted');
  assert.equal(report.verification.erasedEvents, 3);
  const page = renderMarkdown(report);
  assert.ok(page.includes('| tenant | alpha\\|\\<b\\>x\\</b\\> \\# injected |'));
  assert.doesNotMatch(page, /\n# injected/);
});
