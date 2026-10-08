// Auditor evidence packages (docs/evidence-pack.md): a signed export, its attestation and case reports, a machine-readable
// index of evidence per requirement item, Korean and English summaries generated from the index, and a DSSE envelope whose
// in-toto Statement v1 names every file (predicate: in-toto Simple Verification Result v0.2). Pure functions shared by
// scripts/evidence-pack.mjs and the offline verifier: the verifier recomputes the index and the summaries from the verified
// evidence and accepts the package only when every byte matches. "Evidence present" never means that an item is met.
import {lstatSync, readdirSync, readFileSync, statSync} from 'node:fs';
import {join} from 'node:path';
import {gunzipSync} from 'node:zlib';
import {canonical, verifyBundle} from './crypto.mjs';
import {ed25519Verifier, INTOTO_PAYLOAD_TYPE, intotoStatement, openEnvelope, parseStatement, sha256Hex, signEnvelope} from './dsse.mjs';
import {evidenceName, inPeriod, inventory, measure, timeRange} from './evidence-inventory.mjs';
import {checkMapping, frameworkMapping, mappingBytes} from './evidence-pack-frameworks.mjs';
import {replayEvaluations} from './policy-replay.mjs';
import {REGISTRY_TYPES, verifyRegistryHistory} from './agent-registry.mjs';
import {STOP_ORDER_TYPE, verifyExportStopOrders} from './stop-orders.mjs';
import {APPROVAL_TYPE, verifyApprovalHistory} from './approvals.mjs';
import {ATTESTED_FILE_FORMAT, requirementResults, verifyAttestation} from './receipts.mjs';
import {verifyCaseReport} from './report-verifier.mjs';
import {transparencyOptions} from './verify-options.mjs';

const DOC = 'https://github.com/ki0915/EvidScope/blob/main/docs/evidence-pack.md';
export const SVR_PREDICATE = 'https://in-toto.io/attestation/svr/v0.2', BUILDER_ID = `${DOC}#builder-v1`;
export const INDEX_FORMAT = 'evidscope-evidence-pack-index-v1', TAR_ROOT = 'evidence-pack';
export const FILES = {envelope: 'pack.intoto.json', sums: 'SHA256SUMS', index: 'index.json', mapping: 'mapping.json', ko: 'summary.ko.md',
  en: 'summary.en.md', export: 'evidence/export.json', exportAttestation: 'evidence/export.json.intoto.json', cases: 'evidence/case-reports/'};
const MiB = 1024 * 1024, MAX_SEQS = 1000, MAX_FILES = 512;
const SAFE_PATH = /^(?:[A-Za-z0-9][A-Za-z0-9._-]{0,63}\/){0,3}[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/, ISO_UTC = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,3})?Z$/;
const plain = v => !!v && typeof v === 'object' && !Array.isArray(v);
const jsonBytes = value => Buffer.from(JSON.stringify(value, null, 1) + '\n', 'utf8');
export const safePackPath = p => typeof p === 'string' && SAFE_PATH.test(p) && !p.split('/').some(s => s === '.' || s === '..' || s.includes('..'));
function parseJson(bytes, what) {
  const buf = Buffer.from(bytes), text = buf.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(buf)) throw Error(`${what} is not UTF-8`);
  try { return JSON.parse(text); } catch { throw Error(`${what} is not JSON`); }
}
export function checkPeriod(period) {
  if (period === null || period === undefined) return null;
  if (!plain(period) || !ISO_UTC.test(period.from ?? '') || !ISO_UTC.test(period.to ?? '') || !(Date.parse(period.from) < Date.parse(period.to))) {
    throw Error('Period must be {from, to}: ISO 8601 UTC times (…Z) with from before to');
  }
  return {from: period.from, to: period.to};
}
// An API response wrapper (?attest=intoto) is unpacked into the exact attested bytes and its envelope.
export function attestedInput(bytes, what) {
  const value = parseJson(bytes, what);
  if (value?.format !== ATTESTED_FILE_FORMAT) return {bytes: Buffer.from(bytes), attestation: null};
  const content = value.file?.content;
  if (typeof content !== 'string' || !plain(value.envelope) || sha256Hex(Buffer.from(content, 'utf8')) !== value.file.sha256) {
    throw Error(`${what} is a malformed attested file response`);
  }
  return {bytes: Buffer.from(content, 'utf8'), attestation: value.envelope};
}

// ---------- evidence verification: the checks of scripts/verify.mjs (signature, chain, transparency, histories, replay) ----------
const historyError = (name, h) =>
  Error(`${name} history does not verify: ${(h.problems || []).slice(0, 3).map(p => p.message ?? JSON.stringify(p)).join('; ')}`);
// flags: the transparency flags of the CLIs (src/verify-options.mjs); without any, transparency material the export carries is still checked.
export function verifyEvidence({exportBytes, exportAttestation = null, caseReports = [], publicKey, checkpoint, flags = {}}) {
  if (exportBytes.length > 512 * MiB) throw Error('Export exceeds 512 MiB');
  const bundle = parseJson(exportBytes, 'Export');
  if (!plain(bundle) || !Array.isArray(bundle.records)) throw Error('Export is not an EvidScope export');
  const t = transparencyOptions(flags, bundle.transparency !== undefined), options = t ? {transparency: t} : {};
  const result = verifyBundle(bundle, publicKey, checkpoint, options), replay = replayEvaluations(bundle);
  if (!replay.valid) throw Error(`Policy replay mismatch in ${replay.summary.mismatch} evaluation(s)`);
  const registry = bundle.records.some(r => REGISTRY_TYPES.includes(r.type)) ? verifyRegistryHistory(bundle.records) : null;
  if (registry && !registry.valid) throw historyError('Registry', registry);
  const approvals = bundle.records.some(r => r.type === APPROVAL_TYPE) ? verifyApprovalHistory(bundle.records) : null;
  if (approvals && !approvals.valid) throw historyError('Approval', approvals);
  const stopOrders = bundle.records.some(r => r.type === STOP_ORDER_TYPE) ? verifyExportStopOrders(bundle) : null;
  if (stopOrders && !stopOrders.valid) throw historyError('Stop order', stopOrders);
  const attestation = exportAttestation ? verifyAttestation({envelope: exportAttestation, subject: exportBytes, publicKey, options}) : null;
  const decisions = new Map();
  for (const r of bundle.records) if (r.type === 'case_decision' && typeof r.payload?.id === 'string') decisions.set(r.payload.id, r);
  const cases = caseReports.map(c => {
    const report = parseJson(c.bytes, 'Case report'), v = verifyCaseReport(report, publicKey, {expectedTenant: result.tenant, ...options});
    // The report must be a snapshot of this very ledger: its checkpoint head and every event and decision it shows are export records.
    const cp = report.snapshot.checkpoint, head = bundle.records[cp.count - 1];
    if (!head || head.hash !== cp.head) throw Error(`Case report ${v.caseId} is not a snapshot of this export (checkpoint ${cp.count})`);
    const events = Array.isArray(report.snapshot.action.events) ? report.snapshot.action.events : [];
    for (const e of events) {
      const row = bundle.records[e.seq - 1];
      if (!row || row.type !== 'event' || row.hash !== e.hash) throw Error(`Case report ${v.caseId} event ${e.seq} differs from the export`);
    }
    const shown = (Array.isArray(report.snapshot.review.decisions) ? report.snapshot.review.decisions : []).map(d => {
      const row = decisions.get(d?.id);
      if (!row || canonical(row.payload) !== canonical(d)) throw Error(`Case report ${v.caseId} decision ${d?.id} differs from the export`);
      return {id: d.id, seq: row.seq, conclusion: d.conclusion};
    });
    const att = c.attestation ? verifyAttestation({envelope: c.attestation, subject: c.bytes, publicKey, options}) : null;
    return {bytes: Buffer.from(c.bytes), attestation: c.attestation, report, result: v, attestationResult: att, decisions: shown,
      eventSeqs: events.map(e => e.seq)};
  });
  if (new Set(cases.map(c => c.result.reportHash)).size !== cases.length) throw Error('The same case report is given twice');
  return {bundle, exportBytes: Buffer.from(exportBytes), exportAttestation, result, replay, registry, approvals, stopOrders, attestation, cases};
}

// ---------- index ----------
const capSeqs = e => (Array.isArray(e.seqs) && e.seqs.length > MAX_SEQS ? {...e, seqs: e.seqs.slice(0, MAX_SEQS), seqsOmitted: e.seqs.length - MAX_SEQS} : e);
const PRESENT = new Set(['present', 'verified_by_this_package']);
// With a period, the signed-ledger check covers the whole ledger and is no evidence of that period by itself (round 7: a package for
// a period without one log record still claimed "evidence present" for the log-keeping items).
function itemStatus(evidence, period = null) {
  if (evidence.some(e => PRESENT.has(e.status) && !(period && e.type === 'integrityCheck'))) return 'evidence_present';
  return evidence.some(e => e.status === 'none_recorded' || PRESENT.has(e.status)) ? 'no_evidence_recorded' : 'not_in_export';
}
const caseFile = i => `${FILES.cases}case-${i + 1}.json`;
// Same inputs, same index: everything here comes from verified evidence, the mapping and the period.
export function computeIndex({evidence, mapping, period = null}) {
  const {bundle, result, replay} = evidence, data = inventory(bundle, replay, {period, locators: true});
  const inside = bundle.records.filter(r => inPeriod(period, r.recordedAt)), judgements = requirementResults(inside);
  const cases = evidence.cases.map((c, i) => ({file: caseFile(i), sha256: sha256Hex(c.bytes), caseId: c.result.caseId, actionId: c.result.actionId,
    reportHash: c.result.reportHash, exportedAt: c.result.exportedAt, reviewState: c.result.reviewState, checkpointCount: c.report.snapshot.checkpoint.count,
    eventSeqs: c.eventSeqs, decisions: c.decisions, attestation: c.attestation ? caseFile(i) + '.intoto.json' : null}));
  const items = mapping.items.map(item => {
    const found = item.evidence.map(e => {
      const m = capSeqs({type: e.type, ...evidenceName(e), ...(e.checkItems ? {checkItems: e.checkItems} : {}), ...(e.what ? {what: e.what} : {}),
        ...measure(e, data, result, 'verified_by_this_package')});
      if (e.type !== 'record' || e.name !== 'case_decision' || !m.seqs) return m;
      const reports = cases.filter(c => c.decisions.some(d => m.seqs.includes(d.seq))).map(c => c.file);
      return reports.length ? {...m, caseReports: reports} : m;
    });
    const human = item.judgement === null ? null : judgements.filter(j => item.judgement.includes(j.requirementId));
    return {id: item.id, citation: item.citation, title: item.title, sourceStatus: item.sourceStatus, status: itemStatus(found, period), evidence: found,
      humanJudgement: human};
  });
  const tally = s => items.filter(i => i.status === s).length;
  return {format: INDEX_FORMAT, notice: {en: 'Evidence present is not a finding that a requirement is met. This index lists verified records only.',
    ko: '증거가 있다는 것은 요구사항을 충족했다는 판정이 아닙니다. 이 색인은 검증한 기록만 나열합니다.'},
  framework: {id: mapping.id, title: mapping.title, mappingStatus: mapping.mappingStatus, mapping: FILES.mapping},
  scope: {tenant: result.tenant, period, recordsInPeriod: inside.length, recordsTotal: bundle.records.length,
    recordedAt: timeRange(inside.map(r => r.recordedAt))},
  evidence: {export: {file: FILES.export, sha256: sha256Hex(evidence.exportBytes), tenant: result.tenant, count: result.count,
    head: bundle.checkpoint.head, disclosedEvents: result.disclosedEvents, erasedEvents: result.erasedEvents,
    replay: {engine: replay.engine, evaluations: replay.summary.evaluations, replayed: replay.summary.replayed, mismatch: replay.summary.mismatch,
      notReplayable: replay.summary.notReplayable},
    histories: {registry: evidence.registry ? 'verified' : 'absent', approvals: evidence.approvals ? 'verified' : 'absent',
      stopOrders: evidence.stopOrders ? 'verified' : 'absent'},
    transparencyMaterial: bundle.transparency !== undefined, attestation: evidence.exportAttestation ? FILES.exportAttestation : null},
  caseReports: cases},
  counts: {items: items.length, evidencePresent: tally('evidence_present'), noEvidenceRecorded: tally('no_evidence_recorded'),
    notInExport: tally('not_in_export')},
  items, notMapped: mapping.notMapped};
}

// Every index claim must resolve to a verified record of the right kind inside the period; the builder and verifier both run it.
export function assertIndexBacked(index, evidence) {
  const records = evidence.bundle.records, period = index.scope.period;
  const kindOf = {record: null, eventKind: 'event', checkType: 'event', finding: 'evaluation'};
  for (const item of index.items) {
    if (item.status !== itemStatus(item.evidence, period)) throw Error(`Index item ${item.id} claims ${item.status} without matching evidence`);
    for (const e of item.evidence) {
      const located = (e.seqs?.length ?? 0) + (e.seqsOmitted ?? 0), expected = e.type === 'finding' ? e.actions : e.count;
      if (e.status === 'present' ? !(e.count > 0 && located > 0 && located === expected) : e.seqs !== undefined) {
        throw Error(`Index item ${item.id} claims evidence without matching locators`);
      }
      for (const seq of e.seqs || []) {
        const row = records[seq - 1], type = kindOf[e.type] ?? e.name;
        if (!row || row.seq !== seq || row.type !== type || !inPeriod(period, row.recordedAt)) {
          throw Error(`Index item ${item.id} names sequence ${seq}, which is not a verified ${type} record in the period`);
        }
      }
      for (const file of e.caseReports || []) {
        if (!index.evidence.caseReports.some(c => c.file === file)) throw Error(`Index item ${item.id} names a missing case report ${file}`);
      }
    }
    for (const j of item.humanJudgement || []) {
      const row = records[j.seq - 1];
      if (!row || row.type !== 'assessment' || row.hash !== j.recordHash) throw Error(`Index item ${item.id} names an unverified judgement`);
    }
  }
  return true;
}

// ---------- summaries: generated from the index, one claim line per item ----------
const LABEL = {
  ko: {evidence_present: '증거 있음', no_evidence_recorded: '기록된 증거 없음', not_in_export: '내보내기에 담기지 않는 증거 종류만 지정됨'},
  en: {evidence_present: 'evidence present', no_evidence_recorded: 'no evidence recorded', not_in_export: 'only evidence kinds that exports do not carry'},
};
const md = value => String(value).replace(/[\r\n]+/g, ' ').replace(/[\\`*_|<>[\]#!]/g, c => '\\' + c);
const seqSpan = e => (e.seqs?.length ? ` (seq ${e.seqs[0]}${e.seqs.length > 1 ? `–${e.seqs.at(-1)}` : ''}${e.seqsOmitted ? `, +${e.seqsOmitted}` : ''})` : '');
const evidenceLabel = e => md(e.type === 'finding' ? `finding ${e.code}` : e.type === 'eventKind' ? `event ${e.name}/${e.source}`
  : e.type === 'checkType' ? `governance_check ${e.name}` : e.type === 'integrityCheck' ? `${e.name}` : `record ${e.name}`);
const TEXT = {
  ko: {title: 'EvidScope 증거 묶음 요약', made: '이 요약은 index.json에서 생성되었고 검증기가 다시 생성해 바이트 단위로 대조합니다.',
    notice: '"증거 있음"은 요구사항을 충족했다는 판정이 아닙니다. 법적 판단은 사람이 원문과 함께 합니다.', verification: '검증한 증거',
    items: '항목', judgement: '사람 판단', none: '없음', legal: '법률 검토 기록', notMapped: '대응하지 않은 조항', limits: '이 묶음이 증명하지 않는 것',
    period: '기간(recordedAt)', all: '전체', records: '기록', exportLine: '서명 내보내기', replay: '평가 재계산', cases: '사건 보고서'},
  en: {title: 'EvidScope evidence package summary', made: 'Generated from index.json; the verifier regenerates it and compares every byte.',
    notice: '"Evidence present" is not a finding that a requirement is met. Legal judgement stays with people reading the sources.',
    verification: 'Verified evidence', items: 'Items', judgement: 'human judgement', none: 'none', legal: 'legal review record',
    notMapped: 'Provisions not mapped', limits: 'What this package does not prove', period: 'Period (recordedAt)', all: 'all',
    records: 'records', exportLine: 'Signed export', replay: 'evaluation replay', cases: 'Case reports'},
};
export const LIMITS = {
  ko: ['법적 요구사항의 충족이나 인증 적합성. 대응표 자체가 사람 검토 전 초안입니다.',
    '수집의 완전성. EvidScope에 보내지 않은 행동과 출처는 보이지 않으며, 0건은 통제가 없다는 뜻이 아닙니다.',
    '출처가 스스로 보고한 내용(occurredAt, 상태, 측정값)의 진실성. 서명은 vault가 받은 기록을 보증할 뿐입니다.',
    '외부 체크포인트나 위트니스 없이 검증하면 서명 키를 가진 호스트의 되돌리기·잘라내기를 배제하지 못합니다.'],
  en: ['That any legal requirement is met or that a certification criterion is satisfied; the mapping itself is a draft for human review.',
    'Completeness of collection: actions and sources not sent to EvidScope are invisible, and zero records does not mean that a control is absent.',
    'Truth of self-reported fields (occurredAt, status, measurements): the signature covers what the vault received.',
    'Without an external checkpoint or witnesses, a host holding the signing key could roll back or truncate the ledger.'],
};
export function renderSummary(index, lang) {
  const t = TEXT[lang], x = index.evidence.export, period = index.scope.period;
  const lines = [`# ${t.title}: ${md(index.framework.title[lang] ?? index.framework.title.ko)}`, '', `> ${t.notice}`, `> ${t.made}`, '',
    `## ${t.verification}`, '',
    `- ${t.exportLine}: tenant ${md(x.tenant)}, ${x.count} ${t.records}, head \`${x.head}\`, ${t.replay} ${x.replay.replayed}/${x.replay.evaluations}`
      + ` (mismatch ${x.replay.mismatch}, not replayable ${x.replay.notReplayable})`,
    `- ${t.period}: ${period ? `${period.from} – ${period.to}` : t.all}; ${index.scope.recordsInPeriod}/${index.scope.recordsTotal} ${t.records}`,
    `- ${t.cases}: ${index.evidence.caseReports.length ? index.evidence.caseReports.map(c => `${c.file} (${md(c.reviewState)})`).join(', ') : t.none}`,
    '', `## ${t.items}`, ''];
  for (const item of index.items) {
    const present = item.status !== 'evidence_present' ? [] : item.evidence.filter(e => PRESENT.has(e.status))
      .map(e => `${evidenceLabel(e)} ${e.count}${seqSpan(e)}${e.caseReports ? ' → ' + e.caseReports.map(md).join(', ') : ''}`);
    const judgement = j => `${md(j.assessment)}/${md(j.applicability)} seq ${j.seq}${j.legalReviewRecord ? `, ${t.legal} seq ${j.legalReviewRecord.seq}` : ''}`;
    const judged = item.humanJudgement === null ? ''
      : `; ${t.judgement}: ${item.humanJudgement.length ? item.humanJudgement.map(judgement).join(', ') : t.none}`;
    lines.push(`- [${item.id}] ${md(item.citation)} — ${md(item.title[lang] ?? item.title.ko)}: **${LABEL[lang][item.status]}**`
      + `${present.length ? ` — ${present.join(', ')}` : ''}${judged}`);
  }
  lines.push('', `## ${t.notMapped}`, '', ...(index.notMapped.length ? index.notMapped.map(n => `- ${md(n.ref)}: ${md(n.reason[lang])}`) : [`- ${t.none}`]),
    '', `## ${t.limits}`, '', ...LIMITS[lang].map(l => `- ${l}`), '');
  return Buffer.from(lines.join('\n'), 'utf8');
}
// Every line of the items section is a claim about exactly one index item, with that item's status; nothing else may appear there.
export function assertSummaryTraced(summary, index, lang) {
  const text = Buffer.from(summary).toString('utf8'), heading = `## ${TEXT[lang].items}`, start = text.indexOf(`\n${heading}\n`);
  if (start < 0) throw Error(`Summary (${lang}) has no items section`);
  const body = text.slice(start + heading.length + 2), end = body.indexOf('\n## '), lines = body.slice(0, end < 0 ? undefined : end).split('\n');
  const seen = new Set(), items = new Map(index.items.map(i => [i.id, i]));
  for (const line of lines.filter(l => l.trim())) {
    const m = line.match(/^- \[([A-Z][A-Z0-9.-]*)\] .*: \*\*([^*]+)\*\*/), item = m && items.get(m[1]);
    if (!item || seen.has(m[1])) throw Error(`Summary (${lang}) line is not traced to one index item: ${line.slice(0, 80)}`);
    if (m[2] !== LABEL[lang][item.status]) throw Error(`Summary (${lang}) claims "${m[2]}" for ${m[1]}, which the index records as ${item.status}`);
    seen.add(m[1]);
  }
  if (seen.size !== items.size) throw Error(`Summary (${lang}) leaves out index items`);
  return true;
}

// ---------- statement ----------
// Properties are the checks the builder ran; a verifier accepts only those it establishes itself.
export function establishedProperties(evidence) {
  const p = ['EVIDSCOPE_EXPORT_SIGNATURE_AND_CHAIN_VERIFIED', 'EVIDSCOPE_EVALUATION_REPLAY_MATCHED'];
  if (evidence.registry) p.push('EVIDSCOPE_REGISTRY_HISTORY_VERIFIED');
  if (evidence.approvals) p.push('EVIDSCOPE_APPROVAL_HISTORY_VERIFIED');
  if (evidence.stopOrders) p.push('EVIDSCOPE_STOP_ORDER_HISTORY_VERIFIED');
  if (evidence.result.transparency) p.push('EVIDSCOPE_TRANSPARENCY_VERIFIED');
  if (evidence.result.rollbackChecked) p.push('EVIDSCOPE_ROLLBACK_CHECKED');
  if (evidence.attestation) p.push('EVIDSCOPE_EXPORT_ATTESTATION_VERIFIED');
  if (evidence.cases.length) p.push('EVIDSCOPE_CASE_REPORTS_VERIFIED');
  return [...p, 'EVIDSCOPE_INDEX_RECOMPUTED_FROM_VERIFIED_EVIDENCE', 'EVIDSCOPE_SUMMARY_GENERATED_FROM_INDEX'];
}
const sumsFile = files => Buffer.from([...files.keys()].filter(p => p !== FILES.envelope && p !== FILES.sums).sort()
  .map(p => `${sha256Hex(files.get(p))}  ${p}\n`).join(''), 'utf8');

// signer: {keyid, sign(pae) -> signature}, e.g. src/attestation-signer.mjs. Returns the package files; nothing is written here.
export async function buildPack({evidence, framework, period = null, tenant, signer, now = new Date()}) {
  if (tenant !== evidence.result.tenant) throw Error(`Export tenant ${evidence.result.tenant} is not the requested tenant ${tenant}`);
  const mapping = frameworkMapping(framework), mappingFile = mappingBytes(mapping), index = computeIndex({evidence, mapping, period: checkPeriod(period)});
  assertIndexBacked(index, evidence);
  const files = new Map([[FILES.export, evidence.exportBytes]]);
  if (evidence.exportAttestation) files.set(FILES.exportAttestation, jsonBytes(evidence.exportAttestation));
  evidence.cases.forEach((c, i) => {
    files.set(caseFile(i), c.bytes);
    if (c.attestation) files.set(caseFile(i) + '.intoto.json', jsonBytes(c.attestation));
  });
  files.set(FILES.mapping, mappingFile).set(FILES.index, jsonBytes(index));
  for (const lang of ['ko', 'en']) {
    const summary = renderSummary(index, lang);
    assertSummaryTraced(summary, index, lang);
    files.set(FILES[lang], summary);
  }
  files.set(FILES.sums, sumsFile(files));
  const subjects = [...files.keys()].sort().map(name => ({name, sha256: sha256Hex(files.get(name))}));
  const statement = intotoStatement(subjects, SVR_PREDICATE, {verifier: {id: BUILDER_ID, policies: [{name: FILES.mapping,
    uri: `${DOC}#${framework}`, digest: {sha256: sha256Hex(mappingFile)}}]}, timeCreated: now.toISOString(), properties: establishedProperties(evidence)});
  files.set(FILES.envelope, jsonBytes(await signEnvelope(INTOTO_PAYLOAD_TYPE, Buffer.from(canonical(statement), 'utf8'), signer)));
  return {files, index};
}

// ---------- reading a package ----------
// A ustar .tar.gz with every entry under evidence-pack/: regular files and directories only, no links, no duplicates.
export function readTarGz(bytes, {maxBytes = 1024 * MiB} = {}) {
  const tar = gunzipSync(bytes, {maxOutputLength: maxBytes}), files = new Map();
  const field = (h, o, l) => h.subarray(o, o + l).toString('utf8').replace(/\0.*$/s, '');
  for (let off = 0; ; ) {
    if (off + 512 > tar.length) throw Error('Truncated tar archive');
    const h = tar.subarray(off, off + 512);
    if (h.every(b => b === 0)) break;
    const sum = h.reduce((s, b, i) => s + (i >= 148 && i < 156 ? 32 : b), 0), size = parseInt(field(h, 124, 12).trim() || '0', 8);
    if (sum !== parseInt(field(h, 148, 8).trim(), 8) || !Number.isSafeInteger(size) || size < 0) throw Error('Corrupt tar header');
    const prefix = field(h, 345, 155), path = (prefix ? prefix + '/' : '') + field(h, 0, 100), type = String.fromCharCode(h[156] || 48);
    if (!path.startsWith(TAR_ROOT + '/')) throw Error('Tar entry outside ' + TAR_ROOT + '/: ' + path.slice(0, 80));
    const rel = path.slice(TAR_ROOT.length + 1).replace(/\/$/, '');
    if (type === '5') { if (rel && !safePackPath(rel)) throw Error('Unsafe tar directory ' + rel.slice(0, 80)); }
    else if (type === '0') {
      if (!safePackPath(rel) || files.has(rel)) throw Error('Unsafe or duplicate tar entry ' + rel.slice(0, 80));
      if (off + 512 + size > tar.length) throw Error('Truncated tar archive');
      files.set(rel, Buffer.from(tar.subarray(off + 512, off + 512 + size)));
    } else throw Error('Tar entry type ' + JSON.stringify(type) + ' is not allowed in an evidence package');
    off += 512 + Math.ceil(size / 512) * 512;
    if (files.size > MAX_FILES) throw Error('Too many files in the package');
  }
  return files;
}

// A package directory: regular files only (no links, devices or FIFOs), at most MAX_FILES and 1 GiB in all.
export function readPackDirectory(dir) {
  const files = new Map();
  let total = 0;
  const walk = rel => {
    for (const entry of readdirSync(join(dir, rel), {withFileTypes: true}).sort((a, b) => (a.name < b.name ? -1 : 1))) {
      const path = rel ? `${rel}/${entry.name}` : entry.name, st = lstatSync(join(dir, path));
      if (st.isDirectory()) { walk(path); continue; }
      if (!st.isFile() || !safePackPath(path)) throw Error('Package entry is not a regular file with a safe name: ' + path.slice(0, 80));
      if (files.size >= MAX_FILES || (total += st.size) > 1024 * MiB) throw Error('Package exceeds 512 files or 1 GiB');
      files.set(path, readFileSync(join(dir, path)));
    }
  };
  walk('');
  return files;
}
export function readPack(path) {
  const st = statSync(path);
  if (st.isDirectory()) return readPackDirectory(path);
  if (!st.isFile() || st.size > 512 * MiB) throw Error(`Package ${path} is not a directory or a .tar.gz of at most 512 MiB`);
  return readTarGz(readFileSync(path));
}

// files: Map path -> bytes (a directory read or readTarGz). Options as verifyEvidence, plus packKey (the builder's public key;
// default the vault key), expectedTenant and mappingFromPack (accept the package's own mapping when it differs from this verifier's).
export function verifyPack(files, {publicKey, packKey, checkpoint, flags = {}, expectedTenant, mappingFromPack = false}) {
  const envelopeBytes = files.get(FILES.envelope);
  if (!envelopeBytes) throw Error(`Package has no ${FILES.envelope}`);
  let opened;
  try { opened = openEnvelope(parseJson(envelopeBytes, FILES.envelope), [ed25519Verifier(packKey ?? publicKey)]); } catch (error) {
    throw error.message === 'DSSE signature verification failed'
      ? Error(`Package statement signature does not verify with the ${packKey ? 'builder' : 'vault'} key${packKey ? '' : '; pass --pack-key BUILDER_KEY.pem'}`)
      : error;
  }
  const statement = parseStatement(opened.body);
  if (canonical(statement) !== opened.body.toString('utf8')) throw Error('Package statement is not canonical JSON');
  const p = statement.predicate;
  if (statement.predicateType !== SVR_PREDICATE || !plain(p) || p.verifier?.id !== BUILDER_ID || !Array.isArray(p.verifier.policies)
    || !Array.isArray(p.properties) || p.properties.some(x => typeof x !== 'string') || !ISO_UTC.test(p.timeCreated ?? '')) {
    throw Error('Package statement is not an EvidScope evidence package (in-toto SVR v0.2)');
  }
  const names = statement.subject.map(s => s.name);
  if (new Set(names).size !== names.length || names.some(n => !safePackPath(n) || n === FILES.envelope)) throw Error('Package subjects are malformed');
  const present = [...files.keys()].filter(n => n !== FILES.envelope);
  const extra = present.find(n => !names.includes(n)), missing = names.find(n => !files.has(n));
  if (extra !== undefined) throw Error('Package file is not named by the statement: ' + extra);
  if (missing !== undefined) throw Error('Package file named by the statement is missing: ' + missing);
  for (const s of statement.subject) if (s.digest.sha256 !== sha256Hex(files.get(s.name))) throw Error('Package file digest mismatch: ' + s.name);
  const required = [FILES.sums, FILES.index, FILES.mapping, FILES.ko, FILES.en, FILES.export].find(n => !files.has(n));
  if (required !== undefined) throw Error('Package has no ' + required);
  if (!files.get(FILES.sums).equals(sumsFile(files))) throw Error(`${FILES.sums} differs from the package files`);
  const index = parseJson(files.get(FILES.index), FILES.index);
  const packMapping = checkMapping(parseJson(files.get(FILES.mapping), FILES.mapping));
  if (!plain(index) || index.format !== INDEX_FORMAT || index.framework?.id !== packMapping.id) throw Error('Index is not an evidence package index');
  const sameMapping = mappingBytes(frameworkMapping(packMapping.id)).equals(files.get(FILES.mapping));
  if (!sameMapping && !mappingFromPack) {
    throw Error(`Package mapping differs from this verifier's ${packMapping.id} mapping; pass --mapping-from-pack to use it`);
  }
  const policy = p.verifier.policies;
  if (policy.length !== 1 || policy[0].name !== FILES.mapping || policy[0].digest?.sha256 !== sha256Hex(files.get(FILES.mapping))) {
    throw Error('Statement policy does not name the package mapping');
  }
  // The evidence inside, verified as on its own; then everything derived from it must be reproduced exactly.
  // Every file has its place: the fixed files, the export attestation, and the case reports the index lists with their attestations.
  const caseFiles = Array.isArray(index.evidence?.caseReports) ? index.evidence.caseReports.map(c => c?.file) : [];
  if (caseFiles.some(f => typeof f !== 'string' || !f.startsWith(FILES.cases) || !files.has(f)) || new Set(caseFiles).size !== caseFiles.length) {
    throw Error('Index case reports differ from the package files');
  }
  const places = new Set([FILES.sums, FILES.index, FILES.mapping, FILES.ko, FILES.en, FILES.export, FILES.exportAttestation, ...caseFiles,
    ...caseFiles.map(f => f + '.intoto.json')]), stray = present.find(n => !places.has(n));
  if (stray !== undefined) throw Error('Package file has no place in an evidence package: ' + stray);
  const attested = path => (files.has(path + '.intoto.json') ? parseJson(files.get(path + '.intoto.json'), path + '.intoto.json') : null);
  const evidence = verifyEvidence({exportBytes: files.get(FILES.export), exportAttestation: attested(FILES.export),
    caseReports: caseFiles.map(f => ({bytes: files.get(f), attestation: attested(f)})), publicKey, checkpoint, flags});
  if (expectedTenant !== undefined && evidence.result.tenant !== expectedTenant) {
    throw Error(`Package tenant ${evidence.result.tenant} is not ${expectedTenant}`);
  }
  const recomputed = computeIndex({evidence, mapping: packMapping, period: checkPeriod(index.scope?.period ?? null)});
  assertIndexBacked(recomputed, evidence);
  if (!jsonBytes(recomputed).equals(files.get(FILES.index))) {
    const differs = recomputed.items.find((item, i) => canonical(item) !== canonical(index.items?.[i]));
    throw Error(`Index differs from the verified evidence${differs ? ' at item ' + differs.id : ''}`);
  }
  for (const lang of ['ko', 'en']) {
    assertSummaryTraced(files.get(FILES[lang]) ?? Buffer.alloc(0), index, lang);
    if (!renderSummary(recomputed, lang).equals(files.get(FILES[lang]))) throw Error(`Summary (${lang}) differs from the one generated from the index`);
  }
  const established = establishedProperties(evidence), unbacked = p.properties.filter(x => !established.includes(x));
  if (unbacked.length) {
    throw Error(`Statement claims checks this verification did not establish: ${unbacked.join(', ')} (pass the same trust inputs as the builder)`);
  }
  return {valid: true, framework: packMapping.id, mapping: {sha256: sha256Hex(files.get(FILES.mapping)), source: sameMapping ? 'verifier' : 'package'},
    tenant: evidence.result.tenant, period: index.scope.period, counts: index.counts, builtAt: p.timeCreated, packSigner: {keyid: opened.keyids[0],
      key: packKey ? 'pack_key' : 'vault_key'}, properties: p.properties, export: evidence.result,
    caseReports: evidence.cases.map(c => ({caseId: c.result.caseId, reportHash: c.result.reportHash, reviewState: c.result.reviewState})),
    scope: 'Every file, the export and case reports inside, the index and both summaries were verified against the evidence. Evidence present is not'
      + ' a finding that a requirement is met; completeness of collection and the truth of self-reported fields are not established.'};
}
