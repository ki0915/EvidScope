// Offline ISMS-P evidence listing. First verifies an EvidScope export with a trusted public key through the same code as
// scripts/verify.mjs (verifyBundle, and replayEvaluations with --replay); then lists, for each item aligned in
// data/isms-p-alignment.json, how many records of each named evidence kind the verified export carries.
// Usage: node scripts/isms-p-report.mjs EXPORT.json TRUSTED_PUBLIC_KEY.pem [EXTERNAL_CHECKPOINT.json] [--replay] [--markdown]
//          [--witness VKEY]... [--quorum N] [--origin-base BASE] [--min-checkpoint FILE] [--max-staleness S] [--require-transparency]
//          [--require-tenant-witness]
// The presence of evidence is not a finding that a criterion is met: the report counts records and never assesses an item.
// Kinds an export cannot carry (API responses, repository files, online integrity checks) are listed as not_in_export.
// Exit status: 0 = verified and listed (JSON, or Korean Markdown with --markdown);
//              1 = usage, verification failure or a replay mismatch; nothing is printed on stdout then.
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {parseArgs} from 'node:util';
import {verifyBundle} from '../src/crypto.mjs';
import {replayEvaluations} from '../src/policy-replay.mjs';
import {transparencyFlags, transparencyOptions} from './transparency-flags.mjs';
import {evidenceName, inventory, measure, timeRange} from '../src/evidence-inventory.mjs';

export const REPORT_FORMAT = 'evidscope-isms-p-evidence-report-v1';
export const NOTICE = '증거가 있다는 것은 ISMS-P 인증기준을 충족했다는 판정이 아닙니다. 이 보고서는 정렬표가 이름 붙인 증거 종류가 '
  + '검증된 내보내기에 몇 건 있는지만 세며, 어떤 항목도 평가하지 않습니다.';
export const LIMITATIONS = [
  '0건(none_recorded)은 통제가 없다는 뜻이 아닙니다. 수집하지 않은 출처와 EvidScope 밖의 기록은 이 내보내기에 보이지 않습니다.',
  '서명은 이 vault가 기록을 받았음을 인증할 뿐 출처 주장의 진실을 보증하지 않습니다. occurredAt은 출처가 주장한 시각입니다.',
  '신뢰 공개키는 내보내기와 다른 경로로 받은 것이어야 합니다. 서명 키를 가진 사람은 기록 자체를 지어낼 수 있습니다.',
  '외부 체크포인트나 위트니스 없이 검증하면 서명 키를 가진 호스트의 되돌리기(rollback)·잘라내기를 배제하지 못합니다(rollbackChecked).',
  'API 응답, 저장소 파일, 온라인 무결성 검사 결과는 내보내기에 없어 not_in_export로 적습니다. 서명 원장 검사만 이 보고서의 오프라인 검증으로 대신합니다.',
  '발견사항은 행동별 마지막 서명 평가에서 셉니다. --replay 없이 실행하면 평가를 다시 계산하지 않습니다.',
  '파기한 이벤트는 본문이 없어 종류별로 세지 못하고 verification.erasedEvents로만 셉니다.',
  '정렬표 자체가 사람 검토 전 초안(draft_requires_human_review)입니다.',
];

export function buildReport(bundle, alignment, verification, replay) {
  const data = inventory(bundle, replay), titles = new Map(alignment.officialItems.map(i => [i.number, i.title]));
  const items = alignment.alignments.map(a => {
    const supports = a.supports.map(s => ({checkItems: s.checkItems, shows: s.shows,
      evidence: s.evidence.map(e => ({type: e.type, ...evidenceName(e), what: e.what, ...measure(e, data, verification)}))}));
    const all = supports.flatMap(s => s.evidence), tally = status => all.filter(e => e.status === status).length;
    return {item: a.item, title: titles.get(a.item), criterionAssessment: 'not_performed', supports, manual: a.manual,
      summary: {present: tally('present'), noneRecorded: tally('none_recorded'), notInExport: tally('not_in_export'),
        verifiedByThisReport: tally('verified_by_this_report')}};
  });
  const {legal} = alignment.sources;
  return {
    format: REPORT_FORMAT, notice: NOTICE, certificationClaim: false, criterionAssessment: 'not_performed',
    alignment: {id: alignment.id, schemaVersion: alignment.schemaVersion, mappingStatus: alignment.mappingStatus, checkedAt: alignment.checkedAt,
      legalSource: `${legal.title} ${legal.annex}`},
    verification: {valid: verification.valid, tenant: verification.tenant, count: verification.count, head: bundle.checkpoint.head,
      rollbackChecked: verification.rollbackChecked, disclosedEvents: verification.disclosedEvents, erasedEvents: verification.erasedEvents,
      ...(verification.transparency ? {transparency: verification.transparency} : {}),
      replay: replay ? {engine: replay.engine, ...replay.summary} : 'not_requested', scope: verification.scope},
    export: {recordedAt: timeRange(bundle.records.map(r => r.recordedAt))},
    items,
    notAligned: {count: alignment.notAligned.length, see: 'docs/isms-p-alignment.md'},
    limitations: LIMITATIONS,
  };
}

const STATUS = {present: '있음', none_recorded: '기록 없음(none_recorded)', not_in_export: '내보내기에 없음(not_in_export)',
  verified_by_this_report: '이 보고서의 오프라인 검증으로 확인'};
// Bundle-derived text is escaped so a crafted value cannot break the Markdown table or inject links.
const md = value => String(value).replace(/[\r\n]+/g, ' ').replace(/[\\`*_|<>[\]#!]/g, c => '\\' + c);
const code = value => '`' + String(value).replace(/[`\r\n]/g, '').replaceAll('|', '\\|') + '`';
const span = range => range ? `${md(range.from)} ~ ${md(range.to)}${range.unparsed ? ` (해석 불가 ${range.unparsed}건)` : ''}` : '-';
const CIRCLED = '①②③④⑤⑥⑦⑧⑨';
const label = e => e.type === 'api' ? code(`${e.method} ${e.path}`) + (e.field ? `의 ${code(e.field)}` : '') + (e.mode === 'oidc' ? '(OIDC)' : '')
  : e.type === 'finding' ? `발견사항 ${code(e.code)}` : e.type === 'file' ? `파일 ${code(e.path)}`
    : e.type === 'record' ? `기록 ${code(e.name)}` : e.type === 'eventKind' ? `이벤트 ${code(e.name)}(${[e.source, ...(e.alsoAllowed || [])].join('·')} 출처)`
      : e.type === 'checkType' ? `측정 ${code(e.name)}` : `무결성 검사 ${code(e.name)}`;
const detail = e => {
  const parts = [];
  if (e.status === 'verified_by_this_report') parts.push(`서명·해시 체인 검증, 되돌리기 확인 ${e.rollbackChecked ? '함' : '안 함'}`);
  if (e.sourceKinds && e.count) parts.push('출처 ' + Object.entries(e.sourceKinds).map(([k, n]) => `${md(k)} ${n}`).join(', '));
  if (e.type === 'finding' && e.count) {
    parts.push(`행동 ${e.actions}개, 예외로 억제 ${e.suppressed}건`);
    if (e.replay !== 'not_requested') parts.push(`재계산 일치 ${e.replay.replayed}, 재계산 불가 ${e.replay.notReplayable}`);
  }
  if (e.sourceClaimedOccurredAt) parts.push(`출처 주장 시각 ${span(e.sourceClaimedOccurredAt)}`);
  return parts.join('; ') || '-';
};

export function renderMarkdown(report) {
  const v = report.verification, lines = [
    '# ISMS-P 항목별 증거 목록', '',
    `> **${report.notice}**`,
    `> \`criterionAssessment: ${report.criterionAssessment}\`, \`certificationClaim: ${report.certificationClaim}\`. `
      + `정렬표 상태는 \`${report.alignment.mappingStatus}\`(확인일 ${report.alignment.checkedAt})입니다.`, '',
    '## 검증', '', '| 구분 | 값 |', '|---|---|',
    `| 형식 | ${code(report.format)} |`,
    `| 법적 출처 | ${md(report.alignment.legalSource)} |`,
    `| tenant | ${md(v.tenant)} |`,
    `| 원장 기록 수 | ${v.count} |`,
    `| 체크포인트 head | ${code(v.head)} |`,
    `| 되돌리기 확인 | ${v.rollbackChecked ? '확인함(외부 체크포인트 또는 위트니스)' : '확인하지 않음: 외부 체크포인트·위트니스 없이 검증했습니다'} |`,
    `| 공개 이벤트 / 파기 이벤트 | ${v.disclosedEvents} / ${v.erasedEvents} |`,
    `| 평가 재계산 | ${v.replay === 'not_requested' ? '요청하지 않음(--replay)'
      : `평가 ${v.replay.evaluations}, 일치 ${v.replay.replayed}, 불일치 ${v.replay.mismatch}, 재계산 불가 ${v.replay.notReplayable}`} |`,
    `| 기록 기간(recordedAt) | ${span(report.export.recordedAt)} |`, '',
    '## 항목별 증거', '',
    `정렬한 ${report.items.length}개 항목만 싣습니다. 정렬하지 않은 ${report.notAligned.count}개 항목과 그 이유는 ${report.notAligned.see}를 보세요.`, '',
  ];
  for (const item of report.items) {
    lines.push(`### ${item.item} ${md(item.title)}`, '', `판정: 하지 않음(\`${item.criterionAssessment}\`).`, '');
    for (const s of item.supports) {
      lines.push(`확인사항 ${s.checkItems.map(n => CIRCLED[n - 1]).join('')}: ${md(s.shows)}`, '');
      lines.push('| 증거 | 상태 | 건수 | 기간(recordedAt) | 비고 |', '|---|---|---|---|---|');
      for (const e of s.evidence) {
        lines.push(`| ${label(e)} | ${STATUS[e.status]} | ${e.count ?? '-'} | ${span(e.recordedAt)} | ${detail(e)} |`);
      }
      lines.push('');
    }
    lines.push(`사람·조직이 할 일: ${md(item.manual.join('; '))}`, '');
  }
  lines.push('## 한계', '', ...report.limitations.map(text => `- ${text}`), '');
  return lines.join('\n');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const options = {...transparencyFlags, 'min-checkpoint': {type: 'string'}, replay: {type: 'boolean'}, markdown: {type: 'boolean'}};
    const {values, positionals} = parseArgs({allowPositionals: true, options});
    const [bundlePath, keyPath, checkpointPath] = positionals;
    if (!bundlePath || !keyPath || positionals.length > 3) {
      throw Error('Usage: node scripts/isms-p-report.mjs EXPORT.json TRUSTED_PUBLIC_KEY.pem [EXTERNAL_CHECKPOINT.json] [--replay] [--markdown]'
        + ' [transparency flags]');
    }
    const bundle = JSON.parse(readFileSync(bundlePath, 'utf8'));
    const checkpoint = checkpointPath ? JSON.parse(readFileSync(checkpointPath, 'utf8')) : undefined;
    const transparency = transparencyOptions(values, bundle.transparency !== undefined);
    const verification = verifyBundle(bundle, readFileSync(keyPath, 'utf8'), checkpoint, transparency ? {transparency} : {});
    const replay = values.replay ? replayEvaluations(bundle) : null;
    if (replay && !replay.valid) throw Error(`Policy replay mismatch in ${replay.summary.mismatch} evaluation(s); no report produced`);
    const alignment = JSON.parse(readFileSync(new URL('../data/isms-p-alignment.json', import.meta.url), 'utf8'));
    const report = buildReport(bundle, alignment, verification, replay);
    process.stdout.write(values.markdown ? renderMarkdown(report) : JSON.stringify(report, null, 2) + '\n');
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
