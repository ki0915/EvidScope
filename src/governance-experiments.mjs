// Experiment comparison of the governance-mapping model (docs/governance-model.md, "실험 비교"): the comparison reports under
// reports/governance-mapping/ side by side, with every number recomputed from the report's outputs and gold rows (the same
// verification the gate runs), split by label basis (human-reviewed vs derived rows) and by framework, plus the run history from
// the signed factsheets. A report whose candidate adapter is a recorded shakedown adapter shows no candidate numbers.
import {createHash} from 'node:crypto';
import {readFileSync, readdirSync, statSync} from 'node:fs';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {governanceCatalog} from './governance-mapping.mjs';
import {rowEligibility} from './governance-mapping-data.mjs';
import {localTablesFor} from './governance-mapping-sources.mjs';
import {calibrationSummary} from './governance-abstention.mjs';
import {ALL_VARIANTS, CALIBRATED, MODEL_VARIANTS, SAFETY_CHECKS, assessGovernanceReport, evaluateOutputs, measurementProblem, scoreItem,
  verifyGovernanceReport} from './governance-mapping-eval.mjs';
import {assessBaselineMode} from './governance-model.mjs';

export const REPORTS_DIR = fileURLToPath(new URL('../reports/governance-mapping/', import.meta.url));
const LIMITS = Object.freeze({files: 30, bytes: 8 * 1024 * 1024, rows: 400});
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const ratio = (a, b) => (b ? a / b : null);
// The receipt a variant was measured under: the calibrated candidate is the candidate's run plus its abstention rule.
const receiptOf = (report, v) => (v === CALIBRATED ? report.variants.candidate : report.variants[v])?.receipt ?? null;

// Numbers shown for one variant on one set of rows.
export const variantNumbers = x => ({items: x.items, tp: x.tp, fp: x.fp, fn: x.fn, precision: x.precision, recall: x.recall, coverage: x.coverage,
  answeredRate: x.answeredRate, abstentionRate: x.abstention.rate, abstentionOnAnswerable: x.abstention.onAnswerable, exactMatch: x.exactMatch,
  mustAbstainCorrect: x.abstention.mustAbstainCorrect, ece: x.calibration.ece, macroPrecision: x.macro.precision, macroRecall: x.macro.recall,
  safety: Object.fromEntries(SAFETY_CHECKS.map(k => [k, x.safety[k].rate]))});
function byFramework(metrics, catalog) {
  const out = {};
  for (const [id, c] of Object.entries(metrics.perRequirement)) {
    const fw = catalog.byId.get(id)?.framework ?? 'unknown', t = out[fw] ??= {tp: 0, fp: 0, fn: 0};
    t.tp += c.tp; t.fp += c.fp; t.fn += c.fn;
  }
  for (const t of Object.values(out)) Object.assign(t, {precision: ratio(t.tp, t.tp + t.fp), recall: ratio(t.tp, t.tp + t.fn)});
  return out;
}
// One verified report → the comparison the console shows. shakedownAdapters: adapter hashes of recorded shakedown runs.
export function experimentOf(report, {now = Date.now(), catalog = governanceCatalog(), shakedownAdapters = new Set()} = {}) {
  const m = verifyGovernanceReport(report, {now, catalog, requireCandidate: false});
  const variants = [...ALL_VARIANTS, CALIBRATED].filter(v => report.variants[v]), adapter = report.variants.candidate?.receipt?.adapterSha256 ?? null;
  const shakedown = !!adapter && shakedownAdapters.has(adapter), shown = variants.filter(v => !(shakedown && (v === 'candidate' || v === CALIBRATED)));
  const localTables = localTablesFor(report.rows);
  const basis = new Map(report.rows.map(r => { const e = rowEligibility(r, {now, localTables}); return [r.id, e.eligible ? e.basis : 'not_eligible']; }));
  const subset = b => m.gateRows.filter(r => basis.get(r.id) === b);
  const perVariant = {};
  for (const v of shown) {
    const outputs = report.variants[v].outputs;
    perVariant[v] = {gate: variantNumbers(m.metrics[v]), byBasis: Object.fromEntries(['human_reviewed', 'derived'].map(b => [b,
      variantNumbers(evaluateOutputs(subset(b), outputs, catalog))])), byFramework: byFramework(m.metrics[v], catalog),
    allRowsInformational: variantNumbers(m.informational[v]),
    measurement: MODEL_VARIANTS.includes(v) || v === CALIBRATED ? {problem: measurementProblem(report, v), operator: receiptOf(report, v)?.operator ?? null,
      adapterSha256: receiptOf(report, v)?.adapterSha256 ?? null} : {problem: null, deterministic: true}};
  }
  let verdict;
  try {
    if (report.variants.candidate) {
      const a = assessGovernanceReport(report, {now, catalog});
      verdict = {kind: 'promotion_gate', eligible: a.eligible && !shakedown,
        reasons: [...a.reasons, ...(shakedown ? ['candidate adapter is a shakedown adapter'] : [])],
        comparisons: shakedown ? null : a.comparisons, thresholds: a.thresholds};
    } else {
      const b = assessBaselineMode(report, {now});
      verdict = {kind: 'base_mode', eligible: b.allowed, reasons: b.reasons};
    }
  } catch (error) { verdict = {kind: 'unverified', eligible: false, reasons: [error.code || error.message]}; }
  const rows = report.rows.slice(0, LIMITS.rows).map(r => ({id: r.id, basis: basis.get(r.id), kind: r.evidence?.[0]?.kind ?? null,
    labelSource: r.labelSource, mustAbstain: r.truth?.abstain === true, injection: Array.isArray(r.truth?.forbidden),
    exact: Object.fromEntries(shown.map(v => [v, scoreItem(r, report.variants[v].outputs[r.id], catalog).exact]))}));
  return {status: 'verified', createdAt: report.createdAt, preparedBy: report.preparedBy, datasetSha256: report.datasetSha256, split: report.split,
    items: report.rows.length, gateItems: m.gateRows.length,
    rowsByBasis: {human_reviewed: subset('human_reviewed').length, derived: subset('derived').length,
      not_eligible: report.rows.filter(r => basis.get(r.id) === 'not_eligible').length},
    variants: shown, candidateAdapterSha256: adapter, shakedown, variantsData: perVariant, verdict, rows, rowsTruncated: report.rows.length > LIMITS.rows,
    calibration: calibrationSummary(report), qualityClaimAllowed: false};
}

let cache = new Map();
// Reads the report files (newest first by createdAt). Unreadable or unverifiable files are listed with the reason, never scored.
export function experimentsView({reportsDir = REPORTS_DIR, factsheets = [], now = Date.now(), catalog = governanceCatalog()} = {}) {
  const shakedownAdapters = new Set(factsheets.filter(f => f.kind === 'training' && f.runMode === 'shakedown').map(f => f.adapter?.ggufSha256).filter(Boolean));
  let names = [];
  try { names = readdirSync(reportsDir).filter(n => /^[A-Za-z0-9._-]{1,120}\.json$/.test(n)).sort(); } catch {}
  const next = new Map(), reports = [];
  for (const name of names.slice(-LIMITS.files)) {
    const file = join(reportsDir, name);
    let entry;
    try {
      if (!statSync(file).isFile() || statSync(file).size > LIMITS.bytes) throw Error('report_file_too_large');
      const bytes = readFileSync(file), sha = sha256(bytes), key = `${sha}:${[...shakedownAdapters].sort().join(',')}`;
      entry = cache.get(key) ?? (() => {
        const report = JSON.parse(bytes.toString('utf8'));
        try { return {file: name, sha256: sha, ...experimentOf(report, {now, catalog, shakedownAdapters})}; }
        catch (error) { return {file: name, sha256: sha, status: 'unverified', reason: error.code || error.message}; }
      })();
      next.set(key, entry);
    } catch (error) { entry = {file: name, sha256: null, status: 'unreadable', reason: error.code || error.message}; }
    reports.push(entry);
  }
  cache = next;
  reports.sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')));
  const history = [...reports.filter(r => r.status === 'verified').map(r => ({at: r.createdAt, kind: 'report', label: r.shakedown ? 'shakedown'
      : r.variants.includes('candidate') ? 'candidate_evaluation' : 'baseline_evaluation', file: r.file, sha256: r.sha256, by: r.preparedBy,
    eligible: r.verdict.eligible})),
  ...factsheets.map(f => ({at: f.recordedAt, kind: `factsheet_${f.kind}`, label: f.label, id: f.id, by: f.operator?.id ?? null,
    runMode: f.runMode, promotable: f.promotable, qualityResult: f.qualityResult}))]
    .sort((a, b) => String(b.at || '').localeCompare(String(a.at || '')));
  return {reportsDirectory: 'reports/governance-mapping', reports, history, shakedownAdapters: [...shakedownAdapters],
    notice: '모든 수치는 보고서의 출력과 정답 행에서 다시 계산한 값입니다. 사람이 검토한 행과 표에서 파생한 행을 나눠 보여 줍니다. '
      + '셰이크다운 실행은 품질 결과가 아니며 수치를 보여 주지 않습니다.', qualityClaimAllowed: false};
}
