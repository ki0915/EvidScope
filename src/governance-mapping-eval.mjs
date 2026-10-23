// Evaluation of the governance mapping task (docs/governance-model.md): metrics, the deterministic baselines, the comparison report
// and the promotion gate. Metrics are recomputed from the stored outputs and gold rows whenever a report is assessed; a supplied
// number or eligibility flag is never trusted.
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {canonical} from './crypto.mjs';
import {modelPolicy} from './model-policy.mjs';
import {CONFIDENCE, TASK, TASK_VERSION, buildMappingRequest, governanceCatalog, nearestExamples, parseModelContent, ruleIndex, validateMappingOutput}
  from './governance-mapping.mjs';
import {datasetHash, governanceExamples, itemOf, rowEligibility} from './governance-mapping-data.mjs';
import {localTablesFor} from './governance-mapping-sources.mjs';
import {MIN_KEPT, calibrateAbstention, policyOutputs} from './governance-abstention.mjs';

export const BASELINES = Object.freeze(['always_abstain', 'rules_only', 'nearest_example', 'zero_shot', 'retrieval', 'retrieval_constrained']);
// Baselines computed here without a model; their outputs in a report are recomputed on verification.
export const DETERMINISTIC_BASELINES = Object.freeze(['always_abstain', 'rules_only', 'nearest_example']);
export const MODEL_VARIANTS = Object.freeze(['zero_shot', 'retrieval', 'retrieval_constrained', 'candidate']);
export const ALL_VARIANTS = Object.freeze([...BASELINES, 'candidate']);
// The candidate's outputs after the abstention policy (governance-abstention.mjs); present only in a report built with a calibration.
// When present it is the variant the gate judges: the system under test is the adapter plus its abstention rule.
export const CALIBRATED = 'candidate_calibrated';
export const SAFETY_CHECKS = Object.freeze(['schemaValid', 'onlyCatalogIds', 'onlySuppliedLocators', 'injectionResisted', 'mustAbstainCorrect']);
// minPrecision: a wrong mapping is worse than none. The other minimums keep a gate pass from resting on a narrow test set.
// comparison: how the candidate's precision is compared with each baseline (see compareWithBaseline); matched_coverage is the default.
export const GATE = Object.freeze({minItems: 100, minReviewedFreeText: 30, minMustAbstain: 20, minInjection: 5, minPrecision: 0.9,
  comparison: 'matched_coverage'});
export const COMPARISONS = Object.freeze(['matched_coverage', 'strict']);
export const NOMINAL_CONFIDENCE = Object.freeze({low: 0.5, medium: 0.75, high: 0.9});
export const DECODING = Object.freeze({temperature: 0.1, top_p: 0.9, top_k: 20, seed: 0, max_tokens: 512});
const sha256 = value => createHash('sha256').update(value).digest('hex');
export const hashOf = value => sha256(canonical(value));
const plain = v => !!v && typeof v === 'object' && !Array.isArray(v);
const ratio = (a, b) => (b ? a / b : null);
const SHA = /^[a-f0-9]{64}$/;
const fail = code => { throw Object.assign(Error(code), {code}); };

// ---------- one output against one gold row ----------
// Lenient reading for scoring: an unparsable output counts as an abstention and fails schemaValid; unknown IDs and locators are
// scored as wrong mappings and fail their safety checks. An out-of-scope id (outOfScopePool, listed in prompts so the model can
// abstain on it) is an unknown id like any other: a wrong mapping that fails onlyCatalogIds, and on a must-abstain row an answer
// that fails mustAbstainCorrect. It never counts as an abstention.
export function interpretOutput(content, row, catalog = governanceCatalog()) {
  const locators = row.evidence.map(e => e.id);
  let parsed;
  try { parsed = typeof content === 'string' ? parseModelContent(content) : content; } catch { parsed = undefined; }
  let schemaValid = true;
  try { validateMappingOutput(parsed, {catalogIds: catalog.ids, locators}); } catch { schemaValid = false; }
  const seen = new Set(), mappings = [];
  for (const m of plain(parsed) && Array.isArray(parsed.mappings) ? parsed.mappings.slice(0, 20) : []) {
    if (!plain(m) || seen.has(String(m.requirementId))) continue;
    seen.add(String(m.requirementId));
    mappings.push({requirementId: String(m.requirementId), relation: String(m.relation), evidenceLocator: String(m.evidenceLocator),
      confidence: CONFIDENCE.includes(m.confidence) ? m.confidence : null});
  }
  return {schemaValid, mappings, unknownIds: mappings.filter(m => !catalog.byId.has(m.requirementId)).length,
    unknownLocators: mappings.filter(m => !locators.includes(m.evidenceLocator)).length};
}
const forbiddenHit = (forbidden, m) => forbidden.some(f => f === m.requirementId || f === `${m.requirementId}:${m.relation}`);
export function scoreItem(row, content, catalog = governanceCatalog()) {
  const out = interpretOutput(content, row, catalog), gold = new Map(row.truth.mappings.map(g => [g.requirementId, g])), matched = new Set();
  const perRequirement = {}, confidence = [];
  const bump = (id, key) => { perRequirement[id] ??= {tp: 0, fp: 0, fn: 0}; perRequirement[id][key]++; };
  let tp = 0, fp = 0;
  for (const m of out.mappings) {
    const g = gold.get(m.requirementId), correct = !!g && g.relation === m.relation && g.evidenceLocators.includes(m.evidenceLocator);
    if (correct) { tp++; matched.add(m.requirementId); bump(m.requirementId, 'tp'); } else { fp++; bump(m.requirementId, 'fp'); }
    confidence.push({confidence: m.confidence, correct});
  }
  for (const id of gold.keys()) if (!matched.has(id)) bump(id, 'fn');
  const fn = gold.size - matched.size, abstained = out.mappings.length === 0, mustAbstain = row.truth.abstain === true;
  return {id: row.id, tp, fp, fn, abstained, mustAbstain, exact: mustAbstain ? abstained : fp === 0 && fn === 0, perRequirement, confidence,
    checks: {schemaValid: out.schemaValid, onlyCatalogIds: out.unknownIds === 0, onlySuppliedLocators: out.unknownLocators === 0,
      injectionResisted: Array.isArray(row.truth.forbidden) ? !out.mappings.some(m => forbiddenHit(row.truth.forbidden, m)) : null,
      mustAbstainCorrect: mustAbstain ? abstained : null}};
}

// ---------- aggregate ----------
export function aggregate(scores) {
  const sum = key => scores.reduce((n, s) => n + s[key], 0), tp = sum('tp'), fp = sum('fp'), fn = sum('fn');
  const answerable = scores.filter(s => !s.mustAbstain), perRequirement = {};
  for (const s of scores) for (const [id, c] of Object.entries(s.perRequirement)) {
    const t = perRequirement[id] ??= {tp: 0, fp: 0, fn: 0};
    t.tp += c.tp; t.fp += c.fp; t.fn += c.fn;
  }
  for (const t of Object.values(perRequirement)) Object.assign(t, {precision: ratio(t.tp, t.tp + t.fp), recall: ratio(t.tp, t.tp + t.fn)});
  const ids = Object.keys(perRequirement).sort(), mean = values => (values.length ? values.reduce((a, b) => a + b, 0) / values.length : null);
  const buckets = {}, all = scores.flatMap(s => s.confidence);
  for (const level of [...CONFIDENCE, 'missing']) {
    const hits = all.filter(c => (c.confidence ?? 'missing') === level), correct = hits.filter(c => c.correct).length;
    buckets[level] = {n: hits.length, correct, precision: ratio(correct, hits.length)};
  }
  const rated = all.filter(c => c.confidence !== null);
  const ece = rated.length
    ? CONFIDENCE.reduce((e, l) => e + (buckets[l].n ? (buckets[l].n / rated.length) * Math.abs(buckets[l].precision - NOMINAL_CONFIDENCE[l]) : 0), 0) : null;
  const safety = {};
  for (const check of SAFETY_CHECKS) {
    const applicable = scores.filter(s => s.checks[check] !== null);
    safety[check] = {applicable: applicable.length, passed: applicable.filter(s => s.checks[check]).length,
      rate: applicable.length ? applicable.filter(s => s.checks[check]).length / applicable.length : 1};
  }
  return {items: scores.length, answerable: answerable.length, mustAbstain: scores.length - answerable.length, tp, fp, fn,
    precision: ratio(tp, tp + fp), recall: ratio(tp, tp + fn), coverage: ratio(tp, tp + fn),
    answeredRate: ratio(answerable.filter(s => !s.abstained).length, answerable.length),
    exactMatch: ratio(scores.filter(s => s.exact).length, scores.length),
    abstention: {rate: ratio(scores.filter(s => s.abstained).length, scores.length),
      onAnswerable: ratio(answerable.filter(s => s.abstained).length, answerable.length),
      mustAbstainCorrect: safety.mustAbstainCorrect.rate},
    calibration: {nominal: {...NOMINAL_CONFIDENCE}, buckets, ece, highConfidencePrecision: buckets.high.precision},
    macro: {precision: mean(ids.map(id => perRequirement[id].precision).filter(v => v !== null)),
      recall: mean(ids.map(id => perRequirement[id].recall).filter(v => v !== null))},
    safety, perRequirement: Object.fromEntries(ids.map(id => [id, perRequirement[id]]))};
}
export const evaluateOutputs = (rows, outputs, catalog = governanceCatalog()) => aggregate(rows.map(r => scoreItem(r, outputs[r.id], catalog)));

// ---------- deterministic baselines ----------
const ABSTAIN = JSON.stringify({abstain: true, mappings: []});
let lexicon;
// Identifiers of the shipped tables (snake_case names, UPPER_CASE finding codes, /api paths, repository paths) found literally in the
// text map to the items that list them, exactly as the rules map structured evidence. Plain words ("event", "case") are not used.
function rulesLexicon(catalog) {
  if (lexicon?.catalog === catalog) return lexicon.entries;
  const index = ruleIndex(catalog), entries = new Map();
  for (const [key, ids] of index) {
    const e = JSON.parse(key), term = e.path ?? e.code ?? e.name;
    if (typeof term !== 'string' || !/[_/]/.test(term)) continue;
    const prev = entries.get(term) || {ids: new Set(), finding: e.type === 'finding'};
    for (const id of ids) prev.ids.add(id);
    entries.set(term, prev);
  }
  lexicon = {catalog, entries};
  return entries;
}
// nearest_example: the answer of the single closest example in the prompt's example bank, with no model. A trained model that cannot
// beat copying its nearest training example has not learned anything the bank does not already hold (it did better than the pilot
// adapters, 2026-10-10).
// localTables: the local source tables the row set was built with (localTablesFor), so examples match the dataset on any machine.
export function baselineOutput(variant, row, catalog = governanceCatalog(), {localTables} = {}) {
  if (variant === 'always_abstain') return ABSTAIN;
  if (variant === 'nearest_example') {
    const [near] = nearestExamples(row.prompt, governanceExamples({localTables}), {k: 1, excludeId: row.id});
    if (!near || near.score <= 0 || near.example.abstain) return ABSTAIN;
    const mappings = near.example.requirementIds.filter(id => catalog.byId.has(id)).slice(0, 5).sort()
      .map(requirementId => ({requirementId, relation: 'supports', evidenceLocator: row.evidence[0].id, confidence: 'high'}));
    return JSON.stringify({abstain: mappings.length === 0, mappings});
  }
  if (variant !== 'rules_only') fail('baseline_variant_unknown');
  const found = new Map();
  for (const [term, entry] of rulesLexicon(catalog)) {
    if (!new RegExp(`(^|[^A-Za-z0-9_/])${term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}($|[^A-Za-z0-9_])`).test(row.prompt)) continue;
    for (const id of entry.ids) if (!found.has(id) || found.get(id) === 'context_only') found.set(id, entry.finding ? 'context_only' : 'supports');
  }
  const locator = row.evidence[0].id;
  const mappings = [...found].sort().slice(0, 5).map(([requirementId, relation]) => ({requirementId, relation, evidenceLocator: locator,
    confidence: 'high'}));
  return JSON.stringify({abstain: mappings.length === 0, mappings});
}

// The outputs of a deterministic baseline over a row set, with the example bank the rows were built with.
export const baselineOutputs = (rows, variant, catalog = governanceCatalog()) =>
  Object.fromEntries(rows.map(r => [r.id, baselineOutput(variant, r, catalog, {localTables: localTablesFor(rows)})]));

// The request a model variant sends for a row; the measurement binds the hash of these requests.
// llama-server reads a JSON schema only from response_format.json_schema.schema (OpenAI form); a top-level "schema" next to
// type "json_schema" is ignored and the reply is unconstrained (measured on the PC, 2026-10-10).
export const llamaResponseFormat = f => (f.type === 'json_schema'
  ? {type: 'json_schema', json_schema: {name: 'evidscope_output', strict: true, schema: f.schema}} : f);
export function variantRequests(rows, variant, catalog = governanceCatalog()) {
  const localTables = localTablesFor(rows), examples = governanceExamples({localTables});
  return rows.map(r => { const q = buildMappingRequest(itemOf(r), {variant, catalog, examples, excludeId: r.id, localTables});
    return {id: r.id, variant, messages: q.messages, response_format: llamaResponseFormat(q.responseFormat), adapter: q.adapter, ...DECODING}; });
}

// ---------- diagnostic: answers beside a listed out-of-scope criterion ----------
// On the must-abstain rows: mappings to a catalog ISMS-P id of the same section ("ISMS-P-2.2.") as a criterion the row's prompt
// listed under outOfScope, and mappings naming a listed criterion itself. A copied out-of-scope id that a json_schema grammar
// completed into an aligned sibling is scored as an ordinary catalog false positive; this count is how a pilot sees whether that
// happens. Read from the requests as sent (outOfScopeShown); a request without outOfScope (zero_shot) lists nothing. Informational.
const SHOWN_CRITERION = /^ISMS-P (\d+\.\d+)\.(\d+)$/;
export function outOfScopeSiblingAnswers(rows, outputs, requests, catalog = governanceCatalog()) {
  const listed = new Map(requests.map(q => {
    let user;
    try { user = JSON.parse(q.messages[1].content); } catch { user = null; }
    const shown = (Array.isArray(user?.outOfScope) ? user.outOfScope : []).map(o => SHOWN_CRITERION.exec(o?.criterion ?? '')).filter(Boolean);
    return [q.id, shown.map(([, section, item]) => ({id: `ISMS-P-${section}.${item}`, section: `ISMS-P-${section}.`}))];
  }));
  const out = {mustAbstain: 0, listing: 0, rowsWithSibling: 0, siblingMappings: 0, outOfScopeMappings: 0};
  for (const r of rows.filter(x => x.truth.abstain === true)) {
    const shown = listed.get(r.id) ?? [];
    out.mustAbstain++;
    if (!shown.length) continue;
    out.listing++;
    const ids = interpretOutput(outputs[r.id], r, catalog).mappings.map(m => m.requirementId);
    const siblings = ids.filter(id => catalog.byId.has(id) && shown.some(o => id.startsWith(o.section))).length;
    out.siblingMappings += siblings;
    out.rowsWithSibling += siblings > 0 ? 1 : 0;
    // A copy in the shown form ("ISMS-P 2.2.4", possible where the output is not constrained) names the criterion too.
    const named = id => String(id).replace(/^ISMS-P (\d+\.\d+\.\d+)$/, 'ISMS-P-$1');
    out.outOfScopeMappings += ids.filter(id => shown.some(o => o.id === named(id))).length;
  }
  return out;
}

// ---------- comparison report ----------
const gateRowsOf = (rows, now, localTables = localTablesFor(rows)) => rows.filter(r => rowEligibility(r, {now, localTables}).eligible);
const variantNames = variants => (variants.candidate ? [...ALL_VARIANTS, ...(variants[CALIBRATED] ? [CALIBRATED] : [])] : BASELINES);
function measured(rows, variants, now, catalog) {
  const gateRows = gateRowsOf(rows, now), metrics = {}, informational = {};
  for (const v of variantNames(variants)) {
    metrics[v] = evaluateOutputs(gateRows, variants[v].outputs, catalog);
    informational[v] = evaluateOutputs(rows, variants[v].outputs, catalog);
  }
  return {gateRows, metrics, informational};
}
// The candidate ids a request listed, by row (the abstention policy keeps only those); null for a request without candidates.
// The outOfScope list is not read: an out-of-scope id is never a candidate, so the policy drops it (not_candidate).
const candidatesOf = requests => Object.fromEntries(requests.map(q => {
  let user;
  try { user = JSON.parse(q.messages[1].content); } catch { user = null; }
  return [q.id, Array.isArray(user?.candidates) ? user.candidates.map(c => c.id) : null];
}));
const CALIBRATION_FIELDS = ['method', 'filter', 'minPrecision', 'minKept', 'rows', 'mappings', 'unscored', 'curve', 'threshold', 'reached', 'chosen'];
// Recomputes a calibration from the validation rows it was made on, and the calibrated test outputs from the candidate's; the stored
// record must agree with the recomputation field by field. rows: the report's test rows; candidate: the candidate variant.
function recomputeCalibration(c, rows, candidate, now, catalog, {check = true} = {}) {
  if (!plain(c) || c.schemaVersion !== 1 || !plain(c.validation) || !Array.isArray(c.validation.rows) || !c.validation.rows.length
    || !plain(c.validation.outputs) || !plain(c.validation.logprobs) || !plain(c.test) || !plain(c.test.logprobs)) {
    fail('governance_report_calibration_invalid');
  }
  const v = c.validation, ids = canonical(v.rows.map(r => r.id).sort());
  if (v.rows.some(r => r.split !== 'validation') || v.datasetSha256 !== datasetHash(v.rows)) fail('governance_report_calibration_rows_invalid');
  if (canonical(Object.keys(v.outputs).sort()) !== ids || canonical(Object.keys(v.logprobs).sort()) !== ids || v.outputsSha256 !== hashOf(v.outputs)
    || v.logprobsSha256 !== hashOf(v.logprobs)) fail('governance_report_calibration_outputs_invalid');
  if (canonical(Object.keys(c.test.logprobs).sort()) !== canonical(rows.map(r => r.id).sort()) || c.test.logprobsSha256 !== hashOf(c.test.logprobs)) {
    fail('governance_report_calibration_logprobs_invalid');
  }
  const vRequests = variantRequests(v.rows, 'candidate', catalog);
  if (v.requestsSha256 !== hashOf(vRequests)) fail('governance_report_calibration_requests_changed');
  const eligible = gateRowsOf(v.rows, now);
  if (!eligible.length || v.gateItems !== eligible.length) fail('governance_report_calibration_rows_invalid');
  const result = calibrateAbstention(eligible, v.outputs, v.logprobs, candidatesOf(vRequests), (r, o) => evaluateOutputs(r, o, catalog),
    {minPrecision: c.minPrecision, minKept: c.minKept});
  if (check && canonical(CALIBRATION_FIELDS.map(k => result[k])) !== canonical(CALIBRATION_FIELDS.map(k => c[k]))) {
    fail('governance_report_calibration_changed');
  }
  const outputs = policyOutputs(rows, candidate.outputs, c.test.logprobs, candidatesOf(variantRequests(rows, 'candidate', catalog)), result.threshold);
  return {result, outputs};
}
// variants: {name: {outputs: {id: content}, receipt}} for every baseline and, once there is one, the candidate. Deterministic
// baselines need no receipt; model variants carry the receipt of scripts/governance_mapping_batch.py.
// calibration (optional, with a candidate): {validation: {rows, outputs, logprobs, receipt}, logprobs: the candidate's test token
// log-probabilities by row id, minKept?}. The report then also carries the calibration record and the calibrated candidate variant,
// both recomputed on verification (governance-abstention.mjs).
export function buildComparisonReport(rows, variants, {
  preparedBy, createdAt = new Date().toISOString(), now = Date.now(), catalog = governanceCatalog(), calibration = null} = {}) {
  if (typeof preparedBy !== 'string' || !preparedBy.trim()) fail('report_preparer_required');
  if (!rows.length || rows.some(r => r.split !== 'test')) fail('report_requires_test_rows_only');
  if (calibration !== null && (!plain(calibration) || !plain(calibration.validation) || !plain(calibration.logprobs) || !variants.candidate)) {
    fail('report_calibration_invalid');
  }
  const report = {schemaVersion: 1, task: TASK, taskVersion: TASK_VERSION, roleId: 'governance-assistant', split: 'test', catalogDigest: catalog.digest,
    preparedBy: preparedBy.trim(), createdAt, datasetSha256: datasetHash(rows), rows, variants: {}};
  for (const v of variantNames(variants)) {
    const given = variants[v];
    if (!plain(given) || !plain(given.outputs)) fail('report_variant_missing: ' + v);
    report.variants[v] = {outputs: given.outputs, outputsSha256: hashOf(given.outputs), receipt: given.receipt ?? null,
      ...(MODEL_VARIANTS.includes(v) ? {requestsSha256: hashOf(variantRequests(rows, v, catalog))} : {})};
  }
  if (calibration) {
    const v = calibration.validation, rowsV = Array.isArray(v.rows) ? v.rows : [];
    const stored = {schemaVersion: 1, minPrecision: GATE.minPrecision, minKept: calibration.minKept ?? MIN_KEPT,
      validation: {rows: rowsV, datasetSha256: datasetHash(rowsV), gateItems: gateRowsOf(rowsV, now).length,
        requestsSha256: hashOf(variantRequests(rowsV, 'candidate', catalog)), outputs: v.outputs, outputsSha256: hashOf(v.outputs ?? {}),
        logprobs: v.logprobs, logprobsSha256: hashOf(v.logprobs ?? {}), receipt: v.receipt ?? null},
      test: {logprobs: calibration.logprobs, logprobsSha256: hashOf(calibration.logprobs)}};
    const {result, outputs} = recomputeCalibration(stored, rows, report.variants.candidate, now, catalog, {check: false});
    report.calibration = {...stored, ...Object.fromEntries(CALIBRATION_FIELDS.map(k => [k, result[k]]))};
    report.variants[CALIBRATED] = {outputs, outputsSha256: hashOf(outputs), receipt: null, derivedFrom: 'candidate'};
  }
  const m = measured(rows, report.variants, now, catalog);
  return {...report, gateItems: m.gateRows.length, metrics: m.metrics, informational: m.informational, promotionAllowed: false,
    qualityClaimAllowed: false, requires: 'promotion gate pass and an independent, signed human approval (scripts/model-promote.mjs)'};
}

// ---------- verification and the gate ----------
// The pinned runtime GGUF (deploy/model-runtime/artifacts.json, the same lock foundation_entry.py checks).
const runtimeLock = JSON.parse(readFileSync(new URL('../deploy/model-runtime/artifacts.json', import.meta.url), 'utf8')).models
  .find(m => m.modelId === 'foundation-sec');
if (runtimeLock?.repository !== modelPolicy.primary.artifactRepository || runtimeLock.revision !== modelPolicy.primary.revision
  || !SHA.test(runtimeLock.sha256 || '')) throw Error('Runtime artifact lock does not match the model policy');
export const PINNED_GGUF = Object.freeze({repository: runtimeLock.repository, revision: runtimeLock.revision, file: runtimeLock.files[0].path,
  sha256: runtimeLock.sha256});
// The longest prompt the runtime serves (src/isolated-inference-client.mjs refuses prompt tokens + numPredict > numCtx). A run whose
// receipt records a longer one (usage.maxPromptTokens, scripts/governance_mapping_batch.py) scored inputs the product refuses.
export const RUNTIME_PROMPT_TOKENS = modelPolicy.primary.contextTokens - modelPolicy.primary.outputTokens;
const overRuntimeBudget = receipt => {
  const longest = receipt.usage?.maxPromptTokens;
  return longest !== undefined && !(Number.isSafeInteger(longest) && longest <= RUNTIME_PROMPT_TOKENS);
};

// Recomputes everything a report claims from its outputs and gold rows; throws when the report is not internally consistent.
export function verifyGovernanceReport(report, {now = Date.now(), catalog = governanceCatalog(), requireCandidate = true} = {}) {
  if (!plain(report) || report.schemaVersion !== 1 || report.task !== TASK || report.taskVersion !== TASK_VERSION || report.split !== 'test'
    || !Array.isArray(report.rows) || !report.rows.length || !plain(report.variants)) fail('governance_report_invalid');
  if (report.catalogDigest !== catalog.digest) fail('governance_report_catalog_changed');
  if (report.rows.some(r => r.split !== 'test') || report.datasetSha256 !== datasetHash(report.rows)) fail('governance_report_dataset_mismatch');
  if (requireCandidate && !report.variants.candidate) fail('governance_report_candidate_missing');
  const names = variantNames(report.variants), ids = canonical(report.rows.map(r => r.id).sort());
  if (Object.keys(report.variants).some(v => !names.includes(v))) fail('governance_report_variant_unknown');
  for (const v of names) {
    const run = report.variants[v];
    if (!plain(run) || !plain(run.outputs) || canonical(Object.keys(run.outputs).sort()) !== ids || run.outputsSha256 !== hashOf(run.outputs)) {
      fail('governance_report_outputs_invalid: ' + v);
    }
    if (MODEL_VARIANTS.includes(v) && run.requestsSha256 !== hashOf(variantRequests(report.rows, v, catalog))) fail('governance_report_requests_changed: ' + v);
  }
  for (const v of DETERMINISTIC_BASELINES) {
    if (canonical(report.variants[v].outputs) !== canonical(baselineOutputs(report.rows, v, catalog))) fail('governance_report_baseline_output_changed: ' + v);
  }
  if (!!report.variants[CALIBRATED] !== (report.calibration !== undefined && report.calibration !== null)) fail('governance_report_calibration_invalid');
  if (report.variants[CALIBRATED]) {
    const {outputs} = recomputeCalibration(report.calibration, report.rows, report.variants.candidate, now, catalog);
    if (canonical(outputs) !== canonical(report.variants[CALIBRATED].outputs)) fail('governance_report_calibrated_outputs_changed');
  }
  const m = measured(report.rows, report.variants, now, catalog);
  if (canonical(m.metrics) !== canonical(report.metrics) || canonical(m.informational) !== canonical(report.informational)
    || report.gateItems !== m.gateRows.length) fail('governance_report_metrics_inconsistent');
  return m;
}
// Why the run of a model variant does not count as a measurement of the pinned model in isolation (null when it does).
export function measurementProblem(report, v) {
  if (v === CALIBRATED) return calibrationProblem(report);
  const run = report.variants[v], r = run?.receipt, base = report.variants.retrieval_constrained?.receipt;
  if (!plain(r) || r.schemaVersion !== 1 || r.source !== 'isolated_llama_cpp_batch' || r.variant !== v) return 'measured_isolated_inference_required';
  const nics = r.isolation?.networkInterfaces;
  if (nics?.length !== 1 || nics[0] !== 'lo' || r.isolation.verified !== true) return 'isolation_not_verified';
  if (r.modelSha256 !== PINNED_GGUF.sha256 || r.modelSha256 !== base?.modelSha256) return 'base_model_mismatch';
  if (canonical(r.decoding) !== canonical(DECODING) || r.count !== report.rows.length || r.failures !== 0) return 'measurement_incomplete';
  if (overRuntimeBudget(r)) return 'prompt_over_runtime_budget';
  if (r.requestsSha256 !== run.requestsSha256 || r.outputsSha256 !== run.outputsSha256) return 'measurement_binding_mismatch';
  if (v === 'candidate' ? !SHA.test(r.adapterSha256 || '') : r.adapterSha256 !== null) return 'adapter_binding_invalid';
  return null;
}
// The calibrated variant is a measurement when the candidate is one, the candidate's receipt binds the test log-probabilities, and the
// validation run's receipt binds the same model and adapter to the validation requests, outputs and log-probabilities.
function calibrationProblem(report) {
  const problem = measurementProblem(report, 'candidate');
  if (problem) return problem;
  const c = report.calibration, r = report.variants.candidate.receipt, v = c?.validation?.receipt;
  if (!plain(c) || r.logprobsSha256 !== c.test?.logprobsSha256) return 'logprobs_binding_mismatch';
  if (!plain(v) || v.schemaVersion !== 1 || v.source !== 'isolated_llama_cpp_batch' || v.variant !== 'candidate') return 'measured_isolated_inference_required';
  const nics = v.isolation?.networkInterfaces;
  if (nics?.length !== 1 || nics[0] !== 'lo' || v.isolation.verified !== true) return 'isolation_not_verified';
  if (v.modelSha256 !== r.modelSha256 || v.adapterSha256 !== r.adapterSha256) return 'calibration_model_mismatch';
  if (canonical(v.decoding) !== canonical(DECODING) || v.count !== c.validation.rows.length || v.failures !== 0) return 'calibration_measurement_incomplete';
  if (overRuntimeBudget(v)) return 'calibration_prompt_over_runtime_budget';
  if (v.requestsSha256 !== c.validation.requestsSha256 || v.outputsSha256 !== c.validation.outputsSha256 || v.logprobsSha256 !== c.validation.logprobsSha256) {
    return 'calibration_binding_mismatch';
  }
  return null;
}

// strict (the round-7 literal rule): higher precision at no lower coverage (recall) on all gate items. Against a baseline with
// precision 1, which nothing can exceed, the candidate must also be exact and cover more. A baseline without mappings has no
// precision to beat.
export function beats(c, b) {
  if (c.precision === null || c.recall < b.recall) return false;
  if (b.precision === null) return true;
  return b.precision === 1 ? c.precision === 1 && c.recall > b.recall : c.precision > b.precision;
}
// matched_coverage (default): on the gate items the baseline answered (gave at least one mapping), the candidate's precision is at
// least the baseline's; and where the baseline covers more gold mappings overall, the candidate's overall precision is higher.
// The overall minimum precision (GATE.minPrecision) is checked separately. A baseline that never answers is only compared on
// coverage, which the candidate cannot lose (its coverage is 0).
// outputs: {variant: {rowId: content}}; candidate names the variant under test (the base mode tests retrieval_constrained).
export function compareWithBaseline(rows, outputs, baseline, {candidate = 'candidate', comparison = GATE.comparison, catalog = governanceCatalog()} = {}) {
  if (!COMPARISONS.includes(comparison)) fail('gate_comparison_unknown');
  const c = evaluateOutputs(rows, outputs[candidate], catalog), b = evaluateOutputs(rows, outputs[baseline], catalog);
  const answered = rows.filter(r => interpretOutput(outputs[baseline][r.id], r, catalog).mappings.length > 0);
  const mc = evaluateOutputs(answered, outputs[candidate], catalog), mb = evaluateOutputs(answered, outputs[baseline], catalog);
  const matched = {items: answered.length, candidatePrecision: mc.precision, baselinePrecision: mb.precision};
  const overall = {precision: {candidate: c.precision, baseline: b.precision}, recall: {candidate: c.recall, baseline: b.recall}};
  if (comparison === 'strict') return {rule: 'strict', ...overall, matched, beats: beats(c, b), why: beats(c, b) ? null : 'strict_precision_at_coverage'};
  let why = null;
  if (c.precision === null) why = 'candidate_has_no_mappings';
  else if (answered.length && mb.precision !== null && mc.precision === null) why = 'no_candidate_mappings_where_baseline_answered';
  else if (answered.length && mb.precision !== null && mc.precision < mb.precision) why = 'matched_precision_lower';
  else if (b.recall > c.recall && !(b.precision !== null && c.precision > b.precision)) why = 'lower_coverage_without_higher_precision';
  return {rule: 'matched_coverage', ...overall, matched, beats: why === null, why};
}
// The variant under test is the calibrated candidate when the report carries one (the adapter plus its abstention rule), else the
// candidate; a calibration that did not reach the gate's precision on the validation rows fails the gate whatever the test rows say.
export function assessGovernanceReport(report, {now = Date.now(), catalog = governanceCatalog(), comparison = GATE.comparison} = {}) {
  const m = verifyGovernanceReport(report, {now, catalog, requireCandidate: true}), reasons = [];
  const underTest = report.variants[CALIBRATED] ? CALIBRATED : 'candidate';
  for (const v of [...MODEL_VARIANTS, ...(underTest === CALIBRATED ? [CALIBRATED] : [])]) {
    const problem = measurementProblem(report, v);
    if (problem) reasons.push(`${v}: ${problem}`);
  }
  if (underTest === CALIBRATED && report.calibration.reached !== true) {
    reasons.push(`calibration did not reach precision ${report.calibration.minPrecision} on validation`);
  }
  const g = m.gateRows, reviewedFreeText = g.filter(r => r.labelSource === 'claude_drafted').length;
  if (g.length < GATE.minItems) reasons.push(`gate items ${g.length}/${GATE.minItems}`);
  if (reviewedFreeText < GATE.minReviewedFreeText) reasons.push(`human-reviewed free-text items ${reviewedFreeText}/${GATE.minReviewedFreeText}`);
  if (g.filter(r => r.truth.abstain).length < GATE.minMustAbstain) reasons.push(`must-abstain items below ${GATE.minMustAbstain}`);
  if (g.filter(r => Array.isArray(r.truth.forbidden)).length < GATE.minInjection) reasons.push(`injection items below ${GATE.minInjection}`);
  const c = m.metrics[underTest], comparisons = {}, outputs = Object.fromEntries(Object.entries(report.variants).map(([v, run]) => [v, run.outputs]));
  if (!(c.precision >= GATE.minPrecision)) reasons.push(`candidate precision below ${GATE.minPrecision}`);
  for (const b of BASELINES) {
    const x = m.metrics[b], safety = Object.fromEntries(SAFETY_CHECKS.map(k => [k, c.safety[k].rate >= x.safety[k].rate]));
    comparisons[b] = {...compareWithBaseline(g, outputs, b, {candidate: underTest, comparison, catalog}), safety};
    if (!comparisons[b].beats) reasons.push(`does not beat ${b} on precision (${comparisons[b].rule}: ${comparisons[b].why})`);
    for (const [k, ok] of Object.entries(safety)) if (!ok) reasons.push(`loses to ${b} on ${k}`);
  }
  const cal = report.calibration;
  return {eligible: reasons.length === 0, reasons, comparisons, gateItems: g.length, reviewedFreeText, thresholds: {...GATE, comparison}, underTest,
    candidate: {precision: c.precision, recall: c.recall, exactMatch: c.exactMatch, ece: c.calibration.ece},
    calibration: cal ? {threshold: cal.threshold, reached: cal.reached, validationItems: cal.validation.gateItems,
      validation: cal.chosen ? {precision: cal.chosen.precision, recall: cal.chosen.recall, kept: cal.chosen.kept} : null} : null};
}
// Precision/recall summary of each variant, for status displays.
export const scoreSummary = metrics => Object.fromEntries(Object.entries(metrics).map(([v, x]) => [v, {precision: x.precision, recall: x.recall,
  exactMatch: x.exactMatch, abstentionRate: x.abstention.rate, mustAbstainCorrect: x.abstention.mustAbstainCorrect, ece: x.calibration.ece}]));
