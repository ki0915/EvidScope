// Abstention calibration for the governance mapping candidate (docs/governance-model.md, "보류 보정"). The model's own words carry
// no information ("confidence": "high" on every mapping in pilots 1-7), so the signal is the probability the model gave the
// requirement id it wrote: the sum of the token log-probabilities llama-server reports for the tokens of that id (raw softmax,
// before the grammar and the sampler, so constrained decoding does not inflate it). A mapping is kept only when that score reaches
// a threshold and the id was among the candidates the request listed; an item with nothing left abstains. The threshold is chosen
// on the eligible validation rows: the one with the most recall among those at which the policy's precision reaches the gate's
// minimum with at least MIN_KEPT mappings kept; failing that, the most precise one, marked reached: false. The report stores the
// validation rows, outputs and token log-probabilities, so the choice is recomputed on verification (governance-mapping-eval.mjs);
// nothing here trusts a stored number.
import {parseModelContent} from './governance-mapping.mjs';

// Token log-probabilities are integers in micro-nats (logprob × 1e6): Python's repr and JSON.stringify disagree on floats, and the
// receipt and the report hash the same canonical JSON.
export const LOGPROB_SCALE = 1e6;
export const MIN_KEPT = 10;
export const ABSTAIN_OUTPUT = '{"abstain":true,"mappings":[]}';
const plain = v => !!v && typeof v === 'object' && !Array.isArray(v);
const FIELDS = ['requirementId', 'relation', 'evidenceLocator', 'confidence'];
const ratio = (a, b) => (b ? a / b : null);
const ID_VALUE = /"requirementId"\s*:\s*"((?:[^"\\]|\\.)*)"/g;

// tokens: [[text, logprobMicro], ...] as scripts/governance_mapping_batch.py --logprobs stores them. Returns a Map from the
// requirement id (first occurrence) to the sum of the micro-nat log-probabilities of the tokens overlapping that id's value in the
// output text, or null when the tokens do not spell the output (then nothing in it can be scored).
export function mappingScores(content, tokens) {
  if (typeof content !== 'string' || !Array.isArray(tokens)
    || tokens.some(t => !Array.isArray(t) || t.length !== 2 || typeof t[0] !== 'string' || !Number.isInteger(t[1]))) return null;
  if (tokens.map(t => t[0]).join('') !== content) return null;
  const starts = [];
  let offset = 0;
  for (const [text] of tokens) { starts.push(offset); offset += text.length; }
  const scores = new Map();
  for (const match of content.matchAll(ID_VALUE)) {
    const from = match.index + match[0].length - match[1].length - 1, to = from + match[1].length;
    let sum = 0;
    for (let i = 0; i < tokens.length; i++) {
      const end = starts[i] + tokens[i][0].length;
      if (starts[i] < to && end > from) sum += tokens[i][1];
    }
    if (!scores.has(match[1])) scores.set(match[1], sum);
  }
  return scores;
}

// The policy on one output: mappings scored at or above the threshold whose id is among the candidates (null candidates: no filter)
// are kept in order; anything else is dropped with its reason; nothing kept, or nothing readable, abstains.
export function applyAbstention(content, tokens, {threshold, candidates = null} = {}) {
  let parsed;
  try { parsed = parseModelContent(content); } catch { parsed = undefined; }
  const scores = mappingScores(content, tokens), kept = [], dropped = [];
  for (const m of plain(parsed) && Array.isArray(parsed.mappings) ? parsed.mappings : []) {
    if (!plain(m) || FIELDS.some(k => typeof m[k] !== 'string')) continue;
    const id = m.requirementId, score = scores?.get(id) ?? null;
    let why = null;
    if (score === null) why = 'unscored';
    else if (!Number.isInteger(threshold) || score < threshold) why = 'below_threshold';
    else if (Array.isArray(candidates) && !candidates.includes(id)) why = 'not_candidate';
    if (why) dropped.push({requirementId: id, score, why});
    else kept.push(Object.fromEntries(FIELDS.map(k => [k, m[k]])));
  }
  return {content: kept.length ? JSON.stringify({abstain: false, mappings: kept}) : ABSTAIN_OUTPUT, kept: kept.length, dropped};
}

export const policyOutputs = (rows, outputs, logprobs, candidatesById, threshold) =>
  Object.fromEntries(rows.map(r => [r.id, applyAbstention(outputs[r.id], logprobs[r.id], {threshold, candidates: candidatesById[r.id] ?? null}).content]));

// Chooses the threshold on validation rows. evaluate: (rows, outputs) => {precision, recall, tp, fp, fn} (the gate's own scoring).
// The curve lists every distinct score of a scorable candidate mapping as a threshold, most conservative first.
export function calibrateAbstention(rows, outputs, logprobs, candidatesById, evaluate, {minPrecision, minKept = MIN_KEPT} = {}) {
  if (!(minPrecision > 0 && minPrecision <= 1)) throw Object.assign(Error('calibration_min_precision_invalid'), {code: 'calibration_min_precision_invalid'});
  let mappings = 0, unscored = 0;
  const values = new Set();
  for (const r of rows) {
    const scores = mappingScores(outputs[r.id], logprobs[r.id]), candidates = candidatesById[r.id] ?? null;
    let parsed;
    try { parsed = parseModelContent(outputs[r.id]); } catch { parsed = undefined; }
    for (const m of plain(parsed) && Array.isArray(parsed.mappings) ? parsed.mappings : []) {
      if (!plain(m) || typeof m.requirementId !== 'string') continue;
      mappings++;
      const score = scores?.get(m.requirementId);
      if (score === undefined) unscored++;
      else if (!Array.isArray(candidates) || candidates.includes(m.requirementId)) values.add(score);
    }
  }
  const curve = [...values].sort((a, b) => b - a).map(threshold => {
    const out = policyOutputs(rows, outputs, logprobs, candidatesById, threshold), kept = rows.reduce((n, r) =>
      n + applyAbstention(outputs[r.id], logprobs[r.id], {threshold, candidates: candidatesById[r.id] ?? null}).kept, 0);
    const e = evaluate(rows, out);
    return {threshold, kept, tp: e.tp, fp: e.fp, fn: e.fn, precision: e.precision, recall: e.recall};
  });
  const better = (a, b) => (a.recall !== b.recall ? a.recall > b.recall : a.threshold > b.threshold);
  const pick = entries => entries.reduce((best, e) => (!best || better(e, best) ? e : best), null);
  let chosen = pick(curve.filter(e => e.precision !== null && e.precision >= minPrecision && e.kept >= minKept)), reached = !!chosen;
  if (!chosen) {
    const top = Math.max(...curve.map(e => e.precision ?? -1));
    chosen = pick(curve.filter(e => (e.precision ?? -1) === top));
  }
  return {method: 'id_logprob_threshold', filter: 'candidates', minPrecision, minKept, rows: rows.length, mappings, unscored, curve,
    threshold: chosen?.threshold ?? null, reached, chosen: chosen ? {...chosen} : null};
}
export const natsOf = score => (Number.isInteger(score) ? score / LOGPROB_SCALE : null);
// What the numbers in a calibration mean for a reader: p(id) = exp(threshold in nats).
export const thresholdProbability = score => (Number.isInteger(score) ? Math.exp(score / LOGPROB_SCALE) : null);
// What a reader needs of a calibration (governance-abstention.mjs): the threshold as a probability of the id, whether the validation
// rows reached the gate's precision, and the validation numbers at the chosen threshold.
export function calibrationSummary(report) {
  const c = report.calibration;
  if (!c) return null;
  return {method: c.method, filter: c.filter, threshold: c.threshold, thresholdProbability: thresholdProbability(c.threshold), reached: c.reached,
    minPrecision: c.minPrecision, minKept: c.minKept, validationItems: c.validation.gateItems, validationMappings: c.mappings, unscored: c.unscored,
    chosen: c.chosen ? {precision: c.chosen.precision, recall: c.chosen.recall, kept: c.chosen.kept} : null, curvePoints: c.curve.length};
}
