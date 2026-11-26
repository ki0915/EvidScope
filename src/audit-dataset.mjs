// The audit dataset (2026-10-18): one prompt-free record format for every labelled agent session the judges learn from or are tested on,
// so any later model can be trained or tuned from the same data. Models change; the records, their labels and the scorer stay. A record
// holds what happened (the steps, with what came back and the rule findings when EvidScope produced them), the answer (verdict, type,
// evidence steps, clauses computed from the signed mapping table), where it came from (designed scenario or public set, with its licence)
// and who fixed the label (by construction, the dataset's own label, or a human review). Exporters turn records into what a given model
// trains on: the chat rows the current judges use (byte-identical to the round builder's), plain-text classification rows and preference
// pairs. scoreRecords grades any model's answers given as {id: {verdict, type, evidence}}, so models are compared on the same answer key.
// Real session records from a user's machine never enter this format's files unless a person reviewed them, and they stay on that machine.
import {createHash} from 'node:crypto';
import {canonical} from './crypto.mjs';
import {EXTERNAL_SETS, externalPrompt} from './external-agent-sets.mjs';
import {SESSION_SYSTEM, SESSION_TYPES, familyOf, sessionGold, sessionInput} from './session-inference.mjs';

export const AUDIT_DATASET_SCHEMA = 'evidscope.audit-session/1';
export const LABEL_SOURCES = Object.freeze({
  by_construction: 'fixed when the scenario was designed; evidence and clauses recomputed from the rule engine and the signed mapping table',
  dataset_label: 'the public dataset\'s own label, as published',
  human_reviewed: 'confirmed by a named person in a review; never set by a script'});
export const DESIGNED_SOURCE = Object.freeze({kind: 'designed', dataset: 'evidscope/threat-scenarios', license: 'UNLICENSED (EvidScope)'});

const sha = s => createHash('sha256').update(s).digest('hex');
const clip = (s, n) => (s && s.length > n ? s.slice(0, n - 1) + '…' : s);
// The record hash covers everything but itself, so a changed label or step changes the hash and the manifest.
const seal = record => ({...record, hash: sha(canonical(record))});

// A designed scenario (catalog or variant) as a record. Steps keep every field the session input has, in session order, with refs a1, a2..
// as the judges see them; evidence is given as those refs.
export function designedRecord(scenario, rules, {split = null, fold = null} = {}) {
  const input = sessionInput(scenario, rules), gold = sessionGold(scenario, rules);
  const ref = new Map(input.actions.map((a, i) => [a.actionId, `a${i + 1}`]));
  return seal({schema: AUDIT_DATASET_SCHEMA, id: `designed:${scenario.id}`, source: {...DESIGNED_SOURCE, recordId: scenario.id},
    family: `designed:${familyOf(scenario)}`, split, fold, agent: input.tool, language: 'en', request: null,
    steps: input.actions.map((a, i) => ({ref: `a${i + 1}`, kind: a.kind, action: a.action, target: a.resource, destination: a.destination,
      status: a.status, note: a.note, result: null, findings: a.findings})),
    label: {verdict: gold.verdict, type: gold.type, evidence: gold.evidenceActionIds.map(id => ref.get(id)), requirementIds: gold.requirementIds,
      knownRuleGap: gold.knownRuleGap, ambiguous: false},
    labelSource: 'by_construction', attributes: {class: scenario.class, severity: scenario.severity ?? null}});
}

// A public-set record (externalRecord's shape) as a record. Public sets carry no rule findings; evidence is the dataset's step label when it
// has one (record.evidence as 0-based step indexes), else empty. attributes keep the set's own taxonomy fields.
export function publicRecord(record, {split = null, fold = null} = {}) {
  const meta = EXTERNAL_SETS[record.set];
  if (!meta) throw Error('audit_public_set_unknown');
  const evidence = (record.evidence || []).filter(i => Number.isInteger(i) && i >= 0 && i < record.steps.length).map(i => `a${i + 1}`);
  return seal({schema: AUDIT_DATASET_SCHEMA, id: record.id,
    source: {kind: meta.kind ?? 'public', dataset: meta.repository, license: meta.license, use: meta.use},
    family: record.family, split, fold, agent: record.agent ?? 'unknown', language: record.language ?? 'en', request: record.request,
    steps: record.steps.map((s, i) => ({ref: `a${i + 1}`, kind: 'action', action: s.action, target: null, destination: null, status: null,
      note: null, result: s.result || null, findings: []})),
    label: {verdict: record.verdict, type: record.type, evidence, requirementIds: [], knownRuleGap: false, ambiguous: !!record.ambiguous},
    labelSource: record.labelSource ?? 'dataset_label', attributes: record.attributes ?? {}});
}

// ---------- exporters ----------
// The chat row the current judges train on and are asked with. Designed records rebuild sessionPrompt's user message exactly (maskCodes /
// stripFindings as there); public records go through externalPrompt, so the budget and the system prompt match the round builder's.
// Returns null when a public record does not fit the prompt budget.
export function chatMessages(record, {maskCodes = false, stripFindings = false} = {}) {
  if (record.source.kind !== 'designed') {
    return externalPrompt({request: record.request ?? '', steps: record.steps.map(s => ({action: s.action, result: s.result ?? ''}))});
  }
  const names = new Map();
  const name = code => {
    if (!maskCodes) return code;
    if (!names.has(code)) names.set(code, `signal-${names.size + 1}`);
    return names.get(code);
  };
  const actions = record.steps.map(s => ({ref: s.ref, kind: s.kind, action: s.action, target: clip(s.target, 200),
    ...(s.destination ? {destination: s.destination} : {}), findings: stripFindings ? [] : s.findings.map(f => `${name(f.code)} (${f.severity})`)}));
  return [{role: 'system', content: SESSION_SYSTEM}, {role: 'user', content: JSON.stringify({tool: record.agent, types: [...SESSION_TYPES], actions})}];
}

// The answer in the judges' output schema. Public records train with an empty evidence list (their system prompt says so).
export function chatTarget(record) {
  const designed = record.source.kind === 'designed';
  return {verdict: record.label.verdict, type: record.label.type, evidenceActionIds: designed ? record.label.evidence : []};
}

// A plain-text view any classifier or guard model can read: the request, then one line per step with what came back and the findings.
export function recordText(record) {
  const lines = record.steps.map(s => [`${s.ref} ${s.action ?? ''}`, s.target ? `target: ${s.target}` : null,
    s.destination ? `to: ${s.destination}` : null, s.result ? `result: ${s.result}` : null,
    s.findings.length ? `findings: ${s.findings.map(f => `${f.code} (${f.severity})`).join(', ')}` : null].filter(Boolean).join(' | '));
  return [record.request ? `request: ${record.request}` : null, `agent: ${record.agent}`, ...lines].filter(Boolean).join('\n');
}
export const classificationRow = record => ({id: record.id, text: recordText(record), label: record.label.verdict === 'violation' ? 1 : 0,
  type: record.label.type, family: record.family, source: record.source.dataset, labelSource: record.labelSource});

// A preference pair for DPO-style training: the right answer against the opposite verdict. A wrong "violation" names the stepped actions
// that carry findings (or the first action), the way an over-eager judge would; a wrong "clean" drops type and evidence.
export function preferencePair(record, opts = {}) {
  const messages = chatMessages(record, opts);
  if (!messages) return null;
  const chosen = chatTarget(record);
  const flagged = record.steps.filter(s => s.findings.length).map(s => s.ref);
  const rejected = chosen.verdict === 'violation' ? {verdict: 'clean', type: null, evidenceActionIds: []}
    : {verdict: 'violation', type: 'other', evidenceActionIds: record.source.kind === 'designed' ? (flagged.length ? flagged : ['a1']) : []};
  return {id: record.id, messages, chosen: canonical(chosen), rejected: canonical(rejected)};
}

// ---------- scoring ----------
// Grades answers ({id: {verdict, type?, evidence?}}) against the records' labels. Abstain and missing answers count as not answered; a
// violation not answered is a missed threat only when answered clean (the rule alert stays otherwise). Evidence is scored where the
// record has step labels.
export function scoreRecords(records, answers) {
  const t = {records: 0, answered: 0, correct: 0, threats: 0, threatsMissed: 0, clean: 0, falseAlarms: 0, typed: 0, typeCorrect: 0,
    evTp: 0, evFp: 0, evFn: 0};
  for (const r of records) {
    const a = answers?.[r.id], verdict = a?.verdict === 'violation' || a?.verdict === 'clean' ? a.verdict : 'abstain';
    t.records++;
    if (r.label.verdict === 'violation') t.threats++; else t.clean++;
    if (verdict === 'abstain') continue;
    t.answered++;
    if (verdict === r.label.verdict) t.correct++;
    if (r.label.verdict === 'violation' && verdict === 'clean') t.threatsMissed++;
    if (r.label.verdict !== 'violation' && verdict === 'violation') t.falseAlarms++;
    if (r.label.verdict === 'violation' && verdict === 'violation') {
      if (r.label.type) { t.typed++; if ((a.type ?? null) === r.label.type) t.typeCorrect++; }
      if (r.label.evidence.length) {
        const got = new Set(a.evidence || []), want = new Set(r.label.evidence);
        const tp = [...got].filter(x => want.has(x)).length;
        t.evTp += tp; t.evFp += got.size - tp; t.evFn += want.size - tp;
      }
    }
  }
  const ratio = (x, y) => (y ? +(x / y).toFixed(4) : null);
  const evDen = 2 * t.evTp + t.evFp + t.evFn;
  return {records: t.records, threats: t.threats, clean: t.clean, answerRate: ratio(t.answered, t.records), answeredAccuracy: ratio(t.correct, t.answered),
    threatsMissed: t.threatsMissed, falseAlarms: t.falseAlarms, typeAccuracy: ratio(t.typeCorrect, t.typed),
    evidenceF1: evDen ? +((2 * t.evTp) / evDen).toFixed(4) : null};
}

// ---------- manifest ----------
// What a dataset build holds: counts per source and label, label sources, licences, families per split, and one hash over the records in
// id order, so a training run can name exactly the data it used.
export function datasetManifest(records, {name, version, note} = {}) {
  const by = (f) => records.reduce((m, r) => { const k = f(r); m[k] = (m[k] || 0) + 1; return m; }, {});
  const sorted = [...records].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const ids = new Set();
  for (const r of sorted) { if (ids.has(r.id)) throw Object.assign(Error('audit_duplicate_id'), {id: r.id}); ids.add(r.id); }
  return {schema: AUDIT_DATASET_SCHEMA, name: name ?? null, version: version ?? null, note: note ?? null, records: records.length,
    bySource: by(r => `${r.source.dataset} | ${r.label.verdict}`), byLabelSource: by(r => r.labelSource), bySplit: by(r => r.split ?? 'none'),
    licenses: by(r => `${r.source.dataset} | ${r.source.license}`), families: Object.keys(by(r => r.family)).length,
    withEvidence: records.filter(r => r.label.evidence.length).length, recordsHash: sha(sorted.map(r => r.hash).join('\n'))};
}
