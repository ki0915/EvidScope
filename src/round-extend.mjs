// Public-set additions to a prepared judge round (2026-10-18). A round built by judge-round.mjs prepare keeps its designed sessions,
// tests and catalog digest; this adds trainer rows from more public agent-safety sets (StepGuard, ATBench, sessions built from
// injection environments) and more external tests, so a new round differs from its base only by what was added. Every added training
// record that repeats an R-Judge session is dropped (R-Judge stays a test nothing was shaped on), rows already in the base round are
// not added twice, and a test record that repeats an added training record is left out of that test. Counts only in the report.
import {createHash} from 'node:crypto';
import {canonical} from './crypto.mjs';
import {EXTERNAL_SETS, externalOverlap, externalPrompt, externalRecords, externalRequest, externalTrainingRows} from './external-agent-sets.mjs';

const order = key => createHash('sha256').update(String(key)).digest('hex');
const violations = records => records.filter(r => r.verdict === 'violation').length;

// At most max records, whole groups at a time (the two sessions of an injection pair stay together), in an order fixed by the group key.
export function capRecords(records, max) {
  if (max === undefined || records.length <= max) return records;
  const groups = new Map();
  for (const r of records) {
    const key = r.pairKey ?? r.id;
    groups.set(key, [...(groups.get(key) || []), r]);
  }
  const kept = [];
  for (const key of [...groups.keys()].sort((a, b) => (order(a) < order(b) ? -1 : 1))) {
    const group = groups.get(key);
    if (kept.length + group.length <= max) kept.push(...group);
  }
  return kept;
}

// train / test: [{set, text}] as read from the files. existingRows: the base round's train.jsonl rows. rjudge: R-Judge records.
// max: {set: records} caps per training set. Returns the trainer rows to append, request files by name and the report.
export function extendRound({train = [], test = [], rjudge = [], existingRows = [], catalogDigest, runMode = 'candidate', max = {}}) {
  if (train.length && !rjudge.length) throw Error('round_extend_needs_rjudge');
  const seen = new Set(existingRows.map(r => r.messages?.[1]?.content));
  const rows = [], trainRecords = [], requests = {}, report = {train: {}, test: {}};
  for (const {set, text} of train) {
    if (!EXTERNAL_SETS[set] || set === 'rjudge') throw Error('round_extend_set_unknown');
    if (EXTERNAL_SETS[set].use === 'external test only') throw Error('round_extend_test_only_set');
    const {records, skipped} = externalRecords(set, text);
    const overlap = externalOverlap(records, rjudge);
    const usable = records.filter(r => !overlap.has(r.id) && !r.ambiguous && externalPrompt(r));
    const capped = capRecords(usable, max[set]);
    const built = externalTrainingRows(capped, {split: 'tune', catalogDigest, runMode});
    const fresh = built.rows.filter(r => !seen.has(r.messages[1].content));
    for (const r of fresh) seen.add(r.messages[1].content);
    rows.push(...fresh);
    trainRecords.push(...capped);
    report.train[set] = {records: records.length, skipped, rjudgeOverlapDropped: overlap.size,
      ambiguousOrTooLong: records.length - overlap.size - usable.length, cappedOut: usable.length - capped.length, rows: fresh.length,
      violationRows: fresh.filter(r => JSON.parse(r.target).verdict === 'violation').length, alreadyInRound: built.rows.length - fresh.length,
      rowsSkipped: built.skipped};
  }
  for (const {set, text} of test) {
    if (!EXTERNAL_SETS[set] || set === 'rjudge') throw Error('round_extend_set_unknown');
    const {records, skipped} = externalRecords(set, text);
    const overlap = trainRecords.length ? externalOverlap(records, trainRecords) : new Set();
    const usable = records.filter(r => !overlap.has(r.id) && !r.ambiguous && externalPrompt(r));
    if (usable.length) requests[`public-${set}`] = usable.map(r => canonical(externalRequest(r))).join('\n') + '\n';
    report.test[set] = {records: records.length, skipped, trainOverlapDropped: overlap.size,
      ambiguousOrTooLong: records.length - overlap.size - usable.length, test: usable.length, violations: violations(usable)};
  }
  return {rows, requests, report};
}
