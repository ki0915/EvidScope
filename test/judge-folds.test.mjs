// 교차 검증 요약(src/judge-folds.mjs): 회차별 줄을 모으고, 판정자마다 평균·최저를 내며, 없는 값은 평균에서 뺀다.
import test from 'node:test';
import assert from 'node:assert/strict';
import {foldRow, summarizeFolds} from '../src/judge-folds.mjs';

const judgeSummary = ({accuracy, raw, safeFlagged, eligible}) => ({
  gate: {eligible, reasons: eligible ? [] : ['clean sessions 0/15']},
  sets: {
    unseen: {model: {answerRate: 1, answeredAccuracy: accuracy, threatClearedRate: 0, knownGapClearedRate: 1, typeAccuracy: 0.5, evidenceF1: 0.8},
      model_without_abstain: {answeredAccuracy: raw}},
    'unseen.mask': {model_without_abstain: {answeredAccuracy: raw}},
    'unseen.strip': {model_without_abstain: {answeredAccuracy: raw - 0.1}},
    rjudge: {model_without_abstain: {answeredAccuracy: 0.8, ...(safeFlagged === undefined ? {} : {safeFlagged, safe: 269})}},
    'assebench-test': {model_without_abstain: {answeredAccuracy: 0.9}},
  },
});

test('a fold row carries the gated unseen scores, raw accuracies and external sets, or null for a judge the round lacks', () => {
  const summary = {judges: {'jev-cand': judgeSummary({accuracy: 1, raw: 0.98, safeFlagged: 40, eligible: true})}};
  const row = foldRow(summary, 'jev-cand');
  assert.equal(row.unseen.answeredAccuracy, 1);
  assert.deepEqual(row.raw, {unseen: 0.98, mask: 0.98, strip: 0.88});
  assert.deepEqual(row.rjudge, {accuracy: 0.8, safeFlagged: 40, safe: 269});
  assert.equal(foldRow(summary, 'qwen-cand'), null);
});

test('across-round means and minimums skip rounds without the value, and count gate passes', () => {
  const round = (name, opts) => ({name, held: ['a', 'b'], unseenCounts: {sessions: 100}, summary: {judges: {'jev-cand': judgeSummary(opts)}}});
  const out = summarizeFolds([round('r6', {accuracy: 1, raw: 0.98, safeFlagged: 40, eligible: true}),
    round('r8', {accuracy: 0.96, raw: 0.9, eligible: false})], {judges: ['jev-cand', 'qwen-cand']});
  const jev = out.judges['jev-cand'];
  assert.equal(jev.rounds.length, 2);
  assert.deepEqual(jev.across['unseen.answeredAccuracy'], {mean: 0.98, min: 0.96, rounds: 2});
  assert.deepEqual(jev.across['rjudge.safeFlagged'], {mean: 40, min: 40, rounds: 1});
  assert.equal(jev.gatePassed, 1);
  assert.equal(out.judges['qwen-cand'].rounds.length, 0);
  assert.equal(out.judges['qwen-cand'].across['unseen.answeredAccuracy'], null);
  assert.deepEqual(out.rounds[0], {name: 'r6', held: 2, unseen: {sessions: 100}});
});
