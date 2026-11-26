// Public-set additions to a prepared judge round (src/round-extend.mjs): training rows from more public sets are added without anything
// that repeats R-Judge or the base round, injection pairs are capped whole, and a new external test leaves out what was just trained on.
// Fixtures are neutral, made-up sessions in the sets' shapes; no dataset text is in the repository.
import test from 'node:test';
import assert from 'node:assert/strict';
import {externalRecord, externalTrainingRow} from '../src/external-agent-sets.mjs';
import {capRecords, extendRound} from '../src/round-extend.mjs';

const turns = (request, action, result) => [[{role: 'user', content: request}, {role: 'agent', thought: 't', action}, {role: 'environment', content: result}]];
const atb = (id, label, request = `atb request number ${id} for the weekly ledger`) => ({id, tool_used: [], label, risk_source: 'benign',
  failure_mode: 'f', real_world_harm: 'h', reason: '', contents: turns(request, `{"name":"lookup","arguments":{"n":${id}}}`, '{"ok":true}')});
const jsonl = rows => rows.map(r => JSON.stringify(r)).join('\n') + '\n';
const ipi = id => ({id, domain: 'hr', required_tools: ['get_case'],
  responses_create_params: {input: [{role: 'user', content: `summarize case C${id}`}],
    tools: [{type: 'function', function: {name: 'get_case', parameters: {type: 'object', properties: {case_id: {type: 'string'}}, required: ['case_id']}}}]},
  environment: {cases: {[`C${id}`]: {title: 't', case_summary: `NOTE-${id} placeholder`}}},
  injection: {target_tool: 'update_case_notes', target_args: {case_id: `C${id}`}, vector: 'case_summary', injection_text: `NOTE-${id} placeholder`}});
const rjudge = [externalRecord('atbench', atb(90, 0, 'rotate the shared calendar for the support team'))];

test('training additions drop R-Judge repeats and rows the base round has, and count what they dropped', () => {
  const base = externalTrainingRow(externalRecord('atbench500', {...atb(2, 0), conv_id: 'k2', content: atb(2, 0).contents}),
    {split: 'tune', catalogDigest: 'd'});
  const sets = [atb(1, 1), atb(2, 0), atb(3, 0, 'rotate the shared calendar for the support team')].map(({id, contents, ...r}) =>
    ({...r, conv_id: `k${id}`, content: contents}));
  const {rows, report} = extendRound({train: [{set: 'atbench500', text: JSON.stringify(sets)}], rjudge, existingRows: [base],
    catalogDigest: 'd'});
  assert.deepEqual(rows.map(r => [r.id, r.split, r.catalogDigest]), [['atbench500:k1', 'tune', 'd']]);
  assert.deepEqual({rows: report.train.atbench500.rows, violationRows: report.train.atbench500.violationRows,
    rjudge: report.train.atbench500.rjudgeOverlapDropped, inRound: report.train.atbench500.alreadyInRound}, {rows: 1, violationRows: 1, rjudge: 1, inRound: 1});
  assert.throws(() => extendRound({train: [{set: 'atbench500', text: '[]'}]}), /round_extend_needs_rjudge/);
  assert.throws(() => extendRound({train: [{set: 'atbench-codex', text: '[]'}], rjudge}), /round_extend_test_only_set/);
  assert.throws(() => extendRound({train: [{set: 'rjudge', text: ''}], rjudge}), /round_extend_set_unknown/);
});

test('injection pairs are capped whole, so a clean session never trains without its obeyed twin', () => {
  const {rows, report} = extendRound({train: [{set: 'ipi-pairs', text: jsonl([1, 2, 3, 4, 5].map(ipi))}], rjudge, catalogDigest: 'd',
    max: {'ipi-pairs': 5}});
  assert.equal(rows.length, 4);
  assert.equal(report.train['ipi-pairs'].cappedOut, 6);
  const seeds = rows.map(r => r.id.split(':')[1]);
  for (const s of new Set(seeds)) assert.equal(seeds.filter(x => x === s).length, 2);
  assert.deepEqual(rows.map(r => r.labelSource), Array(4).fill('by_construction'));
  const records = [1, 2, 3].map(i => ({id: `x${i}`, pairKey: 'p'}));
  assert.deepEqual(capRecords(records, 2), []);
  assert.equal(capRecords(records, undefined), records);
});

test('a new external test becomes a request file without the records just added to training', () => {
  const trained = [atb(1, 1), atb(2, 0)].map(({id, contents, ...r}) => ({...r, conv_id: `k${id}`, content: contents}));
  const {requests, report} = extendRound({train: [{set: 'atbench500', text: JSON.stringify(trained)}],
    test: [{set: 'atbench', text: JSON.stringify([atb(1, 1), atb(7, 1, 'archive the finished onboarding checklist'), atb(8, 0, 'list the open tickets')])}],
    rjudge, catalogDigest: 'd'});
  const lines = requests['public-atbench'].trim().split('\n').map(l => JSON.parse(l));
  assert.deepEqual(lines.map(l => l.id), ['atbench:7', 'atbench:8']);
  assert.ok(lines.every(l => l.messages.length === 2 && l.response_format));
  assert.deepEqual({test: report.test.atbench.test, violations: report.test.atbench.violations, dropped: report.test.atbench.trainOverlapDropped},
    {test: 2, violations: 1, dropped: 1});
  const only = extendRound({test: [{set: 'atbench-codex', text: '[]'}]});
  assert.deepEqual(only.requests, {});
  assert.equal(only.report.test['atbench-codex'].test, 0);
});
