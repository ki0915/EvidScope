// Public agent-safety sets for the session judge (src/external-agent-sets.mjs): records from ASSEBench's JSON and R-Judge's CSV become
// sessions with the dataset's own label, split by application scenario without leakage, shortened to the prompt budget, and scored on
// the verdict. The fixtures are neutral, made-up sessions in the sets' shapes; no dataset text is in the repository.
import test from 'node:test';
import assert from 'node:assert/strict';
import {EXTERNAL_LIMITS, EXTERNAL_TYPES, externalPrompt, externalRecord, externalRecords, externalRequest, externalTrainingRow, externalTrainingRows,
  parseCsv, scoreExternal, splitExternal} from '../src/external-agent-sets.mjs';
import {SESSION_OUTPUT_SCHEMA, SESSION_TYPES} from '../src/session-inference.mjs';

const turns = (request, action, result) => [[{role: 'user', content: request}, {role: 'agent', thought: 't', action}, {role: 'environment', content: result}]];
const asse = (id, label, scenario, extra = {}) => ({id, profile: 'p', contents: turns(`request ${id}`, `call_tool(${id})`, 'ok'), label,
  application_scenario: scenario, risk_type: 'Data Exfiltration & Leakage', failure_mode: 'f', ambiguous: 0, risk_description: 'd', ...extra});

test('every ASSEBench risk type maps to a session type the output schema allows', () => {
  for (const type of Object.values(EXTERNAL_TYPES)) {
    assert.ok(SESSION_TYPES.includes(type), type);
    assert.ok(SESSION_OUTPUT_SCHEMA.properties.type.enum.includes(type), type);
  }
});

test('an ASSEBench record keeps the request, each action with what came back, the label and its scenario', () => {
  const r = externalRecord('assebench', asse(7, 1, 'Email Management'));
  assert.deepEqual({id: r.id, family: r.family, verdict: r.verdict, type: r.type, ambiguous: r.ambiguous},
    {id: 'assebench:7', family: 'assebench:Email Management', verdict: 'violation', type: 'exfiltration', ambiguous: false});
  assert.equal(r.request, 'request 7');
  assert.deepEqual(r.steps, [{action: 'call_tool(7)', result: 'ok'}]);
  assert.equal(externalRecord('assebench', asse(8, 0, 'Email Management')).type, null);
  assert.equal(externalRecord('assebench', asse(9, 1, 'X', {risk_type: 'Unknown'})).type, 'other');
  assert.equal(externalRecord('assebench', {...asse(10, 1, 'X'), label: 'maybe'}), null);
  assert.equal(externalRecord('assebench', {...asse(11, 1, 'X'), contents: [[{role: 'user', content: 'only a request'}]]}), null);
  assert.equal(externalRecord('nope', asse(12, 1, 'X')), null);
});

test('R-Judge CSV with quoted JSON, doubled quotes and newlines reads as records; its violations carry no type', () => {
  const contents = JSON.stringify(turns('say "hi"\nplease', 'send(x)', 'done')).replaceAll('"', '""');
  const csv = `﻿id,contents,label,application\r\n1,"${contents}",1,Program\r\n2,"${contents}",0,Program\r\n3,"${contents}",x,Program\r\n`;
  assert.equal(parseCsv(csv).length, 3);
  const {records, skipped} = externalRecords('rjudge', csv);
  assert.equal(records.length, 1, 'the same contents twice is one record');
  assert.deepEqual(skipped, {unlabelled: 1, duplicate: 1});
  assert.equal(records[0].family, 'rjudge:Program');
  assert.equal(records[0].type, null);
  assert.equal(records[0].request, 'say "hi"\nplease');
});

test('prompts fit the budget by shortening fields; a record that never fits is left out of every split', () => {
  const actions = Array.from({length: 30}, (_, i) => ({role: 'agent', action: 'a'.repeat(900) + i}));
  const long = asse(20, 1, 'A', {contents: [[{role: 'user', content: 'r'.repeat(9000)}, ...actions]]});
  const r = externalRecord('assebench', long);
  const messages = externalPrompt(r);
  assert.ok(messages[1].content.length <= EXTERNAL_LIMITS.promptChars);
  const user = JSON.parse(messages[1].content);
  assert.equal(user.actions.length, EXTERNAL_LIMITS.actions);
  assert.equal(user.omittedActions, 10);
  assert.equal(user.source, 'benchmark');
  const huge = {...r, id: 'assebench:21', steps: Array.from({length: 20}, () => ({action: 'b'.repeat(400), result: 'c'.repeat(400)}))};
  assert.equal(externalPrompt(huge), null);
  const split = splitExternal([huge, {...r, id: 'assebench:22', ambiguous: true}], {});
  assert.deepEqual(split.skipped, {ambiguous: 1, tooLong: 1});
});

test('the split holds whole scenarios out, refuses a scenario in two splits, and keeps test records out of training rows', () => {
  const records = ['A', 'A', 'B', 'C'].map((f, i) => externalRecord('assebench', asse(30 + i, i % 2, f)));
  const split = splitExternal(records, {testFamilies: ['assebench:B'], validationFamilies: ['assebench:C']});
  assert.deepEqual([split.train.length, split.validation.length, split.test.length], [2, 1, 1]);
  assert.throws(() => splitExternal(records, {testFamilies: ['assebench:B'], validationFamilies: ['assebench:B']}), /external_family_in_two_splits/);
  const row = externalTrainingRow(split.train[0], {split: 'tune', catalogDigest: 'd'.repeat(64)});
  assert.equal(row.labelSource, 'public_dataset');
  assert.equal(row.reviewedPayloadHash, null);
  assert.deepEqual(JSON.parse(row.target).evidenceActionIds, []);
  assert.equal(row.familyId, 'assebench:A');
});

test('records that read the same keep one row, and the same text labelled both ways keeps none', () => {
  const same = (id, label) => ({...externalRecord('assebench', asse(id, label, 'A')), request: 'same', steps: [{action: 'same', result: ''}]});
  const {rows, skipped} = externalTrainingRows([same(40, 1), same(41, 1)], {split: 'tune', catalogDigest: 'd'.repeat(64)});
  assert.equal(rows.length, 1);
  assert.equal(skipped.duplicate, 1);
  const conflict = externalTrainingRows([same(40, 1), same(42, 0)], {split: 'tune', catalogDigest: 'd'.repeat(64)});
  assert.deepEqual([conflict.rows.length, conflict.skipped.conflicting], [0, 2]);
});

test('requests use the session schema; scoring counts found violations, false alarms, abstentions and types', () => {
  const records = [asse(50, 1, 'A'), asse(51, 1, 'A'), asse(52, 0, 'A'), asse(53, 0, 'A')].map(r => externalRecord('assebench', r));
  const request = externalRequest(records[0]);
  assert.deepEqual(request.response_format.json_schema.schema, SESSION_OUTPUT_SCHEMA);
  const reply = (verdict, type = null) => JSON.stringify({verdict, type, evidenceActionIds: []});
  const outputs = {[records[0].id]: reply('violation', 'exfiltration'), [records[1].id]: reply('clean'), [records[2].id]: reply('violation', 'fraud'),
    [records[3].id]: 'not json'};
  const s = scoreExternal(records, outputs);
  assert.deepEqual([s.records, s.violations, s.precision, s.recall, s.typeAccuracy, s.schemaValidRate, s.answerRate], [4, 2, 0.5, 0.5, 1, 0.75, 0.75]);
  assert.deepEqual(s.always_violation, {precision: 0.5, recall: 1});
  // a threshold with no logprobs turns every answer into an abstention
  assert.equal(scoreExternal(records, outputs, {threshold: -1}).answerRate, 0);
});
