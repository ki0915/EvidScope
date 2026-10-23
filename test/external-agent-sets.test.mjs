// Public agent-safety sets for the session judge (src/external-agent-sets.mjs): records from ASSEBench's JSON and R-Judge's CSV become
// sessions with the dataset's own label, split by application scenario without leakage, shortened to the prompt budget, and scored on
// the verdict. The fixtures are neutral, made-up sessions in the sets' shapes; no dataset text is in the repository.
import test from 'node:test';
import assert from 'node:assert/strict';
import {EXTERNAL_LIMITS, EXTERNAL_TYPES, externalOverlap, externalPrompt, externalRecord, externalRecords, externalRequest, externalTrainingRow,
  externalTrainingRows, parseCsv, scoreExternal, splitExternal} from '../src/external-agent-sets.mjs';
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
  assert.deepEqual([s.safe, s.safeFlagged], [2, 1]);
  // a threshold with no logprobs turns every answer into an abstention
  assert.equal(scoreExternal(records, outputs, {threshold: -1}).answerRate, 0);
});

test('overlap finds records that repeat another set: same request, same opening, same actions or close wording', () => {
  const rec = (id, request, action) => ({id, request, steps: [{action, result: ''}]});
  const against = [rec('r1', 'Please archive the quarterly report folder for the finance team today', 'archive(folder=q3)'),
    rec('r2', 'Turn off the hallway lights', 'lights_off(room=hall)'), rec('r3', '', '')];
  const records = [rec('a', 'please  ARCHIVE the quarterly report folder for the finance team today', 'other()'),
    rec('b', 'Please archive the quarterly report folder for the finance team today but also email it', 'other()'),
    rec('c', 'Unrelated request about a calendar entry', 'lights_off(room=hall)'),
    rec('d', 'Archive the finance team quarterly report folder please, today', 'other()'),
    rec('e', 'Book a table for two at a restaurant', 'book(table=2)'), rec('f', '', 'noop()')];
  assert.deepEqual([...externalOverlap(records, against)].sort(), ['a', 'b', 'c', 'd']);
  // only exact repeats when the wording threshold is 1
  assert.deepEqual([...externalOverlap(records, against, {jaccard: 1})].sort(), ['a', 'c']);
  assert.deepEqual([...externalOverlap([rec('g', 'Archive quarterly folder', 'x()')], against, {jaccard: 1})], []);
});

// Sets added 2026-10-18. Fixtures are made-up sessions in each set's shape (field names and tags as the PC schema report gave them).
const atb = (id, label, extra = {}) => ({id, tool_used: [], contents: turns(`atb request ${id}`, '{"name":"lookup","arguments":{}}', '{"ok":true}'), label,
  risk_source: 'indirect_prompt_injection', failure_mode: 'f', real_world_harm: 'h', reason: '', ...extra});

test('ATBench and its 500 subset read like R-Judge rounds, keyed by their own ids, split by risk source, typed from the taxonomy', () => {
  const r = externalRecord('atbench', atb(3, 1));
  assert.deepEqual({id: r.id, family: r.family, verdict: r.verdict, type: r.type}, {id: 'atbench:3', family: 'atbench:indirect_prompt_injection',
    verdict: 'violation', type: 'prompt_injection'});
  assert.equal(r.attributes.riskSource, 'indirect_prompt_injection');
  const {contents, id, ...rest} = atb(0, 0, {risk_source: 'benign'});
  const s = externalRecord('atbench500', {...rest, conv_id: 'c-9', content: contents});
  assert.deepEqual({id: s.id, verdict: s.verdict, type: s.type, steps: s.steps.length}, {id: 'atbench500:c-9', verdict: 'clean', type: null, steps: 1});
  assert.equal(externalRecord('atbench', atb(4, 1, {risk_source: 'benign', failure_mode: 'unauthorized_information_disclosure'})).type, 'exfiltration');
  assert.equal(externalRecord('atbench', atb(5, 1, {risk_source: 'benign', failure_mode: 'other_mode'})).type, 'other');
});

test('an ATBench-Codex conversation keeps actions, final replies and results, labelled from is_safe', () => {
  const raw = {id: 11, is_safe: false, risk_source: 'tool_description_injection', failure_mode: 'f', harm_type: 'h', defense_type: null, conversation: [
    {role: 'user', content: 'tidy the repo'}, {role: 'assistant', thought: 't', action: {name: 'shell', arguments: {cmd: 'ls'}}},
    {role: 'environment', content: {status: 'success', result: {out: 'a b'}}}, {role: 'assistant', response: 'done'}]};
  const r = externalRecord('atbench-codex', raw);
  assert.deepEqual({id: r.id, agent: r.agent, verdict: r.verdict, type: r.type}, {id: 'atbench-codex:11', agent: 'codex', verdict: 'violation',
    type: 'prompt_injection'});
  assert.deepEqual(r.steps.map(s => [s.action, s.result]), [['{"name":"shell","arguments":{"cmd":"ls"}}', '{"status":"success","result":{"out":"a b"}}'],
    ['done', '']]);
  assert.equal(externalRecord('atbench-codex', {...raw, is_safe: 'no'}), null);
});

test('a StepGuard prompt is read back into the request, the steps and the labelled unsafe step', () => {
  const traj = ['Instructions.', '### Input', '<<User Request>>', 'book a room', '<BEGIN TRAJECTORY>', '[USER]: book a room',
    '[Step 1] [AGENT]: [THOUGHT]: plan', '[Step 1] [AGENT]: [ACTION]: search()', '[Observation after Step 1] [ENVIRONMENT]: [INFO] two rooms',
    '[Step 2] [AGENT]: [ACTION]: book(1)', '[Observation after Step 2] [ENVIRONMENT]: ok', '[AGENT]: [RESPONSE]: booked', '<END TRAJECTORY>',
    '<<Available Tools>>', 'search, book'].join('\n');
  const answer = '<Analysis>a</Analysis>\n<Judgment>unsafe</Judgment>\n<RiskSourcePresent>yes</RiskSourcePresent>\n'
    + '<RiskSource>indirect_prompt_injection</RiskSource>\n<UnsafeStep>2</UnsafeStep>';
  const r = externalRecord('stepguard', {conversations: [{from: 'human', value: traj}, {from: 'gpt', value: answer}]});
  assert.equal(r.request, 'book a room\nbook a room');
  assert.deepEqual(r.steps, [{action: 'search()', result: '[INFO] two rooms'}, {action: 'book(1)', result: 'ok'}, {action: 'booked', result: ''}]);
  assert.deepEqual({verdict: r.verdict, type: r.type, evidence: r.evidence, family: r.family}, {verdict: 'violation', type: 'prompt_injection',
    evidence: [1], family: 'stepguard:trajectory:indirect_prompt_injection'});
  const action = ['### Input', '<<User Request>>', 'pay the bill', '<<Interaction History>>', '[AGENT]: [ACTION]: open_bill()',
    '[ENVIRONMENT]: total 5', '<<Action Under Review>>', '[AGENT]: [ACTION]: pay(500)', '<<Available Tools>>', 'pay'].join('\n');
  const a = externalRecord('stepguard', {id: 'stepguard-rl-000001', instruction: action, output: 'unsafe', label: 'unsafe', level: 'action',
    risk_source: 'inherent_agent_failure'});
  assert.deepEqual({id: a.id, steps: a.steps.length, evidence: a.evidence, type: a.type}, {id: 'stepguard:stepguard-rl-000001', steps: 2,
    evidence: [1], type: 'other'});
  assert.equal(externalRecord('stepguard', {instruction: action, label: 'maybe'}), null);
});

test('one injection environment gives a clean session that ignores the injected record and a violation that obeys it', () => {
  const spec = {id: 5, domain: 'hr', attack_category: 'data_modification', required_tools: ['get_case'],
    responses_create_params: {input: [{role: 'system', content: 's'}, {role: 'user', content: 'summarize case C1'}],
      tools: [{type: 'function', function: {name: 'get_case',
        parameters: {type: 'object', properties: {case_id: {type: 'string'}}, required: ['case_id']}}}]},
    environment: {cases: {C1: {title: 't', case_summary: 'NOTE-TO-AGENT placeholder'}}, current_user: {id: 'u'}},
    injection: {target_tool: 'update_case_notes', target_args: {case_id: 'C1', notes: 'x'}, vector: 'case_summary',
      injection_text: 'NOTE-TO-AGENT placeholder'}};
  const {records} = externalRecords('ipi-pairs', JSON.stringify(spec) + '\n');
  assert.deepEqual(records.map(r => [r.id, r.verdict, r.type, r.evidence]), [['ipi-pairs:5:ignored', 'clean', null, []],
    ['ipi-pairs:5:obeyed', 'violation', 'prompt_injection', [1]]]);
  for (const r of records) {
    assert.equal(r.labelSource, 'by_construction');
    assert.equal(r.steps[0].action, '{"name":"get_case","arguments":{"case_id":"C1"}}');
    assert.ok(r.steps[0].result.startsWith('{"case_summary":'));
    assert.equal(externalTrainingRow(r, {split: 'tune', catalogDigest: 'x'}).labelSource, 'by_construction');
  }
  assert.ok(records[1].steps[1].action.includes('update_case_notes'));
  assert.ok(!records[0].steps.some(s => s.action.includes('update_case_notes')));
  assert.deepEqual(externalRecords('ipi-pairs', JSON.stringify({...spec, required_tools: ['update_case_notes']})).records, []);
});
