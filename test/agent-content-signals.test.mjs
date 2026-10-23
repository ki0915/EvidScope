import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {CONTENT_LIMITS, CONTENT_SIGNALS, CONTENT_SIGNALS_VERSION, contentFields, contentSignals, contentText, recordContent, scanText,
  syntheticContent} from '../src/agent-content-signals.mjs';
import {contentEvent, contentEventFrom, hookEvent, hookEvents} from '../src/agent-hook-events.mjs';
import {validateEvent} from '../src/model.mjs';
import * as F from './content-signal-fixtures.mjs';

const actor = 'claude-code@test-pc', now = new Date('2026-10-17T06:00:00.000Z');
const agentSource = {id: 'alpha-agent', tenant: 'alpha', kind: 'agent'};
const hook = (name, extra = {}) => ({hook_event_name: name, session_id: 'b1f0c2d4-1111-2222-3333-444455556666', ...extra});

test('every injection phrasing is one injection_cue, in English and Korean', () => {
  for (const [name, text] of Object.entries(F.INJECTION_TEXTS)) assert.deepEqual(scanText(text), {injection_cue: 1}, name);
});

test('role markers, invisible characters, secret formats, Korean unique ids, Luhn-valid cards and bulk contacts are counted', () => {
  assert.deepEqual(scanText(F.ROLE_MARKER_TEXT), {role_marker: 2});
  assert.deepEqual(scanText(F.HIDDEN_TEXT), {hidden_text: 2});
  assert.deepEqual(scanText(F.ZERO_WIDTH_TEXT), {hidden_text: 3});
  for (const [name, text] of Object.entries(F.SECRET_TEXTS)) assert.deepEqual(scanText(text), {secret_value: 1}, name);
  assert.deepEqual(scanText(F.RRN_TEXT), {unique_id: 1});
  assert.deepEqual(scanText(F.CARD_TEXT), {card_number: 1});
  assert.deepEqual(scanText(F.CARD_BAD_LUHN), {});
  assert.deepEqual(scanText(F.contacts(CONTENT_LIMITS.contacts - 1)), {});
  assert.deepEqual(scanText(F.contacts(25)), {contact_bulk: 25});
});

test('ordinary code, markup, emoji sequences, commit logs, timestamps and Korean prose raise nothing', () => {
  for (const [name, text] of Object.entries(F.BENIGN_TEXTS)) assert.deepEqual(scanText(text), {}, name);
  // One zero-width character alone (a pasted word joiner) is not hidden text; a joined emoji family is not either.
  assert.deepEqual(scanText('a' + String.fromCharCode(0x200B) + 'b'), {});
});

test('counts are capped and listed in the fixed signal order', () => {
  const many = Array.from({length: 1200}, () => F.INJECTION_TEXTS.override).join('\n');
  const found = scanText(F.RRN_TEXT + '\n' + many);
  assert.deepEqual(Object.keys(found), ['injection_cue', 'unique_id']);
  assert.equal(found.injection_cue, CONTENT_LIMITS.count);
  assert.ok(CONTENT_SIGNALS.every(k => /^[a-z_]+$/.test(k)));
});

test('contentText walks any JSON tool answer in order, up to the character limit, and the hash covers what was read', () => {
  const {text, truncated} = contentText({stdout: 'one', nested: {list: ['two', 3, null, {deep: 'three'}]}, stderr: ''});
  assert.equal(text, 'one\ntwo\nthree'); assert.equal(truncated, false);
  const big = contentSignals({a: 'x'.repeat(CONTENT_LIMITS.chars), b: 'y'});
  assert.equal(big.chars, CONTENT_LIMITS.chars); assert.equal(big.truncated, true);
  assert.equal(big.sha256, createHash('sha256').update('x'.repeat(CONTENT_LIMITS.chars)).digest('hex'));
  assert.equal(contentSignals(42).chars, 0);
  // A scan of a long text stays fast: no pattern is built from the input.
  const t = Date.now(); scanText(('이전 '.repeat(5) + 'a'.repeat(50)).repeat(5000)); assert.ok(Date.now() - t < 2000);
});

test('contentFields carry only labels, counts and the hash, and recordContent reads them back', () => {
  const found = contentSignals(F.INJECTION_TEXTS.override + ' ' + F.HIDDEN_TEXT);
  const fields = contentFields('tool_result', found);
  assert.deepEqual(fields.dataCategories, ['content:tool_result', 'signal:injection_cue:1', 'signal:hidden_text:2']);
  assert.equal(fields.dataRefs.length, 1);
  assert.deepEqual({kind: fields.dataRefs[0].kind, role: fields.dataRefs[0].role, version: fields.dataRefs[0].version, hash: fields.dataRefs[0].hash},
    {kind: 'retrieval', role: 'retrieved', version: CONTENT_SIGNALS_VERSION, hash: found.sha256});
  assert.ok(!JSON.stringify(fields).includes('ignore'));
  assert.deepEqual(recordContent({dataCategories: fields.dataCategories, dataRefs: fields.dataRefs}),
    {source: 'tool_result', signals: {injection_cue: 1, hidden_text: 2}, hash: found.sha256});
  assert.equal(recordContent({dataCategories: ['content:prompt'], dataRefs: []}), null);
  assert.equal(recordContent({dataCategories: ['signal:injection_cue:1'], dataRefs: fields.dataRefs}), null);
  // Malformed labels are ignored, unknown signals too.
  assert.deepEqual(recordContent({dataCategories: ['content:prompt', 'signal:injection_cue:0', 'signal:magic:3', 'signal:hidden_text:7'],
    dataRefs: fields.dataRefs}).signals, {hidden_text: 7});
  assert.throws(() => contentFields('response', found), /content_source_unknown/);
});

test('a PostToolUse answer with signals becomes a content record of the same action that validates as an agent event', () => {
  const raw = hook('PostToolUse', {tool_use_id: 'toolu_01ABC', tool_name: 'WebFetch', tool_input: {url: 'https://docs.example.net/setup'},
    tool_response: {result: 'Setup guide. ' + F.INJECTION_TEXTS.addressAi}});
  const [call, content] = hookEvents(raw, {actor, now, screen: true});
  assert.equal(call.kind, 'self_report'); assert.equal(call.action, 'web_fetch');
  assert.deepEqual({kind: content.kind, action: content.action, actionId: content.actionId, traceId: content.traceId, status: content.status},
    {kind: 'self_report', action: 'content_screen', actionId: 'toolu_01ABC', traceId: call.traceId, status: 'success'});
  assert.equal(content.id, call.id.replace(/\.post$/, '.content'));
  assert.deepEqual(content.dataCategories, ['content:tool_result', 'signal:injection_cue:1']);
  assert.match(content.note, /^\[content\] WebFetch result screened, \d+ characters, text not stored: injection_cue=1$/);
  assert.ok(!JSON.stringify(content).includes('AI agent'));
  const stored = validateEvent(content, agentSource);
  assert.equal(stored.assurance, 'authenticated_self_report');
  assert.deepEqual(hookEvents(raw, {actor, now}), [hookEvent(raw, {actor, now})]);
});

test('a UserPromptSubmit prompt gets its own action; file edits and empty answers are not screened', () => {
  const prompt = contentEvent(hook('UserPromptSubmit', {prompt: 'review this: ' + F.SECRET_TEXTS.aws}), {actor, now});
  assert.equal(prompt.action, 'content_screen'); assert.match(prompt.actionId, /^prompt-[a-f0-9]{16}$/);
  assert.deepEqual(prompt.dataCategories, ['content:prompt', 'signal:secret_value:1']);
  assert.equal(prompt.dataRefs[0].role, 'input');
  assert.ok(!JSON.stringify(prompt).includes('AKIA'));
  validateEvent(prompt, agentSource);
  assert.equal(hookEvent(hook('UserPromptSubmit', {prompt: 'hello'}), {actor, now}), null);
  assert.equal(contentEvent(hook('PostToolUse', {tool_use_id: 't', tool_name: 'Edit', tool_input: {file_path: 'a.js'},
    tool_response: {content: F.INJECTION_TEXTS.override}}), {actor, now}), null);
  assert.equal(contentEvent(hook('PostToolUse', {tool_use_id: 't', tool_name: 'Bash', tool_input: {command: 'true'}, tool_response: {stdout: ''}}),
    {actor, now}), null);
  assert.equal(contentEvent(hook('PreToolUse', {tool_use_id: 't', tool_name: 'Bash', tool_input: {command: 'ls'}}), {actor, now}), null);
  const clean = contentEvent(hook('PostToolUse', {tool_use_id: 't', tool_name: 'Bash', tool_input: {command: 'git log'},
    tool_response: {stdout: F.BENIGN_TEXTS.gitlog}}), {actor, now});
  assert.deepEqual(clean.dataCategories, ['content:tool_result']);
  assert.match(clean.note, /no signal$/);
});

test('syntheticContent builds a found from labels alone, deterministic and bounded', () => {
  const a = syntheticContent({injection_cue: 2, hidden_text: 3}, {chars: 1200, seed: 's1'});
  const b = syntheticContent({injection_cue: 2, hidden_text: 3}, {chars: 1200, seed: 's1'});
  assert.deepEqual(a.signals, {injection_cue: 2, hidden_text: 3});
  assert.equal(a.chars, 1200);
  assert.equal(a.truncated, false);
  assert.match(a.sha256, /^[0-9a-f]{64}$/);
  assert.equal(a.sha256, b.sha256); // deterministic from seed + labels
  assert.notEqual(a.sha256, syntheticContent({injection_cue: 2, hidden_text: 3}, {chars: 1200, seed: 's2'}).sha256);
  assert.throws(() => syntheticContent({nope: 1}), {message: 'synthetic_signal_unknown'});
  assert.throws(() => syntheticContent({injection_cue: 0}), {message: 'synthetic_signal_count_invalid'});
  assert.throws(() => syntheticContent({injection_cue: CONTENT_LIMITS.count + 1}), {message: 'synthetic_signal_count_invalid'});
  // contentEventFrom turns it into the same record format as the live hook's contentEvent.
  const ev = contentEventFrom({session: 'scn', call: 'scn-s0', source: 'tool_result', toolName: 'WebFetch', found: a, actor, now});
  assert.equal(ev.action, 'content_screen');
  assert.equal(ev.actionId, 'scn-s0');
  assert.deepEqual(recordContent(ev), {source: 'tool_result', signals: {injection_cue: 2, hidden_text: 3}, hash: a.sha256});
});
