import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {loadData, renderAll, validateEntries} from '../scripts/build-dev-log.mjs';

const data = loadData();

test('development log records follow the schema and vocabulary', () => {
  assert.deepEqual(validateEntries(data.entries, data.vocabulary), []);
  assert.ok(data.entries.length > 0);
});

test('generated development log files are up to date with their records', () => {
  for (const [name, text] of Object.entries(renderAll(data))) {
    assert.equal(readFileSync(new URL(`../docs/dev-log/${name}`, import.meta.url), 'utf8'), text, `${name} is stale: run node scripts/build-dev-log.mjs`);
  }
});

test('validation rejects unknown skills, broken links and a missing owner note field', () => {
  const entry = structuredClone(data.entries[0]);
  entry.skills = ['not_a_skill'];
  entry.related = ['ZZ-99'];
  delete entry.owner_notes;
  const errors = validateEntries([entry], data.vocabulary).join('\n');
  assert.match(errors, /unknown skill not_a_skill/);
  assert.match(errors, /related id ZZ-99 does not exist/);
  assert.match(errors, /missing keys owner_notes/);
});

test('the career profile aggregates skills with the entries that show them', () => {
  const profile = JSON.parse(renderAll(data)['career-profile.json']);
  assert.equal(profile.schema, 'evidscope-career-profile/1');
  for (const skill of profile.skills) {
    assert.equal(skill.count, skill.entries.length);
    for (const id of skill.entries) assert.ok(data.entries.find(e => e.id === id).skills.includes(skill.key));
  }
  const lines = renderAll(data)['entries.jsonl'].trim().split('\n').map(line => JSON.parse(line));
  assert.equal(lines.length, data.entries.length);
});
