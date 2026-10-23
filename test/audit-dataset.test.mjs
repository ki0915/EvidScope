// The audit dataset (src/audit-dataset.mjs): designed scenarios and public-set records become one prompt-free record format, and the
// chat exporter gives back exactly the rows the round builder trains on, so the format can replace the round-specific files without
// changing what the current judges see. Fixtures for public sets are neutral, made-up sessions; no dataset text is in the repository.
import test from 'node:test';
import assert from 'node:assert/strict';
import {dirname, join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {AUDIT_DATASET_SCHEMA, chatMessages, chatTarget, classificationRow, datasetManifest, designedRecord, preferencePair, publicRecord,
  recordText, scoreRecords} from '../src/audit-dataset.mjs';
import {externalPrompt, externalRecord, externalTrainingRow} from '../src/external-agent-sets.mjs';
import {sessionPrompt, sessionTrainingRow} from '../src/session-inference.mjs';
import {composeCatalog, loadCatalog, loadRules} from '../src/threat-scenarios.mjs';
import {buildVariantCatalog} from '../src/session-variants.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const rules = loadRules(join(root, 'data/risk-rules/ai-agent-baseline.json'));
const catalog = composeCatalog(loadCatalog(join(root, 'data/threat-scenarios/v1/catalog.json')),
  loadCatalog(join(root, 'data/threat-scenarios/v1/contrast.json')));
const turns = (request, action, result) => [[{role: 'user', content: request}, {role: 'agent', thought: 't', action}, {role: 'environment', content: result}]];
const asse = (id, label) => ({id, profile: 'p', contents: turns(`request ${id}`, `call_tool(${id})`, 'ok'), label, application_scenario: 'Email Management',
  risk_type: 'Data Exfiltration & Leakage', failure_mode: 'f', ambiguous: 0, risk_description: 'd'});

test('a designed record exports the same chat prompt and answer the round builder trains on, for every variant and copy', () => {
  const variants = buildVariantCatalog(catalog, rules, {perThreat: 3, perBenign: 3});
  assert.ok(variants.scenarios.length > 50);
  for (const s of variants.scenarios) {
    const r = designedRecord(s, rules);
    for (const opts of [{}, {maskCodes: true}, {stripFindings: true}]) {
      assert.deepEqual(chatMessages(r, opts), sessionPrompt(s, rules, opts).messages, `${s.id} ${JSON.stringify(opts)}`);
    }
    assert.deepEqual(chatTarget(r), JSON.parse(sessionTrainingRow(s, rules, {split: 'tune', catalogDigest: 'x'}).target), s.id);
  }
});

test('a designed record keeps the label, its source and a hash that changes when the label changes', () => {
  const s = catalog.scenarios.find(x => x.label.verdict === 'violation');
  const r = designedRecord(s, rules, {split: 'train', fold: 'r7'});
  assert.equal(r.schema, AUDIT_DATASET_SCHEMA);
  assert.equal(r.source.kind, 'designed');
  assert.equal(r.labelSource, 'by_construction');
  assert.equal(r.label.verdict, 'violation');
  assert.ok(r.label.evidence.every(ref => r.steps.some(st => st.ref === ref)));
  assert.match(r.hash, /^[0-9a-f]{64}$/);
  const {hash, ...rest} = r;
  assert.notEqual(designedRecord({...s, label: {...s.label, type: 'other'}}, rules, {split: 'train', fold: 'r7'}).hash, hash);
  assert.equal(rest.split, 'train');
});

test('a public record exports the round builder\'s external prompt and answer, and keeps step labels when the set has them', () => {
  const e = externalRecord('assebench', asse(7, 1));
  const r = publicRecord(e);
  assert.equal(r.source.kind, 'public');
  assert.equal(r.labelSource, 'dataset_label');
  assert.deepEqual(chatMessages(r), externalPrompt(e));
  assert.deepEqual(chatTarget(r), JSON.parse(externalTrainingRow(e, {split: 'tune', catalogDigest: 'x'}).target));
  assert.deepEqual(publicRecord({...e, evidence: [0, 5]}).label.evidence, ['a1']);
  assert.throws(() => publicRecord({...e, set: 'nope'}), /audit_public_set_unknown/);
  const pair = publicRecord({...e, id: 'ipi-pairs:1:obeyed', set: 'ipi-pairs', labelSource: 'by_construction'});
  assert.deepEqual([pair.source.kind, pair.labelSource], ['synthetic', 'by_construction']);
});

test('the plain-text and preference exports carry the answer and its opposite', () => {
  const s = catalog.scenarios.find(x => x.label.verdict === 'clean');
  const r = designedRecord(s, rules);
  const c = classificationRow(r);
  assert.equal(c.label, 0);
  assert.equal(c.text, recordText(r));
  assert.ok(c.text.includes('a1 '));
  const p = preferencePair(r);
  assert.equal(JSON.parse(p.chosen).verdict, 'clean');
  assert.equal(JSON.parse(p.rejected).verdict, 'violation');
  const v = designedRecord(catalog.scenarios.find(x => x.label.verdict === 'violation'), rules);
  assert.equal(JSON.parse(preferencePair(v).rejected).verdict, 'clean');
});

test('scoreRecords grades any model\'s answers against the labels', () => {
  const v = designedRecord(catalog.scenarios.find(x => x.label.verdict === 'violation'), rules);
  const c = designedRecord(catalog.scenarios.find(x => x.label.verdict === 'clean'), rules);
  const score = scoreRecords([v, c], {[v.id]: {verdict: 'clean'}, [c.id]: {verdict: 'violation', type: 'other'}});
  assert.deepEqual({answerRate: score.answerRate, answeredAccuracy: score.answeredAccuracy, threatsMissed: score.threatsMissed,
    falseAlarms: score.falseAlarms}, {answerRate: 1, answeredAccuracy: 0, threatsMissed: 1, falseAlarms: 1});
  const right = scoreRecords([v, c], {[v.id]: {verdict: 'violation', type: v.label.type, evidence: v.label.evidence}, [c.id]: {verdict: 'clean'}});
  assert.equal(right.answeredAccuracy, 1);
  assert.equal(right.typeAccuracy, 1);
  assert.equal(right.evidenceF1, v.label.evidence.length ? 1 : null);
  assert.equal(scoreRecords([v], {}).answerRate, 0);
});

test('the manifest counts sources and labels, hashes the records in id order and refuses a repeated id', () => {
  const rs = catalog.scenarios.slice(0, 6).map(s => designedRecord(s, rules));
  const m = datasetManifest(rs, {name: 'test', version: '0'});
  assert.equal(m.records, 6);
  assert.equal(datasetManifest([...rs].reverse()).recordsHash, m.recordsHash);
  assert.equal(Object.values(m.bySource).reduce((a, b) => a + b, 0), 6);
  assert.throws(() => datasetManifest([rs[0], rs[0]]), /audit_duplicate_id/);
});
