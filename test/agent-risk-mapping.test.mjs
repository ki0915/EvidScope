// Mapping version 3: the findings of the AI agent risk rules (data/risk-rules/ai-agent-baseline.json) as evidence of
// AI 기본법, ISMS-P and EU AI Act items, by code prefix (docs/agent-monitoring.md).
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {AGENT_RISK, FRAMEWORKS, MAPPING_VERSION, checkMapping, frameworkMapping, shippedMapping} from '../src/evidence-pack-frameworks.mjs';
import {findingMatches, measure} from '../src/evidence-inventory.mjs';
import {findingRequirements, presence} from '../src/home-service.mjs';
import {CATALOG_MAPPING_VERSION, governanceCatalog} from '../src/governance-mapping.mjs';

const pack = JSON.parse(readFileSync(new URL('../data/risk-rules/ai-agent-baseline.json', import.meta.url), 'utf8'));
const ruleIds = pack.rules.map(r => r.id);
const prefixEntries = FRAMEWORKS.flatMap(id => frameworkMapping(id).items.flatMap(item => item.evidence
  .filter(e => e.type === 'finding' && e.codePrefix !== undefined).map(e => ({framework: id, item: item.id, ...e}))));
const itemsFor = code => findingRequirements().links.filter(l => findingMatches(l.match, {code})).flatMap(l => l.items.map(i => i.id));

test('version 3 is the shipped current mapping and only adds agent risk prefixes to version 2', () => {
  assert.equal(MAPPING_VERSION, 3);
  for (const id of FRAMEWORKS) {
    const v2 = JSON.parse(shippedMapping(id, 2)), v3 = JSON.parse(shippedMapping(id, 3));
    assert.deepEqual(v3.items.map(i => i.id), v2.items.map(i => i.id), id);
    for (const [n, item] of v3.items.entries()) {
      const added = item.evidence.filter(e => e.codePrefix !== undefined);
      assert.deepEqual(item.evidence.filter(e => e.codePrefix === undefined), v2.items[n].evidence, `${id} ${item.id} keeps its version 2 evidence`);
      for (const e of added) assert.match(e.codePrefix, /^CUSTOM:risk\./);
    }
  }
});

test('every prefix names rules of the pack, and every rule counts for 2.11.3, KR-32-MONITOR and EU 12(2)(a)', () => {
  assert.ok(prefixEntries.length > 0);
  for (const e of prefixEntries) {
    const hits = ruleIds.filter(id => `CUSTOM:${id}:v1`.startsWith(e.codePrefix));
    assert.ok(hits.length > 0, `${e.framework} ${e.item} ${e.codePrefix} names no rule`);
    if (e.codePrefix.endsWith(':')) assert.equal(hits.length, 1, `${e.codePrefix} names exactly one rule`);
  }
  for (const id of ruleIds) {
    const items = itemsFor(`CUSTOM:${id}:v7`);
    for (const must of ['ISMS-P-2.11.3', 'KR-32-MONITOR', 'KR-34-RISK', 'EU-AIA-12-2-A', 'EU-AIA-14-4-A']) assert.ok(items.includes(must), `${id} -> ${must}`);
  }
  assert.ok(Object.values(AGENT_RISK).every(e => ruleIds.some(id => id.startsWith(e.codePrefix.slice('CUSTOM:'.length)))));
});

test('narrow items take only their rules: security tools for 2.10.1, log and monitoring tampering for 2.9.4, outbound for 2.6.7', () => {
  const has = (code, item) => itemsFor(code).includes(item);
  assert.ok(has('CUSTOM:risk.defense.defender:v1', 'ISMS-P-2.10.1')); assert.ok(!has('CUSTOM:risk.defense.defender:v1', 'ISMS-P-2.9.4'));
  assert.ok(has('CUSTOM:risk.defense.clear-eventlog:v2', 'ISMS-P-2.9.4')); assert.ok(!has('CUSTOM:risk.defense.clear-eventlog:v2', 'ISMS-P-2.10.1'));
  assert.ok(!has('CUSTOM:risk.defense.clear-eventlog-ps-x:v1', 'ISMS-P-2.9.4'), 'a rule prefix ends at the version separator');
  assert.ok(has('CUSTOM:risk.audit.claude-settings:v1', 'ISMS-P-2.9.4'));
  for (const item of ['ISMS-P-2.10.1', 'ISMS-P-2.9.4', 'ISMS-P-2.6.7']) assert.ok(!has('CUSTOM:risk.defense.chmod-777:v1', item), item);
  assert.ok(has('CUSTOM:risk.out.scp:v1', 'ISMS-P-2.6.7')); assert.ok(!has('CUSTOM:risk.cred.etc-shadow:v1', 'ISMS-P-2.6.7'));
  assert.deepEqual(itemsFor('CUSTOM:other.rule:v1'), [], 'other tenant rules are not agent risk evidence');
  assert.ok(itemsFor('DESTINATION_OUTSIDE_POLICY').includes('ISMS-P-2.6.7'), 'built-in codes keep their items');
});

test('the package inventory and the home presence count prefixed findings of the latest evaluations', () => {
  const evaluation = (seq, actionId, codes) => ({seq, recordedAt: '2026-10-15T05:00:00.000Z', payload: {actionId, findings: codes.map(code => ({code}))}});
  const rows = [evaluation(7, 'a1', ['CUSTOM:risk.cred.etc-shadow:v1', 'UNREGISTERED_ASSET']), evaluation(9, 'a2', ['CUSTOM:risk.cred.aws:v1']),
    evaluation(11, 'a3', ['CUSTOM:risk.out.scp:v1'])];
  const data = {latest: new Map(rows.map(r => [r.payload.actionId, r])), replayed: null, locators: true};
  assert.deepEqual(measure(AGENT_RISK.cred, data, {}), {status: 'present', count: 2, actions: 2, suppressed: 0,
    recordedAt: {from: '2026-10-15T05:00:00.000Z', to: '2026-10-15T05:00:00.000Z'}, replay: 'not_requested', verification: 'signed_evaluation', seqs: [7, 9]});
  assert.equal(measure(AGENT_RISK.audit, data, {}).status, 'none_recorded');
  const present = presence(rows.map(r => ({type: 'evaluation', ...r})), [], null);
  assert.equal(present(AGENT_RISK.out), true); assert.equal(present(AGENT_RISK.destroy), false);
  assert.equal(present({type: 'finding', code: 'UNREGISTERED_ASSET'}), true);
});

test('a mapping names a finding by one code or one prefix, never both and never an empty prefix', () => {
  const base = frameworkMapping('eu-ai-act-logging'), item = base.items[0];
  const withEvidence = e => ({...base, items: [{...item, evidence: [e]}, ...base.items.slice(1)]});
  checkMapping(withEvidence({type: 'finding', codePrefix: 'CUSTOM:risk.cred.'}));
  for (const bad of [{type: 'finding', code: 'X_Y', codePrefix: 'CUSTOM:'}, {type: 'finding', codePrefix: ''}, {type: 'finding'},
    {type: 'finding', codePrefix: 'C'}, {type: 'finding', code: 'A B'}]) assert.throws(() => checkMapping(withEvidence(bad)), /Malformed evidence/);
});

test('the governance model catalog stays on mapping version 2', () => {
  const catalog = governanceCatalog();
  assert.equal(CATALOG_MAPPING_VERSION, 2);
  for (const id of FRAMEWORKS) assert.equal(catalog.sources[id].version, 2);
  assert.ok(!catalog.entries.some(e => e.evidence.some(x => x.codePrefix !== undefined)));
});
