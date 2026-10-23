import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdirSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {governanceCatalog} from '../src/governance-mapping.mjs';
import {buildDataset, derivedItems, governanceAdmission} from '../src/governance-mapping-data.mjs';
import {ABSTAIN_RATIO, INJECTIONS, INJECTION_RULES, LOCAL_TABLES, LOCAL_TABLES_ENV, SHIPPED_TABLES, TEXT_CHARS, isLocalTableId, localTablesFor,
  parseEuCitation, parseKrCitation, sourceItems, sourceTableStatus} from '../src/governance-mapping-sources.mjs';
import {runGovernanceMappingCommand} from '../scripts/governance-mapping.mjs';

// Governance-mapping tests see only the shipped source tables; a local-only (KOGL) table on this machine must not change them.
process.env.EVIDSCOPE_GOVERNANCE_LOCAL_TABLES ??= '.test-runs/no-local-tables';

const catalog = governanceCatalog();
const NO_LOCAL = {localTables: false};
const committed = readFileSync('data/governance-mapping/v1/dataset.jsonl', 'utf8').trim().split('\n').map(line => JSON.parse(line));

test('citations: Korean article/paragraph/item lists and EU article(paragraph)(point) lists parse; anything else is refused', () => {
  assert.deepEqual(parseKrCitation('인공지능기본법 제34조제1항제5호 / 시행령 제27조제1항·제2항'), [
    {doc: 'law', article: '34', paragraph: '1', item: '5'}, {doc: 'decree', article: '27', paragraph: '1', item: null},
    {doc: 'decree', article: '27', paragraph: '2', item: null}]);
  assert.deepEqual(parseKrCitation('인공지능기본법 제40조 / 제43조제1항제3호'),
    [{doc: 'law', article: '40', paragraph: null, item: null}, {doc: 'law', article: '43', paragraph: '1', item: '3'}]);
  assert.deepEqual(parseKrCitation('시행령 제12조의2'), [{doc: 'decree', article: '12의2', paragraph: null, item: null}]);
  assert.throws(() => parseKrCitation('제3조제1항'), /kr_citation_invalid/);
  assert.throws(() => parseKrCitation('인공지능기본법 제3조 1항'), /kr_citation_invalid/);
  assert.deepEqual(parseEuCitation('Regulation (EU) 2024/1689, Article 72(1) and (2)'),
    [{article: '72', paragraph: '1', point: null}, {article: '72', paragraph: '2', point: null}]);
  assert.deepEqual(parseEuCitation('Article 26(5)(a), (6)'), [{article: '26', paragraph: '5', point: 'a'}, {article: '26', paragraph: '6', point: null}]);
  assert.deepEqual(parseEuCitation('Article 12'), [{article: '12', paragraph: null, point: null}]);
  assert.throws(() => parseEuCitation('Art. 12'), /eu_citation_invalid/);
  for (const e of catalog.entries) {
    if (e.framework === 'kr-ai-basic-act') assert.ok(parseKrCitation(e.citation).length > 0, e.id);
    if (e.framework === 'eu-ai-act-logging') assert.ok(parseEuCitation(e.citation).length > 0, e.id);
  }
});

test('source rows: sentence type sets kind and relation, labels are catalog ids, abstain rows are capped per rule, texts fit the prompt', () => {
  const items = sourceItems(catalog, NO_LOCAL), byRule = new Map();
  for (const i of items) byRule.set(i.rule, [...(byRule.get(i.rule) ?? []), i]);
  assert.deepEqual([...byRule.keys()].sort(), ['eu-law-text', 'kr-law-text', 'prowler-check', 'prowler-defect', 'prowler-evidence']);
  const shape = {'prowler-check': ['document_excerpt', 'context_only'], 'prowler-evidence': ['record_summary', 'supports'],
    'prowler-defect': ['finding_note', 'contradicts'], 'kr-law-text': ['document_excerpt', 'context_only'],
    'eu-law-text': ['document_excerpt', 'context_only']};
  for (const [rule, list] of byRule) {
    assert.ok(list.every(i => i.kind === shape[rule][0] && i.relation === shape[rule][1]), rule);
    assert.ok(list.every(i => i.labels.every(id => catalog.byId.has(id)) && [...i.text].length <= TEXT_CHARS), rule);
    assert.ok(list.every(i => /^[a-f0-9]{64}$/.test(i.tableSha256)), rule);
    const labelled = list.filter(i => i.labels.length).length, abstain = list.length - labelled;
    assert.ok(labelled > 0 && abstain > 0 && abstain <= Math.max(8, Math.ceil(labelled / ABSTAIN_RATIO)), `${rule}: ${labelled} labelled, ${abstain} abstain`);
  }
  assert.equal(new Set(items.map(i => `${i.rule}\n${i.text}`)).size, items.length, 'one row per text within a rule');
  // Prowler sentences: an ISMS-P item of the catalog labels its sentences, one outside the catalog yields rows that must abstain.
  const inCatalog = catalog.ids.filter(id => id.startsWith('ISMS-P-')).map(id => id.slice('ISMS-P-'.length));
  assert.ok(inCatalog.includes('2.9.4') && !inCatalog.includes('1.1.1'));
  const prowler = items.filter(i => i.rule.startsWith('prowler-'));
  assert.ok(prowler.some(i => i.ref === '2.9.4' && i.labels.length === 1 && i.labels[0] === 'ISMS-P-2.9.4'));
  const outside = [...new Set(prowler.flatMap(i => i.ref.split('+')))].filter(n => !inCatalog.includes(n));
  assert.ok(outside.length >= 8, 'items outside the catalog survive the abstain cap');
  assert.ok(prowler.filter(i => !i.ref.split('+').some(n => inCatalog.includes(n))).every(i => i.labels.length === 0));
  // Law text: each row names the article it quotes and labels only requirements of its own framework; EU Annex IV rows abstain.
  const kr = byRule.get('kr-law-text'), eu = byRule.get('eu-law-text');
  assert.ok(kr.every(i => /^인공지능기본법( 시행령)? 제\d+(의\d+)?조/.test(i.text) && i.labels.every(id => catalog.byId.get(id).framework === 'kr-ai-basic-act')));
  assert.ok(kr.some(i => i.text.startsWith('인공지능기본법 시행령 제') && i.labels.length));
  assert.ok(eu.every(i => /^EU AI Act (Article \d+|Annex IV)/.test(i.text) && i.labels.every(id => catalog.byId.get(id).framework === 'eu-ai-act-logging')));
  assert.ok(eu.filter(i => i.text.startsWith('EU AI Act Annex')).every(i => i.labels.length === 0));
  assert.ok(eu.some(i => i.text.startsWith('EU AI Act Article 12') && i.labels.length));
});

test('injection rows: a fixed instruction naming another requirement is appended; the label stays and the named id is forbidden', () => {
  const items = derivedItems(catalog, NO_LOCAL), plain = items.filter(i => !i.injection);
  // Abstain rows of one rule and source item share a family, so the base is the family member whose text the row extends.
  const baseOf = i => plain.find(x => x.familyId === i.derivation.ref && i.text.startsWith(x.text + ' '));
  const injected = items.filter(i => i.injection);
  assert.equal(injected.length, 50);
  assert.equal(injected.filter(i => i.truth.abstain).length, 12);
  for (const i of injected) {
    const base = baseOf(i);
    assert.ok(base && INJECTION_RULES.includes(base.derivation.rule), i.id);
    assert.ok(i.text.startsWith(base.text + ' ') && [...i.text].length <= TEXT_CHARS, i.id);
    assert.deepEqual(i.truth.mappings.map(m => m.requirementId), base.truth.mappings.map(m => m.requirementId));
    assert.deepEqual([i.derivation.rule, i.derivation.framework, i.kind], ['injection', base.derivation.framework, base.kind]);
    if (base.split) assert.equal(i.split, base.split);
    const [forbidden, ...rest] = i.injection.forbidden;
    assert.ok(rest.length === 0 && catalog.byId.has(forbidden) && i.text.includes(forbidden) && !i.truth.mappings.some(m => m.requirementId === forbidden));
  }
  assert.ok(Object.values(INJECTIONS).flat().every(t => t.includes('{id}')));
  // The committed rows carry the forbidden id in their truth, where the gate's injection check reads it.
  const rows = committed.filter(r => r.derivation?.rule === 'injection'), byFamilyRow = new Map(committed.map(r => [r.familyId, r]));
  assert.equal(rows.length, 50);
  assert.ok(rows.every(r => r.truth.forbidden.length === 1 && r.labelSource === 'derived_mapping_table'));
  assert.ok(rows.every(r => r.split === byFamilyRow.get(r.derivation.ref).split), 'an injection row follows the split of the row it extends');
});

test('local-only tables: loaded from the configured directory only, never shipped; the dataset itself says whether it used them', () => {
  assert.equal(isLocalTableId('kisa-isms-p-guide-2023-11'), true);
  assert.ok(SHIPPED_TABLES.every(t => !isLocalTableId(t.id)) && LOCAL_TABLES.every(t => /KOGL/.test(t.licence)));
  const status = sourceTableStatus(NO_LOCAL);
  assert.ok(status.filter(t => t.shipped).every(t => t.present && t.sha256) && status.filter(t => !t.shipped).every(t => !t.present && !t.sha256));
  assert.ok(committed.every(r => !isLocalTableId(r.derivation?.framework)), 'a KOGL-4 table row never reaches the repository');
  assert.equal(localTablesFor(committed), false);
  mkdirSync('.test-runs', {recursive: true});
  const dir = mkdtempSync(resolve('.test-runs/governance-tables-'));
  writeFileSync(join(dir, 'kisa-isms-p-guide-2023-11.json'), JSON.stringify({schemaVersion: 1, id: 'kisa-isms-p-guide-2023-11', items: [
    {number: '2.9.4', title: '로그 및 접속기록 관리', checkItems: ['서버 접속기록을 남기고 있는가?'], evidenceExamples: ['서버 접속기록 보관 현황'],
      defectCases: ['사례 1 : 접속기록을 1년 미만으로 보관하는 경우']},
    {number: '1.1.1', title: '경영진의 참여', checkItems: ['경영진이 참여하는가?'], evidenceExamples: [], defectCases: []}]}));
  const local = sourceItems(catalog, {localTables: dir}).filter(i => i.framework === 'kisa-isms-p-guide-2023-11');
  assert.deepEqual(local.map(i => [i.rule, i.ref, i.text, i.labels]).sort(), [
    ['kisa-check', '1.1.1', '경영진이 참여하는가?', []], ['kisa-check', '2.9.4', '서버 접속기록을 남기고 있는가?', ['ISMS-P-2.9.4']],
    ['kisa-defect', '2.9.4', '접속기록을 1년 미만으로 보관하는 경우', ['ISMS-P-2.9.4']], ['kisa-evidence', '2.9.4', '서버 접속기록 보관 현황', ['ISMS-P-2.9.4']]]);
  assert.ok(sourceTableStatus({localTables: dir}).find(t => t.id === 'kisa-isms-p-guide-2023-11').present);
  const previous = process.env[LOCAL_TABLES_ENV];
  process.env[LOCAL_TABLES_ENV] = dir;
  try {
    const rows = buildDataset({localTables: dir});
    assert.ok(rows.some(r => r.derivation?.framework === 'kisa-isms-p-guide-2023-11' && r.split));
    assert.equal(localTablesFor(rows), dir);
    assert.ok(Object.values(governanceAdmission(rows).counts).every(c => c.excludedInvalid === 0), 'a local build re-derives where it was built');
  } finally { if (previous === undefined) delete process.env[LOCAL_TABLES_ENV]; else process.env[LOCAL_TABLES_ENV] = previous; }
  const sources = runGovernanceMappingCommand(['sources', '--local-tables', 'none']);
  assert.ok(sources.tables.every(t => t.shipped === t.present) && Object.keys(sources.rules).length === 11);
});
