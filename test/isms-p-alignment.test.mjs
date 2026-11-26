import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { resolve, sep } from 'node:path';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { createService } from '../src/service.mjs';
import { createIdentity } from '../src/identity.mjs';
import { validateEvent } from '../src/model.mjs';
import { isSignedObjectType } from '../src/object-integrity.mjs';
import { ACCESS_BATCH_TYPE } from '../src/access-log.mjs';
import { krGovernanceCheckDefinitions } from '../src/kr-governance-evidence.mjs';

// The ISMS-P table names official items and concrete EvidScope features. These tests fail when the item list drifts from
// the notice text it was checked against, when an item is dropped or listed twice, or when a named route, record, finding,
// event rule, check or file disappears, so the reference table cannot drift silently from the sources or the code.
const root = new URL('../', import.meta.url), read = path => readFileSync(new URL(path, root), 'utf8');
const alignment = JSON.parse(read('data/isms-p-alignment.json')), requirements = JSON.parse(read('data/requirements.json'));
const items = alignment.officialItems, byNumber = new Map(items.map(i => [i.number, i]));
const evidence = alignment.alignments.flatMap(a => a.supports.flatMap(s => s.evidence.map(e => ({ ...e, item: a.item }))));
const domains = alignment.officialStructure.flatMap(area => area.domains.map(d => ({ ...d, area: area.area })));
const types = new Set(['api', 'record', 'finding', 'eventKind', 'checkType', 'integrityCheck', 'file']);
const UNROUTED = '지원하지 않는 경로 또는 메서드', KIND_DENIED = '출처 자격에 허용되지 않은 이벤트 유형';
const ITEM_NUMBER = /\b[1-3]\.\d{1,2}\.\d{1,2}\b/g, CIRCLED = '①②③④⑤⑥⑦⑧⑨';
// SHA-256 of [[number, title, checkItems], ...] as read on 2026-10-07 from [별표 7] of the notice (DRF XML below) and the
// KISA workbook. A change to the item list must come with a new source reading, not a silent edit.
const ITEM_LIST_SHA256 = '46c5a53639143f663357161997fd7140680c90ab01b4933308f37cc60e507a9c';
const SOURCE_SHA256 = {
  legal: '1f791301caf2b1135be1b353bddc98a31a2656e1988cb073bb8cafa64a3b09f1',
  check_items: 'ab99cad99473eb8873d0000be42be4f13f098b26515c45a8a141d4625ff4bf2d',
  guide: 'cf80d3bb191f325583e7410840d8016b50ffcf28f9fc5a4d044e4ef600f90a9b',
};
const concrete = path => path.replaceAll('{id}', 'isms-p-alignment-check');
const label = e => `${e.item} ${e.type} ${e.method || ''} ${e.path || e.name || e.code}`;
const strings = value => typeof value === 'string' ? [value] : value && typeof value === 'object' ? Object.values(value).flatMap(strings) : [];

test('ISMS-P alignment stays a human-review draft and records its legal and explanatory sources', () => {
  assert.equal(alignment.schemaVersion, 2);
  assert.equal(alignment.mappingStatus, 'draft_requires_human_review');
  assert.equal(alignment.nature, 'reference_alignment_not_certification');
  assert.equal(alignment.certificationClaim, false);
  assert.equal(alignment.criterionAssessment, 'not_performed');
  assert.equal(alignment.granularity, 'item');
  const { sources } = alignment, { legal } = sources;
  for (const day of [alignment.checkedAt, sources.readAt, legal.promulgatedOn, legal.effectiveOn, ...sources.explanatory.map(s => s.postedOn)]) {
    assert.match(day, /^\d{4}-\d\d-\d\d$/);
  }
  assert.equal(sources.verifiedLevel, 'item_numbers_and_titles_verified_against_notice_check_items_from_kisa_workbook');
  assert.equal(legal.title, '정보보호 및 개인정보보호 관리체계 인증 등에 관한 고시');
  assert.equal(legal.annex, '[별표 7] 인증기준(제23조 관련)');
  assert.equal(legal.sha256, SOURCE_SHA256.legal);
  assert.deepEqual([new URL(legal.url).protocol, new URL(legal.url).hostname], ['https:', 'www.law.go.kr']);
  assert.ok(new URL(legal.url).searchParams.get('admRulSeq') === legal.admRulSeq);
  assert.ok(legal.notices.some(n => n.basis === 'drf_xml_issue_number'));
  for (const n of legal.notices) assert.ok(['drf_xml_issue_number', 'lead_supplied_not_in_drf_xml'].includes(n.basis), n.number);
  assert.deepEqual(sources.explanatory.map(s => s.role).sort(), ['check_items', 'guide']);
  for (const s of sources.explanatory) {
    assert.equal(s.sha256, SOURCE_SHA256[s.role], s.role);
    assert.deepEqual([new URL(s.listUrl).protocol, new URL(s.listUrl).hostname], ['https:', 'isms-p.or.kr']);
  }
  assert.ok(sources.annex7Change.basis.length && sources.annex7Change.limit && sources.limitations.length);
});

test('the official item list has 101 unique items in 21 existing domains, and each is aligned or explained exactly once', () => {
  assert.deepEqual(alignment.officialStructure.map(a => [a.area, a.label, a.criteria, a.checkItems, a.domains.length, a.certifications]),
    [['1', '가', 16, 42, 4, ['ISMS-P', 'ISMS']], ['2', '나', 64, 195, 12, ['ISMS-P', 'ISMS']], ['3', '다', 21, 91, 5, ['ISMS-P']]]);
  for (const d of domains) assert.ok(/^[1-3]\.\d{1,2}$/.test(d.id) && d.id.startsWith(d.area + '.') && d.title.length <= 30, d.id);
  assert.equal(new Set(domains.map(d => d.id)).size, 21);
  assert.equal(items.length, 101);
  assert.equal(byNumber.size, 101, 'item numbers are unique');
  const digest = createHash('sha256').update(JSON.stringify(items.map(i => [i.number, i.title, i.checkItems]))).digest('hex');
  assert.equal(digest, ITEM_LIST_SHA256, 'item numbers, titles and check-item counts match the 2026-10-07 reading of the sources');
  for (const area of alignment.officialStructure) {
    const inArea = items.filter(i => i.number.startsWith(area.area + '.'));
    assert.equal(inArea.length, area.criteria, area.area);
    assert.equal(inArea.reduce((total, i) => total + i.checkItems, 0), area.checkItems, area.area);
  }
  for (const d of domains) {
    const numbers = items.filter(i => i.number.startsWith(d.id + '.')).map(i => i.number);
    assert.ok(numbers.length, d.id);
    assert.deepEqual(numbers, numbers.map((_, index) => `${d.id}.${index + 1}`), `${d.id} items are numbered without gaps`);
  }
  for (const i of items) {
    assert.match(i.number, /^[1-3]\.\d{1,2}\.\d{1,2}$/);
    assert.ok(domains.some(d => i.number.startsWith(d.id + '.')), i.number);
    assert.ok(i.title.length > 0 && i.title.length <= 30 && Number.isInteger(i.checkItems) && i.checkItems >= 1 && i.checkItems <= 9, i.number);
  }
  const listed = [...alignment.alignments, ...alignment.notAligned].map(a => a.item);
  assert.equal(listed.length, 101);
  assert.deepEqual([...listed].sort(), items.map(i => i.number).sort(), 'every official item is either aligned or explained, exactly once');
  // Item numbers anywhere in the data, the notes included, come only from the official list.
  for (const number of JSON.stringify(alignment).match(ITEM_NUMBER)) assert.ok(byNumber.has(number), number);
});

test('aligned items cite check items by position, name evidence and manual work, and never claim a criterion is met', () => {
  for (const a of alignment.alignments) {
    const count = byNumber.get(a.item).checkItems, cited = a.supports.flatMap(s => s.checkItems);
    assert.ok(a.supports.length && a.manual.length, a.item);
    assert.equal(new Set(cited).size, cited.length, a.item + ' cites each check item once');
    for (const s of a.supports) {
      assert.ok(s.checkItems.length && s.checkItems.every(n => Number.isInteger(n) && n >= 1 && n <= count), a.item);
      assert.ok(typeof s.shows === 'string' && s.shows.length > 0 && s.shows.length <= 200, a.item);
      assert.ok(s.evidence.length, a.item);
      for (const e of s.evidence) {
        assert.ok(types.has(e.type), label({ ...e, item: a.item }));
        assert.ok(typeof e.what === 'string' && e.what.length > 0 && e.what.length <= 120, label({ ...e, item: a.item }));
      }
    }
    for (const text of a.manual) assert.ok(typeof text === 'string' && text.length > 0 && text.length <= 200, a.item);
    for (const mark of strings(a).join('').match(/[①-⑨]/g) || []) assert.ok(CIRCLED.indexOf(mark) < count, `${a.item} ${mark}`);
  }
  for (const n of alignment.notAligned) {
    assert.ok(Object.hasOwn(alignment.notAlignedReasons, n.reason), n.item);
    assert.ok(n.note === undefined || (typeof n.note === 'string' && n.note.length <= 200), n.item);
  }
  assert.deepEqual(Object.keys(alignment.notAlignedReasons).sort(), [...new Set(alignment.notAligned.map(n => n.reason))].sort());
  // No KISA check question is copied (they end in "...있는가?"), and no sentence states that a criterion is met.
  for (const text of strings([alignment.alignments, alignment.notAligned, alignment.notAlignedReasons])) {
    assert.doesNotMatch(text, /있는가|\?$/, text);
    assert.doesNotMatch(text, /충족(한다|함|합니다)|준수(한다|함|합니다)|만족(한다|함|합니다)|satisf|complian/i, text);
  }
});

test('every EvidScope route, record, finding, event rule, check and file named in the ISMS-P alignment exists', async t => {
  const parent = resolve('.test-runs'); mkdirSync(parent, { recursive: true });
  const directory = mkdtempSync(resolve(parent, 'isms-p-alignment-'));
  const { privateKey: key } = generateKeyPairSync('ed25519'), admin = { id: 'admin', tenant: 'alpha', role: 'admin', token: 'a'.repeat(40) };
  const service = createService({ dataDir: directory, key, config: { principals: [admin] }, requirements });
  t.after(() => { service.store.close(); assert.ok(resolve(directory).startsWith(parent + sep)); rmSync(directory, { recursive: true, force: true }); });
  const call = async (method, path) => {
    const headers = { authorization: 'Bearer ' + admin.token };
    try { return { status: 200, body: await service.handle(method, new URL(path, 'http://local'), headers, method === 'POST' ? '{}' : '') }; }
    catch (error) { return { status: error.status, message: error.message }; }
  };
  for (const method of ['GET', 'POST']) assert.deepEqual(await call(method, '/api/isms-p-alignment-control'), { status: 404, message: UNROUTED });

  const apis = new Map(evidence.filter(e => e.type === 'api').map(e => [`${e.method} ${e.path} ${e.mode || ''} ${e.field || ''}`, e]));
  for (const e of apis.values()) {
    const result = await call(e.method, concrete(e.path));
    if (e.mode === 'oidc') { assert.deepEqual(result, { status: 404, message: UNROUTED }, label(e) + ' is served only with OIDC'); continue; }
    assert.equal(typeof result.status, 'number', label(e) + ': ' + result.message);
    assert.ok(!(result.status === 404 && result.message === UNROUTED), label(e) + ' is not routed');
    if (e.field) { assert.equal(result.status, 200, label(e)); assert.ok(Object.hasOwn(result.body, e.field), label(e)); }
  }
  const integrity = await call('GET', '/api/integrity');
  assert.equal(integrity.status, 200);
  for (const e of evidence.filter(e => e.type === 'integrityCheck')) assert.ok(integrity.body.verificationScope.checks.includes(e.name), label(e));

  const oidc = { enabled: true, issuer: 'https://identity.example.invalid', publicOrigin: 'https://audit.example.invalid', clientId: 'evidscope',
    clientSecret: 'synthetic-client-secret-32-bytes', bindings: [{ id: 'oidc-admin', tenant: 'alpha', role: 'admin', subject: 'alice' }] };
  const identity = createIdentity({ config: { profile: 'enterprise', principals: [], oidc }, store: service.store });
  const oidcAdmin = { id: 'oidc-admin', tenant: 'alpha', role: 'admin' };
  const served = (method, path) => {
    try { return identity.access(oidcAdmin, method, path, {}) !== undefined; } catch (error) { return typeof error.status === 'number'; }
  };
  assert.equal(served('GET', '/api/access/isms-p-alignment-control'), false);
  for (const e of evidence.filter(e => e.mode === 'oidc')) assert.equal(served(e.method, concrete(e.path)), true, label(e));

  const source = readdirSync(new URL('src/', root)).filter(name => name.endsWith('.mjs')).map(name => read('src/' + name)).join('\n');
  const appended = new Set([...source.matchAll(/\bappend\(\s*[\w.]+\s*,\s*'([a-z_]+)'/g)].map(match => match[1]));
  if (/\bappend\(\s*[\w.]+\s*,\s*ACCESS_BATCH_TYPE\b/.test(source)) appended.add(ACCESS_BATCH_TYPE);
  for (const e of evidence.filter(e => e.type === 'record')) assert.ok(isSignedObjectType(e.name) || appended.has(e.name), label(e));

  // A finding code must be emitted by an add(...) call of the signed evaluation: model.mjs, or the AI scenarios it includes.
  const model = read('src/model.mjs'), emitting = [model, read('src/ai-visibility.mjs')].flatMap(text => text.split('\n')).filter(line => /\badd\(/.test(line));
  assert.match(model, /aiScenarioFindings\(events,assets\)/);
  for (const e of evidence.filter(e => e.type === 'finding')) assert.ok(emitting.some(line => line.includes(`'${e.code}'`)), label(e));

  const literal = model.match(/const kindBySource=(\{[^;]+\});/)[1];
  const sourceKinds = Object.keys(JSON.parse(literal.replaceAll("'", '"').replace(/([{,])(\w+):/g, '$1"$2":')));
  assert.deepEqual(sourceKinds, ['agent', 'tool', 'authority', 'safety', 'telemetry', 'otlp', 'enforcement']);
  const kindError = (kind, kindOfSource) => { try { validateEvent({ kind }, { kind: kindOfSource }); return ''; } catch (error) { return error.message; } };
  for (const e of evidence.filter(e => e.type === 'eventKind')) {
    const allowed = [e.source, ...(e.alsoAllowed || [])];
    assert.deepEqual([...allowed, ...e.deniedSources].sort(), [...sourceKinds].sort(), label(e) + ' classifies every source kind');
    for (const kind of allowed) assert.notEqual(kindError(e.name, kind), KIND_DENIED, label(e) + ' from ' + kind);
    for (const denied of e.deniedSources) assert.equal(kindError(e.name, denied), KIND_DENIED, label(e) + ' from ' + denied);
  }

  for (const e of evidence.filter(e => e.type === 'checkType')) {
    const definition = krGovernanceCheckDefinitions.find(d => d.checkType === e.name);
    assert.ok(definition, label(e));
    if (e.authorityOnly !== undefined) assert.equal(definition.authorityOnly === true, e.authorityOnly, label(e));
  }

  for (const e of evidence.filter(e => e.type === 'file')) {
    assert.match(e.path, /^(?:docs|scripts|src|test)\/[\w-]+(?:\.[\w-]+)*\.(?:md|mjs)$/, label(e));
    assert.ok(existsSync(new URL(e.path, root)), label(e));
  }
});

test('the Korean alignment page states the same status, sources and items as the data', () => {
  const page = read('docs/isms-p-alignment.md');
  const { sources } = alignment, fixed = [alignment.mappingStatus, alignment.checkedAt, sources.verifiedLevel, sources.legal.annex, sources.legal.admRulSeq];
  for (const text of [...fixed, ...Object.values(SOURCE_SHA256)]) assert.ok(page.includes(text), text);
  for (const a of alignment.alignments) assert.ok(page.includes(`| ${a.item} ${byNumber.get(a.item).title} |`), a.item);
  for (const n of alignment.notAligned) assert.ok(page.includes(`${n.item} ${byNumber.get(n.item).title}`), n.item);
  for (const number of page.match(ITEM_NUMBER) || []) assert.ok(byNumber.has(number), number);
  assert.doesNotMatch(page, /있는가/);
});
