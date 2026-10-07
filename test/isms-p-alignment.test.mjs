import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { resolve, sep } from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import { createService } from '../src/service.mjs';
import { createIdentity } from '../src/identity.mjs';
import { validateEvent } from '../src/model.mjs';
import { isSignedObjectType } from '../src/object-integrity.mjs';
import { ACCESS_BATCH_TYPE } from '../src/access-log.mjs';
import { krGovernanceCheckDefinitions } from '../src/kr-governance-evidence.mjs';

// The ISMS-P table names concrete EvidScope features. These tests fail when a named route, record, finding, event rule,
// check or file disappears, so the reference table cannot drift silently from the code.
const root = new URL('../', import.meta.url), read = path => readFileSync(new URL(path, root), 'utf8');
const alignment = JSON.parse(read('data/isms-p-alignment.json')), requirements = JSON.parse(read('data/requirements.json'));
const evidence = alignment.alignments.flatMap(a => a.evidence.map(e => ({ ...e, domain: a.domain })));
const domains = alignment.officialStructure.flatMap(area => area.domains.map(d => ({ ...d, area: area.area })));
const types = new Set(['api', 'record', 'finding', 'eventKind', 'checkType', 'integrityCheck', 'file']);
const UNROUTED = '지원하지 않는 경로 또는 메서드', KIND_DENIED = '출처 자격에 허용되지 않은 이벤트 유형';
const concrete = path => path.replaceAll('{id}', 'isms-p-alignment-check');
const label = e => `${e.domain} ${e.type} ${e.method || ''} ${e.path || e.name || e.code}`;

test('ISMS-P alignment stays a human-review draft at domain level and accounts for every official domain once', () => {
  assert.equal(alignment.mappingStatus, 'draft_requires_human_review');
  assert.equal(alignment.nature, 'reference_alignment_not_certification');
  assert.equal(alignment.certificationClaim, false);
  assert.equal(alignment.granularity, 'domain');
  assert.equal(alignment.source.itemLevelStatus, 'not_verified');
  for (const day of [alignment.checkedAt, alignment.source.readAt]) assert.match(day, /^\d{4}-\d\d-\d\d$/);
  assert.ok(alignment.source.urls.length);
  for (const url of alignment.source.urls.map(value => new URL(value))) assert.deepEqual([url.protocol, url.hostname], ['https:', 'isms-p.or.kr']);
  assert.ok(alignment.source.sourceSha256 === 'not_captured' || /^[a-f0-9]{64}$/.test(alignment.source.sourceSha256));
  assert.deepEqual(alignment.officialStructure.map(a => [a.area, a.criteria, a.domains.length]), [['1', 16, 4], ['2', 64, 12], ['3', 21, 5]]);
  assert.equal(alignment.officialStructure.reduce((total, area) => total + area.criteria, 0), 101);
  for (const d of domains) {
    assert.match(d.id, /^[1-3]\.\d{1,2}$/);
    assert.ok(d.id.startsWith(d.area + '.') && d.title.length <= 30, d.id);
  }
  const ids = domains.map(d => d.id), listed = [...alignment.alignments, ...alignment.notAligned].map(a => a.domain);
  assert.equal(new Set(ids).size, ids.length);
  assert.deepEqual([...listed].sort(), [...ids].sort(), 'every official domain is either aligned or explained, exactly once');
  // Item numbers (three levels) stay out until the item level is read from the official guide.
  assert.doesNotMatch(JSON.stringify([alignment.alignments, alignment.notAligned]), /\b[1-3]\.\d{1,2}\.\d{1,2}\b/);
  for (const a of alignment.alignments) {
    assert.ok(a.aspects.length && a.evidence.length && a.manual.length, a.domain);
    for (const e of a.evidence) {
      assert.ok(types.has(e.type), label({ ...e, domain: a.domain }));
      assert.ok(typeof e.what === 'string' && e.what.length > 0 && e.what.length <= 120, label({ ...e, domain: a.domain }));
    }
  }
  for (const n of alignment.notAligned) assert.ok(typeof n.reason === 'string' && n.reason.length > 0, n.domain);
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

  for (const e of evidence.filter(e => e.type === 'api')) {
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

  const model = read('src/model.mjs');
  for (const e of evidence.filter(e => e.type === 'finding')) assert.ok(model.includes(`add('${e.code}'`), label(e));

  const kindError = (kind, kindOfSource) => { try { validateEvent({ kind }, { kind: kindOfSource }); return ''; } catch (error) { return error.message; } };
  for (const e of evidence.filter(e => e.type === 'eventKind')) {
    assert.notEqual(kindError(e.name, e.source), KIND_DENIED, label(e));
    assert.ok(e.deniedSources.length, label(e));
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

test('the Korean alignment page states the same status, source edition, date and domains as the data', () => {
  const page = read('docs/isms-p-alignment.md');
  for (const text of [alignment.mappingStatus, alignment.checkedAt, 'ISMS-P 인증기준 안내서(2023.11)']) assert.ok(page.includes(text), text);
  for (const a of [...alignment.alignments, ...alignment.notAligned]) assert.ok(page.includes(`| ${a.domain} `), a.domain);
});
