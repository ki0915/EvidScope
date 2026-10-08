// Catalog import end to end (POST /api/registry/import, scripts/import-agent-catalog.mjs, docs/agent-registry.md): roles,
// discovered entries with stored provenance, idempotency and versioning by catalog key, conflicts with live or edited
// entries, no trust escalation, tenant isolation, export with offline verification, and the 503c185 export regression.
import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {createPrivateKey, generateKeyPairSync, randomBytes} from 'node:crypto';
import {mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {harness} from './harness.mjs';
import {digest, makeCheckpoint, verifyBundle} from '../src/crypto.mjs';
import {EVALUATION_ENGINE, EVALUATION_ENGINE_V2} from '../src/model.mjs';
import {signCard} from './support/agent-card.mjs';

const fixture = name => readFileSync(new URL(`./fixtures/catalog/${name}`, import.meta.url), 'utf8');
const sampleCard = fixture('a2a-agent-card-1.0-sample.json'), catalogInfo = fixture('backstage-catalog-info.yaml');
const second = {id: 'alpha-reviewer-2', tenant: 'alpha', role: 'reviewer', token: randomBytes(32).toString('base64url')};
let h;
test.before(async () => {
  h = await harness({beforeStart: ({dir}) => {
    const file = join(dir, 'config.json'), config = JSON.parse(readFileSync(file, 'utf8'));
    config.principals.push(second);writeFileSync(file, JSON.stringify(config));
  }});
  h.config.principals.push(second);
});
test.after(async () => { await h?.close(); });

const call = (path, body, role = 'reviewer', tenant = 'alpha') => h.api(path, {body, role, tenant});
const asSecond = (path, body) => h.api(path, {body, role: 'reviewer', headers: {authorization: `Bearer ${second.token}`}});
const card = changes => JSON.stringify({...JSON.parse(sampleCard), ...changes});
const a2a = (content, locator = 'https://georoute-agent.example.com/.well-known/agent-card.json') => ({format: 'a2a', content, locator});
const backstage = {format: 'backstage', content: catalogInfo, locator: 'https://git.example.com/support/catalog-info.yaml'};
const importDocs = (documents, extra = {}, role = 'reviewer', tenant = 'alpha') => call('/api/registry/import', {documents, ...extra}, role, tenant);
const entry = async id => (await call(`/api/registry/${encodeURIComponent(id)}`, undefined, 'auditor')).body;
let geoId, triageId, signed;

test('only reviewers and admins import; the request shape is closed and bounded', async () => {
  assert.equal((await importDocs([a2a(sampleCard)], {}, 'auditor')).status, 403);
  assert.equal((await importDocs([a2a(sampleCard)], {}, 'agent')).status, 403, 'a source credential is not a human role');
  const anonymous = await fetch(`${h.audit.url}/api/registry/import`, {method: 'POST', headers: {'content-type': 'application/json'},
    body: JSON.stringify({documents: [a2a(sampleCard + ' '.repeat(20000))]})});
  assert.equal(anonymous.status, 401, 'large bodies are authorized before they are buffered');
  assert.equal((await call('/api/registry/import', {documents: [a2a(sampleCard)], fetch: 'https://x'})).status, 400, 'unknown field');
  assert.equal((await call('/api/registry/import', {documents: []})).status, 400);
  assert.equal((await call('/api/registry/import', {documents: Array.from({length: 21}, () => a2a(sampleCard))})).status, 400);
  assert.equal((await call('/api/registry/import', {documents: [{...a2a(sampleCard), url: 'https://x'}]})).status, 400, 'no fetch-from field');
  assert.equal((await call('/api/registry/import', {documents: [a2a(sampleCard)], keys: {keys: [{kty: 'oct', k: 'AA'}]}})).status, 400);
  assert.equal((await call('/api/registry/import', {id: 'x'})).status, 400);
  assert.equal((await call('/api/registry', {id: 'import'})).status, 400, 'import is a reserved registry id');
  const dryRun = await importDocs([a2a(sampleCard), backstage], {dryRun: true});
  assert.equal(dryRun.status, 200, JSON.stringify(dryRun.body));
  assert.deepEqual([dryRun.body.dryRun, dryRun.body.summary.created, dryRun.body.summary.skipped], [true, 2, 2]);
  assert.equal((await call('/api/registry', undefined, 'auditor')).body.items.length, 0, 'a dry run writes nothing');
});

test('documents become discovered entries with provenance and no trusted fields; the lifecycle check passes', async () => {
  const ec = generateKeyPairSync('ec', {namedCurve: 'P-256'}), unsigned = JSON.parse(sampleCard);delete unsigned.signatures;
  signed = JSON.stringify(signCard(unsigned, ec.privateKey, {alg: 'ES256', typ: 'JOSE', kid: 'geo-1'}));
  const keys = {keys: [{...ec.publicKey.export({format: 'jwk'}), kid: 'geo-1'}]};
  const result = await importDocs([a2a(signed), backstage, {format: 'a2a', content: '{"name":', locator: 'file:broken.json'}], {keys});
  assert.equal(result.status, 200, JSON.stringify(result.body));
  const {summary, results, documents} = result.body;
  assert.deepEqual(summary, {created: 2, updated: 0, unchanged: 0, conflict: 0, skipped: 2, rejected: 0, rejectedDocuments: 1});
  assert.deepEqual(documents[2].rejected.code, 'invalid_json');
  const geo = results.find(r => r.key?.startsWith('a2a:')), triage = results.find(r => r.entityRef === 'component:support/support-triage-agent');
  geoId = geo.entry.id;triageId = triage.entry.id;
  assert.equal(geo.signature.status, 'verified');
  const detail = await entry(geoId);
  assert.deepEqual([detail.entry.state, detail.entry.version, detail.entry.change, detail.entry.registeredBy], ['discovered', 1, 'created', 'alpha-reviewer']);
  for (const field of ['sources', 'actors', 'tools', 'models', 'assetIds', 'dataCategories', 'destinations']) assert.deepEqual(detail.entry[field], [], field);
  assert.deepEqual([detail.entry.systemId, detail.entry.risk.override, detail.risk.tier], [null, null, 'low']);
  assert.deepEqual(detail.entry.fingerprint, {version: '1.2.0'});
  const provenance = detail.entry.catalog;
  assert.deepEqual([provenance.format, provenance.key, provenance.locator, provenance.signature.status, provenance.importedBy, provenance.assurance],
    ['a2a-agent-card', 'a2a:https://georoute-agent.example.com/a2a/v1', 'https://georoute-agent.example.com/.well-known/agent-card.json', 'verified',
      'alpha-reviewer', 'self_reported_catalog']);
  assert.equal(provenance.documentDigest, documents[0].documentDigest);assert.match(provenance.entityDigest, /^sha256:/);
  assert.ok(provenance.dropped.includes('skills') && provenance.mapped.includes('purpose'));
  assert.equal(detail.lifecycle.valid, true, JSON.stringify(detail.lifecycle.problems));
  assert.equal((await entry(triageId)).entry.owner, 'group:support/triage-team');
  // A catalog cannot hand out authenticated sources, actor names, a risk tier or a state, even when the reviewer imports it.
  const escalation = await importDocs([a2a(JSON.stringify({name: 'Escalator', url: 'https://escalator.example.com/a2a', sources: ['alpha-agent'],
    actors: ['payments-bot'], tools: ['payment_transfer'], riskTier: 'low', state: 'production'}))]);
  const escalated = await entry(escalation.body.results[0].entry.id);
  assert.deepEqual([escalated.entry.state, escalated.entry.sources, escalated.entry.actors, escalated.entry.tools], ['discovered', [], [], []]);
  assert.deepEqual(escalation.body.results[0].dropped.map(d => d.field).sort(), ['actors', 'riskTier', 'sources', 'state', 'tools', 'url']);
  // Candidates still list the actor: an imported entry covers nothing until a person adds sources or actors.
  assert.equal((await call('/api/registry', {id: 'escalator-2', actors: ['payments-bot']})).status, 200, 'no attribution was claimed by the card');
});

test('re-import is idempotent; a changed document is a new version of the same discovered entry', async () => {
  const again = await importDocs([a2a(signed), backstage]);
  assert.deepEqual(again.body.results.filter(r => r.entry).map(r => [r.entry.id, r.outcome]), [[geoId, 'unchanged'], [triageId, 'unchanged']]);
  assert.equal(again.body.results[0].signature.status, 'unverified', 'the report shows this request\'s signature check; the entry keeps its own');
  assert.equal((await entry(geoId)).versions.length, 1);
  const reformatted = await importDocs([a2a(JSON.stringify(JSON.parse(signed), null, 4))]);
  assert.equal(reformatted.body.results[0].outcome, 'unchanged', 'formatting and key order are not a change');
  const changed = await importDocs([a2a(card({version: '1.3.0', description: 'Route planning, now with rail.'}))]);
  assert.deepEqual([changed.body.results[0].outcome, changed.body.results[0].entry], ['updated', {id: geoId, version: 2, state: 'discovered'}]);
  const detail = await entry(geoId);
  assert.deepEqual([detail.entry.purpose, detail.entry.fingerprint.version, detail.entry.change], ['Route planning, now with rail.', '1.3.0', 'updated']);
  assert.equal(detail.entry.catalog.signature.status, 'unverified');assert.equal(detail.lifecycle.valid, true);
  assert.deepEqual(detail.versions.map(v => v.catalog.importId === changed.body.importId), [false, true]);
  const twice = await importDocs([a2a(card({version: '2.0.0'})), a2a(card({version: '2.0.1'}))]);
  assert.deepEqual(twice.body.results.map(r => [r.outcome, r.reason]), [['updated', undefined], ['conflict', 'duplicate_key_in_request']]);
});

test('entries a person edited or took past discovered are reported as conflicts and never overwritten', async () => {
  assert.equal((await asSecond(`/api/registry/${encodeURIComponent(geoId)}/risk`, {tier: 'high', reason: 'routes customer data'})).status, 200);
  const afterOverride = await importDocs([a2a(card({version: '3.0.0'}))]);
  assert.equal(afterOverride.body.results[0].outcome, 'updated', 'a risk override is not a content edit');
  assert.equal((await entry(geoId)).risk.tier, 'high', 'the override survives an import that does not change the configuration');
  assert.equal((await call(`/api/registry/${encodeURIComponent(geoId)}`, {owner: 'routing-team', actors: ['geo-agent']})).status, 200);
  const edited = await importDocs([a2a(card({version: '3.1.0'}))]);
  assert.deepEqual([edited.body.results[0].outcome, edited.body.results[0].reason], ['conflict', 'edited_since_import']);
  assert.deepEqual([(await entry(geoId)).entry.owner, (await entry(geoId)).entry.fingerprint.version], ['routing-team', '3.0.0']);
  const promoted = await call(`/api/registry/${encodeURIComponent(triageId)}/transitions`, {to: 'draft', reason: 'triaged'});
  assert.equal(promoted.body.entry.state, 'draft');
  const changedCatalog = catalogInfo.replace('A person sends every reply.', 'Replies are sent automatically.');
  const live = await importDocs([{...backstage, content: changedCatalog}]);
  const triage = live.body.results.find(r => r.entityRef === 'component:support/support-triage-agent');
  assert.deepEqual([triage.outcome, triage.reason, triage.entry.state], ['conflict', 'entry_past_discovered', 'draft']);
  assert.match((await entry(triageId)).entry.purpose, /A person sends every reply/);
  assert.equal((await importDocs([backstage])).body.results.find(r => r.entry?.id === triageId).outcome, 'unchanged');
  // A hand-made entry holding the id the importer would choose is never taken over.
  const endpoint = url => [{url, protocolBinding: 'JSONRPC', protocolVersion: '1.0'}];
  const other = card({name: 'Other planner', supportedInterfaces: endpoint('https://other.example.com/a2a')});
  const planned = (await importDocs([a2a(other)], {dryRun: true})).body.results[0];
  assert.equal((await call('/api/registry', {id: planned.entry.id, name: 'hand made'})).status, 200);
  const taken = (await importDocs([a2a(other)])).body.results[0];
  assert.deepEqual([taken.outcome, taken.reason], ['conflict', 'id_in_use']);
  assert.equal((await entry(planned.entry.id)).entry.catalog, undefined);
  for (const id of [geoId, triageId]) assert.equal((await entry(id)).lifecycle.valid, true);
});

test('imports are per tenant: another tenant neither sees nor matches them', async () => {
  const beta = await importDocs([a2a(sampleCard)], {}, 'reviewer', 'beta');
  assert.deepEqual([beta.body.results[0].outcome, beta.body.results[0].entry.version], ['created', 1], 'alpha entries are not matched');
  assert.equal(beta.body.results[0].entry.id, geoId, 'the same card gets the same id in each tenant');
  assert.equal((await call(`/api/registry/${encodeURIComponent(triageId)}`, undefined, 'auditor', 'beta')).status, 404);
  const betaList = (await call('/api/registry', undefined, 'auditor', 'beta')).body.items;
  assert.deepEqual(betaList.map(i => [i.id, i.version, i.catalog.importedBy]), [[geoId, 1, 'beta-reviewer']]);
  assert.equal((await entry(geoId)).entry.version > 1, true, 'alpha keeps its own history');
});

const run = (script, args, env = {}) => {
  const r = spawnSync(process.execPath, [fileURLToPath(new URL(`../scripts/${script}`, import.meta.url)), ...args],
    {encoding: 'utf8', env: {...process.env, ...env}});
  return {status: r.status, out: r.stdout.trim().startsWith('{') ? JSON.parse(r.stdout) : r.stdout, err: r.stderr};
};

test('the CLI previews locally by default and posts to the audit gateway with --send', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'evidscope-catalog-cli-'));t.after(() => rmSync(dir, {recursive: true, force: true}));
  const cardFile = join(dir, 'agent-card.json'), yamlFile = join(dir, 'catalog-info.yaml'), badFile = join(dir, 'bad.yaml');
  const supportedInterfaces = [{url: 'https://cli.example.com/a2a', protocolBinding: 'JSONRPC', protocolVersion: '1.0'}];
  writeFileSync(cardFile, card({name: 'CLI planner', supportedInterfaces}));
  writeFileSync(yamlFile, catalogInfo);writeFileSync(badFile, 'a: &x 1\n');
  const preview = run('import-agent-catalog.mjs', ['--a2a', cardFile, '--backstage', yamlFile]);
  assert.equal(preview.status, 0, preview.err);assert.equal(preview.out.mode, 'preview');
  assert.deepEqual(preview.out.documents.map(d => d.locator), ['file:agent-card.json', 'file:catalog-info.yaml'], 'no local paths leave the machine');
  assert.equal((await call('/api/registry', undefined, 'auditor')).body.items.some(i => i.name === 'CLI planner'), false, 'a preview writes nothing');
  assert.equal(run('import-agent-catalog.mjs', ['--backstage', badFile]).status, 1, 'a refused document fails the preview');
  const keyFile = join(dir, 'keys.json'), requestFile = join(dir, 'request.json');
  writeFileSync(keyFile, JSON.stringify({keys: [{...generateKeyPairSync('ec', {namedCurve: 'P-256'}).privateKey.export({format: 'jwk'}), kid: 'k'}]}));
  assert.equal(run('import-agent-catalog.mjs', ['--a2a', cardFile, '--jwks', keyFile, '--write-request', requestFile]).status, 0);
  assert.deepEqual(Object.keys(JSON.parse(readFileSync(requestFile, 'utf8')).keys.keys[0]).sort(), ['crv', 'kid', 'kty', 'x', 'y'],
    'a private key file never leaves the machine whole');
  const token = h.principal('reviewer').token;
  const sent = run('import-agent-catalog.mjs', ['--a2a', cardFile, '--send', '--base', `${h.audit.url}/`], {EVIDSCOPE_TOKEN: token});
  assert.equal(sent.status, 0, sent.err);assert.deepEqual([sent.out.mode, sent.out.summary.created], ['imported', 1]);
  const resent = run('import-agent-catalog.mjs', ['--a2a', cardFile, '--send', '--base', `${h.audit.url}/`], {EVIDSCOPE_TOKEN: token});
  assert.equal(resent.out.summary.unchanged, 1);
  const denied = run('import-agent-catalog.mjs', ['--a2a', cardFile, '--send', '--base', `${h.audit.url}/`], {EVIDSCOPE_TOKEN: h.principal('auditor').token});
  assert.notEqual(denied.status, 0);assert.match(denied.err, /HTTP 403/);
  assert.notEqual(run('import-agent-catalog.mjs', ['--a2a', cardFile, '--send', '--base', 'http://vault.example.com/'], {EVIDSCOPE_TOKEN: token}).status, 0);
});

function resign(bundle, privateKey) {
  let previous = '0'.repeat(64);
  for (const row of bundle.records) {row.previous = previous;const {hash, ...record} = row;row.hash = digest(record);previous = row.hash;}
  bundle.checkpoint = makeCheckpoint(bundle.checkpoint.tenant, bundle.records.length, previous, privateKey);
  return bundle;
}

test('exports carry imported entries; offline verification passes and catches an import that claims sources or a state', async t => {
  for (let i = 0; i < 20; i++) {const r = (await h.analyze()).body;if (!r.backlog && !r.processed) break;}
  const bundle = (await call('/api/export', undefined, 'auditor')).body;
  const imported = bundle.records.filter(r => r.type === 'agent_registry' && r.payload.catalog);
  assert.ok(imported.length >= 5);
  assert.equal(verifyBundle(bundle, h.publicKey).valid, true);
  const dir = mkdtempSync(join(tmpdir(), 'evidscope-catalog-export-'));t.after(() => rmSync(dir, {recursive: true, force: true}));
  const file = join(dir, 'export.json'), key = join(h.dir, 'trust-anchor.pem');writeFileSync(file, JSON.stringify(bundle));
  for (const [script, extra] of [['evidscope-verify.mjs', ['bundle']], ['verify.mjs', []]]) {
    const r = run(script, [...extra, file, key, '--replay']);
    assert.equal(r.status, 0, r.err);assert.equal(r.out.registry.valid, true, JSON.stringify(r.out.registry.problems));assert.equal(r.out.replay.valid, true);
  }
  const privateKey = createPrivateKey(readFileSync(join(h.dir, 'signing-private.pem')));
  const forgeries = {
    'catalog import changed sources, actors or configuration': row => {row.payload.sources = ['alpha-agent'];},
    'catalog import outside the discovered state': row => {row.payload.state = 'draft';},
    'catalog import set a risk override': row => {row.payload.risk = {...row.payload.risk, override: {tier: 'low', by: row.principal, basisHash: 'x'}};},
    'catalog import principal differs from importedBy': row => {row.payload.catalog.importedBy = 'alpha-admin';},
  };
  for (const [message, forge] of Object.entries(forgeries)) {
    const forged = structuredClone(bundle);
    forge(forged.records.find(r => r.type === 'agent_registry' && r.payload.catalog && r.payload.version === 1));
    writeFileSync(file, JSON.stringify(resign(forged, privateKey)));
    const r = run('evidscope-verify.mjs', ['bundle', file, key]);
    assert.equal(r.status, 1, message);assert.equal(r.out.valid, true, 'chain and checkpoint alone accept it');
    assert.ok(r.out.registry.problems.some(p => p.message === message), `${message}: ${JSON.stringify(r.out.registry.problems)}`);
  }
  // A later version that drops the provenance, or a hand-made entry that later claims some, is caught too.
  const stripped = structuredClone(bundle);
  delete stripped.records.filter(r => r.type === 'agent_registry' && r.payload.id === geoId).at(-1).payload.catalog;
  writeFileSync(file, JSON.stringify(resign(stripped, privateKey)));
  assert.ok(run('evidscope-verify.mjs', ['bundle', file, key]).out.registry.problems.some(p => p.message === 'catalog provenance removed'));
});

test('an export written by 503c185 before catalog import verifies and replays exactly as before', t => {
  const old = JSON.parse(readFileSync(new URL('./fixtures/pre-catalog-export-503c185.json', import.meta.url), 'utf8'));
  const dir = mkdtempSync(join(tmpdir(), 'evidscope-pre-catalog-'));t.after(() => rmSync(dir, {recursive: true, force: true}));
  const file = join(dir, 'export.json'), key = join(dir, 'key.pem');
  writeFileSync(file, JSON.stringify(old.exportBundle));writeFileSync(key, old.publicKeyPem);
  assert.ok(old.exportBundle.records.some(r => r.type === 'agent_registry' && r.payload.state === 'discovered'), 'the fixture has a discovered entry');
  assert.ok(!old.exportBundle.records.some(r => r.payload?.catalog), 'and no catalog provenance');
  for (const [script, extra] of [['evidscope-verify.mjs', ['bundle']], ['verify.mjs', []]]) {
    const r = run(script, [...extra, file, key, '--replay']);
    assert.equal(r.status, 0, r.err);
    assert.deepEqual([r.out.registry.valid, r.out.registry.entries, r.out.registry.transitions, r.out.registry.problems], [true, 2, 5, []]);
    assert.deepEqual([r.out.replay.valid, r.out.replay.summary.replayed, r.out.replay.summary.mismatch], [true, 4, 0]);
    assert.ok(r.out.replay.evaluations.every(e => [EVALUATION_ENGINE, EVALUATION_ENGINE_V2].includes(e.engine) && e.status === 'replayed'));
  }
});
