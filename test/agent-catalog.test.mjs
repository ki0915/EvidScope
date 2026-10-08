// Catalog importer (src/agent-catalog.mjs, docs/agent-registry.md): the documented A2A sample card and Backstage descriptor
// examples map to discovered drafts with provenance; signatures are checked only against supplied keys; hostile documents
// (size, nesting, prototype keys, YAML features outside the subset) are refused; nothing trusted is ever taken from a card.
import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {signCard} from './support/agent-card.mjs';
import {CATALOG_LIMITS, checkCardSignatures, mapCatalogDocument, normalizeKeys, normalizeLocator, parseYamlSubset} from '../src/agent-catalog.mjs';

const fixture = name => readFileSync(new URL(`./fixtures/catalog/${name}`, import.meta.url), 'utf8');
const sampleCard = fixture('a2a-agent-card-1.0-sample.json'), catalogInfo = fixture('backstage-catalog-info.yaml');
const map = (format, content, options, locator) => mapCatalogDocument({format, content, locator}, options);
const refusal = (fn, code) => assert.throws(fn, error => error.code === code, code);

test('the A2A 1.0 sample card maps name, description and version only; the rest is dropped with reasons', () => {
  const result = map('a2a', sampleCard, {}, 'https://user:secret@georoute-agent.example.com/.well-known/agent-card.json?token=x#y');
  assert.equal(result.format, 'a2a-agent-card');assert.match(result.documentDigest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(result.locator, 'https://georoute-agent.example.com/.well-known/agent-card.json', 'credentials, query and fragment are not kept');
  const [card] = result.results;
  assert.equal(card.outcome, 'mapped');
  assert.equal(card.key, 'a2a:https://georoute-agent.example.com/a2a/v1', 'the preferred interface is the identity');
  assert.match(card.suggestedId, /^a2a\.geospatial-route-planner-agent\.[0-9a-f]{10}$/);
  assert.deepEqual(card.draft, {name: 'GeoSpatial Route Planner Agent', owner: '', purpose: JSON.parse(sampleCard).description, fingerprintVersion: '1.2.0'});
  assert.deepEqual(card.mapped.map(m => `${m.from}->${m.field}`), ['name->name', 'description->purpose', 'version->fingerprint.version']);
  const reasons = Object.fromEntries(card.dropped.map(d => [d.field, d.reason]));
  assert.deepEqual(reasons, {supportedInterfaces: 'endpoint_kept_in_provenance_only', provider: 'vendor_is_not_the_accountable_owner',
    iconUrl: 'no_registry_meaning', documentationUrl: 'no_registry_meaning', capabilities: 'protocol_detail',
    securitySchemes: 'self_reported_security_not_trusted', securityRequirements: 'self_reported_security_not_trusted', defaultInputModes: 'protocol_detail',
    defaultOutputModes: 'protocol_detail', skills: 'offered_skills_are_not_tools_used', signatures: 'checked_into_provenance'});
  assert.equal(card.provenance.formatVersion, '1.0');assert.equal(card.provenance.locatorMatchesEndpoint, true);
  assert.equal(card.provenance.signature.status, 'unverified', 'the sample is signed but no key was supplied');
  assert.deepEqual(card.provenance.signature.signatures, [{alg: 'ES256', kid: 'key-1', jku: 'https://example.com/agent/jwks.json', status: 'no_supplied_key'}]);
  // A v0.3 card names its endpoint in `url`; a card on another host than the locator says so.
  const legacy = map('a2a', JSON.stringify({name: 'Old', url: 'https://old.example.com/a2a/', protocolVersion: '0.3.0', skills: []}), {},
    'https://catalog.example.org/old.json').results[0];
  assert.deepEqual([legacy.key, legacy.provenance.formatVersion, legacy.provenance.locatorMatchesEndpoint],
    ['a2a:https://old.example.com/a2a', '0.3.0', false]);
});

test('the Backstage descriptor example is skipped unless its type marks an agent; an agent component maps owner and text', () => {
  const result = map('backstage', catalogInfo);
  assert.deepEqual(result.results.map(r => [r.outcome, r.entityRef]), [['skipped', 'component:default/artist-web'],
    ['mapped', 'component:support/support-triage-agent'], ['skipped', 'api:default/ticket-mcp']]);
  assert.deepEqual(result.results[2].detail, {kind: 'API', type: 'mcp-server'}, 'MCP servers are tools, not agents');
  const agent = result.results[1];
  assert.equal(agent.key, 'backstage:component:support/support-triage-agent');
  assert.deepEqual(agent.draft, {name: 'Support triage agent', owner: 'group:support/triage-team',
    purpose: 'Classifies incoming tickets and drafts replies.\nA person sends every reply.\n', fingerprintVersion: null});
  assert.deepEqual(Object.fromEntries(agent.dropped.map(d => [d.field, d.reason])), {'metadata.tags': 'no_registry_meaning',
    'metadata.annotations': 'no_registry_meaning', 'spec.lifecycle': 'lifecycle_never_sets_registry_state', 'spec.system': 'not_a_governance_system_id',
    'spec.consumesApis': 'relation_not_mapped'});
  // The documented example itself, with its type accepted as an agent type by the operator.
  const web = map('backstage', catalogInfo, {agentTypes: ['website']}).results[0];
  assert.deepEqual([web.outcome, web.draft.name, web.draft.owner, web.draft.purpose], ['mapped', 'artist-web', 'artist-relations-team',
    'The place to be, for great artists']);
  // JSON entities and a catalog API response are accepted too; each entity digest ignores formatting and sibling entities.
  const entity = parseYamlSubset(catalogInfo)[1];
  const asJson = map('backstage', JSON.stringify({items: [entity]})).results[0];
  assert.equal(asJson.entityDigest, agent.entityDigest);
  assert.equal(map('backstage', `${catalogInfo}\n# trailing comment\n`).results[1].entityDigest, agent.entityDigest);
});

test('agent card signatures verify only against supplied keys; a changed card or a wrong key is invalid', () => {
  const card = JSON.parse(sampleCard);delete card.signatures;
  const ec = generateKeyPairSync('ec', {namedCurve: 'P-256'}), other = generateKeyPairSync('ec', {namedCurve: 'P-256'});
  const ed = generateKeyPairSync('ed25519');
  const jwk = (pair, kid) => ({...pair.publicKey.export({format: 'jwk'}), kid});
  const signed = signCard(card, ec.privateKey, {alg: 'ES256', typ: 'JOSE', kid: 'k1', jku: 'https://georoute-agent.example.com/jwks.json'});
  const keys = normalizeKeys({keys: [jwk(ec, 'k1')]});
  const verified = checkCardSignatures(signed, keys);
  assert.equal(verified.status, 'verified');assert.equal(verified.signatures[0].keyThumbprint, keys[0].thumbprint);
  assert.equal(checkCardSignatures(signed, []).status, 'unverified');
  assert.equal(checkCardSignatures({...signed, version: '9.9.9'}, keys).status, 'invalid', 'any change breaks the signature');
  assert.equal(checkCardSignatures(signed, normalizeKeys({keys: [jwk(other, 'k1')]})).status, 'invalid');
  assert.equal(checkCardSignatures(signed, normalizeKeys({keys: [jwk(other, 'k2')]})).status, 'unverified', 'kid must match');
  const edSigned = signCard(card, ed.privateKey, {alg: 'EdDSA', kid: 'ed'});
  assert.equal(checkCardSignatures(edSigned, normalizeKeys({keys: [jwk(ed, 'ed')]})).status, 'verified');
  // Key confusion and unsigned algorithms are refused: an Ed25519 key never checks an ES256 signature; none/HS256 are unsupported.
  assert.equal(checkCardSignatures(signed, normalizeKeys({keys: [jwk(ed, 'k1')]})).status, 'unverified');
  for (const alg of ['none', 'HS256']) {
    const forged = {...card, signatures: [{protected: Buffer.from(JSON.stringify({alg, kid: 'k1'})).toString('base64url'), signature: ''}]};
    assert.equal(checkCardSignatures(forged, keys).status, 'unsupported', alg);
  }
  assert.equal(checkCardSignatures({...card, signatures: [{protected: '!!', signature: 'x'}]}, keys).status, 'malformed');
  assert.equal(checkCardSignatures({...card, signatures: []}, keys).status, 'malformed');
  // A private JWK is reduced to its public half; secret members never travel further.
  const privateJwk = ec.privateKey.export({format: 'jwk'}), [reduced] = normalizeKeys({keys: [privateJwk]});
  assert.equal(reduced.key.type, 'public');
  refusal(() => normalizeKeys({keys: [{kty: 'oct', k: 'c2VjcmV0'}]}), 'invalid_keys');
  refusal(() => normalizeKeys([jwk(ec)]), 'invalid_keys');
  const mapped = map('a2a', JSON.stringify(signed), {keys}).results[0];
  assert.equal(mapped.provenance.signature.status, 'verified');
});

test('hostile documents are refused: size, nesting, prototype keys and YAML features outside the subset', () => {
  refusal(() => map('a2a', ' '.repeat(CATALOG_LIMITS.documentBytes + 1)), 'too_large');
  refusal(() => map('a2a', '['.repeat(100000) + ']'.repeat(100000)), 'too_deep');
  const nested = Array.from({length: CATALOG_LIMITS.depth}).reduce(inner => ({inner}), 1);
  refusal(() => map('a2a', JSON.stringify({name: 'x', nested})), 'too_deep');
  refusal(() => map('a2a', '{"name":"x","url":"https://a.example","__proto__":{"admin":true}}'), 'forbidden_key');
  refusal(() => map('a2a', '{"name":"x","provider":{"constructor":{"prototype":{}}}}'), 'forbidden_key');
  refusal(() => map('a2a', '{"name":'), 'invalid_json');
  refusal(() => map('a2a', JSON.stringify({items: Array.from({length: CATALOG_LIMITS.nodes}, () => 1)})), 'too_many_nodes');
  refusal(() => map('backstage', 'a: 1\n'.repeat(CATALOG_LIMITS.lines + 1)), 'too_many_lines');
  refusal(() => map('backstage', Array.from({length: CATALOG_LIMITS.entities + 1}, (_, i) => `kind: Component\nmetadata:\n  name: a${i}`).join('\n---\n')),
    'too_many_entities');
  const yaml = {
    yaml_unsupported: ['a: &anchor 1\nb: *anchor', 'a: !!python/object x', '<<: {a: 1}', 'a: {b: 1}', 'a: b\n  continued', '%YAML 1.2\n---\na: 1',
      '? complex\n: key', 'a:\n\t- tab', 'a: |+\n  keep', '- - nested', 'a: "open', "a: 'open", 'a: [x, [y]]', 'a: [x,\n  y]', 'a: *alias'],
    duplicate_key: ['a: 1\na: 2'], forbidden_key: ['__proto__:\n  admin: true', 'metadata:\n  constructor: x', '- prototype: 1'],
  };
  for (const [code, documents] of Object.entries(yaml)) for (const document of documents) refusal(() => parseYamlSubset(document), code);
  // Long lines stay linear: no backtracking pattern sees a whole line.
  const started = Date.now();
  for (const line of [`a${' '.repeat(200000)}b`, `a: ${'x '.repeat(100000)}`, `"${'\\"'.repeat(60000)}`, `a: ${' # '.repeat(60000)}`])
    try {parseYamlSubset(line);} catch (error) {assert.ok(error.code, error.message);}
  assert.ok(Date.now() - started < 2000, 'adversarial lines parse in linear time');
  // A prototype key in a parsed document never reaches Object.prototype.
  assert.equal({}.admin, undefined);
  // Control and bidirectional characters are dropped field by field, never stored.
  const card = map('a2a', JSON.stringify({name: 'ok', url: 'https://a.example/a2a', description: 'evil\u202etxt.exe', version: 'x'.repeat(101)})).results[0];
  assert.deepEqual(card.dropped.filter(d => ['description', 'version'].includes(d.field)), [{field: 'description', reason: 'invalid_characters'},
    {field: 'version', reason: 'too_long'}]);
  assert.equal(map('a2a', JSON.stringify({url: 'https://a.example'})).results[0].reason, 'missing_name');
  assert.equal(map('a2a', JSON.stringify({name: 'x', url: 'javascript:alert(1)'})).results[0].reason, 'missing_endpoint');
  assert.equal(map('backstage', 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: x').results[0].reason, 'not_a_backstage_entity');
  assert.equal(map('backstage', 'apiVersion: backstage.io/v1alpha1\nkind: Component\nmetadata:\n  name: "bad name"').results[0].reason, 'invalid_entity_name');
  refusal(() => normalizeLocator('x'.repeat(1001)), 'invalid_locator');
  refusal(() => map('yaml', '{}'), 'unknown_format');
});

test('nothing trusted is taken from a card: sources, actors, tools, risk tier and lifecycle state are dropped', () => {
  const card = {name: 'Escalator', url: 'https://agent.example.com/a2a', sources: ['alpha-agent'], actors: ['payments-bot'],
    tools: [{name: 'payment_transfer'}], risk: {tier: 'low'}, riskTier: 'low', state: 'production', owner: 'ceo'};
  const result = map('a2a', JSON.stringify(card)).results[0];
  assert.deepEqual(Object.keys(result.draft).sort(), ['fingerprintVersion', 'name', 'owner', 'purpose']);
  assert.equal(result.draft.owner, '', 'an A2A card has no accountable owner field; a self-declared one is dropped');
  for (const field of ['sources', 'actors', 'tools', 'risk', 'riskTier', 'state', 'owner'])
    assert.deepEqual(result.dropped.find(d => d.field === field), {field, reason: 'unknown_field'}, field);
  const entity = map('backstage', 'apiVersion: backstage.io/v1alpha1\nkind: Component\nmetadata:\n  name: bot\nspec:\n  type: ai-agent\n'
    + '  lifecycle: production\n  owner: team\n  sources: [alpha-agent]\n  riskTier: low').results[0];
  assert.deepEqual(entity.dropped.map(d => d.field), ['spec.lifecycle', 'spec.sources', 'spec.riskTier']);
});
