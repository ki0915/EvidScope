import test from 'node:test';
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {createServer} from 'node:http';
import {readFileSync, writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {promisify} from 'node:util';
import {harness} from './harness.mjs';
import {tempDir} from './temp-dir.mjs';
import {submit} from '../src/client.mjs';
import {demo} from '../scripts/demo.mjs';
import {ocsfFromBundle, signingKeyId, SPLUNK_SOURCETYPE} from '../src/ocsf.mjs';

const run = promisify(execFile);
const schemas = Object.fromEntries(['1.3.0', '1.9.0'].map(version =>
  [version, JSON.parse(readFileSync(new URL(`./fixtures/ocsf/detection-finding-${version}.json`, import.meta.url), 'utf8'))]));
const primitive = {string_t: v => typeof v === 'string', integer_t: Number.isSafeInteger, long_t: Number.isSafeInteger,
  float_t: v => typeof v === 'number' && Number.isFinite(v), boolean_t: v => typeof v === 'boolean', json_t: () => true};

// Minimal OCSF validator over the extracted schema: required attributes, unknown attributes, types, enum values,
// at_least_one constraints and declared profiles. Returns errors plus missing recommended attributes per path.
function validate(event, schema) {
  const errors = [], missingRecommended = [], declared = event.metadata?.profiles || [];
  const base = type => { let t = type; while (schema.types[t] && schema.types[t] !== t) t = schema.types[t]; return t; };
  for (const profile of declared) if (!schema.class.profiles.includes(profile)) errors.push(`profile ${profile} not applicable`);
  const classAttributes = Object.fromEntries(Object.entries(schema.class.attributes).filter(([, a]) => !a.profile || declared.includes(a.profile)));
  function scalar(value, type, enumKeys, path) {
    if (schema.objects[type]) return object(value, schema.objects[type].attributes, schema.objects[type].constraints, path);
    if (type === 'object') { if (!value || typeof value !== 'object' || Array.isArray(value)) errors.push(`${path}: object expected`); return; }
    const check = primitive[base(type)];
    if (!check) errors.push(`${path}: type ${type} is not in the fixture`);
    else if (!check(value)) errors.push(`${path}: ${JSON.stringify(value)} is not ${type}`);
    if (enumKeys && !enumKeys.includes(String(value))) errors.push(`${path}: ${value} not in enum ${enumKeys}`);
  }
  function object(value, attributes, constraints, path) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return errors.push(`${path}: object expected`);
    for (const [name, a] of Object.entries(attributes)) {
      if (value[name] !== undefined) continue;
      if (a.requirement === 'required') errors.push(`${path}.${name}: required`);
      if (a.requirement === 'recommended') missingRecommended.push(`${path}.${name}`);
    }
    for (const [name, item] of Object.entries(value)) {
      const a = attributes[name], d = schema.dictionary[name] || {};
      if (!a) { errors.push(`${path}.${name}: not defined`); continue; }
      const type = a.type || d.type, isArray = a.is_array ?? d.is_array;
      // class/category/type ids are derived per class, not enumerated in the dictionary.
      const enumKeys = ['class_uid', 'category_uid', 'type_uid'].includes(name) && path === 'event' ? null
        : (a.enum || d.enum) ? [...new Set([...(d.enum || []), ...(a.enum || [])])] : null;
      if (isArray) {
        if (!Array.isArray(item)) errors.push(`${path}.${name}: array expected`);
        else item.forEach((x, i) => scalar(x, type, enumKeys, `${path}.${name}[${i}]`));
      } else scalar(item, type, enumKeys, `${path}.${name}`);
    }
    if (constraints?.at_least_one && !constraints.at_least_one.some(name => value[name] !== undefined)) {
      errors.push(`${path}: needs one of ${constraints.at_least_one}`);
    }
  }
  object(event, classAttributes, null, 'event');
  if (event.category_uid !== schema.category.uid) errors.push('category_uid');
  if (event.class_uid !== schema.category.uid * 1000 + schema.class.uid) errors.push('class_uid');
  if (event.type_uid !== event.class_uid * 100 + event.activity_id) errors.push('type_uid');
  if (event.metadata?.version !== schema.ocsf_version) errors.push('metadata.version');
  return {errors, missingRecommended};
}

const hec = async () => {
  const requests = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => {
      requests.push({url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString('utf8')});
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({text: 'Success', code: 0}));
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return {requests, url: `http://127.0.0.1:${server.address().port}/services/collector/event`, close: () => new Promise(r => server.close(r))};
};

test('OCSF Detection Finding export: schema, versions, attestation, tenant isolation, NDJSON and HEC', async t => {
  const h = await harness(); t.after(() => h.close());
  const scenario = await demo({config: h.config, ingress: h.ingress.url, audit: h.audit.url});
  const beta = {id: 'beta-gap', actionId: 'beta-action', traceId: 'beta-trace', kind: 'gap', note: 'synthetic beta gap', occurredAt: new Date().toISOString()};
  assert.equal((await submit(h.ingress.url, h.principal('telemetry', 'beta'), beta)).status, 202);
  for (let i = 0; i < 5; i++) await h.analyze();
  const alerts = (await h.api('/api/alerts')).body.items;
  assert.ok(alerts.length > 5);

  await t.test('required and recommended fields validate against OCSF 1.3.0 and 1.9.0', async () => {
    for (const version of ['1.3.0', '1.9.0']) {
      const response = await h.api(`/api/export/ocsf?version=${version}`);
      assert.equal(response.status, 200);
      assert.equal(response.body.length, alerts.length, 'one Detection Finding per current finding');
      assert.deepEqual(response.body.map(e => e.finding_info.uid).sort(), alerts.map(a => a.id).sort());
      const recommended = new Set();
      for (const event of response.body) {
        const result = validate(event, schemas[version]);
        assert.deepEqual(result.errors, [], `${version} ${event.finding_info.types[0]}`);
        for (const path of result.missingRecommended) recommended.add(path.replace(/\[\d+\]/g, '[]'));
      }
      // Intentionally absent: no confidence model, no observables, no status codes (top level); product.uid and the
      // 1.9 reporter object have no EvidScope source. Evidence objects carry only actor/api/data/ai_agent by design.
      const present = path => !recommended.has(path);
      assert.deepEqual([...recommended].filter(path => path.split('.').length === 2).sort(),
        ['event.confidence_id', 'event.observables', 'event.status_code']);
      assert.deepEqual([...recommended].filter(path => /^event\.(metadata|finding_info)\./.test(path)).sort(),
        version === '1.3.0' ? ['event.metadata.product.uid'] : ['event.metadata.product.uid', 'event.metadata.reporter']);
      assert.ok(['event.message', 'event.evidences', 'event.resources', 'event.status_id', 'event.timezone_offset'].every(present));
      if (version === '1.9.0') {
        assert.ok(['event.is_alert', 'event.attestation_list[].chain_uid', 'event.attestation_list[].prev_event'].every(present));
        // The demo's OTLP model calls name a model; OTel GenAI spans carry no model uid or separate model version.
        assert.deepEqual([...recommended].filter(path => path.includes('ai_agent.')).sort(), ['event.evidences[].ai_agent.ai_model',
          'event.evidences[].ai_agent.ai_model.uid', 'event.evidences[].ai_agent.ai_model.version',
          'event.evidences[].ai_agent.instance_uid', 'event.evidences[].ai_agent.uid', 'event.evidences[].ai_agent.version']);
      }
    }
  });

  await t.test('the schema check rejects malformed and cross-version events', async () => {
    const [legacy] = (await h.api('/api/export/ocsf')).body, [modern] = (await h.api('/api/export/ocsf?version=1.9.0')).body;
    const broken = (event, version, change) => { const copy = structuredClone(event); change(copy); return validate(copy, schemas[version]).errors; };
    assert.match(broken(legacy, '1.3.0', e => delete e.finding_info.uid).join(), /finding_info\.uid: required/);
    assert.match(broken(legacy, '1.3.0', e => delete e.finding_info.title).join(), /title: required/);
    assert.match(broken(legacy, '1.3.0', e => { e.severity_id = 7; }).join(), /severity_id: 7 not in enum/);
    assert.match(broken(legacy, '1.3.0', e => { e.status_id = 5; }).join(), /status_id: 5 not in enum/);
    assert.match(broken(legacy, '1.3.0', e => { e.attestation_list = modern.attestation_list; }).join(), /attestation_list: not defined/);
    assert.match(broken(legacy, '1.3.0', e => { e.evidences[0].ai_agent = {name: 'x'}; }).join(), /ai_agent: not defined/);
    assert.match(broken(legacy, '1.3.0', e => { e.evidences[0] = {}; }).join(), /needs one of/);
    assert.match(broken(modern, '1.9.0', e => { e.metadata.profiles = []; }).join(), /attestation_list: not defined/);
    assert.match(broken(modern, '1.9.0', e => { e.type_uid = 200402; }).join(), /type_uid/);
    assert.match(broken(modern, '1.9.0', e => { e.attestation_list[0].fingerprint.algorithm_id = 'sha256'; }).join(), /not integer_t/);
  });

  await t.test('version switch: 1.3.0 default without 1.9 objects, 1.9.0 with ai_agent and record_integrity', async () => {
    const legacy = (await h.api('/api/export/ocsf')).body, modern = (await h.api('/api/export/ocsf?version=1.9.0')).body;
    assert.ok(legacy.every(e => e.metadata.version === '1.3.0' && !e.metadata.profiles && !e.attestation_list && e.is_alert === undefined));
    assert.ok(legacy.every(e => e.evidences.every(x => !x.ai_agent && x.uid === undefined)));
    assert.ok(modern.every(e => e.metadata.version === '1.9.0' && e.metadata.profiles.includes('record_integrity') && typeof e.is_alert === 'boolean'));
    const finding = modern.find(e => e.unmapped.evidscope.actionId === scenario.actionId && e.finding_info.types[0] === 'APPROVAL_MISMATCH');
    assert.ok(finding.evidences.some(x => x.ai_agent?.name === 'support-agent'));
    const approval = finding.evidences.find(x => x.name === 'human_approval');
    assert.ok(approval.data.sourceKind === 'authority' && !approval.ai_agent && !approval.actor, 'an approval is not the agent\'s own activity');
    assert.ok(finding.evidences.some(x => x.api?.operation === 'write' && x.api.service.name === 'customer-api'));
    assert.deepEqual(finding.resources, [{name: 'case-42', role_id: 1, role: 'Target'}]);
    assert.equal(finding.severity_id, 3);
    assert.equal(finding.finding_info.analytic.version, 'evidscope-evaluate-v1');
    const custom = modern.find(e => e.finding_info.types[0].startsWith('CUSTOM:'));
    assert.equal(custom.finding_info.analytic.uid, custom.unmapped.evidscope.code.split(':')[1]);
    assert.equal(custom.finding_info.analytic.version, '1');
    assert.deepEqual(legacy.map(e => e.unmapped.evidscope.ledger), modern.map(e => e.unmapped.evidscope.ledger));
    assert.equal((await h.api('/api/export/ocsf?version=1.4.0')).status, 400);
    assert.equal((await h.api('/api/export/ocsf?version=')).status, 400);
  });

  await t.test('attestation and unmapped references lead back to the signed export', async () => {
    const events = (await h.api('/api/export/ocsf?version=1.9.0')).body, bundle = (await h.api('/api/export')).body;
    const keyId = signingKeyId(h.publicKey);
    for (const event of events) {
      const ref = event.unmapped.evidscope, record = bundle.records.find(r => r.seq === ref.ledger.seq);
      assert.equal(record.type, 'evaluation');
      assert.equal(record.payload.id, ref.evaluationId);
      assert.equal(record.payload.actionId, ref.actionId);
      assert.equal(record.hash, ref.ledger.hash);
      assert.equal(record.previous, ref.ledger.previous);
      assert.equal(ref.tenant, 'alpha');
      assert.equal(event.metadata.tenant_uid, 'alpha');
      assert.deepEqual(ref.evidence, record.payload.findings[ref.findingIndex].evidence);
      const [attestation] = event.attestation_list;
      assert.equal(attestation.fingerprint.value, record.hash);
      assert.equal(attestation.fingerprint.serialization_id, 99);
      assert.equal(attestation.prev_event.fingerprint.value, record.previous);
      assert.equal(attestation.prev_event.uid, `evidscope:alpha:${record.seq - 1}`);
      assert.equal(attestation.authority_uid, `ed25519-spki-sha256:${keyId}`);
      assert.ok(ref.checkpoint.count >= record.seq && ref.checkpoint.signature);
    }
  });

  await t.test('human auditor roles only, tenant-scoped', async () => {
    for (const role of ['agent', 'tool', 'authority', 'telemetry']) assert.equal((await h.api('/api/export/ocsf', {role})).status, 403);
    const anonymous = await fetch(`${h.audit.url}/api/export/ocsf`);
    assert.equal(anonymous.status, 401);
    for (const role of ['auditor', 'reviewer', 'admin']) assert.equal((await h.api('/api/export/ocsf', {role})).status, 200);
    const betaEvents = (await h.api('/api/export/ocsf?version=1.9.0', {tenant: 'beta'})).body;
    const alphaEvents = (await h.api('/api/export/ocsf?version=1.9.0')).body;
    assert.ok(betaEvents.length >= 1);
    assert.ok(betaEvents.every(e => e.metadata.tenant_uid === 'beta' && e.unmapped.evidscope.tenant === 'beta'));
    assert.ok(betaEvents.some(e => e.finding_info.types[0] === 'COLLECTION_GAP'));
    assert.ok(!alphaEvents.some(e => e.unmapped.evidscope.actionId === 'beta-action'));
    const alphaIds = new Set(alphaEvents.map(e => e.finding_info.uid));
    assert.ok(betaEvents.every(e => !alphaIds.has(e.finding_info.uid)));
  });

  await t.test('offline bundle path, NDJSON file and Splunk HEC against a local mock', async () => {
    const dir = tempDir('evidscope-ocsf-'), exportFile = join(dir, 'export.json'), key = join(h.dir, 'trust-anchor.pem');
    const bundle = (await h.api('/api/export')).body;
    writeFileSync(exportFile, JSON.stringify(bundle));
    const offline = ocsfFromBundle(bundle, h.publicKey, {version: '1.9.0'});
    assert.deepEqual(offline.map(e => e.finding_info.uid).sort(), alerts.map(a => a.id).sort());
    for (const event of offline) assert.deepEqual(validate(event, schemas['1.9.0']).errors, []);
    const tampered = structuredClone(bundle);
    tampered.records.find(r => r.type === 'evaluation').payload.findings = [];
    assert.throws(() => ocsfFromBundle(tampered, h.publicKey), /Record digest mismatch/);

    const out = join(dir, 'findings.ndjson');
    await run(process.execPath, ['scripts/export-ocsf.mjs', exportFile, key, '--out', out]);
    const lines = readFileSync(out, 'utf8').trimEnd().split('\n').map(line => JSON.parse(line));
    assert.equal(lines.length, offline.length);
    assert.ok(lines.every(e => e.metadata.version === '1.3.0' && validate(e, schemas['1.3.0']).errors.length === 0));

    const collector = await hec(); t.after(() => collector.close());
    await assert.rejects(run(process.execPath, ['scripts/export-ocsf.mjs', exportFile, key, '--hec-url', collector.url],
      {env: {...process.env, SPLUNK_HEC_TOKEN: ''}}), error => /SPLUNK_HEC_TOKEN is not set/.test(error.stderr));
    await assert.rejects(run(process.execPath, ['scripts/export-ocsf.mjs', exportFile, key, '--hec-url', 'http://splunk.example:8088/services/collector'],
      {env: {...process.env, SPLUNK_HEC_TOKEN: 'synthetic'}}), error => /https/.test(error.stderr));
    assert.equal(collector.requests.length, 0, 'nothing is sent without an explicit token and a safe URL');
    await run(process.execPath, ['scripts/export-ocsf.mjs', exportFile, key, '--ocsf-version', '1.9.0', '--hec-url', collector.url,
      '--hec-token-env', 'TEST_HEC_TOKEN', '--index', 'ai_findings'], {env: {...process.env, TEST_HEC_TOKEN: 'synthetic-hec-token'}});
    assert.ok(collector.requests.length >= 1);
    const sent = collector.requests.flatMap(request => {
      assert.equal(request.url, '/services/collector/event');
      assert.equal(request.headers.authorization, 'Splunk synthetic-hec-token');
      return request.body.split('\n').map(line => JSON.parse(line));
    });
    assert.equal(sent.length, offline.length);
    for (const envelope of sent) {
      assert.equal(envelope.sourcetype, SPLUNK_SOURCETYPE);
      assert.equal(envelope.index, 'ai_findings');
      assert.equal(envelope.time, envelope.event.time / 1000);
      assert.equal(envelope.event.metadata.version, '1.9.0');
    }
  });
});
