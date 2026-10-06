import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, unlinkSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {initialize} from '../scripts/init.mjs';
import {createLocalRuntime} from '../scripts/local.mjs';
import {createService} from '../src/service.mjs';

const execute = promisify(execFile), host = process.env.EVIDSCOPE_TEST_HOST || '127.0.0.1';
const requirements = JSON.parse(readFileSync(new URL('../data/requirements.json', import.meta.url), 'utf8'));
const sha = b => createHash('sha256').update(b).digest('hex');
const otlpFixture = readFileSync(new URL('./fixtures/otlp/sdk-genai.json', import.meta.url));

async function upgrade(dir, ...args) {
  const env = {...process.env};
  for (const name of ['DATA_KEY_FILE', 'DATA_KEY_PREVIOUS_FILES', 'DATA_DIR', 'TRANSPARENCY_CONFIG_FILE', 'NODE_TEST_CONTEXT']) delete env[name];
  try {
    const out = await execute(process.execPath, [resolve('scripts/upgrade-local.mjs'), '--dir', dir, ...args], {env, timeout: 60000, windowsHide: true});
    return {code: 0, ...out, json: JSON.parse(out.stdout)};
  } catch (error) {
    return {code: error.code ?? 1, stdout: error.stdout || '', stderr: error.stderr || ''};
  }
}
// A .local directory as it looked before OTLP principals and the separate data key existed, holding one governance document.
async function legacyInstall(t) {
  const dir = mkdtempSync(join(tmpdir(), 'evidscope-upgrade-local-'));
  t.after(() => rmSync(dir, {recursive: true, force: true}));
  initialize(dir);
  const config = JSON.parse(readFileSync(join(dir, 'config.json'), 'utf8'));
  config.principals = config.principals.filter(p => p.kind !== 'otlp');
  writeFileSync(join(dir, 'config.json'), JSON.stringify(config, null, 2), {mode: 0o600});
  unlinkSync(join(dir, 'data-encryption.key'));
  const key = readFileSync(join(dir, 'signing-private.pem'), 'utf8'), reviewer = config.principals.find(p => p.id === 'alpha-reviewer');
  const s = createService({dataDir: join(dir, 'data'), key, config, requirements});
  const call = (path, body) => s.handle('POST', new URL(path, 'http://local'), {authorization: 'Bearer ' + reviewer.token}, JSON.stringify(body));
  try {
    await call('/api/governance/systems', {id: 'credit', name: 'Synthetic credit', owner: 'reviewer', purpose: 'Loan assistance', markets: ['KR'],
      krRoles: ['deployer'], generative: false, highImpact: 'confirmed', supplierId: 'supplier-a', modelId: 'credit-score', modelVersion: 'v1',
      suppliedModelVersion: 'v1', suppliedPurpose: 'Loan assistance', substantialModification: false});
    const bytes = Buffer.from('legacy control text');
    await call('/api/governance/documents', {id: 'control', systemId: 'credit', name: 'control.txt', mediaType: 'text/plain', sha256: sha(bytes),
      contentBase64: bytes.toString('base64')});
  } finally { s.store.close(); }
  return {dir, configBytes: readFileSync(join(dir, 'config.json'))};
}

test('upgrade-local adds OTLP principals, separates the data key, enables monitor transparency, and the launcher uses all three', async t => {
  const {dir, configBytes} = await legacyInstall(t);

  const dry = await upgrade(dir, '--transparency', '--dry-run');
  assert.equal(dry.code, 0, dry.stderr);
  assert.deepEqual(dry.json.steps.map(s => s.status), ['would_add', 'would_create_and_migrate', 'would_create']);
  assert.deepEqual(readFileSync(join(dir, 'config.json')), configBytes);
  for (const file of ['data-encryption.key', 'transparency.json']) assert.equal(existsSync(join(dir, file)), false, file);

  const run = await upgrade(dir, '--transparency');
  assert.equal(run.code, 0, run.stderr);
  const [principals, dataKey, tlog] = run.json.steps;
  assert.deepEqual(principals.principals, ['alpha-otlp', 'beta-otlp']);
  assert.equal(dataKey.status, 'created'); assert.match(dataKey.kid, /^dk1-[a-f0-9]{32}$/);
  assert.deepEqual(dataKey.migration.reencryptedFrom, {'legacy-signing-v1': 1});
  assert.equal(tlog.status, 'created'); assert.match(tlog.origin, /^evidscope\.local\/[a-f0-9]{16}$/);
  const config = JSON.parse(readFileSync(join(dir, 'config.json'), 'utf8')), keyBytes = readFileSync(join(dir, 'data-encryption.key'));
  for (const p of config.principals.filter(p => p.kind === 'otlp')) assert.ok(!run.stdout.includes(p.token), 'token printed');
  for (const encoding of ['hex', 'base64', 'base64url']) assert.ok(!run.stdout.includes(keyBytes.toString(encoding)), 'key printed');
  const backups = readdirSync(run.json.backupDir);
  assert.deepEqual(backups, ['config.json']); assert.deepEqual(readFileSync(join(run.json.backupDir, 'config.json')), configBytes);

  const again = await upgrade(dir, '--transparency');
  assert.equal(again.code, 0, again.stderr); assert.equal(again.json.upgraded, false);
  assert.deepEqual(again.json.steps.map(s => s.status), ['already_present', 'already_present', 'already_present']);

  const runtime = createLocalRuntime({host, portBase: 0, directory: dir});
  t.after(() => runtime.stop());
  const {endpoints} = await runtime.start();
  const token = id => config.principals.find(p => p.id === id).token;
  const sent = await fetch(endpoints.ingress + '/v1/traces', {method: 'POST', body: otlpFixture,
    headers: {'content-type': 'application/json', authorization: 'Bearer ' + token('alpha-otlp')}});
  assert.equal(sent.status, 200); assert.deepEqual(await sent.json(), {});
  const get = async path => (await fetch(endpoints.audit + path, {headers: {authorization: 'Bearer ' + token('alpha-auditor')}})).json();
  const integrity = await get('/api/integrity');
  assert.equal(integrity.valid, true, integrity.error);
  assert.equal(integrity.keySeparation.status, 'separated');
  assert.equal(integrity.transparency.mode, 'monitor');
  assert.ok(integrity.verificationScope.checks.includes('merkle_tree'));
  assert.ok((await get('/api/events?limit=50')).items.some(e => e.sourceKind === 'otlp'));
});

test('upgrade-local leaves a restored vault config alone and refuses a directory without an install', async t => {
  const {dir, configBytes} = await legacyInstall(t);
  writeFileSync(join(dir, 'data', 'vault-restoration.json'), '{}');
  const run = await upgrade(dir);
  assert.equal(run.code, 0, run.stderr);
  assert.equal(run.json.steps[0].status, 'skipped'); assert.match(run.json.steps[0].reason, /restored vault binds config\.json/);
  assert.deepEqual(readFileSync(join(dir, 'config.json')), configBytes);
  const empty = mkdtempSync(join(tmpdir(), 'evidscope-upgrade-empty-'));
  t.after(() => rmSync(empty, {recursive: true, force: true}));
  const refused = await upgrade(empty);
  assert.equal(refused.code, 1); assert.match(refused.stderr, /No local install/);
});
