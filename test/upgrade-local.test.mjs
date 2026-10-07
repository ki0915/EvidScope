import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, unlinkSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {execFile} from 'node:child_process';
import {createServer} from 'node:net';
import {setTimeout as delay} from 'node:timers/promises';
import {promisify} from 'node:util';
import {initialize} from '../scripts/init.mjs';
import {createLocalRuntime} from '../scripts/local.mjs';
import {createService} from '../src/service.mjs';
import {createGovernanceDocumentStorage} from '../src/governance-documents.mjs';
import {dataKeyId} from '../src/data-keys.mjs';

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

test('upgrade-local finishes a document migration that failed after the data key was created', async t => {
  const {dir} = await legacyInstall(t);
  const signingKey = readFileSync(join(dir, 'signing-private.pem'), 'utf8');
  const file = createGovernanceDocumentStorage(join(dir, 'data'), signingKey).location('alpha', sha(Buffer.from('legacy control text')));
  const original = readFileSync(file);
  writeFileSync(file, '{}'); // the migration aborts on this file after the key file exists
  const failed = await upgrade(dir);
  assert.equal(failed.code, 1); assert.match(failed.stderr, /document migration failed: .*Stop the vault and re-run/);
  assert.ok(existsSync(join(dir, 'data-encryption.key')));
  writeFileSync(file, original);
  const kid = dataKeyId(readFileSync(join(dir, 'data-encryption.key')));
  const dry = await upgrade(dir, '--dry-run');
  assert.equal(dry.code, 0, dry.stderr);
  assert.deepEqual(dry.json.steps[1], {step: 'data_key', status: 'would_migrate', kid, pendingFilesByKeyId: {'legacy-signing-v1': 1}});
  assert.equal(JSON.parse(readFileSync(file, 'utf8')).kid, undefined, 'dry run rewrites nothing');
  const resumed = await upgrade(dir);
  assert.equal(resumed.code, 0, resumed.stderr); assert.equal(resumed.json.upgraded, true);
  assert.equal(resumed.json.steps[1].status, 'migrated'); assert.deepEqual(resumed.json.steps[1].migration.reencryptedFrom, {'legacy-signing-v1': 1});
  assert.equal(JSON.parse(readFileSync(file, 'utf8')).kid, kid);
  const again = await upgrade(dir);
  assert.equal(again.code, 0, again.stderr); assert.equal(again.json.steps[1].status, 'already_present'); assert.equal(again.json.upgraded, false);
});

// The local heads signer (docs/signer.md): upgrade-local sets it up, npm start runs it before the vault and stops it with the rest.
const alive = pid => { try { process.kill(pid, 0); return true; } catch { return false; } };
const freePort = () => new Promise(done => {
  const server = createServer().listen(0, '127.0.0.1', () => { const {port} = server.address(); server.close(() => done(port)); });
});
async function runLocal(t, dir, check) {
  const runtime = createLocalRuntime({host, portBase: 0, directory: dir});
  t.after(() => runtime.stop());
  const ready = await runtime.start(), config = JSON.parse(readFileSync(join(dir, 'config.json'), 'utf8'));
  const token = id => config.principals.find(p => p.id === id).token;
  const sent = await fetch(ready.endpoints.ingress + '/v1/traces', {method: 'POST', body: otlpFixture,
    headers: {'content-type': 'application/json', authorization: 'Bearer ' + token('alpha-otlp')}});
  assert.equal(sent.status, 200);
  let integrity = null;
  for (let i = 0; i < 100 && !check(integrity); i++) {
    if (i) await delay(200);
    integrity = await (await fetch(ready.endpoints.audit + '/api/integrity', {headers: {authorization: 'Bearer ' + token('alpha-auditor')}})).json();
  }
  assert.ok(check(integrity), JSON.stringify(integrity.transparency?.runtime));
  const stopped = await runtime.stop();
  assert.ok(stopped.childPids.every(pid => !alive(pid)));
  return {ready, integrity, stopped};
}

test('upgrade-local --heads-signer starts a new heads log at a local heads signer on a Unix socket', {skip: process.platform === 'win32'}, async t => {
  const {dir} = await legacyInstall(t);
  const dry = await upgrade(dir, '--transparency', '--heads-signer', '--dry-run');
  assert.equal(dry.code, 0, dry.stderr);
  assert.deepEqual(dry.json.steps.at(-1), {step: 'heads_signer', status: 'would_create', authorization: 'genesis'});
  assert.equal(existsSync(join(dir, 'signer')), false);
  const run = await upgrade(dir, '--transparency', '--heads-signer');
  assert.equal(run.code, 0, run.stderr);
  const step = run.json.steps.at(-1);
  assert.deepEqual([step.status, step.authorization, step.listen], ['created', 'genesis', join(resolve(dir), 'signer', 'signer.sock')]);
  const tlog = JSON.parse(readFileSync(join(dir, 'transparency.json'), 'utf8'));
  assert.deepEqual(Object.keys(tlog.signer).sort(), ['publicKeyFile', 'socket']);
  const {ready, integrity, stopped} = await runLocal(t, dir, i => i?.transparency?.runtime?.signer?.status === 'consistent');
  assert.equal(ready.headsSigner, step.listen);
  assert.equal(stopped.childPids.length, 5);
  assert.deepEqual([integrity.transparency.runtime.heads.signedBy, integrity.transparency.runtime.signer.size], [step.vkey, 1]);
  assert.ok(integrity.verificationScope.checks.includes('heads_signer'));
  assert.equal((await upgrade(dir, '--heads-signer')).json.steps.at(-1).status, 'already_present');
});

test('upgrade-local --heads-signer hands a vault-key heads log over to a local heads signer on loopback TCP with a token', async t => {
  const {dir} = await legacyInstall(t);
  assert.equal((await upgrade(dir, '--transparency')).code, 0);
  const before = await runLocal(t, dir, i => i?.transparency?.runtime?.heads?.size >= 1);
  assert.equal(before.ready.headsSigner, undefined);
  const port = await freePort(), run = await upgrade(dir, '--heads-signer', '--heads-signer-port', String(port));
  assert.equal(run.code, 0, run.stderr);
  const step = run.json.steps.at(-1), size = before.integrity.transparency.runtime.heads.size;
  assert.deepEqual([step.status, step.authorization, step.listen], ['created', 'handover', `http://127.0.0.1:${port}`]);
  const tlog = JSON.parse(readFileSync(join(dir, 'transparency.json'), 'utf8'));
  assert.deepEqual(Object.keys(tlog.signer).sort(), ['publicKeyFile', 'tokenFile', 'url']);
  const serve = JSON.parse(readFileSync(join(dir, 'signer', 'serve.json'), 'utf8'));
  assert.ok(serve.args.includes('--token-file'));
  const {ready, integrity} = await runLocal(t, dir, i => i?.transparency?.runtime?.signer?.status === 'consistent');
  assert.equal(ready.headsSigner, `http://127.0.0.1:${port}`);
  // The first signer leaf continues the vault-key heads log; the vault key signs no heads checkpoint any more.
  assert.ok(integrity.transparency.runtime.heads.size > size);
  assert.equal(integrity.transparency.runtime.heads.signedBy, step.vkey);
});
