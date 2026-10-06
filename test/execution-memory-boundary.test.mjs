import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, readdir, rm, copyFile } from 'node:fs/promises';
import { dirname, resolve, join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { assertCpuVerificationCanStart } from '../scripts/execution-memory-boundary.mjs';
const execute = promisify(execFile);

async function fixture(t) {
  await mkdir('.test-runs', { recursive: true });
  const root = await mkdtemp(resolve('.test-runs', 'memory-boundary-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

test('CPU verification can start with no owned public-QA lease', async t => {
  await assert.doesNotReject(assertCpuVerificationCanStart(await fixture(t)));
});

test('active GPU lease blocks CPU verification and preserves the original receipt', async t => {
  const root = await fixture(t), directory = join(root, '.local/training');
  await mkdir(directory, { recursive: true });
  const lease = join(directory, 'manual-public-qa-active.json');
  const original = JSON.stringify({ runId: 'public-qa-fixture', createdAt: '2026-10-06T00:00:00Z' });
  await writeFile(lease, original);
  await assert.rejects(assertCpuVerificationCanStart(root), /finish and verify GPU cleanup/);
  assert.equal(await readFile(lease, 'utf8'), original);
});

test('malformed or stale lease stays blocking; age and content do not authorize cleanup', async t => {
  const root = await fixture(t), directory = join(root, '.local/training');
  await mkdir(directory, { recursive: true });
  const lease = join(directory, 'manual-public-qa-active.json');
  await writeFile(lease, 'not JSON');
  await assert.rejects(assertCpuVerificationCanStart(root), /Active or unconfirmed/);
  assert.equal(await readFile(lease, 'utf8'), 'not JSON');
});

async function runnerFixture(t, files) {
  const root = await fixture(t);
  await mkdir(join(root, 'scripts'));
  await mkdir(join(root, 'test'));
  for (const file of ['test-serial.mjs', 'execution-memory-boundary.mjs']) {
    await copyFile(resolve('scripts', file), join(root, 'scripts', file));
  }
  for (const [name, text] of Object.entries(files)) await writeFile(join(root, 'test', name), text);
  return join(root, 'scripts/test-serial.mjs');
}

test('serial runner executes every delivered test file and leaves non-test files out', async t => {
  const runner = await runnerFixture(t, {
    'one.test.mjs': "import test from 'node:test'; test('delivered one', () => {});",
    'two.test.mjs': "import test from 'node:test'; test('delivered two', () => {});",
    'helper.mjs': "throw Error('helper must not execute');",
  });
  const result = await execute(process.execPath, [runner], { timeout: 10000, windowsHide: true });
  assert.match(result.stdout, /# tests 2/);
  assert.match(result.stdout, /# pass 2/);
});

test('serial runner propagates a real failed test exit', async t => {
  const runner = await runnerFixture(t, {
    'failed.test.mjs': "import test from 'node:test'; test('intentional fixture failure', () => {throw Error('fixture failure');});",
  });
  await assert.rejects(execute(process.execPath, [runner], { timeout: 10000, windowsHide: true }),
    error => error.code === 1 && /# fail 1/.test(error.stdout));
});

test('unsupported test arguments are rejected before any fixture test starts', async t => {
  const runner = await runnerFixture(t, {
    'sentinel.test.mjs': "console.log('TEST_SHOULD_NOT_START');",
  });
  await assert.rejects(execute(process.execPath, [runner, '--test-name-pattern=selection'], { timeout: 10000, windowsHide: true }),
    error => error.code === 1 && /Unsupported test arguments/.test(error.stderr)
      && !error.stdout.includes('TEST_SHOULD_NOT_START'));
});

test('serial runner rejects an invalid per-file timeout before any fixture test starts', async t => {
  const runner = await runnerFixture(t, { 'sentinel.test.mjs': "console.log('TEST_SHOULD_NOT_START');" });
  await assert.rejects(execute(process.execPath, [runner], {
    timeout: 10000, windowsHide: true, env: { ...process.env, EVIDSCOPE_TEST_FILE_TIMEOUT_MS: '0' },
  }), error => error.code === 1 && /EVIDSCOPE_TEST_FILE_TIMEOUT_MS/.test(error.stderr) && !error.stdout.includes('TEST_SHOULD_NOT_START'));
});

test('serial runner cancels a file that exceeds its per-file deadline and still runs later files', async t => {
  const runner = await runnerFixture(t, {
    'a-hang.test.mjs': "import test from 'node:test'; test('leaks a handle', () => { setInterval(() => {}, 1000); });",
    'b-after.test.mjs': "import test from 'node:test'; test('runs after the cancelled file', () => {});",
  });
  await assert.rejects(execute(process.execPath, [runner], {
    timeout: 20000, windowsHide: true, env: { ...process.env, EVIDSCOPE_TEST_FILE_TIMEOUT_MS: '1500' },
  }), error => error.code === 1 && /^# cancelled 1$/m.test(error.stdout) && /^# pass 2$/m.test(error.stdout)
    && /^ok \d+ - runs after the cancelled file$/m.test(error.stdout)
    && error.stderr.includes('test/a-hang.test.mjs exceeded the per-file timeout of 1500 ms'));
});

const fixtureWriter = fail => `import test from 'node:test'; import { mkdirSync, writeFileSync } from 'node:fs';
test('writes fixtures', () => {
  mkdirSync('.test-runs/run-new', { recursive: true }); writeFileSync('.test-runs/run-new/signing-private.pem', 'synthetic');
  mkdirSync('.test-runs/run-diag'); writeFileSync('.test-runs/run-diag/config.json', 'synthetic token');
  writeFileSync('.test-runs/run-diag/harness-failure-1.json', '{}');
  ${fail ? "throw Error('fixture failure');" : ''}
});`;
const cleanupEnvironment = () => { const env = { ...process.env }; delete env.EVIDSCOPE_KEEP_TEST_RUNS; return env; };

test('serial runner removes fixtures a passing run created but keeps harness diagnostics and earlier fixtures', async t => {
  const runner = await runnerFixture(t, { 'fixture.test.mjs': fixtureWriter(false) }), root = dirname(dirname(runner));
  await mkdir(join(root, '.test-runs', 'earlier'), { recursive: true });
  await execute(process.execPath, [runner], { timeout: 10000, windowsHide: true, env: cleanupEnvironment() });
  assert.deepEqual((await readdir(join(root, '.test-runs'))).sort(), ['earlier', 'run-diag']);
  assert.deepEqual(await readdir(join(root, '.test-runs', 'run-diag')), ['harness-failure-1.json']);
});

test('serial runner keeps every fixture of a failing run for diagnosis', async t => {
  const runner = await runnerFixture(t, { 'fixture.test.mjs': fixtureWriter(true) }), root = dirname(dirname(runner));
  await assert.rejects(execute(process.execPath, [runner], { timeout: 10000, windowsHide: true, env: cleanupEnvironment() }),
    error => error.code === 1 && /Kept \.test-runs fixtures/.test(error.stderr));
  assert.equal(await readFile(join(root, '.test-runs', 'run-new', 'signing-private.pem'), 'utf8'), 'synthetic');
  assert.deepEqual((await readdir(join(root, '.test-runs', 'run-diag'))).sort(), ['config.json', 'harness-failure-1.json']);
});
