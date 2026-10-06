import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm, copyFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
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
