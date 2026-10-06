import { once } from 'node:events';
import { readdir, rm } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { run } from 'node:test';
import { tap } from 'node:test/reporters';
import { fileURLToPath } from 'node:url';
import { assertCpuVerificationCanStart } from './execution-memory-boundary.mjs';

const repository = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const testRuns = resolve(repository, '.test-runs');
const summaryCounts = { tests: 'tests', suites: 'suites', pass: 'passed', fail: 'failed', cancelled: 'cancelled', skipped: 'skipped', todo: 'todo' };

function fileTimeout() {
  const value = process.env.EVIDSCOPE_TEST_FILE_TIMEOUT_MS ?? '300000';
  if (!/^[1-9]\d*$/.test(value)) throw Error('EVIDSCOPE_TEST_FILE_TIMEOUT_MS must be a positive integer of milliseconds');
  return Number(value);
}

async function testRunEntries() {
  try { return new Set(await readdir(testRuns)); } catch (error) { if (error.code === 'ENOENT') return new Set(); throw error; }
}

// Fixtures under .test-runs hold bearer tokens and private keys. After a fully passing run, remove what this run created
// but keep harness-failure-*.json diagnostics (allowlisted and token-redacted by test/harness.mjs).
async function removeNewTestRuns(before) {
  const remove = path => rm(path, { recursive: true, force: true, maxRetries: 3 })
    .catch(error => console.error(`Could not remove test fixture ${path}: ${error.code || error.message}`));
  for (const name of await testRunEntries()) {
    if (before.has(name)) continue;
    const path = join(testRuns, name);
    let entries = [];
    try { entries = await readdir(path); } catch (error) { if (error.code !== 'ENOTDIR') throw error; }
    const diagnostics = entries.filter(entry => /^harness-failure-.+\.json$/.test(entry));
    if (!diagnostics.length) await remove(path);
    else for (const entry of entries) if (!diagnostics.includes(entry)) await remove(join(path, entry));
  }
}

// Every file runs in its own child process (as with `node --test`) under its own deadline: a hung test or a leaked
// handle cancels that file only, the remaining files still run, and the single TAP summary counts the cancellation.
async function* serialEvents(files, timeoutMs, state) {
  const totals = Object.fromEntries(Object.keys(summaryCounts).map(key => [key, 0]));
  const began = performance.now();
  let number = 0;
  for (const file of files) {
    if (state.interrupted) break;
    const controller = new AbortController();
    let timedOut = false, summarized = false;
    state.abort = () => controller.abort();
    const timer = setTimeout(() => { timedOut = true; controller.abort(); }, timeoutMs);
    try {
      for await (const event of run({ files: [file], cwd: repository, concurrency: 1, signal: controller.signal })) {
        const { type, data } = event;
        if (type === 'test:summary') {
          if (data.file !== undefined) continue;
          summarized = true;
          for (const [key, field] of Object.entries(summaryCounts)) totals[key] += data.counts[field];
          if (!data.success) state.failed = true;
          continue;
        }
        // The per-file plan and summary lines are replaced by one aggregate below.
        if (data.nesting === 0 && data.file === undefined && (type === 'test:plan' || type === 'test:diagnostic')) continue;
        if (data.nesting === 0 && (type === 'test:pass' || type === 'test:fail')) yield { type, data: { ...data, testNumber: ++number } };
        else yield event;
      }
    } finally {
      clearTimeout(timer);
      state.abort = null;
    }
    if (!summarized) state.failed = true;
    if (timedOut) {
      state.failed = true;
      const message = `${file} exceeded the per-file timeout of ${timeoutMs} ms (EVIDSCOPE_TEST_FILE_TIMEOUT_MS) and was cancelled`;
      console.error(message);
      yield { type: 'test:diagnostic', data: { nesting: 0, message } };
    }
  }
  yield { type: 'test:plan', data: { nesting: 0, count: number } };
  for (const [key, value] of Object.entries(totals)) yield { type: 'test:diagnostic', data: { nesting: 0, message: `${key} ${value}` } };
  yield { type: 'test:diagnostic', data: { nesting: 0, message: `duration_ms ${performance.now() - began}` } };
}

try {
  if (process.argv.length !== 2) throw Error('Unsupported test arguments; npm test runs the complete serial suite');
  const timeoutMs = fileTimeout();
  await assertCpuVerificationCanStart(repository);
  const files = (await readdir(resolve(repository, 'test')))
    .filter(name => name.endsWith('.test.mjs')).sort().map(name => `test/${name}`);
  if (!files.length) throw Error('No test files found');
  // A parent node:test worker marker can suppress an explicitly new test run.
  delete process.env.NODE_TEST_CONTEXT;
  const before = await testRunEntries();
  const state = { failed: false, interrupted: false, abort: null };
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => { state.interrupted = true; state.abort?.(); });
  for await (const chunk of tap(serialEvents(files, timeoutMs, state))) {
    if (!process.stdout.write(chunk)) await once(process.stdout, 'drain');
  }
  const passed = !state.failed && !state.interrupted;
  if (passed && process.env.EVIDSCOPE_KEEP_TEST_RUNS !== '1') await removeNewTestRuns(before);
  else if (!passed && [...await testRunEntries()].some(name => !before.has(name))) {
    console.error('Kept .test-runs fixtures of this run for diagnosis; they contain synthetic tokens and private keys.');
  }
  process.exitCode = passed ? 0 : 1;
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
