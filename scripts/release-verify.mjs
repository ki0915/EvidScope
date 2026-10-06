import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createWriteStream } from 'node:fs';
import { lstat, mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { finished } from 'node:stream/promises';
import { assertCpuVerificationCanStart } from './execution-memory-boundary.mjs';

const repository = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const testFiles = [
  'test/local-release.test.mjs', 'test/finance-report-verifier.test.mjs',
  'test/kr-governance-http.test.mjs', 'test/finance-http.test.mjs',
  'test/governance-documents.test.mjs', 'test/vault-recovery.test.mjs', 'test/assistance.test.mjs',
  'test/governance-authorization.test.mjs',
  'test/finance-known-reference.test.mjs', 'test/kr-governance-33-http.test.mjs',
  'test/kr-governance-evidence.test.mjs', 'test/governance-ui.test.mjs',
  'test/kr-supplier-reliance.test.mjs',
  'test/execution-memory-boundary.test.mjs',
];
const watchedDirectories = ['src', 'public', 'data', 'roles'];
const watchedFiles = [
  'scripts/local.mjs', 'scripts/demo.mjs', 'scripts/verify-finance-report.mjs',
  'scripts/release-verify.mjs',
  'scripts/execution-memory-boundary.mjs',
  'scripts/test-serial.mjs',
  'scripts/package-release.mjs', 'package.json', 'package-lock.json', 'Dockerfile', '.dockerignore',
  ...testFiles,
];
const roundTimeoutMs = 180_000;
const terminationConfirmationAllowanceMs = 10_000;
const executionTimeoutMs = roundTimeoutMs - terminationConfirmationAllowanceMs;
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const delay = ms => new Promise(done => setTimeout(done, ms));
const inside = (directory, candidate) => {
  const suffix = relative(directory, candidate);
  return suffix === '' || (!suffix.startsWith('..') && !isAbsolute(suffix));
};

async function sourceSnapshot() {
  const files = [...watchedFiles];
  async function visit(directory) {
    for (const entry of await readdir(resolve(repository, directory), { withFileTypes: true })) {
      const name = `${directory}/${entry.name}`;
      if (entry.isSymbolicLink()) throw Error(`Source symlink rejected: ${name}`);
      if (entry.isDirectory()) await visit(name);
      else if (entry.isFile()) files.push(name);
      else throw Error(`Non-regular source rejected: ${name}`);
    }
  }
  for (const directory of watchedDirectories) await visit(directory);
  const hashes = {};
  for (const name of [...new Set(files)].sort()) {
    if (!(await lstat(resolve(repository, name))).isFile()) throw Error(`Non-regular source rejected: ${name}`);
    hashes[name] = hash(await readFile(resolve(repository, name)));
  }
  return { files: hashes, sha256: hash(JSON.stringify(hashes)) };
}

function parseSummary(log) {
  const summary = {};
  for (const key of ['tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo']) {
    const matches = [...log.matchAll(new RegExp(`^# ${key} (\\d+)\\r?$`, 'gm'))];
    summary[key] = matches.length === 1 ? Number(matches[0][1]) : null;
  }
  return summary;
}

async function runRound(index, directory, initialSnapshot) {
  const startedAt = new Date().toISOString();
  const began = performance.now();
  const logName = `round-${String(index).padStart(2, '0')}.log`;
  const logPath = resolve(directory, logName);
  const log = createWriteStream(logPath, { flags: 'wx' });
  let logError = null;
  log.on('error', error => { logError = error; });
  const child = spawn(process.execPath, [
    '--test', '--test-reporter=tap', '--test-concurrency=1', '--test-timeout=90000', ...testFiles,
  ], {
    cwd: repository,
    env: { ...process.env, EVIDSCOPE_TEST_HOST: '::1', NODE_DISABLE_COLORS: '1', FORCE_COLOR: '0' },
    stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true,
  });
  child.stdout.pipe(log, { end: false });
  child.stderr.pipe(log, { end: false });
  let closed = false;
  let timedOut = false;
  let sourceChanged = false;
  const changedSources = new Set();
  let sourceMonitorError = null;
  let spawnError = null;
  let killRequested = false;
  function terminate() {
    if (!closed && !killRequested) {
      killRequested = true;
      // Only this owned process is signalled. A release container bounds descendants.
      child.kill('SIGKILL');
    }
  }
  child.on('error', error => { spawnError = error.message; });
  const closedPromise = new Promise(done => child.once('close', (exitCode, signal) => {
    closed = true;
    done({ exitCode, signal });
  }));
  const timeout = setTimeout(() => { timedOut = true; terminate(); }, executionTimeoutMs);
  const monitor = (async () => {
    while (!closed && !timedOut && !sourceChanged && !sourceMonitorError) {
      await delay(500);
      if (closed) break;
      try {
        const observed = await sourceSnapshot();
        sourceChanged = observed.sha256 !== initialSnapshot.sha256;
        if (sourceChanged) {
          for (const name of new Set([...Object.keys(initialSnapshot.files), ...Object.keys(observed.files)])) {
            if (initialSnapshot.files[name] !== observed.files[name]) changedSources.add(name);
          }
        }
      } catch (error) { sourceMonitorError = error.message; }
      if (sourceChanged || sourceMonitorError) terminate();
    }
  })();
  // Allow bounded confirmation of an owned process exit after the execution deadline.
  let confirmationTimeout;
  const confirmationDeadline = new Promise(done => {
    confirmationTimeout = setTimeout(() => done({ exitCode: null, signal: null }), roundTimeoutMs);
  });
  const result = await Promise.race([closedPromise, confirmationDeadline]);
  clearTimeout(timeout);
  clearTimeout(confirmationTimeout);
  if (!closed) {
    terminate();
    child.stdout.destroy(); child.stderr.destroy(); child.unref();
  }
  await monitor;
  log.end();
  try { await finished(log); } catch (error) { logError = error; }
  let finalSnapshot = null;
  try {
    finalSnapshot = await sourceSnapshot();
    sourceChanged ||= finalSnapshot.sha256 !== initialSnapshot.sha256;
    for (const name of new Set([...Object.keys(initialSnapshot.files), ...Object.keys(finalSnapshot.files)])) {
      if (initialSnapshot.files[name] !== finalSnapshot.files[name]) changedSources.add(name);
    }
  } catch (error) { sourceMonitorError ||= error.message; }
  const logBytes = await readFile(logPath);
  const counts = parseSummary(logBytes.toString('utf8'));
  const summaryComplete = Object.values(counts).every(Number.isSafeInteger);
  const passed = closed && result.exitCode === 0 && !timedOut && !sourceChanged
    && !sourceMonitorError && !spawnError && !logError && summaryComplete
    && counts.tests > 0 && counts.pass === counts.tests
    && ['fail', 'cancelled', 'skipped', 'todo'].every(key => counts[key] === 0);
  return {
    round: index, startedAt, endedAt: new Date().toISOString(),
    durationMs: Math.round(performance.now() - began), ...result,
    timedOut, terminationConfirmed: closed, sourceChanged, changedSources: [...changedSources].sort(), sourceMonitorError,
    spawnError, logError: logError?.message ?? null, counts, summaryComplete, passed,
    log: logName, logSha256: hash(logBytes),
    sourceSha256After: finalSnapshot?.sha256 ?? null,
  };
}

export async function verifyRelease(outputDirectory) {
  await assertCpuVerificationCanStart(repository);
  const directory = resolve(outputDirectory);
  for (const watched of watchedDirectories) {
    if (inside(resolve(repository, watched), directory)) throw Error('Output cannot be inside monitored source directories');
  }
  // mkdir is exclusive: a preexisting output directory is never reused or removed.
  await mkdir(directory);
  const reportPath = resolve(directory, 'verification.json');
  const report = {
    schemaVersion: 1, startedAt: new Date().toISOString(), endedAt: null,
    requestedRounds: 10, completedRounds: 0, passedRounds: 0, passed: false,
    syntheticInputs: true, realHttpAndProcessExecution: true,
    legalComplianceCertified: false, productionFinancialIntegrationVerified: false,
    runtime: { node: process.version, platform: process.platform, arch: process.arch },
    roundTimeoutMs, executionTimeoutMs, terminationConfirmationAllowanceMs,
    sourceMonitoring: 'full SHA-256 before/after each round and every 500ms during execution',
    testFiles, sourceSnapshot: null, rounds: [], error: null,
  };
  async function save() { await writeFile(reportPath, JSON.stringify(report, null, 2) + '\n'); }
  await save();
  try {
    report.sourceSnapshot = await sourceSnapshot();
    await save();
    for (let index = 1; index <= 10; index++) {
      await assertCpuVerificationCanStart(repository);
      if ((await sourceSnapshot()).sha256 !== report.sourceSnapshot.sha256) throw Error('Source changed before test round');
      const round = await runRound(index, directory, report.sourceSnapshot);
      report.rounds.push(round);
      report.completedRounds = report.rounds.length;
      report.passedRounds = report.rounds.filter(item => item.passed).length;
      await save();
      console.log(`Round ${index}/10: ${round.passed ? 'PASS' : 'FAIL'} (${round.counts.pass ?? '?'}/${round.counts.tests ?? '?'}, ${round.durationMs}ms)`);
      if (!round.passed) throw Error(`Round ${index} failed; evidence preserved in ${logNameFor(index)}`);
    }
    report.passed = report.completedRounds === 10 && report.passedRounds === 10;
  } catch (error) {
    report.error = error.message;
  } finally {
    report.endedAt = new Date().toISOString();
    await save();
  }
  return report;
}

const logNameFor = index => `round-${String(index).padStart(2, '0')}.log`;

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const args = process.argv.slice(2);
  if (args.length !== 2 || args[0] !== '--output' || !args[1]) {
    console.error('Usage: node scripts/release-verify.mjs --output NEW_DIRECTORY');
    process.exitCode = 1;
  } else {
    try {
      const report = await verifyRelease(args[1]);
      console.log(`Release verification: ${report.passedRounds}/10; ${report.passed ? 'PASS' : 'FAIL'}`);
      if (!report.passed) process.exitCode = 1;
    } catch (error) {
      console.error(error.message);
      process.exitCode = 1;
    }
  }
}
