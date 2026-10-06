import { spawn } from 'node:child_process';
import { readdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertCpuVerificationCanStart } from './execution-memory-boundary.mjs';

const repository = resolve(dirname(fileURLToPath(import.meta.url)), '..');
try {
  if (process.argv.length !== 2) throw Error('Unsupported test arguments; npm test runs the complete serial suite');
  await assertCpuVerificationCanStart(repository);
  const files = (await readdir(resolve(repository, 'test')))
    .filter(name => name.endsWith('.test.mjs')).sort().map(name => `test/${name}`);
  if (!files.length) throw Error('No test files found');
  const environment = { ...process.env };
  // A parent node:test worker marker can suppress an explicitly new test run.
  delete environment.NODE_TEST_CONTEXT;
  const child = spawn(process.execPath, ['--test', '--test-reporter=tap', '--test-concurrency=1', ...files], {
    cwd: repository, env: environment, stdio: 'inherit', windowsHide: true,
  });
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => child.kill(signal));
  child.once('error', error => { console.error(error.message); process.exitCode = 1; });
  child.once('close', code => { process.exitCode = code ?? 1; });
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
