// Gate a node:test TAP log (CI, npm run test:ci). Fails on any fail/cancelled/todo, on a missing or repeated summary,
// and on any SKIP whose reason is not allowlisted, so unexplained skips cannot creep in. Prints failing and skipped
// tests and appends the same Markdown to $GITHUB_STEP_SUMMARY when it is set.
// Usage: node scripts/ci-tap-gate.mjs TAP_FILE
//        node scripts/test-serial.mjs | node scripts/ci-tap-gate.mjs -   (stdin is passed through while it streams)
import { appendFileSync, readFileSync } from 'node:fs';

// A skip must say why: Windows-only checks, or an opt-in gate naming the EVIDSCOPE_* variable that enables the test
// (unshipped research artifacts, external interop binaries).
const ALLOWED_SKIPS = [/^Windows-only\b/, /^unshipped research artifacts absent \(/, /\bEVIDSCOPE_[A-Z][A-Z0-9_]*\b/];

async function readTap(source) {
  if (source !== '-') return readFileSync(source, 'utf8');
  let text = '';
  process.stdin.setEncoding('utf8');
  for await (const chunk of process.stdin) { text += chunk; process.stdout.write(chunk); }
  return text;
}

function gate(log) {
  const summary = {}, problems = [];
  for (const key of ['tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo']) {
    const found = [...log.matchAll(new RegExp(`^# ${key} (\\d+)\\r?$`, 'gm'))];
    if (found.length !== 1) problems.push(`summary line "# ${key}" found ${found.length} times`);
    else summary[key] = Number(found[0][1]);
  }
  for (const key of ['fail', 'cancelled', 'todo']) if (summary[key]) problems.push(`${key}=${summary[key]}`);
  if (summary.tests === 0) problems.push('no tests ran');
  const skips = [...log.matchAll(/^\s*ok \d+ - (.*?) # SKIP ?(.*?)\r?$/gm)].map(([, name, reason]) => ({ name, reason: reason.trim() }));
  for (const skip of skips) {
    if (!ALLOWED_SKIPS.some(rule => rule.test(skip.reason))) problems.push(`unapproved skip: "${skip.name}" (reason: ${skip.reason || 'none'})`);
  }
  const failed = [...log.matchAll(/^\s*not ok \d+ - (.*?)\r?$/gm)].map(match => match[1]);
  const markdown = [
    `### node:test ${problems.length ? 'FAILED' : 'passed'}`, '',
    `tests ${summary.tests} · pass ${summary.pass} · fail ${summary.fail} · cancelled ${summary.cancelled} · skipped ${summary.skipped}`, '',
    ...(failed.length ? ['**Failing tests**', '', ...failed.map(name => `- ${name}`), ''] : []),
    ...(skips.length ? ['**Skipped tests**', '', ...skips.map(skip => `- ${skip.name} — ${skip.reason || '(no reason)'}`), ''] : []),
    ...(problems.length ? ['**Gate problems**', '', ...problems.map(problem => `- ${problem}`)] : []),
  ].join('\n');
  return { passed: problems.length === 0, summary, problems, markdown };
}

const source = process.argv[2];
if (process.argv.length !== 3 || !source) {
  console.error('Usage: node scripts/ci-tap-gate.mjs TAP_FILE|-');
  process.exitCode = 2;
} else {
  const result = gate(await readTap(source));
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, result.markdown + '\n');
  console.log('\n' + result.markdown);
  if (!result.passed) process.exitCode = 1;
}
