// Dependency-free source checks (npm run check; CI job "source checks"). Run from the repository root.
//  1. node --check on every tracked or new (untracked, not ignored) .mjs/.js/.cjs file;
//  2. byte hygiene: no UTF-8 BOM, no CR in the committed content, no trailing whitespace; final newline (warning);
//  3. no committed .only in test/;
//  4. line-length baseline: a file listed in scripts/line-length-baseline.json may not gain lines longer than
//     300 characters beyond its recorded count (dense existing code is not reformatted); any other file is new
//     and may not contain lines longer than 160 characters.
// Usage: node scripts/check-source.mjs [--update-baseline]
// --update-baseline rewrites the counts of files already in the baseline to their current values and drops deleted
// files. It never adds files, so new files stay under the 160-character rule. Raised counts are printed and show up
// in review as a diff of the baseline.
import { execFileSync, spawn } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { availableParallelism } from 'node:os';

const DENSE = 300, NEW_FILE = 160, BASELINE = 'scripts/line-length-baseline.json';
const annotate = !!process.env.GITHUB_ACTIONS, update = process.argv.includes('--update-baseline');
const unknown = process.argv.slice(2).filter(arg => arg !== '--update-baseline');
if (unknown.length) {
  console.error(`Unsupported arguments: ${unknown.join(' ')}`);
  process.exit(2);
}

// "i/crlf" is the committed (index) content, independent of a Windows checkout's core.autocrlf conversion.
const listing = execFileSync('git', ['ls-files', '--eol', '-z', '-co', '--exclude-standard', '--', '*.mjs', '*.js', '*.cjs'],
  { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
const files = new Map();
for (const record of listing.split('\0').filter(Boolean)) {
  const tab = record.indexOf('\t'), path = record.slice(tab + 1);
  if (existsSync(path)) files.set(path, record.slice(0, tab).split(/\s+/)[0].slice(2));
}
const paths = [...files.keys()].sort();
const baseline = existsSync(BASELINE) ? JSON.parse(readFileSync(BASELINE, 'utf8')) : null;
const errors = [], warnings = [], counts = {};
const report = (list, kind, file, line, message) => {
  list.push(`${file}:${line}: ${message}`);
  if (annotate) console.log(`::${kind} file=${file},line=${line}::${message}`);
};

for (const file of paths) {
  const bytes = readFileSync(file), indexEol = files.get(file);
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) report(errors, 'error', file, 1, 'UTF-8 BOM');
  const raw = bytes.toString('utf8');
  if (indexEol === 'crlf' || indexEol === 'mixed' || (!indexEol && raw.includes('\r'))) report(errors, 'error', file, 1, 'CR line ending');
  if (bytes.length && !raw.endsWith('\n')) report(warnings, 'warning', file, 1, 'missing final newline');
  const lines = raw.replace(/\r\n/g, '\n').split('\n');
  const known = baseline !== null && Object.hasOwn(baseline, file);
  let dense = 0;
  lines.forEach((line, index) => {
    if (/[ \t]+$/.test(line)) report(errors, 'error', file, index + 1, 'trailing whitespace');
    if (file.startsWith('test/') && /\b(?:test|it|describe|suite)\.only\s*\(|\bonly\s*:\s*true\b/.test(line)) {
      report(errors, 'error', file, index + 1, 'committed .only');
    }
    if (line.length > DENSE) dense++;
    if (!known && baseline !== null && line.length > NEW_FILE) {
      report(errors, 'error', file, index + 1, `line has ${line.length} characters; files new since the baseline allow ${NEW_FILE}`);
    }
  });
  counts[file] = dense;
  if (known && dense > baseline[file] && !update) {
    report(errors, 'error', file, 1, `${dense} lines longer than ${DENSE} characters; baseline allows ${baseline[file]} (wrap the new lines)`);
  }
}

async function syntaxCheck() {
  let next = 0;
  const worker = async () => {
    while (next < paths.length) {
      const file = paths[next++];
      const { code, stderr } = await new Promise(done => {
        const child = spawn(process.execPath, ['--check', file], { stdio: ['ignore', 'ignore', 'pipe'], windowsHide: true });
        let text = '';
        child.stderr.on('data', chunk => { text += chunk; });
        child.once('close', exitCode => done({ code: exitCode, stderr: text }));
      });
      if (code !== 0) report(errors, 'error', file, 1, 'node --check failed: ' + stderr.trim().split('\n').slice(0, 4).join(' | '));
    }
  };
  await Promise.all(Array.from({ length: Math.min(8, availableParallelism()) }, worker));
}
await syntaxCheck();

if (update || baseline === null) {
  const next = {}, changes = [];
  for (const file of paths) {
    if (baseline !== null && !Object.hasOwn(baseline, file)) continue;
    next[file] = counts[file];
    if (baseline !== null && counts[file] !== baseline[file]) changes.push(`${file}: ${baseline[file]} -> ${counts[file]}`);
  }
  writeFileSync(BASELINE, JSON.stringify(next, null, 1) + '\n');
  console.log(`${BASELINE}: ${Object.keys(next).length} files${changes.length ? '; changed ' + changes.join(', ') : ''}`);
}
const summary = { files: paths.length, errors: errors.length, warnings: warnings.length };
summary.linesOver300 = Object.values(counts).reduce((total, count) => total + count, 0);
console.log(JSON.stringify(summary));
for (const warning of warnings.slice(0, 50)) console.error('WARNING ' + warning);
for (const error of errors.slice(0, 100)) console.error('ERROR ' + error);
if (errors.length > 100) console.error(`... and ${errors.length - 100} more errors`);
if (errors.length) process.exitCode = 1;
