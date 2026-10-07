// Builds the separately published offline verifier (docs/receipts.md): a folder and a reproducible .tar.gz holding
// evidscope-verify.mjs, only the src modules it imports, a package.json without dependencies, README.md (Korean),
// README.en.md (English) and SHA256SUMS (sha256sum -c format).
//   node scripts/package-verifier.mjs [--out DIR]     default releases/; existing outputs are never overwritten
// The import closure is computed from src/verify-cli.mjs: only node: built-ins without network or process access and
// modules beside it are allowed, and dynamic import() is refused, so what is listed is all the verifier can load.
import {createHash} from 'node:crypto';
import {existsSync, lstatSync, mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import {dirname, join, posix, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {parseArgs} from 'node:util';
import {gzipSync} from 'node:zlib';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ENTRY = 'src/verify-cli.mjs', NAME = 'evidscope-verify';
export const FORBIDDEN_BUILTINS = ['child_process', 'cluster', 'dgram', 'dns', 'http', 'http2', 'https', 'inspector', 'net', 'tls', 'worker_threads'];
const IMPORTS = /^\s*(?:import|export)\b[^'"`;]*?\bfrom\s*(['"])([^'"]+)\1|^\s*import\s*(['"])([^'"]+)\3/gm;
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

// Static imports of one module; throws on anything the published verifier must not load.
export function moduleImports(file, text) {
  if (/\bimport\s*\(/.test(text) || /\brequire\s*\(/.test(text)) throw Error(`${file}: dynamic import or require is not allowed in the verifier`);
  return [...text.matchAll(IMPORTS)].map(m => m[2] ?? m[4]).filter(spec => {
    if (spec.startsWith('node:')) {
      if (FORBIDDEN_BUILTINS.includes(spec.slice(5).split('/')[0])) throw Error(`${file} imports ${spec}: the verifier must not use the network or processes`);
      return false;
    }
    if (!/^\.\/[a-z0-9-]+\.mjs$/.test(spec)) throw Error(`${file} imports ${spec}: only node: built-ins and modules beside it can be published`);
    return true;
  }).map(spec => posix.join(posix.dirname(file), spec));
}
export function moduleClosure(entry = ENTRY) {
  const out = new Map(), queue = [entry];
  while (queue.length) {
    const file = queue.shift();
    if (out.has(file)) continue;
    if (!file.startsWith('src/') || lstatSync(join(root, file)).isSymbolicLink()) throw Error('Refusing to package ' + file);
    const bytes = readFileSync(join(root, file));
    out.set(file, bytes);
    queue.push(...moduleImports(file, bytes.toString('utf8')));
  }
  return new Map([...out].sort((a, b) => (a[0] < b[0] ? -1 : 1)));
}

// ustar with fixed owner, modes and mtime, entries in path order, so equal inputs give an equal tarball.
function tarEntry(path, data, mtime, mode) {
  const header = Buffer.alloc(512), dir = data === null, field = (value, offset, length) => header.write(value, offset, length, 'utf8');
  if (Buffer.byteLength(path) > 100) throw Error('Path too long for ustar: ' + path);
  const octal = (value, length) => value.toString(8).padStart(length - 1, '0') + '\0';
  field(path, 0, 100);
  field(octal(dir ? 0o755 : mode, 8), 100, 8);
  field(octal(0, 8), 108, 8);
  field(octal(0, 8), 116, 8);
  field(octal(dir ? 0 : data.length, 12), 124, 12);
  field(octal(mtime, 12), 136, 12);
  field('        ', 148, 8);
  field(dir ? '5' : '0', 156, 1);
  field('ustar\0', 257, 6);
  field('00', 263, 2);
  field(header.reduce((sum, b) => sum + b, 0).toString(8).padStart(6, '0') + '\0 ', 148, 8);
  return dir ? header : Buffer.concat([header, data, Buffer.alloc((512 - (data.length % 512)) % 512)]);
}
// entries: [path, bytes or null for a directory, mode].
export function tarGz(entries, mtime = 0) {
  const tar = Buffer.concat([...entries.map(([path, data, mode = 0o644]) => tarEntry(path, data, mtime, mode)), Buffer.alloc(1024)]);
  const gz = gzipSync(tar, {level: 9});
  gz[9] = 3; // gzip OS byte: the same on every build platform
  return gz;
}

export function packageVerifier({out = join(root, 'releases'), mtime = Number(process.env.SOURCE_DATE_EPOCH || 0)} = {}) {
  const version = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version;
  if (typeof version !== 'string' || !/^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$/.test(version)) throw Error('Root package.json version is invalid');
  if (!Number.isSafeInteger(mtime) || mtime < 0 || mtime >= 8 ** 11) throw Error('SOURCE_DATE_EPOCH must be a non-negative integer (seconds)');
  const base = `${NAME}-${version}`, dir = join(resolve(out), base), tarball = dir + '.tar.gz';
  for (const target of [dir, tarball, tarball + '.sha256']) if (existsSync(target)) throw Error(`Refusing to overwrite ${target}`);
  const readme = name => Buffer.from(readFileSync(join(root, 'deploy', 'verifier', name), 'utf8').replaceAll('{{version}}', version), 'utf8');
  const files = new Map([
    [`${NAME}.mjs`, Buffer.from(`#!/usr/bin/env node\n// EvidScope offline verifier ${version}: README.md (한국어), README.en.md (English).\n`
      + `import {main} from './${ENTRY}';\n\nprocess.exitCode = main(process.argv.slice(2));\n`)],
    ['package.json', Buffer.from(JSON.stringify({name: NAME, version, private: true,
      description: 'Offline verifier for EvidScope evidence: exports, case reports, DSSE in-toto attestations and c2sp.org/tlog-proof record receipts',
      type: 'module', bin: {[NAME]: `${NAME}.mjs`}, engines: {node: '>=24.15.0'}, license: 'UNLICENSED'}, null, 2) + '\n')],
    ['README.md', readme('README.md')], ['README.en.md', readme('README.en.md')], ...moduleClosure(),
  ]);
  const paths = [...files.keys()].sort();
  files.set('SHA256SUMS', Buffer.from(paths.map(p => `${sha256(files.get(p))}  ${p}\n`).join('')));
  const listing = [...files.keys()].sort(), dirs = [...new Set(listing.map(p => posix.dirname(p)).filter(d => d !== '.'))];
  const mode = p => (p === `${NAME}.mjs` ? 0o755 : 0o644);
  const gz = tarGz([[base + '/', null], ...dirs.map(d => [`${base}/${d}/`, null]), ...listing.map(p => [`${base}/${p}`, files.get(p), mode(p)])]
    .sort((a, b) => (a[0] < b[0] ? -1 : 1)), mtime);
  for (const p of listing) {
    mkdirSync(dirname(join(dir, p)), {recursive: true});
    writeFileSync(join(dir, p), files.get(p), {flag: 'wx', mode: mode(p)});
  }
  writeFileSync(tarball, gz, {flag: 'wx'});
  writeFileSync(tarball + '.sha256', `${sha256(gz)}  ${base}.tar.gz\n`, {flag: 'wx'});
  return {name: NAME, version, directory: dir, tarball, tarballSha256: sha256(gz),
    files: listing.map(p => ({path: p, sha256: sha256(files.get(p)), bytes: files.get(p).length}))};
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const {values} = parseArgs({options: {out: {type: 'string'}}});
    console.log(JSON.stringify(packageVerifier(values.out ? {out: values.out} : {}), null, 2));
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
