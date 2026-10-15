// scripts/package-verifier.mjs builds the separately published verifier. The first test checks what it builds: manifest,
// dependency-free package.json, import closure and a reproducible tarball. The second runs the verifier unpacked from that
// tarball in an isolated temporary directory: Node's permission model lets it read only the package and the evidence (not the
// repository or the vault data), a preloaded guard ends the process on any network use, and the environment is empty.
import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {createHash, generateKeyPairSync} from 'node:crypto';
import {mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, posix, relative, sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {gunzipSync} from 'node:zlib';
import {moduleImports, packageVerifier} from '../scripts/package-verifier.mjs';
import {canonical} from '../src/crypto.mjs';
import {unpackResponse} from '../src/receipts.mjs';
import {formatTlogPolicy} from '../src/tlog-policy.mjs';
import {SIG_COSIG_ED25519, ed25519RawPublic, logVkey, vkeyString} from '../src/tlog.mjs';
import {BASE} from './support/transparency-fixture.mjs';
import {receiptFixture} from './support/receipt-fixture.mjs';

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const repo = fileURLToPath(new URL('..', import.meta.url));
// node:zlib reads .tar.gz evidence packages (docs/evidence-pack.md).
const BUILTINS = ['node:crypto', 'node:fs', 'node:path', 'node:util', 'node:zlib'];
const walk = (dir, base = dir) => readdirSync(dir, {withFileTypes: true})
  .flatMap(e => (e.isDirectory() ? walk(join(dir, e.name), base) : [relative(base, join(dir, e.name)).split(sep).join('/')])).sort();
// A minimal ustar reader written independently of the packager; header checksums are checked.
function untar(gz) {
  const tar = gunzipSync(gz), entries = new Map();
  for (let offset = 0; offset + 512 <= tar.length;) {
    const h = tar.subarray(offset, offset + 512);
    if (h.every(b => b === 0)) break;
    const text = (from, to) => h.subarray(from, to).toString('utf8').replace(/\0[\s\S]*$/, '');
    const size = parseInt(text(124, 136), 8);
    assert.equal(h.reduce((sum, b, i) => sum + (i >= 148 && i < 156 ? 32 : b), 0), parseInt(text(148, 156), 8), 'tar header checksum');
    assert.equal(text(257, 263), 'ustar');
    entries.set(text(0, 100), {type: text(156, 157), mode: parseInt(text(100, 108), 8), mtime: parseInt(text(136, 148), 8),
      data: Buffer.from(tar.subarray(offset + 512, offset + 512 + size))});
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  return entries;
}
// Ends the process with status 97 on any attempt to use the network; loaded with --import before the verifier.
const GUARD = 'data:text/javascript,' + encodeURIComponent([
  "import {syncBuiltinESMExports} from 'node:module';",
  "import net from 'node:net'; import tls from 'node:tls'; import dns from 'node:dns'; import dgram from 'node:dgram';",
  "import http from 'node:http'; import https from 'node:https'; import http2 from 'node:http2';",
  "const stop = what => function () { process.stderr.write('NETWORK BLOCKED: ' + what + '\\n'); process.exit(97); };",
  "const block = (name, target, keys) => { for (const k of keys) target[k] = stop(name + '.' + k); };",
  "block('net', net, ['connect', 'createConnection', 'createServer']); block('net.Socket', net.Socket.prototype, ['connect']);",
  "block('net.Server', net.Server.prototype, ['listen']); block('tls', tls, ['connect', 'createServer']);",
  "block('http', http, ['request', 'get', 'createServer']); block('https', https, ['request', 'get', 'createServer']);",
  "block('http2', http2, ['connect', 'createServer', 'createSecureServer']); block('dgram', dgram, ['createSocket']);",
  "const lookups = ['lookup', 'lookupService', 'resolve', 'resolve4', 'resolve6', 'resolveAny', 'resolveTxt'];",
  "block('dns', dns, lookups); block('dns.promises', dns.promises, lookups);",
  "block('global', globalThis, ['fetch', 'WebSocket', 'EventSource'].filter(k => k in globalThis));",
  'syncBuiltinESMExports();',
].join('\n'));
const sandbox = ({read = [], write = []}) => ['--permission', ...read.map(p => '--allow-fs-read=' + p), ...write.map(p => '--allow-fs-write=' + p),
  '--import', GUARD];
const node = (args, cwd) => {
  // An empty environment; Windows keeps SystemRoot, without which some system libraries do not load.
  const env = process.platform === 'win32' ? {SystemRoot: process.env.SystemRoot} : {};
  const r = spawnSync(process.execPath, args, {cwd, env, encoding: 'utf8', windowsHide: true});
  return {status: r.status, out: r.stdout.trim().startsWith('{') ? JSON.parse(r.stdout) : r.stdout, err: r.stderr};
};

test('package-verifier builds a dependency-free, reproducible verifier folder and tarball with a SHA-256 manifest', t => {
  const dir = mkdtempSync(join(tmpdir(), 'evidscope-verifier-pkg-'));
  t.after(() => rmSync(dir, {recursive: true, force: true}));
  // Built twice, once through the CLI (--allow-dirty: the tests run on working trees), the tarball is the same.
  const a = packageVerifier({out: join(dir, 'a')}), base = `${a.name}-${a.version}`;
  const cli = spawnSync(process.execPath, [join(repo, 'scripts', 'package-verifier.mjs'), '--out', join(dir, 'b'), '--allow-dirty'], {encoding: 'utf8'});
  assert.equal(cli.status, 0, cli.stderr);
  const b = JSON.parse(cli.stdout);
  assert.equal(a.tarballSha256, b.tarballSha256, 'the same sources give the same tarball');
  assert.ok(readFileSync(b.tarball).equals(readFileSync(a.tarball)));
  assert.equal(sha256(readFileSync(a.tarball)), a.tarballSha256);
  assert.equal(readFileSync(a.tarball + '.sha256', 'utf8'), `${a.tarballSha256}  ${base}.tar.gz\n`);
  assert.throws(() => packageVerifier({out: join(dir, 'a')}), /Refusing to overwrite/);

  const files = walk(a.directory), read = p => readFileSync(join(a.directory, p));
  const pkg = JSON.parse(read('package.json'));
  for (const k of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies', 'bundleDependencies', 'bundledDependencies', 'scripts']) {
    assert.equal(pkg[k], undefined, k);
  }
  assert.deepEqual([pkg.name, pkg.version, pkg.type, pkg.bin], ['evidscope-verify', JSON.parse(readFileSync(join(repo, 'package.json'))).version, 'module',
    {'evidscope-verify': 'evidscope-verify.mjs'}]);
  for (const readme of ['README.md', 'README.en.md']) assert.ok(read(readme).includes(a.version) && !read(readme).includes('{{'), readme);
  assert.match(read('README.md').toString(), /오프라인 검증기/);
  assert.match(read('README.en.md').toString(), /offline verifier/);
  // SHA256SUMS (sha256sum -c format) lists exactly every other file with its digest.
  const sums = read('SHA256SUMS').toString().trimEnd().split('\n').map(line => /^([0-9a-f]{64}) {2}(\S+)$/.exec(line).slice(1));
  assert.deepEqual(sums.map(([, p]) => p), files.filter(p => p !== 'SHA256SUMS'));
  for (const [digest, p] of sums) assert.equal(sha256(read(p)), digest, p);
  // Only the src modules the entry reaches, each importing a few node: built-ins (none with network or process access) or
  // other files of the package; nothing loads code dynamically or reaches for the network through globals.
  assert.deepEqual(files.filter(p => p.startsWith('src/')), a.files.map(f => f.path).filter(p => p.startsWith('src/')));
  assert.ok(files.includes('src/verify-cli.mjs') && !files.includes('src/service.mjs') && !files.includes('src/store.mjs'));
  // The mappings of evidence packages read these data files beside src/, as in the repository, and every shipped mapping version.
  assert.deepEqual(files.filter(p => p.startsWith('data/')), [...['eu-ai-act-logging', 'isms-p', 'kr-ai-basic-act'].flatMap(id => [1, 2, 3, 4]
    .map(v => `data/evidence-pack-mappings/${id}-v${v}.json`)), 'data/isms-p-alignment.json', 'data/requirements.json']);
  for (const p of files.filter(f => f.endsWith('.mjs'))) {
    const text = read(p).toString();
    assert.doesNotMatch(text, /\bimport\s*\(|\brequire\s*\(|\bfetch\s*\(|WebSocket|process\.(binding|dlopen)|createRequire/, p);
    for (const [, spec] of text.matchAll(/(?:\bfrom|^import)\s*['"]([^'"]+)['"]/gm)) {
      if (spec.startsWith('node:')) assert.ok(BUILTINS.includes(spec), `${p} imports ${spec}`);
      else assert.ok(spec.startsWith('./') && files.includes(posix.join(posix.dirname(p), spec)), `${p} imports ${spec}`);
    }
  }
  assert.match(read('evidscope-verify.mjs').toString(), /^#!\/usr\/bin\/env node\n[^\n]*\nimport \{main\} from '\.\/src\/verify-cli\.mjs';\n/);
  // The tarball holds the folder, byte for byte, under one top directory, with fixed owner and time.
  const entries = untar(readFileSync(a.tarball));
  assert.deepEqual([...entries.keys()].filter(k => entries.get(k).type === '0'), files.map(p => `${base}/${p}`));
  for (const p of files) assert.ok(entries.get(`${base}/${p}`).data.equals(read(p)), p);
  assert.ok([...entries.values()].every(e => e.mtime === 0));
  assert.deepEqual([entries.get(`${base}/evidscope-verify.mjs`).mode, entries.get(`${base}/src/tlog.mjs`).mode], [0o755, 0o644]);
  const x = join(dir, 'tar-x');
  mkdirSync(x);
  const tar = spawnSync('tar', ['-xzf', a.tarball, '-C', x], {encoding: 'utf8'});
  if (tar.error?.code === 'ENOENT') t.diagnostic('system tar not found; extraction by tar(1) not checked');
  else {
    assert.equal(tar.status, 0, tar.stderr);
    assert.deepEqual(walk(join(x, base)), files);
    for (const p of files) assert.ok(readFileSync(join(x, base, p)).equals(read(p)), p);
  }
  // The closure check refuses what the published verifier must not load.
  assert.throws(() => moduleImports('src/x.mjs', "import net from 'node:net';\n"), /network or processes/);
  assert.throws(() => moduleImports('src/x.mjs', "import {spawn} from 'node:child_process';\n"), /network or processes/);
  assert.throws(() => moduleImports('src/x.mjs', "const m = await import('./y.mjs');\n"), /dynamic import/);
  assert.throws(() => moduleImports('src/x.mjs', "import {Issuer} from 'openid-client';\n"), /only node: built-ins/);
  assert.throws(() => moduleImports('src/x.mjs', "export {a} from '../scripts/a.mjs';\n"), /only node: built-ins/);
  assert.deepEqual(moduleImports('src/x.mjs', "import {\n  a,\n} from './y.mjs';\nexport * from './z.mjs';\nimport 'node:fs';\n"), ['src/y.mjs', 'src/z.mjs']);
});

test('the packaged verifier runs isolated from the repository and the network and refuses tampered evidence', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'evidscope-verifier-iso-'));
  t.after(() => rmSync(dir, {recursive: true, force: true}));
  const built = packageVerifier({out: join(dir, 'build')}), pkg = join(dir, 'unpacked', `${built.name}-${built.version}`);
  for (const [name, e] of untar(readFileSync(built.tarball))) {
    if (e.type === '5') mkdirSync(join(dir, 'unpacked', name), {recursive: true});
    else writeFileSync(join(dir, 'unpacked', name), e.data);
  }
  const x = await receiptFixture(t, join(dir, 'responses')), ev = join(dir, 'evidence'), cwd = join(dir, 'cwd'), bad = join(dir, 'bad');
  for (const d of [ev, cwd, bad]) mkdirSync(d);
  const verify = (args, {read = [ev], write = []} = {}) => node([...sandbox({read: [pkg, ...read], write}), join(pkg, 'evidscope-verify.mjs'), ...args], cwd);

  // The packaged verifier writes the files of the saved API responses itself.
  for (const name of ['export', 'report', 'record']) {
    const r = verify(['unpack', x.files[name], '--out', ev], {read: [join(dir, 'responses')], write: [ev]});
    assert.equal(r.status, 0, r.err);
    for (const f of unpackResponse(x.responses[name])) assert.ok(readFileSync(join(ev, f.name)).equals(f.bytes), f.name);
  }
  writeFileSync(join(ev, 'vault.pem'), readFileSync(x.files.key));
  const e = name => join(ev, name), exp = x.responses.export.file.name, rep = x.responses.report.file.name;
  const rec = readdirSync(ev).find(n => n.endsWith('.tlog-proof')).slice(0, -'.tlog-proof'.length), key = e('vault.pem');

  let r = verify(['dsse', e(exp + '.intoto.json'), e(exp), key, ...x.flags, '--require-witnessed', '--require-tenant-witness']);
  assert.equal(r.status, 0, r.err);
  assert.deepEqual([r.out.valid, r.out.witnessed, r.out.subject.sha256, r.out.bundle.transparency.rollbackCheckedAgainst],
    [true, true, x.responses.export.file.sha256, 'signing_key_holder']);
  r = verify(['dsse', e(rep + '.intoto.json'), e(rep), key, ...x.flags, '--require-witnessed']);
  assert.deepEqual([r.status, r.out.valid, r.out.report?.caseId], [0, true, x.caseId], r.err);
  r = verify(['tlog-proof', e(rec + '.tlog-proof'), e(rec + '.json'), '--policy', e(rec + '.tlog-policy'), '--key', key, '--origin-base', BASE]);
  assert.deepEqual([r.status, r.out.seq, r.out.witnessed, r.out.quorumMet], [0, 1, true, true], r.err);
  r = verify(['bundle', e(exp), key, ...x.flags, '--replay', '--attestation', e(exp + '.intoto.json')]);
  assert.deepEqual([r.status, r.out.valid, r.out.replay?.valid, r.out.attestation?.valid], [0, true, true, true], r.err);
  r = verify(['report', e(rep), key, '--attestation', e(rep + '.intoto.json')]);
  assert.deepEqual([r.status, r.out.attestation?.valid], [0, true], r.err);

  // Tampered evidence: exit status 1 and the reason on standard error.
  const tampered = (name, bytes) => { writeFileSync(join(bad, name), bytes); return join(bad, name); };
  const refused = (args, pattern, what) => {
    const result = verify(args, {read: [ev, bad]});
    assert.equal(result.status, 1, `${what}: ${result.err}`);
    assert.match(result.err, pattern, what);
    assert.doesNotMatch(result.err, /NETWORK BLOCKED|ERR_ACCESS_DENIED/, what);
  };
  const exportText = readFileSync(e(exp), 'utf8'), envelope = JSON.parse(readFileSync(e(exp + '.intoto.json'), 'utf8'));
  const flipped = exportText.replace('"seq":2,', '"seq":3,');
  assert.notEqual(flipped, exportText);
  refused(['dsse', e(exp + '.intoto.json'), tampered('export.json', flipped), key], /digest is not the subject/, 'export byte');
  refused(['bundle', join(bad, 'export.json'), key], /./, 'export byte, plain bundle check');
  const statement = JSON.parse(Buffer.from(envelope.payload, 'base64'));
  // issuedAt is the one predicate field not recomputed from the subject, so only the signature protects it.
  statement.predicate.issuedAt = '2000-01-01T00:00:00.000Z';
  const payload = Buffer.from(JSON.stringify(statement)).toString('base64');
  assert.notEqual(payload, envelope.payload);
  refused(['dsse', tampered('payload.intoto.json', JSON.stringify({...envelope, payload})), e(exp), key], /signature verification failed/, 'envelope payload');
  const other = generateKeyPairSync('ed25519'), otherPem = tampered('other.pem', other.publicKey.export({format: 'pem', type: 'spki'}));
  refused(['dsse', e(exp + '.intoto.json'), e(exp), otherPem], /signature verification failed/, 'another pinned key');
  const reportText = readFileSync(e(rep), 'utf8'), retitled = reportText.replace('"title":"receipt case"', '"title":"receipt casf"');
  assert.notEqual(retitled, reportText);
  refused(['dsse', e(rep + '.intoto.json'), tampered('report.json', retitled), key], /digest is not the subject/, 'report byte');
  refused(['dsse', e(exp + '.intoto.json'), e(exp), key, '--require-witnessed'], /No embedded tlog-proof meets the witness quorum/, 'no witness pinned');
  const record = readFileSync(e(rec + '.json'), 'utf8'), proof = readFileSync(e(rec + '.tlog-proof'), 'utf8');
  const proofArgs = (p, rcd, ...rest) => ['tlog-proof', p, rcd, ...rest];
  const changed = JSON.parse(record);
  changed.type += '-changed';
  refused(proofArgs(e(rec + '.tlog-proof'), tampered('record.json', canonical(changed)), '--policy', e(rec + '.tlog-policy')), /inclusion proof failed/,
    'record content');
  refused(proofArgs(e(rec + '.tlog-proof'), tampered('spaced.json', record.replace('{', '{ ')), '--policy', e(rec + '.tlog-policy')),
    /exact ledger record body/, 'record bytes not canonical');
  const lines = proof.split('\n'), hashLine = lines.findIndex((l, i) => i > 1 && /^[A-Za-z0-9+/]{43}=$/.test(l));
  assert.ok(hashLine > 1, 'the proof has at least one hash');
  lines[hashLine] = (lines[hashLine][0] === 'A' ? 'B' : 'A') + lines[hashLine].slice(1);
  refused(proofArgs(tampered('proof.tlog-proof', lines.join('\n')), e(rec + '.json'), '--policy', e(rec + '.tlog-policy')), /inclusion proof failed/,
    'proof hash');
  const origin = x.responses.record.origin;
  const strangerLog = formatTlogPolicy({logs: [logVkey(origin, other.publicKey)], witnesses: [{name: 'w', vkey: x.f.w.vkey}], quorum: 'w'});
  refused(proofArgs(e(rec + '.tlog-proof'), e(rec + '.json'), '--policy', tampered('stranger.tlog-policy', strangerLog)), /not signed by a policy log/,
    'policy with another log key');
  refused(proofArgs(e(rec + '.tlog-proof'), e(rec + '.json'), '--policy', e(rec + '.tlog-policy'), '--key', otherPem), /not the pinned vault key/,
    'policy log key differs from the pinned key');
  const stranger = vkeyString('witness.stranger.test', SIG_COSIG_ED25519, ed25519RawPublic(generateKeyPairSync('ed25519').publicKey));
  refused(proofArgs(e(rec + '.tlog-proof'), e(rec + '.json'), '--key', key, '--witness', stranger, '--quorum', '1'),
    /quorum .* is not met/, 'unrelated witness');

  // Controls: the sandbox really denies the repository, and the guard really stops network use.
  const outside = verify(['bundle', join(repo, 'package.json'), key]);
  assert.equal(outside.status, 1);
  assert.match(outside.err, /restricted|ERR_ACCESS_DENIED/);
  for (const code of ["await fetch('http://127.0.0.1:9/')", "import {connect} from 'node:net'; connect(9, '127.0.0.1');",
    "import dns from 'node:dns'; dns.lookup('example.com', () => {});"]) {
    const blocked = node([...sandbox({}), '--input-type=module', '-e', code], cwd);
    assert.deepEqual([blocked.status, /NETWORK BLOCKED/.test(blocked.err)], [97, true], code);
  }
});
