// Builds an auditor evidence package (docs/evidence-pack.md) after verifying its evidence with the checks of scripts/verify.mjs
// (signature, chain, transparency, signed histories, replay); nothing is written unless every check and the package's own
// verification pass. `verify` is evidscope-verify pack.
//   node scripts/evidence-pack.mjs build --framework eu-ai-act-logging|kr-ai-basic-act|isms-p --tenant T --key VAULT_PUBLIC.pem
//     (--signing-key BUILDER_PRIVATE.pem | (--signer-socket PATH | --signer-url URL [--signer-token-file FILE] [--signer-ca CA.pem])
//       --signer-public-key SIGNER_PUBLIC.pem) --out DIR|FILE.tar.gz (--export EXPORT.json [--attestation FILE] | --api URL --token-file FILE)
//     [--case-report REPORT.json]... [--case ID]... [--from ISO --to ISO [--period-only]] [--checkpoint CHECKPOINT.json] [transparency flags]
// --period-only carries only the ledger range of the period, each record with its receipt (docs/evidence-pack.md); without it the
// package carries the whole export. --signer-*: sign through a signer process started with --sign-pack-statements (docs/signer.md).
//   node scripts/evidence-pack.mjs verify PACK KEY.pem [CHECKPOINT.json] [--pack-key BUILDER_PUBLIC.pem] [--tenant T] [--mapping-from-pack]
// --export and --case-report accept the plain file or the vault's ?attest=intoto response. --api reads both with an auditor token
// from the file (or EVIDSCOPE_AUDITOR_TOKEN); tokens are sent only over https or to a loopback address.
// Exit status: 0 built (or verified), 1 not built, 2 usage error.
import {existsSync, mkdirSync, readFileSync, statSync, writeFileSync} from 'node:fs';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {parseArgs} from 'node:util';
import {attestationSigner} from '../src/attestation-signer.mjs';
import {createSignerClient, readSignerToken, statementSigner} from '../src/signer-client.mjs';
import {sha256Hex} from '../src/dsse.mjs';
import {attestedInput, buildPack, FILES, TAR_ROOT, verifyEvidence, verifyPack} from '../src/evidence-pack.mjs';
import {FRAMEWORKS} from '../src/evidence-pack-frameworks.mjs';
import {main as verifyMain} from '../src/verify-cli.mjs';
import {transparencyFlags, transparencyUsage} from '../src/verify-options.mjs';
import {tarGz} from './package-verifier.mjs';

class UsageError extends Error {}
const MiB = 1024 * 1024;
const readFile = (path, max, what) => {
  const st = statSync(path);
  if (!st.isFile() || st.size > max) throw Error(`${what} ${path} is not a regular file of at most ${max / MiB} MiB`);
  return readFileSync(path);
};
const OPTIONS = {...transparencyFlags, 'min-checkpoint': {type: 'string'}, framework: {type: 'string'}, tenant: {type: 'string'},
  key: {type: 'string'}, 'signing-key': {type: 'string'}, out: {type: 'string'}, export: {type: 'string'}, attestation: {type: 'string'},
  api: {type: 'string'}, 'token-file': {type: 'string'}, 'case-report': {type: 'string', multiple: true}, case: {type: 'string', multiple: true},
  from: {type: 'string'}, to: {type: 'string'}, checkpoint: {type: 'string'}, 'period-only': {type: 'boolean'}, 'signer-socket': {type: 'string'},
  'signer-url': {type: 'string'}, 'signer-token-file': {type: 'string'}, 'signer-ca': {type: 'string'}, 'signer-public-key': {type: 'string'}};

// The package signer: the builder's PEM key, or a signer process whose public key the builder pins (src/signer-client.mjs).
function packSigner(values, connect = createSignerClient) {
  const remote = values['signer-socket'] ?? values['signer-url'];
  if (!!values['signing-key'] === (remote !== undefined) || (values['signer-socket'] && values['signer-url'])) {
    throw new UsageError('Pass exactly one of --signing-key FILE, --signer-socket PATH or --signer-url URL');
  }
  if (values['signing-key']) return attestationSigner(readFile(values['signing-key'], 64 * 1024, 'Signing key').toString('utf8'));
  if (!values['signer-public-key']) throw new UsageError('--signer-socket and --signer-url need --signer-public-key SIGNER_PUBLIC.pem');
  const url = values['signer-url'];
  if (url !== undefined && !/^https:\/\//.test(url) && !/^http:\/\/(127\.0\.0\.1|localhost|\[::1\])(:\d+)?\/?$/.test(url)) {
    throw new UsageError('--signer-url must be https (plain http only to a loopback address)');
  }
  const client = connect({...(values['signer-socket'] ? {socket: resolve(values['signer-socket'])} : {url}),
    token: values['signer-token-file'] ? readSignerToken(resolve(values['signer-token-file'])) : null,
    ca: values['signer-ca'] ? readFile(values['signer-ca'], 64 * 1024, 'Signer CA') : null});
  return statementSigner(client, readFile(values['signer-public-key'], 64 * 1024, 'Signer public key').toString('utf8'));
}

// A JSON GET with the auditor token; refuses plain http except to loopback, so the token never crosses a network in clear.
export async function apiGet(base, path, token, fetchImpl = fetch) {
  const url = new URL(path, base.endsWith('/') ? base : base + '/');
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname))) {
    throw Error('--api must be https (plain http only to a loopback address)');
  }
  const response = await fetchImpl(url, {headers: {authorization: 'Bearer ' + token, accept: 'application/json'}, redirect: 'error'});
  if (Number(response.headers?.get?.('content-length')) > 512 * MiB) throw Error(`GET ${url.pathname} announces more than 512 MiB`);
  const bytes = Buffer.from(await response.arrayBuffer());
  if (!response.ok) throw Error(`GET ${url.pathname} answered ${response.status}`);
  if (bytes.length > 512 * MiB) throw Error(`GET ${url.pathname} answered more than 512 MiB`);
  return bytes;
}

async function inputs(values, fetchImpl) {
  if (!!values.export === !!values.api) throw new UsageError('Pass exactly one of --export FILE or --api URL');
  const caseReports = (values['case-report'] || []).map(path => attestedInput(readFile(path, 20 * MiB, 'Case report'), 'Case report ' + path));
  if (values.export) {
    if (values.case) throw new UsageError('--case reads from --api; with --export pass --case-report FILE');
    const exported = attestedInput(readFile(values.export, 512 * MiB, 'Export'), 'Export');
    if (values.attestation) {
      if (exported.attestation) throw new UsageError('--export is already an attested response; omit --attestation');
      exported.attestation = JSON.parse(readFile(values.attestation, 64 * MiB, 'Attestation').toString('utf8'));
    }
    return {exported, caseReports};
  }
  const token = (values['token-file'] ? readFile(values['token-file'], 64 * 1024, 'Token file').toString('utf8') : process.env.EVIDSCOPE_AUDITOR_TOKEN ?? '')
    .trim();
  if (!token) throw new UsageError('--api needs --token-file FILE or EVIDSCOPE_AUDITOR_TOKEN');
  const exported = attestedInput(await apiGet(values.api, 'api/export?attest=intoto', token, fetchImpl), 'Export response');
  for (const id of values.case || []) {
    caseReports.push(attestedInput(await apiGet(values.api, `api/cases/${encodeURIComponent(id)}/report?attest=intoto`, token, fetchImpl), 'Case ' + id));
  }
  return {exported, caseReports};
}

function write(out, files) {
  const target = resolve(out);
  if (existsSync(target)) throw Error(`Refusing to overwrite ${target}`);
  if (target.endsWith('.tar.gz')) {
    const paths = [...files.keys()].sort(), dirs = [...new Set(paths.flatMap(p => p.split('/').slice(0, -1).map((_, i, a) => a.slice(0, i + 1).join('/'))))];
    const gz = tarGz([[TAR_ROOT + '/', null], ...dirs.map(d => [`${TAR_ROOT}/${d}/`, null]), ...paths.map(p => [`${TAR_ROOT}/${p}`, files.get(p)])]
      .sort((a, b) => (a[0] < b[0] ? -1 : 1)));
    writeFileSync(target, gz, {flag: 'wx'});
    return {file: target, sha256: sha256Hex(gz)};
  }
  mkdirSync(target, {recursive: false});
  for (const [path, bytes] of files) {
    mkdirSync(dirname(join(target, path)), {recursive: true});
    writeFileSync(join(target, path), bytes, {flag: 'wx'});
  }
  return {directory: target};
}

export async function build(argv, {fetchImpl = fetch, now = new Date(), connect} = {}) {
  let parsed;
  try { parsed = parseArgs({args: argv, options: OPTIONS, strict: true, allowPositionals: false}); } catch (error) { throw new UsageError(error.message); }
  const {values} = parsed, usage = transparencyUsage(values);
  if (usage) throw new UsageError(usage);
  for (const name of ['framework', 'tenant', 'key', 'out']) if (!values[name]) throw new UsageError('Missing --' + name);
  if (!FRAMEWORKS.includes(values.framework)) throw new UsageError('--framework must be one of ' + FRAMEWORKS.join(', '));
  if (!!values.from !== !!values.to) throw new UsageError('Pass --from and --to together');
  if (values['period-only'] && !values.from) throw new UsageError('--period-only needs --from and --to');
  if (existsSync(resolve(values.out))) throw Error(`Refusing to overwrite ${resolve(values.out)}`);
  const publicKey = readFile(values.key, 64 * 1024, 'Key file').toString('utf8'), signer = packSigner(values, connect);
  const checkpoint = values.checkpoint ? JSON.parse(readFile(values.checkpoint, MiB, 'Checkpoint').toString('utf8')) : undefined;
  const {exported, caseReports} = await inputs(values, fetchImpl);
  // Refuses anything that does not verify, before a single file is written.
  const evidence = verifyEvidence({exportBytes: exported.bytes, exportAttestation: exported.attestation, caseReports, publicKey, checkpoint, flags: values});
  const {files, index} = await buildPack({evidence, framework: values.framework, tenant: values.tenant, signer, now,
    period: values.from ? {from: values.from, to: values.to} : null, periodOnly: !!values['period-only']});
  // The package must verify as an auditor would check it (builder key, same trust inputs) before it is written.
  verifyPack(files, {publicKey, packKey: signer.publicKey, checkpoint, flags: values});
  const written = write(values.out, files);
  return {built: written, framework: values.framework, packageScope: index.scope.kind, tenant: index.scope.tenant, period: index.scope.period,
    counts: index.counts, builderKeyid: signer.keyid, signedBy: values['signing-key'] ? 'signing_key_file' : 'signer_process', statement: FILES.envelope,
    files: [...files.keys()].sort().map(path => ({path, sha256: sha256Hex(files.get(path))})),
    note: 'Give the auditor the builder public key and the vault public key separately from the package.'};
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [command, ...args] = process.argv.slice(2);
  if (command === 'verify') process.exitCode = verifyMain(['pack', ...args]);
  else if (command !== 'build') {
    console.error('Usage: node scripts/evidence-pack.mjs build ... | verify PACK KEY.pem ... (see the header of this file)');
    process.exitCode = 2;
  } else {
    try {
      console.log(JSON.stringify(await build(args), null, 2));
    } catch (error) {
      console.error(error.message);
      process.exitCode = error instanceof UsageError ? 2 : 1;
    }
  }
}
