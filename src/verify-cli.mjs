// evidscope-verify: one offline verifier for EvidScope evidence (docs/receipts.md). It needs no network and no EvidScope
// installation; scripts/package-verifier.mjs publishes it with only the modules imported from here.
import {mkdirSync, readFileSync, statSync, writeFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {parseArgs} from 'node:util';
import {verifyBundle} from './crypto.mjs';
import {replayEvaluations} from './policy-replay.mjs';
import {unpackResponse, verifyAttestation, verifyRecordReceipt} from './receipts.mjs';
import {verifyCaseReport} from './report-verifier.mjs';
import {sha256Hex} from './dsse.mjs';
import {transparencyFlags, transparencyOptions} from './verify-options.mjs';

const MiB = 1024 * 1024;
export const USAGE = `Usage:
  evidscope-verify bundle EXPORT.json KEY.pem [CHECKPOINT.json] [--attestation EXPORT.json.intoto.json] [--replay] [--min-checkpoint FILE] [FLAGS]
  evidscope-verify report REPORT.json KEY.pem [CHECKPOINT.json] [--attestation REPORT.json.intoto.json] [FLAGS]
  evidscope-verify dsse ENVELOPE.intoto.json SUBJECT.json KEY.pem [CHECKPOINT.json] [--policy FILE.tlog-policy] [--require-witnessed] [FLAGS]
  evidscope-verify tlog-proof RECORD.tlog-proof RECORD.json (--policy FILE.tlog-policy | --key KEY.pem) [--key KEY.pem] [--witness VKEY]...
                   [--quorum N] [--origin-base BASE]
  evidscope-verify unpack RESPONSE.json [--out DIR]
FLAGS (transparency, opt-in): --witness VKEY (repeatable) --quorum N --origin-base BASE --max-staleness SECONDS
  --require-transparency --require-tenant-witness --heads-key VKEY (repeatable, the heads signer's key) --require-heads-signer
Exit status: 0 verified, 1 not verified, 2 usage error.`;

class UsageError extends Error {}
// Regular files only, with a size bound, so a FIFO or device cannot stall or exhaust the verifier.
function readBounded(path, max, what) {
  const st = statSync(path);
  if (!st.isFile()) throw Error(`${what} ${path} is not a regular file`);
  if (st.size > max) throw Error(`${what} ${path} exceeds ${Math.round(max / MiB)} MiB`);
  return readFileSync(path);
}
const readJson = (path, max, what) => {
  try { return JSON.parse(readBounded(path, max, what).toString('utf8')); } catch (error) {
    throw error instanceof SyntaxError ? Error(`${what} ${path} is not JSON`) : error;
  }
};
const readKey = path => readBounded(path, 64 * 1024, 'Key file').toString('utf8');
const parse = (args, options, max) => {
  try {
    const r = parseArgs({args, allowPositionals: true, strict: true, options});
    if (r.positionals.length > max) throw new UsageError('Too many arguments');
    return r;
  } catch (error) { throw error instanceof UsageError ? error : new UsageError(error.message); }
};
// Every required argument is checked before any file is read, so a short command line is a usage error.
const need = (values, names) => names.forEach((what, i) => { if (!values[i]) throw new UsageError(`Missing ${what}`); });
const checkpointFile = path => (path ? readJson(path, MiB, 'Checkpoint file') : undefined);

function attestationFor(values, subjectBytes, key, transparency) {
  if (!values.attestation) return undefined;
  const envelope = readJson(values.attestation, 64 * MiB, 'Attestation');
  return verifyAttestation({envelope, subject: subjectBytes, publicKey: key, options: {...(transparency ? {transparency} : {})}});
}
function bundleCommand(args) {
  const {values, positionals: [file, keyPath, checkpointPath]} = parse(args, {...transparencyFlags, 'min-checkpoint': {type: 'string'},
    replay: {type: 'boolean'}, attestation: {type: 'string'}}, 3);
  need([file, keyPath], ['EXPORT.json', 'KEY.pem']);
  const bytes = readBounded(file, 512 * MiB, 'Export'), key = readKey(keyPath);
  const bundle = JSON.parse(bytes.toString('utf8')), transparency = transparencyOptions(values, bundle.transparency !== undefined);
  const result = verifyBundle(bundle, key, checkpointFile(checkpointPath), transparency ? {transparency} : {});
  const replay = values.replay ? replayEvaluations(bundle) : undefined, attestation = attestationFor(values, bytes, key, transparency);
  return {ok: !replay || replay.valid, output: {...result, ...(replay ? {replay} : {}), ...(attestation ? {attestation} : {})}};
}
function reportCommand(args) {
  const {values, positionals: [file, keyPath, checkpointPath]} = parse(args, {...transparencyFlags, attestation: {type: 'string'}}, 3);
  need([file, keyPath], ['REPORT.json', 'KEY.pem']);
  const bytes = readBounded(file, 20 * MiB, 'Report'), key = readKey(keyPath);
  const report = JSON.parse(bytes.toString('utf8')), transparency = transparencyOptions(values, report?.transparency !== undefined);
  const result = verifyCaseReport(report, key, {expectedCheckpoint: checkpointFile(checkpointPath), ...(transparency ? {transparency} : {})});
  const attestation = attestationFor(values, bytes, key, transparency);
  return {ok: true, output: {...result, ...(attestation ? {attestation} : {})}};
}
function dsseCommand(args) {
  const {values, positionals: [envelopePath, subjectPath, keyPath, checkpointPath]} = parse(args, {...transparencyFlags,
    'min-checkpoint': {type: 'string'}, policy: {type: 'string'}, 'require-witnessed': {type: 'boolean'}}, 4);
  need([envelopePath, subjectPath, keyPath], ['ENVELOPE.intoto.json', 'SUBJECT', 'KEY.pem']);
  const envelope = readJson(envelopePath, 64 * MiB, 'Attestation'), subject = readBounded(subjectPath, 512 * MiB, 'Subject'), key = readKey(keyPath);
  // Without flags, verifyAttestation still checks transparency material the subject carries.
  const transparency = transparencyOptions(values, false), policy = values.policy ? readBounded(values.policy, 64 * 1024, 'Policy') : undefined;
  return {ok: true, output: verifyAttestation({envelope, subject, publicKey: key, options: {...(transparency ? {transparency} : {}),
    expectedCheckpoint: checkpointFile(checkpointPath), ...(policy ? {policy} : {}), requireWitnessed: !!values['require-witnessed']}})};
}
function tlogProofCommand(args) {
  const {values, positionals: [proofPath, recordPath]} = parse(args, {policy: {type: 'string'}, key: {type: 'string'},
    witness: {type: 'string', multiple: true}, quorum: {type: 'string'}, 'origin-base': {type: 'string'}}, 2);
  need([proofPath, recordPath], ['RECORD.tlog-proof', 'RECORD.json']);
  if (!values.policy && !values.key) throw new UsageError('Pass --policy FILE.tlog-policy or --key KEY.pem');
  if (values.policy && (values.witness || values.quorum !== undefined)) throw new UsageError('--witness and --quorum build a policy; omit --policy');
  if (values.quorum !== undefined && !/^(0|[1-9][0-9]{0,2})$/.test(values.quorum)) throw new UsageError('--quorum must be a small non-negative integer');
  const quorum = values.quorum === undefined ? undefined : Number(values.quorum);
  const proof = readBounded(proofPath, MiB, 'Proof').toString('utf8'), record = readBounded(recordPath, 16 * MiB, 'Record');
  return {ok: true, output: verifyRecordReceipt({proof, record, policy: values.policy ? readBounded(values.policy, 64 * 1024, 'Policy') : undefined,
    publicKey: values.key ? readKey(values.key) : undefined, witnesses: values.witness || [], quorum, originBase: values['origin-base']})};
}
// Writes the files of an API response; never overwrites, and names come from a fixed safe pattern.
function unpackCommand(args) {
  const {values, positionals: [file]} = parse(args, {out: {type: 'string'}}, 1);
  need([file], ['RESPONSE.json']);
  const files = unpackResponse(readJson(file, 512 * MiB, 'Response')), dir = resolve(values.out || '.');
  mkdirSync(dir, {recursive: true});
  const written = files.map(f => {
    writeFileSync(join(dir, f.name), f.bytes, {flag: 'wx'});
    return {file: join(dir, f.name), sha256: sha256Hex(f.bytes), bytes: f.bytes.length};
  });
  return {ok: true, output: {unpacked: written, note: 'Unpacking checks nothing but the file digest; run dsse or tlog-proof on the files.'}};
}
const COMMANDS = {bundle: bundleCommand, report: reportCommand, dsse: dsseCommand, 'tlog-proof': tlogProofCommand, unpack: unpackCommand};

// Returns the exit status: 0 verified, 1 not verified, 2 usage error.
export function main(argv, {stdout = process.stdout, stderr = process.stderr} = {}) {
  const [command, ...args] = argv;
  if (!command || command === 'help' || command === '--help' || command === '-h') {
    (command ? stdout : stderr).write(USAGE + '\n');
    return command ? 0 : 2;
  }
  try {
    const run = COMMANDS[command];
    if (!run) throw new UsageError('Unknown command ' + command);
    const {ok, output} = run(args);
    stdout.write(JSON.stringify(output, null, 2) + '\n');
    return ok ? 0 : 1;
  } catch (error) {
    stderr.write((error instanceof UsageError ? `${error.message}\n${USAGE}` : error.message) + '\n');
    return error instanceof UsageError ? 2 : 1;
  }
}
