// evidscope-verify (src/verify-cli.mjs), the --attestation option of the existing verifier scripts and the operator CLI
// scripts/receipts.mjs, driven as processes on files saved from the vault API.
import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {unpackResponse} from '../src/receipts.mjs';
import {BASE} from './support/transparency-fixture.mjs';
import {receiptFixture} from './support/receipt-fixture.mjs';

const run = (script, args, cwd) => {
  const r = spawnSync(process.execPath, [script, ...args], {encoding: 'utf8', windowsHide: true, ...(cwd ? {cwd} : {})});
  return {status: r.status, out: r.stdout.trim().startsWith('{') ? JSON.parse(r.stdout) : r.stdout, err: r.stderr};
};
const verify = (args, cwd) => run(new URL('../scripts/evidscope-verify.mjs', import.meta.url).pathname, args, cwd);

test('evidscope-verify checks unpacked attestations, record receipts and the existing formats', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'evidscope-verify-cli-'));
  t.after(() => rmSync(dir, {recursive: true, force: true}));
  const x = await receiptFixture(t, join(dir, 'in')), out = join(dir, 'out');
  for (const name of ['export', 'report', 'record']) assert.equal(verify(['unpack', x.files[name], '--out', out]).status, 0, name);
  const files = readdirSync(out).sort(), path = name => join(out, name);
  const exportName = x.responses.export.file.name, reportName = x.responses.report.file.name;
  const recordBase = files.find(n => n.endsWith('.tlog-proof')).slice(0, -'.tlog-proof'.length);
  assert.deepEqual(files, [exportName, exportName + '.intoto.json', reportName, reportName + '.intoto.json', recordBase + '.json',
    recordBase + '.tlog-policy', recordBase + '.tlog-proof'].sort());
  // Unpacking never overwrites.
  const again = verify(['unpack', x.files.export, '--out', out]);
  assert.equal(again.status, 1);
  assert.match(again.err, /EEXIST/);

  let r = verify(['dsse', path(exportName + '.intoto.json'), path(exportName), x.files.key, ...x.flags, '--require-witnessed', '--require-tenant-witness']);
  assert.equal(r.status, 0, r.err);
  assert.deepEqual([r.out.valid, r.out.witnessed, r.out.bundle.transparency.rollbackCheckedAgainst], [true, true, 'signing_key_holder']);
  r = verify(['dsse', path(reportName + '.intoto.json'), path(reportName), x.files.key, ...x.flags, '--require-witnessed']);
  assert.equal(r.status, 0, r.err);
  assert.equal(r.out.report.caseId, x.caseId);
  r = verify(['tlog-proof', path(recordBase + '.tlog-proof'), path(recordBase + '.json'), '--policy', path(recordBase + '.tlog-policy'), '--key', x.files.key,
    '--origin-base', BASE]);
  assert.equal(r.status, 0, r.err);
  assert.deepEqual([r.out.seq, r.out.witnessed, r.out.quorumMet], [1, true, true]);
  r = verify(['tlog-proof', path(recordBase + '.tlog-proof'), path(recordBase + '.json'), '--key', x.files.key, '--witness', x.f.w.vkey]);
  assert.equal(r.status, 0, r.err);
  r = verify(['bundle', path(exportName), x.files.key, ...x.flags, '--attestation', path(exportName + '.intoto.json')]);
  assert.equal(r.status, 0, r.err);
  assert.deepEqual([r.out.valid, r.out.attestation.valid], [true, true]);
  r = verify(['report', path(reportName), x.files.key, '--attestation', path(reportName + '.intoto.json')]);
  assert.equal(r.status, 0, r.err);
  // The existing scripts take the companion envelope too, and their output is unchanged without it.
  r = run('scripts/verify.mjs', [path(exportName), x.files.key, '--attestation', path(exportName + '.intoto.json')]);
  assert.equal(r.status, 0, r.err);
  assert.equal(r.out.attestation.predicateType, JSON.parse(Buffer.from(x.responses.export.envelope.payload, 'base64')).predicateType);
  r = run('scripts/verify-case-report.mjs', [path(reportName), x.files.key, '--attestation', path(reportName + '.intoto.json')]);
  assert.equal(r.status, 0, r.err);
  assert.equal(run('scripts/verify.mjs', [path(exportName), x.files.key]).out.attestation, undefined);

  // Tampered inputs are refused with exit status 1; misuse is a usage error (2).
  const bad = join(dir, 'bad');
  writeFileSync(bad, readFileSync(path(exportName), 'utf8').replace('"seq":1,', '"seq":1 ,'));
  r = verify(['dsse', path(exportName + '.intoto.json'), bad, x.files.key]);
  assert.deepEqual([r.status, /digest is not the subject/.test(r.err)], [1, true], r.err);
  writeFileSync(bad, readFileSync(path(recordBase + '.json'), 'utf8').replace('"type":', '"type" :'));
  r = verify(['tlog-proof', path(recordBase + '.tlog-proof'), bad, '--policy', path(recordBase + '.tlog-policy')]);
  assert.deepEqual([r.status, /exact ledger record body/.test(r.err)], [1, true], r.err);
  r = verify(['tlog-proof', path(recordBase + '.tlog-proof'), path(recordBase + '.json'), '--key', x.files.key, '--witness', x.f.w.vkey, '--quorum', '1',
    '--origin-base', 'other.test/base']);
  assert.deepEqual([r.status, /pinned origin base/.test(r.err)], [1, true], r.err);
  r = verify(['dsse', path(exportName + '.intoto.json'), path(exportName), x.files.key, '--require-witnessed']);
  assert.deepEqual([r.status, /No embedded tlog-proof meets the witness quorum/.test(r.err)], [1, true], r.err);
  const misuse = [['tlog-proof', 'a', 'b'], ['dsse', 'a'], ['tlog-proof', 'a', 'b', '--policy', 'p', '--quorum', '1'], ['bundle', 'a', 'b', '-x'], ['nope']];
  for (const args of misuse) {
    assert.equal(verify(args).status, 2, args.join(' '));
  }
  assert.match(verify(['bundle', '/dev/null', x.files.key]).err, /not a regular file/);
});

test('scripts/receipts.mjs writes the same record receipt from the data directory and prints the tenant policy', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'evidscope-receipts-cli-'));
  t.after(() => rmSync(dir, {recursive: true, force: true}));
  // The operator needs only the vault public key.
  const x = await receiptFixture(t, join(dir, 'in')), config = join(dir, 'transparency.json'), key = x.files.key;
  writeFileSync(config, JSON.stringify({origin: BASE, mode: 'monitor', witnesses: [{vkey: x.f.w.vkey, url: x.f.ws.url}], witnessTenantLogs: true}));
  const r = run('scripts/receipts.mjs', ['record', '--config', config, '--key', key, '--data-dir', x.f.dataDir, '--tenant', 'alpha', '--seq', '1',
    '--out', join(dir, 'out')]);
  assert.equal(r.status, 0, r.err);
  assert.equal(r.out.witnessed, true);
  for (const f of unpackResponse(x.responses.record)) assert.deepEqual(readFileSync(join(dir, 'out', f.name)), f.bytes, f.name);
  const policy = run('scripts/receipts.mjs', ['policy', '--config', config, '--key', key, '--tenant', 'alpha']);
  assert.equal(policy.out, x.responses.record.policy);
  const missing = run('scripts/receipts.mjs', ['record', '--config', config, '--key', key, '--data-dir', x.f.dataDir, '--tenant', 'alpha', '--seq', '999']);
  assert.equal(missing.status, 1);
  assert.match(missing.err, /아직 없는 기록/);
});
