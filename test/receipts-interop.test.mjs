// Interop of the standard receipts (docs/receipts.md) with independent Go code. Gated: EVIDSCOPE_GO_BIN=/path/to/go, with
// GOPATH, GOMODCACHE and GOCACHE in the environment as that toolchain needs them. Builds run offline (GOPROXY=off), so
// modules come only from the local module cache; the torchwood test skips when they are not there.
//   test/fixtures/interop-go/dsse-verify  Go standard library only: DSSE v1 PAE, Ed25519, keyid, in-toto subject digest
//   test/fixtures/interop-go/tlog-verify  filippo.io/torchwood VerifyProof/ParsePolicy and golang.org/x/mod/sumdb/note
import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {generateKeyPairSync} from 'node:crypto';
import {cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {keyFingerprint} from '../src/dsse.mjs';
import {CASE_REPORT_PREDICATE, EXPORT_PREDICATE, unpackResponse, verifyAttestation} from '../src/receipts.mjs';
import {formatTlogPolicy} from '../src/tlog-policy.mjs';
import {SIG_COSIG_ED25519, ed25519RawPublic, logVkey, vkeyString} from '../src/tlog.mjs';
import {receiptFixture} from './support/receipt-fixture.mjs';

const GO = process.env.EVIDSCOPE_GO_BIN;
const skip = !GO ? 'EVIDSCOPE_GO_BIN is not set' : !existsSync(GO) ? `go binary not found at ${GO}` : false;
const GO_ENV = {GOFLAGS: '-mod=mod', GOPROXY: 'off', GOSUMDB: 'off', GOTOOLCHAIN: 'local', GOWORK: 'off', CGO_ENABLED: '0'};

// Builds one fixture program in a copy under dir; returns the binary, or null with the reason when modules are missing.
function build(dir, name) {
  const src = join(dir, 'go', name), bin = join(dir, 'bin', name);
  cpSync(new URL(`./fixtures/interop-go/${name}/`, import.meta.url), src, {recursive: true});
  const r = spawnSync(GO, ['build', '-o', bin, '.'], {cwd: src, encoding: 'utf8', env: {...process.env, ...GO_ENV}, timeout: 240_000});
  if (r.status === 0) return {bin};
  const missing = r.stderr.split('\n').find(line => /GOPROXY=off|module lookup disabled|cannot find module|missing go\.sum entry/.test(line));
  if (missing) return {missing};
  assert.fail(`go build ${name} failed: ${r.error?.message || r.stderr}`);
}
const run = (bin, args) => {
  const r = spawnSync(bin, args, {encoding: 'utf8', timeout: 60_000});
  return {status: r.status, out: r.stdout.trim(), err: r.stderr.trim()};
};
async function unpacked(t, dir) {
  const x = await receiptFixture(t, join(dir, 'responses')), ev = join(dir, 'evidence');
  mkdirSync(ev, {recursive: true});
  for (const response of Object.values(x.responses)) for (const f of unpackResponse(response)) writeFileSync(join(ev, f.name), f.bytes);
  return {x, ev, path: name => join(ev, name)};
}
const statementOf = envelope => JSON.parse(Buffer.from(envelope.payload, 'base64'));

test('DSSE attestations verify with an independent Go verifier built on the standard library only', {skip}, async t => {
  const dir = mkdtempSync(join(tmpdir(), 'evidscope-dsse-interop-'));
  t.after(() => rmSync(dir, {recursive: true, force: true}));
  const {bin} = build(dir, 'dsse-verify'), {x, path} = await unpacked(t, dir), keyid = keyFingerprint(x.f.publicKey);
  for (const [kind, predicateType] of [['export', EXPORT_PREDICATE], ['report', CASE_REPORT_PREDICATE]]) {
    const name = x.responses[kind].file.name, r = run(bin, [path(name + '.intoto.json'), path(name), x.files.key]);
    assert.equal(r.status, 0, r.err);
    assert.equal(r.out, `ok ${keyid} ${name} ${predicateType}`);
  }
  // The DSSE protocol lets signers use URL-safe base64 without padding; both sides accept it for the same envelope.
  const name = x.responses.export.file.name, envelope = x.responses.export.envelope, url = s => Buffer.from(s, 'base64').toString('base64url');
  const urlSafe = {...envelope, payload: url(envelope.payload), signatures: envelope.signatures.map(s => ({...s, sig: url(s.sig)}))};
  writeFileSync(join(dir, 'url-safe.intoto.json'), JSON.stringify(urlSafe));
  assert.equal(run(bin, [join(dir, 'url-safe.intoto.json'), path(name), x.files.key]).status, 0);
  assert.equal(verifyAttestation({envelope: urlSafe, subject: readFileSync(path(name)), publicKey: x.f.publicKey}).valid, true);

  // The independent verifier refuses what the EvidScope verifier refuses.
  writeFileSync(join(dir, 'subject.json'), readFileSync(path(name), 'utf8').replace('"seq":2,', '"seq":3,'));
  let r = run(bin, [path(name + '.intoto.json'), join(dir, 'subject.json'), x.files.key]);
  assert.deepEqual([r.status, /not a subject/.test(r.err)], [1, true], r.err);
  const statement = statementOf(envelope);
  statement.predicate.issuedAt = '2000-01-01T00:00:00.000Z';
  writeFileSync(join(dir, 'payload.intoto.json'), JSON.stringify({...envelope, payload: Buffer.from(JSON.stringify(statement)).toString('base64')}));
  r = run(bin, [join(dir, 'payload.intoto.json'), path(name), x.files.key]);
  assert.deepEqual([r.status, /no signature verifies/.test(r.err)], [1, true], r.err);
  writeFileSync(join(dir, 'other.pem'), generateKeyPairSync('ed25519').publicKey.export({format: 'pem', type: 'spki'}));
  r = run(bin, [path(name + '.intoto.json'), path(name), join(dir, 'other.pem')]);
  assert.deepEqual([r.status, /no signature verifies/.test(r.err)], [1, true], r.err);
});

test('record receipts and embedded tlog-proofs verify with torchwood, checkpoint notes with sumdb/note', {skip}, async t => {
  const dir = mkdtempSync(join(tmpdir(), 'evidscope-tlog-interop-'));
  t.after(() => rmSync(dir, {recursive: true, force: true}));
  const built = build(dir, 'tlog-verify');
  if (built.missing) { t.skip(`Go modules are not in the local module cache: ${built.missing}`); return; }
  const {bin} = built, {x, path} = await unpacked(t, dir), record = x.responses.record, policyPath = join(dir, 'r.tlog-policy');
  const base = unpackResponse(record)[0].name.slice(0, -'.json'.length);
  // The vault's tenant policy, as torchwood parses it: the tenant log key plus a quorum of the one witness.
  writeFileSync(policyPath, record.policy);
  let r = run(bin, ['proof', path(base + '.tlog-proof'), path(base + '.tlog-policy'), path(base + '.json')]);
  assert.deepEqual([r.status, r.out], [0, 'ok'], r.err);

  // Every tlog-proof embedded in the export and case report predicates verifies: those against the witnessed checkpoint under
  // the same policy, those against the newer checkpoint the witness has not cosigned yet only under a log-only policy.
  const tlog = statementOf(x.responses.export.envelope).predicate.tlog, logKey = logVkey(tlog.origin, x.f.publicKey);
  const logOnly = join(dir, 'log-only.tlog-policy');
  writeFileSync(logOnly, formatTlogPolicy({logs: [logKey], witnesses: [], quorum: 'none'}));
  for (const kind of ['export', 'report']) {
    const {tlogProofs, tlog: reference} = statementOf(x.responses[kind].envelope).predicate;
    assert.ok(tlogProofs.some(p => p.proof.endsWith(reference.cosignedCheckpoint)), kind);
    for (const p of tlogProofs) {
      const witnessed = p.proof.endsWith(reference.cosignedCheckpoint), at = `${kind} ${p.seq}`;
      writeFileSync(join(dir, 'embedded.tlog-proof'), p.proof);
      r = run(bin, ['proof-hash', join(dir, 'embedded.tlog-proof'), witnessed ? policyPath : logOnly, p.hash]);
      assert.deepEqual([r.status, r.out], [0, 'ok'], `${at}: ${r.err}`);
      if (!witnessed) assert.match(run(bin, ['proof-hash', join(dir, 'embedded.tlog-proof'), policyPath, p.hash]).err, /policy components/, at);
    }
  }

  // Checkpoint notes: the tenant log signature checked by golang.org/x/mod/sumdb/note, the cosignature by torchwood.
  writeFileSync(join(dir, 'cosigned.note'), tlog.cosignedCheckpoint);
  r = run(bin, ['note', join(dir, 'cosigned.note'), logKey, x.f.w.vkey]);
  assert.equal(r.status, 0, r.err);
  const [ok, origin, size, cosignatures] = r.out.split(' ');
  assert.deepEqual([ok, origin, Number(cosignatures) >= 1], ['ok', tlog.origin, true]);
  assert.ok(Number(size) >= 1);
  writeFileSync(join(dir, 'latest.note'), tlog.checkpoint);
  assert.equal(run(bin, ['note', join(dir, 'latest.note'), logKey]).status, 0);

  // torchwood refuses what the EvidScope verifier refuses: another record, a quorum the receipt does not meet, another log key.
  const tampered = JSON.parse(readFileSync(path(base + '.json'), 'utf8'));
  tampered.type += '-changed';
  writeFileSync(join(dir, 'record.json'), JSON.stringify(tampered));
  r = run(bin, ['proof', path(base + '.tlog-proof'), policyPath, join(dir, 'record.json')]);
  assert.deepEqual([r.status, /inclusion proof verification failed/.test(r.err)], [1, true], r.err);
  const stranger = vkeyString('witness.stranger.test', SIG_COSIG_ED25519, ed25519RawPublic(generateKeyPairSync('ed25519').publicKey));
  writeFileSync(join(dir, 'stranger.tlog-policy'), formatTlogPolicy({logs: [logKey], witnesses: [{name: 's', vkey: stranger}], quorum: 's'}));
  r = run(bin, ['proof', path(base + '.tlog-proof'), join(dir, 'stranger.tlog-policy'), path(base + '.json')]);
  assert.equal(r.status, 1, r.err);
  assert.equal(run(bin, ['proof', path(base + '.tlog-proof'), logOnly, path(base + '.json')]).status, 0);
  const otherLog = logVkey(tlog.origin, generateKeyPairSync('ed25519').publicKey);
  writeFileSync(join(dir, 'other-log.tlog-policy'), formatTlogPolicy({logs: [otherLog], witnesses: [], quorum: 'none'}));
  assert.equal(run(bin, ['proof', path(base + '.tlog-proof'), join(dir, 'other-log.tlog-policy'), path(base + '.json')]).status, 1);
  writeFileSync(join(dir, 'forged.note'), tlog.checkpoint.replace(/\n(\d+)\n/, (m, n) => `\n${Number(n) + 1}\n`));
  assert.equal(run(bin, ['note', join(dir, 'forged.note'), logKey]).status, 1);
});
