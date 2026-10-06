import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {createHash, sign} from 'node:crypto';
import {canonical} from '../src/crypto.mjs';
import {verifyCaseReport} from '../src/report-verifier.mjs';
import * as T from '../src/tlog.mjs';
import {BASE, transparencyFixture} from './support/transparency-fixture.mjs';

// Review finding: an event without seq/hash matched an absent inclusion proof (undefined === undefined).
test('case-report events must each carry a sequence and hash proven in the signed tenant tree', async t => {
  const f = await transparencyFixture(t);
  const s = await f.open('enforce');
  f.write(s, 'alpha', 3);
  await s.transparency.pump();
  const checkpoint = s.store.checkpoint('alpha'), transparency = s.store.tlogReport('alpha', checkpoint, []);
  assert.ok(transparency?.heads);
  const fingerprint = createHash('sha256').update(f.publicKey.export({format: 'der', type: 'spki'})).digest('hex');
  const report = event => {
    const signed = {format: 'evidscope-case-report-v1', snapshot: {tenant: 'alpha', exportedAt: new Date().toISOString(), case: {id: 'c1', actionId: 'a1'},
      action: {actionId: 'a1', events: [event]}, review: {state: 'unreviewed'}, checkpoint}};
    return {...signed, signature: sign(null, Buffer.from(canonical(signed)), f.privateKey).toString('base64'), publicKeyFingerprint: fingerprint, transparency};
  };
  const options = {transparency: {witnesses: [f.w.vkey], quorum: 1, originBase: BASE, require: true}};
  const fake = {source: 'tool', id: 'fabricated-result', kind: 'result', status: 'success', actionId: 'a1'};
  for (const event of [fake, {...fake, seq: 1}, {...fake, hash: 'a'.repeat(64)}, {...fake, seq: 1, hash: 'a'.repeat(64)}]) {
    assert.throws(() => verifyCaseReport(report(event), f.publicKey, options), /not included in the signed tenant tree/);
  }
});

// Review finding: the witness response was fully buffered before truncation, so a hostile witness could exhaust memory.
test('witness responses are read up to 64 KiB and the rest of the stream is cancelled', async t => {
  const chunk = Buffer.alloc(1 << 20, 0x41);
  let written = 0;
  const server = http.createServer((req, res) => {
    req.resume();
    res.writeHead(200, {'content-type': 'text/plain'});
    const pump = () => { while (written < 256) { written++; if (!res.write(chunk)) return res.once('drain', pump); } res.end(); };
    pump();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const started = Date.now();
  const r = await T.postAddCheckpoint(`http://127.0.0.1:${server.address().port}`, 'old 0\n\nx\n', {timeoutMs: 5000});
  assert.equal(r.status, 200);
  assert.equal(r.body.length, 65536);
  assert.ok(written < 256, `server was not cut off (${written} MiB written)`);
  assert.ok(Date.now() - started < 4000);
});
