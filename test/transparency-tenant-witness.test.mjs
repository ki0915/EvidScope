// Review finding F1: a heads leaf is signed by the vault key alone, so a holder of that key (S2) can append one that rolls a
// single tenant back and still get it cosigned, because a witness only checks that the heads log is append-only. With
// witnessTenantLogs every tenant log is also submitted as its own origin: the witnesses then refuse the rollback themselves,
// and verifiers say whom a rollback check binds (rollbackCheckedAgainst).
import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {createHash, sign} from 'node:crypto';
import {mkdirSync, writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {DatabaseSync} from 'node:sqlite';
import {canonical, verifyBundle} from '../src/crypto.mjs';
import {verifyCaseReport} from '../src/report-verifier.mjs';
import * as T from '../src/tlog.mjs';
import {assertTransparencyAnchors, headsRow, headsSize, probeTransparency} from '../src/transparency.mjs';
import {BASE, replaceDatabase, snapshot, tamper, transparencyFixture} from './support/transparency-fixture.mjs';

const hOrigin = T.headsOrigin(BASE), alphaOrigin = T.tenantOrigin(BASE, 'alpha');
const esc = s => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
const run = (script, args) => {
  const r = spawnSync(process.execPath, [script, ...args], {encoding: 'utf8', windowsHide: true});
  return {status: r.status, out: r.status === 0 && r.stdout.trim().startsWith('{') ? JSON.parse(r.stdout) : r.stdout, err: r.stderr};
};
const policy = (f, extra = {}) => ({witnesses: [f.w.vkey], quorum: 1, originBase: BASE, require: true, maxStalenessSeconds: 3600, ...extra});
const strict = f => policy(f, {requireTenantWitness: true});
const witnessSize = (f, origin) => f.w.logs().find(l => l.origin === origin)?.size ?? null;
const cliFlags = f => ['--witness', f.w.vkey, '--quorum', '1', '--origin-base', BASE, '--max-staleness', '3600', '--require-transparency'];

// The S2 attacker of the review holds the vault key but no witness key. It appends a heads leaf whose entries are the
// latest leaf's entries after `change`, and the witness cosigns it because the heads log stays append-only.
function forgeHeadsLeaf(f, db, change) {
  const n = headsSize(db, hOrigin), last = headsRow(db, hOrigin, n - 1);
  const peaks = T.frontierAppend(T.blobToPeaks(last.peaks, n - 1), n - 1, Buffer.from(last.leaf));
  const entries = T.sortHeadsEntries(change(JSON.parse(last.entries))), content = T.headsLeafContent(entries), leaf = T.headsLeafHash(content);
  const root = T.frontierRoot(T.frontierAppend(peaks, n, leaf));
  const note = T.signNote(T.formatCheckpoint({origin: hOrigin, size: n + 1, root}), T.noteSigner(hOrigin, f.privateKey));
  const r = f.w.addCheckpoint(T.addCheckpointBody(n, T.consistencyProofFromFrontier(n, peaks, [leaf]), note));
  assert.equal(r.status, 200, r.body);
  const evidence = log => {
    const i = entries.findIndex(e => e.log === log);
    return {origin: hOrigin, checkpoint: note + r.body, leafIndex: n, leafProof: peaks.slice().reverse().map(T.b64), leaf: content, entry: entries[i],
      entryIndex: i, entryProof: T.inclusionProof(entries.map(T.headsEntryLeaf), i).map(T.b64)};
  };
  return {n, peaks, leaf, entries, note, cosigned: note + r.body, evidence};
}
const rollBack = (log, records) => entries => entries.map(e => (e.log === log
  ? T.headsEntry(log, records.length, T.mth(records.map(r => T.recordLeaf(r.hash)))) : e));
const insertHeadsRow = (db, forged) => db.prepare('INSERT INTO tlog_heads VALUES(?,?,?,?,?,?,?)')
  .run(hOrigin, forged.n, forged.leaf, T.peaksToBlob(forged.peaks), T.canonicalJson(forged.entries), forged.note, new Date().toISOString());

test('the pump submits every tenant log to the witnesses and exports carry its cosigned checkpoint', async t => {
  const f = await transparencyFixture(t, {tenantLogs: true});
  const s = await f.open('enforce');
  f.write(s, 'alpha', 3);
  f.write(s, 'beta', 2);
  await s.transparency.pump();
  const db = s.store.db, alpha = s.store._tlogRow('alpha'), keyId = s.transparency.config.witnesses[0].keyId;
  assert.equal(witnessSize(f, alphaOrigin), alpha.size);
  assert.equal(witnessSize(f, T.tenantOrigin(BASE, 'beta')), s.store._tlogRow('beta').size);
  // The cosigned checkpoint is kept with its frontier; its cosignature sits in tlog_cosignatures under the tenant origin.
  assert.deepEqual(db.prepare('SELECT size,note FROM tlog_checkpoints WHERE origin=?').all(alphaOrigin).map(r => [r.size, r.note]), [[alpha.size, alpha.note]]);
  assert.deepEqual(db.prepare('SELECT size,key_id FROM tlog_cosignatures WHERE origin=?').all(alphaOrigin).map(r => [r.size, r.key_id]), [[alpha.size, keyId]]);
  assert.deepEqual(s.transparency.status().tenantLogs, [{name: f.w.name, keyId, logs: {consistent: 2}, attention: []}]);
  const exported = await f.call(s, '/api/export');
  assert.ok(exported.transparency.tenantCosigned.checkpoint.startsWith(alphaOrigin + '\n'));
  const verified = verifyBundle(exported, f.publicKey, undefined, {transparency: strict(f)});
  assert.equal(verified.transparency.rollbackCheckedAgainst, 'signing_key_holder');
  const cosigned = verified.transparency.tenantCosigned;
  assert.deepEqual([cosigned.origin, cosigned.size, cosigned.quorumMet, cosigned.fresh], [alphaOrigin, alpha.size, true, true]);
  // Without a pinned origin base the verifier cannot tell a key holder's new origin apart, so the binding drops back.
  const unpinned = verifyBundle(exported, f.publicKey, undefined, {transparency: policy(f, {originBase: undefined})});
  assert.equal(unpinned.transparency.rollbackCheckedAgainst, 'database_tamper');
  const integrity = await f.call(s, '/api/integrity');
  assert.equal(integrity.valid, true, integrity.error);
  assert.ok(integrity.verificationScope.checks.includes('tenant_witness_cosignatures'));
  assert.equal(integrity.transparency.rollbackCheckedAgainst, 'signing_key_holder');
  // The next round follows each tenant log that moved (the reads above were sealed into alpha's ledger as well).
  f.write(s, 'beta', 1);
  await s.transparency.pump();
  for (const tenant of ['alpha', 'beta']) assert.equal(witnessSize(f, T.tenantOrigin(BASE, tenant)), s.store._tlogRow(tenant).size, tenant);
});

test('S2: a cosigned heads leaf that rolls one tenant back verifies only against database tamper once tenant logs are witnessed', async t => {
  let skew = -7200;
  const f = await transparencyFixture(t, {tenantLogs: true, witnessNow: () => Date.now() + skew * 1000});
  const s = await f.open('enforce');
  f.write(s, 'alpha', 3);
  await s.transparency.pump();
  const old = await f.call(s, '/api/export');
  assert.ok(old.transparency.tenantCosigned, 'the older export carries the tenant checkpoint cosigned two hours ago');
  skew = 0;
  f.write(s, 'alpha', 5);
  await s.transparency.pump();
  const current = await f.call(s, '/api/export');
  assert.ok(current.records.length > old.records.length);
  assert.equal(verifyBundle(current, f.publicKey, undefined, {transparency: strict(f)}).transparency.rollbackCheckedAgainst, 'signing_key_holder');
  // The attack of the review still gets its heads leaf cosigned, and the heads evidence alone still verifies ...
  const forged = forgeHeadsLeaf(f, s.store.db, rollBack(alphaOrigin, old.records));
  const rolledBack = {...old, transparency: {...old.transparency, heads: forged.evidence(alphaOrigin)}};
  const v = verifyBundle(rolledBack, f.publicKey, undefined, {transparency: policy(f)});
  assert.equal(v.count, old.records.length);
  assert.deepEqual([v.rollbackChecked, v.transparency.heads.quorumMet, v.transparency.heads.fresh], [true, true, true]);
  // ... but only as a check against database tamper: the newest tenant cosignature the attacker holds for that size is stale.
  assert.equal(v.transparency.rollbackCheckedAgainst, 'database_tamper');
  assert.deepEqual([v.transparency.tenantCosigned.quorumMet, v.transparency.tenantCosigned.fresh], [true, false]);
  assert.throws(() => verifyBundle(rolledBack, f.publicKey, undefined, {transparency: strict(f)}), /tenant witness cosignatures are older than 3600 seconds/);
  // The witness refuses to cosign the rolled-back tenant checkpoint again: 409 with the size it holds, or 400 for an old size
  // beyond the checkpoint. A freshly signed note of the same tree fares no better.
  const held = witnessSize(f, alphaOrigin), oldNote = old.transparency.checkpoint, oldSize = old.checkpoint.count;
  assert.ok(held > oldSize);
  let r = f.w.addCheckpoint(T.addCheckpointBody(oldSize, [], oldNote));
  assert.deepEqual([r.status, r.body], [409, `${held}\n`]);
  r = f.w.addCheckpoint(T.addCheckpointBody(held, [], oldNote));
  assert.equal(r.status, 400);
  const stripped = {...rolledBack, transparency: {...rolledBack.transparency}};
  delete stripped.transparency.tenantCosigned;
  assert.throws(() => verifyBundle(stripped, f.publicKey, undefined, {transparency: strict(f)}), /tenant witness evidence missing/);
  // The same through the offline CLIs (verify.mjs and replay-findings.mjs share the flags).
  const keyPath = join(f.root, 'trusted.pem'), file = name => join(f.root, name);
  writeFileSync(keyPath, f.publicKey.export({format: 'pem', type: 'spki'}));
  writeFileSync(file('current.json'), JSON.stringify(current));
  writeFileSync(file('rolled-back.json'), JSON.stringify(rolledBack));
  for (const script of ['scripts/verify.mjs', 'scripts/replay-findings.mjs']) {
    let c = run(script, [file('rolled-back.json'), keyPath, ...cliFlags(f)]);
    assert.equal(c.status, 0, c.err);
    assert.equal((c.out.verification ?? c.out).transparency.rollbackCheckedAgainst, 'database_tamper');
    c = run(script, [file('rolled-back.json'), keyPath, ...cliFlags(f), '--require-tenant-witness']);
    assert.equal(c.status, 1, script);
    assert.match(c.err, /tenant witness cosignatures are older than 3600 seconds/);
    c = run(script, [file('current.json'), keyPath, ...cliFlags(f), '--require-tenant-witness']);
    assert.equal(c.status, 0, c.err);
    assert.equal((c.out.verification ?? c.out).transparency.rollbackCheckedAgainst, 'signing_key_holder');
  }
  // The vault refuses to continue on top of the forged leaf: the heads row after its pin shrinks the tenant.
  await f.close(s);
  tamper(f.dataDir, db => insertHeadsRow(db, forged));
  await assert.rejects(f.open('enforce'),
    new RegExp(`Transparency startup check failed: .*shrinks tenant log ${esc(alphaOrigin)} from ${held} to ${oldSize} \\(rollback\\)`));
});

test('without witnessTenantLogs the same rollback is reported as checked against database tamper only', async t => {
  const f = await transparencyFixture(t);
  const s = await f.open('enforce');
  f.write(s, 'alpha', 3);
  await s.transparency.pump();
  const old = await f.call(s, '/api/export');
  f.write(s, 'alpha', 5);
  await s.transparency.pump();
  const current = await f.call(s, '/api/export');
  const forged = forgeHeadsLeaf(f, s.store.db, rollBack(alphaOrigin, old.records));
  const rolledBack = {...old, transparency: {...old.transparency, heads: forged.evidence(alphaOrigin)}};
  for (const bundle of [current, rolledBack]) {
    assert.equal(bundle.transparency.tenantCosigned, undefined);
    const v = verifyBundle(bundle, f.publicKey, undefined, {transparency: policy(f)});
    assert.deepEqual([v.rollbackChecked, v.transparency.rollbackCheckedAgainst, v.transparency.tenantCosigned], [true, 'database_tamper', null]);
    assert.throws(() => verifyBundle(bundle, f.publicKey, undefined, {transparency: strict(f)}), /tenant witness evidence missing/);
  }
  const keyPath = join(f.root, 'trusted.pem'), file = join(f.root, 'rolled-back.json');
  writeFileSync(keyPath, f.publicKey.export({format: 'pem', type: 'spki'}));
  writeFileSync(file, JSON.stringify(rolledBack));
  let c = run('scripts/verify.mjs', [file, keyPath, ...cliFlags(f)]);
  assert.equal(c.status, 0, c.err);
  assert.equal(c.out.transparency.rollbackCheckedAgainst, 'database_tamper');
  c = run('scripts/verify.mjs', [file, keyPath, ...cliFlags(f), '--require-tenant-witness']);
  assert.equal(c.status, 1);
  assert.match(c.err, /tenant witness evidence missing/);
  // The live integrity check says the same about the honest vault.
  const integrity = await f.call(s, '/api/integrity');
  assert.deepEqual([integrity.rollbackChecked, integrity.transparency.rollbackCheckedAgainst], [true, 'database_tamper']);
});

test('enforce startup refuses an older database whose heads log and pin a key holder forged to match, once tenant logs are witnessed', async t => {
  const f = await transparencyFixture(t, {tenantLogs: true});
  const s = await f.open('enforce');
  f.write(s, 'alpha', 3);
  await s.transparency.pump();
  const older = join(f.root, 'older.db');
  snapshot(f.dataDir, older);
  f.write(s, 'alpha', 5);
  await s.transparency.pump();
  const witnessed = witnessSize(f, alphaOrigin), copy = new DatabaseSync(older, {readOnly: true});
  const from = headsSize(copy, hOrigin), olderSize = copy.prepare('SELECT size FROM tlog_state WHERE tenant=?').get('alpha').size;
  copy.close();
  // The heads rows the older copy lacks: the witness cosigned their leaves, so the attacker has to keep them.
  const later = {heads: s.store.db.prepare('SELECT * FROM tlog_heads WHERE origin=? AND idx>=?').all(hOrigin, from),
    entries: s.store.db.prepare('SELECT * FROM tlog_heads_entries WHERE origin=? AND idx>=?').all(hOrigin, from)};
  assert.ok(witnessed > olderSize && later.heads.length > 0);
  await f.close(s);
  // S2 swaps in the older copy, re-appends those rows plus a leaf naming the older tenant heads (cosigned by the witness)
  // and pins it, so that the heads log, the pin and the witness's heads log all agree with the older copy.
  replaceDatabase(f.dataDir, older);
  let forged;
  tamper(f.dataDir, db => {
    const heads = db.prepare('INSERT INTO tlog_heads VALUES(?,?,?,?,?,?,?)');
    for (const r of later.heads) heads.run(r.origin, r.idx, r.leaf, r.peaks, r.entries, r.note, r.created_at);
    for (const r of later.entries) db.prepare('INSERT INTO tlog_heads_entries VALUES(?,?,?,?,?)').run(r.origin, r.log, r.idx, r.size, r.root);
    const state = new Map(db.prepare('SELECT origin,size,root FROM tlog_state WHERE size>0').all().map(r => [r.origin, r]));
    const asCopied = e => T.headsEntry(e.log, state.get(e.log).size, Buffer.from(state.get(e.log).root));
    forged = forgeHeadsLeaf(f, db, entries => entries.map(e => (state.has(e.log) ? asCopied(e) : e)));
    insertHeadsRow(db, forged);
  });
  writeFileSync(f.config('enforce').pinFile, JSON.stringify({format: 'evidscope-transparency-pin-v1', origin: hOrigin, size: forged.n + 1,
    checkpoint: forged.cosigned}));
  // Heads-only witnessing has nothing to contradict this state: the vault would start on the rolled-back copy.
  const headsOnly = f.config('enforce', {witnessTenantLogs: false});
  const probe = await probeTransparency({dataDir: f.dataDir, key: f.privateKey, config: headsOnly});
  const gap = assertTransparencyAnchors({dataDir: f.dataDir, key: f.privateKey, config: headsOnly, probe, inspectOnly: true});
  assert.deepEqual([gap.ok, gap.violations], [true, []]);
  // With tenant logs witnessed, the witness holds the tenant log beyond the local one and enforce mode refuses to start.
  await assert.rejects(f.open('enforce'), new RegExp(`Transparency startup check failed: Witness ${esc(f.w.name)}: witness holds tenant log `
    + `${esc(alphaOrigin)} size ${witnessed} but the local tenant log ${esc(alphaOrigin)} has ${olderSize} \\(rollback\\)`));
  const monitored = f.config('monitor');
  const report = assertTransparencyAnchors({dataDir: f.dataDir, key: f.privateKey, config: monitored, inspectOnly: true,
    probe: await probeTransparency({dataDir: f.dataDir, key: f.privateKey, config: monitored})});
  assert.deepEqual(report.violations.map(v => v.kind), ['rollback']);
  // The heads monitor finds the forged leaf from the database alone, without any witness.
  const configPath = join(f.root, 'transparency.json'), keyPath = join(f.root, 'vault.pub.pem');
  writeFileSync(configPath, JSON.stringify({origin: BASE, mode: 'enforce', witnesses: [{vkey: f.w.vkey, url: f.ws.url}], witnessTenantLogs: true}));
  writeFileSync(keyPath, f.publicKey.export({format: 'pem', type: 'spki'}));
  const c = run('scripts/transparency.mjs', ['monitor', '--config', configPath, '--key', keyPath, '--data-dir', f.dataDir]);
  assert.equal(c.status, 2, c.err);
  const out = JSON.parse(c.out), messages = out.violations.map(v => v.message);
  assert.deepEqual([out.ok, out.headsSize, new Set(out.violations.map(v => v.kind))], [false, forged.n + 1, new Set(['rollback'])]);
  const shrink = new RegExp(`^Heads log row ${forged.n} shrinks tenant log ${esc(alphaOrigin)} from ${witnessed} to ${olderSize}`);
  assert.ok(messages.some(m => shrink.test(m)), messages);
  assert.ok(messages.some(m => /^Ledger for tenant log .* is behind its heads entry/.test(m)), messages);
});

test('the startup check refuses a tenant log the witnesses were not probed for', async t => {
  const f = await transparencyFixture(t, {tenantLogs: true});
  const s = await f.open('enforce');
  f.write(s, 'alpha', 1);
  await s.transparency.pump();
  const probedDir = join(f.root, 'probed');
  mkdirSync(probedDir);
  snapshot(f.dataDir, join(probedDir, 'evidence.db'));
  // gamma is signed but not yet in a heads leaf, so the heads log the witnesses saw is unchanged.
  f.write(s, 'gamma', 1);
  await f.close(s);
  const probe = await probeTransparency({dataDir: probedDir, key: f.privateKey, config: f.config('enforce')});
  assert.deepEqual(probe.tenants.map(x => x.tenant).sort(), ['alpha', 'beta']);
  await assert.rejects(f.open('enforce', {probe}), new RegExp(`tenant log ${esc(T.tenantOrigin(BASE, 'gamma'))} \\(size 1\\) was not in the database `
    + 'the witnesses were probed with'));
  await f.close(await f.open('enforce'));
});

test('the pump submits changed tenant logs first, at most 64 per round with 4 in flight, and backs off origins a witness does not know', async t => {
  const seen = [];
  let inflight = 0, peak = 0;
  const fetchImpl = async (url, init) => {
    const note = init.body.slice(init.body.indexOf('\n\n') + 2), origin = note.slice(0, note.indexOf('\n')), tenant = origin !== hOrigin;
    seen.push(origin);
    if (tenant) peak = Math.max(peak, ++inflight);
    try { await delay(5); return await fetch(url, init); } finally { if (tenant) inflight--; }
  };
  const tenantRequests = () => seen.filter(o => o !== hOrigin);
  const f = await transparencyFixture(t, {tenantLogs: true});
  const s = await f.open('enforce', {fetchImpl});
  // The service already wrote a record for each principal's tenant (alpha, beta); gamma is not registered at the witness.
  const gamma = T.tenantOrigin(BASE, 'gamma');
  f.write(s, 'alpha', 1);
  f.write(s, 'gamma', 1);
  await s.transparency.pump();
  assert.deepEqual(tenantRequests().sort(), [alphaOrigin, T.tenantOrigin(BASE, 'beta'), gamma].sort());
  let status = s.transparency.status();
  assert.deepEqual(status.tenantLogs[0].logs, {consistent: 2, unregistered: 1});
  assert.deepEqual(status.tenantLogs[0].attention, [{origin: gamma, status: 'unregistered', message: `tenant log ${gamma} is not registered at the witness`}]);
  assert.deepEqual([status.violations, status.quarantine], [[], null]);
  seen.length = 0;
  await s.transparency.pump();
  assert.deepEqual(seen, [], 'fresh logs are not refreshed and an unregistered origin waits refreshSeconds');
  const bulk = Array.from({length: 100}, (_, i) => `bulk${String(i).padStart(3, '0')}`);
  for (const tenant of bulk) {
    f.registerTenant(tenant);
    f.write(s, tenant, 1);
  }
  await s.transparency.pump();
  assert.equal(tenantRequests().length, 64);
  assert.equal(peak, 4);
  seen.length = 0;
  await s.transparency.pump();
  assert.equal(tenantRequests().length, 36);
  seen.length = 0;
  await s.transparency.pump();
  assert.deepEqual(seen, []);
  f.write(s, 'bulk042', 1);
  await s.transparency.pump();
  assert.deepEqual(seen, [hOrigin, T.tenantOrigin(BASE, 'bulk042')]);
  status = s.transparency.status();
  assert.deepEqual([status.tenantLogs[0].logs, status.violations, status.quarantine], [{consistent: 102, unregistered: 1}, [], null]);
  assert.equal(witnessSize(f, T.tenantOrigin(BASE, 'bulk042')), 2);
});

test('case reports carry the cosigned tenant checkpoint with a consistency proof to the report checkpoint', async t => {
  const f = await transparencyFixture(t, {tenantLogs: true});
  const s = await f.open('enforce');
  f.write(s, 'alpha', 3);
  await s.transparency.pump();
  const cosignedSize = s.store._tlogRow('alpha').size;
  f.write(s, 'alpha', 2);
  const checkpoint = s.store.checkpoint('alpha'), transparency = s.store.tlogReport('alpha', checkpoint, []);
  assert.ok(transparency.tenantCosigned.consistency.length > 0);
  const fingerprint = createHash('sha256').update(f.publicKey.export({format: 'der', type: 'spki'})).digest('hex');
  const signed = {format: 'evidscope-case-report-v1', snapshot: {tenant: 'alpha', exportedAt: new Date().toISOString(), case: {id: 'c1', actionId: 'a1'},
    action: {actionId: 'a1', events: []}, review: {state: 'unreviewed'}, checkpoint}};
  const signature = sign(null, Buffer.from(canonical(signed)), f.privateKey).toString('base64');
  const report = {...signed, signature, publicKeyFingerprint: fingerprint, transparency};
  const verified = verifyCaseReport(report, f.publicKey, {transparency: strict(f)});
  assert.deepEqual([verified.rollbackChecked, verified.transparency.rollbackCheckedAgainst, verified.transparency.tenantCosigned.size],
    [true, 'signing_key_holder', cosignedSize]);
  const bent = structuredClone(report);
  bent.transparency.tenantCosigned.consistency[0] = T.b64(Buffer.alloc(32, 1));
  assert.throws(() => verifyCaseReport(bent, f.publicKey, {transparency: policy(f)}), /inconsistent with the report checkpoint \(fork\)/);
  const bare = structuredClone(report);
  delete bare.transparency.tenantCosigned;
  assert.equal(verifyCaseReport(bare, f.publicKey, {transparency: policy(f)}).transparency.rollbackCheckedAgainst, 'database_tamper');
  assert.throws(() => verifyCaseReport(bare, f.publicKey, {transparency: strict(f)}), /tenant witness evidence missing/);
  const keyPath = join(f.root, 'trusted.pem'), file = name => join(f.root, name);
  writeFileSync(keyPath, f.publicKey.export({format: 'pem', type: 'spki'}));
  writeFileSync(file('report.json'), JSON.stringify(report));
  writeFileSync(file('bare.json'), JSON.stringify(bare));
  let c = run('scripts/verify-case-report.mjs', [file('report.json'), keyPath, ...cliFlags(f), '--require-tenant-witness']);
  assert.equal(c.status, 0, c.err);
  assert.equal(c.out.transparency.rollbackCheckedAgainst, 'signing_key_holder');
  c = run('scripts/verify-case-report.mjs', [file('bare.json'), keyPath, ...cliFlags(f), '--require-tenant-witness']);
  assert.equal(c.status, 1);
  assert.match(c.err, /tenant witness evidence missing/);
});

test('transparency.mjs registers tenant origins, lists tenant logs and replays the heads log', async t => {
  const f = await transparencyFixture(t, {tenantLogs: true});
  const keyPath = join(f.root, 'vault.pem'), configPath = join(f.root, 'transparency.json'), cli = (...args) => run('scripts/transparency.mjs', args);
  writeFileSync(keyPath, f.privateKey.export({format: 'pem', type: 'pkcs8'}));
  writeFileSync(configPath, JSON.stringify({origin: BASE, mode: 'enforce', witnesses: [{vkey: f.w.vkey, url: f.ws.url}], witnessTenantLogs: true}));
  const common = ['--config', configPath, '--key', keyPath];
  let r = cli('witnessctl', ...common, '--db', '/srv/witness.db');
  assert.equal(r.status, 0, r.err);
  assert.equal(r.out.trim().split('\n').length, 2);
  assert.match(r.err, /witnessTenantLogs is on: pass --data-dir DIR or --tenant NAME/);
  const s = await f.open('enforce');
  f.write(s, 'alpha', 2);
  f.write(s, 'beta', 1);
  await s.transparency.pump();
  await f.close(s);
  const gamma = T.tenantOrigin(BASE, 'gamma'), witnessDir = join(f.root, 'dev-witness');
  r = cli('witnessctl', ...common, '--db', '/srv/witness.db', '--data-dir', f.dataDir, '--tenant', 'gamma', '--witness-dir', witnessDir);
  assert.equal(r.status, 0, r.err);
  const lines = r.out.trim().split('\n'), origins = [hOrigin, ...['alpha', 'beta', 'gamma'].map(x => T.tenantOrigin(BASE, x))];
  assert.equal(lines.length, 12);
  for (const origin of origins) {
    assert.ok(lines.includes(`witnessctl add-log -db /srv/witness.db -origin ${origin}`), origin);
    assert.ok(lines.includes(`witnessctl add-key -db /srv/witness.db -origin ${origin} -key ${T.logVkey(origin, f.publicKey)}`), origin);
  }
  // The development witness takes the printed lines as they are, one origin per add-log.
  assert.equal(run('scripts/witness.mjs', ['init', '--dir', witnessDir, '--name', 'witness.test/dev']).status, 0);
  for (const line of lines.filter(l => l.startsWith('node scripts/witness.mjs'))) {
    const args = line.split(' ').slice(1);
    assert.equal(run(args[0], args.slice(1)).status, 0, line);
  }
  const listed = spawnSync(process.execPath, ['scripts/witness.mjs', 'list-logs', '--dir', witnessDir], {encoding: 'utf8'}).stdout.trim().split('\n')
    .map(l => JSON.parse(l));
  assert.deepEqual(listed.map(l => [l.origin, l.keys]), origins.slice().sort().map(o => [o, 1]));
  r = cli('tenants', ...common, '--data-dir', f.dataDir, '--tenant', 'gamma');
  assert.equal(r.status, 0, r.err);
  assert.deepEqual([r.out.originBase, r.out.witnessTenantLogs], [BASE, true]);
  const byTenant = new Map(r.out.tenants.map(x => [x.tenant, x]));
  assert.deepEqual([...byTenant.keys()], ['alpha', 'beta', 'gamma']);
  assert.deepEqual([byTenant.get('alpha').origin, byTenant.get('alpha').logVkey], [alphaOrigin, T.logVkey(alphaOrigin, f.publicKey)]);
  assert.equal(byTenant.get('alpha').witnesses[0].cosignedSize, byTenant.get('alpha').size);
  assert.deepEqual([byTenant.get('gamma').origin, byTenant.get('gamma').size, byTenant.get('gamma').witnesses[0].cosignedSize], [gamma, 0, null]);
  r = cli('monitor', ...common, '--data-dir', f.dataDir);
  assert.equal(r.status, 0, r.err);
  assert.deepEqual([r.out.ok, r.out.logs, r.out.violations], [true, 2, []]);
  assert.ok(r.out.headsSize > 0);
  assert.deepEqual([r.out.cosigned.size, r.out.cosigned.quorumMet, r.out.cosigned.fresh], [r.out.headsSize, true, true]);
});
