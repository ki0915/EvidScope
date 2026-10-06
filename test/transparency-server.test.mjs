import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {existsSync, mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {harness} from './harness.mjs';
import {submit} from '../src/client.mjs';
import {verifyCaseReport} from '../src/report-verifier.mjs';
import * as T from '../src/tlog.mjs';
import {transparencyPinPath} from '../src/transparency.mjs';
import {createWitness} from '../scripts/witness.mjs';
import {replaceDatabase, snapshot} from './support/transparency-fixture.mjs';

const BASE = 'vault.test/server';
async function waitFor(check, what, ms = 8000) {
  for (const end = Date.now() + ms; Date.now() < end; await delay(50)) if (await check()) return;
  throw Error('Timed out waiting for ' + what);
}
// The vault reads TRANSPARENCY_CONFIG_FILE from its environment; the witness learns the vault key after first start.
async function transparentHarness(t, mode, options) {
  const root = mkdtempSync(join(tmpdir(), 'evidscope-transparency-server-'));
  const w = createWitness({dir: join(root, 'witness'), name: 'witness.test/server'}), ws = await w.listen();
  const configFile = join(root, 'transparency.json'), previous = process.env.TRANSPARENCY_CONFIG_FILE;
  writeFileSync(configFile, JSON.stringify({origin: BASE, mode, witnesses: [{vkey: w.vkey, url: ws.url}], intervalMs: 100, timeoutMs: 2000}));
  process.env.TRANSPARENCY_CONFIG_FILE = configFile;
  let h = null;
  t.after(async () => {
    await h?.close();
    if (previous === undefined) delete process.env.TRANSPARENCY_CONFIG_FILE; else process.env.TRANSPARENCY_CONFIG_FILE = previous;
    await ws.close();
    w.close();
    rmSync(root, {recursive: true, force: true});
  });
  h = await harness(options);
  w.addLog(T.headsOrigin(BASE), T.logVkey(T.headsOrigin(BASE), h.publicKey));
  const witnessed = () => w.logs()[0].size;
  return {root, w, h, witnessed, dataDir: join(h.dir, 'data')};
}

test('vault process refuses to start on an older database copy in enforce mode (witness only)', async t => {
  const {root, h, witnessed, dataDir} = await transparentHarness(t, 'enforce', {vaultOnly: true});
  assert.equal((await h.api('/api/overview')).status, 200);
  await waitFor(() => witnessed() > 0, 'first cosigned heads checkpoint');
  snapshot(dataDir, join(root, 'older.db'));
  const before = witnessed();
  // Reads no longer append ledger rows one by one (they are sealed in batches), so a signed write moves the ledger past the copy.
  const rule = {id: 'advance', title: 'Advance the ledger', field: 'note', op: 'eq', value: 'x', severity: 'low'};
  assert.equal((await h.api('/api/rules', {role: 'reviewer', body: rule})).status, 200);
  await waitFor(() => witnessed() > before, 'newer cosigned heads checkpoint');
  const vault = h.vault;
  vault.child.kill('SIGKILL');
  await new Promise(r => (vault.child.exitCode !== null || vault.child.signalCode !== null ? r() : vault.child.once('exit', r)));
  rmSync(transparencyPinPath(dataDir), {force: true});
  replaceDatabase(dataDir, join(root, 'older.db'));
  await assert.rejects(h.start('vault', {PORT: String(vault.port)}), /Transparency startup check failed[\s\S]*rollback/);
});

test('case reports carry inclusion proofs that the offline verifier checks against the witness quorum', async t => {
  const {root, w, h, witnessed} = await transparentHarness(t, 'monitor');
  const base = {actionId: 'tlog-action', traceId: 'tlog-trace', occurredAt: new Date().toISOString(), actor: 'assistant', tool: 'crm', action: 'update',
    resource: 'case-7'};
  const events = [['agent', {id: 'claim', kind: 'self_report', status: 'success'}], ['tool', {id: 'result', kind: 'result', status: 'failure'}]];
  for (const [source, event] of events) {
    assert.equal((await submit(h.ingress.url, h.principal(source), {...base, ...event})).status, 202);
  }
  await h.analyze();
  // Read before the case write: the pump may cosign the new head before the POST returns.
  const before = witnessed();
  const created = await h.api('/api/cases', {body: {title: 'transparency case', owner: 'audit-team', actionId: base.actionId}});
  assert.equal(created.status, 200);
  await waitFor(() => witnessed() > before, 'cosigned heads checkpoint covering the case');
  const report = (await h.api(`/api/cases/${created.body.id}/report`)).body;
  assert.equal(report.transparency.format, 'evidscope-transparency-v1');
  assert.equal(verifyCaseReport(report, h.publicKey).transparency, undefined);
  const reportPath = join(root, 'report.json'), keyPath = join(root, 'trusted.pem'), cli = args => spawnSync(process.execPath,
    ['scripts/verify-case-report.mjs', reportPath, keyPath, ...args], {encoding: 'utf8', windowsHide: true});
  writeFileSync(reportPath, JSON.stringify(report));
  writeFileSync(keyPath, h.publicKey);
  let r = cli(['--witness', w.vkey, '--quorum', '1', '--origin-base', BASE, '--require-transparency']);
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  assert.equal(out.valid, true);
  assert.equal(out.rollbackChecked, true);
  assert.equal(out.transparency.includedEvents, 2);
  assert.equal(out.transparency.heads.quorumMet, true);
  r = cli([]);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(JSON.parse(r.stdout).rollbackChecked, false);
  const unbound = structuredClone(report);
  unbound.transparency.inclusion = unbound.transparency.inclusion.filter(i => i.seq !== report.snapshot.action.events[0].seq);
  writeFileSync(reportPath, JSON.stringify(unbound));
  r = cli(['--witness', w.vkey]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /not included in the signed tenant tree/);
  const integrity = await h.api('/api/integrity');
  assert.equal(integrity.body.valid, true, integrity.body.error);
  assert.equal(integrity.body.transparency.mode, 'monitor');
  assert.equal(integrity.body.transparency.heads.quorumMet, true);
  assert.ok(existsSync(transparencyPinPath(join(h.dir, 'data'))));
});
