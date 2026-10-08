// Provenance of pack-d7413a0/, the old-package regression input of test/evidence-pack-period.test.mjs.
// Run from a checkout of commit d7413a0 (round 6 closed: whole-ledger packages, mapping without a version, index v1):
//   node <this file> OUT_DIR
// Builds two packages from test/fixtures/pack-export-8b3af6c.json with a fresh builder key and a fixed build time:
// eu-ai-act-logging over the whole ledger with the signed case report, and kr-ai-basic-act with a period (phase 1 only).
import {generateKeyPairSync} from 'node:crypto';
import {mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

export async function buildOldPackages(out, root = process.cwd()) {
  const {build} = await import(pathToFileURL(resolve(root, 'scripts/evidence-pack.mjs')).href);
  const fixture = JSON.parse(readFileSync(resolve(root, 'test/fixtures/pack-export-8b3af6c.json'), 'utf8'));
  const tmp = mkdtempSync(join(tmpdir(), 'evidscope-old-pack-')), builder = generateKeyPairSync('ed25519');
  try {
    const save = (name, text) => { writeFileSync(join(tmp, name), text); return join(tmp, name); };
    const vault = save('vault.pem', fixture.publicKeyPem), key = save('builder.pem', builder.privateKey.export({format: 'pem', type: 'pkcs8'}));
    const exported = save('export.json', JSON.stringify(fixture.exportBundle)), report = save('report.json', JSON.stringify(fixture.caseReports[0]));
    const records = fixture.exportBundle.records, cut = records.find(r => r.type === 'system').recordedAt;
    mkdirSync(out, {recursive: true});
    const common = ['--tenant', 'alpha', '--key', vault, '--signing-key', key, '--export', exported];
    const now = new Date('2026-10-08T12:00:00.000Z');
    await build(['--framework', 'eu-ai-act-logging', ...common, '--case-report', report, '--out', join(out, 'eu-whole.tar.gz')], {now});
    await build(['--framework', 'kr-ai-basic-act', ...common, '--from', records[0].recordedAt, '--to', cut, '--out', join(out, 'kr-period.tar.gz')], {now});
    writeFileSync(join(out, 'builder-public.pem'), builder.publicKey.export({format: 'pem', type: 'spki'}));
    writeFileSync(join(out, 'vault-public.pem'), fixture.publicKeyPem);
  } finally { rmSync(tmp, {recursive: true, force: true}); }
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(new URL(import.meta.url).pathname)) {
  await buildOldPackages(resolve(process.argv[2]));
  console.log(JSON.stringify({ok: true, out: resolve(process.argv[2])}));
}
