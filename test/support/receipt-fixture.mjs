// A vault with witnessed tenant logs and the standard receipts it serves (docs/receipts.md), written to files the way an
// auditor would save the API responses.
import {mkdirSync, writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {appendSourceEvent} from '../../src/event-ingest.mjs';
import {validateEvent} from '../../src/model.mjs';
import {BASE, transparencyFixture} from './transparency-fixture.mjs';

const post = (s, path, body, tenant) =>
  s.handle('POST', new URL(path, 'http://local'), {authorization: 'Bearer ' + tenant.repeat(40)}, JSON.stringify(body));
// Two agent events of one action and a case about it; returns the case ID.
export async function caseFor(s, tenant = 'alpha') {
  const src = {id: 'agent-src', tenant, role: 'source', kind: 'agent'}, actionId = 'act-receipt';
  for (const id of ['intent-1', 'claim-1']) {
    const e = validateEvent({id, kind: id.startsWith('intent') ? 'intent' : 'self_report', status: 'success', actionId, traceId: 'trace-1',
      occurredAt: new Date().toISOString(), actor: 'assistant', tool: 'crm', action: 'update', resource: 'case-7'}, src);
    s.store.transaction(() => appendSourceEvent(s.store, src, e));
  }
  return (await post(s, '/api/cases', {title: 'receipt case', owner: 'audit-team', actionId}, tenant)).id;
}
export async function receiptFixture(t, dir) {
  const f = await transparencyFixture(t, {tenantLogs: true}), s = await f.open('enforce');
  const caseId = await caseFor(s);
  f.write(s, 'alpha', 2);
  await s.transparency.pump();
  const responses = {
    export: await f.call(s, '/api/export?attest=intoto'), report: await f.call(s, `/api/cases/${caseId}/report?attest=intoto`),
    record: await f.call(s, '/api/receipts/record?seq=1'),
  };
  mkdirSync(dir, {recursive: true});
  const files = {key: join(dir, 'vault-public.pem')};
  writeFileSync(files.key, f.publicKey.export({format: 'pem', type: 'spki'}));
  for (const [name, value] of Object.entries(responses)) writeFileSync(files[name] = join(dir, `${name}-response.json`), JSON.stringify(value));
  return {f, s, caseId, responses, files, flags: ['--witness', f.w.vkey, '--quorum', '1', '--origin-base', BASE, '--max-staleness', '3600']};
}
