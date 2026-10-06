import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,randomUUID} from 'node:crypto';
import {mkdtempSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {createService} from '../src/service.mjs';
import {digest,mac} from '../src/crypto.mjs';
import {validateEvent} from '../src/model.mjs';

function fixture(t){
 const root=mkdtempSync(join(tmpdir(),'evidscope-receipt-')),{privateKey}=generateKeyPairSync('ed25519');
 const source={id:'alpha-tool',tenant:'alpha',role:'source',kind:'tool',token:'s'.repeat(40),hmacSecret:'receipt-hmac-secret'};
 const reviewer={id:'alpha-reviewer',tenant:'alpha',role:'reviewer',token:'r'.repeat(40)};
 const admin={id:'alpha-admin',tenant:'alpha',role:'admin',token:'a'.repeat(40)};
 const service=createService({dataDir:root,key:privateKey,config:{principals:[source,reviewer,admin]},requirements:[]});t.after(()=>service.store.close());
 const raw=id=>({id,kind:'result',occurredAt:new Date().toISOString(),actionId:'loan-decision',traceId:'trace-1',status:'success'});
 const submit=value=>{const body=JSON.stringify(value),timestamp=String(Date.now()),nonce=randomUUID();return service.handle('POST',new URL('/api/ingest','http://localhost'),{authorization:'Bearer '+source.token,'x-evid-timestamp':timestamp,'x-evid-nonce':nonce,'x-evid-signature':mac(source.hmacSecret,timestamp,nonce,body)},body);};
 const integrity=()=>service.handle('GET',new URL('/api/integrity','http://localhost'),{authorization:'Bearer '+reviewer.token});
 return {root,service,source,reviewer,admin,raw,submit,integrity};
}

test('unsigned receipt injection cannot turn a missing event into durable duplicate success',async t=>{
 const f=fixture(t),event=f.raw('poisoned');
 f.service.store.db.prepare('INSERT INTO receipts VALUES(?,?,?,?)').run('alpha',f.source.id,event.id,digest(event));
 await assert.rejects(f.submit(event),error=>error.status===409&&/영수증|이벤트 조회/.test(error.message));
 assert.equal(f.service.store.db.prepare("SELECT count(*) n FROM ledger WHERE tenant='alpha' AND json_extract(body,'$.type')='event'").get().n,0);
 assert.equal(f.service.store.db.prepare("SELECT count(*) n FROM actions WHERE tenant='alpha'").get().n,0);
 const checked=await f.integrity();assert.equal(checked.valid,false);assert.match(checked.error,/Receipt projection/);
});

test('prepared receipt mutation executed after cache warm cannot bypass runtime invalidation',async t=>{
 const f=fixture(t),event=f.raw('prepared-poison'),prepared=f.service.store.db.prepare('INSERT INTO receipts VALUES(?,?,?,?)');
 f.service.store.transaction(()=>assert.deepEqual(f.service.store.checkActionProjection('alpha'),{valid:true,actions:0}));
 prepared.run('alpha',f.source.id,event.id,digest(event));
 f.service.store.audit(f.reviewer,'read','runtime-clock-regression');
 await assert.rejects(f.submit(event),error=>error.status===409&&/영수증|이벤트 조회/.test(error.message));
 assert.equal(f.service.store.db.prepare("SELECT count(*) n FROM ledger WHERE tenant='alpha' AND json_extract(body,'$.type')='event'").get().n,0);
});

test('mutation clock cannot be reset by application SQL',t=>{
 const f=fixture(t),clock=f.service.store.db.prepare('SELECT serial FROM projection_mutation_clock WHERE id=1').get().serial;
 assert.throws(()=>f.service.store.db.prepare('UPDATE projection_mutation_clock SET serial=? WHERE id=1'),/not authorized/);
 assert.equal(f.service.store.db.prepare('SELECT serial FROM projection_mutation_clock WHERE id=1').get().serial,clock);
});

test('an untrusted trigger cannot hide protected-table side effects inside a trusted append',t=>{
 const f=fixture(t),other=new DatabaseSync(join(f.root,'evidence.db'));t.after(()=>other.close());
 other.exec("CREATE TRIGGER extra_receipt AFTER INSERT ON ledger WHEN NEW.tenant='alpha' BEGIN INSERT OR IGNORE INTO receipts VALUES('alpha','alpha-tool','trigger-poison','"+'a'.repeat(64)+"'); END");
 f.service.store.transaction(()=>f.service.store.checkActionProjection('alpha'));
 assert.throws(()=>f.service.store.audit(f.reviewer,'read','trigger-boundary'),/not authorized/);
 assert.equal(f.service.store.db.prepare("SELECT COUNT(*) n FROM receipts WHERE id='trigger-poison'").get().n,0);
});

test('incremental receipt verification rejects an invalid signed suffix before a cold replay',async t=>{
 const f=fixture(t),event=f.raw('invalid-suffix');await f.submit(event);
 f.service.store.transaction(()=>f.service.store.checkActionProjection('alpha'));
 f.service.store.transaction(()=>f.service.store.append('alpha','event_receipt',{format:'evidscope-event-receipt-v1',basis:'source_ingest',source:f.source.id,id:event.id,fingerprint:digest(event),eventSeq:999,eventHash:'f'.repeat(64)},f.source.id));
 assert.throws(()=>f.service.store.transaction(()=>f.service.store.checkActionProjection('alpha')),/Receipt signed history/);
 f.service.store.actionProjectionCache.clear();
 assert.throws(()=>f.service.store.transaction(()=>f.service.store.checkActionProjection('alpha')),/Receipt signed history/);
});

test('signed receipt binds normal duplicate success and integrity evidence',async t=>{
 const f=fixture(t),event=f.raw('normal');
 const first=await f.submit(event),again=await f.submit(event);assert.equal(first.duplicate,false);assert.equal(again.duplicate,true);
 const records=f.service.store.rawBundle('alpha').records,receipts=records.filter(row=>row.type==='event_receipt');
 assert.equal(receipts.length,1);assert.equal(receipts[0].payload.source,f.source.id);assert.equal(receipts[0].payload.id,event.id);assert.equal(receipts[0].payload.basis,'source_ingest');
 const checked=await f.integrity();assert.equal(checked.valid,true);assert.deepEqual(checked.receiptProjection,{valid:true,receipts:1,signedReceipts:1,legacyRetainedReceipts:0,unverifiableLegacyDisposedReceipts:0});
});

test('retention signs a verified legacy receipt before destroying its event key',async t=>{
 const f=fixture(t),event=f.raw('legacy-retention'),request=(path,body,principal)=>f.service.handle(body===undefined?'GET':'POST',new URL(path,'http://localhost'),{authorization:'Bearer '+principal.token},body===undefined?'':JSON.stringify(body));
 await request('/api/retention/policy',{retentionSeconds:1,purpose:'legacy transition test',reason:'synthetic only'},f.reviewer);
 const normalized=validateEvent(event,f.source);
 f.service.store.transaction(()=>{
  const record=f.service.store.append('alpha','event',normalized,f.source.id);
  f.service.store.project({...normalized,seq:record.seq,hash:record.hash});
  f.service.store.db.prepare('INSERT INTO actions(tenant,id,version) VALUES(?,?,1)').run('alpha',normalized.actionId);
 });
 assert.equal((await f.integrity()).valid,true);
 await new Promise(resolve=>setTimeout(resolve,1100));
 const plan=await request('/api/retention/plans',{reason:'verified legacy expiry'},f.reviewer);assert.equal(plan.items[0].receiptSigned,false);
 await request(`/api/retention/plans/${plan.id}/approve`,{reason:'independent review'},f.admin);
 await request(`/api/retention/plans/${plan.id}/execute`,{},f.admin);
 const records=f.service.store.rawBundle('alpha').records,receipt=records.find(row=>row.type==='event_receipt');
 assert.equal(receipt.payload.basis,'verified_before_retention');assert.equal(receipt.payload.attestedBy,f.admin.id);assert.ok(receipt.seq<records.find(row=>row.type==='retention_disposition').seq);
 assert.equal((await f.integrity()).valid,true);
 const rebuilt=await request('/api/rebuild',{},f.admin);assert.equal(rebuilt.rebuilt,0);assert.equal(rebuilt.receipts,1);
 assert.equal((await f.submit(event)).duplicate,true);assert.equal((await f.integrity()).valid,true);
});

for(const [name,mutate] of [
 ['fingerprint',db=>db.prepare("UPDATE receipts SET fingerprint='forged' WHERE tenant='alpha'").run()],
 ['source',db=>db.prepare("UPDATE receipts SET source='other-source' WHERE tenant='alpha'").run()],
 ['id',db=>db.prepare("UPDATE receipts SET id='other-id' WHERE tenant='alpha'").run()],
 ['missing',db=>db.prepare("DELETE FROM receipts WHERE tenant='alpha'").run()],
 ['extra',db=>db.prepare("INSERT INTO receipts VALUES('alpha','alpha-tool','extra',?)").run('a'.repeat(64))],
])test(`receipt projection detects ${name} rows and rebuild restores only signed truth`,async t=>{
 const f=fixture(t),event=f.raw('bound');await f.submit(event);mutate(f.service.store.db);
 assert.equal((await f.integrity()).valid,false);
 const rebuilt=await f.service.handle('POST',new URL('/api/rebuild','http://localhost'),{authorization:'Bearer '+f.admin.token},'{}');
 assert.equal(rebuilt.receipts,1);assert.equal((await f.submit(event)).duplicate,true);assert.equal((await f.integrity()).valid,true);
});
