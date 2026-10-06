import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,randomUUID} from 'node:crypto';
import {existsSync,mkdtempSync,readFileSync,renameSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve,sep} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {createService} from '../src/service.mjs';
import {canonical,mac,verifyBundle} from '../src/crypto.mjs';
import {ACCESS_BATCH_TYPE,ACCESS_LOG_FILE,verifyAccessBatches,verifyAccessInclusion,verifyAccessLogDatabase} from '../src/access-log.mjs';
import {createVaultBackup,restoreVaultBackup} from '../src/vault-recovery.mjs';
import * as T from '../src/tlog.mjs';
import {BASE,ledgerCount,transparencyFixture} from './support/transparency-fixture.mjs';

const requirements=JSON.parse(readFileSync(new URL('../data/requirements.json',import.meta.url),'utf8'));
const principals=[{id:'auditor',role:'auditor',tenant:'alpha',token:'u'.repeat(40)},{id:'admin',role:'admin',tenant:'alpha',token:'a'.repeat(40)},
 {id:'reviewer',role:'reviewer',tenant:'alpha',token:'r'.repeat(40)},
  {id:'source',role:'source',kind:'tool',tenant:'alpha',token:'s'.repeat(40),hmacSecret:'h'.repeat(40)}];

function fixture(t,accessLog={}){
 const root=mkdtempSync(join(tmpdir(),'evidscope-access-log-')),dir=join(root,'data'),{privateKey,publicKey}=generateKeyPairSync('ed25519');
 const service=createService({dataDir:dir,key:privateKey,config:{principals},requirements,accessLog}),store=service.store;
 t.after(()=>{service.accessLog.stop();store.close();assert.ok(resolve(root).startsWith(resolve(tmpdir())+sep));rmSync(root,{recursive:true,force:true});});
 const call=(path,who=0,body)=>service.handle(body===undefined?'GET':'POST',new URL(path,'http://local'),{authorization:'Bearer '+principals[who].token},
  body===undefined?'':JSON.stringify(body));
 const status=(path,who)=>call(path,who).then(()=>200,error=>error.status);
 const ledger=()=>store.rawBundle('alpha').records;
 // An external connection (another process or a file-level attacker) that bypasses the service's own guards.
 const external=fn=>{const db=new DatabaseSync(join(dir,ACCESS_LOG_FILE));try{return fn(db);}finally{db.close();}};
 const entries=()=>external(db=>db.prepare("SELECT seq,body,hash FROM access_log WHERE tenant='alpha' ORDER BY seq").all());
 async function ingest(id){
  const body=JSON.stringify({id,actionId:'action-one',traceId:'trace',kind:'result',status:'success',occurredAt:new Date().toISOString()});
  const timestamp=String(Date.now()),nonce=randomUUID(),source=principals[3];
  return service.handle('POST',new URL('/api/ingest','http://local'),{authorization:'Bearer '+source.token,'x-evid-timestamp':timestamp,'x-evid-nonce':nonce,
   'x-evid-signature':mac(source.hmacSecret,timestamp,nonce,body)},body);
 }
 return {root,dir,privateKey,publicKey,service,store,call,status,ledger,external,entries,ingest};
}
const settle=()=>new Promise(resolve=>setImmediate(resolve));

test('reads are recorded in the hash-chained access log before routing and never append ledger rows or re-sign the checkpoint',async t=>{
 const h=fixture(t);await h.ingest('event-one');
 const checkpoint=h.store.checkpoint('alpha'),count=h.ledger().length;
 for(const path of ['/api/cases','/api/events?q=secret&kind=result','/api/overview','/api/metrics'])await h.call(path);
 assert.equal(await h.status('/api/audit/reads',2),403,'role-denied read');assert.equal(await h.status('/api/does-not-exist',0),404,'unknown path');
 assert.equal(await h.status('/api/rules',3),403,'non-human principals are refused before the access log, as before');
 assert.deepEqual(h.store.checkpoint('alpha'),checkpoint);assert.equal(h.ledger().length,count);
 const rows=h.entries(),entries=rows.map(row=>JSON.parse(row.body));
 assert.deepEqual(entries.map(e=>e.target),['/api/cases','/api/events','/api/overview','/api/metrics','/api/audit/reads','/api/does-not-exist']);
 assert.deepEqual(verifyAccessBatches('alpha',[],rows),{valid:true,batches:0,sealedEntries:0,unsealedEntries:6});
 const search=entries[1];
 assert.equal(search.principal,'auditor');assert.equal(search.authentication,'bearer');assert.equal(search.method,'GET');assert.equal(search.operation,'read');
 assert.match(search.queryHash,/^[a-f0-9]{64}$/);assert.ok(!rows[1].body.includes('secret'),'query values are stored only as a hash');
  assert.equal(entries[0].queryHash,null);
 assert.deepEqual(search.observed,{count:checkpoint.count,head:checkpoint.head},'each read is bound to the signed state it was served from');
 const metrics=await h.call('/api/metrics');assert.equal(metrics.accessLog.unsealedEntries,7);assert.equal(metrics.accessLog.oldestUnsealedAt,entries[0].at);
});

test('a read whose access record cannot be written fails with 503 and serves nothing',async t=>{
 const h=fixture(t);await h.ingest('event-one');
 h.external(db=>db.exec("CREATE TRIGGER refuse BEFORE INSERT ON access_log BEGIN SELECT RAISE(ABORT,'disk full'); END;"));
 let served=false;const verifiedFacets=h.store.verifiedFacets.bind(h.store);h.store.verifiedFacets=(...args)=>{served=true;return verifiedFacets(...args);};
 await assert.rejects(h.call('/api/events'),error=>error.status===503&&/Access log unavailable/.test(error.message));
 assert.equal(served,false,'the handler never ran');
 h.external(db=>db.exec('DROP TRIGGER refuse'));assert.equal((await h.call('/api/events')).total,1);
});

test('export and integrity seal the unsealed reads, including their own, into a contiguous Merkle-rooted ledger batch',async t=>{
 const h=fixture(t);await h.ingest('event-one');
 for(let i=0;i<5;i++)await h.call('/api/cases');
 const first=await h.call('/api/export');assert.equal(verifyBundle(first,h.store.publicKey).valid,true);
 const batches=first.records.filter(row=>row.type===ACCESS_BATCH_TYPE);assert.equal(batches.length,1);
 assert.deepEqual({...batches[0].payload,merkleRoot:undefined,head:undefined,firstAt:undefined,lastAt:undefined},
  {format:'evidscope-access-batch-v1',fromSeq:1,toSeq:6,count:6,previous:'0'.repeat(64),reason:'export',
   merkleRoot:undefined,head:undefined,firstAt:undefined,lastAt:undefined});
 assert.equal(batches[0].principal,'auditor');assert.equal(JSON.parse(h.entries()[5].body).target,'/api/export','the export covers its own read');
 const second=await h.call('/api/export');assert.notDeepEqual(second.checkpoint,first.checkpoint);
  assert.throws(()=>verifyBundle(first,h.store.publicKey,second.checkpoint));
 await h.call('/api/rules');const integrity=await h.call('/api/integrity');
 assert.equal(integrity.valid,true);assert.ok(integrity.verificationScope.checks.includes('access_log'));
 assert.deepEqual({...integrity.accessLog,oldestUnsealedAt:undefined},
  {valid:true,batches:3,sealedEntries:9,unsealedEntries:0,oldestUnsealedAt:undefined,maxUnsealedAgeMs:900000});
 const all=h.ledger().filter(row=>row.type===ACCESS_BATCH_TYPE);
 assert.deepEqual(all.map(row=>[row.payload.fromSeq,row.payload.toSeq,row.payload.reason]),[[1,6,'export'],[7,7,'export'],[8,9,'integrity']]);
 assert.equal(all[1].payload.previous,all[0].payload.head);
 assert.deepEqual(verifyAccessBatches('alpha',h.ledger(),h.entries()),{valid:true,batches:3,sealedEntries:9,unsealedEntries:0});
 // One read is provable from the signed batch alone; altered bodies, positions and proofs are rejected.
 const proof=await h.call('/api/audit/reads/proof?seq=3',1);
 assert.equal(proof.batch.hash,all[0].hash);assert.equal(verifyAccessInclusion(proof.body,3,all[0].payload,proof.proof),true);
 assert.equal(verifyAccessInclusion(proof.body,4,all[0].payload,proof.proof),false);
 assert.equal(verifyAccessInclusion(proof.body.replace('/api/cases','/api/rules'),3,all[0].payload,proof.proof),false);
 assert.equal(verifyAccessInclusion(proof.body,3,all[0].payload,proof.proof.slice(1)),false);
 assert.equal(await h.status('/api/audit/reads/proof?seq=3',2),403,'reviewers cannot read other people\'s access records');
 const listed=await h.call('/api/audit/reads?fromSeq=2&limit=2',1);assert.deepEqual(listed.items.map(item=>item.seq),[2,3]);
 assert.equal(canonical(listed.items[1].entry),proof.body);
 // Offline: a sealed range with a missing or altered entry no longer matches its signed batch.
 assert.throws(()=>verifyAccessBatches('alpha',h.ledger(),h.entries().filter(row=>row.seq!==4)),/missing|chain mismatch/);
 const forged=h.entries().map(row=>row.seq===4?{...row,body:row.body.replace('/api/cases','/api/rules')}:row);
 assert.throws(()=>verifyAccessBatches('alpha',h.ledger(),forged),/chain mismatch/);
});

test('/api/integrity detects altered, missing and reordered access entries and a stalled sealer',async t=>{
 const h=fixture(t,{maxUnsealedAgeMs:60000});await h.ingest('event-one');
 for(let i=0;i<3;i++)await h.call('/api/cases');
 assert.equal((await h.call('/api/integrity')).valid,true);
 const sealed=h.entries()[1];
 h.external(db=>{db.exec('DROP TRIGGER access_log_immutable_update');
  db.prepare("UPDATE access_log SET body=? WHERE tenant='alpha' AND seq=2").run(sealed.body.replace('/api/cases','/api/rules'));});
 let result=await h.call('/api/integrity');assert.equal(result.valid,false);assert.match(result.error,/Access log/);assert.equal(result.failureRecorded,true);
 const altered=h.entries()[1];
 h.external(db=>db.prepare("UPDATE access_log SET hash=? WHERE tenant='alpha' AND seq=2").run(createHash('sha256').update(altered.body).digest('hex')));
 result=await h.call('/api/integrity');assert.equal(result.valid,false,'a re-hashed entry breaks the chain or the sealed root');
 h.external(db=>db.prepare("UPDATE access_log SET body=?,hash=? WHERE tenant='alpha' AND seq=2").run(sealed.body,sealed.hash));
 assert.equal((await h.call('/api/integrity')).valid,true);
 h.external(db=>{db.exec('DROP TRIGGER access_log_immutable_delete');db.prepare("DELETE FROM access_log WHERE tenant='alpha' AND seq=1").run();});
 result=await h.call('/api/integrity');assert.equal(result.valid,false);assert.match(result.error,/Access log/);
 // The unsealed tail is checked when sealing, so an export refuses to seal over an altered unsealed entry.
 const g0=fixture(t);await g0.call('/api/cases');await g0.call('/api/rules');
 g0.external(db=>{db.exec('DROP TRIGGER access_log_immutable_update');
  db.prepare("UPDATE access_log SET body=replace(body,'/api/rules','/api/cases') WHERE tenant='alpha' AND seq=2").run();});
 assert.equal(await g0.status('/api/export'),409);assert.equal(g0.ledger().filter(row=>row.type===ACCESS_BATCH_TYPE).length,0);
 // A stalled sealer: the unsealed tail is reported and becomes an integrity failure once it exceeds the maximum age.
 const g=fixture(t,{maxUnsealedAgeMs:50});await g.call('/api/cases');
 assert.equal(g.service.accessLog.status('alpha').unsealedEntries,1);
 assert.throws(()=>g.service.accessLog.verify('alpha',g.ledger(),{now:Date.now()+1000}),/sealing has stalled/);
 assert.equal((await g.call('/api/integrity')).valid,true,'integrity seals first, so a working sealer never reports a stale tail');
});

test('the access log seals on threshold, on its interval timer and on shutdown, and sealing keeps the signed ledger verifiable',async t=>{
 const h=fixture(t,{sealThreshold:3,sealIntervalMs:40});await h.ingest('event-one');
 await h.call('/api/cases');await h.call('/api/cases');await settle();
 assert.equal(h.ledger().filter(row=>row.type===ACCESS_BATCH_TYPE).length,0);
 await h.call('/api/cases');await settle();
 assert.deepEqual(h.ledger().filter(row=>row.type===ACCESS_BATCH_TYPE).map(row=>[row.payload.count,row.payload.reason,row.principal]),
  [[3,'threshold','access-log-sealer']]);
 await h.call('/api/rules');h.service.accessLog.start();await new Promise(resolve=>setTimeout(resolve,120));
 assert.deepEqual(h.ledger().filter(row=>row.type===ACCESS_BATCH_TYPE).map(row=>row.payload.reason),['threshold','interval']);
 await h.call('/api/rules');h.service.accessLog.stop();
 assert.deepEqual(h.ledger().filter(row=>row.type===ACCESS_BATCH_TYPE).map(row=>row.payload.reason),['threshold','interval','shutdown']);
 assert.equal(verifyBundle(h.store.bundle('alpha'),h.store.publicKey).valid,true);
 assert.equal(h.store.checkActionProjection('alpha').valid,true,'batch records pass through the verified state');
});

test('a heads checkpoint about to be published first seals pending reads; reads alone do not start a round',async t=>{
 const f=await transparencyFixture(t,{witness:false}),s=await f.open('enforce');
 f.write(s,'alpha',2);await s.transparency.pump();
 const heads=()=>JSON.parse(s.store.db.prepare('SELECT entries FROM tlog_heads WHERE origin=? ORDER BY idx DESC LIMIT 1').get(T.headsOrigin(BASE)).entries)
  .find(entry=>entry.log===T.tenantOrigin(BASE,'alpha'));
 await f.call(s,'/api/cases');const rows=ledgerCount(s,'alpha'),size=heads().size;
 await s.transparency.pump();
 assert.equal(ledgerCount(s,'alpha'),rows,'no seal without a pending checkpoint');assert.equal(s.accessLog.status('alpha').unsealedEntries,1);
 f.write(s,'alpha',1);await s.transparency.pump();
 const last=s.store.rawBundle('alpha').records.at(-1);
 assert.equal(last.type,ACCESS_BATCH_TYPE);assert.equal(last.payload.reason,'checkpoint_publish');
 assert.equal(heads().size,ledgerCount(s,'alpha'),'the published heads leaf covers the sealed reads');assert.ok(heads().size>size);
 assert.equal(s.accessLog.status('alpha').unsealedEntries,0);
});

test('vault backups carry the encrypted access log, restore it verified, and refuse a vault whose sealed reads are missing',async t=>{
 const h=fixture(t);await h.call('/api/cases');await h.call('/api/integrity');await h.call('/api/rules');
 const keys={privateKey:h.privateKey,publicKey:h.publicKey},backupDir=join(h.root,'backup');
 const anchor=await createVaultBackup({dataDir:h.dir,backupDir,...keys}),manifest=JSON.parse(readFileSync(join(backupDir,'manifest.json'),'utf8'));
 assert.ok(manifest.files.some(file=>file.path==='access-log.db.enc'));assert.deepEqual(manifest.accessLog.tenants,{alpha:{sealedEntries:2,batches:1}});
 assert.ok(!readFileSync(join(backupDir,'access-log.db.enc')).includes(Buffer.from('/api/cases')),'the access log is encrypted at rest in the backup');
 const restored=await restoreVaultBackup({backupDir,restoreDir:join(h.root,'restored'),...keys,anchor});
 const db=new DatabaseSync(join(restored.restoredDirectory,ACCESS_LOG_FILE),{readOnly:true});
 try{assert.deepEqual(verifyAccessLogDatabase(db,'alpha',h.ledger()),
  {valid:true,batches:1,sealedEntries:2,unsealedEntries:1,oldestUnsealedAt:JSON.parse(h.entries()[2].body).at});}
 finally{db.close();}
 renameSync(join(h.dir,ACCESS_LOG_FILE),join(h.root,'moved.db'));assert.equal(existsSync(join(h.dir,ACCESS_LOG_FILE)),false);
 await assert.rejects(createVaultBackup({dataDir:h.dir,backupDir:join(h.root,'backup-2'),...keys}),/Access log is missing beneath sealed access batches/);
});
