import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {mkdtempSync,mkdirSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {DatabaseSync,backup} from 'node:sqlite';
import {Store} from '../src/store.mjs';
import {canonical,digest,makeCheckpoint,verifyBundle} from '../src/crypto.mjs';
import {createVaultBackup} from '../src/vault-recovery.mjs';
import {createRetention} from '../src/retention.mjs';
import {createIdentityState} from '../src/identity-state.mjs';
import {signRecoveryFrontier,verifyRecoveryFrontier,applyRecoveryFrontier,MAX_RECOVERY_FRONTIER_BYTES} from '../src/recovery-frontier.mjs';

async function fixture(t,{erase=true,enable=false}={}){
 mkdirSync('.test-runs',{recursive:true});const dir=mkdtempSync(join('.test-runs','evidscope-frontier-')),{privateKey,publicKey}=generateKeyPairSync('ed25519'),source=new Store(join(dir,'source'),privateKey),config={profile:'enterprise',modelId:'credit-v1',principals:[],oidc:{clientSecret:'NOT-EXPORTED-CLIENT-SECRET',bindings:[{id:'alice',tenant:'alpha',subject:'SUBJECT-NOT-EXPORTED',role:'auditor'}]}};
 let restored;t.after(()=>{source.close();restored?.close();rmSync(dir,{recursive:true,force:true});});
 for(const tenant of ['alpha','beta'])source.transaction(()=>{
  source.put({tenant,id:'admin'},'identity_access','alice',{id:'alice',epoch:0,disabled:false});
  source.put({tenant,id:'reviewer'},'retention_policy','current',{id:'current',version:1,retentionSeconds:1});
  const e={tenant,source:'agent',id:'same-event',actionId:'same-action',traceId:'trace',kind:'intent',receivedAt:'2000-01-01T00:00:00.000Z',occurredAt:'2000-01-01T00:00:00.000Z',fingerprint:digest(tenant),note:'NEVER-EXPORT-PLAINTEXT-EVENT-'+tenant};
  const r=source.append(tenant,'event',e,e.source),event={...e,seq:r.seq,hash:r.hash};
  source.projectionMutation(()=>{source.db.prepare('INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)').run(tenant,e.source,e.id,e.fingerprint,e.actionId,e.traceId,e.kind,e.receivedAt,JSON.stringify(event));source.db.prepare('INSERT INTO receipts VALUES(?,?,?,?)').run(tenant,e.source,e.id,e.fingerprint);source.db.prepare('INSERT INTO actions VALUES(?,?,?,?)').run(tenant,e.actionId,1,0);});
 });
 const archiveAnchor=await createVaultBackup({dataDir:join(dir,'source'),backupDir:join(dir,'backup'),privateKey,publicKey});
 // Exercise core replay on the actual pre-change SQLite snapshot. Public restore
 // adds a quarantine marker after replay; activation integration owns that path.
 const restoredPath=join(dir,'restored');mkdirSync(restoredPath);const snapshotDb=new DatabaseSync(join(dir,'source','evidence.db'),{readOnly:true});
 try{await backup(snapshotDb,join(restoredPath,'evidence.db'));}finally{snapshotDb.close();}restored=new Store(restoredPath,privateKey);
 for(const tenant of ['alpha','beta'])assert.deepEqual(restored.checkpoint(tenant),archiveAnchor.checkpoints[tenant]);
 for(const tenant of ['alpha','beta']){
  source.transaction(()=>source.put({tenant,id:'admin'},'identity_access','alice',{id:'alice',epoch:1,disabled:true,action:'disable',reason:'withdrawn',changedBy:'admin',changedAt:new Date().toISOString()}));
  if(enable)source.transaction(()=>source.put({tenant,id:'admin'},'identity_access','alice',{id:'alice',epoch:2,disabled:false,action:'enable'}));
  if(erase){const retention=createRetention(source),reviewer={tenant,id:'reviewer',role:'reviewer'},other={tenant,id:'other-reviewer',role:'reviewer'},admin={tenant,id:'admin',role:'admin'};const p=retention.handle(reviewer,'POST','/api/retention/plans',{reason:'expired synthetic evidence'});retention.handle(other,'POST','/api/retention/plans/'+p.id+'/approve',{reason:'independent review'});retention.handle(admin,'POST','/api/retention/plans/'+p.id+'/execute',{});}
 }
 const bundles=['alpha','beta'].map(tenant=>source.rawBundle(tenant)),signed=signRecoveryFrontier({bundles,archiveAnchor,privateKey,publicKey,config});
 const args={...signed,archiveAnchor,publicKey,config};return {dir,source,restored,privateKey,publicKey,config,bundles,archiveAnchor,...signed,args,apply:()=>applyRecoveryFrontier({store:restored,...args})};
}
function reseal(f,change){const frontier=structuredClone(f.frontier);change(frontier);const {signature,...statement}=frontier;frontier.signature=sign(null,Buffer.from(canonical(statement)),f.privateKey).toString('base64');return {frontier,anchor:{...f.anchor,frontierSha256:digest(frontier)}};}
const snapshot=store=>['alpha','beta'].map(tenant=>({tenant,bundle:store.rawBundle(tenant),events:store.events(tenant),objects:store.list(tenant,'identity_access'),keys:store.db.prepare('SELECT tenant,key_id,seq,hex(key) AS key FROM event_keys WHERE tenant=? ORDER BY seq').all(tenant)}));

test('old backup receives current disable and authorized erasure without restoring revoked access or plaintext',async t=>{
 const f=await fixture(t),before=f.restored.rawBundle('alpha');assert.equal(createIdentityState(f.restored)({id:'alice',tenant:'alpha'}).disabled,false);assert.equal(f.restored.events('alpha').length,1);
 const statement=verifyRecoveryFrontier(f.args);assert.equal(statement.tenants.length,2);
 const serialized=JSON.stringify(f.frontier);for(const secret of ['NOT-EXPORTED-CLIENT-SECRET','SUBJECT-NOT-EXPORTED','NEVER-EXPORT-PLAINTEXT-EVENT-alpha','NEVER-EXPORT-PLAINTEXT-EVENT-beta'])assert.equal(serialized.includes(secret),false);
 assert.equal(serialized.includes('"key"'),false);assert.equal(serialized.includes('ciphertext'),false);
 const receipt=f.apply();assert.deepEqual([receipt.identityStatesApplied,receipt.eventsErased,receipt.executedPlansApplied],[2,2,2]);assert.equal(receipt.freshnessEstablished,false);
 for(const tenant of ['alpha','beta']){
  assert.equal(createIdentityState(f.restored)({id:'alice',tenant}).disabled,true);assert.equal(f.restored.events(tenant).length,0);assert.equal(f.restored.db.prepare('SELECT count(*) AS n FROM event_keys WHERE tenant=?').get(tenant).n,0);
  const b=f.restored.bundle(tenant);assert.equal(verifyBundle(b,f.publicKey).erasedEvents,1);f.restored.checkActionProjection(tenant);assert.equal(f.restored.db.prepare('SELECT version FROM actions WHERE tenant=?').get(tenant).version,2);
  const receiptRow=b.records.find(row=>row.type==='event_receipt'),disposition=b.records.find(row=>row.type==='retention_disposition');assert(receiptRow.seq<disposition.seq);assert.equal(disposition.payload.frontierHash,digest(f.frontier));assert.equal(disposition.payload.sourceDispositions[0].hash,statement.tenants.find(item=>item.tenant===tenant).erasedEvents[0].sourceDispositionHash);
 }
 assert.deepEqual(f.restored.rawBundle('alpha').records.slice(0,before.records.length),before.records);assert.equal(f.restored.list('alpha','retention_plan')[0].status,'executed');
 assert.throws(f.apply,/External checkpoint mismatch/,'a second replay cannot silently alter an activated restored chain');
});

test('latest explicit re-enable wins while other tenant bindings remain distinct',async t=>{
 const f=await fixture(t,{erase:false,enable:true});f.apply();for(const tenant of ['alpha','beta'])assert.deepEqual(createIdentityState(f.restored)({id:'alice',tenant}),{id:'alice',epoch:2,disabled:false,action:'enable'});
 assert.equal(f.restored.events('alpha').length,1);assert.equal(f.restored.events('beta').length,1);assert.equal(createIdentityState(f.restored)({id:'unconfigured',tenant:'beta'}).epoch,0);
});

test('config/model, trust key, frontier signature and independently pinned anchor changes fail closed',async t=>{
 const f=await fixture(t,{erase:false});assert.throws(()=>verifyRecoveryFrontier({...f.args,config:{...f.config,modelId:'credit-v2'}}),/statement/);
 const wrong=generateKeyPairSync('ed25519');assert.throws(()=>verifyRecoveryFrontier({...f.args,publicKey:wrong.publicKey}),/archive anchor/);
 const corrupted={...f.frontier,signature:Buffer.alloc(64).toString('base64')};assert.throws(()=>verifyRecoveryFrontier({...f.args,frontier:corrupted,anchor:{...f.anchor,frontierSha256:digest(corrupted)}}),/signature/);
 for(const mutation of [a=>a.frontierSha256='0'.repeat(64),a=>a.archiveManifestSha256='1'.repeat(64),a=>a.keyFingerprint='2'.repeat(64)]){const anchor=structuredClone(f.anchor);mutation(anchor);assert.throws(()=>verifyRecoveryFrontier({...f.args,anchor}),/anchor/);}
 assert.throws(()=>verifyRecoveryFrontier({...f.args,anchor:undefined}),/anchor/);
});

test('validly signed wrong lineage, missing archive tenant, raw disclosure and plaintext inputs cannot mint a frontier',async t=>{
 const f=await fixture(t,{erase:false}),bundles=structuredClone(f.bundles),b=bundles[0];b.records[0].payload.epoch=100;let previous='0'.repeat(64);for(const row of b.records){row.previous=previous;const {hash,...record}=row;row.hash=digest(record);previous=row.hash;}b.checkpoint=makeCheckpoint('alpha',b.records.length,previous,f.privateKey);
 const input={archiveAnchor:f.archiveAnchor,privateKey:f.privateKey,publicKey:f.publicKey,config:f.config};assert.throws(()=>signRecoveryFrontier({...input,bundles}),/prefix/);
 assert.throws(()=>signRecoveryFrontier({...input,bundles:f.bundles.slice(1)}),/tenant missing/);
 const disclosed=structuredClone(f.bundles);disclosed[0].disclosures=[{seq:3,event:{secret:'private'}}];assert.throws(()=>signRecoveryFrontier({...input,bundles:disclosed}),/raw encrypted/);
 const plaintext=structuredClone(f.bundles),plain=plaintext[0];plain.records[2].payload={tenant:'alpha',actionId:'same-action',note:'plaintext must never be exported'};previous='0'.repeat(64);for(const row of plain.records){row.previous=previous;const {hash,...record}=row;row.hash=digest(record);previous=row.hash;}plain.checkpoint=makeCheckpoint('alpha',plain.records.length,previous,f.privateKey);
 const plainArchive={...f.archiveAnchor,checkpoints:{...f.archiveAnchor.checkpoints,alpha:makeCheckpoint('alpha',3,plain.records[2].hash,f.privateKey)}};assert.throws(()=>signRecoveryFrontier({...input,bundles:plaintext,archiveAnchor:plainArchive}),/plaintext/);
 const altered=structuredClone(f.bundles);altered[0].records[0].payload.epoch=9;assert.throws(()=>signRecoveryFrontier({...input,bundles:altered}),/digest/);
});

test('duplicate tenants, safety references, invalid erasures and oversized payloads are rejected even with a matching fresh signature',async t=>{
 const f=await fixture(t);for(const mutation of [v=>v.tenants.push(structuredClone(v.tenants[0])),v=>v.tenants[0].identityAccess.push(structuredClone(v.tenants[0].identityAccess[0])),v=>v.tenants[0].identityAccess[0].payload.epoch=-1,v=>v.tenants[0].erasedEvents.push(structuredClone(v.tenants[0].erasedEvents[0])),v=>v.tenants[0].erasedEvents[0].seq=999,v=>v.tenants[0].erasedEvents[0].actionId='other-model-action',v=>v.tenants[0].executedRetentionPlans[0].payload.status='approved',v=>v.tenants[0].currentCheckpoint=f.frontier.tenants[1].currentCheckpoint]){assert.throws(()=>verifyRecoveryFrontier({...f.args,...reseal(f,mutation)}));}
 const oversized=structuredClone(f.frontier);oversized.tenants[0].identityAccess[0].payload.reason='x'.repeat(MAX_RECOVERY_FRONTIER_BYTES);assert.throws(()=>verifyRecoveryFrontier({...f.args,frontier:oversized}),/size limit/);
});

test('tampered restored key or signed event hash cannot be replayed',async t=>{
 for(const failure of ['key','hash'])await t.test(failure,async t=>{
  const f=await fixture(t);if(failure==='key')f.restored.db.prepare("UPDATE event_keys SET key=zeroblob(32) WHERE tenant='alpha'").run();else{f.restored.db.exec('DROP TRIGGER immutable_update');f.restored.db.prepare("UPDATE ledger SET hash=? WHERE tenant='alpha' AND seq=3").run('0'.repeat(64));}
  const before=snapshot(f.restored);assert.throws(f.apply);assert.deepEqual(snapshot(f.restored),before);
 });
});

test('later-tenant missing key and cross-tenant injection roll back all earlier safety changes atomically',async t=>{
 for(const failure of ['missing-key','tenant'])await t.test(failure,async t=>{
  const f=await fixture(t);if(failure==='missing-key')f.restored.db.prepare("DELETE FROM event_keys WHERE tenant='beta'").run();else f.restored.db.prepare('INSERT INTO objects VALUES(?,?,?,?)').run('other-tenant','identity_access','alice',JSON.stringify({id:'alice',epoch:0,disabled:false}));
  const before=snapshot(f.restored);assert.throws(f.apply,/key missing|tenant set/);assert.deepEqual(snapshot(f.restored),before);assert.equal(f.restored.get('alpha','identity_access','alice').disabled,false);assert.equal(f.restored.events('alpha').length,1);
 });
});

test('frontier pin authenticates chosen snapshot but cannot certify latest operational freshness',async t=>{
 const f=await fixture(t,{erase:false}),previous=structuredClone(f.args);f.source.transaction(()=>f.source.put({tenant:'alpha',id:'admin'},'identity_access','alice',{id:'alice',epoch:2,disabled:false,action:'enable'}));
 assert.equal(verifyRecoveryFrontier(previous).tenants[0].identityAccess[0].payload.disabled,true);assert.equal(f.apply().freshnessEstablished,false);
});

test('frontier-applied snapshot can be backed up and captured again without replaying its archived derived erasure',async t=>{
 const f=await fixture(t);f.apply();
 const archiveAnchor=await createVaultBackup({dataDir:join(f.dir,'restored'),backupDir:join(f.dir,'second-backup'),privateKey:f.privateKey,publicKey:f.publicKey});
 f.restored.transaction(()=>f.restored.put({tenant:'alpha',id:'admin'},'identity_access','alice',{id:'alice',epoch:2,disabled:false,action:'enable'}));
 const signed=signRecoveryFrontier({bundles:['alpha','beta'].map(tenant=>f.restored.rawBundle(tenant)),archiveAnchor,privateKey:f.privateKey,publicKey:f.publicKey,config:f.config});
 const statement=verifyRecoveryFrontier({...signed,archiveAnchor,publicKey:f.publicKey,config:f.config});assert.equal(statement.tenants.flatMap(item=>item.erasedEvents).length,0);assert.equal(statement.tenants[0].identityAccess[0].payload.disabled,false);
});
