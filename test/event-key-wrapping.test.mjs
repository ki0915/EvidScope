// Round 2, audit S3 step 2: event keys wrapped under per-tenant epoch secrets kept in a keystore outside evidence.db.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createDecipheriv,createPublicKey,generateKeyPairSync} from 'node:crypto';
import {chmodSync,copyFileSync,cpSync,existsSync,readFileSync,readdirSync,rmSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {DatabaseSync} from 'node:sqlite';
import {gunzipSync} from 'node:zlib';
import {Store} from '../src/store.mjs';
import {canonical,digest,verifyBundle} from '../src/crypto.mjs';
import {createKeyring,dataKeyId,generateDataKeyFile,readDataKeyFile} from '../src/data-keys.mjs';
import {compareFingerprint,epochEnd} from '../src/event-keys.mjs';
import {createEventKeystore,dataKeySealer,openEventKeystore} from '../src/event-keystore.mjs';
import {createVaultBackup,restoreVaultBackup} from '../src/vault-recovery.mjs';
import {destroyEventKeyEpoch,listEventKeyEpochs,migrateEventKeystore} from '../scripts/event-keys.mjs';
import {migrateDocuments} from '../scripts/data-key.mjs';
import {submit} from '../src/client.mjs';
import {harness} from './harness.mjs';
import {tempDir} from './temp-dir.mjs';
import {restoreBaseFixture,vault} from './event-key-vault.mjs';

const later=ms=>new Promise(done=>setTimeout(done,ms)),run=promisify(execFile);
const TAG=/^fp2:(\d{4}-(?:0[1-9]|1[0-2])):[a-f0-9]{64}$/;
const onDisk=(dir,needle)=>['evidence.db','evidence.db-wal'].some(name=>existsSync(join(dir,name))&&readFileSync(join(dir,name)).includes(needle));
const policy=(v,retentionSeconds)=>v.call('/api/retention/policy','alpha-reviewer',{retentionSeconds,purpose:'S3 keystore',reason:'synthetic only'});
const receiptOf=(store,id)=>store.bundle('alpha').records.find(row=>row.type==='event_receipt'&&row.payload.id===id).payload;
const event=(id,extra={})=>({id,actionId:id,traceId:'wrap',kind:'intent',occurredAt:new Date().toISOString(),note:`note of ${id}`,...extra});
// A workspace like a deployment: DATA_DIR, the data key and the keystore are three separate places.
function workspace(prefix='evidscope-wrap-'){
 const root=tempDir(prefix),keystoreDir=join(root,'keystore'),keyFile=join(root,'data-encryption.key');
 generateDataKeyFile(keyFile);createEventKeystore(keystoreDir);
 return {root,dataDir:join(root,'data'),keystoreDir,keyFile,dataKey:readDataKeyFile(keyFile)};
}
const keystoreOptions=w=>({dataKey:w.dataKey,eventKeystoreDir:w.keystoreDir});
const keystoreFor=w=>openEventKeystore({dir:w.keystoreDir,sealer:dataKeySealer(createKeyring({dataKey:w.dataKey})),dataDir:w.dataDir});
// A reader of a copied evidence.db that also holds the data key and the current keystore (the strongest copy holder).
function copyReader(t,file,w,key){
 const store=Object.create(Store.prototype);store.key=key;store.publicKey=createPublicKey(key);store.eventKeyProvider=keystoreFor(w);
 store.db=new DatabaseSync(file,{readOnly:true});t.after(()=>store.db.close());return store;
}

test('a keystore vault stores key || salt wrapped under its epoch secret and needs the same keystore and data key to start',async t=>{
 const w=workspace(),v=vault(t,{dir:w.dataDir,options:keystoreOptions(w),cleanup:false});
 assert.deepEqual(v.service.eventKeystore,{keystoreId:keystoreFor(w).id,wrappedKeys:0,importedEpochs:0,importedTombstones:0});
 for(const id of ['wrap-1','wrap-2'])assert.equal((await v.ingest(event(id))).status,202);
 const rows=v.store.db.prepare('SELECT key_id,seq,key FROM event_keys WHERE tenant=? ORDER BY seq').all('alpha');
 for(const row of rows){const key=Buffer.from(row.key);assert.equal(key.length,97);assert.equal(key.subarray(0,4).toString(),'EKW1');}
 assert.equal(v.store.db.prepare('SELECT COUNT(*) n FROM event_key_epochs').get().n,0,'no epoch secret in evidence.db');
 const epoch=TAG.exec(receiptOf(v.store,'wrap-1').fingerprint)[1],keystore=keystoreFor(w);
 assert.deepEqual(keystore.list('alpha').map(item=>[item.epoch,item.kid]),[[epoch,dataKeyId(w.dataKey)]]);
 const files=readdirSync(join(w.keystoreDir,'epochs'),{recursive:true}).filter(name=>name.endsWith('.json'));assert.equal(files.length,1);
 const exported=(await v.call('/api/export','alpha-reviewer')).body;assert.equal(verifyBundle(exported,v.store.publicKey).disclosedEvents,2);
 const integrity=(await v.call('/api/integrity','alpha-reviewer')).body;assert.equal(integrity.valid,true,integrity.error);
 const status=integrity.keySeparation.eventKeys;
 assert.deepEqual([status.storage,status.keys,status.epochs.storage,status.epochDestructionReachesOldCopies,status.confidentialityAgainstDatabaseReader],
  ['keystore_wrapped',{wrapped:2,unwrapped:0},'keystore','ledger_ciphertext_and_receipt_tags',false]);
 assert.equal(status.vaultBackupEventProjection,'excluded_rebuilt_on_restore');
 // The AAD binds each wrapped key to its own event: swapping two of them is detected, not silently decrypted.
 const swap=v.store.db.prepare('UPDATE event_keys SET key=? WHERE tenant=? AND key_id=?');
 swap.run(rows[1].key,'alpha',rows[0].key_id);swap.run(rows[0].key,'alpha',rows[1].key_id);
 assert.equal((await v.call('/api/integrity','alpha-reviewer')).body.valid,false);
 swap.run(rows[0].key,'alpha',rows[0].key_id);swap.run(rows[1].key,'alpha',rows[1].key_id);
 v.store.close();
 const start=options=>vault(t,{dir:w.dataDir,key:v.key,options,cleanup:false});
 assert.throws(()=>start({dataKey:w.dataKey}),/wrapped by event keystore .*EVENT_KEYSTORE_DIR/);
 const other=join(w.root,'other-keystore');createEventKeystore(other);
 assert.throws(()=>start({dataKey:w.dataKey,eventKeystoreDir:other}),/another event keystore/);
 assert.throws(()=>start({eventKeystoreDir:w.keystoreDir}),/data key\(s\) that are not configured/);
 const inside=join(w.dataDir,'keystore');createEventKeystore(inside);
 assert.throws(()=>start({dataKey:w.dataKey,eventKeystoreDir:inside}),/must not be inside DATA_DIR/);
 // A keystore serves one vault: a second vault (another signing key) with the same tenant names would share its epochs.
 assert.throws(()=>vault(t,{dir:join(w.root,'second-vault'),options:keystoreOptions(w),cleanup:false}),/already serves another vault/);
 const again=start(keystoreOptions(w));
 assert.deepEqual(again.store.ledgerEvents('alpha').map(item=>item.note),['note of wrap-1','note of wrap-2']);
 assert.equal((await again.call('/api/integrity','alpha-reviewer')).body.valid,true);
});

test('destroying an epoch secret makes its events unreadable in an older copy of evidence.db and in an older vault backup',async t=>{
 const w=workspace(),v=vault(t,{dir:w.dataDir,options:keystoreOptions(w),cleanup:false}),{publicKey}=v.store;
 const gone=event('gone',{note:'status-11'}),kept=event('kept',{note:'status-4'});
 assert.equal((await policy(v,1)).status,200);assert.equal((await v.ingest(gone)).status,202);
 assert.equal((await policy(v,400*86400)).status,200);assert.equal((await v.ingest(kept)).status,202);
 const epoch=TAG.exec(receiptOf(v.store,'gone').fingerprint)[1],tag=receiptOf(v.store,'gone').fingerprint;
 v.store.db.prepare('PRAGMA wal_checkpoint(TRUNCATE)').get();
 const oldCopy=join(w.root,'old-copy.db');copyFileSync(join(w.dataDir,'evidence.db'),oldCopy);
 const backup=options=>createVaultBackup({dataDir:w.dataDir,privateKey:v.key,publicKey,...keystoreOptions(w),...options});
 const before=join(w.root,'backup-before'),beforeAnchor=await backup({backupDir:before});
 const manifest=JSON.parse(readFileSync(join(before,'manifest.json'),'utf8'));
 assert.deepEqual([manifest.eventProjection,manifest.eventKeystore],['excluded_rebuilt_on_restore',{id:keystoreFor(w).id}]);
 assert.equal(readdirSync(before).some(name=>/keystore|\.key$/.test(name)),false,'neither keystore nor data key enters a backup');
 // Decrypted with the data key, the backup database holds ledger ciphertext and wrapped keys, but no plaintext projection.
 const keyring=createKeyring({dataKey:w.dataKey}),decipher=createDecipheriv('aes-256-gcm',keyring.key('vaultBackup',manifest.database.keyId),
  Buffer.from(manifest.database.iv,'base64'));
 decipher.setAAD(Buffer.from(canonical({format:manifest.format,keyId:manifest.database.keyId})));
 decipher.setAuthTag(Buffer.from(manifest.database.tag,'base64'));
 const plain=Buffer.concat([decipher.update(readFileSync(join(before,'evidence.db.enc'))),decipher.final()]);
 for(const note of [gone.note,kept.note])assert.ok(!plain.includes(Buffer.from(note)),note);
 // Restored before the destruction, the backup rebuilds its projection through the keystore.
 const restore=(backupDir,name,anchor,options=keystoreOptions(w))=>restoreVaultBackup({backupDir,restoreDir:join(w.root,name),privateKey:v.key,publicKey,
  ...options,anchor});
 const early=await restore(before,'restored-early',beforeAnchor);
 assert.equal(early.verified,true);
 const earlyDb=new DatabaseSync(join(early.restoredDirectory,'evidence.db'),{readOnly:true});
 assert.deepEqual(earlyDb.prepare('SELECT id FROM events ORDER BY id').all().map(row=>row.id),['gone','kept']);earlyDb.close();
 await later(1100);assert.deepEqual((await v.erase('expired')).items.map(item=>item.eventId),['gone']);
 const keptSeq=receiptOf(v.store,'kept').eventSeq,destroyed=destroyEpoch(v,w,epoch);assert.equal(destroyed.storage,'keystore');
 assert.ok(!existsSync(join(w.keystoreDir,'epochs',readdirSync(join(w.keystoreDir,'epochs'))[0],`${epoch}.json`)),'epoch file removed');
 // Old database copy, read with the data key and the current keystore: the destroyed epoch's key and receipt tag are dead.
 const reader=copyReader(t,oldCopy,w,v.key);
 assert.throws(()=>reader.decodeRecords(reader.rawBundle('alpha')),/was destroyed/);
 assert.equal(compareFingerprint(reader.eventKeyEpochs(),'alpha',tag,digest(gone)),'unverifiable');
 const keptRow=reader.rawBundle('alpha').records.find(row=>row.type==='event'&&row.seq===keptSeq);
 const keptKey=reader.db.prepare('SELECT key FROM event_keys WHERE key_id=?').get(keptRow.payload.keyId).key;
 assert.equal(reader._openEvent(keptRow.payload,keptKey).event.note,kept.note);
 // Documented residual: a raw copy of evidence.db made before the disposition still holds the plaintext search projection.
 assert.ok(readFileSync(oldCopy).includes(Buffer.from(gone.note)));
 await assert.rejects(restore(before,'restored-late',beforeAnchor),/destroyed since/);
 const after=join(w.root,'backup-after'),afterAnchor=await backup({backupDir:after});
 const restored=await restore(after,'restored-after',afterAnchor);
 const restoredDb=new DatabaseSync(join(restored.restoredDirectory,'evidence.db'),{readOnly:true});t.after(()=>restoredDb.close());
 assert.deepEqual(restoredDb.prepare('SELECT id FROM events').all().map(row=>row.id),['kept']);
 await assert.rejects(restore(after,'restored-nokeystore',afterAnchor,{dataKey:w.dataKey}),/needs its event keystore/);
});
function destroyEpoch(v,w,epoch){
 v.store.close();
 const signingKey=join(w.root,'signing.pem');writeFileSync(signingKey,v.key.export({format:'pem',type:'pkcs8'}),{mode:0o600});
 const env={DATA_KEY_FILE:w.keyFile,EVENT_KEYSTORE_DIR:w.keystoreDir},common={dataDir:w.dataDir,signingKey:readFileSync(signingKey,'utf8'),env};
 assert.equal(listEventKeyEpochs(common).epochs.find(item=>item.epoch===epoch).destroyable,false,'the month has not ended yet');
 return destroyEventKeyEpoch({...common,tenant:'alpha',epoch,reason:'all events of the epoch disposed',now:epochEnd(epoch)});
}

test('a keystore backup restored after an epoch destruction brings the epoch back; /api/integrity fails until it is destroyed again',async t=>{
 const w=workspace(),v=vault(t,{dir:w.dataDir,options:keystoreOptions(w),cleanup:false});
 assert.equal((await policy(v,1)).status,200);assert.equal((await v.ingest(event('old'))).status,202);
 const epoch=TAG.exec(receiptOf(v.store,'old').fingerprint)[1];await later(1100);await v.erase('expired');
 const keystoreBackup=join(w.root,'keystore-backup');cpSync(w.keystoreDir,keystoreBackup,{recursive:true});
 const first=destroyEpoch(v,w,epoch),epochDir=readdirSync(join(w.keystoreDir,'epochs'))[0];
 const common={dataDir:w.dataDir,signingKey:v.key.export({format:'pem',type:'pkcs8'}),env:{DATA_KEY_FILE:w.keyFile,EVENT_KEYSTORE_DIR:w.keystoreDir}};
 const check=async pattern=>{
  const opened=vault(t,{dir:w.dataDir,key:v.key,options:keystoreOptions(w),cleanup:false}),body=(await opened.call('/api/integrity','alpha-reviewer')).body;
  opened.store.close();if(pattern)assert.match(body.error||'',pattern);else assert.equal(body.valid,true,body.error);
 };
 const again=reason=>{
  const item=listEventKeyEpochs({...common,now:epochEnd(epoch)}).epochs.find(value=>value.epoch===epoch);
  assert.deepEqual([item.presentAgain,item.destroyable],[true,true]);
  const result=destroyEventKeyEpoch({...common,tenant:'alpha',epoch,reason,now:epochEnd(epoch)});assert.equal(result.recordSeq,first.recordSeq);
 };
 // The whole keystore restored from the earlier backup: epoch file back, tombstone gone.
 rmSync(w.keystoreDir,{recursive:true});cpSync(keystoreBackup,w.keystoreDir,{recursive:true});chmodSync(w.keystoreDir,0o700);
 await check(/present again/);again('restored keystore backup');await check();
 // Only the epoch file copied back beside its tombstone.
 copyFileSync(join(keystoreBackup,'epochs',epochDir,`${epoch}.json`),join(w.keystoreDir,'epochs',epochDir,`${epoch}.json`));
 await check(/present again/);again('restored epoch file');await check();
 assert.deepEqual(keystoreFor(w).tombstones('alpha').map(item=>item.epoch),[epoch]);
});

test('startup wraps the raw keys of a base-commit vault; the explicit migrate command does the same once',async t=>{
 const w=workspace(),{fixture,dir,key}=restoreBaseFixture(t,{dir:join(w.root,'data')});w.dataDir=dir;
 const raw=new DatabaseSync(gunzipFixture(fixture),{readOnly:true});
 const rawKeys=raw.prepare('SELECT key FROM event_keys').all().map(row=>Buffer.from(row.key));raw.close();assert.equal(rawKeys.length,2);
 const v=vault(t,{dir,key,options:keystoreOptions(w),cleanup:false});
 assert.deepEqual(v.service.eventKeystore,{keystoreId:keystoreFor(w).id,wrappedKeys:2,importedEpochs:0,importedTombstones:0});
 assert.deepEqual(v.store.db.prepare('SELECT length(key) n FROM event_keys ORDER BY seq').all().map(row=>row.n),[65,65]);
 for(const bytes of rawKeys)assert.ok(!onDisk(dir,bytes),'a raw v1 key is left in evidence.db or its WAL');
 const integrity=(await v.call('/api/integrity','alpha-reviewer')).body;assert.equal(integrity.valid,true,integrity.error);
 assert.deepEqual([integrity.keySeparation.eventKeys.storage,integrity.keySeparation.eventKeys.commitments],['keystore_wrapped',{saltedV2:0,unsaltedV1:3}]);
 assert.equal((await v.ingest(fixture.rawEvents.kept)).body.duplicate,true);
 assert.equal((await v.ingest(event('after-migration'))).status,202);
 assert.equal(verifyBundle((await v.call('/api/export','alpha-reviewer')).body,v.store.publicKey).disclosedEvents,3);
 v.store.close();
 assert.deepEqual(vault(t,{dir,key,options:keystoreOptions(w),cleanup:false}).service.eventKeystore.wrappedKeys,0);
 // The same migration as a separate step with the vault stopped (scripts/event-keys.mjs migrate).
 const second=workspace(),copy=restoreBaseFixture(t,{dir:join(second.root,'data')}),signing=join(second.root,'signing.pem');
 writeFileSync(signing,key.export({format:'pem',type:'pkcs8'}),{mode:0o600});
 const env={...process.env,DATA_KEY_FILE:second.keyFile,EVENT_KEYSTORE_DIR:second.keystoreDir};delete env.NODE_TEST_CONTEXT;
 const out=JSON.parse((await run(process.execPath,['scripts/event-keys.mjs','migrate',copy.dir,signing],{env,timeout:30000})).stdout);
 assert.deepEqual([out.migrated,out.wrappedKeys],[true,2]);
 const listed=JSON.parse((await run(process.execPath,['scripts/event-keys.mjs','list',copy.dir,signing],{env,timeout:30000})).stdout);
 assert.equal(listed.storage,'keystore');assert.ok(listed.epochs.every(item=>item.retainedEvents+item.disposedEvents>0));
 assert.throws(()=>vault(t,{dir:copy.dir,key,options:{dataKey:second.dataKey},cleanup:false}),/EVENT_KEYSTORE_DIR/);
});
function gunzipFixture(fixture){
 const file=join(tempDir('evidscope-wrap-raw-'),'evidence.db');writeFileSync(file,gunzipSync(Buffer.from(fixture.evidenceDbGzipBase64,'base64')));return file;
}

test('epoch secrets and tombstones made in database mode move to the keystore and keep comparing receipts',async t=>{
 const w=workspace(),v=vault(t,{dir:w.dataDir,cleanup:false});
 const gone=event('db-gone'),kept=event('db-kept');
 assert.equal((await policy(v,1)).status,200);assert.equal((await v.ingest(gone)).status,202);
 assert.equal((await policy(v,400*86400)).status,200);assert.equal((await v.ingest(kept)).status,202);
 const goneEpoch=TAG.exec(receiptOf(v.store,'db-gone').fingerprint)[1],keptEpoch=TAG.exec(receiptOf(v.store,'db-kept').fingerprint)[1];
 await later(1100);await v.erase('expired');
 const {destroyEpoch:destroy}=await import('../src/event-keys.mjs');
 destroy(v.store,{tenant:'alpha',epoch:goneEpoch,reason:'disposed in database mode',now:epochEnd(goneEpoch)});
 const secret=Buffer.from(v.store.db.prepare('SELECT secret FROM event_key_epochs WHERE epoch=?').get(keptEpoch).secret);
 v.store.close();
 await assert.rejects(createVaultBackup({dataDir:w.dataDir,backupDir:join(w.root,'early-backup'),privateKey:v.key,publicKey:v.store.publicKey,
  ...keystoreOptions(w)}),/has not moved its event keys/);
 const moved=vault(t,{dir:w.dataDir,key:v.key,options:keystoreOptions(w),cleanup:false});
 assert.deepEqual(moved.service.eventKeystore,{keystoreId:keystoreFor(w).id,wrappedKeys:1,importedEpochs:1,importedTombstones:1});
 assert.equal(moved.store.db.prepare('SELECT (SELECT COUNT(*) FROM event_key_epochs)+(SELECT COUNT(*) FROM event_key_epoch_tombstones) n').get().n,0);
 assert.ok(!onDisk(w.dataDir,secret),'the epoch secret moved out of evidence.db');
 assert.deepEqual(keystoreFor(w).tombstones('alpha').map(item=>item.epoch),[goneEpoch]);
 assert.equal((await moved.ingest(kept)).body.duplicate,true,'tags made with the imported secret still compare');
 const refused=await moved.ingest(gone);assert.equal(refused.status,409);assert.match(refused.body.error,/파기/);
 assert.equal((await moved.call('/api/integrity','alpha-reviewer')).body.valid,true);
 moved.store.close();
 // After the first move, epoch rows written into evidence.db (a known secret for a later month, a tombstone for a live epoch)
 // are never imported: the keystore keeps its own state and /api/integrity reports the rows until they are deleted.
 const db=new DatabaseSync(join(w.dataDir,'evidence.db'));t.after(()=>db.close());
 db.prepare('INSERT INTO event_key_epochs VALUES(?,?,?,?)').run('alpha','2099-01',Buffer.alloc(32,7),new Date().toISOString());
 db.prepare('INSERT INTO event_key_epoch_tombstones VALUES(?,?,?,?)').run('alpha',keptEpoch,new Date().toISOString(),'database');
 const planted=vault(t,{dir:w.dataDir,key:v.key,options:keystoreOptions(w),cleanup:false});
 assert.deepEqual([planted.service.eventKeystore.importedEpochs,planted.service.eventKeystore.importedTombstones],[0,0]);
 assert.deepEqual(keystoreFor(w).list('alpha').map(item=>item.epoch),[keptEpoch]);
 assert.match((await planted.call('/api/integrity','alpha-reviewer')).body.error,/never imported/);
 assert.equal((await planted.ingest(kept)).body.duplicate,true,'the live epoch was not destroyed');
 db.exec('DELETE FROM event_key_epochs; DELETE FROM event_key_epoch_tombstones;');
 assert.equal((await planted.call('/api/integrity','alpha-reviewer')).body.valid,true);
});

test('a vault still running without the keystore cannot add raw keys once its database moved to the keystore',async t=>{
 const w=workspace(),v=vault(t,{dir:w.dataDir,cleanup:false});
 assert.equal((await v.ingest(event('before'))).status,202);
 const env={DATA_KEY_FILE:w.keyFile,EVENT_KEYSTORE_DIR:w.keystoreDir};
 assert.equal(migrateEventKeystore({dataDir:w.dataDir,signingKey:v.key.export({format:'pem',type:'pkcs8'}),env}).wrappedKeys,1);
 // The running vault fails closed on its next request (its verified state no longer matches); a direct append is refused too.
 assert.equal((await v.ingest(event('after'))).status,409);
 const direct={...event('direct'),receivedAt:new Date().toISOString(),source:'alpha-agent'};
 assert.throws(()=>v.store.transaction(()=>v.store.append('alpha','event',direct,'alpha-agent')),/moved its event keys/);
 assert.equal((await v.call('/api/integrity','alpha-reviewer')).body.valid,false);
 assert.equal(v.store.db.prepare('SELECT COUNT(*) n FROM event_keys WHERE length(key) IN (32,64)').get().n,0);
});

test('data-key rotation reseals the keystore and refuses to run without it',async t=>{
 const w=workspace(),v=vault(t,{dir:w.dataDir,options:keystoreOptions(w),cleanup:false});
 assert.equal((await v.ingest(event('rotate'))).status,202);v.store.close();
 const signingKey=v.key.export({format:'pem',type:'pkcs8'}),next=join(w.root,'next.key');generateDataKeyFile(next);
 const nextKey=readDataKeyFile(next),oldKid=dataKeyId(w.dataKey);
 assert.throws(()=>migrateDocuments({dataDir:w.dataDir,signingKey,dataKey:nextKey,previousDataKeys:[w.dataKey]}),/EVENT_KEYSTORE_DIR/);
 const result=migrateDocuments({dataDir:w.dataDir,signingKey,dataKey:nextKey,previousDataKeys:[w.dataKey],eventKeystoreDir:w.keystoreDir});
 assert.deepEqual(result.resealedEpochs,{[oldKid]:1});assert.deepEqual(result.retiredKeyIds,[oldKid]);
 const rotated=vault(t,{dir:w.dataDir,key:v.key,options:{dataKey:nextKey,eventKeystoreDir:w.keystoreDir},cleanup:false});
 assert.deepEqual(rotated.store.ledgerEvents('alpha').map(item=>item.id),['rotate']);
 assert.equal((await rotated.call('/api/integrity','alpha-reviewer')).body.valid,true);
});

test('the vault started from server.mjs with EVENT_KEYSTORE_DIR wraps keys and reports it',async t=>{
 const h=await harness({vaultOnly:true,eventKeystore:true});t.after(()=>h.close());
 assert.equal((await submit(h.ingress.url,h.principal('agent'),event('http'))).status,202);
 const integrity=(await h.api('/api/integrity')).body;assert.equal(integrity.valid,true,integrity.error);
 assert.equal(integrity.keySeparation.eventKeys.storage,'keystore_wrapped');
 assert.equal(verifyBundle((await h.api('/api/export')).body,h.publicKey).disclosedEvents,1);
 await h.restart();assert.equal((await h.api('/api/integrity')).body.valid,true);
});
