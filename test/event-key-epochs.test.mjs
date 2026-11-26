// Round 2, audit S3: keyed receipt fingerprints, key epochs and both envelope formats side by side.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createPublicKey} from 'node:crypto';
import {copyFileSync,existsSync,readFileSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {DatabaseSync} from 'node:sqlite';
import {digest,verifyBundle} from '../src/crypto.mjs';
import {compareFingerprint,databaseEpochStore,destroyEpoch,epochEnd} from '../src/event-keys.mjs';
import {restoreBaseFixture,vault} from './event-key-vault.mjs';

const later=ms=>new Promise(done=>setTimeout(done,ms)),run=promisify(execFile);
const TAG=/^fp2:(\d{4}-(?:0[1-9]|1[0-2])):[a-f0-9]{64}$/;
const onDisk=(dir,needle)=>['evidence.db','evidence.db-wal'].some(name=>existsSync(join(dir,name))&&readFileSync(join(dir,name)).includes(needle));
const policy=(v,retentionSeconds)=>v.call('/api/retention/policy','alpha-reviewer',{retentionSeconds,purpose:'S3 epochs',reason:'synthetic only'});
const receiptOf=(store,id)=>store.bundle('alpha').records.find(row=>row.type==='event_receipt'&&row.payload.id===id).payload;

test('keyed receipt fingerprints keep duplicate detection across erasure and epochs; a destroyed epoch cannot confirm a retry',async t=>{
 const v=vault(t),occurredAt=new Date().toISOString();
 const first={id:'dup-1',actionId:'dup',traceId:'dup',kind:'intent',occurredAt,note:'first'};
 assert.equal((await policy(v,1)).status,200);
 assert.equal((await v.ingest(first)).status,202);
 const tag=receiptOf(v.store,'dup-1').fingerprint,epoch=TAG.exec(tag)?.[1];assert.ok(epoch,tag);
 v.store.db.prepare('PRAGMA wal_checkpoint(TRUNCATE)').get();
 assert.ok(!onDisk(v.dir,digest(first)),'the raw-body digest is not stored');
 assert.equal((await v.ingest(first)).body.duplicate,true);
 const conflict=await v.ingest({...first,note:'changed'});assert.equal(conflict.status,409);assert.match(conflict.body.error,/내용 충돌/);
 // Events after a policy change land in a later epoch; a retry still compares under the epoch named in its receipt.
 assert.equal((await policy(v,400*86400)).status,200);
 assert.equal((await v.ingest(first)).body.duplicate,true);
 assert.equal((await v.ingest({id:'dup-2',actionId:'keep',traceId:'dup',kind:'intent',occurredAt,note:'second'})).status,202);
 const laterEpoch=TAG.exec(receiptOf(v.store,'dup-2').fingerprint)[1];assert.notEqual(laterEpoch,epoch);
 await later(1100);assert.deepEqual((await v.erase('first event expired')).items.map(item=>item.eventId),['dup-1']);
 assert.equal((await v.ingest(first)).body.duplicate,true,'the retained receipt still recognises a retry after erasure');
 const secret=Buffer.from(v.store.db.prepare('SELECT secret FROM event_key_epochs WHERE tenant=? AND epoch=?').get('alpha',epoch).secret);
 v.store.db.prepare('PRAGMA wal_checkpoint(TRUNCATE)').get();
 const oldCopy=join(v.dir,'old-copy.db');copyFileSync(join(v.dir,'evidence.db'),oldCopy);
 // Destruction preconditions: the month has ended and every event of the epoch was disposed.
 const destroy=options=>destroyEpoch(v.store,{tenant:'alpha',reason:'every event disposed',...options});
 assert.throws(()=>destroy({epoch,now:Date.now()}),/has not ended/);
 assert.throws(()=>destroy({epoch:laterEpoch,now:epochEnd(laterEpoch)}),/still has retained events/);
 assert.throws(()=>destroy({epoch,now:epochEnd(epoch),reason:' '}),/reason/);
 assert.throws(()=>destroy({epoch:'2026-13',now:epochEnd(epoch)}),/Invalid event-key epoch/);
 const destroyed=destroy({epoch,now:epochEnd(epoch)});
 assert.deepEqual([destroyed.destroyed,destroyed.storage,destroyed.disposedEvents],[true,'database',1]);
 assert.throws(()=>destroy({epoch,now:epochEnd(epoch)}),/already destroyed/);
 const record=v.store.bundle('alpha').records.find(row=>row.type==='event_key_epoch_destroyed');
 assert.deepEqual([record.seq,record.payload.format,record.payload.epoch,record.payload.basis],
  [destroyed.recordSeq,'evidscope-event-key-epoch-destruction-v1',epoch,'all_events_disposed']);
 assert.equal(v.store.db.prepare('SELECT COUNT(*) n FROM event_key_epochs WHERE tenant=? AND epoch=?').get('alpha',epoch).n,0);
 assert.ok(!onDisk(v.dir,secret),'the destroyed epoch secret is not left in evidence.db or its WAL');
 const unverifiable=await v.ingest(first);assert.equal(unverifiable.status,409);assert.match(unverifiable.body.error,/파기/);
 // The current database can no longer test a guess against the tag; a copy taken before destruction still can (database-mode residual).
 assert.equal(compareFingerprint(databaseEpochStore(v.store.db),'alpha',tag,digest(first)),'unverifiable');
 const copy=new DatabaseSync(oldCopy,{readOnly:true});t.after(()=>copy.close());
 assert.equal(compareFingerprint(databaseEpochStore(copy),'alpha',tag,digest(first)),'same');
 const integrity=(await v.call('/api/integrity','alpha-reviewer')).body;assert.equal(integrity.valid,true,integrity.error);
 assert.deepEqual(integrity.keySeparation.eventKeys.epochs,{storage:'database',stored:1,destroyed:1});
 assert.deepEqual(integrity.keySeparation.eventKeys.receiptFingerprints,{keyed:2,unkeyed:0});
 assert.equal(verifyBundle((await v.call('/api/export','alpha-reviewer')).body,v.store.publicKey).erasedEvents,1);
});

test('v1 rows written by the base commit and new v2 rows verify side by side; v1 keeps its unsalted residual',async t=>{
 const {fixture,dir,key}=restoreBaseFixture(t),publicKey=createPublicKey(key);
 const base=verifyBundle(fixture.exportBundle,publicKey);assert.deepEqual([base.disclosedEvents,base.erasedEvents],[2,1]);
 const v=vault(t,{dir,key});
 assert.equal((await v.call('/api/integrity','alpha-reviewer')).body.valid,true);
 const fresh={id:'after-upgrade',actionId:'base-keep-action',traceId:'base-trace',kind:'intent',occurredAt:new Date().toISOString(),note:'new'};
 assert.equal((await v.ingest(fresh)).status,202);
 for(const event of [fixture.rawEvents.kept,fixture.rawEvents.erased,fresh])assert.equal((await v.ingest(event)).body.duplicate,true,event.id);
 assert.equal((await v.ingest({...fixture.rawEvents.kept,note:'changed'})).status,409);
 const bundle=(await v.call('/api/export','alpha-reviewer')).body,events=bundle.records.filter(row=>row.type==='event');
 assert.deepEqual(events.map(row=>row.payload.format.slice(-2)),['v1','v1','v1','v2']);
 assert.deepEqual(bundle.disclosures.map(item=>[item.event.id,typeof item.salt]),
  [['base-kept','undefined'],['base-kept-2','undefined'],['after-upgrade','string']]);
 assert.deepEqual([verifyBundle(bundle,publicKey).disclosedEvents,verifyBundle(bundle,publicKey).erasedEvents],[3,1]);
 // Documented residual: the erased v1 row and its receipt still confirm a correct guess; new rows do not carry such values.
 const erasedRow=events.find(row=>row.seq===fixture.exportBundle.records.find(r=>r.type==='retention_disposition').payload.sequences[0]);
 assert.equal(receiptOf(v.store,'base-erased').fingerprint,digest(fixture.rawEvents.erased));assert.match(erasedRow.payload.payloadHash,/^[a-f0-9]{64}$/);
 assert.match(receiptOf(v.store,'after-upgrade').fingerprint,TAG);
 const integrity=(await v.call('/api/integrity','alpha-reviewer')).body;assert.equal(integrity.valid,true,integrity.error);
 assert.deepEqual(integrity.keySeparation.eventKeys.commitments,{saltedV2:1,unsaltedV1:3});
 assert.deepEqual(integrity.keySeparation.eventKeys.receiptFingerprints,{keyed:1,unkeyed:3});
});

test('event-keys CLI lists epochs and refuses to destroy one that can still take events',async t=>{
 const v=vault(t);
 assert.equal((await v.ingest({id:'cli',actionId:'cli',traceId:'cli',kind:'intent',occurredAt:new Date().toISOString()})).status,202);
 const epoch=TAG.exec(receiptOf(v.store,'cli').fingerprint)[1],signing=join(v.dir,'signing-private.pem');
 writeFileSync(signing,v.key.export({format:'pem',type:'pkcs8'}),{mode:0o600});
 v.store.close();
 const cli=async(...args)=>{
  try{const out=await run(process.execPath,['scripts/event-keys.mjs',...args],{timeout:30000});return {code:0,out:JSON.parse(out.stdout)};}
  catch(error){return {code:error.code,out:JSON.parse(error.stderr)};}
 };
 const listed=await cli('list',v.dir,signing,'alpha');assert.equal(listed.code,0);
 assert.deepEqual(listed.out.epochs.map(item=>[item.epoch,item.retainedEvents,item.stored,item.destroyable]),[[epoch,1,true,false]]);
 const refused=await cli('destroy',v.dir,signing,'alpha',epoch,'synthetic');
 assert.equal(refused.code,1);assert.match(refused.out.error,/has not ended|retained/);
 assert.match((await cli('destroy',v.dir,signing,'alpha')).out.error,/Usage/);
});
