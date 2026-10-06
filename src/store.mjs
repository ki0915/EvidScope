import {DatabaseSync,constants as sqlite} from 'node:sqlite';
import {mkdirSync} from 'node:fs';
import {join} from 'node:path';
import {createPublicKey,createHash} from 'node:crypto';
import {canonical,digest,makeCheckpoint,verifyBundle,verifyCheckpoint} from './crypto.mjs';
import {encryptEvent,decryptEvent} from './encryption.mjs';
import {checkActionRows,createActionProjectionReducer} from './action-integrity.mjs';
import {checkEventProjection} from './event-integrity.mjs';
import {checkDevelopmentRunProjection} from './development-integrity.mjs';
import {checkReceiptProjection,expectedReceiptProjection} from './receipt-integrity.mjs';
import {checkObjectProjection,isSignedObjectType,signedObjectProjection} from './object-integrity.mjs';
import {checkEvaluationProjection} from './evaluation-integrity.mjs';
import {types} from 'node:util';

let transactionSequence=0n;

export class Store {
 constructor(dir,key) {
  mkdirSync(dir,{recursive:true}); this.key=key; this.publicKey=createPublicKey(key);this.db=new DatabaseSync(join(dir,'evidence.db'));
  this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
   CREATE TABLE IF NOT EXISTS ledger(tenant TEXT, seq INTEGER, body TEXT NOT NULL, hash TEXT NOT NULL, PRIMARY KEY(tenant,seq));
   CREATE TABLE IF NOT EXISTS checkpoints(tenant TEXT PRIMARY KEY, body TEXT NOT NULL);
   CREATE TABLE IF NOT EXISTS events(tenant TEXT, source TEXT, id TEXT, fingerprint TEXT, action_id TEXT, trace_id TEXT, kind TEXT, received TEXT, body TEXT, PRIMARY KEY(tenant,source,id));
   CREATE INDEX IF NOT EXISTS event_action ON events(tenant,action_id);
   CREATE INDEX IF NOT EXISTS event_received ON events(tenant,received);
   CREATE TABLE IF NOT EXISTS nonces(source TEXT, nonce TEXT, expires INTEGER, PRIMARY KEY(source,nonce));
   CREATE TABLE IF NOT EXISTS actions(tenant TEXT, id TEXT, version INTEGER NOT NULL, analyzed INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(tenant,id));
   CREATE TABLE IF NOT EXISTS evaluations(id INTEGER PRIMARY KEY AUTOINCREMENT, tenant TEXT, action_id TEXT, version INTEGER, body TEXT);
   CREATE TABLE IF NOT EXISTS objects(tenant TEXT, type TEXT, id TEXT, body TEXT, PRIMARY KEY(tenant,type,id));
   CREATE TABLE IF NOT EXISTS counters(name TEXT PRIMARY KEY,value INTEGER NOT NULL);
   CREATE TABLE IF NOT EXISTS event_keys(tenant TEXT,key_id TEXT,seq INTEGER,key BLOB NOT NULL,PRIMARY KEY(tenant,key_id));
   CREATE TABLE IF NOT EXISTS receipts(tenant TEXT,source TEXT,id TEXT,fingerprint TEXT,PRIMARY KEY(tenant,source,id));
   INSERT OR IGNORE INTO receipts SELECT tenant,source,id,fingerprint FROM events;
   CREATE TRIGGER IF NOT EXISTS immutable_update BEFORE UPDATE ON ledger BEGIN SELECT RAISE(ABORT,'append only'); END;
   CREATE TRIGGER IF NOT EXISTS immutable_delete BEFORE DELETE ON ledger BEGIN SELECT RAISE(ABORT,'append only'); END;
   CREATE TABLE IF NOT EXISTS projection_mutation_clock(id INTEGER PRIMARY KEY CHECK(id=1),serial INTEGER NOT NULL);
   INSERT OR IGNORE INTO projection_mutation_clock VALUES(1,0);
   CREATE TRIGGER IF NOT EXISTS events_mutation_insert AFTER INSERT ON events BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
   CREATE TRIGGER IF NOT EXISTS events_mutation_update AFTER UPDATE ON events BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
   CREATE TRIGGER IF NOT EXISTS events_mutation_delete AFTER DELETE ON events BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
   CREATE TRIGGER IF NOT EXISTS receipts_mutation_insert AFTER INSERT ON receipts BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
   CREATE TRIGGER IF NOT EXISTS receipts_mutation_update AFTER UPDATE ON receipts BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
   CREATE TRIGGER IF NOT EXISTS receipts_mutation_delete AFTER DELETE ON receipts BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
   CREATE TRIGGER IF NOT EXISTS actions_mutation_insert AFTER INSERT ON actions BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
   CREATE TRIGGER IF NOT EXISTS actions_mutation_update AFTER UPDATE ON actions BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
   CREATE TRIGGER IF NOT EXISTS actions_mutation_delete AFTER DELETE ON actions BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
   CREATE TRIGGER IF NOT EXISTS event_keys_mutation_insert AFTER INSERT ON event_keys BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
   CREATE TRIGGER IF NOT EXISTS event_keys_mutation_update AFTER UPDATE ON event_keys BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
   CREATE TRIGGER IF NOT EXISTS event_keys_mutation_delete AFTER DELETE ON event_keys BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
   CREATE TRIGGER IF NOT EXISTS ledger_mutation_insert AFTER INSERT ON ledger BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
   CREATE TRIGGER IF NOT EXISTS ledger_mutation_update AFTER UPDATE ON ledger BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
   CREATE TRIGGER IF NOT EXISTS ledger_mutation_delete AFTER DELETE ON ledger BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
   CREATE TRIGGER IF NOT EXISTS checkpoints_mutation_insert AFTER INSERT ON checkpoints BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
   CREATE TRIGGER IF NOT EXISTS checkpoints_mutation_update AFTER UPDATE ON checkpoints BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
    CREATE TRIGGER IF NOT EXISTS checkpoints_mutation_delete AFTER DELETE ON checkpoints BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
    CREATE TRIGGER IF NOT EXISTS objects_mutation_insert AFTER INSERT ON objects BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
    CREATE TRIGGER IF NOT EXISTS objects_mutation_update AFTER UPDATE ON objects BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
    CREATE TRIGGER IF NOT EXISTS objects_mutation_delete AFTER DELETE ON objects BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
    CREATE TRIGGER IF NOT EXISTS evaluations_mutation_insert AFTER INSERT ON evaluations BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
    CREATE TRIGGER IF NOT EXISTS evaluations_mutation_update AFTER UPDATE ON evaluations BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;
    CREATE TRIGGER IF NOT EXISTS evaluations_mutation_delete AFTER DELETE ON evaluations BEGIN UPDATE projection_mutation_clock SET serial=serial+1 WHERE id=1; END;`);
  this.actionProjectionCache=new Map();this.projectionMutationDepth=0;this.projectionMutationSerial=0;
  this.observedProjectionMutationClock=this.db.prepare('SELECT serial FROM projection_mutation_clock WHERE id=1').get().serial;
   const protectedTables=new Set(['events','receipts','actions','event_keys','ledger','checkpoints','objects','evaluations']);
   const protectedTriggers=new Set(['events_mutation_insert','events_mutation_update','events_mutation_delete','receipts_mutation_insert','receipts_mutation_update','receipts_mutation_delete','actions_mutation_insert','actions_mutation_update','actions_mutation_delete','event_keys_mutation_insert','event_keys_mutation_update','event_keys_mutation_delete','ledger_mutation_insert','ledger_mutation_update','ledger_mutation_delete','checkpoints_mutation_insert','checkpoints_mutation_update','checkpoints_mutation_delete','objects_mutation_insert','objects_mutation_update','objects_mutation_delete','evaluations_mutation_insert','evaluations_mutation_update','evaluations_mutation_delete']);
  this.db.setAuthorizer((action,table,_column,_database,source)=>{
   if(action===sqlite.SQLITE_DROP_TRIGGER&&protectedTriggers.has(table)||[sqlite.SQLITE_DROP_TABLE,sqlite.SQLITE_ALTER_TABLE].includes(action)&&([...protectedTables,'projection_mutation_clock'].includes(table)))return sqlite.SQLITE_DENY;
   if([sqlite.SQLITE_INSERT,sqlite.SQLITE_UPDATE,sqlite.SQLITE_DELETE].includes(action)&&table==='projection_mutation_clock'&&!protectedTriggers.has(source))return sqlite.SQLITE_DENY;
   if([sqlite.SQLITE_INSERT,sqlite.SQLITE_UPDATE,sqlite.SQLITE_DELETE].includes(action)&&protectedTables.has(table)&&source)return sqlite.SQLITE_DENY;
   if([sqlite.SQLITE_INSERT,sqlite.SQLITE_UPDATE,sqlite.SQLITE_DELETE].includes(action)&&protectedTables.has(table)&&this.projectionMutationDepth===0)this.projectionMutationSerial++;
   return sqlite.SQLITE_OK;
  });
 }
 projectionMutation(fn){if(this.projectionMutationDepth===0)this._syncProjectionMutationClock();this.projectionMutationDepth++;try{return fn();}finally{this.projectionMutationDepth--;if(this.projectionMutationDepth===0)this.observedProjectionMutationClock=this.db.prepare('SELECT serial FROM projection_mutation_clock WHERE id=1').get().serial;}}
 _syncProjectionMutationClock(){const actual=this.db.prepare('SELECT serial FROM projection_mutation_clock WHERE id=1').get().serial;if(actual!==this.observedProjectionMutationClock){this.projectionMutationSerial++;this.observedProjectionMutationClock=actual;}}
 transaction(fn) {
  if(typeof fn!=='function'||types.isAsyncFunction(fn))throw TypeError('Store.transaction requires a synchronous callback');
  const nested=this.db.isTransaction,name=`evidscope_transaction_${++transactionSequence}`,ownsLedgerContext=!this.ledgerTransaction;
  const snapshot=!ownsLedgerContext?{heads:new Map([...this.ledgerTransaction.heads].map(([tenant,head])=>[tenant,{...head}])),dirty:new Set(this.ledgerTransaction.dirty),actionCandidates:new Map(this.ledgerTransaction.actionCandidates)}:null;
  this.db.exec(nested?`SAVEPOINT ${name}`:'BEGIN IMMEDIATE');
  if(ownsLedgerContext)this.ledgerTransaction={heads:new Map(),dirty:new Set(),actionCandidates:new Map(),external:nested};
  try{
   const out=fn();
   if(out&&typeof out.then==='function'){if(types.isPromise(out))out.catch(()=>{});throw TypeError('Store.transaction requires a synchronous callback');}
   if(ownsLedgerContext)this.projectionMutation(()=>{for(const tenant of this.ledgerTransaction.dirty){const head=this.ledgerTransaction.heads.get(tenant);this.db.prepare('INSERT INTO checkpoints VALUES(?,?) ON CONFLICT(tenant) DO UPDATE SET body=excluded.body').run(tenant,JSON.stringify(makeCheckpoint(tenant,head.seq,head.hash,this.key)));}});
   this.db.exec(nested?`RELEASE ${name}`:'COMMIT');
   if(ownsLedgerContext&&!this.ledgerTransaction.external)for(const [tenant,candidate] of this.ledgerTransaction.actionCandidates)this.actionProjectionCache.set(tenant,candidate);
   return out;
  }catch(error){
   try{if(nested){this.db.exec(`ROLLBACK TO ${name}`);this.db.exec(`RELEASE ${name}`);}else if(this.db.isTransaction)this.db.exec('ROLLBACK');}
   catch(rollbackError){throw new AggregateError([error,rollbackError],'Store transaction rollback failed');}
   if(snapshot){this.ledgerTransaction.heads=snapshot.heads;this.ledgerTransaction.dirty=snapshot.dirty;this.ledgerTransaction.actionCandidates=snapshot.actionCandidates;}
   throw error;
  }finally{if(ownsLedgerContext)this.ledgerTransaction=null;}
 }
 checkpoint(tenant){
  const pending=this.ledgerTransaction?.dirty.has(tenant)&&this.ledgerTransaction.heads.get(tenant);
  if(pending)return makeCheckpoint(tenant,pending.seq,pending.hash,this.key);
  const saved=this.db.prepare('SELECT body FROM checkpoints WHERE tenant=?').get(tenant);
  return saved?JSON.parse(saved.body):makeCheckpoint(tenant,0,'0'.repeat(64),this.key);
 }
 append(tenant,type,payload,principal) {
  let head=this.ledgerTransaction?.heads.get(tenant);
  if(!head){
   head=this.db.prepare('SELECT seq,hash FROM ledger WHERE tenant=? ORDER BY seq DESC LIMIT 1').get(tenant);
   const saved=this.db.prepare('SELECT body FROM checkpoints WHERE tenant=?').get(tenant);
   if(head){const checkpoint=saved&&JSON.parse(saved.body);verifyCheckpoint(checkpoint,this.publicKey);if(checkpoint.tenant!==tenant||checkpoint.count!==head.seq||checkpoint.head!==head.hash)throw Error('Ledger head differs from previously signed checkpoint; refusing to re-seal');}
   else if(saved)throw Error('Ledger is missing beneath an existing checkpoint');
   if(this.ledgerTransaction)this.ledgerTransaction.heads.set(tenant,head||{seq:0,hash:'0'.repeat(64)});
  }
  const seq=(head?.seq||0)+1;
  if(type==='event'){
   const policy=this.get(tenant,'retention_policy','current')||{version:0,retentionSeconds:30*86400,reason:'합성 파일럿 공학적 기본값; 법적 보존기간 아님'};
   const encrypted=encryptEvent(payload,tenant,seq,policy);this.projectionMutation(()=>this.db.prepare('INSERT INTO event_keys VALUES(?,?,?,?)').run(tenant,encrypted.keyId,seq,encrypted.key));payload=encrypted.payload;
  }
  const record={tenant,seq,previous:head?.hash||'0'.repeat(64),type,recordedAt:new Date().toISOString(),principal,payload};
  const hash=digest(record);this.projectionMutation(()=>this.db.prepare('INSERT INTO ledger VALUES(?,?,?,?)').run(tenant,record.seq,canonical(record),hash));
  if(this.ledgerTransaction){this.ledgerTransaction.heads.set(tenant,{seq:record.seq,hash});this.ledgerTransaction.dirty.add(tenant);}
  else this.projectionMutation(()=>this.db.prepare('INSERT INTO checkpoints VALUES(?,?) ON CONFLICT(tenant) DO UPDATE SET body=excluded.body').run(tenant,JSON.stringify(makeCheckpoint(tenant,record.seq,hash,this.key))));
  return {...record,hash};
 }
 audit(p,operation,target='') {return this.transaction(()=>this.append(p.tenant,'audit_access',{operation,target},p.id));}
 get(tenant,type,id) {const r=this.db.prepare('SELECT body FROM objects WHERE tenant=? AND type=? AND id=?').get(tenant,type,id);return r?JSON.parse(r.body):null;}
 list(tenant,type) {return this.db.prepare('SELECT body FROM objects WHERE tenant=? AND type=? ORDER BY id').all(tenant,type).map(r=>JSON.parse(r.body));}
 put(p,type,id,body) {this.append(p.tenant,type,body,p.id);this.projectionMutation(()=>this.db.prepare('INSERT INTO objects VALUES(?,?,?,?) ON CONFLICT(tenant,type,id) DO UPDATE SET body=excluded.body').run(p.tenant,type,id,JSON.stringify(body)));return body;}
 events(tenant,actionId) {const sql=actionId?'SELECT body FROM events WHERE tenant=? AND action_id=? ORDER BY received,source,id':'SELECT body FROM events WHERE tenant=? ORDER BY received,source,id';return this.db.prepare(sql).all(...(actionId?[tenant,actionId]:[tenant])).map(r=>JSON.parse(r.body));}
 evaluations(tenant,actionId) {return this.db.prepare('SELECT body FROM evaluations WHERE tenant=? AND action_id=? ORDER BY id DESC').all(tenant,actionId).map(r=>JSON.parse(r.body));}
 rawBundle(tenant) {
  const records=this.db.prepare('SELECT seq,body,hash FROM ledger WHERE tenant=? ORDER BY seq').all(tenant).map(r=>{const record=JSON.parse(r.body);if(record.tenant!==tenant||record.seq!==r.seq)throw Error('Ledger SQL tenant or sequence differs from signed record');return {...record,hash:r.hash};});
  const checkpoint=this.checkpoint(tenant);
  if(checkpoint.tenant!==tenant)throw Error('Checkpoint tenant mismatch');
  return {format:'evidscope-export-v2',records,checkpoint,limitations:['Minimized receipt evidence; no original prompt or response','Signature authenticates local vault, not truth of source claims','Pin public key and checkpoint out of band to detect replacement and rollback','Erasure covers live event keys and query copies; prior exports/backups need separate disposition']};
 }
 decodeRecords(bundle){
  const erased=new Set(bundle.records.filter(r=>r.type==='retention_disposition').flatMap(r=>r.payload.keyIds||[]));
  return bundle.records.filter(r=>r.type==='event').flatMap(r=>{
   if(r.payload.format!=='evidscope-encrypted-event-v1')return [{...r.payload,seq:r.seq,hash:r.hash}];
   const k=this.db.prepare('SELECT key FROM event_keys WHERE tenant=? AND key_id=?').get(r.tenant,r.payload.keyId);
   if(erased.has(r.payload.keyId)){if(k)throw Error('Erased event key unexpectedly retained');return [];}
   if(!k)throw Error('Event key missing without authorized disposition');
   return [{...decryptEvent(r.payload,k.key),seq:r.seq,hash:r.hash}];
  });
 }
 bundle(tenant){const b=this.rawBundle(tenant);verifyBundle(b,this.publicKey,undefined,{chainOnly:true});const events=this.decodeRecords(b);const encrypted=new Set(b.records.filter(r=>r.type==='event'&&r.payload.format==='evidscope-encrypted-event-v1').map(r=>r.seq));b.disclosures=events.filter(e=>encrypted.has(e.seq)).map(e=>{const {seq,hash,...event}=e;return {seq,event};});return b;}
 ledgerEvents(tenant,actionId){const b=this.rawBundle(tenant);verifyBundle(b,this.publicKey,undefined,{chainOnly:true});return this.decodeRecords(b).filter(e=>!actionId||e.actionId===actionId).sort((a,b)=>a.receivedAt.localeCompare(b.receivedAt)||a.source.localeCompare(b.source)||a.id.localeCompare(b.id));}
 ledgerObjects(tenant,type){const b=this.rawBundle(tenant);verifyBundle(b,this.publicKey,undefined,{chainOnly:true});return [...new Map(b.records.filter(r=>r.type===type&&r.payload.id).map(r=>[r.payload.id,r.payload])).values()];}
 // Consume this iterator to exhaustion before using any rows: final signed checkpoint
 // verification runs after the last row. A single oversized row is hashed in chunks.
 *verifiedRows(tenant,maxRowBytes){
  const cp=this.checkpoint(tenant);verifyCheckpoint(cp,this.publicKey);
  if(cp.tenant!==tenant)throw Error('Checkpoint tenant mismatch');
  let previous='0'.repeat(64),sequence=0;
  const query=this.db.prepare(`SELECT seq,hash,length(CAST(body AS BLOB)) AS bytes,
   json_extract(body,'$.tenant') AS record_tenant,json_extract(body,'$.seq') AS record_seq,
   json_extract(body,'$.previous') AS previous,
   CASE WHEN length(CAST(body AS BLOB))<=? THEN body ELSE NULL END AS body
   FROM ledger WHERE tenant=? ORDER BY seq`);
  for(const row of query.iterate(maxRowBytes,tenant)){
   if(row.seq!==++sequence||row.record_seq!==sequence||row.record_tenant!==tenant||row.previous!==previous)throw Error('Sequence, tenant or previous hash mismatch');
   let hash;
   if(row.body!==null)hash=digest(row.body);
   else {
    const hasher=createHash('sha256'),chunk=this.db.prepare('SELECT substr(CAST(body AS BLOB),?,65536) AS chunk FROM ledger WHERE tenant=? AND seq=?');
    for(let offset=1;offset<=row.bytes;offset+=65536)hasher.update(chunk.get(offset,tenant,row.seq).chunk);
    hash=hasher.digest('hex');
   }
   if(hash!==row.hash)throw Error('Record digest mismatch');previous=hash;
   yield row.body===null?{oversized:true,bytes:row.bytes,seq:row.seq}:{...JSON.parse(row.body),hash:row.hash,recordBytes:row.bytes};
  }
  if(sequence!==cp.count||previous!==cp.head)throw Error('Truncated or inconsistent export');
 }
 verifiedAnalysisSnapshot(tenant,actionId,limits){
  const maxBytes=limits.snapshotBytes-4096,maxRows={assets:limits.assets,rules:limits.rules,exceptions:limits.exceptions};
  const events=[],maps={assets:new Map(),rules:new Map(),exceptions:new Map()},types={asset:'assets',rule:'rules',exception:'exceptions'};
  let usedBytes=100,observedEvents=0,observedEventsComplete=true;const reasons=new Set();
  const over=reason=>{reasons.add(reason);events.length=0;for(const map of Object.values(maps))map.clear();};
  const keyQuery=this.db.prepare('SELECT key FROM event_keys WHERE tenant=? AND key_id=?');
  const disposition=this.db.prepare(`SELECT 1 FROM ledger l,json_each(l.body,'$.payload.keyIds') k
   WHERE l.tenant=? AND json_extract(l.body,'$.type')='retention_disposition' AND k.value=? LIMIT 1`);
  for(const row of this.verifiedRows(tenant,maxBytes)){
   if(row.oversized){over('ledgerRowBytes');observedEventsComplete=false;continue;}
   if(row.type==='retention_disposition'){
    for(const id of row.payload.keyIds||[])if(keyQuery.get(tenant,id))throw Error('Erased event key unexpectedly retained');
    continue;
   }
   if(row.type==='event'){
    let event;
    if(row.payload.format==='evidscope-encrypted-event-v1'){
     if(row.payload.tenant!==tenant||row.payload.seq!==row.seq)throw Error('Encrypted event envelope mismatch');
     const k=keyQuery.get(tenant,row.payload.keyId);
     if(!k){if(!disposition.get(tenant,row.payload.keyId))throw Error('Event key missing without authorized disposition');continue;}
     if(actionId===null)continue;
     if(Object.hasOwn(row.payload,'actionId')&&row.payload.actionId!==actionId)continue;
     event=decryptEvent(row.payload,k.key);
    }else event=row.payload;
    if(actionId===null||event.actionId!==actionId)continue;observedEvents++;
    if(observedEvents>limits.events)over('events');
    if(reasons.size)continue;
    const value={...event,seq:row.seq,hash:row.hash};usedBytes+=Buffer.byteLength(JSON.stringify(value))+1;
    if(usedBytes>maxBytes)over('snapshotBytes');else events.push(value);
   }else if(types[row.type]&&!reasons.size&&row.payload.id){
    const name=types[row.type],map=maps[name],value=row.type==='rule'?{...row.payload,versions:row.payload.versions.filter(v=>v.status==='active')}:row.payload;
    // Asset versions are historical policy evidence. Preserve every authoritative
    // registration even when legacy entries reused version/updatedAt metadata.
    const mapKey=name==='assets'?`${value.id}:${row.seq}`:value.id;
    const old=map.get(mapKey);usedBytes-=old?Buffer.byteLength(JSON.stringify(old)):0;usedBytes+=Buffer.byteLength(JSON.stringify(value))+1;
    map.set(mapKey,value);
    const count=name==='rules'?[...map.values()].reduce((n,r)=>n+r.versions.length,0):map.size;
    if(count>maxRows[name])over(name);else if(usedBytes>maxBytes)over('snapshotBytes');
   }
  }
  if(reasons.size)return {resourceLimit:{reasons:[...reasons],observedEventsComplete,snapshotBytesAtLeast:usedBytes},observedEvents};
  return {events:events.sort((a,b)=>a.receivedAt.localeCompare(b.receivedAt)||a.source.localeCompare(b.source)||a.id.localeCompare(b.id)),assets:[...maps.assets.values()],rules:[...maps.rules.values()].flatMap(r=>r.versions),exceptions:[...maps.exceptions.values()]};
 }
 cachedAnalysisSnapshot(tenant,actionId,limits){
  this.checkActionProjection(tenant);const state=this.ledgerTransaction?.actionCandidates.get(tenant)||this.actionProjectionCache.get(tenant);if(!state)throw Error('Verified action state is unavailable');
  const events=actionId===null?[]:[...state.eventsBySequence.values()].filter(event=>event.actionId===actionId),assets=[...state.analysisAssets.values()],rules=[...state.analysisRules.values()].flatMap(rule=>(rule.versions||[]).filter(version=>version.status==='active')),exceptions=[...state.analysisExceptions.values()];
  const reasons=[],used=100+[...events,...assets,...rules,...exceptions].reduce((total,value)=>total+Buffer.byteLength(JSON.stringify(value))+1,0),counts={events:events.length,assets:assets.length,rules:rules.length,exceptions:exceptions.length};
  for(const [name,count] of Object.entries(counts))if(count>limits[name])reasons.push(name);if(used>limits.snapshotBytes-4096)reasons.push('snapshotBytes');
  if(reasons.length)return {resourceLimit:{reasons:[...new Set(reasons)],observedEventsComplete:true,snapshotBytesAtLeast:used},observedEvents:events.length};
  return {events:events.sort((a,b)=>a.receivedAt.localeCompare(b.receivedAt)||a.source.localeCompare(b.source)||a.id.localeCompare(b.id)),assets,rules,exceptions};
 }
 cachedSignedObjects(tenant,types){
  if(!Array.isArray(types)||types.some(type=>!isSignedObjectType(type)))throw TypeError('Signed object types are required');
  this.checkActionProjection(tenant);const state=this.ledgerTransaction?.actionCandidates.get(tenant)||this.actionProjectionCache.get(tenant);if(!state)throw Error('Verified object state is unavailable');const selected=new Set(types);
  return [...state.objects.values()].filter(value=>selected.has(value.type)).sort((a,b)=>a.row.seq-b.row.seq).map(value=>({seq:value.row.seq,type:value.type,id:value.id,body:structuredClone(value.payload)}));
 }
 checkProjection(tenant,original=this.ledgerEvents(tenant)){return checkEventProjection(this.db,tenant,original);}
 _databaseVersions(){return {data:this.db.prepare('PRAGMA data_version').get().data_version,schema:this.db.prepare('PRAGMA schema_version').get().schema_version};}
 _keyDigest(value){return createHash('sha256').update(value).digest('hex');}
 _verifyEventKeys(tenant,expected){
  const rows=this.db.prepare('SELECT key_id,seq,key FROM event_keys WHERE tenant=? ORDER BY key_id').all(tenant);
  if(rows.length!==expected.size)throw Error('Event key projection differs from signed evidence');
  for(const row of rows){const value=expected.get(row.key_id);if(!value||value.seq!==row.seq||value.digest!==this._keyDigest(row.key))throw Error('Event key projection differs from signed evidence');}
 }
 _verifyActionState(tenant,state){
  const events=[...state.eventsBySequence.values()];
  checkEventProjection(this.db,tenant,events);
  checkReceiptProjection(this.db,tenant,state.receiptRecords,events);
  this._verifyEventKeys(tenant,state.keys);
  checkObjectProjection(this.db,tenant,[...state.objects.values()].map(value=>value.row));
  checkEvaluationProjection(this.db,tenant,state.evaluations);
  return checkActionRows(this.db,tenant,state.action.finish());
 }
 _applyReceiptEvidence(state,row,disclosed){
  const receiptIdentity=(source,id)=>canonical([source,id]),validDigest=/^[a-f0-9]{64}$/;
  if(row.type==='event'){
   const keyId=row.payload?.keyId;state.receiptEvents.set(row.seq,{hash:row.hash,keyId});
   if(disclosed){const identity=receiptIdentity(disclosed.source,disclosed.id);if(state.receiptEntries.has(identity)||state.receiptCovered.has(row.seq)||typeof disclosed.fingerprint!=='string'||!disclosed.fingerprint)throw Error('Receipt retained event identity is invalid');state.receiptEntries.set(identity,{source:disclosed.source,id:disclosed.id,fingerprint:disclosed.fingerprint,eventSeq:row.seq,eventHash:row.hash,signed:false});state.receiptCovered.add(row.seq);}
   return;
  }
  if(row.type==='event_receipt'){
   const value=row.payload||{},event=state.receiptEvents.get(value.eventSeq),identity=receiptIdentity(value.source,value.id),existing=state.receiptEntries.get(identity),upgrading=existing&&!existing.signed&&existing.eventSeq===value.eventSeq;
   if(value.format!=='evidscope-event-receipt-v1'||typeof value.source!=='string'||!value.source||typeof value.id!=='string'||!value.id||!validDigest.test(value.fingerprint||'')||!Number.isSafeInteger(value.eventSeq)||value.eventSeq<1||!validDigest.test(value.eventHash||'')||!event||event.hash!==value.eventHash||row.seq<=value.eventSeq)throw Error('Receipt signed history is invalid');
   const disposition=state.receiptDispositions.get(event.keyId);if(disposition!==undefined&&row.seq>=disposition)throw Error('Receipt was not preserved before event disposition');
   if(value.basis!==undefined&&!['source_ingest','verified_before_retention'].includes(value.basis))throw Error('Receipt signed history has an invalid basis');
   if(value.basis==='source_ingest'&&row.principal!==value.source)throw Error('Receipt source attestation principal differs');
   if(value.basis==='verified_before_retention'&&value.attestedBy!==row.principal)throw Error('Receipt retention attestation principal differs');
   if(existing&&!upgrading||state.receiptCovered.has(value.eventSeq)&&!upgrading)throw Error('Receipt signed history is duplicated');
   const retained=state.eventsBySequence.get(value.eventSeq);if(retained&&(retained.source!==value.source||retained.id!==value.id||retained.fingerprint!==value.fingerprint))throw Error('Receipt signed history differs from retained event');
   state.receiptEntries.set(identity,{source:value.source,id:value.id,fingerprint:value.fingerprint,eventSeq:value.eventSeq,eventHash:value.eventHash,signed:true});state.receiptCovered.add(value.eventSeq);state.receiptSignedSequences.add(value.eventSeq);return;
  }
  if(row.type==='retention_disposition')for(const keyId of row.payload?.keyIds||[]){const sequence=state.eventKeys.get(keyId);if(sequence!==undefined&&!state.receiptSignedSequences.has(sequence))throw Error('Receipt history is missing for disposed legacy event');if(!state.receiptDispositions.has(keyId))state.receiptDispositions.set(keyId,row.seq);}
 }
 _captureActionTouches(state,row,disclosed,touched){
  if(!touched)return;
  const remember=id=>{if(typeof id==='string'&&id&&!touched.actions.has(id))touched.actions.set(id,state.action.get(id));};
  if(row.type==='event')remember(disclosed?.actionId??row.payload.actionId);
  else if(['asset','rule','exception'].includes(row.type)){if(!touched.allActions){for(const value of state.action.rows())remember(value.id);touched.allActions=true;}}
  else if(row.type==='evaluation')remember(row.payload.actionId);
  else if(row.type==='retention_disposition'){
   const sequences=Array.isArray(row.payload.sequences)?row.payload.sequences:(row.payload.keyIds||[]).map(keyId=>state.eventKeys.get(keyId));
   for(const sequence of sequences)remember(state.actionByEventSequence.get(sequence));
  }
 }
 _applyActionStateRow(tenant,state,row,touched){
  const objectValue=signedObjectProjection(row);if(objectValue){touched?.objects.add(objectValue.key);state.objects.set(objectValue.key,{...objectValue,row});}
  if(row.type==='evaluation')state.evaluations.push(row.payload);
  let disclosed;
  if(row.type==='event'){
   touched?.receiptEvents.add(row.seq);
   if(row.payload.format==='evidscope-encrypted-event-v1'){
    state.receiptRecords.push({tenant:row.tenant,seq:row.seq,type:row.type,payload:{keyId:row.payload.keyId},hash:row.hash,principal:row.principal});
    state.eventKeys.set(row.payload.keyId,row.seq);
    const stored=this.db.prepare('SELECT key FROM event_keys WHERE tenant=? AND key_id=?').get(tenant,row.payload.keyId);
    if(stored){disclosed=decryptEvent(row.payload,stored.key);state.keys.set(row.payload.keyId,{seq:row.seq,digest:this._keyDigest(stored.key)});}
    touched?.keys.add(row.payload.keyId);
   }else {
    disclosed=row.payload;
    state.receiptRecords.push({tenant:row.tenant,seq:row.seq,type:row.type,payload:{},hash:row.hash,principal:row.principal});
   }
  }else if(row.type==='event_receipt'||row.type==='retention_disposition')state.receiptRecords.push(row);
  this._applyReceiptEvidence(state,row,disclosed);this._captureActionTouches(state,row,disclosed,touched);state.action.apply(row,disclosed);
  if(row.type==='event')state.actionByEventSequence.set(row.seq,disclosed?.actionId??row.payload.actionId);
  if(row.type==='asset'&&row.payload.id)state.analysisAssets.set(`${row.payload.id}:${row.seq}`,row.payload);
  if(row.type==='rule'&&row.payload.id)state.analysisRules.set(row.payload.id,row.payload);
  if(row.type==='exception'&&row.payload.id)state.analysisExceptions.set(row.payload.id,row.payload);
  if(disclosed){const event={...disclosed,seq:row.seq,hash:row.hash};state.eventsBySequence.set(row.seq,event);touched?.events.set(canonical([event.source,event.id]),event);touched?.receipts.set(canonical([event.source,event.id]),{source:event.source,id:event.id,fingerprint:event.fingerprint});}
  if(row.type==='event_receipt'){const value=row.payload;touched?.receipts.set(canonical([value.source,value.id]),{source:value.source,id:value.id,fingerprint:value.fingerprint});}
  if(row.type==='retention_disposition')for(const keyId of row.payload.keyIds||[]){const sequence=state.eventKeys.get(keyId),event=sequence===undefined?null:state.eventsBySequence.get(sequence);if(event)touched?.events.set(canonical([event.source,event.id]),null);state.disposed.add(keyId);state.keys.delete(keyId);if(sequence!==undefined)state.eventsBySequence.delete(sequence);touched?.keys.add(keyId);}
 }
 _emptyActionState(tenant){return {tenant,count:0,head:'0'.repeat(64),action:createActionProjectionReducer(tenant),actionByEventSequence:new Map(),analysisAssets:new Map(),analysisRules:new Map(),analysisExceptions:new Map(),objects:new Map(),evaluations:[],receiptRecords:[],receiptEvents:new Map(),receiptEntries:new Map(),receiptCovered:new Set(),receiptSignedSequences:new Set(),receiptDispositions:new Map(),eventsBySequence:new Map(),eventKeys:new Map(),keys:new Map(),disposed:new Set(),versions:this._databaseVersions()};}
 _cloneActionState(state){return {...state,action:state.action.fork(),actionByEventSequence:new Map(state.actionByEventSequence),analysisAssets:new Map(state.analysisAssets),analysisRules:new Map(state.analysisRules),analysisExceptions:new Map(state.analysisExceptions),objects:new Map(state.objects),evaluations:state.evaluations.slice(),receiptRecords:state.receiptRecords.slice(),receiptEvents:new Map(state.receiptEvents),receiptEntries:new Map(state.receiptEntries),receiptCovered:new Set(state.receiptCovered),receiptSignedSequences:new Set(state.receiptSignedSequences),receiptDispositions:new Map(state.receiptDispositions),eventsBySequence:new Map(state.eventsBySequence),eventKeys:new Map(state.eventKeys),keys:new Map(state.keys),disposed:new Set(state.disposed)};}
 _stageActionState(tenant,state){
  state.versions=this._databaseVersions();state.mutationSerial=this.projectionMutationSerial;
  if(this.ledgerTransaction)this.ledgerTransaction.actionCandidates.set(tenant,state);else this.actionProjectionCache.set(tenant,state);
 }
 _verifyActionDelta(tenant,state,touched){
  for(const [id,prior] of touched.actions){const expected=state.action.get(id);if(canonical(prior)===canonical(expected))continue;const row=this.db.prepare('SELECT tenant,id,version,analyzed FROM actions WHERE tenant=? AND id=?').get(tenant,id);if(canonical(row)===canonical(expected))continue;throw Error('Action projection differs from signed evidence');}
  for(const [identity,expected] of touched.events){
   const [source,id]=JSON.parse(identity),row=this.db.prepare('SELECT tenant,source,id,fingerprint,action_id,trace_id,kind,received,body FROM events WHERE tenant=? AND source=? AND id=?').get(tenant,source,id);
   if(expected===null){if(row)throw Error('Event projection differs from signed evidence: retained disposed row');continue;}
   let body;try{body=JSON.parse(row?.body);}catch{throw Error('Event projection differs from signed evidence: invalid body JSON');}
   if(!row||canonical(body)!==canonical(expected)||canonical([row.tenant,row.source,row.id,row.fingerprint,row.action_id,row.trace_id,row.kind,row.received])!==canonical([expected.tenant,expected.source,expected.id,expected.fingerprint,expected.actionId,expected.traceId,expected.kind,expected.receivedAt]))throw Error('Event projection differs from signed evidence');
  }
  for(const [identity,expected] of touched.receipts){const [source,id]=JSON.parse(identity),row=this.db.prepare('SELECT source,id,fingerprint FROM receipts WHERE tenant=? AND source=? AND id=?').get(tenant,source,id);if(!row||canonical(row)!==canonical(expected))throw Error('Receipt projection differs from signed history');}
  for(const keyId of touched.keys){const expected=state.keys.get(keyId),row=this.db.prepare('SELECT seq,key FROM event_keys WHERE tenant=? AND key_id=?').get(tenant,keyId);if(!expected){if(row)throw Error('Event key projection differs from signed evidence');continue;}if(!row||row.seq!==expected.seq||this._keyDigest(row.key)!==expected.digest)throw Error('Event key projection differs from signed evidence');}
  for(const key of touched.objects){const expected=state.objects.get(key);if(!expected)throw Error('Object projection differs from signed evidence');const row=this.db.prepare('SELECT body FROM objects WHERE tenant=? AND type=? AND id=?').get(tenant,expected.type,expected.id);if(!row||canonical(JSON.parse(row.body))!==canonical(expected.payload))throw Error('Object projection differs from signed evidence');}
  if(touched.evaluationsStart!==state.evaluations.length){const rows=this.db.prepare('SELECT action_id,version,body FROM evaluations WHERE tenant=? ORDER BY id LIMIT -1 OFFSET ?').all(tenant,touched.evaluationsStart);if(touched.evaluationsStart+rows.length!==state.evaluations.length)throw Error('Evaluation projection differs from signed evidence');for(let index=0;index<rows.length;index++){const expected=state.evaluations[touched.evaluationsStart+index],row=rows[index];if(row.action_id!==expected.actionId||row.version!==expected.version||canonical(JSON.parse(row.body))!==canonical(expected))throw Error('Evaluation projection differs from signed evidence');}}
  return {valid:true,actions:state.action.size};
 }
 _assertCheckpointHead(tenant,checkpoint){
  const head=this.db.prepare('SELECT seq,hash FROM ledger WHERE tenant=? ORDER BY seq DESC LIMIT 1').get(tenant);
  if(checkpoint.count===0){if(head||checkpoint.head!=='0'.repeat(64))throw Error('Truncated or inconsistent export');}
  else if(!head||head.seq!==checkpoint.count||head.hash!==checkpoint.head)throw Error('Truncated or inconsistent export');
 }
 _coldActionState(tenant,checkpoint){
  const state=this._emptyActionState(tenant);
  for(const row of this.verifiedRows(tenant,16*1024*1024)){
   if(row.oversized){const type=this.db.prepare("SELECT json_extract(body,'$.type') AS type FROM ledger WHERE tenant=? AND seq=?").get(tenant,row.seq)?.type;if(['event','event_receipt','asset','rule','exception','evaluation','retention_disposition'].includes(type)||isSignedObjectType(type))throw Error('Action history row exceeds replay limit');continue;}
   this._applyActionStateRow(tenant,state,row);
  }
  for(const [keyId] of state.eventKeys)if(!state.keys.has(keyId)&&!state.disposed.has(keyId))throw Error('Event key missing without authorized disposition');
  for(const sequence of state.receiptEvents.keys())if(!state.receiptCovered.has(sequence))throw Error('Receipt history is missing for disposed legacy event');
  state.count=checkpoint.count;state.head=checkpoint.head;return state;
 }
 _verifiedActionSuffix(tenant,state,checkpoint){
  const rows=[];let sequence=state.count,previous=state.head;
  const query=this.db.prepare(`SELECT seq,hash,length(CAST(body AS BLOB)) AS bytes,
   json_extract(body,'$.tenant') AS record_tenant,json_extract(body,'$.seq') AS record_seq,
   json_extract(body,'$.previous') AS previous,
   CASE WHEN length(CAST(body AS BLOB))<=? THEN body ELSE NULL END AS body
   FROM ledger WHERE tenant=? AND seq>? ORDER BY seq`);
  for(const row of query.iterate(16*1024*1024,tenant,state.count)){
   if(row.seq!==++sequence||row.record_seq!==sequence||row.record_tenant!==tenant||row.previous!==previous)throw Error('Sequence, tenant or previous hash mismatch');
   let hash;
   if(row.body!==null)hash=digest(row.body);
   else {const hasher=createHash('sha256'),chunk=this.db.prepare('SELECT substr(CAST(body AS BLOB),?,65536) AS chunk FROM ledger WHERE tenant=? AND seq=?');for(let offset=1;offset<=row.bytes;offset+=65536)hasher.update(chunk.get(offset,tenant,row.seq).chunk);hash=hasher.digest('hex');}
   if(hash!==row.hash)throw Error('Record digest mismatch');previous=hash;
    if(row.body===null){const type=this.db.prepare("SELECT json_extract(body,'$.type') AS type FROM ledger WHERE tenant=? AND seq=?").get(tenant,row.seq)?.type;if(['event','event_receipt','asset','rule','exception','evaluation','retention_disposition'].includes(type)||isSignedObjectType(type))throw Error('Action history row exceeds replay limit');continue;}
   rows.push({...JSON.parse(row.body),hash:row.hash,recordBytes:row.bytes});
  }
  if(sequence!==checkpoint.count||previous!==checkpoint.head)throw Error('Truncated or inconsistent export');
  return rows;
 }
 checkActionProjection(tenant){
  this._syncProjectionMutationClock();
  const checkpoint=this.checkpoint(tenant);verifyCheckpoint(checkpoint,this.publicKey);if(checkpoint.tenant!==tenant)throw Error('Checkpoint tenant mismatch');this._assertCheckpointHead(tenant,checkpoint);
  const versions=this._databaseVersions(),cached=this.ledgerTransaction?.actionCandidates.get(tenant)||this.actionProjectionCache.get(tenant);let candidate,result;
  if(!cached||cached.versions.data!==versions.data||cached.versions.schema!==versions.schema||cached.mutationSerial!==this.projectionMutationSerial){candidate=this._coldActionState(tenant,checkpoint);result=this._verifyActionState(tenant,candidate);}
  else {
   if(checkpoint.count<cached.count)throw Error('Ledger checkpoint moved behind previously verified state');
   if(checkpoint.count===cached.count&&checkpoint.head!==cached.head)throw Error('Ledger checkpoint conflicts with previously verified state');
   if(checkpoint.count===cached.count)return {valid:true,actions:cached.action.size};
    const touched={actions:new Map(),allActions:false,events:new Map(),receipts:new Map(),keys:new Set(),receiptEvents:new Set(),objects:new Set(),evaluationsStart:cached.evaluations.length},pending=!!this.ledgerTransaction?.dirty.has(tenant),inPlace=!pending&&!this.ledgerTransaction?.external;
   candidate=inPlace?cached:this._cloneActionState(cached);
   try{
    const suffix=this._verifiedActionSuffix(tenant,candidate,checkpoint);
    for(const row of suffix)this._applyActionStateRow(tenant,candidate,row,touched);
    for(const keyId of touched.keys)if(candidate.eventKeys.has(keyId)&&!candidate.keys.has(keyId)&&!candidate.disposed.has(keyId))throw Error('Event key missing without authorized disposition');
    for(const sequence of touched.receiptEvents)if(!candidate.receiptCovered.has(sequence))throw Error('Receipt history is missing for disposed legacy event');
    candidate.count=checkpoint.count;candidate.head=checkpoint.head;result=this._verifyActionDelta(tenant,candidate,touched);
   }catch(error){if(inPlace){this.actionProjectionCache.delete(tenant);this.ledgerTransaction?.actionCandidates.delete(tenant);}throw error;}
  }
  this._stageActionState(tenant,candidate);return result;
 }
 checkDevelopmentRunProjection(tenant){
  const events=[];
  for(const row of this.verifiedRows(tenant,2*1024*1024)){
   if(row.oversized){const type=this.db.prepare("SELECT json_extract(body,'$.type') AS type FROM ledger WHERE tenant=? AND seq=?").get(tenant,row.seq)?.type;if(!type||type==='development_run_event')throw Error('Development history row exceeds replay limit');continue;}
   if(row.type==='development_run_event')events.push(row.payload);
  }
  return checkDevelopmentRunProjection(this.db,tenant,events);
 }
 rebuild(p) {return this.transaction(()=>{const bundle=this.rawBundle(p.tenant);verifyBundle(bundle,this.publicKey,undefined,{chainOnly:true});const original=this.decodeRecords(bundle),development=bundle.records.filter(row=>row.type==='development_run_event').map(row=>row.payload),receipts=expectedReceiptProjection(p.tenant,bundle.records,original);this.db.prepare('DELETE FROM events WHERE tenant=?').run(p.tenant);this.db.prepare('DELETE FROM receipts WHERE tenant=?').run(p.tenant);for(const e of original)this.project(e);for(const value of receipts.entries.values())this.db.prepare('INSERT OR REPLACE INTO receipts VALUES(?,?,?,?)').run(p.tenant,value.source,value.id,value.fingerprint);this.db.prepare('DELETE FROM development_run_events WHERE tenant=?').run(p.tenant);for(const e of development)this.db.prepare('INSERT INTO development_run_events VALUES(?,?,?,?,?,?,?,?)').run(e.tenant,e.source,e.eventId,e.runId,e.occurredAt,e.receivedAt,e.fingerprint,JSON.stringify(e));this.append(p.tenant,'projection_rebuild',{projections:['events','receipts','development_run_events']},p.id);return {rebuilt:original.length,receipts:receipts.entries.size,developmentEvents:development.length};});}
 project(e) {this.projectionMutation(()=>{this.db.prepare('INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)').run(e.tenant,e.source,e.id,e.fingerprint,e.actionId,e.traceId,e.kind,e.receivedAt,JSON.stringify(e));this.db.prepare('INSERT OR IGNORE INTO receipts VALUES(?,?,?,?)').run(e.tenant,e.source,e.id,e.fingerprint);});}
 count(name) {this.db.prepare('INSERT INTO counters VALUES(?,1) ON CONFLICT(name) DO UPDATE SET value=value+1').run(name);}
 close(){this.db.close();}
}
