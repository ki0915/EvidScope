import {DatabaseSync} from 'node:sqlite';
import {mkdirSync} from 'node:fs';
import {join} from 'node:path';
import {createPublicKey,createHash} from 'node:crypto';
import {canonical,digest,makeCheckpoint,verifyBundle,verifyCheckpoint} from './crypto.mjs';
import {encryptEvent,decryptEvent} from './encryption.mjs';

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
   CREATE TRIGGER IF NOT EXISTS immutable_delete BEFORE DELETE ON ledger BEGIN SELECT RAISE(ABORT,'append only'); END;`);
 }
 transaction(fn) {this.db.exec('BEGIN IMMEDIATE');try {const out=fn();this.db.exec('COMMIT');return out;}catch(e){this.db.exec('ROLLBACK');throw e;}}
 append(tenant,type,payload,principal) {
  const head=this.db.prepare('SELECT seq,hash FROM ledger WHERE tenant=? ORDER BY seq DESC LIMIT 1').get(tenant);
  const saved=this.db.prepare('SELECT body FROM checkpoints WHERE tenant=?').get(tenant);
  if(head){const checkpoint=saved&&JSON.parse(saved.body);verifyCheckpoint(checkpoint,this.publicKey);if(checkpoint.tenant!==tenant||checkpoint.count!==head.seq||checkpoint.head!==head.hash)throw Error('Ledger head differs from previously signed checkpoint; refusing to re-seal');}
  else if(saved)throw Error('Ledger is missing beneath an existing checkpoint');
  const seq=(head?.seq||0)+1;
  if(type==='event'){
   const policy=this.get(tenant,'retention_policy','current')||{version:0,retentionSeconds:30*86400,reason:'합성 파일럿 공학적 기본값; 법적 보존기간 아님'};
   const encrypted=encryptEvent(payload,tenant,seq,policy);this.db.prepare('INSERT INTO event_keys VALUES(?,?,?,?)').run(tenant,encrypted.keyId,seq,encrypted.key);payload=encrypted.payload;
  }
  const record={tenant,seq,previous:head?.hash||'0'.repeat(64),type,recordedAt:new Date().toISOString(),principal,payload};
  const hash=digest(record); this.db.prepare('INSERT INTO ledger VALUES(?,?,?,?)').run(tenant,record.seq,canonical(record),hash);
  this.db.prepare('INSERT INTO checkpoints VALUES(?,?) ON CONFLICT(tenant) DO UPDATE SET body=excluded.body').run(tenant,JSON.stringify(makeCheckpoint(tenant,record.seq,hash,this.key)));
  return {...record,hash};
 }
 audit(p,operation,target='') {return this.transaction(()=>this.append(p.tenant,'audit_access',{operation,target},p.id));}
 get(tenant,type,id) {const r=this.db.prepare('SELECT body FROM objects WHERE tenant=? AND type=? AND id=?').get(tenant,type,id);return r?JSON.parse(r.body):null;}
 list(tenant,type) {return this.db.prepare('SELECT body FROM objects WHERE tenant=? AND type=? ORDER BY id').all(tenant,type).map(r=>JSON.parse(r.body));}
 put(p,type,id,body) {this.append(p.tenant,type,body,p.id);this.db.prepare('INSERT INTO objects VALUES(?,?,?,?) ON CONFLICT(tenant,type,id) DO UPDATE SET body=excluded.body').run(p.tenant,type,id,JSON.stringify(body));return body;}
 events(tenant,actionId) {const sql=actionId?'SELECT body FROM events WHERE tenant=? AND action_id=? ORDER BY received,source,id':'SELECT body FROM events WHERE tenant=? ORDER BY received,source,id';return this.db.prepare(sql).all(...(actionId?[tenant,actionId]:[tenant])).map(r=>JSON.parse(r.body));}
 evaluations(tenant,actionId) {return this.db.prepare('SELECT body FROM evaluations WHERE tenant=? AND action_id=? ORDER BY id DESC').all(tenant,actionId).map(r=>JSON.parse(r.body));}
 rawBundle(tenant) {const records=this.db.prepare('SELECT body,hash FROM ledger WHERE tenant=? ORDER BY seq').all(tenant).map(r=>({...JSON.parse(r.body),hash:r.hash})); const cp=this.db.prepare('SELECT body FROM checkpoints WHERE tenant=?').get(tenant); return {format:'evidscope-export-v2',records,checkpoint:cp?JSON.parse(cp.body):makeCheckpoint(tenant,0,'0'.repeat(64),this.key),limitations:['Minimized receipt evidence; no original prompt or response','Signature authenticates local vault, not truth of source claims','Pin public key and checkpoint out of band to detect replacement and rollback','Erasure covers live event keys and query copies; prior exports/backups need separate disposition']};}
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
  const saved=this.db.prepare('SELECT body FROM checkpoints WHERE tenant=?').get(tenant);
  const cp=saved?JSON.parse(saved.body):makeCheckpoint(tenant,0,'0'.repeat(64),this.key);verifyCheckpoint(cp,this.publicKey);
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
 checkProjection(tenant){const original=this.ledgerEvents(tenant);const projection=this.events(tenant);if(canonical(original)!==canonical(projection))throw Error('Search projection differs from retained original evidence');return {valid:true,retainedEvents:original.length};}
 rebuild(p) {return this.transaction(()=>{const original=this.ledgerEvents(p.tenant);this.db.prepare('DELETE FROM events WHERE tenant=?').run(p.tenant);for(const e of original)this.project(e);this.append(p.tenant,'projection_rebuild',{},p.id);return {rebuilt:original.length};});}
 project(e) {this.db.prepare('INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)').run(e.tenant,e.source,e.id,e.fingerprint,e.actionId,e.traceId,e.kind,e.receivedAt,JSON.stringify(e));this.db.prepare('INSERT OR IGNORE INTO receipts VALUES(?,?,?,?)').run(e.tenant,e.source,e.id,e.fingerprint);}
 count(name) {this.db.prepare('INSERT INTO counters VALUES(?,1) ON CONFLICT(name) DO UPDATE SET value=value+1').run(name);}
 close(){this.db.close();}
}
