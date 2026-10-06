// Per-read access records live outside the signed evidence ledger, in their own SQLite file, as a per-tenant SHA-256 hash
// chain written before any data leaves the process. Contiguous ranges are sealed into the ledger as audit_access_batch
// records that commit to the count, the chain head and an RFC 6962 Merkle root of the entries, so a sealed read is as
// tamper-evident as any ledger record and one read can be proven with an inclusion proof without disclosing the others.
// The ledger is the source of truth for what is sealed; this file holds the entries and the unsealed tail.
import {DatabaseSync,constants as sqlite} from 'node:sqlite';
import {createHash} from 'node:crypto';
import {join} from 'node:path';
import {canonical,verifyCheckpoint} from './crypto.mjs';
import {b64,frontierAppend,frontierRoot,fromB64,leafHash,levelsInclusionProof,levelsRoot,merkleLevels,verifyInclusion} from './tlog.mjs';

export const ACCESS_LOG_FILE='access-log.db';
export const ACCESS_ENTRY_FORMAT='evidscope-access-v1';
export const ACCESS_BATCH_FORMAT='evidscope-access-batch-v1';
export const ACCESS_BATCH_TYPE='audit_access_batch';
export const ACCESS_SEALER='access-log-sealer';
export const ACCESS_LOG_DEFAULTS=Object.freeze({sealIntervalMs:60000,sealThreshold:1000,maxBatch:10000,maxUnsealedAgeMs:15*60000});
const ZERO='0'.repeat(64);
const SEAL_REASONS=new Set(['interval','threshold','export','integrity','checkpoint_publish','shutdown','manual']);
const SCHEMA=`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
 CREATE TABLE IF NOT EXISTS access_log(tenant TEXT NOT NULL,seq INTEGER NOT NULL CHECK(seq>0),body TEXT NOT NULL,hash TEXT NOT NULL,PRIMARY KEY(tenant,seq));
 CREATE TRIGGER IF NOT EXISTS access_log_immutable_update BEFORE UPDATE ON access_log BEGIN SELECT RAISE(ABORT,'append only'); END;
 CREATE TRIGGER IF NOT EXISTS access_log_immutable_delete BEFORE DELETE ON access_log BEGIN SELECT RAISE(ABORT,'append only'); END;`;
const PROTECTED_TRIGGERS=new Set(['access_log_immutable_update','access_log_immutable_delete']);

const sha256Hex=text=>createHash('sha256').update(text).digest('hex');
// Leaf = SHA-256(0x00 || UTF-8(canonical(entry))); the stored body is that canonical text.
export const accessLeafHash=body=>leafHash(Buffer.from(body,'utf8'));
export function accessQueryHash(query){
 const pairs=query?[...(typeof query.entries==='function'?query.entries():Object.entries(query))].map(([k,v])=>[String(k),String(v)]):[];
 if(!pairs.length)return null;
 pairs.sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:a[1]<b[1]?-1:a[1]>b[1]?1:0);
 return sha256Hex(canonical(pairs));
}
function chainError(tenant,seq,detail){return Error(`Access log chain mismatch for tenant ${tenant} at sequence ${seq}: ${detail}`);}

// Checks that rows continue the chain after (seq,previous). Returns the parsed entries.
export function checkAccessChain(tenant,rows,seq,previous){
 const entries=[];
 for(const row of rows){
  seq++;
  if(row.seq!==seq)throw chainError(tenant,seq,'missing or reordered entry');
  let entry;try{entry=JSON.parse(row.body);}catch{throw chainError(tenant,seq,'unreadable entry');}
  if(canonical(entry)!==row.body||sha256Hex(row.body)!==row.hash)throw chainError(tenant,seq,'entry hash differs');
  if(entry.format!==ACCESS_ENTRY_FORMAT||entry.tenant!==tenant||entry.seq!==seq||entry.previous!==previous)
   throw chainError(tenant,seq,'entry does not link to its predecessor');
  previous=row.hash;entries.push(entry);
 }
 return entries;
}
function batchError(record,detail){return Error(`Access log batch at ledger sequence ${record.seq} ${detail}`);}
function checkBatchShape(record,toSeq,head){
 const b=record.payload;
 if(!b||b.format!==ACCESS_BATCH_FORMAT||!Number.isSafeInteger(b.fromSeq)||!Number.isSafeInteger(b.toSeq)||b.toSeq<b.fromSeq||b.count!==b.toSeq-b.fromSeq+1)
  throw batchError(record,'is malformed');
 if(b.fromSeq!==toSeq+1||b.previous!==head)throw batchError(record,'is not contiguous with the previous sealed range');
 return b;
}
// Offline check of sealed batches against exported entries: [{seq,body,hash}] in order, starting at sequence 1.
export function verifyAccessBatches(tenant,records,rows){
 let toSeq=0,head=ZERO,offset=0,batches=0;
 for(const record of records){
  if(record.type!==ACCESS_BATCH_TYPE)continue;
  const b=checkBatchShape(record,toSeq,head),slice=rows.slice(offset,offset+b.count);
  if(slice.length!==b.count)throw batchError(record,'covers entries that are missing');
  const entries=checkAccessChain(tenant,slice,toSeq,head);
  if(slice.at(-1).hash!==b.head||levelsRoot(merkleLevels(slice.map(row=>accessLeafHash(row.body)))).toString('hex')!==b.merkleRoot||
   entries[0].at!==b.firstAt||entries.at(-1).at!==b.lastAt)throw batchError(record,'differs from the sealed entries');
  toSeq=b.toSeq;head=b.head;offset+=b.count;batches++;
 }
 checkAccessChain(tenant,rows.slice(offset),toSeq,head);
 return {valid:true,batches,sealedEntries:toSeq,unsealedEntries:rows.length-offset};
}
// Streams one tenant's entries from an access-log database: every sealed range named by the signed batch records (in ledger
// order) must be present, chained and match its count, head, Merkle root and time span; the unsealed tail must continue the
// chain and be younger than maxUnsealedAgeMs.
export function verifyAccessLogDatabase(db,tenant,records,{now=Date.now(),maxUnsealedAgeMs=Infinity}={}){
 let toSeq=0,head=ZERO,batches=0;
 const range=db.prepare('SELECT seq,body,hash FROM access_log WHERE tenant=? AND seq>=? AND seq<=? ORDER BY seq');
 for(const record of records){
  if(record.type!==ACCESS_BATCH_TYPE)continue;
  const b=checkBatchShape(record,toSeq,head);
  let peaks=[],size=0,seq=toSeq,previous=head,first=null,last=null;
  for(const row of range.iterate(tenant,b.fromSeq,b.toSeq)){
   const [entry]=checkAccessChain(tenant,[row],seq,previous);seq++;previous=row.hash;first??=entry.at;last=entry.at;
   peaks=frontierAppend(peaks,size++,accessLeafHash(row.body));
  }
  if(size!==b.count)throw batchError(record,`covers entries that are missing from the access log (${size} of ${b.count})`);
  if(previous!==b.head||frontierRoot(peaks).toString('hex')!==b.merkleRoot||first!==b.firstAt||last!==b.lastAt)
   throw batchError(record,'differs from the sealed entries');
  toSeq=b.toSeq;head=b.head;batches++;
 }
 let unsealed=0,oldest=null,seq=toSeq,previous=head;
 for(const row of db.prepare('SELECT seq,body,hash FROM access_log WHERE tenant=? AND seq>? ORDER BY seq').iterate(tenant,toSeq)){
  const [entry]=checkAccessChain(tenant,[row],seq,previous);seq++;previous=row.hash;oldest??=entry.at;unsealed++;
 }
 if(oldest&&now-Date.parse(oldest)>maxUnsealedAgeMs)
  throw Error(`Access log unsealed tail for tenant ${tenant} is older than ${maxUnsealedAgeMs} ms; sealing has stalled`);
 return {valid:true,batches,sealedEntries:toSeq,unsealedEntries:unsealed,oldestUnsealedAt:oldest,...(Number.isFinite(maxUnsealedAgeMs)?{maxUnsealedAgeMs}:{})};
}
// Inclusion of one entry (body) at position seq in a sealed batch payload.
export function verifyAccessInclusion(body,seq,batch,proof){
 if(!batch||batch.format!==ACCESS_BATCH_FORMAT||seq<batch.fromSeq||seq>batch.toSeq)return false;
 let entry;try{entry=JSON.parse(body);}catch{return false;}
 if(canonical(entry)!==body||entry.seq!==seq)return false;
 return verifyInclusion(accessLeafHash(body),seq-batch.fromSeq,batch.count,proof.map(fromB64),Buffer.from(batch.merkleRoot,'hex'));
}

export class AccessLog {
 constructor(dir,store,options={}){
  this.store=store;this.options={...ACCESS_LOG_DEFAULTS,...options};this.file=join(dir,ACCESS_LOG_FILE);
  this.db=new DatabaseSync(this.file);this.db.exec(SCHEMA);
  this.db.setAuthorizer((action,table)=>{
   if(action===sqlite.SQLITE_DROP_TRIGGER&&PROTECTED_TRIGGERS.has(table))return sqlite.SQLITE_DENY;
   if([sqlite.SQLITE_DROP_TABLE,sqlite.SQLITE_ALTER_TABLE].includes(action)&&table==='access_log')return sqlite.SQLITE_DENY;
   return sqlite.SQLITE_OK;
  });
  this.sealed=new Map();this.verifiedCheckpoints=new Map();this.pendingSeals=new Set();this.timer=null;
  this.lastSeal=null;this.lastSealError=null;
 }
 // Reads the signed checkpoint and ledger head in one snapshot of the evidence database. A head that differs from the
 // signed checkpoint is reported (the request then fails closed), never re-signed.
 _observe(tenant){
  const db=this.store.db,own=!db.isTransaction;
  if(own)db.exec('SAVEPOINT evidscope_access_observe');
  try{
   const saved=db.prepare('SELECT body FROM checkpoints WHERE tenant=?').get(tenant),
    head=db.prepare('SELECT seq,hash FROM ledger WHERE tenant=? ORDER BY seq DESC LIMIT 1').get(tenant);
   if(!saved)return head?{count:0,head:ZERO,fault:'Ledger is missing a signed checkpoint above its head'}:{count:0,head:ZERO};
   let checkpoint;
   try{
    checkpoint=JSON.parse(saved.body);
    if(this.verifiedCheckpoints.get(tenant)!==saved.body){verifyCheckpoint(checkpoint,this.store.publicKey);this.verifiedCheckpoints.set(tenant,saved.body);}
   }catch{return {count:0,head:ZERO,fault:'Checkpoint signature invalid'};}
   const observed={count:checkpoint.count,head:checkpoint.head};
   if(checkpoint.tenant!==tenant||(head?.seq??0)!==checkpoint.count||(head?.hash??ZERO)!==checkpoint.head)
    return {...observed,fault:'Ledger head differs from previously signed checkpoint; refusing to serve reads'};
   return observed;
  }finally{if(own)db.exec('RELEASE evidscope_access_observe');}
 }
 // Records one access before routing. Throws 503 when the record cannot be written (no data is served) and, after
 // recording, 409 when the ledger head differs from its signed checkpoint and failClosed is set.
 record(p,{method='GET',target,query,operation='read'}={},{failClosed=true}={}){
  const observed=this._observe(p.tenant),{fault,...state}=observed;
  let entry;
  try{
   this.db.exec('BEGIN IMMEDIATE');
   try{
    const last=this.db.prepare('SELECT seq,hash FROM access_log WHERE tenant=? ORDER BY seq DESC LIMIT 1').get(p.tenant);
    entry={format:ACCESS_ENTRY_FORMAT,tenant:p.tenant,seq:(last?.seq??0)+1,previous:last?.hash??ZERO,principal:p.id,authentication:p.authentication||'bearer',
     ...(p.sessionId?{sessionId:p.sessionId}:{}),operation,method,target,queryHash:accessQueryHash(query),at:new Date().toISOString(),observed:state,
     ...(fault?{fault}:{})};
    const body=canonical(entry);this.db.prepare('INSERT INTO access_log VALUES(?,?,?,?)').run(p.tenant,entry.seq,body,sha256Hex(body));
    this.db.exec('COMMIT');
   }catch(error){if(this.db.isTransaction)this.db.exec('ROLLBACK');throw error;}
  }catch(error){throw Object.assign(Error('Access log unavailable; the read was not served: '+error.message),{status:503});}
  if(fault&&failClosed)throw Object.assign(Error(fault),{status:409});
  const sealedTo=this.sealed.get(p.tenant)?.batch.toSeq??0;
  if(entry.seq-sealedTo>=this.options.sealThreshold)this._scheduleSeal(p.tenant);
  return entry;
 }
 _scheduleSeal(tenant){
  if(this.pendingSeals.has(tenant))return;
  this.pendingSeals.add(tenant);
  setImmediate(()=>{
   this.pendingSeals.delete(tenant);
   if(!this.db.isOpen||!this.store.db.isOpen)return;
   try{const status=this.status(tenant);
    if(status.unsealedEntries>=this.options.sealThreshold)this.seal(tenant,'threshold');}catch(error){this._sealFailed(tenant,error);}
  }).unref?.();
 }
 _sealFailed(tenant,error){
  this.lastSealError={tenant,error:error.message,at:new Date().toISOString()};
  process.stderr.write(JSON.stringify({component:'access-log',tenant,error:error.message})+'\n');
 }
 // Last sealed range according to the ledger (inside the caller's evidence snapshot). The cache only remembers how far the
 // ledger was already scanned; that anchor row is re-validated each time and a rewritten or rolled-back ledger is rescanned.
 _lastBatch(tenant){
  const db=this.store.db,cached=this.sealed.get(tenant);
  let from=0,batch={ledgerSeq:0,toSeq:0,head:ZERO};
  if(cached&&db.prepare('SELECT hash FROM ledger WHERE tenant=? AND seq=?').get(tenant,cached.anchorSeq)?.hash===cached.anchorHash)
   {from=cached.anchorSeq;batch=cached.batch;}
  const row=db.prepare("SELECT seq,body FROM ledger WHERE tenant=? AND seq>? AND json_extract(body,'$.type')=? ORDER BY seq DESC LIMIT 1")
   .get(tenant,from,ACCESS_BATCH_TYPE);
  if(row){const b=JSON.parse(row.body).payload;batch={ledgerSeq:row.seq,toSeq:b.toSeq,head:b.head};}
  const top=db.prepare('SELECT seq,hash FROM ledger WHERE tenant=? ORDER BY seq DESC LIMIT 1').get(tenant);
  if(top)this.sealed.set(tenant,{anchorSeq:top.seq,anchorHash:top.hash,batch});else this.sealed.delete(tenant);
  return batch;
 }
 // Seals the unsealed tail (up to maxBatch entries) into one ledger record through the normal append path, so the
 // checkpoint, tenant tlog and heads log stay consistent. Returns the ledger record, or null when nothing is unsealed.
 seal(tenant,reason='manual',principal=ACCESS_SEALER){
  if(!SEAL_REASONS.has(reason))throw Error('Unknown access log seal reason');
  const record=this.store.transaction(()=>{
   const last=this._lastBatch(tenant);
   if(last.toSeq&&this.db.prepare('SELECT hash FROM access_log WHERE tenant=? AND seq=?').get(tenant,last.toSeq)?.hash!==last.head)
    throw Error(`Access log differs from its last sealed batch for tenant ${tenant}`);
   const rows=this.db.prepare('SELECT seq,body,hash FROM access_log WHERE tenant=? AND seq>? ORDER BY seq LIMIT ?')
    .all(tenant,last.toSeq,this.options.maxBatch);
   if(!rows.length)return null;
   const entries=checkAccessChain(tenant,rows,last.toSeq,last.head);
   return this.store.append(tenant,ACCESS_BATCH_TYPE,{format:ACCESS_BATCH_FORMAT,fromSeq:last.toSeq+1,toSeq:rows.at(-1).seq,count:rows.length,
    previous:last.head,
    head:rows.at(-1).hash,merkleRoot:levelsRoot(merkleLevels(rows.map(row=>accessLeafHash(row.body)))).toString('hex'),firstAt:entries[0].at,
    lastAt:entries.at(-1).at,reason},principal);
  });
  if(record){this.lastSeal={tenant,ledgerSeq:record.seq,toSeq:record.payload.toSeq,reason,at:record.recordedAt};
   if(this.lastSealError?.tenant===tenant)this.lastSealError=null;}
  return record;
 }
 tenants(){return this.db.prepare('SELECT tenant,MAX(seq) seq FROM access_log GROUP BY tenant').all();}
 // Seals every tenant with an unsealed tail; failures are logged and reported by status and /api/integrity.
 sealAll(reason){
  const sealed=[];
  for(const {tenant} of this.tenants()){
   try{
    let record;let rounds=0;
    do{record=this.seal(tenant,reason);if(record)sealed.push(record);}while(record&&record.payload.count>=this.options.maxBatch&&++rounds<100);
   }catch(error){this._sealFailed(tenant,error);}
  }
  return sealed;
 }
 status(tenant){
  const last=this._lastBatch(tenant),max=this.db.prepare('SELECT MAX(seq) seq FROM access_log WHERE tenant=?').get(tenant).seq??0;
  const oldest=max>last.toSeq?this.db.prepare('SELECT body FROM access_log WHERE tenant=? AND seq=?').get(tenant,last.toSeq+1):null;
  return {tenant,entries:max,sealedEntries:last.toSeq,unsealedEntries:Math.max(0,max-last.toSeq),oldestUnsealedAt:oldest?JSON.parse(oldest.body).at:null,
   lastSealedLedgerSeq:last.ledgerSeq||null,sealIntervalMs:this.options.sealIntervalMs,sealThreshold:this.options.sealThreshold,
   maxUnsealedAgeMs:this.options.maxUnsealedAgeMs,lastSealError:this.lastSealError?.tenant===tenant?this.lastSealError:null};
 }
 // Verifies every sealed range named by the tenant's signed batch records (in ledger order) against the stored entries,
 // and that the unsealed tail continues the chain and is younger than maxUnsealedAgeMs.
 verify(tenant,records,{now=Date.now()}={}){return verifyAccessLogDatabase(this.db,tenant,records,{now,maxUnsealedAgeMs:this.options.maxUnsealedAgeMs});}
 entries(tenant,{fromSeq=1,limit=100}={}){
  const rows=this.db.prepare('SELECT seq,body,hash FROM access_log WHERE tenant=? AND seq>=? ORDER BY seq LIMIT ?').all(tenant,fromSeq,limit);
  return rows.map(row=>({seq:row.seq,hash:row.hash,entry:JSON.parse(row.body)}));
 }
 // RFC 6962 inclusion proof of entry seq in the sealed batch (a signed ledger record) that covers it.
 proof(tenant,seq,batchRecords){
  const record=batchRecords.find(row=>row.type===ACCESS_BATCH_TYPE&&row.payload.fromSeq<=seq&&seq<=row.payload.toSeq);
  if(!record)return null;
  const b=record.payload,
   rows=this.db.prepare('SELECT seq,body,hash FROM access_log WHERE tenant=? AND seq>=? AND seq<=? ORDER BY seq').all(tenant,b.fromSeq,b.toSeq);
  if(rows.length!==b.count)throw batchError(record,'covers entries that are missing from the access log');
  const tree=merkleLevels(rows.map(row=>accessLeafHash(row.body)));
  if(levelsRoot(tree).toString('hex')!==b.merkleRoot)throw batchError(record,'differs from the sealed entries');
  const row=rows[seq-b.fromSeq];
  return {seq,body:row.body,hash:row.hash,leafIndex:seq-b.fromSeq,proof:levelsInclusionProof(tree,seq-b.fromSeq).map(b64),
   batch:{seq:record.seq,hash:record.hash,payload:b}};
 }
 start(){
  if(this.timer)return;
  this.timer=setInterval(()=>{if(this.db.isOpen&&this.store.db.isOpen)this.sealAll('interval');},this.options.sealIntervalMs);
  this.timer.unref?.();
 }
 stop(){
  if(this.timer)clearInterval(this.timer);this.timer=null;
  if(this.db.isOpen&&this.store.db.isOpen)return this.sealAll('shutdown');
  return [];
 }
 close(){if(this.timer)clearInterval(this.timer);this.timer=null;if(this.db.isOpen)this.db.close();}
}
