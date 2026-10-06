import {DatabaseSync} from 'node:sqlite';
import {mkdirSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {randomUUID} from 'node:crypto';
import {submit} from './client.mjs';
import {canonical,digest} from './crypto.mjs';
import {validateAIObservation} from './ai-observations.mjs';

const envelopeKeys=['id','kind','occurredAt','traceId','actionId','tool','action','status','aiObservation'];
const failure=code=>Object.assign(new Error(code),{code});
const identifier=value=>{if(typeof value!=='string'||!/^[A-Za-z0-9._:@/-]{1,120}$/.test(value))throw failure('invalid_observation_envelope');return value;};
function bounded(value,min,max){if(!Number.isSafeInteger(value)||value<min||value>max)throw failure('invalid_observer_configuration');return value;}

export function validateObservationEnvelope(raw){
 if(!raw||typeof raw!=='object'||Array.isArray(raw)||Object.keys(raw).some(key=>!envelopeKeys.includes(key))||envelopeKeys.some(key=>raw[key]===undefined))throw failure('invalid_observation_envelope');
 if(raw.kind!=='notice'||raw.tool!=='ai-observation-collector'||raw.action!=='ai_usage_observed'||typeof raw.occurredAt!=='string'||!/^\d{4}-\d\d-\d\dT.*(?:Z|[+-]\d\d:\d\d)$/.test(raw.occurredAt)||!Number.isFinite(Date.parse(raw.occurredAt)))throw failure('invalid_observation_envelope');
 const aiObservation=validateAIObservation(raw.aiObservation);if(raw.status!==aiObservation.coverage.status)throw failure('invalid_observation_envelope');
 const event={id:identifier(raw.id),kind:'notice',occurredAt:new Date(raw.occurredAt).toISOString(),traceId:identifier(raw.traceId),actionId:identifier(raw.actionId),tool:'ai-observation-collector',action:'ai_usage_observed',status:raw.status,aiObservation};
 if(Buffer.byteLength(canonical(event))>32768)throw failure('observation_envelope_limit');return event;
}

function sourceConfiguration(url,principal){
 let target;try{target=new URL(url);}catch{throw failure('invalid_observer_source');}
 if(!['http:','https:'].includes(target.protocol)||target.username||target.password||target.search||target.hash||!['','/'].includes(target.pathname))throw failure('invalid_observer_source');
 if(target.protocol==='http:'&&!['127.0.0.1','[::1]','localhost'].includes(target.hostname))throw failure('observer_source_requires_tls');
 if(!principal||typeof principal!=='object'||['token','hmacSecret'].some(key=>typeof principal[key]!=='string'||!principal[key].length))throw failure('invalid_observer_source');
 try{identifier(principal.id);identifier(principal.tenant);}catch{throw failure('invalid_observer_source');}
 return {url:target.origin,principal:{id:principal.id,tenant:principal.tenant,token:principal.token,hmacSecret:principal.hmacSecret}};
}

export class DurableObserver {
 #db;#url;#principal;#submit;#now;#running;#stopping=false;#closed=false;#wake;#owner=randomUUID();
 #local={invalid:0,queueFull:0,diskErrors:0,idConflicts:0};
 constructor({spoolPath,url,principal,capacity=1000,maxAttempts=3,timeoutMs=2000,retryDelayMs=50,submitEvent=submit,now=Date.now}={}){
  this.capacity=bounded(capacity,1,10000);this.maxAttempts=bounded(maxAttempts,1,10);this.timeoutMs=bounded(timeoutMs,1,10000);this.retryDelayMs=bounded(retryDelayMs,0,1000);
  if(typeof spoolPath!=='string'||!spoolPath||spoolPath===':memory:'||spoolPath.startsWith('file:')||typeof submitEvent!=='function'||typeof now!=='function')throw failure('invalid_observer_configuration');
  const source=sourceConfiguration(url,principal);this.#url=source.url;this.#principal=source.principal;this.#submit=submitEvent;this.#now=now;
  try{
   const path=resolve(spoolPath);mkdirSync(dirname(path),{recursive:true});this.#db=new DatabaseSync(path);
   this.#db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=1000;
    CREATE TABLE IF NOT EXISTS observer_meta(name TEXT PRIMARY KEY,value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS observer_queue(id TEXT PRIMARY KEY,fingerprint TEXT NOT NULL,body TEXT,status TEXT NOT NULL CHECK(status IN ('pending','inflight','accepted','rejected','retry_exhausted')),attempts INTEGER NOT NULL DEFAULT 0,next_attempt INTEGER NOT NULL DEFAULT 0,lease_until INTEGER,lease_owner TEXT,created INTEGER NOT NULL,updated INTEGER NOT NULL,last_code INTEGER);
    CREATE INDEX IF NOT EXISTS observer_ready ON observer_queue(status,next_attempt,created);
    CREATE TABLE IF NOT EXISTS observer_metrics(name TEXT PRIMARY KEY,value INTEGER NOT NULL);`);
   this.#transaction(()=>{const binding=digest({url:this.#url,tenant:this.#principal.tenant,source:this.#principal.id}),existing=this.#db.prepare('SELECT value FROM observer_meta WHERE name=?').get('source_binding');if(existing&&existing.value!==binding)throw failure('spool_source_mismatch');this.#db.prepare('INSERT OR IGNORE INTO observer_meta(name,value) VALUES(?,?)').run('source_binding',binding);});
  }catch(error){try{this.#db?.close();}catch{}throw failure(error?.code==='spool_source_mismatch'?'spool_source_mismatch':'observer_spool_unavailable');}
 }
 #transaction(fn){this.#db.exec('BEGIN IMMEDIATE');try{const result=fn();this.#db.exec('COMMIT');return result;}catch(error){try{this.#db.exec('ROLLBACK');}catch{}throw error;}}
 #count(name,amount=1){this.#db.prepare('INSERT INTO observer_metrics(name,value) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=value+excluded.value').run(name,amount);}
 enqueue(raw){
  let event,body;try{event=validateObservationEnvelope(raw);body=canonical(event);}catch{this.#local.invalid++;return {queued:false,outcome:'invalid_event'};}
  if(this.#closed||this.#stopping)return {queued:false,outcome:'stopped'};
  try{return this.#transaction(()=>{
   const fingerprint=digest(body),previous=this.#db.prepare('SELECT fingerprint,status FROM observer_queue WHERE id=?').get(event.id);
   if(previous){if(previous.fingerprint!==fingerprint){this.#local.idConflicts++;return {queued:false,outcome:'id_conflict'};}this.#count('duplicate_enqueues');return {queued:previous.status==='pending'||previous.status==='inflight',outcome:'duplicate',status:previous.status};}
   const {count}=this.#db.prepare("SELECT COUNT(*) count FROM observer_queue WHERE status!='accepted'").get();if(count>=this.capacity){this.#local.queueFull++;this.#count('queue_full');return {queued:false,outcome:'queue_full'};}
   const timestamp=this.#now();this.#db.prepare("INSERT INTO observer_queue(id,fingerprint,body,status,created,updated) VALUES(?,?,?,'pending',?,?)").run(event.id,fingerprint,body,timestamp,timestamp);this.#count('enqueued');return {queued:true,outcome:'queued'};
  });}catch{this.#local.diskErrors++;return {queued:false,outcome:'disk_error'};}
 }
 #claim(){return this.#transaction(()=>{
 const timestamp=this.#now();
  const abandoned=this.#db.prepare("SELECT COUNT(*) count FROM observer_queue WHERE status='inflight' AND lease_until<=? AND attempts>=?").get(timestamp,this.maxAttempts).count;
  this.#db.prepare("UPDATE observer_queue SET status=CASE WHEN attempts>=? THEN 'retry_exhausted' ELSE 'pending' END,lease_owner=NULL,lease_until=NULL,updated=? WHERE status='inflight' AND lease_until<=?").run(this.maxAttempts,timestamp,timestamp);
  const exhausted=this.#db.prepare("UPDATE observer_queue SET status='retry_exhausted',updated=? WHERE status='pending' AND attempts>=?").run(timestamp,this.maxAttempts);if(abandoned+Number(exhausted.changes)>0)this.#count('retry_exhausted',abandoned+Number(exhausted.changes));
  const row=this.#db.prepare("SELECT id,body,attempts FROM observer_queue WHERE status='pending' AND next_attempt<=? ORDER BY created,id LIMIT 1").get(timestamp);if(!row)return null;
  this.#db.prepare("UPDATE observer_queue SET status='inflight',attempts=attempts+1,lease_owner=?,lease_until=?,updated=? WHERE id=? AND status='pending'").run(this.#owner,timestamp+this.timeoutMs+1000,timestamp,row.id);this.#count('attempts');return {...row,attempts:row.attempts+1};
 });}
 async #send(row){
  let event;try{event=validateObservationEnvelope(JSON.parse(row.body));}catch{return {outcome:'rejected',code:null};}
  let timer;const deadline=Symbol('deadline');
  try{
   // Replays retain the event ID but every attempt obtains fresh request authentication.
   const response=await Promise.race([Promise.resolve().then(()=>this.#submit(this.#url,this.#principal,event,{timeoutMs:this.timeoutMs,nonce:randomUUID(),timestamp:String(this.#now())})),new Promise(resolve=>{timer=setTimeout(()=>resolve(deadline),this.timeoutMs);})]);
   if(response===deadline)return {outcome:'retry',code:null};
   const code=Number.isInteger(response?.status)&&response.status>=100&&response.status<=599?response.status:null;
   if(code===202&&response.body?.accepted===true)return {outcome:'accepted',code,duplicate:response.body.duplicate===true};
   if(code!==null&&code>=400&&code<500&&![408,425,429].includes(code))return {outcome:'rejected',code};
   if(code!==null&&code>=300&&code<400)return {outcome:'rejected',code};
   return {outcome:'retry',code};
  }catch{return {outcome:'retry',code:null};}finally{clearTimeout(timer);}
 }
 #finish(row,result){this.#transaction(()=>{
  let outcome=result.outcome;if(outcome==='retry')outcome=row.attempts>=this.maxAttempts?'retry_exhausted':'pending';
  const timestamp=this.#now(),delay=outcome==='pending'?Math.min(1000,this.retryDelayMs*2**(row.attempts-1)):0;
  const changed=this.#db.prepare("UPDATE observer_queue SET status=?,body=CASE WHEN ?='accepted' THEN NULL ELSE body END,next_attempt=?,lease_until=NULL,lease_owner=NULL,updated=?,last_code=? WHERE id=? AND status='inflight' AND lease_owner=?").run(outcome,outcome,timestamp+delay,timestamp,result.code,row.id,this.#owner);
  if(changed.changes){this.#count(outcome==='pending'?'retries':outcome);if(result.duplicate)this.#count('duplicate_acks');if(result.code!==null)this.#count(`http_${result.code}`);}
  // Accepted bodies are removed; bounded receipts prevent a successful sender growing forever.
  this.#db.prepare("DELETE FROM observer_queue WHERE status='accepted' AND id NOT IN (SELECT id FROM observer_queue WHERE status='accepted' ORDER BY updated DESC,id DESC LIMIT ?)").run(this.capacity);
 });}
 async #wait(ms){await new Promise(resolve=>{const timer=setTimeout(done,ms);this.#wake=done;const self=this;function done(){clearTimeout(timer);self.#wake=undefined;resolve();}});}
 async #drain({maxEvents,maxDurationMs}){
  const started=performance.now();let sent=0;
  while(!this.#stopping&&sent<maxEvents&&performance.now()-started<maxDurationMs){
   let row;try{row=this.#claim();}catch{this.#local.diskErrors++;break;}
   if(!row){let next;try{next=this.#db.prepare("SELECT MIN(next_attempt) next FROM observer_queue WHERE status='pending'").get().next;}catch{this.#local.diskErrors++;break;}
    if(next===null)break;await this.#wait(Math.min(1000,Math.max(1,next-this.#now()),Math.max(1,maxDurationMs-(performance.now()-started))));continue;
   }
   sent++;const result=await this.#send(row);try{this.#finish(row,result);}catch{this.#local.diskErrors++;break;}
  }
  return this.stats();
 }
 drain({maxEvents=this.capacity*this.maxAttempts,maxDurationMs=30000}={}){
  bounded(maxEvents,1,100000);bounded(maxDurationMs,1,60000);if(this.#closed||this.#stopping)return Promise.resolve(this.stats());
  if(!this.#running)this.#running=this.#drain({maxEvents,maxDurationMs}).finally(()=>{this.#running=undefined;});return this.#running;
 }
 retryFailed({id}={}){
  if(this.#closed||this.#stopping)return {retried:0,outcome:'stopped'};if(id!==undefined)try{identifier(id);}catch{return {retried:0,outcome:'invalid_id'};}
  try{return this.#transaction(()=>{const parameters=[this.#now()],sql="UPDATE observer_queue SET status='pending',attempts=0,next_attempt=0,lease_owner=NULL,lease_until=NULL,updated=? WHERE status IN ('rejected','retry_exhausted')"+(id===undefined?'':' AND id=?');if(id!==undefined)parameters.push(id);const result=this.#db.prepare(sql).run(...parameters);this.#count('explicit_retries',Number(result.changes));return {retried:Number(result.changes),outcome:'queued'};});}catch{this.#local.diskErrors++;return {retried:0,outcome:'disk_error'};}
 }
 stats(){
  const states={pending:0,inflight:0,accepted:0,rejected:0,retry_exhausted:0};
  try{if(this.#closed)throw Error();for(const row of this.#db.prepare('SELECT status,COUNT(*) count FROM observer_queue GROUP BY status').all())states[row.status]=row.count;const totals=Object.fromEntries(this.#db.prepare('SELECT name,value FROM observer_metrics').all().map(row=>[row.name,row.value]));return {available:true,queue:states,totals,local:{...this.#local},capacity:this.capacity,maxAttempts:this.maxAttempts};}catch{return {available:false,queue:null,totals:null,local:{...this.#local},capacity:this.capacity,maxAttempts:this.maxAttempts};}
 }
 async stop(){this.#stopping=true;this.#wake?.();await this.#running;return this.stats();}
 async close(){if(this.#closed)return;await this.stop();try{this.#db.close();}catch{this.#local.diskErrors++;}this.#closed=true;}
}
