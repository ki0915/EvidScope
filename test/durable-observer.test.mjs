import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {spawnSync} from 'node:child_process';
import {DurableObserver,validateObservationEnvelope} from '../src/durable-observer.mjs';
import {observationEvent} from '../src/ai-observations.mjs';

const principal={id:'telemetry-source',tenant:'alpha',token:'CREDENTIAL-CANARY-TOKEN',hmacSecret:'CREDENTIAL-CANARY-HMAC'};
const url='https://collector.example.com',accepted={status:202,body:{accepted:true,duplicate:false}};
function workspace(t){mkdirSync('.test-runs',{recursive:true});return mkdtempSync(resolve('.test-runs/durable-observer-'));}
function event(id='event-1'){return observationEvent('sdk',{model:'test-model',provider:'openai'},{id,now:Date.parse('2026-09-12T00:00:00Z')});}
function observer(spoolPath,options={}){return new DurableObserver({spoolPath,url,principal,retryDelayMs:0,timeoutMs:50,...options});}

test('disk queue survives reopen; acknowledgement removes body and duplicate acknowledgement is idempotent',async t=>{
 const path=join(workspace(t),'events.sqlite');let first=observer(path,{submitEvent:async()=>accepted});assert.equal(first.enqueue(event()).queued,true);await first.close();
 let calls=0;const second=observer(path,{submitEvent:async(_url,_principal,payload,options)=>{calls++;assert.equal(payload.id,'event-1');assert.ok(options.nonce);return {...accepted,body:{accepted:true,duplicate:true}};}});t.after(()=>second.close());
 assert.equal(second.stats().queue.pending,1);await second.drain();assert.equal(second.stats().queue.accepted,1);assert.equal(second.stats().totals.duplicate_acks,1);
 assert.equal(second.enqueue(event()).outcome,'duplicate');await second.drain();assert.equal(calls,1);
 const db=new DatabaseSync(path);assert.equal(db.prepare('SELECT body FROM observer_queue').get().body,null);db.close();
});

test('retry uses same event ID and fresh nonce; 503 exhausts finite budget then requires explicit retry',async t=>{
 const path=join(workspace(t),'events.sqlite'),attempts=[];let healthy=false;
 const sender=observer(path,{maxAttempts:3,submitEvent:async(_url,_principal,payload,options)=>{attempts.push({id:payload.id,nonce:options.nonce});return healthy?accepted:{status:503,body:{error:'SECRET-RESPONSE-CANARY'}};}});t.after(()=>sender.close());
 sender.enqueue(event());await sender.drain();assert.equal(attempts.length,3);assert.equal(new Set(attempts.map(x=>x.nonce)).size,3);assert.deepEqual(new Set(attempts.map(x=>x.id)),new Set(['event-1']));assert.equal(sender.stats().queue.retry_exhausted,1);
 await sender.drain();assert.equal(attempts.length,3);healthy=true;assert.equal(sender.retryFailed({id:'event-1'}).retried,1);await sender.drain();assert.equal(attempts.length,4);assert.equal(sender.stats().queue.accepted,1);
 assert.ok(!JSON.stringify(sender.stats()).includes('SECRET'));assert.ok(!readFileSync(path).includes(Buffer.from('SECRET-RESPONSE-CANARY')));
});

test('permanent 400 is retained without automatic retries or loss',async t=>{
 const path=join(workspace(t),'events.sqlite');let attempts=0;const sender=observer(path,{submitEvent:async()=>{attempts++;return {status:400,body:{message:'PRIVATE-SERVER-ERROR'}};}});t.after(()=>sender.close());
 sender.enqueue(event());await sender.drain();await sender.drain();assert.equal(attempts,1);assert.equal(sender.stats().queue.rejected,1);
 const db=new DatabaseSync(path);assert.equal(JSON.parse(db.prepare('SELECT body FROM observer_queue').get().body).id,'event-1');db.close();
});

test('expired crash lease resumes at least once and preserves attempt budget',async t=>{
 const path=join(workspace(t),'events.sqlite');const first=observer(path);first.enqueue(event());await first.close();
 const db=new DatabaseSync(path);db.prepare("UPDATE observer_queue SET status='inflight',attempts=1,lease_until=1,lease_owner='crashed'").run();db.close();
 let attempts=0;const recovered=observer(path,{now:()=>1000,submitEvent:async()=>{attempts++;return {...accepted,body:{accepted:true,duplicate:true}};}});t.after(()=>recovered.close());await recovered.drain();assert.equal(attempts,1);assert.equal(recovered.stats().queue.accepted,1);
});

test('crash at retry limit retains failed metadata and cannot restart an infinite delivery loop',async t=>{
 const path=join(workspace(t),'events.sqlite');const first=observer(path);first.enqueue(event());await first.close();
 const db=new DatabaseSync(path);db.prepare("UPDATE observer_queue SET status='inflight',attempts=3,lease_until=1,lease_owner='crashed'").run();db.close();
 let attempts=0;const recovered=observer(path,{now:()=>1000,submitEvent:async()=>{attempts++;return accepted;}});t.after(()=>recovered.close());await recovered.drain();assert.equal(attempts,0);assert.equal(recovered.stats().queue.retry_exhausted,1);assert.equal(recovered.stats().totals.retry_exhausted,1);await recovered.drain();assert.equal(recovered.stats().totals.retry_exhausted,1);
});

test('queue bounds include failed records, accepted receipts stay finite, ID collision is rejected',async t=>{
 const path=join(workspace(t),'events.sqlite');const sender=observer(path,{capacity:2,submitEvent:async()=>accepted});t.after(()=>sender.close());
 assert.equal(sender.enqueue(event('a')).queued,true);assert.equal(sender.enqueue(event('b')).queued,true);assert.equal(sender.enqueue(event('c')).outcome,'queue_full');
 assert.equal(sender.enqueue({...event('a'),actionId:'changed'}).outcome,'id_conflict');await sender.drain();
 for(const id of ['c','d','e']){assert.equal(sender.enqueue(event(id)).queued,true);await sender.drain();}
 assert.equal(sender.stats().queue.accepted,2);assert.equal(sender.stats().totals.accepted,5);
});

test('raw fields and secret-bearing errors never enter spool or aggregate output',async t=>{
 const path=join(workspace(t),'events.sqlite'),canary='RAW-PROMPT-CANARY';const sender=observer(path,{submitEvent:async()=>{throw new Error(canary);}});t.after(()=>sender.close());
 for(const candidate of [{...event(),prompt:canary},{...event(),note:canary},{...event(),aiObservation:{...event().aiObservation,response:canary}},{...event(),headers:{authorization:canary}},{...event(),status:'success'}]){assert.throws(()=>validateObservationEnvelope(candidate));assert.equal(sender.enqueue(candidate).outcome,'invalid_event');}
 assert.equal(sender.stats().queue.pending,0);sender.enqueue(event());await sender.drain();assert.ok(!JSON.stringify(sender.stats()).includes(canary));
 for(const file of [path,path+'-wal']){let content;try{content=readFileSync(file);}catch{continue;}for(const secret of [canary,principal.token,principal.hmacSecret])assert.ok(!content.includes(Buffer.from(secret)));}
});

test('spool is bound to source identity and credentials may rotate without being stored',async t=>{
 const path=join(workspace(t),'events.sqlite');const first=observer(path);first.enqueue(event());await first.close();
 assert.throws(()=>observer(path,{principal:{...principal,id:'other-source'}}),error=>error.code==='spool_source_mismatch');
 const second=observer(path,{principal:{...principal,token:'rotated',hmacSecret:'rotated-secret'}});assert.equal(second.stats().queue.pending,1);await second.close();
});

test('disk unavailable and disk write failure report fixed outcomes, not paths or raw exceptions',async t=>{
 const directory=workspace(t),path=join(directory,'events.sqlite');assert.throws(()=>observer(directory),error=>error.code==='observer_spool_unavailable');
 assert.throws(()=>observer(':memory:'),error=>error.code==='invalid_observer_configuration');
 const sender=observer(path);t.after(()=>sender.close());const db=new DatabaseSync(path);db.exec("CREATE TRIGGER simulated_disk_failure BEFORE INSERT ON observer_queue BEGIN SELECT RAISE(ABORT,'SECRET-DISK-ERROR'); END;");db.close();
 assert.deepEqual(sender.enqueue(event()),{queued:false,outcome:'disk_error'});assert.equal(sender.stats().local.diskErrors,1);assert.ok(!JSON.stringify(sender.stats()).includes('SECRET'));
});

test('shutdown waits only bounded in-flight attempt and starts no following record',async t=>{
 const path=join(workspace(t),'events.sqlite');let calls=0,started;const began=new Promise(resolve=>{started=resolve;});
 const sender=observer(path,{timeoutMs:30,submitEvent:async()=>{calls++;started();await new Promise(()=>{});}});sender.enqueue(event('a'));sender.enqueue(event('b'));const draining=sender.drain();await began;
 const before=performance.now();await sender.stop();assert.ok(performance.now()-before<1000);await draining;assert.equal(calls,1);assert.equal(sender.stats().queue.pending,2);await sender.close();
});

test('pending retry delay is bounded and stop wakes a sender waiting for its next attempt',async t=>{
 const path=join(workspace(t),'events.sqlite');let started;const began=new Promise(resolve=>{started=resolve;});
 const sender=observer(path,{retryDelayMs:1000,submitEvent:async()=>{started();return {status:503,body:{}};}});sender.enqueue(event());const draining=sender.drain();await began;await new Promise(resolve=>setTimeout(resolve,10));const before=performance.now();await sender.stop();assert.ok(performance.now()-before<500);await draining;assert.equal(sender.stats().queue.pending,1);await sender.close();
});

test('CLI rejects unsanitized records and prints aggregate-only errors without credentials',t=>{
 const directory=workspace(t),configPath=join(directory,'source.json'),spoolPath=join(directory,'events.sqlite');writeFileSync(configPath,JSON.stringify({url,principal}));
 const result=spawnSync(process.execPath,['scripts/send-ai-observations.mjs','--source-config',configPath,'--spool',spoolPath],{input:JSON.stringify({...event(),prompt:'RAW-CLI-CANARY'}),encoding:'utf8'});
 assert.equal(result.status,1);const metrics=JSON.parse(result.stdout.trim());assert.equal(metrics.invalid,1);assert.equal(metrics.queue.pending,0);assert.ok(!result.stdout.includes('CANARY'));assert.ok(!result.stderr.includes('CANARY'));
});
