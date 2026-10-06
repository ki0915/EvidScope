import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {generateKeyPairSync} from 'node:crypto';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve,sep} from 'node:path';
import {checkEventProjection} from '../src/event-integrity.mjs';
import {createService} from '../src/service.mjs';

const event={tenant:'alpha',source:'alpha-tool',sourceKind:'tool',id:'event-one',kind:'result',actionId:'work',traceId:'trace-one',occurredAt:'2026-09-29T00:00:00.000Z',receivedAt:'2026-09-29T00:00:01.000Z',fingerprint:'fingerprint-one',status:'success',seq:1,hash:'a'.repeat(64)};

function projection(){
 const db=new DatabaseSync(':memory:');db.exec('CREATE TABLE events(tenant TEXT,source TEXT,id TEXT,fingerprint TEXT,action_id TEXT,trace_id TEXT,kind TEXT,received TEXT,body TEXT,PRIMARY KEY(tenant,source,id))');
 db.prepare('INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)').run(event.tenant,event.source,event.id,event.fingerprint,event.actionId,event.traceId,event.kind,event.receivedAt,JSON.stringify(event));return db;
}

test('event projection compares every SQL index column and the signed body by identity',async t=>{
 const valid=projection();try{assert.deepEqual(checkEventProjection(valid,'alpha',[event]),{valid:true,retainedEvents:1,eventIndexes:1});}finally{valid.close();}
 const changes={tenant:'beta',source:'other-source',id:'other-id',fingerprint:'other-fingerprint',action_id:'other-action',trace_id:'other-trace',kind:'execution',received:'2026-09-29T00:00:02.000Z'};
 for(const [column,value] of Object.entries(changes))await t.test(column,()=>{const db=projection();try{db.prepare(`UPDATE events SET ${column}=?`).run(value);assert.throws(()=>checkEventProjection(db,'alpha',[event]),/Event projection differs/);}finally{db.close();}});
 await t.test('body',()=>{const db=projection();try{db.prepare('UPDATE events SET body=?').run(JSON.stringify({...event,status:'failure'}));assert.throws(()=>checkEventProjection(db,'alpha',[event]),/Event projection differs/);}finally{db.close();}});
 await t.test('missing',()=>{const db=projection();try{db.exec('DELETE FROM events');assert.throws(()=>checkEventProjection(db,'alpha',[event]),/Event projection differs/);}finally{db.close();}});
 await t.test('extra',()=>{const db=projection();try{const extra={...event,id:'event-two',fingerprint:'fingerprint-two'};db.prepare('INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)').run(extra.tenant,extra.source,extra.id,extra.fingerprint,extra.actionId,extra.traceId,extra.kind,extra.receivedAt,JSON.stringify(extra));assert.throws(()=>checkEventProjection(db,'alpha',[event]),/Event projection differs/);}finally{db.close();}});
});

function fixture(t){
 const dir=mkdtempSync(join(tmpdir(),'evidscope-event-index-')),principals=[];
 for(const tenant of ['alpha','beta'])principals.push(
  {id:tenant+'-auditor',role:'auditor',tenant,token:(tenant+'a').repeat(20)},
  {id:tenant+'-admin',role:'admin',tenant,token:(tenant+'m').repeat(20)},
  {id:tenant+'-worker',role:'worker',tenant,token:(tenant+'w').repeat(20)});
 const service=createService({dataDir:dir,key:generateKeyPairSync('ed25519').privateKey,config:{principals}}),store=service.store;
 t.after(()=>{store.close();assert.ok(resolve(dir).startsWith(resolve(tmpdir())+sep));rmSync(dir,{recursive:true,force:true});});
 for(const tenant of ['alpha','beta'])store.transaction(()=>{
  const {seq:unusedSeq,hash:unusedHash,...baseEvent}=event,current={...baseEvent,tenant,source:tenant+'-tool',id:tenant+'-event',fingerprint:tenant+'-fingerprint'};
  const record=store.append(tenant,'event',current,current.source);store.project({...current,seq:record.seq,hash:record.hash});
  store.db.prepare('INSERT INTO actions VALUES(?,?,?,?)').run(tenant,'work',1,1);
  const evaluation={id:tenant+'-evaluation',actionId:'work',version:1,status:'evaluated',authority:'not_observed',effect:'independently_reported_success',findings:[],coverage:{totalFindings:0,returnedFindings:0,truncated:false},createdAt:'2026-09-29T00:00:02.000Z'};
  store.append(tenant,'evaluation',evaluation,tenant+'-worker');store.db.prepare('INSERT INTO evaluations(tenant,action_id,version,body) VALUES(?,?,?,?)').run(tenant,'work',1,JSON.stringify(evaluation));
 });
 const call=(path,{tenant='alpha',role='auditor',method='GET',body}={})=>service.handle(method,new URL(path,'http://local'),{authorization:'Bearer '+principals.find(p=>p.tenant===tenant&&p.role===role).token},body===undefined?'':JSON.stringify(body));
 return {dir,service,store,call};
}

test('unsigned action_id reassignment cannot change online correlation, metrics, or signed integrity',async t=>{
 const h=fixture(t);assert.equal((await h.call('/api/actions/work')).events.length,1);assert.equal((await h.call('/api/metrics')).analyzedEvents,1);
 h.store.db.prepare("UPDATE events SET action_id='other' WHERE tenant='alpha'").run();
 for(const path of ['/api/events','/api/overview','/api/monitoring','/api/ai-visibility','/api/agents','/api/actions/work','/api/metrics','/api/investigations'])await assert.rejects(h.call(path),error=>error.status===409,path);
 await assert.rejects(h.call('/api/cases',{method:'POST',body:{title:'Forged correlation',actionId:'other',owner:'auditor'}}),error=>error.status===409);
 const integrity=await h.call('/api/integrity');assert.equal(integrity.valid,false);assert.match(integrity.error,/Event projection/);assert.ok(integrity.verificationScope.checks.includes('event_indexes'));assert.ok(!integrity.verificationScope.notChecked.includes('event_indexes'));
 assert.equal((await h.call('/api/integrity',{tenant:'beta'})).valid,true,'other tenant remains independently valid');
 await h.call('/api/rebuild',{role:'admin',method:'POST',body:{}});const repaired=await h.call('/api/integrity');assert.equal(repaired.valid,true);assert.equal((await h.call('/api/actions/work')).events.length,1);
});

test('event verification and indexed response share one writer-excluding snapshot',async t=>{
 const h=fixture(t),other=new DatabaseSync(join(h.dir,'evidence.db'),{timeout:0}),original=h.store.checkProjection.bind(h.store);let attempted=false,changed=false,blocked;
 try{
  h.store.checkProjection=(...args)=>{const result=original(...args);if(!attempted){attempted=true;try{other.prepare("UPDATE events SET trace_id='changed' WHERE tenant='alpha'").run();changed=true;}catch(error){blocked=error;}}return result;};
  const result=await h.call('/api/events');assert.equal(result.items.length,1);assert.equal(attempted,true);assert.equal(changed,false);assert.equal(blocked?.errcode,5);assert.match(blocked?.message||'',/locked|busy/i);
 }finally{other.close();}
});
