import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {generateKeyPairSync} from 'node:crypto';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve,sep} from 'node:path';
import {mac} from '../src/crypto.mjs';
import {checkDevelopmentRunProjection} from '../src/development-integrity.mjs';
import {createService} from '../src/service.mjs';

const event={tenant:'alpha',source:'alpha-tool',sourceKind:'tool',sourceEvidence:'external_tool_log',eventId:'event-one',runId:'run-one',teamId:'team-one',roleId:'role-one',parentRunId:null,parentEventId:null,streamSequence:null,timeBasis:'source_observed',model:'unknown',modelEvidence:'unknown',occurredAt:'2026-09-29T00:00:00.000Z',receivedAt:'2026-09-29T00:00:01.000Z',fingerprint:'fingerprint-one',eventName:'run.started',status:'running',toolName:'unknown',usage:null,artifacts:[],late:false};

function projection(){const db=new DatabaseSync(':memory:');db.exec('CREATE TABLE development_run_events(tenant TEXT,source TEXT,event_id TEXT,run_id TEXT,occurred TEXT,received TEXT,fingerprint TEXT,body TEXT,PRIMARY KEY(tenant,source,event_id))');db.prepare('INSERT INTO development_run_events VALUES(?,?,?,?,?,?,?,?)').run(event.tenant,event.source,event.eventId,event.runId,event.occurredAt,event.receivedAt,event.fingerprint,JSON.stringify(event));return db;}

test('development projection compares body and every query index by source event identity',async t=>{
 const valid=projection();try{assert.deepEqual(checkDevelopmentRunProjection(valid,'alpha',[event]),{valid:true,developmentEvents:1});}finally{valid.close();}
 for(const [column,value] of Object.entries({tenant:'beta',source:'other-source',event_id:'other-event',run_id:'other-run',occurred:'2026-09-29T00:00:02.000Z',received:'2026-09-29T00:00:03.000Z',fingerprint:'other-fingerprint'}))await t.test(column,()=>{const db=projection();try{db.prepare(`UPDATE development_run_events SET ${column}=?`).run(value);assert.throws(()=>checkDevelopmentRunProjection(db,'alpha',[event]),/Development projection/);}finally{db.close();}});
 await t.test('body',()=>{const db=projection();try{db.prepare('UPDATE development_run_events SET body=?').run(JSON.stringify({...event,status:'completed'}));assert.throws(()=>checkDevelopmentRunProjection(db,'alpha',[event]),/Development projection/);}finally{db.close();}});
 await t.test('missing',()=>{const db=projection();try{db.exec('DELETE FROM development_run_events');assert.throws(()=>checkDevelopmentRunProjection(db,'alpha',[event]),/Development projection/);}finally{db.close();}});
 await t.test('extra',()=>{const db=projection();try{const extra={...event,eventId:'event-two',fingerprint:'fingerprint-two'};db.prepare('INSERT INTO development_run_events VALUES(?,?,?,?,?,?,?,?)').run(extra.tenant,extra.source,extra.eventId,extra.runId,extra.occurredAt,extra.receivedAt,extra.fingerprint,JSON.stringify(extra));assert.throws(()=>checkDevelopmentRunProjection(db,'alpha',[event]),/Development projection/);}finally{db.close();}});
});

function fixture(t){
 const dir=mkdtempSync(join(tmpdir(),'evidscope-development-projection-')),principals=[];
 for(const tenant of ['alpha','beta'])principals.push(
  {id:tenant+'-auditor',role:'auditor',tenant,token:(tenant+'a').repeat(20)},
  {id:tenant+'-admin',role:'admin',tenant,token:(tenant+'m').repeat(20)},
  {id:tenant+'-tool',role:'source',kind:'tool',tenant,token:(tenant+'t').repeat(20),hmacSecret:(tenant+'h').repeat(20)});
 const service=createService({dataDir:dir,key:generateKeyPairSync('ed25519').privateKey,config:{principals}}),store=service.store;
 t.after(()=>{store.close();assert.ok(resolve(dir).startsWith(resolve(tmpdir())+sep));rmSync(dir,{recursive:true,force:true});});
 for(const tenant of ['alpha','beta'])store.transaction(()=>{const value={...event,tenant,source:tenant+'-tool',eventId:tenant+'-event',fingerprint:tenant+'-fingerprint'};store.append(tenant,'development_run_event',value,value.source);store.db.prepare('INSERT INTO development_run_events VALUES(?,?,?,?,?,?,?,?)').run(value.tenant,value.source,value.eventId,value.runId,value.occurredAt,value.receivedAt,value.fingerprint,JSON.stringify(value));});
 const call=(path,{tenant='alpha',role='auditor',method='GET',body='',headers={}}={})=>service.handle(method,new URL(path,'http://local'),{authorization:'Bearer '+principals.find(p=>p.tenant===tenant&&p.role===role).token,...headers},body);
 return {dir,service,store,principals,call};
}

test('unsigned run reassignment cannot alter development views or admit new signed history',async t=>{
 const h=fixture(t);assert.equal((await h.call('/api/development-runs')).items[0].runId,'run-one');h.store.db.prepare("UPDATE development_run_events SET run_id='forged-run' WHERE tenant='alpha'").run();
 await assert.rejects(h.call('/api/development-runs'),error=>error.status===409);
 const source=h.principals.find(p=>p.tenant==='alpha'&&p.role==='source'),raw={eventId:'new-event',eventName:'run.completed',runId:'run-one',teamId:'team-one',roleId:'role-one',status:'completed',occurredAt:new Date().toISOString(),toolName:'unknown'},body=JSON.stringify(raw),timestamp=String(Date.now()),nonce='development-nonce-0001';
 await assert.rejects(h.call('/api/development-runs/events',{role:'source',method:'POST',body,headers:{'x-evid-timestamp':timestamp,'x-evid-nonce':nonce,'x-evid-signature':mac(source.hmacSecret,timestamp,nonce,body)}}),error=>error.status===409);
 const integrity=await h.call('/api/integrity');assert.equal(integrity.valid,false);assert.match(integrity.error,/Development projection/);assert.ok(integrity.verificationScope.checks.includes('development_run_projections'));assert.deepEqual(integrity.verificationScope.notChecked,[]);
 assert.equal((await h.call('/api/integrity',{tenant:'beta'})).valid,true);
 const rebuilt=await h.call('/api/rebuild',{role:'admin',method:'POST',body:'{}'});assert.equal(rebuilt.developmentEvents,1);assert.equal((await h.call('/api/development-runs')).items[0].runId,'run-one');assert.equal((await h.call('/api/integrity')).valid,true);
});

test('development verification and query share one writer-excluding snapshot',async t=>{
 const h=fixture(t),other=new DatabaseSync(join(h.dir,'evidence.db'),{timeout:0}),original=h.store.checkDevelopmentRunProjection.bind(h.store);let attempted=false,changed=false,blocked;
 try{h.store.checkDevelopmentRunProjection=(...args)=>{const result=original(...args);if(!attempted){attempted=true;try{other.prepare("UPDATE development_run_events SET run_id='changed' WHERE tenant='alpha'").run();changed=true;}catch(error){blocked=error;}}return result;};const result=await h.call('/api/development-runs');assert.equal(result.items.length,1);assert.equal(attempted,true);assert.equal(changed,false);assert.equal(blocked?.errcode,5);assert.match(blocked?.message||'',/locked|busy/i);}finally{other.close();}
});
