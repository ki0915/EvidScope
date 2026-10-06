import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {generateKeyPairSync} from 'node:crypto';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve,sep} from 'node:path';
import {createService} from '../src/service.mjs';

function fixture(t){
 const dir=mkdtempSync(join(tmpdir(),'evidscope-action-projection-')),principals=[];
 for(const tenant of ['alpha','beta'])principals.push(
  {id:tenant+'-auditor',role:'auditor',tenant,token:(tenant+'a').repeat(20)},
  {id:tenant+'-agent',role:'source',kind:'agent',tenant,token:(tenant+'g').repeat(20),hmacSecret:(tenant+'h').repeat(20)},
  {id:tenant+'-tool',role:'source',kind:'tool',tenant,token:(tenant+'t').repeat(20),hmacSecret:(tenant+'s').repeat(20)},
  {id:tenant+'-worker',role:'worker',tenant,token:(tenant+'w').repeat(20)},
 );
 const service=createService({dataDir:dir,key:generateKeyPairSync('ed25519').privateKey,config:{principals}}),store=service.store;
 t.after(()=>{store.close();assert.ok(resolve(dir).startsWith(resolve(tmpdir())+sep));rmSync(dir,{recursive:true,force:true});});
 const call=(path,tenant='alpha')=>service.handle('GET',new URL(path,'http://local'),{authorization:'Bearer '+principals.find(p=>p.tenant===tenant&&p.role==='auditor').token});
 for(const tenant of ['alpha','beta'])store.transaction(()=>{
  const policy={id:'policy',actor:'credit-agent',tool:'credit-tool',owner:'owner',policyVersion:'p1',approvalRequired:false,validFrom:'2026-01-01T00:00:00.000Z',destinations:['internal']};store.put({id:'reviewer',tenant},'asset',policy.id,policy);
  for(const [source,sourceKind,kind,id] of [[tenant+'-agent','agent','intent','intent'],[tenant+'-tool','tool','execution','execution']]){
   const event={tenant,source,sourceKind,kind,id,actionId:'work',traceId:'trace',actor:'credit-agent',tool:'credit-tool',action:'score',resource:'application',destination:'internal',policyVersion:'p1',occurredAt:'2026-09-29T00:00:00.000Z',receivedAt:'2026-09-29T00:00:00.000Z',fingerprint:id};
   const record=store.append(tenant,'event',event,source);store.project({...event,seq:record.seq,hash:record.hash});store.db.prepare('INSERT INTO actions(tenant,id,version) VALUES(?,?,1) ON CONFLICT(tenant,id) DO UPDATE SET version=version+1').run(tenant,event.actionId);
  }
  const evaluation={id:tenant+'-evaluation',actionId:'work',version:2,status:'evaluated',authority:'matched_at_event_time',effect:'unconfirmed',findings:[],coverage:{totalFindings:0,returnedFindings:0,truncated:false},createdAt:'2026-09-29T00:00:01.000Z'};
  store.append(tenant,'evaluation',evaluation,tenant+'-worker');store.db.prepare('INSERT INTO evaluations(tenant,action_id,version,body) VALUES(?,?,?,?)').run(tenant,'work',2,JSON.stringify(evaluation));store.db.prepare('UPDATE actions SET analyzed=2 WHERE tenant=? AND id=?').run(tenant,'work');
  const late={tenant,source:tenant+'-tool',sourceKind:'tool',kind:'result',id:'late-result',actionId:'work',traceId:'trace',actor:'credit-agent',tool:'credit-tool',action:'score',resource:'application',destination:'internal',policyVersion:'p1',occurredAt:'2026-09-29T00:00:02.000Z',receivedAt:'2026-09-29T00:00:02.000Z',fingerprint:'late-result'},lateRecord=store.append(tenant,'event',late,late.source);store.project({...late,seq:lateRecord.seq,hash:lateRecord.hash});store.db.prepare('UPDATE actions SET version=version+1 WHERE tenant=? AND id=?').run(tenant,'work');
  store.put({id:'reviewer',tenant},'case','case-work',{id:'case-work',title:'Action projection review',actionId:'work',owner:'owner',status:'open',comments:[],tasks:[],history:[]});
 });
 return {dir,service,store,principals,call};
}

test('unsigned action state cannot erase backlog, mint compliance, or enter a signed review report',async t=>{
 const h=fixture(t),agent=(await h.call('/api/agents?id='+encodeURIComponent((await h.call('/api/agents')).items[0].id))).item;
 assert.equal(agent.counts.pending,1);assert.equal(agent.counts.compliant,0);assert.equal((await h.call('/api/actions/work')).analysis.pending,true);
 h.store.db.prepare("UPDATE actions SET version=2,analyzed=2 WHERE tenant='alpha' AND id='work'").run();
 for(const path of ['/api/overview','/api/actions/work','/api/metrics','/api/agents','/api/cases/case-work/review-context','/api/cases/case-work/report'])await assert.rejects(h.call(path),error=>error.status===409&&/행동 상태/.test(error.message),path);
 const worker=h.principals.find(p=>p.tenant==='alpha'&&p.role==='worker');assert.throws(()=>h.service.analysis.claim(worker),error=>error.status===409&&/행동 상태/.test(error.message));
 const integrity=await h.call('/api/integrity');assert.equal(integrity.valid,false);assert.match(integrity.error,/Action projection/);assert.ok(integrity.verificationScope.checks.includes('action_projections'));assert.ok(!integrity.verificationScope.notChecked.includes('action_projections'));
 const beta=await h.call('/api/integrity','beta');assert.equal(beta.valid,true);assert.deepEqual(beta.actionProjection,{valid:true,actions:1});
});

test('action verification and response share one writer-excluding snapshot',async t=>{
 const h=fixture(t),other=new DatabaseSync(join(h.dir,'evidence.db'),{timeout:0}),original=h.store.checkActionProjection.bind(h.store);let attempted=false,changed=false,blocked;
 try{
  h.store.checkActionProjection=(...args)=>{const result=original(...args);if(!attempted){attempted=true;try{other.prepare("UPDATE actions SET version=2 WHERE tenant='alpha' AND id='work'").run();changed=true;}catch(error){blocked=error;}}return result;};
  const result=await h.call('/api/actions/work');assert.equal(result.analysis.pending,true);assert.equal(attempted,true);assert.equal(changed,false);assert.equal(blocked?.errcode,5);assert.match(blocked?.message||'',/locked|busy/i);
 }finally{other.close();}
});
