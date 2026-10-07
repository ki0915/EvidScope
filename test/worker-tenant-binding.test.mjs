import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {mkdirSync,mkdtempSync} from 'node:fs';
import {resolve} from 'node:path';
import {Store} from '../src/store.mjs';
import {createAnalysis,workerTenantScopes} from '../src/analysis.mjs';
import {evaluateJob} from '../src/worker.mjs';
import {createService} from '../src/service.mjs';

// Regression tests for adversarial-audit finding S6: workers are bound to tenants, the vault signs only results equal to
// its own deterministic recomputation, and a pending exception never suppresses a finding.
const workers=[
 {id:'alpha-worker',tenant:'alpha',role:'worker'},
 {id:'beta-worker',tenant:'internal',role:'worker',tenants:['beta']},
 {id:'legacy-worker',tenant:'internal',role:'worker'},
];
function fixture(t,principals=workers){
 mkdirSync('.test-runs',{recursive:true});const dir=mkdtempSync(resolve('.test-runs','worker-binding-'));
 const key=generateKeyPairSync('ed25519').privateKey,store=new Store(dir,key);t.after(()=>store.close());
 const analysis=createAnalysis(store,principals),worker=id=>principals.find(p=>p.id===id);
 const event=(tenant,actionId,id=actionId+'-event')=>store.transaction(()=>{
  const at=new Date().toISOString();
  const e={id,actionId,traceId:'trace',tenant,source:'tool-source',sourceKind:'tool',kind:'result',status:'success',occurredAt:at,receivedAt:at,fingerprint:id};
  const record=store.append(tenant,'event',e,e.source);store.project({...e,seq:record.seq,hash:record.hash});
  store.db.prepare('INSERT INTO actions(tenant,id,version) VALUES(?,?,1) ON CONFLICT(tenant,id) DO UPDATE SET version=version+1').run(tenant,actionId);
 });
 // An approval re-opens every action of the tenant for analysis, as the service's exception approval does.
 const exception=(tenant,body)=>store.transaction(()=>{store.put({id:body.approvedBy||body.author,tenant},'exception',body.id,body);
  if(body.status==='approved')store.projectionMutation(()=>store.db.prepare('UPDATE actions SET version=version+1 WHERE tenant=?').run(tenant));});
 return {store,analysis,worker,event,exception,dir,key};
}
const lease=(store,id)=>store.db.prepare('SELECT * FROM analysis_leases WHERE id=?').get(id);

test('S6: a worker claims, counts and commits only its bound tenants',t=>{
 const f=fixture(t);f.event('alpha','alpha-action');f.event('beta','beta-action');
 const alpha=f.analysis.claim(f.worker('alpha-worker'));
 assert.deepEqual(alpha.jobs.map(job=>job.tenant),['alpha']);assert.equal(alpha.backlog,1,'backlog of bound tenants only');
 const beta=f.analysis.claim(f.worker('beta-worker'));assert.deepEqual(beta.jobs.map(job=>job.tenant),['beta']);
 assert.equal(f.analysis.claim(f.worker('legacy-worker')).jobs.length,0,'both actions are leased already');
 // A lease issued before the binding changed cannot be committed for a tenant outside the new binding.
 const rebound=createAnalysis(f.store,[{id:'alpha-worker',tenant:'alpha',role:'worker',tenants:['beta']}]);
 const job=alpha.jobs[0];
 assert.throws(()=>rebound.commit(f.worker('alpha-worker'),{leaseId:job.leaseId,result:evaluateJob(job)}),error=>error.status===403);
 assert.equal(f.analysis.commit(f.worker('alpha-worker'),{leaseId:job.leaseId,result:evaluateJob(job)}).duplicate,false);
});

test('S6: the legacy internal worker keeps serving every tenant in the synthetic-local profile',t=>{
 const f=fixture(t,[workers[2]]);f.event('alpha','alpha-action');f.event('beta','beta-action');
 const claimed=f.analysis.claim(f.worker('legacy-worker'));assert.deepEqual(claimed.jobs.map(job=>job.tenant).sort(),['alpha','beta']);
 for(const job of claimed.jobs)assert.equal(f.analysis.commit(f.worker('legacy-worker'),{leaseId:job.leaseId,result:evaluateJob(job)}).duplicate,false);
});

test('S6: results that differ from the vault recomputation are rejected and the action is claimable again',t=>{
 const f=fixture(t),p=f.worker('alpha-worker');f.event('alpha','forged-action');
 const job=f.analysis.claim(p).jobs[0],honest=evaluateJob(job);assert.ok(honest.findings.length>0);
 const forged=[
  {...honest,findings:[],coverage:{totalFindings:0,returnedFindings:0,truncated:false}},
  {...honest,authority:'matched_at_event_time'},
  {...honest,findings:honest.findings.map(finding=>({...finding,severity:'low'}))},
 ];
 for(const result of forged){
  // The first forgery uses the original lease; each rejection frees the action for a new claim.
  const current=f.analysis.claim(p).jobs[0]||job;
  assert.throws(()=>f.analysis.commit(p,{leaseId:current.leaseId,result}),error=>error.status===422);
  assert.equal(lease(f.store,current.leaseId).state,'rejected');
  assert.equal(f.store.evaluations('alpha','forged-action').length,0);
  assert.throws(()=>f.analysis.commit(p,{leaseId:current.leaseId,result:evaluateJob(current)}),error=>error.status===409,'a rejected lease is closed');
 }
 const retry=f.analysis.claim(p).jobs[0];assert.equal(retry.actionId,'forged-action');
 const accepted=f.analysis.commit(p,{leaseId:retry.leaseId,result:evaluateJob(retry)});assert.equal(accepted.duplicate,false);
 const [evaluation]=f.store.evaluations('alpha','forged-action');assert.equal(evaluation.findings.length,honest.findings.length);
});

test('S6: a pending exception never suppresses; an approved one for the action and rule does',t=>{
 const f=fixture(t),p=f.worker('alpha-worker'),expiresAt=new Date(Date.now()+86400000).toISOString();
 const pending={id:'requested-exception',ruleId:'AUTHORITY_MISSING',actionId:'excepted',reason:'auditor request',owner:'owner',expiresAt,
  status:'pending',author:'alpha-auditor'};
 f.exception('alpha',pending);f.event('alpha','excepted');
 const job=f.analysis.claim(p).jobs[0],honest=evaluateJob(job);
 const index=honest.findings.findIndex(finding=>finding.code==='AUTHORITY_MISSING');assert.ok(index>=0);
 assert.equal(honest.findings[index].suppressedBy,undefined,'evaluate() ignores pending exceptions');
 const forged=structuredClone(honest);forged.findings[index].suppressedBy=pending.id;
 assert.throws(()=>f.analysis.commit(p,{leaseId:job.leaseId,result:forged}),error=>error.status===400&&/승인되지 않았거나/.test(error.message));
 assert.equal(f.store.evaluations('alpha','excepted').length,0);
 // Once a reviewer approves it, evaluate() itself applies it, so the honest result carries it and is accepted.
 f.exception('alpha',{...pending,status:'approved',approvedBy:'alpha-reviewer'});
 const next=f.analysis.claim(p).jobs[0],approved=evaluateJob(next);
 assert.equal(approved.findings.find(finding=>finding.code==='AUTHORITY_MISSING').suppressedBy,pending.id);
 assert.equal(f.analysis.commit(p,{leaseId:next.leaseId,result:approved}).duplicate,false);
});

test('S6: worker tenant bindings are validated; enterprise refuses an unbound worker',t=>{
 const legacy={id:'w',tenant:'internal',role:'worker',token:'w'.repeat(40)};
 assert.equal(workerTenantScopes([legacy]).get('w'),null);
 assert.deepEqual([...workerTenantScopes([{...legacy,tenants:['alpha','beta']}],'enterprise').get('w')],['alpha','beta']);
 assert.deepEqual([...workerTenantScopes([{...legacy,tenant:'alpha'}],'enterprise').get('w')],['alpha']);
 assert.throws(()=>workerTenantScopes([legacy],'enterprise'),/list its tenants/);
 for(const tenants of [[],['alpha','alpha'],['bad tenant'],'alpha',[1]])
  assert.throws(()=>workerTenantScopes([{...legacy,tenants}]),/Invalid worker tenant binding/);
 assert.throws(()=>workerTenantScopes([{id:'r',tenant:'alpha',role:'reviewer',tenants:['beta']}]),/Only worker principals/);
 mkdirSync('.test-runs',{recursive:true});const dir=mkdtempSync(resolve('.test-runs','worker-binding-service-'));
 const config={profile:'enterprise',principals:[legacy]};
 assert.throws(()=>createService({dataDir:dir,key:generateKeyPairSync('ed25519').privateKey,config}),/list its tenants/);
});
