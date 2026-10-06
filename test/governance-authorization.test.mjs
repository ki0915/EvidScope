import test from 'node:test';
import assert from 'node:assert/strict';
import {writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {harness} from './harness.mjs';

test('governance reviewer boundary rejects auditor mutation before signed state changes across gateways and restart',async t=>{
 const h=await harness();t.after(()=>h.close());
 let step='register_system';
 const describeError=error=>error&&Object.fromEntries(['name','message','stack','code','errno','syscall','address','port'].filter(key=>error[key]!==undefined).map(key=>[key,error[key]]).concat(error.cause?[['cause',describeError(error.cause)]]:[]));
 const diagnose=(error,request)=>{
  const processes=Object.fromEntries(['audit','ingress','vault'].map(name=>{const process=h[name];return [name,{url:process.url,pid:process.child.pid,exitCode:process.child.exitCode,signalCode:process.child.signalCode,killed:process.child.killed,connected:process.child.connected,logs:process.logs().slice(-8192)}];}));
  const diagnostic={fixture:h.dir,step,request,error:describeError(error),processes};
  try{writeFileSync(join(h.dir,'governance-authorization-failure.json'),JSON.stringify(diagnostic,null,2)+'\n');}catch(writeError){diagnostic.diagnosticWriteError=describeError(writeError);}
  error.message+='\nGovernance authorization diagnostic: '+JSON.stringify(diagnostic);
 };
 // Preserve the original failure and cause. Diagnostic capture never retries a mutation.
 const originalApi=h.api;
 h.api=async(path,options={})=>{try{return await originalApi(path,options);}catch(error){diagnose(error,{path,base:options.base||h.audit.url,role:options.role||'auditor',tenant:options.tenant||'alpha',method:options.body===undefined?'GET':'POST'});throw error;}};
 const system={id:'authorization-credit',name:'합성 권한 검증',owner:'검토팀',purpose:'합성 대출 검토',markets:['KR'],krRoles:[],aiBusinessOperator:false};
 assert.equal((await h.api('/api/governance/systems',{role:'reviewer',body:system})).status,200);
 step='read_requirement';
 const requirement=(await h.api('/api/governance')).body.requirements.find(r=>r.id==='KR-34-RISK');
 const assessment={systemId:system.id,requirementId:requirement.id,applicability:'unknown',assessment:'unknown',legalReview:'pending',evidence:[],control:'합성 검토',owner:'검토팀',reason:'검토되지 않은 사실은 미확인으로 유지',nextReviewAt:'2099-01-01T00:00:00.000Z'};
 step='initial_assessment';const saved=await h.api('/api/governance/assessments',{role:'reviewer',body:assessment});assert.equal(saved.status,200);
 const requests=[['/api/governance/systems',{...system,owner:'unauthorized'}],['/api/governance/systems',{...system,id:'unauthorized-new'}],['/api/governance/assessments',{...assessment,legalReview:'reviewed'}],['/api/governance/tasks/'+saved.body.id,{status:'open',reason:'unauthorized'}],['/api/governance/tasks/'+saved.body.id,{status:'closed',reason:'unauthorized'}]];
 const signedState=async()=>((await h.api('/api/export')).body.records).filter(r=>['system','assessment','governance_task'].includes(r.type));
 step='capture_before';const before=await signedState();
 for(const base of [h.audit.url,h.vault.url])for(const role of ['auditor','agent','worker'])for(const [path,body]of requests){
  step='reject_unauthorized_mutation';
  const headers=role==='worker'?{authorization:'Bearer '+h.config.principals.find(p=>p.role==='worker').token}:{};
  assert.equal((await h.api(path,{base,role,body,headers})).status,403,`${role} ${path}`);
 }
 step='compare_before';assert.deepEqual(await signedState(),before);
 for(const role of ['reviewer','admin']){
  step='authorized_system';
  const changed=await h.api('/api/governance/systems',{role,body:{...system,owner:role}});assert.equal(changed.status,200);
  step='authorized_assessment';const reviewed=await h.api('/api/governance/assessments',{role,body:assessment});assert.equal(reviewed.status,200);assert.equal(reviewed.body.reviewer,h.principal(role).id);
  step='authorized_task';const task=await h.api('/api/governance/tasks/'+reviewed.body.id,{role,body:{status:'open',reason:'권한 있는 보완 작업'}});assert.equal(task.status,200);assert.equal(task.body.reviewedBy,h.principal(role).id);
 }
 step='closure_without_evidence';assert.equal((await h.api('/api/governance/tasks/'+saved.body.id,{role:'reviewer',body:{status:'closed',reason:'근거 부족'}})).status,409);
 step='capture_final';const final=await signedState();
 assert.ok(final.every(r=>['alpha-reviewer','alpha-admin'].includes(r.principal)));
 step='restart_vault';try{await h.restart();}catch(error){diagnose(error,{operation:'restart_vault'});throw error;}
 step='post_restart_export';assert.deepEqual(await signedState(),final);
 step='post_restart_auditor_denial';
 assert.equal((await h.api('/api/governance/tasks/'+saved.body.id,{body:{status:'open',reason:'재시작 후 사칭'}})).status,403);
 step='post_restart_tenant_denial';assert.equal((await h.api('/api/governance/tasks/'+saved.body.id,{role:'reviewer',tenant:'beta',body:{status:'open'}})).status,404);
 step='integrity';assert.equal((await h.api('/api/integrity')).body.valid,true);
});
