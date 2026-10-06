import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,verify} from 'node:crypto';
import {harness} from './harness.mjs';
import {submit} from '../src/client.mjs';
import {canonical} from '../src/crypto.mjs';

const bytes=Buffer.from('합성 공급사 범위 근거'),sha256=createHash('sha256').update(bytes).digest('hex');
const system=(id,value)=>({id,name:'합성 금융 참조 검증',owner:'검토팀',purpose:value,markets:['KR'],krRoles:['deployer'],supplierId:value,modelId:value,modelVersion:value,suppliedModelVersion:value,suppliedPurpose:value,substantialModification:false});
const bundle=(s)=>({id:s.id+'-bundle',systemId:s.id,synthetic:true,supplierId:s.supplierId,modelId:s.modelId,modelVersion:s.modelVersion,purpose:s.purpose,testScope:'합성 참조 검증',measures:['KR-34-RISK'],documents:[{id:'proof',name:'합성.txt',sha256,contentBase64:bytes.toString('base64')}]});
const result=(s,id,modelId=s.modelId)=>({id,kind:'result',status:'success',occurredAt:new Date().toISOString(),systemId:s.id,actionId:id,traceId:id,requestId:id,attemptId:id,modelId,modelVersion:s.modelVersion,policyVersion:'p1',actor:'synthetic',tool:'credit-score',action:'score',resource:id});
const unknownIssues=['SUPPLIER_UNKNOWN','MODEL_ID_UNKNOWN','MODEL_VERSION_UNKNOWN','PURPOSE_UNKNOWN','SUPPLIED_MODEL_VERSION_UNKNOWN','SUPPLIED_PURPOSE_UNKNOWN'];

test('actual finance HTTP keeps reserved supplier, purpose and model aliases unknown in current views and signed reports',async t=>{
 const h=await harness();t.after(()=>h.close());const frozen=[];
 for(const [index,value]of ['unknown','UNKNOWN','not_recorded','not_provided','none','n/a','미확인',' ＵＮＫＮＯＷＮ ','\u200bunknown'].entries()){
  const s=system('unknown-reference-'+index,value);
  assert.equal((await h.api('/api/governance/systems',{role:'reviewer',body:s})).status,200);
  const imported=await h.api('/api/governance/bundles',{role:'reviewer',body:bundle(s)});assert.equal(imported.status,200);
  assert.equal(imported.body.verification.status,'review_required',value);assert.deepEqual(imported.body.verification.issues,unknownIssues,value);
  assert.equal(imported.body.verification.documents[0].status,'hash_verified_and_retrievable');assert.equal(imported.body.modelId,value,'signed metadata remains unchanged');
  const assessment=await h.api('/api/governance/assessments',{role:'reviewer',body:{systemId:s.id,requirementId:'KR-34-RISK',applicability:'applicable',assessment:'sufficient',legalReview:'reviewed',control:'합성 검토',owner:'검토팀',reason:'미확인 공급사 범위로 충분 판단 시도',nextReviewAt:'2099-01-01T00:00:00.000Z',evidence:[{type:'document',ref:'supplier-bundle:'+imported.body.id}]}});
  assert.equal(assessment.status,400,'unknown supplier scope cannot support a sufficient assessment');
  if(/^[a-zA-Z0-9._:@/-]{1,120}$/.test(value)){
   const event=result(s,'unknown-result-'+index);assert.equal((await submit(h.ingress.url,h.principal('tool'),event)).status,202);await h.analyze();
   const view=(await h.api('/api/governance/finance?systemId='+s.id)).body;
   assert.equal(view.operations[0].modelIssues[0].code,'DEPLOYED_MODEL_UNVERIFIED_OR_CHANGED');assert.equal(view.operations[0].evaluation.status,'evaluated');assert.equal(view.operations[0].analysisPending,false);
  }
  const response=await h.api('/api/governance/finance/report',{body:{systemId:s.id}});assert.equal(response.status,200);
  assert.equal(response.body.snapshot.bundles[0].verification.status,'review_required');assert.equal(response.body.snapshot.automaticLegalVerdict,false);assert.ok(verify(null,Buffer.from(canonical(response.body.snapshot)),h.publicKey,Buffer.from(response.body.signature,'base64')));frozen.push(response.body);
  assert.equal((await h.api('/api/governance/finance/reports/'+response.body.id,{tenant:'beta'})).status,404);
 }
 await h.restart();for(const report of frozen)assert.deepEqual((await h.api('/api/governance/finance/reports/'+report.id)).body,report);
 assert.equal((await h.api('/api/integrity')).body.valid,true);
});

test('normal finance references retain exact case-sensitive matching and historical signed bundle and report snapshots',async t=>{
 const h=await harness();t.after(()=>h.close());const s={...system('normal-reference','credit-A'),supplierId:'supplier-A',purpose:'대출 심사 보조',suppliedPurpose:'대출 심사 보조',modelVersion:'v1',suppliedModelVersion:'v1'};
 assert.equal((await h.api('/api/governance/systems',{role:'reviewer',body:s})).status,200);
 const original=(await h.api('/api/governance/bundles',{role:'reviewer',body:bundle(s)})).body;assert.equal(original.verification.status,'technical_match_human_review_required');
 assert.equal((await submit(h.ingress.url,h.principal('tool'),result(s,'normal-result'))).status,202);await h.analyze();
 const initialView=(await h.api('/api/governance/finance?systemId='+s.id)).body;assert.deepEqual(initialView.operations[0].modelIssues,[]);assert.equal(initialView.operations[0].evaluation.status,'evaluated');
 const frozen=(await h.api('/api/governance/finance/report',{body:{systemId:s.id}})).body;
 const initialSigned=((await h.api('/api/export')).body.records).filter(r=>['system','supplier_bundle','evaluation','finance_report'].includes(r.type));
 const changed=(await h.api('/api/governance/bundles',{role:'reviewer',body:{...bundle(s),modelId:'credit-a'}})).body;assert.equal(changed.verification.status,'review_required');assert.ok(changed.verification.issues.includes('MODEL_ID_MISMATCH'));
 assert.equal((await submit(h.ingress.url,h.principal('tool'),result(s,'changed-case-result','credit-a'))).status,202);await h.analyze();
 const changedView=(await h.api('/api/governance/finance?systemId='+s.id)).body;assert.equal(changedView.operations.find(o=>o.actionId==='changed-case-result').modelIssues[0].code,'DEPLOYED_MODEL_UNVERIFIED_OR_CHANGED');
 const current=(await h.api('/api/governance/finance/report',{body:{systemId:s.id}})).body;assert.equal(current.snapshot.bundles[0].verification.status,'review_required');
 await h.restart();assert.deepEqual((await h.api('/api/governance/finance/reports/'+frozen.id)).body,frozen);
 const afterSigned=((await h.api('/api/export')).body.records).filter(r=>initialSigned.some(old=>old.seq===r.seq));assert.deepEqual(afterSigned,initialSigned);
 assert.equal((await h.api('/api/integrity')).body.valid,true);
});
