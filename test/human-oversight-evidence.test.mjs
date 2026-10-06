import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync} from 'node:crypto';
import {mkdtempSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve,sep} from 'node:path';
import {createService} from '../src/service.mjs';
import {validateEvent} from '../src/model.mjs';
import {appendKrCheck,oversightMetrics} from './fixtures/kr-check-fixture.mjs';

const requirements=JSON.parse(readFileSync(new URL('../data/requirements.json',import.meta.url),'utf8'));
const system={id:'credit',name:'Synthetic credit',owner:'reviewer',purpose:'Loan decision support',markets:['KR'],krRoles:['deployer'],generative:false,highImpact:'confirmed',modelId:'credit-model',modelVersion:'v2',policyVersion:'credit-policy-v3'};
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');

function fixture(t){
 const dir=mkdtempSync(join(tmpdir(),'evidscope-human-oversight-')),principals=[
  {id:'reviewer',role:'reviewer',tenant:'alpha',token:'r'.repeat(40)},
  {id:'alpha-authority',role:'source',kind:'authority',tenant:'alpha',token:'a'.repeat(40),hmacSecret:'h'.repeat(40)},
  {id:'beta-authority',role:'source',kind:'authority',tenant:'beta',token:'b'.repeat(40),hmacSecret:'j'.repeat(40)},
 ];
 const service=createService({dataDir:dir,key:generateKeyPairSync('ed25519').privateKey,config:{principals},requirements});
 t.after(()=>{service.store.close();assert.ok(resolve(dir).startsWith(resolve(tmpdir())+sep));rmSync(dir,{recursive:true,force:true});});
 const call=(path,body)=>service.handle(body===undefined?'GET':'POST',new URL(path,'http://local'),{authorization:'Bearer '+principals[0].token},body===undefined?'':JSON.stringify(body));
 const addEvent=(overrides={})=>{
  const raw={id:'oversight-'+Math.random().toString(36).slice(2),kind:'human_oversight_review',occurredAt:new Date().toISOString(),clockUncertaintyMs:0,traceId:'oversight-trace',actionId:'oversight-action',reviewer:'human-reviewer',systemId:system.id,modelId:system.modelId,modelVersion:system.modelVersion,policyVersion:system.policyVersion,...overrides};
  const event=validateEvent(raw,principals[1]);service.store.transaction(()=>{const record=service.store.append('alpha','event',event,principals[1].id);service.store.project({...event,seq:record.seq,hash:record.hash});});return event;
 };
 const addDocument=async(id='oversight-plan',content='oversight roles, authority, competence and intervention procedure')=>{const bytes=Buffer.from(content);return call('/api/governance/documents',{id,systemId:system.id,name:'감독 계획.txt',mediaType:'text/plain',sha256:sha(bytes),contentBase64:bytes.toString('base64')});};
 return {service,call,addEvent,addDocument};
}

const assessment=evidence=>({systemId:system.id,requirementId:'KR-34-OVERSIGHT',applicability:'applicable',assessment:'sufficient',legalReview:'reviewed',evidence,control:'Human oversight control reviewed by the named owner',owner:'reviewer',reason:'Human legal conclusion remains separate from technical evidence state',nextReviewAt:'2099-01-01T00:00:00.000Z'});
const item=report=>report.items.find(value=>value.requirement.id==='KR-34-OVERSIGHT');

test('self-asserted oversight evidence remains insufficient and leaves a task that cannot be closed',async t=>{
 const h=fixture(t);await h.call('/api/governance/systems',system);
 const saved=await h.call('/api/governance/assessments',assessment([{type:'attestation',ref:'self-asserted-no-object'}]));
 const result=item(await h.call('/api/governance/report?systemId=credit'));
 assert.equal(result.assessment.assessment,'sufficient');assert.equal(result.assessment.legalReview,'reviewed');
 assert.equal(result.status,'evidence_insufficient');assert.equal(result.technicalStatus,'typed_evidence_insufficient');
 assert.deepEqual(result.technicalEvidence.missingChecks,['oversight_plan','human_oversight_review']);
 const task=(await h.call('/api/governance')).tasks.find(value=>value.id===saved.id);assert.equal(task.status,'open');
 await assert.rejects(h.call(`/api/governance/tasks/${task.id}`,{status:'closed',reason:'Self assertion'}),error=>error.status===409&&/현재 법령.*검증 가능한.*증거/.test(error.message));
});

test('oversight plan and review record are each necessary and must bind the current system model and policy',async t=>{
 const h=fixture(t),savedSystem=await h.call('/api/governance/systems',system),document=await h.addDocument();
 await h.call('/api/governance/assessments',assessment([{type:'document',ref:'governance-document:oversight-plan'}]));
 let result=item(await h.call('/api/governance/report?systemId=credit'));assert.equal(result.technicalStatus,'typed_evidence_insufficient');assert.equal(result.status,'evidence_insufficient');
 assert.deepEqual(result.technicalEvidence.missingChecks,['oversight_plan','human_oversight_review']);

 const correct=h.addEvent(),ref=`${correct.source}/${correct.id}`;
 await h.call('/api/governance/assessments',assessment([{type:'event',ref}]));
 result=item(await h.call('/api/governance/report?systemId=credit'));assert.equal(result.technicalStatus,'typed_evidence_insufficient');assert.equal(result.status,'evidence_insufficient');
 assert.deepEqual(result.technicalEvidence.missingChecks,['oversight_plan']);

 await h.call('/api/governance/assessments',assessment([{type:'document',ref:'governance-document:oversight-plan'},{type:'event',ref}]));
 result=item(await h.call('/api/governance/report?systemId=credit'));assert.equal(result.status,'evidence_insufficient','Retrievable arbitrary bytes plus a reviewer record do not measure the oversight plan');assert.deepEqual(result.technicalEvidence.missingChecks,['oversight_plan']);
 const measuredPlan=appendKrCheck(h.service,savedSystem,requirements.find(r=>r.id==='KR-34-OVERSIGHT'),document,'oversight_plan',oversightMetrics);
 await h.call('/api/governance/assessments',assessment([{type:'document',ref:'governance-document:oversight-plan'},measuredPlan]));
 result=item(await h.call('/api/governance/report?systemId=credit'));assert.equal(result.status,'evidence_insufficient');assert.deepEqual(result.technicalEvidence.missingChecks,['human_oversight_review']);

 const saved=await h.call('/api/governance/assessments',assessment([{type:'document',ref:'governance-document:oversight-plan'},{type:'event',ref},measuredPlan]));
 assert.equal(saved.evidence[1].eventSnapshot.kind,'human_oversight_review');assert.match(saved.evidence[1].eventSnapshotHash,/^[a-f0-9]{64}$/);
 result=item(await h.call('/api/governance/report?systemId=credit'));assert.equal(result.technicalStatus,'authenticated_reported_measurement_supported');assert.equal(result.status,'human_evidence_assessed');assert.equal(result.legalStatus,'reviewed');
 assert.equal(saved.evidence[2].eventSnapshot.governanceCheck.documentHash,document.sha256);assert.equal(result.technicalEvidence.automaticLegalVerdict,false);

 for(const overrides of [{modelVersion:'v1'},{policyVersion:'old-policy'},{systemId:'other-system'},{kind:'human_approval',validFrom:'2026-01-01T00:00:00.000Z',validUntil:'2099-01-01T00:00:00.000Z',scope:{actor:'a',tool:'t',action:'x',resource:'r'}}]){
  const event=h.addEvent(overrides),badRef=`${event.source}/${event.id}`;await h.call('/api/governance/assessments',assessment([{type:'document',ref:'governance-document:oversight-plan'},{type:'event',ref:badRef},measuredPlan]));
  const bad=item(await h.call('/api/governance/report?systemId=credit'));assert.equal(bad.status,'evidence_insufficient',JSON.stringify(overrides));assert.equal(bad.technicalStatus,'typed_evidence_insufficient');assert.ok(bad.technicalEvidence.missingChecks.includes('human_oversight_review'));
 }
});

test('document revision makes the bound oversight assessment stale and blocks task closure until reassessment',async t=>{
 const h=fixture(t),savedSystem=await h.call('/api/governance/systems',system),document=await h.addDocument(),measuredPlan=appendKrCheck(h.service,savedSystem,requirements.find(r=>r.id==='KR-34-OVERSIGHT'),document,'oversight_plan',oversightMetrics),event=h.addEvent(),ref=`${event.source}/${event.id}`;
 const missing=await h.call('/api/governance/assessments',assessment([{type:'attestation',ref:'missing'}]));
 await new Promise(resolve=>setTimeout(resolve,2));await h.call('/api/governance/assessments',assessment([{type:'document',ref:'governance-document:oversight-plan'},{type:'event',ref},measuredPlan]));
 const task=(await h.call('/api/governance')).tasks.find(value=>value.id===missing.id);assert.equal((await h.call(`/api/governance/tasks/${task.id}`,{status:'closed',reason:'Current verified evidence'})).status,'closed');
 const revised=await h.addDocument('oversight-plan','revised oversight plan');
 const result=item(await h.call('/api/governance/report?systemId=credit'));assert.equal(result.status,'review_required');assert.equal(result.technicalStatus,'typed_evidence_insufficient');assert.ok(result.technicalEvidence.reasons.includes('document_evidence_stale'));
 const revisionTask=(await h.call('/api/governance')).tasks.find(value=>value.documentId==='oversight-plan'&&value.status==='open');
 await assert.rejects(h.call(`/api/governance/tasks/${revisionTask.id}`,{status:'closed',reason:'Old assessment'}),error=>error.status===409);
 await new Promise(resolve=>setTimeout(resolve,2));await h.call('/api/governance/assessments',assessment([{type:'document',ref:'governance-document:oversight-plan'},{type:'event',ref},measuredPlan]));
 assert.equal(item(await h.call('/api/governance/report?systemId=credit')).status,'evidence_insufficient','Fresh document metadata must not turn the old-hash measurement into a new plan test');
 const newPlan=appendKrCheck(h.service,savedSystem,requirements.find(r=>r.id==='KR-34-OVERSIGHT'),revised,'oversight_plan',oversightMetrics);
 await new Promise(resolve=>setTimeout(resolve,2));await h.call('/api/governance/assessments',assessment([{type:'document',ref:'governance-document:oversight-plan'},{type:'event',ref},newPlan]));
 assert.equal(item(await h.call('/api/governance/report?systemId=credit')).technicalStatus,'authenticated_reported_measurement_supported');
});

test('unidentified reviewers are rejected at intake rather than certified by a valid plan hash',async t=>{
 const h=fixture(t);await h.call('/api/governance/systems',system);
 for(const reviewer of ['unknown','미확인','없음','N/A','unknown\u200b'])assert.throws(()=>h.addEvent({reviewer}),error=>error.status===400);
});
