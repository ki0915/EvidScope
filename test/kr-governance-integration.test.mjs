import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,randomUUID,createHash} from 'node:crypto';
import {mkdtempSync,mkdirSync,readFileSync,rmSync} from 'node:fs';
import {resolve,join,sep} from 'node:path';
import {createService} from '../src/service.mjs';
import {digest,mac} from '../src/crypto.mjs';
import {publicationMetrics,oversightMetrics} from './fixtures/kr-check-fixture.mjs';

const requirements=JSON.parse(readFileSync(new URL('../data/requirements.json',import.meta.url)));
const rawSystem={id:'credit',name:'Synthetic AI supplier service',owner:'reviewer',purpose:'credit assessment support',markets:['KR'],krRoles:['deployer'],aiBusinessOperator:true,domesticImpact:true,generative:true,highImpact:'confirmed',modelId:'credit-model',modelVersion:'v1',policyVersion:'policy-1',providedAt:'2026-10-01T01:00:00.000Z'};
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');

async function fixture(t){
 const parent=resolve('.test-runs/kr-governance-integration');mkdirSync(parent,{recursive:true});const dir=mkdtempSync(join(parent,'case-'));
 const key=generateKeyPairSync('ed25519').privateKey;
 const principals=[{id:'reviewer',tenant:'alpha',role:'reviewer',token:'r'.repeat(40)},...['telemetry','authority','agent'].map((kind,index)=>({id:kind,tenant:'alpha',role:'source',kind,token:String(index).repeat(40),hmacSecret:String(index+3).repeat(48)})),{id:'beta-reviewer',tenant:'beta',role:'reviewer',token:'b'.repeat(40)}];
 let service=createService({dataDir:dir,key,config:{principals},requirements});
 t.after(()=>{service.store.close();assert.ok(resolve(dir).startsWith(parent+sep));rmSync(dir,{recursive:true,force:true});});
 const call=(path,body,who=principals[0])=>service.handle(body===undefined?'GET':'POST',new URL(path,'http://local'),{authorization:'Bearer '+who.token},body===undefined?'':JSON.stringify(body));
 const system=await call('/api/governance/systems',rawSystem);
 async function document(id='proof',content=Buffer.from('Synthetic retained governance evidence')){return call('/api/governance/documents',{id,systemId:system.id,name:'검토 근거.txt',mediaType:'text/plain',contentBase64:content.toString('base64'),sha256:sha(content)});}
 async function ingest(raw,sourceKind='telemetry'){
  const p=principals.find(p=>p.kind===sourceKind),body=JSON.stringify(raw),ts=String(Date.now()),nonce=randomUUID();
  return service.handle('POST',new URL('/api/ingest','http://local'),{authorization:'Bearer '+p.token,'x-evid-timestamp':ts,'x-evid-nonce':nonce,'x-evid-signature':mac(p.hmacSecret,ts,nonce,body)},body);
 }
 async function check(id,type,measurements,doc,extra={}){
  const {sourceKind='telemetry',facts=system,checkOverrides={},...eventOverrides}=extra;
  const requirement=requirements.find(r=>r.id===id),event={id:randomUUID(),kind:'governance_check',occurredAt:new Date().toISOString(),traceId:'trace',actionId:'check-action',systemId:system.id,modelId:system.modelId,modelVersion:system.modelVersion,policyVersion:system.policyVersion,clockUncertaintyMs:0,governanceCheck:{schemaVersion:1,requirementId:id,checkType:type,result:'pass',systemHash:digest(facts),requirementHash:digest(requirement),documentHash:doc.sha256,measurements,...checkOverrides},...eventOverrides};
  await ingest(event,sourceKind);return {type:'event',ref:`${sourceKind}/${event.id}`};
 }
 const assess=(id,evidence,extra={})=>call('/api/governance/assessments',{systemId:system.id,requirementId:id,applicability:'applicable',assessment:'sufficient',legalReview:'reviewed',control:'Recorded control review',owner:'reviewer',reason:'Named reviewer assessed the retained measurement and its stated scope',nextReviewAt:'2099-01-01T00:00:00.000Z',evidence,...extra});
 const report=()=>call('/api/governance/report?systemId=credit');
 return {call,document,ingest,check,assess,report,system,principals,get service(){return service;},restart(nextRequirements=requirements){service.store.close();service=createService({dataDir:dir,key,config:{principals},requirements:nextRequirements});}};
}

const noticeMetrics={noticeAt:'2026-10-01T00:00:00.000Z',providedAt:rawSystem.providedAt,noticeAtUncertaintyMs:100,providedAtUncertaintyMs:100,noticeDelivered:true,deliveryMethod:'screen',methodBasisRecorded:false,targetUsersCovered:true};
const refs=(doc,event)=>[{type:'document',ref:'governance-document:'+doc.id},event];

test('all eighteen Korean requirements keep an unfetched attestation insufficient and block closure',async t=>{
 const h=await fixture(t);
 for(const req of requirements.filter(r=>r.jurisdiction==='KR')){
  const saved=await h.assess(req.id,[{type:'attestation',ref:'nonexistent-reference'}]);
  const item=(await h.report()).items.find(i=>i.requirement.id===req.id);
  assert.equal(item.status,'evidence_insufficient',req.id);assert.equal(item.assessment.assessment,'sufficient');assert.equal(item.technicalEvidence.supportsHumanAssessment,false);
  assert.ok((await h.call('/api/governance')).tasks.some(x=>x.id===saved.id&&x.status==='open'));
  await assert.rejects(h.call('/api/governance/tasks/'+saved.id,{status:'closed',reason:'Unsupported claim'}),e=>e.status===409);
 }
});

test('HMAC source ingestion, retained file and fixed versions support a measured notice review',async t=>{
 const h=await fixture(t),doc=await h.document('notice-screenshot',Buffer.alloc(256*1024,7));
 const event=await h.check('KR-31-1','notice_pre_delivery',noticeMetrics,doc);
 const missing=await h.assess('KR-31-1',[{type:'attestation',ref:'missing'}]);
 await h.assess('KR-31-1',refs(doc,event));
 const item=(await h.report()).items.find(i=>i.requirement.id==='KR-31-1');
 assert.equal(item.status,'human_evidence_assessed');assert.equal(item.technicalEvidence.measurementTrust,'authenticated_reported_measurement_not_independent_truth');assert.equal(item.technicalEvidence.automaticLegalVerdict,false);
 await assert.rejects(h.call('/api/governance/tasks/'+missing.id,{status:'closed',reason:'   '}),e=>e.status===400);
 assert.equal((await h.call('/api/governance/tasks/'+missing.id,{status:'closed',reason:'Current measured review'})).status,'closed');
 assert.deepEqual(Buffer.from((await h.call('/api/governance/documents/'+doc.id+'/export')).contentBase64,'base64'),Buffer.alloc(256*1024,7));
 assert.equal((await h.call('/api/governance')).documentLimits.maximumBytes,4*1024*1024);
});

for(const [name,metrics,extra] of [
 ['after provision',{...noticeMetrics,noticeAt:'2026-10-01T02:00:00.000Z'},{}],
 ['unknown clock',{...noticeMetrics,noticeAtUncertaintyMs:'unknown'},{}],
 ['wrong model',noticeMetrics,{modelVersion:'v2'}],
 ['failed test',noticeMetrics,{checkOverrides:{result:'fail'}}],
])test('notice '+name+' cannot clear a review task',async t=>{
 const h=await fixture(t),doc=await h.document(),event=await h.check('KR-31-1','notice_pre_delivery',metrics,doc,extra),saved=await h.assess('KR-31-1',refs(doc,event));
 assert.equal((await h.report()).items.find(i=>i.requirement.id==='KR-31-1').status,'evidence_insufficient');
 await assert.rejects(h.call('/api/governance/tasks/'+saved.id,{status:'closed',reason:'Claimed pass'}),e=>e.status===409);
});

test('an AI self-report cannot issue a governance check, nor can a caller inject a frozen snapshot',async t=>{
 const h=await fixture(t),doc=await h.document();
 await assert.rejects(h.check('KR-31-1','notice_pre_delivery',noticeMetrics,doc,{sourceKind:'agent'}),e=>e.status===403);
 const event=await h.check('KR-31-1','notice_pre_delivery',noticeMetrics,doc,{modelVersion:'v2'});
 await h.assess('KR-31-1',refs(doc,{...event,eventSnapshot:{kind:'governance_check',modelVersion:'v1'},eventSnapshotHash:'0'.repeat(64)}));
 assert.equal((await h.report()).items.find(i=>i.requirement.id==='KR-31-1').status,'evidence_insufficient');
});

test('current report and closure both reject changed purpose, expired review, pending legal review and changed law',async t=>{
 const h=await fixture(t),doc=await h.document(),event=await h.check('KR-31-1','notice_pre_delivery',noticeMetrics,doc);
 const task=await h.assess('KR-31-1',[{type:'attestation',ref:'missing'}]);await h.assess('KR-31-1',refs(doc,event));
 await h.call('/api/governance/systems',{...rawSystem,purpose:'different purpose'});
 assert.equal((await h.report()).items.find(i=>i.requirement.id==='KR-31-1').status,'review_required');
 await assert.rejects(h.call('/api/governance/tasks/'+task.id,{status:'closed',reason:'Old scope'}),e=>e.status===409);
 const current=(await h.call('/api/governance')).systems.find(s=>s.id==='credit'),newEvent=await h.check('KR-31-1','notice_pre_delivery',noticeMetrics,doc,{facts:current});
 await h.assess('KR-31-1',refs(doc,newEvent),{nextReviewAt:'2020-01-01T00:00:00.000Z'});
 await assert.rejects(h.call('/api/governance/tasks/'+task.id,{status:'closed',reason:'Expired'}),e=>e.status===409);
 await h.assess('KR-31-1',refs(doc,newEvent),{legalReview:'pending'});
 await assert.rejects(h.call('/api/governance/tasks/'+task.id,{status:'closed',reason:'No legal review'}),e=>e.status===409);
 await h.assess('KR-31-1',refs(doc,newEvent));
 assert.equal((await h.call('/api/governance/tasks/'+task.id,{status:'closed',reason:'Fresh scoped review'})).status,'closed');
 h.restart(requirements.map(r=>r.id==='KR-31-1'?{...r,requirement:r.requirement+' Source correction.'}:r));
 assert.equal((await h.report()).items.find(i=>i.requirement.id==='KR-31-1').status,'review_required');
 await assert.rejects(h.call('/api/governance/tasks/'+task.id,{status:'closed',reason:'Prior catalog'}),e=>e.status===409);
});

test('human non-applicability is recorded separately and needs a recoverable basis before closure',async t=>{
 const h=await fixture(t),saved=await h.assess('KR-31-1',[{type:'attestation',ref:'missing'}],{applicability:'not_applicable'});
 await assert.rejects(h.call('/api/governance/tasks/'+saved.id,{status:'closed',reason:'Unfetched basis'}),e=>e.status===409);
 const doc=await h.document('scope-rationale');await h.assess('KR-31-1',[{type:'document',ref:'governance-document:'+doc.id}],{applicability:'not_applicable'});
 const item=(await h.report()).items.find(i=>i.requirement.id==='KR-31-1');assert.equal(item.status,'human_marked_not_applicable');assert.equal(item.technicalEvidence.automaticLegalVerdict,false);
 assert.equal((await h.call('/api/governance/tasks/'+saved.id,{status:'closed',reason:'Reviewed retained scope basis'})).status,'closed');
});

test('the existing vault document alone cannot imply publication or a qualified human oversight plan',async t=>{
 const h=await fixture(t),doc=await h.document('plan');
 for(const id of ['KR-34-DOCUMENT','KR-34-OVERSIGHT']){await h.assess(id,[{type:'document',ref:'governance-document:plan'}]);assert.equal((await h.report()).items.find(i=>i.requirement.id===id).status,'evidence_insufficient');}
 const publication=await h.check('KR-34-DOCUMENT','document_publication_retention',publicationMetrics,doc);await h.assess('KR-34-DOCUMENT',refs(doc,publication));
 assert.equal((await h.report()).items.find(i=>i.requirement.id==='KR-34-DOCUMENT').status,'human_evidence_assessed');
 const plan=await h.check('KR-34-OVERSIGHT','oversight_plan',oversightMetrics,doc),rawReview={id:randomUUID(),kind:'human_oversight_review',occurredAt:new Date().toISOString(),clockUncertaintyMs:0,traceId:'trace',actionId:'human-review',systemId:h.system.id,modelId:h.system.modelId,modelVersion:h.system.modelVersion,policyVersion:h.system.policyVersion,reviewer:'unknown'};
 await assert.rejects(h.ingest(rawReview,'authority'),e=>e.status===400);
 rawReview.reviewer='external-reviewer-17';await h.ingest(rawReview,'authority');
 await h.assess('KR-34-OVERSIGHT',[...refs(doc,plan),{type:'event',ref:'authority/'+rawReview.id}]);
 assert.equal((await h.report()).items.find(i=>i.requirement.id==='KR-34-OVERSIGHT').status,'human_evidence_assessed');
});

test('a different government order cannot close a prior order task; a fresh matching response can',async t=>{
 const h=await fixture(t),docA=await h.document('order-a'),docB=await h.document('order-b');
 const metrics=orderId=>({authority:'MSIT',orderId,orderReceivedAt:'2026-09-30T00:00:00.000Z',deadline:'2099-01-01T00:00:00.000Z',requestedMeasures:['correct'],requestedMeasuresCovered:true,implementationRecorded:true,responseAccepted:true,receiptId:'receipt-'+orderId,responseAt:'2026-10-01T00:00:00.000Z'});
 const failedA=await h.check('KR-40-ORDER','authority_order_response',metrics('order-A'),docA,{sourceKind:'authority',checkOverrides:{result:'fail'}}),taskA=await h.assess('KR-40-ORDER',refs(docA,failedA));
 const recorded=(await h.call('/api/governance')).tasks.find(x=>x.id===taskA.id);assert.deepEqual(recorded.orderTargets,[{checkType:'authority_order_response',orderId:'order-A'}]);
 const passB=await h.check('KR-40-ORDER','authority_order_response',metrics('order-B'),docB,{sourceKind:'authority'});await h.assess('KR-40-ORDER',refs(docB,passB));
 assert.equal((await h.report()).items.find(i=>i.requirement.id==='KR-40-ORDER').status,'human_evidence_assessed');
 await assert.rejects(h.call('/api/governance/tasks/'+taskA.id,{status:'closed',reason:'Order B passed'}),e=>e.status===409&&/다른 명령/.test(e.message));
 assert.equal((await h.call('/api/governance')).tasks.find(x=>x.id===taskA.id).status,'open');
 const passA=await h.check('KR-40-ORDER','authority_order_response',metrics('order-A'),docA,{sourceKind:'authority'});await h.assess('KR-40-ORDER',refs(docA,passA));
 assert.equal((await h.call('/api/governance/tasks/'+taskA.id,{status:'closed',reason:'Current response to order A reviewed'})).status,'closed');
 assert.ok(h.service.store.ledgerEvents('alpha').some(e=>e.id===failedA.ref.split('/')[1]&&e.governanceCheck.result==='fail'));
});
