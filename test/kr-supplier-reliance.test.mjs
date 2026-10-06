import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,randomUUID,verify} from 'node:crypto';
import {readFileSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {harness} from './harness.mjs';
import {submit} from '../src/client.mjs';
import {canonical,digest} from '../src/crypto.mjs';
import {evaluateKrGovernanceEvidence,normalizeGovernanceCheck} from '../src/kr-governance-evidence.mjs';

const types={'KR-34-RISK':'supplier_risk_reliance','KR-34-EXPLAIN':'supplier_explanation_reliance','KR-34-PROTECT':'supplier_protection_reliance'};
const facts={id:'supplier-reliance',name:'합성 대출 AI 제공 서비스',owner:'검토팀',purpose:'대출 심사 보조',markets:['KR'],krRoles:['deployer'],aiBusinessOperator:true,domesticImpact:true,generative:false,highImpact:'confirmed',supplierId:'supplier-a',modelId:'credit-model',modelVersion:'v1',suppliedModelVersion:'v1',suppliedPurpose:'대출 심사 보조',substantialModification:false,policyVersion:'p1'};
function fixture(requirementId='KR-34-RISK'){
 const system=structuredClone(facts),requirement={id:requirementId,title:'Synthetic requirement'},bundleHash=digest('supplier bundle');
 const document={type:'document',ref:'supplier-bundle:scope',contentHash:bundleHash,verification:'supplier_bundle_verified_at_assessment'};
 const check={schemaVersion:1,requirementId,checkType:types[requirementId],result:'pass',systemHash:digest(system),requirementHash:digest(requirement),documentHash:bundleHash,measurements:{supplierBundleRef:document.ref,supplierBundleHash:bundleHash,reviewer:'reviewer-1',reviewedAt:'2026-10-01T00:00:00.000Z',reviewedAtUncertaintyMs:0,supplierPerformedMeasureReviewed:true,fullMeasureScopeReviewed:true,noSubstantialModificationReviewed:true}};
 const snapshot={kind:'governance_check',sourceKind:'authority',systemId:system.id,modelId:system.modelId,modelVersion:system.modelVersion,policyVersion:system.policyVersion,reviewer:'reviewer-1',occurredAt:'2026-10-01T00:00:01.000Z',receivedAt:'2026-10-01T00:00:02.000Z',clockUncertaintyMs:0,governanceCheck:check};
 const event={type:'event',ref:'authority/reliance',contentHash:digest(snapshot),verification:'linked_verified_minimized_record',eventSnapshot:snapshot,eventSnapshotHash:digest(snapshot)};
 return {system,requirement,document,check,event,assessment:{assessment:'sufficient',evidence:[document,event],legalReview:'reviewed'}};
}
const evaluate=(f,options={})=>evaluateKrGovernanceEvidence(f.requirement,f.assessment,{system:f.system,...options});
const reseal=f=>f.event.eventSnapshotHash=digest(f.event.eventSnapshot);

test('reviewed supplier performance evidence supports only each scoped article34 measure without issuing a legal verdict',()=>{
 for(const requirementId of Object.keys(types)){
  const f=fixture(requirementId),original=structuredClone(f.assessment),result=evaluate(f);
  assert.equal(result.supportsHumanAssessment,true,requirementId);assert.equal(result.automaticLegalVerdict,false);assert.equal(result.matchedChecks[0].supplierBundleRef,f.document.ref);assert.equal(result.matchedChecks[0].supplierBundleHash,f.document.contentHash);assert.deepEqual(result.reasons,[]);assert.deepEqual(f.assessment,original);
  assert.deepEqual(evaluate(f),result);assert.equal(normalizeGovernanceCheck(f.check).measurements.reviewer,'reviewer-1');
 }
});

test('a bundle or acknowledgement cannot replace scoped supplier-performance review and exact evidence bindings',()=>{
 for(const [name,mutate] of [
  ['no review',f=>f.assessment.evidence=[f.document]],
  ['telemetry',f=>f.event.eventSnapshot.sourceKind='telemetry'],
  ['different reviewer',f=>f.event.eventSnapshot.reviewer='other'],
  ['unknown reviewer',f=>f.check.measurements.reviewer='미확인'],
  ['acknowledgement only',f=>f.check.measurements={acknowledged:true}],
  ['partial measure',f=>f.check.measurements.fullMeasureScopeReviewed=false],
  ['performance unreviewed',f=>f.check.measurements.supplierPerformedMeasureReviewed=false],
  ['modification unreviewed',f=>f.check.measurements.noSubstantialModificationReviewed=false],
  ['bundle ref',f=>f.check.measurements.supplierBundleRef='supplier-bundle:other'],
  ['bundle revision',f=>f.document.contentHash=digest('revised bundle')],
  ['document',f=>f.check.documentHash=digest('other file')],
  ['unverified bundle',f=>f.document.verification='human_supplied_reference_not_fetched'],
  ['insufficient snapshot',f=>f.assessment.assessment='insufficient'],
  ['future review',f=>f.check.measurements.reviewedAt='2099-01-01T00:00:00.000Z'],
  ['unknown clock',f=>f.check.measurements.reviewedAtUncertaintyMs='unknown'],
  ['failed review',f=>f.check.result='fail'],
  ['other model',f=>f.event.eventSnapshot.modelId='other'],
  ['policy',f=>f.event.eventSnapshot.policyVersion='other'],
  ['requirement',f=>f.check.requirementHash=digest('changed law')],
 ]){const f=fixture();mutate(f);reseal(f);assert.equal(evaluate(f).supportsHumanAssessment,false,name);}
 for(const change of [s=>s.purpose='마케팅',s=>s.modelVersion='v2',s=>s.suppliedModelVersion='v0',s=>s.suppliedPurpose='마케팅',s=>s.substantialModification=true,s=>s.substantialModification='unknown',s=>s.krRoles=[],s=>s.aiBusinessOperator='unknown',s=>s.supplierId='미확인']){
  const f=fixture();change(f.system);f.check.systemHash=digest(f.system);f.event.eventSnapshot.modelVersion=f.system.modelVersion;reseal(f);assert.equal(evaluate(f).supportsHumanAssessment,false,'fresh hash cannot override original supplied scope');
 }
 const unsealed=fixture();unsealed.check.measurements.reviewer='other';assert.equal(evaluate(unsealed).supportsHumanAssessment,false);
 for(const flag of ['documentStale','eventStale'])assert.equal(evaluate(fixture(),{[flag]:true}).supportsHumanAssessment,false);
});

test('supplier alternatives cannot replace pre-review, oversight, documents or erase a selected failed measurement',()=>{
 for(const id of ['KR-33','KR-34-OVERSIGHT','KR-34-DOCUMENT']){
  const f=fixture();f.requirement.id=id;f.check.requirementId=id;f.check.requirementHash=digest(f.requirement);reseal(f);assert.equal(evaluate(f).supportsHumanAssessment,false,id);assert.throws(()=>normalizeGovernanceCheck(f.check),e=>e.status===400);
 }
 const f=fixture(),failed=structuredClone(f.event);failed.ref='authority/failed';failed.eventSnapshot.governanceCheck.result='fail';failed.eventSnapshotHash=digest(failed.eventSnapshot);f.assessment.evidence.push(failed);assert.equal(evaluate(f).supportsHumanAssessment,false);
});

test('actual supplier HTTP intake binds reviewed scope, survives restart and preserves signed tenant history',async t=>{
 const h=await harness();t.after(()=>h.close());const system=(await h.api('/api/governance/systems',{role:'reviewer',body:facts})).body;
 const bytes=Buffer.from('합성 공급사 제34조 조치 근거'),input={id:'scope',systemId:system.id,synthetic:true,supplierId:system.supplierId,modelId:system.modelId,modelVersion:system.modelVersion,purpose:system.purpose,testScope:'제1~3호 검토 자료',measures:Object.keys(types),documents:[{id:'doc',name:'공급사 근거.txt',sha256:createHash('sha256').update(bytes).digest('hex'),contentBase64:bytes.toString('base64')}],reviewerNotes:'간주 범위는 사람 판단'};
 const response=await h.api('/api/governance/bundles',{role:'reviewer',body:input});assert.equal(response.status,200);const bundle=response.body;
 const requirement=(await h.api('/api/governance')).body.requirements.find(r=>r.id==='KR-34-RISK');
 const basic={systemId:system.id,requirementId:requirement.id,applicability:'applicable',assessment:'sufficient',legalReview:'reviewed',control:'공급사 조치 검토',owner:'검토팀',reason:'공급사 실제 조치 자료와 전체 인정 범위 및 본래 사용 목적을 검토함',nextReviewAt:'2099-01-01T00:00:00.000Z'};
 const docRef={type:'document',ref:'supplier-bundle:scope'};
 const post=async(evidence,requirementId=basic.requirementId)=>{const result=await h.api('/api/governance/assessments',{role:'reviewer',body:{...basic,requirementId,evidence}});assert.equal(result.status,200);return result.body;};
 const report=async(id=requirement.id)=>(await h.api('/api/governance/report?systemId='+system.id)).body.items.find(item=>item.requirement.id===id);
 const missing=await post([docRef]);assert.equal((await report()).status,'evidence_insufficient');
 const event={id:randomUUID(),traceId:'supplier',actionId:'supplier',kind:'governance_check',occurredAt:new Date().toISOString(),clockUncertaintyMs:0,systemId:system.id,modelId:system.modelId,modelVersion:system.modelVersion,policyVersion:system.policyVersion,reviewer:h.principal('reviewer').id,governanceCheck:{...fixture().check,systemHash:digest(system),requirementHash:digest(requirement),documentHash:bundle.contentHash,measurements:{...fixture().check.measurements,supplierBundleHash:bundle.contentHash,reviewer:h.principal('reviewer').id,reviewedAt:new Date(Date.now()-1000).toISOString()}}};
 assert.equal((await submit(h.ingress.url,h.principal('authority'),event)).status,202);
 const eventRef={type:'event',ref:'alpha-authority/'+event.id};await post([docRef,eventRef]);const supported=await report();assert.equal(supported.status,'human_evidence_assessed');assert.equal(supported.technicalEvidence.automaticLegalVerdict,false);
 for(const id of ['KR-34-EXPLAIN','KR-34-PROTECT']){
  const req=(await h.api('/api/governance')).body.requirements.find(r=>r.id===id),record=structuredClone(event);record.id=randomUUID();record.governanceCheck.requirementId=id;record.governanceCheck.requirementHash=digest(req);record.governanceCheck.checkType=types[id];
  assert.equal((await submit(h.ingress.url,h.principal('authority'),record)).status,202);await post([docRef,{type:'event',ref:'alpha-authority/'+record.id}],id);assert.equal((await report(id)).status,'human_evidence_assessed');
 }
 const partial=structuredClone(event);partial.id=randomUUID();partial.governanceCheck.measurements.fullMeasureScopeReviewed=false;
 assert.equal((await submit(h.ingress.url,h.principal('authority'),partial)).status,202);await post([docRef,{type:'event',ref:'alpha-authority/'+partial.id}]);assert.equal((await report()).status,'evidence_insufficient');
 const pending=await h.api('/api/governance/assessments',{role:'reviewer',body:{...basic,legalReview:'pending',evidence:[docRef,eventRef]}});assert.equal(pending.status,200);const pendingItem=await report();assert.equal(pendingItem.technicalEvidence.supportsHumanAssessment,true);assert.equal(pendingItem.legalStatus,'pending');
 assert.equal((await h.api('/api/governance/tasks/'+missing.id,{role:'reviewer',body:{status:'closed',reason:'사람 법률 검토 미완료'}})).status,409);
 await post([docRef,eventRef]);
 assert.equal((await h.api('/api/governance/tasks/'+missing.id,{role:'reviewer',body:{status:'closed',reason:'현재 범위의 공급사 조치 근거와 사람 판단'}})).status,200);
 assert.equal((await h.api('/api/governance/assessments',{role:'reviewer',tenant:'beta',body:{...basic,evidence:[docRef,eventRef]}})).status,404);
 await h.analyze();const frozen=(await h.api('/api/governance/finance/report',{role:'reviewer',body:{systemId:system.id}})).body;
 assert.ok(verify(null,Buffer.from(canonical(frozen.snapshot)),h.publicKey,Buffer.from(frozen.signature,'base64')));
 assert.equal((await h.api('/api/governance/finance/reports/'+frozen.id,{tenant:'beta'})).status,404);
 await h.restart();assert.deepEqual((await report()).technicalEvidence,supported.technicalEvidence);
 const tenantHash=createHash('sha256').update('alpha').digest('hex'),path=join(h.dir,'data','finance-documents',tenantHash,bundle.documents[0].sha256+'.json'),original=readFileSync(path);
 try{
  writeFileSync(path,'{}');assert.equal((await report()).status,'review_required');
  const blocked=await h.api('/api/governance/assessments',{role:'reviewer',body:{...basic,evidence:[docRef,eventRef]}});assert.equal(blocked.status,400);
  assert.deepEqual((await h.api('/api/governance/finance/reports/'+frozen.id)).body,frozen);
 }finally{writeFileSync(path,original);}
 assert.equal((await report()).status,'human_evidence_assessed');
 const revision=await h.api('/api/governance/bundles',{role:'reviewer',body:{...input,reviewerNotes:'새 검토 자료로 개정'}});assert.equal(revision.status,200);assert.equal((await report()).status,'review_required');
 await post([docRef,eventRef]);assert.equal((await report()).status,'evidence_insufficient','old review cannot approve a replacement bundle');
 assert.deepEqual((await h.api('/api/governance/finance/reports/'+frozen.id)).body,frozen);
 assert.equal((await h.api('/api/integrity')).body.valid,true);
});
