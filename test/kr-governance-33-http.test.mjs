import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,randomUUID,verify} from 'node:crypto';
import {harness} from './harness.mjs';
import {submit} from '../src/client.mjs';
import {canonical,digest} from '../src/crypto.mjs';

test('KR-33 HTTP keeps mandatory review separate from optional request evidence and preserves frozen tenant history',async t=>{
 const h=await harness();t.after(()=>h.close());
 const reviewedAt=new Date(Date.now()-120000).toISOString(),providedAt=new Date(Date.now()-60000).toISOString();
 const systemInput={id:'kr-33-http',name:'합성 대출 AI 서비스',owner:'검토팀',purpose:'대출 심사 보조',markets:['KR'],krRoles:['deployer'],aiBusinessOperator:true,domesticImpact:true,generative:false,highImpact:'confirmed',modelId:'credit-model',modelVersion:'v1',policyVersion:'p1',providedAt};
 const systemResponse=await h.api('/api/governance/systems',{role:'reviewer',body:systemInput});assert.equal(systemResponse.status,200);const system=systemResponse.body;
 const requirement=(await h.api('/api/governance')).body.requirements.find(r=>r.id==='KR-33');
 const bytes=Buffer.from('합성 고영향 사전 검토와 선택적 요청 근거'),docResponse=await h.api('/api/governance/documents',{role:'reviewer',body:{id:'kr-33-proof',systemId:system.id,name:'사전 검토.txt',mediaType:'text/plain',contentBase64:bytes.toString('base64'),sha256:createHash('sha256').update(bytes).digest('hex')}});
 if(docResponse.status!==200)assert.fail(JSON.stringify(docResponse));
 const doc=docResponse.body;
 const documentRef={type:'document',ref:'governance-document:'+doc.id};
 const assessmentInput={systemId:system.id,requirementId:'KR-33',applicability:'applicable',assessment:'sufficient',legalReview:'reviewed',control:'고영향 해당성 사전 검토',owner:'검토팀',reason:'합성 근거의 제공 전 검토와 선택적 요청 상태를 별도로 검토함',nextReviewAt:'2099-01-01T00:00:00.000Z'};
 const assess=async evidence=>{const response=await h.api('/api/governance/assessments',{role:'reviewer',body:{...assessmentInput,evidence}});assert.equal(response.status,200);return response.body;};
 const report=async()=>{const response=await h.api('/api/governance/report?systemId='+system.id);assert.equal(response.status,200);return response.body.items.find(i=>i.requirement.id==='KR-33');};
 const freeze=async()=>{await h.analyze();const response=await h.api('/api/governance/finance/report',{role:'reviewer',body:{systemId:system.id}});assert.equal(response.status,200);assert.equal(response.body.sha256,digest(response.body.snapshot));assert.ok(verify(null,Buffer.from(canonical(response.body.snapshot)),h.publicKey,Buffer.from(response.body.signature,'base64')));return response.body;};
 const ingest=async(type,measurements,source='telemetry',overrides={})=>{
  // This fixture models completed observations, with a gap before transport.
  // Distinct processes' Date clocks are not proven synchronized to 0ms.
  const event={id:randomUUID(),kind:'governance_check',occurredAt:new Date(Date.now()-1000).toISOString(),traceId:'kr33',actionId:'kr33',systemId:system.id,modelId:system.modelId,modelVersion:system.modelVersion,policyVersion:system.policyVersion,clockUncertaintyMs:0,governanceCheck:{schemaVersion:1,requirementId:requirement.id,checkType:type,result:'pass',systemHash:digest(system),requirementHash:digest(requirement),documentHash:doc.sha256,measurements,...overrides}};
  const response=await submit(h.ingress.url,h.principal(source),event);assert.equal(response.status,202);return {type:'event',ref:'alpha-'+source+'/'+event.id};
 };
 await assess([documentRef]);assert.equal((await report()).status,'evidence_insufficient');const historical=await freeze();
 const pre=await ingest('high_impact_pre_review',{reviewedAt,providedAt,reviewedAtUncertaintyMs:0,providedAtUncertaintyMs:0,domainsReviewed:true,impactSeverityFrequencyReviewed:true,domainSpecificityReviewed:true,conclusionRecorded:true,confirmationRequested:true});
 const complete=await assess([documentRef,pre]),pending=await report();
 assert.equal(pending.status,'human_evidence_assessed');assert.equal(pending.technicalEvidence.supportsHumanAssessment,true);assert.deepEqual(pending.technicalEvidence.missingChecks,[]);
 assert.equal(pending.technicalEvidence.optionalWorkflows[0].status,'request_receipt_missing');assert.equal(pending.technicalEvidence.optionalWorkflows[0].supportsRequestReceipt,false);
 assert.ok(!(await h.api('/api/governance')).body.tasks.some(task=>task.id===complete.id),'optional request alone does not create a mandatory-evidence task');
 const pendingFrozen=await freeze();
 const metrics={authority:'MSIT',requestId:'synthetic-request',requestedAt:new Date(Date.now()-2000).toISOString(),attachments:['product_overview','training_data_overview','process_and_results','other_supporting_material'],requestAccepted:true};
 const unauthorised=await ingest('high_impact_confirmation',metrics,'telemetry');
 await assess([documentRef,pre,unauthorised]);const invalid=await report();assert.equal(invalid.status,'human_evidence_assessed');assert.equal(invalid.technicalEvidence.optionalWorkflows[0].status,'request_evidence_insufficient');assert.match(invalid.technicalEvidence.optionalWorkflows[0].reasons.join(' '),/authority_receipt_source_required/);
 const receipt=await ingest('high_impact_confirmation',metrics,'authority');
 await assess([documentRef,pre,receipt]);const accepted=await report(),diagnostic=JSON.stringify({fixture:h.dir,technicalEvidence:accepted.technicalEvidence});assert.equal(accepted.status,'human_evidence_assessed',diagnostic);assert.equal(accepted.technicalEvidence.optionalWorkflows[0].status,'request_receipt_supported',diagnostic);assert.equal(accepted.technicalEvidence.optionalWorkflows[0].supportsRequestReceipt,true,diagnostic);assert.equal(accepted.technicalEvidence.automaticLegalVerdict,false,diagnostic);
 assert.deepEqual((await report()).technicalEvidence,accepted.technicalEvidence);
 for(const frozen of [historical,pendingFrozen]){
  assert.deepEqual((await h.api('/api/governance/finance/reports/'+frozen.id)).body,frozen);
  assert.equal((await h.api('/api/governance/finance/reports/'+frozen.id,{tenant:'beta'})).status,404);
 }
 const noReview=await assess([documentRef,receipt]);assert.equal((await report()).status,'evidence_insufficient');
 assert.equal((await h.api('/api/governance/tasks/'+noReview.id,{role:'reviewer',body:{status:'closed',reason:'접수만으로 사전 검토 대체'}})).status,409);
 await assess([documentRef,pre,receipt]);await h.restart();assert.deepEqual((await report()).technicalEvidence,accepted.technicalEvidence);
 for(const frozen of [historical,pendingFrozen])assert.deepEqual((await h.api('/api/governance/finance/reports/'+frozen.id)).body,frozen);
 assert.deepEqual(Buffer.from((await h.api('/api/governance/documents/'+doc.id+'/export',{role:'reviewer'})).body.contentBase64,'base64'),bytes);
 assert.equal((await h.api('/api/integrity')).body.valid,true);
});
