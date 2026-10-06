import test from 'node:test';
import assert from 'node:assert/strict';
import {digest} from '../src/crypto.mjs';
import {krGovernanceCheckDefinitions,normalizeGovernanceCheck,evaluateKrGovernanceEvidence} from '../src/kr-governance-evidence.mjs';

const before='2026-10-01T00:00:00.000Z',after='2026-10-01T01:00:00.000Z';
const timing=(first,last)=>({[first]:before,[last]:after,[first+'UncertaintyMs']:100,[last+'UncertaintyMs']:100});
const samples={
 notice_pre_delivery:{...timing('noticeAt','providedAt'),noticeDelivered:true,deliveryMethod:'screen',methodBasisRecorded:false,targetUsersCovered:true},
 generated_output_marking:{outputCount:24,markedOutputCount:24,markingMode:'perceptible',perceptibilityTestPassed:true,machineDetectionTestPassed:false,generationNoticeProvided:false},
 realistic_media_disclosure:{outputCount:12,disclosedOutputCount:12,accessibilityTestPassed:true,userConditionsConsidered:true,creativeExpression:false,enjoymentPreserved:false},
 safety_risk_management:{lifecycleStages:['design','development','deployment','operation','retirement'],riskIdentificationRecorded:true,riskAssessmentRecorded:true,mitigationTestPassed:true,residualRiskReviewed:true},
 safety_incident_monitoring:{monitoringScopeRecorded:true,responseProcedureRecorded:true,responsibleTeamRecorded:true,responseExercisePassed:true,incidentRegisterReviewed:true},
 safety_submission_receipt:{implementationResultsIncluded:true,submissionAccepted:true,authority:'MSIT',receiptId:'receipt-1',acceptedAt:after},
 high_impact_pre_review:{...timing('reviewedAt','providedAt'),domainsReviewed:true,impactSeverityFrequencyReviewed:true,domainSpecificityReviewed:true,conclusionRecorded:true,confirmationRequested:false},
 high_impact_confirmation:{authority:'MSIT',requestId:'request-1',requestedAt:after,attachments:['product_overview','training_data_overview','process_and_results','other_supporting_material'],requestAccepted:true},
 high_impact_risk_management:{riskPolicyRecorded:true,responsibleOrganisationRecorded:true,operatingReviewRecorded:true,mitigationTestPassed:true,residualRiskReviewed:true},
 explanation_plan:{finalResultExplanationRecorded:true,principalCriteriaRecorded:true,trainingDataOverviewRecorded:true,technicalFeasibilityReviewed:true,explanationDeliveryTestPassed:true},
 user_protection:{protectionPolicyRecorded:true,inquiryProcedureRecorded:true,objectionProcedureRecorded:true,damageResponseProcedureRecorded:true,operatingReviewRecorded:true},
 oversight_plan:{sections:['responsibility','authority','competence','intervention','contact'],interventionExercisePassed:true},
 document_publication_retention:{measureDocumentInventoryRecorded:true,retentionYears:5,accessControlTestPassed:true,restoreTestPassed:true,publishedSections:['risk_management','explanation','user_protection','oversight_name_contact'],excludedSections:[],exclusionBasisRecorded:false,publicationTestPassed:true},
 impact_assessment:{...timing('evaluatedAt','providedAt'),sections:['affected_groups','fundamental_rights','social_economic_impact','usage_patterns','indicators_and_method','risk_prevention_mitigation_recovery','improvement_plan'],vulnerableGroupsConsidered:true,resultsRecorded:true,improvementsRequired:true,improvementPlanRecorded:true},
 impact_effort:{...timing('effortAt','providedAt'),effortRecorded:true,incompleteReasonRecorded:true,nextEvaluationPlanRecorded:true},
 public_impact_preference:{publicInstitutionConfirmed:true,candidateComparisonRecorded:true,evaluatedProductsConsidered:true,selectionReasonRecorded:true},
 certification_effort:{...timing('effortAt','providedAt'),effortRecorded:true,certificationReceived:false,certificateScopeReviewed:false,incompleteReasonRecorded:true,nextPlanRecorded:true},
 public_certification_preference:{publicInstitutionConfirmed:true,candidateComparisonRecorded:true,certifiedProductsConsidered:true,certificateScopeReviewed:true,selectionReasonRecorded:true},
 domestic_representative:{writtenDesignationRecorded:true,domesticAddressOrOfficeVerified:true,mandate:['safety_submission','high_impact_confirmation','obligation_support_document_review'],notificationAccepted:true,authority:'MSIT',receiptId:'notification-1',acceptedAt:after},
 authority_order_response:{authority:'MSIT',orderId:'order-1',orderReceivedAt:before,deadline:'2026-10-03T00:00:00.000Z',requestedMeasures:['submit_materials','correct'],requestedMeasuresCovered:true,implementationRecorded:true,responseAccepted:true,receiptId:'response-1',responseAt:after},
};

function fixture(type){
 const definition=krGovernanceCheckDefinitions.find(item=>item.checkType===type);assert.ok(definition);
 const requirement={id:definition.requirementId,title:'Synthetic requirement',sourceUrl:krGovernanceCheckDefinitions.find(item=>item.requirementId===definition.requirementId).sourceUrl};
 const system={id:'loan',purpose:'Synthetic loan support',modelId:'loan-model',modelVersion:'v2',policyVersion:'policy-v3',providedAt:after};
 const documentHash=digest({syntheticDocument:'Original evidence'});
 const check=normalizeGovernanceCheck({schemaVersion:1,requirementId:requirement.id,checkType:type,result:'pass',systemHash:digest(system),requirementHash:digest(requirement),documentHash,measurements:structuredClone(samples[type])});
 const snapshot={kind:'governance_check',sourceKind:definition.authorityOnly?'authority':'telemetry',systemId:system.id,modelId:system.modelId,modelVersion:system.modelVersion,policyVersion:system.policyVersion,occurredAt:'2026-10-02T00:00:00.000Z',receivedAt:'2026-10-02T00:00:01.000Z',clockUncertaintyMs:100,governanceCheck:check};
 const document={type:'document',ref:'governance-document:measure-policy',version:'1',contentHash:documentHash,documentSnapshotHash:digest({systemId:system.id,documentHash,version:1}),verification:'governance_document_verified_at_assessment'};
 const event={type:'event',ref:'collector/check-1',contentHash:digest({syntheticEvent:snapshot}),verification:'linked_verified_minimized_record',eventSnapshot:snapshot,eventSnapshotHash:digest(snapshot)};
 const assessment={assessment:'sufficient',legalReview:'reviewed',applicability:'applicable',evidence:[document,event]};
 if(type==='oversight_plan')assessment.evidence.push(oversightEvent(system));
 if(type==='high_impact_confirmation'){
  const pre=fixture('high_impact_pre_review');pre.check.measurements.confirmationRequested=true;reseal(pre);assessment.evidence.push(pre.event);
 }
 return {requirement,system,assessment,event,document,check,definition};
}
function oversightEvent(system,reviewer='authority:user-1'){
 const snapshot={kind:'human_oversight_review',sourceKind:'authority',systemId:system.id,modelId:system.modelId,modelVersion:system.modelVersion,policyVersion:system.policyVersion,occurredAt:'2026-10-02T01:00:00.000Z',receivedAt:'2026-10-02T01:00:01.000Z',clockUncertaintyMs:100,reviewer};
 return {type:'event',ref:'authority/oversight',contentHash:digest(snapshot),eventSnapshot:snapshot,eventSnapshotHash:digest(snapshot),verification:'linked_verified_minimized_record'};
}
const result=(h,options={})=>evaluateKrGovernanceEvidence(h.requirement,h.assessment,{system:h.system,...options});
function reseal(h){h.event.eventSnapshotHash=digest(h.event.eventSnapshot);}
function negative(h,pattern){const observed=result(h);assert.equal(observed.supportsHumanAssessment,false);assert.equal(observed.status,'typed_evidence_insufficient');if(pattern)assert.match(observed.reasons.join(' ')+observed.missingChecks.join(' '),pattern);return observed;}

test('the schema covers eighteen requirements and confines supplier review alternatives to article34 measures1 through3',()=>{
 assert.equal(new Set(krGovernanceCheckDefinitions.map(item=>item.requirementId)).size,18);
 assert.equal(krGovernanceCheckDefinitions.length,23);
 assert.ok(krGovernanceCheckDefinitions.every(item=>item.sourceUrl.startsWith('https://www.law.go.kr/')));
 assert.deepEqual(krGovernanceCheckDefinitions.filter(item=>item.supplierReliance).map(item=>item.requirementId),['KR-34-RISK','KR-34-EXPLAIN','KR-34-PROTECT']);
});

for(const type of Object.keys(samples))test(`${type}: scoped measurement and retrievable document support a human review without issuing a legal verdict`,()=>{
 const h=fixture(type),beforeHuman=structuredClone(h.assessment),observed=result(h);
 assert.equal(observed.supportsHumanAssessment,true);
 assert.equal(observed.status,'authenticated_reported_measurement_supported');
 assert.equal(observed.automaticLegalVerdict,false);
 assert.equal(observed.measurementTrust,'authenticated_reported_measurement_not_independent_truth');
 assert.ok(observed.limitations.some(item=>/진실성/.test(item)));
 assert.deepEqual(h.assessment,beforeHuman);
});

test('strict normalization rejects unknown fields, wrong requirement, malformed hashes and misleading metric types',()=>{
 const h=fixture('generated_output_marking');
 for(const altered of [{...h.check,compliancePassed:true},{...h.check,schemaVersion:2},{...h.check,requirementId:'KR-31-1'},{...h.check,documentHash:'f'.repeat(63)},{...h.check,checkType:'invented'}, {...h.check,result:'approved'}, {...h.check,measurements:{...h.check.measurements,outputCount:'24'}},{...h.check,measurements:{...h.check.measurements,unreviewed:true}},{...h.check,measurements:{...h.check.measurements,markedOutputCount:25}}])assert.throws(()=>normalizeGovernanceCheck(altered),error=>error.status===400);
 const missing=structuredClone(h.check);delete missing.measurements.perceptibilityTestPassed;
 assert.throws(()=>normalizeGovernanceCheck(missing),error=>error.status===400);
});

test('normalization rejects invalid calendar dates and duplicate or invented document sections',()=>{
 const h=fixture('notice_pre_delivery');
 for(const value of ['2026-02-30T00:00:00.000Z','2026-13-01T00:00:00.000Z','2026-10-01T24:00:00.000Z','not a date'])assert.throws(()=>normalizeGovernanceCheck({...h.check,measurements:{...h.check.measurements,noticeAt:value}}),error=>error.status===400);
 const doc=fixture('document_publication_retention');
 for(const sections of [['risk_management','risk_management'],['invented']])assert.throws(()=>normalizeGovernanceCheck({...doc.check,measurements:{...doc.check.measurements,publishedSections:sections}}),error=>error.status===400);
 assert.throws(()=>normalizeGovernanceCheck({...doc.check,measurements:{...doc.check.measurements,excludedSections:['risk_management']}}),error=>error.status===400);
});

test('self-attestation, external hashes and supplier bundles cannot stand in for typed measured evidence',()=>{
 for(const type of ['attestation','test','document']){
  const h=fixture('high_impact_risk_management');h.assessment.evidence=[{type,ref:'unfetched://claim',version:'1',contentHash:h.document.contentHash}];negative(h,/typed_measurement_missing/);
 }
 const h=fixture('high_impact_risk_management');h.document.ref='supplier-bundle:all-measures';h.document.verification='supplier_bundle_verified_at_assessment';negative(h,/matching_verified_document_missing/);
});

test('the document must have a validated retrieval snapshot and the exact measured content hash',()=>{
 for(const field of ['contentHash','documentSnapshotHash','version','verification']){
  const h=fixture('user_protection');h.document[field]=field==='version'?'unknown':field==='verification'?'human_supplied_reference_not_fetched':'a'.repeat(63);negative(h,/matching_verified_document_missing/);
 }
 const h=fixture('user_protection');h.check.documentHash=digest('different document');reseal(h);negative(h,/matching_verified_document_missing/);
 for(const ref of ['unfetched://claim','supplier-bundle:claim','governance-document:']){const external=fixture('user_protection');external.document.ref=ref;negative(external,/matching_verified_document_missing/);}
});

test('changed purpose, requirement text, model or policy invalidates even a freshly rehashed collector snapshot',()=>{
 const changedPurpose=fixture('high_impact_risk_management');changedPurpose.system.purpose='Debt collection';negative(changedPurpose,/system_facts_hash_mismatch/);
 const changedLaw=fixture('high_impact_risk_management');changedLaw.requirement.title='Changed legal content';negative(changedLaw,/requirement_version_hash_mismatch/);
 for(const field of ['systemId','modelId','modelVersion','policyVersion']){
  const h=fixture('high_impact_risk_management');h.event.eventSnapshot[field]='other';reseal(h);negative(h,/system_model_or_policy_mismatch/);
 }
});

test('agent claims, unsigned copied snapshots, stale records and failed or inconclusive measurements remain insufficient',()=>{
 const agent=fixture('explanation_plan');agent.event.eventSnapshot.sourceKind='agent';reseal(agent);negative(agent,/unauthorised_check_source/);
 const unsigned=fixture('explanation_plan');unsigned.event.eventSnapshot.governanceCheck.measurements.finalResultExplanationRecorded=false;negative(unsigned,/event_snapshot_unverified/);
 for(const stale of ['documentStale','eventStale'])assert.equal(result(fixture('explanation_plan'),{[stale]:true}).supportsHumanAssessment,false);
 for(const value of ['fail','inconclusive']){const h=fixture('explanation_plan');h.check.result=value;reseal(h);negative(h,new RegExp('reported_check_'+value));}
 const absentTime=fixture('explanation_plan');delete absentTime.event.eventSnapshot.occurredAt;reseal(absentTime);negative(absentTime,/check_time_missing/);
});

test('linking a later good check does not silently erase a selected failed check',()=>{
 const h=fixture('explanation_plan'),failed=structuredClone(h.event);failed.ref='collector/failed-check';failed.eventSnapshot.governanceCheck.result='fail';failed.eventSnapshotHash=digest(failed.eventSnapshot);h.assessment.evidence.push(failed);negative(h,/reported_check_fail/);
});

for(const [type,first,last] of [['notice_pre_delivery','noticeAt','providedAt'],['high_impact_pre_review','reviewedAt','providedAt'],['impact_assessment','evaluatedAt','providedAt'],['impact_effort','effortAt','providedAt'],['certification_effort','effortAt','providedAt']])test(`${type}: unknown clocks, overlapping intervals, equality and actual late action do not prove prior action`,()=>{
 for(const transform of [m=>m[first+'UncertaintyMs']='unknown',m=>m[last+'UncertaintyMs']='unknown',m=>{m[last]=m[first];},m=>{m[first]=m[last];},m=>{m[first]=after;m[last]=before;},m=>{m[last]='2026-10-01T00:00:00.100Z';m[first+'UncertaintyMs']=100;m[last+'UncertaintyMs']=100;}]){
  const h=fixture(type);transform(h.check.measurements);reseal(h);negative(h,/time_order_uncertain|not_proven_before_provision/);
 }
});

test('machine-readable marking additionally requires detection and a generation notice, while human-readable marking requires perceptibility',()=>{
 const h=fixture('generated_output_marking');Object.assign(h.check.measurements,{markingMode:'machine_readable',machineDetectionTestPassed:true,generationNoticeProvided:false});reseal(h);negative(h,/generationNoticeProvided/);
 h.check.measurements.generationNoticeProvided=true;reseal(h);assert.equal(result(h).supportsHumanAssessment,true);
 h.check.measurements.markedOutputCount=23;reseal(h);negative(h,/unmarked/);
 const visible=fixture('generated_output_marking');visible.check.measurements.perceptibilityTestPassed=false;reseal(visible);negative(visible,/perceptibilityTestPassed/);
});

test('realistic media tests must cover disclosed outputs, user conditions and accessibility; creative mode preserves enjoyment',()=>{
 for(const [field,value] of [['disclosedOutputCount',11],['userConditionsConsidered',false],['accessibilityTestPassed',false]]){const h=fixture('realistic_media_disclosure');h.check.measurements[field]=value;reseal(h);negative(h);}
 const h=fixture('realistic_media_disclosure');h.check.measurements.creativeExpression=true;reseal(h);negative(h,/enjoymentPreserved/);h.check.measurements.enjoymentPreserved=true;reseal(h);assert.equal(result(h).supportsHumanAssessment,true);
});

test('authority receipts cannot be replaced by telemetry export records or an unaccepted submission',()=>{
 for(const type of ['safety_submission_receipt','domestic_representative','authority_order_response']){
  const h=fixture(type);h.event.eventSnapshot.sourceKind='telemetry';reseal(h);negative(h,/authority_receipt_source_required/);
 }
 const h=fixture('safety_submission_receipt');h.check.measurements.submissionAccepted=false;reseal(h);negative(h,/submissionAccepted/);
 for(const receiptId of ['unknown','not_recorded',' ',''])assert.throws(()=>normalizeGovernanceCheck({...h.check,measurements:{...h.check.measurements,receiptId}}),error=>error.status===400);
});

test('a completed pre-review stays supported when an optional confirmation request has no receipt',()=>{
 const h=fixture('high_impact_pre_review'),original=structuredClone(h.assessment);
 assert.equal(result(h).optionalWorkflows[0].status,'not_requested');
 h.check.measurements.confirmationRequested=true;reseal(h);
 const observed=result(h);assert.equal(observed.supportsHumanAssessment,true);assert.deepEqual(observed.missingChecks,[]);
 assert.deepEqual(observed.matchedChecks.map(item=>item.checkType),['high_impact_pre_review']);
 assert.equal(observed.optionalWorkflows[0].required,false);assert.equal(observed.optionalWorkflows[0].status,'request_receipt_missing');
 assert.equal(observed.optionalWorkflows[0].supportsRequestReceipt,false);
 assert.deepEqual(observed.optionalWorkflows[0].missingChecks,['high_impact_confirmation']);
 assert.deepEqual(result(h),observed);assert.equal(original.evidence[1].eventSnapshot.governanceCheck.measurements.confirmationRequested,false);
});

test('optional request evidence remains independently insufficient for failed, unauthenticated or mismatched receipts',()=>{
 for(const [name,mutate,pattern] of [
  ['attachments',h=>h.check.measurements.attachments=['product_overview'],/sections_missing:attachments/],
  ['unaccepted',h=>h.check.measurements.requestAccepted=false,/requestAccepted/],
  ['failure',h=>h.check.result='fail',/reported_check_fail/],
  ['future',h=>h.check.measurements.requestedAt='2099-01-01T00:00:00.000Z',/completed_measurement_after_observation:requestedAt/],
  ['clock',h=>h.event.eventSnapshot.clockUncertaintyMs='unknown',/observation_clock_uncertain/],
  ['source',h=>h.event.eventSnapshot.sourceKind='telemetry',/authority_receipt_source_required/],
  ['model',h=>h.event.eventSnapshot.modelVersion='other',/system_model_or_policy_mismatch/],
  ['facts',h=>h.check.systemHash=digest('other facts'),/system_facts_hash_mismatch/],
  ['law',h=>h.check.requirementHash=digest('other law'),/requirement_version_hash_mismatch/],
  ['document',h=>h.check.documentHash=digest('other document'),/matching_verified_document_missing/],
  ['malformed',h=>h.check.measurements.requestAccepted='true',/invalid_typed_check/],
 ]){
  const h=fixture('high_impact_confirmation');mutate(h);reseal(h);const observed=result(h);
  assert.equal(observed.supportsHumanAssessment,true,name);assert.deepEqual(observed.reasons,[],name);
  const workflow=observed.optionalWorkflows[0];assert.equal(workflow.status,'request_evidence_insufficient',name);assert.equal(workflow.supportsRequestReceipt,false,name);assert.match(workflow.reasons.join(' '),pattern,name);
 }
 const unsigned=fixture('high_impact_confirmation');unsigned.check.measurements.requestAccepted=false;
 assert.match(result(unsigned).optionalWorkflows[0].reasons.join(' '),/event_snapshot_unverified/);
 const valid=fixture('high_impact_confirmation');const receipt=result(valid).optionalWorkflows[0];
 assert.equal(receipt.status,'request_receipt_supported');assert.equal(receipt.supportsRequestReceipt,true);assert.equal(receipt.matchedChecks[0].checkType,'high_impact_confirmation');
 const failed=structuredClone(valid.event);failed.ref='authority/failed-request';failed.eventSnapshot.governanceCheck.result='fail';failed.eventSnapshotHash=digest(failed.eventSnapshot);valid.assessment.evidence.push(failed);
 assert.equal(result(valid).supportsHumanAssessment,true);assert.equal(result(valid).optionalWorkflows[0].supportsRequestReceipt,false,'a later good receipt does not erase a linked failed request');
});

test('confirmation never replaces missing, contradictory, late or stale mandatory pre-review evidence',()=>{
 const absent=fixture('high_impact_confirmation');absent.assessment.evidence=absent.assessment.evidence.filter(item=>item.eventSnapshot?.governanceCheck?.checkType!=='high_impact_pre_review');negative(absent,/high_impact_pre_review/);
 assert.equal(result(absent).optionalWorkflows[0].supportsRequestReceipt,true);
 for(const mutate of [h=>h.check.result='fail',h=>h.check.measurements.reviewedAt=after,h=>h.check.measurements.conclusionRecorded=false]){
  const h=fixture('high_impact_pre_review');h.assessment.evidence.push(fixture('high_impact_confirmation').event);mutate(h);reseal(h);negative(h);
 }
 const conflicting=fixture('high_impact_pre_review'),failed=structuredClone(conflicting.event);failed.eventSnapshot.governanceCheck.result='fail';failed.eventSnapshotHash=digest(failed.eventSnapshot);conflicting.assessment.evidence.push(failed);negative(conflicting,/reported_check_fail/);
 for(const flag of ['documentStale','eventStale'])assert.equal(result(fixture('high_impact_confirmation'),{[flag]:true}).supportsHumanAssessment,false);
 assert.equal(result(fixture('explanation_plan')).optionalWorkflows,undefined,'other requirement response shapes stay unchanged');
});

test('document publication covers four items, confines exclusions to recorded grounds and tests five-year policy, access and restore',()=>{
 for(const mutate of [m=>m.retentionYears=4,m=>m.restoreTestPassed=false,m=>m.accessControlTestPassed=false,m=>m.publishedSections=['risk_management','explanation','user_protection']]){
  const h=fixture('document_publication_retention');mutate(h.check.measurements);reseal(h);negative(h);
 }
 const h=fixture('document_publication_retention');h.check.measurements.publishedSections.pop();h.check.measurements.excludedSections=['oversight_name_contact'];reseal(h);negative(h,/exclusionBasisRecorded/);
 h.check.measurements.exclusionBasisRecorded=true;reseal(h);assert.equal(result(h).supportsHumanAssessment,true);
 assert.ok(result(h).limitations.some(item=>/5년.*실적/.test(item)));
});

test('impact assessment includes six unconditional areas, conditional improvement plan and vulnerable group characteristics',()=>{
 const h=fixture('impact_assessment');h.check.measurements.sections=h.check.measurements.sections.filter(item=>item!=='usage_patterns');reseal(h);negative(h,/sections_missing/);
 const vulnerable=fixture('impact_assessment');vulnerable.check.measurements.vulnerableGroupsConsidered=false;reseal(vulnerable);negative(vulnerable,/vulnerableGroupsConsidered/);
 const improvement=fixture('impact_assessment');improvement.check.measurements.improvementPlanRecorded=false;reseal(improvement);negative(improvement,/improvementPlanRecorded/);
 improvement.check.measurements.improvementsRequired=false;improvement.check.measurements.sections=improvement.check.measurements.sections.filter(item=>item!=='improvement_plan');reseal(improvement);assert.equal(result(improvement).supportsHumanAssessment,true);
});

test('documented pre-provision efforts are explicitly supported without claiming completed impact assessment or certification',()=>{
 for(const type of ['impact_effort','certification_effort']){
  const h=fixture(type),observed=result(h);assert.equal(observed.supportsHumanAssessment,true);assert.equal(observed.matchedChecks[0].effortOnly,true);assert.ok(observed.limitations.some(item=>/노력 기록.*완료/.test(item)));
 }
 const h=fixture('certification_effort');h.check.measurements.nextPlanRecorded=false;reseal(h);negative(h,/nextPlanRecorded/);
});

test('public preference needs an actual recorded comparison and rationale rather than assuming all institutions selected a certified product',()=>{
 for(const type of ['public_impact_preference','public_certification_preference']){
  for(const field of ['publicInstitutionConfirmed','candidateComparisonRecorded','selectionReasonRecorded']){const h=fixture(type);h.check.measurements[field]=false;reseal(h);negative(h,new RegExp(field));}
 }
});

test('oversight needs its explicit plan measurement plus an authority human reviewer for the same model and policy',()=>{
 for(const reviewer of ['unknown','not_recorded','not_provided','   ','미확인','알 수 없음','없음','N/A','ｕｎｋｎｏｗｎ','unknown\u200b','\u200b']){const h=fixture('oversight_plan');h.assessment.evidence[2]=oversightEvent(h.system,reviewer);negative(h,/human_oversight_review/);}
 for(const mutate of [s=>s.kind='human_approval',s=>s.kind='automated_review',s=>s.sourceKind='telemetry',s=>s.modelVersion='v1',s=>s.policyVersion='other',s=>delete s.occurredAt]){
  const h=fixture('oversight_plan'),review=h.assessment.evidence[2];mutate(review.eventSnapshot);review.eventSnapshotHash=digest(review.eventSnapshot);negative(h,/human_oversight_review/);
 }
 const unrelated=fixture('oversight_plan');unrelated.assessment.evidence.splice(1,1);negative(unrelated,/oversight_plan/);
 const incomplete=fixture('oversight_plan');incomplete.check.measurements.sections=['contact'];reseal(incomplete);negative(incomplete,/sections_missing/);
});

test('domestic representative support requires a written mandate including current document review and a domestic presence',()=>{
 for(const mutate of [m=>m.writtenDesignationRecorded=false,m=>m.domesticAddressOrOfficeVerified=false,m=>m.notificationAccepted=false,m=>m.mandate=['safety_submission','high_impact_confirmation']]){
  const h=fixture('domestic_representative');mutate(h.check.measurements);reseal(h);negative(h);
 }
});

test('actual order response requires specified measures, implementation, acceptance and the recorded response deadline',()=>{
 for(const mutate of [m=>m.requestedMeasures=[],m=>m.requestedMeasuresCovered=false,m=>m.implementationRecorded=false,m=>m.responseAccepted=false,m=>m.responseAt='2026-10-04T00:00:00.000Z',m=>m.responseAt='2026-09-30T00:00:00.000Z']){
  const h=fixture('authority_order_response');mutate(h.check.measurements);reseal(h);negative(h);
 }
});

test('unknown and non-Korean requirements never receive a fabricated technical success',()=>{
 for(const id of ['KR-UNIMPLEMENTED','EU-50-1','NIST-GOVERN']){
  const observed=evaluateKrGovernanceEvidence({id},{assessment:'sufficient',evidence:[{type:'attestation',ref:'claim'}]});assert.equal(observed.supportsHumanAssessment,false);assert.equal(observed.status,'unsupported_requirement');
 }
});

test('every reported completed action or receipt rejects a future measurement despite matching hashes and pass result',()=>{
 for(const [type,field] of [['notice_pre_delivery','noticeAt'],['safety_submission_receipt','acceptedAt'],['high_impact_pre_review','reviewedAt'],['high_impact_confirmation','requestedAt'],['impact_assessment','evaluatedAt'],['impact_effort','effortAt'],['certification_effort','effortAt'],['domestic_representative','acceptedAt'],['authority_order_response','orderReceivedAt'],['authority_order_response','responseAt']]){
  const h=fixture(type);h.check.measurements[field]='2099-01-01T00:00:00.000Z';reseal(h);
  if(type==='high_impact_confirmation'){assert.equal(result(h).supportsHumanAssessment,true);assert.equal(result(h).optionalWorkflows[0].supportsRequestReceipt,false);assert.match(result(h).optionalWorkflows[0].reasons.join(' '),/completed_measurement_after_observation:requestedAt/);}
  else negative(h,new RegExp('completed_measurement_after_observation:'+field));
 }
});

test('future provision and deadline are planned boundaries and never prove actual provision or business results',()=>{
 for(const type of ['notice_pre_delivery','high_impact_pre_review','impact_assessment','impact_effort','certification_effort']){
  const h=fixture(type);h.system.providedAt='2099-01-01T00:00:00.000Z';h.check.systemHash=digest(h.system);h.check.measurements.providedAt=h.system.providedAt;reseal(h);const observed=result(h);assert.equal(observed.supportsHumanAssessment,true,type);assert.match(observed.limitations.join(' '),/미래 값은 예정 경계로만/);assert.match(observed.limitations.join(' '),/별도 운영 기록과 대조/);
 }
 const h=fixture('authority_order_response');h.check.measurements.deadline='2099-01-01T00:00:00.000Z';reseal(h);assert.equal(result(h).supportsHumanAssessment,true);
});

test('fixed receipt times and explicit observation clocks are required for completed timestamp claims',()=>{
 for(const mutate of [snapshot=>delete snapshot.receivedAt,snapshot=>snapshot.receivedAt='unknown',snapshot=>snapshot.receivedAt='2026-02-30T00:00:00.000Z']){const h=fixture('safety_submission_receipt');mutate(h.event.eventSnapshot);reseal(h);negative(h,/fixed_receipt_time_missing/);}
 for(const clock of ['unknown',undefined,-1,300001,Infinity]){const h=fixture('safety_submission_receipt');h.event.eventSnapshot.clockUncertaintyMs=clock;reseal(h);negative(h,/observation_clock_uncertain/);}
 const h=fixture('notice_pre_delivery');h.check.measurements.noticeAtUncertaintyMs='unknown';reseal(h);negative(h,/completed_measurement_clock_uncertain:noticeAt/);
 for(const type of ['explanation_plan','generated_output_marking','document_publication_retention']){const g=fixture(type);g.event.eventSnapshot.occurredAt='2099-01-01T00:00:00.000Z';reseal(g);negative(g,/observation_after_fixed_receipt/);const k=fixture(type);k.event.eventSnapshot.clockUncertaintyMs='unknown';reseal(k);negative(k,/observation_clock_uncertain/);}
});

test('reported observation cannot precede its impossible future fixed receipt and overlapping clock bounds stay unresolved',()=>{
 const h=fixture('safety_submission_receipt');h.event.eventSnapshot.occurredAt='2026-10-02T00:05:00.000Z';reseal(h);negative(h,/observation_after_fixed_receipt/);
 const g=fixture('safety_submission_receipt');g.event.eventSnapshot.receivedAt=g.event.eventSnapshot.occurredAt;reseal(g);negative(g,/observation_receipt_order_uncertain/);
 const k=fixture('safety_submission_receipt');k.check.measurements.acceptedAt=k.event.eventSnapshot.occurredAt;reseal(k);negative(k,/completed_measurement_order_uncertain:acceptedAt/);
 const exact=fixture('safety_submission_receipt');exact.event.eventSnapshot.clockUncertaintyMs=0;exact.check.measurements.acceptedAt=exact.event.eventSnapshot.occurredAt;reseal(exact);assert.equal(result(exact).supportsHumanAssessment,true,'equal exact timestamps may record completion and observation in the same millisecond');
});

test('declared completed-time uncertainty cannot conceal a later or overlapping action',()=>{
 const h=fixture('notice_pre_delivery');h.check.measurements.noticeAt='2026-10-02T00:00:00.100Z';h.check.measurements.noticeAtUncertaintyMs=200;h.check.measurements.providedAt='2026-10-03T00:00:00.000Z';reseal(h);negative(h,/completed_measurement_order_uncertain:noticeAt/);
 const g=fixture('notice_pre_delivery');g.check.measurements.noticeAt='2026-10-02T00:00:02.000Z';g.check.measurements.noticeAtUncertaintyMs=0;g.check.measurements.providedAt='2026-10-03T00:00:00.000Z';reseal(g);negative(g,/completed_measurement_after_observation:noticeAt/);
});

test('adding a good measurement cannot erase a selected future completion record',()=>{
 const h=fixture('safety_submission_receipt'),future=structuredClone(h.event);future.ref='authority/future-receipt';future.eventSnapshot.governanceCheck.measurements.acceptedAt='2099-01-01T00:00:00.000Z';future.eventSnapshotHash=digest(future.eventSnapshot);h.assessment.evidence.push(future);negative(h,/completed_measurement_after_observation:acceptedAt/);
});

test('human oversight reviews with missing fixed receipt, unknown clocks or future observed completion stay missing',()=>{
 for(const mutate of [snapshot=>delete snapshot.receivedAt,snapshot=>snapshot.clockUncertaintyMs='unknown',snapshot=>snapshot.occurredAt='2099-01-01T00:00:00.000Z']){const h=fixture('oversight_plan'),review=h.assessment.evidence.find(item=>item.eventSnapshot?.kind==='human_oversight_review');mutate(review.eventSnapshot);review.eventSnapshotHash=digest(review.eventSnapshot);negative(h,/human_oversight_review/);}
});

test('verification uses the recorded receipt and repeats identically when the current wall clock changes',()=>{
 const h=fixture('safety_submission_receipt'),now=Date.now;let first,second;
 try{Date.now=()=>0;first=result(h);Date.now=()=>253402300799999;second=result(h);}finally{Date.now=now;}
 assert.deepEqual(second,first);assert.equal(first.supportsHumanAssessment,true);
});

for(const type of ['notice_pre_delivery','high_impact_pre_review','impact_assessment','impact_effort','certification_effort'])test(`${type}: a matching current system hash cannot hide a changed or unknown registered provision boundary`,()=>{
 const h=fixture(type);h.system.providedAt='2026-10-01T00:00:00.000Z';h.check.systemHash=digest(h.system);h.check.measurements.providedAt='2027-01-01T00:00:00.000Z';const completed=Object.keys(h.check.measurements).find(key=>['noticeAt','reviewedAt','evaluatedAt','effortAt'].includes(key));h.check.measurements[completed]='2026-10-02T00:00:00.000Z';h.event.eventSnapshot.occurredAt='2026-10-03T00:00:00.000Z';h.event.eventSnapshot.receivedAt='2026-10-03T00:00:01.000Z';reseal(h);negative(h,/registered_provision_time_mismatch/);
 for(const providedAt of [undefined,'unknown','not_recorded','', '2026-02-30T00:00:00.000Z','2026/10/01']){const g=fixture(type);g.system.providedAt=providedAt;g.check.systemHash=digest(g.system);reseal(g);negative(g,/registered_provision_time_unknown/);}
});
