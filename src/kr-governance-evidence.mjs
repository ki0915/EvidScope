import {digest} from './crypto.mjs';

// These checks validate authenticated measurements and their evidence bindings.
// They do not read a document's meaning, certify compliance, or independently
// verify the truth of a collector's measurements or an external receipt.
const law=article=>`https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=${String(article).padStart(4,'0')}&lsiSeq=282791&urlMode=lsScJoRltInfoR`;
const decree=article=>`https://www.law.go.kr/LSW/lsSideInfoP.do?docCls=jo&joBrNo=00&joNo=${String(article).padStart(4,'0')}&lsiSeq=288781&urlMode=lsScJoRltInfoR`;
const bool={type:'boolean'},count={type:'integer',min:0,max:1000000},positiveCount={...count,min:1},time={type:'time'},clock={type:'clock'},text={type:'text'};
const section=values=>({type:'sections',values});
const choice=values=>({type:'enum',values});
const beforeFields=(first,last)=>({[first]:time,[last]:time,[first+'UncertaintyMs']:clock,[last+'UncertaintyMs']:clock});
const definition=(requirementId,checkType,title,metrics,sourceUrl,extra={})=>({requirementId,checkType,title,metrics,sourceUrl,required:true,...extra});
const impactSections=['affected_groups','fundamental_rights','social_economic_impact','usage_patterns','indicators_and_method','risk_prevention_mitigation_recovery','improvement_plan'];
const publishedSections=['risk_management','explanation','user_protection','oversight_name_contact'];
function freeze(value){if(value&&typeof value==='object'&&!Object.isFrozen(value)){for(const item of Object.values(value))freeze(item);Object.freeze(value);}return value;}

export const krGovernanceCheckDefinitions=Object.freeze([
 definition('KR-31-1','notice_pre_delivery','사전 고지 전달·시점',{
  ...beforeFields('noticeAt','providedAt'),noticeDelivered:bool,deliveryMethod:choice(['product_or_terms','screen','physical_notice','minister_recognised']),methodBasisRecorded:bool,targetUsersCovered:bool,
 },decree(23)),
 definition('KR-31-2','generated_output_marking','생성형 결과 표시',{
  outputCount:positiveCount,markedOutputCount:count,markingMode:choice(['perceptible','machine_readable']),perceptibilityTestPassed:bool,machineDetectionTestPassed:bool,generationNoticeProvided:bool,
 },decree(23)),
 definition('KR-31-3','realistic_media_disclosure','사실적 합성물 고지·접근성',{
  outputCount:positiveCount,disclosedOutputCount:count,accessibilityTestPassed:bool,userConditionsConsidered:bool,creativeExpression:bool,enjoymentPreserved:bool,
 },decree(23)),
 definition('KR-32-RISK','safety_risk_management','수명주기 안전성 위험관리',{
  lifecycleStages:section(['design','development','deployment','operation','retirement']),riskIdentificationRecorded:bool,riskAssessmentRecorded:bool,mitigationTestPassed:bool,residualRiskReviewed:bool,
 },law(32)),
 definition('KR-32-MONITOR','safety_incident_monitoring','안전사고 모니터링·대응',{
  monitoringScopeRecorded:bool,responseProcedureRecorded:bool,responsibleTeamRecorded:bool,responseExercisePassed:bool,incidentRegisterReviewed:bool,
 },law(32)),
 definition('KR-32-SUBMIT','safety_submission_receipt','안전성 이행자료 외부 제출 접수',{
  implementationResultsIncluded:bool,submissionAccepted:bool,authority:choice(['MSIT']),receiptId:text,acceptedAt:time,
 },law(32),{authorityOnly:true}),
 definition('KR-33','high_impact_pre_review','고영향 해당 여부 사전 검토',{
  ...beforeFields('reviewedAt','providedAt'),domainsReviewed:bool,impactSeverityFrequencyReviewed:bool,domainSpecificityReviewed:bool,conclusionRecorded:bool,confirmationRequested:bool,
 },law(33)),
 definition('KR-33','high_impact_confirmation','선택적 고영향 확인 요청 자료',{
  authority:choice(['MSIT']),requestId:text,requestedAt:time,attachments:section(['product_overview','training_data_overview','process_and_results','other_supporting_material']),requestAccepted:bool,
 },decree(25),{required:false,authorityOnly:true}),
 definition('KR-34-RISK','high_impact_risk_management','고영향 위험관리 운영',{
  riskPolicyRecorded:bool,responsibleOrganisationRecorded:bool,operatingReviewRecorded:bool,mitigationTestPassed:bool,residualRiskReviewed:bool,
 },law(34),{alternativeGroup:'risk_measure'}),
 definition('KR-34-EXPLAIN','explanation_plan','설명 방안 수립·시행',{
  finalResultExplanationRecorded:bool,principalCriteriaRecorded:bool,trainingDataOverviewRecorded:bool,technicalFeasibilityReviewed:bool,explanationDeliveryTestPassed:bool,
 },law(34),{alternativeGroup:'explanation_measure'}),
 definition('KR-34-PROTECT','user_protection','이용자 보호 절차 운영',{
  protectionPolicyRecorded:bool,inquiryProcedureRecorded:bool,objectionProcedureRecorded:bool,damageResponseProcedureRecorded:bool,operatingReviewRecorded:bool,
 },law(34),{alternativeGroup:'protection_measure'}),
 ...[['KR-34-RISK','supplier_risk_reliance','risk_measure'],['KR-34-EXPLAIN','supplier_explanation_reliance','explanation_measure'],['KR-34-PROTECT','supplier_protection_reliance','protection_measure']].map(([requirementId,checkType,alternativeGroup])=>definition(requirementId,checkType,'공급사 조치 활용 근거 검토',{
  supplierBundleRef:text,supplierBundleHash:{type:'hash'},reviewer:text,reviewedAt:time,reviewedAtUncertaintyMs:clock,supplierPerformedMeasureReviewed:bool,fullMeasureScopeReviewed:bool,noSubstantialModificationReviewed:bool,
 },decree(27),{alternativeGroup,authorityOnly:true,supplierReliance:true})),
 definition('KR-34-OVERSIGHT','oversight_plan','사람 감독 계획·운영 시험',{
  sections:section(['responsibility','authority','competence','intervention','contact']),interventionExercisePassed:bool,
 },law(34)),
 definition('KR-34-DOCUMENT','document_publication_retention','조치 근거 보관·게시',{
  measureDocumentInventoryRecorded:bool,retentionYears:{type:'integer',min:0,max:100},accessControlTestPassed:bool,restoreTestPassed:bool,publishedSections:section(publishedSections),excludedSections:section(publishedSections),exclusionBasisRecorded:bool,publicationTestPassed:bool,
 },decree(27)),
 definition('KR-35-IMPACT','impact_assessment','기본권 영향평가 내용',{
  ...beforeFields('evaluatedAt','providedAt'),sections:section(impactSections),vulnerableGroupsConsidered:bool,resultsRecorded:bool,improvementsRequired:bool,improvementPlanRecorded:bool,
 },decree(28),{alternativeGroup:'impact_assessment_or_effort'}),
 definition('KR-35-IMPACT','impact_effort','영향평가 노력·미완료 계획',{
  ...beforeFields('effortAt','providedAt'),effortRecorded:bool,incompleteReasonRecorded:bool,nextEvaluationPlanRecorded:bool,
 },law(35),{alternativeGroup:'impact_assessment_or_effort',effortOnly:true}),
 definition('KR-35-PUBLIC','public_impact_preference','공공 선정 시 영향평가 제품 우선 고려',{
  publicInstitutionConfirmed:bool,candidateComparisonRecorded:bool,evaluatedProductsConsidered:bool,selectionReasonRecorded:bool,
 },law(35)),
 definition('KR-30-EFFORT','certification_effort','고영향 사전 검·인증 노력',{
  ...beforeFields('effortAt','providedAt'),effortRecorded:bool,certificationReceived:bool,certificateScopeReviewed:bool,incompleteReasonRecorded:bool,nextPlanRecorded:bool,
 },law(30),{effortOnly:true}),
 definition('KR-30-PUBLIC','public_certification_preference','공공 선정 시 검·인증 제품 우선 고려',{
  publicInstitutionConfirmed:bool,candidateComparisonRecorded:bool,certifiedProductsConsidered:bool,certificateScopeReviewed:bool,selectionReasonRecorded:bool,
 },law(30)),
 definition('KR-36-REPRESENTATIVE','domestic_representative','서면 국내대리인 지정·신고 접수',{
  writtenDesignationRecorded:bool,domesticAddressOrOfficeVerified:bool,mandate:section(['safety_submission','high_impact_confirmation','obligation_support_document_review']),notificationAccepted:bool,authority:choice(['MSIT']),receiptId:text,acceptedAt:time,
 },law(36),{authorityOnly:true}),
 definition('KR-40-ORDER','authority_order_response','실제 조사·시정 명령 대응',{
  authority:choice(['MSIT']),orderId:text,orderReceivedAt:time,deadline:time,requestedMeasures:section(['submit_materials','investigation_access','stop','correct']),requestedMeasuresCovered:bool,implementationRecorded:bool,responseAccepted:bool,receiptId:text,responseAt:time,
 },law(40),{authorityOnly:true}),
].map(value=>freeze(value)));

const definitionsByType=new Map(krGovernanceCheckDefinitions.map(value=>[value.checkType,value]));
const hash=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
export function knownGovernanceReference(value){
 if(typeof value!=='string'||/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/u.test(value))return false;
 const normalized=value.normalize('NFKC').replace(/[\u200b-\u200d\ufeff]/gu,'').trim().toLowerCase();
 return !!normalized&&!['unknown','not_recorded','not_provided','not recorded','not provided','none','n/a','na','미확인','알 수 없음','없음','미기록','미제공','확인 필요'].includes(normalized);
}
function invalid(message){const error=new TypeError('거버넌스 측정 형식 오류: '+message);error.status=400;throw error;}
function strictObject(value,keys,label){
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.getPrototypeOf(value)!==Object.prototype&&Object.getPrototypeOf(value)!==null)invalid(label+' 객체 필요');
 if(Object.keys(value).length!==keys.length||keys.some(key=>!Object.hasOwn(value,key))||Object.keys(value).some(key=>!keys.includes(key)))invalid(label+' 필드 누락 또는 미지원 필드');
}
function normalizeMetric(value,schema,label){
 switch(schema.type){
  case 'boolean':if(typeof value!=='boolean')invalid(label+' boolean 필요');return value;
  case 'integer':if(!Number.isSafeInteger(value)||value<schema.min||value>schema.max)invalid(label+' 정수 범위 오류');return value;
  case 'clock':if(value!=='unknown'&&(!Number.isSafeInteger(value)||value<0||value>300000))invalid(label+' 시계 오차 범위 오류');return value;
  case 'time':{
   const parts=typeof value==='string'&&/^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.\d{1,3})?(?:Z|[+-]\d\d:\d\d)$/.exec(value);
   if(!parts||!Number.isFinite(Date.parse(value)))invalid(label+' ISO 시각 필요');
   const [,year,month,day,hour,minute,second]=parts.map(Number),days=new Date(Date.UTC(year+400,month,0)).getUTCDate();
   if(month<1||month>12||day<1||day>days||hour>23||minute>59||second>59)invalid(label+' 달력 시각 오류');
   return new Date(value).toISOString();
  }
  case 'text':if(typeof value!=='string'||value.length>200||/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/u.test(value)||!knownGovernanceReference(value))invalid(label+' 실제 참조 필요');return value.trim();
  case 'hash':if(!hash(value))invalid(label+' SHA-256 필요');return value;
  case 'enum':if(!schema.values.includes(value))invalid(label+' 코드 오류');return value;
  case 'sections':if(!Array.isArray(value)||value.length>schema.values.length||new Set(value).size!==value.length||value.some(item=>!schema.values.includes(item)))invalid(label+' 항목 코드 오류');return [...value];
  default:invalid('지원하지 않는 측정 형식');
 }
}

export function normalizeGovernanceCheck(value){
 const keys=['schemaVersion','requirementId','checkType','result','systemHash','requirementHash','documentHash','measurements'];strictObject(value,keys,'governanceCheck');
 const definition=definitionsByType.get(value.checkType);
 if(value.schemaVersion!==1||!definition||value.requirementId!==definition.requirementId||!['pass','fail','inconclusive'].includes(value.result))invalid('버전·조항·측정 종류·결과 코드 오류');
 for(const field of ['systemHash','requirementHash','documentHash'])if(!hash(value[field]))invalid(field+' SHA-256 필요');
 strictObject(value.measurements,Object.keys(definition.metrics),'measurements');
 const measurements={};for(const [key,schema] of Object.entries(definition.metrics))measurements[key]=normalizeMetric(value.measurements[key],schema,key);
 for(const [total,part] of [['outputCount','markedOutputCount'],['outputCount','disclosedOutputCount']])if(Object.hasOwn(measurements,part)&&measurements[part]>measurements[total])invalid(part+' 전체 결과 수 초과');
 if(measurements.publishedSections?.some(item=>measurements.excludedSections.includes(item)))invalid('동일 게시 항목을 게시와 제외로 중복 선언할 수 없음');
 return {...Object.fromEntries(keys.filter(key=>key!=='measurements').map(key=>[key,value[key]])),measurements};
}

function allSections(actual,expected){return expected.every(item=>actual.includes(item));}
function preDelivery(measurements,first,last,reasons){
 const firstClock=measurements[first+'UncertaintyMs'],lastClock=measurements[last+'UncertaintyMs'];
 if(firstClock==='unknown'||lastClock==='unknown'){reasons.push('time_order_uncertain');return;}
 // A strict non-overlap proves "before" only within the declared clock bounds.
 if(Date.parse(measurements[first])+firstClock>=Date.parse(measurements[last])-lastClock)reasons.push('not_proven_before_provision');
}
function observationTimeState(snapshot){
 const reasons=[];let occurredAt,receivedAt;
 try{occurredAt=Date.parse(normalizeMetric(snapshot.occurredAt,time,'occurredAt'));}catch{reasons.push('check_time_missing');}
 try{receivedAt=Date.parse(normalizeMetric(snapshot.receivedAt,time,'receivedAt'));}catch{reasons.push('fixed_receipt_time_missing');}
 const uncertainty=snapshot.clockUncertaintyMs;
 if(!Number.isSafeInteger(uncertainty)||uncertainty<0||uncertainty>300000)reasons.push('observation_clock_uncertain');
 if(!reasons.length&&occurredAt+uncertainty>receivedAt)reasons.push(occurredAt-uncertainty>receivedAt?'observation_after_fixed_receipt':'observation_receipt_order_uncertain');
 return {reasons,occurredAt,receivedAt,uncertainty};
}
function completedMeasurementTimeReasons(check,snapshot){
 // Provision and deadline may be future planned boundaries. Every other time
 // field claims an action or receipt has already happened, within the declared
 // clock bounds and no later than this immutable observation/receipt. Never
 // replace missing historical receipt times with the verifier's wall clock.
 const fields=Object.entries(definitionsByType.get(check.checkType).metrics).filter(([name,schema])=>schema.type==='time'&&!['providedAt','deadline'].includes(name)).map(([name])=>name);
 const observation=observationTimeState(snapshot),reasons=[...observation.reasons];
 for(const field of fields){
  const ownClock=field+'UncertaintyMs',uncertainty=Object.hasOwn(check.measurements,ownClock)?check.measurements[ownClock]:observation.uncertainty;
  if(!Number.isSafeInteger(uncertainty)||uncertainty<0||uncertainty>300000){reasons.push('completed_measurement_clock_uncertain:'+field);continue;}
  if(observation.reasons.length)continue;
  const at=Date.parse(check.measurements[field]),earliest=at-uncertainty,latest=at+uncertainty;
  if(earliest>observation.occurredAt+observation.uncertainty||earliest>observation.receivedAt)reasons.push('completed_measurement_after_observation:'+field);
  else if(latest>observation.occurredAt-observation.uncertainty||latest>observation.receivedAt)reasons.push('completed_measurement_order_uncertain:'+field);
 }
 return reasons;
}
function registeredProvisionTimeReasons(check,system){
 if(!Object.hasOwn(check.measurements,'providedAt'))return [];
 let registered;try{registered=normalizeMetric(system?.providedAt,time,'system.providedAt');}catch{return ['registered_provision_time_unknown'];}
 return check.measurements.providedAt===registered?[]:['registered_provision_time_mismatch'];
}
function measurementReasons(check){
 const m=check.measurements,reasons=[];
 const need=(field)=>{if(m[field]!==true)reasons.push('measurement_not_passed:'+field);};
 const sections=(field,values)=>{if(!allSections(m[field],values))reasons.push('sections_missing:'+field);};
 switch(check.checkType){
  case 'notice_pre_delivery':preDelivery(m,'noticeAt','providedAt',reasons);for(const key of ['noticeDelivered','targetUsersCovered'])need(key);if(m.deliveryMethod==='minister_recognised')need('methodBasisRecorded');break;
  case 'generated_output_marking':if(m.markedOutputCount!==m.outputCount)reasons.push('some_tested_outputs_unmarked');if(m.markingMode==='machine_readable'){need('machineDetectionTestPassed');need('generationNoticeProvided');}else need('perceptibilityTestPassed');break;
  case 'realistic_media_disclosure':if(m.disclosedOutputCount!==m.outputCount)reasons.push('some_tested_outputs_undisclosed');need('accessibilityTestPassed');need('userConditionsConsidered');if(m.creativeExpression)need('enjoymentPreserved');break;
  case 'safety_risk_management':sections('lifecycleStages',['design','development','deployment','operation','retirement']);for(const key of ['riskIdentificationRecorded','riskAssessmentRecorded','mitigationTestPassed','residualRiskReviewed'])need(key);break;
  case 'safety_incident_monitoring':for(const key of Object.keys(m))need(key);break;
  case 'safety_submission_receipt':need('implementationResultsIncluded');need('submissionAccepted');break;
  case 'high_impact_pre_review':preDelivery(m,'reviewedAt','providedAt',reasons);for(const key of ['domainsReviewed','impactSeverityFrequencyReviewed','domainSpecificityReviewed','conclusionRecorded'])need(key);break;
  case 'high_impact_confirmation':sections('attachments',['product_overview','training_data_overview','process_and_results','other_supporting_material']);need('requestAccepted');break;
  case 'high_impact_risk_management':case 'explanation_plan':case 'user_protection':for(const key of Object.keys(m))need(key);break;
  case 'supplier_risk_reliance':case 'supplier_explanation_reliance':case 'supplier_protection_reliance':for(const key of ['supplierPerformedMeasureReviewed','fullMeasureScopeReviewed','noSubstantialModificationReviewed'])need(key);break;
  case 'oversight_plan':sections('sections',['responsibility','authority','competence','intervention','contact']);need('interventionExercisePassed');break;
  case 'document_publication_retention':for(const key of ['measureDocumentInventoryRecorded','accessControlTestPassed','restoreTestPassed'])need(key);if(m.retentionYears<5)reasons.push('retention_below_five_years');if(!allSections([...m.publishedSections,...m.excludedSections],publishedSections))reasons.push('publication_scope_incomplete');if(m.excludedSections.length)need('exclusionBasisRecorded');if(m.publishedSections.length)need('publicationTestPassed');break;
  case 'impact_assessment':preDelivery(m,'evaluatedAt','providedAt',reasons);sections('sections',m.improvementsRequired?impactSections:impactSections.filter(item=>item!=='improvement_plan'));need('vulnerableGroupsConsidered');need('resultsRecorded');if(m.improvementsRequired)need('improvementPlanRecorded');break;
  case 'impact_effort':preDelivery(m,'effortAt','providedAt',reasons);for(const key of ['effortRecorded','incompleteReasonRecorded','nextEvaluationPlanRecorded'])need(key);break;
  case 'public_impact_preference':case 'public_certification_preference':for(const key of Object.keys(m))need(key);break;
  case 'certification_effort':preDelivery(m,'effortAt','providedAt',reasons);need('effortRecorded');if(m.certificationReceived)need('certificateScopeReviewed');else{need('incompleteReasonRecorded');need('nextPlanRecorded');}break;
  case 'domestic_representative':need('writtenDesignationRecorded');need('domesticAddressOrOfficeVerified');sections('mandate',['safety_submission','high_impact_confirmation','obligation_support_document_review']);need('notificationAccepted');break;
  case 'authority_order_response':if(!m.requestedMeasures.length)reasons.push('order_measures_missing');for(const key of ['requestedMeasuresCovered','implementationRecorded','responseAccepted'])need(key);if(Date.parse(m.orderReceivedAt)>Date.parse(m.responseAt)||Date.parse(m.responseAt)>Date.parse(m.deadline))reasons.push('order_response_time_out_of_range');break;
  default:reasons.push('unsupported_check_type');
 }
 return reasons;
}

const limitations=[
 '출처 인증·원장·파일 검증과 측정값의 관계를 검증합니다. 측정값·문서 내용·정부 접수 보고의 진실성을 독립적으로 보증하지 않습니다.',
 '시험에 포함된 범위의 보고된 결과이며 서비스의 전체 이용자·출력을 시험하거나 법적 충분성·준수·인증을 자동 판정하지 않습니다.',
 '노력 기록은 완료된 검·인증이나 영향평가가 아니며, 내부 업무·영업비밀 등 법률 예외와 공급사 간주는 사람이 별도로 검토합니다.',
 '5년 보관 정책·복구 시험은 경과한 5년의 보존 실적을 입증하지 않습니다. 자연어 문서의 내용 충분성과 적용성은 사람의 판단입니다.',
 'providedAt·deadline의 미래 값은 예정 경계로만 사용합니다. 실제 제품·서비스 제공과 업무 결과는 별도 운영 기록과 대조해야 합니다.',
];
function matchingScope(snapshot,system){
 return !!system&&snapshot.systemId===system.id&&['modelId','modelVersion','policyVersion'].every(field=>knownGovernanceReference(system[field])&&snapshot[field]===system[field]);
}
function verifiedSnapshot(evidence){
 return evidence.type==='event'&&evidence.verification==='linked_verified_minimized_record'&&hash(evidence.contentHash)&&evidence.eventSnapshot&&evidence.eventSnapshotHash===digest(evidence.eventSnapshot);
}
function validEventTime(snapshot){try{normalizeMetric(snapshot.occurredAt,time,'occurredAt');return true;}catch{return false;}}

function supplierRelianceReasons(check,snapshot,assessment,system,documentStale){
 const m=check.measurements,reasons=[],bundle=assessment.evidence.find(item=>item.type==='document'&&item.ref===m.supplierBundleRef&&item.ref.startsWith('supplier-bundle:')&&item.ref.length>'supplier-bundle:'.length);
 if(!bundle||bundle.contentHash!==m.supplierBundleHash||!hash(bundle.contentHash))reasons.push('supplier_bundle_binding_missing');
 // Service intake permits a sufficient supplier assessment only after checking
 // measure coverage, current model/purpose, and every retained supplier file.
 // Its snapshot stores the verified manifest hash, not per-file metadata; use
 // that exact hash and let the existing current-document stale check revalidate.
 if(documentStale||bundle?.verification!=='supplier_bundle_verified_at_assessment'||assessment.assessment!=='sufficient')reasons.push('supplier_scope_not_verified');
 if(check.documentHash!==m.supplierBundleHash)reasons.push('supplier_manifest_hash_mismatch');
 if(!knownGovernanceReference(snapshot.reviewer)||snapshot.reviewer!==m.reviewer)reasons.push('supplier_reviewer_binding_missing');
 if(system?.aiBusinessOperator!==true||!(system.krRoles||[]).includes('deployer')||system.substantialModification!==false)reasons.push('supplier_role_or_change_unconfirmed');
 if(!['supplierId','purpose','suppliedPurpose','suppliedModelVersion'].every(field=>knownGovernanceReference(system?.[field]))||system.suppliedPurpose!==system.purpose||system.suppliedModelVersion!==system.modelVersion)reasons.push('original_supplier_scope_unconfirmed');
 return reasons;
}

export function evaluateKrGovernanceEvidence(requirement,assessment,{system,documentStale=false,eventStale=false}={}){
 const definitions=krGovernanceCheckDefinitions.filter(item=>item.requirementId===requirement?.id),reasons=[],matchedChecks=[],missingChecks=[];
 if(!definitions.length)return {supportsHumanAssessment:false,status:'unsupported_requirement',missingChecks:[],reasons:['typed_check_definition_missing'],limitations:[...limitations]};
 const evidence=Array.isArray(assessment?.evidence)?assessment.evidence:[];
 const documentHashes=new Set(!documentStale?evidence.filter(item=>item.type==='document'&&typeof item.ref==='string'&&item.ref.startsWith('governance-document:')&&item.ref.length>'governance-document:'.length&&item.verification==='governance_document_verified_at_assessment'&&hash(item.contentHash)&&hash(item.documentSnapshotHash)&&knownGovernanceReference(item.version)).map(item=>item.contentHash):[]);
 if(documentStale)reasons.push('document_evidence_stale');if(eventStale)reasons.push('event_evidence_stale');
 const byType=new Map(),invalidTypes=new Set(),optionalReasons=[];
 for(const item of evidence){
  const snapshot=item.eventSnapshot,raw=snapshot?.governanceCheck;
  if(snapshot?.kind!=='governance_check'||raw?.requirementId!==requirement.id)continue;
  const type=raw.checkType,problems=[];let check;
  try{check=normalizeGovernanceCheck(raw);}catch{problems.push('invalid_typed_check');}
  if(!verifiedSnapshot(item))problems.push('event_snapshot_unverified');
  if(eventStale)problems.push('event_evidence_stale');
  if(!['telemetry','authority'].includes(snapshot.sourceKind))problems.push('unauthorised_check_source');
  if(!validEventTime(snapshot))problems.push('check_time_missing');
  if(!matchingScope(snapshot,system))problems.push('system_model_or_policy_mismatch');
  if(check){
   if(check.systemHash!==digest(system||null))problems.push('system_facts_hash_mismatch');
   if(check.requirementHash!==digest(requirement))problems.push('requirement_version_hash_mismatch');
   const definition=definitionsByType.get(type);
   if(definition.supplierReliance)problems.push(...supplierRelianceReasons(check,snapshot,assessment,system,documentStale));
   else if(!documentHashes.has(check.documentHash))problems.push('matching_verified_document_missing');
   if(definition.authorityOnly&&snapshot.sourceKind!=='authority')problems.push('authority_receipt_source_required');
   if(check.result!=='pass')problems.push('reported_check_'+check.result);
   problems.push(...measurementReasons(check));
   problems.push(...completedMeasurementTimeReasons(check,snapshot));
   problems.push(...registeredProvisionTimeReasons(check,system));
  }
  if(problems.length){invalidTypes.add(type);const target=definitions.some(item=>item.checkType===type&&item.required===false)?optionalReasons:reasons;target.push(...problems.map(reason=>type+':'+reason));}
  else {const list=byType.get(type)||[];list.push({ref:item.ref,check});byType.set(type,list);}
 }
 const required=definitions.filter(item=>item.required&&!item.alternativeGroup).map(item=>[item.checkType]);
 for(const group of new Set(definitions.filter(item=>item.alternativeGroup).map(item=>item.alternativeGroup)))required.push(definitions.filter(item=>item.alternativeGroup===group).map(item=>item.checkType));
 for(const alternatives of required){
  const selected=alternatives.find(type=>byType.has(type)&&!invalidTypes.has(type));
  if(!selected)missingChecks.push(alternatives.join('|'));else matchedChecks.push(...byType.get(selected).map(item=>({checkType:selected,ref:item.ref,documentHash:item.check.documentHash,effortOnly:!!definitionsByType.get(selected).effortOnly,...(definitionsByType.get(selected).supplierReliance?{supplierBundleRef:item.check.measurements.supplierBundleRef,supplierBundleHash:item.check.measurements.supplierBundleHash,reviewer:item.check.measurements.reviewer}:{} )})));
 }
 if(requirement.id==='KR-34-OVERSIGHT'){
  const review=evidence.find(item=>verifiedSnapshot(item)&&!eventStale&&item.eventSnapshot.kind==='human_oversight_review'&&item.eventSnapshot.sourceKind==='authority'&&observationTimeState(item.eventSnapshot).reasons.length===0&&matchingScope(item.eventSnapshot,system)&&knownGovernanceReference(item.eventSnapshot.reviewer));
  if(!review)missingChecks.push('human_oversight_review');else matchedChecks.push({checkType:'human_oversight_review',ref:review.ref,reviewer:review.eventSnapshot.reviewer});
 }
 // Article 33 requires pre-review, but requesting ministerial confirmation is
 // optional. Invalid request evidence blocks that workflow, not the pre-review.
 const optionalWorkflows=definitions.filter(item=>item.required===false).map(definition=>{
  const checks=byType.get(definition.checkType)||[],invalid=invalidTypes.has(definition.checkType),preReviews=byType.get('high_impact_pre_review')||[];
  const requested=checks.length>0||preReviews.some(item=>item.check.measurements.confirmationRequested)?true:preReviews.length>0?false:null;
  const supportsRequestReceipt=checks.length>0&&!invalid&&!documentStale&&!eventStale;
  return {checkType:definition.checkType,required:false,requested,status:invalid?'request_evidence_insufficient':supportsRequestReceipt?'request_receipt_supported':requested===true?'request_receipt_missing':requested===false?'not_requested':'request_state_unknown',supportsRequestReceipt,
   missingChecks:!supportsRequestReceipt&&(requested===true||invalid)?[definition.checkType]:[],reasons:[...new Set(optionalReasons)],
   matchedChecks:checks.map(item=>({checkType:definition.checkType,ref:item.ref,documentHash:item.check.documentHash})),
   limitations:['선택적 요청의 인증된 접수 보고를 검증하며 정부의 회신·고영향 해당 여부 결정 또는 법적 준수를 확정하지 않습니다.']};
 });
 // A contradictory mandatory measurement remains visible. A good later record
 // cannot erase its failure; the same rule applies within optional workflows.
 const blockingInvalid=[...invalidTypes].some(type=>!definitions.some(item=>item.checkType===type&&item.required===false));
 const supported=missingChecks.length===0&&!documentStale&&!eventStale&&!blockingInvalid;
 if(!evidence.some(item=>item.eventSnapshot?.kind==='governance_check'))reasons.push('authenticated_typed_measurement_missing');
 if(!documentHashes.size&&!matchedChecks.some(item=>definitionsByType.get(item.checkType)?.supplierReliance))reasons.push('verified_measure_document_missing');
 return {supportsHumanAssessment:supported,status:supported?'authenticated_reported_measurement_supported':'typed_evidence_insufficient',missingChecks,reasons:[...new Set(reasons)],matchedChecks,measurementTrust:'authenticated_reported_measurement_not_independent_truth',automaticLegalVerdict:false,limitations:[...limitations],...(optionalWorkflows.length?{optionalWorkflows}:{})};
}
