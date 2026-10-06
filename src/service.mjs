import {randomUUID,createPublicKey} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {Store} from './store.mjs';
import {canonical,digest,mac,equal,verifyBundle} from './crypto.mjs';
import {fail,cleanText,identifier,date,validateEvent,validateRule,matches} from './model.mjs';
import {createRetention} from './retention.mjs';
import {createAnalysis} from './analysis.mjs';
import {createAuditWorkbench} from './audit-workbench.mjs';
import {monitoring} from './monitoring.mjs';
import {agentInventory} from './agent-inventory.mjs';
import {createAssistance} from './assistance.mjs';
import {createDevelopmentRuns} from './development-runs.mjs';
import {aiVisibility} from './ai-visibility.mjs';
import {modelRuntimeStatus} from './model-runtime.mjs';
import {normalizeSystemFacts,applicabilityCandidate,applicabilityPolicyVersion,applicabilityAssessmentSnapshot,applicabilityCatalogIdentity} from './governance-policy.mjs';
import {createFinanceEvidence} from './finance-evidence.mjs';
import {createGovernanceDocuments} from './governance-documents.mjs';
import {evaluateKrGovernanceEvidence} from './kr-governance-evidence.mjs';
import {createIdentity} from './identity.mjs';
import {checkObjectProjection} from './object-integrity.mjs';
import {checkEvaluationProjection} from './evaluation-integrity.mjs';
import {checkEventProjection} from './event-integrity.mjs';
import {checkDevelopmentRunProjection} from './development-integrity.mjs';
import {checkDocumentFiles} from './document-integrity.mjs';
import {checkReceiptProjection} from './receipt-integrity.mjs';

export function createService({dataDir,config,key,requirements=[],runtimeReceipt=()=>undefined}) {
 const store=new Store(dataDir,key);const publicKey=createPublicKey(key);const retention=createRetention(store),workbench=createAuditWorkbench(store,key),assistance=createAssistance(store,workbench),developmentRuns=createDevelopmentRuns(store);
 if(typeof runtimeReceipt!=='function')throw Error('Invalid model runtime receipt reader');
 const runtimeStatus=()=>{try{return modelRuntimeStatus({receipt:runtimeReceipt()});}catch{return modelRuntimeStatus();}};
 const principals=config.principals||[];
 const analysis=createAnalysis(store,principals);
 const finance=createFinanceEvidence({store,dataDir,key,requirements,governanceReport:report});
 if(principals.some(p=>!p.id||!p.tenant||!p.token||p.token.length<32)||new Set(principals.map(p=>p.token)).size!==principals.length)throw Error('Invalid credential configuration');
 const identity=createIdentity({config,store});
 const tenants=new Set([...principals,...identity.bindings].map(p=>p.tenant));
 const human=p=>{if(!['auditor','reviewer','admin'].includes(p.role))fail(403,'인간 감사 계정만 접근할 수 있습니다');};
 const reviewer=p=>{if(!['reviewer','admin'].includes(p.role))fail(403,'검토자 권한이 필요합니다');};
 const admin=p=>{if(p.role!=='admin')fail(403,'관리자 권한이 필요합니다');};
 const auth=(headers,method)=>{const session=identity.authenticate(headers,method);if(session)return session;const token=(headers.authorization||'').replace(/^Bearer /,'');const p=principals.find(x=>equal(x.token,token));if(!p||identity.enabled&&['auditor','reviewer','admin'].includes(p.role))fail(401,'인증이 필요합니다');return p;};
 const dirty=(tenant)=>store.projectionMutation(()=>store.db.prepare('UPDATE actions SET version=version+1 WHERE tenant=?').run(tenant));
 const obj=(p,type,id)=>store.get(p.tenant,type,id)||fail(404,'대상을 찾을 수 없습니다');
 // Call inside the mutation transaction, before consuming or re-signing history.
 // Match SQL keys as well as bodies, including missing and injected projection rows.
 function verifiedPolicyObjects(p,type){
  const latest=new Map();
  try{
   for(const row of store.verifiedRows(p.tenant,2*1024*1024)){
    if(row.oversized){
     // verifiedRows hashes oversized records in bounded chunks. A large report
     // must not prevent unrelated policy edits; only target objects need parsing.
     const signedType=store.db.prepare("SELECT json_extract(body,'$.type') AS type FROM ledger WHERE tenant=? AND seq=?").get(p.tenant,row.seq)?.type;
     if(!signedType||signedType===type)fail(413,'정책 검토 객체 한도 초과: 부분 검증으로 변경할 수 없습니다');
     continue;
    }
    if(row.type===type){const id=type==='catalog'?'current':row.payload?.id;if(typeof id!=='string'||!id)fail(409,'정책 서명 원장 식별자가 유효하지 않습니다');latest.set(id,row.payload);}
   }
  }catch(error){if(error?.status)throw error;fail(409,'정책 서명 원장을 검증할 수 없습니다');}
  const rows=store.db.prepare('SELECT id,body FROM objects WHERE tenant=? AND type=?').all(p.tenant,type);
  if(rows.length!==latest.size)fail(409,'정책 조회 사본이 서명 원장과 일치하지 않습니다');
  for(const row of rows){let value;try{value=JSON.parse(row.body);}catch{fail(409,'정책 조회 사본이 서명 원장과 일치하지 않습니다');}if(!latest.has(row.id)||canonical(value)!==canonical(latest.get(row.id)))fail(409,'정책 조회 사본이 서명 원장과 일치하지 않습니다');}
  return latest;
 }
 const policyObject=(p,type,id)=>verifiedPolicyObjects(p,type).get(id)||fail(404,'대상을 찾을 수 없습니다');
 const governanceDocuments=createGovernanceDocuments({store,dataDir,key,getSystem:(p,id)=>policyObject(p,'system',id)});
 function verifiedEvaluations(p){
  const signed=[];
  for(const row of store.verifiedRows(p.tenant,2*1024*1024)){
   if(row.oversized){
    const signedType=store.db.prepare("SELECT json_extract(body,'$.type') AS type FROM ledger WHERE tenant=? AND seq=?").get(p.tenant,row.seq)?.type;
    if(!signedType||signedType==='evaluation')fail(413,'분석 조회 객체 한도 초과: 부분 검증으로 조회할 수 없습니다');
   }else if(row.type==='evaluation')signed.push(row.payload);
  }
  try{checkEvaluationProjection(store.db,p.tenant,signed);}catch{fail(409,'분석 조회 사본이 서명 원장과 일치하지 않습니다');}
  return signed;
 }
 function verifiedActions(p){try{return store.checkActionProjection(p.tenant);}catch(error){const message=error?.message||'';if(/^Event projection|^Event key|^Erased event|^Receipt/.test(message))fail(409,'이벤트 조회 사본·색인 또는 접수 영수증이 서명 원장과 일치하지 않습니다');if(/^Evaluation projection/.test(message))fail(409,'분석 조회 사본이 서명 원장과 일치하지 않습니다');if(/^Object projection/.test(message))fail(409,'객체 조회 사본이 서명 원장과 일치하지 않습니다');fail(409,'행동 상태 조회 사본이 서명 원장과 일치하지 않습니다');}}
 function verifiedEvents(p){try{return store.checkProjection(p.tenant);}catch{fail(409,'이벤트 조회 사본 또는 색인이 서명 원장과 일치하지 않습니다');}}
 const latestEvaluations=values=>{const latest=new Map();for(const value of values)latest.set(value.actionId,value);return latest;};
 function verifiedEventReferences(p){
  const original=store.ledgerEvents(p.tenant);
  try{store.checkProjection(p.tenant,original);}catch{fail(409,'이벤트 조회 사본 또는 색인이 서명 원장과 일치하지 않습니다');}
  return new Map(original.map(event=>[`${event.source}/${event.id}`,event]));
 }
 function technicalEvidenceState(requirement,assessment,{documentStale=false,eventStale=false,system=null}={}){
  if(requirement?.id?.startsWith('KR-')&&assessment?.applicability==='not_applicable'){
   const basisVerified=!documentStale&&assessment.evidence.some(e=>e.type==='document'&&e.verification==='governance_document_verified_at_assessment'&&/^[a-f0-9]{64}$/.test(e.contentHash)&&/^[a-f0-9]{64}$/.test(e.documentSnapshotHash||''));
   return {status:basisVerified?'human_applicability_basis_document_verified':'human_applicability_basis_document_missing',supportsHumanAssessment:basisVerified,missingChecks:basisVerified?[]:['applicability_basis_document'],automaticLegalVerdict:false,limitations:['적용 제외 판단은 사람의 기록입니다. 연결된 근거 문서의 해시·복구 가능 여부만 검증하며 법적 결론의 진실성·충분성을 자동 판정하지 않습니다.']};
  }
  if(requirement?.id?.startsWith('KR-'))return evaluateKrGovernanceEvidence(requirement,assessment,{documentStale,eventStale,system});
  const defaultStatus=assessment?.evidence?.some(e=>e.type==='event')?'event_linked_partial_support':'external_or_missing';
  return {status:defaultStatus,supportsHumanAssessment:true};
 }
 function governanceOrderTargets(assessment){
  return [...new Set((assessment?.evidence||[]).filter(e=>e.type==='event'&&e.eventSnapshot?.kind==='governance_check'&&e.eventSnapshot.governanceCheck?.checkType==='authority_order_response').map(e=>e.eventSnapshot.governanceCheck.measurements.orderId))].map(orderId=>({checkType:'authority_order_response',orderId}));
 }
 const safeObject=x=>{if(!x||typeof x!=='object'||Array.isArray(x))fail(400,'JSON 객체 필요');return x;};
 // Startup is a signed-history migration boundary. Verify every projection used
 // as migration input before changing any tenant, and keep verification and use
 // in one writer-excluding transaction. Otherwise a downgraded SQL copy can be
 // normalized and re-signed as if it were authoritative history on restart.
 try{
  store.transaction(()=>{
   const states=[];
   for(const tenant of tenants){
    const p={id:'startup-governance-initializer',tenant};
    states.push({tenant,p,catalogs:verifiedPolicyObjects(p,'catalog'),systems:verifiedPolicyObjects(p,'system'),assessments:verifiedPolicyObjects(p,'assessment')});
   }
   const identity=applicabilityCatalogIdentity(requirements),hash=identity.hash;
   for(const {tenant,catalogs,systems,assessments} of states){
    const previous=catalogs.get('current');
    if(previous?.hash!==hash){
     const p={id:'catalog-loader',tenant},snapshot={...identity,requirements,createdAt:new Date().toISOString()};store.put(p,'catalog','current',snapshot);
     if(previous)for(const a of assessments.values()){const id=randomUUID();store.put(p,'governance_task',id,{id,systemId:a.systemId,requirementId:a.requirementId,title:'규정 출처/적용 후보 정책 버전 변경에 따른 재검토',owner:a.owner,status:'open',previousHash:previous.hash,currentHash:hash,previousPolicyVersion:previous.policyVersion||'not_recorded',currentPolicyVersion:identity.policyVersion});}
    }
    const p={id:'system-facts-migration-v4',tenant};
    for(const old of systems.values())if((old.schemaVersion||1)<4){
     const upgraded={...normalizeSystemFacts(old),updatedAt:old.updatedAt||new Date().toISOString()};store.put(p,'system',old.id,upgraded);const id=randomUUID();store.put(p,'governance_task',id,{id,systemId:old.id,title:'한국 사업자·공급사·모델 사실 추가: 미확인 항목 검토',owner:old.owner,status:'open',previousSystemHash:digest(old)});
    }
   }
  });
 }catch(error){store.close();throw error;}

 function report(p,systemId){
  return store.transaction(()=>{
  const system=policyObject(p,'system',systemId),assessments=[...verifiedPolicyObjects(p,'assessment').values()].filter(a=>a.systemId===systemId),tasks=[...verifiedPolicyObjects(p,'governance_task').values()].filter(t=>t.systemId===systemId);
  const events=assessments.some(a=>a.evidence.some(e=>e.type==='event'))?verifiedEventReferences(p):new Map();
  const items=requirements.map(requirement=>{
   // verifiedPolicyObjects iterates signed ledger order. Millisecond timestamps
   // can tie, so the last recorded assessment is authoritative for this view.
   const assessment=assessments.filter(a=>a.requirementId===requirement.id).at(-1);
   const applicability=applicabilityCandidate(requirement,system),candidate=applicability.status,currentApplicability=applicabilityAssessmentSnapshot(requirement,system),applicabilityReasons=[];
   if(assessment){
    const saved=assessment.applicabilitySnapshot;
    if(assessment.applicability==='unknown')applicabilityReasons.push('human_applicability_unresolved');
    if(!saved||!assessment.applicabilitySnapshotHash||!assessment.applicabilityPolicyVersion)applicabilityReasons.push('assessment_snapshot_missing');
    else{
     if(assessment.applicabilitySnapshotHash!==digest(saved)||assessment.applicabilityPolicyVersion!==saved.policyVersion||saved.requirementId!==assessment.requirementId||saved.requirementHash!==assessment.requirementHash||saved.systemId!==assessment.systemId||saved.systemHash!==assessment.systemHash)applicabilityReasons.push('assessment_snapshot_invalid');
     if(assessment.applicabilityPolicyVersion!==applicabilityPolicyVersion)applicabilityReasons.push('applicability_policy_version_changed');
     if(assessment.applicabilitySnapshotHash!==currentApplicability.hash)applicabilityReasons.push('applicability_candidate_changed');
    }
   }
   const applicabilityReview={status:applicabilityReasons.length?'review_required':'current',reasons:[...new Set(applicabilityReasons)],assessmentPolicyVersion:assessment?.applicabilityPolicyVersion||'not_recorded',currentPolicyVersion:applicabilityPolicyVersion,assessmentSnapshotHash:assessment?.applicabilitySnapshotHash||'not_recorded',currentSnapshotHash:currentApplicability.hash};
   const missingLinkedEvidence=assessment?.evidence.some(e=>e.type==='event'&&(!events.has(e.ref)||e.verification==='linked_verified_minimized_record'&&e.contentHash!==digest(events.get(e.ref))));
   const documentStale=assessment&&(finance.staleEvidence(p,assessment)||governanceDocuments.staleEvidence(p,assessment)),technical=technicalEvidenceState(requirement,assessment,{documentStale,eventStale:missingLinkedEvidence,system});
   const stale=assessment&&(assessment.requirementHash!==digest(requirement)||assessment.systemHash!==digest(system)||Date.parse(assessment.nextReviewAt)<=Date.now()||missingLinkedEvidence||documentStale||applicabilityReview.status==='review_required');
   const status=!assessment?'evidence_missing':stale?'review_required':assessment.applicability==='not_applicable'?(technical.supportsHumanAssessment?'human_marked_not_applicable':'evidence_insufficient'):assessment.assessment==='sufficient'&&assessment.evidence.length&&technical.supportsHumanAssessment?'human_evidence_assessed':'evidence_insufficient';
   return {requirement,status,applicabilityCandidate:candidate,applicability,applicabilityReview,assessment,technicalStatus:technical.status,technicalEvidence:technical,legalStatus:stale?'review_required':assessment?.legalReview||'pending'};
  });const catalog=applicabilityCatalogIdentity(requirements);return {system,items,tasks,applicabilityPolicyVersion,applicabilityPolicyIdentityHash:catalog.hash,limitations:['법적 적용성은 사실관계와 인간 검토를 요구합니다','증거 평가와 법적 준수 판정은 별개이며 자동 준수 통과를 발급하지 않습니다','한국 고영향과 EU 고위험 분류를 공유하지 않습니다','ISO/IEC 42001 본문 미확보: 조항 매핑 미지원']};
  });
 }
 async function handle(method,url,headers,body=''){
  const path=url.pathname;
  if(path==='/healthz'&&method==='GET'){store.db.prepare('SELECT 1').get();return {status:'ready',component:'vault'};}
  if(path.startsWith('/internal/assistance/')){const result=assistance.internal(method,url,headers,body);if(result!==undefined)return result;}
  const p=auth(headers,method);
  const developmentResult=developmentRuns.handle(p,method,url,headers,body);if(developmentResult!==undefined)return developmentResult;
  if(path==='/api/ingest'&&method==='POST'){
   if(p.role!=='source')fail(403,'수집 출처 자격이 필요합니다');
   const ts=headers['x-evid-timestamp'],nonce=headers['x-evid-nonce'],signature=headers['x-evid-signature'];
   if(!/^\d{13}$/.test(ts||'')||Math.abs(Date.now()-Number(ts))>300000||!nonce||!/^[a-zA-Z0-9-]{16,80}$/.test(nonce))fail(401,'서명 시각 또는 nonce가 유효하지 않습니다');
   if(!p.hmacSecret||!equal(mac(p.hmacSecret,ts,nonce,body),signature||''))fail(401,'출처 서명 검증 실패');
   let raw;try{raw=JSON.parse(body);}catch{fail(400,'JSON 형식 오류');}const e=validateEvent(raw,p);
   return store.transaction(()=>{
    verifiedActions(p);
    store.db.prepare('DELETE FROM nonces WHERE expires<?').run(Date.now());
    if(store.db.prepare('SELECT 1 FROM nonces WHERE source=? AND nonce=?').get(p.id,nonce))fail(409,'이미 사용한 nonce입니다');
    store.db.prepare('INSERT INTO nonces VALUES(?,?,?)').run(p.id,nonce,Date.now()+600000);
    const prev=store.db.prepare('SELECT fingerprint FROM receipts WHERE tenant=? AND source=? AND id=?').get(p.tenant,p.id,e.id);
    if(prev){if(prev.fingerprint!==e.fingerprint)fail(409,'동일 출처 이벤트 ID의 내용 충돌');store.count('duplicates');return {accepted:true,duplicate:true,durability:'sqlite_full_commit',analysis:'asynchronous',externalSeal:false};}
    const backlog=store.db.prepare('SELECT COUNT(*) n FROM actions WHERE analyzed<version').get().n;if(backlog>10000)fail(503,'분석 적체: 유한 재시도 후 로컬 손실 지표를 기록하세요');
    const record=store.append(p.tenant,'event',e,p.id);
    store.append(p.tenant,'event_receipt',{format:'evidscope-event-receipt-v1',basis:'source_ingest',source:e.source,id:e.id,fingerprint:e.fingerprint,eventSeq:record.seq,eventHash:record.hash},p.id);
    store.project({...e,seq:record.seq,hash:record.hash});
    store.projectionMutation(()=>store.db.prepare('INSERT INTO actions(tenant,id,version) VALUES(?,?,1) ON CONFLICT(tenant,id) DO UPDATE SET version=version+1').run(p.tenant,e.actionId));
    store.count('accepted');return {accepted:true,duplicate:false,durability:'sqlite_full_commit',analysis:'asynchronous',externalSeal:false};
   });
  }
  if(path==='/internal/claim'&&method==='POST')return analysis.claim(p);
  if(path==='/internal/complete'&&method==='POST'){let result;try{result=JSON.parse(body);}catch{fail(400,'JSON 형식 오류');}return analysis.commit(p,result);}
  if(path==='/internal/analyze'&&method==='POST'){if(p.role!=='worker')fail(403,'분석 서비스 전용');fail(410,'분산 분석 claim/complete API로 전환되었습니다');}
  human(p);
  if(!path.startsWith('/api/'))fail(404,'경로 없음');
  let x={};if(body){try{x=safeObject(JSON.parse(body));}catch(e){if(e.status)throw e;fail(400,'JSON 객체 필요');}}
  if(method==='GET'&&path!=='/api/integrity')store.audit(p,'read',path);
  const accessResult=identity.access(p,method,path,x);if(accessResult!==undefined)return accessResult;
  if(path.startsWith('/api/governance/')){const documentResult=governanceDocuments.handle(p,method,url,x);if(documentResult!==undefined)return documentResult;const result=finance.handle(p,method,url,x);if(result!==undefined)return result;}
  if(path.startsWith('/api/assistance/')){const result=assistance.human(p,method,url,x);if(result!==undefined)return result;}
  if(path.startsWith('/api/retention')){const result=retention.handle(p,method,path,x);if(result!==undefined)return result;}
  if(path==='/api/investigations'||path.startsWith('/api/cases/')){const result=workbench.handle(p,method,url,x);if(result!==undefined)return result;}
  if(path==='/api/overview'&&method==='GET'){
   return store.transaction(()=>{verifiedActions(p);const evaluations=latestEvaluations(verifiedEvaluations(p)),events=store.db.prepare('SELECT COUNT(*) n FROM events WHERE tenant=?').get(p.tenant).n;
   const actions=store.db.prepare('SELECT * FROM actions WHERE tenant=?').all(p.tenant);
   const alerts=actions.flatMap(a=>evaluations.get(a.id)?.findings||[]);
   const sources=principals.filter(s=>s.tenant===p.tenant&&s.role==='source').map(s=>{const row=store.db.prepare('SELECT MAX(received) lastSeen FROM events WHERE tenant=? AND source=?').get(p.tenant,s.id);return {id:s.id,tenant:s.tenant,kind:s.kind,lastSeen:row.lastSeen,status:!row.lastSeen?'not_connected':Date.now()-Date.parse(row.lastSeen)>300000?'stale':'receiving'};});
   return {counts:{events,alerts:alerts.length,cases:verifiedPolicyObjects(p,'case').size,backlog:actions.filter(a=>a.analyzed<a.version).length},sources,limitations:['등록된 출처 기준 상태이며 전체 AI 사용의 가시성 비율은 산출하지 않습니다','미연결·수집 공백은 무사고를 의미하지 않습니다','연동 수집기는 운영자가 배치·등록해야 하며, 합성 시험 기록을 실제 공급자 연결로 해석하지 않습니다']};});
  }
  if(path==='/api/monitoring'&&method==='GET')return store.transaction(()=>{verifiedEvents(p);return monitoring(store,principals,p.tenant,url.searchParams);});
  if(path==='/api/ai-visibility'&&method==='GET')return store.transaction(()=>{verifiedEvents(p);const registrations=[...verifiedPolicyObjects(p,'asset').values()];return aiVisibility(store,p.tenant,url.searchParams,{runtimeStatus:runtimeStatus(),registrations});});
  if(path==='/api/model-runtime'&&method==='GET')return {...runtimeStatus(),training:{state:'not_evaluated',counts:{tune:null,validation:null,test:null},minimumReviewed:{tune:300,validation:50,test:100},qualityClaimAllowed:false},limitations:['실행 상태는 신뢰된 Kubernetes 관측 영수증이 없거나 30초보다 오래되면 확인 불가로 표시합니다. 기본 비활성 설정은 종료 확인이 아닙니다.','모델 가중치 학습·성능 평가는 별도 실행 보고서로 확인하세요.']};
  if(path==='/api/agents'&&method==='GET')return store.transaction(()=>{verifiedActions(p);verifiedEvaluations(p);const decisions=[...verifiedPolicyObjects(p,'case_decision').values()];return agentInventory(store,principals,p.tenant,url.searchParams,Date.now(),decisions);});
  if(path==='/api/events'&&method==='GET'){
   const q=(url.searchParams.get('q')||'').slice(0,200),kind=url.searchParams.get('kind'),trace=url.searchParams.get('traceId');
   return store.transaction(()=>{verifiedEvents(p);let items=store.events(p.tenant).filter(e=>(!q||canonical(e).includes(q))&&(!kind||e.kind===kind)&&(!trace||e.traceId===trace));const total=items.length;const limit=Math.max(1,Math.min(500,Number(url.searchParams.get('limit'))||100));const offset=Math.max(0,Number(url.searchParams.get('offset'))||0);return {items:items.slice(offset,offset+limit),total,offset,limit};});
  }
  if(path.startsWith('/api/actions/')&&method==='GET'){
   return store.transaction(()=>{verifiedActions(p);const actionId=decodeURIComponent(path.slice(13)),evaluations=verifiedEvaluations(p).filter(value=>value.actionId===actionId).reverse(),events=store.events(p.tenant,actionId);
   const references=events.flatMap(e=>(e.dataRefs||[]).map(ref=>({...ref,source:e.source,eventId:e.id,assurance:e.assurance,observedAt:e.occurredAt,verification:e.sourceKind==='agent'?'self_reported_reference':'service_reported_reference'})));
   const business=events.filter(e=>['intent','execution','self_report','result'].includes(e.kind)),v=store.db.prepare('SELECT version,analyzed FROM actions WHERE tenant=? AND id=?').get(p.tenant,actionId);
   return {events,references,analysis:{version:v?.version??null,analyzed:v?.analyzed??null,pending:!!v&&v.analyzed<v.version},evaluations,referenceCoverage:{eventsWithReferences:business.filter(e=>e.dataRefs?.length).length,observedBusinessEvents:business.length,scope:'수신된 업무 이벤트 중 참조 메타데이터 제출 범위이며 전체 AI 지식·참고자료의 가시성 비율이 아닙니다'},limitations:['늦은 증거와 룰 변경은 새 평가 버전을 추가합니다','참고자료 참조는 source의 보고입니다. 모델이 실제 읽거나 판단에 사용했음을 자동 확정하지 않습니다','원문 prompt/response·자료 내용은 기본 미수집; version/hash는 사람이 외부 원본과 대조해야 합니다',...(!references.length?['참고 데이터 출처 미수집: 어떤 자료를 참고했는지 확인할 수 없습니다']:[])]};});
  }
  if(path==='/api/alerts'&&method==='GET'){
   return store.transaction(()=>{verifiedActions(p);const evaluations=latestEvaluations(verifiedEvaluations(p)),actions=store.db.prepare('SELECT id FROM actions WHERE tenant=?').all(p.tenant);return {items:actions.flatMap(a=>{const ev=evaluations.get(a.id);return (ev?.findings||[]).map((f,i)=>({...f,id:`${ev.id}:${i}`,actionId:a.id,createdAt:ev.createdAt,state:f.suppressedBy?'suppressed':'open'}));})};});
  }
  if(path==='/api/assets'&&method==='GET')return store.transaction(()=>({items:[...verifiedPolicyObjects(p,'asset').values()]}));
  if(path==='/api/metrics'&&method==='GET')return store.transaction(()=>{verifiedActions(p);return {vaultRssBytes:process.memoryUsage().rss,events:store.db.prepare('SELECT COUNT(*) n FROM events WHERE tenant=?').get(p.tenant).n,ledgerRecords:store.db.prepare('SELECT COUNT(*) n FROM ledger WHERE tenant=?').get(p.tenant).n,analyzedEvents:store.db.prepare('SELECT COUNT(*) n FROM events e JOIN actions a ON a.tenant=e.tenant AND a.id=e.action_id WHERE e.tenant=? AND a.analyzed=a.version').get(p.tenant).n,backlog:store.db.prepare('SELECT COUNT(*) n FROM actions WHERE tenant=? AND analyzed<version').get(p.tenant).n,scope:'tenant counts; vault process memory shared across tenants'}});
  if(path==='/api/assets'&&method==='POST'){reviewer(p);const a={id:identifier(x.id),actor:cleanText(x.actor,256),tool:cleanText(x.tool,256),owner:cleanText(x.owner,200),purpose:cleanText(x.purpose||'',500),version:cleanText(x.version||'unknown',100),policyVersion:cleanText(x.policyVersion||'unknown',100),approvalRequired:x.approvalRequired===true||x.approvalRequired===false?x.approvalRequired:'unknown',validFrom:date(x.validFrom||new Date().toISOString()),destinations:(x.destinations||[]).slice(0,30).map(s=>cleanText(s,256)),updatedAt:new Date().toISOString()};if(x.validUntil){a.validUntil=date(x.validUntil);if(Date.parse(a.validUntil)<=Date.parse(a.validFrom))fail(400,'자산 정책 유효기간 역전');}return store.transaction(()=>{verifiedPolicyObjects(p,'asset');store.put(p,'asset',a.id,a);dirty(p.tenant);return a;});}
  if(path==='/api/cases'&&method==='GET')return store.transaction(()=>({items:[...verifiedPolicyObjects(p,'case').values()]}));
  if(path==='/api/cases'&&method==='POST'){
   const c={id:randomUUID(),title:cleanText(x.title,200),actionId:identifier(x.actionId),owner:cleanText(x.owner,200),status:'open',comments:[],tasks:[],history:[{by:p.id,at:new Date().toISOString(),action:'created'}]};return store.transaction(()=>{verifiedActions(p);if(!store.events(p.tenant,c.actionId).length)fail(400,'사건에 연결할 관측 행동이 없습니다');return store.put(p,'case',c.id,c);});
  }
  if(path.startsWith('/api/cases/')&&method==='POST'){
   const id=identifier(path.split('/').pop());return store.transaction(()=>{const c=workbench.verifyContext(p,id).case;if(x.status&&!['open','in_review','closed'].includes(x.status))fail(400,'사건 상태 오류');if(x.status==='closed'&&!x.reason)fail(400,'종결 사유 필요');if(x.owner)c.owner=cleanText(x.owner,200);if(x.status)c.status=x.status;
    if(x.comment)c.comments.push({by:p.id,at:new Date().toISOString(),text:cleanText(x.comment,2000)});
    if(x.task){const t=x.task;const task={id:t.id||randomUUID(),title:cleanText(t.title,200),owner:cleanText(t.owner,200),dueAt:date(t.dueAt),status:t.status==='closed'?'closed':'open'};const index=c.tasks.findIndex(v=>v.id===task.id);if(index<0)c.tasks.push(task);else c.tasks[index]=task;}
    c.history.push({by:p.id,at:new Date().toISOString(),status:c.status,reason:cleanText(x.reason||'',1000)});return store.put(p,'case',id,c);});
  }
  if(path==='/api/rules'&&method==='GET')return store.transaction(()=>({items:[...verifiedPolicyObjects(p,'rule').values()].flatMap(r=>r.versions)}));
  if(path==='/api/rules'&&method==='POST'){reviewer(p);return store.transaction(()=>{const rules=verifiedPolicyObjects(p,'rule');if(rules.size>=100&&!rules.has(x.id))fail(409,'테넌트 룰 한도 100');const r=rules.get(x.id)||{id:x.id,versions:[]};const v=validateRule(x,p,r.versions.length+1);r.versions.push(v);store.put(p,'rule',x.id,r);return v;});}
  if(/^\/api\/rules\/[^/]+\/(test|approve)$/.test(path)&&method==='POST'){
   reviewer(p);const [, , ,id,operation]=path.split('/');return store.transaction(()=>{const r=policyObject(p,'rule',id),v=r.versions.find(v=>v.version===Number(x.version));if(!v)fail(404,'룰 버전 없음');if(operation==='test'){const ev=store.ledgerEvents(p.tenant).slice(-1000);const result={version:v.version,testedBy:p.id,testedAt:new Date().toISOString(),evaluated:ev.length,matches:ev.filter(e=>matches(v,e)).map(e=>`${e.source}/${e.id}`),bounded:true};v.test=result;store.put(p,'rule',id,r);return result;}
    if(v.author===p.id)fail(403,'자신이 작성한 룰을 단독 승인할 수 없습니다');if(v.status!=='draft'||!v.test)fail(409,'시험한 초안만 승인 가능');for(const old of r.versions)if(old.status==='active')old.status='retired';v.status='active';v.approvedBy=p.id;v.approvedAt=new Date().toISOString();store.put(p,'rule',id,r);dirty(p.tenant);return v;});
  }
  if(path==='/api/exceptions'&&method==='GET')return store.transaction(()=>({items:[...verifiedPolicyObjects(p,'exception').values()]}));
  if(path==='/api/exceptions'&&method==='POST'){
   const end=date(x.expiresAt);if(Date.parse(end)<=Date.now()||Date.parse(end)>Date.now()+90*86400000)fail(400,'예외 유효기간은 현재 이후 최대 90일');const e={id:randomUUID(),ruleId:identifier(x.ruleId),actionId:identifier(x.actionId),reason:cleanText(x.reason,1000),owner:cleanText(x.owner,200),expiresAt:end,status:'pending',author:p.id};return store.transaction(()=>store.put(p,'exception',e.id,e));
  }
  if(/^\/api\/exceptions\/[^/]+\/approve$/.test(path)&&method==='POST'){reviewer(p);return store.transaction(()=>{const e=policyObject(p,'exception',path.split('/')[3]);if(e.author===p.id||e.owner===p.id)fail(403,'자신이 작성하거나 소유한 예외를 단독 승인할 수 없습니다');if(Date.parse(e.expiresAt)<=Date.now())fail(409,'만료된 예외');e.status='approved';e.approvedBy=p.id;store.put(p,'exception',e.id,e);dirty(p.tenant);return e;});}
  if(path==='/api/export'&&method==='GET')return store.transaction(()=>store.bundle(p.tenant));
  if(path==='/api/integrity'&&method==='GET'){
   const verificationScope={checks:['signed_ledger','retained_event_bodies','event_indexes','receipt_projections','development_run_projections','object_projections','evaluation_projections','action_projections','governance_document_projections','document_files'],notChecked:[],limitations:['document_files covers authenticated referenced local files at each read; unreferenced files and an atomic filesystem snapshot are not claimed']};
   try{const result=store.transaction(()=>{const bundle=store.bundle(p.tenant),evaluations=bundle.records.filter(row=>row.type==='evaluation').map(row=>row.payload),events=store.decodeRecords(bundle),development=bundle.records.filter(row=>row.type==='development_run_event').map(row=>row.payload),documents=checkDocumentFiles({db:store.db,tenant:p.tenant,records:bundle.records,dataDir,key});return {...verifyBundle(bundle,publicKey),projection:checkEventProjection(store.db,p.tenant,events),receiptProjection:checkReceiptProjection(store.db,p.tenant,bundle.records,events),developmentRunProjection:checkDevelopmentRunProjection(store.db,p.tenant,development),objectProjection:checkObjectProjection(store.db,p.tenant,bundle.records),evaluationProjection:checkEvaluationProjection(store.db,p.tenant,evaluations),actionProjection:store.checkActionProjection(p.tenant),governanceDocumentProjection:documents.governanceDocumentProjection,documentFiles:documents.summary,verificationScope};});store.audit(p,'read',path);return result;}catch(e){let failureRecorded=true;try{store.transaction(()=>store.append(p.tenant,'integrity_failure',{message:e.message},p.id));}catch{failureRecorded=false;}return {valid:false,error:e.message,failureRecorded,requiresExternalIncidentRecord:!failureRecorded,verificationScope};}
  }
  if(path==='/api/rebuild'&&method==='POST'){admin(p);verifyBundle(store.bundle(p.tenant),publicKey);return store.rebuild(p);}
  if(path==='/api/governance'&&method==='GET')return store.transaction(()=>({requirements,systems:[...verifiedPolicyObjects(p,'system').values()],supplierBundles:[...verifiedPolicyObjects(p,'supplier_bundle').values()],governanceDocuments:governanceDocuments.list(p),documentLimits:governanceDocuments.limits,assessments:[...verifiedPolicyObjects(p,'assessment').values()],tasks:[...verifiedPolicyObjects(p,'governance_task').values()]}));
  if(path==='/api/governance/systems'&&method==='POST'){
   reviewer(p);
   const s=normalizeSystemFacts(x);
   return store.transaction(()=>{const before=verifiedPolicyObjects(p,'system').get(s.id);if(before){const id=randomUUID();store.put(p,'governance_task',id,{id,systemId:s.id,title:'시스템 사실관계 변경: 적용성 재검토',owner:s.owner,status:'open'});}return store.put(p,'system',s.id,s);});
  }
  if(path==='/api/governance/assessments'&&method==='POST'){
   reviewer(p);
   return store.transaction(()=>{
   const system=policyObject(p,'system',x.systemId),requirement=requirements.find(r=>r.id===x.requirementId);if(!requirement)fail(400,'확인한 요구사항이 아닙니다');
   if(!['applicable','not_applicable','unknown'].includes(x.applicability)||!['sufficient','insufficient','unknown'].includes(x.assessment)||!['pending','reviewed'].includes(x.legalReview))fail(400,'평가 상태 오류');
   if(!Array.isArray(x.evidence)||x.evidence.length>30)fail(400,'증거는 최대 30개');
   const events=x.evidence.some(e=>e.type==='event')?verifiedEventReferences(p):new Map();
   const evidence=x.evidence.map(e=>{if(!['document','event','test','attestation'].includes(e.type))fail(400,'증거 유형 오류');const ref=cleanText(e.ref,1000);const supplier=ref.startsWith('supplier-bundle:')?finance.evidence(p,ref,x.systemId):null,document=ref.startsWith('governance-document:')?governanceDocuments.evidence(p,ref,x.systemId):null;if((supplier||document)&&e.type!=='document')fail(400,'문서 증빙 참조는 document 유형입니다');if(supplier&&x.assessment==='sufficient'&&!supplier.measures.includes(x.requirementId))fail(400,'공급사 증빙의 조치 범위 밖 요구사항은 충분으로 평가할 수 없습니다');if(supplier&&x.assessment==='sufficient'&&supplier.verification.status!=='technical_match_human_review_required')fail(400,'미확인·변경·복구 불가 공급사 증빙으로 충분 평가할 수 없습니다');const event=e.type==='event'?events.get(ref):null;if(e.type==='event'&&!event)fail(400,'동일 tenant 원본 이벤트 참조를 찾을 수 없습니다');const eventSnapshot=event?{kind:event.kind,sourceKind:event.sourceKind,systemId:event.systemId||'not_recorded',modelId:event.modelId||'not_recorded',modelVersion:event.modelVersion||'not_recorded',policyVersion:event.policyVersion||'not_recorded',reviewer:event.reviewer||'not_recorded',occurredAt:event.occurredAt,receivedAt:event.receivedAt,clockUncertaintyMs:event.clockUncertaintyMs??'unknown',...(event.governanceCheck?{governanceCheck:event.governanceCheck}:{})}:null;return {type:e.type,ref,version:document?.version||cleanText(e.version||'unknown',200),notes:cleanText(e.notes||'',1000),contentHash:document?.contentHash||supplier?.contentHash||(event?digest(event):cleanText(e.contentHash||'not_provided',100)),...(document?{documentSnapshotHash:document.documentSnapshotHash}:{}),...(event?{eventSnapshot,eventSnapshotHash:digest(eventSnapshot)}:{}),verification:document?.verification||(supplier?'supplier_bundle_verified_at_assessment':event?'linked_verified_minimized_record':'human_supplied_reference_not_fetched')};});
   if(x.assessment==='sufficient'&&!evidence.length)fail(400,'증거 없이 충분으로 평가할 수 없습니다');
   const applicabilityCapture=applicabilityAssessmentSnapshot(requirement,system);
   const a={id:randomUUID(),systemId:x.systemId,systemHash:digest(system),requirementId:x.requirementId,requirementHash:digest(requirement),requirementSnapshot:requirement,applicabilityPolicyVersion,applicabilitySnapshot:applicabilityCapture.snapshot,applicabilitySnapshotHash:applicabilityCapture.hash,applicability:x.applicability,evidence,control:cleanText(x.control,1000),owner:cleanText(x.owner,200),assessment:x.assessment,legalReview:x.legalReview,reason:cleanText(x.reason,2000),nextReviewAt:date(x.nextReviewAt),reviewer:p.id,createdAt:new Date().toISOString()};
   if(!a.reason.trim())fail(400,'사람의 적용성·증거 판단 근거가 필요합니다');
   const technical=technicalEvidenceState(requirement,a,{system}),technicalEvidenceRequired=!technical.supportsHumanAssessment;
   store.put(p,'assessment',a.id,a);if(a.assessment!=='sufficient'||a.legalReview==='pending'||technicalEvidenceRequired||a.applicability==='unknown')store.put(p,'governance_task',a.id,{id:a.id,systemId:a.systemId,requirementId:a.requirementId,title:technicalEvidenceRequired?'조항별 검증 가능한 이행 근거 보완':a.applicability==='unknown'?'법률 적용성 미확인 사실 검토':a.assessment!=='sufficient'?'증거 보완 및 인간 재검토':'법률 적용성 검토',owner:a.owner,dueAt:a.nextReviewAt,status:'open',missingChecks:technical.missingChecks||[],technicalStatus:technical.status,orderTargets:governanceOrderTargets(a)});return a;
   });
  }
  if(path==='/api/governance/report'&&method==='GET')return report(p,url.searchParams.get('systemId'));
  if(path.startsWith('/api/governance/tasks/')&&method==='POST'){reviewer(p);return store.transaction(()=>{const id=path.split('/').pop(),t=policyObject(p,'governance_task',id);if(x.status==='closed'){
   if(!cleanText(x.reason,1000).trim())fail(400,'거버넌스 과제 종결 사유가 필요합니다');
   // Reuse the report's complete current assessment check, including expiry,
   // policy/facts/catalog changes and recoverable evidence. A narrower closure
   // check would let stale human conclusions clear an unresolved review task.
   const current=report(p,t.systemId),items=t.requirementId?current.items.filter(i=>i.requirement.id===t.requirementId):current.items.filter(i=>i.requirement.id.startsWith('KR-'));
   if(!items.length||items.some(i=>!['human_evidence_assessed','human_marked_not_applicable'].includes(i.status)||i.legalStatus!=='reviewed'||i.assessment?.applicability==='unknown'))fail(409,'현재 법령·시스템·기한의 인간 재검토와 검증 가능한 조항별 증거가 없어 작업을 종결할 수 없습니다');
   const orderTargets=t.orderTargets||governanceOrderTargets(verifiedPolicyObjects(p,'assessment').get(t.id));
   if(orderTargets.some(target=>!items.some(i=>governanceOrderTargets(i.assessment).some(current=>current.orderId===target.orderId))))fail(409,'다른 명령의 대응 근거로 이 명령 과제를 종결할 수 없습니다');
   if(t.bundleId&&!items.some(i=>i.assessment?.evidence?.some(e=>e.ref===`supplier-bundle:${t.bundleId}`)))fail(409,'변경된 공급사 증빙을 검토한 현재 평가가 필요합니다');
   if(t.documentId&&!items.some(i=>i.assessment?.evidence?.some(e=>e.ref===`governance-document:${t.documentId}`)))fail(409,'변경된 문서를 검토한 현재 평가가 필요합니다');
  }t.status=x.status==='closed'?'closed':'open';t.reason=cleanText(x.reason,1000);t.reviewedBy=p.id;t.reviewedAt=new Date().toISOString();return store.put(p,'governance_task',id,t);});}
  fail(404,'지원하지 않는 경로 또는 메서드');
 }
  return {store,handle,analysis,assistance,identity,governanceDocuments};
}
