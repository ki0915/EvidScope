import {randomBytes,randomUUID} from 'node:crypto';
import {dirname,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {canonical,digest,equal} from './crypto.mjs';
import {cleanText,fail,identifier} from './model.mjs';
import {buildRoleExecution,loadRolePackages} from './role-packages.mjs';
import {primaryModelPolicy} from './model-policy.mjs';

const safeModelPolicy=primaryModelPolicy;
const legacyModelPolicy=()=>({provider:'ollama-local',model:'qwen3:4b',cloudAllowed:false,maxResponses:4,timeoutSeconds:300,generation:{think:false,temperature:0.7,topP:0.8,topK:20,numCtx:8192,numPredict:1024,maxPromptBytes:24000}});
const repositoryRoot=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const rolePacks=loadRolePackages({root:repositoryRoot}),rolePackById=new Map(rolePacks.map(pack=>[pack.id,pack]));
const protocolTools=['read_frozen_bundle','submit_advisory_draft'];
const roleMetadata=id=>{const pack=rolePackById.get(id);return {id:pack.id,version:pack.version,packagePath:pack.packagePath,profileOwner:pack.profileOwner,modelVersion:pack.modelVersion,evalStatus:pack.evalStatus,adapter:pack.adapter,declaredTools:[...pack.tools],toolExecution:'declared_not_executable'};};
const baseProfiles=rolePacks.map(pack=>({id:pack.id,version:1,name:pack.title,kind:'runtime',description:`Bounded repository role package ${pack.packagePath}`,instructions:[pack.instructions],tools:[...protocolTools],knowledge:[...pack.knowledge],eval:{required:[...pack.evalSets]},rolePackage:roleMetadata(pack.id),modelPolicy:legacyModelPolicy()}));
const humanRoles=new Set(['auditor','reviewer','admin']);
const editableRoles=new Set(['reviewer','admin']);
const terminalStates=new Set(['completed','abstained','failed','timed_out']);
const allowedOutcome=new Set(terminalStates);
const allowedConfidence=new Set(['low','medium','high']),allowedRelation=new Set(['supports','contradicts','context_only']);
// Includes bounded Pod startup (180s), inference (120s), and cleanup overhead.
// The inference request itself remains capped at120s and one response.
const maxCredentialMs=6*60*1000;
const maxLedgerRowBytes=2*1024*1024;
const maxAssistanceObjects=2000;
const nowIso=()=>new Date().toISOString();
const object=(x,message='JSON 객체가 필요합니다')=>{if(!x||typeof x!=='object'||Array.isArray(x))fail(400,message);return x;};
const exact=(x,keys,message)=>{object(x);if(Object.keys(x).some(k=>!keys.includes(k)))fail(400,message);};
const requiredText=(x,max,message)=>{const value=cleanText(x,max).trim();if(!value)fail(400,message);return value;};
const stringList=(value,maxItems,maxLength,message)=>{if(!Array.isArray(value)||value.length>maxItems)fail(400,message);return value.map(v=>requiredText(v,maxLength,message));};
const clone=x=>structuredClone(x);

function normalizeProfile(x,version){
 exact(x,['id','name','kind','description','instructions','tools','knowledge','eval'], '지원하지 않는 프로필 필드입니다. 모델 정책은 서버가 고정합니다');
 const id=identifier(x.id);if(!baseProfiles.some(profile=>profile.id===id)||x.kind!=='runtime')fail(400,'case assistance는 등록된 네 runtime 역할만 지원합니다');
 const profile={id,version,name:requiredText(x.name,120,'프로필 이름 필요'),kind:x.kind,description:requiredText(x.description,500,'프로필 설명 필요'),instructions:stringList(x.instructions,20,500,'프로필 지시는 최대 20개'),tools:stringList(x.tools,10,100,'도구 목록이 유효하지 않습니다'),knowledge:stringList(x.knowledge,20,200,'지식 목록이 유효하지 않습니다')};
 const supportedTools=new Set(['read_frozen_bundle','submit_advisory_draft']);if(new Set(profile.tools).size!==profile.tools.length||profile.tools.some(tool=>!supportedTools.has(tool)))fail(400,'프로필 도구는 frozen bundle 읽기와 advisory draft 제출 프로토콜만 선언할 수 있습니다');
 exact(x.eval,['required'],'지원하지 않는 평가 프로필 필드');profile.eval={required:stringList(x.eval.required,20,100,'평가 항목이 유효하지 않습니다')};
 if(!profile.instructions.length||!profile.tools.length||!profile.knowledge.length||!profile.eval.required.length)fail(400,'프로필의 지시·도구·지식·평가 항목은 비어 있을 수 없습니다');
 profile.rolePackage=roleMetadata(id);profile.modelPolicy=safeModelPolicy();return profile;
}

function validateDraft(value,availableRefs,availableRequirements=new Set()){
 exact(value,['summary','findings','uncertainties','limitations','recommendedFollowUps','abstained'],'지원하지 않는 advisory draft 필드');
 if(typeof value.abstained!=='boolean')fail(400,'draft abstained 값 필요');
 const draft={summary:requiredText(value.summary,3000,'draft 요약 필요'),findings:[],uncertainties:stringList(value.uncertainties,30,1000,'불확실성 목록 오류'),limitations:stringList(value.limitations,30,1000,'한계 목록 오류'),recommendedFollowUps:stringList(value.recommendedFollowUps,30,1000,'후속조치 목록 오류'),abstained:value.abstained};
 if(!draft.uncertainties.length||!draft.limitations.length)fail(400,'draft는 불확실성과 한계를 각각 하나 이상 명시해야 합니다');
 if(!Array.isArray(value.findings)||value.findings.length>30)fail(400,'findings는 최대 30개');
 for(const finding of value.findings){exact(finding,['claim','evidenceRefs','relation','confidence','requirementRefs'],'지원하지 않는 finding 필드');const refs=stringList(finding.evidenceRefs,30,160,'finding 증거 참조 오류');if(!refs.length||new Set(refs).size!==refs.length||refs.some(ref=>!availableRefs.has(ref)))fail(400,'finding은 frozen bundle의 고유 증거 참조만 사용할 수 있습니다');if(!allowedRelation.has(finding.relation))fail(400,'finding relation 오류');if(!allowedConfidence.has(finding.confidence))fail(400,'finding confidence 오류');const item={claim:requiredText(finding.claim,2000,'finding 주장 필요'),evidenceRefs:refs,relation:finding.relation,confidence:finding.confidence};if(finding.requirementRefs!==undefined){item.requirementRefs=stringList(finding.requirementRefs,3,120,'요구사항 참조 오류');if(new Set(item.requirementRefs).size!==item.requirementRefs.length||item.requirementRefs.some(id=>!availableRequirements.has(id)))fail(400,'선택하지 않은 요구사항을 인용할 수 없습니다');}draft.findings.push(item);}
 if(!draft.abstained&&!draft.findings.length)fail(400,'비기권 draft에는 근거가 있는 finding이 필요합니다');
 return draft;
}
function providerReport(value,reportedModel){
 if(value===undefined||value===null)return {model:reportedModel,modelDigest:null,quantizationLevel:null,inputTokens:null,outputTokens:null,totalDurationNs:null};exact(value,['model','modelDigest','quantizationLevel','inputTokens','outputTokens','totalDurationNs'],'지원하지 않는 provider report 필드');
 const optionalText=(v,max)=>v===null?null:cleanText(v,max),optionalInt=v=>{if(v===null)return null;if(!Number.isSafeInteger(v)||v<0)fail(400,'provider 사용량은 0 이상의 정수 또는 null이어야 합니다');return v;};
 const report={model:optionalText(value.model,100),modelDigest:optionalText(value.modelDigest,160),quantizationLevel:optionalText(value.quantizationLevel,80),inputTokens:optionalInt(value.inputTokens),outputTokens:optionalInt(value.outputTokens),totalDurationNs:optionalInt(value.totalDurationNs)};if(report.model!==reportedModel)fail(400,'provider model 보고 필드가 서로 일치하지 않습니다');return report;
}

export function createAssistance(store,workbench){
 const sorted=items=>[...items].sort((a,b)=>a.id.localeCompare(b.id)||(a.version||0)-(b.version||0));
 function verifiedList(tenant,type){
  const originals=new Map();for(const row of store.verifiedRows(tenant,maxLedgerRowBytes)){if(row.oversized)fail(413,'원장 기록이 assistance 검증 한도를 초과했습니다');if(row.type===type&&row.payload?.id){const key=type==='assistance_profile'?`${row.payload.id}@${row.payload.version}`:row.payload.id;originals.set(key,row.payload);if(originals.size>maxAssistanceObjects)fail(413,'assistance 객체 검증 한도를 초과했습니다');}}
  const original=sorted(originals.values()),projected=sorted(store.list(tenant,type));if(canonical(original)!==canonical(projected))fail(409,`${type} 조회 사본이 서명 원장과 일치하지 않습니다`);return original;
 }
 const get=(tenant,type,id)=>verifiedList(tenant,type).find(item=>item.id===id)||fail(404,'assistance 대상을 찾을 수 없습니다');
 function catalog(tenant){
  let original=null;for(const row of store.verifiedRows(tenant,maxLedgerRowBytes)){if(row.oversized)fail(413,'원장 기록이 assistance 검증 한도를 초과했습니다');if(row.type==='catalog')original=row.payload;}
  const projected=store.get(tenant,'catalog','current');if(canonical(original)!==canonical(projected))fail(409,'catalog 조회 사본이 서명 원장과 일치하지 않습니다');return original||fail(404,'catalog를 찾을 수 없습니다');
 }
 const profiles=tenant=>{const load=()=>{
  const custom=verifiedList(tenant,'assistance_profile'),all=[...baseProfiles.map(clone),...custom];
  // Append a new signed version; historical profiles and their package hashes remain valid.
  for(const base of baseProfiles){const latest=all.filter(p=>p.id===base.id).sort((a,b)=>b.version-a.version)[0];if(canonical(latest.modelPolicy)===canonical(safeModelPolicy()))continue;const upgraded={...clone(latest),version:latest.version+1,modelPolicy:safeModelPolicy(),createdAt:nowIso(),createdBy:'repository-model-policy-upgrade'};delete upgraded.profileHash;upgraded.profileHash=digest(upgraded);store.put({id:upgraded.createdBy,tenant},'assistance_profile',`${upgraded.id}@${upgraded.version}`,upgraded);all.push(upgraded);}
  return all.sort((a,b)=>a.id.localeCompare(b.id)||a.version-b.version);
 };return store.db.isTransaction?load():store.transaction(load);};
 const profile=(tenant,id,version)=>profiles(tenant).find(v=>v.id===id&&v.version===version)||fail(404,'프로필 버전을 찾을 수 없습니다');
 const runs=tenant=>verifiedList(tenant,'assistance_run');
 const reviews=(tenant,runId)=>verifiedList(tenant,'assistance_review').filter(v=>v.runId===runId).sort((a,b)=>a.createdAt.localeCompare(b.createdAt));
 const profileHash=value=>{const copy=clone(value);delete copy.profileHash;return digest(copy);};
 const roleExecutionFor=(roleId,contextRefs,question)=>({...buildRoleExecution(roleId,{root:repositoryRoot,request:question||'Prepare a bounded advisory draft from the frozen assistance package for human review.',contextRefs}),toolExecution:'declared_not_executable'});
 function packageCore(pkg){const {id,status,bundleHash,...core}=pkg;return core;}
 function verifiedPackage(tenant,id){const pkg=get(tenant,'assistance_package',id),known=profile(tenant,pkg.profileSnapshot?.id,pkg.profileSnapshot?.version),knownExecution=roleExecutionFor(pkg.profileSnapshot?.id,(pkg.evidence||[]).map(item=>item.ref),pkg.operatorQuestion);if(pkg.status!=='prepared'||digest(packageCore(pkg))!==pkg.bundleHash||profileHash(pkg.profileSnapshot)!==pkg.profileSnapshotHash||canonical(known)!==canonical(pkg.profileSnapshot)||!pkg.roleExecutionSnapshot||!/^[a-f0-9]{64}$/.test(pkg.roleExecutionHash||'')||digest(pkg.roleExecutionSnapshot)!==pkg.roleExecutionHash||canonical(knownExecution)!==canonical(pkg.roleExecutionSnapshot))fail(409,'assistance package 내용·프로필·role execution hash가 서명 원장과 일치하지 않습니다');return pkg;}
 function verifiedRun(tenant,id){const run=get(tenant,'assistance_run',id),pkg=verifiedPackage(tenant,run.packageId);if(run.packageHash!==pkg.bundleHash||run.profile?.hash!==pkg.profileSnapshotHash||run.profile?.id!==pkg.profileSnapshot.id||run.profile?.version!==pkg.profileSnapshot.version||run.rolePackage?.id!==pkg.roleExecutionSnapshot.roleId||run.rolePackage?.version!==pkg.roleExecutionSnapshot.roleVersion||run.rolePackage?.hash!==pkg.roleExecutionHash||run.caseId!==pkg.caseId||run.caseSnapshotHash!==pkg.caseSnapshotHash||run.contextHash!==pkg.contextHash||run.catalogHash!==pkg.governanceSnapshot.catalogHash)fail(409,'assistance run binding이 서명된 package와 일치하지 않습니다');return run;}
 function currentContext(p,caseId){return workbench.verifyContext(p,caseId);}
 function staleStatus(p,item){
  try{const context=currentContext(p,item.caseId),currentCatalogHash=catalog(p.tenant)?.hash||null,currentCaseSnapshotHash=digest(context.case),catalogChanged=item.catalogHash!==undefined&&item.catalogHash!==currentCatalogHash,caseChanged=item.caseSnapshotHash!==currentCaseSnapshotHash,contextChanged=context.contextHash!==item.contextHash;return {stale:contextChanged||catalogChanged||caseChanged,currentContextHash:context.contextHash,currentCatalogHash,currentCaseSnapshotHash,staleReason:catalogChanged?'catalog_changed':caseChanged?'case_changed':contextChanged?'evidence_or_analysis_changed':null};}
  catch(error){if(error.status!==404)throw error;return {stale:true,currentContextHash:null,currentCatalogHash:null,currentCaseSnapshotHash:null,staleReason:'case_unavailable'};}
 }
 function decorateRun(p,run){const stale=staleStatus(p,run),history=reviews(p.tenant,run.id);const {credentialHash,...safe}=run;return {...safe,...stale,profileId:safe.profile.id,profileVersion:safe.profile.version,updatedAt:safe.finishedAt||safe.startedAt||safe.createdAt,reviewState:history.at(-1)?.action||'unreviewed',reviews:history};}
 function decoratePackage(p,pkg){return {...pkg,...staleStatus(p,pkg)};}
 function createProfile(p,x){
  if(!editableRoles.has(p.role))fail(403,'프로필 버전 작성에는 reviewer 또는 admin이 필요합니다');
  const id=identifier(x.id),versions=profiles(p.tenant).filter(v=>v.id===id),version=Math.max(0,...versions.map(v=>v.version))+1,created=normalizeProfile(x,version);
  created.createdAt=nowIso();created.createdBy=p.id;created.profileHash=digest(created);
  return store.transaction(()=>store.put(p,'assistance_profile',`${id}@${version}`,created));
 }
 function prepare(p,x){
  exact(x,['caseId','contextHash','profileId','profileVersion','selectedEvidenceRefs','selectedRequirementIds','operatorQuestion'],'지원하지 않는 package 필드');
  const caseId=identifier(x.caseId),profileId=identifier(x.profileId),profileVersion=Number(x.profileVersion);if(!Number.isSafeInteger(profileVersion)||profileVersion<1)fail(400,'프로필 버전 오류');
  if(!/^[a-f0-9]{64}$/.test(x.contextHash||''))fail(400,'검토 문맥 hash가 필요합니다');
  const selected=stringList(x.selectedEvidenceRefs,30,160,'증거 참조는 최대 30개');if(!selected.length||new Set(selected).size!==selected.length)fail(400,'고유한 증거 참조를 하나 이상 선택하세요');
  return store.transaction(()=>{
   const context=currentContext(p,caseId);if(context.contextHash!==x.contextHash)fail(409,'증거나 분석 문맥이 바뀌었습니다. 다시 조회하세요');
   const byRef=new Map(context.events.map(event=>[`${event.source}/${event.id}`,event]));if(selected.some(ref=>!byRef.has(ref)))fail(400,'선택한 참조가 이 사건의 보존된 실제 이벤트가 아닙니다');
   const selectedSet=new Set(selected),evidence=selected.map(ref=>{const event=byRef.get(ref);return {ref,eventHash:event.hash,ledgerSeq:event.seq,sourceKind:event.sourceKind,kind:event.kind,occurredAt:event.occurredAt,receivedAt:event.receivedAt,status:event.status||'unknown',assurance:event.assurance,dataRefs:(event.dataRefs||[]).map(r=>({id:r.id,kind:r.kind,role:r.role,version:r.version,hash:r.hash})),...(event.aiObservation?{aiObservation:clone(event.aiObservation)}:{})};});
   const analysisSnapshot={version:context.analysis.version,analyzed:context.analysis.analyzed,pending:context.analysis.pending,evaluations:context.evaluations.map(e=>({id:e.id,version:e.version,status:e.status||'evaluated',effect:e.effect||'unknown',authority:e.authority||'unknown',findings:(e.findings||[]).map(f=>({code:f.code,severity:f.severity,evidence:(f.evidence||[]).filter(ref=>selectedSet.has(ref))}))}))};
   const currentCatalog=catalog(p.tenant),activeRules=verifiedList(p.tenant,'rule').flatMap(r=>r.versions||[]).filter(r=>r.status==='active').map(r=>({id:r.id,version:r.version,field:r.field,op:r.op,severity:r.severity,ruleHash:digest(r)}));
   const governanceSnapshot={catalogHash:currentCatalog?.hash||null,requirementCount:currentCatalog?.requirements?.length||0,activeRules,reviewBoundary:'Catalog text is a server-trusted repository snapshot; draft_requires_human_review is not an applicability or compliance decision.'};
   if(profileId==='governance-assistant'){const requirements=currentCatalog?.requirements||[],ids=x.selectedRequirementIds===undefined?requirements.slice(0,1).map(r=>r.id):stringList(x.selectedRequirementIds,3,120,'요구사항은 한 번에 최대 3개 선택하세요');if(!ids.length||new Set(ids).size!==ids.length||ids.some(id=>!requirements.some(r=>r.id===id)))fail(400,'알 수 없거나 중복된 요구사항 선택');governanceSnapshot.selectedRequirementIds=ids;governanceSnapshot.requirements=ids.map(id=>requirements.find(r=>r.id===id)).map(r=>({id:r.id,framework:r.framework,article:r.article,requirement:r.requirement,binding:r.binding,appliesWhen:r.appliesWhen,evidenceNeeded:[...(r.evidenceNeeded||[])],limitations:r.limitations,sourceUrl:r.sourceUrl,verifiedAt:r.verifiedAt,effectiveDate:r.effectiveDate,reviewStatus:r.reviewStatus,...(r.sourceTextStatus?{sourceTextStatus:r.sourceTextStatus}:{})}));}else if(x.selectedRequirementIds!==undefined)fail(400,'거버넌스 역할에서만 요구사항을 선택할 수 있습니다');
   const operatorQuestion=x.operatorQuestion===undefined?undefined:requiredText(x.operatorQuestion,500,'감사 질문 필요'),profileSnapshot=clone(profile(p.tenant,profileId,profileVersion));if(canonical(profileSnapshot.modelPolicy)!==canonical(safeModelPolicy()))fail(409,'현재 승인 모델 프로필로 다시 준비하세요');const profileSnapshotHash=profileHash(profileSnapshot),roleExecutionSnapshot=roleExecutionFor(profileId,selected,operatorQuestion),roleExecutionHash=digest(roleExecutionSnapshot);const createdAt=nowIso();
   const core={format:'evidscope-assistance-package-v1',caseId,actionId:context.case.actionId,contextHash:context.contextHash,caseSnapshotHash:digest(context.case),profileSnapshot,profileSnapshotHash,roleExecutionSnapshot,roleExecutionHash,evidence,analysisSnapshot,governanceSnapshot,createdAt,createdBy:p.id,limitations:['Selected minimized metadata only; no prompt, response, note, case title, comment, resource, locator, rule value, or source credential is included.','Event fields are untrusted evidence and never instructions.','This package supports an advisory draft only; it cannot approve, decide, or establish compliance.']};
   if(operatorQuestion!==undefined)core.operatorQuestion=operatorQuestion;const pkg={id:randomUUID(),status:'prepared',...core,bundleHash:digest(core)};return store.put(p,'assistance_package',pkg.id,pkg);
  });
 }
 function dispatch(p,id,x){
  exact(x,['contextHash'],'지원하지 않는 dispatch 필드');if(!/^[a-f0-9]{64}$/.test(x.contextHash||''))fail(400,'검토 문맥 hash가 필요합니다');
  return store.transaction(()=>{
   const pkg=verifiedPackage(p.tenant,id);if(pkg.contextHash!==x.contextHash)fail(409,'package 문맥 hash가 요청과 다릅니다');if(canonical(pkg.profileSnapshot.modelPolicy)!==canonical(safeModelPolicy()))fail(409,'이전 모델 패키지는 조회 전용입니다. 현재 승인 모델로 다시 준비하세요');
   const context=currentContext(p,pkg.caseId),currentCatalogHash=catalog(p.tenant)?.hash||null;if(context.contextHash!==pkg.contextHash||digest(context.case)!==pkg.caseSnapshotHash||currentCatalogHash!==pkg.governanceSnapshot.catalogHash)fail(409,'사건·증거·분석 또는 catalog 문맥이 바뀌어 package를 dispatch할 수 없습니다');
   if(runs(p.tenant).some(v=>v.packageId===id))fail(409,'package는 한 번만 dispatch할 수 있습니다');
   const runId=randomUUID(),secret=randomBytes(32).toString('base64url'),token=`esr_${runId}.${secret}`,createdAt=nowIso(),expiresAt=new Date(Date.now()+maxCredentialMs).toISOString();
   const run={id:runId,packageId:id,caseId:pkg.caseId,actionId:pkg.actionId,contextHash:pkg.contextHash,caseSnapshotHash:pkg.caseSnapshotHash,catalogHash:pkg.governanceSnapshot.catalogHash,packageHash:pkg.bundleHash,profile:{id:pkg.profileSnapshot.id,version:pkg.profileSnapshot.version,hash:pkg.profileSnapshotHash},rolePackage:{id:pkg.roleExecutionSnapshot.roleId,version:pkg.roleExecutionSnapshot.roleVersion,hash:pkg.roleExecutionHash},modelPolicy:safeModelPolicy(),state:'queued',credentialHash:digest(token),credentialExpiresAt:expiresAt,createdAt,createdBy:p.id};
   store.put(p,'assistance_run',run.id,run);
   const {credentialHash,...safeRun}=run;return {run:{...safeRun,profileId:run.profile.id,profileVersion:run.profile.version,updatedAt:run.createdAt,stale:false,currentContextHash:context.contextHash,currentCatalogHash,currentCaseSnapshotHash:digest(context.case),staleReason:null,reviewState:'unreviewed',reviews:[]},credential:{format:'evidscope-assistance-credential-v1',runId,token,expiresAt,internalBasePath:`/internal/assistance/runs/${runId}`}};
  });
 }
 function authenticateRun(headers,id){
  identifier(id);const token=String(headers.authorization||'').replace(/^Bearer /,'');const match=/^esr_([a-f0-9-]{36})\.[A-Za-z0-9_-]{43}$/.exec(token);if(!match||match[1]!==id)fail(401,'run-scoped 자격이 필요합니다');
  const row=store.db.prepare("SELECT tenant FROM objects WHERE type='assistance_run' AND id=?").all(id);if(row.length!==1)fail(401,'run-scoped 자격이 유효하지 않습니다');const run=verifiedRun(row[0].tenant,id);if(!equal(run.credentialHash,digest(token)))fail(401,'run-scoped 자격이 유효하지 않습니다');return {tenant:row[0].tenant,run,principal:{id:`assistance-worker:${id}`,tenant:row[0].tenant,role:'assistance_worker'}};
 }
 function expireIfNeeded(tenant,run){
  if(!['queued','running'].includes(run.state)||Date.parse(run.credentialExpiresAt)>Date.now())return {run,expired:false};
  const expired={...run,state:'timed_out',finishedAt:nowIso(),errorCode:'credential_expired'};store.put({id:'assistance-timeout',tenant},'assistance_run',run.id,expired);return {run:expired,expired:true};
 }
 function reconcileExpired(tenant,id){return store.transaction(()=>{const candidates=id?[verifiedRun(tenant,id)]:runs(tenant);let changed=false;for(const candidate of candidates){const result=expireIfNeeded(tenant,candidate);changed=changed||result.expired;}return changed;});}
 function allVerifiedRuns(){const result=[];for(const {tenant} of store.db.prepare('SELECT tenant FROM checkpoints ORDER BY tenant').all())result.push(...runs(tenant));return result;}
 function claim(headers,id){
  const auth=authenticateRun(headers,id);if(reconcileExpired(auth.tenant,id))fail(410,'run 자격이 만료되었습니다');const result=store.transaction(()=>{
   let run=verifiedRun(auth.tenant,id);if(run.state==='timed_out'&&run.errorCode==='credential_expired')return {expired:true};const expiry=expireIfNeeded(auth.tenant,run);if(expiry.expired)return {expired:true};run=expiry.run;if(run.state!=='queued')fail(409,'run package는 한 번만 claim할 수 있습니다');
   const active=allVerifiedRuns().find(candidate=>candidate.id!==id&&candidate.state==='running'&&Date.parse(candidate.credentialExpiresAt)>Date.now());if(active)fail(429,'다른 로컬 assistance run이 실행 중입니다');
   const freshness=staleStatus(auth.principal,run);if(freshness.stale)fail(409,'사건·증거·분석 또는 catalog 문맥이 바뀌어 run을 claim할 수 없습니다');
   run={...run,state:'running',startedAt:nowIso(),packageClaimedAt:nowIso()};store.put(auth.principal,'assistance_run',run.id,run);store.append(auth.tenant,'audit_access',{operation:'read',target:`assistance-package:${id}`},auth.principal.id);
   const pkg=verifiedPackage(auth.tenant,run.packageId);return {run:{id:run.id,packageId:run.packageId,packageHash:run.packageHash,profileHash:run.profile.hash,roleExecutionHash:run.rolePackage.hash,roleId:run.rolePackage.id,roleVersion:run.rolePackage.version,expiresAt:run.credentialExpiresAt,modelPolicy:run.modelPolicy,limits:{globalConcurrency:1,maxResponses:run.modelPolicy.maxResponses,timeoutSeconds:run.modelPolicy.timeoutSeconds}},package:pkg};
  });if(result.expired)fail(410,'run 자격이 만료되었습니다');return result;
 }
 function submit(headers,id,x){
  const auth=authenticateRun(headers,id);exact(x,['packageHash','providerReportedModel','providerReport','responsesUsed','outcome','draft','errorCode'],'지원하지 않는 worker 결과 필드');if(reconcileExpired(auth.tenant,id))fail(410,'run이 만료되어 결과를 받을 수 없습니다');const output=store.transaction(()=>{
   let run=verifiedRun(auth.tenant,id);if(run.state==='timed_out'&&run.errorCode==='credential_expired')return {expired:true};const expiry=expireIfNeeded(auth.tenant,run);if(expiry.expired)return {expired:true};run=expiry.run;if(run.state!=='running')fail(409,'run 결과는 한 번만 제출할 수 있습니다');
   if(x.packageHash!==run.packageHash)fail(403,'결과의 package binding이 일치하지 않습니다');const providerReportedModel=x.providerReportedModel===null?null:cleanText(x.providerReportedModel,100);if(['completed','abstained'].includes(x.outcome)&&providerReportedModel!==run.modelPolicy.model)fail(400,'draft 결과는 해당 run에 고정한 모델과 일치해야 합니다');const boundedProviderReport=providerReport(x.providerReport,providerReportedModel);
   if(!Number.isSafeInteger(x.responsesUsed)||x.responsesUsed<0||x.responsesUsed>run.modelPolicy.maxResponses)fail(400,'모델 응답 수가 실행 한도를 초과했습니다');if(!allowedOutcome.has(x.outcome))fail(400,'run 결과 상태 오류');if(['completed','abstained'].includes(x.outcome)&&x.responsesUsed<1)fail(400,'draft 결과에는 하나 이상의 모델 응답이 필요합니다');
   const pkg=verifiedPackage(auth.tenant,run.packageId),available=new Set(pkg.evidence.map(e=>e.ref));let draft=null;
   if(['completed','abstained'].includes(x.outcome)){draft=validateDraft(x.draft,available,new Set((pkg.governanceSnapshot.requirements||[]).map(r=>r.id)));if((x.outcome==='abstained')!==draft.abstained)fail(400,'outcome과 draft abstention이 일치하지 않습니다');}
   else if(x.draft!==undefined)fail(400,'실패 또는 timeout 결과에 draft를 포함할 수 없습니다');
   const result={...run,state:x.outcome,responsesUsed:x.responsesUsed,providerReportedModel,providerReport:boundedProviderReport,generationSettings:run.modelPolicy.generation,finishedAt:nowIso(),...(draft?{draft}:{errorCode:requiredText(x.errorCode,120,'오류 코드 필요')})};store.put(auth.principal,'assistance_run',run.id,result);return {accepted:true,runId:id,state:result.state};
  });if(output.expired)fail(410,'run이 만료되어 결과를 받을 수 없습니다');return output;
 }
 function review(p,id,x){
  exact(x,['action','contextHash','editedDraft','reason'],'지원하지 않는 advisory review 필드');if(!['accept','reject'].includes(x.action))fail(400,'review action 오류');if(!/^[a-f0-9]{64}$/.test(x.contextHash||''))fail(400,'현재 문맥 hash가 필요합니다');
  return store.transaction(()=>{
   const run=verifiedRun(p.tenant,id),decorated=decorateRun(p,run);if(decorated.stale||decorated.currentContextHash!==x.contextHash||run.contextHash!==x.contextHash)fail(409,'사건·증거·분석 또는 catalog 문맥이 바뀌어 advisory draft가 stale입니다');if(!['completed','abstained'].includes(run.state)||!run.draft)fail(409,'검토할 advisory draft가 없습니다');
   const pkg=verifiedPackage(p.tenant,run.packageId),available=new Set(pkg.evidence.map(e=>e.ref));let draft=run.draft;if(x.editedDraft!==undefined){if(x.action!=='accept')fail(400,'편집 draft는 accept에만 사용할 수 있습니다');draft=validateDraft(x.editedDraft,available,new Set((pkg.governanceSnapshot.requirements||[]).map(r=>r.id)));}
   const reason=x.action==='reject'?requiredText(x.reason,2000,'거절 사유 필요'):cleanText(x.reason||'',2000);const item={id:randomUUID(),runId:id,packageId:run.packageId,caseId:run.caseId,contextHash:run.contextHash,action:x.action,draft,reason,reviewedBy:p.id,createdAt:nowIso(),boundary:'advisory_review_only_not_case_decision_or_compliance_approval'};return store.put(p,'assistance_review',item.id,item);
  });
 }
 function human(p,method,url,x){
  if(!humanRoles.has(p.role))fail(403,'인간 감사 계정만 접근할 수 있습니다');const path=url.pathname;
  if(path==='/api/assistance/profiles'&&method==='GET'){const all=profiles(p.tenant);return {items:url.searchParams.get('history')==='true'?all:[...new Map(all.map(profile=>[profile.id,profile])).values()]};}
  if(path==='/api/assistance/requirements'&&method==='GET')return {items:catalog(p.tenant).requirements,maxSelected:3};
  if(path==='/api/assistance/profiles'&&method==='POST')return createProfile(p,x);
  if(path==='/api/assistance/packages'&&method==='GET')return {items:verifiedList(p.tenant,'assistance_package').map(pkg=>decoratePackage(p,verifiedPackage(p.tenant,pkg.id)))};
  if(path==='/api/assistance/packages'&&method==='POST')return prepare(p,x);
  let match=path.match(/^\/api\/assistance\/packages\/([^/]+)(?:\/(dispatch))?$/);if(match){const id=identifier(decodeURIComponent(match[1]));if(match[2]&&method==='POST')return dispatch(p,id,x);if(!match[2]&&method==='GET')return decoratePackage(p,verifiedPackage(p.tenant,id));fail(405,'지원하지 않는 package 메서드');}
  if(path==='/api/assistance/runs'&&method==='GET'){reconcileExpired(p.tenant);return {items:runs(p.tenant).map(run=>decorateRun(p,verifiedRun(p.tenant,run.id)))}};
  match=path.match(/^\/api\/assistance\/runs\/([^/]+)(?:\/(review))?$/);if(match){const id=identifier(decodeURIComponent(match[1]));if(match[2]&&method==='POST')return review(p,id,x);if(!match[2]&&method==='GET'){reconcileExpired(p.tenant,id);return decorateRun(p,verifiedRun(p.tenant,id));}fail(405,'지원하지 않는 run 메서드');}
  return undefined;
 }
 function internal(method,url,headers,body){const match=url.pathname.match(/^\/internal\/assistance\/runs\/([^/]+)\/(package|result)$/);if(!match)return undefined;let x={};if(body){try{x=object(JSON.parse(body));}catch(error){if(error.status)throw error;fail(400,'JSON 객체가 필요합니다');}}const id=decodeURIComponent(match[1]);if(match[2]==='package'&&method==='GET')return claim(headers,id);if(match[2]==='result'&&method==='POST')return submit(headers,id,x);fail(405,'지원하지 않는 run-scoped 메서드');}
 return {human,internal,validateDraft};
}
