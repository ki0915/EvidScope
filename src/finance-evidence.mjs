import {createHash,randomUUID,sign,createPublicKey} from 'node:crypto';
import {join} from 'node:path';
import {canonical,digest} from './crypto.mjs';
import {identifier,cleanText,fail} from './model.mjs';
import {checkEvaluationProjection} from './evaluation-integrity.mjs';
import {asKeyring} from './data-keys.mjs';
import {createEncryptedDocumentStore} from './document-envelope.mjs';
import {knownGovernanceReference} from './kr-governance-evidence.mjs';
import {normalizeSupplierProvenance,normalizeSupplierProvenanceReview} from './supplier-provenance.mjs';

const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const measures=new Set(['KR-34-RISK','KR-34-EXPLAIN','KR-34-PROTECT']);
const known=knownGovernanceReference;
const limitations=['로컬 문서 보관입니다. 자료 유형은 제출자가 신고하며 실제 공급사 자료의 독립 출처 인증, 5년 운영 실적이나 상용 문서관리소 연결은 입증하지 않습니다.','담당자의 출처 확인은 기록된 수동 검토입니다. 해시·서명은 보고 내용의 진실성·신뢰된 발생 시각을 보증하지 않습니다.','공급사 조치의 활용 후보는 제34조제1항제1~3호에 한정하며 인간 감독·문서 보관을 자동 승계하지 않습니다.','기술적 증거 대조와 법적 적용성·충분성의 인간 판단은 별개입니다.'];

// Content-addressed encrypted local adapter. Paths never contain uploaded names or IDs.
export function createDocumentAdapter(dataDir,key){
 return createEncryptedDocumentStore({root:join(dataDir,'finance-documents'),purpose:'financeDocument',keyring:asKeyring(key),maxEnvelopeBytes:131072,maxPlaintextBytes:64*1024,invalidHash:()=>fail(400,'문서 SHA-256 오류')});
}

export function createFinanceEvidence({store,dataDir,key,keyring=asKeyring(key),requirements,governanceReport}){
 const documents=createDocumentAdapter(dataDir,keyring);
 const get=(p,type,id)=>store.get(p.tenant,type,id)||fail(404,'동일 테넌트 대상을 찾을 수 없습니다');
 const review=p=>{if(!['reviewer','admin'].includes(p.role))fail(403,'검토자 권한이 필요합니다');};
 // Nothing changes inside one read-only request snapshot, so a governance report citing several supplier bundles verifies
 // the finance projections once per tenant and snapshot instead of once per citation.
 const verifiedSnapshots=new WeakMap();
 function verifyProjection(p){
  const scope=store.ledgerTransaction?.readOnly?store.ledgerTransaction:null;
  if(scope&&verifiedSnapshots.get(scope)?.has(p.tenant))return;
  verifyProjectionNow(p);
  if(scope){if(!verifiedSnapshots.has(scope))verifiedSnapshots.set(scope,new Set());verifiedSnapshots.get(scope).add(p.tenant);}
 }
 function verifyProjectionNow(p){
  const types=['system','supplier_bundle','supplier_provenance_review','assessment','governance_task','finance_report'],latest=new Map(types.map(type=>[type,new Map()])),evaluations=[];let size=0;
  for(const row of store.verifiedRows(p.tenant,2*1024*1024)){if((size+=Buffer.byteLength(JSON.stringify(row)))>16*1024*1024)fail(413,'금융 검토 원장 한도 초과: 부분 보고서를 발급하지 않습니다');if(latest.has(row.type))latest.get(row.type).set(row.payload.id,row.payload);if(row.type==='evaluation')evaluations.push(row.payload);}
  // Looking up a document or system uses its SQL key, not just payload.id.
  // A body-only comparison lets renamed or swapped keys redirect that lookup.
  for(const type of types){
   const original=latest.get(type),rows=store.db.prepare('SELECT id,body FROM objects WHERE tenant=? AND type=?').all(p.tenant,type);
   if(rows.length!==original.size||rows.some(row=>!original.has(row.id)||canonical(JSON.parse(row.body))!==canonical(original.get(row.id))))fail(409,'금융 검토 조회 사본이 서명 원장과 일치하지 않습니다');
  }
  // The common checker binds lookup columns, body and ordering to signed history.
  try{checkEvaluationProjection(store.db,p.tenant,evaluations);}catch{fail(409,'금융 분석 사본이 서명 원장과 일치하지 않습니다');}
  store.checkProjection(p.tenant);
 }
 // The enclosing handler/evidence entry verifies the complete ledger and SQL
 // projections while holding one writer-excluding transaction. SQL seq gives
 // review order without trusting client timestamps or random review IDs.
 function reviewHistory(p,id){return store.db.prepare("SELECT body FROM ledger WHERE tenant=? AND json_extract(body,'$.type')='supplier_provenance_review' AND json_extract(body,'$.payload.bundleId')=? ORDER BY seq").all(p.tenant,id).map(row=>JSON.parse(row.body).payload);}
 function provenanceState(p,bundle){
  if(bundle.synthetic===true)return {status:'synthetic_fixture',sourceAuthentication:'not_independently_verified'};
  const history=reviewHistory(p,bundle.id),latest=history.at(-1),base={sourceAuthentication:'not_independently_verified',...(latest?{review:latest,reviewHash:digest(latest)}:{})};
  if(!latest)return {...base,status:'unreviewed'};
  if(latest.bundleHash!==bundle.contentHash||latest.bundleRevision!==bundle.revision||latest.systemId!==bundle.systemId)return {...base,status:'stale'};
  return {...base,status:latest.decision==='verified'?'reviewed':latest.decision==='rejected'?'rejected':'unreviewed'};
 }
 function verify(p,bundle,system){
  const issues=[];
  const provenance=provenanceState(p,bundle);
  if(bundle.synthetic!==true){try{normalizeSupplierProvenance(bundle.synthetic,bundle.provenance);}catch{issues.push('REAL_PROVENANCE_METADATA_MISSING');}}
  if(bundle.synthetic!==true&&provenance.status!=='reviewed')issues.push(provenance.status==='rejected'?'REAL_PROVENANCE_REJECTED':provenance.status==='stale'?'REAL_PROVENANCE_REVIEW_STALE':'REAL_PROVENANCE_REVIEW_REQUIRED');
  for(const [field,code] of [['supplierId','SUPPLIER'],['modelId','MODEL_ID'],['modelVersion','MODEL_VERSION'],['purpose','PURPOSE']]){
   if(!known(system[field])||!known(bundle[field]))issues.push(code+'_UNKNOWN');else if(system[field]!==bundle[field])issues.push(code+'_MISMATCH');
  }
  // Decree 27(3) requires reviewing the originally supplied scope, independently of current matching evidence.
  for(const [supplied,current,code] of [['suppliedModelVersion','modelVersion','SUPPLIED_MODEL_VERSION'],['suppliedPurpose','purpose','SUPPLIED_PURPOSE']]){
   if(!known(system[supplied]))issues.push(code+'_UNKNOWN');
   else if([system[current],bundle[current]].some(value=>known(value)&&value!==system[supplied]))issues.push(code+'_MISMATCH');
  }
  if(!(system.krRoles||[]).includes('deployer'))issues.push('DEPLOYER_ROLE_UNCONFIRMED');
  if(system.substantialModification!==false)issues.push(system.substantialModification===true?'SUBSTANTIAL_CHANGE_REVIEW':'SUBSTANTIAL_CHANGE_UNKNOWN');
  const checked=bundle.documents.map(document=>{try{const bytes=documents.read(p.tenant,document.sha256);return {...document,status:'hash_verified_and_retrievable',bytes:bytes.length};}catch{return {...document,status:'unavailable_or_corrupt'};}});
  if(!checked.length||checked.some(d=>d.status!=='hash_verified_and_retrievable'))issues.push('DOCUMENT_EVIDENCE_MISSING');
  return {status:issues.length?'review_required':'technical_match_human_review_required',issues,documents:checked,provenance,eligibleMeasureCandidates:bundle.measures.filter(id=>measures.has(id)),legalDecision:'human_review_required',checkedAt:new Date().toISOString()};
 }
 function bundleState(p,id){const bundle=get(p,'supplier_bundle',id);return {...bundle,verification:verify(p,bundle,get(p,'system',bundle.systemId))};}
 function view(p,systemId){
  try{store.checkActionProjection(p.tenant);}catch{fail(409,'행동 상태 조회 사본이 서명 원장과 일치하지 않습니다');}
  const system=get(p,'system',systemId),bundles=store.list(p.tenant,'supplier_bundle').filter(b=>b.systemId===systemId).map(b=>({...b,verification:verify(p,b,system)}));
  const all=store.ledgerEvents(p.tenant),linked=all.filter(e=>e.systemId===systemId),ids=[...new Set(linked.map(e=>e.actionId))];
  const operations=ids.map(actionId=>{const events=linked.filter(e=>e.actionId===actionId),allAction=all.filter(e=>e.actionId===actionId),mixed=allAction.some(e=>e.systemId!==systemId),version=store.db.prepare('SELECT version,analyzed FROM actions WHERE tenant=? AND id=?').get(p.tenant,actionId);return {actionId,events,evaluation:mixed?null:store.evaluations(p.tenant,actionId)[0]||null,analysisPending:!version||version.analyzed<version.version,correlationStatus:mixed?'system_correlation_uncertain':'explicit_system_reference',modelIssues:events.filter(e=>['execution','result'].includes(e.kind)&&(!known(e.modelId)||!known(e.modelVersion)||e.modelId!==system.modelId||e.modelVersion!==system.modelVersion)).map(e=>({ref:`${e.source}/${e.id}`,code:'DEPLOYED_MODEL_UNVERIFIED_OR_CHANGED'}))};});
  return {system,bundles,operations,assessments:store.list(p.tenant,'assessment').filter(a=>a.systemId===systemId),tasks:store.list(p.tenant,'governance_task').filter(t=>t.systemId===systemId),operationalStatus:operations.some(o=>o.events.some(e=>e.sourceKind==='tool'&&['execution','result'].includes(e.kind)))?'observed_partial_evidence':'execution_evidence_missing',unassignedEvents:all.filter(e=>!e.systemId).length,limitations};
 }
 function importBundle(p,x){
  review(p);const system=get(p,'system',identifier(x.systemId)),provenance=normalizeSupplierProvenance(x.synthetic,x.provenance);
  const id=identifier(x.id);const previous=store.get(p.tenant,'supplier_bundle',id);if(previous&&previous.systemId!==system.id)fail(409,'기존 증빙 ID의 시스템을 변경할 수 없습니다');
  if(!Array.isArray(x.documents)||!x.documents.length||x.documents.length>10)fail(400,'문서는 1~10개 필요합니다');
  let total=0;const parsed=x.documents.map(d=>{identifier(d.id);if(typeof d.contentBase64!=='string'||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(d.contentBase64))fail(400,'문서 base64 오류');const bytes=Buffer.from(d.contentBase64,'base64');total+=bytes.length;if(!bytes.length||total>65536)fail(413,'문서 전체 한도 64KiB');if(sha(bytes)!==d.sha256)fail(400,'수신 문서 해시 불일치');return {id:d.id,name:cleanText(d.name,200),bytes,sha256:d.sha256};});
  if(new Set(parsed.map(d=>d.id)).size!==parsed.length)fail(400,'중복 문서 ID');
  if(!Array.isArray(x.measures)||!x.measures.length||x.measures.some(id=>!measures.has(id)))fail(400,'공급사 활용 후보는 제34조 위험관리·설명·이용자보호 조치만 허용합니다');
  const createdAt=new Date().toISOString(),until=new Date(createdAt);until.setUTCFullYear(until.getUTCFullYear()+5);
  const bundle={schemaVersion:2,id,systemId:system.id,synthetic:x.synthetic,...(provenance?{provenance}:{}),revision:(previous?.revision||0)+1,supplierId:cleanText(x.supplierId,200),modelId:cleanText(x.modelId,200),modelVersion:cleanText(x.modelVersion,200),purpose:cleanText(x.purpose,1000),testScope:cleanText(x.testScope,2000),measures:[...new Set(x.measures)],reviewerNotes:cleanText(x.reviewerNotes||'',2000),receivedBy:p.id,createdAt,retentionUntil:until.toISOString(),retentionBasis:'KR decree 27(2); local measure-document retention policy, not elapsed preservation proof',documents:parsed.map(({bytes,...d})=>({...d,bytes:bytes.length}))};
  bundle.contentHash=digest(bundle);
  for(const d of parsed)documents.put(p.tenant,d.bytes);
  store.transaction(()=>{store.put(p,'supplier_bundle',id,bundle);if(previous){const taskId=randomUUID();store.put(p,'governance_task',taskId,{id:taskId,systemId:system.id,bundleId:id,title:'공급사 증빙 변경: 연결 평가 재검토',owner:system.owner,status:'open',previousHash:previous.contentHash,currentHash:bundle.contentHash});}});
  return {...bundle,verification:verify(p,bundle,system)};
 }
 function evidence(p,ref,systemId){verifyProjection(p);const id=ref.slice('supplier-bundle:'.length),bundle=bundleState(p,id);if(bundle.systemId!==systemId)fail(400,'다른 시스템의 공급사 증빙입니다');return {contentHash:bundle.contentHash,verification:bundle.verification,measures:bundle.measures,...(bundle.synthetic===false?{provenanceReviewHash:bundle.verification.provenance.reviewHash||null}:{})};}
 function staleEvidence(p,assessment){return assessment.evidence.some(e=>e.ref?.startsWith('supplier-bundle:')&&(()=>{try{const current=evidence(p,e.ref,assessment.systemId);return current.contentHash!==e.contentHash||current.verification.status!=='technical_match_human_review_required'||Object.hasOwn(current,'provenanceReviewHash')&&current.provenanceReviewHash!==e.provenanceReviewHash;}catch{return true;}})());}
 function recordProvenanceReview(p,id,x){
  review(p);const bundle=get(p,'supplier_bundle',id);if(bundle.synthetic!==false)fail(400,'실제 자료로 신고한 증빙만 출처 검토할 수 있습니다');
  normalizeSupplierProvenance(bundle.synthetic,bundle.provenance);
  const decision=normalizeSupplierProvenanceReview(x,bundle),previous=provenanceState(p,bundle);
  const entry={id:randomUUID(),bundleId:id,bundleHash:bundle.contentHash,bundleRevision:bundle.revision,systemId:bundle.systemId,...decision,reviewer:p.id,reviewedAt:new Date().toISOString()};
  store.put(p,'supplier_provenance_review',entry.id,entry);
  for(const assessment of store.list(p.tenant,'assessment').filter(a=>a.systemId===bundle.systemId&&a.evidence?.some(e=>e.ref===`supplier-bundle:${id}`))){const taskId=randomUUID();store.put(p,'governance_task',taskId,{id:taskId,systemId:bundle.systemId,bundleId:id,requirementId:assessment.requirementId,title:'공급사 출처 검토 변경: 연결 평가 재검토',owner:assessment.owner,status:'open',previousReviewHash:previous.reviewHash||null,currentReviewHash:digest(entry)});}
  return entry;
 }
 function scopedHandle(p,method,url,x){
  const path=url.pathname;
  if(path==='/api/governance/bundles'&&method==='POST')return importBundle(p,x);
  if(/^\/api\/governance\/bundles\/[^/]+\/provenance-reviews$/.test(path)){
   const id=identifier(decodeURIComponent(path.split('/')[4]));if(method==='POST')return recordProvenanceReview(p,id,x);
   if(method==='GET'){const bundle=get(p,'supplier_bundle',id);return {bundleId:id,contentHash:bundle.contentHash,reviews:reviewHistory(p,id)};}
  }
  if(path==='/api/governance/finance'&&method==='GET')return view(p,identifier(url.searchParams.get('systemId')));
  if(/^\/api\/governance\/bundles\/[^/]+\/export$/.test(path)&&method==='GET'){
   const b=get(p,'supplier_bundle',decodeURIComponent(path.split('/')[4]));return {...b,documents:b.documents.map(d=>{try{return {...d,contentBase64:documents.read(p.tenant,d.sha256).toString('base64')};}catch{fail(409,'증빙 문서를 복구할 수 없습니다');}})};
  }
  if(path==='/api/governance/finance/report'&&method==='POST'){
   const systemId=identifier(x.systemId),governance=governanceReport(p,systemId),snapshot=JSON.parse(JSON.stringify({schemaVersion:1,id:randomUUID(),createdAt:new Date().toISOString(),reviewer:p.id,tenant:p.tenant,...view(p,systemId),governance,lawCatalogHash:digest(requirements),applicabilityPolicyVersion:governance.applicabilityPolicyVersion,applicabilityPolicyIdentityHash:governance.applicabilityPolicyIdentityHash,automaticLegalVerdict:false}));
   const receipt={snapshot,sha256:digest(snapshot),signature:sign(null,Buffer.from(canonical(snapshot)),key).toString('base64'),publicKey:createPublicKey(key).export({type:'spki',format:'pem'}),trust:'Pin vault public key independently; signature does not prove source truth'};
   return store.transaction(()=>store.put(p,'finance_report',snapshot.id,{id:snapshot.id,...receipt}));
  }
  if(/^\/api\/governance\/finance\/reports\/[^/]+$/.test(path)&&method==='GET')return get(p,'finance_report',decodeURIComponent(path.split('/').at(-1)));
 }
 function handle(p,method,url,x){
  if(!url.pathname.startsWith('/api/governance/bundles')&&!url.pathname.startsWith('/api/governance/finance'))return undefined;
  // Hold one SQLite writer lock from verification through lookup and signing.
  // Nested import/report operations use savepoints and cannot commit this scope.
  return store.transaction(()=>{verifyProjection(p);return scopedHandle(p,method,url,x);});
 }
 return {handle,evidence,staleEvidence,bundleState,view};
}
