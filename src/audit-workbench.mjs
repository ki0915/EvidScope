import {randomUUID,sign,createHash,createPublicKey} from 'node:crypto';
import {canonical,digest} from './crypto.mjs';
import {decryptEvent} from './encryption.mjs';
import {fail,cleanText,identifier,date} from './model.mjs';

const limits={events:1000,evaluations:100,decisions:200,contextBytes:8*1024*1024,reportBytes:10*1024*1024,rowBytes:2*1024*1024};
const limitations=['수신된 최소 메타데이터와 외부 출처 보고를 검토합니다. 전체 AI 내부 사고·원문·실제 자료 이용은 확인하지 않습니다.','사람의 결론은 명시한 범위와 당시 증거에 한정됩니다. 법적 준수·인증·무사고 보증이 아닙니다.','보존 종료·늦은 증거·분석 변경·재검토 기한 도래 시 기존 결론의 재검토가 필요합니다.'];
const bytes=x=>Buffer.byteLength(JSON.stringify(x));
const required=(x,max)=>{const v=cleanText(x,max).trim();if(!v)fail(400,'빈 검토 근거·범위·한계는 허용하지 않습니다');return v;};
const same=(a,b)=>canonical(a)===canonical(b);
const refs=events=>events.flatMap(e=>(e.dataRefs||[]).map(ref=>({...ref,source:e.source,eventId:e.id,assurance:e.assurance,observedAt:e.occurredAt,verification:e.sourceKind==='agent'?'self_reported_reference':'service_reported_reference'})));
const sortEvents=events=>events.sort((a,b)=>a.receivedAt.localeCompare(b.receivedAt)||a.source.localeCompare(b.source)||a.id.localeCompare(b.id));
const contextHash=(tenant,actionId,events,evaluations,version)=>digest({tenant,actionId,events,evaluations,analysis:{version:version?.version??null,analyzed:version?.analyzed??null}});
const state=(decision,hash,now=Date.now())=>!decision?'unreviewed':decision.contextHash!==hash||Date.parse(decision.nextReviewAt)<=now?'stale':decision.conclusion==='inconclusive'?'inconclusive':'reviewed';
const outcome=events=>{const results=events.filter(e=>e.sourceKind==='tool'&&e.kind==='result');const success=results.some(e=>e.status==='success'),failure=results.some(e=>e.status==='failure');return success&&failure?'mixed_results':success?'independently_reported_success':failure?'independently_reported_failure':'unconfirmed';};
const distinct=(events,key)=>{const values=[...new Set(events.map(e=>e[key]).filter(Boolean))];return values.length>1?'multiple':values[0]||'unknown';};

export function createAuditWorkbench(store,key){
 const publicKey=createPublicKey(key),publicKeyFingerprint=createHash('sha256').update(publicKey.export({format:'der',type:'spki'})).digest('hex');
 const human=p=>{if(!['auditor','reviewer','admin'].includes(p.role))fail(403,'인간 감사 계정만 접근할 수 있습니다');};
 function boundedRows(sql,args,maxCount){
  const rows=[];let size=0;for(const row of store.db.prepare(`SELECT CASE WHEN length(CAST(body AS BLOB))<=? THEN body ELSE NULL END AS body FROM (${sql})`).iterate(limits.rowBytes,...args)){
   if(row.body===null||rows.length>=maxCount||(size+=Buffer.byteLength(row.body))>limits.contextBytes)fail(413,'검토 자료 한도 초과: 범위를 나누거나 별도 원장 내보내기를 사용하세요');
   rows.push(JSON.parse(row.body));
  }return rows;
 }
 const projectedEvents=(tenant,actionId)=>boundedRows('SELECT body FROM events WHERE tenant=? AND action_id=? ORDER BY received,source,id',[tenant,actionId],limits.events);
 const projectedEvaluations=(tenant,actionId)=>boundedRows('SELECT body FROM evaluations WHERE tenant=? AND action_id=? ORDER BY id DESC',[tenant,actionId],limits.evaluations);
 const projectedDecisions=(tenant,caseId)=>boundedRows("SELECT body FROM objects WHERE tenant=? AND type='case_decision' AND json_extract(body,'$.caseId')=? ORDER BY rowid DESC",[tenant,caseId],limits.decisions);
 const version=(tenant,actionId)=>store.db.prepare('SELECT version,analyzed FROM actions WHERE tenant=? AND id=?').get(tenant,actionId);
 function getCase(p,id){const row=store.db.prepare("SELECT CASE WHEN length(CAST(body AS BLOB))<=? THEN body ELSE NULL END AS body FROM objects WHERE tenant=? AND type='case' AND id=?").get(limits.rowBytes,p.tenant,id);if(!row)fail(404,'사건을 찾을 수 없습니다');if(row.body===null)fail(413,'사건 기록 한도 초과');return JSON.parse(row.body);}
 function verifyContext(p,id){
  const projectedCase=getCase(p,id),actionId=projectedCase.actionId;
  const events=[],evaluations=[],decisions=[];let originalCase=null,totalBytes=0,retainedCount=0;
  const collect=(arr,value,count)=>{if(arr.length>=count||(totalBytes+=bytes(value))>limits.contextBytes)fail(413,'사건 검토 자료 한도 초과: 부분 결과를 발급하지 않습니다');arr.push(value);};
  const eventProjection=store.db.prepare(`SELECT CASE WHEN length(CAST(body AS BLOB))<=${limits.rowBytes} THEN body ELSE NULL END AS body FROM events WHERE tenant=? AND source=? AND id=?`),keyQuery=store.db.prepare('SELECT key FROM event_keys WHERE tenant=? AND key_id=?');
  const disposed=store.db.prepare("SELECT 1 FROM ledger l,json_each(l.body,'$.payload.keyIds') k WHERE l.tenant=? AND l.seq>? AND json_extract(l.body,'$.type')='retention_disposition' AND k.value=? LIMIT 1");
  for(const row of store.verifiedRows(p.tenant,limits.rowBytes)){
   if(row.oversized)fail(413,'원장 단일 기록이 검토 한도를 초과했습니다');
   if(row.type==='retention_disposition'){for(const keyId of row.payload.keyIds||[])if(keyQuery.get(p.tenant,keyId))fail(409,'정당한 파기 이력과 실제 키 상태가 일치하지 않습니다');}
   if(row.type==='event'){
    let event=row.payload;
    if(event.format==='evidscope-encrypted-event-v1'){
     if(event.tenant!==p.tenant||event.seq!==row.seq)fail(409,'이벤트 암호화 봉투 범위 불일치');
     const k=keyQuery.get(p.tenant,event.keyId);if(!k){if(!disposed.get(p.tenant,row.seq,event.keyId))fail(409,'정당한 파기 증거 없이 이벤트 키가 누락되었습니다');continue;}event=decryptEvent(event,k.key);
    }
    const original={...event,seq:row.seq,hash:row.hash},projected=eventProjection.get(p.tenant,event.source,event.id);retainedCount++;
    if(!projected||projected.body===null||!same(JSON.parse(projected.body),original))fail(409,'원본 이벤트와 조회 사본이 다릅니다. 무결성을 확인하세요');
    if(event.actionId===actionId)collect(events,original,limits.events);
   }else if(row.type==='case'&&row.payload.id===id)originalCase=row.payload;
   else if(row.type==='evaluation'&&row.payload.actionId===actionId)collect(evaluations,row.payload,limits.evaluations);
   else if(row.type==='case_decision'&&row.payload.caseId===id)collect(decisions,row.payload,limits.decisions);
  }
  if(retainedCount!==store.db.prepare('SELECT COUNT(*) n FROM events WHERE tenant=?').get(p.tenant).n)fail(409,'원본에 없는 조회 이벤트가 존재합니다');
  if(!originalCase||!same(originalCase,projectedCase))fail(409,'사건 조회 사본이 서명 원장과 일치하지 않습니다');
  sortEvents(events);evaluations.reverse();decisions.reverse();
  if(!same(evaluations,projectedEvaluations(p.tenant,actionId)))fail(409,'분석 조회 사본이 서명 원장과 일치하지 않습니다');
  const order=a=>[...a].sort((a,b)=>a.id.localeCompare(b.id));
  if(!same(order(decisions),order(projectedDecisions(p.tenant,id))))fail(409,'인간 판단 조회 사본이 서명 원장과 일치하지 않습니다');
  const actionVersion=version(p.tenant,actionId),hash=contextHash(p.tenant,actionId,events,evaluations,actionVersion),latestDecision=decisions[0]||null;
  const context={case:originalCase,events,references:refs(events),evaluations,analysis:{version:actionVersion?.version??null,analyzed:actionVersion?.analyzed??null,pending:!!actionVersion&&actionVersion.analyzed<actionVersion.version},contextHash:hash,reviewState:state(latestDecision,hash),latestDecision,decisions,limitations};
  if(bytes(context)>limits.contextBytes)fail(413,'사건 검토 문맥 한도 초과');return context;
 }
 function decide(p,id,x){
  if(!x||typeof x!=='object'||Array.isArray(x)||Object.keys(x).some(k=>!['contextHash','conclusion','reason','scope','limitations','nextReviewAt','evidence'].includes(k)))fail(400,'지원하지 않는 인간 판단 필드');
  if(!/^[a-f0-9]{64}$/.test(x.contextHash||''))fail(400,'검토 문맥 hash가 필요합니다');
  if(!['confirmed_issue','no_issue_found','inconclusive'].includes(x.conclusion))fail(400,'사람의 판단 결론이 유효하지 않습니다');
  const reason=required(x.reason,3000),scope=required(x.scope,2000),reviewLimitations=required(x.limitations,2000),nextReviewAt=date(x.nextReviewAt);
  if(Date.parse(nextReviewAt)<=Date.now())fail(400,'재검토 기한은 현재 이후여야 합니다');
  if(!Array.isArray(x.evidence)||x.evidence.length>30||(x.conclusion!=='inconclusive'&&!x.evidence.length))fail(400,'확정 결론에는 증거가 필요하며 최대 30개까지 연결할 수 있습니다');
  return store.transaction(()=>{
   const context=verifyContext(p,id);if(context.contextHash!==x.contextHash)fail(409,'증거나 분석 문맥이 바뀌었습니다. 다시 조회하고 검토하세요');
   const available=new Set(context.events.map(e=>`${e.source}/${e.id}`));
   const evidence=x.evidence.map(e=>{if(!e||typeof e!=='object'||Array.isArray(e)||Object.keys(e).some(k=>!['ref','supports','note'].includes(k))||!available.has(e.ref)||!['supports','contradicts','context'].includes(e.supports))fail(400,'같은 사건 행동의 보존된 증거 참조와 근거 구분이 필요합니다');return {ref:e.ref,supports:e.supports,note:cleanText(e.note??'',1000)};});
   if(new Set(evidence.map(e=>e.ref)).size!==evidence.length)fail(400,'증거 참조를 중복해서 제출할 수 없습니다');
   if(Date.parse(nextReviewAt)<=Date.now())fail(400,'재검토 기한이 지나 다시 입력해야 합니다');
   const decision={id:randomUUID(),caseId:id,actionId:context.case.actionId,contextHash:context.contextHash,conclusion:x.conclusion,reason,scope,limitations:reviewLimitations,nextReviewAt,evidence,
    evidenceManifest:context.events.map(e=>({ref:`${e.source}/${e.id}`,hash:e.hash,seq:e.seq})),evaluationManifest:context.evaluations.map(e=>({id:e.id,version:e.version})),analysisVersion:context.analysis,
    checkpoint:JSON.parse(store.db.prepare('SELECT body FROM checkpoints WHERE tenant=?').get(p.tenant).body),reviewedBy:p.id,createdAt:new Date().toISOString()};
   return store.put(p,'case_decision',decision.id,decision);
  });
 }
 function report(p,id){return store.transaction(()=>{
  const context=verifyContext(p,id),checkpoint=JSON.parse(store.db.prepare('SELECT body FROM checkpoints WHERE tenant=?').get(p.tenant).body);
  const snapshot={tenant:p.tenant,exportedAt:new Date().toISOString(),exportedBy:p.id,case:context.case,action:{actionId:context.case.actionId,events:context.events,references:context.references,evaluations:context.evaluations,analysis:context.analysis},review:{state:context.reviewState,latestDecision:context.latestDecision,decisions:context.decisions,contextHash:context.contextHash},checkpoint,limitations:[...limitations,'이 서명은 EvidScope 서버가 이 보고서 문맥을 발급했다는 증명이며 외부 사실 확인·독립 시각 봉인·법적 결론 보증이 아닙니다.','전체 서명 원장과 독립 신뢰 기준점은 별도 /api/export로 확보해야 합니다. 공개키 지문은 신뢰할 수 있는 별도 경로로 대조하세요.','테넌트 이벤트 조회 사본과 이 사건·분석·인간 판단 사본을 서명 원장과 대조했습니다.']};
  const signed={format:'evidscope-case-report-v1',snapshot};if(bytes(signed)>limits.reportBytes-1024)fail(413,'서명 보고서 크기 한도 초과');
  return {...signed,signature:sign(null,Buffer.from(canonical(signed)),key).toString('base64'),publicKeyFingerprint};
 });}
 function investigations(p,params){
  const q=cleanText(params.get('q')||'',200).trim(),filter=params.get('state')||'all';if(!['needs_review','reviewed','all'].includes(filter))fail(400,'검토 상태 필터 오류');
  const pageNumber=(name,fallback,max)=>{const s=params.get(name);if(s===null)return fallback;const n=Number(s);if(!Number.isSafeInteger(n)||n<0||(name==='limit'&&n<1)||n>max)fail(400,'목록 페이지 범위 오류');return n;};
  const limit=pageNumber('limit',50,100),offset=pageNumber('offset',0,10000000),pattern=`%${q.replace(/[\\%_]/g,'\\$&')}%`;
  const rows=store.db.prepare(`SELECT a.*, (SELECT MAX(received) FROM events e WHERE e.tenant=a.tenant AND e.action_id=a.id) AS last_seen FROM actions a WHERE a.tenant=? AND
   (?='' OR a.id LIKE ? ESCAPE '\\' OR EXISTS(SELECT 1 FROM events e WHERE e.tenant=a.tenant AND e.action_id=a.id AND e.body LIKE ? ESCAPE '\\')) ORDER BY last_seen DESC,a.id`);
  const items=[],counts={needsReview:0,reviewed:0,analysisPending:0};let total=0,itemBytes=4096;
  for(const row of rows.iterate(p.tenant,q,pattern,pattern)){
   let events=[],evaluations=[],detailUnavailable=false;
   try{events=projectedEvents(p.tenant,row.id);evaluations=projectedEvaluations(p.tenant,row.id);}catch(e){if(e.status!==413)throw e;detailUnavailable=true;}
   const caseIds=[];for(const c of store.db.prepare("SELECT id FROM objects WHERE tenant=? AND type='case' AND json_extract(body,'$.actionId')=? ORDER BY id").iterate(p.tenant,row.id)){if(caseIds.length>=1000)fail(413,'행동에 연결된 사건 수가 조회 한도를 초과했습니다');caseIds.push(c.id);}
   const last=store.db.prepare(`SELECT CASE WHEN length(CAST(body AS BLOB))<=${limits.rowBytes} THEN body ELSE NULL END AS body FROM objects WHERE tenant=? AND type='case_decision' AND json_extract(body,'$.actionId')=? ORDER BY rowid DESC LIMIT 1`).get(p.tenant,row.id);if(last?.body===null)fail(413,'사람 판단 기록 크기 한도 초과');
   const latestDecision=last?JSON.parse(last.body):null,hash=detailUnavailable?null:contextHash(p.tenant,row.id,events,evaluations,row),reviewState=state(latestDecision,hash),pending=row.analyzed<row.version;
   const latest=evaluations[0]||(detailUnavailable?boundedRows('SELECT body FROM evaluations WHERE tenant=? AND action_id=? ORDER BY id DESC LIMIT 1',[p.tenant,row.id],1)[0]:null),findings=latest?.findings||[];
   if(pending)counts.analysisPending++;if(reviewState==='reviewed')counts.reviewed++;else counts.needsReview++;
   if(filter==='reviewed'&&reviewState!=='reviewed'||filter==='needs_review'&&reviewState==='reviewed')continue;
   total++;if(total<=offset||items.length>=limit)continue;
   const analysisStatus=latest?.status==='quarantined_resource_limit'&&latest.version===row.version?'quarantined_resource_limit':pending?'pending':latest?'evaluated':'not_observed';
   const highestSeverity=['high','medium','low'].find(s=>findings.some(f=>f.severity===s))||(latest?'none':'unknown'),references=refs(events),attention=[];
   if(pending)attention.push('새 증거 또는 정책 변경에 대한 분석이 아직 완료되지 않았습니다');
   if(analysisStatus==='quarantined_resource_limit'||detailUnavailable)attention.push('자료 한도 초과로 상세 분석·검토가 제한됩니다. 무사고를 뜻하지 않습니다');
   if(!references.length)attention.push('참고 데이터 출처가 제출되지 않아 실제 참고 자료를 확인할 수 없습니다');
   if(!latestDecision)attention.push('사람의 검토 결론이 아직 없습니다');else if(reviewState==='stale')attention.push('증거·분석 변경 또는 재검토 기한 도래로 이전 판단을 다시 검토해야 합니다');else if(reviewState==='inconclusive')attention.push('사람이 판단을 유보했습니다. 추가 증거와 후속 검토가 필요합니다');
   if(latest?.coverage?.truncated)attention.push('분석 findings 표시가 제한되어 전체 탐지 수와 표시 수가 다릅니다');
   const result=outcome(events);if(result==='mixed_results')attention.push('독립 서비스가 성공과 실패를 모두 보고했습니다. 개별 결과를 대조하세요');
   const timestamps=events.map(e=>e.receivedAt).sort();
   const item={actionId:row.id,traceIds:[...new Set(events.map(e=>e.traceId).filter(Boolean))],actor:distinct(events,'actor'),tool:distinct(events,'tool'),operation:distinct(events,'action'),resource:distinct(events,'resource'),destination:distinct(events,'destination'),firstSeen:timestamps[0]||null,lastSeen:timestamps.at(-1)||row.last_seen||null,eventCount:store.db.prepare('SELECT COUNT(*) n FROM events WHERE tenant=? AND action_id=?').get(p.tenant,row.id).n,referenceCount:detailUnavailable?null:references.length,highestSeverity,findingCount:detailUnavailable?null:latest?.coverage?.totalFindings??findings.length,analysisStatus,pending,reviewState,latestDecision,caseIds,attention,outcome:detailUnavailable?'unconfirmed':result,authority:latest?.authority||'not_observed'};
   if((itemBytes+=bytes(item))>limits.reportBytes)fail(413,'조사 목록 응답 크기 한도 초과: limit를 줄여 다시 조회하세요');items.push(item);
  }
  return {items,total,limit,offset,counts,scope:'검색어에 일치하는 테넌트 행동의 조회 사본 기준입니다. counts는 검토 상태 필터 적용 전입니다. 서명 원본·사본 무결성은 사건 검토 및 보고서 발급 시 대조합니다. 전체 AI 사용의 가시성 비율이 아닙니다.'};
 }
 function handle(p,method,url,x){human(p);const path=url.pathname;
  if(path==='/api/investigations'&&method==='GET')return investigations(p,url.searchParams);
  const match=path.match(/^\/api\/cases\/([^/]+)\/(review-context|decisions|report)$/);if(!match)return undefined;
  const id=identifier(decodeURIComponent(match[1])),operation=match[2];
  if(operation==='review-context'&&method==='GET')return store.transaction(()=>verifyContext(p,id));
  if(operation==='decisions'&&method==='POST')return decide(p,id,x);
  if(operation==='report'&&method==='GET')return report(p,id);
  fail(405,'검토 이력은 수정할 수 없으며 지원하는 조회·추가 메서드만 사용할 수 있습니다');
 }
 return {handle};
}
