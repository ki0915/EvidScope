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

export function createService({dataDir,config,key,requirements=[]}) {
 const store=new Store(dataDir,key);const publicKey=createPublicKey(key);const retention=createRetention(store),workbench=createAuditWorkbench(store,key),assistance=createAssistance(store,workbench),developmentRuns=createDevelopmentRuns(store);
 const principals=config.principals||[];
 const analysis=createAnalysis(store,principals);
 if(principals.some(p=>!p.id||!p.tenant||!p.token||p.token.length<32)||new Set(principals.map(p=>p.token)).size!==principals.length)throw Error('Invalid credential configuration');
 const human=p=>{if(!['auditor','reviewer','admin'].includes(p.role))fail(403,'인간 감사 계정만 접근할 수 있습니다');};
 const reviewer=p=>{if(!['reviewer','admin'].includes(p.role))fail(403,'검토자 권한이 필요합니다');};
 const admin=p=>{if(p.role!=='admin')fail(403,'관리자 권한이 필요합니다');};
 const auth=headers=>{const token=(headers.authorization||'').replace(/^Bearer /,'');const p=principals.find(x=>equal(x.token,token));if(!p)fail(401,'인증이 필요합니다');return p;};
 const dirty=(tenant)=>store.db.prepare('UPDATE actions SET version=version+1 WHERE tenant=?').run(tenant);
 const obj=(p,type,id)=>store.get(p.tenant,type,id)||fail(404,'대상을 찾을 수 없습니다');
 const safeObject=x=>{if(!x||typeof x!=='object'||Array.isArray(x))fail(400,'JSON 객체 필요');return x;};
 const snapshots=()=>{
  for(const tenant of new Set(principals.map(p=>p.tenant))){
   const p={id:'catalog-loader',tenant}; const previous=store.get(tenant,'catalog','current');const hash=digest(requirements);
   if(previous?.hash===hash)continue;
   store.transaction(()=>{
    const snapshot={hash,requirements,createdAt:new Date().toISOString()};store.put(p,'catalog','current',snapshot);
    if(previous)for(const a of store.list(tenant,'assessment')){const id=randomUUID();store.put(p,'governance_task',id,{id,systemId:a.systemId,requirementId:a.requirementId,title:'규정 출처/버전 변경에 따른 재검토',owner:a.owner,status:'open',previousHash:previous.hash,currentHash:hash});}
   });
  }
 };snapshots();
 function report(p,systemId){
  const system=obj(p,'system',systemId),assessments=store.list(p.tenant,'assessment').filter(a=>a.systemId===systemId);
  const items=requirements.map(requirement=>{
   const assessment=assessments.filter(a=>a.requirementId===requirement.id).sort((a,b)=>b.createdAt.localeCompare(a.createdAt))[0];
   let candidate='unknown';const art=String(requirement.article),j=String(requirement.jurisdiction);
   if(j.includes('KR')||j.includes('한국')||j.includes('Korea')){
    if(!system.markets.includes('KR'))candidate='unknown';
    else if(art.includes('31'))candidate=system.generative||system.highImpact==='confirmed'?'candidate':'unknown';
    else if(art.includes('34')||art.includes('35'))candidate=['candidate','confirmed'].includes(system.highImpact)?'candidate':'unknown';
    else candidate='unknown';
   }else if(String(requirement.framework).includes('NIST'))candidate='voluntary';
   const missingLinkedEvidence=assessment?.evidence.some(e=>e.type==='event'&&!store.events(p.tenant).some(v=>`${v.source}/${v.id}`===e.ref));
   const stale=assessment&&(assessment.requirementHash!==digest(requirement)||assessment.systemHash!==digest(system)||Date.parse(assessment.nextReviewAt)<=Date.now()||missingLinkedEvidence);
   const status=!assessment?'evidence_missing':stale?'review_required':assessment.applicability==='not_applicable'?'human_marked_not_applicable':assessment.assessment==='sufficient'&&assessment.evidence.length?'human_evidence_assessed':'evidence_insufficient';
   return {requirement,status,applicabilityCandidate:candidate,assessment,technicalStatus:assessment?.evidence?.some(e=>e.type==='event')?'event_linked_partial_support':'external_or_missing',legalStatus:stale?'review_required':assessment?.legalReview||'pending'};
  });return {system,items,tasks:store.list(p.tenant,'governance_task').filter(t=>t.systemId===systemId),limitations:['법적 적용성은 사실관계와 인간 검토를 요구합니다','증거 평가와 법적 준수 판정은 별개이며 자동 준수 통과를 발급하지 않습니다','한국 고영향과 EU 고위험 분류를 공유하지 않습니다','ISO/IEC 42001 본문 미확보: 조항 매핑 미지원']};
 }
 async function handle(method,url,headers,body=''){
  const path=url.pathname;
  if(path==='/healthz'&&method==='GET'){store.db.prepare('SELECT 1').get();return {status:'ready',component:'vault'};}
  if(path.startsWith('/internal/assistance/')){const result=assistance.internal(method,url,headers,body);if(result!==undefined)return result;}
  const p=auth(headers);
  const developmentResult=developmentRuns.handle(p,method,url,headers,body);if(developmentResult!==undefined)return developmentResult;
  if(path==='/api/ingest'&&method==='POST'){
   if(p.role!=='source')fail(403,'수집 출처 자격이 필요합니다');
   const ts=headers['x-evid-timestamp'],nonce=headers['x-evid-nonce'],signature=headers['x-evid-signature'];
   if(!/^\d{13}$/.test(ts||'')||Math.abs(Date.now()-Number(ts))>300000||!nonce||!/^[a-zA-Z0-9-]{16,80}$/.test(nonce))fail(401,'서명 시각 또는 nonce가 유효하지 않습니다');
   if(!p.hmacSecret||!equal(mac(p.hmacSecret,ts,nonce,body),signature||''))fail(401,'출처 서명 검증 실패');
   let raw;try{raw=JSON.parse(body);}catch{fail(400,'JSON 형식 오류');}const e=validateEvent(raw,p);
   return store.transaction(()=>{
    store.db.prepare('DELETE FROM nonces WHERE expires<?').run(Date.now());
    if(store.db.prepare('SELECT 1 FROM nonces WHERE source=? AND nonce=?').get(p.id,nonce))fail(409,'이미 사용한 nonce입니다');
    store.db.prepare('INSERT INTO nonces VALUES(?,?,?)').run(p.id,nonce,Date.now()+600000);
    const prev=store.db.prepare('SELECT fingerprint FROM receipts WHERE tenant=? AND source=? AND id=?').get(p.tenant,p.id,e.id);
    if(prev){if(prev.fingerprint!==e.fingerprint)fail(409,'동일 출처 이벤트 ID의 내용 충돌');store.count('duplicates');return {accepted:true,duplicate:true,durability:'sqlite_full_commit',analysis:'asynchronous',externalSeal:false};}
    const backlog=store.db.prepare('SELECT COUNT(*) n FROM actions WHERE analyzed<version').get().n;if(backlog>10000)fail(503,'분석 적체: 유한 재시도 후 로컬 손실 지표를 기록하세요');
    const record=store.append(p.tenant,'event',e,p.id);store.project({...e,seq:record.seq,hash:record.hash});
    store.db.prepare('INSERT INTO actions(tenant,id,version) VALUES(?,?,1) ON CONFLICT(tenant,id) DO UPDATE SET version=version+1').run(p.tenant,e.actionId);
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
  if(path.startsWith('/api/assistance/')){const result=assistance.human(p,method,url,x);if(result!==undefined)return result;}
  if(path.startsWith('/api/retention')){const result=retention.handle(p,method,path,x);if(result!==undefined)return result;}
  if(path==='/api/investigations'||path.startsWith('/api/cases/')){const result=workbench.handle(p,method,url,x);if(result!==undefined)return result;}
  if(path==='/api/overview'&&method==='GET'){
   const events=store.db.prepare('SELECT COUNT(*) n FROM events WHERE tenant=?').get(p.tenant).n;
   const actions=store.db.prepare('SELECT * FROM actions WHERE tenant=?').all(p.tenant);
   const alerts=actions.flatMap(a=>store.evaluations(p.tenant,a.id)[0]?.findings||[]);
   const sources=principals.filter(s=>s.tenant===p.tenant&&s.role==='source').map(s=>{const row=store.db.prepare('SELECT MAX(received) lastSeen FROM events WHERE tenant=? AND source=?').get(p.tenant,s.id);return {id:s.id,tenant:s.tenant,kind:s.kind,lastSeen:row.lastSeen,status:!row.lastSeen?'not_connected':Date.now()-Date.parse(row.lastSeen)>300000?'stale':'receiving'};});
   return {counts:{events,alerts:alerts.length,cases:store.list(p.tenant,'case').length,backlog:actions.filter(a=>a.analyzed<a.version).length},sources,limitations:['등록된 출처 기준 상태이며 전체 AI 사용의 가시성 비율은 산출하지 않습니다','미연결·수집 공백은 무사고를 의미하지 않습니다','외부 공급자 실연동 없음 — 합성 예제 프로파일']};
  }
  if(path==='/api/monitoring'&&method==='GET')return monitoring(store,principals,p.tenant,url.searchParams);
  if(path==='/api/agents'&&method==='GET')return agentInventory(store,principals,p.tenant,url.searchParams);
  if(path==='/api/events'&&method==='GET'){
   const q=(url.searchParams.get('q')||'').slice(0,200),kind=url.searchParams.get('kind'),trace=url.searchParams.get('traceId');
   let items=store.events(p.tenant).filter(e=>(!q||canonical(e).includes(q))&&(!kind||e.kind===kind)&&(!trace||e.traceId===trace));const total=items.length;const limit=Math.max(1,Math.min(500,Number(url.searchParams.get('limit'))||100));const offset=Math.max(0,Number(url.searchParams.get('offset'))||0);return {items:items.slice(offset,offset+limit),total,offset,limit};
  }
  if(path.startsWith('/api/actions/')&&method==='GET'){
   const actionId=decodeURIComponent(path.slice(13)),events=store.events(p.tenant,actionId);
   const references=events.flatMap(e=>(e.dataRefs||[]).map(ref=>({...ref,source:e.source,eventId:e.id,assurance:e.assurance,observedAt:e.occurredAt,verification:e.sourceKind==='agent'?'self_reported_reference':'service_reported_reference'})));
   const business=events.filter(e=>['intent','execution','self_report','result'].includes(e.kind)),v=store.db.prepare('SELECT version,analyzed FROM actions WHERE tenant=? AND id=?').get(p.tenant,actionId);
   return {events,references,analysis:{version:v?.version??null,analyzed:v?.analyzed??null,pending:!!v&&v.analyzed<v.version},evaluations:store.evaluations(p.tenant,actionId),referenceCoverage:{eventsWithReferences:business.filter(e=>e.dataRefs?.length).length,observedBusinessEvents:business.length,scope:'수신된 업무 이벤트 중 참조 메타데이터 제출 범위이며 전체 AI 지식·참고자료의 가시성 비율이 아닙니다'},limitations:['늦은 증거와 룰 변경은 새 평가 버전을 추가합니다','참고자료 참조는 source의 보고입니다. 모델이 실제 읽거나 판단에 사용했음을 자동 확정하지 않습니다','원문 prompt/response·자료 내용은 기본 미수집; version/hash는 사람이 외부 원본과 대조해야 합니다',...(!references.length?['참고 데이터 출처 미수집: 어떤 자료를 참고했는지 확인할 수 없습니다']:[])]};
  }
  if(path==='/api/alerts'&&method==='GET'){
   const actions=store.db.prepare('SELECT id FROM actions WHERE tenant=?').all(p.tenant);return {items:actions.flatMap(a=>{const ev=store.evaluations(p.tenant,a.id)[0];return (ev?.findings||[]).map((f,i)=>({...f,id:`${ev.id}:${i}`,actionId:a.id,createdAt:ev.createdAt,state:f.suppressedBy?'suppressed':'open'}));})};
  }
  if(path==='/api/assets'&&method==='GET')return {items:store.list(p.tenant,'asset')};
  if(path==='/api/metrics'&&method==='GET')return {vaultRssBytes:process.memoryUsage().rss,events:store.db.prepare('SELECT COUNT(*) n FROM events WHERE tenant=?').get(p.tenant).n,ledgerRecords:store.db.prepare('SELECT COUNT(*) n FROM ledger WHERE tenant=?').get(p.tenant).n,analyzedEvents:store.db.prepare('SELECT COUNT(*) n FROM events e JOIN actions a ON a.tenant=e.tenant AND a.id=e.action_id WHERE e.tenant=? AND a.analyzed=a.version').get(p.tenant).n,backlog:store.db.prepare('SELECT COUNT(*) n FROM actions WHERE tenant=? AND analyzed<version').get(p.tenant).n,scope:'tenant counts; vault process memory shared across tenants'};
  if(path==='/api/assets'&&method==='POST'){reviewer(p);const a={id:identifier(x.id),actor:cleanText(x.actor,256),tool:cleanText(x.tool,256),owner:cleanText(x.owner,200),purpose:cleanText(x.purpose||'',500),version:cleanText(x.version||'unknown',100),policyVersion:cleanText(x.policyVersion||'unknown',100),validFrom:date(x.validFrom||new Date().toISOString()),destinations:(x.destinations||[]).slice(0,30).map(s=>cleanText(s,256)),updatedAt:new Date().toISOString()};if(x.validUntil){a.validUntil=date(x.validUntil);if(Date.parse(a.validUntil)<=Date.parse(a.validFrom))fail(400,'자산 정책 유효기간 역전');}return store.transaction(()=>{store.put(p,'asset',a.id,a);dirty(p.tenant);return a;});}
  if(path==='/api/cases'&&method==='GET')return {items:store.list(p.tenant,'case')};
  if(path==='/api/cases'&&method==='POST'){
   const c={id:randomUUID(),title:cleanText(x.title,200),actionId:identifier(x.actionId),owner:cleanText(x.owner,200),status:'open',comments:[],tasks:[],history:[{by:p.id,at:new Date().toISOString(),action:'created'}]};if(!store.events(p.tenant,c.actionId).length)fail(400,'사건에 연결할 관측 행동이 없습니다');return store.transaction(()=>store.put(p,'case',c.id,c));
  }
  if(path.startsWith('/api/cases/')&&method==='POST'){
   const id=identifier(path.split('/').pop());return store.transaction(()=>{const c=obj(p,'case',id);if(x.status&&!['open','in_review','closed'].includes(x.status))fail(400,'사건 상태 오류');if(x.status==='closed'&&!x.reason)fail(400,'종결 사유 필요');if(x.owner)c.owner=cleanText(x.owner,200);if(x.status)c.status=x.status;
    if(x.comment)c.comments.push({by:p.id,at:new Date().toISOString(),text:cleanText(x.comment,2000)});
    if(x.task){const t=x.task;const task={id:t.id||randomUUID(),title:cleanText(t.title,200),owner:cleanText(t.owner,200),dueAt:date(t.dueAt),status:t.status==='closed'?'closed':'open'};const index=c.tasks.findIndex(v=>v.id===task.id);if(index<0)c.tasks.push(task);else c.tasks[index]=task;}
    c.history.push({by:p.id,at:new Date().toISOString(),status:c.status,reason:cleanText(x.reason||'',1000)});return store.put(p,'case',id,c);});
  }
  if(path==='/api/rules'&&method==='GET')return {items:store.list(p.tenant,'rule').flatMap(r=>r.versions)};
  if(path==='/api/rules'&&method==='POST'){reviewer(p);return store.transaction(()=>{if(store.list(p.tenant,'rule').length>=100&&!store.get(p.tenant,'rule',x.id))fail(409,'테넌트 룰 한도 100');const r=store.get(p.tenant,'rule',x.id)||{id:x.id,versions:[]};const v=validateRule(x,p,r.versions.length+1);r.versions.push(v);store.put(p,'rule',x.id,r);return v;});}
  if(/^\/api\/rules\/[^/]+\/(test|approve)$/.test(path)&&method==='POST'){
   reviewer(p);const [, , ,id,operation]=path.split('/');return store.transaction(()=>{const r=obj(p,'rule',id),v=r.versions.find(v=>v.version===Number(x.version));if(!v)fail(404,'룰 버전 없음');if(operation==='test'){const ev=store.events(p.tenant).slice(-1000);const result={version:v.version,testedBy:p.id,testedAt:new Date().toISOString(),evaluated:ev.length,matches:ev.filter(e=>matches(v,e)).map(e=>`${e.source}/${e.id}`),bounded:true};v.test=result;store.put(p,'rule',id,r);return result;}
    if(v.author===p.id)fail(403,'자신이 작성한 룰을 단독 승인할 수 없습니다');if(v.status!=='draft'||!v.test)fail(409,'시험한 초안만 승인 가능');for(const old of r.versions)if(old.status==='active')old.status='retired';v.status='active';v.approvedBy=p.id;v.approvedAt=new Date().toISOString();store.put(p,'rule',id,r);dirty(p.tenant);return v;});
  }
  if(path==='/api/exceptions'&&method==='GET')return {items:store.list(p.tenant,'exception')};
  if(path==='/api/exceptions'&&method==='POST'){
   const end=date(x.expiresAt);if(Date.parse(end)<=Date.now()||Date.parse(end)>Date.now()+90*86400000)fail(400,'예외 유효기간은 현재 이후 최대 90일');const e={id:randomUUID(),ruleId:identifier(x.ruleId),actionId:identifier(x.actionId),reason:cleanText(x.reason,1000),owner:cleanText(x.owner,200),expiresAt:end,status:'pending',author:p.id};return store.transaction(()=>store.put(p,'exception',e.id,e));
  }
  if(/^\/api\/exceptions\/[^/]+\/approve$/.test(path)&&method==='POST'){reviewer(p);return store.transaction(()=>{const e=obj(p,'exception',path.split('/')[3]);if(e.author===p.id||e.owner===p.id)fail(403,'자신이 작성하거나 소유한 예외를 단독 승인할 수 없습니다');if(Date.parse(e.expiresAt)<=Date.now())fail(409,'만료된 예외');e.status='approved';e.approvedBy=p.id;store.put(p,'exception',e.id,e);dirty(p.tenant);return e;});}
  if(path==='/api/export'&&method==='GET')return store.transaction(()=>store.bundle(p.tenant));
  if(path==='/api/integrity'&&method==='GET'){
   try{const result=store.transaction(()=>({...verifyBundle(store.bundle(p.tenant),publicKey),projection:store.checkProjection(p.tenant)}));store.audit(p,'read',path);return result;}catch(e){let failureRecorded=true;try{store.transaction(()=>store.append(p.tenant,'integrity_failure',{message:e.message},p.id));}catch{failureRecorded=false;}return {valid:false,error:e.message,failureRecorded,requiresExternalIncidentRecord:!failureRecorded};}
  }
  if(path==='/api/rebuild'&&method==='POST'){admin(p);verifyBundle(store.bundle(p.tenant),publicKey);return store.rebuild(p);}
  if(path==='/api/governance'&&method==='GET')return {requirements,systems:store.list(p.tenant,'system'),assessments:store.list(p.tenant,'assessment'),tasks:store.list(p.tenant,'governance_task')};
  if(path==='/api/governance/systems'&&method==='POST'){
   const s={id:identifier(x.id),name:cleanText(x.name,200),owner:cleanText(x.owner,200),purpose:cleanText(x.purpose,1000),role:cleanText(x.role,200),markets:(x.markets||[]).slice(0,20).map(v=>cleanText(v,100)),domain:cleanText(x.domain||'unknown',200),generative:x.generative===true,highImpact:['unknown','candidate','confirmed','no'].includes(x.highImpact)?x.highImpact:'unknown',euHighRisk:cleanText(x.euHighRisk||'unknown',100),dataCategories:(x.dataCategories||[]).slice(0,20).map(v=>cleanText(v,100)),affectedPeople:cleanText(x.affectedPeople||'unknown',500),status:'human_applicability_review_required',updatedAt:new Date().toISOString()};
   return store.transaction(()=>{const before=store.get(p.tenant,'system',s.id);if(before){const id=randomUUID();store.put(p,'governance_task',id,{id,systemId:s.id,title:'시스템 사실관계 변경: 적용성 재검토',owner:s.owner,status:'open'});}return store.put(p,'system',s.id,s);});
  }
  if(path==='/api/governance/assessments'&&method==='POST'){
   obj(p,'system',x.systemId);const requirement=requirements.find(r=>r.id===x.requirementId);if(!requirement)fail(400,'확인한 요구사항이 아닙니다');
   if(!['applicable','not_applicable','unknown'].includes(x.applicability)||!['sufficient','insufficient','unknown'].includes(x.assessment)||!['pending','reviewed'].includes(x.legalReview))fail(400,'평가 상태 오류');
   if(!Array.isArray(x.evidence)||x.evidence.length>30)fail(400,'증거는 최대 30개');
   const evidence=x.evidence.map(e=>{if(!['document','event','test','attestation'].includes(e.type))fail(400,'증거 유형 오류');const ref=cleanText(e.ref,1000);if(e.type==='event'&&!store.events(p.tenant).some(v=>`${v.source}/${v.id}`===ref))fail(400,'동일 tenant 원본 이벤트 참조를 찾을 수 없습니다');return {type:e.type,ref,version:cleanText(e.version||'unknown',200),notes:cleanText(e.notes||'',1000),contentHash:cleanText(e.contentHash||'not_provided',100),verification:e.type==='event'?'linked_minimized_record':'human_supplied_reference_not_fetched'};});
   if(x.assessment==='sufficient'&&!evidence.length)fail(400,'증거 없이 충분으로 평가할 수 없습니다');
   const a={id:randomUUID(),systemId:x.systemId,systemHash:digest(obj(p,'system',x.systemId)),requirementId:x.requirementId,requirementHash:digest(requirement),requirementSnapshot:requirement,applicability:x.applicability,evidence,control:cleanText(x.control,1000),owner:cleanText(x.owner,200),assessment:x.assessment,legalReview:x.legalReview,reason:cleanText(x.reason,2000),nextReviewAt:date(x.nextReviewAt),reviewer:p.id,createdAt:new Date().toISOString()};
   return store.transaction(()=>{store.put(p,'assessment',a.id,a);if(a.assessment!=='sufficient'||a.legalReview==='pending')store.put(p,'governance_task',a.id,{id:a.id,systemId:a.systemId,requirementId:a.requirementId,title:a.assessment!=='sufficient'?'증거 보완 및 인간 재검토':'법률 적용성 검토',owner:a.owner,dueAt:a.nextReviewAt,status:'open'});return a;});
  }
  if(path==='/api/governance/report'&&method==='GET')return report(p,url.searchParams.get('systemId'));
  if(path.startsWith('/api/governance/tasks/')&&method==='POST'){return store.transaction(()=>{const id=path.split('/').pop(),t=obj(p,'governance_task',id);t.status=x.status==='closed'?'closed':'open';t.reason=cleanText(x.reason,1000);t.reviewedBy=p.id;t.reviewedAt=new Date().toISOString();return store.put(p,'governance_task',id,t);});}
  fail(404,'지원하지 않는 경로 또는 메서드');
 }
 return {store,handle,analysis,assistance};
}
