import {randomUUID} from 'node:crypto';
import {cleanText,date,identifier,fail} from './model.mjs';
import {canonical,digest,isEncryptedEvent,verifyBundle} from './crypto.mjs';
import {ROTATION_PRINCIPAL,ROTATION_TYPE,checkRotationHistory,eventRotationClass,requiredRotationSeconds,rotationTermsProblem,verifyRotationHistory}
 from './retention-rotation.mjs';
import {ACCESS_PRUNE_TYPE} from './access-log.mjs';

// Destruction is an explicit two-person operation: a plan per erasure, or a rotation policy two people activated beforehand
// (src/retention-rotation.mjs). Changing policy is never retroactive.
// rotation: {intervalMs} runs every activated rotation policy on that interval (off when absent); accessLog prunes sealed ranges.
export function createRetention(store,{rotation:{intervalMs=0}={},accessLog}={}){
 const review=p=>{if(!['reviewer','admin'].includes(p.role))fail(403,'보존 검토자 권한이 필요합니다');};
 const admin=p=>{if(p.role!=='admin')fail(403,'파기 실행은 관리자 권한이 필요합니다');};
 const get=(p,type,id)=>store.get(p.tenant,type,id)||fail(404,'보존 대상을 찾을 수 없습니다');
 function verifyProjection(p){
  const bundle=store.bundle(p.tenant);verifyBundle(bundle,store.publicKey);
  const types=['retention_policy','retention_hold','retention_plan','case',ROTATION_TYPE],latest=new Map(types.map(type=>[type,new Map()]));
  for(const row of bundle.records)if(latest.has(row.type))latest.get(row.type).set(row.payload.id,row.payload);
  // These projections control irreversible erasure. Check their row identifiers,
  // contents and omissions against the signed history before reading authority.
  for(const type of types){
   const original=latest.get(type),rows=store.db.prepare('SELECT id,body FROM objects WHERE tenant=? AND type=?').all(p.tenant,type);
   if(rows.length!==original.size||rows.some(row=>!original.has(row.id)||canonical(JSON.parse(row.body))!==canonical(original.get(row.id))))fail(409,'보존 판단 사본이 서명 원장과 일치하지 않습니다');
  }
  return bundle;
 }
 function scan(p){
  const bundle=verifyProjection(p);const originals=store.ledgerEvents(p.tenant);const bySeq=new Map(originals.map(e=>[e.seq,e]));
  const signedReceiptSequences=new Set(bundle.records.filter(r=>r.type==='event_receipt').map(r=>r.payload?.eventSeq));
  const holds=store.list(p.tenant,'retention_hold').filter(h=>h.status==='active');const cases=store.list(p.tenant,'case').filter(c=>c.status!=='closed');
  const disposed=new Set(bundle.records.filter(r=>r.type==='retention_disposition').flatMap(r=>r.payload.keyIds));
  const items=bundle.records.filter(r=>r.type==='event'&&isEncryptedEvent(r.payload)&&!disposed.has(r.payload.keyId)).map(r=>{
   const e=bySeq.get(r.seq),blockingHolds=holds.filter(h=>h.scope==='tenant'||h.scope===e.actionId).map(h=>h.id);const openCases=cases.filter(c=>c.actionId===e.actionId).map(c=>c.id);
   return {seq:r.seq,keyId:r.payload.keyId,source:e.source,eventId:e.id,fingerprint:e.fingerprint,eventHash:e.hash,receiptSigned:signedReceiptSequences.has(r.seq),actionId:e.actionId,retainUntil:r.payload.retainUntil,policyVersion:r.payload.policyVersion,expired:Date.parse(r.payload.retainUntil)<=Date.now(),blockingHolds,openCases,eligible:Date.parse(r.payload.retainUntil)<=Date.now()&&!blockingHolds.length&&!openCases.length};
  });
  return {bundle,bySeq,items};
 }
 function inventory(p){
  const {bundle,items}=scan(p);
  return {policy:store.get(p.tenant,'retention_policy','current')||{id:'current',version:0,retentionSeconds:30*86400,reason:'합성 파일럿 공학적 기본값; 법적 보존기간 아님'},items,holds:store.list(p.tenant,'retention_hold'),plans:store.list(p.tenant,'retention_plan'),legacyPlaintextEvents:bundle.records.filter(r=>r.type==='event'&&!isEncryptedEvent(r.payload)).length,limitations:['기간 종료만으로 자동 파기하지 않습니다. 다른 검토자 승인과 관리자 실행, 또는 두 사람이 사전 승인한 로테이션 정책이 필요합니다.','파기는 live DEK 및 검색 사본만 대상으로 합니다. 기존 export·backup·WAL/디스크 잔존물에는 별도 파기 통제가 필요합니다.','사건·평가·거버넌스의 인간 작성 내용과 최소 접수 영수증은 이 이벤트 파기 범위 밖입니다.','키를 파기한 이벤트는 내용을 재조사할 수 없고 서명된 commitment 및 파기 이력만 검증할 수 있습니다.','기존 v1 평문 원장은 이 방식으로 파기하지 못합니다. 별도 승인된 migration 및 보존 절차가 필요합니다.']};
 }
 function handle(p,method,path,x){
  // One snapshot for the verification passes and the inventory (a read snapshot under the GET read-only scope).
  if(path==='/api/retention'&&method==='GET')return store.transaction(()=>inventory(p));
  if(path==='/api/retention/policy'&&method==='POST'){review(p);if(!Number.isSafeInteger(x.retentionSeconds)||x.retentionSeconds<1||x.retentionSeconds>10*365*86400)fail(400,'보존기간은 1초~10년 사이 정수');
   return store.transaction(()=>{verifyProjection(p);
   const policy={id:'current',version:(store.get(p.tenant,'retention_policy','current')?.version||0)+1,retentionSeconds:x.retentionSeconds,purpose:cleanText(x.purpose,500),reason:cleanText(x.reason,1000),reviewer:p.id,legalReview:cleanText(x.legalReview||'pending',100),createdAt:new Date().toISOString(),scope:'new_minimized_event_payloads_only'};
   return store.put(p,'retention_policy','current',policy);});
  }
  if(path==='/api/retention/holds'&&method==='POST'){review(p);const hold={id:randomUUID(),scope:x.scope==='tenant'?'tenant':identifier(x.scope),reason:cleanText(x.reason,1000),author:p.id,status:'active',createdAt:new Date().toISOString()};return store.transaction(()=>{verifyProjection(p);return store.put(p,'retention_hold',hold.id,hold);});}
  if(/^\/api\/retention\/holds\/[^/]+\/release$/.test(path)&&method==='POST'){review(p);return store.transaction(()=>{verifyProjection(p);const hold=get(p,'retention_hold',path.split('/')[4]);if(hold.author===p.id)fail(403,'다른 검토자가 보존 hold 해제를 검토해야 합니다');if(hold.status!=='active')fail(409,'활성 hold가 아닙니다');hold.status='released';hold.releasedBy=p.id;hold.releaseReason=cleanText(x.reason,1000);hold.releasedAt=new Date().toISOString();return store.put(p,'retention_hold',hold.id,hold);});}
  if(path==='/api/retention/plans'&&method==='POST'){review(p);return store.transaction(()=>{const selected=inventory(p).items.filter(i=>i.eligible).slice(0,1000);if(!selected.length)fail(409,'기간이 끝나고 보존 hold·미종결 사건이 없는 이벤트가 없습니다');const plan={id:randomUUID(),author:p.id,status:'pending',reason:cleanText(x.reason,1000),items:selected,selectionHash:digest(selected),createdAt:new Date().toISOString(),expiresAt:new Date(Date.now()+86400000).toISOString()};return store.put(p,'retention_plan',plan.id,plan);});}
  if(/^\/api\/retention\/plans\/[^/]+\/approve$/.test(path)&&method==='POST'){review(p);return store.transaction(()=>{verifyProjection(p);const plan=get(p,'retention_plan',path.split('/')[4]);if(plan.author===p.id)fail(403,'자신의 파기 계획을 승인할 수 없습니다');if(plan.status!=='pending'||Date.parse(plan.expiresAt)<=Date.now())fail(409,'계획이 만료됐거나 승인 가능한 상태가 아닙니다');plan.status='approved';plan.approvedBy=p.id;plan.approvedAt=new Date().toISOString();plan.approvalReason=cleanText(x.reason,1000);return store.put(p,'retention_plan',plan.id,plan);});}
  if(/^\/api\/retention\/plans\/[^/]+\/execute$/.test(path)&&method==='POST'){admin(p);const executed=store.transaction(()=>{
   try{store.checkActionProjection(p.tenant);}catch{fail(409,'행동 상태 조회 사본이 서명 원장과 일치하지 않습니다');}
   const currentInventory=inventory(p);
   const plan=get(p,'retention_plan',path.split('/')[4]);if(plan.status!=='approved'||!plan.approvedBy||plan.approvedBy===plan.author||Date.parse(plan.expiresAt)<=Date.now())fail(409,'유효한 두 사람 승인 계획 필요');
   const inventoryByKey=new Map(currentInventory.items.map(i=>[i.keyId,i]));if(plan.items.some(i=>!inventoryByKey.get(i.keyId)?.eligible))fail(409,'보존 hold·사건·파기 상태가 바뀌었습니다. 새 계획을 검토하세요');
   return erase(p,plan,inventoryByKey);
  });store.checkpointAfterErasure();return executed;}
  if(path.startsWith('/api/retention/rotation'))return rotationRoute(p,method,path,x);
  return undefined;
 }
 // The erasure itself, inside the caller's transaction, for a plan whose items were checked against the current inventory.
 function erase(p,plan,inventoryByKey,extra={}){
  const keyIds=plan.items.map(i=>i.keyId);for(const item of plan.items){
   const verified=inventoryByKey.get(item.keyId);
   if(!verified.receiptSigned)store.append(p.tenant,'event_receipt',{format:'evidscope-event-receipt-v1',basis:'verified_before_retention',
    attestedBy:p.id,source:verified.source,id:verified.eventId,fingerprint:verified.fingerprint,eventSeq:verified.seq,eventHash:verified.eventHash},p.id);
   store.projectionMutation(()=>{store.db.prepare('DELETE FROM event_keys WHERE tenant=? AND key_id=?').run(p.tenant,item.keyId);
    store.db.prepare('DELETE FROM events WHERE tenant=? AND source=? AND id=?').run(p.tenant,item.source,item.eventId);
    store.db.prepare('UPDATE actions SET version=version+1 WHERE tenant=? AND id=?').run(p.tenant,item.actionId);});
  }
  const disposition={id:randomUUID(),planId:plan.id,selectionHash:plan.selectionHash,keyIds,sequences:plan.items.map(i=>i.seq),reason:plan.reason,
   approvedBy:plan.approvedBy,executedBy:p.id,executedAt:extra.executedAt||new Date().toISOString(),scope:'live_event_keys_and_search_projection',
   externalCopies:'not_verified',physicalMediaErasure:'not_verified',...(extra.rotation?{rotation:extra.rotation}:{})};
  store.append(p.tenant,'retention_disposition',disposition,p.id);plan.status='executed';plan.disposition=disposition;store.put(p,'retention_plan',plan.id,plan);
  for(const a of store.list(p.tenant,'assessment').filter(a=>a.evidence.some(e=>e.type==='event'&&plan.items.some(i=>`${i.source}/${i.eventId}`===e.ref)))){
   const id=randomUUID();
   store.put(p,'governance_task',id,{id,systemId:a.systemId,requirementId:a.requirementId,title:'연결 증거 보존 종료: 충분성 재검토',owner:a.owner,status:'open',dispositionId:disposition.id});
  }
  return disposition;
 }
 // Rotation policies: proposed by a reviewer, activated by a different administrator, suspended by any reviewer (the safe way).
 function rotationRoute(p,method,path,x){
  if(path==='/api/retention/rotation'&&method==='GET')return store.transaction(()=>rotationStatus(p));
  if(path==='/api/retention/rotation'&&method==='POST'){review(p);
   if(!Array.isArray(x.classes))fail(400,'로테이션 대상 분류 목록이 필요합니다');
   const terms={classes:x.classes.map(c=>({sourceKind:c?.sourceKind,kind:c?.kind??'*',sensitivity:c?.sensitivity??'any',retentionSeconds:c?.retentionSeconds})),
    accessLogRetentionSeconds:x.accessLogRetentionSeconds??null,maxPerRun:x.maxPerRun??1000,validDays:x.validDays??365,purpose:cleanText(x.purpose,500),reason:cleanText(x.reason,1000)};
   termsAllowed(terms);
   return store.transaction(()=>{verifyProjection(p);const version=Math.max(0,...store.list(p.tenant,ROTATION_TYPE).map(v=>v.version))+1,now=Date.now();
    const policy={id:randomUUID(),version,status:'proposed',terms,proposedBy:p.id,proposedAt:new Date(now).toISOString(),expiresAt:new Date(now+7*86400000).toISOString()};
    return store.put(p,ROTATION_TYPE,policy.id,policy);});
  }
  if(path==='/api/retention/rotation/run'&&method==='POST'){admin(p);return rotate(p.tenant);}
  const match=/^\/api\/retention\/rotation\/([^/]+)\/(approve|reject|suspend)$/.exec(path);
  if(!match||method!=='POST')return undefined;
  const [,id,step]=match;
  if(step==='approve')admin(p);else review(p);
  const executed=store.transaction(()=>{verifyProjection(p);const policy=get(p,ROTATION_TYPE,id),now=new Date(),at=now.toISOString(),reason=cleanText(x.reason,1000);
   if(step==='approve'){
    if(policy.proposedBy===p.id)fail(403,'자신이 제안한 로테이션 정책을 승인할 수 없습니다(두 사람 사전 승인)');
    if(policy.status!=='proposed'||Date.parse(policy.expiresAt)<=now)fail(409,'승인 가능한 로테이션 정책 제안이 아니거나 만료됐습니다');
    termsAllowed(policy.terms);
    for(const old of store.list(p.tenant,ROTATION_TYPE).filter(v=>v.status==='active'))store.put(p,ROTATION_TYPE,old.id,{...old,status:'superseded',supersededBy:policy.id,supersededAt:at});
    return store.put(p,ROTATION_TYPE,id,{...policy,status:'active',approvedBy:p.id,approvedAt:at,approvalReason:reason,
     validUntil:new Date(now.getTime()+policy.terms.validDays*86400000).toISOString()});
   }
   if(step==='reject'){if(policy.status!=='proposed')fail(409,'제안 상태의 정책만 반려할 수 있습니다');return store.put(p,ROTATION_TYPE,id,{...policy,status:'rejected',rejectedBy:p.id,rejectedAt:at,rejectReason:reason});}
   if(policy.status!=='active')fail(409,'활성 로테이션 정책만 중지할 수 있습니다');
   return store.put(p,ROTATION_TYPE,id,{...policy,status:'suspended',suspendedBy:p.id,suspendedAt:at,suspendReason:reason});
  });
  return executed;
 }
 function termsAllowed(terms){
  const problem=rotationTermsProblem(terms);if(!problem)return;
  if(/critical/.test(problem))fail(400,`결정·승인·중지·사건 등 중요 기록 분류는 로테이션 대상으로 지정할 수 없습니다 (${problem})`);
  fail(400,`로테이션 정책 형식 오류 (${problem})`);
 }
 // One scheduled run for a tenant: erases due routine events under its active policy as one signed disposition. Holds, open cases
 // and the event's own retainUntil always win (scan marks such events ineligible); the verifier then checks what was written.
 function rotate(tenant){
  const p={tenant,id:ROTATION_PRINCIPAL,role:'system'};
  // Access-log rows are deleted after the commit, so the run must own its transaction: an outer rollback could undo the signed boundary.
  if(store.db.isTransaction||store.ledgerTransaction)throw Error('Retention rotation must run in its own transaction');
  const result=store.transaction(()=>{
   try{store.checkActionProjection(tenant);}catch{fail(409,'행동 상태 조회 사본이 서명 원장과 일치하지 않습니다');}
   const {bundle,bySeq,items}=scan(p),policy=checkRotationHistory(bundle.records).active,now=new Date(),at=now.toISOString();
   if(!policy)return {tenant,status:'no_active_policy',erased:0,at};
   if(Date.parse(policy.validUntil)<=now)return {tenant,status:'policy_expired',erased:0,at,policyVersion:policy.version};
   const rows=new Map(bundle.records.filter(r=>r.type==='event').map(r=>[r.seq,r])),selected=[];
   for(const item of items){
    // An envelope without its actionId in the clear (early v1) cannot be checked against holds and cases offline: never rotated.
    const row=rows.get(item.seq);if(!item.eligible||Date.parse(item.retainUntil)>now||typeof row.payload.actionId!=='string')continue;
    const c=eventRotationClass(bySeq.get(item.seq)),required=requiredRotationSeconds(policy.terms,c);
    if(required===null||now-Date.parse(row.recordedAt)<required*1000)continue;
    selected.push({...item,class:c});if(selected.length>=policy.terms.maxPerRun)break;
   }
   const authority={policyId:policy.id,policyVersion:policy.version,policyRecordHash:policy.recordHash};
   // Sealed access ranges past the policy's access log period, unless a tenant-wide hold stands.
   const tenantHold=store.list(tenant,'retention_hold').some(h=>h.status==='active'&&h.scope==='tenant');
   const planned=accessLog&&policy.terms.accessLogRetentionSeconds!==null&&!tenantHold
    ?accessLog.planPrune(tenant,bundle.records,{retentionSeconds:policy.terms.accessLogRetentionSeconds,now:now.getTime()}):null;
   const prune=planned&&{...planned,prunedAt:at,rotation:authority};
   if(prune)store.append(tenant,ACCESS_PRUNE_TYPE,prune,ROTATION_PRINCIPAL);
   if(!selected.length){
    if(prune)checkRotationHistory(store.rawBundle(tenant).records);
    return {tenant,status:prune?'access_log_pruned':'nothing_due',erased:0,at,policyVersion:policy.version,...(prune?{prune}:{})};
   }
   const plan={id:randomUUID(),author:policy.proposedBy,status:'approved',reason:`정기 로테이션: 사전 승인 정책 v${policy.version}`,items:selected,
    selectionHash:digest(selected),createdAt:at,expiresAt:at,approvedBy:policy.approvedBy,approvedAt:policy.approvedAt,
    approvalReason:`두 사람(${policy.proposedBy}, ${policy.approvedBy})이 사전 승인한 로테이션 정책 v${policy.version}`,
    rotation:{...authority,selectedBy:ROTATION_PRINCIPAL}};
   const disposition=erase(p,plan,new Map(selected.map(i=>[i.keyId,i])),{executedAt:at,rotation:{...authority,classes:selected.map(i=>i.class)}});
   // What was just written must pass the offline verifier, or the whole erasure rolls back.
   checkRotationHistory(store.rawBundle(tenant).records);
   return {tenant,status:'erased',erased:selected.length,at,policyVersion:policy.version,dispositionId:disposition.id,...(prune?{prune}:{})};
  });
  // The rows go only after the signed prune boundary committed; a crash in between leaves them for the next run.
  const {prune,...out}=result;
  if(prune)out.accessLogPruned={throughSeq:prune.throughSeq,deleted:accessLog.applyPrune(tenant,prune)};
  runs.set(tenant,out);if(out.erased)store.checkpointAfterErasure();
  return out;
 }
 const runs=new Map();let timer=null,nextRunAt=null;
 function runAll(){
  const tenants=store.db.prepare('SELECT DISTINCT tenant FROM objects WHERE type=? ORDER BY tenant').all(ROTATION_TYPE).map(row=>row.tenant),results=[];
  for(const tenant of tenants){
   let result;try{result=rotate(tenant);}catch(error){result={tenant,status:'failed',erased:0,at:new Date().toISOString(),error:error.message};
    process.stderr.write(JSON.stringify({component:'retention-rotation',tenant,error:error.message})+'\n');}
   runs.set(tenant,result);results.push(result);
  }
  return results;
 }
 function rotationStatus(p){
  // An unverifiable history is reported, not hidden: runs refuse it, and the screen shows why.
  const bundle=verifyProjection(p),history=verifyRotationHistory(bundle.records),policies=store.list(p.tenant,ROTATION_TYPE);
  const last=bundle.records.filter(r=>r.type==='retention_disposition'&&r.payload.rotation).at(-1);
  return {historyValid:history.valid,...(history.valid?{}:{historyError:history.error}),active:history.active??null,policies:policies.sort((a,b)=>b.version-a.version),
   scheduler:{enabled:intervalMs>0,intervalMs:intervalMs||null,lastRun:runs.get(p.tenant)||null,nextRunAt:intervalMs>0?nextRunAt:null},
   lastDisposition:last?{seq:last.seq,executedAt:last.payload.executedAt,erased:last.payload.keyIds.length,policyVersion:last.payload.rotation.policyVersion}:null,
   erasedByClass:history.erasedByClass,scheduledDispositions:history.scheduledDispositions,rotatedEvents:history.rotatedEvents,
   accessLog:accessLog?.retentionStatus?.(p.tenant)??null,
   limitations:['로테이션은 이벤트 내용 키와 검색 사본만 파기합니다. 서명 원장 기록·해시·접수 영수증은 그대로 남고 원장은 잘리지 않습니다.',
    '결정·승인·중지·안전·수집 공백·조항 검증 기록과 보존 hold 또는 미종결 사건의 이벤트는 로테이션하지 않습니다.',
    '기존 export·백업·외부 사본은 이 로테이션으로 파기되지 않습니다.']};
 }
 return {handle,inventory,rotation:{run:rotate,runAll,
  start(){if(!(intervalMs>0)||timer)return;nextRunAt=new Date(Date.now()+intervalMs).toISOString();
   timer=setInterval(()=>{nextRunAt=new Date(Date.now()+intervalMs).toISOString();
    // A GET's read-only scope ends before another task runs; a busy connection is retried on the next tick.
    if(!store.db.isOpen||store.db.isTransaction||store.readOnlyRequest)return;runAll();},intervalMs);timer.unref?.();},
  stop(){if(timer)clearInterval(timer);timer=null;nextRunAt=null;}}};
}
