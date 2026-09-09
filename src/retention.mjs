import {randomUUID} from 'node:crypto';
import {cleanText,date,identifier,fail} from './model.mjs';
import {digest,verifyBundle} from './crypto.mjs';

// Destruction is an explicit two-person operation. Changing policy is never retroactive.
export function createRetention(store){
 const review=p=>{if(!['reviewer','admin'].includes(p.role))fail(403,'보존 검토자 권한이 필요합니다');};
 const admin=p=>{if(p.role!=='admin')fail(403,'파기 실행은 관리자 권한이 필요합니다');};
 const get=(p,type,id)=>store.get(p.tenant,type,id)||fail(404,'보존 대상을 찾을 수 없습니다');
 function inventory(p){
  const bundle=store.bundle(p.tenant);verifyBundle(bundle,store.publicKey);const originals=store.ledgerEvents(p.tenant);const bySeq=new Map(originals.map(e=>[e.seq,e]));
  const holds=store.list(p.tenant,'retention_hold').filter(h=>h.status==='active');const cases=store.list(p.tenant,'case').filter(c=>c.status!=='closed');
  const disposed=new Set(bundle.records.filter(r=>r.type==='retention_disposition').flatMap(r=>r.payload.keyIds));
  const items=bundle.records.filter(r=>r.type==='event'&&r.payload.format==='evidscope-encrypted-event-v1'&&!disposed.has(r.payload.keyId)).map(r=>{
   const e=bySeq.get(r.seq),blockingHolds=holds.filter(h=>h.scope==='tenant'||h.scope===e.actionId).map(h=>h.id);const openCases=cases.filter(c=>c.actionId===e.actionId).map(c=>c.id);
   return {seq:r.seq,keyId:r.payload.keyId,source:e.source,eventId:e.id,actionId:e.actionId,retainUntil:r.payload.retainUntil,policyVersion:r.payload.policyVersion,expired:Date.parse(r.payload.retainUntil)<=Date.now(),blockingHolds,openCases,eligible:Date.parse(r.payload.retainUntil)<=Date.now()&&!blockingHolds.length&&!openCases.length};
  });
  return {policy:store.get(p.tenant,'retention_policy','current')||{id:'current',version:0,retentionSeconds:30*86400,reason:'합성 파일럿 공학적 기본값; 법적 보존기간 아님'},items,holds:store.list(p.tenant,'retention_hold'),plans:store.list(p.tenant,'retention_plan'),legacyPlaintextEvents:bundle.records.filter(r=>r.type==='event'&&r.payload.format!=='evidscope-encrypted-event-v1').length,limitations:['기간 종료만으로 자동 파기하지 않습니다. 다른 검토자 승인과 관리자 실행이 필요합니다.','파기는 live DEK 및 검색 사본만 대상으로 합니다. 기존 export·backup·WAL/디스크 잔존물에는 별도 파기 통제가 필요합니다.','사건·평가·거버넌스의 인간 작성 내용과 최소 접수 영수증은 이 이벤트 파기 범위 밖입니다.','키를 파기한 이벤트는 내용을 재조사할 수 없고 서명된 commitment 및 파기 이력만 검증할 수 있습니다.','기존 v1 평문 원장은 이 방식으로 파기하지 못합니다. 별도 승인된 migration 및 보존 절차가 필요합니다.']};
 }
 function handle(p,method,path,x){
  if(path==='/api/retention'&&method==='GET')return inventory(p);
  if(path==='/api/retention/policy'&&method==='POST'){review(p);if(!Number.isSafeInteger(x.retentionSeconds)||x.retentionSeconds<1||x.retentionSeconds>10*365*86400)fail(400,'보존기간은 1초~10년 사이 정수');
   const policy={id:'current',version:(store.get(p.tenant,'retention_policy','current')?.version||0)+1,retentionSeconds:x.retentionSeconds,purpose:cleanText(x.purpose,500),reason:cleanText(x.reason,1000),reviewer:p.id,legalReview:cleanText(x.legalReview||'pending',100),createdAt:new Date().toISOString(),scope:'new_minimized_event_payloads_only'};
   return store.transaction(()=>store.put(p,'retention_policy','current',policy));
  }
  if(path==='/api/retention/holds'&&method==='POST'){review(p);const hold={id:randomUUID(),scope:x.scope==='tenant'?'tenant':identifier(x.scope),reason:cleanText(x.reason,1000),author:p.id,status:'active',createdAt:new Date().toISOString()};return store.transaction(()=>store.put(p,'retention_hold',hold.id,hold));}
  if(/^\/api\/retention\/holds\/[^/]+\/release$/.test(path)&&method==='POST'){review(p);return store.transaction(()=>{const hold=get(p,'retention_hold',path.split('/')[4]);if(hold.author===p.id)fail(403,'다른 검토자가 보존 hold 해제를 검토해야 합니다');if(hold.status!=='active')fail(409,'활성 hold가 아닙니다');hold.status='released';hold.releasedBy=p.id;hold.releaseReason=cleanText(x.reason,1000);hold.releasedAt=new Date().toISOString();return store.put(p,'retention_hold',hold.id,hold);});}
  if(path==='/api/retention/plans'&&method==='POST'){review(p);return store.transaction(()=>{const selected=inventory(p).items.filter(i=>i.eligible).slice(0,1000);if(!selected.length)fail(409,'기간이 끝나고 보존 hold·미종결 사건이 없는 이벤트가 없습니다');const plan={id:randomUUID(),author:p.id,status:'pending',reason:cleanText(x.reason,1000),items:selected,selectionHash:digest(selected),createdAt:new Date().toISOString(),expiresAt:new Date(Date.now()+86400000).toISOString()};return store.put(p,'retention_plan',plan.id,plan);});}
  if(/^\/api\/retention\/plans\/[^/]+\/approve$/.test(path)&&method==='POST'){review(p);return store.transaction(()=>{const plan=get(p,'retention_plan',path.split('/')[4]);if(plan.author===p.id)fail(403,'자신의 파기 계획을 승인할 수 없습니다');if(plan.status!=='pending'||Date.parse(plan.expiresAt)<=Date.now())fail(409,'계획이 만료됐거나 승인 가능한 상태가 아닙니다');plan.status='approved';plan.approvedBy=p.id;plan.approvedAt=new Date().toISOString();plan.approvalReason=cleanText(x.reason,1000);return store.put(p,'retention_plan',plan.id,plan);});}
  if(/^\/api\/retention\/plans\/[^/]+\/execute$/.test(path)&&method==='POST'){admin(p);return store.transaction(()=>{
   const plan=get(p,'retention_plan',path.split('/')[4]);if(plan.status!=='approved'||!plan.approvedBy||plan.approvedBy===plan.author||Date.parse(plan.expiresAt)<=Date.now())fail(409,'유효한 두 사람 승인 계획 필요');
   const inventoryByKey=new Map(inventory(p).items.map(i=>[i.keyId,i]));if(plan.items.some(i=>!inventoryByKey.get(i.keyId)?.eligible))fail(409,'보존 hold·사건·파기 상태가 바뀌었습니다. 새 계획을 검토하세요');
   const keyIds=plan.items.map(i=>i.keyId);for(const item of plan.items){store.db.prepare('DELETE FROM event_keys WHERE tenant=? AND key_id=?').run(p.tenant,item.keyId);store.db.prepare('DELETE FROM events WHERE tenant=? AND source=? AND id=?').run(p.tenant,item.source,item.eventId);store.db.prepare('UPDATE actions SET version=version+1 WHERE tenant=? AND id=?').run(p.tenant,item.actionId);}
   const disposition={id:randomUUID(),planId:plan.id,selectionHash:plan.selectionHash,keyIds,sequences:plan.items.map(i=>i.seq),reason:plan.reason,approvedBy:plan.approvedBy,executedBy:p.id,executedAt:new Date().toISOString(),scope:'live_event_keys_and_search_projection',externalCopies:'not_verified',physicalMediaErasure:'not_verified'};
   store.append(p.tenant,'retention_disposition',disposition,p.id);plan.status='executed';plan.disposition=disposition;store.put(p,'retention_plan',plan.id,plan);
   for(const a of store.list(p.tenant,'assessment').filter(a=>a.evidence.some(e=>e.type==='event'&&plan.items.some(i=>`${i.source}/${i.eventId}`===e.ref)))){const id=randomUUID();store.put(p,'governance_task',id,{id,systemId:a.systemId,requirementId:a.requirementId,title:'연결 증거 보존 종료: 충분성 재검토',owner:a.owner,status:'open',dispositionId:disposition.id});}
   return disposition;
  });}
  return undefined;
 }
 return {handle,inventory};
}
