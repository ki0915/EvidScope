import {randomUUID} from 'node:crypto';
import {digest} from './crypto.mjs';
import {fail,cleanText} from './model.mjs';

export const analysisLimits=Object.freeze({jobs:5,snapshotBytes:10*1024*1024,events:1000,assets:5000,rules:100,exceptions:5000,findings:100,resultBytes:1024*1024,leaseMs:30000});
const bytes=x=>Buffer.byteLength(JSON.stringify(x));
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const keys=(x,allowed)=>{if(!object(x)||Object.keys(x).some(k=>!allowed.includes(k)))fail(400,'분석 결과의 객체 또는 필드가 유효하지 않습니다');};

// The vault owns leases and durable commits. Evaluation CPU runs in worker.mjs.
// Leases persist identifiers and a snapshot digest, never an extra plaintext event copy.
export function createAnalysis(store,principals){
 store.db.exec(`CREATE TABLE IF NOT EXISTS analysis_leases(
  id TEXT PRIMARY KEY,tenant TEXT NOT NULL,action_id TEXT NOT NULL,version INTEGER NOT NULL,
  worker TEXT NOT NULL,expires INTEGER NOT NULL,analysis_time INTEGER NOT NULL,snapshot_hash TEXT NOT NULL,
  state TEXT NOT NULL,result_hash TEXT,evaluation_id TEXT);
  CREATE INDEX IF NOT EXISTS analysis_lease_action ON analysis_leases(tenant,action_id,version,state,expires);
  CREATE TABLE IF NOT EXISTS analysis_quarantine(tenant TEXT,action_id TEXT,version INTEGER,reason TEXT,PRIMARY KEY(tenant,action_id,version));`);
 const worker=p=>{if(p?.role!=='worker'||!principals.some(v=>v.id===p.id&&v.role==='worker'&&v.tenant===p.tenant))fail(403,'인증된 분석 서비스 전용');};
 const snapshot=(tenant,actionId)=>store.cachedAnalysisSnapshot(tenant,actionId,analysisLimits);
 const coverage=()=>({quarantinedActions:store.db.prepare('SELECT COUNT(*) n FROM analysis_quarantine q JOIN actions a ON a.tenant=q.tenant AND a.id=q.action_id AND a.version=q.version WHERE a.analyzed<a.version').get().n});
 const backlog=()=>store.db.prepare('SELECT COUNT(*) n FROM actions WHERE analyzed<version').get().n;
 const verifyActions=tenant=>{try{store.checkActionProjection(tenant);}catch{fail(409,'행동 상태 조회 사본이 서명 원장과 일치하지 않습니다');}};
 function expireExceptions(now){
  for(const tenant of new Set(principals.map(p=>p.tenant)))for(const e of snapshot(tenant,null).exceptions||[])if(e.status==='approved'&&Date.parse(e.expiresAt)<=now){
   store.put({id:'analysis-expiration',tenant},'exception',e.id,{...e,status:'expired'});
   store.projectionMutation(()=>store.db.prepare('UPDATE actions SET version=version+1 WHERE tenant=?').run(tenant));
  }
 }
 function claim(p){worker(p);return store.transaction(()=>{
  for(const tenant of new Set(principals.map(value=>value.tenant)))verifyActions(tenant);const now=Date.now();expireExceptions(now);
  store.db.prepare("UPDATE analysis_leases SET state='expired' WHERE state='leased' AND expires<=?").run(now);
  const candidates=store.db.prepare(`SELECT a.* FROM actions a WHERE a.analyzed<a.version
   AND NOT EXISTS(SELECT 1 FROM analysis_quarantine q WHERE q.tenant=a.tenant AND q.action_id=a.id AND q.version=a.version)
   AND NOT EXISTS(SELECT 1 FROM analysis_leases l WHERE l.tenant=a.tenant AND l.action_id=a.id AND l.version=a.version AND l.state='leased' AND l.expires>?)
   ORDER BY a.tenant,a.id LIMIT ?`).all(now,analysisLimits.jobs);
  const jobs=[];let sent=0;
  for(const a of candidates){
   const data=snapshot(a.tenant,a.id),size=data.resourceLimit?.snapshotBytesAtLeast||bytes(data);
   const over=data.resourceLimit?.reasons||Object.entries({events:analysisLimits.events,assets:analysisLimits.assets,rules:analysisLimits.rules,exceptions:analysisLimits.exceptions}).filter(([k,n])=>data[k].length>n).map(([k])=>k);
   if(size>analysisLimits.snapshotBytes-4096)over.push('snapshotBytes');
   if(over.length){
    const reason=`resource_limit:${over.join(',')}`,evaluation={id:randomUUID(),actionId:a.id,version:a.version,createdAt:new Date(now).toISOString(),status:'quarantined_resource_limit',findings:[],authority:'unverified_or_mismatch',effect:'unconfirmed',coverage:{evaluated:false,reason,observedEvents:data.observedEvents??data.events.length,observedEventsComplete:data.resourceLimit?.observedEventsComplete??true,snapshotBytesAtLeast:size,totalFindings:null,returnedFindings:0,truncated:false},limitations:['리소스 한도를 초과하여 분석하지 않았습니다. 관측 공백이며 무사고 판정이 아닙니다.']};
    store.append(a.tenant,'evaluation',evaluation,p.id);
     store.projectionMutation(()=>store.db.prepare('INSERT INTO evaluations(tenant,action_id,version,body) VALUES(?,?,?,?)').run(a.tenant,a.id,a.version,JSON.stringify(evaluation)));
    store.db.prepare('INSERT INTO analysis_quarantine VALUES(?,?,?,?)').run(a.tenant,a.id,a.version,reason);continue;
   }
   const job={leaseId:randomUUID(),tenant:a.tenant,actionId:a.id,version:a.version,analysisTime:now,expiresAt:new Date(now+analysisLimits.leaseMs).toISOString(),...data};
   const jobSize=bytes(job);
   // Count envelope and separators conservatively toward the full response limit.
   if(sent+jobSize+4096>analysisLimits.snapshotBytes)break;
   store.db.prepare('INSERT INTO analysis_leases(id,tenant,action_id,version,worker,expires,analysis_time,snapshot_hash,state) VALUES(?,?,?,?,?,?,?,?,?)').run(job.leaseId,a.tenant,a.id,a.version,p.id,now+analysisLimits.leaseMs,now,digest(data),'leased');
   jobs.push(job);sent+=jobSize;
  }
  return {jobs,backlog:backlog(),coverage:coverage(),limits:analysisLimits};
 });}
 function validateResult(result,data){
  keys(result,['findings','authority','effect','limitations','coverage']);
  if(bytes(result)>analysisLimits.resultBytes||!Array.isArray(result.findings)||result.findings.length>analysisLimits.findings)fail(400,'분석 결과 크기 한도 초과');
  if(!['unverified_or_mismatch','matched_at_event_time','not_observed'].includes(result.authority)||!['independently_reported_success','independently_reported_failure','mixed_results','unconfirmed'].includes(result.effect))fail(400,'분석 결과 상태 오류');
  const refs=new Set(data.events.map(e=>`${e.source}/${e.id}`)),exceptions=new Set(data.exceptions.map(e=>e.id));
  for(const f of result.findings){
   keys(f,['code','severity','message','evidence','suppressedBy']);cleanText(f.code,300);cleanText(f.message,2000);
   if(!['low','medium','high'].includes(f.severity)||!Array.isArray(f.evidence)||f.evidence.length>analysisLimits.events||f.evidence.some(r=>typeof r!=='string'||!refs.has(r)))fail(400,'분석 작업 밖의 증거 또는 잘못된 finding');
   if(f.suppressedBy!==undefined&&!exceptions.has(f.suppressedBy))fail(400,'분석 작업 밖의 예외');
  }
  if(!Array.isArray(result.limitations)||result.limitations.length>20)fail(400,'분석 한계 형식 오류');result.limitations.forEach(s=>cleanText(s,2000));
  keys(result.coverage,['totalFindings','returnedFindings','truncated']);const c=result.coverage;
  if(!Number.isSafeInteger(c.totalFindings)||c.totalFindings<result.findings.length||c.returnedFindings!==result.findings.length||c.truncated!==(c.totalFindings>c.returnedFindings))fail(400,'분석 coverage 오류');
 }
 function commit(p,body){worker(p);keys(body,['leaseId','result']);cleanText(body.leaseId,100);keys(body.result,['findings','authority','effect','limitations','coverage']);if(bytes(body.result)>analysisLimits.resultBytes)fail(400,'분석 결과 크기 한도 초과');return store.transaction(()=>{
  const lease=store.db.prepare('SELECT * FROM analysis_leases WHERE id=?').get(body.leaseId);
  if(!lease||lease.worker!==p.id)fail(403,'이 분석 서비스에 할당된 lease가 아닙니다');
  const resultHash=digest(body.result);
  if(lease.state==='completed'){
   if(lease.result_hash!==resultHash)fail(409,'완료된 lease 결과 내용 충돌');
   return {accepted:true,duplicate:true,evaluationId:lease.evaluation_id,backlog:backlog()};
  }
  if(lease.state!=='leased'||lease.expires<=Date.now())fail(409,'분석 lease 만료: 다시 claim 하세요');
  verifyActions(lease.tenant);const a=store.db.prepare('SELECT * FROM actions WHERE tenant=? AND id=?').get(lease.tenant,lease.action_id);
  if(!a||a.version!==lease.version||a.analyzed>=lease.version)fail(409,'늦은 증거나 정책 변경으로 분석 버전이 갱신되었습니다');
  const data=snapshot(lease.tenant,lease.action_id);
  if(data.resourceLimit)fail(409,'분석 snapshot이 리소스 한도를 초과했습니다');
  if(digest(data)!==lease.snapshot_hash)fail(409,'분석 snapshot이 변경되었습니다');
  validateResult(body.result,data);
  const evaluation={...body.result,id:randomUUID(),actionId:lease.action_id,version:lease.version,createdAt:new Date().toISOString(),analysisTime:new Date(lease.analysis_time).toISOString(),status:'evaluated',worker:p.id,snapshotHash:lease.snapshot_hash};
  store.append(lease.tenant,'evaluation',evaluation,p.id);
   store.projectionMutation(()=>store.db.prepare('INSERT INTO evaluations(tenant,action_id,version,body) VALUES(?,?,?,?)').run(lease.tenant,lease.action_id,lease.version,JSON.stringify(evaluation)));
  store.projectionMutation(()=>store.db.prepare('UPDATE actions SET analyzed=? WHERE tenant=? AND id=? AND version=?').run(lease.version,lease.tenant,lease.action_id,lease.version));
  store.db.prepare("UPDATE analysis_leases SET state='completed',result_hash=?,evaluation_id=? WHERE id=?").run(resultHash,evaluation.id,lease.id);
  return {accepted:true,duplicate:false,evaluationId:evaluation.id,backlog:backlog()};
 });}
 return {claim,commit};
}
