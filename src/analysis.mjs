import {randomUUID} from 'node:crypto';
import {canonical,digest} from './crypto.mjs';
import {fail,cleanText,identifier,EVALUATION_ENGINE,evaluationEngine,boundedEvaluation,suppressingException} from './model.mjs';
import {credentialFingerprint} from './credentials.mjs';

export const analysisLimits=Object.freeze({jobs:5,snapshotBytes:10*1024*1024,events:1000,assets:5000,rules:100,exceptions:5000,findings:100,resultBytes:1024*1024,leaseMs:30000,
 // One credential holds at most this many live leases (worker replicas sharing a credential share it); expired and
 // rejected leases are deleted leaseRetentionMs after they were claimed (round-2 re-audit).
 liveLeasesPerCredential:64,leaseRetentionMs:24*3600*1000});
const bytes=x=>Buffer.byteLength(JSON.stringify(x));
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const keys=(x,allowed)=>{if(!object(x)||Object.keys(x).some(k=>!allowed.includes(k)))fail(400,'분석 결과의 객체 또는 필드가 유효하지 않습니다');};
// Signed evaluations name their engine, bounds and inputs so src/policy-replay.mjs can recompute them offline.
// Registry, related-deny, approval, stop-order, related-step and agent-command inputs are named only when present, so a v1 evaluation record
// keeps its v1 shape.
const v2Inputs=data=>({...(data.registry?{registry:{entries:data.registry.entries.length,policies:data.registry.policies.length}}:{}),...(data.relatedDecisions?{relatedDecisions:data.relatedDecisions.map(d=>d.seq)}:{}),
 ...(data.approvals?{approvals:data.approvals.map(a=>({id:a.id,version:a.version}))}:{}),
 ...(data.stopOrders?{stopOrders:{orders:data.stopOrders.orders.length,activations:data.stopOrders.activations.map(a=>a.seq)}}:{}),
 ...(data.relatedSteps?{relatedSteps:data.relatedSteps.map(s=>s.seq)}:{}),...(data.agentCommands?{agentCommands:data.agentCommands}:{})});
const replayInputs=data=>({engine:evaluationEngine(data),limits:{findings:analysisLimits.findings,resultBytes:analysisLimits.resultBytes},
 inputs:{events:data.events.map(e=>e.seq),assets:data.assets.length,rules:data.rules.map(r=>({id:r.id,version:r.version})),exceptions:data.exceptions.length,...v2Inputs(data)}});
const quarantineInputs=(engine=EVALUATION_ENGINE)=>({engine,limits:{events:analysisLimits.events,assets:analysisLimits.assets,rules:analysisLimits.rules,exceptions:analysisLimits.exceptions,snapshotBytes:analysisLimits.snapshotBytes}});

// A worker principal analyzes only the tenants it is bound to (S6): its `tenants` list or, without one, its own
// `tenant`. A legacy worker with tenant 'internal' and no list still serves every tenant in the synthetic-local
// profile; the enterprise profile refuses to start with such an unbound worker. null means "every tenant".
export function workerTenantScope(p,profile){
 if(p.tenants!==undefined){
  if(!Array.isArray(p.tenants)||!p.tenants.length||p.tenants.length>1000)throw Error('Invalid worker tenant binding');
  let scope;try{scope=new Set(p.tenants.map(tenant=>identifier(tenant)));}catch{throw Error('Invalid worker tenant binding');}
  if(scope.size!==p.tenants.length)throw Error('Invalid worker tenant binding');
  return scope;
 }
 if(p.tenant!=='internal')return new Set([p.tenant]);
 if(profile==='enterprise')throw Error('Enterprise profile requires each worker principal to list its tenants');
 return null;
}
// Validates the worker bindings of a configuration and returns the scopes by principal id. Ids are unique in a loaded
// configuration (src/credentials.mjs); the analysis itself keys scopes by credential, never by id (round-2 re-audit).
export function workerTenantScopes(principals=[],profile){
 const scopes=new Map();
 for(const p of principals){
  if(p.tenants!==undefined&&p.role!=='worker')throw Error('Only worker principals take a tenants list');
  if(p.role!=='worker')continue;
  if(scopes.has(p.id))throw Error('Duplicate worker principal id');
  scopes.set(p.id,workerTenantScope(p,profile));
 }
 return scopes;
}

// The vault owns leases and durable commits. Evaluation CPU runs in worker.mjs; the vault recomputes the deterministic
// result before it signs one. Leases persist identifiers and a snapshot digest, never an extra plaintext event copy.
export function createAnalysis(store,principals,{profile}={}){
 store.db.exec(`CREATE TABLE IF NOT EXISTS analysis_leases(
  id TEXT PRIMARY KEY,tenant TEXT NOT NULL,action_id TEXT NOT NULL,version INTEGER NOT NULL,
  worker TEXT NOT NULL,expires INTEGER NOT NULL,analysis_time INTEGER NOT NULL,snapshot_hash TEXT NOT NULL,
  state TEXT NOT NULL,result_hash TEXT,evaluation_id TEXT,credential TEXT);
  CREATE INDEX IF NOT EXISTS analysis_lease_action ON analysis_leases(tenant,action_id,version,state,expires);
  CREATE TABLE IF NOT EXISTS analysis_quarantine(tenant TEXT,action_id TEXT,version INTEGER,reason TEXT,PRIMARY KEY(tenant,action_id,version));`);
 // A lease records the fingerprint of the credential that claimed it (round-2 re-audit, S6). Live leases from before
 // have none; they are ended here and claimed again.
 if(!store.db.prepare("SELECT 1 FROM pragma_table_info('analysis_leases') WHERE name='credential'").get())
  store.db.exec("ALTER TABLE analysis_leases ADD COLUMN credential TEXT;UPDATE analysis_leases SET state='expired' WHERE state='leased';");
 store.db.exec(`CREATE INDEX IF NOT EXISTS analysis_lease_state ON analysis_leases(state,expires);
  CREATE INDEX IF NOT EXISTS analysis_lease_claimed ON analysis_leases(state,analysis_time);
  CREATE INDEX IF NOT EXISTS analysis_lease_credential ON analysis_leases(credential,state,expires);`);
 // Worker entries by credential, not by id: two entries that share an id keep their own tenant scope and leases.
 const workers=new Map();
 for(const entry of principals){
  if(entry.tenants!==undefined&&entry.role!=='worker')throw Error('Only worker principals take a tenants list');
  if(entry.role!=='worker')continue;
  const credential=credentialFingerprint(entry);if(workers.has(credential))throw Error('Duplicate worker credential');
  workers.set(credential,{credential,entry,scope:workerTenantScope(entry,profile)});
 }
 // The authenticated worker: its credential fingerprint and tenant scope (a Set, or null for a legacy all-tenant worker).
 const worker=p=>{
  const bound=p?.role==='worker'?workers.get(credentialFingerprint(p)):undefined;
  if(!bound||bound.entry.id!==p.id||bound.entry.tenant!==p.tenant)fail(403,'인증된 분석 서비스 전용');
  return bound;
 };
 const snapshot=(tenant,actionId)=>store.cachedAnalysisSnapshot(tenant,actionId,analysisLimits);
 // SQL filter for a scope; json_each keeps the tenant list a bound parameter.
 const within=(scope,column)=>scope?{sql:` AND ${column} IN (SELECT value FROM json_each(?))`,args:[JSON.stringify([...scope])]}:{sql:'',args:[]};
 const coverage=scope=>{const filter=within(scope,'a.tenant');return {quarantinedActions:store.db.prepare(`SELECT COUNT(*) n FROM analysis_quarantine q
  JOIN actions a ON a.tenant=q.tenant AND a.id=q.action_id AND a.version=q.version WHERE a.analyzed<a.version${filter.sql}`).get(...filter.args).n};};
 const backlog=scope=>{const filter=within(scope,'tenant');return store.db.prepare(`SELECT COUNT(*) n FROM actions WHERE analyzed<version${filter.sql}`).get(...filter.args).n;};
 const verifyActions=tenant=>{try{store.checkActionProjection(tenant);}catch{fail(409,'행동 상태 조회 사본이 서명 원장과 일치하지 않습니다');}};
 const scopeTenants=scope=>scope?[...scope]:[...new Set(principals.map(p=>p.tenant))];
 function expireExceptions(now,tenants){
  for(const tenant of tenants)for(const e of snapshot(tenant,null).exceptions||[])if(e.status==='approved'&&Date.parse(e.expiresAt)<=now){
   store.put({id:'analysis-expiration',tenant},'exception',e.id,{...e,status:'expired'});
   store.projectionMutation(()=>store.db.prepare('UPDATE actions SET version=version+1 WHERE tenant=?').run(tenant));
  }
 }
 function claim(p){const {scope,credential}=worker(p);return store.transaction(()=>{
  const tenants=scopeTenants(scope);for(const tenant of tenants)verifyActions(tenant);const now=Date.now();expireExceptions(now,tenants);
  store.db.prepare("UPDATE analysis_leases SET state='expired' WHERE state='leased' AND expires<=?").run(now);
  store.db.prepare("DELETE FROM analysis_leases WHERE state IN ('expired','rejected') AND analysis_time<=?").run(now-analysisLimits.leaseRetentionMs);
  // A credential that never completes cannot keep more than its share of the scope leased (round-2 re-audit).
  const live=store.db.prepare("SELECT COUNT(*) n FROM analysis_leases WHERE credential=? AND state='leased' AND expires>?").get(credential,now).n;
  const room=Math.min(analysisLimits.jobs,Math.max(0,analysisLimits.liveLeasesPerCredential-live));
  const filter=within(scope,'a.tenant');
  const candidates=store.db.prepare(`SELECT a.* FROM actions a WHERE a.analyzed<a.version${filter.sql}
   AND NOT EXISTS(SELECT 1 FROM analysis_quarantine q WHERE q.tenant=a.tenant AND q.action_id=a.id AND q.version=a.version)
   AND NOT EXISTS(SELECT 1 FROM analysis_leases l WHERE l.tenant=a.tenant AND l.action_id=a.id AND l.version=a.version AND l.state='leased' AND l.expires>?)
   ORDER BY a.tenant,a.id LIMIT ?`).all(...filter.args,now,room);
  const jobs=[];let sent=0;
  for(const a of candidates){
   const data=snapshot(a.tenant,a.id),size=data.resourceLimit?.snapshotBytesAtLeast||bytes(data);
   const over=data.resourceLimit?.reasons||Object.entries({events:analysisLimits.events,assets:analysisLimits.assets,rules:analysisLimits.rules,exceptions:analysisLimits.exceptions}).filter(([k,n])=>data[k].length>n).map(([k])=>k);
   if(size>analysisLimits.snapshotBytes-4096)over.push('snapshotBytes');
   if(over.length){
    const reason=`resource_limit:${over.join(',')}`,evaluation={id:randomUUID(),actionId:a.id,version:a.version,createdAt:new Date(now).toISOString(),status:'quarantined_resource_limit',findings:[],authority:'unverified_or_mismatch',effect:'unconfirmed',coverage:{evaluated:false,reason,observedEvents:data.observedEvents??data.events.length,observedEventsComplete:data.resourceLimit?.observedEventsComplete??true,snapshotBytesAtLeast:size,totalFindings:null,returnedFindings:0,truncated:false},limitations:['리소스 한도를 초과하여 분석하지 않았습니다. 관측 공백이며 무사고 판정이 아닙니다.'],replay:quarantineInputs(data.resourceLimit?.engine||evaluationEngine(data))};
    store.append(a.tenant,'evaluation',evaluation,p.id);
     store.projectionMutation(()=>store.db.prepare('INSERT INTO evaluations(tenant,action_id,version,body) VALUES(?,?,?,?)').run(a.tenant,a.id,a.version,JSON.stringify(evaluation)));
    store.db.prepare('INSERT INTO analysis_quarantine VALUES(?,?,?,?)').run(a.tenant,a.id,a.version,reason);continue;
   }
   const job={leaseId:randomUUID(),tenant:a.tenant,actionId:a.id,version:a.version,analysisTime:now,expiresAt:new Date(now+analysisLimits.leaseMs).toISOString(),...data};
   const jobSize=bytes(job);
   // Count envelope and separators conservatively toward the full response limit.
   if(sent+jobSize+4096>analysisLimits.snapshotBytes)break;
   store.db.prepare(`INSERT INTO analysis_leases(id,tenant,action_id,version,worker,expires,analysis_time,snapshot_hash,state,credential)
    VALUES(?,?,?,?,?,?,?,?,?,?)`).run(job.leaseId,a.tenant,a.id,a.version,p.id,now+analysisLimits.leaseMs,now,digest(data),'leased',credential);
   jobs.push(job);sent+=jobSize;
  }
  return {jobs,backlog:backlog(scope),coverage:coverage(scope),limits:analysisLimits};
 });}
 function validateResult(result,data,lease){
  keys(result,['findings','authority','effect','limitations','coverage']);
  if(bytes(result)>analysisLimits.resultBytes||!Array.isArray(result.findings)||result.findings.length>analysisLimits.findings)fail(400,'분석 결과 크기 한도 초과');
  if(!['unverified_or_mismatch','matched_at_event_time','not_observed'].includes(result.authority)||!['independently_reported_success','independently_reported_failure','mixed_results','unconfirmed'].includes(result.effect))fail(400,'분석 결과 상태 오류');
  const refs=new Set(data.events.map(e=>`${e.source}/${e.id}`));
  for(const f of result.findings){
   keys(f,['code','severity','message','evidence','suppressedBy']);cleanText(f.code,300);cleanText(f.message,2000);
   if(!['low','medium','high'].includes(f.severity)||!Array.isArray(f.evidence)||f.evidence.length>analysisLimits.events||f.evidence.some(r=>typeof r!=='string'||!refs.has(r)))fail(400,'분석 작업 밖의 증거 또는 잘못된 finding');
   // A pending exception (any human may request one) never suppresses; only an approved, unexpired one for this action and rule.
   if(f.suppressedBy!==undefined&&suppressingException(data.exceptions,f,lease.action_id,lease.analysis_time)?.id!==f.suppressedBy)fail(400,'승인되지 않았거나 이 finding에 해당하지 않는 예외입니다');
  }
  if(!Array.isArray(result.limitations)||result.limitations.length>20)fail(400,'분석 한계 형식 오류');result.limitations.forEach(s=>cleanText(s,2000));
  keys(result.coverage,['totalFindings','returnedFindings','truncated']);const c=result.coverage;
  if(!Number.isSafeInteger(c.totalFindings)||c.totalFindings<result.findings.length||c.returnedFindings!==result.findings.length||c.truncated!==(c.totalFindings>c.returnedFindings))fail(400,'분석 coverage 오류');
 }
 function commit(p,body){const {scope,credential}=worker(p);keys(body,['leaseId','result']);cleanText(body.leaseId,100);keys(body.result,['findings','authority','effect','limitations','coverage']);if(bytes(body.result)>analysisLimits.resultBytes)fail(400,'분석 결과 크기 한도 초과');
  const output=store.transaction(()=>{
  const lease=store.db.prepare('SELECT * FROM analysis_leases WHERE id=?').get(body.leaseId);
  // Only the credential that claimed a lease commits it; a lease from before credential binding is claimed again.
  if(!lease||lease.worker!==p.id||lease.credential!==null&&lease.credential!==credential)fail(403,'이 분석 서비스에 할당된 lease가 아닙니다');
  if(lease.credential===null)fail(409,'분석 lease 만료: 다시 claim 하세요');
  if(scope&&!scope.has(lease.tenant))fail(403,'이 분석 서비스에 허용되지 않은 테넌트입니다');
  const resultHash=digest(body.result);
  if(lease.state==='completed'){
   if(lease.result_hash!==resultHash)fail(409,'완료된 lease 결과 내용 충돌');
   return {accepted:true,duplicate:true,evaluationId:lease.evaluation_id,backlog:backlog(scope)};
  }
  if(lease.state!=='leased'||lease.expires<=Date.now())fail(409,'분석 lease 만료: 다시 claim 하세요');
  verifyActions(lease.tenant);const a=store.db.prepare('SELECT * FROM actions WHERE tenant=? AND id=?').get(lease.tenant,lease.action_id);
  if(!a||a.version!==lease.version||a.analyzed>=lease.version)fail(409,'늦은 증거나 정책 변경으로 분석 버전이 갱신되었습니다');
  const data=snapshot(lease.tenant,lease.action_id);
  if(data.resourceLimit)fail(409,'분석 snapshot이 리소스 한도를 초과했습니다');
  if(digest(data)!==lease.snapshot_hash)fail(409,'분석 snapshot이 변경되었습니다');
  validateResult(body.result,data,lease);
  // The vault recomputes the deterministic evaluation from the same snapshot and analysis time and signs only an
  // identical result: a worker credential cannot add, drop, alter or suppress findings (S6). A mismatch ends the lease
  // (state 'rejected', kept outside the signed ledger) so the action can be claimed again.
  // A JSON copy: the worker evaluated the same JSON, and the verified snapshot cache must not be shared with evaluate().
  const expected=boundedEvaluation({...JSON.parse(JSON.stringify(data)),analysisTime:lease.analysis_time},analysisLimits);
  if(canonical(expected)!==canonical(body.result)){
   store.db.prepare("UPDATE analysis_leases SET state='rejected',result_hash=? WHERE id=?").run(resultHash,lease.id);return {rejected:true};
  }
  const evaluation={...expected,id:randomUUID(),actionId:lease.action_id,version:lease.version,createdAt:new Date().toISOString(),analysisTime:new Date(lease.analysis_time).toISOString(),status:'evaluated',worker:p.id,snapshotHash:lease.snapshot_hash,replay:replayInputs(data)};
  store.append(lease.tenant,'evaluation',evaluation,p.id);
   store.projectionMutation(()=>store.db.prepare('INSERT INTO evaluations(tenant,action_id,version,body) VALUES(?,?,?,?)').run(lease.tenant,lease.action_id,lease.version,JSON.stringify(evaluation)));
  store.projectionMutation(()=>store.db.prepare('UPDATE actions SET analyzed=? WHERE tenant=? AND id=? AND version=?').run(lease.version,lease.tenant,lease.action_id,lease.version));
  store.db.prepare("UPDATE analysis_leases SET state='completed',result_hash=?,evaluation_id=? WHERE id=?").run(resultHash,evaluation.id,lease.id);
  return {accepted:true,duplicate:false,evaluationId:evaluation.id,backlog:backlog(scope)};
  });
  if(output.rejected)fail(422,'분석 결과가 vault의 결정적 재계산과 일치하지 않아 거부했습니다');
  return output;
 }
 return {claim,commit};
}
