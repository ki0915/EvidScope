import {digest} from './crypto.mjs';
import {fail} from './model.mjs';

const gaps=new Set(['UNREGISTERED_ASSET','POLICY_CONTEXT_UNVERIFIED','DELEGATION_UNVERIFIED','AUTHORITY_MISMATCH','AUTHORITY_MISSING','APPROVAL_MISMATCH','HUMAN_APPROVAL_MISSING','COLLECTION_GAP','REFERENCE_METADATA_CONFLICT','CONTRADICTING_RESULT','STOP_UNCONFIRMED','LOG_INJECTION_SIGNAL']);
export function policyState(events,evaluation,version,{ambiguous=false}={}){
 if(ambiguous)return {state:'unconfirmed',reason:'같은 행동에 여러 에이전트 또는 서로 다른 행위자 보고가 있어 귀속을 확정하지 못했습니다'};
 if(!version||version.analyzed<version.version)return {state:'pending',reason:'새 증거 또는 정책 변경에 대한 분석 대기'};
 if(!evaluation||evaluation.version!==version.version||evaluation.status!=='evaluated'||evaluation.coverage?.truncated||evaluation.coverage?.totalFindings!==evaluation.findings?.length)return {state:'unconfirmed',reason:'최신 평가 또는 전체 평가 결과를 확인할 수 없습니다'};
 const findings=evaluation.findings||[],policy=f=>f.code==='DESTINATION_OUTSIDE_POLICY'||f.code?.startsWith('CUSTOM:');
 if(findings.some(f=>policy(f)&&!f.suppressedBy))return {state:'violation',reason:'목적지 또는 사용자 정책 룰 위반 신호가 있습니다'};
 if(findings.some(f=>f.suppressedBy))return {state:'exception',reason:'승인된 한시 예외가 적용됐으며 준수로 합산하지 않습니다'};
 if(findings.some(f=>!gaps.has(f.code)&&f.code!=='LATE_EVIDENCE'&&!policy(f)))return {state:'unconfirmed',reason:'현재 준수율 기준에 분류되지 않은 평가 신호가 있어 개별 검토가 필요합니다'};
 const execution=events.filter(e=>e.sourceKind==='tool'&&['execution','result'].includes(e.kind));
 if(!execution.length||execution.some(e=>!e.policyVersion)||evaluation.authority!=='matched_at_event_time'||findings.some(f=>gaps.has(f.code)))return {state:'unconfirmed',reason:'등록·정책 버전·권한·승인·관측 근거 중 확인되지 않은 항목이 있습니다'};
 return {state:'compliant',reason:'수집된 실행의 기본 정책 점검에서 위반·근거 누락 신호가 없습니다. 법적 준수 확정은 아닙니다'};
}

export function agentInventory(store,principals,tenant,params,now=Date.now()){
 const ranges={'24h':86400000,'7d':604800000,'30d':2592000000,all:null};
 const range=params.get('range')||'all',focus=params.get('focus')||'all',sort=params.get('sort')||'recent';
 if(!Object.hasOwn(ranges,range)||!['all','violation','unconfirmed','stale','inactive'].includes(focus)||!['recent','attention','coverage'].includes(sort))fail(400,'에이전트 조회 조건 오류');
 const requestedEnd=params.get('end'),end=requestedEnd?Date.parse(requestedEnd):now;
 if(!Number.isFinite(end)||end>now||requestedEnd&&new Date(end).toISOString()!==requestedEnd)fail(400,'조회 종료 시각 오류');
 const start=ranges[range]===null?null:end-ranges[range];
 const q=(params.get('q')||'').trim();if(q.length>200)fail(400,'검색어 길이 한도');
 const offset=Number(params.get('offset')||0),limit=Number(params.get('limit')||50),selected=params.get('id');
 if(!Number.isSafeInteger(offset)||offset<0||!Number.isSafeInteger(limit)||limit<1||limit>100)fail(400,'목록 범위 오류');
 let used=0,count=0;
 function read(sql,args){const rows=[];for(const row of store.db.prepare(sql).iterate(...args)){if(row.bytes>1024*1024||(used+=row.bytes)>32*1024*1024||++count>50000)fail(413,'에이전트 집계 한도 초과: 부분 준수율을 발급하지 않습니다');rows.push(JSON.parse(row.body));}return rows;}
 const events=read('SELECT CASE WHEN length(CAST(body AS BLOB))<=1048576 THEN body ELSE NULL END body,length(CAST(body AS BLOB)) bytes FROM events WHERE tenant=? ORDER BY received,source,id',[tenant]);
 const groups=new Map(),actions=new Map(),owners=new Map();
 const identity=(source,actor)=>digest({source,actor});
 for(const e of events){if(!actions.has(e.actionId))actions.set(e.actionId,[]);actions.get(e.actionId).push(e);if(e.sourceKind!=='agent')continue;
  const actor=e.actor||'',id=identity(e.source,actor);if(!groups.has(id))groups.set(id,{id,source:e.source,actor:actor||'행위자 미수집',identityComplete:!!actor,models:new Set(),actionIds:new Set(),lastSeen:e.receivedAt});const g=groups.get(id);g.actionIds.add(e.actionId);if(e.model)g.models.add(e.model);g.lastSeen=e.receivedAt;
  if(!owners.has(e.actionId))owners.set(e.actionId,new Set());owners.get(e.actionId).add(id);
 }
 for(const p of principals.filter(p=>p.tenant===tenant&&p.role==='source'&&p.kind==='agent'))if(![...groups.values()].some(g=>g.source===p.id)){const id=identity(p.id,'');groups.set(id,{id,source:p.id,actor:'수신 대기',identityComplete:false,models:new Set(),actionIds:new Set(),lastSeen:null});}
 const versions=new Map(store.db.prepare('SELECT id,version,analyzed FROM actions WHERE tenant=?').all(tenant).map(v=>[v.id,v]));
 const evaluations=read('SELECT CASE WHEN length(CAST(body AS BLOB))<=1048576 THEN body ELSE NULL END body,length(CAST(body AS BLOB)) bytes FROM evaluations WHERE tenant=? ORDER BY id DESC',[tenant]),evals=new Map();for(const e of evaluations){if(!evals.has(e.actionId))evals.set(e.actionId,[]);evals.get(e.actionId).push(e);}
 const decisions=read("SELECT CASE WHEN length(CAST(body AS BLOB))<=1048576 THEN body ELSE NULL END body,length(CAST(body AS BLOB)) bytes FROM objects WHERE tenant=? AND type='case_decision' ORDER BY rowid DESC",[tenant]),latest=new Map();for(const d of decisions)if(!latest.has(d.actionId))latest.set(d.actionId,d);
 // Select the cohort by first retained agent receipt, then evaluate its complete evidence.
 const firstSeen=new Map([...actions].map(([id,ev])=>[id,(ev.find(e=>e.sourceKind==='agent')||ev[0]).receivedAt]));
 const inWindow=id=>{const at=Date.parse(firstSeen.get(id));return at<=end&&(start===null||at>=start);};
 const all=[];
 for(const g of groups.values()){
  const counts={compliant:0,violation:0,unconfirmed:0,pending:0,exception:0},reviews={unreviewed:0,stale:0,inconclusive:0,reviewed:0},details=[],policyVersions=new Set();let references=0;
  for(const actionId of g.actionIds){if(!inWindow(actionId))continue;const ev=actions.get(actionId),evaluation=evals.get(actionId)?.[0],v=versions.get(actionId),actors=new Set(ev.map(e=>e.actor).filter(Boolean));
   const policy=policyState(ev,evaluation,v,{ambiguous:!g.identityComplete||owners.get(actionId).size>1||actors.size>1});counts[policy.state]++;
   const version=v?{version:v.version,analyzed:v.analyzed}:{version:null,analyzed:null};
   const context=digest({tenant,actionId,events:ev,evaluations:evals.get(actionId)||[],analysis:version}),decision=latest.get(actionId);
   const review=!decision?'unreviewed':decision.contextHash!==context||Date.parse(decision.nextReviewAt)<=now?'stale':decision.conclusion==='inconclusive'?'inconclusive':'reviewed';reviews[review]++;
   if(ev.some(e=>e.dataRefs?.length))references++;
   ev.forEach(e=>{if(e.policyVersion)policyVersions.add(e.policyVersion);});
   details.push({actionId,state:policy.state,reason:policy.reason,reviewState:review,firstSeen:firstSeen.get(actionId),lastSeen:ev.at(-1)?.receivedAt,policyVersions:[...new Set(ev.map(e=>e.policyVersion).filter(Boolean))],findings:(evaluation?.findings||[]).map(f=>({code:f.code,severity:f.severity,suppressed:!!f.suppressedBy})).slice(0,30)});
  }
  const assessed=counts.compliant+counts.violation,total=details.length;
  all.push({id:g.id,source:g.source,actor:g.actor,identityComplete:g.identityComplete,models:[...g.models],lastSeen:g.lastSeen,actions:total,counts,reviews,referenceActions:references,policyVersions:[...policyVersions],compliance:{numerator:counts.compliant,denominator:assessed,percent:assessed?Math.round(counts.compliant/assessed*1000)/10:null,coveragePercent:total?Math.round(assessed/total*1000)/10:null},...(selected===g.id?{details:details.sort((a,b)=>(b.lastSeen||'').localeCompare(a.lastSeen||''))}:{} )});
 }
 const recent=(a,b)=>(b.lastSeen||'').localeCompare(a.lastSeen||'')||a.id.localeCompare(b.id);
 all.sort((a,b)=>sort==='attention'?(b.counts.violation-a.counts.violation||b.reviews.stale-a.reviews.stale||b.counts.unconfirmed-a.counts.unconfirmed||recent(a,b)):sort==='coverage'?((a.compliance.coveragePercent??-1)-(b.compliance.coveragePercent??-1)||recent(a,b)):recent(a,b));
 const searched=all.filter(g=>!q||[g.actor,g.source,...g.models].some(v=>v.toLowerCase().includes(q.toLowerCase())));
 const matches=g=>focus==='all'||(focus==='stale'?g.reviews.stale>0:focus==='inactive'?g.actions===0:g.counts[focus]>0);
 const filtered=searched.filter(matches);
 const definition={version:'evidscope-observed-policy-v1',formula:'충족 행동 / (충족 행동 + 위반 신호 행동). 미확인·분석 대기·예외는 제외하며 평가 범위를 함께 표시합니다.',checks:'등록 자산·당시 목적지 정책·독립 실행 권한·사람 승인 근거 및 사용자 정책 룰의 최신 전체 평가',scope:'선택 기간에 첫 에이전트 기록이 수신된 행동의 현재 평가입니다. 기간 밖 연관 근거도 대조합니다. 과거 당시의 판정 또는 법적 준수율이 아닙니다. 파기로 보존 기록이 줄면 집계가 달라질 수 있습니다.',identity:'테넌트 내부의 인증된 수집 출처 + 보고된 actor로 구분합니다. 출처 인증이 actor의 실제 신원을 증명하지 않습니다. 다중 귀속 행동은 각 에이전트에 미확인으로 표시하므로 행별 행동 수의 합은 고유 행동 수와 다를 수 있습니다.'};
 const window={range,start:start===null?null:new Date(start).toISOString(),end:new Date(end).toISOString(),basis:'first_retained_agent_receipt',evaluation:'latest_with_all_retained_evidence'};
 const common={generatedAt:new Date(now).toISOString(),tenant,window,definition};
 if(selected){const item=all.find(g=>g.id===selected);if(!item)fail(404,'에이전트를 찾을 수 없습니다');
  const from=start??Math.min(end,...item.details.map(d=>Date.parse(d.firstSeen))),bins=range==='24h'?24:range==='7d'?7:30,step=Math.max(1,Math.ceil((end-from)/bins));
  const trend=Array.from({length:bins},(_,i)=>({at:new Date(Math.min(end,from+i*step)).toISOString(),end:new Date(Math.min(end,from+(i+1)*step)).toISOString(),counts:{compliant:0,violation:0,unconfirmed:0,pending:0,exception:0},actions:0}));
  for(const d of item.details){const bucket=Math.min(bins-1,Math.floor((Date.parse(d.firstSeen)-from)/step));trend[bucket].counts[d.state]++;trend[bucket].actions++;d.bucket=bucket;}
  return {...common,item,trend};}
 const summary={agents:searched.length,violation:searched.filter(g=>g.counts.violation).length,unconfirmed:searched.filter(g=>g.counts.unconfirmed).length,stale:searched.filter(g=>g.reviews.stale).length,inactive:searched.filter(g=>!g.actions).length};
 return {...common,items:filtered.slice(offset,offset+limit),total:filtered.length,summary,unattributedActions:[...actions.keys()].filter(id=>!owners.has(id)&&inWindow(id)).length,ambiguousActions:[...owners].filter(([id,ids])=>ids.size>1&&inWindow(id)).length,offset,limit};
}
