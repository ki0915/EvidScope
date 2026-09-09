import {digest,mac,equal} from './crypto.mjs';
import {fail,cleanText,identifier,date} from './model.mjs';

const EVENT_NAMES=new Set(['run.started','run.completed','run.failed','run.cancelled','agent.started','agent.completed','agent.failed','tool.started','tool.completed','tool.failed','review.started','review.completed','review.failed','artifact.created','usage.observed']);
const STATUSES=new Set(['queued','running','completed','failed','cancelled','blocked','unknown']);
const TOOLS=new Set(['shell','file_read','file_edit','search','browser','mcp','test','review','agent','other','unknown']);
const FIELDS=new Set(['eventId','eventName','runId','teamId','roleId','parentRunId','parentEventId','streamSequence','timeBasis','model','modelObserved','status','occurredAt','toolName','usage','artifacts']);
const ARTIFACT_FIELDS=new Set(['name','kind','path','hash']);
const USAGE_FIELDS=new Set(['inputTokens','cacheCreationInputTokens','cacheReadInputTokens','outputTokens','totalTokens']);

function object(value,message='JSON 객체가 필요합니다'){if(!value||typeof value!=='object'||Array.isArray(value))fail(400,message);return value;}
function onlyKeys(value,allowed,message){for(const key of Object.keys(value))if(!allowed.has(key))fail(400,`${message}: ${key}`);}
function natural(value,name){if(value===undefined||value===null)return null;if(!Number.isSafeInteger(value)||value<0)fail(400,`${name}은 0 이상의 정수여야 합니다`);return value;}
function relativeArtifactPath(value){const text=cleanText(value,500).replaceAll('\\','/');if(text.startsWith('/')||/^[A-Za-z]:\//.test(text)||text.split('/').includes('..'))fail(400,'artifact path는 저장소 상대 경로여야 합니다');return text;}
function usage(value){
 if(value===undefined)return null;object(value,'usage 객체가 필요합니다');onlyKeys(value,USAGE_FIELDS,'미수집 usage 필드');
 const inputTokens=natural(value.inputTokens,'inputTokens'),cacheCreationInputTokens=natural(value.cacheCreationInputTokens,'cacheCreationInputTokens'),cacheReadInputTokens=natural(value.cacheReadInputTokens,'cacheReadInputTokens'),outputTokens=natural(value.outputTokens,'outputTokens'),reportedTotal=natural(value.totalTokens,'totalTokens');
 const components=[inputTokens,cacheCreationInputTokens,cacheReadInputTokens,outputTokens],totalTokens=reportedTotal??(components.every(v=>v!==null)?components.reduce((a,b)=>a+b,0):null);
 return {inputTokens,cacheCreationInputTokens,cacheReadInputTokens,outputTokens,totalTokens,status:components.every(v=>v===null)&&totalTokens===null?'unknown':'observed'};
}
function artifacts(value){
 if(value===undefined)return [];if(!Array.isArray(value)||value.length>20)fail(400,'artifacts는 최대 20개입니다');
 return value.map(raw=>{object(raw,'artifact 객체가 필요합니다');onlyKeys(raw,ARTIFACT_FIELDS,'미수집 artifact 필드');const item={name:cleanText(raw.name,200),kind:cleanText(raw.kind,80),path:relativeArtifactPath(raw.path)};if(raw.hash!==undefined){if(!/^[a-f0-9]{64}$/.test(raw.hash))fail(400,'artifact hash는 SHA-256 hex여야 합니다');item.hash=raw.hash;}return item;});
}
function normalize(raw,principal,now){
 object(raw);onlyKeys(raw,FIELDS,'원문·명령·tool args를 포함할 수 없는 필드');
 if(!EVENT_NAMES.has(raw.eventName))fail(400,'허용되지 않은 development event 이름');
 const occurredAt=date(raw.occurredAt),model=raw.model===undefined?'unknown':cleanText(raw.model,120),external=principal.kind==='tool'||principal.kind==='telemetry';
 const timeBasis=raw.timeBasis||'source_observed',item={eventId:identifier(raw.eventId),eventName:raw.eventName,runId:identifier(raw.runId),teamId:identifier(raw.teamId),roleId:identifier(raw.roleId),parentRunId:raw.parentRunId===undefined?null:identifier(raw.parentRunId),parentEventId:raw.parentEventId===undefined?null:identifier(raw.parentEventId),streamSequence:raw.streamSequence===undefined?null:natural(raw.streamSequence,'streamSequence'),timeBasis,model:model||'unknown',modelEvidence:external&&raw.modelObserved===true?'actual_observed':principal.kind==='agent'?'source_self_report':'unknown',status:raw.status===undefined?'unknown':raw.status,occurredAt,toolName:raw.toolName===undefined?'unknown':raw.toolName,usage:usage(raw.usage),artifacts:artifacts(raw.artifacts),tenant:principal.tenant,source:principal.id,sourceKind:principal.kind,sourceEvidence:external?'external_tool_log':'source_self_report',receivedAt:new Date(now).toISOString(),late:timeBasis==='source_observed'&&now-Date.parse(occurredAt)>300000,minimization:{allowlistMetadataOnly:true,rawPromptStored:false,rawThinkingStored:false,commandStored:false,toolArgumentsStored:false,rawSecretFieldsExcluded:true,humanMinimizationRequired:true,semanticRedactionUnverified:true}};
 if(!['source_observed','collector_received','replayed_unknown'].includes(item.timeBasis))fail(400,'허용되지 않은 timeBasis');if(item.parentRunId===item.runId)fail(400,'run은 자신을 parent로 지정할 수 없습니다');
 if(!STATUSES.has(item.status))fail(400,'허용되지 않은 status');if(!TOOLS.has(item.toolName))fail(400,'허용되지 않은 toolName');
 return {...item,fingerprint:digest(raw)};
}
function unknownUsage(){return {inputTokens:null,cacheCreationInputTokens:null,cacheReadInputTokens:null,outputTokens:null,totalTokens:null,status:'unknown'};}
function runView(events,knownRuns){
 const sorted=events.toSorted((a,b)=>(a.streamSequence??Number.MAX_SAFE_INTEGER)-(b.streamSequence??Number.MAX_SAFE_INTEGER)||a.occurredAt.localeCompare(b.occurredAt)||a.receivedAt.localeCompare(b.receivedAt)||a.eventId.localeCompare(b.eventId));const first=sorted[0];
 const observedModel=[...sorted].reverse().find(e=>e.modelEvidence==='actual_observed'&&e.model!=='unknown')||[...sorted].reverse().find(e=>e.model!=='unknown');
 const usageEvent=[...sorted].reverse().find(e=>e.usage?.status==='observed');
 const artifacts=[...new Map(sorted.flatMap(e=>e.artifacts).map(a=>[`${a.kind}|${a.path}|${a.hash||''}`,a])).values()];
 const finished=sorted.filter(e=>['run.completed','run.failed','run.cancelled'].includes(e.eventName)).at(-1);
 const runState=[...sorted].reverse().find(e=>e.eventName.startsWith('run.'));
 return {id:`${first.source}:${first.runId}`,runId:first.runId,teamId:first.teamId,roleId:first.roleId,parentRunId:first.parentRunId,parentEvidence:first.parentRunId?(knownRuns.has(`${first.source}|${first.parentRunId}`)?'observed_same_source':'unresolved'):'none',model:observedModel?.model||'unknown',modelEvidence:observedModel?.modelEvidence||'unknown',status:finished?.status||runState?.status||'unknown',startedAt:sorted.find(e=>e.eventName==='run.started')?.occurredAt||first.occurredAt,startedAtBasis:sorted.find(e=>e.eventName==='run.started')?.timeBasis||first.timeBasis,finishedAt:finished?.occurredAt||null,finishedAtBasis:finished?.timeBasis||null,usage:usageEvent?.usage||unknownUsage(),artifacts,eventCount:sorted.length,lateEventCount:sorted.filter(e=>e.late).length,source:first.source,sourceKind:first.sourceKind,sourceEvidence:first.sourceEvidence};
}

export function createDevelopmentRuns(store,{now=()=>Date.now()}={}){
 store.db.exec(`CREATE TABLE IF NOT EXISTS development_run_events(tenant TEXT NOT NULL,source TEXT NOT NULL,event_id TEXT NOT NULL,run_id TEXT NOT NULL,occurred TEXT NOT NULL,received TEXT NOT NULL,fingerprint TEXT NOT NULL,body TEXT NOT NULL,PRIMARY KEY(tenant,source,event_id));CREATE INDEX IF NOT EXISTS development_run_tenant_run ON development_run_events(tenant,run_id,occurred);CREATE TABLE IF NOT EXISTS development_run_nonces(tenant TEXT NOT NULL,source TEXT NOT NULL,nonce TEXT NOT NULL,expires INTEGER NOT NULL,PRIMARY KEY(tenant,source,nonce));`);
 function authenticateWrite(principal,headers,body,current){
  if(principal?.role!=='source'||!['agent','tool','telemetry'].includes(principal.kind))fail(403,'development event source 자격이 필요합니다');
  const ts=headers['x-evid-timestamp'],nonce=headers['x-evid-nonce'],signature=headers['x-evid-signature'];
  if(!/^\d{13}$/.test(ts||'')||Math.abs(current-Number(ts))>300000||!nonce||!/^[a-zA-Z0-9-]{16,80}$/.test(nonce))fail(401,'서명 시각 또는 nonce가 유효하지 않습니다');
  if(!principal.hmacSecret||!equal(mac(principal.hmacSecret,ts,nonce,body),signature||''))fail(401,'출처 서명 검증 실패');return nonce;
 }
 function ingest(principal,headers,body){
  const current=now(),nonce=authenticateWrite(principal,headers,body,current);let raw;try{raw=JSON.parse(body);}catch{fail(400,'JSON 형식 오류');}const event=normalize(raw,principal,current);
  return store.transaction(()=>{store.db.prepare('DELETE FROM development_run_nonces WHERE expires<?').run(current);if(store.db.prepare('SELECT 1 FROM development_run_nonces WHERE tenant=? AND source=? AND nonce=?').get(principal.tenant,principal.id,nonce))fail(409,'이미 사용한 nonce입니다');store.db.prepare('INSERT INTO development_run_nonces VALUES(?,?,?,?)').run(principal.tenant,principal.id,nonce,current+600000);
   const prior=store.db.prepare('SELECT fingerprint FROM development_run_events WHERE tenant=? AND source=? AND event_id=?').get(principal.tenant,principal.id,event.eventId);if(prior){if(prior.fingerprint!==event.fingerprint)fail(409,'동일 출처 development event ID 내용 충돌');return {accepted:true,duplicate:true,late:event.late};}
   const existing=store.db.prepare('SELECT body FROM development_run_events WHERE tenant=? AND source=? AND run_id=? LIMIT 1').get(principal.tenant,principal.id,event.runId);if(existing){const bound=JSON.parse(existing.body);if(bound.teamId!==event.teamId||bound.roleId!==event.roleId||bound.parentRunId!==event.parentRunId)fail(409,'run의 team/role/parent binding 충돌');}
   if(event.parentRunId){let cursor=event.parentRunId;const visited=new Set([event.runId]);while(cursor){if(visited.has(cursor))fail(409,'run parent cycle');visited.add(cursor);const row=store.db.prepare('SELECT body FROM development_run_events WHERE tenant=? AND source=? AND run_id=? LIMIT 1').get(principal.tenant,principal.id,cursor);cursor=row?JSON.parse(row.body).parentRunId:null;}}
   store.append(principal.tenant,'development_run_event',event,principal.id);store.db.prepare('INSERT INTO development_run_events VALUES(?,?,?,?,?,?,?,?)').run(principal.tenant,principal.id,event.eventId,event.runId,event.occurredAt,event.receivedAt,event.fingerprint,JSON.stringify(event));return {accepted:true,duplicate:false,late:event.late};});
 }
 function query(principal,url){
  if(!['auditor','reviewer','admin'].includes(principal?.role))fail(403,'인간 감사 계정만 접근할 수 있습니다');
  store.audit(principal,'read','/api/development-runs');
  const teamId=url.searchParams.get('teamId'),roleId=url.searchParams.get('roleId'),limit=Math.max(1,Math.min(200,Number(url.searchParams.get('limit'))||100)),offset=Math.max(0,Number(url.searchParams.get('offset'))||0);
  if(teamId)identifier(teamId);if(roleId)identifier(roleId);const rows=store.db.prepare('SELECT body FROM development_run_events WHERE tenant=? ORDER BY occurred,received,event_id').all(principal.tenant).map(row=>JSON.parse(row.body));
  const groups=new Map(),knownRuns=new Set(rows.map(event=>`${event.source}|${event.runId}`));for(const event of rows){if(teamId&&event.teamId!==teamId||roleId&&event.roleId!==roleId)continue;const key=`${event.source}|${event.runId}`;if(!groups.has(key))groups.set(key,[]);groups.get(key).push(event);}
  const all=[...groups.values()].map(events=>runView(events,knownRuns)).toSorted((a,b)=>b.startedAt.localeCompare(a.startedAt)||a.id.localeCompare(b.id)),items=all.slice(offset,offset+limit);const statuses={};for(const run of all)statuses[run.status]=(statuses[run.status]||0)+1;
  return {items,summary:{total:all.length,statuses,completed:all.filter(r=>r.status==='completed').length,failed:all.filter(r=>r.status==='failed').length,active:all.filter(r=>['queued','running','blocked'].includes(r.status)).length},coverage:{events:rows.length,attributedRuns:all.length,actualModelObserved:all.filter(r=>r.modelEvidence==='actual_observed').length,usageObserved:all.filter(r=>r.usage.status==='observed').length,lateEvents:rows.filter(e=>e.late).length,scope:'authenticated tenant development metadata only; absence is unknown, not zero'},total:all.length,offset,limit};
 }
 return {handle(principal,method,url,headers={},body=''){if(url.pathname==='/api/development-runs/events'&&method==='POST')return ingest(principal,headers,body);if(url.pathname==='/api/development-runs'&&method==='GET')return query(principal,url);return undefined;}};
}

export const DEVELOPMENT_EVENT_NAMES=Object.freeze([...EVENT_NAMES]);
