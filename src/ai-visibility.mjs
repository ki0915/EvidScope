import {modelRuntimeStatus} from './model-runtime.mjs';

const windows={'1h':3600000,'24h':86400000,'7d':604800000};
const scripts=()=>({hangul:0,latin:0,mixed:0,undetermined:0});
const scriptKey=value=>({hangul_script:'hangul',korean_script:'hangul',latin_script:'latin',english_script:'latin',mixed_script:'mixed'})[value]||'undetermined';
const ref=e=>`${e.source}/${e.id}`;
const signalMessages={UNREGISTERED_AI:'수집기가 미등록 AI 사용 후보를 보고했습니다',DESTINATION_OUTSIDE_POLICY:'수집기가 허용 목적지 밖 사용을 보고했습니다',DLP_SENSITIVE_CONTENT:'민감정보 분류 신호입니다. 실제 유출 여부는 별도 확인이 필요합니다',PROMPT_INJECTION_SIGNAL:'수집기가 프롬프트·로그 인젝션 의심 신호를 보고했습니다',TOOL_AUTHORITY_UNVERIFIED:'수집기가 도구 권한 확인 부족을 보고했습니다',COLLECTION_GAP:'수집 공백이 보고되었습니다',EVIDENCE_CONFLICT:'수집기가 증거 불일치를 보고했습니다',STOP_UNCONFIRMED:'수집기가 실행 중단 확인 부족을 보고했습니다'};

export function aiScenarioFindings(events,assets){
 const findings=[],add=(code,message,e,severity='medium')=>findings.push({code,severity,message,evidence:[ref(e)]});
 for(const e of events){const o=e.aiObservation;if(!o)continue;const registered=assets.find(a=>a.id===o.assetRef);
  if(!registered)add('AI_UNREGISTERED_ASSET','관측 자산이 등록 목록에 없습니다. 미등록 후보이며 악성 확정이 아닙니다',e);
  const host=o.network?.destinationHost;
  if(registered?.destinations?.length&&host&&!registered.destinations.includes(host))add('AI_DESTINATION_OUTSIDE_POLICY','관측 목적지가 현재 자산 허용 목록 밖입니다. 행동 당시 정책은 별도 대조해야 합니다',e,'high');
  for(const signal of o.signals||[])add(`AI_SOURCE_${signal}`,signalMessages[signal],e,['DLP_SENSITIVE_CONTENT','COLLECTION_GAP'].includes(signal)?'high':'medium');
  if(o.screening&&['partial','timeout','error'].includes(o.screening.status))add('AI_SCREENING_INCOMPLETE','본문 검사가 완료되지 않았습니다. 미검사 구간을 안전으로 처리하지 않습니다',e);
  if(o.screening?.safety==='controversial')add('AI_PRIVACY_REVIEW_REQUIRED','민감정보 분류가 모호하여 사람의 검토가 필요합니다',e);
 }
 return findings;
}

export function aiVisibility(store,tenant,params=new URLSearchParams(),{now=Date.now(),runtimeStatus=modelRuntimeStatus(),registrations}={}){
 if(!Array.isArray(registrations))throw Error('verified_asset_projection_required');
 const range=Object.hasOwn(windows,params.get('range'))?params.get('range'):'24h',end=now,start=end-windows[range],q=(params.get('q')||'').slice(0,200).toLowerCase(),assetRef=params.get('assetRef');
 const all=store.events(tenant),observed=all.filter(e=>e.aiObservation&&Date.parse(e.receivedAt)<=end),input=observed.slice(-10000),truncated=observed.length>input.length;
 const assets=new Map();
 function ensure(id){if(!assets.has(id)){const a=registrations.find(a=>a.id===id);assets.set(id,{id,registered:!!a,owner:a?.owner||null,lastSeen:null,observationCount:0,providers:new Set(),models:new Set(),collectors:new Set(),contentObserved:0,bodyNotObserved:0,screeningIncomplete:0,languageSignals:scripts(),attention:[]});}return assets.get(id);}
 for(const a of registrations)ensure(a.id);
 const screening={completed:0,incomplete:0,not_observed:0,not_run:0,unsafe:0,controversial:0},languageSignals=scripts();let totalObservations=0;
 const included=[];
 for(const e of input){const at=Date.parse(e.receivedAt);if(at<start||!Number.isFinite(at))continue;const o=e.aiObservation,a=ensure(o.assetRef);if(assetRef&&assetRef!==a.id||q&&!`${a.id} ${a.owner||''} ${o.model} ${o.provider}`.toLowerCase().includes(q))continue;
  included.push(e);totalObservations++;a.observationCount++;if(!a.lastSeen||Date.parse(a.lastSeen)<at)a.lastSeen=e.receivedAt;a.providers.add(o.provider);a.models.add(o.model);a.collectors.add(o.collector.id);
  const body=o.coverage.mode==='content';if(body)a.contentObserved++;else {a.bodyNotObserved++;screening.not_observed++;}
  const s=o.screening;if(s?.status==='complete')screening.completed++;else if(['partial','timeout','error'].includes(s?.status)){screening.incomplete++;a.screeningIncomplete++;}else if(body)screening.not_run++;
  if(s?.safety==='unsafe')screening.unsafe++;if(s?.safety==='controversial')screening.controversial++;
  if(body&&o.languageSignals){const key=scriptKey(o.languageSignals.classification);a.languageSignals[key]++;languageSignals[key]++;}
  for(const f of aiScenarioFindings([e],registrations))a.attention.push({code:f.code,severity:f.severity,message:f.message,evidenceRefs:f.evidence});
 }
 // Bounded cross-action observations are investigation signals, separate from case decisions.
 for(const a of assets.values()){
  const history=input.filter(e=>e.aiObservation.assetRef===a.id),current=history.filter(e=>Date.parse(e.receivedAt)>=end-300000),baseline=history.filter(e=>Date.parse(e.receivedAt)>=end-3900000&&Date.parse(e.receivedAt)<end-300000);
  if(current.length>=20&&baseline.length>=20&&current.length/5>=5*baseline.length/60)a.attention.push({code:'AI_CALL_RATE_SPIKE',severity:'medium',message:'최근 5분 호출률이 직전 60분 기준의 5배 이상입니다. 정상 배치 작업 여부를 확인하세요',evidenceRefs:current.slice(0,20).map(ref)});
  const priorModels=new Set(history.filter(e=>Date.parse(e.receivedAt)<start).map(e=>e.aiObservation.model));
  if(priorModels.size)for(const model of a.models)if(model!=='unknown'&&!priorModels.has(model)){const first=included.find(e=>e.aiObservation.assetRef===a.id&&e.aiObservation.model===model);a.attention.push({code:'AI_NEW_MODEL_OBSERVED',severity:'low',message:'이 관측 기간 이전 기록에 없는 모델입니다. 처음 관측됐다는 뜻이며 악성 판정이 아닙니다',evidenceRefs:first?[ref(first)]:[]});}
  a.attention=a.attention.slice(0,100);
 }
 const output=[...assets.values()].filter(a=>(!assetRef||assetRef===a.id)&&(!q||`${a.id} ${a.owner||''} ${[...a.models].join(' ')} ${[...a.providers].join(' ')}`.toLowerCase().includes(q))).map(a=>({...a,providers:[...a.providers],models:[...a.models],collectors:[...a.collectors]})).sort((a,b)=>b.attention.length-a.attention.length||a.id.localeCompare(b.id));
 return {version:1,window:{range,start:new Date(start).toISOString(),end:new Date(end).toISOString(),timeBasis:'receivedAt'},summary:{assets:output.length,registeredAssets:output.filter(a=>a.registered).length,observedAssets:output.filter(a=>a.observationCount).length,totalObservations,contentObserved:output.reduce((n,a)=>n+a.contentObserved,0),bodyNotObserved:output.reduce((n,a)=>n+a.bodyNotObserved,0),screeningIncomplete:screening.incomplete,attentionCount:output.reduce((n,a)=>n+a.attention.length,0)},assets:output,screening,languageSignals,modelRuntime:runtimeStatus,coverage:{observationsConsidered:input.length,truncated,limit:10000},limitations:['등록 자산과 연동 수집 지점에서 관측된 범위입니다. 전체 조직의 AI 사용률이 아닙니다.','문자 집계는 명시적 본문 필드 기준이며 라틴 문자를 영어 이해로 해석하지 않습니다.','출처 인증과 분류 점수는 내용의 진실성·유출·침해·법규 준수를 확정하지 않습니다.',...(truncated?['관측 집계 한도를 초과했습니다. 부분 결과입니다.']:[])]};
}
