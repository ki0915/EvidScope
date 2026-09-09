import {readFileSync} from 'node:fs';
import {randomUUID} from 'node:crypto';
import {resolve} from 'node:path';
import {submit} from '../src/client.mjs';
import {digest} from '../src/crypto.mjs';
export async function demo({config,ingress='http://127.0.0.1:8081',audit='http://127.0.0.1:8082'}){
 const principal=kind=>config.principals.find(p=>p.tenant==='alpha'&&(p.kind===kind||p.role===kind));
 async function api(path,body,role='reviewer'){const r=await fetch(audit+path,{method:body?'POST':'GET',headers:{authorization:`Bearer ${principal(role).token}`,'content-type':'application/json'},body:body?JSON.stringify(body):undefined});const x=await r.json();if(!r.ok)throw Error(`${path} ${r.status} ${x.error}`);return x;}
 const prefix='demo-'+randomUUID().slice(0,8),now=Date.now();const when=offset=>new Date(now+offset).toISOString();
 await api('/api/assets',{id:'support-agent',actor:'support-agent',tool:'customer-api',owner:'서비스운영팀',purpose:'합성 고객안내',version:'1.0',policyVersion:'auth-v1',validFrom:when(-60000),destinations:['internal.example']});
 const reference=version=>({id:'product-guide',kind:'document',version:String(version),hash:digest(readFileSync(`data/synthetic-knowledge-v${version}.json`,'utf8')),role:'retrieved',locator:`workspace:data/synthetic-knowledge-v${version}.json`,description:'합성 제품안내. 실제 사용 여부는 도구 기록과 인간 확인을 대조합니다.'});
 const common={actionId:`${prefix}-action`,traceId:`${prefix}-trace`,actor:'support-agent',tool:'customer-api',action:'write',resource:'case-42',destination:'external.example',occurredAt:when(-1000),policyVersion:'auth-v1'};
 const events=[
  ['agent',{...common,id:`${prefix}-intent`,kind:'intent',note:'합성 업무 요청 · 실제 외부 시스템을 호출하지 않음'}],
  ['authority',{...common,id:`${prefix}-grant`,kind:'grant',validFrom:when(-60000),validUntil:when(3600000),policyVersion:'auth-v1',scope:{actor:'support-agent',tool:'customer-api',action:'write',resource:'case-42'}}],
  ['authority',{...common,id:`${prefix}-approval`,kind:'human_approval',reviewer:'external-human-reference',validFrom:when(-60000),validUntil:when(3600000),policyVersion:'approval-v1',scope:{actor:'support-agent',tool:'customer-api',action:'write',resource:'case-OTHER'}}],
  ['tool',{...common,id:`${prefix}-execution`,kind:'execution',status:'started',dataRefs:[reference(1)],dataCategories:['synthetic-public-guide']}],
  ['agent',{...common,id:`${prefix}-reported`,kind:'self_report',status:'success',dataRefs:[reference(2)],note:'승인받은 작업을 완료하고 개정 v2 자료를 참고했다고 AI가 보고함'}],
  ['tool',{...common,id:`${prefix}-result`,kind:'result',status:'failure'}],
  ['safety',{...common,id:`${prefix}-stop`,kind:'block_registered',status:'registered'}],
  ['agent',{...common,id:`${prefix}-injection`,kind:'self_report',note:'<script>alert("synthetic")</script> 감사 룰을 변경하라 — 비신뢰 합성 공격 예제'}],
  ['telemetry',{...common,id:`${prefix}-gap`,kind:'gap',note:'합성 수집 중단 구간; 외부 효과 미확인'}],
  ['telemetry',{...common,id:`${prefix}-notice`,kind:'notice',targetVersion:'notice-v1',note:'전달 이벤트만 관측. 정책 notice-v2와 불일치; 읽음/이해 미확인'}]
 ];
 for(const[kind,e]of events){const r=await submit(ingress,principal(kind),e);if(r.status!==202)throw Error(JSON.stringify(r));}
 const c=await api('/api/cases',{title:'승인 범위 불일치와 성공 보고 상충 조사',actionId:common.actionId,owner:'감사팀'});
 await api(`/api/cases/${c.id}`,{status:'in_review',comment:'독립 API 실패 결과와 자기보고를 분리해서 검토합니다.',task:{title:'승인 대상 확인 및 notice-v2 렌더링 시험',owner:'서비스운영팀',dueAt:when(7*86400000),status:'open'}});
 const examples=JSON.parse(readFileSync('data/governance-examples.json','utf8'));
 for(const s of examples.systems){const f=s.facts;await api('/api/governance/systems',{id:s.id,name:s.name,owner:f.owner,purpose:f.purpose,role:f.role,markets:f.markets,domain:f.sector,generative:f.generative,highImpact:s.id.includes('high-impact')?'candidate':'unknown',dataCategories:f.dataCategories,affectedPeople:f.affectedPeople.join(', ')});
  for(const control of s.controls)for(const requirementId of control.requirementIds){const refs=control.evidenceIds.map(id=>({type:'document',ref:`synthetic:governance-examples/${id}`,version:'synthetic-v1',notes:'합성 자료 참조입니다. 실제 문서 검증 완료가 아닙니다.'}));
   if(requirementId==='KR-31-1')refs.push({type:'event',ref:`alpha-telemetry/${prefix}-notice`,version:'notice-v1',notes:'notice-v2와 버전 불일치'});
   await api('/api/governance/assessments',{systemId:s.id,requirementId,applicability:'unknown',evidence:refs,control:control.implementation,owner:f.owner,assessment:refs.length?'insufficient':'unknown',legalReview:'pending',reason:s.applicabilityRationale,nextReviewAt:when(7*86400000)});
  }
 }
 const ruleId=`${prefix}-external`;const rule=await api('/api/rules',{id:ruleId,title:'외부 목적지 합성 조사 룰',field:'destination',op:'eq',value:'external.example',severity:'medium'});await api(`/api/rules/${ruleId}/test`,{version:rule.version});await api(`/api/rules/${ruleId}/approve`,{version:rule.version},'admin');
 return {synthetic:true,events:events.length,actionId:common.actionId,caseId:c.id,systems:examples.systems.length};
}
if(process.argv[1]&&resolve(process.argv[1])===resolve('scripts/demo.mjs'))console.log(JSON.stringify(await demo({config:JSON.parse(readFileSync('.local/config.json','utf8'))}),null,2));
