import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,generateKeyPairSync} from 'node:crypto';
import {fork} from 'node:child_process';
import {join} from 'node:path';
import {readFileSync} from 'node:fs';
import {harness} from './harness.mjs';
import {submit,Observer} from '../src/client.mjs';
import {verifyBundle} from '../src/crypto.mjs';
import {demo} from '../scripts/demo.mjs';
import {tick} from '../src/worker.mjs';

test('실제 HTTP 경계 · 증거 · 거버넌스 · 복구 통합',async t=>{
 const h=await harness();t.after(()=>h.close());
 const event=(id,extra={})=>({id,kind:'intent',actionId:'action-main',traceId:'trace-main',occurredAt:new Date().toISOString(),actor:'agent',tool:'tool',action:'read',resource:'r1',...extra});
 let first=event('first');
 await t.test('원문/tenant/source 사칭, 임의 조회와 변조 HMAC 거부',async()=>{
  assert.equal((await h.api('/api/events',{role:'agent'})).status,403);
  for(const path of ['/api/export','/api/rules','/api/governance','/api/integrity','/api/cases'])assert.equal((await h.api(path,{role:'agent'})).status,403);
  assert.equal((await h.api('/api/rebuild',{role:'agent',body:{}})).status,403);
  assert.equal((await h.api('/api/events',{role:'agent',base:h.ingress.url})).status,403);
  assert.equal((await h.api('/api/events',{headers:{authorization:'Bearer wrong'}})).status,401);
  assert.equal((await submit(h.ingress.url,h.principal('agent'),{...first,tenant:'beta'})).status,400);
  assert.equal((await submit(h.ingress.url,h.principal('agent'),{...first,kind:'result'})).status,403);
  assert.equal((await submit(h.ingress.url,h.principal('agent'),{...first,kind:'human_approval'})).status,403);
  assert.equal((await submit(h.ingress.url,h.principal('agent'),{...first,prompt:'secret raw content'})).status,400);
  assert.equal((await submit(h.ingress.url,h.principal('agent'),first,{signature:'a'.repeat(64)})).status,401);
  assert.equal((await submit(h.ingress.url,h.principal('agent'),first,{timestamp:String(Date.now()-600001)})).status,401);
  assert.equal((await h.api('/api/events',{headers:{origin:'https://attacker.example'}})).status,403);
 });
 await t.test('접수 COMMIT, replay/duplicate/ID conflict, tenant 격리',async()=>{
  const nonce=randomUUID();assert.equal((await submit(h.ingress.url,h.principal('agent'),first,{nonce})).status,202);
  assert.equal((await submit(h.ingress.url,h.principal('agent'),first,{nonce})).status,409);
  assert.equal((await submit(h.ingress.url,h.principal('agent'),first)).body.duplicate,true);
  assert.equal((await submit(h.ingress.url,h.principal('agent'),{...first,resource:'changed'})).status,409);
  assert.equal((await submit(h.ingress.url,h.principal('agent','beta'),first)).status,202);
  assert.equal((await h.api('/api/events')).body.total,1);
  const beta=(await h.api('/api/events',{tenant:'beta'})).body;assert.equal(beta.total,1);assert.equal(beta.items[0].tenant,'beta');
  assert.equal((await h.api('/api/events?q=changed')).body.total,0);
 });
 await t.test('자기보고/독립 결과, 자동검토/사람승인, 뒤늦은 권한 재평가',async()=>{
  const when=Date.now()-1000;const common={actionId:'action-real',traceId:'trace-real',occurredAt:new Date(when).toISOString(),policyVersion:'v1',actor:'a',tool:'t',action:'write',resource:'r'};
  assert.equal((await h.api('/api/assets',{role:'reviewer',body:{id:'prior-approval-policy',actor:'a',tool:'t',owner:'reviewer',policyVersion:'v1',validFrom:new Date(when-60000).toISOString(),approvalRequired:true}})).status,200);
  const scope={actor:'a',tool:'t',action:'write',resource:'r'};
  for(const [source,e]of [['tool',{id:'exec',kind:'result',status:'failure'}],['agent',{id:'claim',kind:'self_report',status:'success'}],['authority',{id:'auto',kind:'automated_review',scope,validFrom:new Date(when-1000).toISOString(),validUntil:new Date(when+60000).toISOString()}],['safety',{id:'stop',kind:'block_registered'}]])assert.equal((await submit(h.ingress.url,h.principal(source),{...common,...e})).status,202);
  await h.analyze();let a=(await h.api('/api/actions/action-real')).body;let codes=a.evaluations[0].findings.map(f=>f.code);
  assert.ok(codes.includes('AUTHORITY_MISSING'));assert.ok(codes.includes('HUMAN_APPROVAL_MISSING'));assert.ok(codes.includes('CONTRADICTING_RESULT'));assert.ok(codes.includes('STOP_UNCONFIRMED'));assert.equal(a.evaluations[0].effect,'independently_reported_failure');
  for(const [id,kind]of [['grant','grant'],['human','human_approval']])assert.equal((await submit(h.ingress.url,h.principal('authority'),{...common,id,kind,reviewer:'external-human',scope,validFrom:new Date(when-1000).toISOString(),validUntil:new Date(when+60000).toISOString()})).status,202);
  await h.analyze();a=(await h.api('/api/actions/action-real')).body;assert.equal(a.evaluations.length,2);assert.equal(a.evaluations[0].authority,'matched_at_event_time');assert.ok(a.evaluations[1].findings.some(f=>f.code==='AUTHORITY_MISSING'));
  assert.equal((await submit(h.ingress.url,h.principal('authority'),{...common,id:'revocation',kind:'revoke',authorityId:'grant',occurredAt:new Date(when-1).toISOString()})).status,202);await h.analyze();assert.equal((await h.api('/api/actions/action-real')).body.evaluations[0].authority,'unverified_or_mismatch');
 });
 await t.test('안전한 룰 DSL·시험·두 사람 승인·예외 만료',async()=>{
  const rule={id:'rule-test',title:'읽기 조사',field:'action',op:'eq',value:'read',severity:'medium'};
  assert.equal((await h.api('/api/rules',{role:'reviewer',body:{...rule,op:'javascript'}})).status,400);
  assert.equal((await h.api('/api/rules',{role:'reviewer',body:rule})).status,200);
  assert.equal((await h.api('/api/rules/rule-test/approve',{role:'admin',body:{version:1}})).status,409);
  assert.equal((await h.api('/api/rules/rule-test/test',{role:'reviewer',body:{version:1}})).body.matches.length,1);
  assert.equal((await h.api('/api/rules/rule-test/approve',{role:'reviewer',body:{version:1}})).status,403);
  assert.equal((await h.api('/api/rules/rule-test/approve',{role:'admin',body:{version:1}})).status,200);await h.analyze();
  const ex=(await h.api('/api/exceptions',{body:{ruleId:'rule-test',actionId:'action-main',owner:'alpha-auditor',reason:'합성 만료 시험',expiresAt:new Date(Date.now()+600).toISOString()}})).body;
  assert.equal((await h.api(`/api/exceptions/${ex.id}/approve`,{role:'auditor',body:{}})).status,403);
  assert.equal((await h.api(`/api/exceptions/${ex.id}/approve`,{role:'admin',body:{}})).status,200);await h.analyze();
  assert.ok((await h.api('/api/alerts')).body.items.some(a=>a.code.startsWith('CUSTOM:')&&a.state==='suppressed'));
  await new Promise(r=>setTimeout(r,700));await h.analyze();assert.ok((await h.api('/api/alerts')).body.items.some(a=>a.code.startsWith('CUSTOM:')&&a.state==='open'));
 });
 await t.test('원본 참조 사건 담당·의견·종결 사유·tenant 접근',async()=>{
  const c=(await h.api('/api/cases',{body:{title:'합성 조사',actionId:'action-main',owner:'조사자'}})).body;
  assert.equal((await h.api(`/api/cases/${c.id}`,{body:{status:'closed'}})).status,400);
  assert.equal((await h.api(`/api/cases/${c.id}`,{tenant:'beta',body:{comment:'cross tenant'}})).status,404);
  const updated=(await h.api(`/api/cases/${c.id}`,{body:{comment:'근거 검토',status:'closed',reason:'합성 조사 완료'}})).body;assert.equal(updated.history.length,2);assert.equal(updated.comments.length,1);
  assert.equal((await h.api('/api/events')).body.total,8);
 });
 await t.test('빈 증거 통과 금지, 시스템 변경·기한 재검토, 보완과제 쓰기',async()=>{
  const s={id:'system-test',name:'생성형',owner:'담당',purpose:'고객 안내',role:'이용사업자',markets:['KR'],generative:true,highImpact:'unknown'};
  assert.equal((await h.api('/api/governance/systems',{role:'reviewer',body:s})).status,200);
  const a={systemId:s.id,requirementId:'KR-31-1',applicability:'applicable',evidence:[],control:'고지',owner:'담당',assessment:'sufficient',legalReview:'pending',reason:'합성',nextReviewAt:new Date(Date.now()+86400000).toISOString()};
  assert.equal((await h.api('/api/governance/assessments',{role:'reviewer',body:a})).status,400);
  a.evidence=[{type:'event',ref:'beta-agent/first',version:'1'}];assert.equal((await h.api('/api/governance/assessments',{role:'reviewer',body:a})).status,400);
  a.evidence=[{type:'event',ref:'alpha-agent/first',version:'1'}];assert.equal((await h.api('/api/governance/assessments',{role:'reviewer',body:a})).status,200);
  let report=(await h.api('/api/governance/report?systemId=system-test')).body;
  const initial=report.items.find(i=>i.requirement.id==='KR-31-1');
  assert.equal(initial.status,'evidence_insufficient');assert.equal(initial.legalStatus,'pending');assert.equal(initial.assessment.assessment,'sufficient');
  assert.equal(initial.technicalEvidence.supportsHumanAssessment,false);assert.ok(initial.technicalEvidence.reasons.includes('authenticated_typed_measurement_missing'));
  assert.ok(report.tasks.length>0);
  for(const task of report.tasks)assert.equal((await h.api('/api/governance/tasks/'+task.id,{role:'reviewer',body:{status:'closed',reason:'일반 intent를 고지 증거로 주장'}})).status,409);
  assert.equal((await h.api('/api/governance/systems',{role:'reviewer',body:{...s,purpose:'채용 의사결정'}})).status,200);
  report=(await h.api('/api/governance/report?systemId=system-test')).body;
  assert.equal(report.items.find(i=>i.requirement.id==='KR-31-1').status,'review_required');
  assert.ok(report.tasks.some(task=>task.title.includes('시스템 사실관계 변경')));
  for(const task of report.tasks)assert.equal((await h.api('/api/governance/tasks/'+task.id,{role:'reviewer',body:{status:'closed',reason:'검토 계획만 수립'}})).status,409);
  assert.ok((await h.api('/api/governance/report?systemId=system-test')).body.tasks.every(task=>task.status==='open'));
 });
 await t.test('독립 신뢰키 검증·내용/누락/순서/키 대체 및 rollback 탐지',async()=>{
  const bundle=(await h.api('/api/export')).body;assert.equal(verifyBundle(bundle,h.publicKey).valid,true);
  const bad=structuredClone(bundle);bad.records[0].payload.extra='tampered';assert.throws(()=>verifyBundle(bad,h.publicKey));
  const missing=structuredClone(bundle);missing.records.splice(1,1);assert.throws(()=>verifyBundle(missing,h.publicKey));
  const reorder=structuredClone(bundle);[reorder.records[0],reorder.records[1]]=[reorder.records[1],reorder.records[0]];assert.throws(()=>verifyBundle(reorder,h.publicKey));
  assert.throws(()=>verifyBundle(bundle,generateKeyPairSync('ed25519').publicKey));
  const newer=(await h.api('/api/export')).body;assert.throws(()=>verifyBundle(bundle,h.publicKey,newer.checkpoint));
  assert.ok(bundle.records.some(r=>r.type==='audit_access'));assert.ok(!JSON.stringify(bundle).includes('secret raw content'));
 });
 await t.test('다중 실제 writer·worker 동시성: 중복·체인 분기 없음',async()=>{
  const second=await h.start('vault');const shared=event('simultaneous');
  const results=await Promise.all(Array.from({length:40},(_,i)=>submit(i%2?h.vault.url:second.url,h.principal('agent'),i<10?shared:event('concurrent-'+i),{timeoutMs:10000})));
  assert.ok(results.every(r=>r.status===202));assert.equal(results.filter(r=>r.body.duplicate).length,9);
  const token=h.config.principals.find(p=>p.role==='worker').token;await Promise.all(Array.from({length:6},(_,i)=>tick(i%2?second.url:h.vault.url,token)));
  assert.equal((await h.api('/api/overview')).body.counts.backlog,0);const bundle=(await h.api('/api/export')).body;assert.equal(verifyBundle(bundle,h.publicKey).valid,true);
  second.child.send('shutdown');await new Promise(r=>second.child.once('exit',r));
 });
 await t.test('강제 종료 이후 성공 접수 보존·조회 사본 재구축',async()=>{
  const before=(await h.api('/api/events?limit=500')).body;
  await h.restart();const after=(await h.api('/api/events?limit=500')).body;assert.equal(after.total,before.total);assert.deepEqual(after.items.map(e=>e.id),before.items.map(e=>e.id));
  assert.equal((await h.api('/api/rebuild',{role:'admin',body:{}})).body.rebuilt,before.total);
  const rebuilt=(await h.api('/api/events?limit=500')).body;assert.deepEqual(rebuilt.items,after.items);assert.equal((await h.api('/api/integrity')).body.valid,true);
 });
 await t.test('실제 SQLite 쓰기 잠금 장애: 거짓 성공 없음·해제 뒤 재전송',async()=>{
  const child=fork('test/lock-store.mjs',[join(h.dir,'data','evidence.db')],{stdio:['ignore','ignore','ignore','ipc']});
  const exited=()=>child.exitCode!==null||child.signalCode!==null;
  const waitExit=ms=>new Promise(resolve=>{if(exited())return resolve(true);const finish=done=>{clearTimeout(timer);child.off('exit',onExit);resolve(done);},onExit=()=>finish(true),timer=setTimeout(()=>finish(false),ms);child.once('exit',onExit);});
  let failure;const e=event('outage');
  try{
   await new Promise((resolve,reject)=>{
    const finish=error=>{clearTimeout(timer);child.off('message',onMessage);child.off('error',onError);child.off('exit',onExit);error?reject(error):resolve();};
    const onMessage=message=>message==='locked'?finish():finish(Error('SQLite lock helper returned an unexpected readiness message'));
    const onError=error=>finish(error),onExit=(code,signal)=>finish(Error(`SQLite lock helper exited before readiness: ${code??signal}`)),timer=setTimeout(()=>finish(Error('SQLite lock helper readiness timeout after 10s')),10000);
    child.once('message',onMessage);child.once('error',onError);child.once('exit',onExit);
   });
   const result=await submit(h.ingress.url,h.principal('agent'),e,{timeoutMs:9000});assert.equal(result.status,503);
  }catch(error){failure=error;}
  finally{
   try{
    if(!exited()){
     if(child.connected){try{child.send('release',error=>{if(error&&!exited())child.kill();});}catch{child.kill();}}
     else child.kill();
     if(!await waitExit(3000)){child.kill();if(!await waitExit(3000))throw Error(`Owned SQLite lock helper ${child.pid} did not exit after release and kill`);}
    }
   }catch(error){failure=failure?new AggregateError([failure,error],'SQLite lock assertion and helper cleanup both failed'):error;}
  }
  if(failure)throw failure;
  assert.equal((await submit(h.ingress.url,h.principal('agent'),e)).status,202);
 });
 await t.test('수집 실패가 업무 호출을 대기시키지 않는 유한 SDK',async()=>{
  const observer=new Observer('http://127.0.0.1:1',h.principal('agent'),{capacity:1,attempts:1,timeoutMs:50});const start=performance.now();for(let i=0;i<10;i++)observer.observe(event('sdk-'+i));assert.ok(performance.now()-start<100);while(observer.running)await new Promise(r=>setTimeout(r,20));assert.equal(observer.metrics.observed,10);assert.equal(observer.metrics.dropped,10);
 });
 await t.test('합성 예제 end-to-end 실제 API 시드·전체 요구 31개와 한국 18개',async()=>{
  const result=await demo({config:h.config,ingress:h.ingress.url,audit:h.audit.url});assert.equal(result.events,10);for(let i=0;i<5;i++)await h.analyze();
  const gov=(await h.api('/api/governance')).body;assert.equal(gov.requirements.length,31);assert.equal(gov.requirements.filter(item=>item.jurisdiction==='KR').length,18);assert.ok(gov.systems.length>=2);assert.ok(gov.tasks.length>0);
  const action=(await h.api('/api/actions/'+result.actionId)).body;assert.ok(action.evaluations[0].findings.some(f=>f.code==='APPROVAL_MISMATCH'));assert.ok(action.evaluations[0].findings.some(f=>f.code==='LOG_INJECTION_SIGNAL'));
  assert.equal((await h.api('/api/integrity')).body.valid,true);
 });
});
