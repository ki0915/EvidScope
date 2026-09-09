import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {join} from 'node:path';
import {generateKeyPairSync} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {harness} from './harness.mjs';
import {submit} from '../src/client.mjs';
import {verifyCaseReport} from '../src/report-verifier.mjs';

async function fixture(h,actionId='review-action') {
 const base={actionId,traceId:'review-trace',occurredAt:new Date().toISOString(),actor:'assistant',tool:'crm',action:'update',resource:'case-42'};
 for(const [source,event] of [['agent',{id:'claim',kind:'self_report',status:'success'}],['tool',{id:'result',kind:'result',status:'failure'}]])assert.equal((await submit(h.ingress.url,h.principal(source),{...base,...event})).status,202);
 await h.analyze();
 const response=await h.api('/api/cases',{body:{title:'합성 실무 조사',owner:'audit-team',actionId}});assert.equal(response.status,200);
 return {base,case:response.body,path:`/api/cases/${response.body.id}`,ref:`${h.principal('tool').id}/result`};
}
function decision(contextHash,ref,extra={}) {return {contextHash,conclusion:'confirmed_issue',scope:'이 행동의 요청과 서비스 결과 대조',reason:'서비스 실패가 자기보고 성공과 상충함',limitations:'외부 원본과 최종 업무 상태는 별도 확인 필요',nextReviewAt:new Date(Date.now()+86400000).toISOString(),evidence:[{ref,supports:'supports',note:'인증된 서비스 결과'}],...extra};}

test('행동 조사함: 이벤트를 행동으로 묶고 미확인·혼합 결과·권한 경계를 유지',async t=>{
 const h=await harness();t.after(()=>h.close());const f=await fixture(h);
 let response=await h.api('/api/investigations?state=needs_review&limit=1');assert.equal(response.status,200);assert.equal(response.body.total,1);assert.equal(response.body.items.length,1);
 let item=response.body.items[0];assert.equal(item.actionId,f.base.actionId);assert.equal(item.eventCount,2);assert.equal(item.reviewState,'unreviewed');assert.equal(item.outcome,'independently_reported_failure');assert.ok(item.attention.length);assert.ok(item.caseIds.includes(f.case.id));
 assert.equal((await h.api('/api/investigations?q=not-found')).body.total,0);
 assert.equal((await h.api('/api/investigations?offset=1&limit=1')).body.items.length,0);
 assert.equal((await h.api('/api/investigations',{tenant:'beta'})).body.total,0);
 assert.equal((await h.api('/api/investigations',{role:'agent'})).status,403);
 assert.equal((await h.api('/api/investigations',{base:h.ingress.url})).status,403);
 await submit(h.ingress.url,h.principal('tool'),{...f.base,id:'later-success',kind:'result',status:'success'});
 await h.analyze();item=(await h.api('/api/investigations')).body.items[0];assert.equal(item.outcome,'mixed_results');
});

test('사람 판단: 필수 사유·범위·반증과 같은 행동 근거만 연결하고 작성자 위조를 차단',async t=>{
 const h=await harness();t.after(()=>h.close());const f=await fixture(h),path=f.path+'/decisions';
 const context=(await h.api(f.path+'/review-context')).body;
 for(const extra of [{reason:'  '},{scope:'  '},{limitations:'\n'},{nextReviewAt:'2020-01-01T00:00:00Z'},{evidence:[]},{evidence:[{ref:'beta-tool/result',supports:'supports',note:''}]},{evidence:[{ref:f.ref,supports:'invented',note:''}]}])assert.equal((await h.api(path,{body:decision(context.contextHash,f.ref,extra)})).status,400,JSON.stringify(extra));
 await submit(h.ingress.url,h.principal('agent'),{...f.base,id:'unrelated',actionId:'other-action',kind:'intent'});
 assert.equal((await h.api(path,{body:decision(context.contextHash,f.ref,{evidence:[{ref:h.principal('agent').id+'/unrelated',supports:'supports',note:''}]})})).status,400);
 assert.equal((await h.api(path,{role:'agent',body:decision(context.contextHash,f.ref)})).status,403);
 assert.equal((await h.api(f.path+'/review-context',{tenant:'beta'})).status,404);
 assert.equal((await h.api(path,{body:decision(context.contextHash,f.ref,{reviewedBy:'forged-admin',createdAt:'2000-01-01T00:00:00Z'})})).status,400);
 const saved=await h.api(path,{body:decision(context.contextHash,f.ref)});assert.equal(saved.status,200);assert.equal(saved.body.reviewedBy,h.principal('auditor').id);
 const current=(await h.api(f.path+'/review-context')).body;assert.equal(current.reviewState,'reviewed');assert.equal(current.decisions.length,1);assert.equal(current.latestDecision.id,saved.body.id);
 assert.equal((await h.api('/api/investigations?state=reviewed')).body.total,1);
 await h.api(f.path,{body:{comment:'별도 코멘트 추가'}});
 assert.equal((await h.api(f.path+'/review-context')).body.contextHash,current.contextHash,'reading or commenting must not make evidence stale');
});

test('새 증거·분석 변경은 재검토, 오래된 화면의 판단은 409, 사건 보고서는 독립 검증',async t=>{
 const h=await harness();t.after(()=>h.close());const f=await fixture(h);
 let context=(await h.api(f.path+'/review-context')).body;
 assert.equal((await h.api(f.path+'/decisions',{body:decision(context.contextHash,f.ref)})).status,200);
 const exported=await h.api(f.path+'/report');assert.equal(exported.status,200);
 const checked=verifyCaseReport(exported.body,h.publicKey,{expectedTenant:'alpha',expectedCaseId:f.case.id});assert.equal(checked.valid,true);assert.equal(checked.rollbackChecked,false);assert.equal(checked.reviewState,'reviewed');
 const reportPath=join(h.dir,'case-report.json'),keyPath=join(h.dir,'trusted.pem');writeFileSync(reportPath,JSON.stringify(exported.body));writeFileSync(keyPath,h.publicKey);
 const cli=spawnSync(process.execPath,['scripts/verify-case-report.mjs',reportPath,keyPath],{encoding:'utf8',windowsHide:true});assert.equal(cli.status,0,cli.stderr);assert.equal(JSON.parse(cli.stdout).valid,true);
 const altered=structuredClone(exported.body);altered.snapshot.review.latestDecision.reason='바뀐 판단';assert.throws(()=>verifyCaseReport(altered,h.publicKey),/signature/);
 writeFileSync(reportPath,JSON.stringify(altered));assert.equal(spawnSync(process.execPath,['scripts/verify-case-report.mjs',reportPath,keyPath],{encoding:'utf8',windowsHide:true}).status,1);
 const changedEvidence=structuredClone(exported.body);changedEvidence.snapshot.action.events[0].status='forged';assert.throws(()=>verifyCaseReport(changedEvidence,h.publicKey),/signature/);
 assert.throws(()=>verifyCaseReport(exported.body,generateKeyPairSync('ed25519').publicKey),/key/);
 assert.throws(()=>verifyCaseReport(exported.body,h.publicKey,{expectedTenant:'beta'}),/tenant/);
 assert.throws(()=>verifyCaseReport(exported.body,h.publicKey,{expectedReportHash:'0'.repeat(64)}),/digest/);
 assert.equal(verifyCaseReport(exported.body,h.publicKey,{expectedReportHash:checked.reportHash}).rollbackChecked,true);
 await submit(h.ingress.url,h.principal('tool'),{...f.base,id:'late-new-result',kind:'result',status:'success'});
 assert.equal((await h.api(f.path+'/review-context')).body.reviewState,'stale');
 assert.equal((await h.api(f.path+'/decisions',{body:decision(context.contextHash,f.ref)})).status,409);
 await h.analyze();context=(await h.api(f.path+'/review-context')).body;assert.equal(context.decisions.length,1);assert.equal(context.reviewState,'stale');
 const next=await h.api(f.path+'/decisions',{body:decision(context.contextHash,f.ref,{conclusion:'inconclusive',evidence:[]})});assert.equal(next.status,200);
 assert.equal((await h.api(f.path+'/review-context')).body.reviewState,'inconclusive');
 const newer=(await h.api(f.path+'/report')).body;assert.equal(verifyCaseReport(newer,h.publicKey).reviewState,'inconclusive');
 assert.throws(()=>verifyCaseReport(exported.body,h.publicKey,{expectedCheckpoint:newer.snapshot.checkpoint}),/rollback/);
 await h.restart();assert.equal((await h.api(f.path+'/review-context')).body.decisions.length,2);
});

test('보고서는 이벤트·사건·판단·평가의 변조된 조회 복사본을 서명하지 않는다',async t=>{
 const h=await harness();t.after(()=>h.close());const f=await fixture(h);
 const context=(await h.api(f.path+'/review-context')).body;
 const saved=(await h.api(f.path+'/decisions',{body:decision(context.contextHash,f.ref)})).body;
 const db=new DatabaseSync(join(h.dir,'data','evidence.db'));t.after(()=>db.close());
 const targets=[
  {table:'events',where:'tenant=? AND source=? AND id=?',args:['alpha',h.principal('tool').id,'result'],change:v=>({...v,status:'success'})},
  {table:'objects',where:'tenant=? AND type=? AND id=?',args:['alpha','case',f.case.id],change:v=>({...v,title:'forged case'})},
  {table:'evaluations',where:'tenant=? AND action_id=?',args:['alpha',f.base.actionId],change:v=>({...v,findings:[]})},
 ];
 const decisionRow=db.prepare('SELECT type FROM objects WHERE tenant=? AND id=?').get('alpha',saved.id);assert.ok(decisionRow);
 targets.push({table:'objects',where:'tenant=? AND type=? AND id=?',args:['alpha',decisionRow.type,saved.id],change:v=>({...v,reason:'forged decision'})});
 for(const item of targets){const original=db.prepare(`SELECT body FROM ${item.table} WHERE ${item.where}`).get(...item.args).body;db.prepare(`UPDATE ${item.table} SET body=? WHERE ${item.where}`).run(JSON.stringify(item.change(JSON.parse(original))),...item.args);try{const r=await h.api(f.path+'/report');assert.notEqual(r.status,200,`${item.table} corruption must not be signed`);}finally{db.prepare(`UPDATE ${item.table} SET body=? WHERE ${item.where}`).run(original,...item.args);}}
 assert.equal((await h.api(f.path+'/report')).status,200);
});

test('검토 기한 만료와 정당한 원문 파기는 과거 판단을 보존하며 재검토로 표시',async t=>{
 const h=await harness();t.after(()=>h.close());
 assert.equal((await h.api('/api/retention/policy',{role:'reviewer',body:{retentionSeconds:1,purpose:'합성 검토와 보존 연계 시험',reason:'실제 개인정보 없는 시험'}})).status,200);
 const f=await fixture(h);let context=(await h.api(f.path+'/review-context')).body;
 assert.equal((await h.api(f.path+'/decisions',{body:decision(context.contextHash,f.ref,{nextReviewAt:new Date(Date.now()+500).toISOString()})})).status,200);
 assert.equal((await h.api(f.path+'/review-context')).body.reviewState,'reviewed');
 await new Promise(resolve=>setTimeout(resolve,600));context=(await h.api(f.path+'/review-context')).body;assert.equal(context.reviewState,'stale');
 assert.equal((await h.api(f.path+'/decisions',{body:decision(context.contextHash,f.ref)})).status,200);
 await h.api(f.path,{body:{status:'closed',reason:'합성 보존 연계 시험을 위한 사건 종결'}});
 await new Promise(resolve=>setTimeout(resolve,600));
 const plan=(await h.api('/api/retention/plans',{role:'reviewer',body:{reason:'합성 원문 만료'}})).body;assert.ok(plan.id);
 assert.equal((await h.api(`/api/retention/plans/${plan.id}/approve`,{role:'admin',body:{reason:'다른 검토자가 범위 확인'}})).status,200);
 assert.equal((await h.api(`/api/retention/plans/${plan.id}/execute`,{role:'admin',body:{}})).status,200);
 context=(await h.api(f.path+'/review-context')).body;assert.equal(context.events.length,0);assert.equal(context.decisions.length,2);assert.equal(context.reviewState,'stale');
 const report=await h.api(f.path+'/report');assert.equal(report.status,200);assert.equal(verifyCaseReport(report.body,h.publicKey).reviewState,'stale');assert.equal(report.body.snapshot.action.events.length,0);
});
