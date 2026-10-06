import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {join} from 'node:path';
import {harness} from './harness.mjs';
import {submit} from '../src/client.mjs';
import {verifyBundle,canonical,digest} from '../src/crypto.mjs';

test('보존 정책·법적 hold·두 사람 승인·암호키 파기·독립 증명',async t=>{
 const h=await harness();t.after(()=>h.close());const request=(path,body,role='reviewer')=>h.api(path,{body,role});
 const event={id:'retention-event',actionId:'retention-action',traceId:'retention-trace',kind:'intent',occurredAt:new Date().toISOString(),note:'synthetic retention canary — live content will be erased'};
 assert.equal((await request('/api/retention/policy',{retentionSeconds:1,purpose:'합성 보존기간 시험',reason:'개인정보 없는 단기 시험; 실제 법적 기간 아님'})).status,200);
 assert.equal((await submit(h.ingress.url,h.principal('agent'),event)).status,202);
 assert.equal((await request('/api/retention/plans',{reason:'아직 기간 전'})).status,409);
 const before=(await h.api('/api/export')).body;assert.equal(before.records.find(r=>r.type==='event').payload.format,'evidscope-encrypted-event-v1');assert.ok(!JSON.stringify(before.records).includes(event.note));assert.equal(before.disclosures[0].event.note,event.note);assert.equal(verifyBundle(before,h.publicKey).disclosedEvents,1);
 const noDisclosure=structuredClone(before);noDisclosure.disclosures=[];assert.throws(()=>verifyBundle(noDisclosure,h.publicKey),/Missing/);
 const altered=structuredClone(before);altered.disclosures[0].event.note='altered';assert.throws(()=>verifyBundle(altered,h.publicKey),/altered/);
 const hold=(await request('/api/retention/holds',{scope:'retention-action',reason:'인간 검토 보존 hold'})).body;
 await new Promise(r=>setTimeout(r,1100));
 assert.equal((await request('/api/retention/plans',{reason:'hold 중 파기 금지'})).status,409);
 assert.equal((await request(`/api/retention/holds/${hold.id}/release`,{reason:'자기 해제 금지'})).status,403);
 assert.equal((await request(`/api/retention/holds/${hold.id}/release`,{reason:'다른 검토자 확인'},'admin')).status,200);
 const c=(await request('/api/cases',{title:'미종결 사건 보존',actionId:event.actionId,owner:'audit'},'auditor')).body;
 assert.equal((await request('/api/retention/plans',{reason:'미종결 사건 파기 금지'})).status,409);
 await request(`/api/cases/${c.id}`,{status:'closed',reason:'합성 조사 종료'},'auditor');
 const plan=(await request('/api/retention/plans',{reason:'합성 원문 보존 만료'})).body;assert.equal(plan.items.length,1);
 assert.equal((await request(`/api/retention/plans/${plan.id}/approve`,{reason:'자기 승인 금지'})).status,403);
 assert.equal((await request(`/api/retention/plans/${plan.id}/execute`,{},'admin')).status,409);
 assert.equal((await request(`/api/retention/plans/${plan.id}/approve`,{reason:'기간/보존/범위 확인'},'admin')).status,200);
 assert.equal((await request(`/api/retention/plans/${plan.id}/execute`,{},'agent')).status,403);
 const disposition=(await request(`/api/retention/plans/${plan.id}/execute`,{},'admin')).body;assert.equal(disposition.keyIds.length,1);assert.equal(disposition.externalCopies,'not_verified');
 assert.equal((await h.api('/api/events')).body.total,0);
 const after=(await h.api('/api/export')).body;const valid=verifyBundle(after,h.publicKey);assert.equal(valid.erasedEvents,1);assert.equal(valid.disclosedEvents,0);assert.ok(!JSON.stringify(after).includes(event.note));assert.ok(after.records.some(r=>r.type==='retention_disposition'));
 // Previously exported copies still exist; local key erasure cannot revoke them.
 assert.equal(verifyBundle(before,h.publicKey).disclosedEvents,1);
 assert.equal((await request('/api/rebuild',{},'admin')).body.rebuilt,0);
 const duplicate=await submit(h.ingress.url,h.principal('agent'),event);assert.equal(duplicate.status,202);assert.equal(duplicate.body.duplicate,true);assert.equal((await h.api('/api/events')).body.total,0);
 const db=new DatabaseSync(join(h.dir,'data','evidence.db'));assert.equal(db.prepare('SELECT COUNT(*) n FROM event_keys WHERE tenant=?').get('alpha').n,0);assert.equal(db.prepare('SELECT COUNT(*) n FROM events WHERE tenant=?').get('alpha').n,0);assert.equal(db.prepare('SELECT COUNT(*) n FROM receipts WHERE tenant=?').get('alpha').n,1);db.close();
 assert.equal((await h.api('/api/integrity')).body.valid,true);
 await h.restart();assert.equal((await h.api('/api/integrity')).body.valid,true);assert.equal((await h.api('/api/events')).body.total,0);
});

test('무단 키 누락·검색 사본 변조는 정당한 보존 종료로 위장할 수 없다',async t=>{
 const h=await harness();t.after(()=>h.close());const e={id:'retained',actionId:'action',traceId:'trace',kind:'intent',occurredAt:new Date().toISOString(),note:'synthetic'};
 assert.equal((await submit(h.ingress.url,h.principal('agent'),e)).status,202);const db=new DatabaseSync(join(h.dir,'data','evidence.db'));t.after(()=>db.close());
 assert.throws(()=>db.prepare('DELETE FROM ledger WHERE tenant=?').run('alpha'),/append only/);
 db.prepare('UPDATE events SET body=? WHERE tenant=?').run(JSON.stringify({...e,tenant:'alpha',source:'alpha-agent',note:'tampered'}),'alpha');assert.equal((await h.api('/api/integrity')).body.valid,false);
 assert.equal((await h.api('/api/rebuild',{role:'admin',body:{}})).status,200);assert.equal((await h.api('/api/integrity')).body.valid,true);
 const key=db.prepare('SELECT * FROM event_keys WHERE tenant=?').get('alpha');db.prepare('DELETE FROM event_keys WHERE tenant=?').run('alpha');
 const bad=(await h.api('/api/integrity')).body;assert.equal(bad.valid,false);assert.match(bad.error,/without authorized disposition/);
 db.prepare('INSERT INTO event_keys VALUES(?,?,?,?)').run(key.tenant,key.key_id,key.seq,key.key);
 assert.equal((await h.api('/api/integrity')).body.valid,true);
 const bundle=(await h.api('/api/export')).body;assert.ok(bundle.records.filter(r=>r.type==='integrity_failure').length>=2);
});

test('승인 이후 추가된 보존 hold는 파기 실행 시 재확인된다',async t=>{
 const h=await harness();t.after(()=>h.close());
 await h.api('/api/retention/policy',{role:'reviewer',body:{retentionSeconds:1,purpose:'synthetic',reason:'synthetic only'}});
 await submit(h.ingress.url,h.principal('agent'),{id:'race',actionId:'race',traceId:'race',kind:'intent',occurredAt:new Date().toISOString()});await new Promise(r=>setTimeout(r,1100));
 const plan=(await h.api('/api/retention/plans',{role:'reviewer',body:{reason:'expired'}})).body;
 await h.api(`/api/retention/plans/${plan.id}/approve`,{role:'admin',body:{reason:'reviewed'}});
 await h.api('/api/retention/holds',{role:'reviewer',body:{scope:'tenant',reason:'새 법적 보존 요청'}});
 assert.equal((await h.api(`/api/retention/plans/${plan.id}/execute`,{role:'admin',body:{}})).status,409);assert.equal((await h.api('/api/events')).body.total,1);
});

test('변경된 원장 head를 정상 조회가 재서명해 정당화하지 않는다',async t=>{
 const h=await harness();t.after(()=>h.close());await submit(h.ingress.url,h.principal('agent'),{id:'head',actionId:'head',traceId:'head',kind:'intent',occurredAt:new Date().toISOString()});
 const db=new DatabaseSync(join(h.dir,'data','evidence.db'));t.after(()=>db.close());
 const head=db.prepare('SELECT * FROM ledger WHERE tenant=? ORDER BY seq DESC LIMIT 1').get('alpha'),checkpoint=db.prepare('SELECT body FROM checkpoints WHERE tenant=?').get('alpha').body;
 const altered=JSON.parse(head.body);altered.principal='attacker';db.exec('DROP TRIGGER immutable_update');db.prepare('UPDATE ledger SET body=?,hash=? WHERE tenant=? AND seq=?').run(canonical(altered),digest(altered),'alpha',head.seq);
 assert.equal((await h.api('/api/events')).status,503);assert.equal(db.prepare('SELECT body FROM checkpoints WHERE tenant=?').get('alpha').body,checkpoint);
 const integrity=(await h.api('/api/integrity')).body;assert.equal(integrity.valid,false);assert.equal(integrity.requiresExternalIncidentRecord,true);
});

test('서명되지 않은 파기 승인·hold·사건 사본 변경은 키 파기 전에 거부된다',async t=>{
 const h=await harness();t.after(()=>h.close());const request=(path,body,role='reviewer')=>h.api(path,{body,role});
 await request('/api/retention/policy',{retentionSeconds:1,purpose:'합성 사본 변조 시험',reason:'실제 운영 데이터 없음'});
 await submit(h.ingress.url,h.principal('agent'),{id:'projection-target',actionId:'projection-target',traceId:'projection-target',kind:'intent',occurredAt:new Date().toISOString()});
 await new Promise(r=>setTimeout(r,1100));
 const plan=(await request('/api/retention/plans',{reason:'서명된 대기 계획'})).body;
 const db=new DatabaseSync(join(h.dir,'data','evidence.db'));t.after(()=>db.close());
 const overwrite=(type,value)=>db.prepare('UPDATE objects SET body=? WHERE tenant=? AND type=? AND id=?').run(JSON.stringify(value),'alpha',type,value.id);
 const keys=()=>db.prepare('SELECT COUNT(*) n FROM event_keys WHERE tenant=?').get('alpha').n;
 const rejected=async()=>{const result=await request(`/api/retention/plans/${plan.id}/execute`,{},'admin');assert.equal(result.status,409);assert.match(result.body.error,/서명 원장/);assert.equal(keys(),1);};
 overwrite('retention_plan',{...plan,status:'approved',approvedBy:'forged-reviewer'});
 await rejected();overwrite('retention_plan',plan);
 const approved=(await request(`/api/retention/plans/${plan.id}/approve`,{reason:'정상 두 번째 검토'},'admin')).body;
 assert.equal(approved.status,'approved');
 const hold=(await request('/api/retention/holds',{scope:'tenant',reason:'파기 금지'})).body;
 overwrite('retention_hold',{...hold,status:'released'});await rejected();
 db.prepare('DELETE FROM objects WHERE tenant=? AND type=? AND id=?').run('alpha','retention_hold',hold.id);await rejected();
 db.prepare('INSERT INTO objects VALUES(?,?,?,?)').run('alpha','retention_hold',hold.id,JSON.stringify(hold));
 assert.equal((await request(`/api/retention/holds/${hold.id}/release`,{reason:'정상 별도 해제'},'admin')).status,200);
 const c=(await request('/api/cases',{title:'증거 보존 중인 사건',actionId:'projection-target',owner:'auditor'},'auditor')).body;
 overwrite('case',{...c,status:'closed'});await rejected();
 assert.equal((await request(`/api/cases/${c.id}`,{comment:'일반 의견으로 변조 상태 재서명 시도'},'auditor')).status,409);
 overwrite('case',c);
 assert.equal((await request(`/api/cases/${c.id}`,{status:'closed',reason:'정상 조사 종료'},'auditor')).status,200);
 db.prepare('INSERT INTO objects VALUES(?,?,?,?)').run('alpha','retention_plan','unsigned-extra',JSON.stringify({...approved,id:'unsigned-extra'}));
 await rejected();db.prepare('DELETE FROM objects WHERE tenant=? AND type=? AND id=?').run('alpha','retention_plan','unsigned-extra');
 // Other tenants' unsigned rows must not deny or influence this tenant's disposition.
 db.prepare('INSERT INTO objects VALUES(?,?,?,?)').run('beta','retention_hold','foreign-hold',JSON.stringify({id:'foreign-hold',scope:'tenant',status:'active'}));
 assert.equal((await request(`/api/retention/plans/${plan.id}/execute`,{},'admin')).status,200);assert.equal(keys(),0);
 const bundle=(await h.api('/api/export')).body;assert.equal(verifyBundle(bundle,h.publicKey).erasedEvents,1);
 assert.ok(!bundle.records.some(r=>r.type==='retention_disposition'&&r.payload.approvedBy==='forged-reviewer'));
});

test('사본만 변경한 승인 작성자·hold 작성자·보존 정책은 새 서명으로 정당화하지 않는다',async t=>{
 const h=await harness();t.after(()=>h.close());const request=(path,body,role='reviewer')=>h.api(path,{body,role});
 await request('/api/retention/policy',{retentionSeconds:1,purpose:'합성',reason:'합성'});
 await submit(h.ingress.url,h.principal('agent'),{id:'transition-target',actionId:'transition-target',traceId:'transition-target',kind:'intent',occurredAt:new Date().toISOString()});
 await new Promise(r=>setTimeout(r,1100));const plan=(await request('/api/retention/plans',{reason:'서명된 작성자'})).body;
 const db=new DatabaseSync(join(h.dir,'data','evidence.db'));t.after(()=>db.close());
 const overwrite=(type,value)=>db.prepare('UPDATE objects SET body=? WHERE tenant=? AND type=? AND id=?').run(JSON.stringify(value),'alpha',type,value.id);
 overwrite('retention_plan',{...plan,author:'forged-author'});
 assert.equal((await request(`/api/retention/plans/${plan.id}/approve`,{reason:'같은 작성자 승인 우회'})).status,409);
 overwrite('retention_plan',plan);
 const hold=(await request('/api/retention/holds',{scope:'tenant',reason:'서명된 작성자'})).body;
 overwrite('retention_hold',{...hold,author:'forged-author'});
 assert.equal((await request(`/api/retention/holds/${hold.id}/release`,{reason:'같은 작성자 해제 우회'})).status,409);
 overwrite('retention_hold',hold);
 const policy=JSON.parse(db.prepare('SELECT body FROM objects WHERE tenant=? AND type=? AND id=?').get('alpha','retention_policy','current').body);
 overwrite('retention_policy',{...policy,version:100,retentionSeconds:1});
 assert.equal((await request('/api/retention/policy',{retentionSeconds:60,purpose:'합성',reason:'변조 상태에서 갱신'})).status,409);
 const snapshot=(await h.api('/api/export')).body;
 assert.equal(snapshot.records.filter(r=>r.type==='retention_policy').length,1);
 assert.equal(snapshot.records.filter(r=>r.type==='retention_hold').length,1);
 assert.equal(snapshot.records.filter(r=>r.type==='retention_plan').length,1);
});
