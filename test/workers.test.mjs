import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,randomBytes,createCipheriv} from 'node:crypto';
import {mkdirSync,mkdtempSync} from 'node:fs';
import {resolve} from 'node:path';
import {Store} from '../src/store.mjs';
import {createAnalysis,analysisLimits} from '../src/analysis.mjs';
import {evaluateJob,tick} from '../src/worker.mjs';
import {harness} from './harness.mjs';
import {submit} from '../src/client.mjs';
import {canonical,digest,makeCheckpoint} from '../src/crypto.mjs';

function fixture(t){
 mkdirSync('.test-runs',{recursive:true});const dir=mkdtempSync(resolve('.test-runs','worker-'));
 const key=generateKeyPairSync('ed25519').privateKey,store=new Store(dir,key);t.after(()=>store.close());
 // Compatibility fixture while Store's ledger accessors land in the same change.
 store.ledgerEvents??=((tenant,actionId)=>store.bundle(tenant).records.filter(r=>r.type==='event'&&r.payload.actionId===actionId).map(r=>({...r.payload,seq:r.seq,hash:r.hash})));
 store.ledgerObjects??=((tenant,type)=>[...new Map(store.bundle(tenant).records.filter(r=>r.type===type).map(r=>[r.payload.id,r.payload])).values()]);
 const principals=[{id:'worker-one',tenant:'internal',role:'worker'},{id:'worker-two',tenant:'internal',role:'worker'},{id:'source',tenant:'alpha',role:'source'}],p=principals[0];
 const analysis=createAnalysis(store,principals);
 function event(actionId='action',id='event',extra={}){return store.transaction(()=>{
  const e={id,actionId,traceId:'trace',tenant:'alpha',source:'tool-source',sourceKind:'tool',kind:'result',status:'success',occurredAt:new Date().toISOString(),receivedAt:new Date().toISOString(),fingerprint:id,...extra};
  const record=store.append('alpha','event',e,e.source);store.project({...e,seq:record.seq,hash:record.hash});store.db.prepare('INSERT INTO actions(tenant,id,version) VALUES(?,?,1) ON CONFLICT(tenant,id) DO UPDATE SET version=version+1').run('alpha',actionId);return e;
 });}
 return {store,analysis,p,principals,event,dir,key};
}

test('worker leases distribute disjoint jobs and commit deterministic output once',t=>{
 const f=fixture(t);for(let i=0;i<8;i++)f.event(`action-${i}`,`event-${i}`);
 const a=f.analysis.claim(f.p),b=f.analysis.claim(f.principals[1]);assert.equal(a.jobs.length,5);assert.equal(b.jobs.length,3);
 assert.equal(new Set([...a.jobs,...b.jobs].map(j=>j.actionId)).size,8);
 const job=a.jobs[0],result=evaluateJob(job),completed=f.analysis.commit(f.p,{leaseId:job.leaseId,result});assert.equal(completed.duplicate,false);
 assert.equal(f.analysis.commit(f.p,{leaseId:job.leaseId,result}).duplicate,true);assert.equal(f.store.evaluations('alpha',job.actionId).length,1);
 assert.throws(()=>f.analysis.commit(f.p,{leaseId:job.leaseId,result:{...result,effect:'unconfirmed'}}),e=>e.status===409);
 assert.equal(f.store.evaluations('alpha',job.actionId)[0].worker,f.p.id);
 const lease=f.store.db.prepare('SELECT * FROM analysis_leases WHERE id=?').get(job.leaseId);assert.ok(!JSON.stringify(lease).includes('tool-source'));
});
test('worker identity, evidence references and tenant/action override cannot be supplied by caller',t=>{
 const f=fixture(t);f.event();const job=f.analysis.claim(f.p).jobs[0],result=evaluateJob(job);
 assert.throws(()=>f.analysis.claim(f.principals[2]),e=>e.status===403);
 assert.throws(()=>f.analysis.commit(f.principals[1],{leaseId:job.leaseId,result}),e=>e.status===403);
 assert.throws(()=>f.analysis.commit(f.p,{leaseId:job.leaseId,result,tenant:'beta'}),e=>e.status===400);
 assert.throws(()=>f.analysis.commit(f.p,{leaseId:job.leaseId,result:{...result,actionId:'other'}}),e=>e.status===400);
 const altered=structuredClone(result);altered.findings[0].evidence=['outside-tenant/event'];assert.throws(()=>f.analysis.commit(f.p,{leaseId:job.leaseId,result:altered}),e=>e.status===400);
 assert.equal(f.store.evaluations('alpha','action').length,0);
});
test('second vault connection observes durable leases and completed results',t=>{
 const f=fixture(t);f.event();const secondStore=new Store(f.dir,f.key);t.after(()=>secondStore.close());
 const second=createAnalysis(secondStore,f.principals),job=f.analysis.claim(f.p).jobs[0];
 assert.equal(second.claim(f.principals[1]).jobs.length,0);
 const result=evaluateJob(job);second.commit(f.p,{leaseId:job.leaseId,result});
 assert.equal(f.analysis.commit(f.p,{leaseId:job.leaseId,result}).duplicate,true);assert.equal(f.store.evaluations('alpha','action').length,1);
});
test('late evidence invalidates old results and expired leases recover after worker restart',t=>{
 const f=fixture(t);f.event();const old=f.analysis.claim(f.p).jobs[0];f.event('action','late');
 assert.throws(()=>f.analysis.commit(f.p,{leaseId:old.leaseId,result:evaluateJob(old)}),e=>e.status===409);
 const second=f.analysis.claim(f.principals[1]).jobs[0];assert.equal(second.version,2);
 f.store.db.prepare('UPDATE analysis_leases SET expires=0 WHERE id=?').run(second.leaseId);
 const restarted=createAnalysis(f.store,f.principals),third=restarted.claim(f.p).jobs[0];assert.notEqual(third.leaseId,second.leaseId);
 assert.throws(()=>restarted.commit(f.principals[1],{leaseId:second.leaseId,result:evaluateJob(second)}),e=>e.status===409);
 restarted.commit(f.p,{leaseId:third.leaseId,result:evaluateJob(third)});assert.equal(f.store.evaluations('alpha','action').length,1);assert.equal(f.store.evaluations('alpha','action')[0].version,2);
});
test('query projection edits cannot alter worker source evidence or policy snapshot',t=>{
 const f=fixture(t);f.event();f.store.transaction(()=>f.store.put({id:'reviewer',tenant:'alpha'},'asset','asset',{id:'asset',actor:'actor',tool:'tool'}));
 f.store.db.prepare("UPDATE events SET body='{}' WHERE tenant='alpha'").run();f.store.db.prepare("UPDATE objects SET body='{}' WHERE tenant='alpha' AND type='asset'").run();
 const job=f.analysis.claim(f.p).jobs[0];assert.equal(job.events[0].id,'event');assert.equal(job.assets[0].id,'asset');f.analysis.commit(f.p,{leaseId:job.leaseId,result:evaluateJob(job)});
});
test('evaluation, checkpoint, action version and lease completion roll back atomically on persistence failure',t=>{
 const f=fixture(t);f.event();const job=f.analysis.claim(f.p).jobs[0],result=evaluateJob(job);
 const checkpoint=f.store.db.prepare('SELECT body FROM checkpoints WHERE tenant=?').get('alpha').body;
 f.store.db.exec("CREATE TRIGGER test_fail_evaluation BEFORE INSERT ON evaluations BEGIN SELECT RAISE(ABORT,'synthetic persistence fault'); END;");
 assert.throws(()=>f.analysis.commit(f.p,{leaseId:job.leaseId,result}),/synthetic persistence fault/);
 assert.equal(f.store.db.prepare('SELECT body FROM checkpoints WHERE tenant=?').get('alpha').body,checkpoint);
 assert.equal(f.store.db.prepare('SELECT state FROM analysis_leases WHERE id=?').get(job.leaseId).state,'leased');
 assert.equal(f.store.db.prepare('SELECT analyzed FROM actions WHERE tenant=? AND id=?').get('alpha','action').analyzed,0);
 f.store.db.exec('DROP TRIGGER test_fail_evaluation');f.analysis.commit(f.p,{leaseId:job.leaseId,result});assert.equal(f.store.evaluations('alpha','action').length,1);
});
test('findings are bounded with explicit total coverage, never reported as full analysis',t=>{
 const f=fixture(t);for(let i=0;i<60;i++)f.event('action',`event-${i}`);
 const job=f.analysis.claim(f.p).jobs[0],result=evaluateJob(job);assert.equal(result.findings.length,100);assert.equal(result.coverage.totalFindings,120);assert.equal(result.coverage.truncated,true);
 f.analysis.commit(f.p,{leaseId:job.leaseId,result});assert.equal(f.store.evaluations('alpha','action')[0].coverage.totalFindings,120);
});
test('oversized action quarantines explicitly and stays unanalyzed without looping duplicate evaluations',t=>{
 const f=fixture(t);for(let i=0;i<=analysisLimits.events;i++)f.event('oversized',`event-${i}`);
 const claim=f.analysis.claim(f.p);assert.equal(claim.jobs.length,0);assert.equal(claim.backlog,1);assert.equal(claim.coverage.quarantinedActions,1);
 assert.equal(f.store.evaluations('alpha','oversized')[0].status,'quarantined_resource_limit');assert.equal(f.store.evaluations('alpha','oversized')[0].coverage.evaluated,false);
 f.analysis.claim(f.p);assert.equal(f.store.evaluations('alpha','oversized').length,1);
});
test('analysis snapshot streams original ledger without bundle arrays and preserves historical asset policies',t=>{
 const f=fixture(t);for(let i=0;i<30;i++)f.event(`other-${i}`,`other-${i}`);f.event('target','target');
 f.store.transaction(()=>{for(let version=1;version<=3;version++)f.store.put({id:'reviewer',tenant:'alpha'},'asset','asset',{id:'asset',version});});
 for(const name of ['rawBundle','bundle','ledgerEvents','ledgerObjects','events','list'])f.store[name]=()=>{throw Error('unbounded path used');};
 const snapshot=f.store.verifiedAnalysisSnapshot('alpha','target',analysisLimits);assert.equal(snapshot.events.length,1);assert.equal(snapshot.events[0].id,'target');assert.deepEqual(snapshot.assets.map(a=>a.version),[1,2,3]);
 assert.equal(f.analysis.claim(f.p).jobs.length,5);
});
test('oversized individual ledger rows are quarantined before parsing while checkpoint completeness remains mandatory',t=>{
 const f=fixture(t);f.event();f.store.transaction(()=>f.store.append('alpha','large-test',{note:'x'.repeat(15000)},'tester'));
 const limits={...analysisLimits,snapshotBytes:12000},snapshot=f.store.verifiedAnalysisSnapshot('alpha','action',limits);
 assert.ok(snapshot.resourceLimit.reasons.includes('ledgerRowBytes'));assert.equal(snapshot.resourceLimit.observedEventsComplete,false);assert.equal(snapshot.events,undefined);
 f.store.db.exec('DROP TRIGGER immutable_delete');f.store.db.prepare('DELETE FROM ledger WHERE tenant=? AND seq=2').run('alpha');
 assert.throws(()=>f.store.verifiedAnalysisSnapshot('alpha','action',limits),/Truncated/);
});
test('streaming snapshot distinguishes authorized erasure, missing keys and illegally retained erased keys',t=>{
 const f=fixture(t);f.event();const key=f.store.db.prepare('SELECT * FROM event_keys WHERE tenant=?').get('alpha');
 f.store.db.prepare('DELETE FROM event_keys WHERE tenant=?').run('alpha');assert.throws(()=>f.store.verifiedAnalysisSnapshot('alpha','action',analysisLimits),/without authorized disposition/);
 f.store.transaction(()=>f.store.append('alpha','retention_disposition',{keyIds:[key.key_id]},'admin'));
 assert.equal(f.store.verifiedAnalysisSnapshot('alpha','action',analysisLimits).events.length,0);
 f.store.db.prepare('INSERT INTO event_keys VALUES(?,?,?,?)').run(key.tenant,key.key_id,key.seq,key.key);
 assert.throws(()=>f.store.verifiedAnalysisSnapshot('alpha','action',analysisLimits),/unexpectedly retained/);
});
test('encrypted records without the new action header remain readable through bounded streaming',t=>{
 const f=fixture(t),event={id:'legacy',tenant:'alpha',source:'legacy-source',actionId:'legacy-action',receivedAt:new Date().toISOString()};
 const key=randomBytes(32),iv=randomBytes(12),header={format:'evidscope-encrypted-event-v1',keyId:'legacy-key',tenant:'alpha',seq:1,policyVersion:0,retainUntil:'2030-01-01T00:00:00.000Z'};
 const cipher=createCipheriv('aes-256-gcm',key,iv);cipher.setAAD(Buffer.from(canonical(header)));const plaintext=canonical(event),ciphertext=Buffer.concat([cipher.update(plaintext,'utf8'),cipher.final()]);
 const payload={...header,iv:iv.toString('base64'),ciphertext:ciphertext.toString('base64'),tag:cipher.getAuthTag().toString('base64'),payloadHash:digest(plaintext)};
 const row={tenant:'alpha',seq:1,previous:'0'.repeat(64),type:'event',recordedAt:new Date().toISOString(),principal:'legacy-source',payload},hash=digest(row);
 f.store.transaction(()=>{f.store.db.prepare('INSERT INTO ledger VALUES(?,?,?,?)').run('alpha',1,canonical(row),hash);f.store.db.prepare('INSERT INTO checkpoints VALUES(?,?)').run('alpha',JSON.stringify(makeCheckpoint('alpha',1,hash,f.key)));f.store.db.prepare('INSERT INTO event_keys VALUES(?,?,?,?)').run('alpha','legacy-key',1,key);});
 const snapshot=f.store.verifiedAnalysisSnapshot('alpha','legacy-action',analysisLimits);assert.equal(snapshot.events[0].id,'legacy');assert.equal(f.store.verifiedAnalysisSnapshot('alpha','different-action',analysisLimits).events.length,0);
});
test('worker HTTP claim/complete runs computation in client and denies source and audit boundary access',async t=>{
 const h=await harness();t.after(()=>h.close());
 const event={id:'distributed-event',actionId:'distributed-action',traceId:'distributed-trace',kind:'result',status:'success',occurredAt:new Date().toISOString()};
 assert.equal((await submit(h.ingress.url,h.principal('tool'),event)).status,202);
 const token=h.config.principals.find(p=>p.role==='worker').token;
 assert.equal((await h.api('/internal/claim',{base:h.vault.url,role:'tool',body:{}})).status,403);
 assert.equal((await h.api('/internal/claim',{body:{},headers:{authorization:`Bearer ${token}`}})).status,403);
 const outcome=await tick(h.vault.url,token);assert.equal(outcome.processed,1);assert.equal(outcome.backlog,0);
 const action=(await h.api('/api/actions/distributed-action')).body;assert.equal(action.evaluations[0].status,'evaluated');assert.equal(action.evaluations[0].coverage.truncated,false);
});
