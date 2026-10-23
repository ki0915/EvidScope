import test from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash,generateKeyPairSync,randomUUID} from 'node:crypto';
import {readFileSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {tempDir} from './temp-dir.mjs';
import {harness} from './harness.mjs';
import {submit} from '../src/client.mjs';
import {createService} from '../src/service.mjs';
import {canonical,digest,mac,makeCheckpoint,verifyBundle} from '../src/crypto.mjs';
import {evaluateJob} from '../src/worker.mjs';
import {replayEvaluations} from '../src/policy-replay.mjs';
import {checkRotationHistory,eventRotationClass,rotationClassProblem,verifyRotationHistory} from '../src/retention-rotation.mjs';
import {signRecoveryFrontier} from '../src/recovery-frontier.mjs';
import {AccessLog,verifyAccessBatches} from '../src/access-log.mjs';
import {DatabaseSync} from 'node:sqlite';

const token=s=>s.repeat(40).slice(0,40);
const principals=[{id:'reviewer',role:'reviewer',tenant:'alpha',token:token('r1')},{id:'reviewer-2',role:'reviewer',tenant:'alpha',token:token('r2')},
 {id:'admin',role:'admin',tenant:'alpha',token:token('a1')},{id:'admin-2',role:'admin',tenant:'alpha',token:token('a2')},
 {id:'auditor',role:'auditor',tenant:'alpha',token:token('au')},
 {id:'agent',role:'source',kind:'agent',tenant:'alpha',token:token('sa'),hmacSecret:token('ha')},
 {id:'telemetry',role:'source',kind:'telemetry',tenant:'alpha',token:token('st'),hmacSecret:token('ht')},
 {id:'safety',role:'source',kind:'safety',tenant:'alpha',token:token('ss'),hmacSecret:token('hs')},
 {id:'beta-reviewer',role:'reviewer',tenant:'beta',token:token('br')},{id:'beta-admin',role:'admin',tenant:'beta',token:token('ba')},
 {id:'beta-agent',role:'source',kind:'agent',tenant:'beta',token:token('bs'),hmacSecret:token('bh')},
 {id:'worker',role:'worker',tenant:'internal',tenants:['alpha','beta'],token:token('wk')}];
const who=id=>principals.find(p=>p.id===id);
const ROUTINE=[{sourceKind:'agent',kind:'intent',sensitivity:'none',retentionSeconds:1},{sourceKind:'telemetry',kind:'*',sensitivity:'any',retentionSeconds:1}];
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));

function fixture(t,options={}){
 const dir=tempDir('evidscope-rotation-'),{privateKey}=generateKeyPairSync('ed25519');
 const service=createService({dataDir:dir,key:privateKey,config:{principals},...options}),store=service.store;
 t.after(()=>{service.retention.rotation.stop();service.accessLog.close();store.close();});
 const call=(path,body,id='reviewer')=>service.handle(body===undefined?'GET':'POST',new URL(path,'http://local'),
  {authorization:'Bearer '+who(id).token},body===undefined?'':JSON.stringify(body));
 const status=(path,body,id)=>call(path,body,id).then(()=>200,error=>error.status||error.message);
 async function ingest(source,event){
  const body=JSON.stringify({traceId:'trace',occurredAt:new Date().toISOString(),...event}),stamp=String(Date.now()),nonce=randomUUID(),p=who(source);
  const out=await service.handle('POST',new URL('/api/ingest','http://local'),{authorization:'Bearer '+p.token,'x-evid-timestamp':stamp,
   'x-evid-nonce':nonce,'x-evid-signature':mac(p.hmacSecret,stamp,nonce,body)},body);
  assert.equal(out.accepted,true);return out;
 }
 function analyze(){
  for(let round=0;round<20;round++){const {jobs}=service.analysis.claim(who('worker'));if(!jobs.length)return;
   for(const job of jobs)service.analysis.commit(who('worker'),{leaseId:job.leaseId,result:evaluateJob(JSON.parse(JSON.stringify(job)))});}
 }
 // Proposed by one reviewer, activated by a different administrator.
 async function activate(classes=ROUTINE,{proposer='reviewer',approver='admin',...terms}={}){
  const proposal=await call('/api/retention/rotation',{classes,purpose:'synthetic routine telemetry',reason:'synthetic only',...terms},proposer);
  return call(`/api/retention/rotation/${proposal.id}/approve`,{reason:'second person checked the classes'},approver);
 }
 const liveEvents=tenant=>store.db.prepare('SELECT id FROM events WHERE tenant=? ORDER BY id').all(tenant).map(row=>row.id);
 return {dir,service,store,call,status,ingest,analyze,activate,liveEvents,privateKey};
}
// Re-hash the chain and re-sign the checkpoint with the vault's own key: only the rotation checks can notice the change.
function resign(bundle,privateKey){
 let previous='0'.repeat(64);
 for(const row of bundle.records){row.previous=previous;const {hash,...record}=row;row.hash=digest(record);previous=row.hash;}
 bundle.checkpoint=makeCheckpoint(bundle.checkpoint.tenant,bundle.records.length,previous,privateKey);return bundle;
}
function verifyCli(bundle,publicKeyPem,extra=[]){
 const dir=tempDir('evidscope-rotation-cli-'),file=join(dir,'export.json'),key=join(dir,'trust-anchor.pub');
 writeFileSync(file,JSON.stringify(bundle));writeFileSync(key,publicKeyPem);
 try{
  const out=execFileSync(process.execPath,['scripts/verify.mjs',file,key,...extra],{encoding:'utf8',stdio:['ignore','pipe','pipe']});
  return {status:0,out:JSON.parse(out)};
 }
 catch(error){return {status:error.status,out:error.stdout?JSON.parse(error.stdout):null,stderr:error.stderr};}
}

test('critical classes are refused at policy time and one person cannot enable rotation',async t=>{
 const f=fixture(t);
 for(const c of [{sourceKind:'safety',kind:'stop_requested'},{sourceKind:'authority',kind:'*'},{sourceKind:'enforcement',kind:'policy_decision'},
  {sourceKind:'telemetry',kind:'gap'},{sourceKind:'telemetry',kind:'governance_check'}]){
  const error=await f.call('/api/retention/rotation',{classes:[{...c,retentionSeconds:86400}],purpose:'x',reason:'x'}).catch(e=>e);
  assert.equal(error.status,400);assert.match(error.message,/중요 기록/);
 }
 assert.equal(await f.status('/api/retention/rotation',{classes:[{sourceKind:'agent',kind:'stop_requested',retentionSeconds:1}],purpose:'x',reason:'x'}),400);
 assert.equal(await f.status('/api/retention/rotation',{classes:ROUTINE,purpose:'x',reason:'x',accessLogRetentionSeconds:86400}),400,'access log floor');
 assert.equal(await f.status('/api/retention/rotation',{classes:ROUTINE,purpose:'x',reason:'x'},'auditor'),403);
 const proposal=await f.call('/api/retention/rotation',{classes:ROUTINE,purpose:'x',reason:'x'});
 assert.equal(proposal.status,'proposed');
 assert.equal(await f.status(`/api/retention/rotation/${proposal.id}/approve`,{reason:'self'},'reviewer'),403,'the proposer cannot activate');
 assert.equal(await f.status(`/api/retention/rotation/${proposal.id}/approve`,{reason:'reviewer'},'reviewer-2'),403,'activation needs an administrator');
 const own=await f.call('/api/retention/rotation',{classes:ROUTINE,purpose:'x',reason:'x'},'admin');
 assert.equal(await f.status(`/api/retention/rotation/${own.id}/approve`,{reason:'self'},'admin'),403,'an administrator cannot activate their own proposal');
 const status=await f.call('/api/retention/rotation',undefined,'auditor');
 assert.equal(status.active,null);assert.equal(status.scheduler.enabled,false,'scheduler is off by default');assert.equal(status.scheduler.nextRunAt,null);
 assert.deepEqual(status.policies.map(p=>p.status),['proposed','proposed']);
 assert.equal(await f.status('/api/retention/rotation/run',{},'reviewer'),403);
 assert.equal((await f.call('/api/retention/rotation/run',{},'admin')).status,'no_active_policy');
 // The class of a stored event can only be routine or critical, never both.
 assert.equal(rotationClassProblem(eventRotationClass({sourceKind:'safety',kind:'safety_alert'}),{concrete:true})?.includes('critical'),true);
});

test('a routine class is erased on schedule; critical, held, open-case and sensitive events stay; replay and verification keep working',async t=>{
 const f=fixture(t,{retentionRotation:{intervalMs:400}});
 await f.call('/api/retention/policy',{retentionSeconds:1,purpose:'synthetic',reason:'synthetic only; not a legal period'});
 await f.ingest('agent',{id:'routine-intent',actionId:'a-routine',kind:'intent'});
 await f.ingest('telemetry',{id:'routine-heartbeat',actionId:'a-heartbeat',kind:'heartbeat'});
 await f.ingest('safety',{id:'critical-alert',actionId:'a-routine',kind:'safety_alert'});
 await f.ingest('agent',{id:'held-intent',actionId:'a-held',kind:'intent'});
 await f.ingest('agent',{id:'case-intent',actionId:'a-case',kind:'intent'});
 await f.ingest('agent',{id:'sensitive-intent',actionId:'a-sensitive',kind:'intent',dataCategories:['health']});
 await f.ingest('agent',{id:'self-report',actionId:'a-other',kind:'self_report',status:'success'});
 f.analyze();
 await f.call('/api/retention/holds',{scope:'a-held',reason:'legal hold'});
 await f.call('/api/cases',{title:'open case',actionId:'a-case',owner:'audit'},'auditor');
 const active=await f.activate();
 assert.equal(active.status,'active');assert.equal(active.approvedBy,'admin');assert.equal(active.proposedBy,'reviewer');
 assert.equal((await f.call('/api/retention/rotation/run',{},'admin')).status,'nothing_due','nothing is older than its period yet');
 f.service.retention.rotation.start();
 assert.ok((await f.call('/api/retention/rotation',undefined,'auditor')).scheduler.nextRunAt);
 let status;
 for(let i=0;i<40&&!status?.rotatedEvents;i++){await sleep(200);status=await f.call('/api/retention/rotation',undefined,'auditor');}
 assert.ok(['erased','nothing_due'].includes(status.scheduler.lastRun?.status),JSON.stringify(status.scheduler));
 assert.deepEqual(status.erasedByClass,{'agent/intent/none':1,'telemetry/heartbeat/none':1});
 assert.equal(status.lastDisposition.erased,2);assert.equal(status.rotatedEvents,2);
 assert.deepEqual(f.liveEvents('alpha'),['case-intent','critical-alert','held-intent','self-report','sensitive-intent']);
 // The chain is never truncated: the envelopes, hashes and receipts of the erased events stay; only their keys went.
 const bundle=f.store.exportBundle('alpha');
 assert.equal(bundle.records.filter(r=>r.type==='event').length,7);
 const verified=verifyBundle(bundle,f.store.publicKey);assert.equal(verified.erasedEvents,2);assert.equal(verified.disclosedEvents,5);
 const history=verifyRotationHistory(bundle.records);assert.equal(history.valid,true);assert.equal(history.scheduledDispositions,1);
 const disposition=bundle.records.find(r=>r.type==='retention_disposition');
 assert.equal(disposition.principal,'retention-rotation');assert.equal(disposition.payload.approvedBy,'admin');
 assert.equal(disposition.payload.rotation.policyVersion,active.version);
 assert.ok(bundle.records.filter(r=>r.type==='event_receipt').length>=7);
 // Replay: evaluations whose inputs were rotated are not_replayable with their reason; the others still replay exactly.
 f.analyze();
 const replay=replayEvaluations(f.store.exportBundle('alpha'));
 assert.equal(replay.valid,true);assert.equal(replay.summary.mismatch,0);assert.ok(replay.summary.notReplayableReasons.erased_input>=2);
 assert.ok(replay.summary.replayed>=3);
 assert.equal((await f.call('/api/integrity',undefined,'auditor')).valid,true);
 const cli=verifyCli(f.store.exportBundle('alpha'),f.store.publicKey.export({format:'pem',type:'spki'}),['--replay']);
 assert.equal(cli.status,0,cli.stderr);assert.equal(cli.out.retentionRotation.valid,true);assert.equal(cli.out.retentionRotation.rotatedEvents,2);
 // Releasing the hold and closing the case lets a later run take those events; the critical one never goes.
 const hold=f.store.list('alpha','retention_hold')[0],kase=f.store.list('alpha','case')[0];
 await f.call(`/api/retention/holds/${hold.id}/release`,{reason:'released'},'admin');
 await f.call(`/api/cases/${kase.id}`,{status:'closed',reason:'done'},'admin');
 const second=await f.call('/api/retention/rotation/run',{},'admin');
 assert.equal(second.status,'erased');assert.equal(second.erased,2);
 assert.deepEqual(f.liveEvents('alpha'),['critical-alert','self-report','sensitive-intent']);
 assert.equal(verifyRotationHistory(f.store.exportBundle('alpha').records).valid,true);
});

test('tenant isolation, suspension and supersession: a run only ever uses its own tenant policy',async t=>{
 const f=fixture(t);
 for(const id of ['reviewer','beta-reviewer'])await f.call('/api/retention/policy',{retentionSeconds:1,purpose:'synthetic',reason:'synthetic'},id);
 await f.ingest('agent',{id:'alpha-1',actionId:'alpha-a',kind:'intent'});await f.ingest('beta-agent',{id:'beta-1',actionId:'beta-a',kind:'intent'});
 const first=await f.activate();
 await sleep(1100);
 assert.equal(await f.status(`/api/retention/rotation/${first.id}/approve`,{reason:'other tenant'},'beta-admin'),404);
 assert.equal((await f.call('/api/retention/rotation',undefined,'beta-reviewer')).active,null);
 const results=f.service.retention.rotation.runAll();
 assert.deepEqual(results.map(r=>[r.tenant,r.status]),[['alpha','erased']]);
 assert.deepEqual(f.liveEvents('alpha'),[]);assert.deepEqual(f.liveEvents('beta'),['beta-1']);
 assert.equal((await f.call('/api/retention/rotation/run',{},'beta-admin')).status,'no_active_policy');
 // One person may stop rotation at once; starting it again needs two people again.
 await f.ingest('agent',{id:'alpha-2',actionId:'alpha-b',kind:'intent'});await sleep(1100);
 assert.equal((await f.call(`/api/retention/rotation/${first.id}/suspend`,{reason:'pause'},'reviewer-2')).status,'suspended');
 assert.equal((await f.call('/api/retention/rotation/run',{},'admin')).status,'no_active_policy');
 assert.deepEqual(f.liveEvents('alpha'),['alpha-2']);
 const second=await f.activate([{sourceKind:'telemetry',kind:'heartbeat',sensitivity:'any',retentionSeconds:1}],{proposer:'reviewer-2',approver:'admin-2'});
 assert.equal((await f.call('/api/retention/rotation/run',{},'admin')).status,'nothing_due','agent intents are no longer routine');
 const third=await f.activate();
 const policies=new Map((await f.call('/api/retention/rotation',undefined,'auditor')).policies.map(p=>[p.id,p.status]));
 assert.equal(policies.get(second.id),'superseded');assert.equal(policies.get(third.id),'active');assert.equal(policies.get(first.id),'suspended');
 assert.equal((await f.call('/api/retention/rotation/run',{},'admin')).erased,1);
 const history=checkRotationHistory(f.store.exportBundle('alpha').records);
 assert.equal(history.active.id,third.id);assert.equal(history.scheduledDispositions,2);
});

test('the verifier refuses a critical class, a one-person activation or an early erasure forced into the ledger',async t=>{
 const f=fixture(t);
 await f.call('/api/retention/policy',{retentionSeconds:1,purpose:'synthetic',reason:'synthetic'});
 await f.ingest('agent',{id:'routine',actionId:'a-1',kind:'intent'});await f.ingest('safety',{id:'alert',actionId:'a-2',kind:'safety_alert'});
 await f.activate();await sleep(1100);
 assert.equal((await f.call('/api/retention/rotation/run',{},'admin')).erased,1);
 const good=f.store.exportBundle('alpha'),pem=f.store.publicKey.export({format:'pem',type:'spki'});
 assert.equal(verifyCli(good,pem).status,0);
 const forge=edit=>{const b=structuredClone(good);edit(b);return resign(b,f.privateKey);};
 const disposition=b=>b.records.find(r=>r.type==='retention_disposition');
 const activation=b=>b.records.find(r=>r.type==='retention_rotation'&&r.payload.status==='active');
 const reasons={critical:/critical class/,criticalPolicy:/critical class/,onePerson:/second person/,early:/before its period/,unnamedClass:/does not name/,
  undatedApproval:/outlives/,longApproval:/outlives/,
  heldAction:/hold or an open case/};
 const cases={
  critical:b=>{disposition(b).payload.rotation.classes[0]={sourceKind:'safety',kind:'safety_alert',sensitivity:'none'};},
  criticalPolicy:b=>{
   const critical={sourceKind:'safety',kind:'*',sensitivity:'any',retentionSeconds:1};
   for(const r of b.records.filter(r=>r.type==='retention_rotation'))r.payload.terms.classes.push(critical);
  },
  onePerson:b=>{
   const row=activation(b),person=row.payload.proposedBy;
   row.payload.approvedBy=person;row.principal=person;disposition(b).payload.approvedBy=person;
  },
  early:b=>{const d=disposition(b);d.payload.executedAt=b.records.find(r=>r.type==='event').recordedAt;},
  undatedApproval:b=>{delete activation(b).payload.approvedAt;},
  longApproval:b=>{const row=activation(b);row.payload.validUntil=new Date(Date.parse(row.payload.approvedAt)+2000*86400000).toISOString();},
  unnamedClass:b=>{disposition(b).payload.rotation.classes[0]={sourceKind:'tool',kind:'result',sensitivity:'none'};},
  heldAction:b=>{
   const at=b.records.indexOf(disposition(b)),hold={...b.records[at],type:'retention_hold',payload:{id:'forced',scope:'a-1',status:'active',reason:'x'}};
   b.records.splice(at,0,hold);b.records.forEach((r,i)=>{r.seq=i+1;});},
 };
 for(const [name,edit] of Object.entries(cases)){
  const bundle=forge(edit),history=verifyRotationHistory(bundle.records);
  assert.equal(history.valid,false,name);assert.match(history.error,reasons[name]);
  const cli=verifyCli(bundle,pem);assert.equal(cli.status,1,name);
 }
 // A manual policy object written straight into the ledger (no proposal record) is not an activation either.
 const direct=forge(b=>{b.records.splice(b.records.findIndex(r=>r.type==='retention_rotation'),1);b.records.forEach((r,i)=>{r.seq=i+1;});});
 assert.match(verifyRotationHistory(direct.records).error,/changed its terms/);
 // The vault refuses to run on a policy history it cannot verify.
 f.store.transaction(()=>f.store.put({tenant:'alpha',id:'admin'},'retention_rotation','forced',{...activation(good).payload,id:'forced'}));
 await assert.rejects(()=>f.call('/api/retention/rotation/run',{},'admin'),/Retention rotation history invalid/);
 const shown=await f.call('/api/retention/rotation',undefined,'auditor');
 assert.equal(shown.historyValid,false);assert.match(shown.historyError,/changed its terms/);assert.equal(shown.active,null);
});

test('exports written before rotation keep verifying, and recovery frontiers accept scheduled dispositions',async t=>{
 const fixtureFile=JSON.parse(readFileSync(new URL('./fixtures/pre-rotation-export-5cea6b8.json',import.meta.url),'utf8'));
 const old=fixtureFile.exportBundle,verified=verifyBundle(old,fixtureFile.publicKeyPem);
 assert.equal(verified.valid,true);assert.equal(verified.erasedEvents,4);
 const history=verifyRotationHistory(old.records);
 assert.equal(history.valid,true);assert.equal(history.scheduledDispositions,0);assert.equal(history.active,null);
 assert.equal(replayEvaluations(old).valid,true);
 const cli=verifyCli(old,fixtureFile.publicKeyPem,['--replay']);assert.equal(cli.status,0,cli.stderr);assert.equal(cli.out.retentionRotation,undefined);
 const f=fixture(t);
 await f.call('/api/retention/policy',{retentionSeconds:1,purpose:'synthetic',reason:'synthetic'});
 await f.ingest('agent',{id:'routine',actionId:'a-1',kind:'intent'});
 const backup=f.store.rawBundle('alpha');
 await f.activate();await sleep(1100);
 assert.equal((await f.call('/api/retention/rotation/run',{},'admin')).erased,1);
 const current=f.store.rawBundle('alpha'),archiveAnchor={format:'evidscope-recovery-anchor-v1',manifestSha256:'0'.repeat(64),
  keyFingerprint:createHash('sha256').update(f.store.publicKey.export({format:'der',type:'spki'})).digest('hex'),checkpoints:{alpha:backup.checkpoint}};
 const config={principals};
 const signed=signRecoveryFrontier({bundles:[current],archiveAnchor,privateKey:f.privateKey,publicKey:f.store.publicKey,config});
 assert.equal(signed.frontier.tenants[0].executedRetentionPlans.length,1);
 assert.equal(signed.frontier.tenants[0].executedRetentionPlans[0].payload.rotation.policyVersion,1);
 const erased=signed.frontier.tenants[0].erasedEvents;
 assert.equal(erased.length,1);assert.equal(erased[0].sourcePlanId,signed.frontier.tenants[0].executedRetentionPlans[0].payload.id);
 assert.equal(canonical(erased[0].keyId),canonical(backup.records.find(r=>r.type==='event').payload.keyId));
});

test('sealed access ranges past the policy period are pruned under the signed floor; the chain and later entries still verify',async t=>{
 const f=fixture(t),log=f.service.accessLog;
 const reads=async n=>{for(let i=0;i<n;i++)await f.call('/api/retention/rotation',undefined,'auditor');};
 await reads(3);const first=log.seal('alpha','manual');await reads(2);const second=log.seal('alpha','manual');await reads(2);
 await f.activate(ROUTINE,{accessLogRetentionSeconds:365*86400,validDays:1000});
 assert.equal((await f.call('/api/retention/rotation/run',{},'admin')).status,'nothing_due','sealed ranges are younger than a year');
 t.mock.timers.enable({apis:['Date'],now:Date.now()+366*86400000});
 // A tenant-wide hold keeps every access record.
 const hold=await f.call('/api/retention/holds',{scope:'tenant',reason:'litigation hold'});
 assert.equal((await f.call('/api/retention/rotation/run',{},'admin')).status,'nothing_due');
 await f.call(`/api/retention/holds/${hold.id}/release`,{reason:'released'},'admin');
 const run=await f.call('/api/retention/rotation/run',{},'admin');
 assert.equal(run.status,'access_log_pruned');assert.equal(run.accessLogPruned.throughSeq,second.payload.toSeq);
 assert.equal(run.accessLogPruned.deleted,second.payload.toSeq);
 const rows=()=>log.db.prepare('SELECT seq FROM access_log WHERE tenant=? ORDER BY seq').all('alpha').map(r=>r.seq);
 assert.equal(rows()[0],second.payload.toSeq+1);
 // Rows above the floor stay append-only, and the floor cannot go back.
 assert.throws(()=>log.db.prepare('DELETE FROM access_log WHERE tenant=? AND seq=?').run('alpha',second.payload.toSeq+1),/append only/);
 assert.throws(()=>log.db.prepare('UPDATE access_log_floor SET through_seq=1 WHERE tenant=?').run('alpha'),/prune floor regression/);
 // The chain continues: the unsealed tail seals onto the pruned batch head.
 const third=log.seal('alpha','manual');assert.equal(third.payload.previous,second.payload.head);
 const records=()=>f.store.rawBundle('alpha').records,checked=log.verify('alpha',records());
 assert.equal(checked.valid,true);assert.equal(checked.prunedThrough,second.payload.toSeq);assert.equal(checked.prunedBatches,2);
 const history=verifyRotationHistory(records());assert.equal(history.valid,true);assert.equal(history.accessLogPrunes,1);
 assert.equal(history.accessLogPrunedThrough,second.payload.toSeq);
 assert.equal(await f.status(`/api/audit/reads/proof?seq=${first.payload.fromSeq}`,undefined,'auditor'),404,'a pruned entry has no proof');
 assert.equal((await f.call(`/api/audit/reads/proof?seq=${third.payload.fromSeq}`,undefined,'auditor')).leafIndex,0);
 // Exported rows after the floor verify offline.
 assert.equal((await f.call('/api/integrity',undefined,'auditor')).valid,true);
 const entries=log.db.prepare('SELECT seq,body,hash FROM access_log WHERE tenant=? ORDER BY seq').all('alpha');
 assert.equal(verifyAccessBatches('alpha',records(),entries).valid,true);
 assert.throws(()=>verifyAccessBatches('alpha',records(),entries.slice(1)),/start at/);
 const altered=entries.map((r,i)=>i===1?{...r,hash:'0'.repeat(64)}:r);
 assert.throws(()=>verifyAccessBatches('alpha',records(),altered),/chain mismatch/,'kept rows stay tamper-evident');
 assert.throws(()=>verifyAccessBatches('alpha',records(),entries.filter((r,i)=>i!==1)),/missing|chain mismatch/,'and complete above the floor');
 // A second year: everything sealed goes, and new reads continue the chain from the signed floor.
 t.mock.timers.setTime(Date.now()+366*86400000);
 log.seal('alpha','manual');
 const again=await f.call('/api/retention/rotation/run',{},'admin');assert.equal(again.status,'access_log_pruned');
 assert.deepEqual(rows(),[]);
 await reads(1);const last=log.seal('alpha','manual');assert.equal(last.payload.fromSeq,again.accessLogPruned.throughSeq+1);
 assert.equal(log.verify('alpha',records()).valid,true);assert.equal(verifyRotationHistory(records()).valid,true);
 // A prune record that no two-person policy allows, or that does not end at a batch, is refused.
 const forged=records().map(r=>r.type==='audit_access_prune'?{...r,payload:{...r.payload,rotation:{...r.payload.rotation,policyRecordHash:'0'.repeat(64)}}}:r);
 assert.match(verifyRotationHistory(forged).error,/no active policy/);
 const offBoundary=records().map(r=>r.type==='audit_access_prune'?{...r,payload:{...r.payload,throughSeq:r.payload.throughSeq-1}}:r);
 assert.throws(()=>verifyAccessBatches('alpha',offBoundary,[]),/does not end at an earlier sealed batch/);
});

test('an access log from before pruning gets the floor-aware delete trigger and stays append-only',t=>{
 const dir=tempDir('evidscope-access-migrate-'),db=new DatabaseSync(join(dir,'access-log.db'));
 db.exec(`CREATE TABLE access_log(tenant TEXT NOT NULL,seq INTEGER NOT NULL CHECK(seq>0),body TEXT NOT NULL,hash TEXT NOT NULL,PRIMARY KEY(tenant,seq));
  CREATE TRIGGER access_log_immutable_delete BEFORE DELETE ON access_log BEGIN SELECT RAISE(ABORT,'append only'); END;
  INSERT INTO access_log VALUES('alpha',1,'{}','x');`);db.close();
 const log=new AccessLog(dir,{db:{isOpen:true}});t.after(()=>log.close());
 assert.match(log.db.prepare("SELECT sql FROM sqlite_schema WHERE name='access_log_immutable_delete'").get().sql,/access_log_floor/);
 assert.throws(()=>log.db.prepare('DELETE FROM access_log WHERE tenant=?').run('alpha'),/append only/);
 assert.throws(()=>log.db.exec('DROP TRIGGER access_log_immutable_delete'),/not authorized/);
});

test('the vault schedules rotation from RETENTION_ROTATION_INTERVAL_MS and erases a routine event over HTTP',async t=>{
 process.env.RETENTION_ROTATION_INTERVAL_MS='1000';
 let h;try{h=await harness({vaultOnly:true});}finally{delete process.env.RETENTION_ROTATION_INTERVAL_MS;}
 t.after(()=>h.close());
 const api=(path,body,role='reviewer')=>h.api(path,{body,role});
 assert.equal((await api('/api/retention/policy',{retentionSeconds:1,purpose:'synthetic',reason:'synthetic only'})).status,200);
 const event={id:'heartbeat-1',actionId:'heartbeat',traceId:'heartbeat',kind:'heartbeat',occurredAt:new Date().toISOString()};
 assert.equal((await submit(h.ingress.url,h.principal('telemetry'),event)).status,202);
 const proposal=(await api('/api/retention/rotation',{classes:[{sourceKind:'telemetry',kind:'heartbeat',retentionSeconds:1}],purpose:'x',reason:'x'})).body;
 assert.equal((await api(`/api/retention/rotation/${proposal.id}/approve`,{reason:'second person'},'admin')).status,200);
 let status;
 for(let i=0;i<40&&!status?.rotatedEvents;i++){await sleep(250);status=(await h.api('/api/retention/rotation')).body;}
 assert.equal(status.scheduler.enabled,true);assert.equal(status.scheduler.intervalMs,1000);
 assert.equal(status.rotatedEvents,1,JSON.stringify(status.scheduler));
 assert.equal((await h.api('/api/events')).body.total,0);
 assert.equal((await h.api('/api/integrity')).body.valid,true);
});
