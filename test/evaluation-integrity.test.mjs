import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {generateKeyPairSync} from 'node:crypto';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve,sep} from 'node:path';
import {createService} from '../src/service.mjs';

function fixture(t){
 const dir=mkdtempSync(join(tmpdir(),'evidscope-evaluation-integrity-')),principals=['alpha','beta'].map(tenant=>({id:tenant+'-reviewer',role:'reviewer',tenant,token:tenant.repeat(40)}));
 const service=createService({dataDir:dir,key:generateKeyPairSync('ed25519').privateKey,config:{principals}}),store=service.store;
 t.after(()=>{store.close();assert.ok(resolve(dir).startsWith(resolve(tmpdir())+sep));rmSync(dir,{recursive:true,force:true});});
 const call=(path,tenant='alpha')=>service.handle('GET',new URL(path,'http://local'),{authorization:'Bearer '+principals.find(p=>p.tenant===tenant).token});
 for(const principal of principals)store.transaction(()=>{
  for(const version of [1,2]){
   const event={tenant:principal.tenant,source:principal.tenant+'-tool',sourceKind:'tool',id:'event-'+version,actionId:'action-a',traceId:'trace-a',kind:'execution',receivedAt:`2026-09-29T00:00:0${version}.000Z`,occurredAt:`2026-09-29T00:00:0${version}.000Z`,fingerprint:'event-'+version};
   const record=store.append(principal.tenant,'event',event,principal.id);store.project({...event,seq:record.seq,hash:record.hash});store.db.prepare('INSERT INTO actions(tenant,id,version) VALUES(?,?,1) ON CONFLICT(tenant,id) DO UPDATE SET version=version+1').run(principal.tenant,event.actionId);
   const evaluation={id:`${principal.tenant}-evaluation-${version}`,actionId:'action-a',version,status:'evaluated',authority:'unverified_or_mismatch',effect:'unconfirmed',findings:version===2?[{code:'SYNTHETIC_FINDING',severity:'high',message:'Original signed finding'}]:[],createdAt:`2026-09-29T00:00:0${version}.000Z`};
   store.append(principal.tenant,'evaluation',evaluation,principal.id);
   store.db.prepare('INSERT INTO evaluations(tenant,action_id,version,body) VALUES(?,?,?,?)').run(principal.tenant,evaluation.actionId,evaluation.version,JSON.stringify(evaluation));
   store.db.prepare('UPDATE actions SET analyzed=? WHERE tenant=? AND id=?').run(version,principal.tenant,event.actionId);
  }
 });
 return {dir,store,call};
}

const mutations={
 body:store=>{const row=store.db.prepare("SELECT id,body FROM evaluations WHERE tenant='alpha' AND version=2").get(),value=JSON.parse(row.body);value.findings[0].message='Forged unsigned finding';store.db.prepare('UPDATE evaluations SET body=? WHERE id=?').run(JSON.stringify(value),row.id);},
 malformed:store=>store.db.prepare("UPDATE evaluations SET body='{' WHERE tenant='alpha' AND version=2").run(),
 action:store=>store.db.prepare("UPDATE evaluations SET action_id='redirected' WHERE tenant='alpha' AND version=2").run(),
 version:store=>store.db.prepare("UPDATE evaluations SET version=999 WHERE tenant='alpha' AND version=2").run(),
 missing:store=>store.db.prepare("DELETE FROM evaluations WHERE tenant='alpha' AND version=2").run(),
 extra:store=>store.db.prepare("INSERT INTO evaluations(tenant,action_id,version,body) VALUES('alpha','action-a',3,?)").run(JSON.stringify({id:'unsigned',actionId:'action-a',version:3,findings:[]})),
 ordering:store=>store.db.prepare("UPDATE evaluations SET id=id+1000 WHERE tenant='alpha' AND version=1").run(),
};

for(const [name,mutate] of Object.entries(mutations))test(`integrity rejects ${name} evaluation projection tampering without affecting another tenant`,async t=>{
 const h=fixture(t);mutate(h.store);const result=await h.call('/api/integrity');
 assert.equal(result.valid,false);assert.match(result.error,/Evaluation projection/);assert.equal(result.failureRecorded,true);
 assert.ok(result.verificationScope.checks.includes('evaluation_projections'));assert.ok(!result.verificationScope.notChecked.includes('evaluation_projections'));
 const healthy=await h.call('/api/integrity','beta');assert.equal(healthy.valid,true);assert.deepEqual(healthy.evaluationProjection,{valid:true,evaluations:2});
});

test('overview, action and alert reads reject a forged evaluation instead of rendering it',async t=>{
 const h=fixture(t),baseline=await h.call('/api/actions/action-a');assert.equal(baseline.evaluations[0].version,2);assert.equal(baseline.evaluations[0].findings[0].message,'Original signed finding');
 mutations.body(h.store);
 for(const path of ['/api/overview','/api/actions/action-a','/api/alerts'])await assert.rejects(h.call(path),error=>error.status===409&&/분석 조회 사본/.test(error.message));
 assert.ok(!JSON.stringify(h.store.rawBundle('alpha')).includes('Forged unsigned finding'));
});

test('valid reads preserve latest-first behavior and the integrity scope remains explicit',async t=>{
 const h=fixture(t),overview=await h.call('/api/overview'),action=await h.call('/api/actions/action-a'),alerts=await h.call('/api/alerts'),integrity=await h.call('/api/integrity');
 assert.equal(overview.counts.alerts,1);assert.deepEqual(action.evaluations.map(value=>value.version),[2,1]);assert.equal(alerts.items.length,1);assert.equal(alerts.items[0].message,'Original signed finding');
 assert.equal(integrity.valid,true);assert.deepEqual(integrity.evaluationProjection,{valid:true,evaluations:2});assert.deepEqual(integrity.actionProjection,{valid:true,actions:1});assert.deepEqual(integrity.developmentRunProjection,{valid:true,developmentEvents:0});assert.deepEqual(integrity.governanceDocumentProjection,{valid:true,documents:0,revisions:0});assert.deepEqual(integrity.documentFiles,{valid:true,financeFiles:0,governanceFiles:0,uniqueFiles:0,plaintextBytes:0,verification:'referenced_ciphertext_decrypted_authenticated_and_hashed_per_file',unreferencedFilesScanned:false,filesystemSnapshotProven:false});assert.deepEqual(integrity.verificationScope.notChecked,[]);
});

test('evaluation verification and response use one writer-excluding snapshot',async t=>{
 const h=fixture(t),other=new DatabaseSync(join(h.dir,'evidence.db'),{timeout:0});
 try{
  const original=h.store.verifiedRows.bind(h.store);let attempted=false,changed=false,blocked;
  h.store.verifiedRows=function*(...args){yield* original(...args);if(!attempted){attempted=true;try{const row=other.prepare("SELECT id,body FROM evaluations WHERE tenant='alpha' AND version=2").get(),value=JSON.parse(row.body);value.findings[0].message='Forged after verification';other.prepare('UPDATE evaluations SET body=? WHERE id=?').run(JSON.stringify(value),row.id);changed=true;}catch(error){blocked=error;}}};
  const result=await h.call('/api/actions/action-a');assert.equal(attempted,true);assert.equal(changed,false);assert.equal(blocked?.errcode,5);assert.match(blocked?.message||'',/locked|busy/i);assert.equal(result.evaluations[0].findings[0].message,'Original signed finding');
 }finally{other.close();}
});
