import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,verify} from 'node:crypto';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve,sep} from 'node:path';
import {createService} from '../src/service.mjs';
import {canonical} from '../src/crypto.mjs';

async function fixture(t){
 const dir=mkdtempSync(join(tmpdir(),'evidscope-finance-evaluation-')),principals=['alpha','beta'].map(tenant=>({id:tenant+'-reviewer',role:'reviewer',tenant,token:tenant.repeat(40)}));
 const service=createService({dataDir:dir,key:generateKeyPairSync('ed25519').privateKey,config:{principals}}),store=service.store;
 t.after(()=>{store.close();assert.ok(resolve(dir).startsWith(resolve(tmpdir())+sep));rmSync(dir,{recursive:true,force:true});});
 const call=(path,body,tenant='alpha')=>service.handle(body===undefined?'GET':'POST',new URL(path,'http://local'),{authorization:'Bearer '+principals.find(p=>p.tenant===tenant).token},body===undefined?'':JSON.stringify(body));
 for(const p of principals){
  await call('/api/governance/systems',{id:'credit',name:'Synthetic credit',owner:p.id,purpose:'Synthetic loan review',markets:['KR'],krRoles:['deployer']},p.tenant);
  store.transaction(()=>{
   for(const actionId of ['action-a','action-b']){
    for(const version of [1,2]){
     const event={tenant:p.tenant,source:p.tenant+'-tool',sourceKind:'tool',id:`${actionId}-event-${version}`,actionId,systemId:'credit',traceId:actionId+'-trace',kind:'execution',receivedAt:`2026-09-29T00:00:0${version}.000Z`,occurredAt:`2026-09-29T00:00:0${version}.000Z`,fingerprint:`${actionId}-${version}`};
     const record=store.append(p.tenant,'event',event,p.id);store.project({...event,seq:record.seq,hash:record.hash});store.db.prepare('INSERT INTO actions(tenant,id,version) VALUES(?,?,1) ON CONFLICT(tenant,id) DO UPDATE SET version=version+1').run(p.tenant,actionId);
     const evaluation={id:p.tenant+'-'+actionId+'-v'+version,actionId,version,status:'evaluated',authority:'unverified_or_mismatch',effect:'unconfirmed',findings:[],createdAt:`2026-09-29T00:00:0${version}.000Z`};
     store.append(p.tenant,'evaluation',evaluation,p.id);store.db.prepare('INSERT INTO evaluations(tenant,action_id,version,body) VALUES(?,?,?,?)').run(p.tenant,actionId,version,JSON.stringify(evaluation));store.db.prepare('UPDATE actions SET analyzed=? WHERE tenant=? AND id=?').run(version,p.tenant,actionId);
    }
   }
  });
 }
 return {store,call};
}

for(const mutation of ['move','swap','version','ordering'])test(`finance refuses evaluation ${mutation} SQL tampering before reading or signing a mismatched operation`,async t=>{
 const h=await fixture(t),before=h.store.ledgerObjects('alpha','evaluation');
 if(mutation==='move')h.store.db.prepare("UPDATE evaluations SET action_id='action-a' WHERE tenant='alpha' AND action_id='action-b'").run();
 if(mutation==='swap')h.store.db.prepare("UPDATE evaluations SET action_id=CASE action_id WHEN 'action-a' THEN 'action-b' ELSE 'action-a' END WHERE tenant='alpha'").run();
 if(mutation==='version')h.store.db.prepare("UPDATE evaluations SET version=999 WHERE tenant='alpha' AND action_id='action-a'").run();
 if(mutation==='ordering')h.store.db.prepare("UPDATE evaluations SET id=1000+id WHERE tenant='alpha' AND action_id='action-a' AND version=1").run();
 await assert.rejects(h.call('/api/governance/finance?systemId=credit'),e=>e.status===409&&/서명 원장/.test(e.message));
 const checkpoint=h.store.db.prepare("SELECT body FROM checkpoints WHERE tenant='alpha'").get().body;
 await assert.rejects(h.call('/api/governance/finance/report',{systemId:'credit'}),e=>e.status===409&&/서명 원장/.test(e.message));
 assert.equal(h.store.db.prepare("SELECT body FROM checkpoints WHERE tenant='alpha'").get().body,checkpoint,'rejected report cannot append a signed record');
 assert.deepEqual(h.store.ledgerObjects('alpha','evaluation'),before,'signed evaluation history remains unchanged');
 assert.equal(h.store.list('alpha','finance_report').length,0);
 const healthy=await h.call('/api/governance/finance/report',{systemId:'credit'},'beta');
 assert.deepEqual(healthy.snapshot.operations.map(o=>[o.actionId,o.evaluation.actionId,o.evaluation.version]),[['action-a','action-a',2],['action-b','action-b',2]]);
 assert.ok(healthy.snapshot.operations.every(o=>o.evaluation.id.startsWith('beta-')));
});

test('finance preserves signed latest evaluation selection and tenant separation for valid history',async t=>{
 const h=await fixture(t);
 for(const tenant of ['alpha','beta']){
  const report=await h.call('/api/governance/finance/report',{systemId:'credit'},tenant);
  assert.deepEqual(report.snapshot.operations.map(o=>[o.actionId,o.evaluation.id,o.evaluation.version]),[['action-a',tenant+'-action-a-v2',2],['action-b',tenant+'-action-b-v2',2]]);
  assert.ok(verify(null,Buffer.from(canonical(report.snapshot)),report.publicKey,Buffer.from(report.signature,'base64')));
  assert.deepEqual(await h.call('/api/governance/finance/reports/'+report.id,undefined,tenant),report);
 }
});
