import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {generateKeyPairSync,createHash} from 'node:crypto';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve,sep} from 'node:path';
import {createService} from '../src/service.mjs';
import {canonical,verifyBundle} from '../src/crypto.mjs';

function fixture(t){
 const dir=mkdtempSync(join(tmpdir(),'evidscope-finance-atomic-')),principal={id:'reviewer',tenant:'alpha',role:'reviewer',token:'r'.repeat(40)},service=createService({dataDir:dir,key:generateKeyPairSync('ed25519').privateKey,config:{principals:[principal]}}),store=service.store;
 const other=new DatabaseSync(join(dir,'evidence.db'),{timeout:0});
 t.after(()=>{other.close();store.close();assert.ok(resolve(dir).startsWith(resolve(tmpdir())+sep));rmSync(dir,{recursive:true,force:true});});
 const call=(path,body)=>service.handle(body===undefined?'GET':'POST',new URL(path,'http://local'),{authorization:'Bearer '+principal.token},body===undefined?'':JSON.stringify(body));
 const put=id=>store.put(principal,'governance_task',id,{id,title:id});
 const state=()=>canonical({ledger:store.db.prepare('SELECT * FROM ledger ORDER BY tenant,seq').all(),checkpoints:store.db.prepare('SELECT * FROM checkpoints ORDER BY tenant').all(),objects:store.db.prepare('SELECT * FROM objects ORDER BY tenant,type,id').all()});
 return {store,other,principal,call,put,state};
}
const system={id:'credit',name:'Synthetic credit',owner:'reviewer',purpose:'대출 심사 보조',role:'deployer',krRoles:['deployer'],markets:['KR'],domain:'credit',generative:false,highImpact:'candidate',supplierId:'supplier',modelId:'model',modelVersion:'v1',suppliedModelVersion:'v1',suppliedPurpose:'대출 심사 보조',substantialModification:false};
function bundle(){const bytes=Buffer.from('합성 시험 문서');return {id:'bundle',systemId:'credit',synthetic:true,supplierId:'supplier',modelId:'model',modelVersion:'v1',purpose:system.purpose,testScope:'Original test scope',reviewerNotes:'Original notes',measures:['KR-34-RISK'],documents:[{id:'doc',name:'synthetic.txt',contentBase64:bytes.toString('base64'),sha256:createHash('sha256').update(bytes).digest('hex')}]};}

for(const operation of ['view','export','import','report','saved-report'])test(`finance ${operation} keeps verification and consumption in one writer-excluding snapshot`,async t=>{
 const h=fixture(t);await h.call('/api/governance/systems',system);await h.call('/api/governance/bundles',bundle());
 const saved=operation==='saved-report'?await h.call('/api/governance/finance/report',{systemId:'credit'}):null;
 const verify=h.store.checkProjection.bind(h.store);let attempted=false,changed=false,blocked;
 h.store.checkProjection=(tenant)=>{const result=verify(tenant);if(!attempted){attempted=true;try{h.other.prepare("UPDATE objects SET body=json_set(body,'$.reviewerNotes','forged after verification','$.revision',33) WHERE tenant='alpha' AND type='supplier_bundle'").run();changed=true;}catch(error){blocked=error;}}return result;};
 let result;if(operation==='view')result=await h.call('/api/governance/finance?systemId=credit');if(operation==='export')result=await h.call('/api/governance/bundles/bundle/export');if(operation==='import')result=await h.call('/api/governance/bundles',bundle());if(operation==='report')result=await h.call('/api/governance/finance/report',{systemId:'credit'});if(operation==='saved-report')result=await h.call('/api/governance/finance/reports/'+saved.id);
 assert.equal(attempted,true);assert.equal(changed,false,'a second SQLite writer must not alter a verified object before use');assert.equal(blocked?.errcode,5,'the competing write is rejected with SQLITE_BUSY');assert.match(blocked?.message||'',/locked|busy/i);assert.ok(!JSON.stringify(result).includes('forged after verification'));
 if(operation==='import')assert.equal(result.revision,2);if(operation==='report')assert.equal(result.snapshot.bundles[0].reviewerNotes,'Original notes');if(operation==='export')assert.equal(result.documents[0].contentBase64,bundle().documents[0].contentBase64);
 assert.equal(h.store.db.isTransaction,false);assert.equal(verifyBundle(h.store.bundle('alpha'),h.store.publicKey).valid,true);
});

test('successful nested savepoints remain subject to complete outer rollback',t=>{
 const h=fixture(t),before=h.state();assert.throws(()=>h.store.transaction(()=>{h.put('outer');h.store.transaction(()=>{h.put('inner');h.store.transaction(()=>h.put('deepest'));});throw Error('outer cancelled');}),/outer cancelled/);
 assert.equal(h.state(),before);assert.equal(h.store.db.isTransaction,false);
});

test('caught inner failure rolls back its ledger, checkpoint and objects while outer work commits',t=>{
 const h=fixture(t);h.store.transaction(()=>{h.put('outer-first');const before=h.state();assert.throws(()=>h.store.transaction(()=>{h.put('inner-discarded');h.store.transaction(()=>h.put('deep-discarded'));throw Error('inner cancelled');}),/inner cancelled/);assert.equal(h.state(),before);h.put('outer-last');});
 assert.deepEqual(h.store.ledgerObjects('alpha','governance_task').map(x=>x.id),['outer-first','outer-last']);assert.equal(verifyBundle(h.store.bundle('alpha'),h.store.publicKey).valid,true);assert.equal(h.store.db.isTransaction,false);
});

test('one transaction exposes its pending signed head and publishes only the final checkpoint',t=>{
 const h=fixture(t),persistedBefore=JSON.parse(h.store.db.prepare('SELECT body FROM checkpoints WHERE tenant=?').get('alpha').body);h.store.transaction(()=>{
  h.put('first');const first=verifyBundle(h.store.rawBundle('alpha'),h.store.publicKey);assert.equal(first.count,persistedBefore.count+1);
  assert.equal(JSON.parse(h.store.db.prepare('SELECT body FROM checkpoints WHERE tenant=?').get('alpha').body).count,persistedBefore.count);
  h.put('second');const second=verifyBundle(h.store.rawBundle('alpha'),h.store.publicKey);assert.equal(second.count,persistedBefore.count+2);
  assert.equal(JSON.parse(h.store.db.prepare('SELECT body FROM checkpoints WHERE tenant=?').get('alpha').body).count,persistedBefore.count);
 });
 const checkpoint=JSON.parse(h.store.db.prepare('SELECT body FROM checkpoints WHERE tenant=?').get('alpha').body);assert.equal(checkpoint.count,persistedBefore.count+2);assert.equal(verifyBundle(h.store.rawBundle('alpha'),h.store.publicKey).count,persistedBefore.count+2);
});

test('an existing transaction started outside Store uses a savepoint and is not committed by the helper',t=>{
 const h=fixture(t),before=h.state();h.store.transaction(()=>h.store.checkActionProjection('alpha'));h.store.db.exec('BEGIN IMMEDIATE');try{h.store.transaction(()=>{h.put('external-transaction');h.store.checkActionProjection('alpha');});assert.equal(h.store.db.isTransaction,true);}finally{h.store.db.exec('ROLLBACK');}assert.equal(h.state(),before);assert.deepEqual(h.store.transaction(()=>h.store.checkActionProjection('alpha')),{valid:true,actions:0});
});

test('a busy BEGIN leaves no pending ledger head that can bypass checkpoint publication',t=>{
 const h=fixture(t),before=h.state();h.other.exec('BEGIN IMMEDIATE');
 try{assert.throws(()=>h.store.transaction(()=>h.put('must-not-run')),error=>error.errcode===5);assert.ok(!h.store.ledgerTransaction);assert.equal(h.state(),before);}
 finally{h.other.exec('ROLLBACK');}
 h.store.transaction(()=>h.put('after-busy'));assert.equal(verifyBundle(h.store.rawBundle('alpha'),h.store.publicKey).valid,true);
 const checkpoint=JSON.parse(h.store.db.prepare('SELECT body FROM checkpoints WHERE tenant=?').get('alpha').body),head=h.store.db.prepare('SELECT seq,hash FROM ledger WHERE tenant=? ORDER BY seq DESC LIMIT 1').get('alpha');assert.equal(checkpoint.count,head.seq);assert.equal(checkpoint.head,head.hash);
});

test('transaction callbacks must be synchronous and never commit a returned promise',t=>{
 const h=fixture(t),before=h.state();let asyncBodyRan=false;
 assert.throws(()=>h.store.transaction(async()=>{asyncBodyRan=true;h.put('async-invalid');}),/synchronous/);assert.equal(asyncBodyRan,false);assert.equal(h.state(),before);
 assert.throws(()=>h.store.transaction(()=>{h.put('promise-invalid');return Promise.resolve('not synchronous');}),/synchronous/);assert.equal(h.state(),before);assert.equal(h.store.db.isTransaction,false);
});
