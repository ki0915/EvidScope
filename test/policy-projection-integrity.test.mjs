import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,randomUUID} from 'node:crypto';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve,sep} from 'node:path';
import {createService} from '../src/service.mjs';
import {canonical,mac} from '../src/crypto.mjs';

function fixture(t){
 const dir=mkdtempSync(join(tmpdir(),'evidscope-policy-projection-'));
 const principals=[{id:'reviewer',role:'reviewer',tenant:'alpha',token:'r'.repeat(40)},{id:'admin',role:'admin',tenant:'alpha',token:'a'.repeat(40)},{id:'beta-reviewer',role:'reviewer',tenant:'beta',token:'b'.repeat(40)},{id:'source',role:'source',kind:'agent',tenant:'alpha',token:'s'.repeat(40),hmacSecret:'h'.repeat(40)}];
 const service=createService({dataDir:dir,key:generateKeyPairSync('ed25519').privateKey,config:{principals}}),store=service.store,db=store.db;
 t.after(()=>{store.close();assert.ok(resolve(dir).startsWith(resolve(tmpdir())+sep));rmSync(dir,{recursive:true,force:true});});
 const call=(path,body={},who=0)=>service.handle('POST',new URL(path,'http://local'),{authorization:'Bearer '+principals[who].token},JSON.stringify(body));
 const saved=(type,id)=>store.get('alpha',type,id);
 const replace=(type,id,value)=>db.prepare('UPDATE objects SET body=? WHERE tenant=? AND type=? AND id=?').run(JSON.stringify(value),'alpha',type,id);
 const records=()=>db.prepare('SELECT tenant,seq,body,hash FROM ledger ORDER BY tenant,seq').all();
 async function rejected(path,body={},who=0){const before=records();await assert.rejects(call(path,body,who),e=>e.status===409&&/서명 원장/.test(e.message));assert.deepEqual(records(),before,'rejected mutation must not append or re-sign any ledger record');}
 async function ingest(){const raw={id:'original-event',actionId:'action',traceId:'trace',kind:'intent',occurredAt:new Date().toISOString(),note:'original'},body=JSON.stringify(raw),timestamp=String(Date.now()),nonce=randomUUID();await service.handle('POST',new URL('/api/ingest','http://local'),{authorization:'Bearer '+principals[3].token,'x-evid-timestamp':timestamp,'x-evid-nonce':nonce,'x-evid-signature':mac(principals[3].hmacSecret,timestamp,nonce,body)},body);}
 return {store,db,principals,call,saved,replace,rejected,ingest};
}
const rule={id:'rule-one',title:'Original rule',field:'note',op:'eq',value:'original',severity:'high'};

for(const operation of ['create-version','test','approve'])test(`rule ${operation} cannot re-sign forged history, authorship or test evidence`,async t=>{
 const h=fixture(t);await h.call('/api/rules',rule);await h.call('/api/rules/rule-one/test',{version:1});
 const original=h.saved('rule','rule-one'),forged=structuredClone(original);Object.assign(forged.versions[0],{author:'forged-author',value:'forged-match',test:{matches:[],testedBy:'forged-tester'}});h.replace('rule','rule-one',forged);
 await h.rejected(operation==='create-version'?'/api/rules':`/api/rules/rule-one/${operation}`,operation==='create-version'?{...rule,title:'Routine new version'}:{version:1},1);
 h.replace('rule','rule-one',original);
 if(operation==='create-version'){assert.equal((await h.call('/api/rules',{...rule,title:'Next version'})).version,2);assert.deepEqual(h.saved('rule','rule-one').versions[0],original.versions[0]);}
 else if(operation==='test')assert.equal((await h.call('/api/rules/rule-one/test',{version:1})).testedBy,'reviewer');
 else{await assert.rejects(h.call('/api/rules/rule-one/approve',{version:1}),e=>e.status===403);assert.equal((await h.call('/api/rules/rule-one/approve',{version:1},1)).status,'active');}
});

test('exception approval cannot sign forged scope, expiry or two-person identities',async t=>{
 const h=fixture(t),original=await h.call('/api/exceptions',{ruleId:'rule-one',actionId:'action',reason:'Original exception',owner:'reviewer',expiresAt:new Date(Date.now()+3600000).toISOString()});
 h.replace('exception',original.id,{...original,author:'forged-author',owner:'forged-owner',actionId:'another-action',expiresAt:'2099-01-01T00:00:00.000Z'});
 await h.rejected(`/api/exceptions/${original.id}/approve`,{},0);h.replace('exception',original.id,original);
 await assert.rejects(h.call(`/api/exceptions/${original.id}/approve`),e=>e.status===403);
 const approved=await h.call(`/api/exceptions/${original.id}/approve`,{},1);assert.deepEqual(approved,{...original,status:'approved',approvedBy:'admin'});
});

test('governance task updates preserve signed target and prior evidence',async t=>{
 const h=fixture(t),original={id:'task-one',systemId:'credit',requirementId:'KR-34-RISK',owner:'reviewer',title:'Original task',status:'open',previousHash:'original-context'};
 h.store.transaction(()=>h.store.put(h.principals[0],'governance_task',original.id,original));h.replace('governance_task',original.id,{...original,systemId:'other-system',requirementId:'OTHER',previousHash:'forged-context'});
 await h.rejected('/api/governance/tasks/task-one',{status:'closed',reason:'Routine close'});h.replace('governance_task',original.id,original);
 // A signed task alone does not supply the missing system or legal evidence.
 await assert.rejects(h.call('/api/governance/tasks/task-one',{status:'closed',reason:'No registered evidence'}),e=>e.status===404);
 const updated=await h.call('/api/governance/tasks/task-one',{status:'open',reason:'Review pending'});assert.equal(updated.status,'open');assert.equal(updated.systemId,original.systemId);assert.equal(updated.previousHash,original.previousHash);
 assert.equal((await h.call('/api/governance/tasks/task-one',{status:'open',reason:'Follow up'})).status,'open');
});

for(const type of ['rule','exception','governance_task'])for(const alteration of ['missing','extra','body-id','sql-id'])test(`${type}: ${alteration} projection is rejected without a new signed record`,async t=>{
 const h=fixture(t);let target,path,body;
 if(type==='rule'){await h.call('/api/rules',rule);target=h.saved(type,rule.id);path='/api/rules';body={...rule,title:'Next version'};}
 else if(type==='exception'){target=await h.call('/api/exceptions',{ruleId:'rule-one',actionId:'action',owner:'reviewer',reason:'Original',expiresAt:new Date(Date.now()+3600000).toISOString()});path=`/api/exceptions/${target.id}/approve`;body={};}
 else{target={id:'task-one',systemId:'credit',title:'Original task',status:'open'};h.store.transaction(()=>h.store.put(h.principals[0],type,target.id,target));path='/api/governance/tasks/task-one';body={status:'closed',reason:'Routine close'};}
 if(alteration==='missing')h.db.prepare('DELETE FROM objects WHERE tenant=? AND type=? AND id=?').run('alpha',type,target.id);
 if(alteration==='extra')h.db.prepare('INSERT INTO objects VALUES(?,?,?,?)').run('alpha',type,'unsigned-extra',JSON.stringify({...target,id:'unsigned-extra'}));
 if(alteration==='body-id')h.replace(type,target.id,{...target,id:'wrong-body-id'});
 if(alteration==='sql-id')h.db.prepare('UPDATE objects SET id=? WHERE tenant=? AND type=? AND id=?').run('wrong-sql-id','alpha',type,target.id);
 await h.rejected(path,body,1);
});

test('rule tests use signed decrypted events despite tampered, missing and extra event projections',async t=>{
 const h=fixture(t);await h.call('/api/rules',rule);await h.ingest();
 const original=h.db.prepare('SELECT * FROM events WHERE tenant=?').get('alpha');
 h.db.prepare('UPDATE events SET body=? WHERE tenant=?').run(JSON.stringify({...JSON.parse(original.body),note:'forged'}),'alpha');
 assert.deepEqual((await h.call('/api/rules/rule-one/test',{version:1})).matches,['source/original-event']);
 h.db.prepare('DELETE FROM events WHERE tenant=?').run('alpha');
 assert.deepEqual((await h.call('/api/rules/rule-one/test',{version:1})).matches,['source/original-event']);
 const forged={...JSON.parse(original.body),id:'unsigned-event'};h.store.project(forged);
 assert.deepEqual((await h.call('/api/rules/rule-one/test',{version:1})).matches,['source/original-event']);
 assert.equal(h.store.ledgerObjects('alpha','rule')[0].versions[0].test.evaluated,1);
});

test('projection checks preserve tenant isolation and do not retire or rewrite previous versions on rejection',async t=>{
 const h=fixture(t);await h.call('/api/rules',rule);await h.call('/api/rules/rule-one/test',{version:1});await h.call('/api/rules/rule-one/approve',{version:1},1);await h.call('/api/rules',{...rule,title:'Second'});await h.call('/api/rules/rule-one/test',{version:2});
 const original=h.saved('rule',rule.id),signedBefore=canonical(h.store.ledgerObjects('alpha','rule'));
 h.replace('rule',rule.id,{...original,versions:original.versions.map(v=>({...v,title:'forged'}))});await h.rejected('/api/rules/rule-one/approve',{version:2},1);assert.equal(canonical(h.store.ledgerObjects('alpha','rule')),signedBefore);
 assert.equal((await h.call('/api/rules',rule,2)).version,1,'other tenant has an independent projection and history');h.replace('rule',rule.id,original);
 await h.call('/api/rules/rule-one/approve',{version:2},1);assert.deepEqual(h.saved('rule',rule.id).versions.map(v=>v.status),['retired','active']);
});

test('large unrelated signed records are fully hashed without blocking policy edits; oversized policy history fails closed',async t=>{
 const h=fixture(t),padding='x'.repeat(2*1024*1024+1);
 h.store.transaction(()=>h.store.append('alpha','audit_access',{padding},'synthetic'));
 assert.equal((await h.call('/api/rules',rule)).version,1);
 const original=h.saved('rule',rule.id);
 h.store.transaction(()=>h.store.put(h.principals[0],'rule',rule.id,{...original,padding}));
 await assert.rejects(h.call('/api/rules',{...rule,title:'Too large history'}),e=>e.status===413);
});
