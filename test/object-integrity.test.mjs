import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve,sep} from 'node:path';
import {createService} from '../src/service.mjs';
import {createVaultBackup,restoreVaultBackup} from '../src/vault-recovery.mjs';

function fixture(t){
 const root=mkdtempSync(join(tmpdir(),'evidscope-object-integrity-')),dataDir=join(root,'data'),{privateKey,publicKey}=generateKeyPairSync('ed25519');
 const principals=['alpha','beta'].map(tenant=>({id:tenant+'-reviewer',tenant,role:'reviewer',token:tenant.repeat(40)})),config={principals};
 const service=createService({dataDir,key:privateKey,config}),store=service.store,db=store.db;
 t.after(()=>{store.close();assert.ok(resolve(root).startsWith(resolve(tmpdir())+sep));rmSync(root,{recursive:true,force:true});});
 const call=(path='/api/integrity',tenant='alpha',{method='GET',body}={})=>service.handle(method,new URL(path,'http://local'),{authorization:'Bearer '+principals.find(p=>p.tenant===tenant).token},body===undefined?'':JSON.stringify(body));
 const put=(type,id,body)=>store.transaction(()=>store.put(principals[0],type,id,body));
 const sample=(type)=>type==='catalog'?{id:'current',body:store.get('alpha','catalog','current')}:type==='assistance_profile'?{id:'profile@1',body:{id:'profile',version:1,title:'Original profile'}}:{id:type+'-one',body:{id:type+'-one',title:'Original',...(type==='identity_access'?{disabled:true,epoch:1}:type==='system'?{schemaVersion:4,name:'Synthetic system',owner:'reviewer',purpose:'Projection verification'}:type==='rule'?{versions:[{version:1,status:'draft'}]}:type==='exception'?{status:'pending'}:{})}};
 return {root,dataDir,privateKey,publicKey,config,service,store,db,call,put,sample};
}

for(const type of ['rule','assessment','governance_task','identity_access','catalog','assistance_profile'])for(const alteration of ['forged','missing','extra','sql-id','body-id'])test(`integrity rejects ${type} ${alteration} projection`,async t=>{
 const h=fixture(t),sample=h.sample(type);if(type!=='catalog')h.put(type,sample.id,sample.body);
 if(alteration==='forged')h.db.prepare('UPDATE objects SET body=? WHERE tenant=? AND type=? AND id=?').run(JSON.stringify({...sample.body,title:'Forged',disabled:false}),'alpha',type,sample.id);
 if(alteration==='missing')h.db.prepare('DELETE FROM objects WHERE tenant=? AND type=? AND id=?').run('alpha',type,sample.id);
 if(alteration==='extra')h.db.prepare('INSERT INTO objects VALUES(?,?,?,?)').run('alpha',type,'unsigned-extra',JSON.stringify({...sample.body,id:'unsigned-extra'}));
 if(alteration==='sql-id')h.db.prepare('UPDATE objects SET id=? WHERE tenant=? AND type=? AND id=?').run('wrong-sql-id','alpha',type,sample.id);
 if(alteration==='body-id')h.db.prepare('UPDATE objects SET body=? WHERE tenant=? AND type=? AND id=?').run(JSON.stringify({...sample.body,id:'wrong-body-id'}),'alpha',type,sample.id);
 const before=h.store.ledgerObjects('alpha',type),result=await h.call();assert.equal(result.valid,false,'object corruption must prevent the generic integrity success');assert.match(result.error,/Object projection differs/);assert.equal(result.failureRecorded,true);assert.deepEqual(h.store.ledgerObjects('alpha',type),before,'integrity check must not repair or re-sign corrupt objects');
 assert.equal((await h.call('/api/integrity','beta')).valid,true,'other tenants retain independent verification');
});

test('valid latest objects and every assistance profile version survive API verification and backup recovery',async t=>{
 const h=fixture(t);
 for(const type of ['system','assessment','governance_task','asset','case','case_decision','rule','exception','retention_policy','retention_hold','retention_plan','supplier_bundle','finance_report','assistance_package','assistance_run','assistance_review','identity_access']){const item=h.sample(type);h.put(type,item.id,item.body);h.put(type,item.id,{...item.body,title:'Latest signed value'});}
 h.put('assistance_profile','profile@1',{id:'profile',version:1,title:'First immutable version'});h.put('assistance_profile','profile@2',{id:'profile',version:2,title:'Second immutable version'});
 const rawBundle=h.store.rawBundle.bind(h.store);let scans=0;h.store.rawBundle=(...args)=>{scans++;return rawBundle(...args);};
 const result=await h.call();assert.equal(result.valid,true);assert.deepEqual(result.objectProjection,{valid:true,objects:20});assert.equal(result.projection.valid,true);assert.equal(scans,1,'integrity reuses the verified bundle for event and object checks');
 assert.deepEqual(result.verificationScope.checks,['signed_ledger','retained_event_bodies','event_indexes','receipt_projections','development_run_projections','object_projections','evaluation_projections','action_projections','governance_document_projections','document_files']);
 assert.deepEqual(result.verificationScope.notChecked,[]);assert.equal(result.documentFiles.uniqueFiles,0);assert.equal(result.governanceDocumentProjection.revisions,0);
 const backupDir=join(h.root,'backup'),anchor=await createVaultBackup({dataDir:h.dataDir,backupDir,privateKey:h.privateKey,publicKey:h.publicKey});
 const receipt=await restoreVaultBackup({backupDir,restoreDir:join(h.root,'restored'),privateKey:h.privateKey,publicKey:h.publicKey,anchor});
 const restored=createService({dataDir:receipt.restoredDirectory,key:h.privateKey,config:h.config});try{const checked=await restored.handle('GET',new URL('/api/integrity','http://local'),{authorization:'Bearer '+h.config.principals[0].token});assert.deepEqual(checked.objectProjection,result.objectProjection);assert.equal(checked.valid,true);assert.equal(restored.store.get('alpha','assistance_profile','profile@1').title,'First immutable version');}finally{restored.store.close();}
});

test('unknown unsigned object types are rejected by API and backup with the same comparison',async t=>{
 const h=fixture(t);h.db.prepare('INSERT INTO objects VALUES(?,?,?,?)').run('alpha','unsigned_type','extra',JSON.stringify({id:'extra'}));
 assert.equal((await h.call()).valid,false);
 await assert.rejects(createVaultBackup({dataDir:h.dataDir,backupDir:join(h.root,'backup'),privateKey:h.privateKey,publicKey:h.publicKey}),/Object projection differs from signed evidence/);
});

for(const [type,paths] of Object.entries({asset:['/api/assets','/api/ai-visibility'],case:['/api/cases','/api/overview'],rule:['/api/rules'],exception:['/api/exceptions'],system:['/api/governance'],supplier_bundle:['/api/governance'],assessment:['/api/governance'],governance_task:['/api/governance']}))test(`ordinary ${type} reads never display an altered unsigned projection`,async t=>{
 const h=fixture(t),sample=h.sample(type);h.put(type,sample.id,sample.body);h.db.prepare('UPDATE objects SET body=? WHERE tenant=? AND type=? AND id=?').run(JSON.stringify({...sample.body,title:'Forged display value',owner:'attacker'}),'alpha',type,sample.id);
 for(const path of paths)await assert.rejects(h.call(path),error=>error.status===409,path);
 assert.ok(await h.call(paths[0],'beta'),'another tenant remains readable');
});

for(const type of ['asset','system'])test(`altered ${type} projection cannot be repaired and re-signed by an ordinary update`,async t=>{
 const h=fixture(t),sample=h.sample(type);h.put(type,sample.id,sample.body);const before=h.store.ledgerObjects('alpha',type);h.db.prepare('UPDATE objects SET body=? WHERE tenant=? AND type=? AND id=?').run(JSON.stringify({...sample.body,owner:'attacker'}),'alpha',type,sample.id);
 const body=type==='asset'?{id:sample.id,actor:'agent',tool:'tool',owner:'reviewer',validFrom:'2026-09-29T00:00:00.000Z'}:{id:sample.id,name:'Updated',owner:'reviewer',purpose:'verified update'};
 await assert.rejects(h.call(type==='asset'?'/api/assets':'/api/governance/systems','alpha',{method:'POST',body}),error=>error.status===409);
 assert.deepEqual(h.store.ledgerObjects('alpha',type),before);
});
