import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {existsSync,mkdirSync,mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {join,relative,resolve} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {Store} from '../src/store.mjs';
import {createService} from '../src/service.mjs';
import {digest,verifyBundle} from '../src/crypto.mjs';
import {createVaultBackup,createVaultRecoveryFrontier,restoreVaultBackup} from '../src/vault-recovery.mjs';
import {assertRecoveryActivation,configRebindingPath,configRebindingPinPath,rebindRecoveryConfig} from '../src/recovery-state.mjs';
import * as T from '../src/tlog.mjs';
import {probeTransparency} from '../src/transparency.mjs';
import {BASE,principals,transparencyFixture} from './support/transparency-fixture.mjs';

// Regression tests for adversarial-audit finding S8: after an activated restore, a configuration change (rotated token,
// added principal) starts only through a signed, externally pinned rebinding that the vault ledger then records.
const token=character=>character.repeat(40);
const original={profile:'synthetic-local',principals:[{id:'alpha-reviewer',tenant:'alpha',role:'reviewer',token:token('r')},
 {id:'beta-auditor',tenant:'beta',role:'auditor',token:token('b')}]};
const rotated={...original,principals:original.principals.map(p=>p.id==='alpha-reviewer'?{...p,token:token('R')}:p)};
const extended={...rotated,principals:[...rotated.principals,{id:'alpha-auditor',tenant:'alpha',role:'auditor',token:token('a')}]};
const reduced={...extended,principals:extended.principals.filter(p=>p.id!=='beta-auditor')};
const execute=promisify(execFile);
const cli=async args=>{
 try{return {...await execute(process.execPath,['scripts/vault-backup.mjs',...args],{windowsHide:true,timeout:15000,maxBuffer:1024*1024}),code:0};}
 catch(error){return {code:error.code,stdout:error.stdout,stderr:error.stderr};}
};

async function fixture(t){
 mkdirSync('.test-runs',{recursive:true});const root=resolve(mkdtempSync(join('.test-runs','config-rebinding-')));
 t.after(()=>rmSync(root,{recursive:true,force:true}));
 const {privateKey,publicKey}=generateKeyPairSync('ed25519'),dataDir=join(root,'source'),source=new Store(dataDir,privateKey);
 for(const tenant of ['alpha','beta'])source.put({id:'admin',tenant},'identity_access','subject',{id:'subject',epoch:0,disabled:false});
 const backupDir=join(root,'backup'),anchor=await createVaultBackup({dataDir,backupDir,privateKey,publicKey});
 const latest=await createVaultRecoveryFrontier({dataDir,privateKey,publicKey,anchor,config:original});source.close();
 const restore=async(name,activate=true)=>(await restoreVaultBackup({backupDir,restoreDir:join(root,name),privateKey,publicKey,anchor,
  ...(activate?{frontier:latest.frontier,frontierAnchor:latest.anchor,config:original}:{})})).restoredDirectory;
 const dir=await restore('restored');
 // Starts the vault service, runs a check against it and stops it again.
 const run=async(config,check=()=>{},at=dir)=>{const service=createService({dataDir:at,key:privateKey,config});try{return await check(service);}
  finally{service.store.close();}};
 const start=(config,at=dir)=>{createService({dataDir:at,key:privateKey,config}).store.close();};
 const rebind=(currentConfig,config,reason='CHG-1 rotate a leaked token',at=dir)=>rebindRecoveryConfig({dataDir:at,key:privateKey,currentConfig,config,reason});
 return {root,dir,privateKey,publicKey,restore,run,start,rebind};
}
// The rebinding rows are part of each tenant's signed, verifiable export.
const rebindingRows=(service,tenant)=>{
 const bundle=service.store.bundle(tenant);verifyBundle(bundle,service.store.publicKey);
 return bundle.records.filter(row=>row.type==='recovery_config_rebinding').map(row=>row.payload);
};
const overview=(service,secret)=>service.handle('GET',new URL('http://local/api/overview'),{authorization:'Bearer '+secret},'');

test('S8: a rotated token or an added principal starts after a signed, pinned rebinding that every restored ledger records',async t=>{
 const f=await fixture(t);f.start(original);
 assert.throws(()=>f.start(rotated),/config binding changed/,'an unrecorded token rotation is refused');
 const first=f.rebind(original,rotated);
 assert.equal(first.sequence,1);assert.equal(first.previousConfigHash,digest(original));assert.equal(first.configHash,digest(rotated));
 assert.equal(first.record,configRebindingPath(f.dir));assert.equal(first.externalPin,configRebindingPinPath(f.dir));
 assert.throws(()=>f.start(original),/config binding changed/,'the restore-time configuration no longer starts');
 await f.run(rotated,async service=>{
  for(const tenant of ['alpha','beta'])assert.deepEqual(rebindingRows(service,tenant).map(row=>[row.sequence,row.previousConfigHash,row.configHash,row.reason]),
   [[1,digest(original),digest(rotated),'CHG-1 rotate a leaked token']]);
  assert.ok(await overview(service,token('R')));await assert.rejects(overview(service,token('r')),error=>error.status===401);
 });
 await f.run(rotated,service=>assert.equal(rebindingRows(service,'alpha').length,1,'a restart records nothing twice'));
 const second=f.rebind(rotated,extended,'CHG-2 add an auditor');assert.equal(second.sequence,2);
 await f.run(extended,async service=>{
  assert.deepEqual(rebindingRows(service,'beta').map(row=>row.sequence),[1,2]);assert.ok(await overview(service,token('a')));
 });
 const activation=assertRecoveryActivation({dataDir:f.dir,key:f.privateKey,config:extended});
 assert.deepEqual(activation.rebindings.map(entry=>entry.configHash),[digest(rotated),digest(extended)]);
 assert.deepEqual(activation.tenants,['alpha','beta']);
});

test('S8: a backup of a rebound vault restores and starts under the configuration bound at that restore',async t=>{
 const f=await fixture(t);f.rebind(original,rotated);f.start(rotated);
 const backupDir=join(f.root,'second-backup'),keys={privateKey:f.privateKey,publicKey:f.publicKey};
 const anchor=await createVaultBackup({dataDir:f.dir,backupDir,...keys});
 const latest=await createVaultRecoveryFrontier({dataDir:f.dir,...keys,anchor,config:rotated});
 const again=(await restoreVaultBackup({backupDir,restoreDir:join(f.root,'second-restore'),...keys,anchor,frontier:latest.frontier,
  frontierAnchor:latest.anchor,config:rotated})).restoredDirectory;
 assert.equal(existsSync(configRebindingPath(again)),false,'rebinding files belong to one restoration and are not part of a backup');
 await f.run(rotated,service=>{
  const rows=service.store.bundle('alpha').records.filter(row=>['recovery_restore','recovery_config_rebinding'].includes(row.type)).map(row=>row.type);
  assert.deepEqual(rows,['recovery_restore','recovery_config_rebinding','recovery_restore']);
 },again);
 assert.throws(()=>f.start(original,again),/config binding changed/);
 f.rebind(rotated,extended,'CHG-11 add an auditor',again);f.start(extended,again);
});

test('S8: rebinding needs the bound configuration, a change, a reason, valid credentials and an activated restore',async t=>{
 const f=await fixture(t);
 assert.throws(()=>f.rebind(rotated,extended),/config binding changed/,'the current configuration must be the bound one');
 assert.throws(()=>f.rebind(original,original),/already bound/);
 assert.throws(()=>f.rebind(original,rotated,' '),/reason/);
 assert.throws(()=>f.rebind(original,{principals:[{id:'x',tenant:'alpha',role:'auditor',token:'short'}]}),/invalid credentials/);
 assert.throws(()=>f.rebind(original,{principals:[...original.principals,{...original.principals[0],id:'copy'}]}),/invalid credentials/);
 assert.equal(existsSync(configRebindingPath(f.dir)),false,'a refusal writes nothing');
 assert.equal(existsSync(configRebindingPinPath(f.dir)),false);
 const quarantined=await f.restore('quarantined',false);
 assert.throws(()=>f.rebind(original,rotated,'CHG-3',quarantined),/snapshot quarantined/);
 mkdirSync(join(f.root,'fresh'));assert.throws(()=>f.rebind(original,rotated,'CHG-4',join(f.root,'fresh')),/no restoration marker/);
});

test('S8: tampered, unpinned, foreign or rolled-back rebinding records stop activation',async t=>{
 const f=await fixture(t),record=configRebindingPath(f.dir),pin=configRebindingPinPath(f.dir);f.rebind(original,rotated);
 const firstRecord=readFileSync(record),firstPin=readFileSync(pin),chain=JSON.parse(firstRecord);
 chain.entries[0].configHash=digest(extended);writeFileSync(record,JSON.stringify(chain));
 assert.throws(()=>f.start(extended),/config rebinding signature/);writeFileSync(record,firstRecord);
 rmSync(pin);for(const config of [original,rotated])assert.throws(()=>f.start(config),/not pinned/);writeFileSync(pin,firstPin);
 rmSync(record);for(const config of [original,rotated])assert.throws(()=>f.start(config),/record missing/);writeFileSync(record,firstRecord);
 const other=await f.restore('other');f.rebind(original,rotated,'CHG-5',other);
 writeFileSync(pin,readFileSync(configRebindingPinPath(other)));assert.throws(()=>f.start(rotated),/pin invalid/);writeFileSync(pin,firstPin);
 writeFileSync(record,readFileSync(configRebindingPath(other)));assert.throws(()=>f.start(rotated),/another restoration/);writeFileSync(record,firstRecord);
 f.start(rotated);f.rebind(rotated,extended,'CHG-6 add an auditor');f.start(extended);
 // The ledger recorded rebinding 2: an older, consistently pinned pair or no rebinding files at all is a rollback.
 writeFileSync(record,firstRecord);writeFileSync(pin,firstPin);assert.throws(()=>f.start(rotated),/config rebinding rollback/);
 rmSync(record);rmSync(pin);assert.throws(()=>f.start(original),/config rebinding rollback/);
});

test('S8: an interrupted rebinding keeps the vault stopped until the same command is rerun',async t=>{
 const f=await fixture(t),pin=configRebindingPinPath(f.dir);f.rebind(original,rotated);f.start(rotated);
 const pinned=readFileSync(pin);f.rebind(rotated,extended,'CHG-7 add an auditor');writeFileSync(pin,pinned);
 for(const config of [rotated,extended])assert.throws(()=>f.start(config),/not pinned; rerun/);
 assert.throws(()=>f.rebind(rotated,reduced,'CHG-8 other change'),/unpinned rebinding to another configuration is pending/);
 const resumed=f.rebind(rotated,extended,'CHG-7 add an auditor');
 assert.equal(resumed.completedInterruptedRun,true);assert.equal(resumed.sequence,2);
 await f.run(extended,service=>assert.deepEqual(rebindingRows(service,'alpha').map(row=>row.reason),['CHG-1 rotate a leaked token','CHG-7 add an auditor']));
});

test('S8: the rebind command checks the pinned key, needs a reason and prints no credentials',async t=>{
 const f=await fixture(t),path=name=>join(f.root,name),relativePath=file=>relative(process.cwd(),file);
 writeFileSync(path('private.pem'),f.privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600});
 writeFileSync(path('public.pem'),f.publicKey.export({format:'pem',type:'spki'}));
 writeFileSync(path('other.pem'),generateKeyPairSync('ed25519').publicKey.export({format:'pem',type:'spki'}));
 writeFileSync(path('current.json'),JSON.stringify(original));writeFileSync(path('next.json'),'﻿'+JSON.stringify(rotated));
 const args=(publicKey='public.pem')=>['rebind',f.dir,path('private.pem'),path(publicKey),path('current.json'),path('next.json')];
 const missing=await cli(args());assert.notEqual(missing.code,0);assert.match(missing.stderr,/Usage: rebind/);
 const wrongKey=await cli([...args('other.pem'),'--reason','CHG-9']);assert.notEqual(wrongKey.code,0);assert.match(wrongKey.stderr,/pinned public key/);
 const foreign=await cli([...args(),'--accept-loss','x']);assert.notEqual(foreign.code,0);assert.match(foreign.stderr,/not an option of rebind/);
 assert.equal(existsSync(configRebindingPath(f.dir)),false);
 const done=await cli(['rebind',...args().slice(1).map(relativePath),'--reason','CHG-9 rotate the alpha reviewer token']);
 assert.equal(done.code,0,done.stderr);const output=JSON.parse(done.stdout);
 assert.equal(output.rebound,true);assert.equal(output.sequence,1);assert.equal(output.configHash,digest(rotated));
 assert.equal(done.stdout.includes(token('R')),false);assert.equal(done.stdout.includes(token('r')),false);
 f.start(rotated);
});

test('S8: rebinding rows join the transparency log of an enforce-mode vault restored into a new epoch',async t=>{
 const f=await transparencyFixture(t),source=await f.open('enforce'),config={principals};f.write(source,'alpha',3);await source.transparency.pump();
 const backupDir=join(f.root,'backup'),keys={privateKey:f.privateKey,publicKey:f.publicKey};
 const anchor=await createVaultBackup({dataDir:f.dataDir,backupDir,...keys});
 const old={origin:BASE,mode:'enforce',witnesses:[{vkey:f.w.vkey,url:f.ws.url}],intervalMs:100,timeoutMs:2000},next='vault.test/evidscope-e2';
 const latest=await createVaultRecoveryFrontier({dataDir:f.dataDir,...keys,anchor,config,transparency:old});await f.close(source);
 const dir=join(f.root,'epoch'),receipt=await restoreVaultBackup({backupDir,restoreDir:dir,...keys,anchor,frontier:latest.frontier,frontierAnchor:latest.anchor,
  config,transparency:{config:{...old,origin:next},frontierTransparency:latest.transparency}});
 assert.equal(receipt.activationAccepted,true);f.w.addLog(T.headsOrigin(next),T.logVkey(T.headsOrigin(next),f.publicKey));
 const rotatedConfig={principals:principals.map(p=>p.tenant==='alpha'?{...p,token:token('A')}:p)};
 rebindRecoveryConfig({dataDir:dir,key:f.privateKey,currentConfig:config,config:rotatedConfig,reason:'CHG-10 rotate the alpha admin token'});
 const cfg=f.config('enforce',{dir,origin:next});
 for(let start=0;start<2;start++){
  const probe=await probeTransparency({dataDir:dir,key:f.privateKey,config:cfg});
  const service=createService({dataDir:dir,key:f.privateKey,config:rotatedConfig,transparency:{config:cfg,probe}});
  try{
   assert.equal(service.transparency.status().startup.ok,true);await service.transparency.pump();
   const call=path=>service.handle('GET',new URL(path,'http://local'),{authorization:'Bearer '+token('A')},'');
   const exported=await call('/api/export');assert.equal(exported.records.filter(row=>row.type==='recovery_config_rebinding').length,1);
   verifyBundle(exported,f.publicKey,undefined,{transparency:{witnesses:[f.w.vkey],quorum:1,originBase:BASE,require:true}});
   const integrity=await call('/api/integrity');assert.equal(integrity.valid,true,integrity.error);
  }finally{await service.transparency.stop();service.store.close();}
 }
});
