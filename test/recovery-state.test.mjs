import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {mkdtempSync,mkdirSync,readFileSync,writeFileSync,unlinkSync,copyFileSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {Store} from '../src/store.mjs';
import {createService} from '../src/service.mjs';
import {createVaultBackup,createVaultRecoveryFrontier,restoreVaultBackup} from '../src/vault-recovery.mjs';
import {assertRecoveryActivation} from '../src/recovery-state.mjs';

async function fixture(t){
 mkdirSync('.test-runs',{recursive:true});const root=mkdtempSync(resolve('.test-runs','recovery-activation-')),dataDir=join(root,'source'),{privateKey,publicKey}=generateKeyPairSync('ed25519'),config={principals:[]},store=new Store(dataDir,privateKey);t.after(()=>store.close());
 const p={tenant:'alpha',id:'admin'};store.put(p,'identity_access','bob',{id:'bob',epoch:0,disabled:false});
 const backupDir=join(root,'backup'),anchor=await createVaultBackup({dataDir,backupDir,privateKey,publicKey});
 store.put(p,'identity_access','bob',{id:'bob',epoch:1,disabled:true});
 const safety=await createVaultRecoveryFrontier({dataDir,privateKey,publicKey,anchor,config});
 const restore=async(name,activate=false)=>restoreVaultBackup({backupDir,restoreDir:join(root,name),privateKey,publicKey,anchor,...(activate?{frontier:safety.frontier,frontierAnchor:safety.anchor,config}:{})});
 const guard=dir=>assertRecoveryActivation({dataDir:dir,key:privateKey,config});return {root,config,privateKey,publicKey,restore,guard};
}

test('old snapshot is quarantined before service startup mutates its database; removing marker cannot enable it',async t=>{
 const f=await fixture(t),r=await f.restore('quarantined');assert.equal(r.verified,true);assert.equal(r.activationAccepted,false);
 const file=join(r.restoredDirectory,'evidence.db'),before=readFileSync(file);
 assert.throws(()=>createService({dataDir:r.restoredDirectory,key:f.privateKey,config:f.config}),/snapshot quarantined/);assert.deepEqual(readFileSync(file),before);
 unlinkSync(join(r.restoredDirectory,'vault-restoration.json'));assert.throws(()=>f.guard(r.restoredDirectory),/marker missing/);assert.deepEqual(readFileSync(file),before);
});

test('accepted restored access state survives restart and allows legitimate subsequent signed history',async t=>{
 const f=await fixture(t),r=await f.restore('accepted',true);assert.equal(r.activationAccepted,true);f.guard(r.restoredDirectory);
 const service=createService({dataDir:r.restoredDirectory,key:f.privateKey,config:f.config});
 assert.equal(service.store.get('alpha','identity_access','bob').disabled,true);service.store.append('alpha','audit_access',{operation:'post-restore-read'},'admin');service.store.close();f.guard(r.restoredDirectory);
});

test('changed credential config, tampered marker and rollback beneath accepted prefix cannot activate',async t=>{
 const f=await fixture(t),r=await f.restore('accepted',true),dir=r.restoredDirectory,file=join(dir,'vault-restoration.json'),original=readFileSync(file);
 assert.throws(()=>assertRecoveryActivation({dataDir:dir,key:f.privateKey,config:{...f.config,changed:true}}),/config binding/);
 const marker=JSON.parse(original);marker.status='quarantined';writeFileSync(file,JSON.stringify(marker));assert.throws(()=>f.guard(dir),/pin mismatch|marker signature/);writeFileSync(file,original);
 const old=await f.restore('old');copyFileSync(join(old.restoredDirectory,'evidence.db'),join(dir,'evidence.db'));assert.throws(()=>f.guard(dir),/rollback|lineage|binding/);
});

test('replacing both database and marker with an older signed state is rejected by the external restoration pin',async t=>{
 const f=await fixture(t),r=await f.restore('accepted',true),old=await f.restore('old');
 copyFileSync(join(old.restoredDirectory,'evidence.db'),join(r.restoredDirectory,'evidence.db'));
 unlinkSync(join(r.restoredDirectory,'vault-restoration.json'));
 assert.throws(()=>f.guard(r.restoredDirectory),/externally pinned restoration marker missing/);
 copyFileSync(join(old.restoredDirectory,'vault-restoration.json'),join(r.restoredDirectory,'vault-restoration.json'));
 assert.throws(()=>f.guard(r.restoredDirectory),/external restoration pin mismatch/);
});

test('an empty restored vault is also quarantined even after its marker is removed',async t=>{
 mkdirSync('.test-runs',{recursive:true});const root=mkdtempSync(resolve('.test-runs','recovery-empty-')),{privateKey,publicKey}=generateKeyPairSync('ed25519'),dataDir=join(root,'source'),backupDir=join(root,'backup'),store=new Store(dataDir,privateKey);store.close();
 const anchor=await createVaultBackup({dataDir,backupDir,privateKey,publicKey}),r=await restoreVaultBackup({backupDir,restoreDir:join(root,'restored'),privateKey,publicKey,anchor});
 unlinkSync(join(r.restoredDirectory,'vault-restoration.json'));assert.throws(()=>assertRecoveryActivation({dataDir:r.restoredDirectory,key:privateKey,config:{principals:[]}}),/marker missing/);
});
