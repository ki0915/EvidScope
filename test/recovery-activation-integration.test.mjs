import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,verify} from 'node:crypto';
import {mkdtempSync,mkdirSync,readFileSync,writeFileSync,existsSync,rmSync,symlinkSync} from 'node:fs';
import {join,resolve,relative,dirname} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {Store} from '../src/store.mjs';
import {canonical,digest,verifyBundle} from '../src/crypto.mjs';
import {createRetention} from '../src/retention.mjs';
import {createIdentityState} from '../src/identity-state.mjs';
import {createService} from '../src/service.mjs';
import {createVaultBackup,createVaultRecoveryFrontier,restoreVaultBackup} from '../src/vault-recovery.mjs';
import {recoveryPinPath,assertRecoveryActivation} from '../src/recovery-state.mjs';

const execute=promisify(execFile),json=path=>JSON.parse(readFileSync(path,'utf8'));
const cli=async args=>{try{return {...await execute(process.execPath,['scripts/vault-backup.mjs',...args],{windowsHide:true,timeout:15000,maxBuffer:1024*1024}),code:0};}catch(error){return {code:error.code,stdout:error.stdout,stderr:error.stderr};}};
async function fixture(t){
 mkdirSync('.test-runs',{recursive:true});const root=resolve(mkdtempSync(join('.test-runs','recovery-activation-'))),dataDir=join(root,'data'),backupDir=join(root,'backup'),{privateKey,publicKey}=generateKeyPairSync('ed25519'),source=new Store(dataDir,privateKey),config={principals:[]};
 t.after(()=>{source.close();rmSync(root,{recursive:true,force:true});});
 for(const tenant of ['alpha','beta'])source.transaction(()=>{
  source.put({id:'admin',tenant},'identity_access','same-subject',{id:'same-subject',epoch:0,disabled:false});
  source.put({id:'reviewer-one',tenant},'retention_policy','current',{id:'current',version:1,retentionSeconds:1});
  const event={tenant,id:'same-event',source:'collector',actionId:'same-action',traceId:'trace',kind:'intent',occurredAt:'2000-01-01T00:00:00.000Z',receivedAt:'2000-01-01T00:00:00.000Z',fingerprint:digest(tenant),note:'SYNTHETIC-PRIVATE-CONTENT-'+tenant};
  const row=source.append(tenant,'event',event,event.source),saved={...event,seq:row.seq,hash:row.hash};
  source.projectionMutation(()=>{source.db.prepare('INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)').run(tenant,event.source,event.id,event.fingerprint,event.actionId,event.traceId,event.kind,event.receivedAt,JSON.stringify(saved));source.db.prepare('INSERT INTO receipts VALUES(?,?,?,?)').run(tenant,event.source,event.id,event.fingerprint);source.db.prepare('INSERT INTO actions VALUES(?,?,?,?)').run(tenant,event.actionId,1,0);});
 });
 const shared={privateKey,publicKey},archiveAnchor=await createVaultBackup({dataDir,backupDir,...shared}),archiveRecords=Object.fromEntries(['alpha','beta'].map(tenant=>[tenant,source.rawBundle(tenant).records]));
 const plans={};
 for(const tenant of ['alpha','beta']){
  const retention=createRetention(source),author={id:'reviewer-one',tenant,role:'reviewer'},approver={id:'reviewer-two',tenant,role:'reviewer'},admin={id:'admin',tenant,role:'admin'};
  const p=retention.handle(author,'POST','/api/retention/plans',{reason:'expired synthetic event'});assert.throws(()=>retention.handle(author,'POST','/api/retention/plans/'+p.id+'/approve',{reason:'self approval'}),/자신의/);
  retention.handle(approver,'POST','/api/retention/plans/'+p.id+'/approve',{reason:'independent review'});retention.handle(admin,'POST','/api/retention/plans/'+p.id+'/execute',{});plans[tenant]=source.get(tenant,'retention_plan',p.id);
  source.transaction(()=>source.put(admin,'identity_access','same-subject',{id:'same-subject',epoch:1,disabled:true,action:'disable',reason:'access withdrawn',changedBy:admin.id,changedAt:new Date().toISOString()}));
 }
 const paths={key:join(root,'private.pem'),public:join(root,'public.pem'),archive:join(root,'archive-anchor.json'),config:join(root,'config.json'),frontier:join(root,'frontier.json'),frontierAnchor:join(root,'frontier-anchor.json')};
 writeFileSync(paths.key,privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600});writeFileSync(paths.public,publicKey.export({format:'pem',type:'spki'}));writeFileSync(paths.archive,JSON.stringify(archiveAnchor));writeFileSync(paths.config,JSON.stringify(config));
 return {root,dataDir,backupDir,source,config,shared,archiveAnchor,archiveRecords,plans,paths};
}
function verifyAccepted(f,restoredDirectory,receipt,expectedFrontier){
 assert.equal(receipt.activationAccepted,true);assert.equal(receipt.activationStatus,'accepted');assert.equal(receipt.servicesStarted,false);assert.equal(receipt.frontierSha256,digest(expectedFrontier));
 const marker=json(join(restoredDirectory,'vault-restoration.json')),pin=json(recoveryPinPath(restoredDirectory)),{signature,...statement}=marker;
 assert.equal(marker.status,'accepted');assert.equal(marker.configHash,digest(f.config));assert.equal(marker.frontierSha256,digest(expectedFrontier));assert.equal(verify(null,Buffer.from(canonical(statement)),f.shared.publicKey,Buffer.from(signature,'base64')),true);
 assert.equal(receipt.activationPin,recoveryPinPath(restoredDirectory));assert.equal(pin.markerSha256,digest(marker));assert.equal(dirname(receipt.activationPin),dirname(restoredDirectory));assert.equal(pin.dataDir,resolve(restoredDirectory));
 const {signature:pinSignature,...pinStatement}=pin;assert.equal(verify(null,Buffer.from(canonical(pinStatement)),f.shared.publicKey,Buffer.from(pinSignature,'base64')),true);
 assertRecoveryActivation({dataDir:restoredDirectory,key:f.shared.privateKey,config:f.config});
 const service=createService({dataDir:restoredDirectory,key:f.shared.privateKey,config:f.config});
 try{for(const tenant of ['alpha','beta']){
  assert.equal(createIdentityState(service.store)({tenant,id:'same-subject'}).disabled,true);assert.equal(service.store.events(tenant).length,0);assert.equal(service.store.db.prepare('SELECT count(*) AS n FROM event_keys WHERE tenant=?').get(tenant).n,0);
  const b=service.store.bundle(tenant);assert.equal(verifyBundle(b,f.shared.publicKey).erasedEvents,1);service.store.checkActionProjection(tenant);assert.equal(service.store.db.prepare('SELECT version FROM actions WHERE tenant=?').get(tenant).version,2);
  assert.deepEqual(b.records.slice(0,f.archiveRecords[tenant].length),f.archiveRecords[tenant]);assert.deepEqual(service.store.get(tenant,'retention_plan',f.plans[tenant].id),f.plans[tenant]);
  const signedReceipt=b.records.find(row=>row.type==='event_receipt'),disposition=b.records.find(row=>row.type==='retention_disposition');assert(signedReceipt.seq<disposition.seq);assert.equal(disposition.payload.frontierHash,digest(expectedFrontier));assert.equal(service.store.db.prepare('SELECT count(*) AS n FROM receipts WHERE tenant=?').get(tenant).n,1);assert(b.records.some(row=>row.type==='recovery_restore'));
 }}finally{service.store.close();}
 return {marker,pin};
}

test('wrapper restores pre-erasure backup with latest two-person destruction and disabled access before service activation',async t=>{
 const f=await fixture(t),latest=await createVaultRecoveryFrontier({dataDir:f.dataDir,anchor:f.archiveAnchor,config:f.config,...f.shared}),restoredDirectory=join(f.root,'restored');
 if(process.platform==='win32')await assert.rejects(restoreVaultBackup({backupDir:f.backupDir,restoreDir:join(f.backupDir.toUpperCase(),'nested-restoration'),anchor:f.archiveAnchor,...f.shared}),/new directory outside the backup/);
 const receipt=await restoreVaultBackup({backupDir:f.backupDir,restoreDir:restoredDirectory,anchor:f.archiveAnchor,frontier:latest.frontier,frontierAnchor:latest.anchor,config:f.config,...f.shared});verifyAccepted(f,restoredDirectory,receipt,latest.frontier);
 // Accepted restoration history remains capturable in a subsequent real backup.
 const nextBackup=join(f.root,'next-backup'),nextAnchor=await createVaultBackup({dataDir:restoredDirectory,backupDir:nextBackup,...f.shared});
 const nextFrontier=await createVaultRecoveryFrontier({dataDir:restoredDirectory,anchor:nextAnchor,config:f.config,...f.shared});assert.equal(nextFrontier.frontier.tenants.flatMap(tenant=>tenant.erasedEvents).length,0);
 const pinPath=recoveryPinPath(restoredDirectory),pinBytes=readFileSync(pinPath);rmSync(pinPath);assert.throws(()=>createService({dataDir:restoredDirectory,key:f.shared.privateKey,config:f.config}),/external restoration pin missing/);writeFileSync(pinPath,pinBytes);
});

test('actual frontier and activation restore CLI commands preserve access, erasure and external restoration pin',async t=>{
 const f=await fixture(t),relativePath=path=>relative(process.cwd(),path),p=f.paths;
 if(process.platform==='win32'){
  const inside=join(f.dataDir.toUpperCase(),'forbidden-frontier.json'),rejected=await cli(['frontier',f.dataDir,p.key,p.public,p.archive,p.config,inside,p.frontierAnchor]);assert.notEqual(rejected.code,0);assert.match(rejected.stderr,/outside data and backup/);assert.equal(existsSync(inside),false);assert.equal(existsSync(p.frontierAnchor),false);
 }
 const captured=await cli(['frontier',...([f.dataDir,p.key,p.public,p.archive,p.config,p.frontier,p.frontierAnchor].map(relativePath))]);assert.equal(captured.code,0,captured.stderr);assert.equal(JSON.parse(captured.stdout).created,true);
 const restoredDirectory=join(f.root,'cli-restored'),restored=await cli(['restore',...([f.backupDir,restoredDirectory,p.key,p.public,p.archive,p.frontier,p.frontierAnchor,p.config].map(relativePath))]);assert.equal(restored.code,0,restored.stderr);
 const receipt=JSON.parse(restored.stdout);verifyAccepted(f,restoredDirectory,receipt,json(p.frontier));
 assert(!captured.stdout.includes('PRIVATE KEY'));assert(!restored.stdout.includes('SYNTHETIC-PRIVATE-CONTENT'));
});

test('frontier CLI rejects new output through symlink or junction parents without writing either destination',async t=>{
 const f=await fixture(t),actual=join(f.root,'actual-output'),link=join(f.root,'linked-output');mkdirSync(actual);symlinkSync(actual,link,process.platform==='win32'?'junction':'dir');
 for(const kind of ['frontier','anchor']){
  const frontier=kind==='frontier'?join(link,'new-frontier.json'):join(f.root,'new-frontier.json'),anchor=kind==='anchor'?join(link,'new-anchor.json'):join(f.root,'new-anchor.json');
  const result=await cli(['frontier',f.dataDir,f.paths.key,f.paths.public,f.paths.archive,f.paths.config,frontier,anchor]);assert.notEqual(result.code,0);assert.match(result.stderr,/symlink or junction/);assert.equal(existsSync(frontier),false);assert.equal(existsSync(anchor),false);assert.equal(existsSync(join(actual,'new-frontier.json')),false);assert.equal(existsSync(join(actual,'new-anchor.json')),false);
 }
});
