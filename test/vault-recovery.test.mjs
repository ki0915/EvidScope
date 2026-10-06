import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,createCipheriv,createDecipheriv,randomBytes,randomUUID,sign,verify} from 'node:crypto';
import {mkdtempSync,mkdirSync,readFileSync,writeFileSync,existsSync,symlinkSync,unlinkSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {Store} from '../src/store.mjs';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createService} from '../src/service.mjs';
import {createVaultBackup,restoreVaultBackup} from '../src/vault-recovery.mjs';
import {canonical,digest,mac} from '../src/crypto.mjs';
import {harness} from './harness.mjs';

const requirements=JSON.parse(readFileSync('data/requirements.json','utf8'));
const system={id:'credit',name:'합성 대출 심사',owner:'감사팀',purpose:'대출 심사 보조',role:'deployer',krRoles:['deployer'],markets:['KR'],domain:'credit',generative:false,highImpact:'candidate',supplierId:'supplier-a',modelId:'credit-score',modelVersion:'v1',suppliedModelVersion:'v1',suppliedPurpose:'대출 심사 보조',substantialModification:false};
function bundle(text='합성 근거 원본',id='bundle'){const data=Buffer.from(text);return {id,systemId:'credit',synthetic:true,supplierId:'supplier-a',modelId:'credit-score',modelVersion:'v1',purpose:system.purpose,testScope:'합성 시험',measures:['KR-34-RISK'],documents:[{id:'doc',name:'근거.txt',sha256:createHash('sha256').update(data).digest('hex'),contentBase64:data.toString('base64')}]};}
async function fixture(t){
 const root=mkdtempSync(join(tmpdir(),'evidscope-recovery-')),data=join(root,'data'),{privateKey,publicKey}=generateKeyPairSync('ed25519');
 const principals=['alpha','beta'].flatMap(tenant=>[{id:tenant+'-r',tenant,role:'reviewer',token:(tenant+'r').repeat(12)},{id:tenant+'-s',tenant,role:'source',kind:'agent',token:(tenant+'s').repeat(12),hmacSecret:'hmac-'+tenant}]);
 const config={principals},service=createService({dataDir:data,key:privateKey,config,requirements});t.after(()=>service.store.close());
 const call=(path,body,tenant='alpha')=>service.handle(body===undefined?'GET':'POST',new URL(path,'http://localhost'),{authorization:'Bearer '+principals.find(p=>p.tenant===tenant&&p.role==='reviewer').token},body===undefined?'':JSON.stringify(body));
 for(const tenant of ['alpha','beta']){await call('/api/governance/systems',system,tenant);await call('/api/governance/bundles',bundle(tenant+' 합성 문서'),tenant);}
 const source=principals.find(p=>p.role==='source'),body=JSON.stringify({id:'event-1',actionId:'a-1',traceId:'t-1',kind:'intent',occurredAt:new Date().toISOString(),note:'합성 수집 원본'}),stamp=String(Date.now()),nonce=randomUUID();
 await service.handle('POST',new URL('/api/ingest','http://localhost'),{authorization:'Bearer '+source.token,'x-evid-timestamp':stamp,'x-evid-nonce':nonce,'x-evid-signature':mac(source.hmacSecret,stamp,nonce,body)},body);
 return {root,data,privateKey,publicKey,config,service,call,options:{dataDir:data,backupDir:join(root,'backup'),privateKey,publicKey},restore:(backupDir,anchor,restoreDir=join(root,'restored'))=>restoreVaultBackup({backupDir,restoreDir,privateKey,publicKey,anchor})};
}

test('online WAL snapshot restores both tenants, historic documents, signed report and exact evidence',async t=>{
 const f=await fixture(t);const report=await f.call('/api/governance/finance/report',{systemId:'credit'});
 await f.call('/api/governance/bundles',bundle('alpha 합성 변경 문서'));
 const anchor=await createVaultBackup(f.options);
 const manifest=JSON.parse(readFileSync(join(f.options.backupDir,'manifest.json')));
 assert.equal(manifest.files.filter(x=>x.path.startsWith('finance-documents/')).length,3);
 assert.ok(!readFileSync(join(f.options.backupDir,'evidence.db.enc')).includes(Buffer.from('SQLite format')));
 assert.ok(!existsSync(join(f.options.backupDir,'.snapshot.db')));
 assert.equal(manifest.files.some(x=>/pem|config/.test(x.path)),false);
 // The live source keeps accepting changes after the snapshot is sealed.
 await f.call('/api/governance/systems',{...system,modelVersion:'v2'});
 const receipt=await f.restore(f.options.backupDir,anchor);assert.equal(receipt.documents,3);assert.equal(receipt.rollbackChecked,true);assert.equal(receipt.servicesStarted,false);
 const restored=createService({dataDir:receipt.restoredDirectory,key:f.privateKey,config:f.config,requirements});t.after(()=>restored.store.close());
 assert.equal(restored.store.get('alpha','system','credit').modelVersion,'v1');
 assert.equal(restored.store.events('alpha').length,1);assert.equal(restored.store.events('beta').length,0);
 const saved=restored.store.get('alpha','finance_report',report.id);assert.deepEqual(saved,report);assert.ok(verify(null,Buffer.from(canonical(saved.snapshot)),f.publicKey,Buffer.from(saved.signature,'base64')));
 const original=f.service.store.events('alpha');assert.deepEqual(restored.store.events('alpha'),original);
 const restoredApi=path=>restored.handle('GET',new URL(path,'http://localhost'),{authorization:'Bearer '+f.config.principals[0].token});
 const exported=await restoredApi('/api/governance/bundles/bundle/export');assert.equal(Buffer.from(exported.documents[0].contentBase64,'base64').toString(),'alpha 합성 변경 문서');
});

test('ciphertext tamper, extra members and stale independent anchors fail before publication',async t=>{
 const f=await fixture(t),anchor=await createVaultBackup(f.options);
 await f.call('/api/governance/systems',{...system,modelVersion:'v2'});
 const newer=await createVaultBackup({...f.options,backupDir:join(f.root,'newer')});
 await assert.rejects(f.restore(f.options.backupDir,newer),/anchor mismatch/);assert.equal(existsSync(join(f.root,'restored')),false);
 const cipher=join(f.options.backupDir,'evidence.db.enc'),bytes=readFileSync(cipher);bytes[3]^=1;writeFileSync(cipher,bytes);
 await assert.rejects(f.restore(f.options.backupDir,anchor),/digest mismatch/);assert.equal(existsSync(join(f.root,'restored')),false);
 const extra=join(f.root,'newer','unlisted');writeFileSync(extra,'extra');await assert.rejects(f.restore(join(f.root,'newer'),newer),/unlisted/);
});

test('wrong vault key, forged manifest and absent external anchor are rejected',async t=>{
 const f=await fixture(t),anchor=await createVaultBackup(f.options),wrong=generateKeyPairSync('ed25519');
 await assert.rejects(restoreVaultBackup({backupDir:f.options.backupDir,restoreDir:join(f.root,'wrong'),privateKey:wrong.privateKey,publicKey:f.publicKey,anchor}),/trust key/);
 await assert.rejects(f.restore(f.options.backupDir,undefined),/anchor mismatch/);
 const path=join(f.options.backupDir,'manifest.json'),manifest=JSON.parse(readFileSync(path));manifest.tenants[0].retainedEvents=500;writeFileSync(path,JSON.stringify(manifest));
 await assert.rejects(f.restore(f.options.backupDir,anchor),/signature invalid/);
});

test('forged object projections cannot be certified by a new backup',async t=>{
 const f=await fixture(t);f.service.store.db.prepare('UPDATE objects SET body=? WHERE tenant=? AND type=?').run(JSON.stringify({...system,modelVersion:'forged'}),'alpha','system');
 await assert.rejects(createVaultBackup(f.options),/Object projection/);assert.equal(existsSync(join(f.options.backupDir,'manifest.json')),false);assert.equal(existsSync(join(f.options.backupDir,'.snapshot.db')),false);
});

test('actions-only tenants cannot be omitted from whole-vault backup verification',async t=>{
 const f=await fixture(t);
 f.service.store.db.prepare('INSERT INTO actions(tenant,id,version,analyzed) VALUES(?,?,?,?)').run('orphan-tenant','forged-action',1,0);
 await assert.rejects(createVaultBackup(f.options),/Action projection differs/);
 assert.equal(existsSync(join(f.options.backupDir,'manifest.json')),false);
 assert.equal(existsSync(join(f.options.backupDir,'.snapshot.db')),false);
});

test('a signed legacy archive omitting an actions-only tenant fails restore before publication',async t=>{
 const root=mkdtempSync(join(tmpdir(),'evidscope-recovery-orphan-')),dataDir=join(root,'data'),backupDir=join(root,'backup'),restoreDir=join(root,'restored'),{privateKey,publicKey}=generateKeyPairSync('ed25519');
 const store=new Store(dataDir,privateKey);store.close();
 const anchor=await createVaultBackup({dataDir,backupDir,privateKey,publicKey}),manifestFile=join(backupDir,'manifest.json'),manifest=JSON.parse(readFileSync(manifestFile)),hash=bytes=>createHash('sha256').update(bytes).digest('hex');
 // Model a backup sealed by the old inventory: a valid signature and ciphertext,
 // but an unsigned tenant projection that was absent from its checkpoint set.
 const encryption=createHash('sha256').update('evidscope-vault-backup-encryption-v1').update(privateKey.export({format:'der',type:'pkcs8'})).digest(),aad=Buffer.from(manifest.format),encryptedFile=join(backupDir,'evidence.db.enc');
 const decipher=createDecipheriv('aes-256-gcm',encryption,Buffer.from(manifest.database.iv,'base64'));decipher.setAAD(aad);decipher.setAuthTag(Buffer.from(manifest.database.tag,'base64'));
 const plaintextFile=join(root,'legacy-snapshot.db');writeFileSync(plaintextFile,Buffer.concat([decipher.update(readFileSync(encryptedFile)),decipher.final()]));
 const db=new DatabaseSync(plaintextFile);db.prepare('INSERT INTO actions(tenant,id,version,analyzed) VALUES(?,?,?,?)').run('orphan-tenant','forged-action',1,0);db.close();
 const bytes=readFileSync(plaintextFile),iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',encryption,iv);cipher.setAAD(aad);const encrypted=Buffer.concat([cipher.update(bytes),cipher.final()]);writeFileSync(encryptedFile,encrypted);unlinkSync(plaintextFile);
 manifest.database={...manifest.database,iv:iv.toString('base64'),tag:cipher.getAuthTag().toString('base64'),plaintextSha256:hash(bytes)};
 const inventory=manifest.files.find(file=>file.path==='evidence.db.enc');inventory.bytes=encrypted.length;inventory.sha256=hash(encrypted);
 const {signature,...statement}=manifest;manifest.signature=sign(null,Buffer.from(canonical(statement)),privateKey).toString('base64');writeFileSync(manifestFile,JSON.stringify(manifest));
 await assert.rejects(restoreVaultBackup({backupDir,restoreDir,privateKey,publicKey,anchor:{...anchor,manifestSha256:digest(manifest)}}),/Tenant set differs from independent checkpoints/);
 assert.equal(existsSync(restoreDir),false);
});

test('missing source or archived document fails recovery and never leaves plaintext staging files',async t=>{
 const f=await fixture(t),anchor=await createVaultBackup(f.options),manifest=JSON.parse(readFileSync(join(f.options.backupDir,'manifest.json'))),document=manifest.files.find(x=>x.path.startsWith('finance-documents/')).path;
 unlinkSync(join(f.options.backupDir,...document.split('/')));
 await assert.rejects(f.restore(f.options.backupDir,anchor),/inventory/);
 unlinkSync(join(f.data,...document.split('/')));
 await assert.rejects(createVaultBackup({...f.options,backupDir:join(f.root,'missing-document')}),/ENOENT/);
 assert.equal(existsSync(join(f.root,'missing-document','.snapshot.db')),false);
});

test('SQL tenant relabeling and event index tampering cannot be sealed into a valid backup',async t=>{
 const f=await fixture(t);
 f.service.store.db.exec('DROP TRIGGER immutable_update');
 f.service.store.db.prepare('UPDATE ledger SET tenant=? WHERE tenant=?').run('relabelled','beta');
 f.service.store.db.prepare('UPDATE checkpoints SET tenant=? WHERE tenant=?').run('relabelled','beta');
 f.service.store.db.prepare('UPDATE objects SET tenant=? WHERE tenant=?').run('relabelled','beta');
 await assert.rejects(createVaultBackup(f.options),/tenant|checkpoint/i);
 const other=await fixture(t);other.service.store.db.prepare('UPDATE events SET action_id=? WHERE tenant=?').run('another-action','alpha');
 await assert.rejects(createVaultBackup(other.options),/Event (index|projection)/);
});

test('development event content, deletion, and index tampering fail signed snapshot verification',async t=>{
 for(const change of ['content','delete','index'])await t.test(change,async t=>{
  const f=await fixture(t),e={tenant:'alpha',source:'alpha-s',eventId:'dev1',runId:'run1',occurredAt:new Date().toISOString(),receivedAt:new Date().toISOString(),fingerprint:'fixture',status:'failed'};
  f.service.store.transaction(()=>{f.service.store.append('alpha','development_run_event',e,'alpha-s');f.service.store.db.prepare('INSERT INTO development_run_events VALUES(?,?,?,?,?,?,?,?)').run(e.tenant,e.source,e.eventId,e.runId,e.occurredAt,e.receivedAt,e.fingerprint,JSON.stringify(e));});
  const good=await createVaultBackup({...f.options,backupDir:join(f.root,'good')});assert.equal((await f.restore(join(f.root,'good'),good)).tenants.find(t=>t.tenant==='alpha').developmentEvents,1);
  if(change==='content')f.service.store.db.prepare('UPDATE development_run_events SET body=?').run(JSON.stringify({...e,status:'completed'}));
  if(change==='delete')f.service.store.db.exec('DELETE FROM development_run_events');
  if(change==='index')f.service.store.db.prepare('UPDATE development_run_events SET run_id=?').run('forged-run');
  await assert.rejects(createVaultBackup(f.options),/Development/);
 });
});

test('mixed-case development IDs use identical ordering for signed and SQL records',async t=>{
 const f=await fixture(t);
 for(const id of ['Z','a']){const e={tenant:'alpha',source:'alpha-s',eventId:id,runId:'run1',occurredAt:new Date().toISOString(),receivedAt:new Date().toISOString(),fingerprint:'fixture-'+id,status:'failed'};
  f.service.store.transaction(()=>{f.service.store.append('alpha','development_run_event',e,'alpha-s');f.service.store.db.prepare('INSERT INTO development_run_events VALUES(?,?,?,?,?,?,?,?)').run(e.tenant,e.source,e.eventId,e.runId,e.occurredAt,e.receivedAt,e.fingerprint,JSON.stringify(e));});}
 const anchor=await createVaultBackup(f.options),receipt=await f.restore(f.options.backupDir,anchor);assert.equal(receipt.tenants.find(t=>t.tenant==='alpha').developmentEvents,2);
});

test('restoration never overwrites an existing directory or crosses a symlink',async t=>{
 const f=await fixture(t),anchor=await createVaultBackup(f.options),existing=join(f.root,'existing');mkdirSync(existing);writeFileSync(join(existing,'keep.txt'),'preserved');
 await assert.rejects(f.restore(f.options.backupDir,anchor,existing),/new directory/);assert.equal(readFileSync(join(existing,'keep.txt'),'utf8'),'preserved');
 const link=join(f.root,'link');symlinkSync(existing,link,process.platform==='win32'?'junction':'dir');
 await assert.rejects(f.restore(f.options.backupDir,anchor,join(link,'escape')),/Symlink/);assert.equal(existsSync(join(existing,'escape')),false);
});

test('deleted event keys stay deleted after snapshot recovery',async t=>{
 const f=await fixture(t),p={id:'synthetic-admin',tenant:'alpha'};
 // A pre-existing signed disposition fixture, not an authorization bypass test.
 f.service.store.transaction(()=>{const key=f.service.store.db.prepare('SELECT key_id,seq FROM event_keys WHERE tenant=?').get('alpha'),event=f.service.store.db.prepare('SELECT action_id FROM events WHERE tenant=?').get('alpha');f.service.store.db.prepare('DELETE FROM event_keys WHERE tenant=?').run('alpha');f.service.store.db.prepare('DELETE FROM events WHERE tenant=?').run('alpha');f.service.store.db.prepare('UPDATE actions SET version=version+1 WHERE tenant=? AND id=?').run('alpha',event.action_id);f.service.store.append('alpha','retention_disposition',{keyIds:[key.key_id],sequences:[key.seq]},p.id);});
 const anchor=await createVaultBackup(f.options),receipt=await f.restore(f.options.backupDir,anchor),db=new DatabaseSync(join(receipt.restoredDirectory,'evidence.db'),{readOnly:true});t.after(()=>db.close());
 assert.equal(db.prepare('SELECT count(*) n FROM event_keys').get().n,0);assert.equal(db.prepare('SELECT count(*) n FROM receipts').get().n,1);
});

test('actual restored HTTP vault serves supplier bytes and preserves tenant access boundaries',async t=>{
 const h=await harness();t.after(()=>h.close());
 assert.equal((await h.api('/api/governance/systems',{role:'reviewer',body:system})).status,200);
 assert.equal((await h.api('/api/governance/bundles',{role:'reviewer',body:bundle()})).status,200);
 const privateKey=readFileSync(join(h.dir,'signing-private.pem')),backupDir=join(h.dir,'backup'),restoreDir=join(h.dir,'restored');
 const anchor=await createVaultBackup({dataDir:join(h.dir,'data'),backupDir,privateKey,publicKey:h.publicKey});
 await restoreVaultBackup({backupDir,restoreDir,privateKey,publicKey:h.publicKey,anchor});
 const restored=await h.start('vault',{DATA_DIR:restoreDir});
 const document=await h.api('/api/governance/bundles/bundle/export',{base:restored.url});assert.equal(document.status,200);assert.equal(document.body.documents[0].contentBase64,bundle().documents[0].contentBase64);
 assert.equal((await h.api('/api/governance/bundles/bundle/export',{base:restored.url,tenant:'beta'})).status,404);
 assert.equal((await h.api('/api/integrity',{base:restored.url})).body.valid,true);
});

test('operator CLI creates an external anchor and restores without copying credentials',async t=>{
 const f=await fixture(t),key=join(f.root,'key.pem'),publicKey=join(f.root,'public.pem'),anchor=join(f.root,'independent-anchor.json'),restore=join(f.root,'cli-restored');
 writeFileSync(key,f.privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600});writeFileSync(publicKey,f.publicKey.export({type:'spki',format:'pem'}));
 const run=promisify(execFile),options={encoding:'utf8',windowsHide:true};
 const created=JSON.parse((await run(process.execPath,['scripts/vault-backup.mjs','create',f.data,f.options.backupDir,key,publicKey,anchor],options)).stdout);assert.equal(created.privateKeyIncluded,false);
 const recovered=JSON.parse((await run(process.execPath,['scripts/vault-backup.mjs','restore',f.options.backupDir,restore,key,publicKey,anchor],options)).stdout);assert.equal(recovered.verified,true);assert.equal(existsSync(join(restore,'config.json')),false);
 await assert.rejects(run(process.execPath,['scripts/vault-backup.mjs','create',f.data,join(f.root,'another-backup'),key,publicKey,anchor],options));assert.equal(existsSync(join(f.root,'another-backup')),false);
});
