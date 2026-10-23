import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,createDecipheriv,generateKeyPairSync,randomBytes,hkdfSync,sign} from 'node:crypto';
import {mkdtempSync,readFileSync,writeFileSync,rmSync,statSync,chmodSync,readdirSync,cpSync,mkdirSync,copyFileSync,existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,delimiter} from 'node:path';
import {createService} from '../src/service.mjs';
import {createKeyring,dataKeyId,readDataKeyFile,dataKeysFromEnv,PURPOSES,LEGACY_KEY_ID} from '../src/data-keys.mjs';
import {parseDocumentEnvelope} from '../src/document-envelope.mjs';
import {canonical,digest} from '../src/crypto.mjs';
import {createGovernanceDocumentStorage} from '../src/governance-documents.mjs';
import {createDocumentAdapter} from '../src/finance-evidence.mjs';
import {createVaultBackup,createVaultRecoveryFrontier,restoreVaultBackup} from '../src/vault-recovery.mjs';
import {initialize} from '../scripts/init.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex');
const requirements=JSON.parse(readFileSync(new URL('../data/requirements.json',import.meta.url),'utf8'));
const system={id:'credit',name:'Synthetic credit',owner:'reviewer',purpose:'Loan assistance',markets:['KR'],krRoles:['deployer'],generative:false,
 highImpact:'confirmed',supplierId:'supplier-a',modelId:'credit-score',modelVersion:'v1',suppliedModelVersion:'v1',suppliedPurpose:'Loan assistance',
 substantialModification:false};
const gov=(bytes,id='control')=>({id,systemId:'credit',name:'control.txt',mediaType:'text/plain',sha256:sha(bytes),contentBase64:bytes.toString('base64')});
const sup=(bytes)=>({id:'supplier',systemId:'credit',synthetic:true,supplierId:'supplier-a',modelId:'credit-score',modelVersion:'v1',purpose:system.purpose,
 testScope:'s',measures:['KR-34-RISK'],documents:[{id:'d',name:'s.txt',sha256:sha(bytes),contentBase64:bytes.toString('base64')}],reviewerNotes:'synthetic'});
function fixture(t){
 const dir=mkdtempSync(join(tmpdir(),'evidscope-data-key-')),{privateKey,publicKey}=generateKeyPairSync('ed25519');
 const principals=[{id:'alpha-reviewer',role:'reviewer',tenant:'alpha',token:'a'.repeat(40)}];
 const services=[];t.after(()=>{for(const s of services)try{s.store.close();}catch{}rmSync(dir,{recursive:true,force:true});});
 const boot=(extra={})=>{const s=createService({dataDir:join(dir,'data'),key:privateKey,config:{principals},requirements,...extra});services.push(s);return s;};
 const call=(s,path,body)=>s.handle(body===undefined?'GET':'POST',new URL(path,'http://local'),{authorization:'Bearer '+'a'.repeat(40)},
  body===undefined?'':JSON.stringify(body));
 return {dir,privateKey,publicKey,boot,call};
}

test('HKDF purpose keys are distinct, key ids are stable, legacy derivation is byte-identical to v1',()=>{
 const root=randomBytes(32),{privateKey}=generateKeyPairSync('ed25519'),ring=createKeyring({signingKey:privateKey,dataKey:root});
 const keys=Object.keys(PURPOSES).map(p=>ring.key(p,ring.currentKeyId).toString('hex'));assert.equal(new Set(keys).size,4);
 assert.match(dataKeyId(root),/^dk1-[a-f0-9]{32}$/);assert.equal(dataKeyId(root),ring.currentKeyId);
 assert.deepEqual(ring.key('governanceDocument',ring.currentKeyId),Buffer.from(hkdfSync('sha256',root,Buffer.alloc(0),
  Buffer.from('evidscope/data-key/v1/governance-document'),32)));
 const legacy=createHash('sha256').update('evidscope-governance-documents-v1').update(privateKey.export({type:'pkcs8',format:'der'})).digest();
 assert.deepEqual(ring.key('governanceDocument',LEGACY_KEY_ID),legacy);
 assert.notDeepEqual(ring.key('governanceDocument',ring.currentKeyId),legacy);
 assert.throws(()=>createKeyring({dataKey:root}).key('governanceDocument',LEGACY_KEY_ID),/signing private key/);
});

test('separated vault writes v2 envelopes the signing key alone cannot open (S2 PoC regression)',async t=>{
 const f=fixture(t),root=randomBytes(32),s=f.boot({dataKey:root}),doc=Buffer.from('TOP SECRET governance doc 900101-1234567');
 await f.call(s,'/api/governance/systems',system);await f.call(s,'/api/governance/documents',gov(doc));
  await f.call(s,'/api/governance/bundles',sup(Buffer.from('supplier')));
 const file=join(f.dir,'data','governance-documents',sha(Buffer.from('alpha')),sha(doc)+'.json'),env=JSON.parse(readFileSync(file,'utf8'));
 assert.deepEqual(Object.keys(env).sort(),['data','format','iv','kid','tag']);assert.equal(env.kid,dataKeyId(root));
  assert.equal(env.format,'evidscope-document-envelope-v2');
 const legacyMaster=createHash('sha256').update('evidscope-governance-documents-v1').update(f.privateKey.export({type:'pkcs8',format:'der'})).digest();
 assert.throws(()=>{const d=createDecipheriv('aes-256-gcm',legacyMaster,Buffer.from(env.iv,'base64'));d.setAAD(Buffer.from(`alpha:${sha(doc)}`));
  d.setAuthTag(Buffer.from(env.tag,'base64'));Buffer.concat([d.update(Buffer.from(env.data,'base64')),d.final()]);});
 assert.deepEqual(createGovernanceDocumentStorage(join(f.dir,'data'),createKeyring({dataKey:root})).read('alpha',sha(doc)),doc,'v2 read needs no signing key');
 const r=await f.call(s,'/api/integrity');assert.equal(r.valid,true,r.error);assert.equal(r.keySeparation.status,'separated');
  assert.deepEqual(r.keySeparation.documentFilesByKeyId,{[dataKeyId(root)]:2});
 // kid is authenticated: relabel the envelope with another configured kid => fail
 const other=randomBytes(32);s.store.close();const s2=f.boot({dataKey:root,previousDataKeys:[other]});
 writeFileSync(file,JSON.stringify({...env,kid:dataKeyId(other)}));assert.equal((await f.call(s2,'/api/integrity')).valid,false);
});

test('legacy vault upgraded in place: old files stay readable, new files use the data key, re-encryption completes migration',async t=>{
 const f=fixture(t),v1=Buffer.from('legacy v1'),v2=Buffer.from('separated v2');let s=f.boot();
 await f.call(s,'/api/governance/systems',system);await f.call(s,'/api/governance/documents',gov(v1));
 assert.equal((await f.call(s,'/api/integrity')).keySeparation.status,'not_separated');s.store.close();
 const root=randomBytes(32);s=f.boot({dataKey:root});await f.call(s,'/api/governance/documents',gov(v2));
 let r=await f.call(s,'/api/integrity');assert.equal(r.valid,true,r.error);assert.equal(r.keySeparation.status,'migration_pending');
  assert.deepEqual(r.keySeparation.documentFilesByKeyId,{[LEGACY_KEY_ID]:1,[dataKeyId(root)]:1});
 const storage=createGovernanceDocumentStorage(join(f.dir,'data'),createKeyring({signingKey:f.privateKey,dataKey:root}));
 assert.deepEqual(storage.reencrypt('alpha',sha(v1)),{changed:true,from:LEGACY_KEY_ID,to:dataKeyId(root)});
  assert.equal(storage.reencrypt('alpha',sha(v2)).changed,false);
 r=await f.call(s,'/api/integrity');assert.equal(r.keySeparation.status,'separated');
});

test('a vault refuses to start when a data key that sealed stored data is not configured',async t=>{
 const f=fixture(t),a=randomBytes(32),b=randomBytes(32);let s=f.boot({dataKey:a});
 await f.call(s,'/api/governance/systems',system);await f.call(s,'/api/governance/documents',gov(Buffer.from('x')));s.store.close();
 assert.throws(()=>f.boot({dataKey:b}),new RegExp(dataKeyId(a)));
 s=f.boot({dataKey:b,previousDataKeys:[a]});assert.equal((await f.call(s,'/api/integrity')).valid,true);
 assert.throws(()=>createService({dataDir:join(f.dir,'other'),key:f.privateKey,config:{profile:'enterprise',principals:[]}}),/DATA_KEY_FILE/);
});

test('v2 backups are sealed by the data key and need it to restore',async t=>{
 const f=fixture(t),root=randomBytes(32),s=f.boot({dataKey:root}),doc=Buffer.from('backup me');
 await f.call(s,'/api/governance/systems',system);await f.call(s,'/api/governance/documents',gov(doc));
 const out=mkdtempSync(join(tmpdir(),'evidscope-data-key-backup-'));t.after(()=>rmSync(out,{recursive:true,force:true}));
 const shared={privateKey:f.privateKey,publicKey:f.publicKey};
 const anchor=await createVaultBackup({dataDir:join(f.dir,'data'),backupDir:join(out,'b'),...shared,dataKey:root});
 const manifest=JSON.parse(readFileSync(join(out,'b','manifest.json'),'utf8'));
 assert.equal(manifest.format,'evidscope-vault-backup-v2');assert.equal(manifest.database.keyId,dataKeyId(root));
  assert.equal(manifest.database.kdf,'hkdf-sha256');
 await assert.rejects(restoreVaultBackup({backupDir:join(out,'b'),restoreDir:join(out,'r1'),...shared,anchor}),/not configured/);
 const receipt=await restoreVaultBackup({backupDir:join(out,'b'),restoreDir:join(out,'r2'),...shared,dataKey:root,anchor});assert.equal(receipt.verified,true);
  assert.equal(receipt.governanceDocuments,1);
 await assert.rejects(createVaultBackup({dataDir:join(f.dir,'data'),backupDir:join(out,'b2'),...shared}),/not configured/,
  'legacy-only keyring cannot verify v2 documents');
});

test('data key file loader enforces length and permissions; init generates a 0600 32-byte key',t=>{
 const dir=mkdtempSync(join(tmpdir(),'evidscope-data-key-file-'));t.after(()=>rmSync(dir,{recursive:true,force:true}));
 const file=join(dir,'k');writeFileSync(file,randomBytes(31),{mode:0o600});assert.throws(()=>readDataKeyFile(file),/32 raw bytes/);
 writeFileSync(file,randomBytes(32));chmodSync(file,0o644);if(process.platform!=='win32')assert.throws(()=>readDataKeyFile(file),/permissions/);
 chmodSync(file,0o440);assert.equal(readDataKeyFile(file).length,32);
 initialize(join(dir,'init'));const key=join(dir,'init','data-encryption.key');assert.equal(readFileSync(key).length,32);
  if(process.platform!=='win32')assert.equal(statSync(key).mode&0o777,0o600);
 assert.ok(readdirSync(join(dir,'init')).includes('signing-private.pem'));
});

test('offline migration re-encrypts legacy files, rotation retires the previous key id, then the old key can be dropped',async t=>{
 const {migrateDocuments}=await import('../scripts/data-key.mjs');
 const f=fixture(t),a=randomBytes(32),b=randomBytes(32),dataDir=join(f.dir,'data');let s=f.boot();
 await f.call(s,'/api/governance/systems',system);await f.call(s,'/api/governance/documents',gov(Buffer.from('g1')));
  await f.call(s,'/api/governance/bundles',sup(Buffer.from('s1')));s.store.close();
 let r=migrateDocuments({dataDir,signingKey:f.privateKey,dataKey:a});assert.deepEqual(r.reencryptedFrom,{[LEGACY_KEY_ID]:2});assert.equal(r.legacyRemaining,0);
 s=f.boot({dataKey:a});assert.equal((await f.call(s,'/api/integrity')).keySeparation.status,'separated');s.store.close();
 assert.throws(()=>f.boot({dataKey:b}),/not configured/);
 r=migrateDocuments({dataDir,signingKey:f.privateKey,dataKey:b,previousDataKeys:[a]});assert.deepEqual(r.reencryptedFrom,{[dataKeyId(a)]:2});
  assert.deepEqual(r.retiredKeyIds,[dataKeyId(a)]);
 s=f.boot({dataKey:b});const out=await f.call(s,'/api/integrity');assert.equal(out.valid,true,out.error);
  assert.deepEqual(out.keySeparation.documentFilesByKeyId,{[dataKeyId(b)]:2});
});

test('document envelope parser accepts only exact v1 and v2 shapes',()=>{
 const b64=n=>randomBytes(n).toString('base64'),kid=dataKeyId(randomBytes(32)),v2={format:'evidscope-document-envelope-v2',kid,iv:b64(12),tag:b64(16),
  data:b64(20)};
 assert.equal(parseDocumentEnvelope(v2).version,2);assert.equal(parseDocumentEnvelope({iv:v2.iv,tag:v2.tag,data:v2.data}).kid,LEGACY_KEY_ID);
 const {kid:_kid,...noKid}=v2,{format:_format,...noFormat}=v2;
 for(const bad of [null,[],'x',{...v2,extra:1},noKid,noFormat,{...v2,kid:'dk1-'+'A'.repeat(32)},{...v2,kid:'dk2-'+'a'.repeat(32)},{...v2,kid:LEGACY_KEY_ID},
  {...v2,format:'evidscope-document-envelope-v3'},
  {iv:v2.iv,tag:v2.tag,data:v2.data,kid},{...v2,iv:b64(16)},{...v2,tag:b64(12)},{...v2,data:''},{...v2,data:v2.data.replace(/=*$/,'')+'@'}])
  assert.throws(()=>parseDocumentEnvelope(bad),/Invalid encrypted document envelope/);
});

test('v2 envelopes bind key id, purpose and tenant: wrong, relabelled, downgraded or moved envelopes fail closed',t=>{
 const dir=mkdtempSync(join(tmpdir(),'evidscope-envelope-'));t.after(()=>rmSync(dir,{recursive:true,force:true}));
 const {privateKey}=generateKeyPairSync('ed25519'),a=randomBytes(32),b=randomBytes(32),ring=createKeyring({signingKey:privateKey,dataKey:a,
  previousDataKeys:[b]});
 const governance=createGovernanceDocumentStorage(dir,ring),finance=createDocumentAdapter(dir,ring),doc=Buffer.from('bound document'),hash=sha(doc);
 governance.put('alpha',doc);const file=governance.location('alpha',hash),original=readFileSync(file),envelope=JSON.parse(original);
 assert.equal(envelope.kid,dataKeyId(a));
 const tamper=(value,read=()=>governance.read('alpha',hash))=>{writeFileSync(file,JSON.stringify(value));try{read();}finally{writeFileSync(file,original);}};
 assert.throws(()=>tamper({...envelope,kid:dataKeyId(randomBytes(32))}),/^Error: Data key dk1-[a-f0-9]{32} is not configured$/);
 assert.throws(()=>tamper({...envelope,kid:dataKeyId(b)}),/unable to authenticate data/,'kid is in the AAD: relabelling to another configured key fails');
 assert.throws(()=>tamper({iv:envelope.iv,tag:envelope.tag,data:envelope.data}),/unable to authenticate data/,'v2 cannot be downgraded to a v1 envelope');
 assert.deepEqual(governance.read('alpha',hash),doc);
 // Cross-purpose: the same bytes copied to the finance store at the same tenant/hash do not open.
 const financeFile=finance.location('alpha',hash);mkdirSync(join(financeFile,'..'),{recursive:true});copyFileSync(file,financeFile);
 assert.throws(()=>finance.read('alpha',hash),/unable to authenticate data/);rmSync(financeFile);
 finance.put('alpha',doc);copyFileSync(financeFile,file);assert.throws(()=>governance.read('alpha',hash),/unable to authenticate data/);
  writeFileSync(file,original);
 // Cross-tenant: an envelope copied under another tenant does not open.
 const betaFile=governance.location('beta',hash);mkdirSync(join(betaFile,'..'),{recursive:true});copyFileSync(file,betaFile);
 assert.throws(()=>governance.read('beta',hash),/unable to authenticate data/);
 assert.throws(()=>createKeyring({signingKey:privateKey,dataKey:a,previousDataKeys:[Buffer.from(a)]}),/Duplicate data key/);
 assert.throws(()=>ring.key('__proto__',ring.currentKeyId),/Unknown data key purpose/);
});

test('legacy v1 envelopes and v1 backups still decrypt with the signing key after a data key is configured',async t=>{
 const f=fixture(t),doc=Buffer.from('legacy evidence');let s=f.boot();
 await f.call(s,'/api/governance/systems',system);await f.call(s,'/api/governance/documents',gov(doc));
  await f.call(s,'/api/governance/bundles',sup(Buffer.from('legacy supplier')));s.store.close();
 const out=mkdtempSync(join(tmpdir(),'evidscope-legacy-backup-'));t.after(()=>rmSync(out,{recursive:true,force:true}));
 const shared={privateKey:f.privateKey,publicKey:f.publicKey},root=randomBytes(32);
 const anchor=await createVaultBackup({dataDir:join(f.dir,'data'),backupDir:join(out,'b'),...shared});
 const manifest=JSON.parse(readFileSync(join(out,'b','manifest.json'),'utf8'));
 assert.equal(manifest.format,'evidscope-vault-backup-v1');assert.deepEqual(Object.keys(manifest.database).sort(),['algorithm','iv','plaintextSha256','tag']);
 const receipt=await restoreVaultBackup({backupDir:join(out,'b'),restoreDir:join(out,'r'),...shared,dataKey:root,anchor});assert.equal(receipt.verified,true);
 const restored=createGovernanceDocumentStorage(join(out,'r'),createKeyring({signingKey:f.privateKey,dataKey:root}));
 assert.deepEqual(restored.open('alpha',sha(doc)),{bytes:doc,kid:LEGACY_KEY_ID,version:1});
 assert.equal(createDocumentAdapter(join(out,'r'),createKeyring({signingKey:f.privateKey})).read('alpha',sha(Buffer.from('legacy supplier'))).toString(),
  'legacy supplier');
 assert.throws(()=>createGovernanceDocumentStorage(join(out,'r'),createKeyring({dataKey:root})).read('alpha',sha(doc)),/requires the signing private key/);
 s=f.boot({dataKey:root});const r=await f.call(s,'/api/integrity');assert.equal(r.valid,true,r.error);
 assert.equal(r.keySeparation.status,'migration_pending');assert.deepEqual(r.keySeparation.documentFilesByKeyId,{[LEGACY_KEY_ID]:2});
  assert.equal(r.keySeparation.newWritesUse,dataKeyId(root));
 assert.equal(r.keySeparation.limitations.length,2);assert.equal(r.keySeparation.eventKeys.confidentialityAgainstDatabaseReader,false);
});

test('backup manifests: re-signed key-id, KDF and format substitutions are rejected before publication',async t=>{
 const f=fixture(t),a=randomBytes(32),b=randomBytes(32),s=f.boot({dataKey:a});
 await f.call(s,'/api/governance/systems',system);await f.call(s,'/api/governance/documents',gov(Buffer.from('manifest negatives')));
 const out=mkdtempSync(join(tmpdir(),'evidscope-manifest-'));t.after(()=>rmSync(out,{recursive:true,force:true}));
 const shared={privateKey:f.privateKey,publicKey:f.publicKey},anchor=await createVaultBackup({dataDir:join(f.dir,'data'),backupDir:join(out,'v2'),...shared,
  dataKey:a});
 let n=0;
 const variant=(source,mutate)=>{
  const dir=join(out,'variant-'+(++n));cpSync(source,dir,{recursive:true});
   const path=join(dir,'manifest.json'),{signature:_old,...statement}=JSON.parse(readFileSync(path,'utf8'));
  mutate(statement);const manifest={...statement,signature:sign(null,Buffer.from(canonical(statement)),f.privateKey).toString('base64')};
   writeFileSync(path,JSON.stringify(manifest));
  return {dir,anchor:{...anchor,manifestSha256:digest(manifest)}};
 };
 const restore=async({dir,anchor},keys={dataKey:a,previousDataKeys:[b]})=>{const target=join(out,'restore-'+n);
  try{return await restoreVaultBackup({backupDir:dir,restoreDir:target,...shared,...keys,anchor});
  }finally{assert.equal(existsSync(target),false,'nothing published');}};
 await assert.rejects(restore(variant(join(out,'v2'),m=>{m.database.info='evidscope/data-key/v1/governance-document';})),/Unsupported backup encryption/);
 await assert.rejects(restore(variant(join(out,'v2'),m=>{delete m.database.kdf;})),/Unsupported backup encryption/);
 await assert.rejects(restore(variant(join(out,'v2'),m=>{m.database.keyId='legacy-signing-v1';})),/Unsupported backup encryption/);
 await assert.rejects(restore(variant(join(out,'v2'),m=>{m.database.keyId=dataKeyId(b);})),/unable to authenticate data/,'keyId is bound in the AAD');
 await assert.rejects(restore(variant(join(out,'v2'),m=>{m.format='evidscope-vault-backup-v1';for(const k of ['kdf','info','keyId'])delete m.database[k];
  })),/unable to authenticate data/,'v2 cannot be downgraded to v1');
 await assert.rejects(restore(variant(join(out,'v2'),m=>{m.format='evidscope-vault-backup-v3';})),/Backup signature invalid/);
 await assert.rejects(restore(variant(join(out,'v2'),()=>{}),{}),/Data key dk1-[a-f0-9]{32} is not configured/);
 // A legacy v1 manifest must not carry v2 key fields.
 s.store.close();const legacy=fixture(t),ls=legacy.boot();await legacy.call(ls,'/api/governance/systems',system);
 const legacyAnchor=await createVaultBackup({dataDir:join(legacy.dir,'data'),backupDir:join(out,'v1'),privateKey:legacy.privateKey,publicKey:legacy.publicKey});
 const v1=join(out,'v1-keyid');cpSync(join(out,'v1'),v1,{recursive:true});
  const path=join(v1,'manifest.json'),{signature:_s,...statement}=JSON.parse(readFileSync(path,'utf8'));
 statement.database.keyId=dataKeyId(a);
  const manifest={...statement,signature:sign(null,Buffer.from(canonical(statement)),legacy.privateKey).toString('base64')};
  writeFileSync(path,JSON.stringify(manifest));
 await assert.rejects(restoreVaultBackup({backupDir:v1,restoreDir:join(out,'v1-restore'),privateKey:legacy.privateKey,publicKey:legacy.publicKey,dataKey:a,
  anchor:{...legacyAnchor,manifestSha256:digest(manifest)}}),/Unsupported backup encryption/);
 assert.equal((await restoreVaultBackup({backupDir:join(out,'v1'),restoreDir:join(out,'v1-ok'),privateKey:legacy.privateKey,publicKey:legacy.publicKey,
  anchor:legacyAnchor})).verified,true);
});

test('key files from the environment: previous keys need a current key and keys may not live inside DATA_DIR',t=>{
 const dir=mkdtempSync(join(tmpdir(),'evidscope-data-key-env-'));t.after(()=>rmSync(dir,{recursive:true,force:true}));
 const key=name=>{const file=join(dir,name);mkdirSync(join(file,'..'),{recursive:true});writeFileSync(file,randomBytes(32),{mode:0o600});return file;};
 const current=key('current.key'),old1=key('old1.key'),old2=key('old2.key'),inside=key('data/inside.key');
 assert.deepEqual(dataKeysFromEnv({}),{dataKey:undefined,previousDataKeys:[]});
 assert.throws(()=>dataKeysFromEnv({DATA_KEY_PREVIOUS_FILES:old1}),/DATA_KEY_PREVIOUS_FILES requires DATA_KEY_FILE/);
 const keys=dataKeysFromEnv({DATA_KEY_FILE:current,DATA_KEY_PREVIOUS_FILES:[old1,old2].join(delimiter),DATA_DIR:join(dir,'data')});
 assert.deepEqual(keys.dataKey,readFileSync(current));assert.deepEqual(keys.previousDataKeys,[readFileSync(old1),readFileSync(old2)]);
 assert.throws(()=>dataKeysFromEnv({DATA_KEY_FILE:inside,DATA_DIR:join(dir,'data')}),/must not be stored inside DATA_DIR/);
 assert.throws(()=>dataKeysFromEnv({DATA_KEY_FILE:current,DATA_KEY_PREVIOUS_FILES:inside,DATA_DIR:join(dir,'data','..','data')}),
  /must not be stored inside DATA_DIR/);
 assert.throws(()=>dataKeysFromEnv({DATA_KEY_FILE:join(dir,'missing.key')}),/ENOENT/);
});

test('an interrupted migration still makes a vault without the new data key refuse to start',async t=>{
 const {migrateDocuments}=await import('../scripts/data-key.mjs');
 const f=fixture(t),a=randomBytes(32),dataDir=join(f.dir,'data'),tenants=['alpha','beta'];
 const principals=tenants.map(tenant=>({id:tenant+'-reviewer',role:'reviewer',tenant,token:tenant[0].repeat(40)}));
 const s=f.boot({config:{principals}});
 for(const tenant of tenants){
  const call=(path,body)=>s.handle('POST',new URL(path,'http://local'),{authorization:'Bearer '+tenant[0].repeat(40)},JSON.stringify(body));
  await call('/api/governance/systems',system);await call('/api/governance/documents',gov(Buffer.from(tenant+' doc')));
 }
 s.store.close();
 const storage=createGovernanceDocumentStorage(dataDir,f.privateKey),[alpha,beta]=tenants.map(tenant=>storage.location(tenant,sha(Buffer.from(tenant+' doc'))));
 // Tenants migrate in order: alpha's file is rewritten before beta's unreadable file aborts the run.
 writeFileSync(beta,'{}');
 assert.throws(()=>migrateDocuments({dataDir,signingKey:f.privateKey,dataKey:a}),/Invalid encrypted document envelope/);
 assert.equal(JSON.parse(readFileSync(alpha,'utf8')).kid,dataKeyId(a),'alpha was already re-encrypted');
 assert.throws(()=>f.boot({config:{principals}}),new RegExp(`not configured: ${dataKeyId(a)}`));
});

test('separation starts at the first start with DATA_KEY_FILE: restart, backup and frontier without the key are refused',async t=>{
 const {migrateDocuments}=await import('../scripts/data-key.mjs');
 const f=fixture(t),a=randomBytes(32),b=randomBytes(32),dataDir=join(f.dir,'data'),shared={privateKey:f.privateKey,publicKey:f.publicKey};
 const config={principals:[{id:'alpha-reviewer',role:'reviewer',tenant:'alpha',token:'a'.repeat(40)}]};
 let s=f.boot({dataKey:a});await f.call(s,'/api/governance/systems',system); // signed history, but no document sealed by the data key
 const active=()=>s.store.db.prepare('SELECT kid FROM data_key_usage WHERE retired_at IS NULL ORDER BY kid').all().map(r=>r.kid);
 assert.deepEqual(active(),[dataKeyId(a)]);s.store.close();
 assert.throws(()=>f.boot(),new RegExp(`not configured: ${dataKeyId(a)}`));
 const out=mkdtempSync(join(tmpdir(),'evidscope-separation-start-'));t.after(()=>rmSync(out,{recursive:true,force:true}));
 const refused=new RegExp(`key separation is active: data key\\(s\\) ${dataKeyId(a)} are not configured; refusing a backup`);
 await assert.rejects(createVaultBackup({dataDir,backupDir:join(out,'legacy'),...shared}),refused);
 assert.deepEqual(readdirSync(join(out,'legacy')),[],'nothing sealed');
 const anchor=await createVaultBackup({dataDir,backupDir:join(out,'v2'),...shared,dataKey:a});
 assert.equal(JSON.parse(readFileSync(join(out,'v2','manifest.json'),'utf8')).database.keyId,dataKeyId(a));
 await assert.rejects(createVaultRecoveryFrontier({dataDir,...shared,anchor,config}),/key separation is active.*refusing a recovery frontier/);
 const latest=await createVaultRecoveryFrontier({dataDir,...shared,dataKey:a,anchor,config});
 const restored=await restoreVaultBackup({backupDir:join(out,'v2'),restoreDir:join(out,'restored'),...shared,dataKey:a,anchor,frontier:latest.frontier,
  frontierAnchor:latest.anchor,config});
 assert.equal(restored.activationAccepted,true);
 assert.throws(()=>createService({dataDir:join(out,'restored'),key:f.privateKey,config,requirements}),/not configured/,'restored vault keeps separation');
 // A retired key id no longer binds: after rotation to b, b alone opens, backs up and certifies the vault.
 assert.equal(migrateDocuments({dataDir,signingKey:f.privateKey,dataKey:b,previousDataKeys:[a]}).retiredKeyIds[0],dataKeyId(a));
 s=f.boot({dataKey:b});assert.deepEqual(active(),[dataKeyId(b)]);s.store.close();
 const rotated=await createVaultBackup({dataDir,backupDir:join(out,'rotated'),...shared,dataKey:b});
 assert.ok(await createVaultRecoveryFrontier({dataDir,...shared,dataKey:b,anchor:rotated,config}));
 // Enterprise profile: even a vault that never ran with a data key gets no signing-key-sealed backup or frontier.
 const legacy=fixture(t),ls=legacy.boot();await legacy.call(ls,'/api/governance/systems',system);ls.store.close();
 const legacyShared={dataDir:join(legacy.dir,'data'),privateKey:legacy.privateKey,publicKey:legacy.publicKey};
 await assert.rejects(createVaultBackup({...legacyShared,backupDir:join(out,'enterprise'),config:{profile:'enterprise'}}),
  /Enterprise profile requires DATA_KEY_FILE for a backup/);
 const legacyAnchor=await createVaultBackup({...legacyShared,backupDir:join(out,'local-profile')});
 assert.equal(JSON.parse(readFileSync(join(out,'local-profile','manifest.json'),'utf8')).format,'evidscope-vault-backup-v1','legacy local vaults keep v1');
 await assert.rejects(createVaultRecoveryFrontier({...legacyShared,anchor:legacyAnchor,config:{...config,profile:'enterprise'}}),
  /Enterprise profile requires DATA_KEY_FILE for a recovery frontier/);
});
