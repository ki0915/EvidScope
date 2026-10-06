import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,createDecipheriv,generateKeyPairSync,randomBytes,hkdfSync} from 'node:crypto';
import {mkdtempSync,readFileSync,writeFileSync,rmSync,statSync,chmodSync,readdirSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createService} from '../src/service.mjs';
import {createKeyring,dataKeyId,readDataKeyFile,PURPOSES,LEGACY_KEY_ID} from '../src/data-keys.mjs';
import {createGovernanceDocumentStorage} from '../src/governance-documents.mjs';
import {createDocumentAdapter} from '../src/finance-evidence.mjs';
import {createVaultBackup,restoreVaultBackup} from '../src/vault-recovery.mjs';
import {initialize} from '../scripts/init.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex');
const requirements=JSON.parse(readFileSync(new URL('../data/requirements.json',import.meta.url),'utf8'));
const system={id:'credit',name:'Synthetic credit',owner:'reviewer',purpose:'Loan assistance',markets:['KR'],krRoles:['deployer'],generative:false,highImpact:'confirmed',supplierId:'supplier-a',modelId:'credit-score',modelVersion:'v1',suppliedModelVersion:'v1',suppliedPurpose:'Loan assistance',substantialModification:false};
const gov=(bytes,id='control')=>({id,systemId:'credit',name:'control.txt',mediaType:'text/plain',sha256:sha(bytes),contentBase64:bytes.toString('base64')});
const sup=(bytes)=>({id:'supplier',systemId:'credit',synthetic:true,supplierId:'supplier-a',modelId:'credit-score',modelVersion:'v1',purpose:system.purpose,testScope:'s',measures:['KR-34-RISK'],documents:[{id:'d',name:'s.txt',sha256:sha(bytes),contentBase64:bytes.toString('base64')}],reviewerNotes:'synthetic'});
function fixture(t){
 const dir=mkdtempSync(join(tmpdir(),'evidscope-data-key-')),{privateKey,publicKey}=generateKeyPairSync('ed25519');
 const principals=[{id:'alpha-reviewer',role:'reviewer',tenant:'alpha',token:'a'.repeat(40)}];
 const services=[];t.after(()=>{for(const s of services)try{s.store.close();}catch{}rmSync(dir,{recursive:true,force:true});});
 const boot=(extra={})=>{const s=createService({dataDir:join(dir,'data'),key:privateKey,config:{principals},requirements,...extra});services.push(s);return s;};
 const call=(s,path,body)=>s.handle(body===undefined?'GET':'POST',new URL(path,'http://local'),{authorization:'Bearer '+'a'.repeat(40)},body===undefined?'':JSON.stringify(body));
 return {dir,privateKey,publicKey,boot,call};
}

test('HKDF purpose keys are distinct, key ids are stable, legacy derivation is byte-identical to v1',()=>{
 const root=randomBytes(32),{privateKey}=generateKeyPairSync('ed25519'),ring=createKeyring({signingKey:privateKey,dataKey:root});
 const keys=Object.keys(PURPOSES).map(p=>ring.key(p,ring.currentKeyId).toString('hex'));assert.equal(new Set(keys).size,3);
 assert.match(dataKeyId(root),/^dk1-[a-f0-9]{32}$/);assert.equal(dataKeyId(root),ring.currentKeyId);
 assert.deepEqual(ring.key('governanceDocument',ring.currentKeyId),Buffer.from(hkdfSync('sha256',root,Buffer.alloc(0),Buffer.from('evidscope/data-key/v1/governance-document'),32)));
 const legacy=createHash('sha256').update('evidscope-governance-documents-v1').update(privateKey.export({type:'pkcs8',format:'der'})).digest();
 assert.deepEqual(ring.key('governanceDocument',LEGACY_KEY_ID),legacy);
 assert.notDeepEqual(ring.key('governanceDocument',ring.currentKeyId),legacy);
 assert.throws(()=>createKeyring({dataKey:root}).key('governanceDocument',LEGACY_KEY_ID),/signing private key/);
});

test('separated vault writes v2 envelopes the signing key alone cannot open (S2 PoC regression)',async t=>{
 const f=fixture(t),root=randomBytes(32),s=f.boot({dataKey:root}),doc=Buffer.from('TOP SECRET governance doc 900101-1234567');
 await f.call(s,'/api/governance/systems',system);await f.call(s,'/api/governance/documents',gov(doc));await f.call(s,'/api/governance/bundles',sup(Buffer.from('supplier')));
 const file=join(f.dir,'data','governance-documents',sha(Buffer.from('alpha')),sha(doc)+'.json'),env=JSON.parse(readFileSync(file,'utf8'));
 assert.deepEqual(Object.keys(env).sort(),['data','format','iv','kid','tag']);assert.equal(env.kid,dataKeyId(root));assert.equal(env.format,'evidscope-document-envelope-v2');
 const legacyMaster=createHash('sha256').update('evidscope-governance-documents-v1').update(f.privateKey.export({type:'pkcs8',format:'der'})).digest();
 assert.throws(()=>{const d=createDecipheriv('aes-256-gcm',legacyMaster,Buffer.from(env.iv,'base64'));d.setAAD(Buffer.from(`alpha:${sha(doc)}`));d.setAuthTag(Buffer.from(env.tag,'base64'));Buffer.concat([d.update(Buffer.from(env.data,'base64')),d.final()]);});
 assert.deepEqual(createGovernanceDocumentStorage(join(f.dir,'data'),createKeyring({dataKey:root})).read('alpha',sha(doc)),doc,'v2 read needs no signing key');
 const r=await f.call(s,'/api/integrity');assert.equal(r.valid,true,r.error);assert.equal(r.keySeparation.status,'separated');assert.deepEqual(r.keySeparation.documentFilesByKeyId,{[dataKeyId(root)]:2});
 // kid is authenticated: relabel the envelope with another configured kid => fail
 const other=randomBytes(32);s.store.close();const s2=f.boot({dataKey:root,previousDataKeys:[other]});
 writeFileSync(file,JSON.stringify({...env,kid:dataKeyId(other)}));assert.equal((await f.call(s2,'/api/integrity')).valid,false);
});

test('legacy vault upgraded in place: old files stay readable, new files use the data key, re-encryption completes migration',async t=>{
 const f=fixture(t),v1=Buffer.from('legacy v1'),v2=Buffer.from('separated v2');let s=f.boot();
 await f.call(s,'/api/governance/systems',system);await f.call(s,'/api/governance/documents',gov(v1));
 assert.equal((await f.call(s,'/api/integrity')).keySeparation.status,'not_separated');s.store.close();
 const root=randomBytes(32);s=f.boot({dataKey:root});await f.call(s,'/api/governance/documents',gov(v2));
 let r=await f.call(s,'/api/integrity');assert.equal(r.valid,true,r.error);assert.equal(r.keySeparation.status,'migration_pending');assert.deepEqual(r.keySeparation.documentFilesByKeyId,{[LEGACY_KEY_ID]:1,[dataKeyId(root)]:1});
 const storage=createGovernanceDocumentStorage(join(f.dir,'data'),createKeyring({signingKey:f.privateKey,dataKey:root}));
 assert.deepEqual(storage.reencrypt('alpha',sha(v1)),{changed:true,from:LEGACY_KEY_ID,to:dataKeyId(root)});assert.equal(storage.reencrypt('alpha',sha(v2)).changed,false);
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
 assert.equal(manifest.format,'evidscope-vault-backup-v2');assert.equal(manifest.database.keyId,dataKeyId(root));assert.equal(manifest.database.kdf,'hkdf-sha256');
 await assert.rejects(restoreVaultBackup({backupDir:join(out,'b'),restoreDir:join(out,'r1'),...shared,anchor}),/not configured/);
 const receipt=await restoreVaultBackup({backupDir:join(out,'b'),restoreDir:join(out,'r2'),...shared,dataKey:root,anchor});assert.equal(receipt.verified,true);assert.equal(receipt.governanceDocuments,1);
 await assert.rejects(createVaultBackup({dataDir:join(f.dir,'data'),backupDir:join(out,'b2'),...shared}),/not configured/,'legacy-only keyring cannot verify v2 documents');
});

test('data key file loader enforces length and permissions; init generates a 0600 32-byte key',t=>{
 const dir=mkdtempSync(join(tmpdir(),'evidscope-data-key-file-'));t.after(()=>rmSync(dir,{recursive:true,force:true}));
 const file=join(dir,'k');writeFileSync(file,randomBytes(31),{mode:0o600});assert.throws(()=>readDataKeyFile(file),/32 raw bytes/);
 writeFileSync(file,randomBytes(32));chmodSync(file,0o644);if(process.platform!=='win32')assert.throws(()=>readDataKeyFile(file),/permissions/);
 chmodSync(file,0o440);assert.equal(readDataKeyFile(file).length,32);
 initialize(join(dir,'init'));const key=join(dir,'init','data-encryption.key');assert.equal(readFileSync(key).length,32);if(process.platform!=='win32')assert.equal(statSync(key).mode&0o777,0o600);
 assert.ok(readdirSync(join(dir,'init')).includes('signing-private.pem'));
});

test('offline migration re-encrypts legacy files, rotation retires the previous key id, then the old key can be dropped',async t=>{
 const {migrateDocuments}=await import('../scripts/data-key.mjs');
 const f=fixture(t),a=randomBytes(32),b=randomBytes(32),dataDir=join(f.dir,'data');let s=f.boot();
 await f.call(s,'/api/governance/systems',system);await f.call(s,'/api/governance/documents',gov(Buffer.from('g1')));await f.call(s,'/api/governance/bundles',sup(Buffer.from('s1')));s.store.close();
 let r=migrateDocuments({dataDir,signingKey:f.privateKey,dataKey:a});assert.deepEqual(r.reencryptedFrom,{[LEGACY_KEY_ID]:2});assert.equal(r.legacyRemaining,0);
 s=f.boot({dataKey:a});assert.equal((await f.call(s,'/api/integrity')).keySeparation.status,'separated');s.store.close();
 assert.throws(()=>f.boot({dataKey:b}),/not configured/);
 r=migrateDocuments({dataDir,signingKey:f.privateKey,dataKey:b,previousDataKeys:[a]});assert.deepEqual(r.reencryptedFrom,{[dataKeyId(a)]:2});assert.deepEqual(r.retiredKeyIds,[dataKeyId(a)]);
 s=f.boot({dataKey:b});const out=await f.call(s,'/api/integrity');assert.equal(out.valid,true,out.error);assert.deepEqual(out.keySeparation.documentFilesByKeyId,{[dataKeyId(b)]:2});
});
