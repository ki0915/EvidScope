import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync} from 'node:crypto';
import {chmodSync,copyFileSync,existsSync,mkdtempSync,readFileSync,readdirSync,rmSync,statSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createService} from '../src/service.mjs';
import {dataKeyId,readDataKeyFile,LEGACY_KEY_ID} from '../src/data-keys.mjs';

const execute=promisify(execFile),sha=b=>createHash('sha256').update(b).digest('hex');
const requirements=JSON.parse(readFileSync(new URL('../data/requirements.json',import.meta.url),'utf8'));
const baseEnv=()=>{const env={...process.env};for(const name of ['DATA_KEY_FILE','DATA_KEY_PREVIOUS_FILES','DATA_DIR','NODE_TEST_CONTEXT'])delete env[name];return env;};
async function run(script,args,env={}){
 try{const out=await execute(process.execPath,[script,...args],{env:{...baseEnv(),...env},windowsHide:true,timeout:30000,maxBuffer:1024*1024});return {code:0,...out};}
 catch(error){return {code:error.code??1,stdout:error.stdout||'',stderr:error.stderr||''};}
}
const system={id:'credit',name:'Synthetic credit',owner:'reviewer',purpose:'Loan assistance',markets:['KR'],krRoles:['deployer'],generative:false,highImpact:'confirmed',supplierId:'supplier-a',modelId:'credit-score',modelVersion:'v1',suppliedModelVersion:'v1',suppliedPurpose:'Loan assistance',substantialModification:false};
const gov=bytes=>({id:'control',systemId:'credit',name:'control.txt',mediaType:'text/plain',sha256:sha(bytes),contentBase64:bytes.toString('base64')});
function workspace(t){
 const dir=mkdtempSync(join(tmpdir(),'evidscope-data-key-cli-')),{privateKey,publicKey}=generateKeyPairSync('ed25519');t.after(()=>rmSync(dir,{recursive:true,force:true}));
 const signingFile=join(dir,'signing-private.pem'),publicFile=join(dir,'trust-anchor.pem');
 writeFileSync(signingFile,privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600});writeFileSync(publicFile,publicKey.export({format:'pem',type:'spki'}));
 return {dir,privateKey,publicKey,signingFile,publicFile,dataDir:join(dir,'data')};
}
// A legacy (pre-separation) vault holding one governance document, closed afterwards.
async function legacyVault(w,extra={}){
 const principals=[{id:'alpha-reviewer',role:'reviewer',tenant:'alpha',token:'a'.repeat(40)}];
 const s=createService({dataDir:w.dataDir,key:w.privateKey,config:{principals},requirements,...extra});
 const call=(path,body)=>s.handle('POST',new URL(path,'http://local'),{authorization:'Bearer '+'a'.repeat(40)},JSON.stringify(body));
 try{await call('/api/governance/systems',system);await call('/api/governance/documents',gov(Buffer.from('legacy control text')));}finally{s.store.close();}
}

test('data-key generate writes a 0600 32-byte key once, id reproduces the kid, and no key material is printed',async t=>{
 const w=workspace(t),file=join(w.dir,'data-encryption.key');
 const made=await run('scripts/data-key.mjs',['generate',file]);assert.equal(made.code,0,made.stderr);
 const out=JSON.parse(made.stdout),bytes=readFileSync(file);
 assert.equal(out.created,true);assert.match(out.kid,/^dk1-[a-f0-9]{32}$/);assert.equal(out.kid,dataKeyId(bytes));assert.equal(bytes.length,32);
 if(process.platform!=='win32')assert.equal(statSync(file).mode&0o777,0o600);
 for(const text of [made.stdout,made.stderr])for(const encoding of ['hex','base64','base64url'])assert.ok(!text.includes(bytes.toString(encoding)),'key material printed');
 const id=await run('scripts/data-key.mjs',['id',file]);assert.equal(id.code,0,id.stderr);assert.deepEqual(JSON.parse(id.stdout),{kid:out.kid});
 const again=await run('scripts/data-key.mjs',['generate',file]);assert.equal(again.code,1);assert.equal(JSON.parse(again.stderr).ok,false);assert.match(again.stderr,/EEXIST/);
 assert.deepEqual(readFileSync(file),bytes,'existing key must never be overwritten');
 const open=join(w.dir,'open.key');copyFileSync(file,open);chmodSync(open,0o644);
 if(process.platform!=='win32'){const r=await run('scripts/data-key.mjs',['id',open]);assert.equal(r.code,1);assert.match(r.stderr,/permissions too open/);}
 const pem=await run('scripts/data-key.mjs',['id',w.signingFile]);assert.equal(pem.code,1);assert.match(pem.stderr,/exactly 32 raw bytes/);
 for(const args of [[],['generate'],['id',file,'extra'],['rotate',file]]){const r=await run('scripts/data-key.mjs',args);assert.equal(r.code,1);assert.match(r.stderr,/Usage/);}
});

test('data-key migrate CLI re-encrypts a legacy vault under DATA_KEY_FILE and refuses unsafe key configuration',async t=>{
 const w=workspace(t);await legacyVault(w);
 const keyFile=join(w.dir,'data-encryption.key');const kid=JSON.parse((await run('scripts/data-key.mjs',['generate',keyFile])).stdout).kid;
 let r=await run('scripts/data-key.mjs',['migrate',w.dataDir,w.signingFile]);assert.equal(r.code,1);assert.match(r.stderr,/migrate requires DATA_KEY_FILE/);
 r=await run('scripts/data-key.mjs',['migrate',w.dataDir,w.signingFile],{DATA_KEY_PREVIOUS_FILES:keyFile});assert.equal(r.code,1);assert.match(r.stderr,/DATA_KEY_PREVIOUS_FILES requires DATA_KEY_FILE/);
 const inside=join(w.dataDir,'inside.key');copyFileSync(keyFile,inside);chmodSync(inside,0o600);
 r=await run('scripts/data-key.mjs',['migrate',w.dataDir,w.signingFile],{DATA_KEY_FILE:inside});assert.equal(r.code,1);assert.match(r.stderr,/must not be stored inside DATA_DIR/);rmSync(inside);
 const tenantDir=join(w.dataDir,'governance-documents',sha(Buffer.from('alpha'))),[name]=readdirSync(tenantDir);
 assert.deepEqual(Object.keys(JSON.parse(readFileSync(join(tenantDir,name),'utf8'))).sort(),['data','iv','tag'],'legacy v1 envelope before migration');
 r=await run('scripts/data-key.mjs',['migrate',w.dataDir,w.signingFile],{DATA_KEY_FILE:keyFile});assert.equal(r.code,0,r.stderr);
 const out=JSON.parse(r.stdout);assert.equal(out.migrated,true);assert.equal(out.currentKeyId,kid);assert.deepEqual(out.reencryptedFrom,{[LEGACY_KEY_ID]:1});assert.equal(out.legacyRemaining,0);assert.deepEqual(out.referencedFilesByKeyId,{[kid]:1});
 const envelope=JSON.parse(readFileSync(join(tenantDir,name),'utf8'));assert.equal(envelope.format,'evidscope-document-envelope-v2');assert.equal(envelope.kid,kid);
 r=await run('scripts/data-key.mjs',['migrate',w.dataDir,w.signingFile],{DATA_KEY_FILE:keyFile});assert.equal(r.code,0,r.stderr);assert.deepEqual(JSON.parse(r.stdout).reencryptedFrom,{},'migration is idempotent');
 assert.throws(()=>createService({dataDir:w.dataDir,key:w.privateKey,config:{principals:[]}}).store.close(),new RegExp(`not configured: ${kid}`),'vault without the key that sealed data must refuse to start');
});

test('vault-backup CLI seals v2 backups with DATA_KEY_FILE and cannot restore them without it',async t=>{
 const w=workspace(t),keyFile=join(w.dir,'data-encryption.key');await run('scripts/data-key.mjs',['generate',keyFile]);
 await legacyVault(w,{dataKey:readDataKeyFile(keyFile)});
 const backupDir=join(w.dir,'backup'),anchorFile=join(w.dir,'anchor.json');
 let r=await run('scripts/vault-backup.mjs',['create',w.dataDir,backupDir,w.signingFile,w.publicFile,anchorFile],{DATA_KEY_FILE:keyFile});assert.equal(r.code,0,r.stderr);
 const created=JSON.parse(r.stdout);assert.equal(created.backupEncryption,'data_key_hkdf');assert.equal(created.dataKeyIncluded,false);assert.equal(created.privateKeyIncluded,false);
 const manifest=JSON.parse(readFileSync(join(backupDir,'manifest.json'),'utf8'));assert.equal(manifest.format,'evidscope-vault-backup-v2');assert.equal(manifest.database.keyId,dataKeyId(readFileSync(keyFile)));
 assert.ok(!readdirSync(backupDir).some(name=>/\.key$|\.pem$/.test(name)));
 r=await run('scripts/vault-backup.mjs',['create',w.dataDir,join(w.dir,'legacy-backup'),w.signingFile,w.publicFile,join(w.dir,'legacy-anchor.json')]);assert.notEqual(r.code,0);assert.match(r.stderr,/not configured/);
 r=await run('scripts/vault-backup.mjs',['restore',backupDir,join(w.dir,'restore-without-key'),w.signingFile,w.publicFile,anchorFile]);assert.notEqual(r.code,0);assert.match(r.stderr,/Data key dk1-[a-f0-9]{32} is not configured/);
 assert.equal(existsSync(join(w.dir,'restore-without-key')),false);
 r=await run('scripts/vault-backup.mjs',['restore',backupDir,join(w.dir,'restored'),w.signingFile,w.publicFile,anchorFile],{DATA_KEY_FILE:keyFile});assert.equal(r.code,0,r.stderr);assert.equal(JSON.parse(r.stdout).verified,true);
});
