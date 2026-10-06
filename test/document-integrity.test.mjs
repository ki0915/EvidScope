import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync} from 'node:crypto';
import {appendFileSync,mkdtempSync,mkdirSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve,sep} from 'node:path';
import {createService} from '../src/service.mjs';
import {createVaultBackup,restoreVaultBackup} from '../src/vault-recovery.mjs';
import {readBoundedRegularFile} from '../src/bounded-file.mjs';
import {createGovernanceDocumentStorage,MAX_GOVERNANCE_DOCUMENT_BYTES} from '../src/governance-documents.mjs';
import {checkDocumentFiles} from '../src/document-integrity.mjs';

const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const requirements=JSON.parse(readFileSync(new URL('../data/requirements.json',import.meta.url),'utf8'));
const system={id:'credit',name:'Synthetic credit',owner:'reviewer',purpose:'Loan assistance',markets:['KR'],krRoles:['deployer'],generative:false,highImpact:'confirmed',supplierId:'supplier-a',modelId:'credit-score',modelVersion:'v1',suppliedModelVersion:'v1',suppliedPurpose:'Loan assistance',substantialModification:false};
const governanceInput=(bytes)=>({id:'control',systemId:'credit',name:'control.txt',mediaType:'text/plain',sha256:sha(bytes),contentBase64:bytes.toString('base64')});
const supplierInput=(bytes,scope)=>({id:'supplier',systemId:'credit',synthetic:true,supplierId:'supplier-a',modelId:'credit-score',modelVersion:'v1',purpose:system.purpose,testScope:scope,measures:['KR-34-RISK'],documents:[{id:'supplier-doc',name:'supplier.txt',sha256:sha(bytes),contentBase64:bytes.toString('base64')}],reviewerNotes:'synthetic'});

function fixture(t){
 const dir=mkdtempSync(join(tmpdir(),'evidscope-document-integrity-')),{privateKey,publicKey}=generateKeyPairSync('ed25519');
 const principals=['alpha','beta'].map(tenant=>({id:`${tenant}-reviewer`,role:'reviewer',tenant,token:tenant.repeat(40)}));
 const service=createService({dataDir:dir,key:privateKey,config:{principals},requirements});
 t.after(()=>{service.store.close();assert.ok(resolve(dir).startsWith(resolve(tmpdir())+sep));rmSync(dir,{recursive:true,force:true});});
 const call=(path,body,tenant='alpha')=>service.handle(body===undefined?'GET':'POST',new URL(path,'http://local'),{authorization:'Bearer '+principals.find(p=>p.tenant===tenant).token},body===undefined?'':JSON.stringify(body));
 const pathFor=(kind,tenant,hash)=>join(dir,kind==='finance'?'finance-documents':'governance-documents',sha(Buffer.from(tenant)),`${hash}.json`);
 return {dir,privateKey,publicKey,principals,service,call,pathFor};
}

test('accepted governance documents above 64 KiB through 4 MiB remain verifiable and recoverable across every historical revision',async t=>{
 const h=fixture(t),output=mkdtempSync(join(tmpdir(),'evidscope-large-document-recovery-'));
 t.after(()=>{assert.ok(resolve(output).startsWith(resolve(tmpdir())+sep));rmSync(output,{recursive:true,force:true});});
 await h.call('/api/governance/systems',system);
 const revisions=[64*1024,64*1024+1,256*1024,MAX_GOVERNANCE_DOCUMENT_BYTES].map((size,i)=>Buffer.alloc(size,0x41+i));
 for(const [i,bytes] of revisions.entries()){
  const saved=await h.call('/api/governance/documents',governanceInput(bytes));assert.equal(saved.version,i+1);
  const result=await h.call('/api/integrity');assert.equal(result.valid,true,result.error);
  assert.equal(result.documentFiles.governanceFiles,i+1);
  assert.equal(result.documentFiles.plaintextBytes,revisions.slice(0,i+1).reduce((total,item)=>total+item.length,0));
 }
 const supplier=Buffer.alloc(64*1024,0x53);await h.call('/api/governance/bundles',supplierInput(supplier,'maximum accepted supplier document'));
 assert.equal((await h.call('/api/integrity')).valid,true);
 const backupDir=join(output,'backup'),restoreDir=join(output,'restored');
 const anchor=await createVaultBackup({dataDir:h.dir,backupDir,privateKey:h.privateKey,publicKey:h.publicKey});
 const receipt=await restoreVaultBackup({backupDir,restoreDir,privateKey:h.privateKey,publicKey:h.publicKey,anchor});
 assert.equal(receipt.verified,true);assert.equal(receipt.governanceDocuments,4);assert.equal(receipt.documents,5);
 const restored=createService({dataDir:restoreDir,key:h.privateKey,config:{principals:h.principals},requirements});
 try{
  const call=(path,tenant='alpha')=>restored.handle('GET',new URL(path,'http://local'),{authorization:'Bearer '+h.principals.find(p=>p.tenant===tenant).token});
  assert.equal((await call('/api/integrity')).valid,true);
  assert.deepEqual(Buffer.from((await call('/api/governance/documents/control/export')).contentBase64,'base64'),revisions.at(-1));
  const storage=createGovernanceDocumentStorage(restoreDir,h.privateKey);
  for(const bytes of revisions)assert.deepEqual(storage.read('alpha',sha(bytes)),bytes,'every historical revision must survive backup and recovery');
  await assert.rejects(call('/api/governance/documents/control/export','beta'),error=>error.status===404);
  const historical=join(restoreDir,'governance-documents',sha(Buffer.from('alpha')),sha(revisions[1])+'.json');
  const envelope=JSON.parse(readFileSync(historical,'utf8')),ciphertext=Buffer.from(envelope.data,'base64');ciphertext[0]^=1;envelope.data=ciphertext.toString('base64');writeFileSync(historical,JSON.stringify(envelope));
  assert.equal((await call('/api/integrity')).valid,false,'a corrupt large historical revision must fail integrity despite current retrieval');
  assert.deepEqual(Buffer.from((await call('/api/governance/documents/control/export')).contentBase64,'base64'),revisions.at(-1));
  await assert.rejects(createVaultBackup({dataDir:restoreDir,backupDir:join(output,'corrupt-backup'),privateKey:h.privateKey,publicKey:h.publicKey}));
 }finally{restored.store.close();}
});

test('governance size compatibility does not expand supplier or oversized governance intake and integrity bounds',async t=>{
 const h=fixture(t);await h.call('/api/governance/systems',system);
 await assert.rejects(h.call('/api/governance/documents',governanceInput(Buffer.alloc(MAX_GOVERNANCE_DOCUMENT_BYTES+1,0x47))),error=>error.status===413);
 await assert.rejects(h.call('/api/governance/bundles',supplierInput(Buffer.alloc(64*1024+1,0x53),'oversized supplier')),error=>error.status===413);
 const supplier=Buffer.alloc(64*1024,0x53);await h.call('/api/governance/bundles',supplierInput(supplier,'maximum supplier'));
 const records=structuredClone(h.service.store.rawBundle('alpha').records);
 records.find(row=>row.type==='supplier_bundle').payload.documents[0].bytes=64*1024+1;
 assert.throws(()=>checkDocumentFiles({db:h.service.store.db,tenant:'alpha',records,dataDir:h.dir,key:h.privateKey}),/Document file metadata is invalid/,'defensive supplier metadata bound must remain 64 KiB');
 assert.equal((await h.call('/api/integrity')).valid,true,'rejected input and isolated forged records must not change stored evidence');
});

test('bounded document reads reject growth after the path check without reading past cap+1',t=>{
 const root=mkdtempSync(join(tmpdir(),'evidscope-bounded-document-')),file=join(root,'envelope.json');t.after(()=>{assert.ok(resolve(root).startsWith(resolve(tmpdir())+sep));rmSync(root,{recursive:true,force:true});});writeFileSync(file,'{}');
 assert.throws(()=>readBoundedRegularFile(file,32,{afterLstat:()=>appendFileSync(file,' '.repeat(64))}),/size limit/);
});

test('integrity authenticates every referenced finance and governance file while excluding orphans explicitly',async t=>{
 const h=fixture(t),supplier=Buffer.from('supplier evidence'),governance1=Buffer.from('governance evidence v1'),governance2=Buffer.from('governance evidence v2');
 await h.call('/api/governance/systems',system);await h.call('/api/governance/bundles',supplierInput(supplier,'v1'));await h.call('/api/governance/documents',governanceInput(governance1));await h.call('/api/governance/documents',governanceInput(governance2));
 const orphanDir=join(h.dir,'finance-documents',sha(Buffer.from('alpha')));mkdirSync(orphanDir,{recursive:true});writeFileSync(join(orphanDir,'f'.repeat(64)+'.json'),'unreferenced corrupt orphan');
 const result=await h.call('/api/integrity');assert.equal(result.valid,true);assert.deepEqual(result.governanceDocumentProjection,{valid:true,documents:1,revisions:2});
 assert.deepEqual(result.documentFiles,{valid:true,financeFiles:1,governanceFiles:2,uniqueFiles:3,plaintextBytes:supplier.length+governance1.length+governance2.length,verification:'referenced_ciphertext_decrypted_authenticated_and_hashed_per_file',unreferencedFilesScanned:false,filesystemSnapshotProven:false});
 assert.deepEqual(result.verificationScope.notChecked,['rollback','truncation','tenant_removal']);assert.match(result.verificationScope.limitations[0],/unreferenced files/);
});

test('a corrupt historical supplier file fails integrity and backup even when the latest revision is retrievable',async t=>{
 const h=fixture(t),v1=Buffer.from('supplier v1'),v2=Buffer.from('supplier v2'),backupRoot=mkdtempSync(join(tmpdir(),'evidscope-document-backup-'));t.after(()=>{assert.ok(resolve(backupRoot).startsWith(resolve(tmpdir())+sep));rmSync(backupRoot,{recursive:true,force:true});});await h.call('/api/governance/systems',system);
 await h.call('/api/governance/bundles',supplierInput(v1,'v1'));await h.call('/api/governance/bundles',supplierInput(v2,'v2'));writeFileSync(h.pathFor('finance','alpha',sha(v1)),'corrupt');
 const result=await h.call('/api/integrity');assert.equal(result.valid,false);assert.equal(result.failureRecorded,true);assert.ok(result.verificationScope.checks.includes('document_files'));
 assert.equal((await h.call('/api/integrity',undefined,'beta')).valid,true);
 await assert.rejects(createVaultBackup({dataDir:h.dir,backupDir:join(backupRoot,'backup'),privateKey:h.privateKey,publicKey:h.publicKey}),/document|JSON|Unexpected/i);
});

test('a corrupt historical governance file or forged governance projection cannot pass generic integrity',async t=>{
 const h=fixture(t),v1=Buffer.from('governance v1'),v2=Buffer.from('governance v2');await h.call('/api/governance/systems',system);
 await h.call('/api/governance/documents',governanceInput(v1));await h.call('/api/governance/documents',governanceInput(v2));writeFileSync(h.pathFor('governance','alpha',sha(v1)),'corrupt');
 let result=await h.call('/api/integrity');assert.equal(result.valid,false);assert.equal(result.failureRecorded,true);
 writeFileSync(h.pathFor('governance','alpha',sha(v1)),readFileSync(h.pathFor('governance','alpha',sha(v2))));result=await h.call('/api/integrity');assert.equal(result.valid,false,'tenant/hash AAD must reject a ciphertext copied from another reference');
 const row=h.service.store.db.prepare("SELECT body FROM governance_documents WHERE tenant='alpha' AND id='control'").get();h.service.store.db.prepare("UPDATE governance_documents SET body=? WHERE tenant='alpha' AND id='control'").run(JSON.stringify({...JSON.parse(row.body),displayName:'forged'}));
 result=await h.call('/api/integrity');assert.equal(result.valid,false);assert.match(result.error,/거버넌스 문서 조회 사본/);
});

test('tenant ciphertext exchange fails only the altered tenant',async t=>{
 const h=fixture(t),bytes=Buffer.from('same plaintext, tenant-bound ciphertext');
 for(const tenant of ['alpha','beta']){await h.call('/api/governance/systems',system,tenant);await h.call('/api/governance/documents',governanceInput(bytes),tenant);}
 const alpha=h.pathFor('governance','alpha',sha(bytes)),beta=h.pathFor('governance','beta',sha(bytes));writeFileSync(alpha,readFileSync(beta));
 assert.equal((await h.call('/api/integrity')).valid,false);assert.equal((await h.call('/api/integrity',undefined,'beta')).valid,true);
});
