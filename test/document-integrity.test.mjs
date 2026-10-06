import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync} from 'node:crypto';
import {appendFileSync,mkdtempSync,mkdirSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve,sep} from 'node:path';
import {createService} from '../src/service.mjs';
import {createVaultBackup} from '../src/vault-recovery.mjs';
import {readBoundedRegularFile} from '../src/bounded-file.mjs';

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
 return {dir,privateKey,publicKey,service,call,pathFor};
}

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
 assert.deepEqual(result.verificationScope.notChecked,[]);assert.match(result.verificationScope.limitations[0],/unreferenced files/);
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
