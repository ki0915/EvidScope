import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync} from 'node:crypto';
import {mkdtempSync,readFileSync,readdirSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve,sep} from 'node:path';
import {createService} from '../src/service.mjs';
import {createVaultBackup,restoreVaultBackup} from '../src/vault-recovery.mjs';
import {harness} from './harness.mjs';
import {appendKrCheck,publicationMetrics} from './fixtures/kr-check-fixture.mjs';

const requirements=JSON.parse(readFileSync(new URL('../data/requirements.json',import.meta.url),'utf8'));
const system={id:'credit',name:'Synthetic credit',owner:'reviewer',purpose:'Loan assistance',markets:['KR'],krRoles:['deployer'],generative:false,highImpact:'confirmed',modelId:'credit-model',modelVersion:'v1',policyVersion:'credit-policy-v1'};
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const input=(id,bytes,extra={})=>({id,systemId:system.id,name:'조치 근거 문서.txt',mediaType:'text/plain',sha256:sha(bytes),contentBase64:bytes.toString('base64'),...extra});

function fixture(t){
 const dir=mkdtempSync(join(tmpdir(),'evidscope-governance-documents-'));
 const principals=[
  {id:'reviewer',role:'reviewer',tenant:'alpha',token:'r'.repeat(40)},
  {id:'admin',role:'admin',tenant:'alpha',token:'m'.repeat(40)},
  {id:'auditor',role:'auditor',tenant:'alpha',token:'a'.repeat(40)},
  {id:'beta-reviewer',role:'reviewer',tenant:'beta',token:'b'.repeat(40)},
 ];
 const {privateKey,publicKey}=generateKeyPairSync('ed25519'),service=createService({dataDir:dir,key:privateKey,config:{principals},requirements});
 t.after(()=>{service.store.close();assert.ok(resolve(dir).startsWith(resolve(tmpdir())+sep));rmSync(dir,{recursive:true,force:true});});
 const call=(path,body,who=0)=>service.handle(body===undefined?'GET':'POST',new URL(path,'http://local'),{authorization:'Bearer '+principals[who].token},body===undefined?'':JSON.stringify(body));
 return {dir,service,principals,privateKey,publicKey,call};
}

function assessment(evidence){
 return {systemId:system.id,requirementId:'KR-34-DOCUMENT',applicability:'applicable',assessment:'sufficient',legalReview:'reviewed',evidence,control:'Document retention control',owner:'reviewer',reason:'Human legal conclusion remains separate',nextReviewAt:'2099-01-01T00:00:00.000Z'};
}

const findStoredFile=(dir,hash)=>{
 const root=join(dir,'governance-documents');
 const tenantDirectory=readdirSync(root,{withFileTypes:true}).find(entry=>entry.isDirectory());
 const files=readdirSync(join(root,tenantDirectory.name));
 return join(root,tenantDirectory.name,hash?`${hash}.json`:files[0]);
};

test('reviewer intake stores and retrieves tenant-bound encrypted content-addressed bytes with a five-year metadata snapshot',async t=>{
 const h=fixture(t),bytes=Buffer.from('first-party Korean AI governance evidence');
 await h.call('/api/governance/systems',system);
 await assert.rejects(h.call('/api/governance/documents',input('doc-1',bytes),2),error=>error.status===403);
 const saved=await h.call('/api/governance/documents',input('doc-1',bytes));
 assert.equal(saved.version,1);assert.equal(saved.sha256,sha(bytes));assert.match(saved.snapshotHash,/^[a-f0-9]{64}$/);
 const expected=new Date(saved.receivedAt);expected.setUTCFullYear(expected.getUTCFullYear()+5);
 assert.equal(saved.retentionUntil,expected.toISOString());assert.match(saved.retentionBasis,/제27조제2항/);assert.match(saved.retentionBasis,/입증하지/);
 const stored=findStoredFile(h.dir);assert.equal(stored.includes('조치 근거 문서'),false);assert.equal(readFileSync(stored).includes(bytes),false);
 const detail=await h.call('/api/governance/documents/doc-1');assert.equal(detail.verification.status,'hash_verified_and_retrievable');
 const exported=await h.call('/api/governance/documents/doc-1/export',undefined,1);assert.deepEqual(Buffer.from(exported.contentBase64,'base64'),bytes);
 await assert.rejects(h.call('/api/governance/documents/doc-1',undefined,2),error=>error.status===403);
 await assert.rejects(h.call('/api/governance/documents/doc-1/export',undefined,3),error=>error.status===404);
 assert.deepEqual(h.service.store.ledgerObjects('alpha','governance_document'),[saved]);
});

test('intake rejects non-canonical base64, wrong hashes, oversized bytes, unknown systems and system reassignment',async t=>{
 const h=fixture(t),bytes=Buffer.from('document');await h.call('/api/governance/systems',system);
 for(const contentBase64 of ['ZA','ZA===',' Z A==',''])await assert.rejects(h.call('/api/governance/documents',{...input('bad-base64',bytes),contentBase64}),error=>error.status===400);
 await assert.rejects(h.call('/api/governance/documents',{...input('bad-hash',bytes),sha256:'0'.repeat(64)}),error=>error.status===400);
 await assert.rejects(h.call('/api/governance/documents',input('large',Buffer.alloc(4*1024*1024+1))),error=>error.status===413);
 await assert.rejects(h.call('/api/governance/documents',input('missing-system',bytes,{systemId:'missing'})),error=>error.status===404);
 await h.call('/api/governance/documents',input('stable-id',bytes));
 await h.call('/api/governance/systems',{...system,id:'other'});
 await assert.rejects(h.call('/api/governance/documents',input('stable-id',Buffer.from('revision'),{systemId:'other'})),error=>error.status===409);
});

test('a 256 KiB actual document is fully retrievable without treating its hash as a publication measurement',async t=>{
 const h=fixture(t),bytes=Buffer.alloc(256*1024,0x47);await h.call('/api/governance/systems',system);
 const saved=await h.call('/api/governance/documents',input('larger-real-document',bytes));assert.equal(saved.bytes,bytes.length);
 const exported=await h.call('/api/governance/documents/larger-real-document/export');assert.deepEqual(Buffer.from(exported.contentBase64,'base64'),bytes);
 await h.call('/api/governance/assessments',assessment([{type:'document',ref:'governance-document:larger-real-document'}]));
 const item=(await h.call('/api/governance/report?systemId=credit')).items.find(r=>r.requirement.id==='KR-34-DOCUMENT');assert.equal(item.status,'evidence_insufficient');assert.deepEqual(item.technicalEvidence.missingChecks,['document_publication_retention']);
});

test('assessment binds the signed document system, version, content hash and snapshot then permits task closure only while retrievable',async t=>{
 const h=fixture(t),bytes=Buffer.from('verified control evidence'),savedSystem=await h.call('/api/governance/systems',system);
 const missing=await h.call('/api/governance/assessments',assessment([{type:'document',ref:'external-only'}]));
 const open=(await h.call('/api/governance')).tasks.find(task=>task.id===missing.id);
 await assert.rejects(h.call(`/api/governance/tasks/${open.id}`,{status:'closed',reason:'premature'}),error=>error.status===409);
 await new Promise(resolve=>setTimeout(resolve,2));await h.call('/api/governance/assessments',{...assessment([{type:'document',ref:'external-only'}]),applicability:'not_applicable'});
 await assert.rejects(h.call(`/api/governance/tasks/${open.id}`,{status:'closed',reason:'unverified not-applicable claim'}),error=>error.status===409);
 const document=await h.call('/api/governance/documents',input('control-evidence',bytes));
 await h.call('/api/governance/systems',{...system,id:'other'});
 await assert.rejects(h.call('/api/governance/assessments',{...assessment([{type:'document',ref:'governance-document:control-evidence'}]),systemId:'other'}),error=>error.status===400&&/다른 시스템/.test(error.message));
 await new Promise(resolve=>setTimeout(resolve,2));
 await h.call('/api/governance/assessments',assessment([{type:'document',ref:'governance-document:control-evidence',version:'999',contentHash:'0'.repeat(64)}]));
 let item=(await h.call('/api/governance/report?systemId=credit')).items.find(value=>value.requirement.id==='KR-34-DOCUMENT');assert.equal(item.status,'evidence_insufficient');assert.deepEqual(item.technicalEvidence.missingChecks,['document_publication_retention']);
 await assert.rejects(h.call(`/api/governance/tasks/${open.id}`,{status:'closed',reason:'Hash alone'}),error=>error.status===409);
 const measurement=appendKrCheck(h.service,savedSystem,requirements.find(r=>r.id==='KR-34-DOCUMENT'),document,'document_publication_retention',publicationMetrics);
 const saved=await h.call('/api/governance/assessments',assessment([{type:'document',ref:'governance-document:control-evidence',version:'999',contentHash:'0'.repeat(64)},measurement]));
 assert.equal(saved.evidence[0].version,'1');assert.equal(saved.evidence[0].contentHash,document.sha256);assert.equal(saved.evidence[0].documentSnapshotHash,document.snapshotHash);
 assert.equal(saved.evidence[0].verification,'governance_document_verified_at_assessment');
 item=(await h.call('/api/governance/report?systemId=credit')).items.find(value=>value.requirement.id==='KR-34-DOCUMENT');
 assert.equal(item.status,'human_evidence_assessed');assert.equal(item.technicalStatus,'authenticated_reported_measurement_supported');
 assert.equal(saved.evidence[1].eventSnapshot.governanceCheck.documentHash,document.sha256);assert.equal(item.technicalEvidence.automaticLegalVerdict,false);
 assert.equal((await h.call(`/api/governance/tasks/${open.id}`,{status:'closed',reason:'verified bytes and snapshot'})).status,'closed');
});

test('new document revision invalidates the assessment and corruption keeps review work open until a new verified snapshot',async t=>{
 const h=fixture(t),v1=Buffer.from('version one'),v2=Buffer.from('version two'),savedSystem=await h.call('/api/governance/systems',system);
 const firstDocument=await h.call('/api/governance/documents',input('revised',v1)),firstMeasurement=appendKrCheck(h.service,savedSystem,requirements.find(r=>r.id==='KR-34-DOCUMENT'),firstDocument,'document_publication_retention',publicationMetrics);
 await h.call('/api/governance/assessments',assessment([{type:'document',ref:'governance-document:revised'},firstMeasurement]));
 assert.equal((await h.call('/api/governance/report?systemId=credit')).items.find(value=>value.requirement.id==='KR-34-DOCUMENT').status,'human_evidence_assessed');
 const revised=await h.call('/api/governance/documents',input('revised',v2));assert.equal(revised.version,2);
 let report=await h.call('/api/governance/report?systemId=credit'),item=report.items.find(value=>value.requirement.id==='KR-34-DOCUMENT');
 assert.equal(item.status,'review_required');assert.equal(item.technicalStatus,'typed_evidence_insufficient');assert.ok(item.technicalEvidence.reasons.includes('document_evidence_stale'));
 const revisionTask=report.tasks.find(task=>task.documentId==='revised');assert.equal(revisionTask.status,'open');
 await assert.rejects(h.call(`/api/governance/tasks/${revisionTask.id}`,{status:'closed',reason:'old assessment'}),error=>error.status===409);
 await new Promise(resolve=>setTimeout(resolve,2));
 await h.call('/api/governance/assessments',assessment([{type:'document',ref:'governance-document:revised'},firstMeasurement]));
 assert.equal((await h.call('/api/governance/report?systemId=credit')).items.find(value=>value.requirement.id==='KR-34-DOCUMENT').status,'evidence_insufficient','A v1 publication measurement cannot certify v2 bytes');
 const revisedMeasurement=appendKrCheck(h.service,savedSystem,requirements.find(r=>r.id==='KR-34-DOCUMENT'),revised,'document_publication_retention',publicationMetrics);
 await new Promise(resolve=>setTimeout(resolve,2));await h.call('/api/governance/assessments',assessment([{type:'document',ref:'governance-document:revised'},revisedMeasurement]));
 assert.equal((await h.call('/api/governance/report?systemId=credit')).items.find(value=>value.requirement.id==='KR-34-DOCUMENT').status,'human_evidence_assessed');
 writeFileSync(findStoredFile(h.dir,revised.sha256),'corrupt encrypted bytes');
 report=await h.call('/api/governance/report?systemId=credit');item=report.items.find(value=>value.requirement.id==='KR-34-DOCUMENT');
 assert.equal(item.status,'review_required');assert.equal(item.technicalStatus,'typed_evidence_insufficient');assert.ok(item.technicalEvidence.reasons.includes('document_evidence_stale'));
 await assert.rejects(h.call('/api/governance/documents/revised/export'),error=>error.status===409);
 await assert.rejects(h.call(`/api/governance/tasks/${revisionTask.id}`,{status:'closed',reason:'corrupt bytes'}),error=>error.status===409);
});

test('governance document projection tampering is rejected and cannot create a verified assessment',async t=>{
 const h=fixture(t),bytes=Buffer.from('projection-bound');await h.call('/api/governance/systems',system);await h.call('/api/governance/documents',input('projected',bytes));
 const row=h.service.store.db.prepare("SELECT body FROM governance_documents WHERE tenant='alpha' AND id='projected'").get();
 const forged={...JSON.parse(row.body),sha256:'f'.repeat(64)};h.service.store.db.prepare("UPDATE governance_documents SET body=? WHERE tenant='alpha' AND id='projected'").run(JSON.stringify(forged));
 await assert.rejects(h.call('/api/governance/documents/projected'),error=>error.status===409);
 await assert.rejects(h.call('/api/governance/assessments',assessment([{type:'document',ref:'governance-document:projected'}])),error=>error.status===409);
});

test('HTTP boundary accepts and retrieves a complete 4 MiB document and rejects documents or payloads above their limits',async t=>{
 const h=await harness({vaultOnly:true});t.after(()=>h.close());
 const httpSystem={...system,id:'credit-http'};assert.equal((await h.api('/api/governance/systems',{body:httpSystem,role:'reviewer'})).status,200);
 const bytes=Buffer.alloc(4*1024*1024,0x41),body=input('http-max',bytes,{systemId:httpSystem.id});
 const response=await h.api('/api/governance/documents',{body,role:'reviewer'});assert.equal(response.status,200);assert.equal(response.body.sha256,sha(bytes));
 assert.equal(response.body.bytes,bytes.length);
 const exported=await h.api('/api/governance/documents/http-max/export',{role:'reviewer'});assert.equal(exported.status,200);assert.deepEqual(Buffer.from(exported.body.contentBase64,'base64'),bytes);
 const tooLarge=await h.api('/api/governance/documents',{body:input('http-too-large',Buffer.alloc(4*1024*1024+1,0x41),{systemId:httpSystem.id}),role:'reviewer'});assert.equal(tooLarge.status,413);
 const tooLargePayload=await h.api('/api/governance/documents',{body:{...body,contentBase64:'A'.repeat(6*1024*1024)},role:'reviewer'});assert.equal(tooLargePayload.status,413);
 const index=await h.api('/api/governance',{role:'reviewer'});assert.equal(index.body.governanceDocuments.length,1,'Rejected document and oversized HTTP requests must not publish metadata');
});

test('vault backup verifies and restores governance document ciphertext and signed metadata without claiming elapsed retention',async t=>{
 const h=fixture(t),bytes=Buffer.from('recoverable first-party governance evidence'),revisedBytes=Buffer.from('revised recoverable governance evidence'),savedSystem=await h.call('/api/governance/systems',system);
 const output=mkdtempSync(join(tmpdir(),'evidscope-governance-recovery-'));
 await h.call('/api/governance/documents',input('recoverable',bytes));const saved=await h.call('/api/governance/documents',input('recoverable',revisedBytes)),backupDir=join(output,'backup'),restoreDir=join(output,'restored');
 const measurement=appendKrCheck(h.service,savedSystem,requirements.find(r=>r.id==='KR-34-DOCUMENT'),saved,'document_publication_retention',publicationMetrics);await h.call('/api/governance/assessments',assessment([{type:'document',ref:'governance-document:recoverable'},measurement]));
 const anchor=await createVaultBackup({dataDir:h.dir,backupDir,privateKey:h.privateKey,publicKey:h.publicKey});
 const manifest=JSON.parse(readFileSync(join(backupDir,'manifest.json'))),members=manifest.files.filter(file=>file.path.startsWith('governance-documents/'));
 assert.equal(members.length,2);assert.match(manifest.scope,/does not prove elapsed five-year retention/);for(const member of members){const encrypted=readFileSync(join(backupDir,...member.path.split('/')));assert.equal(encrypted.includes(bytes),false);assert.equal(encrypted.includes(revisedBytes),false);}
 const receipt=await restoreVaultBackup({backupDir,restoreDir,privateKey:h.privateKey,publicKey:h.publicKey,anchor});assert.equal(receipt.governanceDocuments,2);assert.match(receipt.scope,/not elapsed five-year retention/);
 const restored=createService({dataDir:restoreDir,key:h.privateKey,config:{principals:h.principals},requirements});t.after(()=>restored.store.close());t.after(()=>{assert.ok(resolve(output).startsWith(resolve(tmpdir())+sep));rmSync(output,{recursive:true,force:true});});
 const call=(path,who=0)=>restored.handle('GET',new URL(path,'http://local'),{authorization:'Bearer '+h.principals[who].token});
 const metadata=await call('/api/governance/documents/recoverable');assert.equal(metadata.snapshotHash,saved.snapshotHash);assert.equal(metadata.verification.status,'hash_verified_and_retrievable');
 assert.equal((await call('/api/governance/documents/recoverable/export')).contentBase64,revisedBytes.toString('base64'));assert.equal(restored.store.rawBundle('alpha').records.filter(row=>row.type==='governance_document').length,2);
 const restoredAssessment=(await call('/api/governance/report?systemId=credit')).items.find(r=>r.requirement.id==='KR-34-DOCUMENT');assert.equal(restoredAssessment.status,'human_evidence_assessed');assert.equal(restoredAssessment.technicalStatus,'authenticated_reported_measurement_supported');assert.equal(restoredAssessment.assessment.evidence[1].ref,measurement.ref);
 await assert.rejects(call('/api/governance/documents/recoverable',3),error=>error.status===404);
 h.service.store.db.prepare("UPDATE governance_documents SET body=? WHERE tenant='alpha' AND id='recoverable'").run('{}');
 await assert.rejects(createVaultBackup({dataDir:h.dir,backupDir:join(output,'forged-backup'),privateKey:h.privateKey,publicKey:h.publicKey}),/거버넌스 문서 조회 사본/);
});
