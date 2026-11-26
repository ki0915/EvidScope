import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,randomUUID} from 'node:crypto';
import {mkdtempSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createService} from '../src/service.mjs';
import {digest} from '../src/crypto.mjs';

// Regression tests for adversarial-audit finding S11: self-asserted evidence is labelled, a legal review counts only when
// a principal other than the assessment author confirms it, and the author cannot close the governance task.
const requirements=JSON.parse(readFileSync(new URL('../data/requirements.json',import.meta.url),'utf8'));
const system={id:'sys1',name:'S',owner:'o',purpose:'p',markets:['EU','KR'],euRoles:['provider'],krRoles:['developer'],domesticImpact:true,
 aiBusinessOperator:true,defenceOrNationalSecurityOnly:false,highImpact:'confirmed',providedAt:new Date().toISOString()};
const principals=[
 {id:'author',role:'reviewer',tenant:'alpha',token:'a'.repeat(40)},
 {id:'legal',role:'reviewer',tenant:'alpha',token:'l'.repeat(40)},
 {id:'viewer',role:'auditor',tenant:'alpha',token:'v'.repeat(40)},
];
function fixture(t){
 const dir=mkdtempSync(join(tmpdir(),'evidscope-governance-separation-'));
 const service=createService({dataDir:dir,key:generateKeyPairSync('ed25519').privateKey,config:{principals},requirements});
 t.after(()=>{service.store.close();rmSync(dir,{recursive:true,force:true});});
 const call=(path,body,who='author')=>service.handle(body===undefined?'GET':'POST',new URL(path,'http://local'),
  {authorization:'Bearer '+principals.find(p=>p.id===who).token},body===undefined?'':JSON.stringify(body));
 const assess=(evidence,extra={})=>call('/api/governance/assessments',{systemId:system.id,requirementId:'EU-50-1',applicability:'applicable',
  assessment:'sufficient',legalReview:'reviewed',evidence,control:'c',owner:'o',reason:'because',nextReviewAt:'2099-01-01T00:00:00.000Z',...extra});
 const item=async(id='EU-50-1')=>(await call('/api/governance/report?systemId='+system.id)).items.find(i=>i.requirement.id===id);
 const confirm=(assessment,who='legal')=>call(`/api/governance/assessments/${assessment.id}/legal-review`,{reason:'independent legal review'},who);
 const close=(task,who='author')=>call(`/api/governance/tasks/${task.id}`,{status:'closed',reason:'done'},who);
 return {service,call,assess,item,confirm,close};
}
const promise=[{type:'attestation',ref:'we promise it is fine',notes:'self-declared'}];

test('S11: self-asserted non-KR evidence is labelled and one reviewer cannot author, legal-review and close',async t=>{
 const h=fixture(t);await h.call('/api/governance/systems',system);
 const task=await h.assess(promise,{assessment:'insufficient'}),current=await h.assess(promise);
 let row=await h.item();
 assert.equal(row.status,'human_evidence_assessed');assert.equal(row.evidenceAssurance.level,'self_asserted');
 assert.deepEqual(row.evidenceAssurance.items,[{type:'attestation',ref:'we promise it is fine',assurance:'self_asserted'}]);
 assert.equal(row.technicalEvidence.assurance,'self_asserted');assert.match(row.technicalEvidence.limitations[0],/self_asserted/);
 assert.equal(row.legalStatus,'pending');assert.equal(row.legalReview.authorClaim,'reviewed');assert.equal(row.legalReview.status,'pending');
 await assert.rejects(h.close(task),error=>error.status===409,'an unconfirmed legal review blocks closure');
 await assert.rejects(h.confirm(current,'author'),error=>error.status===403,'the author cannot confirm a legal review');
 await assert.rejects(h.confirm(current,'viewer'),error=>error.status===403,'an auditor cannot record a legal review');
 await assert.rejects(h.call(`/api/governance/assessments/${current.id}/legal-review`,{reason:' '},'legal'),error=>error.status===400);
 const review=await h.confirm(current);assert.equal(review.reviewedBy,'legal');assert.equal(review.assessmentHash,digest(current));
 row=await h.item();assert.equal(row.legalStatus,'reviewed');assert.equal(row.legalReview.reviewedBy,'legal');
 await assert.rejects(h.close(task),error=>error.status===403,'the author cannot close a task over their own assessment');
 assert.equal((await h.close(task,'legal')).status,'closed');
});

test('S11: a legal review binds the exact current assessment and never counts the author',async t=>{
 const h=fixture(t);await h.call('/api/governance/systems',system);
 const first=await h.assess(promise);await h.confirm(first);assert.equal((await h.item()).legalStatus,'reviewed');
 const second=await h.assess(promise,{reason:'changed conclusion'});
 assert.equal((await h.item()).legalStatus,'pending','a new assessment needs its own review');
 await assert.rejects(h.confirm(first),error=>error.status===409,'only the latest assessment can be confirmed');
 await h.confirm(second);assert.equal((await h.item()).legalStatus,'reviewed');
 // A signed confirmation naming the author (for example written around the endpoint) is ignored by the report.
 const third=await h.assess(promise,{reason:'third conclusion'}),id=randomUUID();
 h.service.store.transaction(()=>h.service.store.put({id:'author',tenant:'alpha'},'governance_legal_review',id,{id,assessmentId:third.id,
  assessmentHash:digest(third),systemId:system.id,requirementId:'EU-50-1',decision:'reviewed',reason:'self',reviewedBy:'author',
  reviewedAt:new Date().toISOString()}));
 assert.equal((await h.item()).legalStatus,'pending');
});

test('S11: assurance distinguishes vault-bound documents and source events from self-asserted references',async t=>{
 const h=fixture(t);await h.call('/api/governance/systems',system);
 const bytes=Buffer.from('retained policy'),sha256=createHash('sha256').update(bytes).digest('hex');
 const upload={id:'policy',systemId:system.id,name:'policy.txt',mediaType:'text/plain',sha256,contentBase64:bytes.toString('base64')};
 await h.call('/api/governance/documents',upload);
 const store=h.service.store,event={tenant:'alpha',source:'eu-tool',sourceKind:'tool',id:'execution',actionId:'action',systemId:system.id,traceId:'trace',
  kind:'execution',receivedAt:'2026-09-29T00:00:00.000Z',occurredAt:'2026-09-29T00:00:00.000Z',fingerprint:'synthetic'};
 store.transaction(()=>{const record=store.append('alpha','event',event,'eu-tool');store.project({...event,seq:record.seq,hash:record.hash});});
 await h.assess([{type:'document',ref:'governance-document:policy'},{type:'event',ref:'eu-tool/execution'},{type:'test',ref:'https://example.invalid/report'}]);
 const row=await h.item();
 assert.deepEqual(row.evidenceAssurance.items.map(i=>i.assurance),['vault_verified_document','authenticated_source_record','self_asserted']);
 assert.equal(row.evidenceAssurance.level,'mixed');assert.equal(row.evidenceAssurance.selfAssertedItems,1);
 await h.assess([{type:'document',ref:'governance-document:policy'}]);assert.equal((await h.item()).evidenceAssurance.level,'source_bound');
});
