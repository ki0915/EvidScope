import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync} from 'node:crypto';
import {mkdtempSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve,sep} from 'node:path';
import {createService} from '../src/service.mjs';
import {appendKrCheck} from './fixtures/kr-check-fixture.mjs';

const requirements=JSON.parse(readFileSync(new URL('../data/requirements.json',import.meta.url),'utf8'));
const system={id:'credit',name:'Synthetic credit',owner:'reviewer',purpose:'Loan assistance',markets:['KR'],krRoles:['deployer'],generative:false,highImpact:'confirmed',modelId:'credit-model',modelVersion:'v1',policyVersion:'credit-policy-v1'};

function fixture(t){
 const dir=mkdtempSync(join(tmpdir(),'evidscope-document-evidence-')),principal={id:'reviewer',role:'reviewer',tenant:'alpha',token:'x'.repeat(40)};
 const service=createService({dataDir:dir,key:generateKeyPairSync('ed25519').privateKey,config:{principals:[principal]},requirements});
 t.after(()=>{service.store.close();assert.ok(resolve(dir).startsWith(resolve(tmpdir())+sep));rmSync(dir,{recursive:true,force:true});});
 const call=(path,body)=>service.handle(body===undefined?'GET':'POST',new URL(path,'http://local'),{authorization:'Bearer '+principal.token},body===undefined?'':JSON.stringify(body));
 return {service,principal,call};
}

function assessment(requirementId,evidence){
 return {systemId:system.id,requirementId,applicability:'applicable',assessment:'sufficient',legalReview:'reviewed',evidence,control:'Synthetic control review',owner:'reviewer',reason:'Human conclusion retained independently',nextReviewAt:'2099-01-01T00:00:00.000Z'};
}

for(const [name,evidence] of [
 ['missing document',[{type:'attestation',ref:'document-exists-claim'}]],
 ['unhashed external document',[{type:'document',ref:'missing-file'}]],
 ['unretrievable externally hashed document',[{type:'document',ref:'missing-file',version:'1',contentHash:'a'.repeat(64)}]],
])test(`KR-34-DOCUMENT keeps ${name} technically insufficient and its task open`,async t=>{
 const h=fixture(t);await h.call('/api/governance/systems',system);
 const saved=await h.call('/api/governance/assessments',assessment('KR-34-DOCUMENT',evidence));
 assert.equal(saved.assessment,'sufficient');assert.equal(saved.legalReview,'reviewed','The human conclusion remains immutable evidence');
 const item=(await h.call('/api/governance/report?systemId=credit')).items.find(v=>v.requirement.id==='KR-34-DOCUMENT');
 assert.equal(item.assessment.id,saved.id);assert.equal(item.assessment.assessment,'sufficient');assert.equal(item.assessment.legalReview,'reviewed');
 assert.equal(item.status,'evidence_insufficient');assert.equal(item.technicalStatus,'typed_evidence_insufficient');
 assert.deepEqual(item.technicalEvidence.missingChecks,['document_publication_retention']);assert.ok(item.technicalEvidence.reasons.includes('verified_measure_document_missing'));
 const task=(await h.call('/api/governance')).tasks.find(v=>v.id===saved.id);assert.equal(task?.status,'open');
 await assert.rejects(h.call(`/api/governance/tasks/${task.id}`,{status:'closed',reason:'Claimed complete'}),error=>error.status===409&&/검증 가능한.*증거/.test(error.message));
 assert.equal((await h.call('/api/governance')).tasks.find(v=>v.id===saved.id).status,'open');
});

test('a verified tool execution alone leaves risk control insufficient until a scoped risk measurement and actual document are linked',async t=>{
 const h=fixture(t),savedSystem=await h.call('/api/governance/systems',system);
 const event={tenant:h.principal.tenant,source:'credit-tool',sourceKind:'tool',id:'execution',actionId:'action',systemId:system.id,traceId:'trace',kind:'execution',receivedAt:'2026-09-29T00:00:00.000Z',occurredAt:'2026-09-29T00:00:00.000Z',fingerprint:'synthetic'};
 h.service.store.transaction(()=>{const record=h.service.store.append(h.principal.tenant,'event',event,h.principal.id);h.service.store.project({...event,seq:record.seq,hash:record.hash});});
 await h.call('/api/governance/assessments',assessment('KR-34-RISK',[{type:'event',ref:'credit-tool/execution'}]));
 let item=(await h.call('/api/governance/report?systemId=credit')).items.find(v=>v.requirement.id==='KR-34-RISK');
 assert.equal(item.status,'evidence_insufficient');assert.equal(item.technicalStatus,'typed_evidence_insufficient');assert.deepEqual(item.technicalEvidence.missingChecks,['high_impact_risk_management']);
 const task=(await h.call('/api/governance')).tasks.find(v=>v.requirementId==='KR-34-RISK');assert.equal(task.status,'open');
 await assert.rejects(h.call(`/api/governance/tasks/${task.id}`,{status:'closed',reason:'Execution happened'}),error=>error.status===409);
 const bytes=Buffer.from('Synthetic documented risk policy, organisation, mitigation test and residual risk review');
 const document=await h.call('/api/governance/documents',{id:'risk-policy',systemId:system.id,name:'risk-policy.txt',mediaType:'text/plain',sha256:createHash('sha256').update(bytes).digest('hex'),contentBase64:bytes.toString('base64')});
 const measured=appendKrCheck(h.service,savedSystem,requirements.find(r=>r.id==='KR-34-RISK'),document,'high_impact_risk_management',{riskPolicyRecorded:true,responsibleOrganisationRecorded:true,operatingReviewRecorded:true,mitigationTestPassed:true,residualRiskReviewed:true});
 await h.call('/api/governance/assessments',assessment('KR-34-RISK',[{type:'document',ref:'governance-document:risk-policy'},{type:'event',ref:'credit-tool/execution'},measured]));
 item=(await h.call('/api/governance/report?systemId=credit')).items.find(v=>v.requirement.id==='KR-34-RISK');assert.equal(item.status,'human_evidence_assessed');assert.equal(item.technicalStatus,'authenticated_reported_measurement_supported');assert.equal(item.technicalEvidence.automaticLegalVerdict,false);
 assert.equal(item.assessment.evidence[2].eventSnapshot.governanceCheck.systemHash,item.assessment.systemHash);
 assert.equal((await h.call(`/api/governance/tasks/${task.id}`,{status:'closed',reason:'Current document and reported risk measurements reviewed'})).status,'closed');
});
