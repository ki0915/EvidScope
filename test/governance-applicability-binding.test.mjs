import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,verify} from 'node:crypto';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve,sep} from 'node:path';
import {createService} from '../src/service.mjs';
import {canonical,digest} from '../src/crypto.mjs';
import {applicabilityAssessmentSnapshot,applicabilityCatalogIdentity,applicabilityPolicyVersion} from '../src/governance-policy.mjs';
import {appendKrCheck} from './fixtures/kr-check-fixture.mjs';

const requirement={id:'KR-34-RISK',title:'Risk management'};
const system={id:'credit',name:'Synthetic credit',owner:'reviewer',purpose:'credit assistance',markets:['KR'],krRoles:['deployer'],generative:false,highImpact:'candidate',modelId:'credit-model',modelVersion:'v1',policyVersion:'credit-policy-v1'};
const assessment={systemId:'credit',requirementId:requirement.id,applicability:'applicable',assessment:'sufficient',legalReview:'reviewed',control:'Synthetic review',owner:'reviewer',reason:'Human reviewed the evidence',nextReviewAt:'2099-01-01T00:00:00.000Z',evidence:[{type:'document',ref:'external-reference',version:'1'}]};

function fixture(t){
 const dir=mkdtempSync(join(tmpdir(),'evidscope-applicability-')),key=generateKeyPairSync('ed25519').privateKey,principal={id:'reviewer',tenant:'alpha',role:'reviewer',token:'r'.repeat(40)},options={dataDir:dir,key,config:{principals:[principal]},requirements:[requirement]};
 let service=createService(options);
 const call=(path,body)=>service.handle(body===undefined?'GET':'POST',new URL(path,'http://local'),{authorization:'Bearer '+principal.token},body===undefined?'':JSON.stringify(body));
 const restart=()=>{service.store.close();service=createService(options);return service;};
 const measuredAssessment=async savedSystem=>{const bytes=Buffer.from('Synthetic documented risk control, organisation and operating review'),document=await call('/api/governance/documents',{id:'risk-control',systemId:system.id,name:'risk-control.txt',mediaType:'text/plain',sha256:createHash('sha256').update(bytes).digest('hex'),contentBase64:bytes.toString('base64')}),measurement=appendKrCheck(service,savedSystem,requirement,document,'high_impact_risk_management',{riskPolicyRecorded:true,responsibleOrganisationRecorded:true,operatingReviewRecorded:true,mitigationTestPassed:true,residualRiskReviewed:true});return {...assessment,evidence:[{type:'document',ref:'governance-document:risk-control'},measurement]};};
 t.after(()=>{service.store.close();assert.ok(resolve(dir).startsWith(resolve(tmpdir())+sep));rmSync(dir,{recursive:true,force:true});});
 return {call,restart,principal,measuredAssessment,get service(){return service;}};
}

test('assessment signs a server-computed applicability snapshot and ignores client provenance fields',async t=>{
 const h=fixture(t),savedSystem=await h.call('/api/governance/systems',system);
 const supplied=await h.measuredAssessment(savedSystem),saved=await h.call('/api/governance/assessments',{...supplied,applicabilityPolicyVersion:'client-policy',applicabilitySnapshot:{forged:true},applicabilitySnapshotHash:'0'.repeat(64)});
 const expected=applicabilityAssessmentSnapshot(requirement,savedSystem);
 assert.equal(saved.applicabilityPolicyVersion,applicabilityPolicyVersion);
 assert.deepEqual(saved.applicabilitySnapshot,expected.snapshot);
 assert.equal(saved.applicabilitySnapshotHash,expected.hash);
 assert.equal(saved.applicabilitySnapshotHash,digest(saved.applicabilitySnapshot));
 assert.deepEqual(h.service.store.ledgerObjects('alpha','assessment').at(-1),saved);
 const report=await h.call('/api/governance/report?systemId=credit'),item=report.items[0];
 assert.equal(item.status,'human_evidence_assessed');
 assert.equal(item.technicalStatus,'authenticated_reported_measurement_supported');assert.equal(saved.evidence[1].eventSnapshot.governanceCheck.systemHash,digest(savedSystem));assert.equal(saved.evidence[1].eventSnapshot.governanceCheck.requirementHash,digest(requirement));
 assert.deepEqual(item.applicabilityReview,{status:'current',reasons:[],assessmentPolicyVersion:applicabilityPolicyVersion,currentPolicyVersion:applicabilityPolicyVersion,assessmentSnapshotHash:expected.hash,currentSnapshotHash:expected.hash});
 assert.equal(report.applicabilityPolicyIdentityHash,applicabilityCatalogIdentity([requirement]).hash);
});

test('legacy catalog and assessment provenance trigger a signed re-review task without replacing the human conclusion',async t=>{
 const h=fixture(t),savedSystem=await h.call('/api/governance/systems',system);
 const saved=await h.call('/api/governance/assessments',await h.measuredAssessment(savedSystem)),{applicabilityPolicyVersion:ignoredVersion,applicabilitySnapshot:ignoredSnapshot,applicabilitySnapshotHash:ignoredHash,...legacy}=saved;
 const oldCatalog={hash:digest([requirement]),requirements:[requirement],createdAt:'2026-01-22T00:00:00.000Z'};
 h.service.store.transaction(()=>{h.service.store.put(h.principal,'assessment',saved.id,legacy);h.service.store.put(h.principal,'catalog','current',oldCatalog);});
 h.restart();
 const report=await h.call('/api/governance/report?systemId=credit'),item=report.items[0];
 assert.equal(item.status,'review_required');
 assert.equal(item.legalStatus,'review_required');
 assert.equal(item.assessment.applicability,'applicable');
 assert.equal(item.assessment.assessment,'sufficient');
 assert.equal(item.assessment.legalReview,'reviewed');
 assert.deepEqual(item.applicabilityReview.reasons,['assessment_snapshot_missing']);
 const task=report.tasks.find(value=>value.requirementId===requirement.id&&/적용 후보 정책 버전 변경/.test(value.title));
 assert.ok(task);assert.equal(task.status,'open');assert.equal(task.previousPolicyVersion,'not_recorded');assert.equal(task.currentPolicyVersion,applicabilityPolicyVersion);
 assert.equal(task.previousHash,oldCatalog.hash);assert.equal(task.currentHash,applicabilityCatalogIdentity([requirement]).hash);
});

test('signed finance reports freeze policy provenance while a later fact change only marks the live review stale',async t=>{
 const h=fixture(t),savedSystem=await h.call('/api/governance/systems',system);await h.call('/api/governance/assessments',await h.measuredAssessment(savedSystem));
 const first=await h.call('/api/governance/finance/report',{systemId:'credit'}),frozen=canonical(first.snapshot);
 assert.equal(first.snapshot.applicabilityPolicyVersion,applicabilityPolicyVersion);
 assert.equal(first.snapshot.applicabilityPolicyIdentityHash,applicabilityCatalogIdentity([requirement]).hash);
 assert.equal(first.snapshot.governance.items[0].applicabilityReview.status,'current');
 assert.equal(first.snapshot.governance.items[0].technicalStatus,'authenticated_reported_measurement_supported');
 assert.equal(first.snapshot.automaticLegalVerdict,false);
 assert.ok(verify(null,Buffer.from(canonical(first.snapshot)),first.publicKey,Buffer.from(first.signature,'base64')));
 await h.call('/api/governance/systems',{...system,modelVersion:'v2'});
 const live=await h.call('/api/governance/report?systemId=credit');
 assert.equal(live.items[0].status,'review_required');
 assert.equal(live.items[0].assessment.applicability,'applicable');
 assert.ok(live.items[0].applicabilityReview.reasons.includes('applicability_candidate_changed'));
 assert.equal(live.items[0].technicalStatus,'typed_evidence_insufficient');assert.ok(live.items[0].technicalEvidence.reasons.some(reason=>reason.includes('system_facts_hash_mismatch')));
 const retained=await h.call('/api/governance/finance/reports/'+first.id);
 assert.equal(canonical(retained.snapshot),frozen);
 assert.ok(verify(null,Buffer.from(canonical(retained.snapshot)),retained.publicKey,Buffer.from(retained.signature,'base64')));
 const second=await h.call('/api/governance/finance/report',{systemId:'credit'});
 assert.equal(second.snapshot.governance.items[0].status,'review_required');
 assert.equal(second.snapshot.governance.items[0].assessment.legalReview,'reviewed');
 assert.equal(second.snapshot.automaticLegalVerdict,false);
});
