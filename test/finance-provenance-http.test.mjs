import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,verify} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {join} from 'node:path';
import {harness} from './harness.mjs';
import {canonical,digest,verifyBundle} from '../src/crypto.mjs';

// These bytes are test fixtures submitted through the non-synthetic input contract.
// Neither synthetic:false nor a recorded review makes them actual supplier proof.
const system={id:'provenance-credit',name:'출처 검토 HTTP fixture',owner:'감사팀',purpose:'대출 심사 보조',role:'deployer',krRoles:['deployer'],markets:['KR'],domain:'credit',generative:false,highImpact:'candidate',supplierId:'supplier-a',modelId:'credit-score',modelVersion:'v1',suppliedModelVersion:'v1',suppliedPurpose:'대출 심사 보조',substantialModification:false};
function input(text='HTTP provenance test fixture; not customer or supplier evidence.'){
 const bytes=Buffer.from(text);
 return {id:'provenance-bundle',systemId:system.id,synthetic:false,supplierId:system.supplierId,modelId:system.modelId,modelVersion:system.modelVersion,purpose:system.purpose,testScope:'입력 계약 검증용 fixture',measures:['KR-34-RISK'],provenance:{channel:'supplier_portal',reference:'fixture://delivery/001',suppliedAt:'2026-10-01T00:00:00.000Z'},documents:[{id:'fixture-doc',name:'fixture.txt',sha256:createHash('sha256').update(bytes).digest('hex'),contentBase64:bytes.toString('base64')}],reviewerNotes:'실제 공급사 자료 아님; HTTP 입력·검토 계약 시험'};
}
const reviewPath='/api/governance/bundles/provenance-bundle/provenance-reviews';
const allChecks={supplierIdentityChecked:true,deliveryReferenceChecked:true,modelPurposeScopeChecked:true};
const reviewInput=(bundle,decision='verified')=>({bundleHash:bundle.contentHash,decision,reason:'Fixture의 인증된 검토 기록 계약 확인',checks:allChecks});
const assessment={systemId:system.id,requirementId:'KR-34-RISK',applicability:'applicable',assessment:'sufficient',legalReview:'reviewed',evidence:[{type:'document',ref:'supplier-bundle:provenance-bundle'}],control:'공급사 증빙 대조',owner:'감사팀',reason:'Fixture 평가 연결 검증',nextReviewAt:'2099-01-01T00:00:00Z'};
async function api(h,path,options,status=200){const response=await h.api(path,options);assert.equal(response.status,status,`${path}: ${JSON.stringify(response.body)}`);return response.body;}
const post=(h,path,body,status=200,role='reviewer',tenant='alpha')=>api(h,path,{body,role,tenant},status);
async function current(h,tenant='alpha'){return (await api(h,'/api/governance/finance?systemId='+system.id,{tenant})).bundles[0];}
async function governanceItem(h){return (await api(h,'/api/governance/report?systemId='+system.id)).items.find(x=>x.requirement.id==='KR-34-RISK');}
function provenance(bundle,status){assert.equal(bundle.verification.provenance.status,status);assert.equal(bundle.verification.provenance.sourceAuthentication,'not_independently_verified');assert.equal(bundle.verification.legalDecision,'human_review_required');}

test('actual HTTP provenance: authenticated latest review, assessment invalidation, tenant isolation and frozen signed history',async t=>{
 const h=await harness();t.after(()=>h.close());
 await post(h,'/api/governance/systems',system);
 const bundle=await post(h,'/api/governance/bundles',input());
 assert.equal(bundle.schemaVersion,2);assert.equal(bundle.synthetic,false);assert.deepEqual(bundle.provenance,input().provenance);provenance(bundle,'unreviewed');
 assert.equal(bundle.receivedBy,'alpha-reviewer');assert.equal(bundle.verification.status,'review_required');assert.ok(bundle.verification.issues.includes('REAL_PROVENANCE_REVIEW_REQUIRED'));
 await post(h,'/api/governance/assessments',assessment,400);
 assert.deepEqual((await api(h,reviewPath)).reviews,[]);
 await post(h,reviewPath,reviewInput(bundle),403,'auditor');
 await post(h,reviewPath,reviewInput(bundle),403,'agent');
 await post(h,reviewPath,reviewInput(bundle),401,'missing');
 await post(h,reviewPath,reviewInput(bundle),404,'reviewer','beta');
 await api(h,reviewPath,{tenant:'beta'},404);
 await post(h,reviewPath,{...reviewInput(bundle),bundleHash:'0'.repeat(64)},409);
 await post(h,reviewPath,{...reviewInput(bundle),checks:{...allChecks,deliveryReferenceChecked:false}},400);
 await post(h,reviewPath,{...reviewInput(bundle),reviewer:'spoofed',reviewedAt:'2000-01-01T00:00:00Z'},400);
 assert.equal((await api(h,reviewPath)).reviews.length,0,'Rejected input must not append a review');
 const first=await post(h,reviewPath,reviewInput(bundle));
 assert.equal(first.reviewer,'alpha-reviewer');assert.ok(Number.isFinite(Date.parse(first.reviewedAt)));assert.equal(first.bundleHash,bundle.contentHash);assert.equal(first.bundleRevision,1);
 const confirmed=await current(h);provenance(confirmed,'reviewed');assert.equal(confirmed.verification.status,'technical_match_human_review_required');assert.deepEqual(confirmed.verification.provenance.review,first);assert.equal(confirmed.verification.provenance.reviewHash,digest(first));
 const firstAssessment=await post(h,'/api/governance/assessments',assessment);assert.equal(firstAssessment.evidence[0].provenanceReviewHash,digest(first));assert.equal(firstAssessment.evidence[0].contentHash,bundle.contentHash);
 const frozen=await post(h,'/api/governance/finance/report',{systemId:system.id},200,'auditor');
 assert.equal(frozen.snapshot.automaticLegalVerdict,false);assert.equal(frozen.sha256,digest(frozen.snapshot));assert.ok(verify(null,Buffer.from(canonical(frozen.snapshot)),h.publicKey,Buffer.from(frozen.signature,'base64')));assert.equal(frozen.snapshot.bundles[0].verification.provenance.reviewHash,digest(first));
 const second=await post(h,reviewPath,reviewInput(bundle));assert.notEqual(digest(second),digest(first));
 assert.equal((await governanceItem(h)).status,'review_required','Even a new verified review invalidates the previous assessment binding');
 const secondAssessment=await post(h,'/api/governance/assessments',assessment);assert.equal(secondAssessment.evidence[0].provenanceReviewHash,digest(second));
 const unverified=await post(h,reviewPath,{...reviewInput(bundle,'unverified'),checks:{...allChecks,deliveryReferenceChecked:false}});
 provenance(await current(h),'unreviewed');assert.equal((await governanceItem(h)).status,'review_required');await post(h,'/api/governance/assessments',assessment,400);
 const rejected=await post(h,reviewPath,reviewInput(bundle,'rejected'),200,'admin');assert.equal(rejected.reviewer,'alpha-admin');
 const denied=await current(h);provenance(denied,'rejected');assert.ok(denied.verification.issues.includes('REAL_PROVENANCE_REJECTED'));
 const next=await post(h,'/api/governance/bundles',input('Changed fixture document, not supplier evidence.'));
 assert.equal(next.revision,2);assert.notEqual(next.contentHash,bundle.contentHash);provenance(next,'stale');assert.equal(next.verification.provenance.reviewHash,digest(rejected));assert.ok(next.verification.issues.includes('REAL_PROVENANCE_REVIEW_STALE'));
 await post(h,reviewPath,reviewInput(bundle),409);
 const latest=await post(h,reviewPath,reviewInput(next));assert.equal(latest.bundleRevision,2);provenance(await current(h),'reviewed');
 const currentAssessment=await post(h,'/api/governance/assessments',assessment);assert.equal(currentAssessment.evidence[0].provenanceReviewHash,digest(latest));
 const history=await api(h,reviewPath);assert.equal(history.contentHash,next.contentHash);assert.deepEqual(history.reviews,[first,second,unverified,rejected,latest]);
 const overview=await api(h,'/api/governance');assert.deepEqual(overview.assessments.find(a=>a.id===firstAssessment.id),firstAssessment);assert.ok(overview.tasks.some(task=>task.previousReviewHash===digest(first)&&task.currentReviewHash===digest(second)));
 const exported=await api(h,'/api/export');assert.equal(verifyBundle(exported,h.publicKey).valid,true);assert.deepEqual(exported.records.filter(r=>r.type==='supplier_provenance_review').map(r=>r.payload),history.reviews);
 await post(h,'/api/governance/systems',system,200,'reviewer','beta');const beta=await post(h,'/api/governance/bundles',input(),200,'reviewer','beta');
 await post(h,reviewPath,reviewInput(next),409,'reviewer','beta');const betaReview=await post(h,reviewPath,reviewInput(beta),200,'reviewer','beta');assert.equal(betaReview.reviewer,'beta-reviewer');
 assert.deepEqual((await api(h,reviewPath)).reviews,history.reviews);assert.deepEqual((await api(h,reviewPath,{tenant:'beta'})).reviews,[betaReview]);await api(h,'/api/governance/finance/reports/'+frozen.id,{tenant:'beta'},404);
 await post(h,'/api/governance/systems',{...system,modelVersion:'v2'});const mismatch=await current(h);provenance(mismatch,'reviewed');assert.ok(mismatch.verification.issues.includes('MODEL_VERSION_MISMATCH'));await post(h,'/api/governance/assessments',assessment,400);
 assert.deepEqual((await api(h,'/api/governance/finance/reports/'+frozen.id)),frozen);
 await h.restart();assert.deepEqual((await api(h,reviewPath)).reviews,history.reviews);assert.deepEqual((await api(h,'/api/governance/finance/reports/'+frozen.id)),frozen);
 const download=await api(h,'/api/governance/bundles/provenance-bundle/export');assert.equal(download.documents[0].contentBase64,input('Changed fixture document, not supplier evidence.').documents[0].contentBase64);
});

test('actual HTTP provenance: explicit metadata contract and synthetic fixture compatibility',async t=>{
 const h=await harness();t.after(()=>h.close());await post(h,'/api/governance/systems',system);
 for(const malformed of [
  {...input(),synthetic:undefined},{...input(),synthetic:'false'},{...input(),provenance:undefined},
  {...input(),provenance:{channel:'external_attestation',reference:'fixture'}},
  {...input(),provenance:{channel:'email',reference:'   '}},
  {...input(),provenance:{...input().provenance,suppliedAt:'not-a-date'}},
  {...input(),provenance:{...input().provenance,sourceAuthenticated:true}},
 ])await post(h,'/api/governance/bundles',malformed,400);
 assert.equal((await api(h,'/api/governance/finance?systemId='+system.id)).bundles.length,0);
 const synthetic={...input(),synthetic:true};delete synthetic.provenance;
 const saved=await post(h,'/api/governance/bundles',synthetic);provenance(saved,'synthetic_fixture');assert.equal(saved.verification.status,'technical_match_human_review_required');
 await post(h,reviewPath,reviewInput(saved),400);const legacyAssessment=await post(h,'/api/governance/assessments',assessment);assert.equal(Object.hasOwn(legacyAssessment.evidence[0],'provenanceReviewHash'),false);
});

test('actual HTTP provenance: tampered signed review projection fails closed',async t=>{
 const h=await harness();t.after(()=>h.close());await post(h,'/api/governance/systems',system);const bundle=await post(h,'/api/governance/bundles',input());
 const entry=await post(h,reviewPath,reviewInput(bundle));const db=new DatabaseSync(join(h.dir,'data','evidence.db'));
 try{const changed=db.prepare("UPDATE objects SET body=? WHERE tenant='alpha' AND type='supplier_provenance_review' AND id=?").run(JSON.stringify({...entry,decision:'rejected'}),entry.id);assert.equal(changed.changes,1);}finally{db.close();}
 await api(h,reviewPath,undefined,409);await api(h,'/api/governance/finance?systemId='+system.id,undefined,409);await post(h,'/api/governance/finance/report',{systemId:system.id},409,'auditor');
 const raw=await api(h,'/api/export');assert.equal(verifyBundle(raw,h.publicKey).valid,true);assert.deepEqual(raw.records.find(r=>r.type==='supplier_provenance_review').payload,entry);assert.equal(raw.records.filter(r=>r.type==='finance_report').length,0,'Failed projection must not issue a new signed report');
});
