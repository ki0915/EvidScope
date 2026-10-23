import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import {normalizeSystemFacts,applicabilityCandidate,applicabilityAssessmentSnapshot} from '../src/governance-policy.mjs';
import {canonical} from '../src/crypto.mjs';
import {verifyFinanceReport} from '../src/report-verifier.mjs';
import {harness} from './harness.mjs';

const requirements=JSON.parse(readFileSync(new URL('../data/requirements.json',import.meta.url),'utf8'));
const requirement=id=>requirements.find(item=>item.id===id);
const facts={id:'loan',name:'합성 대출 검토',owner:'reviewer',purpose:'대출 심사 보조',markets:['KR'],krRoles:['deployer'],aiBusinessOperator:true,domesticImpact:true,defenceOrNationalSecurityOnly:false,highImpact:'confirmed',generative:false,modelId:'credit-model',modelVersion:'v1',policyVersion:'p1',providedAt:'2026-09-01T00:00:00Z'};
const measure=code=>({code,description:'해당 법적 조치의 실제 이행 근거 검토',performed:true,evidenceRef:'governance-document:credit-review',contentHash:'a'.repeat(64)});
const explanation=()=>({id:'explain-review',basisCode:'loan_credit_explanation',requirementId:'KR-34-EXPLAIN',recognitionLaw:'CREDIT_INFORMATION_ACT',systemId:'loan',modelId:'credit-model',modelVersion:'v1',purpose:facts.purpose,loanReview:true,performedMeasures:[measure('article_35_2_explanation'),measure('article_36_2_1_procedure')],reviewer:'declared-law-reviewer',reviewedAt:'2026-09-02T00:00:00Z'});
const protection=()=>({...explanation(),id:'protect-review',basisCode:'loan_consumer_protection',requirementId:'KR-34-PROTECT',recognitionLaw:'FINANCIAL_CONSUMER_PROTECTION_ACT',performedMeasures:[measure('article_10_all_obligations')]});
const system=claims=>normalizeSystemFacts({...facts,otherLawRecognitionClaims:claims});
const review=(id,claims)=>applicabilityCandidate(requirement(id),system(claims)).otherLawRecognitionReview;

test('loan explanation and protection declare separate other-law review routes without supplier or legal certification',()=>{
 for(const [id,claim,annex] of [['KR-34-EXPLAIN',explanation(),'2다'],['KR-34-PROTECT',protection(),'3나']]){
  const result=review(id,[claim]);assert.equal(result.route,'other_law_recognition');assert.equal(result.supplierReliance,false);
  assert.equal(result.status,'human_review_required');assert.equal(result.automaticLegalVerdict,false);assert.equal(result.supportsHumanAssessment,false);
  assert.equal(result.items[0].annexItem,annex);assert.equal(result.items[0].declaredScopeComplete,true);assert.deepEqual(result.items[0].reasons,[]);
  assert.equal(result.items[0].evidenceVerification,'declared_references_not_fetched');assert.equal(result.items[0].reviewerVerification,'declared_reviewer_not_authenticated');
  assert.match(result.source.sourceSha256,/^[a-f0-9]{64}$/);
 }
});

test('credit explanation requires both statutory measures, actual performance declarations and document bindings',()=>{
 const mutations=[
  [c=>c.performedMeasures.pop(),'measure_missing:article_36_2_1_procedure'],
  [c=>c.performedMeasures[0].performed=false,'measure_performance_unconfirmed:article_35_2_explanation'],
  [c=>c.performedMeasures[0].contentHash='not_provided','measure_document_binding_incomplete:article_35_2_explanation'],
  [c=>c.performedMeasures[0].evidenceRef='supplier-bundle:supplier','measure_document_binding_incomplete:article_35_2_explanation'],
  [c=>c.performedMeasures[0].evidenceRef='governance-document:','measure_document_binding_incomplete:article_35_2_explanation'],
  [c=>c.performedMeasures.push(measure('all_ai_obligations')),'measure_scope_not_mapped'],
 ];
 for(const [mutate,reason] of mutations){const claim=explanation();mutate(claim);const item=review('KR-34-EXPLAIN',[claim]).items[0];assert.equal(item.declaredScopeComplete,false);assert.ok(item.reasons.includes(reason),reason);assert.equal(item.supportsHumanAssessment,false);}
});

test('a financial institution or general credit score is not automatically a loan-review scope',()=>{
 const claim=explanation();delete claim.loanReview;
 assert.ok(review('KR-34-EXPLAIN',[claim]).items[0].reasons.includes('loan_review_scope_unconfirmed'));
 const normalized=system([explanation()]);normalized.aiBusinessOperator=false;
 assert.ok(applicabilityCandidate(requirement('KR-34-EXPLAIN'),normalized).otherLawRecognitionReview.items[0].reasons.includes('ai_business_operator_unconfirmed'));
});

test('foreign targets, models, purposes, laws and requirement scope cannot silently inherit recognition',()=>{
 for(const field of ['systemId','modelId','modelVersion','purpose','recognitionLaw']){
  const claim=explanation();claim[field]='different';const item=review('KR-34-EXPLAIN',[claim]).items[0];assert.equal(item.declaredScopeComplete,false,field);
 }
 const wrong=explanation();wrong.requirementId='KR-34-OVERSIGHT';
 for(const id of ['KR-34-EXPLAIN','KR-34-OVERSIGHT'])assert.ok(review(id,[wrong]).items[0].reasons.includes('recognition_requirement_mismatch'));
 for(const id of ['KR-34-RISK','KR-34-OVERSIGHT','KR-34-DOCUMENT'])assert.deepEqual(review(id,[explanation(),protection()]).items,[]);
});

test('unmapped recognition such as wholesale privacy or supplier reliance stays an explicit human review gap',()=>{
 for(const code of ['privacy_all_ai_measures','supplier_explanation_reliance','unverified_annex_route','constructor','__proto__','toString']){
  const claim=explanation();claim.basisCode=code;const item=review('KR-34-EXPLAIN',[claim]).items[0];assert.equal(item.status,'human_review_required');assert.equal(item.declaredScopeComplete,false);assert.ok(item.reasons.includes('recognition_basis_not_mapped'));assert.equal(item.automaticLegalVerdict,false);
 }
});

test('claim schema rejects false authority flags, invalid hashes, duplicates and unbounded input',()=>{
 for(const edit of [c=>c.automaticLegalVerdict=true,c=>c.evidenceVerification='verified',c=>c.performedMeasures[0].contentHash='fake',c=>c.performedMeasures.push(c.performedMeasures[0]),c=>c.performedMeasures[0].description='x'.repeat(1001)]){
  const claim=explanation();edit(claim);assert.throws(()=>system([claim]),error=>error.status===400);
 }
 assert.throws(()=>system([explanation(),explanation()]),error=>error.status===400);
 assert.throws(()=>system(Array.from({length:11},(_,i)=>({...explanation(),id:'claim-'+i}))),error=>error.status===400);
 assert.throws(()=>system({}),error=>error.status===400);
});

test('document hashes reject JSON arrays and objects instead of coercing them into declarations',()=>{
 for(const contentHash of [['a'.repeat(64)],{value:'a'.repeat(64)},[],42,null]){
  const claim=explanation();claim.performedMeasures[0].contentHash=contentHash;
  assert.throws(()=>system([claim]),error=>error.status===400);
 }
});

test('actual HTTP accepts browser compact payload round trips within 16 KiB and rejects larger requests without losing saved claims',async t=>{
 const h=await harness();t.after(()=>h.close());
 const source=readFileSync('public/app.js','utf8'),browser={TextEncoder};
 vm.runInNewContext(source.slice(source.indexOf('const systemTriFacts ='),source.indexOf('async function financeEvidenceView(')),browser);
 const claims=Array.from({length:3},(_,i)=>({...explanation(),id:'large-'+i,reviewedAt:'2026-09-02T00:00:00.000Z',performedMeasures:explanation().performedMeasures.map(item=>({...item,description:'D'.repeat(1000),evidenceRef:'governance-document:'+ 'r'.repeat(850)}))}));
 const input={...facts,markets:'KR',krRole_deployer:'on',generative:'false',aiBusinessOperator:'true',domesticImpact:'true',defenceOrNationalSecurityOnly:'false',otherLawRecognitionJson:JSON.stringify(claims,null,2)};
 assert.ok(Buffer.byteLength(input.otherLawRecognitionJson)>12000);
 const payload=browser.systemFactsPayload(input);assert.ok(Buffer.byteLength(JSON.stringify(payload))<=16384);
 assert.equal((await h.api('/api/governance/systems',{body:payload,role:'reviewer'})).status,200);
 const first=await h.api('/api/governance/report?systemId=loan');assert.equal(first.status,200);assert.deepEqual(first.body.system.otherLawRecognitionClaims,claims);
 const updated=browser.systemFactsPayload({...input,owner:'updated-reviewer',otherLawRecognitionJson:JSON.stringify(first.body.system.otherLawRecognitionClaims,null,2)});
 assert.equal((await h.api('/api/governance/systems',{body:updated,role:'reviewer'})).status,200);
 const oversized=[...claims,{...claims[0],id:'large-3'}];
 assert.throws(()=>browser.systemFactsPayload({...input,otherLawRecognitionJson:JSON.stringify(oversized)}),/16 KiB/);
 assert.equal((await h.api('/api/governance/systems',{body:{...facts,otherLawRecognitionClaims:oversized},role:'reviewer'})).status,413);
 const current=await h.api('/api/governance/report?systemId=loan');assert.equal(current.body.system.owner,'updated-reviewer');assert.deepEqual(current.body.system.otherLawRecognitionClaims,claims);
 assert.equal((await h.api('/api/governance/report?systemId=loan',{tenant:'beta'})).status,404);
});

test('legacy facts stay explicit not-recorded while claim changes alter review snapshots and normalize idempotently',()=>{
 const legacy=normalizeSystemFacts(facts);assert.equal(applicabilityCandidate(requirement('KR-34-EXPLAIN'),legacy).otherLawRecognitionReview.status,'not_recorded');
 const normalized=system([explanation()]);assert.deepEqual(normalizeSystemFacts(normalized).otherLawRecognitionClaims,normalized.otherLawRecognitionClaims);
 const before=applicabilityAssessmentSnapshot(requirement('KR-34-EXPLAIN'),normalized);
 const changed=structuredClone(normalized);changed.modelVersion='v2';const after=applicabilityAssessmentSnapshot(requirement('KR-34-EXPLAIN'),changed);
 assert.notEqual(before.hash,after.hash);assert.ok(after.snapshot.candidate.otherLawRecognitionReview.items[0].reasons.includes('target_modelVersion_mismatch_or_unconfirmed'));
});

test('actual HTTP stores review claims, separates technical insufficiency, freezes signed history and preserves tenants across restart',async t=>{
 const h=await harness();t.after(()=>h.close());const unmapped={...explanation(),id:'unlinked-review',basisCode:'future_basis',requirementId:'KR-34-FUTURE',reviewedAt:'2026-09-02T00:00:00.000Z'},submitted={...facts,otherLawRecognitionClaims:[explanation(),protection(),unmapped]};
 assert.equal((await h.api('/api/governance/systems',{body:submitted,role:'reviewer'})).status,200);
 const first=await h.api('/api/governance/report?systemId=loan');assert.equal(first.status,200);
 const item=first.body.items.find(row=>row.requirement.id==='KR-34-EXPLAIN');assert.equal(item.applicability.otherLawRecognitionReview.items[0].declaredScopeComplete,true);
 assert.deepEqual(first.body.system.otherLawRecognitionClaims.at(-1),unmapped);
 assert.equal(first.body.items.some(row=>row.applicability?.otherLawRecognitionReview?.items.some(entry=>entry.claim.id===unmapped.id)),false,'the system-level unlinked declaration remains available without fabricating a statutory mapping');
 assert.equal(item.applicability.otherLawRecognitionReview.supportsHumanAssessment,false);assert.equal(item.status,'evidence_missing');assert.equal(item.technicalEvidence.supportsHumanAssessment,false);
 const issued=await h.api('/api/governance/finance/report',{body:{systemId:'loan'},role:'reviewer'});assert.equal(issued.status,200);assert.equal(verifyFinanceReport(issued.body,h.publicKey).valid,true);
 const frozen=canonical(issued.body.snapshot);
 assert.equal((await h.api('/api/governance/report?systemId=loan',{tenant:'beta'})).status,404);
 assert.equal((await h.api('/api/governance/systems',{body:{...submitted,modelVersion:'v2'},role:'reviewer'})).status,200);
 await h.restart();
 const current=await h.api('/api/governance/report?systemId=loan');const currentItem=current.body.items.find(row=>row.requirement.id==='KR-34-EXPLAIN');
 assert.ok(currentItem.applicability.otherLawRecognitionReview.items[0].reasons.includes('target_modelVersion_mismatch_or_unconfirmed'));
 const old=await h.api('/api/governance/finance/reports/'+issued.body.id);assert.equal(old.status,200);assert.equal(canonical(old.body.snapshot),frozen);assert.equal(verifyFinanceReport(old.body,h.publicKey).valid,true);
 assert.equal((await h.api('/api/governance/finance/reports/'+issued.body.id,{tenant:'beta'})).status,404);
});
