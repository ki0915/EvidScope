import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {normalizeSystemFacts,applicabilityCandidate,applicabilityPolicyVersion} from '../src/governance-policy.mjs';

const requirements=JSON.parse(readFileSync(new URL('../data/requirements.json',import.meta.url),'utf8'));
const requirement=id=>requirements.find(v=>v.id===id);
const base=overrides=>normalizeSystemFacts({id:'system-1',name:'검토 시스템',owner:'보안팀',purpose:'AI 감사 지원',role:'provider',markets:[],...overrides});

test('unknown system facts remain unknown and never become an automatic non-applicability decision',()=>{
 const system=base({markets:['KR']});assert.equal(system.generative,'unknown');assert.equal(system.internalOnly,'unknown');
 const result=applicabilityCandidate(requirement('KR-31-1'),system);assert.equal(result.status,'unknown');assert.equal(result.decision,'human_review_required');assert.ok(result.missingFacts.includes('generative_or_highImpact'));assert.equal(result.policyVersion,applicabilityPolicyVersion);
});

test('Korean high-impact and frontier thresholds are evaluated as separate review candidates',()=>{
 const generative=base({markets:['KR'],generative:true,internalOnly:false});assert.equal(applicabilityCandidate(requirement('KR-31-1'),generative).status,'candidate');
 const frontier=base({markets:['KR'],trainingCompute:1e26,frontierTechnology:true,broadSignificantRisk:true});assert.equal(applicabilityCandidate(requirement('KR-32-RISK'),frontier).status,'candidate');
 const publicUnknown=base({markets:['KR'],highImpact:'confirmed'}),publicResult=applicabilityCandidate(requirement('KR-35-PUBLIC'),publicUnknown);assert.equal(publicResult.status,'unknown');assert.ok(publicResult.missingFacts.includes('publicInstitution'));
});

test('EU transparency candidates require market, role and feature facts and preserve amendment warning',()=>{
 const system=base({markets:['EU'],euRoles:['deployer'],realisticSyntheticMedia:true,publicInterestText:false,marketEntryAt:'2026-08-02T00:00:00Z'});
 const media=applicabilityCandidate(requirement('EU-50-4-MEDIA'),system);assert.equal(media.status,'candidate');assert.equal(media.decision,'human_review_required');assert.match(media.reason,/개정/);
 const text=applicabilityCandidate(requirement('EU-50-4-TEXT'),system);assert.equal(text.status,'unknown');assert.ok(text.missingFacts.includes('publicInterestText'));
 const absent=applicabilityCandidate(requirement('EU-50-3'),base({emotionRecognition:true,euRoles:['deployer']}));assert.equal(absent.status,'unknown');assert.ok(absent.missingFacts.includes('markets.EU'));
});

test('NIST remains voluntary and ISO remains readiness-only',()=>{
 assert.equal(applicabilityCandidate(requirement('NIST-SECURITY'),base({})).status,'voluntary');
 assert.equal(applicabilityCandidate(requirement('ISO-42001-READINESS'),base({})).status,'readiness_only');
});

test('Korean article 31 distinguishes high-impact notice, generated output and realistic synthetic media',()=>{
 const high=base({markets:['KR'],krRoles:['deployer'],generative:false,highImpact:'confirmed',realisticSyntheticMedia:false,internalOnly:false});
 assert.equal(applicabilityCandidate(requirement('KR-31-1'),high).status,'candidate');
 for(const id of ['KR-31-2','KR-31-3']){const result=applicabilityCandidate(requirement(id),high);assert.equal(result.status,'unknown');assert.equal(result.decision,'human_review_required');}
 const gen={...high,highImpact:'no',generative:true};
 assert.equal(applicabilityCandidate(requirement('KR-31-2'),gen).status,'candidate');
 assert.equal(applicabilityCandidate(requirement('KR-31-3'),gen).status,'unknown');
 assert.equal(applicabilityCandidate(requirement('KR-31-3'),{...gen,realisticSyntheticMedia:true}).status,'candidate');
 assert.equal(applicabilityCandidate(requirement('KR-31-3'),{...high,realisticSyntheticMedia:true}).status,'candidate');
 const missing=applicabilityCandidate(requirement('KR-31-3'),base({markets:['KR']}));
 for(const field of ['krRoles','realisticSyntheticMedia','internalOnly'])assert.ok(missing.missingFacts.includes(field));
});

test('legacy and financial system facts require review without inferring high-impact or a legal role',()=>{
 const legacy=base({domain:'credit',role:'provider'});
 assert.equal(legacy.schemaVersion,4);assert.deepEqual(legacy.krRoles,[]);
 for(const field of ['supplierId','modelId','decisionInfluence','suppliedModelVersion','suppliedPurpose','substantialModification','highImpact'])assert.equal(legacy[field],'unknown');
 const credit=base({krRoles:['deployer'],supplierId:'vendor',modelId:'credit',modelVersion:'2',suppliedModelVersion:'1',suppliedPurpose:'credit assessment',decisionInfluence:'automated',substantialModification:false});
 assert.equal(credit.highImpact,'unknown');assert.equal(credit.substantialModification,false);assert.equal(credit.suppliedModelVersion,'1');
 assert.throws(()=>base({krRoles:['provider']}));
 assert.match(requirement('KR-34-RISK').limitations,/제27조제5항/);
});

test('Korean expanded scope facts migrate to unknown without inferring operator, exemption or presence',()=>{
 const legacy=base({markets:['KR'],krRoles:['deployer'],domain:'credit'});
 for(const field of ['domesticImpact','aiBusinessOperator','defenceOrNationalSecurityOnly','designatedDefenceSecurityWork','hasDomesticAddressOrOffice','previousYearTotalRevenueKrw','previousYearAiRevenueKrw','domesticDailyAverageUsersLast3Months','priorArticle43OrderFine','governmentOrderPresent','providedAt','transparencyObvious','artisticCreativeExpression','seriousLifeSafetyRightsRisk'])assert.equal(legacy[field],'unknown');
 assert.deepEqual(legacy.highImpactDomains,[]);
 const result=applicabilityCandidate(requirement('KR-33'),legacy);
 for(const field of ['domesticImpact','aiBusinessOperator','defenceOrNationalSecurityOnly','providedAt','highImpactDomains','seriousLifeSafetyRightsRisk'])assert.ok(result.missingFacts.includes(field),field);
 assert.equal(result.decision,'human_review_required');
 const invalid=base({previousYearTotalRevenueKrw:'1000000000000',previousYearAiRevenueKrw:-1,domesticDailyAverageUsersLast3Months:Infinity});
 for(const field of ['previousYearTotalRevenueKrw','previousYearAiRevenueKrw','domesticDailyAverageUsersLast3Months'])assert.equal(invalid[field],'unknown');
});

test('domestic impact supports extraterritorial triage and does not depend only on a KR market label',()=>{
 const overseas=base({markets:['US'],domesticImpact:true,aiBusinessOperator:true,defenceOrNationalSecurityOnly:false,generative:true,internalOnly:false});
 assert.equal(applicabilityCandidate(requirement('KR-31-1'),overseas).status,'candidate');
 for(const system of [{...overseas,domesticImpact:false,markets:['KR']},{...overseas,aiBusinessOperator:false},{...overseas,defenceOrNationalSecurityOnly:true,designatedDefenceSecurityWork:true}]){
  const result=applicabilityCandidate(requirement('KR-31-1'),system);
  assert.equal(result.status,'unknown');assert.equal(result.decision,'human_review_required');
 }
 const incomplete=applicabilityCandidate(requirement('KR-31-1'),{...overseas,defenceOrNationalSecurityOnly:true,designatedDefenceSecurityWork:'unknown'});
 assert.ok(incomplete.missingFacts.includes('designatedDefenceSecurityWork'));
 assert.notEqual(incomplete.status,'not_applicable');
});

test('realistic synthetic media triage follows article 31 paragraph 3 independently of generative classification',()=>{
 const result=applicabilityCandidate(requirement('KR-31-3'),base({domesticImpact:true,realisticSyntheticMedia:true,generative:false,internalOnly:false,transparencyObvious:false,artisticCreativeExpression:true}));
 assert.equal(result.status,'candidate');assert.match(result.reason,/생성형 분류와 별도로/);assert.doesNotMatch(result.reason,/비생성형 분류.*함께/);
 const exception=applicabilityCandidate(requirement('KR-31-2'),base({markets:['KR'],generative:true,internalOnly:true,transparencyObvious:true}));
 assert.equal(exception.status,'candidate');assert.equal(exception.decision,'human_review_required');assert.match(exception.reason,/전부 또는 일부 예외/);
});

test('domestic representative thresholds are four OR branches with exact boundaries and foreign-presence AND',()=>{
 const facts={domesticImpact:true,aiBusinessOperator:true,defenceOrNationalSecurityOnly:false,hasDomesticAddressOrOffice:false,previousYearTotalRevenueKrw:0,previousYearAiRevenueKrw:0,domesticDailyAverageUsersLast3Months:0,priorArticle43OrderFine:false,krRoles:['developer']};
 for(const [field,limit] of [['previousYearTotalRevenueKrw',1e12],['previousYearAiRevenueKrw',1e10],['domesticDailyAverageUsersLast3Months',1e6]]){
  assert.equal(applicabilityCandidate(requirement('KR-36-REPRESENTATIVE'),base({...facts,[field]:limit})).status,'candidate',field);
  assert.equal(applicabilityCandidate(requirement('KR-36-REPRESENTATIVE'),base({...facts,[field]:limit-1})).status,'unknown',field);
 }
 assert.equal(applicabilityCandidate(requirement('KR-36-REPRESENTATIVE'),base({...facts,priorArticle43OrderFine:true})).status,'candidate');
 assert.equal(applicabilityCandidate(requirement('KR-36-REPRESENTATIVE'),base({...facts,previousYearTotalRevenueKrw:1e12,defenceOrNationalSecurityOnly:true,designatedDefenceSecurityWork:false})).status,'candidate');
 for(const changed of [{hasDomesticAddressOrOffice:true},{hasDomesticAddressOrOffice:'unknown'},{aiBusinessOperator:false},{aiBusinessOperator:'unknown'},{domesticImpact:false},{domesticImpact:'unknown'},{defenceOrNationalSecurityOnly:'unknown'},{defenceOrNationalSecurityOnly:true,designatedDefenceSecurityWork:true}]){
  const result=applicabilityCandidate(requirement('KR-36-REPRESENTATIVE'),base({...facts,previousYearTotalRevenueKrw:1e12,...changed}));
  assert.equal(result.status,'unknown');assert.equal(result.decision,'human_review_required');
 }
 const missing=applicabilityCandidate(requirement('KR-36-REPRESENTATIVE'),base({...facts,previousYearTotalRevenueKrw:'unknown',previousYearAiRevenueKrw:'unknown',domesticDailyAverageUsersLast3Months:'unknown',priorArticle43OrderFine:'unknown'}));
 for(const field of ['previousYearTotalRevenueKrw','previousYearAiRevenueKrw','domesticDailyAverageUsersLast3Months','priorArticle43OrderFine'])assert.ok(missing.missingFacts.includes(field));
});

test('public procurement duties do not require the institution to supply AI as a business operator',()=>{
 const publicUser=base({markets:['KR'],domesticImpact:true,publicInstitution:true,aiBusinessOperator:false,highImpact:'confirmed',defenceOrNationalSecurityOnly:false});
 for(const id of ['KR-30-PUBLIC','KR-35-PUBLIC']){
  const result=applicabilityCandidate(requirement(id),publicUser);assert.equal(result.status,'candidate');assert.ok(!result.missingFacts.includes('aiBusinessOperator'));assert.ok(!result.missingFacts.includes('krRoles'));assert.equal(result.decision,'human_review_required');
  assert.equal(applicabilityCandidate(requirement(id),{...publicUser,publicInstitution:false}).status,'unknown');
 }
 assert.equal(applicabilityCandidate(requirement('KR-30-EFFORT'),{...publicUser,aiBusinessOperator:true,krRoles:['developer']}).status,'candidate');
});

test('a mere user institution is not automatically classified as an AI business operator for any business duty',()=>{
 const bank=base({name:'대출 심사 AI 사용기관',markets:['KR'],domesticImpact:true,aiBusinessOperator:false,krRoles:['deployer'],publicInstitution:false,defenceOrNationalSecurityOnly:false,generative:true,realisticSyntheticMedia:true,highImpact:'confirmed',trainingCompute:1e26,frontierTechnology:true,broadSignificantRisk:true,hasDomesticAddressOrOffice:false,previousYearTotalRevenueKrw:1e12,governmentOrderPresent:true});
 for(const item of requirements.filter(row=>row.jurisdiction==='KR'&&!['KR-30-PUBLIC','KR-35-PUBLIC'].includes(row.id))){
  const result=applicabilityCandidate(item,bank);
  assert.equal(result.status,'unknown',item.id);assert.equal(result.decision,'human_review_required',item.id);
  assert.match(result.reason,/AI 제품·서비스를 제공하는 사업자인지/,item.id);assert.match(result.reason,/단순 사용기관 역할과 구분/,item.id);
 }
});

test('government order is a distinct fact and lack of a current order never becomes automatic compliance',()=>{
 const system=base({domesticImpact:true,aiBusinessOperator:true,defenceOrNationalSecurityOnly:false,governmentOrderPresent:true});
 assert.equal(applicabilityCandidate(requirement('KR-40-ORDER'),system).status,'candidate');
 const absent=applicabilityCandidate(requirement('KR-40-ORDER'),{...system,governmentOrderPresent:false});assert.equal(absent.status,'unknown');assert.equal(absent.decision,'human_review_required');
 const missing=applicabilityCandidate(requirement('KR-40-ORDER'),{...system,governmentOrderPresent:'unknown'});assert.ok(missing.missingFacts.includes('governmentOrderPresent'));
});

test('Korean catalog states verified legal scope, publication items, seven impact contents and unverified notices',()=>{
 const korean=requirements.filter(v=>v.jurisdiction==='KR');assert.equal(korean.length,18);
 for(const id of ['KR-30-EFFORT','KR-30-PUBLIC','KR-36-REPRESENTATIVE','KR-40-ORDER'])assert.ok(requirement(id));
 for(const item of korean){assert.equal(item.verifiedAt,'2026-10-06');assert.equal(item.sourceTextStatus,'verified_statute_and_decree');assert.equal(item.reviewStatus,'draft_requires_human_review');}
 assert.equal(requirement('KR-34-DOCUMENT').publicationItems.length,4);assert.match(requirement('KR-34-DOCUMENT').publicationException,/사항만/);
 assert.equal(requirement('KR-35-IMPACT').impactContentItems.length,7);assert.ok(requirement('KR-35-IMPACT').impactContentItems.some(x=>x.includes('사용 행태')));
 assert.equal(requirement('KR-35-IMPACT').vulnerableGroupScope.length,10);assert.ok(requirement('KR-35-IMPACT').evidenceNeeded.some(x=>x.includes('제1조의2')));assert.ok(!requirement('KR-35-IMPACT').evidenceNeeded.some(x=>x.includes('제2조의2')));
 assert.ok(requirement('KR-34-EXPLAIN').otherLawRecognition.some(x=>x.includes('제35조의2')&&x.includes('제36조의2제1항')&&x.includes('모두')));
 assert.ok(requirement('KR-34-PROTECT').otherLawRecognition.some(x=>x.includes('제10조')&&x.includes('모두')));
 for(const id of ['KR-31-1','KR-32-SUBMIT','KR-33','KR-34-RISK','KR-35-IMPACT'])assert.equal(requirement(id).detailNoticeStatus,'not_verified');
 assert.match(requirement('KR-30-EFFORT').binding,/노력/);assert.match(requirement('KR-36-REPRESENTATIVE').limitations,/OR.*AND/);
 assert.equal(requirement('KR-35-IMPACT').effectiveDate,'2026-07-21 (취약계층 후단); 기존 노력의무 2026-01-22');
});
