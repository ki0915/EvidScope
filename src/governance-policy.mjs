import {cleanText,identifier,date,fail} from './model.mjs';
import {digest} from './crypto.mjs';

export const applicabilityPolicyVersion='evidscope-applicability-2026-10-06';
const tri=(value)=>value===true||value===false?value:'unknown';
const text=(value,max=200)=>cleanText(value??'unknown',max);
const nonNegative=(value)=>typeof value==='number'&&Number.isFinite(value)&&value>=0?value:'unknown';

export function normalizeSystemFacts(x){
 const array=(value,max)=>{if(!Array.isArray(value??[])||(value??[]).length>max)fail(400,'시스템 사실관계 목록 한도 오류');return (value??[]).map(v=>text(v,100));};
 const result={schemaVersion:3,id:identifier(x.id),name:cleanText(x.name,200),owner:cleanText(x.owner,200),purpose:cleanText(x.purpose,1000),role:text(x.role),markets:array(x.markets,20),domain:text(x.domain),generative:tri(x.generative),highImpact:['unknown','candidate','confirmed','no'].includes(x.highImpact)?x.highImpact:'unknown',euHighRisk:text(x.euHighRisk,100),dataCategories:array(x.dataCategories,20),affectedPeople:text(Array.isArray(x.affectedPeople)?x.affectedPeople.join(', '):x.affectedPeople,500),modelVersion:text(x.modelVersion),policyVersion:text(x.policyVersion),internalOnly:tri(x.internalOnly),publicInstitution:tri(x.publicInstitution),realisticSyntheticMedia:tri(x.realisticSyntheticMedia),emotionRecognition:tri(x.emotionRecognition),biometricCategorisation:tri(x.biometricCategorisation),publicInterestText:tri(x.publicInterestText),frontierTechnology:tri(x.frontierTechnology),broadSignificantRisk:tri(x.broadSignificantRisk),trainingCompute:typeof x.trainingCompute==='number'&&Number.isFinite(x.trainingCompute)&&x.trainingCompute>=0?x.trainingCompute:'unknown',euRoles:array(x.euRoles,4),status:'human_applicability_review_required',updatedAt:new Date().toISOString()};
 Object.assign(result,{schemaVersion:3,krRoles:array(x.krRoles,2),supplierId:text(x.supplierId),modelId:text(x.modelId),decisionInfluence:['advisory','material','automated'].includes(x.decisionInfluence)?x.decisionInfluence:'unknown',suppliedModelVersion:text(x.suppliedModelVersion),suppliedPurpose:text(x.suppliedPurpose,1000),substantialModification:tri(x.substantialModification)});
 Object.assign(result,{schemaVersion:4,domesticImpact:tri(x.domesticImpact),aiBusinessOperator:tri(x.aiBusinessOperator),defenceOrNationalSecurityOnly:tri(x.defenceOrNationalSecurityOnly),designatedDefenceSecurityWork:tri(x.designatedDefenceSecurityWork),hasDomesticAddressOrOffice:tri(x.hasDomesticAddressOrOffice),previousYearTotalRevenueKrw:nonNegative(x.previousYearTotalRevenueKrw),previousYearAiRevenueKrw:nonNegative(x.previousYearAiRevenueKrw),domesticDailyAverageUsersLast3Months:nonNegative(x.domesticDailyAverageUsersLast3Months),priorArticle43OrderFine:tri(x.priorArticle43OrderFine),governmentOrderPresent:tri(x.governmentOrderPresent),transparencyObvious:tri(x.transparencyObvious),artisticCreativeExpression:tri(x.artisticCreativeExpression),highImpactDomains:array(x.highImpactDomains,11),seriousLifeSafetyRightsRisk:tri(x.seriousLifeSafetyRightsRisk)});
 result.providedAt=x.providedAt&&x.providedAt!=='unknown'?date(x.providedAt):'unknown';
 if(result.krRoles.some(r=>!['developer','deployer'].includes(r)))fail(400,'한국 사업자 역할 코드 오류');
 if(result.euRoles.some(r=>!['provider','deployer','importer','distributor'].includes(r)))fail(400,'EU 역할 코드 오류');
 if(x.marketEntryAt)result.marketEntryAt=date(x.marketEntryAt);
 return result;
}

// Versioned triage of supplied facts, never an automatic legal determination.
export function applicabilityCandidate(requirement,system){
 const missingFacts=[],id=requirement.id;let status='unknown',reason='관할·역할·예외와 사실관계를 사람이 확인해야 합니다';
 const requireFact=(name,condition)=>{if(!condition)missingFacts.push(name);return condition;};
 if(id.startsWith('NIST-')){status='voluntary';reason='조직이 채택한 범위의 자율 프레임워크';}
 else if(id.startsWith('ISO-')){status='readiness_only';reason='공개 소개에 근거한 준비 기록이며 표준 조항 매핑·인증 판정이 아닙니다';}
 else if(id.startsWith('KR-')){
  const publicUse=['KR-30-PUBLIC','KR-35-PUBLIC'].includes(id),known=value=>value!==undefined&&value!==null&&value!=='unknown';
  const domestic=system.domesticImpact===true||system.domesticImpact!==false&&system.markets?.includes('KR');
  if(!known(system.domesticImpact))missingFacts.push('domesticImpact');
  if(!domestic&&!system.markets?.includes('KR'))missingFacts.push('markets.KR_or_domesticImpact');
  if(!known(system.defenceOrNationalSecurityOnly))missingFacts.push('defenceOrNationalSecurityOnly');
  if(system.defenceOrNationalSecurityOnly===true&&!known(system.designatedDefenceSecurityWork))missingFacts.push('designatedDefenceSecurityWork');
  if(!publicUse){if(!known(system.aiBusinessOperator))missingFacts.push('aiBusinessOperator');if(!(system.krRoles||[]).length)missingFacts.push('krRoles');}
  const excludedCandidate=system.defenceOrNationalSecurityOnly===true&&system.designatedDefenceSecurityWork===true;
  if(system.domesticImpact===false)reason='국내 영향이 없다는 제출 사실의 범위·기간·시장 또는 이용자 영향을 사람이 확인해야 합니다. 자동 적용 제외가 아닙니다';
  else if(excludedCandidate)reason='국방·국가안보 전용 목적과 시행령 제2조 지정업무의 적용 제외 후보입니다. 지정 근거·전용성·실제 이용 범위를 사람이 확인해야 합니다';
  else if(!publicUse&&system.aiBusinessOperator===false)reason='AI 제품·서비스를 제공하는 사업자인지 법 제2조제7호의 실제 역할을 확인하고, 단순 사용기관 역할과 구분해야 합니다. 은행·금융기관이라는 명칭만으로 이용사업자로 분류하지 않으며 자동 면책 판정도 아닙니다';
  else if(domestic){
   if(!publicUse&&id!=='KR-40-ORDER'&&(!system.providedAt||system.providedAt==='unknown'))missingFacts.push('providedAt');
   if(id.startsWith('KR-31')){
    if(id==='KR-31-1'){if(system.generative===true||system.highImpact==='confirmed')status='candidate';else if(system.generative===false&&system.highImpact==='no')reason='제출된 사실에서 고지 대상 특성이 확인되지 않았습니다. 역할·제공 형태·예외를 검토하세요';else missingFacts.push('generative_or_highImpact');}
    else if(id==='KR-31-2'){if(system.generative===true)status='candidate';else if(system.generative!==false)missingFacts.push('generative');else reason='제출된 비생성형 사실에서 생성형 결과 표시 대상이 확인되지 않았습니다. 적용 제외 확정은 아닙니다';}
    else if(id==='KR-31-3'){
     if(system.realisticSyntheticMedia===true){status='candidate';reason='제31조제3항은 인공지능시스템으로 만든 사실적인 합성물을 대상으로 합니다. 생성형 분류와 별도로 명확한 고지·표시 방식을 검토하세요';if(!known(system.artisticCreativeExpression))missingFacts.push('artisticCreativeExpression');}
     else {reason='사실적인 합성물 생성 여부와 제공 형태를 검토해야 합니다';if(system.realisticSyntheticMedia===undefined||system.realisticSyntheticMedia==='unknown')missingFacts.push('realisticSyntheticMedia');}
    }
    if(system.internalOnly===true)reason='내부 이용 사실과 적용 예외의 범위를 사람이 검토해야 합니다';
    if(system.internalOnly===undefined||system.internalOnly==='unknown')missingFacts.push('internalOnly');
    if(!known(system.transparencyObvious))missingFacts.push('transparencyObvious');
    if(system.transparencyObvious===true)reason='AI 활용 명백성의 전부 또는 일부 예외 후보입니다. 제31조의 각 의무별 예외 범위와 근거를 사람이 확인해야 합니다';
   }
   else if(id.startsWith('KR-32')){for(const field of ['trainingCompute','frontierTechnology','broadSignificantRisk'])requireFact(field,system[field]!==undefined&&system[field]!=='unknown');if(system.trainingCompute>=1e26&&system.frontierTechnology===true&&system.broadSignificantRisk===true)status='candidate';}
   else if(id==='KR-33'){status='candidate';if(!(system.highImpactDomains||[]).length)missingFacts.push('highImpactDomains');if(!known(system.seriousLifeSafetyRightsRisk))missingFacts.push('seriousLifeSafetyRightsRisk');}
   else if(id==='KR-36-REPRESENTATIVE'){
    for(const field of ['hasDomesticAddressOrOffice','previousYearTotalRevenueKrw','previousYearAiRevenueKrw','domesticDailyAverageUsersLast3Months','priorArticle43OrderFine'])requireFact(field,known(system[field]));
    const threshold=system.previousYearTotalRevenueKrw>=1e12||system.previousYearAiRevenueKrw>=1e10||system.domesticDailyAverageUsersLast3Months>=1e6||system.priorArticle43OrderFine===true;
    const exemptionReviewed=system.defenceOrNationalSecurityOnly===false||system.defenceOrNationalSecurityOnly===true&&system.designatedDefenceSecurityWork===false;
    const scopeConfirmed=system.domesticImpact===true&&system.aiBusinessOperator===true&&exemptionReviewed;
    if(scopeConfirmed&&system.hasDomesticAddressOrOffice===false&&threshold){status='candidate';reason='국내 주소·영업소 없음과 시행령 제29조의 OR 기준에서 지정·서면 위임·신고의 검토 후보입니다. 전년도 산정기간·평균환율·원화 환산 근거를 검토하세요';}
    else reason='국내 영향·사업자·적용 제외·국내 주소 또는 영업소와 전년도 매출/국내 이용자/제43조제1항제3호 과태료 조건을 함께 검토해야 합니다. 미확인·기준 미확인은 자동 적용 제외가 아닙니다';
   }
   else if(id==='KR-40-ORDER'){if(system.governmentOrderPresent===true){status='candidate';reason='제40조제3항 중지·시정명령의 실제 문서·대상·기한·이행 결과를 대조하는 검토 후보입니다';}else if(!known(system.governmentOrderPresent))missingFacts.push('governmentOrderPresent');else reason='현재 제출 사실에서 중지·시정명령이 확인되지 않았습니다. 이후 명령 수령 시 재검토해야 합니다';}
   else if(id.startsWith('KR-30')||id.startsWith('KR-34')||id.startsWith('KR-35')){if(['candidate','confirmed'].includes(system.highImpact))status='candidate';else if(system.highImpact==='no')reason='고영향이 아니라는 제출 사실을 활용 영역과 중대한 영향·위험 근거에 대조해야 합니다. 자동 적용 제외가 아닙니다';else missingFacts.push('highImpact');if(publicUse&&system.publicInstitution!==true){status='unknown';if(!known(system.publicInstitution))missingFacts.push('publicInstitution');else reason='국가기관등이 아니라는 제출 사실의 기관 범위를 확인해야 합니다';}}
  }
 }else if(id.startsWith('EU-')){
  const roles=system.euRoles||[],market=requireFact('markets.EU',system.markets?.includes('EU'));
  if(!roles.length)missingFacts.push('euRoles');
  if(market&&roles.length){
   if(['EU-50-1','EU-50-2'].includes(id)&&roles.includes('provider'))status='candidate';
   if(id==='EU-50-3'&&roles.includes('deployer')){if(system.emotionRecognition===true||system.biometricCategorisation===true)status='candidate';else missingFacts.push('emotionRecognition_or_biometricCategorisation');}
   if(id==='EU-50-4-MEDIA'&&roles.includes('deployer')){if(system.realisticSyntheticMedia===true)status='candidate';else missingFacts.push('realisticSyntheticMedia');}
   if(id==='EU-50-4-TEXT'&&roles.includes('deployer')){if(system.publicInterestText===true)status='candidate';else missingFacts.push('publicInterestText');}
   if(id==='EU-50-5')status='candidate';
  }
  if(id==='EU-50-2'&&!system.marketEntryAt)missingFacts.push('marketEntryAt');
  if(requirement.sourceTextStatus==='amendment_consolidation_unverified')reason='공식 안내 페이지가 개정 반영 전임을 표시합니다. 통합 원문과 전환 조건을 검토하세요';
 }
 return {status,reason,missingFacts:[...new Set(missingFacts)],policyVersion:applicabilityPolicyVersion,decision:'human_review_required'};
}

// Deterministic server-side capture of the facts and policy result used at review time.
// It records a review candidate, never a legal applicability or compliance decision.
export function applicabilityAssessmentSnapshot(requirement,system){
 const snapshot={schemaVersion:1,policyVersion:applicabilityPolicyVersion,requirementId:requirement.id,requirementHash:digest(requirement),systemId:system.id,systemHash:digest(system),candidate:applicabilityCandidate(requirement,system)};
 return {snapshot,hash:digest(snapshot)};
}

export function applicabilityCatalogIdentity(requirements){
 const identity={schemaVersion:1,requirementsHash:digest(requirements),policyVersion:applicabilityPolicyVersion};
 return {...identity,hash:digest(identity)};
}
