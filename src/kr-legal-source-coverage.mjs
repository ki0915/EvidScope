import {digest} from './crypto.mjs';

export const krLegalSourceCoverageVersion='evidscope-kr-legal-source-coverage-v1';

// Product/source scope, not the system's legal applicability or evidence verdict.
// A registered catalog is a selection of obligations, never proof of whole-law coverage.
export function krLegalSourceCoverage(requirements=[]){
 const korean=requirements.filter(requirement=>requirement.jurisdiction==='KR');
 const grouped=new Map();
 for(const requirement of korean)for(const gap of requirement.legalSourceGaps||[]){
  const {id,article,title,status,sourceUrl,checkedAt}=gap;
  const key=digest({id,article,title,status,sourceUrl,checkedAt});
  if(!grouped.has(key))grouped.set(key,{id,article,title,status,sourceUrl,checkedAt,affectedRequirementIds:[]});
  grouped.get(key).affectedRequirementIds.push(requirement.id);
 }
 const unresolvedSources=[...grouped.values()].map(gap=>({...gap,affectedRequirementIds:[...new Set(gap.affectedRequirementIds)].sort()})).sort((a,b)=>a.id.localeCompare(b.id)||a.article.localeCompare(b.article));
 const unverifiedDetailNoticeRequirementIds=korean.filter(requirement=>requirement.detailNoticeStatus==='not_verified').map(requirement=>requirement.id).sort();
 const dates=[...korean.map(requirement=>requirement.verifiedAt),...unresolvedSources.map(gap=>gap.checkedAt)];
 const checkedAt=dates.length&&dates.every(value=>typeof value==='string'&&/^\d{4}-\d{2}-\d{2}$/.test(value))?[...dates].sort()[0]:null;
 const snapshot={schemaVersion:1,version:krLegalSourceCoverageVersion,jurisdiction:'KR',scope:'selected_ai_operator_and_public_user_governance_requirements',scopeDescription:'등록된 주요 사업자·공공 이용자의 거버넌스 의무를 검토하며 한국 AI 기본법 전체를 포괄하지 않습니다.',status:!korean.length?'not_recorded':unresolvedSources.length||unverifiedDetailNoticeRequirementIds.length?'source_verification_incomplete':'partial',registeredRequirements:korean.length,wholeLawComplete:false,automaticLegalVerdict:false,checkedAt,requirementsHash:digest(requirements),unverifiedDetailNoticeRequirementIds,unresolvedSources,limitations:['법률·시행령 원문 확인과 하위 고시·위원회 결정 확인은 별개입니다. 미확인은 부존재·적용 제외·법 위반 판정이 아닙니다.','개별 조치의 기술 근거 또는 사람의 충분성 평가가 확인되어도 한국법 전체 지원 완료를 의미하지 않습니다.']};
 return {...snapshot,hash:digest(snapshot)};
}
