import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {digest} from '../src/crypto.mjs';
import {krLegalSourceCoverage,krLegalSourceCoverageVersion} from '../src/kr-legal-source-coverage.mjs';
import {applicabilityCatalogIdentity} from '../src/governance-policy.mjs';

const requirements=JSON.parse(readFileSync(new URL('../data/requirements.json',import.meta.url),'utf8'));
const kr34=['KR-34-DOCUMENT','KR-34-EXPLAIN','KR-34-OVERSIGHT','KR-34-PROTECT','KR-34-RISK'];

test('current registered KR obligations expose four exact unresolved source scopes without claiming the whole law',()=>{
 const coverage=krLegalSourceCoverage(requirements);
 assert.equal(requirements.length,31);assert.equal(coverage.registeredRequirements,18);
 assert.equal(coverage.version,krLegalSourceCoverageVersion);assert.equal(coverage.checkedAt,'2026-10-06');
 assert.equal(coverage.status,'source_verification_incomplete');assert.equal(coverage.wholeLawComplete,false);assert.equal(coverage.automaticLegalVerdict,false);
 assert.equal(coverage.unverifiedDetailNoticeRequirementIds.length,13);assert.equal(coverage.unresolvedSources.length,4);
 const sources=Object.fromEntries(coverage.unresolvedSources.map(source=>[source.id,source]));
 assert.deepEqual(sources['KR-34-1-6-COMMITTEE'].affectedRequirementIds,kr34);
 assert.equal(sources['KR-34-1-6-COMMITTEE'].article,'법 제34조제1항제6호');
 assert.deepEqual(sources['KR-34-2-DETAIL-NOTICE'].affectedRequirementIds,kr34);assert.equal(sources['KR-34-2-DETAIL-NOTICE'].article,'법 제34조제2항');
 assert.deepEqual(sources['KR-DECREE-23-4-3-EXCEPTION'].affectedRequirementIds,['KR-31-1','KR-31-2','KR-31-3']);assert.equal(sources['KR-DECREE-23-4-3-EXCEPTION'].article,'시행령 제23조제4항제3호');
 assert.deepEqual(sources['KR-DECREE-25-2-5-CRITERIA'].affectedRequirementIds,['KR-33']);assert.equal(sources['KR-DECREE-25-2-5-CRITERIA'].article,'시행령 제25조제2항제5호');
 for(const source of coverage.unresolvedSources){assert.equal(source.status,'not_verified');assert.equal(new URL(source.sourceUrl).hostname,'www.law.go.kr');}
 assert.ok(!requirements.some(requirement=>requirement.id==='KR-34-1-6-COMMITTEE'),'a source gap is not a new legal obligation');
 for(const requirement of requirements.filter(requirement=>requirement.jurisdiction==='KR'))assert.equal(requirement.sourceTextStatus,'verified_statute_and_decree');
});

test('individual sufficient technical and human conclusions cannot promote catalog coverage or mutate them',()=>{
 const supported=requirements.filter(requirement=>kr34.includes(requirement.id)).map(requirement=>({...requirement,assessment:'sufficient',legalReview:'reviewed',technicalEvidence:{supportsHumanAssessment:true}}));
 const before=structuredClone(supported),coverage=krLegalSourceCoverage(supported);
 assert.equal(coverage.registeredRequirements,5);assert.equal(coverage.wholeLawComplete,false);assert.equal(coverage.status,'source_verification_incomplete');
 assert.equal(coverage.unresolvedSources.length,2);assert.equal(coverage.unresolvedSources.find(source=>source.id==='KR-34-1-6-COMMITTEE').affectedRequirementIds.length,5);
 assert.deepEqual(supported,before);
});

test('exact source-gap metadata and coverage projection are bound to requirement digests and catalog identity',()=>{
 const before=krLegalSourceCoverage(requirements),identity=applicabilityCatalogIdentity(requirements),changed=structuredClone(requirements);
 const row=changed.find(requirement=>requirement.id==='KR-34-RISK'),original=requirements.find(requirement=>requirement.id===row.id);
 row.legalSourceGaps[0].checkedAt='2026-10-05';
 const after=krLegalSourceCoverage(changed),nextIdentity=applicabilityCatalogIdentity(changed);
 assert.notEqual(digest(row),digest(original));assert.notEqual(after.requirementsHash,before.requirementsHash);assert.notEqual(after.hash,before.hash);assert.notEqual(nextIdentity.hash,identity.hash);
 assert.equal(identity.legalSourceCoverageHash,before.hash);assert.equal(nextIdentity.legalSourceCoverageHash,after.hash);
 const {hash,...snapshot}=before;assert.equal(hash,digest(snapshot));assert.deepEqual(krLegalSourceCoverage(requirements),before);
});

test('legacy metadata absence and incomplete source dates remain explicitly partial or unrecorded',()=>{
 const empty=krLegalSourceCoverage([]);assert.equal(empty.status,'not_recorded');assert.equal(empty.checkedAt,null);assert.equal(empty.wholeLawComplete,false);
 const legacy=requirements.filter(requirement=>requirement.jurisdiction==='KR').map(({legalSourceGaps,detailNoticeStatus,...requirement})=>requirement),coverage=krLegalSourceCoverage(legacy);
 assert.equal(coverage.status,'partial');assert.equal(coverage.wholeLawComplete,false);assert.deepEqual(coverage.unresolvedSources,[]);
 const missingDate=structuredClone(requirements);delete missingDate.find(requirement=>requirement.id==='KR-34-RISK').legalSourceGaps[0].checkedAt;
 assert.equal(krLegalSourceCoverage(missingDate).checkedAt,null);
});

test('conflicting metadata for one source ID stays distinct instead of erasing an unresolved version',()=>{
 const changed=structuredClone(requirements),row=changed.find(requirement=>requirement.id==='KR-34-RISK');row.legalSourceGaps[0].title+=' (다른 출처 기록)';
 const coverage=krLegalSourceCoverage(changed),committee=coverage.unresolvedSources.filter(source=>source.id==='KR-34-1-6-COMMITTEE');
 assert.equal(committee.length,2);assert.equal(coverage.wholeLawComplete,false);assert.equal(coverage.status,'source_verification_incomplete');
 assert.ok(committee.some(source=>source.affectedRequirementIds.length===1&&source.affectedRequirementIds[0]===row.id));assert.ok(committee.some(source=>source.affectedRequirementIds.length===4));
});
