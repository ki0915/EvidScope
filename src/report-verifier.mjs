import {createHash,createPublicKey,verify} from 'node:crypto';
import {canonical,digest,verifyCheckpoint} from './crypto.mjs';

// Only a separately distributed public key is trusted. A signed report is an
// attestation of a vault snapshot, not proof that a source's claim is true.
export function verifyCaseReport(report,trustedPublicKey,options={}) {
 const key=typeof trustedPublicKey==='object'&&trustedPublicKey.type==='public'?trustedPublicKey:createPublicKey(trustedPublicKey);
 if(key.asymmetricKeyType!=='ed25519')throw Error('Trusted key must be Ed25519');
 if(report?.format!=='evidscope-case-report-v1'||!report.snapshot||typeof report.snapshot!=='object')throw Error('Unsupported case report');
 const fingerprint=createHash('sha256').update(key.export({format:'der',type:'spki'})).digest('hex');
 if(report.publicKeyFingerprint!==fingerprint)throw Error('Report key differs from separately trusted key');
 const payload=canonical({format:report.format,snapshot:report.snapshot});
 if(Buffer.byteLength(payload)>20*1024*1024)throw Error('Report exceeds verification size limit');
 if(typeof report.signature!=='string'||!/^[A-Za-z0-9+/]{86}==$/.test(report.signature)||!verify(null,Buffer.from(payload),key,Buffer.from(report.signature,'base64')))throw Error('Case report signature invalid');
 const s=report.snapshot;
 if(!s.tenant||!s.case?.id||!s.action?.actionId||s.case.actionId!==s.action.actionId||!s.review||!Number.isFinite(Date.parse(s.exportedAt)))throw Error('Case report context invalid');
 if(s.checkpoint?.tenant!==s.tenant)throw Error('Checkpoint tenant differs from report');
 verifyCheckpoint(s.checkpoint,key);
 if(options.expectedTenant&&options.expectedTenant!==s.tenant)throw Error('Unexpected report tenant');
 if(options.expectedCaseId&&options.expectedCaseId!==s.case.id)throw Error('Unexpected case ID');
 if(options.expectedCheckpoint&&canonical(options.expectedCheckpoint)!==canonical(s.checkpoint))throw Error('External checkpoint mismatch: possible rollback');
 const reportHash=digest(payload);
 if(options.expectedReportHash&&options.expectedReportHash!==reportHash)throw Error('External report digest mismatch');
 return {valid:true,tenant:s.tenant,caseId:s.case.id,actionId:s.action.actionId,exportedAt:s.exportedAt,reviewState:s.review.state,reportHash,publicKeyFingerprint:fingerprint,rollbackChecked:!!(options.expectedCheckpoint||options.expectedReportHash),scope:'서명된 사건 스냅샷과 체크포인트를 검증했습니다. 원본 전체 체인의 포함·완전성 검증은 별도 전체 증적 내보내기로 수행해야 합니다. 출처 주장의 진실성·외부 효과·법적 준수는 보증하지 않습니다.'};
}

// Finance envelopes contain a signed snapshot, without a ledger checkpoint.
// A separately pinned snapshot hash can detect replay of another report.
export function verifyFinanceReport(report,trustedPublicKey,{expectedReportHash}={}){
 const key=typeof trustedPublicKey==='object'&&trustedPublicKey.type==='public'?trustedPublicKey:createPublicKey(trustedPublicKey);
 if(key.asymmetricKeyType!=='ed25519')throw Error('Trusted key must be Ed25519');
 const snapshot=report?.snapshot;
 if(snapshot?.schemaVersion!==1||!snapshot.id||!snapshot.tenant||!snapshot.system?.id||!snapshot.governance||snapshot.automaticLegalVerdict!==false||!Number.isFinite(Date.parse(snapshot.createdAt)))throw Error('Unsupported finance report');
 const payload=canonical(snapshot);
 if(Buffer.byteLength(payload)>20*1024*1024)throw Error('Report exceeds verification size limit');
 const reportHash=digest(snapshot);
 if(report.sha256!==reportHash)throw Error('Finance snapshot digest mismatch');
 if(typeof report.signature!=='string'||!/^[A-Za-z0-9+/]{86}==$/.test(report.signature)||!verify(null,Buffer.from(payload),key,Buffer.from(report.signature,'base64')))throw Error('Finance report signature invalid');
 if(expectedReportHash!==undefined&&(!/^[a-f0-9]{64}$/.test(expectedReportHash)||expectedReportHash!==reportHash))throw Error('External report digest mismatch');
 return {valid:true,reportId:snapshot.id,tenant:snapshot.tenant,systemId:snapshot.system.id,createdAt:snapshot.createdAt,reportHash,publicKeyFingerprint:createHash('sha256').update(key.export({format:'der',type:'spki'})).digest('hex'),rollbackChecked:expectedReportHash!==undefined,automaticLegalVerdict:false,scope:'서명된 금융·거버넌스 스냅샷을 검증했습니다. 원장 체인·출처 진실성·법률 충분성은 별도 검토입니다.'};
}
