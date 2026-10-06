import {readFileSync,writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {assessComparisonReport} from './model-evaluate.mjs';
const hash=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
export function promoteCandidate(registry,report,approval){
 if(!assessComparisonReport(report).eligible)throw Error('candidate_evaluation_failed');
 if(approval?.reportHash!==hash(report)||approval?.approved!==true||approval?.semanticGroundingReviewed!==true||approval?.koreanQualityReviewed!==true||approval?.privacyReviewed!==true||approval?.injectionReviewed!==true||typeof approval?.reviewerId!=='string'||!approval.reviewerId.trim()||!Number.isFinite(Date.parse(approval.reviewedAt))||Date.parse(approval.reviewedAt)>Date.now())throw Error('independent_human_approval_required');
 if(registry?.activeArtifactSha256!==report.baselineArtifactSha256||!/^[a-f0-9]{64}$/.test(report.candidateArtifactSha256||''))throw Error('registry_base_changed');
 return {...registry,activeArtifactSha256:report.candidateArtifactSha256,previousArtifactSha256:registry.activeArtifactSha256,promotion:{reportHash:hash(report),reviewerId:approval.reviewerId,reviewedAt:approval.reviewedAt},deploymentChanged:false};
}
export function rollbackCandidate(registry){if(!/^[a-f0-9]{64}$/.test(registry?.previousArtifactSha256||''))throw Error('rollback_artifact_unavailable');return {...registry,activeArtifactSha256:registry.previousArtifactSha256,previousArtifactSha256:registry.activeArtifactSha256,promotion:null,deploymentChanged:false};}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){const [command,input,output,reportFile,approvalFile]=process.argv.slice(2),registry=JSON.parse(readFileSync(input,'utf8'));const updated=command==='rollback'?rollbackCandidate(registry):command==='promote'?promoteCandidate(registry,JSON.parse(readFileSync(reportFile,'utf8')),JSON.parse(readFileSync(approvalFile,'utf8'))):null;if(!updated)throw Error('unknown_registry_command');writeFileSync(output,JSON.stringify(updated,null,2)+'\n',{flag:'wx'});process.stdout.write(JSON.stringify({registryWritten:true,deploymentChanged:false})+'\n');}
