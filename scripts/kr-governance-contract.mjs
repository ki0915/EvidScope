import {readFileSync} from 'node:fs';
import {digest} from '../src/crypto.mjs';
import {krGovernanceCheckDefinitions} from '../src/kr-governance-evidence.mjs';
import {applicabilityCatalogIdentity} from '../src/governance-policy.mjs';

const requirements=JSON.parse(readFileSync(new URL('../data/requirements.json',import.meta.url),'utf8'));
const sources=['src/kr-governance-evidence.mjs','src/governance-policy.mjs','src/service.mjs','src/model.mjs','src/governance-documents.mjs'];
const contract={schemaVersion:1,eventKind:'governance_check',catalog:applicabilityCatalogIdentity(requirements),measurementTrust:'authenticated_reported_measurement_not_independent_truth',automaticLegalVerdict:false,sourceKinds:['telemetry','authority'],documentReferencePrefix:'governance-document:',bindingFields:['systemId','modelId','modelVersion','policyVersion','systemHash','requirementHash','documentHash'],fixedEventFields:['occurredAt','receivedAt','clockUncertaintyMs'],requirements:requirements.filter(r=>r.jurisdiction==='KR').map(r=>({id:r.id,title:r.title,requirementHash:digest(r),sourceUrl:r.sourceUrl})),checks:krGovernanceCheckDefinitions,sourceHashes:Object.fromEntries(sources.map(path=>[path,digest(readFileSync(new URL('../'+path,import.meta.url),'utf8'))]))};
console.log(JSON.stringify(contract,null,2));
