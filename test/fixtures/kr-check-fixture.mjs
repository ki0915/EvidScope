import {randomUUID} from 'node:crypto';
import {digest} from '../../src/crypto.mjs';
import {validateEvent} from '../../src/model.mjs';

export const publicationMetrics={measureDocumentInventoryRecorded:true,retentionYears:5,accessControlTestPassed:true,restoreTestPassed:true,publishedSections:['risk_management','explanation','user_protection','oversight_name_contact'],excludedSections:[],exclusionBasisRecorded:false,publicationTestPassed:true};
export const oversightMetrics={sections:['responsibility','authority','competence','intervention','contact'],interventionExercisePassed:true};

// Test-only authenticated measurement, kept separate from production collectors.
export function appendKrCheck(service,system,requirement,document,checkType,measurements,{sourceKind='telemetry',source='test-measurements',...overrides}={}){
 const p={id:source,tenant:'alpha',kind:sourceKind};
 const event=validateEvent({id:randomUUID(),kind:'governance_check',occurredAt:new Date().toISOString(),traceId:'check-trace',actionId:'check-action',systemId:system.id,modelId:system.modelId,modelVersion:system.modelVersion,policyVersion:system.policyVersion,clockUncertaintyMs:0,governanceCheck:{schemaVersion:1,requirementId:requirement.id,checkType,result:'pass',systemHash:digest(system),requirementHash:digest(requirement),documentHash:document.sha256,measurements},...overrides},p);
 service.store.transaction(()=>{const record=service.store.append(p.tenant,'event',event,p.id);service.store.project({...event,seq:record.seq,hash:record.hash});service.store.projectionMutation(()=>service.store.db.prepare('INSERT INTO actions(tenant,id,version) VALUES(?,?,1) ON CONFLICT(tenant,id) DO UPDATE SET version=version+1').run(p.tenant,event.actionId));});
 return {type:'event',ref:`${event.source}/${event.id}`};
}
