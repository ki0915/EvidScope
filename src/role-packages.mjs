import {readFileSync} from 'node:fs';
import {resolve,join} from 'node:path';

export const ROLE_IDS=Object.freeze(['evidence-organizer','evidence-reconciler','governance-assistant','report-drafter']);

function validate(pack){
 if(!pack||pack.schemaVersion!==1||!ROLE_IDS.includes(pack.id)||pack.version!=='1.0.0')throw Error('Invalid role package identity/version');
 for(const field of ['tools','knowledge','outputSchema','refusalPolicy','evalSets'])if(!pack[field])throw Error(`Role package ${pack.id} missing ${field}`);
 if(!Array.isArray(pack.tools)||!Array.isArray(pack.knowledge)||!Array.isArray(pack.evalSets))throw Error(`Role package ${pack.id} list field invalid`);return pack;
}

export function loadRolePackage(roleId,{root=resolve('.')}={}){
 if(!ROLE_IDS.includes(roleId))throw Error(`Unknown operational role: ${roleId}`);const directory=join(root,'roles',roleId,'v1');const pack=validate(JSON.parse(readFileSync(join(directory,'role.json'),'utf8')));const instructions=readFileSync(join(directory,'instructions.md'),'utf8').trim();if(!instructions)throw Error(`Role package ${roleId} has empty instructions`);return Object.freeze({...pack,instructions,packagePath:`roles/${roleId}/v1`});
}
export function loadRolePackages(options){return ROLE_IDS.map(id=>loadRolePackage(id,options));}
export function buildRoleExecution(roleId,{request,contextRefs=[],root=resolve('.')}={}){const profile=loadRolePackage(roleId,{root});if(typeof request!=='string'||!request.trim())throw Error('Role request is required');if(!Array.isArray(contextRefs)||contextRefs.some(v=>typeof v!=='string'))throw Error('contextRefs must be string identifiers');return {roleId:profile.id,roleVersion:profile.version,systemInstructions:profile.instructions,allowedTools:profile.tools,knowledge:profile.knowledge,input:{request:request.trim(),contextRefs},outputSchema:profile.outputSchema,refusalPolicy:profile.refusalPolicy,evalSets:profile.evalSets};}
