// POST /api/registry/import (docs/agent-registry.md): catalog documents in the request body become registry entries in the
// discovered state with their provenance (src/agent-catalog.mjs maps; this module decides and writes). The vault fetches
// nothing. An entry is matched by its catalog key; the same entity again is a no-op, a changed one is a new version of the
// same discovered entry, and an entry that a person took past discovered or edited since its last import is reported as a
// conflict and never overwritten. Reviewers and admins only (the registry route checks the role before this runs).
import {randomUUID} from 'node:crypto';
import {fail} from './model.mjs';
import {CATALOG_LIMITS,isCatalogError,mapCatalogDocument,normalizeAgentTypes,normalizeKeys} from './agent-catalog.mjs';

const OUTCOMES=['created','updated','unchanged','conflict','skipped','rejected'];
const only=(x,allowed,name)=>{
 if(!x||typeof x!=='object'||Array.isArray(x))fail(400,`${name}는 JSON 객체여야 합니다`);
 for(const k of Object.keys(x))if(!allowed.includes(k))fail(400,`${name}에 허용되지 않은 필드: ${k}`);return x;
};
// The version an import wrote is the entry's latest edit: nobody changed the content since (a risk override or nothing).
export const lastEditWasImport=entry=>!!entry.catalog&&entry.editedBy===entry.catalog.importedBy&&entry.editedAt===entry.catalog.importedAt;

export function createCatalogImport({store,policyObjects,putVersion,riskRecord,supersede,now}){
 const options=x=>{
  try{return {keys:normalizeKeys(x.keys),agentTypes:normalizeAgentTypes(x.agentTypes)};}
  catch(error){if(isCatalogError(error))fail(400,`가져오기 옵션 오류(${error.code}): ${error.message}`);throw error;}
 };
 function plan(p,entries,claimed,mapping,document,importId,at,dryRun){
  const {key,draft}=mapping,matches=[...entries.values()].filter(v=>v.catalog?.key===key);
  const match=matches.find(v=>v.state!=='retired')||matches[0];
  const catalog={key,...mapping.provenance,documentDigest:document.documentDigest,entityDigest:mapping.entityDigest,entityIndex:mapping.entityIndex,
   locator:document.locator,importId,importedBy:p.id,importedAt:at,mapped:mapping.mapped.map(m=>m.field),dropped:mapping.dropped.map(d=>d.field).slice(0,50),
   assurance:'self_reported_catalog'};
  if(claimed.has(key))return {outcome:'conflict',reason:'duplicate_key_in_request',entry:{id:claimed.get(key)}};
  if(match){
   claimed.set(key,match.id);
   const entry={id:match.id,version:match.version,state:match.state};
   if(match.catalog.entityDigest===mapping.entityDigest)return {outcome:'unchanged',entry};
   if(match.state!=='discovered')return {outcome:'conflict',reason:match.state==='retired'?'entry_retired':'entry_past_discovered',entry};
   if(!lastEditWasImport(match))return {outcome:'conflict',reason:'edited_since_import',entry};
   const fingerprint={...match.fingerprint};if(draft.fingerprintVersion)fingerprint.version=draft.fingerprintVersion;else delete fingerprint.version;
   const next={...match,name:draft.name,owner:draft.owner,purpose:draft.purpose,fingerprint,editedBy:p.id,editedAt:at,catalog,
    version:match.version+1,effectiveFrom:at,change:'updated'};
   if(!dryRun){supersede(p,match.id,'registry_version_changed');putVersion(p,{...next,risk:riskRecord(p,next)});}
   return {outcome:'updated',entry:{id:match.id,version:next.version,state:next.state}};
  }
  const id=mapping.suggestedId;
  const taken=entries.get(id);
  if(taken||[...claimed.values()].includes(id))return {outcome:'conflict',reason:'id_in_use',entry:taken?{id,version:taken.version,state:taken.state}:{id}};
  // Self-reported content only: no sources, actors, tools, links or risk override, and never past discovered.
  const base={id,name:draft.name,owner:draft.owner,purpose:draft.purpose,sources:[],actors:[],assetIds:[],systemId:null,models:[],tools:[],
   dataCategories:[],destinations:[],fingerprint:draft.fingerprintVersion?{version:draft.fingerprintVersion}:{},state:'discovered',registeredBy:p.id,
   registeredAt:at,editedBy:p.id,editedAt:at,version:1,effectiveFrom:at,change:'created',catalog};
  claimed.set(key,id);if(!dryRun)putVersion(p,{...base,risk:riskRecord(p,base)});
  return {outcome:'created',entry:{id,version:1,state:'discovered'}};
 }
 function importCatalog(p,x){
  only(x,['documents','keys','agentTypes','dryRun'],'가져오기 요청');
  if(!Array.isArray(x.documents)||!x.documents.length||x.documents.length>CATALOG_LIMITS.documents)
   fail(400,`documents는 1~${CATALOG_LIMITS.documents}개 배열입니다`);
  if(x.dryRun!==undefined&&typeof x.dryRun!=='boolean')fail(400,'dryRun은 true 또는 false입니다');
  const settings=options(x),dryRun=x.dryRun===true;
  const documents=x.documents.map((d,index)=>{
   only(d,['format','content','locator'],`documents[${index}]`);
   try{return {index,...mapCatalogDocument(d,settings)};}
   catch(error){
    if(!isCatalogError(error))throw error;
    return {index,format:typeof d.format==='string'?d.format.slice(0,40):null,rejected:{code:error.code,message:error.message}};
   }
  });
  const total=documents.reduce((n,d)=>n+(d.results?.length||0),0);
  if(total>CATALOG_LIMITS.entities)fail(413,`한 번에 가져올 수 있는 항목은 ${CATALOG_LIMITS.entities}개입니다`);
  const importId=randomUUID();
  return store.transaction(()=>{
   const entries=policyObjects(p,'agent_registry'),claimed=new Map(),at=now(),results=[];
   for(const document of documents)for(const mapping of document.results||[]){
    const common={documentIndex:document.index,entityIndex:mapping.entityIndex,key:mapping.key??null,entityDigest:mapping.entityDigest,
     ...(mapping.entityRef?{entityRef:mapping.entityRef}:{}),mapped:mapping.mapped,dropped:mapping.dropped,
     ...(mapping.provenance?{signature:mapping.provenance.signature}:{})};
    if(mapping.outcome!=='mapped'){
     results.push({...common,outcome:mapping.outcome,reason:mapping.reason,...(mapping.detail?{detail:mapping.detail}:{})});continue;
    }
    results.push({...common,...plan(p,entries,claimed,mapping,document,importId,at,dryRun)});
   }
   const summary=Object.fromEntries(OUTCOMES.map(o=>[o,results.filter(r=>r.outcome===o).length]));
   summary.rejectedDocuments=documents.filter(d=>d.rejected).length;
   return {importId,dryRun,importedAt:at,summary,documents:documents.map(d=>({index:d.index,format:d.format,locator:d.locator??null,
    documentDigest:d.documentDigest??null,bytes:d.bytes??null,entities:d.results?.length??0,...(d.rejected?{rejected:d.rejected}:{})})),results,
    limitations:['카탈로그 문서의 값은 자기 보고입니다. 인증된 출처 자격·행위자·도구·위험 등급·상태는 문서에서 가져오지 않으며 항목은 discovered로만 기록됩니다',
     'vault는 문서를 가져오지 않습니다(외부 요청 없음). locator는 제출자가 적은 위치이며 확인하지 않습니다',
     'A2A 서명은 요청에 함께 보낸 공개 키로만 확인합니다. jku는 기록만 하고 가져오지 않습니다']};
  });
 }
 return {importCatalog};
}
