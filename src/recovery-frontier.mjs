import {createPublicKey,createPrivateKey,createHash,sign,verify,randomUUID} from 'node:crypto';
import {canonical,digest,verifyBundle,verifyCheckpoint,makeCheckpoint} from './crypto.mjs';
import {checkObjectProjection} from './object-integrity.mjs';
import {checkEventProjection} from './event-integrity.mjs';
import {checkReceiptProjection} from './receipt-integrity.mjs';

const FORMAT='evidscope-recovery-frontier-v1',ANCHOR='evidscope-recovery-frontier-anchor-v1';
export const MAX_RECOVERY_FRONTIER_BYTES=16*1024*1024;
const zero='0'.repeat(64),hex=/^[a-f0-9]{64}$/,uuid=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const requireValue=(value,message)=>{if(!value)throw Error('Recovery frontier: '+message);};
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value)&&[Object.prototype,null].includes(Object.getPrototypeOf(value));
const text=value=>typeof value==='string'&&value.length>0&&value.length<=4096;
const seq=value=>Number.isSafeInteger(value)&&value>0;
const exact=(value,names)=>object(value)&&Object.keys(value).length===names.length&&names.every(name=>Object.hasOwn(value,name));
const same=(a,b)=>canonical(a)===canonical(b);
function json(value){
 if(value===null||typeof value==='string'||typeof value==='boolean')return;
 if(typeof value==='number'){requireValue(Number.isFinite(value),'non-finite JSON');return;}
 requireValue(Array.isArray(value)||object(value),'plain JSON required');for(const child of Object.values(value))json(child);
}
function bounded(value){json(value);requireValue(Buffer.byteLength(canonical(value))<=MAX_RECOVERY_FRONTIER_BYTES,'size limit exceeded');}
const pubKey=value=>value?.type==='public'?value:createPublicKey(value);
const fingerprint=key=>createHash('sha256').update(pubKey(key).export({format:'der',type:'spki'})).digest('hex');
function checkpoint(value,tenant,key){
 requireValue(exact(value,['format','tenant','count','head','signature'])&&value.tenant===tenant&&text(tenant)&&Number.isSafeInteger(value.count)&&value.count>=0&&hex.test(value.head)&&typeof value.signature==='string','invalid checkpoint');
 requireValue(value.count!==0||value.head===zero,'invalid empty checkpoint');verifyCheckpoint(value,key);
}
function archive(value,key){
 requireValue(pubKey(key).asymmetricKeyType==='ed25519','unsupported trust key');
 requireValue(exact(value,['format','manifestSha256','keyFingerprint','checkpoints'])&&value.format==='evidscope-recovery-anchor-v1'&&hex.test(value.manifestSha256)&&value.keyFingerprint===fingerprint(key)&&object(value.checkpoints),'invalid archive anchor');
 for(const [tenant,cp]of Object.entries(value.checkpoints))checkpoint(cp,tenant,key);
}
function access(value){
 const names=['id','epoch','disabled','action','reason','changedBy','changedAt'];
 requireValue(object(value)&&Object.keys(value).every(key=>names.includes(key))&&text(value.id)&&Number.isSafeInteger(value.epoch)&&value.epoch>=0&&typeof value.disabled==='boolean','invalid identity access');
 for(const key of ['reason','changedBy','changedAt'])if(Object.hasOwn(value,key))requireValue(typeof value[key]==='string','invalid identity metadata');
 if(Object.hasOwn(value,'action'))requireValue(['enable','disable','revoke_sessions'].includes(value.action)&&(!['enable','disable'].includes(value.action)||value.disabled===(value.action==='disable')),'invalid identity action');
}
function plan(value){
 const names=['id','author','status','reason','items','selectionHash','createdAt','expiresAt','approvedBy','approvedAt','approvalReason','disposition'];
 requireValue(object(value)&&Object.keys(value).every(key=>names.includes(key))&&text(value.id)&&value.status==='executed'&&text(value.author)&&text(value.approvedBy)&&value.author!==value.approvedBy&&Array.isArray(value.items)&&value.items.length>0&&value.items.length<=1000&&value.selectionHash===digest(value.items),'invalid executed retention plan');
 const ids=new Set(),sequences=new Set(),itemNames=['seq','keyId','source','eventId','fingerprint','eventHash','receiptSigned','actionId','retainUntil','policyVersion','expired','blockingHolds','openCases','eligible'];
 for(const item of value.items){
  requireValue(object(item)&&Object.keys(item).every(key=>itemNames.includes(key))&&seq(item.seq)&&uuid.test(item.keyId)&&text(item.source)&&text(item.eventId)&&text(item.actionId)&&hex.test(item.fingerprint)&&hex.test(item.eventHash)&&!ids.has(item.keyId)&&!sequences.has(item.seq),'invalid plan item');ids.add(item.keyId);sequences.add(item.seq);
 }
 const d=value.disposition,dNames=['id','planId','selectionHash','keyIds','sequences','reason','approvedBy','executedBy','executedAt','scope','externalCopies','physicalMediaErasure'];
 requireValue(object(d)&&Object.keys(d).every(key=>dNames.includes(key))&&text(d.id)&&d.planId===value.id&&d.selectionHash===value.selectionHash&&d.approvedBy===value.approvedBy&&text(d.executedBy)&&same(d.keyIds,value.items.map(item=>item.keyId))&&same(d.sequences,value.items.map(item=>item.seq)),'invalid plan disposition');
}
function recordRef(value,count,validator){requireValue(exact(value,['seq','recordHash','payload'])&&seq(value.seq)&&value.seq<=count&&hex.test(value.recordHash),'invalid safety record reference');validator(value.payload);}

export function signRecoveryFrontier({bundles,archiveAnchor,privateKey,publicKey,config}){
 const key=privateKey?.type==='private'?privateKey:createPrivateKey(privateKey),pub=pubKey(publicKey);
 requireValue(key.asymmetricKeyType==='ed25519'&&same(createPublicKey(key).export({format:'der',type:'spki'}).toString('base64'),pub.export({format:'der',type:'spki'}).toString('base64')),'signing key mismatch');
 archive(archiveAnchor,pub);json(config);requireValue(object(config)&&Array.isArray(bundles),'invalid signing inputs');
 const tenants=[],names=new Set();
 for(const bundle of bundles){
  requireValue(object(bundle)&&Array.isArray(bundle.records)&&(!Object.hasOwn(bundle,'disclosures')||Array.isArray(bundle.disclosures)&&bundle.disclosures.length===0),'raw encrypted bundles required');
  verifyBundle(bundle,pub,undefined,{chainOnly:true});const tenant=bundle.checkpoint.tenant;checkpoint(bundle.checkpoint,tenant,pub);requireValue(!names.has(tenant),'duplicate tenant');names.add(tenant);
  const cp=Object.hasOwn(archiveAnchor.checkpoints,tenant)?archiveAnchor.checkpoints[tenant]:makeCheckpoint(tenant,0,zero,key);
  requireValue(bundle.checkpoint.count>=cp.count&&(cp.count===0?cp.head===zero:bundle.records[cp.count-1]?.hash===cp.head),'archive is not exact source prefix');
  const identity=new Map(),plans=new Map(),events=new Map(),disposed=new Set(),erasures=[];
  for(const row of bundle.records){
   if(row.type==='identity_access'){access(row.payload);identity.set(row.payload.id,{seq:row.seq,recordHash:row.hash,payload:structuredClone(row.payload)});}
   if(row.type==='retention_plan'){requireValue(object(row.payload)&&text(row.payload.id),'invalid retention record');plans.set(row.payload.id,row);}
   if(row.type==='event'){requireValue(row.payload?.format==='evidscope-encrypted-event-v1'&&row.payload.tenant===tenant&&row.payload.seq===row.seq&&uuid.test(row.payload.keyId)&&text(row.payload.actionId),'plaintext or invalid source event');requireValue(!events.has(row.payload.keyId),'duplicate event key');events.set(row.payload.keyId,row);}
  }
  const executed=[...plans.values()].filter(row=>row.payload.status==='executed');for(const row of executed)plan(row.payload);
  const byPlan=new Map(executed.map(row=>[row.payload.id,row]));
  for(const row of bundle.records.filter(row=>row.type==='retention_disposition')){
   const d=row.payload,p=byPlan.get(d?.planId),later=row.seq>cp.count;
   requireValue(object(d)&&Array.isArray(d.keyIds)&&d.keyIds.length>0&&d.keyIds.length===d.sequences?.length,'invalid source disposition');
   if(later)requireValue(p&&p.seq>row.seq&&same(p.payload.disposition,d),'unbound source disposition');
   for(let index=0;index<d.keyIds.length;index++){
    const event=events.get(d.keyIds[index]);requireValue(event&&event.seq===d.sequences[index]&&event.seq<row.seq&&!disposed.has(event.payload.keyId),'invalid source erasure');disposed.add(event.payload.keyId);
    if(later){
     const item=p.payload.items[index];requireValue(item.seq===event.seq&&item.keyId===event.payload.keyId&&item.eventHash===event.hash&&item.actionId===event.payload.actionId,'plan event mismatch');
     requireValue(bundle.records.some(receipt=>receipt.type==='event_receipt'&&receipt.seq>event.seq&&receipt.seq<row.seq&&receipt.payload?.format==='evidscope-event-receipt-v1'&&receipt.payload.eventSeq===event.seq&&receipt.payload.eventHash===event.hash&&receipt.payload.source===item.source&&receipt.payload.id===item.eventId&&receipt.payload.fingerprint===item.fingerprint),'source erasure receipt missing');
     if(event.seq<=cp.count)erasures.push({seq:event.seq,keyId:event.payload.keyId,actionId:event.payload.actionId,eventRecordHash:event.hash,sourceDispositionHash:row.hash,sourceDispositionSeq:row.seq,sourcePlanId:d.planId});
    }
   }
  }
  tenants.push({tenant,archiveCheckpoint:structuredClone(cp),currentCheckpoint:structuredClone(bundle.checkpoint),identityAccess:[...identity.values()].sort((a,b)=>a.payload.id.localeCompare(b.payload.id)),executedRetentionPlans:executed.map(row=>({seq:row.seq,recordHash:row.hash,payload:structuredClone(row.payload)})).sort((a,b)=>a.payload.id.localeCompare(b.payload.id)),erasedEvents:erasures.sort((a,b)=>a.seq-b.seq)});
 }
 requireValue(Object.keys(archiveAnchor.checkpoints).every(tenant=>names.has(tenant)),'archive tenant missing');
 const statement={format:FORMAT,archiveManifestSha256:archiveAnchor.manifestSha256,keyFingerprint:fingerprint(pub),configHash:digest(config),tenants:tenants.sort((a,b)=>a.tenant.localeCompare(b.tenant))};
 bounded(statement);const frontier={...statement,signature:sign(null,Buffer.from(canonical(statement)),key).toString('base64')};bounded(frontier);
 const anchor={format:ANCHOR,frontierSha256:digest(frontier),keyFingerprint:statement.keyFingerprint,archiveManifestSha256:statement.archiveManifestSha256};
 verifyRecoveryFrontier({frontier,anchor,archiveAnchor,publicKey:pub,config});return {frontier,anchor};
}

export function verifyRecoveryFrontier({frontier,anchor,archiveAnchor,publicKey,config}){
 const pub=pubKey(publicKey);archive(archiveAnchor,pub);json(config);bounded(frontier);
 requireValue(exact(frontier,['format','archiveManifestSha256','keyFingerprint','configHash','tenants','signature'])&&frontier.format===FORMAT&&frontier.archiveManifestSha256===archiveAnchor.manifestSha256&&frontier.keyFingerprint===fingerprint(pub)&&frontier.configHash===digest(config)&&Array.isArray(frontier.tenants),'invalid frontier statement');
 requireValue(exact(anchor,['format','frontierSha256','keyFingerprint','archiveManifestSha256'])&&anchor.format===ANCHOR&&anchor.frontierSha256===digest(frontier)&&anchor.keyFingerprint===frontier.keyFingerprint&&anchor.archiveManifestSha256===archiveAnchor.manifestSha256,'external frontier anchor mismatch');
 const {signature,...statement}=frontier;requireValue(typeof signature==='string'&&verify(null,Buffer.from(canonical(statement)),pub,Buffer.from(signature,'base64')),'frontier signature invalid');
 const tenants=new Set();
 for(const entry of statement.tenants){
  requireValue(exact(entry,['tenant','archiveCheckpoint','currentCheckpoint','identityAccess','executedRetentionPlans','erasedEvents'])&&text(entry.tenant)&&!tenants.has(entry.tenant),'invalid or duplicate tenant');tenants.add(entry.tenant);
  checkpoint(entry.archiveCheckpoint,entry.tenant,pub);checkpoint(entry.currentCheckpoint,entry.tenant,pub);
  const archived=Object.hasOwn(archiveAnchor.checkpoints,entry.tenant)?archiveAnchor.checkpoints[entry.tenant]:undefined;requireValue(archived?same(archived,entry.archiveCheckpoint):entry.archiveCheckpoint.count===0,'archive checkpoint changed');
  requireValue(entry.currentCheckpoint.count>=entry.archiveCheckpoint.count&&(entry.currentCheckpoint.count!==entry.archiveCheckpoint.count||entry.currentCheckpoint.head===entry.archiveCheckpoint.head),'checkpoint regressed');
  const safetySeqs=new Set();
  for(const [key,validator]of [['identityAccess',access],['executedRetentionPlans',plan]]){
   requireValue(Array.isArray(entry[key]),'invalid safety list');const ids=new Set();
   for(const item of entry[key]){recordRef(item,entry.currentCheckpoint.count,validator);requireValue(!ids.has(item.payload.id)&&!safetySeqs.has(item.seq),'duplicate safety record');ids.add(item.payload.id);safetySeqs.add(item.seq);}
  }
  requireValue(Array.isArray(entry.erasedEvents),'invalid erasure list');const keys=new Set(),sequences=new Set(),plans=new Map(entry.executedRetentionPlans.map(item=>[item.payload.id,item]));
  for(const e of entry.erasedEvents){
   const p=plans.get(e?.sourcePlanId),item=p?.payload.items.find(item=>item.keyId===e?.keyId);
   requireValue(exact(e,['seq','keyId','actionId','eventRecordHash','sourceDispositionHash','sourceDispositionSeq','sourcePlanId'])&&seq(e.seq)&&e.seq<=entry.archiveCheckpoint.count&&uuid.test(e.keyId)&&text(e.actionId)&&hex.test(e.eventRecordHash)&&hex.test(e.sourceDispositionHash)&&seq(e.sourceDispositionSeq)&&e.sourceDispositionSeq>entry.archiveCheckpoint.count&&e.sourceDispositionSeq<=(entry.currentCheckpoint.count)&&p&&p.seq>e.sourceDispositionSeq&&item&&item.seq===e.seq&&item.actionId===e.actionId&&item.eventHash===e.eventRecordHash&&!keys.has(e.keyId)&&!sequences.has(e.seq),'invalid erasure reference');keys.add(e.keyId);sequences.add(e.seq);
  }
 }
 requireValue(Object.keys(archiveAnchor.checkpoints).every(tenant=>tenants.has(tenant)),'archive tenant missing');
 return structuredClone(statement);
}

// An externally pinned matching frontier authenticates a chosen safety snapshot.
// It cannot by itself establish that the operator supplied the latest frontier and pin; a restore's witness check can.
// freshness (optional): the restore's witness check for the previous transparency origin (transparency-epoch.mjs).
export function applyRecoveryFrontier({store,frontier,anchor,archiveAnchor,config,freshness}){
 const statement=verifyRecoveryFrontier({frontier,anchor,archiveAnchor,publicKey:store.publicKey,config}),frontierHash=digest(frontier);
 const applied=store.transaction(()=>{
  const actualTenants=store.db.prepare('SELECT tenant FROM ledger UNION SELECT tenant FROM checkpoints UNION SELECT tenant FROM objects UNION SELECT tenant FROM events UNION SELECT tenant FROM actions UNION SELECT tenant FROM event_keys UNION SELECT tenant FROM receipts UNION SELECT tenant FROM tlog_state ORDER BY tenant').all().map(row=>row.tenant);
  requireValue(same(actualTenants,Object.keys(archiveAnchor.checkpoints).sort()),'restored tenant set mismatch');
  let identities=0,erased=0,plansApplied=0;
  for(const entry of statement.tenants){
   const tenant=entry.tenant,bundle=store.bundle(tenant);verifyBundle(bundle,store.publicKey,entry.archiveCheckpoint);store.checkActionProjection(tenant);checkObjectProjection(store.db,tenant,bundle.records);const events=store.decodeRecords(bundle);checkEventProjection(store.db,tenant,events);checkReceiptProjection(store.db,tenant,bundle.records,events);
   const bySeq=new Map(events.map(event=>[event.seq,event])),records=new Map(bundle.records.map(row=>[row.seq,row])),existingReceipts=new Set(bundle.records.filter(row=>row.type==='event_receipt').map(row=>row.payload.eventSeq));
   const actor={tenant,id:'recovery-frontier'};
   for(const item of entry.identityAccess){store.put(actor,'identity_access',item.payload.id,item.payload);identities++;}
   for(const item of entry.executedRetentionPlans){store.put(actor,'retention_plan',item.payload.id,item.payload);plansApplied++;}
   for(const reference of entry.erasedEvents){
    const row=records.get(reference.seq),event=bySeq.get(reference.seq),key=store.db.prepare('SELECT seq,key FROM event_keys WHERE tenant=? AND key_id=?').get(tenant,reference.keyId);
    requireValue(row?.type==='event'&&row.hash===reference.eventRecordHash&&row.payload.format==='evidscope-encrypted-event-v1'&&row.payload.keyId===reference.keyId&&row.payload.actionId===reference.actionId&&event&&event.actionId===reference.actionId&&key&&key.seq===reference.seq&&key.key?.length===32,'restored event or key mismatch');
    if(!existingReceipts.has(reference.seq))store.append(tenant,'event_receipt',{format:'evidscope-event-receipt-v1',basis:'verified_before_retention',attestedBy:actor.id,source:event.source,id:event.id,fingerprint:event.fingerprint,eventSeq:reference.seq,eventHash:row.hash},actor.id);
    store.projectionMutation(()=>{requireValue(store.db.prepare('DELETE FROM event_keys WHERE tenant=? AND key_id=?').run(tenant,reference.keyId).changes===1,'missing restored key');requireValue(store.db.prepare('DELETE FROM events WHERE tenant=? AND source=? AND id=?').run(tenant,event.source,event.id).changes===1,'missing restored event');requireValue(store.db.prepare('UPDATE actions SET version=version+1 WHERE tenant=? AND id=?').run(tenant,reference.actionId).changes===1,'missing restored action');});erased++;
   }
   if(entry.erasedEvents.length)store.append(tenant,'retention_disposition',{id:randomUUID(),keyIds:entry.erasedEvents.map(e=>e.keyId),sequences:entry.erasedEvents.map(e=>e.seq),executedBy:actor.id,executedAt:new Date().toISOString(),scope:'live_event_keys_and_search_projection',externalCopies:'not_verified',physicalMediaErasure:'not_verified',frontierHash,archiveManifestSha256:statement.archiveManifestSha256,sourceDispositions:entry.erasedEvents.map(e=>({eventSeq:e.seq,hash:e.sourceDispositionHash,seq:e.sourceDispositionSeq,planId:e.sourcePlanId}))},actor.id);
   const after=store.bundle(tenant);verifyBundle(after,store.publicKey);store.checkActionProjection(tenant);checkObjectProjection(store.db,tenant,after.records);const decoded=store.decodeRecords(after);checkEventProjection(store.db,tenant,decoded);checkReceiptProjection(store.db,tenant,after.records,decoded);
   store.append(tenant,'recovery_frontier_applied',{format:FORMAT,frontierHash,archiveManifestSha256:statement.archiveManifestSha256,sourceCheckpoint:entry.currentCheckpoint},actor.id);
  }
  return {applied:true,frontierSha256:frontierHash,identityStatesApplied:identities,eventsErased:erased,executedPlansApplied:plansApplied,freshnessEstablished:freshness?.established===true,...(freshness?{transparencyFreshness:freshness}:{}),limitations:[freshness?.established?'Freshness covers what the witness quorum cosigned for the previous origin; records newer than its latest cosigned heads checkpoint stay undetectable.':'A stale frontier with a matching external pin cannot be identified as latest by this module.','Replay removes live restored event keys and search projections, not existing backups or physical media.']};
 });
 if(applied.eventsErased)store.checkpointAfterErasure?.();
 return applied;
}
