import {canonical} from './crypto.mjs';

const encryptedFormat='evidscope-encrypted-event-v1';
const mismatch=detail=>{throw Error(`Action projection differs from signed evidence${detail?`: ${detail}`:''}`);};
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const actionId=value=>typeof value==='string'&&value.length>0?value:mismatch('event actionId is not replayable');

function decodedBySequence(tenant,decodedEvents){
 if(!Array.isArray(decodedEvents))throw TypeError('Decoded events must be an array');
 const decoded=new Map();
 for(const item of decodedEvents){
  if(!object(item))mismatch('invalid decoded event');
  const event=object(item.event)?item.event:item,seq=item.seq??event.seq;
  if(!Number.isSafeInteger(seq)||seq<1||decoded.has(seq)||!object(event))mismatch('invalid decoded event sequence');
  if(event.tenant!==undefined&&event.tenant!==tenant)mismatch('decoded event tenant mismatch');
  decoded.set(seq,event);
 }
 return decoded;
}

function ruleStatuses(payload){
 if(!object(payload)||typeof payload.id!=='string'||!Array.isArray(payload.versions))mismatch('invalid rule history');
 const statuses=new Map();
 for(const version of payload.versions){
  if(!object(version)||(!Number.isSafeInteger(version.version)&&typeof version.version!=='string'))mismatch('invalid rule version');
  const key=String(version.version);if(statuses.has(key))mismatch('duplicate rule version');statuses.set(key,version.status);
 }
 return statuses;
}

function reducer(tenant,seed){
 const eventSequences=seed?new Set(seed.eventSequences):new Set(),eventActions=seed?new Map(seed.eventActions):new Map(),eventKeys=seed?new Map(seed.eventKeys):new Map(),actions=seed?new Map([...seed.actions].map(([id,value])=>[id,{...value}])):new Map(),rules=seed?new Map([...seed.rules].map(([id,versions])=>[id,new Map(versions)])):new Map(),exceptions=seed?new Map(seed.exceptions):new Map(),disposed=seed?new Set(seed.disposed):new Set();
 let previousSequence=seed?.previousSequence||0;
 const current=id=>actions.get(id)||mismatch('history references an unknown action');
 const increment=id=>{const value=actions.get(id);if(value)value.version++;else actions.set(id,{tenant,id,version:1,analyzed:0});};
 const incrementAll=()=>{for(const value of actions.values())value.version++;};
 function apply(row,disclosed){
  if(!object(row)||row.tenant!==tenant||!Number.isSafeInteger(row.seq)||row.seq<=previousSequence||typeof row.type!=='string'||!object(row.payload))mismatch('invalid record order or tenant');
  previousSequence=row.seq;
  if(row.type==='event'){
   const payload=row.payload;
   if(disclosed!==undefined&&(!object(disclosed)||disclosed.tenant!==undefined&&disclosed.tenant!==tenant))mismatch('decoded event tenant mismatch');
   let id=payload.actionId;
   if(disclosed){
    const disclosedId=actionId(disclosed.actionId);
    if(id!==undefined&&id!==disclosedId)mismatch('encrypted event actionId mismatch');
    id=id??disclosedId;
   }
   id=actionId(id);
   if(payload.format===encryptedFormat){
    if(payload.tenant!==tenant||payload.seq!==row.seq)mismatch('encrypted event binding mismatch');
    if(typeof payload.keyId!=='string'||!payload.keyId||eventKeys.has(payload.keyId))mismatch('invalid encrypted event key');
    eventKeys.set(payload.keyId,row.seq);
   }else if(payload.tenant!==undefined&&payload.tenant!==tenant)mismatch('event tenant mismatch');
   eventSequences.add(row.seq);eventActions.set(row.seq,id);increment(id);return;
  }
  if(row.type==='asset'){incrementAll();return;}
  if(row.type==='rule'){
   const next=ruleStatuses(row.payload),prior=rules.get(row.payload.id)||new Map();
   if([...next].some(([version,status])=>status==='active'&&prior.get(version)!=='active'))incrementAll();
   rules.set(row.payload.id,next);return;
  }
  if(row.type==='exception'){
   const payload=row.payload;if(typeof payload.id!=='string'||!['pending','approved','expired'].includes(payload.status))mismatch('invalid exception history');
   const prior=exceptions.get(payload.id);
   if(payload.status==='pending'){if(prior!==undefined&&prior!=='pending')mismatch('invalid exception transition');}
   else if(payload.status==='approved'){if(prior!=='pending')mismatch('invalid exception transition');incrementAll();}
   else {if(prior!=='approved')mismatch('invalid exception transition');incrementAll();}
   exceptions.set(payload.id,payload.status);return;
  }
  if(row.type==='evaluation'&&row.payload.status==='evaluated'){
   const payload=row.payload,id=typeof payload.actionId==='string'?payload.actionId:null,version=payload.version,value=id&&actions.get(id);
   if(!value||!Number.isSafeInteger(version)||version<1||value.version!==version||value.analyzed>=version)mismatch('evaluated action version is not replayable');
   value.analyzed=version;return;
  }
  if(row.type==='retention_disposition'){
   const payload=row.payload,hasSequences=Array.isArray(payload.sequences),hasKeys=Array.isArray(payload.keyIds);let sequences;
   if(hasSequences)sequences=payload.sequences;
   else if(hasKeys)sequences=payload.keyIds.map(key=>eventKeys.get(key));
   else mismatch('retention event selection is not replayable');
   if(hasSequences&&hasKeys){
    if(payload.keyIds.length!==sequences.length) mismatch('retention event selection mismatch');
    for(let index=0;index<sequences.length;index++)if(eventKeys.get(payload.keyIds[index])!==sequences[index])mismatch('retention event selection mismatch');
   }
   const unique=new Set();
   for(const seq of sequences){
    if(!Number.isSafeInteger(seq)||seq<1||seq>=row.seq||!eventSequences.has(seq)||unique.has(seq)||disposed.has(seq))mismatch('invalid retention event sequence');
    unique.add(seq);disposed.add(seq);const id=eventActions.get(seq);current(id).version++;
   }
  }
 }
 return {
  apply,
  finish(decodedSequences=[]){for(const seq of decodedSequences)if(!eventSequences.has(seq))mismatch('decoded event is not in signed records');return this.rows();},
  rows(){return [...actions.values()].map(value=>({...value})).sort((a,b)=>a.id<b.id?-1:a.id>b.id?1:0);},
  get(id){const value=actions.get(id);return value?{...value}:undefined;},
  get size(){return actions.size;},
  fork(){return reducer(tenant,{eventSequences,eventActions,eventKeys,actions,rules,exceptions,disposed,previousSequence});},
  get lastSequence(){return previousSequence;},
 };
}

// The caller must authenticate records through the final signed checkpoint and
// bind decoded events to those records before applying them. A reducer can be
// forked so an authenticated suffix is published only after every row passes.
export function createActionProjectionReducer(tenant){
 if(typeof tenant!=='string'||!tenant)throw TypeError('Tenant is required');
 return reducer(tenant);
}

export function reconstructActionProjection(tenant,verifiedRecords,decodedEvents=[]){
 if(typeof tenant!=='string'||!tenant||!Array.isArray(verifiedRecords))throw TypeError('Tenant and verified records are required');
 const decoded=decodedBySequence(tenant,decodedEvents),replay=createActionProjectionReducer(tenant);
 for(const row of verifiedRecords)replay.apply(row,decoded.get(row.seq));
 return replay.finish(decoded.keys());
}

// Keep this comparison and all later uses of the actions projection inside the
// same writer-excluding SQLite transaction.
export function checkActionProjection(db,tenant,verifiedRecords,decodedEvents=[]){
 const expected=reconstructActionProjection(tenant,verifiedRecords,decodedEvents);
 return checkActionRows(db,tenant,expected);
}

export function checkActionRows(db,tenant,expected){
 if(typeof tenant!=='string'||!tenant||!Array.isArray(expected))throw TypeError('Tenant and expected action rows are required');
 const projected=db.prepare('SELECT tenant,id,version,analyzed FROM actions WHERE tenant=? ORDER BY id').all(tenant);
 const byId=new Map(expected.map(row=>[row.id,row]));
 if(projected.length!==expected.length||projected.some(row=>canonical(row)!==canonical(byId.get(row.id))))mismatch();
 return {valid:true,actions:expected.length};
}
