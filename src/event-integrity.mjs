import {canonical} from './crypto.mjs';

const mismatch=detail=>{throw Error(`Event projection differs from signed evidence${detail?`: ${detail}`:''}`);};
const key=(source,id)=>canonical([source,id]);

// Call only with events authenticated through the tenant's final checkpoint.
// Keep this comparison and every later indexed read in one SQLite transaction.
export function checkEventProjection(db,tenant,authenticatedEvents){
 if(typeof tenant!=='string'||!tenant||!Array.isArray(authenticatedEvents))throw TypeError('Tenant and authenticated events are required');
 const expected=new Map();
 for(const event of authenticatedEvents){
  if(!event||typeof event!=='object'||Array.isArray(event)||event.tenant!==tenant||typeof event.source!=='string'||typeof event.id!=='string')mismatch('invalid authenticated event');
  const identity=key(event.source,event.id);if(expected.has(identity))mismatch('duplicate authenticated event identity');expected.set(identity,event);
 }
 const rows=db.prepare('SELECT tenant,source,id,fingerprint,action_id,trace_id,kind,received,body FROM events WHERE tenant=?').all(tenant);
 if(rows.length!==expected.size)mismatch('row count');
 for(const row of rows){
  const signed=expected.get(key(row.source,row.id));if(!signed)mismatch('unsigned or re-keyed row');
  let body;try{body=JSON.parse(row.body);}catch{mismatch('invalid body JSON');}
  if(canonical(body)!==canonical(signed))mismatch('body');
  if(canonical([row.tenant,row.source,row.id,row.fingerprint,row.action_id,row.trace_id,row.kind,row.received])!==canonical([signed.tenant,signed.source,signed.id,signed.fingerprint,signed.actionId,signed.traceId,signed.kind,signed.receivedAt]))mismatch('index');
 }
 return {valid:true,retainedEvents:rows.length,eventIndexes:rows.length};
}
